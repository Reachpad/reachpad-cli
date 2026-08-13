//! WorkOS AuthKit CLI Auth, followed by a one-time exchange for Reachpad's
//! ordinary ADR-0034 operator credential.
//!
//! WorkOS owns every authentication operation: device codes, browser
//! confirmation, Magic Auth, MFA, SSO, policy and short-lived session tokens.
//! This module never receives a password or factor and never persists a WorkOS
//! token. The only durable result is the same `rpop1` credential the manual
//! `/connect` handoff already produced.

use anyhow::Context as _;

use crate::http_min;
use crate::transport::{HubUrl, TlsTrust};

pub const DEFAULT_ACCOUNT_URL: &str = "https://reachpad.dev";
const WORKOS_API_URL: &str = "https://api.workos.com";
const WORKOS_DEVICE_PATH: &str = "/user_management/authorize/device";
const WORKOS_TOKEN_PATH: &str = "/user_management/authenticate";
const CLI_CONFIG_PATH: &str = "/.well-known/reachpad-cli";
const CLI_EXCHANGE_PATH: &str = "/api/cli-auth/exchange";
const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

const MAX_CODE_LEN: usize = 2048;
const MAX_URL_LEN: usize = 4096;
const MAX_TOKEN_LEN: usize = 32 * 1024;
const AUTH_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

/// WorkOS's pending authorization. The secret device code deliberately has no
/// Debug implementation, so a convenient `{:?}` cannot put it in a log.
pub struct DeviceAuthorization {
    device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: String,
    expires_in: u64,
    interval: u64,
    client_id: String,
}

/// The only values that survive WorkOS authentication.
pub struct CliLogin {
    pub operator_token: String,
    pub operator_expires_at_ms: u64,
    pub controld_url: String,
    pub hub_url: String,
    pub email: Option<String>,
}

fn body_string(body: &serde_json::Value, name: &str, max_len: usize) -> anyhow::Result<String> {
    let value = body[name]
        .as_str()
        .with_context(|| format!("authentication response has no {name}"))?;
    anyhow::ensure!(
        !value.is_empty() && value.len() <= max_len,
        "authentication response has an invalid {name}"
    );
    Ok(value.to_owned())
}

fn response_error(body: &serde_json::Value) -> &str {
    body["error"].as_str().unwrap_or("authentication_failed")
}

fn validate_https_or_loopback(url: &str) -> anyhow::Result<()> {
    anyhow::ensure!(url.len() <= MAX_URL_LEN, "authentication URL is too long");
    let endpoint = http_min::parse_url(url)?;
    endpoint.ensure_confidential()
}

/// A WorkOS token is sent to this origin, so a merely TLS-valid arbitrary
/// `--account-url` would be a credential exfiltration footgun. Production is
/// confined to Reachpad-controlled DNS; loopback remains available for local
/// integration tests.
fn validate_account_url(url: &str) -> anyhow::Result<()> {
    anyhow::ensure!(url.len() <= MAX_URL_LEN, "account URL is too long");
    let endpoint = http_min::parse_url(url)?;
    endpoint.ensure_confidential()?;
    if endpoint.is_loopback() {
        return Ok(());
    }
    anyhow::ensure!(
        endpoint.scheme == http_min::Scheme::Tls
            && endpoint.port == 443
            && endpoint.base_path.is_empty()
            && (endpoint.host == "reachpad.dev" || endpoint.host.ends_with(".reachpad.dev")),
        "refusing non-Reachpad account URL: a WorkOS access token is sent to this origin"
    );
    Ok(())
}

fn validate_hub_url(url: &str) -> anyhow::Result<()> {
    anyhow::ensure!(url.len() <= MAX_URL_LEN, "hub URL is too long");
    match HubUrl::parse(url)? {
        HubUrl::Quic { .. } => Ok(()),
        HubUrl::Ws(_) if url.starts_with("wss://") => Ok(()),
        HubUrl::Ws(_) => {
            let as_http = url.replacen("ws://", "http://", 1);
            http_min::parse_url(&as_http)?.ensure_confidential()
        }
    }
}

/// Validate a saved or server-returned pair before either can influence a
/// credential-bearing connection.
pub fn validate_connection_urls(controld_url: &str, hub_url: &str) -> anyhow::Result<()> {
    validate_https_or_loopback(controld_url)?;
    validate_hub_url(hub_url)
}

fn validate_operator_token(value: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        value.len() <= MAX_TOKEN_LEN,
        "operator credential is too long"
    );
    let mut parts = value.split('.');
    anyhow::ensure!(
        parts.next() == Some("rpop1")
            && parts.next().is_some_and(|part| !part.is_empty())
            && parts.next().is_some_and(|part| !part.is_empty())
            && parts.next().is_none(),
        "credential exchange returned an invalid operator credential"
    );
    Ok(())
}

/// Start WorkOS's native device flow. Reachpad contributes only the public
/// client id discovered from its deployment; no Reachpad authorization record
/// is created here.
pub async fn start_device_authorization(
    account_url: &str,
    reachpad_trust: &TlsTrust,
) -> anyhow::Result<DeviceAuthorization> {
    validate_account_url(account_url)?;
    let config = tokio::time::timeout(
        AUTH_REQUEST_TIMEOUT,
        http_min::get_json_trust(account_url, CLI_CONFIG_PATH, None, reachpad_trust),
    )
    .await
    .context("Reachpad CLI authentication configuration timed out")?
    .context("reading Reachpad CLI authentication configuration")?;
    anyhow::ensure!(
        config.status == 200,
        "Reachpad CLI authentication is unavailable ({})",
        response_error(&config.body)
    );
    let client_id = body_string(&config.body, "workos_client_id", 256)?;
    anyhow::ensure!(
        client_id.starts_with("client_"),
        "Reachpad returned an invalid WorkOS client id"
    );

    // WorkOS is a separate trust boundary. Always use platform roots for its
    // public API; --hub-ca narrows trust for a Reachpad staging deployment and
    // must not replace the roots used for api.workos.com.
    let response = tokio::time::timeout(
        AUTH_REQUEST_TIMEOUT,
        http_min::post_form_trust(
            WORKOS_API_URL,
            WORKOS_DEVICE_PATH,
            &[("client_id", client_id.as_str())],
            &TlsTrust::default(),
        ),
    )
    .await
    .context("WorkOS CLI authentication request timed out")?
    .context("starting WorkOS CLI authentication")?;
    anyhow::ensure!(
        response.status == 200,
        "WorkOS refused CLI authentication ({})",
        response_error(&response.body)
    );

    let device_code = body_string(&response.body, "device_code", MAX_CODE_LEN)?;
    let user_code = body_string(&response.body, "user_code", 64)?;
    let verification_uri = body_string(&response.body, "verification_uri", MAX_URL_LEN)?;
    let verification_uri_complete = response.body["verification_uri_complete"]
        .as_str()
        .filter(|value| !value.is_empty() && value.len() <= MAX_URL_LEN)
        .unwrap_or(&verification_uri)
        .to_owned();
    validate_https_or_loopback(&verification_uri)?;
    validate_https_or_loopback(&verification_uri_complete)?;
    let expires_in = response.body["expires_in"]
        .as_u64()
        .context("WorkOS response has no expires_in")?;
    // RFC 8628 specifies five seconds when the authorization server omits the
    // optional interval, which WorkOS's API reference permits.
    let interval = response.body["interval"].as_u64().unwrap_or(5);
    anyhow::ensure!(
        (30..=900).contains(&expires_in),
        "WorkOS returned an invalid device-code lifetime"
    );
    anyhow::ensure!(
        (1..=60).contains(&interval),
        "WorkOS returned an invalid polling interval"
    );

    Ok(DeviceAuthorization {
        device_code,
        user_code,
        verification_uri,
        verification_uri_complete,
        expires_in,
        interval,
        client_id,
    })
}

/// Poll WorkOS until browser authorization finishes, then immediately trade
/// the short-lived WorkOS token for Reachpad's credential and forget both
/// WorkOS tokens. No refresh token crosses this function boundary.
pub async fn complete_device_authorization(
    account_url: &str,
    device: DeviceAuthorization,
    reachpad_trust: &TlsTrust,
) -> anyhow::Result<CliLogin> {
    // Re-check at the credential-bearing boundary even though the normal
    // caller already checked before starting the device flow.
    validate_account_url(account_url)?;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(device.expires_in);
    let mut interval = device.interval;
    let (access_token, email) = loop {
        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "WorkOS CLI authentication timed out"
        );
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let response = tokio::time::timeout(
            AUTH_REQUEST_TIMEOUT.min(remaining),
            http_min::post_form_trust(
                WORKOS_API_URL,
                WORKOS_TOKEN_PATH,
                &[
                    ("grant_type", DEVICE_GRANT),
                    ("device_code", device.device_code.as_str()),
                    ("client_id", device.client_id.as_str()),
                ],
                &TlsTrust::default(),
            ),
        )
        .await
        .context("WorkOS CLI authentication timed out")?
        .context("polling WorkOS CLI authentication")?;
        if response.status == 200 {
            let access_token = body_string(&response.body, "access_token", MAX_TOKEN_LEN)?;
            // WorkOS also returns a refresh token. It is deliberately not read:
            // the CLI needs one durable Reachpad credential, not a second
            // persisted WorkOS session with its own rotation lifecycle.
            let email = response.body["user"]["email"]
                .as_str()
                .filter(|value| !value.is_empty() && value.len() <= 320)
                .map(str::to_owned);
            break (access_token, email);
        }
        match response_error(&response.body) {
            "authorization_pending" => {}
            // WorkOS requires an increase of at least five seconds.
            "slow_down" => interval = interval.saturating_add(5).min(60),
            "access_denied" => anyhow::bail!("WorkOS CLI authentication was denied"),
            "expired_token" => anyhow::bail!("WorkOS CLI authentication expired"),
            _ => anyhow::bail!("WorkOS CLI authentication failed"),
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let pause = std::time::Duration::from_secs(interval).min(remaining);
        tokio::time::sleep(pause).await;
    };

    let response = tokio::time::timeout(
        AUTH_REQUEST_TIMEOUT,
        http_min::post_json_trust(
            account_url,
            CLI_EXCHANGE_PATH,
            &serde_json::json!({}),
            Some(&access_token),
            reachpad_trust,
        ),
    )
    .await
    .context("Reachpad credential exchange timed out")?
    .context("exchanging the WorkOS session for a Reachpad credential")?;
    anyhow::ensure!(
        response.status == 200,
        "Reachpad refused the authenticated CLI session ({})",
        response_error(&response.body)
    );

    let operator_token = body_string(&response.body, "operator_token", MAX_TOKEN_LEN)?;
    validate_operator_token(&operator_token)?;
    let controld_url = body_string(&response.body, "controld_url", MAX_URL_LEN)?;
    let hub_url = body_string(&response.body, "hub_url", MAX_URL_LEN)?;
    validate_connection_urls(&controld_url, &hub_url)?;
    let operator_expires_at_ms = response.body["expires_at_ms"]
        .as_u64()
        .context("credential exchange returned no expiry")?;

    Ok(CliLogin {
        operator_token,
        operator_expires_at_ms,
        controld_url,
        hub_url,
        email,
    })
}

/// Best-effort convenience only. Printing the URI and code remains the real
/// flow, so a remote machine with no desktop works without port forwarding.
pub fn open_browser(url: &str) -> bool {
    #[cfg(target_os = "linux")]
    if std::env::var_os("DISPLAY").is_none() && std::env::var_os("WAYLAND_DISPLAY").is_none() {
        return false;
    }
    #[cfg(target_os = "linux")]
    let mut command = std::process::Command::new("xdg-open");
    #[cfg(target_os = "macos")]
    let mut command = std::process::Command::new("open");
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    return false;

    command
        .arg(url)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_validation_refuses_plaintext_off_box() {
        assert!(validate_https_or_loopback("https://reachpad.dev").is_ok());
        assert!(validate_https_or_loopback("http://127.0.0.1:3000").is_ok());
        assert!(validate_https_or_loopback("http://reachpad.dev").is_err());
        assert!(validate_hub_url("wss://m1.reachpad.dev/ws").is_ok());
        assert!(validate_hub_url("ws://127.0.0.1:7420/ws").is_ok());
        assert!(validate_hub_url("ws://m1.reachpad.dev/ws").is_err());
    }

    #[test]
    fn account_exchange_is_pinned_to_reachpad_or_loopback() {
        assert!(validate_account_url("https://reachpad.dev").is_ok());
        assert!(validate_account_url("https://staging.reachpad.dev").is_ok());
        assert!(validate_account_url("http://127.0.0.1:3000").is_ok());
        assert!(validate_account_url("https://example.com").is_err());
        assert!(validate_account_url("https://reachpad.dev.example.com").is_err());
        assert!(validate_account_url("https://reachpad.dev:444").is_err());
        assert!(validate_account_url("https://reachpad.dev/prefix").is_err());
    }

    #[test]
    fn operator_credential_shape_is_checked_before_persistence() {
        assert!(validate_operator_token("rpop1.id.secret").is_ok());
        assert!(validate_operator_token("rpop1.id").is_err());
        assert!(validate_operator_token("rpak1.id.secret").is_err());
        assert!(validate_operator_token("rpop1.id.secret.extra").is_err());
    }
}
