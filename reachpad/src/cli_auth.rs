//! WorkOS AuthKit CLI Auth, followed by a one-time exchange for Reachpad's
//! ordinary ADR-0034 operator credential.
//!
//! WorkOS owns every authentication operation: device codes, browser
//! confirmation, Magic Auth, MFA, SSO, policy and short-lived session tokens.
//! This module never receives a password or factor.
//!
//! It produces TWO durable results, not one. The first is the same `rpop1`
//! operator credential the manual `/connect` handoff already produced, and it
//! is what the whole fleet surface runs on. The second is the WorkOS
//! access/refresh pair itself, added when the apps surface arrived: the apps
//! API is a WorkOS-protected resource and takes the access token as its bearer
//! (reports/apps-v1 API.md "Auth"), so dropping the pair the way this module
//! used to would have meant a second sign-in ceremony for the same account.
//! Both live in one 0600 file (`conf::Credential`) and both go away together on
//! `logout`.

use anyhow::Context as _;

use crate::http_min;
use crate::transport::{HubUrl, TlsTrust};

pub const DEFAULT_ACCOUNT_URL: &str = "https://reachpad.dev";
const WORKOS_API_URL: &str = "https://api.workos.com";
const WORKOS_DEVICE_PATH: &str = "/user_management/authorize/device";
const WORKOS_TOKEN_PATH: &str = "/user_management/authenticate";
const CLI_CONFIG_PATH: &str = "/.well-known/reachpad-cli";
const CLI_EXCHANGE_PATH: &str = "/api/cli-auth/exchange";
/// The credential exchange's answer when the account endpoint fronts no fleet.
const FLEET_UNCONFIGURED: &str = "fleet_unconfigured";
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

/// The fleet half of a sign-in: the ADR-0034 operator credential and the two
/// URLs that say which fleet it belongs to.
pub struct FleetLogin {
    pub operator_token: String,
    pub operator_expires_at_ms: u64,
    pub controld_url: String,
    pub hub_url: String,
}

/// The only values that survive WorkOS authentication.
pub struct CliLogin {
    /// Absent when the account endpoint has no fleet configured, which is the
    /// ordinary answer on reachpad.dev since the product there became apps.
    /// The sign-in still happened; there is just no workspace half to it.
    pub fleet: Option<FleetLogin>,
    pub email: Option<String>,
    /// The WorkOS session itself, kept because the apps API is a WorkOS
    /// resource and takes this token as its bearer (reports/apps-v1 API.md
    /// "Auth"). Before apps existed this pair was deliberately dropped one
    /// line after the exchange; a second sign-in ceremony for the same account
    /// is not a better answer than persisting it beside the credential it was
    /// exchanged for, in the same 0600 file, revoked by the same `logout`.
    pub workos: crate::conf::WorkosSession,
}

/// Trade a refresh token for a fresh access token, rotating the refresh token
/// with it. WorkOS access tokens live about five minutes, so this is the call
/// that stands between a sign-in and every apps command after it.
///
/// The new refresh token REPLACES the old one — WorkOS rotates on every
/// refresh, and keeping the spent one would sign the laptop out on its next
/// command.
pub async fn refresh_workos(
    session: &crate::conf::WorkosSession,
) -> anyhow::Result<crate::conf::WorkosSession> {
    let response = tokio::time::timeout(
        AUTH_REQUEST_TIMEOUT,
        http_min::post_form_trust(
            WORKOS_API_URL,
            WORKOS_TOKEN_PATH,
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", session.refresh_token.as_str()),
                ("client_id", session.client_id.as_str()),
            ],
            &TlsTrust::default(),
        ),
    )
    .await
    .context("refreshing the WorkOS session timed out")?
    .context("refreshing the WorkOS session")?;
    anyhow::ensure!(
        response.status == 200,
        "your sign-in could not be refreshed ({})",
        response_error(&response.body)
    );
    workos_session(&response.body, &session.client_id)
}

/// Read the access/refresh pair out of a WorkOS token response.
fn workos_session(
    body: &serde_json::Value,
    client_id: &str,
) -> anyhow::Result<crate::conf::WorkosSession> {
    let access_token = body_string(body, "access_token", MAX_TOKEN_LEN)?;
    let refresh_token = body_string(body, "refresh_token", MAX_TOKEN_LEN)?;
    let expires_at_ms = access_token_expiry_ms(&access_token);
    Ok(crate::conf::WorkosSession {
        access_token,
        refresh_token,
        expires_at_ms,
        client_id: client_id.to_owned(),
    })
}

/// When a WorkOS access token stops being accepted, read from its own `exp`
/// claim.
///
/// The claim, not a client-side clock arithmetic on `expires_in`: WorkOS does
/// not always send one, and the token itself is the authority on when it dies.
/// A token whose payload cannot be read returns `None`, which
/// [`crate::conf::Credential::workos_access`] treats as spent — one wasted
/// refresh, never a stale bearer.
fn access_token_expiry_ms(access_token: &str) -> Option<u64> {
    use base64::Engine as _;
    let payload = access_token.split('.').nth(1)?;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
    claims["exp"].as_u64()?.checked_mul(1_000)
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

/// The one allowlist for every origin this CLI hands a long-lived secret to.
///
/// Two callers, one rule. `--account-url` receives a WorkOS access token; the
/// control plane `--endpoint` expands to receives the `rpop1` operator
/// credential on an `Authorization: Bearer` header. A merely TLS-valid
/// arbitrary host on either would be a credential exfiltration footgun, and
/// `--endpoint` was the sharper of the two: it had `env =
/// "REACHPAD_ENDPOINT"`, so one exported variable was enough to send the
/// account's root credential wherever the exporter liked. Production is
/// confined to Reachpad-controlled DNS on 443 with no path prefix (ADR-0040:
/// one host, one port, both planes); loopback remains available for local
/// integration tests, where plaintext can only ever reach this machine.
///
/// There is deliberately no second copy of this check. A divergent allowlist
/// is how one of two doors ends up wider than the other.
pub fn validate_credential_origin(url: &str) -> anyhow::Result<()> {
    anyhow::ensure!(url.len() <= MAX_URL_LEN, "control URL is too long");
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
        "refusing to send a credential to {}: this CLI speaks to reachpad.dev, \
         *.reachpad.dev on 443, or a controld on this machine, and nothing else. \
         An operator credential or a WorkOS access token is sent to this origin.",
        endpoint.host
    );
    Ok(())
}

/// The same rule for the DATA plane. A `ws://` hub off-box carries workspace
/// Biscuits in the clear, so it is refused for exactly the reason the control
/// plane refuses plaintext; `quic://` and `wss://` are confidential by
/// construction. Public because [`crate::transport::ClientTransport::connect_with`]
/// is the last gate before a socket opens.
pub fn validate_hub_url(url: &str) -> anyhow::Result<()> {
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

/// The host a hub URL dials, for the one comparison below. `ws://` and
/// `wss://` are handed to tungstenite verbatim, so their host is read the same
/// way `http_min` reads one.
fn hub_host(url: &str) -> anyhow::Result<String> {
    match HubUrl::parse(url)? {
        HubUrl::Quic { host, .. } => Ok(host),
        HubUrl::Ws(_) => {
            let as_http = url
                .replacen("wss://", "https://", 1)
                .replacen("ws://", "http://", 1);
            Ok(http_min::parse_url(&as_http)?.host)
        }
    }
}

/// Collapse the exchange's plane pair into the one string the v1 CLI keeps
/// (`[endpoint]` in config.toml): ADR-0040 is one host, one port, both planes,
/// and `Cli::planes` derives control and hub from it.
///
/// The pair is not simply trusted. Both planes must name the SAME host; a
/// deployment that split them is one this CLI's `--endpoint` cannot describe,
/// and silently keeping only the control host would leave the hub pointing
/// somewhere the server did not say. That refusal names the override flags.
pub fn endpoint_from_login(controld_url: &str, hub_url: &str) -> anyhow::Result<String> {
    validate_connection_urls(controld_url, hub_url)?;
    let control = http_min::parse_url(controld_url)?;
    anyhow::ensure!(
        control.base_path.is_empty(),
        "sign-in returned a control-plane URL with a path prefix, which `--endpoint` cannot carry"
    );
    let hub = hub_host(hub_url)?;
    anyhow::ensure!(
        hub.eq_ignore_ascii_case(&control.host),
        "sign-in put the control plane on {} and the hub on {hub}; this CLI describes one host \
         for both. Use --controld and --hub explicitly.",
        control.host
    );
    Ok(match control.scheme {
        // Loopback development: keep the scheme and port, which is exactly
        // what `Cli::planes` expects to see for a plaintext endpoint.
        http_min::Scheme::Plaintext => format!("http://{}", control.authority()),
        http_min::Scheme::Tls if control.port == 443 => control.host,
        http_min::Scheme::Tls => control.authority(),
    })
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
    validate_credential_origin(account_url)?;
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
    validate_credential_origin(account_url)?;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(device.expires_in);
    let mut interval = device.interval;
    let (workos, email) = loop {
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
            // Both halves are kept now. The access token is spent immediately
            // on the credential exchange below AND persisted for the apps API;
            // the refresh token is what keeps that working past five minutes.
            let workos = workos_session(&response.body, &device.client_id)?;
            let email = response.body["user"]["email"]
                .as_str()
                .filter(|value| !value.is_empty() && value.len() <= 320)
                .map(str::to_owned);
            break (workos, email);
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

    let fleet = exchange_for_fleet(account_url, &workos.access_token, reachpad_trust).await?;

    Ok(CliLogin {
        fleet,
        email,
        workos,
    })
}

/// Trade the WorkOS access token for the fleet credential, and treat exactly
/// one refusal as an answer rather than as a failure.
///
/// `fleet_unconfigured` is reachpad.dev saying it is not a fleet front door.
/// That is not a broken login and it is not a reason to throw away a session
/// the browser just approved: the apps API takes the WorkOS token directly,
/// and apps is the product on that endpoint. So this returns `Ok(None)` and
/// the caller stores the session anyway. Every OTHER non-200 is still a failed
/// sign-in, refused here with the error the server named — widening this to
/// any refusal would turn a revoked account or a rejected token into a
/// half-signed-in machine.
pub async fn exchange_for_fleet(
    account_url: &str,
    access_token: &str,
    reachpad_trust: &TlsTrust,
) -> anyhow::Result<Option<FleetLogin>> {
    let response = tokio::time::timeout(
        AUTH_REQUEST_TIMEOUT,
        http_min::post_json_trust(
            account_url,
            CLI_EXCHANGE_PATH,
            &serde_json::json!({}),
            Some(access_token),
            reachpad_trust,
        ),
    )
    .await
    .context("Reachpad credential exchange timed out")?
    .context("exchanging the WorkOS session for a Reachpad credential")?;
    if response.status != 200 {
        let error = response_error(&response.body);
        if error == FLEET_UNCONFIGURED {
            return Ok(None);
        }
        anyhow::bail!("Reachpad refused the authenticated CLI session ({error})");
    }

    let operator_token = body_string(&response.body, "operator_token", MAX_TOKEN_LEN)?;
    validate_operator_token(&operator_token)?;
    let controld_url = body_string(&response.body, "controld_url", MAX_URL_LEN)?;
    let hub_url = body_string(&response.body, "hub_url", MAX_URL_LEN)?;
    validate_connection_urls(&controld_url, &hub_url)?;
    let operator_expires_at_ms = response.body["expires_at_ms"]
        .as_u64()
        .context("credential exchange returned no expiry")?;

    Ok(Some(FleetLogin {
        operator_token,
        operator_expires_at_ms,
        controld_url,
        hub_url,
    }))
}

/// Best-effort convenience only. Printing the URI and code remains the real
/// flow, so a remote machine with no desktop works without port forwarding.
pub fn open_browser(url: &str) -> bool {
    #[cfg(target_os = "linux")]
    {
        // Reachpad workspaces expose the owner's real browser through this
        // host command even though the remote shell has no desktop display.
        // Other Linux machines fall through to their ordinary desktop opener.
        if std::process::Command::new("devbox-browser-open")
            .arg(url)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .is_ok()
        {
            return true;
        }
        if std::env::var_os("DISPLAY").is_none() && std::env::var_os("WAYLAND_DISPLAY").is_none() {
            return false;
        }
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
        assert!(validate_credential_origin("https://reachpad.dev").is_ok());
        assert!(validate_credential_origin("https://staging.reachpad.dev").is_ok());
        assert!(validate_credential_origin("http://127.0.0.1:3000").is_ok());
        assert!(validate_credential_origin("https://example.com").is_err());
        assert!(validate_credential_origin("https://reachpad.dev.example.com").is_err());
        assert!(validate_credential_origin("https://reachpad.dev:444").is_err());
        assert!(validate_credential_origin("https://reachpad.dev/prefix").is_err());
    }

    #[test]
    fn the_exchanged_pair_collapses_to_one_endpoint_or_is_refused() {
        assert_eq!(
            endpoint_from_login("https://m1.reachpad.dev", "quic://m1.reachpad.dev").unwrap(),
            "m1.reachpad.dev"
        );
        assert_eq!(
            endpoint_from_login("https://m1.reachpad.dev", "wss://m1.reachpad.dev/ws").unwrap(),
            "m1.reachpad.dev"
        );
        assert_eq!(
            endpoint_from_login("http://127.0.0.1:7401", "ws://127.0.0.1:7420/ws").unwrap(),
            "http://127.0.0.1:7401"
        );
        // Two hosts is a fleet shape one `--endpoint` cannot describe, so it
        // is refused rather than half-kept.
        assert!(endpoint_from_login("https://m1.reachpad.dev", "quic://m2.reachpad.dev").is_err());
        // And the pair is still validated on this path.
        assert!(endpoint_from_login("http://m1.reachpad.dev", "quic://m1.reachpad.dev").is_err());
        assert!(endpoint_from_login("https://m1.reachpad.dev", "ws://m1.reachpad.dev/ws").is_err());
    }

    #[test]
    fn operator_credential_shape_is_checked_before_persistence() {
        assert!(validate_operator_token("rpop1.id.secret").is_ok());
        assert!(validate_operator_token("rpop1.id").is_err());
        assert!(validate_operator_token("rpak1.id.secret").is_err());
        assert!(validate_operator_token("rpop1.id.secret.extra").is_err());
    }
}
