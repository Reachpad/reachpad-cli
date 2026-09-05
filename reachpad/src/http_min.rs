//! Hand-rolled minimal HTTP/1.1 JSON client, over a tokio `TcpStream` or a
//! `tokio-rustls` TLS stream on top of one.
//!
//! Deliberately not reqwest/hyper: the CLI needs a small set of JSON and form
//! requests with `Content-Length` and `Connection: close` semantics — a
//! dependency tree is not warranted for that (§10 posture). Response
//! parsing handles `Content-Length` and `chunked` transfer encoding, which
//! covers everything axum/hyper emits for the controld API.
//!
//! # `https://` is the point (ADR-0040)
//!
//! This module used to reject `https://` outright ("only http:// is
//! supported"), which meant the control client had no TLS at all: from a
//! laptop there was literally no way to run `auth login`, `ws create` or
//! `share` without an SSH tunnel. It now speaks TLS with the same
//! [`TlsTrust`] postures the QUIC data path uses — OS trust store by default,
//! `--hub-ca` to narrow to explicit anchors, never anything that skips
//! verification.
//!
//! # Fail closed on plaintext
//!
//! Every call this client makes carries a credential (an operator credential,
//! an identity token, or a Biscuit). [`Endpoint::ensure_confidential`]
//! therefore REFUSES plain `http://` to any host that is not loopback, before
//! a socket is opened and before a credential is formatted into a request —
//! with an error naming the host and the URL to use instead. Loopback stays
//! permitted because that is where hub forwards control requests to controld
//! (ADR-0040) and where every in-process test drives them.

use std::{future::Future, sync::Arc, time::Duration};

use anyhow::Context;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::transport::TlsTrust;

/// ALPN offered on `https://` control connections: hub's TLS endpoint serves
/// the control plane over HTTP/1.1 (it speaks no h2).
pub const HTTP_1_1_ALPN: &[u8] = b"http/1.1";

/// Phase budgets for the CLI's control transport. A failed host must not
/// inherit the kernel's multi-minute SYN retry schedule, and a peer that
/// accepts TCP but never completes TLS must not hold a command forever.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Ordinary control calls return one small JSON response. Exec is deliberately
/// excluded: its NDJSON response lasts for the command's caller-supplied
/// timeout and is bounded by `errors::exec_deadline_ms` instead.
const REQUEST_RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);

/// The control API returns small JSON documents. Bound both sides of the
/// header delimiter so a peer cannot turn a CLI command into an unbounded
/// allocation by never closing its response or by declaring a giant body.
const MAX_RESPONSE_HEADER_BYTES: usize = 64 * 1024;
const MAX_RESPONSE_BODY_BYTES: usize = 16 * 1024 * 1024;
/// Transfer coding is buffered before the ordinary response is decoded, so it
/// needs a bound of its own. This allowance is deliberately separate from the
/// decoded JSON ceiling: a payload exactly at that ceiling remains valid when
/// chunk-size lines and CRLFs are added on the wire.
const MAX_RESPONSE_CHUNK_FRAMING_BYTES: usize = 1024 * 1024;
// Keep this in step with controld's `execbroker::MAX_NDJSON_LINE`: a guest
// control frame can be 1 MiB, and base64 plus its JSON envelope stays below
// 2 MiB. The stream as a whole remains unbounded and backpressured.
const MAX_NDJSON_LINE_BYTES: usize = 2 * 1024 * 1024;

/// A parsed HTTP response: status code + JSON body (Null when empty).
#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub body: serde_json::Value,
}

/// Transport for a control URL. There are exactly two, and only one of them
/// may reach off-box.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// `http://` — permitted for loopback only.
    Plaintext,
    /// `https://` — the public control path.
    Tls,
}

/// A parsed `--controld` URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub scheme: Scheme,
    pub host: String,
    pub port: u16,
    /// Never ends in `/`, so `format!("{base_path}{path}")` is safe.
    pub base_path: String,
}

impl Endpoint {
    /// Is this host on this machine? Only literal loopback addresses and the
    /// name `localhost` count — deliberately no DNS resolution, so a name that
    /// merely *resolves* to 127.0.0.1 today cannot unlock plaintext.
    pub fn is_loopback(&self) -> bool {
        if self.host.eq_ignore_ascii_case("localhost") {
            return true;
        }
        self.host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false)
    }

    /// The authority as it goes into the `Host` header.
    pub fn authority(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    /// Refuse to speak plaintext to anything but this machine.
    ///
    /// The failure is the feature: a client that quietly downgraded would put
    /// an operator credential on the wire in the clear. The message names the
    /// host and the exact URL to use instead, because "connection refused" is
    /// not an instruction.
    pub fn ensure_confidential(&self) -> anyhow::Result<()> {
        if self.scheme == Scheme::Tls || self.is_loopback() {
            return Ok(());
        }
        anyhow::bail!(
            "refusing to send a credential in plaintext to {host}: every reach control call \
             carries one (operator credential, identity token or Biscuit), and the control \
             plane is TLS-only (ADR-0040). Use --controld https://{host} instead — it is the \
             same public endpoint on 443, verified against your OS trust store. Add \
             --hub-ca <pem> only if that hub holds a Let's Encrypt *staging* certificate. \
             Plain http:// is accepted for loopback (127.0.0.1, [::1], localhost) only.",
            host = self.host
        )
    }
}

/// Split an `http://` or `https://` URL into its [`Endpoint`] parts.
///
/// Default ports follow the scheme (80 / 443), so `https://m1.reachpad.dev`
/// is the whole thing a laptop has to type.
pub fn parse_url(url: &str) -> anyhow::Result<Endpoint> {
    let (scheme, rest, default_port) = if let Some(rest) = url.strip_prefix("https://") {
        (Scheme::Tls, rest, 443u16)
    } else if let Some(rest) = url.strip_prefix("http://") {
        (Scheme::Plaintext, rest, 80u16)
    } else {
        anyhow::bail!(
            "unsupported URL {url:?}: use https://<host> for the public control endpoint, \
             or http://127.0.0.1:<port> for a controld on this machine"
        );
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    // Bracketed IPv6 keeps its own colons; only a trailing `:port` is split.
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') || (h.starts_with('[') && h.ends_with(']')) => (
            h.to_owned(),
            p.parse::<u16>()
                .with_context(|| format!("invalid port in URL {url:?}"))?,
        ),
        _ => (authority.to_owned(), default_port),
    };
    anyhow::ensure!(!host.is_empty(), "empty host in URL {url:?}");
    Ok(Endpoint {
        scheme,
        host: host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_owned(),
        port,
        base_path: path.trim_end_matches('/').to_owned(),
    })
}

/// Kept for the URL-shaped call sites that only want the parts.
pub fn parse_http_url(url: &str) -> anyhow::Result<(String, u16, String)> {
    let endpoint = parse_url(url)?;
    Ok((endpoint.host, endpoint.port, endpoint.base_path))
}

/// POST `body` as JSON to `base_url` + `path` and parse the response.
pub async fn post_json(
    base_url: &str,
    path: &str,
    body: &serde_json::Value,
) -> anyhow::Result<Response> {
    post_json_auth(base_url, path, body, None).await
}

/// [`post_json`] with an optional `Authorization: Bearer` credential — the
/// operator credential exchange (ADR-0034/0039). The value is written to the
/// socket and nowhere else: it is never logged and never echoed.
pub async fn post_json_auth(
    base_url: &str,
    path: &str,
    body: &serde_json::Value,
    bearer: Option<&str>,
) -> anyhow::Result<Response> {
    post_json_trust(base_url, path, body, bearer, &TlsTrust::default()).await
}

/// [`post_json_auth`] with an explicit TLS trust posture for `https://`
/// (ignored by loopback `http://`, which has no certificate to verify).
pub async fn post_json_trust(
    base_url: &str,
    path: &str,
    body: &serde_json::Value,
    bearer: Option<&str>,
    trust: &TlsTrust,
) -> anyhow::Result<Response> {
    send_json(base_url, "POST", path, Some(body), bearer, None, trust).await
}

/// POST with an `Idempotency-Key` header.
///
/// Every edge mutation on controld's `/v1` surface requires one (design §5:
/// the API's main clients are agents, and agents retry), and a replay returns
/// the STORED RESPONSE rather than re-executing. Separate from
/// [`post_json_trust`] so the header cannot be forgotten on a route that
/// needs it or sent on one that does not.
pub async fn post_json_keyed(
    base_url: &str,
    path: &str,
    body: &serde_json::Value,
    bearer: Option<&str>,
    idempotency_key: &str,
    trust: &TlsTrust,
) -> anyhow::Result<Response> {
    send_json(
        base_url,
        "POST",
        path,
        Some(body),
        bearer,
        Some(idempotency_key),
        trust,
    )
    .await
}

/// POST an `application/x-www-form-urlencoded` body. WorkOS CLI Auth uses
/// the OAuth device grant's form encoding rather than JSON; keeping it in this
/// transport preserves the CLI's one rustls trust posture and avoids adding a
/// second HTTP stack just for login.
pub async fn post_form_trust(
    base_url: &str,
    path: &str,
    fields: &[(&str, &str)],
    trust: &TlsTrust,
) -> anyhow::Result<Response> {
    let mut payload = String::new();
    for (index, (name, value)) in fields.iter().enumerate() {
        if index > 0 {
            payload.push('&');
        }
        payload.push_str(&form_component(name));
        payload.push('=');
        payload.push_str(&form_component(value));
    }
    send_payload(
        base_url,
        "POST",
        path,
        payload.as_bytes(),
        None,
        "application/x-www-form-urlencoded",
        trust,
    )
    .await
}

/// GET `path` (which may carry a query string) and parse the response. Same
/// confidentiality rule as [`post_json_trust`]: a listing is authorized by a
/// credential too, so plaintext off-box is refused.
pub async fn get_json_trust(
    base_url: &str,
    path: &str,
    bearer: Option<&str>,
    trust: &TlsTrust,
) -> anyhow::Result<Response> {
    send_json(base_url, "GET", path, None, bearer, None, trust).await
}

/// Any method with an optional JSON body — what the apps API needs, where the
/// same client has to speak `PUT`, `PATCH` and `DELETE` as well as the two
/// verbs the fleet routes use. Same confidentiality rule as everything else in
/// this module.
pub async fn json_request(
    base_url: &str,
    method: &str,
    path: &str,
    body: Option<&serde_json::Value>,
    bearer: Option<&str>,
    trust: &TlsTrust,
) -> anyhow::Result<Response> {
    send_json(base_url, method, path, body, bearer, None, trust).await
}

/// A response whose body is BYTES, not JSON: the source of one file, and the
/// snapshot tarball. `parse_response` insists on JSON, which is right for every
/// control route and wrong for the two apps routes that answer with content.
#[derive(Debug)]
pub struct Raw {
    pub status: u16,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
}

impl Raw {
    /// The body as JSON, for the error case: every apps failure answers with
    /// `{ error, message }` whatever the route's success shape is.
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap_or(serde_json::Value::Null)
    }
}

/// Send `payload` with an explicit content type and read the reply as bytes.
/// The two directions the apps snapshot travels — the `PUT` to the upload
/// ticket, and the `GET` of a version's source — are both this call.
pub async fn request_bytes(
    base_url: &str,
    method: &str,
    path: &str,
    payload: &[u8],
    content_type: &str,
    bearer: Option<&str>,
    trust: &TlsTrust,
) -> anyhow::Result<Raw> {
    let endpoint = parse_url(base_url)?;
    endpoint.ensure_confidential()?;
    let request = request_head_with_type(
        &endpoint,
        method,
        path,
        bearer,
        None,
        payload.len(),
        content_type,
    )?;
    let tcp = connect_tcp(&endpoint).await?;
    match endpoint.scheme {
        Scheme::Plaintext => {
            exchange_raw_within(tcp, request.as_bytes(), payload, &endpoint.authority()).await
        }
        Scheme::Tls => {
            let tls = connect_tls(tcp, &endpoint, trust).await?;
            exchange_raw_within(tls, request.as_bytes(), payload, &endpoint.authority()).await
        }
    }
}

/// The most a bytes-bodied response may be. The snapshot routes are the only
/// callers and API.md caps a snapshot at 50 MiB; this is the ceiling that stops
/// a peer streaming forever into a `Vec` that grows until the process is killed.
const MAX_RAW_RESPONSE_BYTES: usize = 128 * 1024 * 1024;

async fn exchange_raw<S>(stream: S, head: &[u8], payload: &[u8]) -> anyhow::Result<Raw>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    exchange_raw_capped(stream, head, payload, MAX_RAW_RESPONSE_BYTES).await
}

async fn exchange_raw_capped<S>(
    mut stream: S,
    head: &[u8],
    payload: &[u8],
    cap: usize,
) -> anyhow::Result<Raw>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream.write_all(head).await?;
    stream.write_all(payload).await?;
    stream.flush().await?;
    let mut raw = Vec::new();
    let mut header_end = None;
    let mut chunked = false;
    let mut chunk = [0u8; 8192];
    loop {
        match stream.read(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => {
                if let Some(end) = header_end {
                    ensure_response_wire_size(
                        raw.len().saturating_sub(end).saturating_add(n),
                        cap,
                        chunked,
                    )?;
                    raw.extend_from_slice(&chunk[..n]);
                    continue;
                }

                raw.extend_from_slice(&chunk[..n]);
                match raw.windows(4).position(|w| w == b"\r\n\r\n") {
                    Some(pos) => {
                        let end = pos + 4;
                        ensure_response_header_size(end)?;
                        let head = std::str::from_utf8(&raw[..end - 4])
                            .context("HTTP response headers are not UTF-8")?;
                        let (is_chunked, content_length) = response_framing(head)?;
                        if let Some(len) = content_length {
                            ensure_buffered_body_size(len, cap)?;
                        }
                        chunked = is_chunked;
                        ensure_response_wire_size(raw.len() - end, cap, chunked)?;
                        header_end = Some(end);
                    }
                    None => ensure_response_header_size(raw.len())?,
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof && !raw.is_empty() => break,
            Err(e) => return Err(e).context("reading HTTP response"),
        }
    }
    parse_raw_capped(&raw, cap)
}

/// Give byte responses the same ordinary exchange deadline as JSON calls.
/// The larger body ceiling is a size distinction, not permission for a peer
/// to stall a publish or pull indefinitely.
async fn exchange_raw_within<S>(
    stream: S,
    head: &[u8],
    payload: &[u8],
    authority: &str,
) -> anyhow::Result<Raw>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let operation = async {
        exchange_raw(stream, head, payload)
            .await
            .with_context(|| format!("HTTP request to {authority} failed"))
    };
    within_phase(
        "HTTP response",
        REQUEST_RESPONSE_TIMEOUT,
        Box::pin(operation),
    )
    .await
}

/// GET with a JSON BODY — `GET /v1/api-keys` is the one route shaped this
/// way (the operator credential travels in the body, docs/API.md §7.2), and
/// hub relays methods it does not interpret, so the shape survives the proxy.
pub async fn get_json_body_trust(
    base_url: &str,
    path: &str,
    body: &serde_json::Value,
    trust: &TlsTrust,
) -> anyhow::Result<Response> {
    send_json(base_url, "GET", path, Some(body), None, None, trust).await
}

async fn send_json(
    base_url: &str,
    method: &str,
    path: &str,
    body: Option<&serde_json::Value>,
    bearer: Option<&str>,
    idempotency_key: Option<&str>,
    trust: &TlsTrust,
) -> anyhow::Result<Response> {
    let payload = match body {
        Some(body) => serde_json::to_vec(body).context("request body serialization")?,
        None => Vec::new(),
    };
    send_payload_keyed(
        base_url,
        method,
        path,
        &payload,
        bearer,
        idempotency_key,
        "application/json",
        trust,
    )
    .await
}

async fn send_payload(
    base_url: &str,
    method: &str,
    path: &str,
    payload: &[u8],
    bearer: Option<&str>,
    content_type: &str,
    trust: &TlsTrust,
) -> anyhow::Result<Response> {
    send_payload_keyed(
        base_url,
        method,
        path,
        payload,
        bearer,
        None,
        content_type,
        trust,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn send_payload_keyed(
    base_url: &str,
    method: &str,
    path: &str,
    payload: &[u8],
    bearer: Option<&str>,
    idempotency_key: Option<&str>,
    content_type: &str,
    trust: &TlsTrust,
) -> anyhow::Result<Response> {
    let endpoint = parse_url(base_url)?;
    // BEFORE the socket, and before the credential is formatted into bytes.
    endpoint.ensure_confidential()?;
    let request = request_head_with_type(
        &endpoint,
        method,
        path,
        bearer,
        idempotency_key,
        payload.len(),
        content_type,
    )?;

    let tcp = connect_tcp(&endpoint).await?;
    match endpoint.scheme {
        Scheme::Plaintext => {
            exchange_within(tcp, request.as_bytes(), payload, &endpoint.authority()).await
        }
        Scheme::Tls => {
            let tls = connect_tls(tcp, &endpoint, trust).await?;
            exchange_within(tls, request.as_bytes(), payload, &endpoint.authority()).await
        }
    }
}

/// TCP connect under an explicit budget. The kernel's default SYN retry
/// schedule is measured in minutes, which is not a useful CLI failure mode.
async fn connect_tcp(endpoint: &Endpoint) -> anyhow::Result<TcpStream> {
    // Box before entering the generic timeout wrapper so this concrete I/O
    // future is pointer-sized in `within_phase`'s debug state.
    within_phase(
        "TCP connect",
        CONNECT_TIMEOUT,
        Box::pin(async {
            TcpStream::connect((endpoint.host.as_str(), endpoint.port))
                .await
                .with_context(|| format!("connecting to {}", endpoint.authority()))
        }),
    )
    .await
}

/// Apply one transport phase's deadline without putting peer-controlled
/// values in its timeout diagnostic. The ordinary I/O error still carries
/// the authority where it is useful; the deadline says only which phase
/// stalled, so it cannot accidentally echo a credential-bearing URL.
async fn within_phase<T, F>(
    phase: &'static str,
    within: Duration,
    operation: F,
) -> anyhow::Result<T>
where
    F: Future<Output = anyhow::Result<T>>,
{
    match tokio::time::timeout(within, operation).await {
        Ok(result) => result,
        Err(_) => anyhow::bail!(
            "control-plane {phase} timed out after {} seconds",
            within.as_secs()
        ),
    }
}

/// TLS setup has its own phase budget, separate from TCP and the response.
async fn connect_tls(
    tcp: TcpStream,
    endpoint: &Endpoint,
    trust: &TlsTrust,
) -> anyhow::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let config = trust.client_config(&[HTTP_1_1_ALPN])?;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    // An IP literal becomes ServerName::IpAddress and is checked against the
    // certificate's IP SANs; a name is checked as a name.
    let server_name =
        rustls::pki_types::ServerName::try_from(endpoint.host.clone()).with_context(|| {
            format!(
                "{:?} is not a name or address a certificate can be verified against",
                endpoint.host
            )
        })?;
    within_phase(
        "TLS handshake",
        TLS_HANDSHAKE_TIMEOUT,
        Box::pin(async {
            connector.connect(server_name, tcp).await.with_context(|| {
                format!(
                    "TLS handshake with {} failed (trusting {})",
                    endpoint.authority(),
                    trust.describe()
                )
            })
        }),
    )
    .await
}

/// Build the request head. Split out so the credential-handling rule (no line
/// breaks, ever) is one place and testable without a socket.
fn request_head(
    endpoint: &Endpoint,
    method: &str,
    path: &str,
    bearer: Option<&str>,
    content_length: usize,
) -> anyhow::Result<String> {
    request_head_with_type(
        endpoint,
        method,
        path,
        bearer,
        None,
        content_length,
        "application/json",
    )
}

#[allow(clippy::too_many_arguments)]
fn request_head_with_type(
    endpoint: &Endpoint,
    method: &str,
    path: &str,
    bearer: Option<&str>,
    idempotency_key: Option<&str>,
    content_length: usize,
    content_type: &str,
) -> anyhow::Result<String> {
    anyhow::ensure!(
        !content_type.contains(['\r', '\n']),
        "content type contains a line break"
    );
    // Same rule as the credential: a value with a line break in it would
    // inject a header, so it is refused rather than escaped.
    let idempotency = match idempotency_key {
        Some(key) => {
            anyhow::ensure!(
                !key.contains(['\r', '\n']),
                "idempotency key contains a line break"
            );
            format!("Idempotency-Key: {key}\r\n")
        }
        None => String::new(),
    };
    let authorization = match bearer {
        Some(token) => {
            anyhow::ensure!(
                !token.contains(['\r', '\n']),
                "credential contains a line break (refusing to build a request from it)"
            );
            format!("Authorization: Bearer {token}\r\n")
        }
        None => String::new(),
    };
    Ok(format!(
        "{method} {base}{path} HTTP/1.1\r\n\
         Host: {authority}\r\n\
         Content-Type: {content_type}\r\n\
         {authorization}\
         {idempotency}\
         Content-Length: {content_length}\r\n\
         Connection: close\r\n\r\n",
        base = endpoint.base_path,
        authority = endpoint.authority(),
    ))
}

fn form_component(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(char::from(byte));
            }
            b' ' => encoded.push('+'),
            other => {
                encoded.push('%');
                encoded.push(char::from(HEX[usize::from(other >> 4)]));
                encoded.push(char::from(HEX[usize::from(other & 0x0f)]));
            }
        }
    }
    encoded
}

/// Write the request, read the whole response (we always send
/// `Connection: close`, so EOF delimits it), parse. Generic over the stream so
/// plaintext and TLS are the same code path above the socket.
async fn exchange<S>(mut stream: S, head: &[u8], payload: &[u8]) -> anyhow::Result<Response>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let raw = exchange_raw_capped(&mut stream, head, payload, MAX_RESPONSE_BODY_BYTES).await?;
    response_from_raw(raw)
}

/// Bound the write plus response read for ordinary request/response calls.
/// This wrapper, rather than `exchange` itself, keeps the streaming exec path
/// free to use the command's longer caller-supplied deadline.
async fn exchange_within<S>(
    stream: S,
    head: &[u8],
    payload: &[u8],
    authority: &str,
) -> anyhow::Result<Response>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // `authority` is deliberately used only for immediate I/O errors. Timeout
    // text must name the stalled phase without reflecting a URL-shaped value.
    let operation = async {
        exchange(stream, head, payload)
            .await
            .with_context(|| format!("HTTP request to {authority} failed"))
    };
    within_phase(
        "HTTP response",
        REQUEST_RESPONSE_TIMEOUT,
        Box::pin(operation),
    )
    .await
}

/// Parse a complete HTTP/1.1 response (we always send `Connection: close`,
/// so the peer's EOF delimits it).
pub fn parse_response(raw: &[u8]) -> anyhow::Result<Response> {
    response_from_raw(parse_raw_capped(raw, MAX_RESPONSE_BODY_BYTES)?)
}

fn response_from_raw(raw: Raw) -> anyhow::Result<Response> {
    let body = if raw.body.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&raw.body).context("response body is not JSON")?
    };
    Ok(Response {
        status: raw.status,
        body,
    })
}

/// The same parse, stopping one step short of the JSON. Everything about
/// framing — `Content-Length`, `chunked`, EOF — lives here once.
pub fn parse_raw(raw: &[u8]) -> anyhow::Result<Raw> {
    parse_raw_capped(raw, MAX_RAW_RESPONSE_BYTES)
}

fn parse_raw_capped(raw: &[u8], body_limit: usize) -> anyhow::Result<Raw> {
    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|pos| pos + 4)
        .context("malformed HTTP response: no header terminator")?;
    ensure_response_header_size(header_end)?;
    let head = std::str::from_utf8(&raw[..header_end - 4])
        .context("HTTP response headers are not UTF-8")?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().context("empty HTTP response")?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .with_context(|| format!("malformed status line {status_line:?}"))?;

    let mut content_type: Option<String> = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-type") {
            content_type = Some(value.to_owned());
        }
    }
    let (chunked, content_length) = response_framing(head)?;

    let rest = &raw[header_end..];
    ensure_response_wire_size(rest.len(), body_limit, chunked)?;
    let body: Vec<u8> = if chunked {
        decode_chunked(rest, body_limit)?
    } else if let Some(len) = content_length {
        ensure_buffered_body_size(len, body_limit)?;
        anyhow::ensure!(rest.len() >= len, "truncated HTTP body");
        rest[..len].to_vec()
    } else {
        rest.to_vec() // Connection: close — EOF delimits the body
    };
    Ok(Raw {
        status,
        content_type,
        body,
    })
}

/// Decode a `Transfer-Encoding: chunked` body.
fn decode_chunked(mut rest: &[u8], body_limit: usize) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut framing_bytes = 0usize;
    loop {
        let line_end = rest
            .windows(2)
            .position(|w| w == b"\r\n")
            .context("malformed chunked body: missing size line")?;
        framing_bytes = framing_bytes.saturating_add(line_end + 2);
        ensure_chunk_framing_size(framing_bytes)?;
        let size_line = std::str::from_utf8(&rest[..line_end])
            .context("chunk size line is not UTF-8")?
            .split(';') // chunk extensions are ignored
            .next()
            .unwrap_or("")
            .trim();
        let size = usize::from_str_radix(size_line, 16)
            .with_context(|| format!("bad chunk size {size_line:?}"))?;
        rest = &rest[line_end + 2..];
        if size == 0 {
            let trailer_bytes = if rest.starts_with(b"\r\n") {
                2
            } else {
                rest.windows(4)
                    .position(|w| w == b"\r\n\r\n")
                    .map(|pos| pos + 4)
                    .context("truncated chunked body: incomplete trailer section")?
            };
            framing_bytes = framing_bytes.saturating_add(trailer_bytes);
            ensure_chunk_framing_size(framing_bytes)?;
            anyhow::ensure!(
                rest.len() == trailer_bytes,
                "malformed chunked body: bytes after the terminal chunk"
            );
            return Ok(out);
        }
        // Check the bound before `size + 2` or slicing: a size line holding
        // `usize::MAX` used to overflow here and then panic below.
        ensure_buffered_body_size(out.len().saturating_add(size), body_limit)?;
        let framed_size = size + 2; // safe: `size` is now below the bounded body cap
        anyhow::ensure!(rest.len() >= framed_size, "truncated chunk");
        out.extend_from_slice(&rest[..size]);
        anyhow::ensure!(&rest[size..size + 2] == b"\r\n", "missing chunk terminator");
        framing_bytes = framing_bytes.saturating_add(2);
        ensure_chunk_framing_size(framing_bytes)?;
        rest = &rest[size + 2..];
    }
}

fn response_framing(head: &str) -> anyhow::Result<(bool, Option<usize>)> {
    let mut content_length = None;
    let mut chunked = false;
    let mut transfer_encoding_seen = false;
    for line in head.split("\r\n").skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            let parsed = value
                .parse::<usize>()
                .context("malformed Content-Length response header")?;
            anyhow::ensure!(
                content_length.is_none_or(|prior| prior == parsed),
                "conflicting Content-Length response headers"
            );
            content_length = Some(parsed);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            anyhow::ensure!(
                !transfer_encoding_seen,
                "multiple Transfer-Encoding response headers are unsupported"
            );
            transfer_encoding_seen = true;
            let mut codings = value.split(',').map(str::trim);
            let first = codings.next().unwrap_or("");
            anyhow::ensure!(
                first.eq_ignore_ascii_case("chunked") && codings.next().is_none(),
                "unsupported Transfer-Encoding response header"
            );
            chunked = true;
        }
    }
    anyhow::ensure!(
        !(chunked && content_length.is_some()),
        "ambiguous HTTP response framing: both Transfer-Encoding and Content-Length"
    );
    Ok((chunked, content_length))
}

fn ensure_response_header_size(bytes: usize) -> anyhow::Result<()> {
    anyhow::ensure!(
        bytes <= MAX_RESPONSE_HEADER_BYTES,
        "control-plane HTTP response headers exceed the 64 KiB safety limit \
         ({bytes} bytes > {MAX_RESPONSE_HEADER_BYTES} bytes); refusing to buffer them"
    );
    Ok(())
}

fn ensure_response_body_size(bytes: usize) -> anyhow::Result<()> {
    anyhow::ensure!(
        bytes <= MAX_RESPONSE_BODY_BYTES,
        "control-plane HTTP response body exceeds the 16 MiB safety limit \
         ({bytes} bytes > {MAX_RESPONSE_BODY_BYTES} bytes); refusing to buffer it; \
         the control API must paginate larger responses"
    );
    Ok(())
}

fn ensure_buffered_body_size(bytes: usize, limit: usize) -> anyhow::Result<()> {
    if limit == MAX_RESPONSE_BODY_BYTES {
        return ensure_response_body_size(bytes);
    }
    anyhow::ensure!(
        bytes <= limit,
        "HTTP byte response body exceeds its safety limit \
         ({bytes} bytes > {limit} bytes); refusing to buffer it"
    );
    Ok(())
}

fn ensure_response_wire_size(bytes: usize, body_limit: usize, chunked: bool) -> anyhow::Result<()> {
    if !chunked {
        return ensure_buffered_body_size(bytes, body_limit);
    }
    let wire_limit = body_limit.saturating_add(MAX_RESPONSE_CHUNK_FRAMING_BYTES);
    anyhow::ensure!(
        bytes <= wire_limit,
        "chunked control-plane HTTP response exceeds the combined decoded-body and framing \
         safety limit ({bytes} bytes > {wire_limit} bytes); refusing to buffer it"
    );
    Ok(())
}

fn ensure_chunk_framing_size(bytes: usize) -> anyhow::Result<()> {
    anyhow::ensure!(
        bytes <= MAX_RESPONSE_CHUNK_FRAMING_BYTES,
        "control-plane HTTP chunk framing exceeds the 1 MiB safety limit \
         ({bytes} bytes > {MAX_RESPONSE_CHUNK_FRAMING_BYTES} bytes); refusing to buffer it"
    );
    Ok(())
}

/// POST and consume the response body **line by line as it arrives**.
///
/// ADR-0059's exec surface answers `application/x-ndjson`, and a client that
/// buffered it would break the property the whole chain exists for: the stall
/// has to reach the guest. `exchange` above reads to EOF on purpose (it is
/// answering request/response calls); this one hands each line to `on_line`
/// the moment it completes, so a slow consumer really is slow all the way
/// back to the command's `write()`.
///
/// `on_line` returning `false` stops reading — which drops the connection and
/// is exactly how a caller cancels an exec.
pub async fn post_ndjson_stream<F>(
    base_url: &str,
    path: &str,
    body: &serde_json::Value,
    bearer: Option<&str>,
    trust: &TlsTrust,
    on_line: F,
) -> anyhow::Result<u16>
where
    F: FnMut(&str) -> bool,
{
    let endpoint = parse_url(base_url)?;
    endpoint.ensure_confidential()?;
    let payload = serde_json::to_vec(body).context("request body serialization")?;
    let request = request_head(&endpoint, "POST", path, bearer, payload.len())?;
    let tcp = connect_tcp(&endpoint).await?;
    match endpoint.scheme {
        Scheme::Plaintext => stream_lines(tcp, request.as_bytes(), &payload, on_line).await,
        Scheme::Tls => {
            let tls = connect_tls(tcp, &endpoint, trust).await?;
            stream_lines(tls, request.as_bytes(), &payload, on_line).await
        }
    }
}

/// Write the request, then read headers and stream the body as lines.
/// Returns the HTTP status.
async fn stream_lines<S, F>(
    mut stream: S,
    head: &[u8],
    payload: &[u8],
    mut on_line: F,
) -> anyhow::Result<u16>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnMut(&str) -> bool,
{
    stream.write_all(head).await?;
    stream.write_all(payload).await?;
    stream.flush().await?;

    let mut buf: Vec<u8> = Vec::with_capacity(8192);
    let mut chunk = [0u8; 8192];
    // Headers first, and ONLY the headers: everything after the blank line is
    // body and must not be swallowed by the header read.
    let head_end = loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let end = pos + 4;
            ensure_response_header_size(end)?;
            break end;
        }
        let n = stream.read(&mut chunk).await.context("reading headers")?;
        if n == 0 {
            anyhow::bail!("connection closed before the response headers were complete");
        }
        buf.extend_from_slice(&chunk[..n]);
        if !buf.windows(4).any(|w| w == b"\r\n\r\n") {
            ensure_response_header_size(buf.len())?;
        }
    };
    let headers = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let status: u16 = headers
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .context("no status line in the response")?;
    let (chunked, content_length) = response_framing(&headers)?;

    // THE TRANSFER ENCODING IS DECODED, not guessed at.
    //
    // The first version split the RAW stream on newlines and skipped any
    // "line" that did not start with `{`, on the theory that chunk-size lines
    // are hex and NDJSON objects are not. That works right up until a JSON
    // line spans two chunks — then the chunk header lands in the MIDDLE of
    // it, the reassembled line does not start with `{`, and the output is
    // silently dropped. It passed once and failed on the next run with no
    // change, which is exactly what a boundary-dependent bug looks like.
    //
    // `raw` is the socket buffer; `body` is decoded body bytes; `line` is
    // whatever is left of a partial NDJSON line. Three buffers because there
    // are three layers, and collapsing any two of them is the bug above.
    let mut raw: Vec<u8> = buf[head_end..].to_vec();
    let mut line: Vec<u8> = Vec::new();
    let mut eof = false;
    let mut in_trailers = false;
    let mut content_remaining = if chunked { None } else { content_length };
    // Chunked state: bytes still to read from the current chunk, or `None`
    // when the next thing on the wire is a size line.
    let mut remaining: Option<usize> = None;

    loop {
        let mut body: Vec<u8> = Vec::new();
        if chunked {
            loop {
                if in_trailers {
                    let trailer_end = if raw.starts_with(b"\r\n") {
                        Some(2)
                    } else {
                        raw.windows(4)
                            .position(|w| w == b"\r\n\r\n")
                            .map(|pos| pos + 4)
                    };
                    let Some(end) = trailer_end else {
                        ensure_response_header_size(raw.len())
                            .context("chunk trailers exceed the HTTP framing safety limit")?;
                        break;
                    };
                    ensure_response_header_size(end)
                        .context("chunk trailers exceed the HTTP framing safety limit")?;
                    anyhow::ensure!(
                        raw.len() == end,
                        "malformed chunked body: bytes after the terminal chunk"
                    );
                    raw.drain(..end);
                    eof = true;
                    break;
                }
                match remaining {
                    None => {
                        let Some(pos) = raw.windows(2).position(|w| w == b"\r\n") else {
                            ensure_response_header_size(raw.len())
                                .context("chunk size line exceeds the HTTP framing safety limit")?;
                            break;
                        };
                        let size_line = String::from_utf8_lossy(&raw[..pos]).into_owned();
                        raw.drain(..pos + 2);
                        // A chunk extension (`1a;name=value`) is legal; the
                        // size is everything before the first `;`.
                        let hex = size_line.split(';').next().unwrap_or("").trim();
                        if hex.is_empty() {
                            continue;
                        }
                        let size = usize::from_str_radix(hex, 16)
                            .with_context(|| format!("bad chunk size {hex:?}"))?;
                        if size == 0 {
                            in_trailers = true;
                            continue;
                        }
                        remaining = Some(size);
                    }
                    Some(0) => {
                        if raw.len() < 2 {
                            break;
                        }
                        anyhow::ensure!(&raw[..2] == b"\r\n", "missing chunk terminator");
                        raw.drain(..2);
                        remaining = None;
                    }
                    Some(want) => {
                        let take = want.min(raw.len());
                        body.extend_from_slice(&raw[..take]);
                        raw.drain(..take);
                        if take == want {
                            // The terminator may be split across socket reads.
                            // `Some(0)` validates it before any later bytes can
                            // accumulate behind malformed framing.
                            remaining = Some(0);
                        } else {
                            remaining = Some(want - take);
                            break;
                        }
                    }
                }
            }
        } else {
            if let Some(want) = content_remaining {
                anyhow::ensure!(
                    raw.len() <= want,
                    "HTTP response body exceeds its declared Content-Length"
                );
                let took = raw.len();
                body.append(&mut raw);
                let left = want - took;
                content_remaining = Some(left);
                if left == 0 {
                    eof = true;
                }
            } else {
                body.append(&mut raw);
            }
        }

        line.extend_from_slice(&body);
        while let Some(pos) = line.iter().position(|b| *b == b'\n') {
            ensure_ndjson_line_size(pos)?;
            let one: Vec<u8> = line.drain(..=pos).collect();
            let text = String::from_utf8_lossy(&one[..one.len() - 1]);
            let text = text.trim_end_matches('\r');
            if text.is_empty() {
                continue;
            }
            if !on_line(text) {
                return Ok(status);
            }
        }
        ensure_ndjson_line_size(line.len())?;

        if eof {
            break;
        }
        let n = match stream.read(&mut chunk).await {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => 0,
            Err(e) => return Err(e).context("reading the ndjson body"),
        };
        if n == 0 {
            if chunked {
                let reason = if in_trailers {
                    "incomplete trailer section"
                } else {
                    match remaining {
                        Some(0) => "missing chunk terminator",
                        Some(_) => "chunk ended before its declared size",
                        None => "missing terminal zero chunk",
                    }
                };
                anyhow::bail!("truncated chunked response: {reason}");
            }
            if content_remaining.is_some_and(|left| left != 0) {
                anyhow::bail!("truncated HTTP response body");
            }
            break;
        }
        raw.extend_from_slice(&chunk[..n]);
    }

    // A trailing fragment with no newline is still a line.
    if !line.is_empty() {
        let text = String::from_utf8_lossy(&line).trim_end().to_owned();
        if !text.is_empty() {
            on_line(&text);
        }
    }
    Ok(status)
}

fn ensure_ndjson_line_size(bytes: usize) -> anyhow::Result<()> {
    anyhow::ensure!(
        bytes <= MAX_NDJSON_LINE_BYTES,
        "exec response NDJSON line exceeds the 2 MiB safety limit \
         ({bytes} bytes > {MAX_NDJSON_LINE_BYTES} bytes); refusing to buffer it"
    );
    Ok(())
}

#[cfg(test)]
mod raw_body_tests {
    use super::*;

    /// The bytes-bodied routes intentionally have a larger ceiling than JSON,
    /// but a peer still cannot stream forever into the process.
    #[tokio::test]
    async fn a_response_body_past_the_ceiling_is_refused_instead_of_buffered() {
        let (client, mut server) = tokio::io::duplex(8192);
        let writer = tokio::spawn(async move {
            let head = b"HTTP/1.1 200 OK\r\nContent-Type: application/gzip\r\n\r\n";
            let _ = server.write_all(head).await;
            // More than any cap this test sets, written until the reader stops.
            let block = vec![0u8; 8192];
            for _ in 0..64 {
                if server.write_all(&block).await.is_err() {
                    return;
                }
            }
        });
        let refusal = exchange_raw_capped(client, b"GET / HTTP/1.1\r\n\r\n", &[], 4096)
            .await
            .unwrap_err();
        assert!(
            format!("{refusal:#}").contains("HTTP byte response body exceeds its safety limit"),
            "{refusal:#}"
        );
        writer.abort();
    }

    /// The control: a body under the ceiling still arrives whole.
    #[tokio::test]
    async fn a_response_under_the_ceiling_still_arrives_whole() {
        let (client, mut server) = tokio::io::duplex(8192);
        tokio::spawn(async move {
            let _ = server
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi")
                .await;
        });
        let raw = exchange_raw_capped(client, b"GET / HTTP/1.1\r\n\r\n", &[], 4096)
            .await
            .unwrap();
        assert_eq!(raw.status, 200);
        assert_eq!(raw.body, b"hi");
    }

    #[test]
    fn byte_responses_keep_their_own_body_cap_and_content_type() {
        let wire =
            b"HTTP/1.1 200 OK\r\nContent-Type: application/gzip\r\nContent-Length: 5\r\n\r\nhello";
        let raw = parse_raw_capped(wire, 5).unwrap();
        assert_eq!(raw.content_type.as_deref(), Some("application/gzip"));
        assert_eq!(raw.body, b"hello");

        let err = parse_raw_capped(wire, 4).unwrap_err().to_string();
        assert!(err.contains("5 bytes > 4 bytes"), "{err}");
        const { assert!(MAX_RAW_RESPONSE_BYTES > MAX_RESPONSE_BODY_BYTES) };
    }

    #[tokio::test(start_paused = true)]
    async fn a_stalled_byte_response_has_the_ordinary_exchange_deadline() {
        let (client, mut peer) = tokio::io::duplex(1024);
        let server = tokio::spawn(async move {
            let mut request = [0u8; 1024];
            let _ = peer.read(&mut request).await.unwrap();
            peer.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{")
                .await
                .unwrap();
            assert_eq!(peer.read(&mut request).await.unwrap(), 0);
        });

        let started = tokio::time::Instant::now();
        let err = exchange_raw_within(
            client,
            b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n",
            b"",
            "must-not-appear.example",
        )
        .await
        .unwrap_err()
        .to_string();
        assert_eq!(
            err,
            "control-plane HTTP response timed out after 30 seconds"
        );
        assert!(!err.contains("must-not-appear.example"));
        assert_eq!(
            tokio::time::Instant::now().duration_since(started),
            REQUEST_RESPONSE_TIMEOUT
        );
        server.await.unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_parsing_covers_defaults_and_base_paths() {
        assert_eq!(
            parse_http_url("http://127.0.0.1:7401").unwrap(),
            ("127.0.0.1".to_owned(), 7401, String::new())
        );
        assert_eq!(
            parse_http_url("http://localhost/api/").unwrap(),
            ("localhost".to_owned(), 80, "/api".to_owned())
        );
        assert!(parse_http_url("http://:80").is_err());
        assert!(parse_http_url("http://h:notaport/").is_err());
        assert!(parse_http_url("ftp://h/").is_err());
    }

    /// ADR-0040: the whole reason the control path was unusable from a laptop
    /// was that this parser rejected `https://`.
    #[test]
    fn https_parses_and_defaults_to_443() {
        let e = parse_url("https://m1.reachpad.dev").unwrap();
        assert_eq!(e.scheme, Scheme::Tls);
        assert_eq!(e.host, "m1.reachpad.dev");
        assert_eq!(e.port, 443);
        assert_eq!(e.base_path, "");
        assert!(!e.is_loopback());

        let e = parse_url("https://m1.reachpad.dev:8443/api/").unwrap();
        assert_eq!(e.port, 8443);
        assert_eq!(e.base_path, "/api");

        // Bracketed IPv6, with and without a port.
        let e = parse_url("https://[2001:db8::1]:8443").unwrap();
        assert_eq!(e.host, "2001:db8::1");
        assert_eq!(e.port, 8443);
        let e = parse_url("http://[::1]").unwrap();
        assert_eq!(e.host, "::1");
        assert_eq!(e.port, 80);
        assert!(e.is_loopback());
    }

    /// The fail-closed rule, asserted as an *error message* and not merely as
    /// a failure: a user who hits this must be told where to go.
    #[test]
    fn plaintext_to_a_non_loopback_host_is_refused_with_an_actionable_error() {
        for url in [
            "http://m1.reachpad.dev:7401",
            "http://m1.reachpad.dev",
            "http://51.81.203.66:7401",
            "http://10.0.0.7:7401",
        ] {
            let endpoint = parse_url(url).unwrap();
            let err = endpoint
                .ensure_confidential()
                .expect_err("plaintext to a non-loopback host must be refused")
                .to_string();
            assert!(
                err.contains(&endpoint.host),
                "the refusal must name the host: {err}"
            );
            assert!(
                err.contains(&format!("https://{}", endpoint.host)),
                "the refusal must name the URL to use instead: {err}"
            );
            assert!(err.contains("credential"), "{err}");
        }

        // Loopback plaintext stays legal: that is the hop hub uses to reach
        // controld, and what every in-process test drives.
        for url in [
            "http://127.0.0.1:7401",
            "http://localhost:7401",
            "http://LOCALHOST:7401",
            "http://[::1]:7401",
            "http://127.0.0.2:7401",
        ] {
            parse_url(url).unwrap().ensure_confidential().expect(url);
        }
        // …and TLS anywhere is fine.
        parse_url("https://m1.reachpad.dev")
            .unwrap()
            .ensure_confidential()
            .unwrap();
    }

    /// A name is not trusted just because it resolves to a loopback address
    /// somewhere: only literal loopback addresses and `localhost` count.
    #[test]
    fn a_hostname_does_not_become_loopback_by_resolving_there() {
        let endpoint = parse_url("http://localtest.me:7401").unwrap();
        assert!(!endpoint.is_loopback());
        assert!(endpoint.ensure_confidential().is_err());
    }

    #[test]
    fn a_credential_with_a_line_break_never_becomes_a_request() {
        let endpoint = parse_url("https://m1.reachpad.dev").unwrap();
        assert!(request_head(&endpoint, "POST", "/v1/x", Some("rpop1.aaa\r\nX: y"), 0).is_err());
        let head = request_head(&endpoint, "POST", "/v1/x", Some("rpop1.aaa"), 7).unwrap();
        assert!(head.starts_with("POST /v1/x HTTP/1.1\r\n"));
        assert!(head.contains("Host: m1.reachpad.dev:443\r\n"));
        assert!(head.contains("Authorization: Bearer rpop1.aaa\r\n"));
        assert!(head.contains("Content-Length: 7\r\n"));
    }

    #[test]
    fn oauth_form_encoding_cannot_change_field_boundaries() {
        assert_eq!(form_component("client_abc"), "client_abc");
        assert_eq!(form_component("a b&c=d/é"), "a+b%26c%3Dd%2F%C3%A9");
    }

    #[test]
    fn parses_content_length_response() {
        let raw = b"HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: 13\r\n\r\n{\"ok\":\"yes\"}\n";
        let r = parse_response(raw).unwrap();
        assert_eq!(r.status, 201);
        assert_eq!(r.body["ok"], "yes");
    }

    #[test]
    fn parses_chunked_response() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n7\r\n{\"a\":1,\r\n6\r\n\"b\":2}\r\n0\r\n\r\n";
        let r = parse_response(raw).unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.body["a"], 1);
        assert_eq!(r.body["b"], 2);
    }

    #[test]
    fn chunked_body_limit_is_inclusive_after_transfer_decoding() {
        let json = format!("\"{}\"", "x".repeat(MAX_RESPONSE_BODY_BYTES - 2));
        assert_eq!(json.len(), MAX_RESPONSE_BODY_BYTES);
        let mut raw = format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n",
            json.len()
        )
        .into_bytes();
        raw.extend_from_slice(json.as_bytes());
        raw.extend_from_slice(b"\r\n0\r\n\r\n");

        let response = parse_response(&raw).expect("wire framing must not consume body budget");
        assert_eq!(
            response.body.as_str().unwrap().len(),
            MAX_RESPONSE_BODY_BYTES - 2
        );

        let too_large = MAX_RESPONSE_BODY_BYTES + 1;
        let raw =
            format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{too_large:x}\r\nx");
        let err = parse_response(raw.as_bytes()).unwrap_err().to_string();
        assert!(
            err.contains("body exceeds the 16 MiB safety limit"),
            "{err}"
        );
    }

    #[test]
    fn chunk_framing_has_its_own_bound() {
        let extension = "x".repeat(MAX_RESPONSE_CHUNK_FRAMING_BYTES);
        let raw =
            format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0;{extension}\r\n\r\n");
        let err = parse_response(raw.as_bytes()).unwrap_err().to_string();
        assert!(
            err.contains("chunk framing exceeds the 1 MiB safety limit"),
            "{err}"
        );
    }

    #[test]
    fn parses_eof_delimited_and_empty_bodies() {
        let r = parse_response(b"HTTP/1.1 204 No Content\r\n\r\n").unwrap();
        assert_eq!(r.status, 204);
        assert!(r.body.is_null());

        let r = parse_response(b"HTTP/1.1 200 OK\r\n\r\n{\"x\":true}").unwrap();
        assert_eq!(r.body["x"], true);
    }

    #[test]
    fn rejects_malformed_responses() {
        assert!(parse_response(b"garbage").is_err());
        assert!(parse_response(b"HTTP/1.1 abc\r\n\r\n").is_err());
        // Truncated content-length body.
        assert!(parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\n{}").is_err());
        // Body that is not JSON.
        assert!(parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nxyz").is_err());
        assert!(parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: nope\r\n\r\n{}").is_err());
        assert!(parse_response(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\n{}"
        )
        .is_err());
        assert!(parse_response(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
        )
        .is_err());
        assert!(parse_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n{}").is_err());
    }

    #[test]
    fn oversized_response_bodies_are_refused_for_every_framing_mode() {
        let too_large = MAX_RESPONSE_BODY_BYTES + 1;

        // The limits are inclusive: callers never receive a silently
        // truncated response at the boundary.
        ensure_response_header_size(MAX_RESPONSE_HEADER_BYTES).unwrap();
        ensure_response_body_size(MAX_RESPONSE_BODY_BYTES).unwrap();

        let declared = format!("HTTP/1.1 200 OK\r\nContent-Length: {too_large}\r\n\r\n{{}}");
        let err = parse_response(declared.as_bytes()).unwrap_err().to_string();
        assert!(
            err.contains("body exceeds the 16 MiB safety limit"),
            "{err}"
        );
        assert!(
            err.contains(&format!("> {MAX_RESPONSE_BODY_BYTES} bytes")),
            "{err}"
        );
        assert!(err.contains("must paginate larger responses"), "{err}");

        // `usize::MAX + 2` was the pre-fix overflow/panic at the chunk
        // terminator check. It must be an ordinary, actionable refusal.
        let chunked = format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\nx",
            usize::MAX
        );
        let err = parse_response(chunked.as_bytes()).unwrap_err().to_string();
        assert!(
            err.contains("body exceeds the 16 MiB safety limit"),
            "{err}"
        );

        let prefix = b"HTTP/1.1 200 OK\r\n\r\n";
        let mut eof_delimited = Vec::with_capacity(prefix.len() + too_large);
        eof_delimited.extend_from_slice(prefix);
        eof_delimited.resize(prefix.len() + too_large, b' ');
        let err = parse_response(&eof_delimited).unwrap_err().to_string();
        assert!(
            err.contains("body exceeds the 16 MiB safety limit"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn an_unterminated_oversized_response_header_is_refused_while_reading() {
        let (client, mut peer) = tokio::io::duplex(MAX_RESPONSE_HEADER_BYTES + 8192);
        let server = tokio::spawn(async move {
            let mut request = [0u8; 1024];
            let _ = peer.read(&mut request).await.unwrap();
            let oversized = vec![b'x'; MAX_RESPONSE_HEADER_BYTES + 1];
            peer.write_all(&oversized).await.unwrap();
        });

        let err = exchange(client, b"GET / HTTP/1.1\r\n\r\n", b"")
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("headers exceed the 64 KiB safety limit"),
            "{err}"
        );
        server.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn a_stalled_connect_has_a_phase_specific_deadline() {
        let started = tokio::time::Instant::now();
        let err = within_phase(
            "TCP connect",
            CONNECT_TIMEOUT,
            Box::pin(std::future::pending::<anyhow::Result<()>>()),
        )
        .await
        .unwrap_err()
        .to_string();
        assert_eq!(err, "control-plane TCP connect timed out after 5 seconds");
        assert_eq!(
            tokio::time::Instant::now().duration_since(started),
            CONNECT_TIMEOUT
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_peer_that_stalls_tls_has_a_phase_specific_deadline() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut peer, _) = listener.accept().await.unwrap();
            let mut hello = [0u8; 1024];
            assert!(peer.read(&mut hello).await.unwrap() > 0);
            // Read again instead of replying. The deadline drops the TLS
            // stream, at which point the peer sees EOF and this task exits.
            assert_eq!(peer.read(&mut hello).await.unwrap(), 0);
        });
        let tcp = TcpStream::connect(addr).await.unwrap();
        let endpoint = parse_url(&format!("https://127.0.0.1:{}", addr.port())).unwrap();
        let started = tokio::time::Instant::now();
        let err = connect_tls(tcp, &endpoint, &TlsTrust::default())
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(
            err,
            "control-plane TLS handshake timed out after 10 seconds"
        );
        assert_eq!(
            tokio::time::Instant::now().duration_since(started),
            TLS_HANDSHAKE_TIMEOUT
        );
        server.await.unwrap();
    }

    async fn stalled_response_error(prefix: &'static [u8]) -> String {
        let (client, mut peer) = tokio::io::duplex(1024);
        let server = tokio::spawn(async move {
            let mut request = [0u8; 1024];
            let _ = peer.read(&mut request).await.unwrap();
            peer.write_all(prefix).await.unwrap();
            // Keep the response open. When the deadline drops the client side,
            // this observes EOF and lets the task finish without real time.
            assert_eq!(peer.read(&mut request).await.unwrap(), 0);
        });

        let err = exchange_within(
            client,
            b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n",
            b"",
            "127.0.0.1:7401",
        )
        .await
        .unwrap_err()
        .to_string();
        server.await.unwrap();
        err
    }

    #[tokio::test(start_paused = true)]
    async fn a_stalled_declared_body_has_an_http_response_deadline() {
        let started = tokio::time::Instant::now();
        let err = stalled_response_error(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{").await;
        assert_eq!(
            err,
            "control-plane HTTP response timed out after 30 seconds"
        );
        assert_eq!(
            tokio::time::Instant::now().duration_since(started),
            REQUEST_RESPONSE_TIMEOUT
        );
    }

    #[tokio::test(start_paused = true)]
    async fn an_eof_delimited_response_cannot_wait_forever_for_close() {
        let started = tokio::time::Instant::now();
        let err = stalled_response_error(b"HTTP/1.1 200 OK\r\n\r\n{}").await;
        assert_eq!(
            err,
            "control-plane HTTP response timed out after 30 seconds"
        );
        assert_eq!(
            tokio::time::Instant::now().duration_since(started),
            REQUEST_RESPONSE_TIMEOUT
        );
    }

    async fn scripted_stream(response: Vec<u8>) -> (anyhow::Result<u16>, Vec<String>) {
        let (client, mut peer) = tokio::io::duplex(8192);
        let server = tokio::spawn(async move {
            let mut request = [0u8; 1024];
            let _ = peer.read(&mut request).await.unwrap();
            peer.write_all(&response).await.unwrap();
        });
        let mut lines = Vec::new();
        let result = stream_lines(client, b"GET / HTTP/1.1\r\n\r\n", b"", |line| {
            lines.push(line.to_owned());
            true
        })
        .await;
        server.await.unwrap();
        (result, lines)
    }

    #[tokio::test]
    async fn streaming_exec_rejects_eof_after_exec_end_but_before_the_zero_chunk() {
        let end = b"{\"ev\":\"exec.end\",\"exit_code\":0}\n";
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n",
            end.len()
        )
        .into_bytes();
        response.extend_from_slice(end);
        response.extend_from_slice(b"\r\n");

        let (result, lines) = scripted_stream(response).await;
        assert_eq!(
            lines,
            vec![String::from_utf8(end[..end.len() - 1].to_vec()).unwrap()]
        );
        let err = result.unwrap_err().to_string();
        assert!(err.contains("missing terminal zero chunk"), "{err}");
    }

    #[tokio::test]
    async fn streaming_exec_rejects_eof_mid_chunk_and_in_declared_body() {
        let line = b"{\"ev\":\"exec.end\"}\n";
        let mut chunked = format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n",
            line.len() + 5
        )
        .into_bytes();
        chunked.extend_from_slice(line);
        let (result, lines) = scripted_stream(chunked).await;
        assert_eq!(
            lines.len(),
            1,
            "the terminal event arrived before truncation"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("chunk ended before its declared size"),
            "{err}"
        );

        let mut declared = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
            line.len() + 5
        )
        .into_bytes();
        declared.extend_from_slice(line);
        let (result, lines) = scripted_stream(declared).await;
        assert_eq!(
            lines.len(),
            1,
            "the terminal event arrived before truncation"
        );
        let err = result.unwrap_err().to_string();
        assert!(err.contains("truncated HTTP response body"), "{err}");
    }

    #[tokio::test]
    async fn streaming_exec_requires_the_terminal_chunks_final_crlf() {
        let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n".to_vec();
        let (result, _) = scripted_stream(response).await;
        let err = result.unwrap_err().to_string();
        assert!(err.contains("incomplete trailer section"), "{err}");
    }

    #[tokio::test]
    async fn streaming_exec_bounds_each_buffered_unit_and_rejects_bad_framing() {
        let (client, mut peer) = tokio::io::duplex(8192);
        let server = tokio::spawn(async move {
            let mut request = [0u8; 1024];
            let _ = peer.read(&mut request).await.unwrap();
            let head = b"HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\n\r\n";
            peer.write_all(head).await.unwrap();
            // A stream has no total-body limit, but one unterminated frame is
            // still one allocation and must be bounded.
            let oversized = vec![b'x'; MAX_NDJSON_LINE_BYTES + 1];
            let _ = peer.write_all(&oversized).await;
        });
        let err = stream_lines(client, b"GET / HTTP/1.1\r\n\r\n", b"", |_| true)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("NDJSON line exceeds the 2 MiB safety limit"),
            "{err}"
        );
        server.await.unwrap();

        let (client, mut peer) = tokio::io::duplex(1024);
        let server = tokio::spawn(async move {
            let mut request = [0u8; 1024];
            let _ = peer.read(&mut request).await.unwrap();
            peer.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nxNO")
                .await
                .unwrap();
        });
        let err = stream_lines(client, b"GET / HTTP/1.1\r\n\r\n", b"", |_| true)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("missing chunk terminator"), "{err}");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn post_json_round_trips_against_a_scripted_server() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let mut read = 0;
            // Read until we have the full request (headers + body).
            let body = loop {
                let n = sock.read(&mut buf[read..]).await.unwrap();
                read += n;
                if let Some(pos) = buf[..read].windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = std::str::from_utf8(&buf[..pos]).unwrap().to_owned();
                    let want: usize = head
                        .lines()
                        .find_map(|l| l.strip_prefix("Content-Length: "))
                        .unwrap()
                        .parse()
                        .unwrap();
                    if read >= pos + 4 + want {
                        assert!(head.starts_with("POST /v1/echo HTTP/1.1"));
                        break buf[pos + 4..pos + 4 + want].to_vec();
                    }
                }
            };
            let reply = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            sock.write_all(reply.as_bytes()).await.unwrap();
            sock.write_all(&body).await.unwrap();
        });

        let base = format!("http://{addr}");
        let r = post_json(&base, "/v1/echo", &serde_json::json!({ "hello": "world" }))
            .await
            .unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.body["hello"], "world");
        server.await.unwrap();
    }
}
