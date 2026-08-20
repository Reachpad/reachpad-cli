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

use std::sync::Arc;

use anyhow::Context;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::transport::TlsTrust;

/// ALPN offered on `https://` control connections: hub's TLS endpoint serves
/// the control plane over HTTP/1.1 (it speaks no h2).
pub const HTTP_1_1_ALPN: &[u8] = b"http/1.1";

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

    let tcp = TcpStream::connect((endpoint.host.as_str(), endpoint.port))
        .await
        .with_context(|| format!("connecting to {}", endpoint.authority()))?;
    match endpoint.scheme {
        Scheme::Plaintext => exchange(tcp, request.as_bytes(), payload).await,
        Scheme::Tls => {
            let config = trust.client_config(&[HTTP_1_1_ALPN])?;
            let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
            // An IP literal becomes ServerName::IpAddress and is checked
            // against the certificate's IP SANs; a name is checked as a name.
            let server_name = rustls::pki_types::ServerName::try_from(endpoint.host.clone())
                .with_context(|| {
                    format!(
                        "{:?} is not a name or address a certificate can be verified against",
                        endpoint.host
                    )
                })?;
            let tls = connector.connect(server_name, tcp).await.with_context(|| {
                format!(
                    "TLS handshake with {} failed (trusting {})",
                    endpoint.authority(),
                    trust.describe()
                )
            })?;
            exchange(tls, request.as_bytes(), payload).await
        }
    }
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
    stream.write_all(head).await?;
    stream.write_all(payload).await?;
    stream.flush().await?;
    let mut raw = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match stream.read(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => raw.extend_from_slice(&chunk[..n]),
            // A peer that drops the connection without a TLS close_notify is
            // common and harmless once a complete response is in hand; only an
            // empty read is a real failure.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof && !raw.is_empty() => break,
            Err(e) => return Err(e).context("reading HTTP response"),
        }
    }
    parse_response(&raw)
}

/// Parse a complete HTTP/1.1 response (we always send `Connection: close`,
/// so the peer's EOF delimits it).
pub fn parse_response(raw: &[u8]) -> anyhow::Result<Response> {
    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .context("malformed HTTP response: no header terminator")?;
    let head =
        std::str::from_utf8(&raw[..header_end]).context("HTTP response headers are not UTF-8")?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().context("empty HTTP response")?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .with_context(|| format!("malformed status line {status_line:?}"))?;

    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            content_length = value.parse().ok();
        } else if name.eq_ignore_ascii_case("transfer-encoding")
            && value.eq_ignore_ascii_case("chunked")
        {
            chunked = true;
        }
    }

    let rest = &raw[header_end + 4..];
    let body: Vec<u8> = if chunked {
        decode_chunked(rest)?
    } else if let Some(len) = content_length {
        anyhow::ensure!(rest.len() >= len, "truncated HTTP body");
        rest[..len].to_vec()
    } else {
        rest.to_vec() // Connection: close — EOF delimits the body
    };

    let body = if body.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&body).context("response body is not JSON")?
    };
    Ok(Response { status, body })
}

/// Decode a `Transfer-Encoding: chunked` body.
fn decode_chunked(mut rest: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line_end = rest
            .windows(2)
            .position(|w| w == b"\r\n")
            .context("malformed chunked body: missing size line")?;
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
            return Ok(out);
        }
        anyhow::ensure!(rest.len() >= size + 2, "truncated chunk");
        out.extend_from_slice(&rest[..size]);
        anyhow::ensure!(&rest[size..size + 2] == b"\r\n", "missing chunk terminator");
        rest = &rest[size + 2..];
    }
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
    let tcp = TcpStream::connect((endpoint.host.as_str(), endpoint.port))
        .await
        .with_context(|| format!("connecting to {}", endpoint.authority()))?;
    match endpoint.scheme {
        Scheme::Plaintext => stream_lines(tcp, request.as_bytes(), &payload, on_line).await,
        Scheme::Tls => {
            let config = trust.client_config(&[HTTP_1_1_ALPN])?;
            let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
            let server_name = rustls::pki_types::ServerName::try_from(endpoint.host.clone())
                .with_context(|| {
                    format!(
                        "{:?} is not a name or address a certificate can be verified against",
                        endpoint.host
                    )
                })?;
            let tls = connector.connect(server_name, tcp).await.with_context(|| {
                format!(
                    "TLS handshake with {} failed (trusting {})",
                    endpoint.authority(),
                    trust.describe()
                )
            })?;
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
            break pos + 4;
        }
        let n = stream.read(&mut chunk).await.context("reading headers")?;
        if n == 0 {
            anyhow::bail!("connection closed before the response headers were complete");
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let headers = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let status: u16 = headers
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .context("no status line in the response")?;
    let chunked = headers
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked");

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
    // Chunked state: bytes still to read from the current chunk, or `None`
    // when the next thing on the wire is a size line.
    let mut remaining: Option<usize> = None;

    loop {
        let mut body: Vec<u8> = Vec::new();
        if chunked {
            loop {
                match remaining {
                    None => {
                        let Some(pos) = raw.windows(2).position(|w| w == b"\r\n") else {
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
                            eof = true;
                            break;
                        }
                        remaining = Some(size);
                    }
                    Some(want) => {
                        let take = want.min(raw.len());
                        body.extend_from_slice(&raw[..take]);
                        raw.drain(..take);
                        if take == want {
                            // Consume the CRLF that closes the chunk, when it
                            // has arrived.
                            if raw.len() >= 2 && &raw[..2] == b"\r\n" {
                                raw.drain(..2);
                                remaining = None;
                            } else {
                                remaining = Some(0);
                                break;
                            }
                        } else {
                            remaining = Some(want - take);
                            break;
                        }
                    }
                }
            }
        } else {
            body.append(&mut raw);
        }

        line.extend_from_slice(&body);
        while let Some(pos) = line.iter().position(|b| *b == b'\n') {
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

        if eof {
            break;
        }
        let n = match stream.read(&mut chunk).await {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => 0,
            Err(e) => return Err(e).context("reading the ndjson body"),
        };
        if n == 0 {
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
