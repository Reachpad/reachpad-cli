//! Client transports for the frozen §6 frames (ADR-0007 WebSocket fallback,
//! ADR-0026 QUIC): one seam, two backends, identical frames.
//!
//! `--hub` URL schemes:
//! - `ws://` / `wss://` — the WebSocket fallback: every binary message
//!   carries exactly one length-prefixed frame.
//! - `quic://host[:port]` (port defaults to 443) — quinn with ALPN
//!   `reachpad/1`; every stream opens with a 2-byte channel-binding
//!   preamble, the first stream binds `ctl`, and the client may bind a
//!   dedicated stream per channel ([`proto::quic`]). The frame header's
//!   `channel` field stays authoritative for dispatch — frames are handled
//!   the same whichever stream they arrive on.
//!
//! TLS for `quic://`: real hostnames are verified against the platform
//! trust store. `--quic-dev-pin` instead pins the hub's DETERMINISTIC dev
//! certificate ([`dev_pinned_hub_cert`]) by exact DER equality — dev only:
//! that key is derived from a public constant, so the pinned cert
//! authenticates nothing outside a machine you already trust.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use bytes::BytesMut;
use futures::{SinkExt as _, StreamExt as _};
use proto::framing::{channel, Frame};
use proto::quic::{preamble, FrameAccumulator};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// Dev TLS derivation — MUST match `hub::tls::DEV_TLS_DERIVATION` (same
/// shared-derivation pattern as the dev Biscuit root hub shares with
/// controld). `tests/quic_tail.rs` pins the two to byte-identical certs.
pub const DEV_TLS_DERIVATION: &str = "reachpad-dev-hub-tls";

/// DNS name inside the pinned dev cert — MUST match `hub::tls::DEV_TLS_DNS`.
pub const DEV_TLS_DNS: &str = "hub.dev.reachpad.invalid";

/// PKCS#8 v1 prefix for a raw Ed25519 key (RFC 8410).
const ED25519_PKCS8_PREFIX: &[u8] = &[
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

/// Rebuild the hub's deterministic pinned dev certificate (DER). Ed25519
/// signatures are deterministic and every rcgen field an RNG could touch is
/// pinned, so this is byte-identical to what a dev hub serves.
pub fn dev_pinned_hub_cert() -> anyhow::Result<CertificateDer<'static>> {
    let seed = blake3_hash(DEV_TLS_DERIVATION);
    let mut pkcs8 = Vec::with_capacity(ED25519_PKCS8_PREFIX.len() + 32);
    pkcs8.extend_from_slice(ED25519_PKCS8_PREFIX);
    pkcs8.extend_from_slice(&seed);
    let key = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
        &PrivatePkcs8KeyDer::from(pkcs8.as_slice()),
        &rcgen::PKCS_ED25519,
    )
    .map_err(|e| anyhow::anyhow!("derived key rejected by rcgen: {e}"))?;
    let mut params = rcgen::CertificateParams::new(vec![DEV_TLS_DNS.to_owned()])
        .map_err(|e| anyhow::anyhow!("certificate params: {e}"))?;
    params.serial_number = Some(rcgen::SerialNumber::from(vec![0x01]));
    params.not_before = rcgen::date_time_ymd(2026, 1, 1);
    params.not_after = rcgen::date_time_ymd(2036, 1, 1);
    let cert = params
        .self_signed(&key)
        .map_err(|e| anyhow::anyhow!("self-signing failed: {e}"))?;
    Ok(cert.der().clone().into_owned())
}

fn blake3_hash(s: &str) -> [u8; 32] {
    *blake3::hash(s.as_bytes()).as_bytes()
}

/// What a `quic://` dial trusts.
///
/// Three postures, in increasing order of how much you should think about it:
///
/// - **default** — the OS trust store (`rustls-platform-verifier`). Correct
///   against a hub holding a Let's Encrypt PRODUCTION certificate.
/// - **`ca_files`** — trust EXACTLY these PEM anchors and nothing else. This
///   is what a hub on a Let's Encrypt **staging** certificate needs: the
///   staging hierarchy deliberately roots in no OS trust store, so a real
///   client must be told about it explicitly. Narrower than the default, not
///   wider — the OS roots are not added back.
/// - **`dev_pin`** — the deterministic dev certificate, by exact DER equality.
///   Dev only (its key derives from a public constant) and it wins over
///   `ca_files` when both are set.
#[derive(Debug, Clone, Default)]
pub struct TlsTrust {
    pub dev_pin: bool,
    pub ca_files: Vec<std::path::PathBuf>,
}

impl TlsTrust {
    #[must_use]
    pub fn dev_pin(dev_pin: bool) -> Self {
        TlsTrust {
            dev_pin,
            ca_files: Vec::new(),
        }
    }

    /// The rustls client configuration this posture describes, offering
    /// `alpn`.
    ///
    /// One function for both transports (ADR-0040): `quic://` asks for
    /// `reachpad/1`, `https://` asks for `http/1.1`, and neither can end up
    /// with a *different* trust decision than the other — which matters now
    /// that control and data ride the same hostname on the same port.
    /// There is deliberately no posture that disables verification.
    pub fn client_config(&self, alpn: &[&[u8]]) -> anyhow::Result<rustls::ClientConfig> {
        let mut config = if self.dev_pin {
            pinned_dev_config()?
        } else if self.ca_files.is_empty() {
            platform_config()?
        } else {
            explicit_roots_config(&self.ca_files)?
        };
        config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        Ok(config)
    }

    /// Human summary for the "what am I trusting" line a client should print.
    #[must_use]
    pub fn describe(&self) -> String {
        if self.dev_pin {
            "pinned dev certificate (DEV ONLY)".to_owned()
        } else if self.ca_files.is_empty() {
            "the OS trust store".to_owned()
        } else {
            format!(
                "{} explicit CA anchor(s): {}",
                self.ca_files.len(),
                self.ca_files
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }
    }
}

/// A parsed `--hub` URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HubUrl {
    /// `ws://…` / `wss://…`, dialed verbatim by tungstenite.
    Ws(String),
    /// `quic://host[:port]`; port defaults to 443.
    Quic { host: String, port: u16 },
}

impl HubUrl {
    pub fn parse(url: &str) -> anyhow::Result<Self> {
        if url.starts_with("ws://") || url.starts_with("wss://") {
            return Ok(HubUrl::Ws(url.to_owned()));
        }
        let Some(rest) = url.strip_prefix("quic://") else {
            anyhow::bail!("unsupported hub URL scheme in {url:?} (use ws://, wss://, or quic://)");
        };
        let rest = rest.split(['/', '?']).next().unwrap_or(rest);
        anyhow::ensure!(!rest.is_empty(), "empty host in {url:?}");
        // `host:port` with an optional port; bracketed IPv6 supported.
        let (host, port) = match rest.rsplit_once(':') {
            Some((h, p)) if !h.contains(':') || (h.starts_with('[') && h.ends_with(']')) => {
                let port: u16 = p
                    .parse()
                    .map_err(|_| anyhow::anyhow!("invalid port {p:?} in {url:?}"))?;
                (h.trim_start_matches('[').trim_end_matches(']'), port)
            }
            _ => (rest.trim_start_matches('[').trim_end_matches(']'), 443),
        };
        Ok(HubUrl::Quic {
            host: host.to_owned(),
            port,
        })
    }
}

/// One client transport: frozen frames in and out, backend-invisible above
/// this line.
pub enum ClientTransport {
    Ws(Box<WsStream>),
    Quic(QuicClient),
}

impl ClientTransport {
    /// Dial `hub_url`. `quic_dev_pin` selects the pinned dev certificate
    /// instead of platform trust for `quic://` (dev only; no effect on ws).
    pub async fn connect(hub_url: &str, quic_dev_pin: bool) -> anyhow::Result<Self> {
        Self::connect_with(hub_url, &TlsTrust::dev_pin(quic_dev_pin)).await
    }

    /// Dial with an explicit trust posture ([`TlsTrust`]). `ws://`/`wss://`
    /// ignore it: the WebSocket fallback verifies against webpki roots.
    pub async fn connect_with(hub_url: &str, trust: &TlsTrust) -> anyhow::Result<Self> {
        match HubUrl::parse(hub_url)? {
            HubUrl::Ws(url) => {
                let (ws, _) = tokio_tungstenite::connect_async(&url)
                    .await
                    .with_context(|| format!("connecting to hub at {url}"))?;
                Ok(ClientTransport::Ws(Box::new(ws)))
            }
            HubUrl::Quic { host, port } => Ok(ClientTransport::Quic(
                QuicClient::connect(&host, port, trust)
                    .await
                    .with_context(|| format!("connecting to hub at quic://{host}:{port}"))?,
            )),
        }
    }

    pub async fn send_frame(&mut self, frame: Frame) -> anyhow::Result<()> {
        match self {
            ClientTransport::Ws(ws) => {
                let mut buf = BytesMut::new();
                frame.encode_stream(&mut buf);
                ws.send(Message::Binary(buf.to_vec()))
                    .await
                    .context("websocket send failed")
            }
            ClientTransport::Quic(q) => q.send_frame(frame).await,
        }
    }

    /// Next frame from the peer, whatever stream/message carried it;
    /// `None` on clean close.
    pub async fn recv_frame(&mut self) -> anyhow::Result<Option<Frame>> {
        match self {
            ClientTransport::Ws(ws) => {
                while let Some(msg) = ws.next().await {
                    match msg.context("websocket receive failed")? {
                        Message::Binary(data) => return parse_one_frame(&data).map(Some),
                        Message::Close(_) => return Ok(None),
                        _ => {} // text/ping/pong: skipped, never fatal (§6)
                    }
                }
                Ok(None)
            }
            ClientTransport::Quic(q) => q.recv_frame().await,
        }
    }

    /// Bind a dedicated stream to `channel` (§6: pty channels get their own
    /// QUIC streams — no head-of-line blocking with fs). No-op over
    /// WebSocket, which has a single pipe by construction.
    pub async fn bind_channel_stream(&mut self, channel: u16) -> anyhow::Result<()> {
        match self {
            ClientTransport::Ws(_) => Ok(()),
            ClientTransport::Quic(q) => q.bind_channel_stream(channel).await,
        }
    }
}

/// One binary message = exactly one length-prefixed frame (ADR-0007; the
/// same rule hub enforces on its side).
fn parse_one_frame(data: &[u8]) -> anyhow::Result<Frame> {
    let mut buf = BytesMut::from(data);
    let Some(frame) = Frame::decode_stream(&mut buf)? else {
        anyhow::bail!("truncated frame in websocket message");
    };
    anyhow::ensure!(
        buf.is_empty(),
        "websocket message must contain exactly one frame"
    );
    Ok(frame)
}

enum Incoming {
    Frame(Frame),
    CtlEnd(Option<anyhow::Error>),
}

/// The quinn half: mirrors hub's server transport (ADR-0026 mapping).
pub struct QuicClient {
    /// Keeps the UDP socket alive for the life of the connection.
    _endpoint: quinn::Endpoint,
    conn: quinn::Connection,
    frames: mpsc::Receiver<Incoming>,
    frame_tx: mpsc::Sender<Incoming>,
    sends: HashMap<u16, quinn::SendStream>,
    done: bool,
}

/// How long one address may spend handshaking before the next is tried —
/// same rationale as `noded::hubquic::ADDR_HANDSHAKE_TIMEOUT` (report §53.1):
/// an address that black-holes makes quinn retry silently for longer than any
/// user waits, so without a bound the second resolved address is never
/// reached.
const ADDR_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

impl QuicClient {
    async fn connect(host: &str, port: u16, trust: &TlsTrust) -> anyhow::Result<Self> {
        // Every resolved address is tried in order (the fix hubquic.rs::dial
        // carries, mirrored here per this file's header: the two transports
        // stay in step by hand, not by a shared crate).
        let addrs = resolve(host, port).await?;
        let endpoint = quinn::Endpoint::client("[::]:0".parse().expect("valid bind addr"))
            .or_else(|_| quinn::Endpoint::client("0.0.0.0:0".parse().expect("valid bind addr")))
            .context("binding a client UDP socket")?;

        let tls = trust.client_config(&[proto::quic::ALPN])?;
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(tls))
            .map_err(|e| anyhow::anyhow!("rustls config not usable for QUIC: {e}"))?;
        let client_config = quinn::ClientConfig::new(Arc::new(crypto));

        let mut failures = Vec::new();
        let mut connected = None;
        for &addr in &addrs {
            let attempt = endpoint
                .connect_with(client_config.clone(), addr, host)
                .context("starting the QUIC connection");
            match attempt {
                Ok(connecting) => {
                    match tokio::time::timeout(ADDR_HANDSHAKE_TIMEOUT, connecting).await {
                        Ok(Ok(conn)) => {
                            connected = Some(conn);
                            break;
                        }
                        Ok(Err(e)) => failures.push(format!("{addr}: QUIC handshake failed: {e}")),
                        Err(_) => failures.push(format!(
                            "{addr}: no handshake within {ADDR_HANDSHAKE_TIMEOUT:?}"
                        )),
                    }
                }
                Err(e) => failures.push(format!("{addr}: {e:#}")),
            }
        }
        let Some(conn) = connected else {
            anyhow::bail!(
                "{host} unreachable at every resolved address: {}",
                failures.join("; ")
            );
        };

        // First stream binds ctl (ADR-0026): open it and send the preamble
        // before anything else so the hub can accept the session.
        let (mut ctl_send, ctl_recv) = conn.open_bi().await.context("opening the ctl stream")?;
        ctl_send
            .write_all(&preamble(channel::CTL))
            .await
            .context("sending the ctl preamble")?;

        let (frame_tx, frames) = mpsc::channel(256);
        tokio::spawn(read_stream(ctl_recv, frame_tx.clone(), true));

        let mut sends = HashMap::new();
        sends.insert(channel::CTL, ctl_send);
        Ok(QuicClient {
            _endpoint: endpoint,
            conn,
            frames,
            frame_tx,
            sends,
            done: false,
        })
    }

    async fn bind_channel_stream(&mut self, ch: u16) -> anyhow::Result<()> {
        anyhow::ensure!(ch != channel::CTL, "ctl is bound at connect");
        if self.sends.contains_key(&ch) {
            return Ok(());
        }
        let (mut send, recv) = self
            .conn
            .open_bi()
            .await
            .context("opening a channel stream")?;
        send.write_all(&preamble(ch))
            .await
            .context("sending the channel preamble")?;
        tokio::spawn(read_stream(recv, self.frame_tx.clone(), false));
        self.sends.insert(ch, send);
        Ok(())
    }

    async fn send_frame(&mut self, frame: Frame) -> anyhow::Result<()> {
        let mut buf = BytesMut::new();
        frame.encode_stream(&mut buf);
        let ch = frame.channel;
        if ch != channel::CTL && self.sends.contains_key(&ch) {
            let stream = self.sends.get_mut(&ch).expect("checked contains_key");
            match stream.write_all(&buf).await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    tracing::debug!(channel = ch, error = %e, "bound stream dead; falling back to ctl");
                    self.sends.remove(&ch);
                }
            }
        }
        let ctl = self
            .sends
            .get_mut(&channel::CTL)
            .expect("ctl stream lives as long as the client");
        ctl.write_all(&buf)
            .await
            .context("quic send failed on ctl stream")
    }

    async fn recv_frame(&mut self) -> anyhow::Result<Option<Frame>> {
        if self.done {
            return Ok(None);
        }
        match self.frames.recv().await {
            Some(Incoming::Frame(frame)) => Ok(Some(frame)),
            Some(Incoming::CtlEnd(None)) | None => {
                self.done = true;
                Ok(None)
            }
            Some(Incoming::CtlEnd(Some(e))) => {
                self.done = true;
                Err(e)
            }
        }
    }
}

/// Every address the name resolves to, in resolver order (mirror of
/// `noded::hubquic::resolve` — dialing only the first strands any client
/// whose server name resolves an unroutable address first, §53.1).
async fn resolve(host: &str, port: u16) -> anyhow::Result<Vec<SocketAddr>> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .with_context(|| format!("resolving {host}"))?
        .collect();
    anyhow::ensure!(!addrs.is_empty(), "{host} resolved to no addresses");
    Ok(addrs)
}

/// Did the peer close the connection deliberately and without complaint?
///
/// QUIC gives an endpoint one number to say why it closed, and the hub spends
/// it: `0` for a session that ended (`bins/hub/src/quic.rs`), a non-zero
/// `ERR_*` for everything it refuses. `LocallyClosed` is this process closing
/// its own connection — a detach — and is graceful for the same reason.
///
/// Anything else (a timeout, a reset, a transport error, a non-zero code) is
/// still a failure and still says so. A client that called EVERY disconnect
/// graceful would hide the ones worth seeing.
fn is_graceful_close(e: &quinn::ReadError) -> bool {
    match e {
        quinn::ReadError::ConnectionLost(conn) => {
            matches!(
                conn,
                quinn::ConnectionError::ApplicationClosed(close) if close.error_code.into_inner() == 0
            ) || matches!(conn, quinn::ConnectionError::LocallyClosed)
        }
        _ => false,
    }
}

/// Pump one stream through the shared frozen-frame decoder — the mirror of
/// hub's read path: a framing error poisons only its own stream, except on
/// ctl where it ends the session.
async fn read_stream(mut recv: quinn::RecvStream, tx: mpsc::Sender<Incoming>, is_ctl: bool) {
    let mut acc = FrameAccumulator::new();
    let mut chunk = vec![0u8; 64 * 1024];
    let end: Option<anyhow::Error> = 'outer: loop {
        match recv.read(&mut chunk).await {
            Ok(Some(n)) => {
                acc.push(&chunk[..n]);
                loop {
                    match acc.next_frame() {
                        Ok(Some(frame)) => {
                            if tx.send(Incoming::Frame(frame)).await.is_err() {
                                return;
                            }
                        }
                        Ok(None) => break,
                        Err(e) => {
                            let _ = recv.stop(quinn::VarInt::from_u32(1));
                            break 'outer Some(anyhow::anyhow!("framing error: {e}"));
                        }
                    }
                }
            }
            Ok(None) => {
                if acc.buffered() > 0 {
                    break Some(anyhow::anyhow!(
                        "stream ended mid-frame with {} undecoded byte(s)",
                        acc.buffered()
                    ));
                }
                break None;
            }
            // The peer hung up on purpose. `bins/hub/src/quic.rs` ends a
            // finished session with `conn.close(0, b"session ended")`, and a
            // zero application code is the whole vocabulary QUIC has for
            // "nothing went wrong" — every real fault the hub reports carries
            // a non-zero `ERR_*`. Reported as a read failure, that close was
            // the last thing a user saw after typing `exit`:
            //
            //     logout
            //     reachpad: stream read failed: connection lost
            //     $ echo $?
            //     1
            //
            // A clean logout is now a clean end of stream, and the exit code
            // is the 0 the session actually earned.
            Err(e) if is_graceful_close(&e) => break None,
            Err(e) => break Some(anyhow::anyhow!("stream read failed: {e}")),
        }
    };
    match (is_ctl, end) {
        (true, e) => {
            let _ = tx.send(Incoming::CtlEnd(e)).await;
        }
        (false, Some(e)) => {
            tracing::debug!(error = %e, "non-ctl stream closed (contained)");
        }
        (false, None) => {}
    }
}

fn ring_provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Platform trust (OS root store via `rustls-platform-verifier`, the same
/// verifier quinn's default feature uses): the posture for a REAL hub
/// hostname with an ACME certificate.
fn platform_config() -> anyhow::Result<rustls::ClientConfig> {
    use rustls_platform_verifier::BuilderVerifierExt as _;
    let config = rustls::ClientConfig::builder_with_provider(ring_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| anyhow::anyhow!("TLS 1.3 unavailable: {e}"))?
        .with_platform_verifier()
        .map_err(|e| anyhow::anyhow!("platform certificate verifier unavailable: {e}"))?
        .with_no_client_auth();
    Ok(config)
}

/// Trust EXACTLY the given PEM anchors — the posture a Let's Encrypt
/// **staging** hub needs, since the staging hierarchy roots in no OS trust
/// store on purpose. Hostname verification, expiry and the signature chain are
/// all still enforced by the ordinary rustls verifier; only the set of roots
/// differs, and it is narrower than the default rather than wider.
fn explicit_roots_config(ca_files: &[std::path::PathBuf]) -> anyhow::Result<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    let mut added = 0usize;
    for path in ca_files {
        let pem =
            std::fs::read(path).with_context(|| format!("reading CA anchor {}", path.display()))?;
        let mut cursor = std::io::Cursor::new(pem);
        for cert in rustls_pemfile::certs(&mut cursor) {
            let cert = cert.with_context(|| format!("parsing {}", path.display()))?;
            roots
                .add(cert)
                .with_context(|| format!("adding an anchor from {}", path.display()))?;
            added += 1;
        }
    }
    anyhow::ensure!(
        added > 0,
        "no certificate found in {} — refusing to dial with an empty trust store",
        ca_files
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
    let config = rustls::ClientConfig::builder_with_provider(ring_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| anyhow::anyhow!("TLS 1.3 unavailable: {e}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(config)
}

/// Exact-DER pin of the deterministic dev hub certificate (`--quic-dev-pin`).
fn pinned_dev_config() -> anyhow::Result<rustls::ClientConfig> {
    let expected = dev_pinned_hub_cert()?;
    let provider = ring_provider();
    let verifier = Arc::new(PinnedCert {
        expected,
        provider: provider.clone(),
    });
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| anyhow::anyhow!("TLS 1.3 unavailable: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    Ok(config)
}

/// Accepts exactly one certificate: the deterministic dev hub cert, by DER
/// equality. Signatures are still verified against that cert's key, so a
/// connection either speaks to a holder of the (public, dev-only) key or
/// fails loudly.
#[derive(Debug)]
struct PinnedCert {
    expected: CertificateDer<'static>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl rustls::client::danger::ServerCertVerifier for PinnedCert {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if end_entity.as_ref() == self.expected.as_ref() {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "server certificate does not match the pinned dev hub certificate \
                 (is the hub running with REACHPAD_HUB_DNS set?)"
                    .into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        // QUIC is TLS 1.3 only.
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hub_urls_parse() {
        assert_eq!(
            HubUrl::parse("ws://127.0.0.1:7420/ws").unwrap(),
            HubUrl::Ws("ws://127.0.0.1:7420/ws".into())
        );
        assert_eq!(
            HubUrl::parse("wss://hub.example.com/ws").unwrap(),
            HubUrl::Ws("wss://hub.example.com/ws".into())
        );
        assert_eq!(
            HubUrl::parse("quic://hub.example.com").unwrap(),
            HubUrl::Quic {
                host: "hub.example.com".into(),
                port: 443
            }
        );
        assert_eq!(
            HubUrl::parse("quic://127.0.0.1:7443").unwrap(),
            HubUrl::Quic {
                host: "127.0.0.1".into(),
                port: 7443
            }
        );
        assert!(HubUrl::parse("http://x").is_err());
        assert!(HubUrl::parse("quic://").is_err());
        assert!(HubUrl::parse("quic://host:notaport").is_err());
    }

    #[test]
    fn dev_pinned_cert_is_deterministic() {
        let a = dev_pinned_hub_cert().unwrap();
        let b = dev_pinned_hub_cert().unwrap();
        assert_eq!(a.as_ref(), b.as_ref());
        assert!(!a.as_ref().is_empty());
    }
}
