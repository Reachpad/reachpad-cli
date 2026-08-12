//! `reach tail` — a client of hub speaking the FROZEN §6 framing exactly as
//! `bins/hub/src/session.rs` expects, over EITHER transport (ADR-0007
//! WebSocket fallback / ADR-0026 QUIC — see [`crate::transport`]):
//!
//! - first frame: `ClientHello` on ctl (Biscuit + workspace) →
//!   `ServerHello` (non-empty `error` = refused); the negotiated version
//!   and capability set are KEPT and gate client behavior;
//! - the events channel is proposed via `ChannelOpen` on ctl and acked;
//!   over QUIC it then gets its own dedicated stream;
//! - envelopes then stream server→client; unknown channels are skipped,
//!   never fatal (§6);
//! - with the `durable-watermark` capability negotiated, `durable
//!   through seq N` control messages on the events channel surface as
//!   [`TailItem::DurableThrough`] — everything at or below that seq
//!   survives a hub SIGKILL, everything above is live-but-tentative.

use std::collections::BTreeSet;

use anyhow::Context;
use proto::framing::{channel, PROTOCOL_VERSION};
use proto::handshake::{self, ChannelKind, ChannelMap};
use proto::{codec, events, wire};

use crate::transport::ClientTransport;

/// Capability requesting durable watermarks (must match hub's
/// `DURABLE_WATERMARK_CAP`; pinned by `tests/quic_tail.rs`).
pub const DURABLE_WATERMARK_CAP: &str = "durable-watermark";

/// Prefix of the `WsLifecycle::transition` carrying a watermark (client
/// half of hub's contract; pinned by `tests/quic_tail.rs`).
pub const DURABLE_THROUGH_PREFIX: &str = "durable-through:";

/// Server→client capability naming the hub process incarnation.
pub const INCARNATION_CAP_PREFIX: &str = "incarnation=";

/// Read a watermark control message (`durable-through:<N>`).
#[must_use]
pub fn parse_durable_through(transition: &str) -> Option<u64> {
    transition
        .strip_prefix(DURABLE_THROUGH_PREFIX)?
        .parse()
        .ok()
}

/// One pretty-printable event off the live tail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailEvent {
    pub seq: u64,
    pub ts_ms: u64,
    pub principal: String,
    pub type_code: u32,
    pub type_name: &'static str,
    pub summary: String,
}

impl TailEvent {
    pub fn from_wire(event: &wire::Event) -> Self {
        TailEvent {
            seq: event.seq,
            ts_ms: event.ts_ms,
            principal: String::from_utf8_lossy(&event.principal).into_owned(),
            type_code: event.r#type,
            type_name: type_name(event.r#type),
            summary: summarize(event.r#type, &event.payload),
        }
    }
}

impl std::fmt::Display for TailEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "seq={:<6} principal={:<16} type={:<16} {}",
            self.seq, self.principal, self.type_name, self.summary
        )
    }
}

/// Registry name for an event type (append-only registry, §4.2).
pub fn type_name(code: u32) -> &'static str {
    match code {
        events::PTY_OUT => "pty.out",
        events::PTY_IN => "pty.in",
        events::HARNESS_STEP => "harness.step",
        events::FS_DIFF => "fs.diff",
        events::GIT_OP => "git.op",
        events::LEASE_ACQUIRED => "lease.acquired",
        events::LEASE_RELEASED => "lease.released",
        events::SNAPSHOT_SEALED => "snapshot.sealed",
        events::GRANT_CHANGED => "grant.changed",
        events::SECRET_USED => "secret.used",
        events::PRESENCE_JOIN => "presence.join",
        events::PRESENCE_LEAVE => "presence.leave",
        events::WS_LIFECYCLE => "ws.lifecycle",
        events::AUTHZ_DENIED => "authz.denied",
        events::EXEC_RAN => "exec.ran",
        events::NOTIFY => "notify",
        events::PREVIEW => "preview",
        _ => "unknown", // append-only registry: newer peers are fine (§6)
    }
}

/// Short human summary of a typed payload. Decoding failures and unknown
/// types degrade to a byte count — never an error (§6 skip posture).
pub fn summarize(type_code: u32, payload: &[u8]) -> String {
    use prost::Message as _;
    let fallback = || format!("{} payload byte(s)", payload.len());
    match type_code {
        events::PTY_OUT | events::PTY_IN => wire::PtyData::decode(payload)
            .map(|p| format!("pty={} {}B {}", p.pty, p.data.len(), text_preview(&p.data)))
            .unwrap_or_else(|_| fallback()),
        events::HARNESS_STEP => wire::HarnessStep::decode(payload)
            .map(|h| format!("harness={} kind={}", h.harness, h.kind))
            .unwrap_or_else(|_| fallback()),
        events::FS_DIFF => wire::FsDiff::decode(payload)
            .map(|d| format!("path={} {}B", d.path, d.diff.len()))
            .unwrap_or_else(|_| fallback()),
        events::GIT_OP => wire::GitOp::decode(payload)
            .map(|g| format!("op={} ref={}", g.op, g.r#ref))
            .unwrap_or_else(|_| fallback()),
        events::LEASE_ACQUIRED | events::LEASE_RELEASED => wire::LeaseChange::decode(payload)
            .map(|l| {
                format!(
                    "node={} fencing_token={}",
                    String::from_utf8_lossy(&l.node),
                    l.fencing_token
                )
            })
            .unwrap_or_else(|_| fallback()),
        events::SNAPSHOT_SEALED => wire::SnapshotSealed::decode(payload)
            .map(|s| format!("log_seq={} kind={}", s.log_seq, s.kind))
            .unwrap_or_else(|_| fallback()),
        events::GRANT_CHANGED => wire::GrantChanged::decode(payload)
            .map(|g| {
                format!(
                    "grantee={} role={} expires_at_ms={}",
                    String::from_utf8_lossy(&g.principal),
                    g.role,
                    g.expires_at_ms
                )
            })
            .unwrap_or_else(|_| fallback()),
        events::SECRET_USED => wire::SecretUsed::decode(payload)
            .map(|s| format!("credential={} use_point={}", s.credential_id, s.use_point))
            .unwrap_or_else(|_| fallback()),
        // ADR-0064: the payload IS the (redacted) message text — show it,
        // because "42 payload byte(s)" hides exactly the thing an agent sent
        // to be seen.
        events::NOTIFY => format!("notify {}", text_preview(payload)),
        // ADR-0065: a JSON envelope `{name, media, data_b64}`. The bytes stay
        // encoded — a terminal wants the fact and the size, not the image.
        events::PREVIEW => serde_json::from_slice::<serde_json::Value>(payload)
            .ok()
            .and_then(|v| {
                let name = v.get("name")?.as_str()?.to_owned();
                let media = v
                    .get("media")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("?")
                    .to_owned();
                let b64_len = v
                    .get("data_b64")
                    .and_then(serde_json::Value::as_str)
                    .map_or(0, str::len);
                // Base64 length → approximate decoded size; exact enough for
                // a human deciding whether to fetch it.
                Some(format!(
                    "preview name={name} media={media} ~{}B",
                    b64_len / 4 * 3
                ))
            })
            .unwrap_or_else(fallback),
        events::PRESENCE_JOIN | events::PRESENCE_LEAVE => wire::Presence::decode(payload)
            .map(|p| {
                format!(
                    "principal={} display={}",
                    String::from_utf8_lossy(&p.principal),
                    p.display
                )
            })
            .unwrap_or_else(|_| fallback()),
        events::WS_LIFECYCLE | events::AUTHZ_DENIED => wire::WsLifecycle::decode(payload)
            .map(|w| format!("transition={}", w.transition))
            .unwrap_or_else(|_| fallback()),
        _ => fallback(),
    }
}

const PREVIEW_MAX: usize = 48;

/// Printable preview of raw PTY bytes (control chars escaped, truncated).
fn text_preview(data: &[u8]) -> String {
    let text: String = String::from_utf8_lossy(data)
        .chars()
        .flat_map(char::escape_debug)
        .take(PREVIEW_MAX)
        .collect();
    format!("{text:?}")
}

/// One item off the tail: a committed/live event, or the durable watermark
/// advancing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TailItem {
    Event(TailEvent),
    /// Every seq in `1..=N` is in the store (hub's `durable-watermark`
    /// contract). Only arrives when the capability was negotiated.
    DurableThrough(u64),
}

/// Options for [`TailSession::connect_with`].
#[derive(Debug, Clone, Default)]
pub struct TailOptions {
    /// The TLS trust posture for the dial — OS roots by default, explicit
    /// `--hub-ca` anchors, or the pinned dev certificate. The same
    /// [`TlsTrust`] `attach` and the control plane use: one trust decision
    /// per invocation, applied to every connection it opens.
    pub trust: crate::transport::TlsTrust,
}

/// An established tail session: handshake done, events channel open and
/// acked. Constructing one is the readiness signal tests rely on — once
/// `connect` returns, hub is fanning this workspace's events our way.
pub struct TailSession {
    transport: ClientTransport,
    events_channel: u16,
    version: u32,
    capabilities: BTreeSet<String>,
    incarnation: Option<String>,
    watermarks: bool,
    durable_through: Option<u64>,
}

impl TailSession {
    /// Dial hub, run the §6 handshake, open the events channel, await its
    /// ack. Default options (no dev pin).
    pub async fn connect(hub_url: &str, workspace: &str, token: &[u8]) -> anyhow::Result<Self> {
        Self::connect_with(hub_url, workspace, token, TailOptions::default()).await
    }

    /// [`connect`](Self::connect) with explicit [`TailOptions`].
    pub async fn connect_with(
        hub_url: &str,
        workspace: &str,
        token: &[u8],
        options: TailOptions,
    ) -> anyhow::Result<Self> {
        let mut transport = ClientTransport::connect_with(hub_url, &options.trust).await?;

        // 1. ClientHello on ctl (Biscuit + workspace; capability strings the
        //    server does not know are ignored, never fatal — §6).
        let hello = handshake::client_hello(
            PROTOCOL_VERSION,
            PROTOCOL_VERSION,
            ["live-tail", DURABLE_WATERMARK_CAP],
            token.to_vec(),
            workspace.as_bytes().to_vec(),
        );
        transport
            .send_frame(codec::frame_message(channel::CTL, 1, 0, &hello)?)
            .await?;

        // 2. ServerHello — non-empty error = session refused. The
        //    negotiated version and capabilities are KEPT (M0 ignored them;
        //    M1 features arrive as capabilities and must be gated on).
        let first = transport
            .recv_frame()
            .await?
            .context("hub closed the connection during the handshake")?;
        anyhow::ensure!(
            first.channel == channel::CTL,
            "handshake reply arrived on channel {} instead of ctl",
            first.channel
        );
        let server: wire::ServerHello = codec::decode_message(&first)?;
        if !server.error.is_empty() {
            anyhow::bail!("hub refused the session: {}", server.error);
        }
        let capabilities: BTreeSet<String> = server.capabilities.iter().cloned().collect();
        let incarnation = server
            .capabilities
            .iter()
            .find_map(|c| c.strip_prefix(INCARNATION_CAP_PREFIX))
            .map(str::to_owned);
        let watermarks = capabilities.contains(DURABLE_WATERMARK_CAP);

        // 3. Propose the events channel on ctl; wait for its ack.
        let mut channels = ChannelMap::new();
        let (events_channel, open) = channels
            .open(ChannelKind::Events)
            .map_err(|e| anyhow::anyhow!("events channel allocation failed: {e}"))?;
        transport
            .send_frame(codec::frame_message(channel::CTL, 2, first.seq, &open)?)
            .await?;
        loop {
            let frame = transport
                .recv_frame()
                .await?
                .context("hub closed the connection before acking the events channel")?;
            if frame.channel != channel::CTL {
                continue; // nothing can arrive on events before the ack
            }
            let Ok(ack) = codec::decode_message::<wire::ChannelAck>(&frame) else {
                continue; // other ctl traffic: skipped, never fatal (§6)
            };
            if ack.channel == u32::from(events_channel) {
                anyhow::ensure!(
                    ack.accepted,
                    "hub refused the events channel: {}",
                    ack.error
                );
                break;
            }
        }

        // 4. Over QUIC, give the events channel its own stream (ADR-0026;
        //    dispatch stays by frame header, so frames the hub already sent
        //    on ctl are handled identically).
        transport.bind_channel_stream(events_channel).await?;

        Ok(TailSession {
            transport,
            events_channel,
            version: server.version,
            capabilities,
            incarnation,
            watermarks,
            durable_through: None,
        })
    }

    /// The protocol version the hub negotiated.
    #[must_use]
    pub fn version(&self) -> u32 {
        self.version
    }

    /// The capability set echoed in the `ServerHello` (plus the additive
    /// `incarnation=` string).
    #[must_use]
    pub fn capabilities(&self) -> &BTreeSet<String> {
        &self.capabilities
    }

    /// The hub process incarnation, if the hub reported one. A different
    /// id after a reconnect means the live tail died with that process.
    #[must_use]
    pub fn incarnation(&self) -> Option<&str> {
        self.incarnation.as_deref()
    }

    /// Did the hub negotiate `durable-watermark`?
    #[must_use]
    pub fn watermarks(&self) -> bool {
        self.watermarks
    }

    /// Highest `durable through` seq seen so far: everything at or below it
    /// is in the store; `None` until the first watermark arrives.
    #[must_use]
    pub fn durable_through(&self) -> Option<u64> {
        self.durable_through
    }

    /// Next item off the events channel — an event envelope or a durable
    /// watermark; `None` on clean EOF. Frames on unknown channels and
    /// undecodable payloads are skipped (§6).
    pub async fn next_item(&mut self) -> anyhow::Result<Option<TailItem>> {
        loop {
            let Some(frame) = self.transport.recv_frame().await? else {
                return Ok(None);
            };
            if frame.channel != self.events_channel {
                continue;
            }
            // An `Event` starts with a varint field 1, a watermark
            // (`WsLifecycle`) with a length-delimited field 1 — a strict
            // decode cannot mistake one for the other (hub pins this).
            if let Ok(event) = codec::decode_message::<wire::Event>(&frame) {
                return Ok(Some(TailItem::Event(TailEvent::from_wire(&event))));
            }
            if self.watermarks {
                if let Ok(note) = codec::decode_message::<wire::WsLifecycle>(&frame) {
                    if let Some(seq) = parse_durable_through(&note.transition) {
                        self.durable_through = Some(seq);
                        return Ok(Some(TailItem::DurableThrough(seq)));
                    }
                }
            }
            tracing::debug!("undecodable events-channel frame skipped");
        }
    }

    /// Next event envelope, skipping watermarks (which still update
    /// [`durable_through`](Self::durable_through)); `None` on clean EOF.
    pub async fn next_event(&mut self) -> anyhow::Result<Option<TailEvent>> {
        loop {
            match self.next_item().await? {
                None => return Ok(None),
                Some(TailItem::Event(event)) => return Ok(Some(event)),
                Some(TailItem::DurableThrough(_)) => continue,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message as _;

    #[test]
    fn durable_through_parses_and_rejects_noise() {
        assert_eq!(parse_durable_through("durable-through:42"), Some(42));
        assert_eq!(parse_durable_through("durable-through:0"), Some(0));
        assert_eq!(parse_durable_through("attached"), None);
        assert_eq!(parse_durable_through("durable-through:"), None);
        assert_eq!(parse_durable_through("durable-through:x"), None);
    }

    #[test]
    fn type_names_cover_the_registry_and_tolerate_future_types() {
        assert_eq!(type_name(events::PTY_OUT), "pty.out");
        assert_eq!(type_name(events::GRANT_CHANGED), "grant.changed");
        assert_eq!(type_name(events::AUTHZ_DENIED), "authz.denied");
        assert_eq!(type_name(10_000), "unknown");
    }

    #[test]
    fn summaries_decode_typed_payloads_and_degrade_gracefully() {
        let pty = wire::PtyData {
            data: b"ls -la\n".to_vec(),
            pty: 0,
        }
        .encode_to_vec();
        let s = summarize(events::PTY_OUT, &pty);
        assert!(s.contains("pty=0") && s.contains("ls -la"), "{s}");

        let presence = wire::Presence {
            principal: b"p-9".to_vec(),
            display: "viewer".into(),
        }
        .encode_to_vec();
        let s = summarize(events::PRESENCE_JOIN, &presence);
        assert!(s.contains("p-9") && s.contains("viewer"), "{s}");

        // Garbage payloads degrade to a byte count, never an error.
        let s = summarize(events::GRANT_CHANGED, &[0xFF, 0xFF, 0xFF]);
        assert!(s.contains("3 payload byte(s)"), "{s}");
        // Unknown types too.
        let s = summarize(10_000, b"xy");
        assert!(s.contains("2 payload byte(s)"), "{s}");
    }

    #[test]
    fn pty_preview_escapes_control_bytes_and_truncates() {
        let p = text_preview(b"a\x1b[31mred\x07\n");
        assert!(!p.contains('\x1b'), "escape byte leaked: {p}");
        assert!(!p.contains('\x07'), "bell byte leaked: {p}");
        let long = text_preview(&[b'x'; 500]);
        assert!(long.len() < 80, "preview not truncated: {}", long.len());
    }

    #[test]
    fn display_formats_one_line_per_event() {
        let ev = TailEvent {
            seq: 3,
            ts_ms: 1,
            principal: "dev-principal".into(),
            type_code: events::PRESENCE_JOIN,
            type_name: "presence.join",
            summary: "principal=dev-principal display=owner".into(),
        };
        let line = ev.to_string();
        assert!(line.contains("seq=3"), "{line}");
        assert!(line.contains("type=presence.join"), "{line}");
        assert!(!line.contains('\n'));
    }
}
