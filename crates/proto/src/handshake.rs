//! §6 capability negotiation over the frozen frames.
//!
//! Versioning rules (INFRA_SPEC.md §6): capability negotiation happens at
//! handshake; unknown channels/types are *skipped, never fatal*. The frozen
//! frame header carries a `u32 version`; which versions a session accepts is
//! decided here, not in [`crate::framing`].
//!
//! - [`client_hello`] builds the wire [`wire::ClientHello`].
//! - [`negotiate`] is the server side: highest common version, capability
//!   intersection (unknown client capabilities are ignored — §6).
//! - [`ChannelMap`] is the per-session channel bookkeeping shared by both
//!   sides: `ctl` is always channel 0; every other channel is proposed via
//!   [`wire::ChannelOpen`] on ctl. Unknown kinds in an incoming open are
//!   skipped ([`OpenOutcome::Skip`]), never fatal.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::RangeInclusive;

use crate::framing::channel;
use crate::wire;

/// Errors for a *malformed* handshake (protocol misuse by the peer).
///
/// A mere lack of version overlap is NOT an error at this layer: per the
/// spec's "never fatal" posture (§6) the server still answers with a
/// [`wire::ServerHello`] whose `error` field is set, so the client learns
/// *why* it was refused. See [`negotiate`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum HandshakeError {
    /// `min_version > max_version` in the ClientHello — not a version
    /// mismatch but a malformed message.
    #[error("client version range inverted: min {min} > max {max}")]
    InvertedClientRange { min: u32, max: u32 },
    /// The server was configured with an empty/inverted supported range.
    #[error("server version range inverted: min {min} > max {max}")]
    InvertedServerRange { min: u32, max: u32 },
}

/// Build a [`wire::ClientHello`] advertising versions `[min, max]` and a
/// capability set. Capabilities are deduplicated and sorted so the wire
/// encoding is canonical (two clients with the same capabilities produce
/// byte-identical hellos).
pub fn client_hello(
    min_version: u32,
    max_version: u32,
    capabilities: impl IntoIterator<Item = impl Into<String>>,
    token: impl Into<Vec<u8>>,
    workspace: impl Into<Vec<u8>>,
) -> wire::ClientHello {
    let caps: BTreeSet<String> = capabilities.into_iter().map(Into::into).collect();
    wire::ClientHello {
        min_version,
        max_version,
        capabilities: caps.into_iter().collect(),
        token: token.into(),
        workspace: workspace.into(),
    }
}

/// Server-side negotiation (§6).
///
/// - **Version**: the highest version in both the server's supported range
///   and the client's `[min_version, max_version]`.
/// - **Capabilities**: the intersection of client and server sets. Client
///   capabilities the server does not know are IGNORED — never fatal (§6).
/// - **No overlap**: returns `Ok` with a [`wire::ServerHello`] whose `error`
///   is set (and `version`/`capabilities` zeroed); the transport should send
///   it and close. Only a *malformed* hello yields [`HandshakeError`].
pub fn negotiate(
    server_supported_versions: RangeInclusive<u32>,
    server_capabilities: &BTreeSet<String>,
    hello: &wire::ClientHello,
) -> Result<wire::ServerHello, HandshakeError> {
    let (smin, smax) = (
        *server_supported_versions.start(),
        *server_supported_versions.end(),
    );
    if smin > smax {
        return Err(HandshakeError::InvertedServerRange {
            min: smin,
            max: smax,
        });
    }
    if hello.min_version > hello.max_version {
        return Err(HandshakeError::InvertedClientRange {
            min: hello.min_version,
            max: hello.max_version,
        });
    }

    // Highest common version, if the ranges intersect at all.
    let lo = smin.max(hello.min_version);
    let hi = smax.min(hello.max_version);
    if lo > hi {
        return Ok(wire::ServerHello {
            version: 0,
            capabilities: Vec::new(),
            error: format!(
                "no common protocol version: server supports {smin}..={smax}, \
                 client offers {}..={}",
                hello.min_version, hello.max_version
            ),
        });
    }

    // Intersection; unknown client capabilities are ignored (§6).
    let caps: Vec<String> = hello
        .capabilities
        .iter()
        .filter(|c| server_capabilities.contains(*c))
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();

    Ok(wire::ServerHello {
        version: hi,
        capabilities: caps,
        error: String::new(),
    })
}

/// The channel kinds defined by §6. The set is extensible by capability
/// negotiation; kinds not in this enum are represented only as wire strings
/// and are skipped by [`ChannelMap::handle_open`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ChannelKind {
    Ctl,
    /// `pty/<n>` — the index is the pty number.
    Pty(u32),
    Events,
    Fs,
    Presence,
    /// `tcp/<port>` — one in-guest TCP connection to `127.0.0.1:<port>`.
    /// The index is the port, so a single kind covers every port; each
    /// connection gets its own channel (see [`ChannelKind::well_known_id`]).
    Tcp(u32),
}

impl ChannelKind {
    /// Parse a wire `(kind, index)` pair. `None` = unknown kind (§6: skip).
    pub fn from_wire(kind: &str, index: u32) -> Option<Self> {
        match kind {
            "ctl" => Some(ChannelKind::Ctl),
            "pty" => Some(ChannelKind::Pty(index)),
            "events" => Some(ChannelKind::Events),
            "fs" => Some(ChannelKind::Fs),
            "presence" => Some(ChannelKind::Presence),
            "tcp" => Some(ChannelKind::Tcp(index)),
            _ => None,
        }
    }

    /// Wire `(kind, index)` pair for this kind.
    pub fn to_wire(self) -> (&'static str, u32) {
        match self {
            ChannelKind::Ctl => ("ctl", 0),
            ChannelKind::Pty(n) => ("pty", n),
            ChannelKind::Events => ("events", 0),
            ChannelKind::Fs => ("fs", 0),
            ChannelKind::Presence => ("presence", 0),
            ChannelKind::Tcp(port) => ("tcp", port),
        }
    }

    /// The well-known channel id this kind conventionally lives on
    /// (see [`crate::framing::channel`]), if it fits in a u16.
    fn well_known_id(self) -> Option<u16> {
        match self {
            ChannelKind::Ctl => Some(channel::CTL),
            ChannelKind::Events => Some(channel::EVENTS),
            ChannelKind::Fs => Some(channel::FS),
            ChannelKind::Presence => Some(channel::PRESENCE),
            ChannelKind::Pty(n) => u16::try_from(u32::from(channel::PTY_BASE).checked_add(n)?).ok(),
            // Deliberately none: a tcp channel is one *connection*, not one
            // port, so N concurrent connections to the same port must each
            // get their own id. `None` sends every open through
            // `alloc_dynamic()` (ids >= DYNAMIC_BASE). Carving a well-known
            // `TCP_BASE + port` range out of `crate::framing::channel` would
            // both collide with `PTY_BASE` and cap the feature at one
            // connection per port.
            ChannelKind::Tcp(_) => None,
        }
    }
}

/// Errors from channel bookkeeping. Note that an *unknown kind* in an
/// incoming [`wire::ChannelOpen`] is NOT an error — it is
/// [`OpenOutcome::Skip`] (§6: unknown channels are skipped, never fatal).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ChannelError {
    #[error("channel {0} is already open")]
    AlreadyOpen(u16),
    #[error("channel id {0} does not fit in the frozen u16 channel field")]
    IdOutOfRange(u32),
    #[error("dynamic channel id space exhausted")]
    Exhausted,
    #[error("channel 0 (ctl) is reserved and always open")]
    CtlReserved,
    #[error("pty index {0} overflows the channel id space")]
    PtyIndexOverflow(u32),
}

/// Result of processing an incoming [`wire::ChannelOpen`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenOutcome {
    /// The channel was registered under this id; ack with `accepted = true`.
    Accepted(u16),
    /// Unknown kind: per §6 the open is skipped — the peer may be newer and
    /// speak kinds we don't know. Ack with `accepted = false`, no error, and
    /// carry on; skipping is never fatal.
    Skip,
}

/// First dynamic channel id. Ids below are reserved for well-known channels
/// (`ctl`, `events`, `fs`, `presence`, `pty/<n>` at `PTY_BASE + n`).
pub const DYNAMIC_BASE: u16 = 0x4000;

/// Per-session channel bookkeeping (§6).
///
/// `ctl` (channel 0) is implicitly open on every session. All other channels
/// are proposed with [`wire::ChannelOpen`] on ctl: use [`ChannelMap::open`]
/// to allocate a local proposal and [`ChannelMap::handle_open`] to process a
/// peer's proposal.
#[derive(Debug, Clone)]
pub struct ChannelMap {
    /// Next id to try for dynamically allocated channels (>= [`DYNAMIC_BASE`]).
    next_dynamic: u16,
    /// id -> kind for every open channel, ctl included.
    channels: BTreeMap<u16, ChannelKind>,
}

impl Default for ChannelMap {
    fn default() -> Self {
        Self::new()
    }
}

impl ChannelMap {
    /// A fresh session: only ctl (channel 0) is open.
    pub fn new() -> Self {
        let mut channels = BTreeMap::new();
        channels.insert(channel::CTL, ChannelKind::Ctl);
        ChannelMap {
            next_dynamic: DYNAMIC_BASE,
            channels,
        }
    }

    /// Open a local channel of `kind`, allocating its id: the well-known id
    /// if free, otherwise the next dynamic id. Returns the id together with
    /// the [`wire::ChannelOpen`] to send on ctl.
    ///
    /// `ChannelKind::Ctl` is rejected — ctl is always open, never negotiated.
    pub fn open(&mut self, kind: ChannelKind) -> Result<(u16, wire::ChannelOpen), ChannelError> {
        if kind == ChannelKind::Ctl {
            return Err(ChannelError::CtlReserved);
        }
        let id = match kind.well_known_id() {
            Some(id) if !self.channels.contains_key(&id) => id,
            Some(_) | None => {
                // For pty, an id that can't be derived at all means the index
                // itself overflows the frozen u16 channel field.
                if let ChannelKind::Pty(n) = kind {
                    if kind.well_known_id().is_none() {
                        return Err(ChannelError::PtyIndexOverflow(n));
                    }
                }
                self.alloc_dynamic()?
            }
        };
        self.channels.insert(id, kind);
        let (kind_str, index) = kind.to_wire();
        Ok((
            id,
            wire::ChannelOpen {
                channel: u32::from(id),
                kind: kind_str.to_owned(),
                index,
            },
        ))
    }

    /// Process an incoming [`wire::ChannelOpen`].
    ///
    /// - Unknown `kind` → `Ok(OpenOutcome::Skip)` — §6: skipped, never fatal.
    /// - Known kind, valid free id → registered, `Ok(OpenOutcome::Accepted)`.
    /// - Id out of u16 range, id 0 (ctl), or id already open → `Err`; the
    ///   caller answers with [`wire::ChannelAck`] `{ accepted: false, error }`.
    pub fn handle_open(&mut self, open: &wire::ChannelOpen) -> Result<OpenOutcome, ChannelError> {
        let Some(kind) = ChannelKind::from_wire(&open.kind, open.index) else {
            return Ok(OpenOutcome::Skip);
        };
        let id =
            u16::try_from(open.channel).map_err(|_| ChannelError::IdOutOfRange(open.channel))?;
        if id == channel::CTL {
            return Err(ChannelError::CtlReserved);
        }
        if self.channels.contains_key(&id) {
            return Err(ChannelError::AlreadyOpen(id));
        }
        self.channels.insert(id, kind);
        Ok(OpenOutcome::Accepted(id))
    }

    /// Build the [`wire::ChannelAck`] for an outcome of [`handle_open`].
    ///
    /// [`handle_open`]: ChannelMap::handle_open
    pub fn ack_for(
        open: &wire::ChannelOpen,
        outcome: &Result<OpenOutcome, ChannelError>,
    ) -> wire::ChannelAck {
        match outcome {
            Ok(OpenOutcome::Accepted(id)) => wire::ChannelAck {
                channel: u32::from(*id),
                accepted: true,
                error: String::new(),
            },
            Ok(OpenOutcome::Skip) => wire::ChannelAck {
                channel: open.channel,
                accepted: false,
                error: String::new(), // skip, not failure (§6)
            },
            Err(e) => wire::ChannelAck {
                channel: open.channel,
                accepted: false,
                error: e.to_string(),
            },
        }
    }

    /// Kind of an open channel, if any.
    pub fn kind(&self, id: u16) -> Option<ChannelKind> {
        self.channels.get(&id).copied()
    }

    /// Close a channel, returning its kind if it was open. Ctl cannot close.
    pub fn close(&mut self, id: u16) -> Result<Option<ChannelKind>, ChannelError> {
        if id == channel::CTL {
            return Err(ChannelError::CtlReserved);
        }
        Ok(self.channels.remove(&id))
    }

    /// Iterate open channels as `(id, kind)`, ascending by id.
    pub fn iter(&self) -> impl Iterator<Item = (u16, ChannelKind)> + '_ {
        self.channels.iter().map(|(id, k)| (*id, *k))
    }

    fn alloc_dynamic(&mut self) -> Result<u16, ChannelError> {
        // Linear scan from next_dynamic; the id space is 16 bits so this
        // terminates quickly even when crowded.
        let start = self.next_dynamic.max(DYNAMIC_BASE);
        let mut id = start;
        loop {
            if !self.channels.contains_key(&id) {
                self.next_dynamic = id.checked_add(1).unwrap_or(DYNAMIC_BASE);
                return Ok(id);
            }
            id = id.checked_add(1).unwrap_or(DYNAMIC_BASE);
            if id == start {
                return Err(ChannelError::Exhausted);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn client_hello_sorts_and_dedups_capabilities() {
        let h = client_hello(1, 2, ["b", "a", "b"], b"tok".to_vec(), b"ws".to_vec());
        assert_eq!(h.capabilities, vec!["a".to_owned(), "b".to_owned()]);
        assert_eq!(h.min_version, 1);
        assert_eq!(h.max_version, 2);
        assert_eq!(h.token, b"tok");
        assert_eq!(h.workspace, b"ws");
    }

    #[test]
    fn negotiate_picks_highest_common_version() {
        let h = client_hello(1, 5, Vec::<String>::new(), vec![], vec![]);
        let s = negotiate(2..=7, &caps(&[]), &h).unwrap();
        assert_eq!(s.version, 5);
        assert!(s.error.is_empty());
    }

    #[test]
    fn negotiate_intersects_capabilities_and_ignores_unknown() {
        // "future-cap" is unknown to the server: ignored, never fatal (§6).
        let h = client_hello(1, 1, ["mosh-echo", "future-cap", "zstd"], vec![], vec![]);
        let s = negotiate(1..=1, &caps(&["zstd", "mosh-echo", "server-only"]), &h).unwrap();
        assert_eq!(
            s.capabilities,
            vec!["mosh-echo".to_owned(), "zstd".to_owned()]
        );
        assert!(s.error.is_empty());
    }

    #[test]
    fn negotiate_no_overlap_sets_error_not_err() {
        let h = client_hello(1, 2, Vec::<String>::new(), vec![], vec![]);
        let s = negotiate(3..=4, &caps(&[]), &h).unwrap();
        assert_eq!(s.version, 0);
        assert!(!s.error.is_empty());
        assert!(s.capabilities.is_empty());
    }

    #[test]
    fn negotiate_rejects_inverted_ranges() {
        let bad = client_hello(5, 1, Vec::<String>::new(), vec![], vec![]);
        assert_eq!(
            negotiate(1..=1, &caps(&[]), &bad).unwrap_err(),
            HandshakeError::InvertedClientRange { min: 5, max: 1 }
        );
        let ok = client_hello(1, 1, Vec::<String>::new(), vec![], vec![]);
        #[allow(clippy::reversed_empty_ranges)]
        let inverted = 4..=3;
        assert_eq!(
            negotiate(inverted, &caps(&[]), &ok).unwrap_err(),
            HandshakeError::InvertedServerRange { min: 4, max: 3 }
        );
    }

    #[test]
    fn channel_map_starts_with_ctl_only() {
        let m = ChannelMap::new();
        assert_eq!(m.kind(0), Some(ChannelKind::Ctl));
        assert_eq!(m.iter().count(), 1);
    }

    #[test]
    fn open_uses_well_known_ids() {
        let mut m = ChannelMap::new();
        let (id_ev, msg) = m.open(ChannelKind::Events).unwrap();
        assert_eq!(id_ev, channel::EVENTS);
        assert_eq!(msg.kind, "events");
        let (id_pty3, msg) = m.open(ChannelKind::Pty(3)).unwrap();
        assert_eq!(id_pty3, channel::PTY_BASE + 3);
        assert_eq!((msg.kind.as_str(), msg.index), ("pty", 3));
    }

    #[test]
    fn open_falls_back_to_dynamic_on_collision() {
        let mut m = ChannelMap::new();
        // Peer already took the well-known events id.
        m.handle_open(&wire::ChannelOpen {
            channel: u32::from(channel::EVENTS),
            kind: "events".into(),
            index: 0,
        })
        .unwrap();
        let (id, _) = m.open(ChannelKind::Events).unwrap();
        assert_eq!(id, DYNAMIC_BASE);
        assert_eq!(m.kind(id), Some(ChannelKind::Events));
    }

    #[test]
    fn open_rejects_ctl_and_pty_overflow() {
        let mut m = ChannelMap::new();
        assert_eq!(
            m.open(ChannelKind::Ctl).unwrap_err(),
            ChannelError::CtlReserved
        );
        assert_eq!(
            m.open(ChannelKind::Pty(u32::MAX)).unwrap_err(),
            ChannelError::PtyIndexOverflow(u32::MAX)
        );
    }

    #[test]
    fn tcp_round_trips_wire() {
        assert_eq!(
            ChannelKind::from_wire("tcp", 3000),
            Some(ChannelKind::Tcp(3000))
        );
        assert_eq!(ChannelKind::Tcp(3000).to_wire(), ("tcp", 3000));
    }

    #[test]
    fn tcp_takes_a_dynamic_id_per_connection() {
        let mut m = ChannelMap::new();
        // Two channels for the SAME port: one preview page opening two
        // parallel HTTP connections must not collide.
        let (first, msg) = m.open(ChannelKind::Tcp(3000)).unwrap();
        assert_eq!(first, DYNAMIC_BASE);
        assert_eq!((msg.kind.as_str(), msg.index), ("tcp", 3000));
        let (second, _) = m.open(ChannelKind::Tcp(3000)).unwrap();
        assert_eq!(second, DYNAMIC_BASE + 1);
        assert_eq!(m.kind(second), Some(ChannelKind::Tcp(3000)));
    }

    #[test]
    fn tcp_open_from_an_old_peer_is_skipped_not_fatal() {
        // A peer that predates the `tcp` kind parses it as unknown. Emulate
        // that side by construction: `from_wire` is the whole vocabulary, so
        // an old peer's answer is exactly the Skip path below.
        let mut m = ChannelMap::new();
        let open = wire::ChannelOpen {
            channel: u32::from(DYNAMIC_BASE),
            kind: "tcp".into(),
            index: 3000,
        };
        // New peer: accepted.
        assert_eq!(
            m.handle_open(&open).unwrap(),
            OpenOutcome::Accepted(DYNAMIC_BASE)
        );
        // Old peer: the kind is not in its vocabulary, so the open is
        // skipped and acked with accepted=false and an EMPTY error, which is
        // how a caller tells "not supported" from "failed".
        let ack = ChannelMap::ack_for(&open, &Ok(OpenOutcome::Skip));
        assert_eq!(ack.channel, u32::from(DYNAMIC_BASE));
        assert!(!ack.accepted);
        assert!(ack.error.is_empty());
    }

    #[test]
    fn handle_open_unknown_kind_is_skip_never_fatal() {
        let mut m = ChannelMap::new();
        let open = wire::ChannelOpen {
            channel: 99,
            kind: "holo-deck".into(),
            index: 0,
        };
        assert_eq!(m.handle_open(&open).unwrap(), OpenOutcome::Skip);
        // Nothing registered; the session continues untouched.
        assert_eq!(m.kind(99), None);
        let ack = ChannelMap::ack_for(&open, &Ok(OpenOutcome::Skip));
        assert!(!ack.accepted);
        assert!(ack.error.is_empty());
    }

    #[test]
    fn handle_open_validates_id() {
        let mut m = ChannelMap::new();
        let bad_range = wire::ChannelOpen {
            channel: 70_000, // > u16::MAX
            kind: "fs".into(),
            index: 0,
        };
        assert_eq!(
            m.handle_open(&bad_range).unwrap_err(),
            ChannelError::IdOutOfRange(70_000)
        );
        let ctl = wire::ChannelOpen {
            channel: 0,
            kind: "fs".into(),
            index: 0,
        };
        assert_eq!(m.handle_open(&ctl).unwrap_err(), ChannelError::CtlReserved);
        let ok = wire::ChannelOpen {
            channel: 2,
            kind: "fs".into(),
            index: 0,
        };
        assert_eq!(m.handle_open(&ok).unwrap(), OpenOutcome::Accepted(2));
        assert_eq!(
            m.handle_open(&ok).unwrap_err(),
            ChannelError::AlreadyOpen(2)
        );
    }

    #[test]
    fn close_and_reopen() {
        let mut m = ChannelMap::new();
        let (id, _) = m.open(ChannelKind::Fs).unwrap();
        assert_eq!(m.close(id).unwrap(), Some(ChannelKind::Fs));
        assert_eq!(m.kind(id), None);
        let (id2, _) = m.open(ChannelKind::Fs).unwrap();
        assert_eq!(id2, id); // well-known id is free again
        assert_eq!(m.close(0).unwrap_err(), ChannelError::CtlReserved);
    }
}
