//! Frozen protocol formats (INFRA_SPEC.md §4.2, §4.3, §6).
//!
//! - [`framing`]: the frozen wire frame.
//! - [`wire`]: prost-generated messages (Event envelope, Manifest, handshake).
//! - [`events`]: the append-only event type registry.
//! - [`handshake`]: §6 capability negotiation + channel bookkeeping.
//! - [`codec`]: typed payloads in frames + event-envelope validation.
//! - [`quic`]: how the frozen frames map onto QUIC streams (ADR-0026) —
//!   additive, the frozen formats above are untouched.

pub mod codec;
pub mod framing;
pub mod handshake;
pub mod quic;

pub mod wire {
    include!(concat!(env!("OUT_DIR"), "/reachpad.v1.rs"));
}

/// Append-only event type registry (§4.2). Numbers are FROZEN once assigned;
/// new types are appended, never renumbered.
pub mod events {
    pub const PTY_OUT: u32 = 1;
    pub const PTY_IN: u32 = 2;
    pub const HARNESS_STEP: u32 = 3;
    pub const FS_DIFF: u32 = 4;
    pub const GIT_OP: u32 = 5;
    pub const LEASE_ACQUIRED: u32 = 6;
    pub const LEASE_RELEASED: u32 = 7;
    pub const SNAPSHOT_SEALED: u32 = 8;
    pub const GRANT_CHANGED: u32 = 9;
    pub const SECRET_USED: u32 = 10;
    pub const PRESENCE_JOIN: u32 = 11;
    pub const PRESENCE_LEAVE: u32 = 12;
    pub const WS_LIFECYCLE: u32 = 13;
    /// An authorization denial the hub enforced and logged (e.g. viewer
    /// `pty.in` dropped at the hub, §5.2/§7.4). Appended for the sim wave.
    pub const AUTHZ_DENIED: u32 = 14;
    /// A snapshot that is LESS than what was attempted — a pause whose disk
    /// half sealed and whose memory half did not (report §30.6).
    ///
    /// Appended 2026-08-06 under §4.2's "agents MAY add types" rule. It
    /// exists because `SNAPSHOT_SEALED{kind: Disk}` cannot distinguish a
    /// pause that never tried to seal memory from one whose memory seal
    /// FAILED, and the difference is the whole of "resumes mid-thought"
    /// having been silently withdrawn from a workspace.
    pub const SNAPSHOT_DEGRADED: u32 = 15;

    /// One command run through the exec surface (ADR-0059 §7), emitted when
    /// the exec ENDS — however it ended, including "the node stopped
    /// streaming", because the attempts that fail are the interesting half of
    /// an audit trail.
    ///
    /// Carries `exec_id`, `argv[0]` and an argument COUNT — **never the
    /// arguments**: arguments carry secrets often enough (`--token=…`) that a
    /// log which records them is a log that leaks them — plus `cwd`,
    /// `exit_code`, `signal`, `duration_ms`, `truncated`, `timed_out`, the
    /// `api_key_id` when one was used, and `caused_resume`.
    ///
    /// `caused_resume` is the deferred-billing hedge: the owner SPLIT
    /// ADR-0059 §12(e), ruling that an exec against a paused workspace
    /// resumes it while leaving the BILLING question undecided. Usage is
    /// reconstructable from this log later (`ts_ms`, a never-empty principal,
    /// and `lease.acquired`/`lease.released`, which `NEVER_THINNED` exempts),
    /// so no metering needs to exist now — but whether a given exec is what
    /// WOKE a workspace is knowable only at the request that found it paused.
    /// One boolean now; a migration otherwise.
    ///
    /// Exec OUTPUT is deliberately not here: it is transport (§4.2), it can be
    /// gigabytes, and the caller is receiving it directly. What is durable is
    /// that the exec happened and how it ended.
    pub const EXEC_RAN: u32 = 16;

    /// A message a guest-side process addressed to whoever watches the
    /// workspace (ADR-0064): payload is redacted UTF-8 text, principal is
    /// whoever asked the guest to send it. Appended under §4.2's "agents MAY
    /// add types" rule. A notification is an EVENT rather than a pty escape
    /// because it must be durable, attributed, and visible to every client
    /// of the workspace API equally, including one with no terminal at all.
    pub const NOTIFY: u32 = 17;

    /// A file a guest-side process chose to SHOW whoever watches the
    /// workspace (ADR-0065): payload is a JSON envelope `{name, media,
    /// data_b64}`, bytes redacted before encoding, 512 KiB ceiling enforced
    /// at the source. A push, deliberately: the requester is already inside
    /// the guest, so showing a file grants no authority reading one would.
    pub const PREVIEW: u32 = 18;

    /// Types that are never thinned by retention (§4.2).
    pub const NEVER_THINNED: &[u32] = &[SECRET_USED, GRANT_CHANGED, LEASE_ACQUIRED, LEASE_RELEASED];
}

/// Envelope format version written by this build (I11).
pub const EVENT_ENVELOPE_V: u32 = 1;
/// Manifest format version written by this build (I11).
pub const MANIFEST_V: u32 = 1;
