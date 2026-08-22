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
    // 15 was SNAPSHOT_DEGRADED: a pause whose disk half sealed and whose
    // memory half did not. Removed 2026-08-20 with memory snapshots — a
    // snapshot has one half now, so "less than what was attempted" is not a
    // state a pause can reach. The registry is append-only and numbers are
    // never renumbered, so 15 is RESERVED rather than reused.

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

    /// One credential decrypted by controld, on either of the two mTLS read
    /// paths (ADR-0078, ADR-0082). Appended 2026-08-14 under §4.2's "agents
    /// MAY add types" rule.
    ///
    /// - `POST /node/v1/creds/resolve` — an `exposed`-class value handed to
    ///   the node that holds the workspace's lease; the summary names the peer
    ///   node and the fencing token.
    /// - `POST /svc/v1/creds/resolve` — a `brokered`-class value handed to an
    ///   enrolled use-point; the summary names the **service identity**, which
    ///   design §5 requires of every decrypt audit event.
    ///
    /// Distinct from [`SECRET_USED`] on purpose. This records a *decrypt*: the
    /// platform reading a value back out of the locker, attributed to the
    /// platform principal, with the peer and the authorization generation in
    /// the summary. `secret.used` records a *use* at the use-point, attributed
    /// to the acting principal — it counts uses, not brokerings (design §6).
    /// Collapsing the two would make "who read this credential" unanswerable,
    /// because the answer has two very different shapes.
    ///
    /// The payload carries the credential id, never the value and never the
    /// owner-chosen name.
    pub const CREDS_RESOLVED: u32 = 19;

    /// A node reported that its guest no longer holds one `exposed`-class
    /// credential it was ordered to drop (ADR-0078, `POST
    /// /node/v1/creds/ack`, design §7 revoke step 3). Appended 2026-08-16
    /// under §4.2's "agents MAY add types" rule.
    ///
    /// This is the event that makes a revocation TRUE rather than merely
    /// ordered. The cut itself is already recorded — `link.changed revoked`
    /// on [`GRANT_CHANGED`] — but a cut row says only that controld stopped
    /// authorizing a value; for the exposed class the value is a file inside
    /// a running guest, and nothing about the cut removes it. The pair is the
    /// audit trail an operator actually needs: "cut at T, gone from the guest
    /// at T+n", or a conspicuous absence of the second half.
    ///
    /// The summary carries the credential id, the peer node, the fencing
    /// token and the generation acked — never the value, and never the
    /// owner-chosen `name`.
    pub const CREDS_REVOKE_ACKED: u32 = 20;

    /// A guest asked for a credential its workspace does not hold, and — on
    /// the same type — the person's answer (ADR-0081, design §7). Appended
    /// 2026-08-16 under §4.2's "agents MAY add types" rule.
    ///
    /// Three summaries, one type: `link.requested`, `link.request_denied`,
    /// `link.request_approved`. Deliberately NOT [`GRANT_CHANGED`] — nothing
    /// about authorization changes when an agent asks, and an ask in the
    /// stream that means "an edge moved" would make the audit trail say
    /// something false. An approval emits BOTH: this type for the answer, and
    /// `GRANT_CHANGED` for the link it created.
    ///
    /// The summary carries the request id and the owner's own name for the
    /// connection — never the agent's prose, which is untrusted text that
    /// every future reader of a log line would render as the system's words.
    pub const LINK_REQUESTED: u32 = 21;

    /// A PORT SHARE on this workspace was created or revoked (ADR-0103, the
    /// port-share PoC). Appended 2026-08-19 under §4.2's "agents MAY add
    /// types" rule.
    ///
    /// Two summaries, one type: `port_share.created` and
    /// `port_share.revoked`. Deliberately NOT [`GRANT_CHANGED`], which means
    /// "an authorization EDGE moved" — a port share authorizes no principal
    /// to act in the workspace and carries no role; it opens one TCP port to
    /// whoever holds a uuid and is signed in. Folding it into `grant.changed`
    /// would make `reach tail` say an edge moved when none did.
    ///
    /// The summary carries the port and the workspace's own facts — **never
    /// the token**, which is the capability itself: an event stream a
    /// collaborator can read must not hand them a live share URL.
    ///
    /// In [`NEVER_THINNED`] for the same reason [`GRANT_CHANGED`] is: "when
    /// was this port opened to the internet, and by whom" is a question an
    /// incident review asks about the distant past, and retention must not be
    /// the reason it has no answer.
    pub const PORT_SHARE_CHANGED: u32 = 22;

    /// Types that are never thinned by retention (§4.2).
    pub const NEVER_THINNED: &[u32] = &[
        SECRET_USED,
        GRANT_CHANGED,
        LEASE_ACQUIRED,
        LEASE_RELEASED,
        PORT_SHARE_CHANGED,
    ];
}

/// Envelope format version written by this build (I11).
pub const EVENT_ENVELOPE_V: u32 = 1;
/// Manifest format version written by this build (I11).
pub const MANIFEST_V: u32 = 1;
