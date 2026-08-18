//! authz — Biscuit capability tokens (INFRA_SPEC §7.2, I6).
//!
//! Three token **audiences** live here, and every verifier demands the one it
//! expects (ADR-0021, ADR-0076).
//!
//! **User-facing** ([`mint`], [`mint_harness`], [`attenuate`], [`verify`]).
//! Every workspace operation is authorized by a chain rooted in a grant. The
//! **authority block** (minted only by controld, which holds the root private
//! key) asserts the frozen fact structure of §7.2/§12 — and nothing else:
//!
//! ```datalog
//! principal("<id>"); workspace("<id>"); role("<role>"); exp(<ms>);
//! check if time($t), $t < <ms>;
//! ```
//!
//! **Node-scoped** ([`mint_node_token`], [`verify_node_token`]). A machine
//! credential issued to the one node holding one lease generation:
//!
//! ```datalog
//! audience("node"); node("<node id>"); workspace("<id>");
//! fencing_token(<u64>); exp(<ms>);
//! check if time($t), $t < <ms>;
//! ```
//!
//! **Workspace handles** ([`mint_workspace_handle`], [`verify_workspace_handle`],
//! ADR-0076). The credential a *guest* holds: it names the workspace it runs
//! in, the owner principal everything in that guest acts as, the workspace's
//! `authz_generation` at mint time, and the current VM instance's fencing
//! token:
//!
//! ```datalog
//! audience("guest"); workspace("<id>"); owner_principal("<id>");
//! generation(<u64>); fencing_token(<u64>); exp(<ms>);
//! check if time($t), $t < <ms>;
//! check if op($o),
//!   ["list_links", "spawn", "request_link", "use_credential"].contains($o);
//! ```
//!
//! **The op set is inside the token bytes, so widening it needs a re-mint.**
//! `use_credential` (creds milestone C4) is the fourth op, and every handle
//! minted before it existed carries the three-op literal in its authority
//! block: such a handle is refused for `UseCredential` by its OWN check, even
//! against a verifier that knows the op. That is the allowlist working, and it
//! self-heals — handles live minutes (`controld::edges::HANDLE_TTL_MS`) and the
//! node's refresher re-mints them, so the fleet converges within one TTL of
//! the controld deploy. Pinned by
//! `invariants::g_a_handle_minted_before_use_credential_existed_refuses_it`.
//!
//! A handle authorizes a **positive allowlist** of guest operations
//! ([`GuestOp`]) and nothing else. "Nothing else" is a mechanism, not a prose
//! promise: the op vocabulary is a closed enum matched exhaustively by
//! [`verify_workspace_handle`] (no `_` arm, so a new variant cannot be added
//! without deciding its verdict), *and* the same allowlist is carried as a
//! check in the minted authority block, so a caller that went around the
//! verifier still gets nothing. Lifecycle and destructive operations (archive,
//! release, rewind, cross-workspace exec or fork) are outside the allowlist by
//! construction — they have no [`GuestOp`] to name them.
//!
//! The generation and the fencing token are the freshness half. Neither is
//! trusted by the token holder: a verifier compares them against the rows
//! (`workspaces.authz_generation`, the live lease) and re-mints when they no
//! longer match. Instance binding is what makes a handle resident in an
//! inherited or restored memory image dead on arrival — resume, fork and
//! rewind all rotate the instance's fencing token (the node-fencing pattern,
//! ADR-0006/ADR-0021).
//!
//! A fencing token is deliberately **not** a user-facing fact (§7.2; the
//! amendment proposing it was rejected — ADR-0015). Authorization and fencing
//! have opposite lifecycles: a grant changes rarely and is meant to be
//! attenuated and handed out *offline*, while a fencing token changes on every
//! attach. Embedding one in the other would make every share link carry an
//! epoch that goes stale the moment the owner reattaches, destroying offline
//! attenuation — the exact property §10 picks Biscuit for. Writers that must
//! *prove* a lease generation (nodes) use the node audience instead, which is
//! issued to one node for one generation, is never shared, and is never
//! attenuated.
//!
//! The separation is checked **in every direction, explicitly** — never
//! incidentally: [`verify`] refuses a token carrying any `audience` fact (a
//! node token or a workspace handle is not a workspace capability and
//! authorizes nothing), [`verify_node_token`] refuses anything that does not
//! carry `audience("node")` (a user-facing token, however privileged, proves
//! no lease generation), and [`verify_workspace_handle`] refuses anything that
//! does not carry `audience("guest")` (neither a user token nor a node token
//! is a guest handle). Every refusal happens before the request is authorized
//! at all, so the error names the audience rather than some downstream symptom.
//!
//! Attenuation appends blocks that contain **only checks**, never facts the
//! authorizer trusts. It narrows an existing token's own role and expiry
//! offline; it is *not* how a workspace is shared with another person —
//! appended blocks cannot rebind `principal`, so a share is server-minted for
//! the grantee's own principal instead (ADR-0075, superseding "a share link IS
//! an attenuated token"). In biscuit v2+ datalog semantics, the authorizer's
//! rules and checks only match facts from the authority block and the
//! authorizer itself; facts added by appended blocks are untrusted (invisible
//! to the authorizer and to earlier blocks). Since appended blocks can therefore
//! only ADD constraints, attenuation can only narrow — widening is
//! structurally impossible. The tests in `tests/invariants.rs` pin this.
//! Audience-bearing tokens take no part in it: [`attenuate`] *refuses* them,
//! and [`verify_node_token`] / [`verify_workspace_handle`] each accept a
//! single authority block only.
//!
//! That "appended blocks are checks only" contract is not just documentation:
//! [`verify`] *enforces* it structurally before it evaluates any datalog (see
//! [`check_appended_block_shapes`]). A token that does not conform was not produced by
//! this crate, so it is rejected as [`Error::Denied`] instead of being
//! evaluated — which is what keeps the datalog evaluation budget both small
//! and impossible to trip by accident.
//!
//! Time is never read from a wall clock here (I12): `verify` takes `now_ms`
//! and supplies the `time(<ms>)` fact to the datalog world; expiry facts are
//! integer milliseconds since the Unix epoch.
//!
//! Format versioning (I11): [`TOKEN_SCHEME_VERSION`] names the fact/check
//! layout minted by this crate. The biscuit wire format itself additionally
//! embeds a schema version in every serialized token, enforced on parse by
//! `biscuit-auth` (tokens with an unknown wire version fail to deserialize).

use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;
use std::time::{Duration, Instant};

use biscuit_auth::builder::{BlockBuilder, Fact, Term};
use biscuit_auth::datalog::RunLimits;
use biscuit_auth::error as berror;
use biscuit_auth::{Authorizer, Biscuit, UnverifiedBiscuit};

// ---------------------------------------------------------------------------
// Datalog evaluation budget (fail-fast without spurious denies)
// ---------------------------------------------------------------------------
//
// biscuit's `RunLimits::max_time` is per authorize/query call, and one
// `verify` needs several of them (the request itself, three effective-role
// probes, two authority queries). Two things went wrong historically:
//
// * the 1 ms default is *less* than one honest evaluation costs on a loaded
//   host or in a debug build (measured: ~5 ms per run, unoptimized), so valid
//   tokens were denied at random — fail-fast as a correctness bug;
// * raising it to 500 ms *per call* made the worst case ~3 s of CPU for ONE
//   request, which a validly-signed low-privilege token (an attenuated share
//   link with hostile appended datalog) can force on every verify — fail-slow
//   as a CPU-DoS.
//
// The fix is not a different number, it is bounding the input: with
// the structural gate rejecting everything this crate cannot mint, the
// evaluated world is fixed-shape and tiny — appended blocks may only carry
// checks, and those checks can only join over authority facts, of which there
// is at most one per predicate name. Measured cost of a full `verify` of a
// legitimate two-block chain: ~0.75 ms release, ~29 ms debug (all runs
// together). So one deadline for the whole call, shared by every run, is both
// generous (≈8× the debug cost, for scheduler noise on a loaded CI box) and a
// hard ceiling on what a single request can cost even if some future block
// shape slips past the structural gate.
const DATALOG_BUDGET: Duration = Duration::from_millis(250);

/// Fact ceiling per datalog run. A conforming token's world holds ~35 facts
/// (≤ 12 authority + `time`/`op`/`append_principal` + the 15-entry `role_op`
/// table), so this is 7× headroom and still far below biscuit's 1000 default.
const MAX_DATALOG_FACTS: u64 = 256;

/// Iteration ceiling per datalog run. Conforming tokens contain no rules at
/// all, so evaluation saturates after one iteration.
const MAX_DATALOG_ITERATIONS: u64 = 16;

/// One wall-clock deadline shared by every datalog run of a single [`verify`].
///
/// Reading the clock here is fine under I12: authz is a shell, not a
/// statemachine core, and no *decision* depends on the clock — expiry uses the
/// injected `now_ms`. Exceeding the budget can only deny, never allow.
struct Budget {
    deadline: Instant,
}

impl Budget {
    fn start() -> Self {
        Budget {
            deadline: Instant::now() + DATALOG_BUDGET,
        }
    }

    /// Limits for the next run: whatever is left of the per-verify budget.
    /// A used-up budget yields `max_time: 0`, which biscuit reports as a run
    /// limit, which [`verify`] maps to [`Error::Denied`] — never a pass.
    fn limits(&self) -> RunLimits {
        RunLimits {
            max_facts: MAX_DATALOG_FACTS,
            max_iterations: MAX_DATALOG_ITERATIONS,
            max_time: self.deadline.saturating_duration_since(Instant::now()),
        }
    }
}

// ---------------------------------------------------------------------------
// Structural contract on token shape
// ---------------------------------------------------------------------------

/// Serialized-token ceiling. A minted token is ~250 bytes and each attenuation
/// adds ~130; [`MAX_BLOCKS`] blocks of legitimate datalog cannot approach 8
/// KiB. Checked before parsing, so an absurd token costs nothing.
const MAX_TOKEN_BYTES: usize = 8 * 1024;

/// Block ceiling (authority + 15 attenuations). Checked before signature
/// verification, which is O(blocks) ed25519 verifies.
const MAX_BLOCKS: usize = 16;

/// Per-block datalog source ceiling. `mint_harness` (the largest block this
/// crate emits) prints ~330 bytes; `attenuate` blocks ~100.
const MAX_BLOCK_SOURCE_BYTES: usize = 1024;

/// Statement ceiling for the authority block: 6 facts + 2 checks at the
/// widest today ([`mint_workspace_handle`]; `mint_harness` is 4 + 3), and
/// unescaped quotes in a hostile principal string can split a printed fact
/// into a couple of apparent statements (see [`top_level_statements`]).
const MAX_AUTHORITY_STATEMENTS: usize = 16;

/// Check ceiling for an appended block. `attenuate` emits 2.
const MAX_APPENDED_CHECKS: usize = 8;

/// Symbol-length ceiling for an appended block (see [`symbol_is_inert`]).
const MAX_APPENDED_SYMBOL_BYTES: usize = 128;

/// Enforce the structural contract this crate documents on every
/// attacker-controlled (appended) block, before the token costs anything: this
/// runs on the *unverified* token, so a hostile share link is refused without
/// even paying for its signature chain (O(blocks) ed25519 verifies — ~12 ms
/// per block in a debug build, which is 100× the cost of this gate).
///
/// **Appended blocks contain only checks** — no facts, no rules. That is
/// exactly what [`attenuate`] produces, and it is what makes evaluation cheap:
/// a block's checks trust only `{authority, that block}`, so with no facts of
/// its own a check can only join over authority facts, of which there is one
/// per predicate name. Fat joins, fact explosions and rule-driven fixpoint
/// blowups all become unrepresentable.
///
/// Nothing here is *trusted* — the gate only ever rejects, and the signature
/// chain is still what makes a token acceptable. A non-conforming token is
/// either hostile or from a future scheme version ([`TOKEN_SCHEME_VERSION`]);
/// both are [`Error::Denied`], not evaluated.
fn check_appended_block_shapes(unverified: &UnverifiedBiscuit) -> Result<(), Error> {
    for index in 1..unverified.block_count() {
        let source = unverified
            .print_block_source(index)
            .map_err(|e| Error::Denied(format!("block {index} is unreadable: {e}")))?;
        check_block_source_len(index, &source)?;
        let statements = top_level_statements(&source);
        if statements.len() > MAX_APPENDED_CHECKS {
            return Err(Error::Denied(format!(
                "appended block {index} carries {} statements, limit is {MAX_APPENDED_CHECKS}",
                statements.len()
            )));
        }
        if let Some(offending) = statements.iter().position(|s| !is_check(s)) {
            return Err(Error::Denied(format!(
                "appended block {index} statement {offending} is not a check: appended \
                 blocks may contain only checks, never facts and never rules"
            )));
        }
    }
    Ok(())
}

/// The rest of the structural contract, on the signature-verified token, still
/// before any authorizer is built or any datalog runs.
///
/// * the **authority block** is root-signed and therefore trusted; bounding its
///   shape anyway keeps a compromised mint from handing verifiers unbounded
///   work. It could hand them `role("owner")` just as easily, so this is
///   defence in depth, not a security boundary — which is also why it is
///   checked *after* the signature says the block really is our minter's.
/// * **appended-block symbols must be syntactically inert**
///   ([`symbol_is_inert`]): hand-crafted protobuf can put arbitrary bytes in a
///   block's symbol table, and biscuit prints predicate names verbatim, so
///   without this a fact named `check if x($a), x($b)` would *print* like a
///   check and slip past [`check_appended_block_shapes`]. Symbol tables are
///   only reachable through the verified type, hence the split.
fn check_verified_token_shape(biscuit: &Biscuit) -> Result<(), Error> {
    let authority = biscuit
        .print_block_source(0)
        .map_err(|e| Error::Denied(format!("authority block is unreadable: {e}")))?;
    check_block_source_len(0, &authority)?;
    let statements = top_level_statements(&authority);
    if statements.len() > MAX_AUTHORITY_STATEMENTS {
        return Err(Error::Denied(format!(
            "authority block carries {} statements, limit is {MAX_AUTHORITY_STATEMENTS}",
            statements.len()
        )));
    }

    for index in 1..biscuit.block_count() {
        for symbol in biscuit
            .block_symbols(index)
            .map_err(|e| Error::Denied(format!("block {index} symbols unreadable: {e}")))?
        {
            if !symbol_is_inert(&symbol) {
                return Err(Error::Denied(format!(
                    "appended block {index} carries a symbol that is not syntactically \
                     inert ({} bytes)",
                    symbol.len()
                )));
            }
        }
    }
    Ok(())
}

/// Does the authority block of this (unverified) token declare an `audience`
/// fact — i.e. is it something other than a user-facing token?
///
/// Text-level and best-effort by construction: [`attenuate`] takes no root
/// public key, so it cannot know whether the authority block is genuinely
/// ours. That is fine, because this only ever makes [`attenuate`] *refuse*.
/// The authoritative audience checks are the signature-verified ones in
/// [`verify`], [`verify_node_token`] and [`verify_workspace_handle`].
fn authority_declares_an_audience(unverified: &UnverifiedBiscuit) -> bool {
    unverified
        .print_block_source(0)
        .map(|source| {
            top_level_statements(&source)
                .iter()
                .any(|s| s.starts_with("audience("))
        })
        .unwrap_or(false)
}

fn check_block_source_len(index: usize, source: &str) -> Result<(), Error> {
    if source.len() > MAX_BLOCK_SOURCE_BYTES {
        return Err(Error::Denied(format!(
            "block {index} carries {} bytes of datalog, limit is {MAX_BLOCK_SOURCE_BYTES}",
            source.len()
        )));
    }
    Ok(())
}

/// Split printed block datalog into top-level statements, respecting string
/// literals so that a `;` inside a string is not a statement boundary.
///
/// biscuit's printer does not escape quotes *inside* strings, so a crafted
/// string term containing an odd number of `"` can make this scanner swallow
/// the rest of the block. That can only ever MERGE statements, never split
/// one, and the printer emits facts first, then rules, then checks — so if a
/// block contains any fact or rule, the first statement still starts with it,
/// and [`is_check`] still rejects the block.
fn top_level_statements(source: &str) -> Vec<&str> {
    fn push<'a>(slice: &'a str, out: &mut Vec<&'a str>) {
        let trimmed = slice.trim();
        if !trimmed.is_empty() {
            out.push(trimmed);
        }
    }

    let mut statements = Vec::new();
    let mut in_string = false;
    let mut start = 0usize;
    for (i, c) in source.char_indices() {
        match c {
            '"' => in_string = !in_string,
            ';' if !in_string => {
                push(&source[start..i], &mut statements);
                start = i + c.len_utf8();
            }
            _ => {}
        }
    }
    push(&source[start..], &mut statements);
    statements
}

/// Is this printed statement a check?
///
/// Facts print as `name(terms)` and rules as `name(terms) <- body`; neither
/// can begin with `check` followed by a space unless the predicate *name*
/// itself contains a space, which [`symbol_is_inert`] forbids in appended
/// blocks.
fn is_check(statement: &str) -> bool {
    statement.starts_with("check if") || statement.starts_with("check all")
}

/// A symbol (predicate name, variable name or string literal) from an appended
/// block must be syntactically inert: no whitespace, quotes, parentheses,
/// `$`, `,`, `;` or `<`/`>`. Hand-crafted protobuf can put arbitrary bytes in
/// a block's symbol table, and biscuit's printer emits predicate names
/// verbatim — an inert charset is what stops a fact named
/// `check if x($a), x($b)` from *printing* like a check. Everything
/// [`attenuate`] emits (op names, variable names) is inert.
fn symbol_is_inert(symbol: &str) -> bool {
    symbol.len() <= MAX_APPENDED_SYMBOL_BYTES
        && symbol.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':' | '@' | '/' | '+' | '=')
        })
}

// Downstream crates (hub, controld, gatewayd, reach, …) use these key types
// without depending on biscuit-auth directly.
pub use biscuit_auth::{KeyPair, PrivateKey, PublicKey};

/// Version of the fact/check layout this crate mints and verifies (I11).
///
/// Bump when the datalog scheme changes shape. The biscuit *wire* format
/// carries its own embedded schema version, checked at parse time.
///
/// * v1 — user-facing `principal`/`workspace`/`role`/`exp` + expiry check.
///
/// The node audience (ADR-0021) and the guest audience (ADR-0076) are
/// *separate* token kinds, not changes to the layout above, so neither bumps
/// this. A v2 that added `fencing_token` to the user-facing authority block
/// was implemented and then rejected (ADR-0015); the version returns to 1
/// with it.
pub const TOKEN_SCHEME_VERSION: u32 = 1;

/// Value of the `audience` authority fact in a node-scoped token (ADR-0021).
///
/// User-facing tokens carry no `audience` fact at all — §7.2's fact set is
/// frozen at `principal`/`workspace`/`role`/`exp` — so "has an audience" and
/// "is not a workspace capability" are the same statement, checked in every
/// direction by [`verify`], [`verify_node_token`] and
/// [`verify_workspace_handle`].
const NODE_AUDIENCE: &str = "node";

/// Value of the `audience` authority fact in a workspace handle (ADR-0076):
/// the credential a guest holds. Sibling of [`NODE_AUDIENCE`], and the same
/// bargain — declaring an audience is what makes [`verify`] refuse it for
/// free, so a handle that leaks out of a guest authorizes no workspace
/// capability at any user route.
const GUEST_AUDIENCE: &str = "guest";

/// Domain-separation context for deriving dev/test root keys from a seed.
const ROOT_KEY_CONTEXT: &str = "reachpad.dev 2026-07 authz root key v1";

/// Errors produced by this crate.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Key material was malformed (wrong length, bad hex, …).
    #[error("invalid key material: {0}")]
    InvalidKey(String),
    /// The token failed to parse or its signature chain failed to verify.
    #[error("invalid token: {0}")]
    Token(#[from] berror::Token),
    /// The token parsed and its signatures verified, but authorization was
    /// denied (failed check: expired, wrong workspace, role does not allow
    /// the operation, principal binding violated, …).
    #[error("authorization denied: {0}")]
    Denied(String),
    /// A millisecond timestamp did not fit the datalog integer domain.
    #[error("timestamp out of range for datalog int: {0}")]
    TimeOutOfRange(u64),
    /// A fencing token did not fit the datalog integer domain (datalog ints
    /// are i64; fencing tokens come from a BIGSERIAL, so this cannot happen
    /// for real leases — ADR-0006). Only [`mint_node_token`] can raise it:
    /// user-facing tokens carry no fencing token at all (ADR-0015).
    #[error("fencing token out of range for datalog int: {0}")]
    FencingOutOfRange(u64),
    /// An authorization generation did not fit the datalog integer domain
    /// (same story as [`Error::FencingOutOfRange`]: `authz_generation` is a
    /// BIGINT, so a real workspace cannot reach this). Only
    /// [`mint_workspace_handle`] can raise it.
    #[error("authorization generation out of range for datalog int: {0}")]
    GenerationOutOfRange(u64),
    /// An unknown role string was encountered.
    #[error("unknown role: {0:?}")]
    UnknownRole(String),
    /// A **workspace handle** (ADR-0076) verified and is simply past its
    /// `exp`. Its own variant, and only for handles, because of what a guest
    /// does next: a handle expires every [five minutes]
    /// (`controld::edges::HANDLE_TTL_MS`) by design and the holder's correct
    /// response is *ask the node for a fresh one*, which is a different
    /// action from the one a forged, foreign-audience or wrong-workspace
    /// token calls for. Folded into [`Error::Denied`] — where every other
    /// failed check lives — the two are one 403 and an agent mid-turn
    /// concludes its key is bad and stops (creds milestone C3, WP3.2 risk 1).
    ///
    /// Only reachable **after** the signature chain verifies, so it is no
    /// oracle: a caller who cannot produce a token this fleet minted never
    /// sees it.
    #[error("workspace handle expired at {exp_ms} (now {now_ms})")]
    HandleExpired { exp_ms: u64, now_ms: u64 },
}

/// Roles, ordered `owner > collaborator > viewer` (§7.4). `Harness` is the
/// capability profile of harness tokens (§7.2): append own events and mirror
/// sync only — it is not part of the human role lattice.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Role {
    /// Everything, including grant administration.
    Owner,
    /// Read + write + append own events + mirror sync; no grant admin.
    Collaborator,
    /// Read-only streams.
    Viewer,
    /// Harness principal profile: append own events + mirror sync only.
    Harness,
}

impl Role {
    /// The role's fact value as stored in `role(<value>)`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Role::Owner => "owner",
            Role::Collaborator => "collaborator",
            Role::Viewer => "viewer",
            Role::Harness => "harness",
        }
    }

    /// Operation names this role allows (the `role_op` table the verifier
    /// installs, and the op sets attenuation blocks constrain to).
    pub const fn allowed_ops(self) -> &'static [&'static str] {
        match self {
            Role::Owner => &["read", "write", "admin", "append_own_events", "mirror_sync"],
            Role::Collaborator => &["read", "write", "append_own_events", "mirror_sync"],
            Role::Viewer => &["read"],
            Role::Harness => &["append_own_events", "mirror_sync"],
        }
    }

    const ALL: [Role; 4] = [Role::Owner, Role::Collaborator, Role::Viewer, Role::Harness];
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Role {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        match s {
            "owner" => Ok(Role::Owner),
            "collaborator" => Ok(Role::Collaborator),
            "viewer" => Ok(Role::Viewer),
            "harness" => Ok(Role::Harness),
            other => Err(Error::UnknownRole(other.to_owned())),
        }
    }
}

/// A requested workspace operation, checked by [`verify`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Op {
    /// Read streams / snapshots.
    Read,
    /// Mutate: PTY input, fs writes, run harnesses.
    Write,
    /// Grant administration (share/unshare).
    Admin,
    /// Append events attributed to `principal` to the workspace log. The
    /// verifier enforces that `principal` equals the token's own principal
    /// fact ("own" events, I5) — for every token, not only harness tokens.
    AppendOwnEvents {
        /// The principal the events would be attributed to.
        principal: String,
    },
    /// Sync with the owning user's git mirror.
    MirrorSync,
}

impl Op {
    /// The operation's datalog name, as used in `op(<name>)` / `role_op`.
    pub const fn name(&self) -> &'static str {
        match self {
            Op::Read => "read",
            Op::Write => "write",
            Op::Admin => "admin",
            Op::AppendOwnEvents { .. } => "append_own_events",
            Op::MirrorSync => "mirror_sync",
        }
    }
}

/// An operation a **workspace handle** can request (ADR-0076), checked by
/// [`verify_workspace_handle`].
///
/// Deliberately a *separate* vocabulary from [`Op`], not extra [`Op`]
/// variants: [`Op`]'s names populate the `role_op` table that every
/// user-facing authorizer installs, and [`authorize_verified`]'s effective-role
/// ladder assumes that table's op sets stay strictly nested. Widening it for
/// operations no role should ever have would be a change to every verifier in
/// the fleet to express a restriction. A closed enum verified in one place
/// costs nothing anywhere else.
///
/// The whole enum **is** the allowlist: an operation with no variant here
/// cannot be asked for at all, which is why archive/release/rewind and
/// cross-workspace exec or fork are absent rather than listed as forbidden.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum GuestOp {
    /// List the credential links of the guest's own workspace.
    ListLinks,
    /// Create a child workspace of the guest's own workspace.
    Spawn,
    /// Ask for a credential to be linked into the guest's own workspace
    /// (a request — approval is the account owner's, not the guest's).
    RequestLink,
    /// **Spend** one of the guest's own workspace's brokered credentials
    /// through a use-point (creds milestone C4, design §5).
    ///
    /// The op a guest presents to the LLM/git/derived use-points, which pass
    /// the handle through to controld's `POST /svc/v1/creds/resolve`. It is
    /// the narrowest possible widening of the audience: it names no
    /// credential, authorizes nothing by itself, and the value it eventually
    /// reaches is decided by the `share ∧ link` rows re-read on that request
    /// — the handle is one of three factors, never the authority (§6:
    /// "tokens authenticate; rows authorize").
    ///
    /// Note where it is NOT presented: no route on controld's `/v1` router
    /// accepts it, because that router is what hub forwards verbatim from
    /// 443. The only door is the mTLS service plane, which a guest cannot
    /// reach at all — it can only ask a use-point to ask on its behalf.
    UseCredential,
}

impl GuestOp {
    /// Every variant, so callers (and the allowlist test) can enumerate the
    /// vocabulary instead of restating it. Drift is fail-closed: a variant
    /// missing from here is left out of the minted block's allowlist, so it is
    /// refused rather than quietly permitted.
    pub const ALL: [GuestOp; 4] = [
        GuestOp::ListLinks,
        GuestOp::Spawn,
        GuestOp::RequestLink,
        GuestOp::UseCredential,
    ];

    /// The operation's datalog name, as used in `op(<name>)`.
    ///
    /// Exhaustive by construction (no `_` arm): a new variant does not compile
    /// until it has been named.
    pub const fn name(self) -> &'static str {
        match self {
            GuestOp::ListLinks => "list_links",
            GuestOp::Spawn => "spawn",
            GuestOp::RequestLink => "request_link",
            GuestOp::UseCredential => "use_credential",
        }
    }

    /// **The positive allowlist.** Does the guest audience authorize this
    /// operation at all?
    ///
    /// Exhaustive by construction, and the *only* place the answer is written:
    /// [`mint_workspace_handle`] builds the authority block's op check from
    /// it, and [`verify_workspace_handle`] consults it before any datalog
    /// runs. Adding a variant fails to compile until its verdict is decided —
    /// which is the mechanism a prose "never" list is not.
    const fn allowed(self) -> bool {
        match self {
            GuestOp::ListLinks => true,
            GuestOp::Spawn => true,
            GuestOp::RequestLink => true,
            GuestOp::UseCredential => true,
        }
    }

    /// The allowed op names, in [`GuestOp::ALL`] order — the set literal the
    /// minted authority block carries.
    fn allowed_names() -> Vec<&'static str> {
        GuestOp::ALL
            .iter()
            .filter(|op| op.allowed())
            .map(|op| op.name())
            .collect()
    }
}

/// Serialized Biscuit token bytes (the biscuit wire format, which embeds its
/// own schema version — I11).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenBytes(Vec<u8>);

impl TokenBytes {
    /// Wrap raw serialized token bytes.
    pub fn from_vec(bytes: Vec<u8>) -> Self {
        TokenBytes(bytes)
    }

    /// The raw serialized token.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consume into the raw serialized token.
    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }
}

impl AsRef<[u8]> for TokenBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for TokenBytes {
    fn from(bytes: Vec<u8>) -> Self {
        TokenBytes(bytes)
    }
}

/// The outcome of a successful [`verify`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified {
    /// The principal the token was minted for (from the authority block —
    /// facts appended after minting are never trusted).
    pub principal: String,
    /// The token's *effective* role: what the whole chain (authority block
    /// plus every attenuation) can actually do right now, which is at most
    /// the authority role and shrinks with each attenuation.
    pub role_effective: Role,
}

/// The outcome of a successful [`verify_node_token`] (ADR-0021).
///
/// Every field is read from the **authority block only** — a node token has no
/// other block, and one that does is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedNode {
    /// The node id the token was issued to.
    pub node: String,
    /// The workspace whose lease generation this token attests.
    pub workspace: String,
    /// The lease generation the minter (controld, which allocates it) attests
    /// (I2, ADR-0006). Verifiers compare it against their own persisted
    /// high-water mark; they never trust a number a peer declares alongside
    /// the token.
    pub fencing_token: u64,
}

/// The outcome of a successful [`verify_workspace_handle`] (ADR-0076).
///
/// Every field is read from the **authority block only** — a handle has no
/// other block, and one that does is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedHandle {
    /// The workspace the guest is running in.
    pub workspace: String,
    /// The principal everything inside that guest acts as: the workspace's
    /// **owner**, never the person who happened to start it (design §6
    /// ruling). Attribution and billing follow this field.
    pub owner_principal: String,
    /// The workspace's `authz_generation` at mint time. The caller compares it
    /// against the row and re-mints when it has moved; a handle never proves
    /// its own freshness.
    pub generation: u64,
    /// The fencing token of the VM instance this handle was minted for (I2,
    /// ADR-0006). Resume, fork and rewind all rotate it, so a handle recovered
    /// from an inherited memory image names a generation that is no longer
    /// live. As with [`VerifiedNode::fencing_token`], the comparison is the
    /// caller's: this crate reports what the token attests, never whether it
    /// is current.
    pub fencing_token: u64,
}

// ---------------------------------------------------------------------------
// Root key handling
// ---------------------------------------------------------------------------

/// Deterministically derive a root keypair from a seed — dev/tests only
/// (I12: no ambient RNG). Production roots come from KMS via
/// `REACHPAD_BISCUIT_ROOT_KEY` and are loaded with [`root_from_bytes`] /
/// [`root_from_hex`].
pub fn generate_root(seed: u64) -> KeyPair {
    let secret = blake3::derive_key(ROOT_KEY_CONTEXT, &seed.to_le_bytes());
    let private =
        PrivateKey::from_bytes(&secret).expect("32 bytes is always a valid ed25519 secret");
    KeyPair::from(&private)
}

/// Load a root keypair from 32 raw ed25519 private-key bytes.
pub fn root_from_bytes(bytes: &[u8]) -> Result<KeyPair, Error> {
    let private = PrivateKey::from_bytes(bytes).map_err(|e| Error::InvalidKey(e.to_string()))?;
    Ok(KeyPair::from(&private))
}

/// Load a root keypair from a hex-encoded 32-byte ed25519 private key.
pub fn root_from_hex(hex_str: &str) -> Result<KeyPair, Error> {
    let private =
        PrivateKey::from_bytes_hex(hex_str).map_err(|e| Error::InvalidKey(e.to_string()))?;
    Ok(KeyPair::from(&private))
}

/// Load a verifying public key from 32 raw bytes (`REACHPAD_BISCUIT_PUBLIC_KEY`
/// consumers: hub, gatewayd, noded — verify-only, can never mint).
pub fn public_from_bytes(bytes: &[u8]) -> Result<PublicKey, Error> {
    PublicKey::from_bytes(bytes).map_err(|e| Error::InvalidKey(e.to_string()))
}

/// Load a verifying public key from hex.
pub fn public_from_hex(hex_str: &str) -> Result<PublicKey, Error> {
    PublicKey::from_bytes_hex(hex_str).map_err(|e| Error::InvalidKey(e.to_string()))
}

// ---------------------------------------------------------------------------
// Minting
// ---------------------------------------------------------------------------

fn to_datalog_ms(ms: u64) -> Result<i64, Error> {
    i64::try_from(ms).map_err(|_| Error::TimeOutOfRange(ms))
}

fn to_datalog_fencing(token: u64) -> Result<i64, Error> {
    i64::try_from(token).map_err(|_| Error::FencingOutOfRange(token))
}

fn to_datalog_generation(generation: u64) -> Result<i64, Error> {
    i64::try_from(generation).map_err(|_| Error::GenerationOutOfRange(generation))
}

fn str_params(pairs: &[(&str, &str)]) -> HashMap<String, Term> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), Term::Str((*v).to_owned())))
        .collect()
}

/// Render a constant op list as a datalog set literal, e.g.
/// `["read", "write"]`. Only ever called with the `'static` op names from
/// [`Role::allowed_ops`] — never with user input.
fn ops_set_literal(ops: &[&'static str]) -> String {
    let inner = ops
        .iter()
        .map(|o| format!("\"{o}\""))
        .collect::<Vec<_>>()
        .join(", ");
    format!("[{inner}]")
}

/// Mint a user-facing token whose authority block carries the frozen fact
/// structure (§7.2/§12): `principal`, `workspace`, `role`, `exp`, plus the
/// time-binding check `check if time($t), $t < exp` — and nothing else. In
/// particular no fencing token (ADR-0015) and no `audience` fact: the absence
/// of one is what makes this the user-facing audience, and [`verify`] is the
/// only verifier that accepts it.
///
/// Only controld holds the root private key; everything else verifies.
pub fn mint(
    root: &KeyPair,
    principal: &str,
    workspace: &str,
    role: Role,
    exp_ms: u64,
) -> Result<TokenBytes, Error> {
    let exp = to_datalog_ms(exp_ms)?;
    let mut builder = Biscuit::builder();
    // Untrusted strings (principal, workspace) go in as *parameters*, never
    // interpolated into datalog source: a principal named `") or true` must
    // stay a string, not become syntax.
    let source = format!(
        "principal({{principal}});\n\
         workspace({{workspace}});\n\
         role({{role}});\n\
         exp({exp});\n\
         check if time($t), $t < {exp};"
    );
    let mut params = str_params(&[("principal", principal), ("workspace", workspace)]);
    params.insert("role".to_owned(), Term::Str(role.as_str().to_owned()));
    builder.add_code_with_params(&source, params, HashMap::new())?;
    let token = builder.build(root)?;
    Ok(TokenBytes(token.to_vec()?))
}

/// Mint a **node-scoped** token (ADR-0021): the credential a node presents to
/// prove which lease generation it is writing at.
///
/// The authority block carries an explicit `audience("node")` fact plus
/// `node`, `workspace`, `fencing_token` and `exp`, and the usual time-binding
/// check. It deliberately carries no `principal` and no `role`: it is not a
/// workspace capability and authorizes nothing through [`verify`], which
/// refuses it on the audience.
///
/// It is issued to one node for one lease generation and dies with it — never
/// shared, never attenuated ([`attenuate`] refuses it, and
/// [`verify_node_token`] accepts a single authority block only). Only the
/// holder of the root private key (controld, which also allocates the fencing
/// token) can mint one, which is what makes the number trustworthy rather than
/// self-declared.
pub fn mint_node_token(
    root: &KeyPair,
    node_id: &str,
    workspace: &str,
    fencing_token: u64,
    exp_ms: u64,
) -> Result<TokenBytes, Error> {
    let exp = to_datalog_ms(exp_ms)?;
    // Integer, not a string: no injection surface.
    let fencing = to_datalog_fencing(fencing_token)?;
    let mut builder = Biscuit::builder();
    // Untrusted strings (node id, workspace) go in as parameters, never as
    // datalog source — same rule as `mint`.
    let source = format!(
        "audience({{audience}});\n\
         node({{node}});\n\
         workspace({{workspace}});\n\
         fencing_token({fencing});\n\
         exp({exp});\n\
         check if time($t), $t < {exp};"
    );
    let params = str_params(&[
        ("audience", NODE_AUDIENCE),
        ("node", node_id),
        ("workspace", workspace),
    ]);
    builder.add_code_with_params(&source, params, HashMap::new())?;
    let token = builder.build(root)?;
    Ok(TokenBytes(token.to_vec()?))
}

/// Mint a harness token (§7.2): can only `append_own_events` and
/// `mirror_sync`, and appends only as its own principal. The restrictions are
/// carried in the authority block itself (self-contained checks), in addition
/// to the verifier's `role_op` table for `role("harness")`.
pub fn mint_harness(
    root: &KeyPair,
    principal: &str,
    workspace: &str,
    exp_ms: u64,
) -> Result<TokenBytes, Error> {
    let exp = to_datalog_ms(exp_ms)?;
    let ops = ops_set_literal(Role::Harness.allowed_ops());
    let mut builder = Biscuit::builder();
    let source = format!(
        "principal({{principal}});\n\
         workspace({{workspace}});\n\
         role({{role}});\n\
         exp({exp});\n\
         check if time($t), $t < {exp};\n\
         check if op($o), {ops}.contains($o);\n\
         check if append_principal({{principal}}) or op($o), $o != \"append_own_events\";"
    );
    let mut params = str_params(&[("principal", principal), ("workspace", workspace)]);
    params.insert(
        "role".to_owned(),
        Term::Str(Role::Harness.as_str().to_owned()),
    );
    builder.add_code_with_params(&source, params, HashMap::new())?;
    let token = builder.build(root)?;
    Ok(TokenBytes(token.to_vec()?))
}

/// Mint a **workspace handle** (ADR-0076): the credential a guest holds.
///
/// The authority block carries `audience("guest")` plus `workspace`,
/// `owner_principal`, `generation`, `fencing_token` and `exp`, the usual
/// time-binding check, and — following [`mint_harness`]'s belt-and-braces
/// shape — the guest allowlist as a check *in the block itself*, so the
/// restriction travels with the token rather than living only in the verifier.
///
/// It carries no `principal` and no `role`: it is not a workspace capability
/// and authorizes nothing through [`verify`], which refuses it on the
/// audience. Everything inside the guest acts as the workspace's **owner**
/// principal (design §6 ruling), which is what `owner_principal` names.
///
/// Like a node token it is never attenuated ([`attenuate`] refuses it, and
/// [`verify_workspace_handle`] accepts a single authority block only), and it
/// is short-lived: freshness is the caller's comparison of `generation`
/// against the workspace row and of `fencing_token` against the live lease,
/// not something the token can assert about itself.
pub fn mint_workspace_handle(
    root: &KeyPair,
    workspace: &str,
    owner_principal: &str,
    generation: u64,
    fencing_token: u64,
    exp_ms: u64,
) -> Result<TokenBytes, Error> {
    let exp = to_datalog_ms(exp_ms)?;
    // Integers, not strings: no injection surface.
    let gen_int = to_datalog_generation(generation)?;
    let fencing = to_datalog_fencing(fencing_token)?;
    let ops = ops_set_literal(&GuestOp::allowed_names());
    let mut builder = Biscuit::builder();
    // Untrusted strings (workspace, owner principal) go in as parameters,
    // never as datalog source — same rule as `mint`.
    let source = format!(
        "audience({{audience}});\n\
         workspace({{workspace}});\n\
         owner_principal({{owner_principal}});\n\
         generation({gen_int});\n\
         fencing_token({fencing});\n\
         exp({exp});\n\
         check if time($t), $t < {exp};\n\
         check if op($o), {ops}.contains($o);"
    );
    let params = str_params(&[
        ("audience", GUEST_AUDIENCE),
        ("workspace", workspace),
        ("owner_principal", owner_principal),
    ]);
    builder.add_code_with_params(&source, params, HashMap::new())?;
    let token = builder.build(root)?;
    Ok(TokenBytes(token.to_vec()?))
}

// ---------------------------------------------------------------------------
// Attenuation
// ---------------------------------------------------------------------------

/// Append an attenuation block narrowing the token to `narrower_role`'s op
/// set and to `earlier_exp_ms`.
///
/// This is offline (§7.2): no root key and no server round-trip. It narrows a
/// token the caller already holds; it does **not** hand a workspace to someone
/// else, because an appended block cannot rebind `principal` — a share is
/// minted server-side for the grantee's own principal instead (ADR-0075).
/// The appended block contains **only checks**; by biscuit
/// scoping semantics the verifier never trusts facts from appended blocks,
/// so any chain of `attenuate` calls (or hand-crafted appended blocks) can
/// only shrink what the token authorizes:
///
/// - "attenuating" to a *wider* role adds a check that is simply implied by
///   the existing ones — the original role/attenuation checks still apply;
/// - a *later* expiry adds a check that never fires before the original
///   `check if time($t), $t < exp`, which still applies.
///
/// The authority block is untouched, so `principal`, `workspace`, `role` and
/// `exp` are carried through exactly as minted.
///
/// **Audience-bearing tokens are refused here** (ADR-0021, ADR-0076), not
/// merely never attenuated in practice: narrowing is exclusively about
/// user-facing tokens, and a node token names one node at one lease
/// generation while a workspace handle names one VM instance at one
/// authorization generation, so a narrowed copy of either is meaningless. The
/// refusal is [`Error::Denied`] and is belt-and-braces only —
/// [`verify_node_token`] and [`verify_workspace_handle`] each independently
/// reject any token that carries an appended block, however it was appended.
///
/// The checks-only shape emitted here is the shape [`verify`] enforces
/// ([`check_appended_block_shapes`]); appending anything else produces a token
/// verifies as [`Error::Denied`].
pub fn attenuate(
    token: &TokenBytes,
    narrower_role: Role,
    earlier_exp_ms: u64,
) -> Result<TokenBytes, Error> {
    let exp = to_datalog_ms(earlier_exp_ms)?;
    let unverified = UnverifiedBiscuit::from(token.as_bytes())?;
    if authority_declares_an_audience(&unverified) {
        return Err(Error::Denied(
            "audience-bearing tokens are never attenuated (ADR-0021, ADR-0076): each is \
             issued to one holder for one generation and is never shared"
                .to_owned(),
        ));
    }
    let ops = ops_set_literal(narrower_role.allowed_ops());
    let mut block = BlockBuilder::new();
    block.add_code(format!(
        "check if op($o), {ops}.contains($o);\n\
         check if time($t), $t < {exp};"
    ))?;
    let attenuated = unverified.append(block)?;
    Ok(TokenBytes(attenuated.to_vec()?))
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/// Verify a **user-facing** `token` against the root public key and authorize
/// `requested_op` on `expected_workspace` at time `now_ms` (injected — I12).
///
/// A node-scoped token (ADR-0021) is refused here on its audience, before
/// anything is authorized: it is a machine credential attesting a lease
/// generation, not a workspace capability, and it must authorize *nothing*
/// through this path. See [`verify_node_token`] for the other direction.
///
/// On success returns the token's principal and effective role. Signature or
/// parse failures return [`Error::Token`]; failed
/// authorization (expiry, workspace mismatch, insufficient role,
/// principal-binding violation) and non-conforming token shape (see
/// [`check_appended_block_shapes`] and [`check_verified_token_shape`]) return
/// [`Error::Denied`].
///
/// Cost is bounded on every path: size and depth are checked before any
/// signature verification, block shape before any datalog, and all datalog
/// runs share one [`DATALOG_BUDGET`] deadline.
pub fn verify(
    token: &TokenBytes,
    root_public: &PublicKey,
    expected_workspace: &str,
    requested_op: &Op,
    now_ms: u64,
) -> Result<Verified, Error> {
    let now = to_datalog_ms(now_ms)?;

    // Bound the work before doing any: signature verification is O(blocks),
    // so a 10k-block token must not get that far.
    if token.as_bytes().len() > MAX_TOKEN_BYTES {
        return Err(Error::Denied(format!(
            "token is {} bytes, limit is {MAX_TOKEN_BYTES}",
            token.as_bytes().len()
        )));
    }
    let unverified = UnverifiedBiscuit::from(token.as_bytes())?;
    if unverified.block_count() > MAX_BLOCKS {
        return Err(Error::Denied(format!(
            "token has {} blocks, limit is {MAX_BLOCKS}",
            unverified.block_count()
        )));
    }

    // Structural contract on the attacker-controlled blocks, before the token
    // costs any crypto at all.
    check_appended_block_shapes(&unverified)?;

    // Verify the signature chain (test g: tampered bytes die here). Same
    // check as `Biscuit::from`, without parsing the token a second time.
    let biscuit = unverified
        .verify(*root_public)
        .map_err(berror::Token::Format)?;

    // Remaining structural contract, before any authorizer exists.
    check_verified_token_shape(&biscuit)?;

    authorize_verified(&biscuit, expected_workspace, requested_op, now)
}

/// Datalog half of [`verify`]: authorize the request, then read back the
/// authority facts. Assumes the structural gate has already passed — which
/// is what makes [`DATALOG_BUDGET`] impossible to trip by accident.
fn authorize_verified(
    biscuit: &Biscuit,
    expected_workspace: &str,
    requested_op: &Op,
    now: i64,
) -> Result<Verified, Error> {
    let budget = Budget::start();

    // Audience separation (ADR-0021), checked explicitly and FIRST so the
    // refusal names the audience instead of being a downstream symptom (a node
    // token carries no `role`, so authorization would fail anyway — that would
    // be incidental, and incidental is not a contract). User-facing tokens
    // carry no `audience` fact: §7.2's fact set is frozen at
    // principal/workspace/role/exp.
    if let Some(audience) = query_authority_audience(biscuit, &budget)? {
        return Err(Error::Denied(format!(
            "token is minted for the {audience:?} audience and authorizes nothing as a \
             workspace capability"
        )));
    }

    // Authorize the actual request.
    let mut authorizer = build_authorizer(biscuit, expected_workspace, requested_op, now)?;
    match authorizer.authorize_with_limits(budget.limits()) {
        Ok(_) => {}
        Err(berror::Token::FailedLogic(logic)) => return Err(Error::Denied(logic.to_string())),
        Err(berror::Token::RunLimit(limit)) => return Err(Error::Denied(limit.to_string())),
        Err(other) => return Err(Error::Token(other)),
    }

    // The principal comes from the authority block only: authorizer queries
    // trust {authority, authorizer} origins, so facts smuggled into appended
    // blocks are invisible here.
    let principal = query_authority_principal(&mut authorizer, &budget)?;

    // Effective role: the op sets are strictly nested
    // (owner ⊃ collaborator ⊃ viewer; harness disjoint from viewer), so three
    // probes classify the whole chain's actual capability. A probe that runs
    // out of budget reads as "not allowed", which can only *understate* the
    // role — fail-closed, never a widening.
    let role_effective = if probe(biscuit, expected_workspace, &Op::Admin, now, &budget) {
        Role::Owner
    } else if probe(biscuit, expected_workspace, &Op::Write, now, &budget) {
        Role::Collaborator
    } else if probe(biscuit, expected_workspace, &Op::Read, now, &budget) {
        Role::Viewer
    } else {
        Role::Harness
    };

    Ok(Verified {
        principal,
        role_effective,
    })
}

/// Build the authorizer world for one operation request.
///
/// Trusted facts (authorizer origin): `time`, `op`, optionally
/// `append_principal`, and the static `role_op` table. Trusted checks:
/// workspace binding, role→op mapping, expiry (defense in depth — the
/// authority block carries its own time check), and the own-principal
/// binding for `append_own_events`.
fn build_authorizer(
    biscuit: &Biscuit,
    expected_workspace: &str,
    op: &Op,
    now: i64,
) -> Result<Authorizer, Error> {
    let mut authorizer = biscuit.authorizer()?;

    let mut source = String::new();
    source.push_str(&format!("time({now});\n"));
    // Op names are 'static constants from Op::name(), safe to inline.
    source.push_str(&format!("op(\"{}\");\n", op.name()));
    for role in Role::ALL {
        for allowed in role.allowed_ops() {
            source.push_str(&format!("role_op(\"{}\", \"{allowed}\");\n", role.as_str()));
        }
    }
    source.push_str("check if workspace({expected_workspace});\n");
    // Default authorizer scope trusts only the authority block + authorizer
    // facts: role($r) here can never bind to a role fact from an appended
    // block. This line is why appended facts cannot widen anything.
    source.push_str("check if role($r), op($o), role_op($r, $o);\n");
    source.push_str("check if exp($e), time($t), $t < $e;\n");
    source.push_str(
        "check if append_principal($q), principal($p), $p == $q \
         or op($o), $o != \"append_own_events\";\n",
    );
    source.push_str("allow if true;");

    let mut params = str_params(&[("expected_workspace", expected_workspace)]);
    if let Op::AppendOwnEvents { principal } = op {
        source.push_str("\nappend_principal({append_principal});");
        params.insert("append_principal".to_owned(), Term::Str(principal.clone()));
    }
    authorizer.add_code_with_params(&source, params, HashMap::new())?;
    Ok(authorizer)
}

/// Would `op` be authorized? Used only to compute the effective role.
fn probe(biscuit: &Biscuit, expected_workspace: &str, op: &Op, now: i64, budget: &Budget) -> bool {
    build_authorizer(biscuit, expected_workspace, op, now)
        .and_then(|mut a| {
            a.authorize_with_limits(budget.limits())
                .map_err(Error::Token)
        })
        .is_ok()
}

/// A single-string-term fact, for reading `principal($p)` back out.
struct StrFact(String);

impl TryFrom<Fact> for StrFact {
    type Error = berror::Token;

    fn try_from(fact: Fact) -> Result<Self, berror::Token> {
        match fact.predicate.terms.as_slice() {
            [Term::Str(s)] => Ok(StrFact(s.clone())),
            _ => Err(berror::Token::InternalError),
        }
    }
}

/// A single-integer-term fact, for reading `fencing_token($f)` back out.
struct IntFact(i64);

impl TryFrom<Fact> for IntFact {
    type Error = berror::Token;

    fn try_from(fact: Fact) -> Result<Self, berror::Token> {
        match fact.predicate.terms.as_slice() {
            [Term::Integer(i)] => Ok(IntFact(*i)),
            _ => Err(berror::Token::InternalError),
        }
    }
}

fn query_authority_principal(
    authorizer: &mut Authorizer,
    budget: &Budget,
) -> Result<String, Error> {
    // Query scope defaults to {authority, authorizer}: appended-block
    // principal facts are not visible. Explicit limits: `query`'s default
    // max_time is 1 ms of wall time — see Budget.
    let mut principals: Vec<StrFact> =
        authorizer.query_with_limits("data($p) <- principal($p)", budget.limits())?;
    if principals.len() != 1 {
        return Err(Error::Denied(format!(
            "token must carry exactly one authority principal fact, found {}",
            principals.len()
        )));
    }
    Ok(principals.remove(0).0)
}

/// Read a single mandatory string fact out of the authority block.
///
/// Same {authority, authorizer} query scope as everything else here: a fact
/// smuggled into an appended block is invisible (and such a block is refused
/// by the shape gate anyway).
fn query_authority_str(
    authorizer: &mut Authorizer,
    predicate: &str,
    budget: &Budget,
) -> Result<String, Error> {
    let query = format!("data($v) <- {predicate}($v)");
    let mut found: Vec<StrFact> = authorizer.query_with_limits(query.as_str(), budget.limits())?;
    if found.len() != 1 {
        return Err(Error::Denied(format!(
            "token must carry exactly one authority {predicate} fact, found {}",
            found.len()
        )));
    }
    Ok(found.remove(0).0)
}

/// The audience this token was minted for, or `None` for the user-facing
/// audience (which carries no `audience` fact — §7.2's frozen fact set).
///
/// Builds its own bare authorizer so the check can run *before* any request is
/// authorized: audience separation must be the reason a token is refused, not
/// a side effect of some later check failing.
fn query_authority_audience(biscuit: &Biscuit, budget: &Budget) -> Result<Option<String>, Error> {
    let mut authorizer = biscuit.authorizer()?;
    let mut found: Vec<StrFact> =
        authorizer.query_with_limits("data($a) <- audience($a)", budget.limits())?;
    match found.len() {
        0 => Ok(None),
        1 => Ok(Some(found.remove(0).0)),
        n => Err(Error::Denied(format!(
            "token must carry at most one authority audience fact, found {n}"
        ))),
    }
}

/// Read a single mandatory non-negative integer fact (an attested lease
/// generation, an attested authorization generation) out of the authority
/// block.
///
/// Required, never optional: a token that omits the counter it exists to
/// attest proves nothing, so its absence is [`Error::Denied`] rather than a
/// `None` some caller might read as permissive. Same {authority, authorizer}
/// query scope as [`query_authority_str`].
fn query_authority_u64(
    authorizer: &mut Authorizer,
    predicate: &str,
    budget: &Budget,
) -> Result<u64, Error> {
    let query = format!("data($v) <- {predicate}($v)");
    let mut found: Vec<IntFact> = authorizer.query_with_limits(query.as_str(), budget.limits())?;
    if found.len() != 1 {
        return Err(Error::Denied(format!(
            "token must carry exactly one authority {predicate} fact, found {}",
            found.len()
        )));
    }
    let raw = found.remove(0).0;
    u64::try_from(raw)
        .map_err(|_| Error::Denied(format!("authority {predicate} must be non-negative: {raw}")))
}

/// Verify a **node-scoped** token (ADR-0021) against the root public key at
/// time `now_ms` (injected — I12), and return what it attests.
///
/// This is the credential a node presents to prove *which lease generation* it
/// is writing at, so that hub (and, one hop down, blockd) can admit the
/// current holder and reject a zombie whose lease has moved on. It is refused
/// unless it is exactly what [`mint_node_token`] produces:
///
/// * `audience("node")` must be present — a user-facing token, however
///   privileged, is refused here explicitly (it attests no generation);
/// * the token must be a **single authority block** — node tokens are never
///   attenuated, so an appended block means the token is not ours, whoever
///   appended it and whatever it says;
/// * `fencing_token` must be present, and `workspace` must match
///   `expected_workspace`, and `exp` must be in the future.
///
/// Cost is bounded exactly as [`verify`]'s is (ADR-0014): size before parsing,
/// shape before any datalog, and all datalog runs share one
/// [`DATALOG_BUDGET`] deadline.
pub fn verify_node_token(
    token: &TokenBytes,
    root_public: &PublicKey,
    expected_workspace: &str,
    now_ms: u64,
) -> Result<VerifiedNode, Error> {
    let now = to_datalog_ms(now_ms)?;

    if token.as_bytes().len() > MAX_TOKEN_BYTES {
        return Err(Error::Denied(format!(
            "token is {} bytes, limit is {MAX_TOKEN_BYTES}",
            token.as_bytes().len()
        )));
    }
    let unverified = UnverifiedBiscuit::from(token.as_bytes())?;
    if unverified.block_count() != 1 {
        return Err(Error::Denied(format!(
            "a node token is a single authority block and is never attenuated \
             (ADR-0021); this one has {} blocks",
            unverified.block_count()
        )));
    }

    let biscuit = unverified
        .verify(*root_public)
        .map_err(berror::Token::Format)?;
    check_verified_token_shape(&biscuit)?;

    let budget = Budget::start();

    // Audience separation, explicit and first (see `authorize_verified` for
    // the mirror image of this check).
    match query_authority_audience(&biscuit, &budget)? {
        Some(audience) if audience == NODE_AUDIENCE => {}
        Some(audience) => {
            return Err(Error::Denied(format!(
                "token is minted for the {audience:?} audience, not {NODE_AUDIENCE:?}"
            )))
        }
        None => {
            return Err(Error::Denied(
                "token carries no audience fact: a user-facing token attests no lease \
                 generation and is not a node token"
                    .to_owned(),
            ))
        }
    }

    let mut authorizer = biscuit.authorizer()?;
    let mut source = String::new();
    source.push_str(&format!("time({now});\n"));
    source.push_str("check if workspace({expected_workspace});\n");
    source.push_str("check if exp($e), time($t), $t < $e;\n");
    source.push_str("allow if true;");
    authorizer.add_code_with_params(
        &source,
        str_params(&[("expected_workspace", expected_workspace)]),
        HashMap::new(),
    )?;
    match authorizer.authorize_with_limits(budget.limits()) {
        Ok(_) => {}
        Err(berror::Token::FailedLogic(logic)) => return Err(Error::Denied(logic.to_string())),
        Err(berror::Token::RunLimit(limit)) => return Err(Error::Denied(limit.to_string())),
        Err(other) => return Err(Error::Token(other)),
    }

    let node = query_authority_str(&mut authorizer, "node", &budget)?;
    let workspace = query_authority_str(&mut authorizer, "workspace", &budget)?;
    let fencing_token = query_authority_u64(&mut authorizer, "fencing_token", &budget)?;

    Ok(VerifiedNode {
        node,
        workspace,
        fencing_token,
    })
}

/// Verify a **workspace handle** (ADR-0076) against the root public key at
/// time `now_ms` (injected — I12), for one guest operation, and return what it
/// attests.
///
/// This is the credential a guest holds. It is refused unless it is exactly
/// what [`mint_workspace_handle`] produces:
///
/// * `requested_op` must be in the guest allowlist (see [`GuestOp`]) — checked
///   first, by exhaustive match, before any datalog runs, and again by the
///   authority block's own op check;
/// * `audience("guest")` must be present — a user-facing token, however
///   privileged, and a node token, however current, are both refused here
///   explicitly;
/// * the token must be a **single authority block** — handles are never
///   attenuated, so an appended block means the token is not ours, whoever
///   appended it and whatever it says;
/// * `owner_principal`, `generation` and `fencing_token` must each be present
///   exactly once, `workspace` must match `expected_workspace`, and `exp` must
///   be in the future — a past `exp` is [`Error::HandleExpired`] and not
///   [`Error::Denied`], because the holder's remedy (ask for a fresh handle)
///   differs from every other refusal's (stop).
///
/// Success is **not** freshness. `generation` and `fencing_token` are reported,
/// never judged: the caller compares them against `workspaces.authz_generation`
/// and the live lease, exactly as hub compares a node token's generation
/// against its own high-water mark. A verifier that skipped that comparison
/// would honour a handle from a workspace whose shares were cut an hour ago.
///
/// Cost is bounded exactly as [`verify`]'s is (ADR-0014): size before parsing,
/// shape before any datalog, and all datalog runs share one
/// [`DATALOG_BUDGET`] deadline.
pub fn verify_workspace_handle(
    token: &TokenBytes,
    root_public: &PublicKey,
    expected_workspace: &str,
    requested_op: GuestOp,
    now_ms: u64,
) -> Result<VerifiedHandle, Error> {
    let now = to_datalog_ms(now_ms)?;

    // The positive allowlist, before anything is parsed: an operation outside
    // it is refused here whatever the token says. The authority block carries
    // the same list as a check, so a future caller that reached the datalog
    // without coming through this arm is refused there too.
    if !requested_op.allowed() {
        return Err(Error::Denied(format!(
            "the {GUEST_AUDIENCE:?} audience does not authorize {requested_op:?}: its \
             operation set is a positive allowlist"
        )));
    }

    if token.as_bytes().len() > MAX_TOKEN_BYTES {
        return Err(Error::Denied(format!(
            "token is {} bytes, limit is {MAX_TOKEN_BYTES}",
            token.as_bytes().len()
        )));
    }
    let unverified = UnverifiedBiscuit::from(token.as_bytes())?;
    if unverified.block_count() != 1 {
        return Err(Error::Denied(format!(
            "a workspace handle is a single authority block and is never attenuated \
             (ADR-0076); this one has {} blocks",
            unverified.block_count()
        )));
    }

    let biscuit = unverified
        .verify(*root_public)
        .map_err(berror::Token::Format)?;
    check_verified_token_shape(&biscuit)?;

    let budget = Budget::start();

    // Audience separation, explicit and first (see `authorize_verified` and
    // `verify_node_token` for the other two faces of this check).
    match query_authority_audience(&biscuit, &budget)? {
        Some(audience) if audience == GUEST_AUDIENCE => {}
        Some(audience) => {
            return Err(Error::Denied(format!(
                "token is minted for the {audience:?} audience, not {GUEST_AUDIENCE:?}"
            )))
        }
        None => {
            return Err(Error::Denied(
                "token carries no audience fact: a user-facing token is a workspace \
                 capability, not a guest handle"
                    .to_owned(),
            ))
        }
    }

    let mut authorizer = biscuit.authorizer()?;

    // EXPIRY IS READ BEFORE THE DATALOG RUNS, so that "this handle is five
    // minutes old" is a different answer from "this token is not ours".
    //
    // The authority block's own `check if exp($e), time($t), $t < $e` still
    // runs below and is still what enforces the bound — this is a
    // CLASSIFICATION, not the check. It has to be here rather than after
    // `authorize_with_limits`, because a failed check aborts authorization
    // and biscuit reports it as one `FailedLogic` string among several; that
    // string is not a stable interface to match on.
    //
    // Everything above has already verified the signature chain and the
    // audience, so nothing that is not a handle this fleet minted reaches
    // this line (see [`Error::HandleExpired`]).
    let exp_ms = query_authority_u64(&mut authorizer, "exp", &budget)?;
    if now_ms >= exp_ms {
        return Err(Error::HandleExpired { exp_ms, now_ms });
    }

    let mut source = String::new();
    source.push_str(&format!("time({now});\n"));
    // Op names are 'static constants from GuestOp::name(), safe to inline.
    source.push_str(&format!("op(\"{}\");\n", requested_op.name()));
    source.push_str("check if workspace({expected_workspace});\n");
    source.push_str("check if exp($e), time($t), $t < $e;\n");
    source.push_str("allow if true;");
    authorizer.add_code_with_params(
        &source,
        str_params(&[("expected_workspace", expected_workspace)]),
        HashMap::new(),
    )?;
    match authorizer.authorize_with_limits(budget.limits()) {
        Ok(_) => {}
        Err(berror::Token::FailedLogic(logic)) => return Err(Error::Denied(logic.to_string())),
        Err(berror::Token::RunLimit(limit)) => return Err(Error::Denied(limit.to_string())),
        Err(other) => return Err(Error::Token(other)),
    }

    let workspace = query_authority_str(&mut authorizer, "workspace", &budget)?;
    let owner_principal = query_authority_str(&mut authorizer, "owner_principal", &budget)?;
    let generation = query_authority_u64(&mut authorizer, "generation", &budget)?;
    let fencing_token = query_authority_u64(&mut authorizer, "fencing_token", &budget)?;

    Ok(VerifiedHandle {
        workspace,
        owner_principal,
        generation,
        fencing_token,
    })
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn generate_root_is_deterministic() {
        let a = generate_root(42);
        let b = generate_root(42);
        let c = generate_root(43);
        assert_eq!(a.public().to_bytes(), b.public().to_bytes());
        assert_ne!(a.public().to_bytes(), c.public().to_bytes());
    }

    #[test]
    fn root_key_hex_and_bytes_round_trip() {
        let root = generate_root(7);
        let hex_str = root.private().to_bytes_hex();
        let from_hex = root_from_hex(&hex_str).unwrap();
        assert_eq!(root.public().to_bytes(), from_hex.public().to_bytes());

        let bytes = root.private().to_bytes();
        let from_bytes = root_from_bytes(&bytes).unwrap();
        assert_eq!(root.public().to_bytes(), from_bytes.public().to_bytes());

        let pub_hex = root.public().to_bytes_hex();
        assert_eq!(
            public_from_hex(&pub_hex).unwrap().to_bytes(),
            root.public().to_bytes()
        );
        assert!(root_from_hex("zz").is_err());
        assert!(root_from_bytes(&[1, 2, 3]).is_err());
        assert!(public_from_bytes(&[0u8; 3]).is_err());
    }

    #[test]
    fn role_round_trip_and_order_of_ops() {
        for role in Role::ALL {
            assert_eq!(role.as_str().parse::<Role>().unwrap(), role);
        }
        assert!("root".parse::<Role>().is_err());
        // owner ⊃ collaborator ⊃ viewer (monotone lattice the effective-role
        // probe relies on).
        let owner: std::collections::HashSet<_> = Role::Owner.allowed_ops().iter().collect();
        let collab: std::collections::HashSet<_> =
            Role::Collaborator.allowed_ops().iter().collect();
        let viewer: std::collections::HashSet<_> = Role::Viewer.allowed_ops().iter().collect();
        assert!(collab.is_subset(&owner));
        assert!(viewer.is_subset(&collab));
    }

    #[test]
    fn exp_out_of_range_is_rejected() {
        let root = generate_root(1);
        let err = mint(&root, "p", "w", Role::Owner, u64::MAX).unwrap_err();
        assert!(matches!(err, Error::TimeOutOfRange(_)));
    }

    #[test]
    fn fencing_token_out_of_range_is_rejected() {
        // Only node tokens carry a fencing token at all (ADR-0015/ADR-0021).
        let root = generate_root(1);
        let err = mint_node_token(&root, "n1", "w", u64::MAX, 10).unwrap_err();
        assert!(matches!(err, Error::FencingOutOfRange(u64::MAX)));
        // i64::MAX still fits.
        mint_node_token(&root, "n1", "w", i64::MAX as u64, 10).unwrap();
    }

    #[test]
    fn statements_split_on_top_level_semicolons_only() {
        let src = "principal(\"a;b\");\nrole(\"owner\");\ncheck if time($t), $t < 5;\n";
        assert_eq!(
            top_level_statements(src),
            vec![
                "principal(\"a;b\")",
                "role(\"owner\")",
                "check if time($t), $t < 5"
            ]
        );
        assert!(top_level_statements("").is_empty());
        assert!(top_level_statements(";\n ;").is_empty());

        assert!(is_check("check if op($o), [\"read\"].contains($o)"));
        assert!(is_check("check all op($o), $o != \"write\""));
        assert!(!is_check("role(\"owner\")"));
        assert!(!is_check("checked(1)"));
        assert!(!is_check("role(\"owner\") <- workspace($w)"));
    }

    #[test]
    fn inert_symbols_exclude_everything_datalog_syntax_needs() {
        for ok in ["op", "o", "read", "append_own_events", "a.b:c@d/e+f=g", "1"] {
            assert!(symbol_is_inert(ok), "{ok} should be inert");
        }
        for bad in [
            "check if x($a), x($b)",
            "a b",
            "a\"b",
            "x(1)",
            "$a",
            "a,b",
            "a;b",
            "a<-b",
        ] {
            assert!(!symbol_is_inert(bad), "{bad} must not be inert");
        }
        assert!(!symbol_is_inert(&"a".repeat(MAX_APPENDED_SYMBOL_BYTES + 1)));
    }

    /// Defence in depth behind the structural gate: even if a block carrying
    /// facts somehow reached the datalog stage, the authority-only query scope
    /// means an appended `principal`/`audience` fact is invisible. Calls the
    /// datalog half directly, which is the only way to see past the shape gate
    /// (`verify` rejects this token outright — see the integration test
    /// `n_appended_audience_fact_cannot_change_the_audience`).
    #[test]
    fn appended_facts_are_invisible_to_authority_queries() {
        let root = generate_root(5);
        let token = mint(&root, "alice", "ws-1", Role::Owner, 1_000).unwrap();

        let unverified = UnverifiedBiscuit::from(token.as_bytes()).unwrap();
        let mut block = BlockBuilder::new();
        block
            .add_code("audience(\"node\");\nprincipal(\"mallory\");")
            .unwrap();
        let forged = unverified.append(block).unwrap().to_vec().unwrap();

        // Shape gate rejects it...
        let err = verify(
            &TokenBytes::from_vec(forged.clone()),
            &root.public(),
            "ws-1",
            &Op::Read,
            500,
        )
        .unwrap_err();
        assert!(matches!(err, Error::Denied(_)), "got {err:?}");

        // ...and the layer behind it ignores the forged facts anyway.
        let biscuit = Biscuit::from(&forged, root.public()).unwrap();
        let verified = authorize_verified(&biscuit, "ws-1", &Op::Read, 500).unwrap();
        assert_eq!(verified.principal, "alice");
        assert_eq!(verified.role_effective, Role::Owner);
    }
}
