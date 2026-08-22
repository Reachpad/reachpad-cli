//! One compiled table from wire code to the sentence a user acts on, the exit
//! code that sentence deserves, and whether trying again could help.
//!
//! Three rules the table exists to keep:
//!
//! - **Numbers come from the server.** A row's `numbers` clause is rendered
//!   only when every field it names is in the refusal body (I13: limits are
//!   entitlement values read off the wire, never constants in a client). The
//!   clause disappears rather than inventing a number.
//! - **Sentences are product words.** No `§`, no "biscuit", no bare code, no
//!   milliseconds-since-epoch; each one names the next command.
//! - **The exit code is semantic.** `run` carries the guest's own code; every
//!   other command exits 0/2/3/4/5/6/7, and 70 means reachpad accepted the
//!   command and lost its result.

use serde_json::{json, Value};

use crate::api::ApiError;

pub const EXIT_OK: i32 = 0;
pub const EXIT_USAGE: i32 = 2;
pub const EXIT_CREDENTIAL: i32 = 3;
pub const EXIT_NO_SUCH_WORKSPACE: i32 = 4;
pub const EXIT_WRONG_STATE: i32 = 5;
pub const EXIT_LIMIT: i32 = 6;
pub const EXIT_UNAVAILABLE: i32 = 7;
/// EX_SOFTWARE: the command was accepted and its result was lost.
pub const EXIT_LOST_RESULT: i32 = 70;

/// controld self-terminates an exec stream this long after the timeout it was
/// given (`execbroker::EXEC_STREAM_GRACE_MS`).
pub const EXEC_STREAM_GRACE_MS: u64 = 150_000;
/// Room for that verdict to travel back before the client stops waiting.
pub const DEADLINE_MARGIN_MS: u64 = 30_000;
/// The exec timeout controld applies when the request names none.
pub const DEFAULT_EXEC_TIMEOUT_MS: u64 = 600_000;

/// How long the client waits for an exec, given the timeout the user asked
/// for. Strictly longer than the server's own bound (trap 31), so the verdict
/// the user sees is the server's `exec.end` and not a local timeout that says
/// nothing about whether the command ran.
pub fn exec_deadline_ms(timeout_ms: Option<u64>) -> u64 {
    timeout_ms
        .unwrap_or(DEFAULT_EXEC_TIMEOUT_MS)
        .saturating_add(EXEC_STREAM_GRACE_MS)
        .saturating_add(DEADLINE_MARGIN_MS)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Retriable {
    No,
    Yes,
    /// `no_capacity` only: the fleet may make room, or it may be structurally
    /// unable to serve this workspace. The body's `cause` says which.
    WhenCauseTransient,
}

pub struct Row {
    pub code: &'static str,
    /// Chooses between rows sharing a code: the body field and the value it
    /// must have. Selective rows come first; a row with `None` is the
    /// fallback.
    pub selector: Option<(&'static str, &'static str)>,
    /// Always safe to render: it names no server number.
    pub sentence: &'static str,
    /// Rendered only when every `{field}` in it is present in the body.
    pub numbers: Option<&'static str>,
    pub next_command: Option<&'static str>,
    pub exit_code: i32,
    pub retriable: Retriable,
}

const SIGN_IN: &str = "reachpad auth login";

pub const TABLE: &[Row] = &[
    // ---- no credential, in all five spellings the fleet has for it --------
    Row {
        code: "no_credential",
        selector: None,
        sentence: "Not signed in. Run `reachpad auth login` — get your credential at https://reachpad.dev/connect.",
        numbers: None,
        next_command: Some(SIGN_IN),
        exit_code: EXIT_CREDENTIAL,
        retriable: Retriable::No,
    },
    // ADR-0059 §4, said to the caller instead of silently worked around. The
    // CLI used to reach for the SAVED credential whenever a verb could not
    // use the key it was handed — so `keys mint --api-key <k>` minted under
    // the operator credential and printed a key, and a key scoped to one
    // workspace for a day produced one covering the whole account for ninety.
    // Nothing was escalated server-side; the caller was simply not told which
    // credential acted. Falling back to a broader one is the thing this
    // refusal exists to prevent.
    Row {
        code: "api_key_not_accepted",
        selector: None,
        sentence: "This needs your own credential, not an API key: a key cannot mint or read keys, and cannot answer for the whole account. Drop `--api-key` / `REACHPAD_API_KEY`, or run `reachpad auth login`.",
        numbers: None,
        next_command: Some(SIGN_IN),
        exit_code: EXIT_CREDENTIAL,
        retriable: Retriable::No,
    },
    Row {
        code: "no_identity_token",
        selector: None,
        sentence: "Not signed in. Run `reachpad auth login` — get your credential at https://reachpad.dev/connect.",
        numbers: None,
        next_command: Some(SIGN_IN),
        exit_code: EXIT_CREDENTIAL,
        retriable: Retriable::No,
    },
    Row {
        code: "no_token",
        selector: None,
        sentence: "Not signed in. Run `reachpad auth login` — get your credential at https://reachpad.dev/connect.",
        numbers: None,
        next_command: Some(SIGN_IN),
        exit_code: EXIT_CREDENTIAL,
        retriable: Retriable::No,
    },
    Row {
        code: "no_operator_token",
        selector: None,
        sentence: "Not signed in. Run `reachpad auth login` — get your credential at https://reachpad.dev/connect.",
        numbers: None,
        next_command: Some(SIGN_IN),
        exit_code: EXIT_CREDENTIAL,
        retriable: Retriable::No,
    },
    Row {
        code: "no_authority",
        selector: None,
        sentence: "Nothing proved who is asking. Run `reachpad auth login`, or pass an API key with `--api-key env:<VAR>`.",
        numbers: None,
        next_command: Some(SIGN_IN),
        exit_code: EXIT_CREDENTIAL,
        retriable: Retriable::No,
    },
    // ---- the credential is there and not accepted ------------------------
    Row {
        code: "bad_operator_token",
        selector: None,
        sentence: "That credential was not accepted. Get a fresh one at https://reachpad.dev/connect and run `reachpad auth login`.",
        numbers: None,
        next_command: Some(SIGN_IN),
        exit_code: EXIT_CREDENTIAL,
        retriable: Retriable::No,
    },
    Row {
        code: "operator_token_expired",
        selector: None,
        sentence: "Your credential has expired. Get a fresh one at https://reachpad.dev/connect and run `reachpad auth login`.",
        numbers: None,
        next_command: Some(SIGN_IN),
        exit_code: EXIT_CREDENTIAL,
        retriable: Retriable::No,
    },
    Row {
        code: "operator_token_revoked",
        selector: None,
        sentence: "Your credential was revoked. Get a new one at https://reachpad.dev/connect and run `reachpad auth login`.",
        numbers: None,
        next_command: Some(SIGN_IN),
        exit_code: EXIT_CREDENTIAL,
        retriable: Retriable::No,
    },
    Row {
        code: "operator_token_scoped",
        selector: None,
        sentence: "That credential is scoped to one purpose and cannot drive workspaces. Get a full one at https://reachpad.dev/connect.",
        numbers: None,
        next_command: Some(SIGN_IN),
        exit_code: EXIT_CREDENTIAL,
        retriable: Retriable::No,
    },
    Row {
        code: "scope_required",
        selector: None,
        sentence: "That credential is not scoped for this. Get the right one at https://reachpad.dev/connect.",
        numbers: None,
        next_command: Some(SIGN_IN),
        exit_code: EXIT_CREDENTIAL,
        retriable: Retriable::No,
    },
    Row {
        code: "not_user_identity",
        selector: None,
        sentence: "That credential does not identify a user. Run `reachpad auth login`.",
        numbers: None,
        next_command: Some(SIGN_IN),
        exit_code: EXIT_CREDENTIAL,
        retriable: Retriable::No,
    },
    Row {
        code: "bad_idp_assertion",
        selector: None,
        sentence: "Your sign-in was not accepted. Get a fresh credential at https://reachpad.dev/connect.",
        numbers: None,
        next_command: Some(SIGN_IN),
        exit_code: EXIT_CREDENTIAL,
        retriable: Retriable::No,
    },
    Row {
        code: "bad_token",
        selector: None,
        sentence: "The saved access for {workspace} is unreadable. Run the command again — reachpad mints a fresh one.",
        numbers: None,
        next_command: None,
        exit_code: EXIT_CREDENTIAL,
        retriable: Retriable::Yes,
    },
    Row {
        code: "bad_token_encoding",
        selector: None,
        sentence: "The saved access for {workspace} is unreadable. Run the command again — reachpad mints a fresh one.",
        numbers: None,
        next_command: None,
        exit_code: EXIT_CREDENTIAL,
        retriable: Retriable::Yes,
    },
    Row {
        code: "user_unknown",
        selector: None,
        sentence: "This account is not set up yet. Sign in at https://reachpad.dev/connect first.",
        numbers: None,
        next_command: Some(SIGN_IN),
        exit_code: EXIT_CREDENTIAL,
        retriable: Retriable::No,
    },
    // ---- the credential is fine and does not reach this far --------------
    Row {
        code: "not_authorized",
        selector: None,
        sentence: "Your access to {workspace} does not allow this.",
        numbers: None,
        next_command: None,
        exit_code: EXIT_CREDENTIAL,
        retriable: Retriable::No,
    },
    Row {
        code: "not_owner",
        selector: None,
        sentence: "This needs owner access to {workspace}. Mint the key with `--role owner`, or use the credential from `reachpad auth login`.",
        numbers: None,
        next_command: Some(SIGN_IN),
        exit_code: EXIT_CREDENTIAL,
        retriable: Retriable::No,
    },
    Row {
        // The ports verbs, which is where this refusal is most likely to be
        // read by somebody automating. `--role owner` is the honest advice
        // and it is not the whole story: there is no role between
        // `collaborator` and `owner`, so the key that may publish a port is
        // also the key that may archive the workspace. Saying so here is not
        // a fix — the roles are a frozen lattice (§7.4) and a narrower one
        // needs an ADR — but it stops the remedy reading as free.
        code: "not_owner_port_share",
        selector: None,
        sentence: "Opening or listing a port on {workspace} needs owner access: a link is a capability, and so is the list of them. Mint the key with `--role owner` — noting that an owner key can also archive this workspace, because there is no narrower role today.",
        numbers: None,
        next_command: None,
        exit_code: EXIT_CREDENTIAL,
        retriable: Retriable::No,
    },
    Row {
        // Decided by this client, not by a server: the state route withholds
        // the fencing token from a caller it would not let write, and pause
        // needs write access — NOT owner, which is what the `not_owner`
        // sentence would have sent the user to mint.
        code: "no_write_access",
        selector: None,
        sentence: "Pausing {workspace} needs write access, and this credential can only read it. Use a key minted with `--role collaborator` (or `--role owner`), or ask its owner to share it with `--role collaborator`.",
        numbers: None,
        next_command: None,
        exit_code: EXIT_CREDENTIAL,
        retriable: Retriable::No,
    },
    Row {
        code: "not_workspace_owner",
        selector: None,
        sentence: "This needs owner access to {workspace}. Mint the key with `--role owner`, or use the credential from `reachpad auth login`.",
        numbers: None,
        next_command: Some(SIGN_IN),
        exit_code: EXIT_CREDENTIAL,
        retriable: Retriable::No,
    },
    Row {
        code: "principal_unknown",
        selector: None,
        sentence: "That credential does not name anyone this fleet knows. Run `reachpad auth login` again.",
        numbers: None,
        next_command: Some(SIGN_IN),
        exit_code: EXIT_CREDENTIAL,
        retriable: Retriable::No,
    },
    Row {
        code: "principal_not_of_user",
        selector: None,
        sentence: "That credential belongs to another account. Run `reachpad auth login` again.",
        numbers: None,
        next_command: Some(SIGN_IN),
        exit_code: EXIT_CREDENTIAL,
        retriable: Retriable::No,
    },
    Row {
        code: "not_your_user",
        selector: None,
        sentence: "That credential belongs to another account. Run `reachpad auth login` again.",
        numbers: None,
        next_command: Some(SIGN_IN),
        exit_code: EXIT_CREDENTIAL,
        retriable: Retriable::No,
    },
    // ---- API keys --------------------------------------------------------
    Row {
        code: "api_key_unknown",
        selector: None,
        sentence: "That API key is not known here. Mint one with `reachpad keys mint`.",
        numbers: None,
        next_command: Some("reachpad keys mint"),
        exit_code: EXIT_CREDENTIAL,
        retriable: Retriable::No,
    },
    Row {
        code: "api_key_expired",
        selector: None,
        sentence: "That API key has expired. Mint a new one with `reachpad keys mint`.",
        numbers: None,
        next_command: Some("reachpad keys mint"),
        exit_code: EXIT_CREDENTIAL,
        retriable: Retriable::No,
    },
    Row {
        code: "api_key_revoked",
        selector: None,
        sentence: "That API key was revoked. Mint a new one with `reachpad keys mint`.",
        numbers: None,
        next_command: Some("reachpad keys mint"),
        exit_code: EXIT_CREDENTIAL,
        retriable: Retriable::No,
    },
    Row {
        code: "api_key_out_of_scope",
        selector: None,
        sentence: "That API key does not cover {workspace}. Mint one that names it: `reachpad keys mint --workspace {workspace}`.",
        numbers: None,
        next_command: Some("reachpad keys mint"),
        exit_code: EXIT_CREDENTIAL,
        retriable: Retriable::No,
    },
    Row {
        code: "api_key_lookup_failed",
        selector: None,
        sentence: "reachpad could not check that API key just now. Try again.",
        numbers: None,
        next_command: None,
        exit_code: EXIT_UNAVAILABLE,
        retriable: Retriable::Yes,
    },
    Row {
        code: "unknown_api_key",
        selector: None,
        sentence: "There is no such API key on this account. `reachpad keys list` shows the ones there are.",
        numbers: None,
        next_command: Some("reachpad keys list"),
        exit_code: EXIT_NO_SUCH_WORKSPACE,
        retriable: Retriable::No,
    },
    Row {
        code: "bad_role",
        selector: None,
        sentence: "That is not a role a key can have. Use `--role collaborator` or `--role owner`.",
        numbers: None,
        next_command: None,
        exit_code: EXIT_USAGE,
        retriable: Retriable::No,
    },
    Row {
        // The grant roles are narrower than a key's, because `owner` is not
        // grantable (§7.4). No `--role` is named: ADR-0075 removed the CLI's
        // `share` verb, so the only caller that meets this code is one posting
        // to `/v1/workspaces/:id/shares` directly, and a flag it cannot type
        // sends it looking for a command that is not there.
        code: "invalid_role",
        selector: None,
        sentence: "That is not a role a share can have. A share is `viewer` or `collaborator`; `owner` cannot be granted.",
        numbers: None,
        next_command: None,
        exit_code: EXIT_USAGE,
        retriable: Retriable::No,
    },
    Row {
        // The sharing toggle, refused from either direction (design §4 rule 2):
        // sharing a workspace that holds a link to a connection whose sharing
        // is off, or linking such a connection into an already-shared
        // workspace. Wrong state, not a bad request — the command is well
        // formed and would succeed once the toggle moves.
        code: "sharing_disabled",
        selector: None,
        sentence: "A connection linked to this workspace is not marked shareable, so the workspace cannot be shared. Turn sharing on for that connection, or unlink it, and try again.",
        numbers: None,
        next_command: None,
        exit_code: EXIT_WRONG_STATE,
        retriable: Retriable::No,
    },
    Row {
        // viewer × exposed, refused from either direction (design §7). A
        // viewer can read what the workspace can read, so a connection whose
        // value is visible inside the workspace cannot coexist with one.
        code: "viewer_exposed_conflict",
        selector: None,
        sentence: "A viewer cannot be added while a connection whose value is visible inside the workspace is linked to it. Share with `--role collaborator` instead, or unlink that connection first.",
        numbers: None,
        next_command: None,
        exit_code: EXIT_WRONG_STATE,
        retriable: Retriable::No,
    },
    Row {
        // The same connection is already linked to this workspace. Wrong
        // state, not a bad request: at most one LIVE link per pair, and the
        // existing one already grants what this asked for.
        code: "link_already_live",
        selector: None,
        sentence: "That connection is already linked to this workspace, so there is nothing to add.",
        numbers: None,
        next_command: None,
        exit_code: EXIT_WRONG_STATE,
        retriable: Retriable::No,
    },
    Row {
        // "No such connection" and "not your connection" are ONE answer, so
        // this sentence must fit both without saying which — an id that is not
        // yours must not be distinguishable from one that does not exist.
        code: "connection_not_found",
        selector: None,
        sentence: "No connection or secret by that name on this account.",
        numbers: None,
        next_command: None,
        exit_code: EXIT_NO_SUCH_WORKSPACE,
        retriable: Retriable::No,
    },
    Row {
        code: "share_not_found",
        selector: None,
        sentence: "No share by that id on this workspace. It may already have been revoked.",
        numbers: None,
        next_command: None,
        exit_code: EXIT_NO_SUCH_WORKSPACE,
        retriable: Retriable::No,
    },
    Row {
        code: "link_not_found",
        selector: None,
        sentence: "No link by that id on this workspace. It may already have been revoked.",
        numbers: None,
        next_command: None,
        exit_code: EXIT_NO_SUCH_WORKSPACE,
        retriable: Retriable::No,
    },
    // ---- port shares (ADR-0103) ------------------------------------------
    //
    // The rows land with the routes rather than with the `reachpad ports`
    // verbs that will call them, because `scripts/ci/check-error-table.py`
    // measures the SERVER: a `/v1` handler that can emit a code the table
    // does not carry fails the gate the moment the handler exists, whether or
    // not a CLI verb reaches it yet.
    Row {
        code: "invalid_port",
        selector: None,
        sentence: "That is not a port. Give a number between 1 and 65535 — the port your app is listening on inside the workspace.",
        numbers: None,
        next_command: None,
        exit_code: EXIT_USAGE,
        retriable: Retriable::No,
    },
    Row {
        code: "port_share_not_found",
        selector: None,
        sentence: "That port is not shared on {workspace}. It may already have been revoked.",
        numbers: None,
        next_command: None,
        exit_code: EXIT_NO_SUCH_WORKSPACE,
        retriable: Retriable::No,
    },
    Row {
        // Every edge change takes an idempotency key, because the callers that
        // make them are agents and agents retry.
        code: "idempotency_key_required",
        selector: None,
        sentence: "This change needs an `Idempotency-Key` header of at most 255 characters, so a retry cannot apply it twice.",
        numbers: None,
        next_command: None,
        exit_code: EXIT_USAGE,
        retriable: Retriable::No,
    },
    Row {
        // The same key, a different request. Answering from the stored
        // response would return another request's answer, so it is refused.
        code: "idempotency_key_conflict",
        selector: None,
        sentence: "That idempotency key was already used for a different request. Use a new key for a new change.",
        numbers: None,
        next_command: None,
        exit_code: EXIT_WRONG_STATE,
        retriable: Retriable::No,
    },
    Row {
        // Claimed, never completed: something died between the change and the
        // record of it, so whether it applied is unknown. Retrying the same
        // key would be a guess.
        code: "idempotency_key_in_flight",
        selector: None,
        sentence: "An earlier attempt with that idempotency key never finished, so whether it applied is unknown. Check the current state and use a new key.",
        numbers: None,
        next_command: None,
        exit_code: EXIT_WRONG_STATE,
        retriable: Retriable::No,
    },
    Row {
        // The workspace's access changed, or the machine it runs on was
        // replaced, since the guest's handle was issued.
        code: "handle_stale",
        selector: None,
        sentence: "This workspace credential was issued before the workspace's access last changed, so it is no longer current. Ask for a new one.",
        numbers: None,
        next_command: None,
        exit_code: EXIT_WRONG_STATE,
        retriable: Retriable::No,
    },
    Row {
        // A workspace credential names the machine the workspace is running
        // on, so there is nothing to issue one against. Same wording shape as
        // `no_active_lease`, which is the same fact for a different verb.
        code: "workspace_not_running",
        selector: None,
        sentence: "{workspace} is not running, so there is no live machine to issue a workspace credential for. `reachpad run {workspace} -- <command>` starts it.",
        numbers: None,
        next_command: Some("reachpad run {workspace} -- <command>"),
        exit_code: EXIT_WRONG_STATE,
        retriable: Retriable::No,
    },
    Row {
        code: "workspace_not_of_user",
        selector: None,
        sentence: "One of the workspaces named for this key is not on this account. `reachpad list` shows the ones that are.",
        numbers: None,
        next_command: Some("reachpad list"),
        exit_code: EXIT_NO_SUCH_WORKSPACE,
        retriable: Retriable::No,
    },
    // ---- spawn and link requests (design §7, ADR-0081) -------------------
    Row {
        // A spawn named a connection the parent workspace does not hold a
        // live link to — including one this account owns but never linked
        // here, and one that was linked and has been cut. ONE sentence for
        // all of them, because the server gives one answer: distinguishing
        // them would let a caller inside a guest enumerate the account's
        // locker.
        code: "link_not_held",
        selector: None,
        // `reachpad connections list` was never a verb. The listing of what
        // a workspace holds is `GET /v1/workspaces/:id/links`, and the CLI
        // reaches it through `budget show --workspace`, which prints one line
        // per live link.
        sentence: "That workspace cannot pass down a connection it does not have. `reachpad budget show --workspace {workspace}` lists the links it holds.",
        numbers: None,
        next_command: Some("reachpad budget show --workspace {workspace}"),
        exit_code: EXIT_WRONG_STATE,
        retriable: Retriable::No,
    },
    Row {
        // `--with` takes connections or the word `parent`.
        code: "bad_with",
        selector: None,
        sentence: "`--with` takes a list of connections, or the word `parent` to pass down everything the workspace holds.",
        numbers: None,
        next_command: None,
        exit_code: EXIT_USAGE,
        retriable: Retriable::No,
    },
    Row {
        code: "invalid_connection_name",
        selector: None,
        sentence: "That is not a usable connection name.",
        numbers: None,
        next_command: None,
        exit_code: EXIT_USAGE,
        retriable: Retriable::No,
    },
    Row {
        // Agent prose, bounded at the boundary: the reason lands in a
        // person's inbox.
        code: "reason_too_long",
        selector: None,
        sentence: "That reason is too long to put in front of the person who has to read it. Shorten it and ask again.",
        numbers: None,
        next_command: None,
        exit_code: EXIT_USAGE,
        retriable: Retriable::No,
    },
    Row {
        code: "invalid_decision",
        selector: None,
        sentence: "A request is answered `approve` or `deny`.",
        numbers: None,
        next_command: None,
        exit_code: EXIT_USAGE,
        retriable: Retriable::No,
    },
    Row {
        // Two people answered one request. Wrong state, not a bad request:
        // the answer already exists and the body carries it.
        code: "link_request_decided",
        selector: None,
        sentence: "That request has already been answered.",
        numbers: None,
        next_command: None,
        exit_code: EXIT_WRONG_STATE,
        retriable: Retriable::No,
    },
    // ---- no such thing ---------------------------------------------------
    Row {
        // "No such request" and "not a request on a workspace you own" are
        // ONE answer: the id is read before the caller is authorized, so this
        // sentence must fit both without saying which.
        code: "link_request_not_found",
        selector: None,
        sentence: "No credential request by that id.",
        numbers: None,
        next_command: None,
        exit_code: EXIT_NO_SUCH_WORKSPACE,
        retriable: Retriable::No,
    },
    Row {
        code: "workspace_not_found",
        selector: None,
        sentence: "There is no workspace {workspace} on this account. `reachpad list` shows the ones there are.",
        numbers: None,
        next_command: Some("reachpad list"),
        exit_code: EXIT_NO_SUCH_WORKSPACE,
        retriable: Retriable::No,
    },
    Row {
        // `share --grantee`: a mistyped principal is the ordinary case, so it
        // says which half of the command to look at.
        code: "grantee_unknown",
        selector: None,
        sentence: "There is no such principal on this fleet, so {workspace} was not shared. Check the id given to `--grantee`.",
        numbers: None,
        next_command: None,
        exit_code: EXIT_NO_SUCH_WORKSPACE,
        retriable: Retriable::No,
    },
    Row {
        code: "snapshot_not_found",
        selector: None,
        sentence: "That save does not exist. `reachpad status {workspace}` shows the one {workspace} resumes from.",
        numbers: None,
        next_command: Some("reachpad status {workspace}"),
        exit_code: EXIT_NO_SUCH_WORKSPACE,
        retriable: Retriable::No,
    },
    Row {
        code: "snapshot_not_of_workspace",
        selector: None,
        sentence: "That save belongs to another workspace.",
        numbers: None,
        next_command: Some("reachpad status {workspace}"),
        exit_code: EXIT_WRONG_STATE,
        retriable: Retriable::No,
    },
    Row {
        code: "operator_token_not_found",
        selector: None,
        sentence: "That credential is no longer on this account.",
        numbers: None,
        next_command: Some(SIGN_IN),
        exit_code: EXIT_NO_SUCH_WORKSPACE,
        retriable: Retriable::No,
    },
    // ---- wrong state -----------------------------------------------------
    Row {
        // 409 from attach, 410 from run: one fact, two statuses.
        code: "workspace_archived",
        selector: None,
        sentence: "{workspace} is archived. Fork it to work from its last save: `reachpad fork {workspace}`.",
        numbers: None,
        next_command: Some("reachpad fork {workspace}"),
        exit_code: EXIT_WRONG_STATE,
        retriable: Retriable::No,
    },
    Row {
        // I7: sharing is gated on the redaction filter being on, and the gate
        // refuses the share rather than trusting later enforcement.
        code: "redaction_filter_disabled",
        selector: None,
        sentence: "{workspace} cannot be shared while its redaction filter is off.",
        numbers: None,
        next_command: None,
        exit_code: EXIT_WRONG_STATE,
        retriable: Retriable::No,
    },
    Row {
        code: "lease_held",
        selector: None,
        sentence: "{workspace} is running on another node. Pause it first: `reachpad pause {workspace}`.",
        numbers: Some("It is held by {holder_node}."),
        next_command: Some("reachpad pause {workspace}"),
        exit_code: EXIT_WRONG_STATE,
        retriable: Retriable::No,
    },
    Row {
        // Also the answer for a workspace that has never started. NOT the
        // `no_sealed_snapshot` sentence: that one says there is nothing to
        // fork from, and a fork child that has never run IS forkable.
        code: "no_active_lease",
        selector: None,
        sentence: "{workspace} is not running, so there is nothing to save. `reachpad run {workspace} -- <command>` starts it.",
        numbers: None,
        next_command: Some("reachpad run {workspace} -- <command>"),
        exit_code: EXIT_WRONG_STATE,
        retriable: Retriable::No,
    },
    Row {
        code: "stale_fencing_token",
        selector: None,
        sentence: "Something else took over {workspace} while this command was running. Run `reachpad status {workspace}` and try again.",
        numbers: None,
        next_command: Some("reachpad status {workspace}"),
        exit_code: EXIT_WRONG_STATE,
        retriable: Retriable::Yes,
    },
    Row {
        code: "no_sealed_snapshot",
        selector: None,
        sentence: "{workspace} has never been saved, so there is nothing to fork from. `reachpad pause {workspace}` saves it now.",
        numbers: None,
        next_command: Some("reachpad pause {workspace}"),
        exit_code: EXIT_WRONG_STATE,
        retriable: Retriable::No,
    },
    Row {
        code: "workspace_stopping",
        selector: None,
        sentence: "{workspace} is saving on its way down.",
        numbers: Some("Try again in about {retry_after_s}s."),
        next_command: Some("reachpad status {workspace}"),
        exit_code: EXIT_WRONG_STATE,
        retriable: Retriable::Yes,
    },
    Row {
        code: "already_at_snapshot",
        selector: None,
        sentence: "{workspace} already resumes from that save.",
        numbers: None,
        next_command: None,
        exit_code: EXIT_WRONG_STATE,
        retriable: Retriable::No,
    },
    Row {
        code: "not_an_earlier_snapshot",
        selector: None,
        sentence: "That save is not earlier than the one {workspace} resumes from now.",
        numbers: None,
        next_command: Some("reachpad status {workspace}"),
        exit_code: EXIT_WRONG_STATE,
        retriable: Retriable::No,
    },
    // ---- GitHub coverage (INT-171) ---------------------------------------
    //
    // All three are EXIT_WRONG_STATE, not EXIT_CREDENTIAL: the credential this
    // command presented is fine and re-signing in would change nothing. What
    // is missing is an App installation on a GitHub account, which is a state
    // somebody changes on GitHub — the same shape as `sharing_disabled`.
    Row {
        // `create --repo` passes what it was given through verbatim and lets
        // controld normalize it, so this is the one github row that is a
        // TYPO rather than a state: the account is fine, the connection is
        // fine, and what arrived is not a repository.
        code: "bad_repo",
        selector: None,
        sentence: "That is not a repository reachpad can read. Give it as `org/name`, or paste the GitHub URL.",
        numbers: None,
        next_command: None,
        exit_code: EXIT_USAGE,
        retriable: Retriable::No,
    },
    Row {
        // The org and the link are the SERVER's to say (I13). A client that
        // composed either URL would send people to whichever App its own
        // constant named, which on a self-hosted fleet is the wrong one.
        //
        // THE LINK IS `connect_url`, NOT `install_url`, and the difference is
        // the difference between a remedy and a loop: installing the App
        // creates an installation and no GRANT, and coverage needs both — so
        // somebody sent to GitHub's install screen installs, retries, and is
        // refused again by the same predicate. The webapp's ceremony is the
        // door that produces both. `install_url` is still in the body for
        // consumers that want the raw screen; this row does not use it.
        //
        // The link lives in `numbers` rather than the sentence because `fill`
        // drops that clause whole when a field is missing while an
        // unrenderable SENTENCE degrades to nothing at all: against a fleet
        // that predates `connect_url` this row still says what happened, and
        // `next_command` below carries the remedy.
        code: "github_not_installed",
        selector: None,
        sentence: "Reachpad is not installed on that GitHub account, so it cannot reach those repositories.",
        numbers: Some("Connect it for {org} at {connect_url}, then retry."),
        next_command: Some("reachpad connect github"),
        exit_code: EXIT_WRONG_STATE,
        retriable: Retriable::No,
    },
    Row {
        // The installation is still there; this account's join to it is not.
        // Reconnecting is the whole remedy, and it does not touch GitHub.
        code: "github_grant_revoked",
        selector: None,
        sentence: "Your GitHub connection was disconnected, so Reachpad can no longer reach those repositories.",
        numbers: Some("Connect it again at {connect_url}."),
        next_command: Some("reachpad connect github"),
        exit_code: EXIT_WRONG_STATE,
        retriable: Retriable::No,
    },
    Row {
        // Suspension is GitHub's own switch, so reconnecting here would not
        // move it: the remedy is in GitHub's settings and this row says so
        // rather than naming a reachpad command that cannot help.
        code: "github_installation_suspended",
        selector: None,
        sentence: "Reachpad's GitHub install is suspended, so it cannot reach those repositories. Unsuspend it in GitHub's settings, then retry.",
        numbers: Some("It is suspended on {org}."),
        next_command: None,
        exit_code: EXIT_WRONG_STATE,
        retriable: Retriable::No,
    },
    // ---- limits ----------------------------------------------------------
    Row {
        code: "entitlement_limit",
        selector: Some(("limit", "max_workspaces")),
        sentence: "You are at your workspace limit. Archive one you are done with: `reachpad archive <id>`.",
        numbers: Some("You have {live_workspaces} of {max_workspaces}."),
        next_command: Some("reachpad archive <id>"),
        exit_code: EXIT_LIMIT,
        retriable: Retriable::No,
    },
    Row {
        code: "entitlement_limit",
        selector: Some(("limit", "max_concurrent")),
        // "or wait" is gone with idle auto-pause (unlimited during beta): a
        // workspace runs until its owner pauses it, so waiting frees nothing
        // and the advice would strand the reader.
        sentence: "You are at your limit of workspaces running at once. Pause one to free a slot.",
        numbers: Some("{active_leases} of {max_concurrent} are running."),
        next_command: Some("reachpad pause <id>"),
        exit_code: EXIT_LIMIT,
        retriable: Retriable::Yes,
    },
    Row {
        code: "entitlement_limit",
        selector: None,
        sentence: "You are at an account limit. `reachpad auth whoami` shows your limits.",
        numbers: None,
        next_command: Some("reachpad auth whoami"),
        exit_code: EXIT_LIMIT,
        retriable: Retriable::No,
    },
    // ---- budgets and ceilings (creds milestone C5, design §9) ------------
    Row {
        // THE distinguishable exhaustion. Design §9 is explicit that this must
        // not be a bare 429: an agent told only "later" cannot tell a ceiling
        // that resets in a minute from one that resets in three weeks, and
        // will retry until it is rate-limited for a different reason. The
        // numbers clause names the scope and the ceiling, both read off the
        // wire (I13).
        //
        // `EXIT_LIMIT` (6), the same class as `entitlement_limit`: the
        // platform gave you an amount and you used it.
        code: "cap_exhausted",
        selector: None,
        sentence: "This workspace has spent its model budget for the period. Raise the ceiling with `reachpad budget ceiling`, or wait for the period to roll over.",
        numbers: Some("{scope} {scope_id}: {spent_micros} of {cap_micros} micro-dollars spent."),
        next_command: Some("reachpad budget show"),
        exit_code: EXIT_LIMIT,
        retriable: Retriable::No,
    },
    Row {
        // The account-wide stop. Wrong state rather than a limit: nothing is
        // exhausted, somebody pulled the switch, and the remedy is a person.
        code: "kill_switch_engaged",
        selector: None,
        sentence: "This account's kill switch is engaged: nothing starts and nothing spends until it is released. Run `reachpad kill-switch release` to allow spend again.",
        numbers: None,
        next_command: Some("reachpad kill-switch release"),
        exit_code: EXIT_WRONG_STATE,
        retriable: Retriable::No,
    },
    Row {
        // The narrowing law applied to money: a spawned child's per-link cap
        // may not exceed its parent's. Both numbers are in the body, so the
        // agent that hit it can retry with one that fits instead of guessing.
        code: "budget_exceeds_parent",
        selector: None,
        sentence: "A spawned workspace cannot be given a bigger budget than the one that spawned it. Ask for the parent's cap or less.",
        numbers: Some("Asked for {requested_micros} micro-dollars; the parent's cap is {parent_micros}."),
        next_command: None,
        exit_code: EXIT_USAGE,
        retriable: Retriable::No,
    },
    Row {
        // C3's link-request row already holds the selector-less `reason_too_long`,
        // and `row()` returns the FIRST selector-less match — so a second bare
        // row here would be unreachable prose and the owner of a stopped
        // account would be told to "ask again", which is not what a kill
        // switch does. The route therefore names which limit it hit, exactly
        // as `entitlement_limit` does, and this row is selected on it.
        code: "reason_too_long",
        selector: Some(("limit", "kill_switch_reason")),
        sentence: "That reason is too long. Keep it under 1024 bytes and pull the switch again.",
        numbers: Some("You sent {presented_bytes} bytes; the limit is {limit_bytes}."),
        next_command: None,
        exit_code: EXIT_USAGE,
        retriable: Retriable::No,
    },
    Row {
        // Trap 41's posture for the C5 verbs: refuse and name the redeploy,
        // never a silent downgrade. A `budget show` that printed zeroes
        // against an older controld would be a client inventing a number, and
        // a `kill-switch engage` that answered `ok` would be a safety feature
        // reporting success while nothing stopped.
        code: "fleet_predates_budgets",
        selector: None,
        sentence: "This fleet has no budget or kill-switch routes yet, and reachpad will not guess an answer for them. Wait for it to be redeployed.",
        numbers: None,
        next_command: None,
        exit_code: EXIT_UNAVAILABLE,
        retriable: Retriable::No,
    },
    Row {
        // The echo check (ADR-0079 §4). The call succeeded and the server
        // reported a different cap than the one asked for — which is a fleet
        // that accepted the request and did something else with it.
        code: "cap_not_applied",
        selector: None,
        sentence: "The fleet accepted that cap and reported a different one, so nothing here can say what {workspace} is limited to. Run `reachpad budget show --workspace {workspace}`.",
        numbers: None,
        next_command: Some("reachpad budget show --workspace {workspace}"),
        exit_code: EXIT_UNAVAILABLE,
        retriable: Retriable::No,
    },
    Row {
        // Not /pricing. That page publishes the free preview and nothing else
        // (the paid tier is deliberately withheld until its rate and purchase
        // path settle), so sending an account with no allowance there is a
        // dead end. /docs/billing names this address for the same reason.
        code: "no_entitlement",
        selector: None,
        sentence: "This account has no workspace allowance. Write to seiji@reachpad.dev to have one set up.",
        numbers: None,
        next_command: Some("reachpad auth whoami"),
        exit_code: EXIT_LIMIT,
        retriable: Retriable::No,
    },
    Row {
        // The refusal body's `balance_credits` is a server-side constant 0,
        // not a reading — so this row states no balance.
        code: "credits_exhausted",
        selector: None,
        // Top-ups are handled by hand during the preview; there is nothing to
        // buy on /pricing. Same address as `no_entitlement` above and as
        // /docs/billing, so the three cannot drift apart.
        sentence: "Out of compute credits. Write to seiji@reachpad.dev to top up.",
        numbers: None,
        next_command: Some("reachpad auth whoami"),
        exit_code: EXIT_LIMIT,
        retriable: Retriable::No,
    },
    Row {
        code: "exec_concurrency_exceeded",
        selector: None,
        sentence: "{workspace} is already running as many commands at once as it may.",
        numbers: Some("{running} of {exec_max_concurrent} are running."),
        next_command: None,
        exit_code: EXIT_LIMIT,
        retriable: Retriable::Yes,
    },
    // ---- unavailable -----------------------------------------------------
    Row {
        code: "no_capacity",
        selector: None,
        sentence: "The fleet has no room for {workspace} right now.",
        numbers: None,
        next_command: None,
        exit_code: EXIT_UNAVAILABLE,
        retriable: Retriable::WhenCauseTransient,
    },
    Row {
        code: "core_state_contended",
        selector: None,
        sentence: "reachpad is busy coordinating this account. Try again.",
        numbers: None,
        next_command: None,
        exit_code: EXIT_UNAVAILABLE,
        retriable: Retriable::Yes,
    },
    Row {
        code: "placement_incomplete",
        selector: None,
        sentence: "reachpad could not finish starting {workspace}. Try again.",
        numbers: None,
        next_command: None,
        exit_code: EXIT_UNAVAILABLE,
        retriable: Retriable::Yes,
    },
    Row {
        code: "control_upstream_unavailable",
        selector: None,
        sentence: "reachpad's control plane is not answering right now. Try again.",
        numbers: None,
        next_command: None,
        exit_code: EXIT_UNAVAILABLE,
        retriable: Retriable::Yes,
    },
    // ---- the model gateway, which is a SECOND upstream behind the same
    // front door (ADR-0083). Its two failures are deliberately distinct: one
    // says the fleet has no gateway, the other says the gateway it has is
    // down. Collapsing them would leave an operator reading a journal unable
    // to tell a missing deploy from a crashed one.
    Row {
        code: "llm_upstream_unavailable",
        selector: None,
        sentence: "reachpad's model gateway is not answering right now. Try again.",
        numbers: None,
        next_command: None,
        exit_code: EXIT_UNAVAILABLE,
        retriable: Retriable::Yes,
    },
    Row {
        code: "llm_use_point_not_configured",
        selector: None,
        sentence: "This fleet does not run model calls for you — it has no gateway deployed. \
                   Use your own provider key in this workspace instead.",
        numbers: None,
        next_command: None,
        exit_code: EXIT_UNAVAILABLE,
        retriable: Retriable::No,
    },
    // ---- the git use-point, which is a THIRD upstream behind that same
    // front door (INT-171, on ADR-0083's terms). The pair below splits the
    // same way the gateway's does, and for the same reason. What a person
    // usually meets is `git` printing the status line itself — these
    // sentences exist because the table is the fleet's one vocabulary for a
    // code, not because `reachpad` is the common way to reach them.
    Row {
        code: "git_upstream_unavailable",
        selector: None,
        sentence: "reachpad's git use-point is not answering right now, so clones and pushes through this workspace will fail. Try again.",
        numbers: None,
        next_command: None,
        exit_code: EXIT_UNAVAILABLE,
        retriable: Retriable::Yes,
    },
    Row {
        code: "git_use_point_not_configured",
        selector: None,
        sentence: "This fleet does not carry github.com traffic for you — it has no git use-point deployed. Use your own GitHub credentials in this workspace instead.",
        numbers: None,
        next_command: None,
        exit_code: EXIT_UNAVAILABLE,
        retriable: Retriable::No,
    },
    Row {
        code: "internal",
        selector: None,
        sentence: "reachpad hit an error on its side. Try again; if it persists, report it at https://reachpad.dev.",
        numbers: None,
        next_command: None,
        exit_code: EXIT_UNAVAILABLE,
        retriable: Retriable::Yes,
    },
    // ---- the request itself ----------------------------------------------
    Row {
        code: "empty_argv",
        selector: None,
        sentence: "No command was given to run. Put it after `--`: `reachpad run {workspace} -- <command>`.",
        numbers: None,
        next_command: None,
        exit_code: EXIT_USAGE,
        retriable: Retriable::No,
    },
    Row {
        code: "control_request_too_large",
        selector: None,
        sentence: "That request is too large for reachpad's front door — `--stdin` carries about 1 MiB.",
        numbers: None,
        next_command: None,
        exit_code: EXIT_USAGE,
        retriable: Retriable::No,
    },
    Row {
        // The model gateway's own cap, which is thirty-two times the control
        // plane's: a prompt is not a control request (ADR-0083).
        code: "llm_request_too_large",
        selector: None,
        sentence: "That model request is too large for reachpad's front door — it carries about 32 MiB. Send less context.",
        numbers: None,
        next_command: None,
        exit_code: EXIT_USAGE,
        retriable: Retriable::No,
    },
    Row {
        // And the git use-point's, which is a thousand times the control
        // plane's: a first push is the size of the work somebody did.
        code: "git_request_too_large",
        selector: None,
        sentence: "That push is too large for reachpad's front door — it carries about 1 GiB. Push it in smaller pieces.",
        numbers: None,
        next_command: None,
        exit_code: EXIT_USAGE,
        retriable: Retriable::No,
    },
    Row {
        code: "malformed_control_request",
        selector: None,
        sentence: "reachpad's front door could not read that request.",
        numbers: None,
        next_command: None,
        exit_code: EXIT_USAGE,
        retriable: Retriable::No,
    },
    Row {
        // The axum extractors refuse a body before any handler runs, so this
        // one arrives WITHOUT the `{"error":…}` shape every other row has.
        code: "request_not_understood",
        selector: None,
        sentence: "This fleet could not read reachpad's request. Update the CLI (`reachpad --version`), or the fleet is older than it.",
        numbers: None,
        next_command: None,
        exit_code: EXIT_USAGE,
        retriable: Retriable::No,
    },
    // ---- a command that started and whose result was lost ----------------
    Row {
        code: "node_gone",
        selector: None,
        sentence: "reachpad accepted the command for {workspace} and lost its result — whether it ran is unknown; it may never have started.",
        numbers: None,
        next_command: Some("reachpad events {workspace}"),
        exit_code: EXIT_LOST_RESULT,
        retriable: Retriable::No,
    },
    Row {
        code: "exec_deadline_exceeded",
        selector: None,
        sentence: "The command on {workspace} hit its timeout and was killed. Give it longer with `--timeout`.",
        numbers: None,
        next_command: None,
        exit_code: EXIT_LOST_RESULT,
        retriable: Retriable::No,
    },
    Row {
        code: "client_deadline_exceeded",
        selector: None,
        sentence: "reachpad stopped waiting for {workspace} before the fleet answered — whether the command ran is unknown.",
        numbers: None,
        next_command: Some("reachpad events {workspace}"),
        exit_code: EXIT_LOST_RESULT,
        retriable: Retriable::No,
    },
    // ---- a wait this client gave up on -----------------------------------
    Row {
        // Distinct from `wait_timeout` on purpose: a workspace still sealing
        // is working, and saying "gave up waiting" about it reads as a
        // failure it is not. The seal budget is the server's, not ours.
        code: "still_sealing",
        selector: None,
        sentence: "{workspace} is still saving.",
        numbers: Some("It has been saving for {waited_s}s."),
        next_command: Some("reachpad status {workspace}"),
        exit_code: EXIT_UNAVAILABLE,
        retriable: Retriable::Yes,
    },
    Row {
        // `connect github` waiting on a ceremony that happens somewhere else.
        // Retriable, and it says so: installing the App on an organization can
        // need an owner's approval, which arrives on nobody's schedule, and
        // re-running the command picks it up whenever it lands. Nothing was
        // lost by giving up — the browser half finishes without this process.
        code: "github_connect_timeout",
        selector: None,
        sentence: "Gave up waiting for GitHub. Finish the install in your browser, then run `reachpad connect github` again — it prints what is connected.",
        numbers: Some("It was still not connected after {waited_s}s."),
        next_command: Some("reachpad connect github"),
        exit_code: EXIT_UNAVAILABLE,
        retriable: Retriable::Yes,
    },
    Row {
        code: "wait_timeout",
        selector: None,
        sentence: "Gave up waiting for {workspace}.",
        numbers: Some("It was {state} after {waited_s}s, not {target}."),
        next_command: Some("reachpad status {workspace}"),
        exit_code: EXIT_UNAVAILABLE,
        retriable: Retriable::Yes,
    },
    // ---- a fleet older than this CLI (deployment skew) --------------------
    Row {
        // hub's answer for a path it does not forward. `api::is_route_absent`
        // turns it into the fallback each verb has one for; this row is the
        // sentence for the verbs that have none.
        code: "not_found",
        selector: None,
        sentence: "This fleet has no such endpoint: it is older than this CLI. Redeploy the fleet, or run an older reachpad against it.",
        numbers: None,
        next_command: None,
        exit_code: EXIT_UNAVAILABLE,
        retriable: Retriable::No,
    },
    Row {
        // A notice, not a refusal: the command still runs, with less to say.
        // Emitted once per command.
        code: "fleet_older_than_cli",
        selector: None,
        sentence: "This fleet is older than this CLI: it cannot report a workspace's state directly, so some fields read `unknown`.",
        numbers: None,
        next_command: None,
        exit_code: EXIT_OK,
        retriable: Retriable::No,
    },
    Row {
        code: "fleet_predates_pause",
        selector: None,
        sentence: "This fleet predates one-call pause, so reachpad will not guess how to stop {workspace}. Run `reachpad status {workspace}` once it is redeployed.",
        numbers: None,
        next_command: Some("reachpad status {workspace}"),
        exit_code: EXIT_UNAVAILABLE,
        retriable: Retriable::No,
    },
    Row {
        // A fleet with no state route cannot say when a workspace reaches a
        // state, so a `--wait` against it could only poll toward an answer
        // that never comes. Refused at once, and never reported as a wait
        // that succeeded.
        code: "fleet_predates_wait",
        selector: None,
        sentence: "This fleet cannot report a workspace's state, so `--wait` would never see {workspace} change. Run the command without `--wait`, or wait for the fleet to be redeployed.",
        numbers: None,
        next_command: None,
        exit_code: EXIT_UNAVAILABLE,
        retriable: Retriable::No,
    },
    Row {
        // ADR-0079 §4 for `reachpad ports`: the verb ships with its route and
        // refuses against a fleet that predates it. Decided by the CLI, from
        // two wire shapes — no such route (a bare 404), and an answer that
        // does not echo the port it acted on (trap 41). Neither is degradable:
        // what this verb prints is a link its user is about to send to another
        // person, and a link that reaches nothing is worse than a refusal.
        code: "fleet_predates_port_shares",
        selector: None,
        sentence: "This fleet cannot open a port on {workspace}: it is older than this CLI. Ask for it to be redeployed, or run an older reachpad against it.",
        numbers: None,
        next_command: None,
        exit_code: EXIT_UNAVAILABLE,
        retriable: Retriable::No,
    },
    Row {
        // ADR-0079 §4 again, for `reachpad connect github`: the verb ships
        // with its route and refuses against a fleet that predates it. A fleet
        // without the route answers a bare 404, which reads as "the fleet
        // refused this: unknown" unless it is named here — and the remedy for
        // it has nothing to do with GitHub.
        code: "fleet_predates_github",
        selector: None,
        sentence: "This fleet cannot connect GitHub: it is older than this CLI. Ask for it to be redeployed, or run an older reachpad against it.",
        numbers: None,
        next_command: None,
        exit_code: EXIT_UNAVAILABLE,
        retriable: Retriable::No,
    },
    Row {
        code: "fleet_predates_replay",
        selector: None,
        sentence: "This fleet cannot replay past events, and reachpad will not show a live stream as if it were the replay you asked for. Run `reachpad events {workspace}` without `--since`.",
        numbers: None,
        next_command: Some("reachpad events {workspace}"),
        exit_code: EXIT_UNAVAILABLE,
        retriable: Retriable::No,
    },
    // ---- the WORKSPACE ran out of room, not the command ------------------
    Row {
        // WP-CP.4. Emitted by the node on `exec.end` when the guest's own
        // `statvfs` says the filesystem the command was working on is full AND
        // the command did not succeed. Before this existed the user read a
        // linker SIGBUS or rustc's "No space left on device" and went looking
        // for a toolchain bug.
        //
        // `EXIT_LIMIT` (6), the same class as `entitlement_limit`, because it
        // is the same kind of answer: the platform gave you an amount of
        // something and you have reached it. It is NOT `EXIT_WRONG_STATE` —
        // nothing is wrong with the workspace's state, it is simply full.
        code: "workspace_disk_full",
        selector: None,
        sentence: "{workspace} ran out of disk while this command was running, so what \
                   it reported may be a symptom rather than the cause. Free some space, \
                   or start a bigger workspace — an existing disk is never grown.",
        numbers: Some("{disk_path} has {disk_free_h} free of {disk_total_h}."),
        next_command: Some("reachpad run {workspace} -- df -h"),
        exit_code: EXIT_LIMIT,
        retriable: Retriable::No,
    },
];

/// `no_capacity` causes that a later attempt could see differently
/// (`scheduler::why_no_capacity`). The rest describe a fleet that does not
/// serve this workspace at all, and retrying only wastes the user's time.
const TRANSIENT_CAPACITY_CAUSES: &[&str] = &[
    "all_full",
    "all_draining_or_cordoned",
    "reserved_for_other_users",
    "unknown",
];

/// The row for `code`, preferring one whose selector matches the body.
pub fn row(code: &str, body: &Value) -> Option<&'static Row> {
    let mut fallback = None;
    for row in TABLE {
        if row.code != code {
            continue;
        }
        match row.selector {
            Some((field, value)) => {
                if body.get(field).and_then(Value::as_str) == Some(value) {
                    return Some(row);
                }
            }
            None => fallback = fallback.or(Some(row)),
        }
    }
    fallback
}

/// A rendered refusal: what to say, what it means, and what to exit with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliError {
    pub code: String,
    pub message: String,
    pub next_command: Option<String>,
    pub retriable: bool,
    pub status: Option<u16>,
    pub exit_code: i32,
    /// What the command DID before it was refused, when that is something a
    /// caller has to know about — `fork --count`'s children, which exist and
    /// hold slots whether or not the fan-out finished. `None` on every
    /// refusal that changed nothing, which is nearly all of them.
    pub data: Option<Value>,
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CliError {}

impl From<anyhow::Error> for CliError {
    /// Anything the table does not know about is a local failure: it has a
    /// sentence of its own already, and no exit code more specific than 1.
    fn from(err: anyhow::Error) -> CliError {
        CliError {
            code: "reachpad_error".to_owned(),
            message: format!("{err:#}"),
            next_command: None,
            retriable: false,
            status: None,
            exit_code: 1,
            data: None,
        }
    }
}

impl CliError {
    /// A usage refusal decided locally, before anything left this machine.
    pub fn usage(message: impl Into<String>) -> CliError {
        CliError {
            code: "usage".to_owned(),
            message: message.into(),
            next_command: None,
            retriable: false,
            status: None,
            exit_code: EXIT_USAGE,
            data: None,
        }
    }

    /// A table row by code alone — for the refusals the client decides itself
    /// (a missing credential, a fleet too old for the command).
    pub fn from_code(code: &str, workspace: Option<&str>) -> CliError {
        CliError::from_body(code, &Value::Null, workspace)
    }

    /// A table row whose numbers this CLI knows rather than the server — how
    /// long a `--wait` waited, and what it was waiting for. The rule is
    /// unchanged: a clause renders only when every field it names is present.
    pub fn from_body(code: &str, body: &Value, workspace: Option<&str>) -> CliError {
        CliError::render(code, body, None, workspace)
            .unwrap_or_else(|| CliError::unnamed(code, None, None, 1))
    }

    pub fn from_api(err: &ApiError, workspace: Option<&str>) -> CliError {
        match err {
            ApiError::Api {
                status,
                code,
                detail,
                body,
            } => CliError::render(code, body, Some(*status), workspace).unwrap_or_else(|| {
                // No row: say exactly what the server said rather than
                // paraphrase a code this CLI does not know.
                CliError::unnamed(code, detail.as_deref(), Some(*status), 1)
            }),
            ApiError::Deadline => CliError::from_code("client_deadline_exceeded", workspace),
            ApiError::Transport(message) | ApiError::Shape(message) => CliError {
                code: "reachpad_error".to_owned(),
                message: message.clone(),
                next_command: None,
                retriable: false,
                status: None,
                exit_code: 1,
                data: None,
            },
        }
    }

    /// The terminal `exec.end` of a run that carried an `error` instead of an
    /// exit code.
    pub fn from_exec_end(end: &Value, workspace: Option<&str>) -> CliError {
        let code = end
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("node_gone");
        CliError::render(code, end, None, workspace).unwrap_or_else(|| {
            CliError::unnamed(
                code,
                end.get("detail").and_then(Value::as_str),
                None,
                EXIT_LOST_RESULT,
            )
        })
    }

    /// The **advisory** reading of an `exec.end` (WP-CP.4): the sentence for a
    /// workspace condition that did NOT cause this command to fail.
    ///
    /// Separate from [`CliError::from_exec_end`] on purpose. That one turns a
    /// frame into a failure and an exit code; this one only borrows the
    /// sentence, because the command succeeded and its zero is the answer the
    /// caller gets. Returns `None` when the frame carries no condition, which
    /// is every frame from a healthy workspace and every frame from a guest
    /// that predates the capability.
    #[must_use]
    pub fn workspace_condition(end: &Value, workspace: Option<&str>) -> Option<String> {
        let code = end.get("workspace_condition").and_then(Value::as_str)?;
        CliError::render(code, end, None, workspace).map(|e| e.message)
    }

    /// A code with no row: the server's own words, and no claim about what it
    /// means beyond the exit code the caller decided.
    fn unnamed(code: &str, detail: Option<&str>, status: Option<u16>, exit_code: i32) -> CliError {
        CliError {
            code: code.to_owned(),
            message: match detail {
                Some(detail) => format!("{code}: {detail}"),
                None => format!("the fleet refused this: {code}"),
            },
            next_command: None,
            retriable: false,
            status,
            exit_code,
            data: None,
        }
    }

    fn render(
        code: &str,
        body: &Value,
        status: Option<u16>,
        workspace: Option<&str>,
    ) -> Option<CliError> {
        let row = row(code, body)?;
        let mut message = fill(row.sentence, body, workspace).unwrap_or_else(|| {
            fill(row.sentence, body, Some("this workspace")).unwrap_or_default()
        });
        if let Some(numbers) = row.numbers.and_then(|n| fill(n, body, workspace)) {
            message.push(' ');
            message.push_str(&numbers);
        }
        Some(CliError {
            code: code.to_owned(),
            message,
            next_command: row.next_command.and_then(|c| fill(c, body, workspace)),
            retriable: match row.retriable {
                Retriable::No => false,
                Retriable::Yes => true,
                Retriable::WhenCauseTransient => body
                    .get("cause")
                    .and_then(Value::as_str)
                    .is_some_and(|cause| TRANSIENT_CAPACITY_CAUSES.contains(&cause)),
            },
            status,
            exit_code: row.exit_code,
            data: None,
        })
    }

    /// `{"ok":false,…}` — the machine-readable half of the same refusal.
    /// `data` appears only when the refused command changed something first.
    pub fn envelope(&self, command: &str) -> Value {
        let mut out = json!({
            "ok": false,
            "command": command,
            "error": {
                "code": self.code,
                "message": self.message,
                "retriable": self.retriable,
                "next_command": self.next_command,
                "status": self.status,
            }
        });
        if let Some(data) = &self.data {
            out["data"] = data.clone();
        }
        out
    }
}

/// `{"ok":true,…}` — every command's `--json` success line.
pub fn ok_envelope(command: &str, data: Value) -> Value {
    json!({ "ok": true, "command": command, "data": data })
}

/// Substitute `{field}` from the refusal body, plus `{workspace}` which the
/// client knows. `None` when any field is absent — that is what keeps a
/// sentence from claiming a number the server did not send.
fn fill(template: &str, body: &Value, workspace: Option<&str>) -> Option<String> {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let close = rest[open..].find('}')? + open;
        let name = &rest[open + 1..close];
        out.push_str(&field(name, body, workspace)?);
        rest = &rest[close + 1..];
    }
    out.push_str(rest);
    Some(out)
}

fn field(name: &str, body: &Value, workspace: Option<&str>) -> Option<String> {
    if name == "workspace" {
        return workspace.map(str::to_owned);
    }
    // The one derived field: a wait a person can read, from the milliseconds
    // the server sends.
    if name == "retry_after_s" {
        let ms = body.get("retry_after_ms")?.as_u64()?;
        return Some(ms.div_ceil(1000).to_string());
    }
    // `{disk_free_h}` renders the body's `disk_free_bytes` in the units a
    // `df` inside the guest agrees with. The server keeps sending bytes (I13:
    // the number comes from the wire, and a byte count is the fact); turning
    // 214748364 into "204 MiB" is presentation, and presentation is the
    // client's. Absent the byte field, the whole `numbers` clause disappears
    // rather than rendering a blank — same rule as every other substitution.
    if let Some(stem) = name.strip_suffix("_h") {
        let bytes = body.get(format!("{stem}_bytes"))?.as_u64()?;
        return Some(crate::render::gib(bytes));
    }
    match body.get(name)? {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every refusal in these tests has a row; a code with none is its own
    /// test below.
    fn render(code: &str, body: &Value, status: Option<u16>, workspace: Option<&str>) -> CliError {
        CliError::render(code, body, status, workspace).expect("the table has a row for this code")
    }

    #[test]
    fn every_row_is_renderable_and_carries_a_semantic_exit_code() {
        let allowed = [
            EXIT_OK,
            EXIT_USAGE,
            EXIT_CREDENTIAL,
            EXIT_NO_SUCH_WORKSPACE,
            EXIT_WRONG_STATE,
            EXIT_LIMIT,
            EXIT_UNAVAILABLE,
            EXIT_LOST_RESULT,
        ];
        for row in TABLE {
            assert!(
                allowed.contains(&row.exit_code),
                "{}: exit {}",
                row.code,
                row.exit_code
            );
            assert!(
                fill(row.sentence, &Value::Null, Some("ws-1")).is_some(),
                "{}: the sentence names a field the server may not send",
                row.code
            );
            assert!(!row.sentence.contains('§'), "{}", row.code);
            assert!(
                !row.sentence.to_lowercase().contains("biscuit"),
                "{}",
                row.code
            );
        }
    }

    #[test]
    fn a_code_with_selectors_resolves_to_the_right_row() {
        let concurrent =
            json!({"limit": "max_concurrent", "max_concurrent": 5, "active_leases": 5});
        let err = render("entitlement_limit", &concurrent, Some(403), Some("ws-1"));
        assert!(
            err.message.contains("5 of 5 are running"),
            "{}",
            err.message
        );
        assert_eq!(err.exit_code, EXIT_LIMIT);

        let workspaces =
            json!({"limit": "max_workspaces", "max_workspaces": 10, "live_workspaces": 10});
        let err = render("entitlement_limit", &workspaces, Some(403), Some("ws-1"));
        assert!(err.message.contains("10 of 10"), "{}", err.message);
        assert_eq!(err.next_command.as_deref(), Some("reachpad archive <id>"));

        // No `limit` field at all: the fallback row, and no invented numbers.
        let err = render("entitlement_limit", &json!({}), Some(403), Some("ws-1"));
        assert!(err.message.contains("account limit"), "{}", err.message);
    }

    /// **The GitHub refusals name only what the server named (I13).**
    ///
    /// The org somebody tried to reach and the URL that fixes it are both
    /// facts of the fleet — a self-hosted deployment runs its own GitHub App
    /// and its own webapp — so a client constant for either would send people
    /// somewhere that is not their fleet. When the fleet sends neither, the
    /// clause disappears and the next command carries the whole remedy.
    #[test]
    fn the_github_refusals_take_the_org_and_the_link_off_the_wire() {
        let body = json!({
            "org": "acme",
            "install_url": "https://github.com/apps/reachpad/installations/new",
            "connect_url": "https://reachpad.dev/connect/github",
        });
        let err = render("github_not_installed", &body, Some(403), None);
        assert!(err.message.contains("acme"), "{}", err.message);
        // THE CONNECT URL, not the install URL. Installing the App creates an
        // installation and no grant, and coverage needs both — so the raw
        // install screen would send this person round the same refusal again.
        assert!(
            err.message.contains("https://reachpad.dev/connect/github"),
            "{}",
            err.message
        );
        assert!(
            !err.message.contains("apps/reachpad/installations/new"),
            "the CLI must not send a person to the install screen: {}",
            err.message
        );
        assert_eq!(err.next_command.as_deref(), Some("reachpad connect github"));
        assert_eq!(err.exit_code, EXIT_WRONG_STATE);
        assert!(!err.retriable);

        // A fleet that predates `connect_url` sends the body without it. The
        // whole clause goes, rather than a sentence reading "connect it at
        // null" — and the org goes with it, because a half-rendered clause is
        // the thing `fill` exists to prevent. What must survive is the
        // sentence and the next command, so the person is not left with an
        // empty message.
        let err = render(
            "github_not_installed",
            &json!({ "org": "acme", "install_url": Value::Null }),
            Some(403),
            None,
        );
        assert!(!err.message.contains('{'), "{}", err.message);
        assert!(!err.message.contains("null"), "{}", err.message);
        assert!(
            err.message.contains("not installed on that GitHub account"),
            "{}",
            err.message
        );
        assert_eq!(err.next_command.as_deref(), Some("reachpad connect github"));

        // Suspension is GitHub's switch, not Reachpad's: the remedy is in
        // GitHub's settings, and this row names no reachpad command that
        // cannot move it.
        let err = render(
            "github_installation_suspended",
            &json!({ "org": "acme" }),
            Some(403),
            None,
        );
        assert!(err.message.contains("suspended on acme"), "{}", err.message);
        assert_eq!(err.next_command, None);
        assert_eq!(err.exit_code, EXIT_WRONG_STATE);

        // A revoked grant is not a credential problem: signing in again would
        // change nothing, so it must not exit 3 and send somebody there.
        let err = render(
            "github_grant_revoked",
            &json!({ "connect_url": "https://reachpad.dev/connect/github" }),
            Some(403),
            None,
        );
        assert_eq!(err.next_command.as_deref(), Some("reachpad connect github"));
        assert_eq!(err.exit_code, EXIT_WRONG_STATE);
        assert_ne!(err.exit_code, EXIT_CREDENTIAL);
        assert!(err.message.contains("disconnected"), "{}", err.message);
        assert!(
            err.message.contains("https://reachpad.dev/connect/github"),
            "{}",
            err.message
        );
        // And it still says what happened against a fleet that sends no link.
        let err = render("github_grant_revoked", &json!({}), Some(403), None);
        assert!(err.message.contains("disconnected"), "{}", err.message);
        assert!(!err.message.contains('{'), "{}", err.message);
        assert_eq!(err.next_command.as_deref(), Some("reachpad connect github"));
    }

    /// Giving up on the browser half is a wait that ended, not a failure: the
    /// install may land a minute later, and re-running the command picks it
    /// up. So it is retriable, and it says how long it waited using the only
    /// clock that knows — this one.
    #[test]
    fn the_connect_wait_says_how_long_it_waited_and_invites_a_retry() {
        let err = CliError::from_body("github_connect_timeout", &json!({ "waited_s": 600 }), None);
        assert!(err.message.contains("600s"), "{}", err.message);
        assert!(err.retriable);
        assert_eq!(err.exit_code, EXIT_UNAVAILABLE);
        assert_eq!(err.next_command.as_deref(), Some("reachpad connect github"));
        // With no elapsed time to report the sentence still stands alone.
        let err = CliError::from_body("github_connect_timeout", &json!({}), None);
        assert!(!err.message.contains('{'), "{}", err.message);
    }

    /// **Two routes answer `reason_too_long`, and each gets its own sentence.**
    ///
    /// C3's link-request row is the selector-less one, so it is what `row()`
    /// falls back to; C5's kill switch names its limit and gets the sentence
    /// that fits an emergency stop. Without the selector the second row is
    /// unreachable prose — which is exactly what it was when this test was
    /// written (creds C5, WP5.3).
    #[test]
    fn one_code_two_routes_two_sentences() {
        let switch = json!({
            "limit": "kill_switch_reason",
            "limit_bytes": 1024,
            "presented_bytes": 2000,
        });
        let err = render("reason_too_long", &switch, Some(400), None);
        assert!(
            err.message.contains("pull the switch again"),
            "the kill switch got another route's sentence: {}",
            err.message
        );
        assert!(
            err.message.contains("2000 bytes; the limit is 1024"),
            "{}",
            err.message
        );

        // The link-request route sends no `limit`, and keeps its own prose.
        let err = render("reason_too_long", &json!({}), Some(400), None);
        assert!(
            err.message.contains("person who has to read it"),
            "{}",
            err.message
        );
        assert_eq!(err.exit_code, EXIT_USAGE);
    }

    #[test]
    fn a_number_the_server_did_not_send_is_not_printed() {
        let err = render("lease_held", &json!({}), Some(409), Some("ws-1"));
        assert_eq!(
            err.message,
            "ws-1 is running on another node. Pause it first: `reachpad pause ws-1`."
        );
        let err = render(
            "lease_held",
            &json!({"holder_node": "n-01"}),
            Some(409),
            Some("ws-1"),
        );
        assert!(
            err.message.ends_with("It is held by n-01."),
            "{}",
            err.message
        );
    }

    #[test]
    fn the_hardcoded_zero_balance_is_never_quoted_back() {
        let body =
            json!({"balance_credits": 0, "detail": "no compute credits", "remedy": "top up"});
        let err = render("credits_exhausted", &body, Some(402), Some("ws-1"));
        assert_eq!(
            err.message,
            "Out of compute credits. Write to seiji@reachpad.dev to top up."
        );
        assert!(!err.message.contains('0'), "{}", err.message);
    }

    #[test]
    fn no_capacity_is_retriable_only_when_the_cause_can_change() {
        let transient = render(
            "no_capacity",
            &json!({"cause": "all_full"}),
            Some(503),
            Some("ws-1"),
        );
        assert!(transient.retriable);
        let structural = render(
            "no_capacity",
            &json!({"cause": "no_node_serves_this_class"}),
            Some(503),
            Some("ws-1"),
        );
        assert!(!structural.retriable);
        // No cause at all is not a promise that retrying helps.
        let unknown = render("no_capacity", &json!({}), Some(503), Some("ws-1"));
        assert!(!unknown.retriable);
    }

    #[test]
    fn a_wait_is_stated_in_seconds_from_the_servers_milliseconds() {
        let err = render(
            "workspace_stopping",
            &json!({"retry_after_ms": 30000}),
            Some(409),
            Some("ws-1"),
        );
        assert!(
            err.message.ends_with("Try again in about 30s."),
            "{}",
            err.message
        );
        assert!(err.retriable);
    }

    #[test]
    fn both_archived_statuses_are_one_sentence_and_one_exit_code() {
        for status in [409u16, 410] {
            let err = render("workspace_archived", &json!({}), Some(status), Some("ws-9"));
            assert_eq!(err.exit_code, EXIT_WRONG_STATE);
            assert!(err.message.contains("ws-9 is archived"), "{}", err.message);
            assert_eq!(err.status, Some(status));
        }
    }

    #[test]
    fn a_code_with_no_row_keeps_the_servers_own_words_and_exits_one() {
        let err = CliError::from_api(
            &ApiError::Api {
                status: 500,
                code: "something_new".to_owned(),
                detail: Some("a fleet newer than this CLI".to_owned()),
                body: json!({"error": "something_new"}),
            },
            Some("ws-1"),
        );
        assert_eq!(err.exit_code, 1);
        assert!(
            err.message.contains("a fleet newer than this CLI"),
            "{}",
            err.message
        );
    }

    #[test]
    fn an_exec_end_that_lost_the_result_exits_70() {
        let err = CliError::from_exec_end(
            &json!({"ev": "exec.end", "error": "node_gone", "exit_code": Value::Null}),
            Some("ws-1"),
        );
        assert_eq!(err.exit_code, EXIT_LOST_RESULT);
        assert!(
            err.message.contains("may never have started"),
            "{}",
            err.message
        );
    }

    #[test]
    fn the_client_deadline_leaves_room_for_the_servers_own_verdict() {
        assert_eq!(exec_deadline_ms(Some(600_000)), 600_000 + 150_000 + 30_000);
        assert_eq!(exec_deadline_ms(None), 780_000);
        assert!(exec_deadline_ms(Some(1_000)) > 1_000 + EXEC_STREAM_GRACE_MS);
    }

    #[test]
    fn the_envelopes_are_the_shape_an_agent_parses() {
        let err = render("workspace_not_found", &json!({}), Some(404), Some("ws-7"));
        assert_eq!(
            err.envelope("workspace.status"),
            json!({
                "ok": false,
                "command": "workspace.status",
                "error": {
                    "code": "workspace_not_found",
                    "message": "There is no workspace ws-7 on this account. `reachpad list` shows the ones there are.",
                    "retriable": false,
                    "next_command": "reachpad list",
                    "status": 404,
                }
            })
        );
        assert_eq!(
            ok_envelope("workspace.create", json!({"id": "ws-7"})),
            json!({"ok": true, "command": "workspace.create", "data": {"id": "ws-7"}})
        );
    }

    /// `pause` on a workspace that never ran says what pause means, not what
    /// fork means: a fork child has a snapshot to fork from the moment it is
    /// born, so "nothing to fork from" would be false as well as off-topic.
    #[test]
    fn nothing_to_save_is_not_nothing_to_fork_from() {
        let err = CliError::from_code("no_active_lease", Some("ws-1"));
        assert_eq!(err.exit_code, EXIT_WRONG_STATE);
        assert!(!err.message.contains("fork"), "{}", err.message);
        assert!(err.message.contains("nothing to save"), "{}", err.message);
        assert!(err.message.contains("reachpad run ws-1"), "{}", err.message);
        // The fork refusal is the other sentence, and still says its own
        // thing.
        let fork = CliError::from_code("no_sealed_snapshot", Some("ws-1"));
        assert!(
            fork.message.contains("nothing to fork from"),
            "{}",
            fork.message
        );
    }

    #[test]
    fn all_five_no_credential_spellings_exit_three() {
        for code in [
            "no_credential",
            "no_identity_token",
            "no_token",
            "no_operator_token",
            "no_authority",
        ] {
            let err = CliError::from_code(code, None);
            assert_eq!(err.exit_code, EXIT_CREDENTIAL, "{code}");
            assert_eq!(err.next_command.as_deref(), Some(SIGN_IN), "{code}");
        }
    }

    // -- WP-CP.4: the workspace ran out of room --------------------------

    /// The frame the node sends when a command FAILED on a full disk: one
    /// sentence naming the workspace, the two figures in units a `df` agrees
    /// with, and exit 6.
    #[test]
    fn a_failed_command_on_a_full_disk_names_the_disk_and_exits_six() {
        let end = json!({
            "ev": "exec.end",
            "exit_code": 101,
            "error": "workspace_disk_full",
            "workspace_condition": "workspace_disk_full",
            "disk_path": "/mnt",
            "disk_free_bytes": 4096u64,
            "disk_total_bytes": 20u64 * 1024 * 1024 * 1024,
        });
        let err = CliError::from_exec_end(&end, Some("ws-77"));
        assert_eq!(err.exit_code, EXIT_LIMIT);
        assert_eq!(err.code, "workspace_disk_full");
        assert!(err.message.contains("ws-77"), "{}", err.message);
        assert!(err.message.contains("ran out of disk"), "{}", err.message);
        // The numbers come off the WIRE (I13) and are rendered in binary
        // units: a user comparing this with `df` inside the guest must not
        // have to convert anything.
        assert!(err.message.contains("/mnt"), "{}", err.message);
        assert!(err.message.contains("20 GiB"), "{}", err.message);
        assert_eq!(
            err.next_command.as_deref(),
            Some("reachpad run ws-77 -- df -h")
        );
        assert!(!err.retriable, "the disk does not empty itself");
    }

    /// The numbers clause DISAPPEARS rather than rendering blanks when the
    /// server did not send the figures — the table's standing rule, checked
    /// here because this row is the first with a derived `_h` substitution
    /// and a derived field is exactly where a silent empty string would hide.
    #[test]
    fn the_disk_figures_vanish_together_when_the_server_sends_none() {
        let err = CliError::from_exec_end(
            &json!({"ev": "exec.end", "exit_code": 1, "error": "workspace_disk_full"}),
            Some("ws-77"),
        );
        assert_eq!(err.exit_code, EXIT_LIMIT);
        assert!(err.message.contains("ran out of disk"), "{}", err.message);
        assert!(
            !err.message.contains("free of"),
            "a numbers clause rendered with no numbers: {}",
            err.message
        );
    }

    /// **The advisory arm.** A command that SUCCEEDED on a full disk carries
    /// the condition but no `error`, so `from_exec_end` must never be reached
    /// and the sentence is borrowed instead. This is what keeps `reachpad run`
    /// exiting 0 for a command that worked.
    #[test]
    fn a_successful_command_on_a_full_disk_yields_a_sentence_and_no_failure() {
        let end = json!({
            "ev": "exec.end",
            "exit_code": 0,
            "workspace_condition": "workspace_disk_full",
            "disk_path": "/tmp",
            "disk_free_bytes": 1024u64,
            "disk_total_bytes": 1024u64 * 1024 * 1024,
        });
        assert!(
            end.get("error").is_none(),
            "the node must not set `error` for a command that succeeded"
        );
        let sentence = CliError::workspace_condition(&end, Some("ws-77"))
            .expect("the condition has a row and therefore a sentence");
        assert!(sentence.contains("ws-77"), "{sentence}");
        assert!(sentence.contains("/tmp"), "{sentence}");
    }

    /// **NEGATIVE CONTROL (b) at the CLI edge.** A healthy workspace whose
    /// command failed carries no condition, so there is no sentence to print
    /// and `from_exec_end` is never called: the caller sees exit 101 and
    /// nothing about disks.
    #[test]
    fn negative_control_a_failed_command_on_a_healthy_workspace_says_nothing_about_disks() {
        let end = json!({"ev": "exec.end", "exit_code": 101});
        assert_eq!(CliError::workspace_condition(&end, Some("ws-77")), None);
        assert!(
            end.get("error").is_none(),
            "no error key means `reachpad run` exits with the command's own code"
        );
    }
}
