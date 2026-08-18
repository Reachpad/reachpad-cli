//! Typed calls to controld's public HTTP API (§5.1 surface). This is the
//! same surface the web app uses — no privileged interface exists (I6).

use serde_json::{json, Value};

use crate::http_min;
use crate::transport::TlsTrust;

/// What to run, as the client states it. A struct rather than four positional
/// arguments because `exec(ws, auth, argv, cwd, env, timeout, cb)` is a call
/// nobody can read at the call site, and swapping two `Option<&str>`s in it
/// would still compile.
#[derive(Debug)]
pub struct ExecSpec<'a> {
    pub argv: &'a [String],
    pub cwd: Option<&'a str>,
    pub env: &'a std::collections::BTreeMap<String, String>,
    pub timeout_ms: Option<u64>,
    /// Bytes to feed the command's stdin, already base64-encoded (the route's
    /// own `stdin_b64` field). `None` sends no stdin at all.
    pub stdin_b64: Option<String>,
}

/// What an exec stream hands back as it runs.
///
/// One callback rather than two, because the caller's decision — bytes to the
/// terminal or a JSON line — is the same decision for both, and a second
/// closure is a second place to forget one of them.
#[derive(Debug)]
pub enum ExecItem<'a> {
    /// Output as it arrives. `fd` is 1 or 2, never merged.
    Out { fd: u8, bytes: &'a [u8] },
    /// This command found the workspace down and woke it, so the delay is a
    /// boot rather than a hang.
    ///
    /// `reason` is the server's word for what it is doing — `starting`
    /// (nothing to restore), `restoring` (a disk-only head) or `resuming` (a
    /// `disk+mem` head, the mid-thought case). It is rendered verbatim, so a
    /// server that learns a new one needs no CLI release; the CLI only owns
    /// the sentence around it.
    Waiting { reason: &'a str },
}

/// How a call on ONE workspace proves it may act: the caller's own capability
/// for that workspace, or an API key that mints one server-side (ADR-0059 §4,
/// extended to the workspace-scoped reads and writes by ADR-0069).
///
/// An enum rather than two optional strings so "neither" and "both" are
/// unrepresentable — the first is a request the server must refuse and the
/// second is a question about precedence nobody should have to answer.
///
/// The two carriers differ on the wire: a Biscuit goes in the request body
/// (or, on a GET, the bearer header), a key always goes on the bearer header.
#[derive(Clone, Copy, Debug)]
pub enum Auth<'a> {
    Biscuit(&'a str),
    ApiKey(&'a str),
}

impl<'a> Auth<'a> {
    /// The bearer header this carrier uses on a GET, where there is no body
    /// to put a Biscuit in.
    fn bearer(self) -> &'a str {
        match self {
            Auth::Biscuit(b) | Auth::ApiKey(b) => b,
        }
    }

    /// `(bearer, body-biscuit)` for a POST: a key authenticates by header, a
    /// Biscuit by the route's own `biscuit` field.
    fn split(self) -> (Option<&'a str>, Option<&'a str>) {
        match self {
            Auth::ApiKey(k) => (Some(k), None),
            Auth::Biscuit(b) => (None, Some(b)),
        }
    }
}

/// API failure: transport trouble, a non-2xx status (with controld's error
/// code — codes only, never values), or an unexpected body shape.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("transport: {0}")]
    Transport(String),
    /// A non-2xx answer. `detail` is the server's own sentence about it when
    /// there is one — an error code alone tells a user nothing they can act
    /// on, and `entitlement_limit` with no numbers is how someone concludes
    /// the product is broken rather than that they are at a documented cap.
    #[error("{}", match detail {
        Some(d) => format!("{status} {code}: {d}"),
        None => format!("server returned {status}: {code}"),
    })]
    Api {
        status: u16,
        code: String,
        detail: Option<String>,
        /// The whole refusal body. The sentence a user reads interpolates the
        /// server's own numbers out of it, and hardcoding any of them client
        /// side would break I13.
        body: Value,
    },
    #[error("unexpected response shape: {0}")]
    Shape(String),
    /// The client stopped waiting before the server answered.
    #[error("reachpad stopped waiting before the fleet answered")]
    Deadline,
}

/// Turn a non-2xx answer into the refusal the error table renders.
///
/// A body with no `error` field is not controld's shape at all: the axum
/// extractors refuse a malformed request before any handler runs, and that is
/// the one refusal with no code in it.
fn refusal(resp: http_min::Response) -> ApiError {
    let code = resp
        .body
        .get("error")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| match resp.status {
            400 | 415 | 422 => "request_not_understood".to_owned(),
            _ => "unknown".to_owned(),
        });
    let detail = resp
        .body
        .get("detail")
        .and_then(Value::as_str)
        .map(str::to_owned);
    ApiError::Api {
        status: resp.status,
        code,
        detail,
        body: resp.body,
    }
}

/// Result of a workspace creation (§8 flow 2): the new id plus the creator's
/// owner Biscuit, which authorizes every later call for that workspace (I6).
#[derive(Debug, Clone)]
pub struct Created {
    pub workspace: String,
    pub biscuit_b64: String,
}

/// Result of an attach (§8 flow 3).
#[derive(Debug, Clone)]
pub struct Attach {
    pub node: String,
    pub fencing_token: u64,
    pub biscuit_b64: String,
    pub expires_at_ms: u64,
    pub credits_remaining_millicredits: Option<u64>,
}

/// What an operator credential exchanges for (ADR-0034): the short-lived
/// user-scoped identity token, and who it says you are.
///
/// `token_id` / `token_expires_at_ms` describe the CREDENTIAL ROW that was
/// presented — the 30-90 day one on disk — not the hour-long identity token
/// in `expires_at_ms`. A fleet that predates ADR-0069 sends neither.
#[derive(Debug, Clone)]
pub struct OperatorSession {
    pub user_id: String,
    pub principal_id: String,
    pub identity_token: String,
    pub expires_at_ms: u64,
    pub token_id: Option<String>,
    pub token_expires_at_ms: Option<u64>,
    pub scopes: Vec<String>,
}

/// One credential row of `GET /v1/operator/tokens`.
///
/// `scopes` is the field that tells a laptop credential apart from the
/// account's scoped doors (`identity`, `provision`): an EMPTY scope list is a
/// credential a person signs in with, and a non-empty one belongs to a
/// service — `auth logout --all` revokes the first kind only.
#[derive(Debug, Clone)]
pub struct OperatorTokenRow {
    pub id: String,
    pub label: String,
    pub expires_at_ms: u64,
    pub usable: bool,
    pub scopes: Vec<String>,
}

/// The entitlement values a listing or a status carries, so a manager plans
/// against its caps instead of discovering them by a refusal.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Limits {
    pub max_workspaces: Option<u64>,
    pub max_concurrent: Option<u64>,
    /// Running + sealing: everything holding a concurrency slot.
    pub live_workspaces: u64,
}

/// One row of `reachpad list`. `state` and `head` are absent against a fleet
/// that predates ADR-0069.
#[derive(Debug, Clone)]
pub struct Workspace {
    pub id: String,
    pub name: String,
    pub forks: usize,
    pub state: Option<String>,
    pub head: Option<Head>,
    pub parent: Option<Parent>,
    pub created_at_ms: u64,
    pub archived_at_ms: Option<u64>,
}

/// The save a workspace resumes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Head {
    pub snapshot: String,
    pub kind: String,
    pub sealed_at_ms: Option<u64>,
}

/// The workspace and save a fork was rooted at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parent {
    pub workspace: String,
    pub snapshot: Option<String>,
}

/// The result of `GET /v1/workspaces` — rows plus the account's limits.
#[derive(Debug, Clone)]
pub struct Listing {
    pub workspaces: Vec<Workspace>,
    /// `None` against a fleet that predates ADR-0069.
    pub limits: Option<Limits>,
}

/// The live lease on a workspace. `fencing_token` arrives only for a caller
/// the server also authorizes to write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    pub node: String,
    pub expires_at_ms: u64,
    pub heartbeat_at_ms: u64,
    pub fencing_token: Option<u64>,
}

/// `GET /v1/workspaces/:id` (S2): everything derivable about one workspace,
/// read without taking a lease or waking anything.
#[derive(Debug, Clone)]
pub struct Status {
    pub id: String,
    pub name: String,
    pub state: String,
    pub lease: Option<Lease>,
    pub head: Option<Head>,
    pub parent: Option<Parent>,
    pub snapshots: u64,
    pub forks: u64,
    pub idle_pause_seconds: u64,
    pub limits: Limits,
    /// The workspace's own block-device size, and what a workspace created
    /// right now would get (WP-CP.3). `None` against a fleet that predates
    /// the field — absent, not zero, because "0 bytes" is a lie and a `?` is
    /// not.
    pub device: Option<DeviceSize>,
    /// How much of that device is still writable, as the GUEST last measured
    /// it (WP-CP.4). `None` whenever the fleet does not report it — which is
    /// every fleet today, see [`GuestDisk`].
    pub guest_disk: Option<GuestDisk>,
    pub created_at_ms: u64,
    pub archived_at_ms: Option<u64>,
}

/// Free space inside the workspace's filesystem, measured by the guest.
///
/// # Why this is an option that is currently always `None`
///
/// The figure exists: workspaced runs `statvfs` on the two-second status
/// cadence and puts it on `GuestStatus`, and the node has it in hand. What
/// does not exist is a path from the node's heartbeat to this read-only route
/// — controld would have to persist the sample on the lease row, which means
/// two nullable columns, a migration, and a write on the heartbeat's hot path
/// for a value that is a *sample* rather than reconstructible state (§4.1).
/// WP-CP.4 scoped that out rather than doing it badly; the client half ships
/// now so that the day the fleet reports it, no CLI release is needed.
///
/// The client's posture until then is the one trap 41 asks for: **say
/// nothing.** No guessed number, no "0 bytes free", no `?` — the line simply
/// is not printed, and `status --json` carries `null`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestDisk {
    pub free_bytes: u64,
    pub total_bytes: u64,
}

/// Two disk sizes that must be read together: a workspace keeps the size it
/// was created with, and nothing grows it in place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceSize {
    /// This workspace's device.
    pub workspace_bytes: u64,
    /// What a workspace created now is stamped with.
    pub new_workspace_bytes: u64,
}

/// What a release did: `released` ended the lease now (a discard), `sealing`
/// means the node was told to save first and the lease ends when it stops
/// renewing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Released {
    pub released: bool,
    pub sealing: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreditBalance {
    pub balance_millicredits: u64,
    pub unit: String,
    pub updated_at_ms: u64,
}

/// Percent-encode one PATH segment. Same alphabet as [`encode_query`], which
/// is what makes it segment-safe: `/` is escaped too, so an id that arrived
/// from a file, an environment variable or an agent's output cannot add a
/// path element — nor a CRLF and a second request line — to the request this
/// client is building.
fn encode_segment(value: &str) -> String {
    encode_query(value)
}

/// Percent-encode everything that is not unreserved, so a user id can never
/// reshape the query (or the request line).
fn encode_query(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char)
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

/// Result of a fork (§8 flow 5).
#[derive(Debug, Clone)]
pub struct Forked {
    pub workspace: String,
    pub name: String,
    /// The sealed snapshot of the SOURCE the child roots at.
    pub origin_snapshot: String,
    pub origin_log_seq: u64,
    /// Owner Biscuit for the CHILD.
    pub biscuit_b64: String,
}

/// Result of a rewind (§8 flow 6).
#[derive(Debug, Clone)]
pub struct Rewound {
    /// What the workspace now resumes from.
    pub head_snapshot: String,
    pub head_log_seq: u64,
    /// The auto-created fork preserving the forward history.
    pub preserved_fork: String,
    pub preserved_fork_name: String,
}

/// One sealed snapshot in a lineage listing.
#[derive(Debug, Clone)]
pub struct SnapshotRow {
    pub id: String,
    /// `disk+mem` resumes mid-thought (within its pool); `disk` boots.
    pub kind: String,
    pub log_seq: u64,
    pub sealed_at_ms: u64,
    pub pool_id: Option<String>,
}

/// The lineage view a rewind is driven from.
#[derive(Debug, Clone)]
pub struct Lineage {
    pub head: Option<SnapshotRow>,
    /// Every sealed snapshot, oldest first.
    pub snapshots: Vec<SnapshotRow>,
    /// Child workspace ids.
    pub forks: Vec<String>,
}

/// A freshly minted API key (ADR-0059 §4). `key` is shown once.
#[derive(Debug, Clone)]
pub struct ApiKeyMinted {
    pub key: String,
    pub id: String,
    pub role: String,
    pub expires_at_ms: u64,
}

/// One row of `key list` — metadata only, the secret is never readable.
#[derive(Debug, Clone)]
pub struct ApiKeyRow {
    pub id: String,
    pub label: String,
    pub role: String,
    /// Empty = the whole account (the mint-time "absent" scope).
    pub workspace_ids: Vec<String>,
    pub expires_at_ms: u64,
    pub revoked_at_ms: Option<u64>,
    pub usable: bool,
}

/// Result of a share/grant (§8 flow 7).
#[derive(Debug, Clone)]
pub struct Share {
    pub role: String,
    pub expires_at_ms: u64,
    pub share_token_b64: String,
}

/// Thin client of controld's public endpoints.
///
/// The base URL is `https://<hub-dns>` in production (ADR-0040: hub terminates
/// TLS on 443 and forwards `/v1/*` to controld over loopback) and
/// `http://127.0.0.1:7401` on the box itself. Plaintext to anything else is
/// refused before a socket opens — see [`http_min::Endpoint::ensure_confidential`].
#[derive(Debug, Clone)]
pub struct Client {
    controld: String,
    trust: TlsTrust,
}

impl Client {
    /// A client with the default TLS posture: the OS trust store for
    /// `https://`, which is what a laptop against the real endpoint wants.
    pub fn new(controld: impl Into<String>) -> Self {
        Client {
            controld: controld.into(),
            trust: TlsTrust::default(),
        }
    }

    /// A client with an explicit trust posture — `--hub-ca` anchors for a hub
    /// on a Let's Encrypt *staging* certificate, or the pinned dev identity.
    /// Narrower than the default, never wider; there is no way to disable
    /// verification.
    pub fn with_trust(controld: impl Into<String>, trust: TlsTrust) -> Self {
        Client {
            controld: controld.into(),
            trust,
        }
    }

    async fn post(&self, path: &str, body: Value) -> Result<Value, ApiError> {
        self.post_auth(path, body, None).await
    }

    async fn post_auth(
        &self,
        path: &str,
        body: Value,
        bearer: Option<&str>,
    ) -> Result<Value, ApiError> {
        let resp = http_min::post_json_trust(&self.controld, path, &body, bearer, &self.trust)
            .await
            .map_err(|e| ApiError::Transport(format!("{e:#}")))?;
        if (200..300).contains(&resp.status) {
            Ok(resp.body)
        } else {
            Err(refusal(resp))
        }
    }

    /// POST /v1/identity/tokens → the caller's user-scoped identity token.
    ///
    /// Creating a workspace is a user-level action, so it is authorized by the
    /// user's own token rather than by naming a principal (I6). The IdP
    /// assertion is what the identity provider vouches for; in dev it is
    /// `controld::identity::dev_idp_assertion` (deterministic, no
    /// provisioning — ADR-0011).
    pub async fn identity_token(
        &self,
        user_id: &str,
        principal_id: &str,
        idp_assertion: &str,
    ) -> Result<String, ApiError> {
        let body = self
            .post(
                "/v1/identity/tokens",
                json!({
                    "user_id": user_id,
                    "principal_id": principal_id,
                    "idp_assertion": idp_assertion,
                }),
            )
            .await?;
        str_at(&body, &["identity_token"])
    }

    /// POST /v1/operator/session → the identity token an operator credential
    /// is worth (ADR-0034).
    ///
    /// This is the whole client half of the operator credential: the laptop
    /// presents `Authorization: Bearer rpop1.…` once and receives exactly what
    /// `POST /v1/identity/tokens` would have produced, after which every
    /// command runs the ordinary capability path (I6). Nothing about the
    /// authorization model is special-cased for a human at a terminal.
    pub async fn operator_session(
        &self,
        operator_token: &str,
    ) -> Result<OperatorSession, ApiError> {
        let body = self
            .post_auth("/v1/operator/session", json!({}), Some(operator_token))
            .await?;
        Ok(OperatorSession {
            user_id: str_at(&body, &["user_id"])?,
            principal_id: str_at(&body, &["principal_id"])?,
            identity_token: str_at(&body, &["identity_token"])?,
            expires_at_ms: u64_at(&body, &["expires_at_ms"])?,
            token_id: body["token_id"].as_str().map(str::to_owned),
            token_expires_at_ms: body["token_expires_at_ms"].as_u64(),
            scopes: string_array(&body["scopes"]),
        })
    }

    /// GET /v1/operator/tokens → every credential row on this account, which
    /// is what `auth logout --all` revokes.
    pub async fn operator_tokens(
        &self,
        operator_token: &str,
    ) -> Result<Vec<OperatorTokenRow>, ApiError> {
        let resp = http_min::get_json_trust(
            &self.controld,
            "/v1/operator/tokens",
            Some(operator_token),
            &self.trust,
        )
        .await
        .map_err(|e| ApiError::Transport(format!("{e:#}")))?;
        if !(200..300).contains(&resp.status) {
            return Err(refusal(resp));
        }
        Ok(at(&resp.body, &["operator_tokens"])?
            .as_array()
            .ok_or_else(|| ApiError::Shape("operator_tokens is not an array".to_owned()))?
            .iter()
            .map(|t| OperatorTokenRow {
                id: t["id"].as_str().unwrap_or_default().to_owned(),
                label: t["label"].as_str().unwrap_or_default().to_owned(),
                expires_at_ms: t["expires_at_ms"].as_u64().unwrap_or(0),
                usable: t["usable"].as_bool().unwrap_or(false),
                scopes: string_array(&t["scopes"]),
            })
            .collect())
    }

    /// POST /v1/operator/tokens/:id/revoke, authenticated by a live
    /// credential of the same user — which is why `logout` revokes its own
    /// row LAST.
    pub async fn revoke_operator_token(
        &self,
        operator_token: &str,
        id: &str,
    ) -> Result<(), ApiError> {
        self.post_auth(
            &format!("/v1/operator/tokens/{}/revoke", encode_segment(id)),
            json!({}),
            Some(operator_token),
        )
        .await
        .map(|_| ())
    }

    pub async fn credit_balance(
        &self,
        user_id: &str,
        identity_token: &str,
    ) -> Result<CreditBalance, ApiError> {
        let body = self
            .post(
                "/v1/credits/balance",
                json!({ "user_id": user_id, "identity_token": identity_token }),
            )
            .await?;
        Ok(CreditBalance {
            balance_millicredits: u64_at(&body, &["balance_millicredits"])?,
            unit: str_at(&body, &["unit"])?,
            updated_at_ms: u64_at(&body, &["updated_at_ms"])?,
        })
    }

    /// POST /v1/workspaces → (workspace id, the creator's owner Biscuit).
    ///
    /// The returned Biscuit is what every later call for this workspace
    /// presents; there is no way to name a principal instead (I6).
    ///
    /// `name` is ALWAYS sent, empty string included: a fleet that predates
    /// the optional-name change refuses a body without the field, so omitting
    /// it would make an unnamed `create` depend on deployment order.
    pub async fn create_workspace(
        &self,
        user_id: &str,
        identity_token: &str,
        name: &str,
    ) -> Result<Created, ApiError> {
        let body = self
            .post(
                "/v1/workspaces",
                json!({
                    "user_id": user_id,
                    "identity_token": identity_token,
                    "name": name,
                }),
            )
            .await?;
        Ok(Created {
            workspace: str_at(&body, &["workspace", "id"])?,
            biscuit_b64: str_at(&body, &["biscuit"])?,
        })
    }

    /// GET /v1/workspaces?user_id=… → the caller's workspaces and their forks.
    ///
    /// Authorized by the same user-scoped identity token `create_workspace`
    /// needs (I6). A GET, so it goes through the ADR-0040 control plane on
    /// exactly the same path as everything else — hub relays methods it does
    /// not interpret.
    pub async fn list_workspaces(
        &self,
        user_id: &str,
        identity_token: &str,
    ) -> Result<Listing, ApiError> {
        let path = format!("/v1/workspaces?user_id={}", encode_query(user_id));
        let resp =
            http_min::get_json_trust(&self.controld, &path, Some(identity_token), &self.trust)
                .await
                .map_err(|e| ApiError::Transport(format!("{e:#}")))?;
        if !(200..300).contains(&resp.status) {
            return Err(refusal(resp));
        }
        let rows = at(&resp.body, &["workspaces"])?
            .as_array()
            .ok_or_else(|| ApiError::Shape("workspaces is not an array".to_owned()))?;
        let workspaces = rows
            .iter()
            .map(|row| {
                Ok(Workspace {
                    id: str_at(row, &["id"])?,
                    name: str_at(row, &["name"]).unwrap_or_default(),
                    forks: row
                        .get("forks")
                        .and_then(Value::as_array)
                        .map(Vec::len)
                        .unwrap_or(0),
                    state: row["state"].as_str().map(str::to_owned),
                    head: row["head"]["snapshot"].as_str().map(|s| Head {
                        snapshot: s.to_owned(),
                        kind: row["head"]["kind"].as_str().unwrap_or_default().to_owned(),
                        sealed_at_ms: None,
                    }),
                    parent: parent_of(&row["origin"]),
                    created_at_ms: row["created_at_ms"].as_u64().unwrap_or(0),
                    archived_at_ms: row["archived_at_ms"].as_u64(),
                })
            })
            .collect::<Result<Vec<_>, ApiError>>()?;
        Ok(Listing {
            workspaces,
            limits: limits_of(&resp.body["limits"]),
        })
    }

    /// GET /v1/workspaces/:id (S2) — the read every other verb is decided
    /// from. Never takes a lease, never wakes anything, never spends a credit.
    ///
    /// Against a fleet that predates this route the answer is a bare 404;
    /// [`is_route_absent`] tells that apart from "no such workspace", which
    /// carries controld's own `workspace_not_found`.
    pub async fn workspace_status(
        &self,
        workspace: &str,
        auth: Auth<'_>,
    ) -> Result<Status, ApiError> {
        let path = format!("/v1/workspaces/{}", encode_segment(workspace));
        let resp =
            http_min::get_json_trust(&self.controld, &path, Some(auth.bearer()), &self.trust)
                .await
                .map_err(|e| ApiError::Transport(format!("{e:#}")))?;
        if !(200..300).contains(&resp.status) {
            return Err(refusal(resp));
        }
        let body = resp.body;
        let ws = &body["workspace"];
        Ok(Status {
            id: str_at(ws, &["id"])?,
            name: ws["name"].as_str().unwrap_or_default().to_owned(),
            state: str_at(&body, &["state"])?,
            lease: body["lease"].as_object().map(|l| Lease {
                node: l
                    .get("node")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                expires_at_ms: l.get("expires_at_ms").and_then(Value::as_u64).unwrap_or(0),
                heartbeat_at_ms: l
                    .get("heartbeat_at_ms")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
                fencing_token: l.get("fencing_token").and_then(Value::as_u64),
            }),
            head: body["head_snapshot"]["id"].as_str().map(|id| Head {
                snapshot: id.to_owned(),
                kind: body["head_snapshot"]["kind"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned(),
                sealed_at_ms: body["head_snapshot"]["sealed_at_ms"].as_u64(),
            }),
            parent: parent_of(&ws["origin"]),
            snapshots: body["snapshots"].as_u64().unwrap_or(0),
            forks: body["forks"].as_u64().unwrap_or(0),
            idle_pause_seconds: body["idle_pause_seconds"].as_u64().unwrap_or(0),
            limits: limits_of(&body["limits"]).unwrap_or_default(),
            // Both halves or neither (trap 41 posture): a fleet that reports
            // one and not the other is one this client cannot describe
            // honestly, so it says nothing rather than inventing the missing
            // number.
            device: match (
                body["device_bytes"]["workspace"].as_u64(),
                body["device_bytes"]["new_workspace"].as_u64(),
            ) {
                (Some(workspace_bytes), Some(new_workspace_bytes)) => Some(DeviceSize {
                    workspace_bytes,
                    new_workspace_bytes,
                }),
                _ => None,
            },
            // Both halves or neither, for the same reason as `device` above:
            // a free figure with no total cannot be rendered as a fraction,
            // and a total with no free says nothing at all.
            guest_disk: match (
                body["guest_disk"]["free_bytes"].as_u64(),
                body["guest_disk"]["total_bytes"].as_u64(),
            ) {
                (Some(free_bytes), Some(total_bytes)) => Some(GuestDisk {
                    free_bytes,
                    total_bytes,
                }),
                _ => None,
            },
            created_at_ms: ws["created_at_ms"].as_u64().unwrap_or(0),
            archived_at_ms: ws["archived_at_ms"].as_u64(),
        })
    }

    /// POST /v1/workspaces/:id/attach → node, fencing token, Biscuit.
    pub async fn attach(&self, workspace: &str, biscuit_b64: &str) -> Result<Attach, ApiError> {
        let body = self
            .post(
                &format!("/v1/workspaces/{}/attach", encode_segment(workspace)),
                json!({ "biscuit": biscuit_b64 }),
            )
            .await?;
        Ok(Attach {
            node: str_at(&body, &["node"])?,
            fencing_token: u64_at(&body, &["fencing_token"])?,
            biscuit_b64: str_at(&body, &["biscuit"])?,
            expires_at_ms: u64_at(&body, &["lease", "expires_at_ms"])?,
            credits_remaining_millicredits: body["credits_remaining_millicredits"].as_u64(),
        })
    }

    /// POST /v1/workspaces/:id/release. Stale fencing tokens are rejected
    /// server-side (I2). Returns `true` if the lease was ended NOW (discard)
    /// and `false` if a seal-first stop was ordered instead — the default
    /// (report §55.5 finding 3): the node seals, then stops, and the lease
    /// ends when it stops renewing.
    pub async fn release(
        &self,
        workspace: &str,
        auth: Auth<'_>,
        fencing_token: u64,
        discard: bool,
    ) -> Result<Released, ApiError> {
        let (bearer, biscuit) = auth.split();
        let body = self
            .post_auth(
                &format!("/v1/workspaces/{}/release", encode_segment(workspace)),
                json!({
                    "fencing_token": fencing_token,
                    "biscuit": biscuit.unwrap_or_default(),
                    "discard": discard,
                }),
                bearer,
            )
            .await?;
        Ok(Released {
            released: body["released"].as_bool().unwrap_or(false),
            sealing: body["sealing"].as_bool().unwrap_or(false),
        })
    }

    /// POST /v1/workspaces/:id/exec — run one command (ADR-0059).
    ///
    /// Streams: `on_item` is called for each output chunk as it arrives,
    /// never after the fact. The return value is the terminating `exec.end`
    /// object.
    ///
    /// **A stream that ends without `exec.end` is a FAILURE**, and this
    /// function turns that into an `Err` rather than a zero exit — §6's rule,
    /// enforced at the one place every caller goes through, because a caller
    /// that has to remember it is a caller that will not.
    pub async fn exec<F>(
        &self,
        workspace: &str,
        auth: Auth<'_>,
        spec: &ExecSpec<'_>,
        mut on_item: F,
    ) -> Result<Value, ApiError>
    where
        F: FnMut(ExecItem<'_>),
    {
        let mut body = json!({ "argv": spec.argv, "env": spec.env });
        if let Some(cwd) = spec.cwd {
            body["cwd"] = json!(cwd);
        }
        if let Some(t) = spec.timeout_ms {
            body["timeout_ms"] = json!(t);
        }
        if let Some(stdin) = &spec.stdin_b64 {
            body["stdin_b64"] = json!(stdin);
        }
        let (bearer, biscuit) = auth.split();
        if let Some(b) = biscuit {
            body["biscuit"] = json!(b);
        }
        let mut end: Option<Value> = None;
        let mut streamed_refusal: Option<Value> = None;
        let path = format!("/v1/workspaces/{}/exec", encode_segment(workspace));
        let stream = http_min::post_ndjson_stream(
            &self.controld,
            &path,
            &body,
            bearer,
            &self.trust,
            |line| {
                let Ok(v) = serde_json::from_str::<Value>(line) else {
                    return true;
                };
                match v.get("ev").and_then(Value::as_str) {
                    Some("exec.out") => {
                        use base64::Engine as _;
                        let fd = v.get("fd").and_then(Value::as_u64).unwrap_or(1) as u8;
                        if let Some(b64) = v.get("data_b64").and_then(Value::as_str) {
                            if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(b64)
                            {
                                on_item(ExecItem::Out { fd, bytes: &bytes });
                            }
                        }
                    }
                    Some("exec.waiting") => {
                        let reason = v
                            .get("reason")
                            .and_then(Value::as_str)
                            .unwrap_or("resuming");
                        on_item(ExecItem::Waiting { reason });
                    }
                    Some("exec.end") => end = Some(v),
                    // A non-streamed refusal (the request never became a
                    // stream): keep it so the error names what happened.
                    _ => {
                        if v.get("error").is_some() {
                            streamed_refusal = Some(v);
                        }
                    }
                }
                true
            },
        );
        // Strictly longer than controld's own bound on this stream, so the
        // verdict the caller reports is the server's `exec.end` rather than a
        // local timeout that says nothing about whether the command ran
        // (trap 31).
        let deadline =
            std::time::Duration::from_millis(crate::errors::exec_deadline_ms(spec.timeout_ms));
        let status = tokio::time::timeout(deadline, stream)
            .await
            .map_err(|_| ApiError::Deadline)?
            .map_err(|e| ApiError::Transport(e.to_string()))?;

        if let Some(end) = end {
            return Ok(end);
        }
        if let Some(r) = streamed_refusal {
            let code = r
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("exec_refused")
                .to_owned();
            let detail = r.get("detail").and_then(Value::as_str).map(str::to_owned);
            return Err(ApiError::Api {
                status,
                code,
                detail,
                body: r,
            });
        }
        Err(ApiError::Transport(format!(
            "the exec stream ended without `exec.end` (HTTP {status}). Whether the command              ran is UNKNOWN — this is not a zero exit, and must not be treated as one."
        )))
    }

    /// GET /v1/workspaces/:id/lineage — the head snapshot and the fork tree.
    ///
    /// Returns `(kind, pool_id)` of the snapshot this workspace RESUMES from,
    /// or `None` when it has never been sealed. A client needs this to tell a
    /// warm resume from a cold boot without reaching into the database, which
    /// no client may do (I6: there is no privileged interface).
    pub async fn head_snapshot(
        &self,
        workspace: &str,
        auth: Auth<'_>,
    ) -> Result<Option<(String, Option<String>)>, ApiError> {
        let path = format!("/v1/workspaces/{}/lineage", encode_segment(workspace));
        let resp =
            http_min::get_json_trust(&self.controld, &path, Some(auth.bearer()), &self.trust)
                .await
                .map_err(|e| ApiError::Transport(format!("{e:#}")))?;
        if !(200..300).contains(&resp.status) {
            return Err(refusal(resp));
        }
        let head = &resp.body["head_snapshot"];
        Ok(head["kind"]
            .as_str()
            .map(|k| (k.to_owned(), head["pool_id"].as_str().map(str::to_owned))))
    }

    /// POST /v1/workspaces/:id/fork → a child workspace rooted at a sealed
    /// snapshot of the source (§8 flow 5). Owner-only: a fork spends a
    /// `max_workspaces` slot. `snapshot_id: None` forks the current head.
    pub async fn fork(
        &self,
        workspace: &str,
        biscuit_b64: &str,
        snapshot_id: Option<&str>,
        name: Option<&str>,
    ) -> Result<Forked, ApiError> {
        let mut req = json!({ "biscuit": biscuit_b64 });
        if let Some(id) = snapshot_id {
            req["snapshot_id"] = json!(id);
        }
        if let Some(n) = name {
            req["name"] = json!(n);
        }
        let body = self
            .post(
                &format!("/v1/workspaces/{}/fork", encode_segment(workspace)),
                req,
            )
            .await?;
        Ok(Forked {
            workspace: str_at(&body, &["workspace", "id"])?,
            name: str_at(&body, &["workspace", "name"]).unwrap_or_default(),
            origin_snapshot: str_at(&body, &["origin_snapshot", "id"])?,
            origin_log_seq: u64_at(&body, &["origin_snapshot", "log_seq"]).unwrap_or(0),
            biscuit_b64: str_at(&body, &["biscuit"])?,
        })
    }

    /// POST /v1/workspaces/:id/rewind → move the head to an earlier sealed
    /// snapshot of THIS workspace (§8 flow 6). Owner-only, refused while a
    /// node holds the lease (`lease_held` — pause first). The forward history
    /// is preserved as an auto-created fork, never destroyed.
    pub async fn rewind(
        &self,
        workspace: &str,
        biscuit_b64: &str,
        snapshot_id: &str,
        preserved_name: Option<&str>,
    ) -> Result<Rewound, ApiError> {
        let mut req = json!({ "biscuit": biscuit_b64, "snapshot_id": snapshot_id });
        if let Some(n) = preserved_name {
            req["preserved_name"] = json!(n);
        }
        let body = self
            .post(
                &format!("/v1/workspaces/{}/rewind", encode_segment(workspace)),
                req,
            )
            .await?;
        Ok(Rewound {
            head_snapshot: str_at(&body, &["head_snapshot", "id"])?,
            head_log_seq: u64_at(&body, &["head_snapshot", "log_seq"]).unwrap_or(0),
            preserved_fork: str_at(&body, &["preserved_fork", "id"])?,
            preserved_fork_name: str_at(&body, &["preserved_fork", "name"]).unwrap_or_default(),
        })
    }

    /// GET /v1/workspaces/:id/lineage → every sealed snapshot (oldest first)
    /// and the head this workspace resumes from. This is what makes `rewind`
    /// drivable: a caller picks a snapshot id off this list.
    ///
    /// The token travels as `Authorization: Bearer`, not in the query: hub
    /// logs the request line of every non-success it proxies, and a credential
    /// in a URL is a credential in a log file.
    pub async fn lineage(&self, workspace: &str, auth: Auth<'_>) -> Result<Lineage, ApiError> {
        let path = format!("/v1/workspaces/{}/lineage", encode_segment(workspace));
        let resp =
            http_min::get_json_trust(&self.controld, &path, Some(auth.bearer()), &self.trust)
                .await
                .map_err(|e| ApiError::Transport(format!("{e:#}")))?;
        if !(200..300).contains(&resp.status) {
            return Err(refusal(resp));
        }
        let snapshot_row = |v: &Value| SnapshotRow {
            id: v["id"].as_str().unwrap_or_default().to_owned(),
            kind: v["kind"].as_str().unwrap_or_default().to_owned(),
            log_seq: v["log_seq"].as_u64().unwrap_or(0),
            sealed_at_ms: v["sealed_at_ms"].as_u64().unwrap_or(0),
            pool_id: v["pool_id"].as_str().map(str::to_owned),
        };
        Ok(Lineage {
            head: resp
                .body
                .get("head_snapshot")
                .filter(|h| !h.is_null())
                .map(snapshot_row),
            snapshots: resp
                .body
                .get("snapshots")
                .and_then(Value::as_array)
                .map(|rows| rows.iter().map(snapshot_row).collect())
                .unwrap_or_default(),
            forks: resp
                .body
                .get("forks")
                .and_then(Value::as_array)
                .map(|rows| {
                    rows.iter()
                        .map(|w| w["id"].as_str().unwrap_or_default().to_owned())
                        .collect()
                })
                .unwrap_or_default(),
        })
    }

    /// POST /v1/api-keys → mint an `rpak1.…` (ADR-0059 §4). The operator
    /// credential travels in the BODY — that is the route's own shape.
    /// The value is returned once and never recoverable.
    pub async fn create_api_key(
        &self,
        operator_token: &str,
        label: Option<&str>,
        role: &str,
        workspace_ids: Option<&[String]>,
        ttl_ms: Option<u64>,
    ) -> Result<ApiKeyMinted, ApiError> {
        let mut req = json!({ "operator_token": operator_token, "role": role });
        if let Some(l) = label {
            req["label"] = json!(l);
        }
        if let Some(ids) = workspace_ids {
            req["workspace_ids"] = json!(ids);
        }
        if let Some(t) = ttl_ms {
            req["ttl_ms"] = json!(t);
        }
        let body = self.post("/v1/api-keys", req).await?;
        Ok(ApiKeyMinted {
            key: str_at(&body, &["api_key"])?,
            id: str_at(&body, &["key_id"])?,
            role: str_at(&body, &["role"])?,
            expires_at_ms: u64_at(&body, &["expires_at_ms"])?,
        })
    }

    /// GET /v1/api-keys (operator credential in a JSON body — the route's own
    /// shape) → metadata only; the secret half is never readable again.
    pub async fn list_api_keys(&self, operator_token: &str) -> Result<Vec<ApiKeyRow>, ApiError> {
        let resp = http_min::get_json_body_trust(
            &self.controld,
            "/v1/api-keys",
            &json!({ "operator_token": operator_token }),
            &self.trust,
        )
        .await
        .map_err(|e| ApiError::Transport(format!("{e:#}")))?;
        if !(200..300).contains(&resp.status) {
            return Err(refusal(resp));
        }
        let body = resp.body;
        let rows = at(&body, &["api_keys"])?
            .as_array()
            .ok_or_else(|| ApiError::Shape("api_keys is not an array".to_owned()))?;
        Ok(rows
            .iter()
            .map(|k| ApiKeyRow {
                id: k["key_id"].as_str().unwrap_or_default().to_owned(),
                label: k["label"].as_str().unwrap_or_default().to_owned(),
                role: k["role"].as_str().unwrap_or_default().to_owned(),
                workspace_ids: k["workspace_ids"]
                    .as_array()
                    .map(|ids| {
                        ids.iter()
                            .filter_map(Value::as_str)
                            .map(str::to_owned)
                            .collect()
                    })
                    .unwrap_or_default(),
                expires_at_ms: k["expires_at_ms"].as_u64().unwrap_or(0),
                revoked_at_ms: k["revoked_at_ms"].as_u64(),
                usable: k["usable"].as_bool().unwrap_or(false),
            })
            .collect())
    }

    /// POST /v1/api-keys/:id/revoke — idempotent; "not yours" and "no such
    /// key" are the same `404 unknown_api_key` by design.
    pub async fn revoke_api_key(&self, operator_token: &str, key_id: &str) -> Result<(), ApiError> {
        self.post(
            &format!("/v1/api-keys/{}/revoke", encode_segment(key_id)),
            json!({ "operator_token": operator_token }),
        )
        .await
        .map(|_| ())
    }

    /// POST /v1/workspaces/:id/token → an owner Biscuit for a workspace this
    /// user already owns (ADR-0060, [trap 33]).
    ///
    /// This is the ONE edge from identity authority to workspace authority for
    /// a workspace that already exists. Before it, a workspace whose one-hour
    /// chain had lapsed could not be attached, could not be archived, and so
    /// held its `max_workspaces` slot for good.
    pub async fn workspace_token(
        &self,
        workspace: &str,
        user_id: &str,
        identity_token: &str,
    ) -> Result<(String, u64), ApiError> {
        let body = self
            .post(
                &format!("/v1/workspaces/{}/token", encode_segment(workspace)),
                json!({ "user_id": user_id, "identity_token": identity_token }),
            )
            .await?;
        Ok((
            str_at(&body, &["biscuit"])?,
            u64_at(&body, &["expires_at_ms"])?,
        ))
    }

    /// POST /v1/workspaces/:id/archive. Owner-only, and it deletes nothing
    /// immediately: the chain and the log stay, the workspace stops counting
    /// against `max_workspaces` (I13). Archived state follows ADR-0070's
    /// managed-retention boundary rather than a permanent-backup promise.
    /// Returns when it was archived.
    pub async fn archive(&self, workspace: &str, auth: Auth<'_>) -> Result<u64, ApiError> {
        let (bearer, biscuit) = auth.split();
        let body = self
            .post_auth(
                &format!("/v1/workspaces/{}/archive", encode_segment(workspace)),
                json!({ "biscuit": biscuit.unwrap_or_default() }),
                bearer,
            )
            .await?;
        Ok(u64_at(&body, &["archived_at_ms"]).unwrap_or(0))
    }

    /// POST /v1/grants — authorized by the presented Biscuit, not by who is
    /// asking (I6). Returns the server-minted share token.
    pub async fn grant(
        &self,
        workspace: &str,
        biscuit_b64: &str,
        grantee: &str,
        role: &str,
        expires_at_ms: u64,
    ) -> Result<Share, ApiError> {
        let body = self
            .post(
                "/v1/grants",
                json!({
                    "workspace_id": workspace,
                    "biscuit": biscuit_b64,
                    "grantee_principal_id": grantee,
                    "role": role,
                    "expires_at_ms": expires_at_ms,
                }),
            )
            .await?;
        Ok(Share {
            role: str_at(&body, &["grant", "role"])?,
            expires_at_ms: u64_at(&body, &["grant", "expires_at_ms"])?,
            share_token_b64: str_at(&body, &["share_token"])?,
        })
    }
}

/// Did this refusal mean "this fleet has no such ROUTE" rather than "no such
/// workspace"?
///
/// controld answers an unknown workspace with its own `workspace_not_found`
/// (the 404-collapse), and hub answers an unproxied path with `not_found`; a
/// 404 with no code at all is an axum router that never heard of the path.
/// Telling them apart is what lets `status` fall back on an older fleet
/// instead of claiming the workspace is gone.
#[must_use]
pub fn is_route_absent(err: &ApiError) -> bool {
    matches!(
        err,
        ApiError::Api { status: 404, code, .. } if code == "unknown" || code == "not_found"
    )
}

fn limits_of(value: &Value) -> Option<Limits> {
    value.as_object().map(|l| Limits {
        max_workspaces: l.get("max_workspaces").and_then(Value::as_u64),
        max_concurrent: l.get("max_concurrent").and_then(Value::as_u64),
        live_workspaces: l
            .get("live_workspaces")
            .and_then(Value::as_u64)
            .unwrap_or(0),
    })
}

fn parent_of(origin: &Value) -> Option<Parent> {
    Some(Parent {
        workspace: origin["workspace_id"].as_str()?.to_owned(),
        snapshot: origin["snapshot_id"].as_str().map(str::to_owned),
    })
}

fn string_array(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn at<'v>(body: &'v Value, path: &[&str]) -> Result<&'v Value, ApiError> {
    let mut cur = body;
    for key in path {
        cur = cur
            .get(key)
            .ok_or_else(|| ApiError::Shape(format!("missing field {}", path.join("."))))?;
    }
    Ok(cur)
}

fn str_at(body: &Value, path: &[&str]) -> Result<String, ApiError> {
    at(body, path)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| ApiError::Shape(format!("field {} is not a string", path.join("."))))
}

fn u64_at(body: &Value, path: &[&str]) -> Result<u64, ApiError> {
    at(body, path)?
        .as_u64()
        .ok_or_else(|| ApiError::Shape(format!("field {} is not a u64", path.join("."))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_encoding_cannot_reshape_the_request_line() {
        assert_eq!(encode_query("dev-user"), "dev-user");
        assert_eq!(encode_query("a b"), "a%20b");
        assert_eq!(
            encode_query("x HTTP/1.1\r\nX: y"),
            "x%20HTTP%2F1.1%0D%0AX%3A%20y"
        );
        assert_eq!(encode_query("a&b=c"), "a%26b%3Dc");
    }

    /// The same property for the PATH: a workspace id that came from a file,
    /// an environment variable or an agent's output cannot add a path element
    /// or a second request line to the request this client builds.
    #[test]
    fn a_workspace_id_cannot_reshape_the_request_line_either() {
        assert_eq!(encode_segment("ws-402"), "ws-402");
        assert_eq!(
            encode_segment("ws-1 HTTP/1.1\r\nX: y"),
            "ws-1%20HTTP%2F1.1%0D%0AX%3A%20y"
        );
        assert_eq!(
            encode_segment("../../admin/v1/nodes"),
            "..%2F..%2Fadmin%2Fv1%2Fnodes"
        );
        assert_eq!(encode_segment("ws-1?biscuit=x"), "ws-1%3Fbiscuit%3Dx");
    }

    #[test]
    fn value_extraction_reports_the_missing_path() {
        let body = json!({ "workspace": { "id": "ws-1" }, "fencing_token": 4 });
        assert_eq!(str_at(&body, &["workspace", "id"]).unwrap(), "ws-1");
        assert_eq!(u64_at(&body, &["fencing_token"]).unwrap(), 4);
        let err = str_at(&body, &["workspace", "name"]).unwrap_err();
        assert!(err.to_string().contains("workspace.name"), "{err}");
        let err = u64_at(&body, &["workspace", "id"]).unwrap_err();
        assert!(err.to_string().contains("not a u64"), "{err}");
    }
}
