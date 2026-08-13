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

/// How an exec proves it may run: the caller's own capability, or an API key
/// that mints one server-side (ADR-0059 §4).
///
/// An enum rather than two optional strings so "neither" and "both" are
/// unrepresentable — the first is a request the server must refuse and the
/// second is a question about precedence nobody should have to answer.
#[derive(Clone, Copy, Debug)]
pub enum ExecAuth<'a> {
    Biscuit(&'a str),
    ApiKey(&'a str),
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
    },
    #[error("unexpected response shape: {0}")]
    Shape(String),
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
#[derive(Debug, Clone)]
pub struct OperatorSession {
    pub user_id: String,
    pub principal_id: String,
    pub identity_token: String,
    pub expires_at_ms: u64,
}

/// One row of `reach ws list`.
#[derive(Debug, Clone)]
pub struct Workspace {
    pub id: String,
    pub name: String,
    pub forks: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreditBalance {
    pub balance_millicredits: u64,
    pub unit: String,
    pub updated_at_ms: u64,
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
            let code = resp
                .body
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_owned();
            Err(ApiError::Api {
                status: resp.status,
                code,
                detail: resp
                    .body
                    .get("detail")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
            })
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
        })
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
    ) -> Result<Vec<Workspace>, ApiError> {
        let path = format!("/v1/workspaces?user_id={}", encode_query(user_id));
        let resp =
            http_min::get_json_trust(&self.controld, &path, Some(identity_token), &self.trust)
                .await
                .map_err(|e| ApiError::Transport(format!("{e:#}")))?;
        if !(200..300).contains(&resp.status) {
            let code = resp
                .body
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_owned();
            return Err(ApiError::Api {
                status: resp.status,
                code,
                detail: resp
                    .body
                    .get("detail")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
            });
        }
        let rows = at(&resp.body, &["workspaces"])?
            .as_array()
            .ok_or_else(|| ApiError::Shape("workspaces is not an array".to_owned()))?;
        rows.iter()
            .map(|row| {
                Ok(Workspace {
                    id: str_at(row, &["id"])?,
                    name: str_at(row, &["name"]).unwrap_or_default(),
                    forks: row
                        .get("forks")
                        .and_then(Value::as_array)
                        .map(Vec::len)
                        .unwrap_or(0),
                })
            })
            .collect()
    }

    /// POST /v1/workspaces/:id/attach → node, fencing token, Biscuit.
    pub async fn attach(&self, workspace: &str, biscuit_b64: &str) -> Result<Attach, ApiError> {
        let body = self
            .post(
                &format!("/v1/workspaces/{workspace}/attach"),
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
        biscuit_b64: &str,
        fencing_token: u64,
        discard: bool,
    ) -> Result<bool, ApiError> {
        let body = self
            .post(
                &format!("/v1/workspaces/{workspace}/release"),
                json!({
                    "fencing_token": fencing_token,
                    "biscuit": biscuit_b64,
                    "discard": discard,
                }),
            )
            .await?;
        Ok(body["released"].as_bool().unwrap_or(false))
    }

    /// POST /v1/workspaces/:id/exec — run one command (ADR-0059).
    ///
    /// Streams: `on_out` is called with `(fd, bytes)` for each output chunk as
    /// it arrives, never after the fact. The return value is the terminating
    /// `exec.end` object.
    ///
    /// **A stream that ends without `exec.end` is a FAILURE**, and this
    /// function turns that into an `Err` rather than a zero exit — §6's rule,
    /// enforced at the one place every caller goes through, because a caller
    /// that has to remember it is a caller that will not.
    pub async fn exec<F>(
        &self,
        workspace: &str,
        auth: ExecAuth<'_>,
        spec: &ExecSpec<'_>,
        mut on_out: F,
    ) -> Result<Value, ApiError>
    where
        F: FnMut(u8, &[u8]),
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
        let bearer = match auth {
            ExecAuth::ApiKey(k) => Some(k),
            ExecAuth::Biscuit(b) => {
                body["biscuit"] = json!(b);
                None
            }
        };
        let mut end: Option<Value> = None;
        let mut refusal: Option<Value> = None;
        let status = http_min::post_ndjson_stream(
            &self.controld,
            &format!("/v1/workspaces/{workspace}/exec"),
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
                                on_out(fd, &bytes);
                            }
                        }
                    }
                    Some("exec.waiting") => {
                        // The workspace was paused and this exec woke it. Said
                        // out loud so a caller knows the delay is a RESUME and
                        // not a hang.
                        eprintln!("reachpad: workspace is resuming…");
                    }
                    Some("exec.end") => end = Some(v),
                    // A non-streamed refusal (the request never became a
                    // stream): keep it so the error names what happened.
                    _ => {
                        if v.get("error").is_some() {
                            refusal = Some(v);
                        }
                    }
                }
                true
            },
        )
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))?;

        if let Some(end) = end {
            return Ok(end);
        }
        if let Some(r) = refusal {
            return Err(ApiError::Api {
                status,
                code: r
                    .get("error")
                    .and_then(Value::as_str)
                    .unwrap_or("exec_refused")
                    .to_owned(),
                detail: r.get("detail").and_then(Value::as_str).map(str::to_owned),
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
        biscuit_b64: &str,
    ) -> Result<Option<(String, Option<String>)>, ApiError> {
        let path = format!(
            "/v1/workspaces/{workspace}/lineage?biscuit={}",
            encode_query(biscuit_b64)
        );
        let resp = http_min::get_json_trust(&self.controld, &path, None, &self.trust)
            .await
            .map_err(|e| ApiError::Transport(format!("{e:#}")))?;
        if !(200..300).contains(&resp.status) {
            return Err(ApiError::Api {
                status: resp.status,
                code: resp
                    .body
                    .get("error")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_owned(),
                detail: resp
                    .body
                    .get("detail")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
            });
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
            .post(&format!("/v1/workspaces/{workspace}/fork"), req)
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
            .post(&format!("/v1/workspaces/{workspace}/rewind"), req)
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
    pub async fn lineage(&self, workspace: &str, biscuit_b64: &str) -> Result<Lineage, ApiError> {
        let path = format!(
            "/v1/workspaces/{workspace}/lineage?biscuit={}",
            encode_query(biscuit_b64)
        );
        let resp = http_min::get_json_trust(&self.controld, &path, None, &self.trust)
            .await
            .map_err(|e| ApiError::Transport(format!("{e:#}")))?;
        if !(200..300).contains(&resp.status) {
            return Err(ApiError::Api {
                status: resp.status,
                code: resp
                    .body
                    .get("error")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_owned(),
                detail: resp
                    .body
                    .get("detail")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
            });
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
            return Err(ApiError::Api {
                status: resp.status,
                code: resp
                    .body
                    .get("error")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_owned(),
                detail: resp
                    .body
                    .get("detail")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
            });
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
            &format!("/v1/api-keys/{key_id}/revoke"),
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
                &format!("/v1/workspaces/{workspace}/token"),
                json!({ "user_id": user_id, "identity_token": identity_token }),
            )
            .await?;
        Ok((
            str_at(&body, &["biscuit"])?,
            u64_at(&body, &["expires_at_ms"])?,
        ))
    }

    /// POST /v1/workspaces/:id/archive. Owner-only, and it destroys nothing:
    /// the chain and the log stay, the workspace stops counting against
    /// `max_workspaces` (I13). Returns when it was archived.
    pub async fn archive(&self, workspace: &str, biscuit_b64: &str) -> Result<u64, ApiError> {
        let body = self
            .post(
                &format!("/v1/workspaces/{workspace}/archive"),
                json!({ "biscuit": biscuit_b64 }),
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
