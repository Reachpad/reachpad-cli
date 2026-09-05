//! The apps REST client: one bearer, one base URL, one error shape.
//!
//! Everything here goes to `https://reachpad.dev/api/apps` (reports/apps-v1
//! API.md), which is a DIFFERENT service from the fleet control plane every
//! other verb in this CLI talks to, with a different credential: the apps API
//! is a WorkOS-protected resource and takes the WorkOS access token as its
//! bearer, where controld takes the `rpop1` operator credential. Both come out
//! of the same `reachpad login`; see [`bearer`].
//!
//! Errors are uniform — `{ "error": code, "message": sentence }` — and
//! [`Apps::refuse`] prints the server's sentence verbatim, because a client
//! that paraphrases a server's refusal is a client that will one day paraphrase
//! it wrongly.

use serde_json::{json, Value};

use crate::conf;
use crate::errors::CliError;
use crate::http_min;
use crate::transport::TlsTrust;

/// The apps API, unless `REACHPAD_APPS_API` says otherwise.
pub const DEFAULT_APPS_API: &str = "https://reachpad.dev/api/apps";
/// The override, for Vercel previews and for the tests' fake server.
pub const APPS_API_ENV: &str = "REACHPAD_APPS_API";

/// Where this CLI is willing to send a WorkOS access token, and where it is
/// willing to PUT a customer's source.
///
/// The same posture as [`crate::cli_auth::validate_credential_origin`], widened
/// by exactly two things and no more: a path prefix (the apps API lives under
/// `/api/apps`, where the control plane lives at the root), and `*.vercel.app`
/// on 443, because API.md says the API is also served on any Vercel preview
/// origin and a preview is the only way to try a change before it is live.
/// Loopback keeps plaintext, which is what makes the fake-server tests possible
/// without a certificate.
pub fn validate_apps_origin(url: &str) -> Result<(), CliError> {
    let endpoint = http_min::parse_url(url).map_err(CliError::from)?;
    endpoint.ensure_confidential().map_err(CliError::from)?;
    if endpoint.is_loopback() {
        return Ok(());
    }
    let host = endpoint.host.as_str();
    let allowed = endpoint.scheme == http_min::Scheme::Tls
        && endpoint.port == 443
        && (host == "reachpad.dev"
            || host.ends_with(".reachpad.dev")
            || host.ends_with(".vercel.app"));
    if !allowed {
        return Err(super::failure(format!(
            "refusing to send your sign-in and your source to {host}: the apps API is \
             reachpad.dev, *.reachpad.dev or a Vercel preview on 443, or a server on this \
             machine, and nothing else."
        )));
    }
    Ok(())
}

/// A ready-to-use apps client: the base URL and a bearer that is known good for
/// the next few minutes.
pub struct Apps {
    base: String,
    bearer: String,
    trust: TlsTrust,
}

impl Apps {
    pub fn new(base: String, bearer: String, trust: TlsTrust) -> Result<Apps, CliError> {
        validate_apps_origin(&base)?;
        Ok(Apps {
            base: base.trim_end_matches('/').to_owned(),
            bearer,
            trust,
        })
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    // -- the calls ----------------------------------------------------------

    pub async fn me(&self) -> Result<Value, CliError> {
        self.get("/me").await
    }

    pub async fn resolve(&self, url: &str) -> Result<Value, CliError> {
        self.get(&format!("/resolve?url={}", encode(url))).await
    }

    pub async fn app(&self, id: &str) -> Result<Value, CliError> {
        self.get(&format!("/{}", encode(id))).await
    }

    pub async fn list(&self, query: &str) -> Result<Value, CliError> {
        self.get(&format!("?{query}")).await
    }

    pub async fn search(&self, query: &str) -> Result<Value, CliError> {
        self.get(&format!("/search?{query}")).await
    }

    pub async fn upload_ticket(&self, bytes: u64) -> Result<Value, CliError> {
        self.post("/uploads", &json!({ "bytes": bytes })).await
    }

    /// PUT the tarball at the ticket's absolute `put_url`. The ticket is the
    /// authorization, so no bearer travels with it — but the URL still goes
    /// through the origin allowlist, because the body is the customer's source.
    pub async fn put_snapshot(&self, put_url: &str, tarball: &[u8]) -> Result<Value, CliError> {
        let endpoint = http_min::parse_url(put_url).map_err(CliError::from)?;
        let base = match endpoint.scheme {
            http_min::Scheme::Tls => format!("https://{}", endpoint.authority()),
            http_min::Scheme::Plaintext => format!("http://{}", endpoint.authority()),
        };
        validate_apps_origin(&base)?;
        let path = if endpoint.base_path.is_empty() {
            "/".to_owned()
        } else {
            endpoint.base_path.clone()
        };
        let raw = http_min::request_bytes(
            &base,
            "PUT",
            &path,
            tarball,
            "application/gzip",
            None,
            &self.trust,
        )
        .await
        .map_err(CliError::from)?;
        if !(200..300).contains(&raw.status) {
            return Err(refuse(raw.status, &raw.json()));
        }
        Ok(raw.json())
    }

    pub async fn create_app(&self, body: &Value) -> Result<Value, CliError> {
        self.post("", body).await
    }

    pub async fn create_version(&self, app: &str, body: &Value) -> Result<Value, CliError> {
        self.post(&format!("/{}/versions", encode(app)), body).await
    }

    pub async fn promote(&self, app: &str, number: u64) -> Result<Value, CliError> {
        self.post(
            &format!("/{}/versions/{number}/promote", encode(app)),
            &json!({}),
        )
        .await
    }

    pub async fn versions(&self, app: &str, limit: u32) -> Result<Value, CliError> {
        self.get(&format!("/{}/versions?limit={limit}", encode(app)))
            .await
    }

    /// One file, or the whole snapshot as a tarball, from a version.
    pub async fn source(
        &self,
        app: &str,
        version: Option<u64>,
        query: &str,
    ) -> Result<http_min::Raw, CliError> {
        let mut path = format!("/{}/source?{query}", encode(app));
        if let Some(number) = version {
            path.push_str(&format!("&version={number}"));
        }
        let raw = http_min::request_bytes(
            &self.base,
            "GET",
            &path,
            &[],
            "application/json",
            Some(&self.bearer),
            &self.trust,
        )
        .await
        .map_err(CliError::from)?;
        if !(200..300).contains(&raw.status) {
            return Err(refuse(raw.status, &raw.json()));
        }
        Ok(raw)
    }

    pub async fn set_access(&self, app: &str, body: &Value) -> Result<Value, CliError> {
        self.send("PUT", &format!("/{}/access", encode(app)), Some(body))
            .await
    }

    pub async fn patch_app(&self, app: &str, body: &Value) -> Result<Value, CliError> {
        self.send("PATCH", &format!("/{}", encode(app)), Some(body))
            .await
    }

    pub async fn shares(&self, app: &str) -> Result<Value, CliError> {
        self.get(&format!("/{}/shares", encode(app))).await
    }

    pub async fn add_share(&self, app: &str, body: &Value) -> Result<Value, CliError> {
        self.post(&format!("/{}/shares", encode(app)), body).await
    }

    pub async fn revoke_share(&self, app: &str, share: &str) -> Result<Value, CliError> {
        self.send(
            "DELETE",
            &format!("/{}/shares/{}", encode(app), encode(share)),
            None,
        )
        .await
    }

    // -- the org's secrets, which belong to no app --------------------------

    /// `…/api/apps` with the last segment dropped: `…/api`.
    ///
    /// The secret routes are SIBLINGS of the apps API, not children of it, and
    /// the base URL this client was built with is the one thing that has been
    /// through [`validate_apps_origin`]. Deriving the root from it keeps both
    /// on the one validated origin, and keeps `REACHPAD_APPS_API` pointing a
    /// preview's secrets at that same preview.
    fn org_root(&self) -> String {
        self.base
            .strip_suffix("/apps")
            .unwrap_or(&self.base)
            .to_owned()
    }

    /// Set one org secret. The value travels in the body and nowhere else: not
    /// in the path, not in a query string, not in a log line.
    pub async fn set_secret(&self, name: &str, value: &str) -> Result<Value, CliError> {
        self.send_to(
            &self.org_root(),
            "PUT",
            &format!("/secrets/{}", encode(name)),
            Some(&json!({ "value": value })),
        )
        .await
    }

    /// Every secret the org has set. Names and metadata; never values.
    pub async fn secrets(&self) -> Result<Value, CliError> {
        self.send_to(&self.org_root(), "GET", "/secrets", None)
            .await
    }

    pub async fn remove_secret(&self, name: &str) -> Result<Value, CliError> {
        self.send_to(
            &self.org_root(),
            "DELETE",
            &format!("/secrets/{}", encode(name)),
            None,
        )
        .await
    }

    pub async fn folders(&self) -> Result<Value, CliError> {
        self.get("/folders").await
    }

    pub async fn create_folder(&self, body: &Value) -> Result<Value, CliError> {
        self.post("/folders", body).await
    }

    pub async fn patch_folder(&self, id: &str, body: &Value) -> Result<Value, CliError> {
        self.send("PATCH", &format!("/folders/{}", encode(id)), Some(body))
            .await
    }

    pub async fn delete_folder(&self, id: &str) -> Result<Value, CliError> {
        self.send("DELETE", &format!("/folders/{}", encode(id)), None)
            .await
    }

    pub async fn logs(&self, app: &str, query: &str) -> Result<Value, CliError> {
        self.get(&format!("/{}/logs?{query}", encode(app))).await
    }

    /// One SQL statement against the app's database. The body is the whole of
    /// the contract: `{ "sql": …, "params": [...] }` in, `{ "rows": [...],
    /// "changes": n, "lastInsertRowid": n }` back.
    pub async fn db(&self, app: &str, body: &Value) -> Result<Value, CliError> {
        self.post(&format!("/{}/db", encode(app)), body).await
    }

    // -- the one place a request is made ------------------------------------

    async fn get(&self, path: &str) -> Result<Value, CliError> {
        self.send("GET", path, None).await
    }

    async fn post(&self, path: &str, body: &Value) -> Result<Value, CliError> {
        self.send("POST", path, Some(body)).await
    }

    async fn send(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Value, CliError> {
        self.send_to(&self.base, method, path, body).await
    }

    async fn send_to(
        &self,
        base: &str,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Value, CliError> {
        let response =
            http_min::json_request(base, method, path, body, Some(&self.bearer), &self.trust)
                .await
                .map_err(CliError::from)?;
        if !(200..300).contains(&response.status) {
            return Err(refuse(response.status, &response.body));
        }
        Ok(response.body)
    }
}

/// The API's refusal, said the API's way.
///
/// CLI.md is exact about this: print the `message` verbatim and exit 1, except
/// for 401, where the sentence a person can act on is the one this CLI owns.
/// A body with no message at all still names the status, because "it failed" is
/// not something anyone can do anything with.
pub fn refuse(status: u16, body: &Value) -> CliError {
    if status == 401 {
        return CliError {
            code: "unauthorized".to_owned(),
            message: "Run `reachpad login`.".to_owned(),
            next_command: Some("reachpad login".to_owned()),
            retriable: false,
            status: Some(status),
            exit_code: 1,
            data: None,
        };
    }
    let code = body["error"].as_str().unwrap_or("request_failed");
    // The sentence, else the code, else the status. A body that carries only
    // `{"error": "schema_change_refused"}` says more with its code than a
    // sentence about the status number does.
    let message = body["message"]
        .as_str()
        .or_else(|| body["error"].as_str())
        .map(str::to_owned)
        .unwrap_or_else(|| format!("the apps API answered {status} and said nothing more."));
    CliError {
        code: code.to_owned(),
        message,
        next_command: None,
        retriable: matches!(status, 429 | 500 | 503),
        status: Some(status),
        exit_code: 1,
        data: None,
    }
}

/// Percent-encode one query-string or path component. Deliberately strict:
/// everything but the unreserved set is escaped, so a slug, an email or a URL
/// cannot smuggle a `&`, a `?` or a path segment into the request.
pub fn encode(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(char::from(byte))
            }
            other => {
                out.push('%');
                out.push(char::from(HEX[usize::from(other >> 4)]));
                out.push(char::from(HEX[usize::from(other & 0x0f)]));
            }
        }
    }
    out
}

/// The bearer for the apps API, refreshed and re-saved when it has gone stale.
///
/// This is the whole of the auth story CLI.md asked about. `reachpad login`
/// already runs the WorkOS device flow; what it did NOT do was keep the tokens,
/// so the pair is now persisted beside the operator credential and spent here.
/// A refresh rotates both halves, so the write-back is not optional — the old
/// refresh token stops working the moment the new one is issued.
pub async fn bearer(paths: &conf::Paths, now_ms: u64) -> Result<String, CliError> {
    let credential = match conf::load_credential(paths, now_ms)? {
        conf::Stored::Present(credential) => credential,
        conf::Stored::Missing | conf::Stored::Expired => {
            return Err(super::failure("Run `reachpad login`."))
        }
    };
    if let Some(access) = credential.workos_access(now_ms) {
        return Ok(access.to_owned());
    }
    let Some(session) = credential.workos.clone() else {
        // The `--operator-token` path: a real Reachpad credential, and no
        // WorkOS session at all. Say which sign-in is missing rather than
        // "unauthorized".
        return Err(super::failure(
            "This machine signed in with an operator credential, which the apps API does not \
             take. Run `reachpad login` to sign in through your browser.",
        ));
    };
    let refreshed = match crate::cli_auth::refresh_workos(&session).await {
        Ok(refreshed) => refreshed,
        Err(e) => {
            // The refresh token rotates, so two `reachpad` commands started at
            // once both spend the same one and exactly one of them wins. The
            // loser's token is not broken, it is superseded — and the winner
            // has already written the replacement to the file both read. Look
            // there before telling anyone to sign in again.
            if let Some(access) = reread_access(paths, now_ms, &session) {
                return Ok(access);
            }
            return Err(super::failure(format!("{e:#} Run `reachpad login`.")));
        }
    };
    let access = refreshed.access_token.clone();
    store_workos(paths, now_ms, refreshed)?;
    Ok(access)
}

/// The access token another process wrote while this one was refreshing, if it
/// wrote one and it is not the token this process just spent.
fn reread_access(paths: &conf::Paths, now_ms: u64, spent: &conf::WorkosSession) -> Option<String> {
    let conf::Stored::Present(current) = conf::load_credential(paths, now_ms).ok()? else {
        return None;
    };
    let fresh = current.workos_access(now_ms)?;
    (fresh != spent.access_token).then(|| fresh.to_owned())
}

/// Write the refreshed session back, MERGED into whatever is on disk now.
///
/// Not into the record this process read a moment ago: `save_credential`
/// replaces the whole profile section, so writing a stale copy of it would undo
/// a `reachpad login` that landed in between — reinstating an operator token
/// the fleet has already revoked. Only the WorkOS half is this function's to
/// change.
fn store_workos(
    paths: &conf::Paths,
    now_ms: u64,
    refreshed: conf::WorkosSession,
) -> Result<(), CliError> {
    let current = match conf::load_credential(paths, now_ms)? {
        conf::Stored::Present(current) => current,
        // The credential went away underneath us (a `logout` in another
        // window). Re-creating it here would resurrect a sign-in the person
        // just ended, so the refreshed session is dropped instead.
        conf::Stored::Missing | conf::Stored::Expired => return Ok(()),
    };
    conf::save_credential(
        paths,
        &conf::Credential {
            workos: Some(refreshed),
            ..current
        },
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> conf::Paths {
        let home = std::env::temp_dir().join(format!(
            "reach-apps-client-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        conf::Paths::under(&home, conf::DEFAULT_PROFILE)
    }

    fn session(access: &str, refresh: &str) -> conf::WorkosSession {
        conf::WorkosSession {
            access_token: access.to_owned(),
            refresh_token: refresh.to_owned(),
            expires_at_ms: Some(4_102_444_800_000),
            client_id: "client_test".to_owned(),
        }
    }

    fn stored(paths: &conf::Paths) -> conf::Credential {
        match conf::load_credential(paths, 1_000).unwrap() {
            conf::Stored::Present(credential) => credential,
            other => panic!("no credential: {other:?}"),
        }
    }

    /// `save_credential` REPLACES the whole profile section, so writing back a
    /// copy read before the refresh started undoes anything that landed in
    /// between — a `reachpad login` in another window, whose operator token is
    /// the one the fleet now accepts. Only the WorkOS half is this path's.
    #[test]
    fn a_refresh_write_back_keeps_the_operator_token_that_is_on_disk_now() {
        let paths = scratch("merge");
        conf::save_credential(
            &paths,
            &conf::Credential {
                operator_token: "rpop1.old.secret".into(),
                token_id: Some("tok-old".into()),
                expires_at_ms: None,
                endpoint_host: Some("m1.reachpad.dev".into()),
                workos: Some(session("access-1", "refresh-1")),
            },
        )
        .unwrap();
        // What this process read when it decided to refresh.
        let read_earlier = stored(&paths);
        // A `login` in another window lands while the refresh is in flight.
        conf::save_credential(
            &paths,
            &conf::Credential {
                operator_token: "rpop1.new.secret".into(),
                token_id: Some("tok-new".into()),
                ..read_earlier
            },
        )
        .unwrap();

        store_workos(&paths, 1_000, session("access-2", "refresh-2")).unwrap();

        let after = stored(&paths);
        assert_eq!(after.operator_token, "rpop1.new.secret");
        assert_eq!(after.token_id.as_deref(), Some("tok-new"));
        assert_eq!(after.workos.as_ref().unwrap().access_token, "access-2");
        assert_eq!(after.workos.as_ref().unwrap().refresh_token, "refresh-2");
    }

    /// An apps-only record (PR #128: a sign-in against an endpoint with no
    /// fleet, so no operator half at all) has to come out of a refresh
    /// unchanged except for the two tokens that were refreshed. Nothing here
    /// may invent an operator token, and nothing may drop the WorkOS keys and
    /// leave the file reading as "no credential".
    #[test]
    fn an_apps_only_record_survives_a_refresh_with_only_the_tokens_changed() {
        let paths = scratch("apps-only-refresh");
        let before = conf::Credential {
            operator_token: String::new(),
            token_id: None,
            expires_at_ms: None,
            endpoint_host: Some("reachpad.dev".into()),
            workos: Some(session("access-1", "refresh-1")),
        };
        conf::save_credential(&paths, &before).unwrap();
        assert_eq!(stored(&paths), before);

        store_workos(&paths, 1_000, session("access-2", "refresh-2")).unwrap();

        assert_eq!(
            stored(&paths),
            conf::Credential {
                workos: Some(session("access-2", "refresh-2")),
                ..before
            }
        );
    }

    /// A `logout` in another window while a refresh is in flight must not be
    /// undone by the write-back: the credential is gone on purpose.
    #[test]
    fn a_refresh_does_not_resurrect_a_credential_that_was_just_logged_out() {
        let paths = scratch("logout");
        conf::save_credential(
            &paths,
            &conf::Credential {
                operator_token: "rpop1.old.secret".into(),
                token_id: None,
                expires_at_ms: None,
                endpoint_host: None,
                workos: Some(session("access-1", "refresh-1")),
            },
        )
        .unwrap();
        conf::forget_credential(&paths).unwrap();
        store_workos(&paths, 1_000, session("access-2", "refresh-2")).unwrap();
        assert_eq!(
            conf::load_credential(&paths, 1_000).unwrap(),
            conf::Stored::Missing
        );
    }

    /// WorkOS rotates the refresh token, so two commands started at once both
    /// spend the same one and exactly one is refused. The loser's session is
    /// not broken; the winner has already written its replacement to the file
    /// they share, and telling the person to sign in again is wrong.
    #[test]
    fn a_lost_refresh_race_reads_the_winners_token_instead_of_demanding_a_login() {
        let paths = scratch("race");
        let spent = session("access-1", "refresh-1");
        conf::save_credential(
            &paths,
            &conf::Credential {
                operator_token: "rpop1.a.b".into(),
                token_id: None,
                expires_at_ms: None,
                endpoint_host: None,
                workos: Some(spent.clone()),
            },
        )
        .unwrap();
        // Nothing new on disk yet: the failure is a real one.
        assert_eq!(reread_access(&paths, 1_000, &spent), None);
        // The other process wins and writes the replacement.
        store_workos(&paths, 1_000, session("access-2", "refresh-2")).unwrap();
        assert_eq!(
            reread_access(&paths, 1_000, &spent),
            Some("access-2".to_owned())
        );
    }

    #[test]
    fn the_apps_origin_allowlist_is_the_credential_one_plus_previews() {
        assert!(validate_apps_origin("https://reachpad.dev/api/apps").is_ok());
        assert!(validate_apps_origin("https://staging.reachpad.dev/api/apps").is_ok());
        assert!(validate_apps_origin("https://reachpad-abc123.vercel.app/api/apps").is_ok());
        assert!(validate_apps_origin("http://127.0.0.1:7777/api/apps").is_ok());
        // Everything else, including a lookalike and a non-443 port.
        assert!(validate_apps_origin("https://example.com/api/apps").is_err());
        assert!(validate_apps_origin("https://reachpad.dev.example.com/api").is_err());
        assert!(validate_apps_origin("https://reachpad.dev:8443/api/apps").is_err());
        assert!(validate_apps_origin("http://reachpad.dev/api/apps").is_err());
    }

    #[test]
    fn a_refusal_is_the_servers_sentence_and_exit_one() {
        let error = refuse(
            409,
            &json!({ "error": "slug_taken", "message": "That address is already in use." }),
        );
        assert_eq!(error.code, "slug_taken");
        assert_eq!(error.message, "That address is already in use.");
        assert_eq!(error.exit_code, 1);
        // 401 is the one sentence this CLI owns, because it names the remedy.
        let unauthorized = refuse(401, &json!({ "error": "x", "message": "Nope." }));
        assert_eq!(unauthorized.message, "Run `reachpad login`.");
        assert_eq!(unauthorized.exit_code, 1);
        // And a body with nothing in it still says the status out loud.
        assert!(refuse(500, &Value::Null).message.contains("500"));
    }

    #[test]
    fn every_component_that_reaches_a_url_is_escaped() {
        assert_eq!(encode("app_abc"), "app_abc");
        assert_eq!(encode("a b&c=d"), "a%20b%26c%3Dd");
        assert_eq!(
            encode("https://todo.apps.reachpad.dev/"),
            "https%3A%2F%2Ftodo.apps.reachpad.dev%2F"
        );
        assert_eq!(encode("me+tag@example.com"), "me%2Btag%40example.com");
    }
}
