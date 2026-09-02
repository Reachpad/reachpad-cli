//! The per-profile state directory: cached workspace tokens, the cached
//! identity token, and the one-time migration off v0.1.0's single token file.
//!
//! ```text
//! ~/.local/state/reachpad/<profile>/    (0700)
//!   identity.json                       (0600)  the user-scoped token
//!   workspaces/<ws-id>.json             (0600)  that workspace's token
//! ```
//!
//! Everything here is a CACHE (I1): deleting the directory costs a round trip,
//! never correctness. A missing or expired entry is re-minted silently, which
//! is what makes the file safe to delete — and one file per workspace is what
//! makes N `reachpad` processes on one box safe to run, where v0.1.0's single
//! token file had them overwriting each other.
//!
//! `identity.json` holds a real credential, so it obeys the credential rules:
//! 0600, checked on read, and an expiry decided fail-closed.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::api::Client;
use crate::conf::{self, Paths};
use crate::errors::CliError;
use crate::privatefile;

/// A token this close to its expiry is treated as spent: re-minting costs one
/// round trip, and using it costs a refusal the user did not cause.
const EXPIRY_MARGIN_MS: u64 = 60_000;

/// What is cached for one workspace: its token, and what the last attach
/// placed it on. Both halves are optional — the file exists as soon as either
/// is known.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceCache {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fencing_token: Option<u64>,
}

impl WorkspaceCache {
    /// The cached token, or `None` when there is none, it is about to expire,
    /// or the clock could not be read (fail closed, as everywhere).
    pub fn usable_token(&self, now_ms: u64) -> Option<&str> {
        if spent(self.expires_at_ms?, now_ms) {
            return None;
        }
        self.token.as_deref()
    }
}

/// Whether a cached token is past using. The margin is taken off the EXPIRY
/// rather than added to the clock, so a clock that could not be read
/// (`now_ms == 0`) still fails closed.
fn spent(expires_at_ms: u64, now_ms: u64) -> bool {
    conf::is_expired(Some(expires_at_ms.saturating_sub(EXPIRY_MARGIN_MS)), now_ms)
}

/// The user-scoped identity token an operator credential exchanges for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    pub user_id: String,
    pub principal_id: String,
    pub identity_token: String,
    pub expires_at_ms: u64,
}

fn workspace_file(paths: &Paths, workspace: &str) -> anyhow::Result<PathBuf> {
    // The id becomes a filename, so it may hold only what an id holds — a
    // workspace called `../../credentials` must not name a file.
    anyhow::ensure!(
        !workspace.is_empty()
            && workspace
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_')),
        "{workspace:?} is not a workspace id"
    );
    Ok(paths
        .state_dir()
        .join("workspaces")
        .join(format!("{workspace}.json")))
}

pub fn load_workspace(paths: &Paths, workspace: &str) -> anyhow::Result<WorkspaceCache> {
    let path = workspace_file(paths, workspace)?;
    let Some(text) = privatefile::read(&path)? else {
        return Ok(WorkspaceCache::default());
    };
    // A cache that no longer parses is a cache, not an error: drop it.
    Ok(serde_json::from_str(&text).unwrap_or_default())
}

pub fn save_workspace(
    paths: &Paths,
    workspace: &str,
    cache: &WorkspaceCache,
) -> anyhow::Result<()> {
    let path = workspace_file(paths, workspace)?;
    privatefile::write(&path, serde_json::to_vec_pretty(cache)?.as_slice())
}

pub fn load_identity(paths: &Paths, now_ms: u64) -> anyhow::Result<Option<Identity>> {
    let Some(text) = privatefile::read(&paths.state_dir().join("identity.json"))? else {
        return Ok(None);
    };
    let Ok(identity) = serde_json::from_str::<Identity>(&text) else {
        return Ok(None);
    };
    if spent(identity.expires_at_ms, now_ms) {
        return Ok(None);
    }
    Ok(Some(identity))
}

pub fn save_identity(paths: &Paths, identity: &Identity) -> anyhow::Result<()> {
    privatefile::write(
        &paths.state_dir().join("identity.json"),
        serde_json::to_vec_pretty(identity)?.as_slice(),
    )
}

/// Forget everything cached for this profile — what `auth logout` does after
/// the server-side revoke.
pub fn forget_all(paths: &Paths) -> anyhow::Result<()> {
    let dir = paths.state_dir();
    match std::fs::remove_dir_all(&dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(anyhow::anyhow!("deleting {}: {e}", dir.display())),
    }
}

// ---------------------------------------------------------------------------
// Re-minting
// ---------------------------------------------------------------------------

/// Refuse to send a stored credential to a host other than the one that issued
/// it, and say so out loud when the record cannot answer the question.
///
/// The two doors that produce an operator credential — [`identity`] here and
/// `Ctx::credential` — both call this, for the same reason `deny_api_key`
/// guards doors rather than verbs: a new account-wide verb reaches for one of
/// them on its first line and inherits the check without anyone remembering.
///
/// A record with no `endpoint_host` is a laptop that signed in before the
/// field existed. It gets a warning and a re-auth prompt, NOT a refusal:
/// hard-failing would sign out every existing installation on upgrade over a
/// binding it never had the chance to write, and a security fix that logs the
/// whole userbase out is a security fix nobody ships. The warning goes to
/// stderr, so `--json` keeps one parseable line on stdout, and it is said once
/// per command — the credential is loaded more than once inside one.
pub fn bind_to_endpoint(
    credential: &conf::Credential,
    endpoint_host: &str,
) -> Result<(), CliError> {
    match credential.check_endpoint(endpoint_host) {
        conf::Binding::Ok => Ok(()),
        conf::Binding::Unbound => {
            if !UNBOUND_SAID.swap(true, std::sync::atomic::Ordering::Relaxed) {
                eprintln!(
                    "reachpad: your saved credential does not record which endpoint issued it, \
                     so it cannot be checked against {endpoint_host}. Run `reachpad auth login` \
                     to re-bind it."
                );
            }
            Ok(())
        }
        conf::Binding::Foreign { stored_host } => Err(CliError::from_body(
            "credential_endpoint_mismatch",
            &serde_json::json!({
                "stored_host": stored_host,
                "endpoint_host": endpoint_host,
            }),
            None,
        )),
    }
}

/// Once per process, which is once per command: this CLI runs one verb and
/// exits, and the credential is loaded on more than one path inside it.
static UNBOUND_SAID: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The identity token, from the cache when it is still good and from the saved
/// operator credential otherwise.
pub async fn identity(client: &Client, paths: &Paths, now_ms: u64) -> Result<Identity, CliError> {
    if let Some(identity) = load_identity(paths, now_ms)? {
        return Ok(identity);
    }
    let credential = match conf::load_credential(paths, now_ms)? {
        conf::Stored::Present(c) => c,
        conf::Stored::Missing => return Err(CliError::from_code("no_credential", None)),
        conf::Stored::Expired => return Err(CliError::from_code("operator_token_expired", None)),
    };
    // The host this client dials, not the endpoint some caller believes in:
    // the bearer header below is about to go to exactly that host.
    let host = crate::http_min::parse_url(client.controld())
        .map(|control| control.host)
        .map_err(CliError::from)?;
    bind_to_endpoint(&credential, &host)?;
    let session = client
        .operator_session(credential.bearer())
        .await
        .map_err(|e| CliError::from_api(&e, None))?;
    let identity = Identity {
        user_id: session.user_id,
        principal_id: session.principal_id,
        identity_token: session.identity_token,
        expires_at_ms: session.expires_at_ms,
    };
    save_identity(paths, &identity)?;
    Ok(identity)
}

/// This workspace's token, re-minted silently when the cached one is gone or
/// spent. The cache is never the reason a command fails.
pub async fn workspace_token(
    client: &Client,
    paths: &Paths,
    workspace: &str,
    now_ms: u64,
) -> Result<String, CliError> {
    let mut cache = load_workspace(paths, workspace)?;
    if let Some(token) = cache.usable_token(now_ms) {
        return Ok(token.to_owned());
    }
    let identity = identity(client, paths, now_ms).await?;
    let (token, expires_at_ms) = client
        .workspace_token(workspace, &identity.user_id, &identity.identity_token)
        .await
        .map_err(|e| CliError::from_api(&e, Some(workspace)))?;
    cache.token = Some(token.clone());
    cache.expires_at_ms = Some(expires_at_ms);
    save_workspace(paths, workspace, &cache)?;
    Ok(token)
}

// ---------------------------------------------------------------------------
// Migration off v0.1.0
// ---------------------------------------------------------------------------

/// Move a v0.1.0 laptop's credential and attach state into the new layout,
/// once. Returns the one line to print about it.
///
/// v0.1.0 kept `~/.config/reachpad/token{,.operator,.state.json}` (with a
/// read-through fallback to the pre-rename `~/.config/reach/`), and v0.1.1
/// added `token.config.json` — the endpoint pair a WorkOS sign-in returned.
/// The operator credential, the endpoint and the per-workspace fencing tokens
/// carry over; the single `token` file does not, because it holds ONE
/// workspace's token with nothing saying which workspace — and that ambiguity
/// was the defect this layout exists to fix. It is a cache, so losing it costs
/// one round trip.
///
/// A legacy file that cannot be read SAFELY (group- or world-readable) is not
/// a reason to refuse: this runs inside every command, so refusing would stop
/// `auth login` — the one command that installs a fresh credential and ends
/// the migration — on a file the user is being asked to abandon anyway. It is
/// reported as a warning and NOT migrated.
pub fn migrate_v0_files(paths: &Paths, now_ms: u64) -> anyhow::Result<Option<String>> {
    if paths.profile() != conf::DEFAULT_PROFILE {
        return Ok(None);
    }
    if !matches!(conf::load_credential(paths, now_ms)?, conf::Stored::Missing) {
        return Ok(None);
    }
    let config = paths.home().join(".config");
    let Some(old_token) = [
        config.join("reachpad").join("token"),
        config.join("reach").join("token"),
    ]
    .into_iter()
    .find(|p| {
        p.with_file_name(format!("{}.operator", file_name(p)))
            .exists()
    }) else {
        return Ok(None);
    };
    let operator = old_token.with_file_name(format!("{}.operator", file_name(&old_token)));
    let credential = match privatefile::read(&operator) {
        Ok(Some(credential)) => credential,
        Ok(None) => return Ok(None),
        Err(e) => {
            return Ok(Some(format!(
                "your v0.1.0 credential was NOT migrated: {e:#} Delete it, or `chmod 600` it and \
                 run this again — nothing else on this machine is affected."
            )))
        }
    };
    let credential = credential.trim();
    if credential.is_empty() {
        return Ok(None);
    }
    conf::save_credential(
        paths,
        &conf::Credential {
            operator_token: credential.to_owned(),
            token_id: None,
            expires_at_ms: None,
            // A v0.1.0 file never recorded an endpoint, and inventing one here
            // would bind the credential to whatever host this migrating
            // command happened to be aimed at. `None` is the honest answer,
            // and it takes the warn-and-re-auth path.
            endpoint_host: None,
        },
    )?;

    // v0.1.1's `token.config.json`: the endpoint the WorkOS exchange named.
    // Best effort — a laptop that never signed in through a browser has none,
    // and one whose pair this CLI cannot describe simply keeps the default.
    if let Ok(Some(saved)) = crate::tokenfile::read_connection_config(&old_token) {
        if let Ok(endpoint) = crate::cli_auth::endpoint_from_login(&saved.controld, &saved.hub) {
            let _ = conf::save_endpoint(paths, &endpoint);
        }
    }

    let states = old_token.with_file_name(format!("{}.state.json", file_name(&old_token)));
    let mut workspaces = 0usize;
    // Same leniency, and cheaper: this half is a cache of fencing tokens.
    if let Ok(Some(text)) = privatefile::read(&states) {
        #[derive(Deserialize)]
        struct V0AttachState {
            node: String,
            fencing_token: u64,
        }
        let rows: std::collections::BTreeMap<String, V0AttachState> =
            serde_json::from_str(&text).unwrap_or_default();
        for (workspace, row) in rows {
            let Ok(mut cache) = load_workspace(paths, &workspace) else {
                continue;
            };
            cache.node = Some(row.node);
            cache.fencing_token = Some(row.fencing_token);
            if save_workspace(paths, &workspace, &cache).is_ok() {
                workspaces += 1;
            }
        }
    }
    Ok(Some(format!(
        "migrated your credential from {} to {} ({workspaces} workspace(s) carried over); the old files were left alone",
        operator.display(),
        paths.credentials_file().display()
    )))
}

fn file_name(path: &std::path::Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "token".to_owned())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("reach-state-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn one_file_per_workspace_and_nothing_shared() {
        let dir = scratch("perws");
        let paths = Paths::under(&dir, conf::DEFAULT_PROFILE);
        save_workspace(
            &paths,
            "ws-1",
            &WorkspaceCache {
                token: Some("token-1".into()),
                expires_at_ms: Some(10_000_000),
                ..WorkspaceCache::default()
            },
        )
        .unwrap();
        save_workspace(
            &paths,
            "ws-2",
            &WorkspaceCache {
                token: Some("token-2".into()),
                expires_at_ms: Some(10_000_000),
                node: Some("n-02".into()),
                fencing_token: Some(9),
            },
        )
        .unwrap();
        assert_eq!(
            load_workspace(&paths, "ws-1").unwrap().usable_token(1_000),
            Some("token-1")
        );
        let two = load_workspace(&paths, "ws-2").unwrap();
        assert_eq!(two.usable_token(1_000), Some("token-2"));
        assert_eq!(two.fencing_token, Some(9));
        assert_eq!(
            load_workspace(&paths, "ws-3").unwrap(),
            WorkspaceCache::default()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_workspace_id_can_never_name_another_file() {
        let dir = scratch("traversal");
        let paths = Paths::under(&dir, conf::DEFAULT_PROFILE);
        for bad in ["../credentials", "a/b", "", "ws 1"] {
            assert!(load_workspace(&paths, bad).is_err(), "{bad:?}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cached_tokens_expire_fail_closed() {
        let cache = WorkspaceCache {
            token: Some("t".into()),
            expires_at_ms: Some(1_000_000),
            ..WorkspaceCache::default()
        };
        assert_eq!(cache.usable_token(500_000), Some("t"));
        // Inside the margin, and after the expiry, it is spent.
        assert_eq!(cache.usable_token(1_000_000 - EXPIRY_MARGIN_MS), None);
        assert_eq!(cache.usable_token(2_000_000), None);
        // A clock that could not be read is not a fresh token.
        assert_eq!(cache.usable_token(0), None);
        assert_eq!(
            WorkspaceCache {
                token: Some("t".into()),
                ..WorkspaceCache::default()
            }
            .usable_token(1),
            None,
            "a token with no known expiry is not usable"
        );
    }

    #[test]
    fn the_identity_cache_is_a_credential_and_expires_fail_closed() {
        let dir = scratch("identity");
        let paths = Paths::under(&dir, conf::DEFAULT_PROFILE);
        let identity = Identity {
            user_id: "user_1".into(),
            principal_id: "p_1".into(),
            identity_token: "identity".into(),
            expires_at_ms: 1_000_000,
        };
        save_identity(&paths, &identity).unwrap();
        assert_eq!(load_identity(&paths, 500_000).unwrap(), Some(identity));
        assert_eq!(load_identity(&paths, 1_000_001).unwrap(), None);
        assert_eq!(load_identity(&paths, 0).unwrap(), None);
        assert_eq!(
            std::fs::metadata(paths.state_dir().join("identity.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            privatefile::FILE_MODE
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_v0_credential_and_fencing_tokens_are_migrated_once() {
        let dir = scratch("migrate");
        let paths = Paths::under(&dir, conf::DEFAULT_PROFILE);
        let old = dir.join(".config").join("reach").join("token");
        privatefile::write(&old, b"a-workspace-biscuit\n").unwrap();
        privatefile::write(&old.with_file_name("token.operator"), b"rpop1.credential\n").unwrap();
        privatefile::write(
            &old.with_file_name("token.state.json"),
            br#"{"ws-1":{"node":"n-01","fencing_token":4,"principal":"p"}}"#,
        )
        .unwrap();

        let line = migrate_v0_files(&paths, 1).unwrap().expect("migrated");
        assert!(line.contains("credentials.toml"), "{line}");
        let conf::Stored::Present(c) = conf::load_credential(&paths, 1).unwrap() else {
            panic!("the credential carried over");
        };
        assert_eq!(c.bearer(), "rpop1.credential");
        assert_eq!(
            load_workspace(&paths, "ws-1").unwrap().fencing_token,
            Some(4)
        );
        assert!(old.exists(), "the old files are left alone");
        // Once: with a credential in place there is nothing to migrate.
        assert_eq!(migrate_v0_files(&paths, 1).unwrap(), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// v0.1.1 signed in through WorkOS and saved the endpoint pair the
    /// exchange named in `token.config.json`. That laptop must not come back
    /// on the production default after upgrading — it may not be its fleet.
    #[test]
    fn a_v0_1_1_laptops_endpoint_comes_across_with_its_credential() {
        let dir = scratch("migrate-endpoint");
        let paths = Paths::under(&dir, conf::DEFAULT_PROFILE);
        let old = dir.join(".config").join("reachpad").join("token");
        privatefile::write(&old.with_file_name("token.operator"), b"rpop1.credential\n").unwrap();
        crate::tokenfile::write_connection_config(
            &old,
            &crate::tokenfile::ConnectionConfig {
                controld: "https://m9.reachpad.dev".into(),
                hub: "wss://m9.reachpad.dev/ws".into(),
            },
        )
        .unwrap();

        migrate_v0_files(&paths, 1).unwrap().expect("migrated");
        assert_eq!(
            conf::load_config(&paths).unwrap().endpoint.as_deref(),
            Some("m9.reachpad.dev"),
            "the pair collapses to the one endpoint the v1 CLI keeps"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The other half of that: a laptop that never signed in through a
    /// browser has no such file, and migration must not invent an endpoint
    /// for it — an absent `[endpoint]` is what makes the production default
    /// apply.
    #[test]
    fn a_v0_1_0_laptop_gets_no_endpoint_invented_for_it() {
        let dir = scratch("migrate-no-endpoint");
        let paths = Paths::under(&dir, conf::DEFAULT_PROFILE);
        let old = dir.join(".config").join("reachpad").join("token");
        privatefile::write(&old.with_file_name("token.operator"), b"rpop1.credential\n").unwrap();

        migrate_v0_files(&paths, 1).unwrap().expect("migrated");
        assert_eq!(conf::load_config(&paths).unwrap().endpoint, None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A legacy credential the CLI will not read must not brick the CLI:
    /// migration runs inside EVERY command, so refusing here refused
    /// `auth login` too — the one command that ends the migration for good.
    #[test]
    fn a_legacy_file_nobody_may_read_is_a_warning_and_not_a_refusal() {
        let dir = scratch("migrate-perms");
        let paths = Paths::under(&dir, conf::DEFAULT_PROFILE);
        let old = dir.join(".config").join("reachpad").join("token");
        privatefile::write(&old, b"a-workspace-biscuit\n").unwrap();
        let operator = old.with_file_name("token.operator");
        privatefile::write(&operator, b"rpop1.credential\n").unwrap();
        std::fs::set_permissions(&operator, std::fs::Permissions::from_mode(0o644)).unwrap();

        let line = migrate_v0_files(&paths, 1)
            .expect("a loose legacy file is not an error")
            .expect("but it is said out loud");
        assert!(line.contains("NOT migrated"), "{line}");
        assert!(line.contains("chmod 600"), "{line}");
        // And nothing was taken from it.
        assert_eq!(
            conf::load_credential(&paths, 1).unwrap(),
            conf::Stored::Missing
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
