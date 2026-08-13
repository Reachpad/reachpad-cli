//! Token file handling. The user's Biscuit — the ONLY credential this CLI
//! touches (§15: reach holds zero platform secrets) — lives at
//! `~/.config/reach/token`, written with 0600 permissions. A small sidecar
//! (`<token>.state.json`, also 0600) remembers the fencing token and node
//! from the last attach per workspace so `reachpad ws release <id>` works
//! without re-typing the fencing token.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt;
#[cfg(test)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Context;
use serde::{Deserialize, Serialize};

/// Permissions for everything this module writes.
pub const FILE_MODE: u32 = 0o600;

/// Default token path: `$HOME/.config/reachpad/token` — with a read-through
/// fallback to the pre-rename `~/.config/reach/token`. A laptop that logged
/// in before the binary became `reachpad` keeps its credentials without any
/// migration step: if the new directory has no token yet and the old one
/// does, the old location stays authoritative (reads AND writes, so the
/// credential never splits across two directories).
pub fn default_token_path() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    let current = home.join(".config").join("reachpad").join("token");
    let legacy = home.join(".config").join("reach").join("token");
    // The operator credential lives in a SIDECAR (`token.operator`), so "the
    // user has credentials here" must consider both files — `auth login`
    // writes only the sidecar.
    let holds_credentials = |p: &std::path::Path| p.exists() || operator_path(p).exists();
    if !holds_credentials(&current) && holds_credentials(&legacy) {
        return legacy;
    }
    current
}

/// Path of the operator credential sidecar (`<token>.operator`), next to the
/// token file and written 0600 like everything else here.
///
/// This is the ONE long-lived credential `reach` keeps (ADR-0034/0039). It is
/// not a capability: it authorizes nothing directly and is only ever
/// exchanged, over the coordination plane's TLS, for the same short-lived
/// identity token the IdP path yields.
pub fn operator_path(token_path: &Path) -> PathBuf {
    sidecar(token_path, ".operator")
}

/// Whether this credential set already has an operator credential.
///
/// Existence is enough here. An empty or unreadable file is deliberately not
/// treated as signed out, because replacing a damaged credential without
/// naming the damage would hide the state the user needs to repair.
pub fn operator_token_exists(token_path: &Path) -> anyhow::Result<bool> {
    let path = operator_path(token_path);
    path.try_exists()
        .with_context(|| format!("checking operator credential {}", path.display()))
}

/// Sidecar path for attach state, next to the token file.
pub fn state_path(token_path: &Path) -> PathBuf {
    sidecar(token_path, ".state.json")
}

/// Connection configuration learned from the authenticated Reachpad exchange.
pub fn connection_path(token_path: &Path) -> PathBuf {
    sidecar(token_path, ".config.json")
}

fn sidecar(token_path: &Path, suffix: &str) -> PathBuf {
    let mut name = token_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "token".to_owned());
    name.push_str(suffix);
    token_path.with_file_name(name)
}

/// State remembered from the last `ws attach` per workspace.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttachState {
    pub node: String,
    pub fencing_token: u64,
    pub principal: String,
}

static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

fn write_0600(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("creating directory {}", dir.display()))?;
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| "token".to_owned());
    let mut last_collision = None;
    for _ in 0..100 {
        let sequence = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let temporary = parent.join(format!(".{name}.tmp-{}-{sequence}", std::process::id()));
        let opened = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(FILE_MODE)
            .open(&temporary);
        let mut file = match opened {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                last_collision = Some(error);
                continue;
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("opening temporary file beside {}", path.display()));
            }
        };
        let result = (|| -> anyhow::Result<()> {
            file.write_all(bytes)?;
            file.sync_all()?;
            std::fs::rename(&temporary, path)
                .with_context(|| format!("atomically replacing {}", path.display()))?;
            // Persist the rename itself when the filesystem supports syncing a
            // directory. The credential is either the old complete file or
            // the new complete file, never a truncated in-between.
            std::fs::File::open(parent)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        return result;
    }
    Err(last_collision.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "temporary file collision",
        )
    }))
    .with_context(|| format!("creating a temporary file beside {}", path.display()))
}

/// Write the Biscuit (base64) to `path`, 0600, creating parent dirs.
pub fn write_token(path: &Path, token_b64: &str) -> anyhow::Result<()> {
    let mut contents = token_b64.trim().to_owned();
    contents.push('\n');
    write_0600(path, contents.as_bytes())
}

/// Read the Biscuit (base64) from `path`.
pub fn read_token(path: &Path) -> anyhow::Result<String> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading token file {}", path.display()))?;
    let token = raw.trim();
    anyhow::ensure!(!token.is_empty(), "token file {} is empty", path.display());
    Ok(token.to_owned())
}

/// Save the operator credential (0600). Overwrites any previous one: a
/// laptop holds at most one.
pub fn write_operator_token(token_path: &Path, credential: &str) -> anyhow::Result<()> {
    let credential = credential.trim();
    anyhow::ensure!(!credential.is_empty(), "empty operator credential");
    let mut contents = credential.to_owned();
    contents.push('\n');
    write_0600(&operator_path(token_path), contents.as_bytes())
}

/// Read the saved operator credential.
pub fn read_operator_token(token_path: &Path) -> anyhow::Result<String> {
    let path = operator_path(token_path);
    let raw = std::fs::read_to_string(&path).with_context(|| {
        format!(
            "no operator credential at {} (run `reachpad auth login`)",
            path.display()
        )
    })?;
    let token = raw.trim();
    anyhow::ensure!(
        !token.is_empty(),
        "operator credential file {} is empty",
        path.display()
    );
    Ok(token.to_owned())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConnectionConfig {
    pub controld: String,
    pub hub: String,
}

/// Save the non-secret endpoint pair beside the credential. It is still 0600
/// because a single file mode for the credential set is easier to audit.
pub fn write_connection_config(token_path: &Path, config: &ConnectionConfig) -> anyhow::Result<()> {
    let mut json = serde_json::to_vec_pretty(config)?;
    json.push(b'\n');
    write_0600(&connection_path(token_path), &json)
}

pub fn read_connection_config(token_path: &Path) -> anyhow::Result<Option<ConnectionConfig>> {
    let path = connection_path(token_path);
    let raw = match std::fs::read(&path) {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("reading {}", path.display()));
        }
    };
    let config = serde_json::from_slice(&raw)
        .with_context(|| format!("parsing saved connection configuration {}", path.display()))?;
    Ok(Some(config))
}

fn read_states(token_path: &Path) -> BTreeMap<String, AttachState> {
    let path = state_path(token_path);
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

/// Remember the attach result for `workspace` (0600 sidecar).
pub fn save_attach_state(
    token_path: &Path,
    workspace: &str,
    state: AttachState,
) -> anyhow::Result<()> {
    let mut states = read_states(token_path);
    states.insert(workspace.to_owned(), state);
    let json = serde_json::to_vec_pretty(&states)?;
    write_0600(&state_path(token_path), &json)
}

/// The attach state saved for `workspace`, if any.
pub fn load_attach_state(token_path: &Path, workspace: &str) -> Option<AttachState> {
    read_states(token_path).remove(workspace)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch_dir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("reach-tokenfile-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn mode_of(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn token_write_creates_dirs_sets_0600_and_round_trips() {
        let dir = scratch_dir("perms");
        let path = dir.join("nested").join("token");
        write_token(&path, "  dGVzdA==\n").unwrap();
        assert_eq!(mode_of(&path), FILE_MODE, "token file must be 0600");
        assert_eq!(read_token(&path).unwrap(), "dGVzdA==");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rewriting_a_loose_permission_file_tightens_it_back_to_0600() {
        let dir = scratch_dir("tighten");
        let path = dir.join("token");
        write_token(&path, "first").unwrap();
        // Simulate the user loosening it.
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o644);
        std::fs::set_permissions(&path, perms).unwrap();
        write_token(&path, "second").unwrap();
        assert_eq!(mode_of(&path), FILE_MODE, "rewrite must restore 0600");
        assert_eq!(read_token(&path).unwrap(), "second");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn connection_config_round_trips_atomically_at_0600() {
        let dir = scratch_dir("connection");
        let path = dir.join("token");
        let config = ConnectionConfig {
            controld: "https://m1.reachpad.dev".into(),
            hub: "wss://m1.reachpad.dev/ws".into(),
        };
        write_connection_config(&path, &config).unwrap();
        assert_eq!(read_connection_config(&path).unwrap(), Some(config));
        assert_eq!(mode_of(&connection_path(&path)), FILE_MODE);
        let leftovers = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp-"))
            .count();
        assert_eq!(
            leftovers, 0,
            "an atomic write must not leave its staging file"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_or_missing_token_file_is_an_error() {
        let dir = scratch_dir("empty");
        let path = dir.join("token");
        assert!(read_token(&path).is_err(), "missing file");
        write_token(&path, "   ").unwrap();
        assert!(read_token(&path).is_err(), "blank token");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn operator_token_existence_distinguishes_first_run_from_damage() {
        let dir = scratch_dir("operator-exists");
        let path = dir.join("token");
        assert!(!operator_token_exists(&path).unwrap());

        write_operator_token(&path, "rpop1.id.secret").unwrap();
        assert!(operator_token_exists(&path).unwrap());

        std::fs::write(operator_path(&path), []).unwrap();
        assert!(
            operator_token_exists(&path).unwrap(),
            "an empty credential is damaged, not a new installation"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn attach_state_round_trips_per_workspace_and_is_0600() {
        let dir = scratch_dir("state");
        let path = dir.join("token");
        let a = AttachState {
            node: "dev-node".into(),
            fencing_token: 7,
            principal: "dev-principal".into(),
        };
        save_attach_state(&path, "ws-1", a.clone()).unwrap();
        save_attach_state(
            &path,
            "ws-2",
            AttachState {
                node: "n2".into(),
                fencing_token: 9,
                principal: "p".into(),
            },
        )
        .unwrap();
        assert_eq!(load_attach_state(&path, "ws-1"), Some(a));
        assert_eq!(load_attach_state(&path, "ws-2").unwrap().fencing_token, 9);
        assert_eq!(load_attach_state(&path, "ws-3"), None);
        assert_eq!(mode_of(&state_path(&path)), FILE_MODE);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
