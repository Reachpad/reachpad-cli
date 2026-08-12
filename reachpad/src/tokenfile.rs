//! Token file handling. The user's Biscuit — the ONLY credential this CLI
//! touches (§15: reach holds zero platform secrets) — lives at
//! `~/.config/reach/token`, written with 0600 permissions. A small sidecar
//! (`<token>.state.json`, also 0600) remembers the fencing token and node
//! from the last attach per workspace so `reachpad ws release <id>` works
//! without re-typing the fencing token.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

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

/// Sidecar path for attach state, next to the token file.
pub fn state_path(token_path: &Path) -> PathBuf {
    sidecar(token_path, ".state.json")
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

fn write_0600(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("creating directory {}", dir.display()))?;
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(FILE_MODE)
        .open(path)
        .with_context(|| format!("opening {} for writing", path.display()))?;
    file.write_all(bytes)?;
    // `mode()` applies only on create; a pre-existing file keeps its old
    // permissions — force 0600 either way.
    let mut perms = file.metadata()?.permissions();
    perms.set_mode(FILE_MODE);
    std::fs::set_permissions(path, perms)?;
    Ok(())
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
            "no operator credential at {} (run `reachpad auth login --operator-token …`)",
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
    fn empty_or_missing_token_file_is_an_error() {
        let dir = scratch_dir("empty");
        let path = dir.join("token");
        assert!(read_token(&path).is_err(), "missing file");
        write_token(&path, "   ").unwrap();
        assert!(read_token(&path).is_err(), "blank token");
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
