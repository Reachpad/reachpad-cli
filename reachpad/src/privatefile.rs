//! The files this CLI keeps on disk. Every one of them holds a credential or
//! a cache of one, so they all obey the same rule: 0700 directories, 0600
//! files, written atomically, and checked on read.
//!
//! A loose FILE is refused rather than repaired: the secret in it has already
//! been readable by someone else, and continuing would hide that. A loose
//! DIRECTORY is tightened and the read continues — a directory exposes names,
//! not secrets, and v0.1.0 created these directories with the ambient umask.

use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::Context;

pub const FILE_MODE: u32 = 0o600;
pub const DIR_MODE: u32 = 0o700;

/// Create `dir` if needed and force it to 0700.
pub fn ensure_dir(dir: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir)
        .with_context(|| format!("creating directory {}", dir.display()))?;
    let mut perms = std::fs::metadata(dir)
        .with_context(|| format!("reading permissions of {}", dir.display()))?
        .permissions();
    if perms.mode() & 0o777 != DIR_MODE {
        perms.set_mode(DIR_MODE);
        std::fs::set_permissions(dir, perms)
            .with_context(|| format!("tightening {} to 0700", dir.display()))?;
    }
    Ok(())
}

/// Write `bytes` to `path` atomically: a 0600 temporary file in the same
/// directory, fsynced, then renamed over the target. A reader either sees the
/// whole old file or the whole new one, and two `reachpad` processes writing
/// at once never interleave.
pub fn write(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    ensure_dir(dir)?;
    let tmp = tmp_path(path);
    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(FILE_MODE)
            .open(&tmp)
            .with_context(|| format!("opening {} for writing", tmp.display()))?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    // `mode()` applies only when the file is created, so a leftover temporary
    // from a crashed process would keep its own bits.
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(FILE_MODE))?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("renaming {} onto {}", tmp.display(), path.display()))?;
    Ok(())
}

/// Read `path`, or `None` when it does not exist. Refuses a file any other
/// user can read.
pub fn read(path: &Path) -> anyhow::Result<Option<String>> {
    let meta = match std::fs::metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    let mode = meta.permissions().mode() & 0o777;
    anyhow::ensure!(
        mode & 0o077 == 0,
        "{} is readable by other users (mode {mode:o}). Fix it with `chmod 600 {}` — and treat what was in it as disclosed.",
        path.display(),
        path.display()
    );
    if let Some(dir) = path.parent() {
        if dir.exists() {
            ensure_dir(dir)?;
        }
    }
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    Ok(Some(text))
}

/// Delete `path`; a file that is not there is already deleted.
pub fn remove(path: &Path) -> anyhow::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("deleting {}", path.display())),
    }
}

fn tmp_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".to_owned());
    path.with_file_name(format!(".{name}.tmp.{}", std::process::id()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("reach-privatefile-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn mode_of(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn a_write_creates_a_0700_directory_and_a_0600_file() {
        let dir = scratch("write");
        let path = dir.join("nested").join("credentials.toml");
        write(&path, b"hello\n").unwrap();
        assert_eq!(mode_of(&path), FILE_MODE);
        assert_eq!(mode_of(path.parent().unwrap()), DIR_MODE);
        assert_eq!(read(&path).unwrap().as_deref(), Some("hello\n"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_write_leaves_no_temporary_behind() {
        let dir = scratch("atomic");
        let path = dir.join("f");
        write(&path, b"one").unwrap();
        write(&path, b"two").unwrap();
        let names: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["f".to_owned()]);
        assert_eq!(read(&path).unwrap().as_deref(), Some("two"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_file_reads_as_none_and_removing_it_is_fine() {
        let dir = scratch("missing");
        let path = dir.join("f");
        assert!(read(&path).unwrap().is_none());
        remove(&path).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_world_readable_file_is_refused_and_a_loose_directory_is_tightened() {
        let dir = scratch("perms");
        let path = dir.join("f");
        write(&path, b"secret").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = read(&path).unwrap_err().to_string();
        assert!(err.contains("chmod 600"), "{err}");

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(FILE_MODE)).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(read(&path).unwrap().as_deref(), Some("secret"));
        assert_eq!(mode_of(&dir), DIR_MODE, "a loose directory is repaired");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
