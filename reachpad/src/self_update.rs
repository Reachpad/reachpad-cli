//! `reachpad update` — native release updates.
//!
//! ADR-0072. The rule the whole module exists for: **whoever installed the
//! binary owns it.** Homebrew tracks the files it wrote and will fight a
//! second writer, and a Cargo target directory is rebuilt from source, so for
//! both this command prints the command that installer owns instead of
//! replacing files behind its back. Only a native install — the one this CLI
//! placed itself — updates itself, by re-running the same checksum-verifying
//! installer that put it there.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::Context;
use serde_json::json;

use crate::commands::Ctx;
use crate::errors::{CliError, EXIT_OK};

const INSTALLER_URL: &str = "https://reachpad.dev/install";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstallSource {
    Homebrew,
    Development,
    Native,
}

impl InstallSource {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            InstallSource::Homebrew => "homebrew",
            InstallSource::Development => "development",
            InstallSource::Native => "native",
        }
    }
}

/// Which installer owns this file, decided from the path alone — no network,
/// no package database. Homebrew's two prefixes (`Caskroom`, `Cellar`) and a
/// cargo `target/{debug,release}` are the shapes that must never be
/// self-modified.
pub fn install_source(executable: &Path) -> InstallSource {
    let components: Vec<_> = executable
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect();
    if components
        .iter()
        .any(|component| component == "Caskroom" || component == "Cellar")
    {
        return InstallSource::Homebrew;
    }
    if components
        .windows(2)
        .any(|pair| pair[0] == "target" && (pair[1] == "debug" || pair[1] == "release"))
    {
        return InstallSource::Development;
    }
    InstallSource::Native
}

pub(crate) fn run(ctx: &Ctx) -> Result<i32, CliError> {
    let executable = std::env::current_exe()
        .context("locating the running reachpad binary")
        .map_err(CliError::from)?;
    let source = install_source(&executable);
    if let Some(command) = deferred_to(source) {
        ctx.emit(
            json!({
                "installed_by": source.as_str(),
                "updated": false,
                "run": command,
            }),
            &[
                format!("This copy of reachpad was installed by {}.", owner(source)),
                format!("  Update it with: {command}"),
            ],
        );
        return Ok(EXIT_OK);
    }

    let install_dir = executable
        .parent()
        .context("the running reachpad binary has no parent directory")
        .map_err(CliError::from)?;
    // The installer writes `reachpad` into this directory. If the running file
    // is named something else, the update would leave the caller running a
    // binary the update did not touch, and say it succeeded.
    if executable.file_name().and_then(|name| name.to_str()) != Some("reachpad") {
        return Err(CliError::usage(format!(
            "refusing to update {}: it is not named reachpad, so the installer \
             would write a different file than the one running.",
            executable.display()
        )));
    }

    let scratch = create_scratch_dir().map_err(CliError::from)?;
    let installer = scratch.join("install.sh");
    let result = run_native_update(&installer, install_dir);
    let _ = std::fs::remove_file(&installer);
    let _ = std::fs::remove_dir(&scratch);
    result.map_err(CliError::from)?;

    ctx.emit(
        json!({
            "installed_by": source.as_str(),
            "updated": true,
            "install_dir": install_dir.display().to_string(),
        }),
        &[
            format!("Updated reachpad in {}.", install_dir.display()),
            "  `reachpad --version` says which version is installed now.".to_owned(),
        ],
    );
    Ok(EXIT_OK)
}

/// The command that owns updates for an installation this one must not touch.
fn deferred_to(source: InstallSource) -> Option<&'static str> {
    match source {
        InstallSource::Homebrew => Some("brew upgrade --cask reachpad"),
        InstallSource::Development => Some("cargo build -p reach"),
        InstallSource::Native => None,
    }
}

fn owner(source: InstallSource) -> &'static str {
    match source {
        InstallSource::Homebrew => "Homebrew",
        InstallSource::Development => "cargo, in a target directory",
        InstallSource::Native => "the Reachpad installer",
    }
}

fn create_scratch_dir() -> anyhow::Result<PathBuf> {
    let base = std::env::temp_dir();
    for sequence in 0..100_u32 {
        let path = base.join(format!("reachpad-update-{}-{sequence}", std::process::id()));
        match std::fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("creating update directory {}", path.display()));
            }
        }
    }
    anyhow::bail!("could not reserve a temporary directory for the update")
}

fn run_native_update(installer: &Path, install_dir: &Path) -> anyhow::Result<()> {
    let downloaded = Command::new("curl")
        .args([
            "--proto",
            "=https",
            "--tlsv1.2",
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--output",
        ])
        .arg(installer)
        .arg(INSTALLER_URL)
        .stdin(Stdio::null())
        .status()
        .context("running curl; install curl or update through Homebrew")?;
    anyhow::ensure!(
        downloaded.success(),
        "downloading {INSTALLER_URL} failed with {downloaded}"
    );

    let installed = Command::new("sh")
        .arg(installer)
        .env("REACHPAD_INSTALL_DIR", install_dir)
        .stdin(Stdio::null())
        .status()
        .context("running the Reachpad installer")?;
    anyhow::ensure!(
        installed.success(),
        "the Reachpad installer exited with {installed}"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_manager_and_development_paths_are_not_self_modified() {
        assert_eq!(
            install_source(Path::new("/opt/homebrew/Caskroom/reachpad/0.1.1/reachpad")),
            InstallSource::Homebrew
        );
        assert_eq!(
            install_source(Path::new(
                "/home/linuxbrew/.linuxbrew/Cellar/reachpad/1/bin/reachpad"
            )),
            InstallSource::Homebrew
        );
        assert_eq!(
            install_source(Path::new("/work/reachpad/target/debug/reachpad")),
            InstallSource::Development
        );
        assert_eq!(
            install_source(Path::new("/home/user/.local/bin/reachpad")),
            InstallSource::Native
        );
    }

    /// The two sources this command must not write to are exactly the two
    /// that name someone else's command; a native install names none.
    #[test]
    fn only_a_native_install_updates_itself() {
        assert_eq!(
            deferred_to(InstallSource::Homebrew),
            Some("brew upgrade --cask reachpad")
        );
        assert_eq!(
            deferred_to(InstallSource::Development),
            Some("cargo build -p reach")
        );
        assert_eq!(deferred_to(InstallSource::Native), None);
    }
}
