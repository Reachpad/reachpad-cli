//! `reachpad update` — native release updates.
//!
//! ADR-0072. The rule the whole module exists for: **whoever installed the
//! binary owns it.** Homebrew tracks the files it wrote and will fight a
//! second writer, npm owns everything under `node_modules` and reinstalls it
//! from a lockfile, and a Cargo target directory is rebuilt from source, so
//! for all three this command prints the command that installer owns instead
//! of replacing files behind its back. Only a native install — the one this
//! CLI placed itself — updates itself, by re-running the same
//! checksum-verifying installer that put it there.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::Context;
use serde_json::json;

use crate::commands::Ctx;
use crate::errors::{CliError, EXIT_OK};

const INSTALLER_URL: &str = "https://reachpad.dev/install";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstallSource {
    /// A `brew install` of the tap formula, under `Cellar`.
    Homebrew,
    /// A `brew install --cask` from before 2026-08-13, under `Caskroom`. The
    /// tap ships a formula now — Homebrew quarantines what a cask stages and
    /// macOS then refuses to run this un-notarized binary — so `brew upgrade`
    /// has no cask left to act on and these installs must migrate instead.
    HomebrewCask,
    /// `npm install -g @reachpad/cli`, under a `node_modules` tree.
    Npm,
    Development,
    Native,
}

impl InstallSource {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            InstallSource::Homebrew => "homebrew",
            InstallSource::HomebrewCask => "homebrew-cask",
            InstallSource::Npm => "npm",
            InstallSource::Development => "development",
            InstallSource::Native => "native",
        }
    }
}

/// Which installer owns this file, decided from the path alone — no network,
/// no package database. Homebrew's two prefixes (`Caskroom`, `Cellar`), an
/// npm `node_modules` tree, and a cargo `target/{debug,release}` are the
/// shapes that must never be self-modified. The two Homebrew prefixes are
/// kept apart because they need different commands: a formula upgrades, a
/// leftover cask has to migrate.
///
/// `node_modules` is tested FIRST because it is the most specific claim on a
/// path: a global npm prefix can sit inside a Homebrew one
/// (`/opt/homebrew/lib/node_modules/@reachpad/cli-darwin-arm64/bin/reachpad`),
/// and there npm is the writer that will put the file back, not brew.
pub fn install_source(executable: &Path) -> InstallSource {
    let components: Vec<_> = executable
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect();
    if components
        .iter()
        .any(|component| component == "node_modules")
    {
        return InstallSource::Npm;
    }
    if components.iter().any(|component| component == "Caskroom") {
        return InstallSource::HomebrewCask;
    }
    if components.iter().any(|component| component == "Cellar") {
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
        // A FORMULA, not a cask. The tap shipped a cask until 2026-08-13 and
        // `brew upgrade --cask reachpad` now names nothing that exists — it
        // fails with "no available cask", which reads to the person typing it
        // like their install is broken rather than like this string is stale.
        InstallSource::Homebrew => Some("brew upgrade reachpad"),
        // And an upgrade is not what a leftover cask needs either: there is
        // no formula-installed copy for `brew upgrade` to raise, and running
        // the install would leave two reachpads with the Caskroom one still
        // shadowing PATH. The cask has to go first.
        InstallSource::HomebrewCask => {
            Some("brew uninstall --cask reachpad && brew install reachpad/tap/reachpad")
        }
        InstallSource::Npm => Some("npm install -g @reachpad/cli@latest"),
        InstallSource::Development => Some("cargo build -p reach"),
        InstallSource::Native => None,
    }
}

fn owner(source: InstallSource) -> &'static str {
    match source {
        InstallSource::Homebrew => "Homebrew",
        InstallSource::HomebrewCask => "Homebrew, as a cask the tap no longer ships",
        InstallSource::Npm => "npm",
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
            InstallSource::HomebrewCask
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

    /// Every layout npm can put the binary in. Before these, all four read as
    /// `Native`, and `reachpad update` would have run the curl installer
    /// straight over a file npm owns — leaving a tree whose lockfile and
    /// contents disagree, and whose next `npm ci` silently reverts the update.
    #[test]
    fn npm_owns_everything_under_node_modules() {
        for path in [
            // macOS, Homebrew-installed node: a global npm prefix INSIDE a
            // Homebrew prefix. npm wins — it is the one that rewrites the file.
            "/opt/homebrew/lib/node_modules/@reachpad/cli-darwin-arm64/bin/reachpad",
            // Linux, nvm or a user prefix.
            "/home/user/.nvm/versions/node/v22.11.0/lib/node_modules/@reachpad/cli-linux-x64/bin/reachpad",
            // A project-local dependency, which is how an agent gets it.
            "/work/repo/node_modules/@reachpad/cli-linux-arm64/bin/reachpad",
            // npx, straight out of the cache.
            "/home/user/.npm/_npx/2f3a1b/node_modules/@reachpad/cli-linux-x64/bin/reachpad",
        ] {
            assert_eq!(install_source(Path::new(path)), InstallSource::Npm, "{path}");
        }
    }

    /// The four sources this command must not write to are exactly the four
    /// that name someone else's command; a native install names none.
    #[test]
    fn only_a_native_install_updates_itself() {
        assert_eq!(
            deferred_to(InstallSource::Homebrew),
            Some("brew upgrade reachpad")
        );
        assert_eq!(
            deferred_to(InstallSource::HomebrewCask),
            Some("brew uninstall --cask reachpad && brew install reachpad/tap/reachpad")
        );
        assert_eq!(
            deferred_to(InstallSource::Npm),
            Some("npm install -g @reachpad/cli@latest")
        );
        assert_eq!(
            deferred_to(InstallSource::Development),
            Some("cargo build -p reach")
        );
        assert_eq!(deferred_to(InstallSource::Native), None);
    }

    /// The tap ships a formula, so `brew upgrade --cask reachpad` names
    /// nothing and a command the CLI prints must be one the reader can paste.
    /// The ONE surviving `--cask` is the uninstall half of the migration,
    /// which is exactly the command that still has a cask to act on.
    #[test]
    fn only_the_cask_migration_still_says_cask() {
        assert_eq!(
            deferred_to(InstallSource::Homebrew),
            Some("brew upgrade reachpad")
        );
        for source in [
            InstallSource::Homebrew,
            InstallSource::Npm,
            InstallSource::Development,
        ] {
            assert!(
                !deferred_to(source).unwrap().contains("--cask"),
                "{source:?} still prints a cask command"
            );
        }
        assert!(deferred_to(InstallSource::HomebrewCask)
            .unwrap()
            .starts_with("brew uninstall --cask"));
    }
}
