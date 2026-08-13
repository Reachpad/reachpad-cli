//! Native release updates. Homebrew owns files it installs, so its update
//! path remains Homebrew rather than a second writer racing the cask.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::Context;

const INSTALLER_URL: &str = "https://reachpad.dev/install";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstallSource {
    Homebrew,
    Development,
    Native,
}

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

pub fn run() -> anyhow::Result<i32> {
    let executable = std::env::current_exe().context("locating the running reachpad binary")?;
    match install_source(&executable) {
        InstallSource::Homebrew => {
            println!("Reachpad is installed by Homebrew.");
            println!("Run: brew upgrade --cask reachpad");
            return Ok(0);
        }
        InstallSource::Development => {
            println!("Reachpad is running from a Cargo target directory.");
            println!("Rebuild this checkout with: cargo build -p reach");
            return Ok(0);
        }
        InstallSource::Native => {}
    }

    let install_dir = executable
        .parent()
        .context("the running reachpad binary has no parent directory")?;
    anyhow::ensure!(
        executable.file_name().and_then(|name| name.to_str()) == Some("reachpad"),
        "refusing to update a binary not named reachpad at {}",
        executable.display()
    );

    let scratch = create_scratch_dir()?;
    let installer = scratch.join("install.sh");
    let result = run_native_update(&installer, install_dir);
    let _ = std::fs::remove_file(&installer);
    let _ = std::fs::remove_dir(&scratch);
    result?;

    println!("Reachpad update completed in {}.", install_dir.display());
    println!("Run `reachpad --version` to confirm the installed version.");
    Ok(0)
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
}
