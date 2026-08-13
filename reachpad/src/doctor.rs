//! Read-only diagnostics for the local CLI installation and account session.

use std::path::Path;

use crate::api::Client;
use crate::self_update::{install_source, InstallSource};
use crate::{cli_auth, tokenfile, transport::TlsTrust};

struct Report {
    failures: usize,
}

impl Report {
    fn ok(&self, name: &str, detail: impl std::fmt::Display) {
        println!("[ok]   {name}: {detail}");
    }

    fn fail(&mut self, name: &str, detail: impl std::fmt::Display) {
        self.failures += 1;
        println!("[fail] {name}: {detail}");
    }
}

pub async fn run(
    controld: &str,
    hub: &str,
    trust: TlsTrust,
    token_path: &Path,
) -> anyhow::Result<i32> {
    let mut report = Report { failures: 0 };
    let executable = std::env::current_exe();

    report.ok("version", env!("CARGO_PKG_VERSION"));
    match &executable {
        Ok(path) => {
            let source = match install_source(path) {
                InstallSource::Homebrew => "Homebrew",
                InstallSource::Development => "Cargo development build",
                InstallSource::Native => "native installer",
            };
            report.ok("binary", format!("{} ({source})", path.display()));
            if executable_is_on_path(path) {
                report.ok("PATH", "reachpad resolves to this binary");
            } else {
                report.fail(
                    "PATH",
                    format!(
                        "{} is not the reachpad resolved through PATH",
                        path.display()
                    ),
                );
            }
            if install_source(path) == InstallSource::Native && !command_on_path("curl") {
                report.fail("updater", "curl is required by `reachpad update`");
            } else {
                report.ok("updater", "installation source has an update path");
            }
        }
        Err(error) => report.fail("binary", error),
    }

    let endpoints_safe = match cli_auth::validate_connection_urls(controld, hub) {
        Err(error) => {
            report.fail("endpoints", error);
            false
        }
        Ok(()) => {
            report.ok("control endpoint", controld);
            report.ok("workspace endpoint", hub);
            true
        }
    };

    let operator_path = tokenfile::operator_path(token_path);
    let credential = match tokenfile::read_operator_token(token_path) {
        Ok(credential) => {
            match private_file(&operator_path) {
                Ok(()) => report.ok(
                    "credential file",
                    format!("{} has mode 0600", operator_path.display()),
                ),
                Err(error) => report.fail("credential file", error),
            }
            Some(credential)
        }
        Err(error) => {
            report.fail("saved login", error);
            None
        }
    };

    let connection_path = tokenfile::connection_path(token_path);
    match tokenfile::read_connection_config(token_path) {
        Ok(Some(saved)) => {
            match private_file(&connection_path) {
                Ok(()) => report.ok(
                    "endpoint file",
                    format!("{} has mode 0600", connection_path.display()),
                ),
                Err(error) => report.fail("endpoint file", error),
            }
            if let Err(error) = cli_auth::validate_connection_urls(&saved.controld, &saved.hub) {
                report.fail("saved endpoints", error);
            } else {
                report.ok("saved endpoints", "configuration is safe");
            }
        }
        Ok(None) => report.ok(
            "endpoint file",
            "not present; command-line endpoints are active",
        ),
        Err(error) => report.fail("endpoint file", error),
    }

    if let Some(credential) = credential.filter(|_| endpoints_safe) {
        let client = Client::with_trust(controld, trust);
        match client.operator_session(&credential).await {
            Ok(session) => report.ok(
                "account",
                format!(
                    "authenticated as user={} principal={}",
                    session.user_id, session.principal_id
                ),
            ),
            Err(error) => report.fail("account", error),
        }
    }

    if report.failures == 0 {
        println!("doctor: all checks passed");
        Ok(0)
    } else {
        println!("doctor: {} check(s) failed", report.failures);
        Ok(1)
    }
}

fn command_on_path(name: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|directory| directory.join(name).is_file())
}

fn executable_is_on_path(executable: &Path) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    executable_is_on_paths(executable, std::env::split_paths(&path))
}

fn executable_is_on_paths(
    executable: &Path,
    paths: impl Iterator<Item = std::path::PathBuf>,
) -> bool {
    let Ok(expected) = executable.canonicalize() else {
        return false;
    };
    paths.into_iter().any(|directory| {
        directory
            .join("reachpad")
            .canonicalize()
            .is_ok_and(|candidate| candidate == expected)
    })
}

#[cfg(unix)]
fn private_file(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt as _;

    let metadata =
        std::fs::metadata(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let mode = metadata.permissions().mode() & 0o777;
    if mode == tokenfile::FILE_MODE {
        Ok(())
    } else {
        Err(format!(
            "{} has mode {mode:04o}; run `chmod 600 {}`",
            path.display(),
            path.display()
        ))
    }
}

#[cfg(not(unix))]
fn private_file(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_resolution_follows_symlinks_to_the_running_binary() {
        let dir = std::env::temp_dir().join(format!("reach-doctor-path-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let binary = dir.join("actual-reachpad");
        std::fs::write(&binary, b"binary").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&binary, dir.join("reachpad")).unwrap();

        assert!(executable_is_on_paths(&binary, [dir.clone()].into_iter()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn credential_permission_check_requires_exactly_0600() {
        use std::os::unix::fs::PermissionsExt as _;

        let path = std::env::temp_dir().join(format!("reach-doctor-mode-{}", std::process::id()));
        std::fs::write(&path, b"credential").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(private_file(&path).is_ok());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(private_file(&path).is_err());
        let _ = std::fs::remove_file(path);
    }
}
