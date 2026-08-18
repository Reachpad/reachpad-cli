//! `reachpad doctor` — read-only diagnostics for this installation.
//!
//! Every check answers one question a broken install raises, in the order a
//! command hits them: is the binary the one PATH resolves, is the endpoint
//! safe, is the credential there and private, and does the fleet actually
//! accept it. No check here writes or repairs anything — a diagnostic that
//! changes state cannot be run twice to see whether something changed. (The
//! one write that can happen during a `doctor` run is the v0.1.0 credential
//! migration every command performs on startup, which announces itself.)
//!
//! No credential VALUE is ever printed: presence, file mode, and the server's
//! answer are the whole story, and none of those require echoing a secret.

use std::path::Path;

use serde_json::json;

use crate::commands::Ctx;
use crate::conf;
use crate::errors::{CliError, EXIT_OK};
use crate::self_update::{install_source, InstallSource};

/// One line of the report. `ok: false` is a finding, not an error: doctor's
/// job is to print all of them, so no single failed check may end the run.
struct Check {
    name: &'static str,
    ok: bool,
    detail: String,
}

#[derive(Default)]
struct Report {
    checks: Vec<Check>,
}

impl Report {
    fn ok(&mut self, name: &'static str, detail: impl std::fmt::Display) {
        self.checks.push(Check {
            name,
            ok: true,
            detail: detail.to_string(),
        });
    }

    fn fail(&mut self, name: &'static str, detail: impl std::fmt::Display) {
        self.checks.push(Check {
            name,
            ok: false,
            detail: detail.to_string(),
        });
    }

    fn failures(&self) -> usize {
        self.checks.iter().filter(|c| !c.ok).count()
    }
}

pub(crate) async fn run(ctx: &Ctx) -> Result<i32, CliError> {
    let mut report = Report::default();

    report.ok("version", env!("CARGO_PKG_VERSION"));
    match std::env::current_exe() {
        Ok(path) => {
            let source = install_source(&path);
            report.ok("binary", format!("{} ({})", path.display(), owner(source)));
            // An npm install is EXPECTED not to be the file on PATH: what npm
            // links into a bin directory is its own launcher, which then
            // execs this binary out of `node_modules`. Comparing the two
            // failed that check on every healthy npm install — a red line on
            // a working machine, which teaches people to ignore doctor.
            if source == InstallSource::Npm {
                report.ok("path", "`reachpad` is npm's launcher for this binary");
            } else if executable_is_on_path(&path) {
                report.ok("path", "`reachpad` resolves to this binary");
            } else {
                report.fail(
                    "path",
                    format!(
                        "`reachpad` on PATH is not {} — an update would leave the \
                         other copy in place",
                        path.display()
                    ),
                );
            }
            if source == InstallSource::Native && !command_on_path("curl") {
                report.fail(
                    "updater",
                    "`reachpad update` needs curl, which is not on PATH",
                );
            } else {
                report.ok("updater", update_path(source));
            }
        }
        Err(error) => report.fail("binary", error),
    }

    // The endpoint this invocation would actually use, after the saved
    // config and every override — the one a wrong answer here would explain.
    report.ok("endpoint", &ctx.endpoint);
    match crate::cli_auth::validate_connection_urls(&ctx.controld, &ctx.hub) {
        Ok(()) => {
            report.ok("control plane", &ctx.controld);
            report.ok("workspace plane", &ctx.hub);
        }
        Err(error) => report.fail("endpoint safety", error),
    }

    // The config file is read again here rather than taken from the context:
    // `doctor` is built with a tolerant context precisely so an unparsable
    // file reaches THIS line and is named, instead of stopping the command.
    // Permissions first here too, for the same reason as the credential.
    let config_file = ctx.paths.config_file();
    if check_mode(&mut report, "config permissions", &config_file) {
        match conf::load_config(&ctx.paths) {
            Ok(config) => match config.endpoint {
                Some(saved) => report.ok("saved endpoint", saved),
                None => report.ok(
                    "saved endpoint",
                    "none saved; the default or an override is in use",
                ),
            },
            Err(error) => report.fail(
                "config file",
                format!("{}: {error:#}", config_file.display()),
            ),
        }
    } else {
        report.fail(
            "saved endpoint",
            "not checked: the file's permissions have to be fixed first",
        );
    }

    // Permissions FIRST, then content. The credential reader refuses a
    // world-readable file itself, so asking in the other order would report
    // one broken file as two independent findings.
    let credentials_file = ctx.paths.credentials_file();
    let private = check_mode(&mut report, "credential permissions", &credentials_file);
    let credential = if !private {
        report.fail(
            "credential",
            "not checked: the file's permissions have to be fixed first",
        );
        None
    } else {
        match conf::load_credential(&ctx.paths, crate::commands::now_ms()) {
            Ok(conf::Stored::Present(credential)) => {
                report.ok("credential", "a saved sign-in is present and unexpired");
                Some(credential)
            }
            Ok(conf::Stored::Missing) => {
                report.fail("credential", "no saved sign-in; run `reachpad auth login`");
                None
            }
            Ok(conf::Stored::Expired) => {
                report.fail(
                    "credential",
                    "the saved sign-in has expired; run `reachpad auth login`",
                );
                None
            }
            // Unreadable is NOT the same as absent, and saying so is the
            // point: "run login" would overwrite the evidence of whatever
            // went wrong.
            Err(error) => {
                report.fail(
                    "credential",
                    format!("{}: {error:#}", credentials_file.display()),
                );
                None
            }
        }
    };

    // The only check that leaves the machine, and the only one that proves
    // anything: everything above can be right while the fleet still says no.
    match credential {
        Some(credential) => match ctx.client().operator_session(credential.bearer()).await {
            Ok(session) => report.ok(
                "account",
                format!("signed in as {} at {}", session.user_id, ctx.endpoint),
            ),
            Err(error) => report.fail("account", format!("{error}")),
        },
        None => report.fail("account", "not checked: no usable credential"),
    }

    let failures = report.failures();
    let human: Vec<String> = report
        .checks
        .iter()
        .map(|c| {
            format!(
                "{} {}: {}",
                if c.ok { "ok  " } else { "FAIL" },
                c.name,
                c.detail
            )
        })
        .chain(std::iter::once(if failures == 0 {
            "All checks passed.".to_owned()
        } else {
            format!("{failures} check(s) failed.")
        }))
        .collect();
    ctx.emit(
        json!({
            "checks": report.checks.iter().map(|c| json!({
                "name": c.name,
                "ok": c.ok,
                "detail": c.detail,
            })).collect::<Vec<_>>(),
            "failures": failures,
        }),
        &human,
    );
    // Exit 1, not a coded refusal: nothing was refused. A failing check is a
    // finding about this machine, and 1 is what a script tests for.
    Ok(if failures == 0 { EXIT_OK } else { 1 })
}

fn owner(source: InstallSource) -> &'static str {
    match source {
        InstallSource::Homebrew => "installed by Homebrew",
        InstallSource::HomebrewCask => "installed by Homebrew as a cask the tap no longer ships",
        InstallSource::Npm => "installed by npm",
        InstallSource::Development => "a cargo build in this checkout",
        InstallSource::Native => "installed by the Reachpad installer",
    }
}

fn update_path(source: InstallSource) -> &'static str {
    match source {
        InstallSource::Homebrew => "`reachpad update` defers to `brew upgrade reachpad`",
        InstallSource::HomebrewCask => {
            "`reachpad update` prints the cask-to-formula migration: the tap ships a formula now"
        }
        InstallSource::Npm => "`reachpad update` defers to `npm install -g @reachpad/cli@latest`",
        InstallSource::Development => "`reachpad update` defers to `cargo build -p reach`",
        InstallSource::Native => "`reachpad update` can replace this binary",
    }
}

/// A missing file is not a permission finding: whether its absence matters
/// was already decided by the check that looked for its CONTENT, and saying
/// it twice would make one problem look like two.
///
/// Returns whether the file is safe for a later check to READ: a wrong mode
/// is not, and an absent file trivially is.
fn check_mode(report: &mut Report, name: &'static str, path: &Path) -> bool {
    match private_file(path) {
        Ok(()) => {
            report.ok(name, format!("{} is 0600", path.display()));
            true
        }
        Err(FileMode::Absent) => {
            report.ok(name, format!("{} not present", path.display()));
            true
        }
        Err(FileMode::Wrong(mode)) => {
            report.fail(
                name,
                format!(
                    "{} is {mode:04o}; anyone on this machine can read it. \
                     Fix with `chmod 600 {}`, and treat what was in it as disclosed.",
                    path.display(),
                    path.display()
                ),
            );
            false
        }
        Err(FileMode::Unreadable(error)) => {
            report.fail(name, format!("{}: {error}", path.display()));
            false
        }
    }
}

enum FileMode {
    Absent,
    Wrong(u32),
    Unreadable(String),
}

#[cfg(unix)]
fn private_file(path: &Path) -> Result<(), FileMode> {
    use std::os::unix::fs::PermissionsExt as _;

    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Err(FileMode::Absent),
        Err(error) => return Err(FileMode::Unreadable(error.to_string())),
    };
    let mode = metadata.permissions().mode() & 0o777;
    if mode == 0o600 {
        Ok(())
    } else {
        Err(FileMode::Wrong(mode))
    }
}

#[cfg(not(unix))]
fn private_file(path: &Path) -> Result<(), FileMode> {
    match std::fs::metadata(path) {
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Err(FileMode::Absent),
        Err(error) => Err(FileMode::Unreadable(error.to_string())),
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

/// Both sides are canonicalized, so the common install — a symlink in
/// `~/.local/bin` pointing at the real file — reads as the same binary
/// rather than a second copy.
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

    /// A different binary of the same name earlier on PATH is the failure
    /// this check exists for: `reachpad update` would update one copy while
    /// the shell kept running the other.
    #[test]
    fn a_different_reachpad_on_path_is_not_this_one() {
        let dir = std::env::temp_dir().join(format!("reach-doctor-other-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let running = dir.join("running-reachpad");
        std::fs::write(&running, b"a").unwrap();
        std::fs::write(dir.join("reachpad"), b"b").unwrap();

        assert!(!executable_is_on_paths(&running, [dir.clone()].into_iter()));
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
        assert!(matches!(private_file(&path), Err(FileMode::Wrong(0o644))));
        let _ = std::fs::remove_file(&path);
        assert!(matches!(private_file(&path), Err(FileMode::Absent)));
    }
}
