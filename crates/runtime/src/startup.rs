//! Startup entry point shared by all binaries: `--check-config` handling
//! (§15: "every binary supports `--check-config`") plus normal config load.

use std::io::Write;

use crate::config::{self, Config, ConfigError, Spec, VarStatus};

/// Outcome of [`run_startup`].
pub enum Startup {
    /// Normal start: validated config, proceed to serve.
    Run(Config),
    /// `--check-config` was requested and the report was printed to
    /// stdout. The caller should exit with status 0 if `ok`, else 1.
    CheckConfigDone { ok: bool },
}

/// Shared boot entry point.
///
/// If `argv` contains `--check-config`, prints one line per declared
/// variable — `SET` / `MOCKED` / `MISSING`, never a value — to stdout and
/// returns [`Startup::CheckConfigDone`]. Otherwise loads and validates the
/// config ([`config::load`]) and returns [`Startup::Run`].
///
/// Pass the full process argv (`std::env::args()`); the binary name in
/// position 0 is harmless.
pub fn run_startup<I, S>(spec: &Spec, argv: I) -> Result<Startup, ConfigError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let check_requested = argv.into_iter().any(|a| a.as_ref() == "--check-config");
    if check_requested {
        let mut stdout = std::io::stdout().lock();
        let ok = check_config_report(spec, config::env_lookup, &mut stdout);
        Ok(Startup::CheckConfigDone { ok })
    } else {
        config::load(spec).map(Startup::Run)
    }
}

/// Writes the `--check-config` report for `spec` to `out` and returns
/// whether the configuration is startable (`true` iff no required variable
/// is missing and the mode is valid). Values are never written.
///
/// Public with an injectable lookup/writer so binaries and tests can run
/// the exact production report deterministically.
pub fn check_config_report<F, W>(spec: &Spec, lookup: F, out: &mut W) -> bool
where
    F: Fn(&str) -> Option<String>,
    W: Write,
{
    let cfg = match config::collect(spec, lookup) {
        Ok(cfg) => cfg,
        Err(e) => {
            // BadMode is the only collect error; it carries no value.
            let _ = writeln!(out, "{}: config check FAILED: {e}", spec.bin);
            return false;
        }
    };

    let _ = writeln!(
        out,
        "{} config check (mode: {})",
        spec.bin,
        cfg.mode().as_str()
    );
    let width = cfg.vars.keys().map(|n| n.len()).max().unwrap_or(0);
    let mut missing_required = 0usize;
    for (name, st) in &cfg.vars {
        let label = match st.status {
            VarStatus::Set => "SET",
            VarStatus::Mocked => "MOCKED",
            VarStatus::Missing if st.required => {
                missing_required += 1;
                "MISSING"
            }
            VarStatus::Missing => "MISSING (optional)",
        };
        let _ = writeln!(out, "  {name:<width$}  {label}");
    }
    let ok = missing_required == 0;
    if ok {
        let _ = writeln!(out, "ok");
    } else {
        let _ = writeln!(
            out,
            "FAILED: {missing_required} required variable(s) missing"
        );
    }
    ok
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::MODE_VAR;

    const SPEC: Spec = Spec {
        bin: "checkd",
        required: &["REACHPAD_PG_URL", "REACHPAD_KMS_KEY_ID", "REACHPAD_CA_KEY"],
        optional: &["REACHPAD_IDP_API_KEY"],
    };

    fn report(lookup: impl Fn(&str) -> Option<String>) -> (bool, String) {
        let mut buf = Vec::new();
        let ok = check_config_report(&SPEC, lookup, &mut buf);
        (ok, String::from_utf8(buf).unwrap())
    }

    #[test]
    fn check_config_lists_every_var_in_dev_and_is_ok() {
        let canary = "present-value-77aa";
        let (ok, out) = report(|name| match name {
            "REACHPAD_PG_URL" => Some(canary.to_owned()),
            _ => None,
        });
        assert!(ok);
        // Every declared var appears, with its status.
        for name in SPEC.required.iter().chain(SPEC.optional) {
            assert!(out.contains(name), "missing {name} in:\n{out}");
        }
        assert!(out.contains("SET"));
        assert!(out.contains("MOCKED"));
        assert!(out.contains("(mode: dev)"));
        assert!(out.contains("ok"));
        // Never values.
        assert!(!out.contains(canary), "value leaked:\n{out}");
    }

    #[test]
    fn check_config_reports_missing_in_prod_and_fails() {
        let (ok, out) = report(|name| match name {
            MODE_VAR => Some("prod".to_owned()),
            "REACHPAD_PG_URL" => Some("x".to_owned()),
            _ => None,
        });
        assert!(!ok);
        assert!(out.contains("(mode: prod)"));
        assert!(out.contains("REACHPAD_KMS_KEY_ID"));
        assert!(out.contains("REACHPAD_CA_KEY"));
        assert!(out.contains("MISSING"));
        assert!(
            out.contains("MISSING (optional)"),
            "optional flagged:\n{out}"
        );
        assert!(out.contains("FAILED: 2 required variable(s) missing"));
    }

    #[test]
    fn check_config_fails_on_bad_mode_without_echoing_it() {
        let bad = "staging-with-token-b2c4";
        let mut buf = Vec::new();
        let ok = check_config_report(
            &SPEC,
            |name| (name == MODE_VAR).then(|| bad.to_owned()),
            &mut buf,
        );
        let out = String::from_utf8(buf).unwrap();
        assert!(!ok);
        assert!(out.contains("FAILED"));
        assert!(!out.contains(bad), "mode value leaked:\n{out}");
    }
}
