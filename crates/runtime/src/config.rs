//! Declarative environment-variable registry per binary (INFRA_SPEC §15).
//!
//! Each binary declares a [`Spec`] listing its required and optional
//! `REACHPAD_*` variables (names exactly as the §15 registry). [`load`]
//! reads the process environment and yields a [`Config`].
//!
//! Mode selection: `REACHPAD_MODE` — `"dev"` or `"prod"`. **Unset defaults
//! to `dev`** so a bare checkout runs with zero real secrets (§15 dev/sim
//! convention). Any other value is an error (the offending value is not
//! echoed back).
//!
//! - **prod:** all missing required variables are collected and reported in
//!   ONE [`ConfigError::MissingRequired`], names only. Missing optional
//!   variables are simply absent ([`Config::try_get`] returns `None`).
//! - **dev:** missing variables (required and optional alike) are filled
//!   with deterministic mocks so every component boots without
//!   provisioning:
//!   - `REACHPAD_STORE_URL` → `"mem://"` (in-memory object store)
//!   - other `REACHPAD_<ROLE>_URL` → `"mock://<role>"` (lower-cased), e.g.
//!     `REACHPAD_PG_URL` → `"mock://pg"`
//!   - everything else → `"dev-mock-<VARNAME>"`
//!
//! Redaction safety: `Config`'s `Debug` impl and every error/panic message
//! produced here render variable names and statuses only — never values.
//!
//! Environment values that are not valid Unicode are treated as missing
//! (they cannot be exposed as `&str`, and echoing them anywhere would risk
//! leaking bytes).

use std::collections::BTreeMap;
use std::fmt;

/// The mode-selector variable. Not listed in specs; always consulted.
pub const MODE_VAR: &str = "REACHPAD_MODE";

/// Runtime mode, from `REACHPAD_MODE`. Default: [`Mode::Dev`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Missing variables are filled with deterministic mocks.
    Dev,
    /// Missing required variables are a startup error.
    Prod,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Dev => "dev",
            Mode::Prod => "prod",
        }
    }
}

/// Declarative env registry for one binary.
///
/// Names must be the exact §15 registry names; inventing new secrets
/// requires an ADR. Duplicates between `required` and `optional` are
/// tolerated (required wins).
pub struct Spec {
    /// Binary name, used in error messages and `--check-config` output.
    pub bin: &'static str,
    /// Variables the binary cannot start without (in prod).
    pub required: &'static [&'static str],
    /// Variables the binary uses when present.
    pub optional: &'static [&'static str],
}

/// Where a variable's value came from. Printable; never carries the value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VarStatus {
    /// Present in the environment.
    Set,
    /// Absent; filled with a deterministic dev mock (dev mode only).
    Mocked,
    /// Absent and unfilled (prod mode; fatal iff required).
    Missing,
}

pub(crate) struct VarState {
    pub(crate) value: Option<String>,
    pub(crate) status: VarStatus,
    pub(crate) required: bool,
}

/// Validated configuration for one binary.
///
/// Values are reachable only through [`Config::get`] / [`Config::try_get`];
/// the `Debug` impl renders `<set>` / `<mocked>` / `<missing>` per variable
/// and never a value.
pub struct Config {
    bin: &'static str,
    mode: Mode,
    pub(crate) vars: BTreeMap<&'static str, VarState>,
}

impl Config {
    /// The value of `name`. Panics (names only, no values) if `name` was
    /// not declared in the [`Spec`] or is absent (missing optional in
    /// prod) — both are programming errors; use [`Config::try_get`] for
    /// optional variables.
    pub fn get(&self, name: &str) -> &str {
        match self.try_get(name) {
            Some(v) => v,
            None => panic!(
                "config: variable {name} is not available in {} (mode {}); \
                 declared in the Spec and set/mocked? use try_get for optional vars",
                self.bin,
                self.mode.as_str()
            ),
        }
    }

    /// The value of `name`, or `None` if undeclared or absent.
    pub fn try_get(&self, name: &str) -> Option<&str> {
        self.vars.get(name).and_then(|s| s.value.as_deref())
    }

    /// Status of a declared variable, or `None` if undeclared.
    pub fn status(&self, name: &str) -> Option<VarStatus> {
        self.vars.get(name).map(|s| s.status)
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    pub fn bin(&self) -> &'static str {
        self.bin
    }
}

impl fmt::Debug for Config {
    /// Renders statuses only — never values (I7 discipline for platform
    /// secrets; §15 "never in logs or error messages").
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_struct("Config");
        d.field("bin", &self.bin);
        d.field("mode", &self.mode.as_str());
        for (name, st) in &self.vars {
            let repr = match st.status {
                VarStatus::Set => "<set>",
                VarStatus::Mocked => "<mocked>",
                VarStatus::Missing => "<missing>",
            };
            d.field(name, &repr);
        }
        d.finish()
    }
}

/// Config loading errors. Display strings carry variable *names* only.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// `REACHPAD_MODE` held something other than `dev`/`prod`. The value
    /// is deliberately not echoed.
    #[error(
        "REACHPAD_MODE has an unrecognized value; expected \"dev\" or \"prod\" (value not shown)"
    )]
    BadMode,
    /// One error listing ALL missing required variables at once (§15:
    /// "fails fast at startup, listing ALL missing variables at once").
    #[error("{bin}: missing required environment variables: {}", .names.join(", "))]
    MissingRequired {
        bin: &'static str,
        names: Vec<&'static str>,
    },
}

/// Deterministic dev-mode filler for an absent variable (§15: every secret
/// has a deterministic mock; the sim harness runs with zero real secrets).
fn dev_mock(name: &str) -> String {
    if name == "REACHPAD_STORE_URL" {
        return "mem://".to_owned();
    }
    if let Some(inner) = name
        .strip_prefix("REACHPAD_")
        .and_then(|s| s.strip_suffix("_URL"))
    {
        return format!("mock://{}", inner.to_ascii_lowercase());
    }
    format!("dev-mock-{name}")
}

/// Environment lookup used by [`load`]. Non-Unicode values read as absent.
pub(crate) fn env_lookup(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

/// Builds a [`Config`] without enforcing required-ness (used by both
/// [`load_with`] and `--check-config`, which must report per-var status
/// even when the check fails). Only [`ConfigError::BadMode`] is possible.
pub(crate) fn collect<F>(spec: &Spec, lookup: F) -> Result<Config, ConfigError>
where
    F: Fn(&str) -> Option<String>,
{
    let mode = match lookup(MODE_VAR).as_deref() {
        None | Some("dev") => Mode::Dev,
        Some("prod") => Mode::Prod,
        Some(_) => return Err(ConfigError::BadMode),
    };

    let mut vars: BTreeMap<&'static str, VarState> = BTreeMap::new();
    let required_first = spec
        .required
        .iter()
        .copied()
        .map(|n| (n, true))
        .chain(spec.optional.iter().copied().map(|n| (n, false)));
    for (name, required) in required_first {
        if let Some(existing) = vars.get_mut(name) {
            existing.required |= required;
            continue;
        }
        let state = match lookup(name) {
            Some(v) => VarState {
                value: Some(v),
                status: VarStatus::Set,
                required,
            },
            None => match mode {
                Mode::Dev => VarState {
                    value: Some(dev_mock(name)),
                    status: VarStatus::Mocked,
                    required,
                },
                Mode::Prod => VarState {
                    value: None,
                    status: VarStatus::Missing,
                    required,
                },
            },
        };
        vars.insert(name, state);
    }

    Ok(Config {
        bin: spec.bin,
        mode,
        vars,
    })
}

/// [`load`] with an injected lookup — the seam for deterministic tests
/// (no process-global environment involved).
pub fn load_with<F>(spec: &Spec, lookup: F) -> Result<Config, ConfigError>
where
    F: Fn(&str) -> Option<String>,
{
    let cfg = collect(spec, lookup)?;
    let missing: Vec<&'static str> = cfg
        .vars
        .iter()
        .filter(|(_, s)| s.required && s.status == VarStatus::Missing)
        .map(|(n, _)| *n)
        .collect();
    if missing.is_empty() {
        Ok(cfg)
    } else {
        Err(ConfigError::MissingRequired {
            bin: spec.bin,
            names: missing,
        })
    }
}

/// Loads and validates config for `spec` from the process environment.
pub fn load(spec: &Spec) -> Result<Config, ConfigError> {
    load_with(spec, env_lookup)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPEC: Spec = Spec {
        bin: "testd",
        required: &[
            "REACHPAD_PG_URL",
            "REACHPAD_STORE_URL",
            "REACHPAD_KMS_KEY_ID",
        ],
        optional: &["REACHPAD_IDP_API_KEY"],
    };

    fn none(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn dev_is_the_default_mode_and_fills_deterministic_mocks() {
        let cfg = load_with(&SPEC, none).unwrap();
        assert_eq!(cfg.mode(), Mode::Dev);
        assert_eq!(cfg.get("REACHPAD_PG_URL"), "mock://pg");
        assert_eq!(cfg.get("REACHPAD_STORE_URL"), "mem://");
        assert_eq!(
            cfg.get("REACHPAD_KMS_KEY_ID"),
            "dev-mock-REACHPAD_KMS_KEY_ID"
        );
        // Optional vars are mocked in dev too — dev boots need nothing.
        assert_eq!(
            cfg.get("REACHPAD_IDP_API_KEY"),
            "dev-mock-REACHPAD_IDP_API_KEY"
        );
        for name in SPEC.required.iter().chain(SPEC.optional) {
            assert_eq!(cfg.status(name), Some(VarStatus::Mocked));
        }
    }

    #[test]
    fn dev_mock_url_rule_applies_to_any_reachpad_url_var() {
        assert_eq!(dev_mock("REACHPAD_UPSTREAM_URL"), "mock://upstream");
        assert_eq!(dev_mock("REACHPAD_STORE_URL"), "mem://");
        assert_eq!(
            dev_mock("REACHPAD_BILLING_SECRET"),
            "dev-mock-REACHPAD_BILLING_SECRET"
        );
    }

    #[test]
    fn prod_reports_all_missing_required_vars_in_one_error_without_values() {
        let canary = "canary-value-3f9a1c-do-not-print";
        let lookup = |name: &str| match name {
            MODE_VAR => Some("prod".to_owned()),
            "REACHPAD_PG_URL" => Some(canary.to_owned()),
            _ => None,
        };
        let err = load_with(&SPEC, lookup).unwrap_err();
        let msg = err.to_string();
        // Every missing name, in one message (M0 item 11).
        assert!(msg.contains("REACHPAD_STORE_URL"), "missing name in: {msg}");
        assert!(
            msg.contains("REACHPAD_KMS_KEY_ID"),
            "missing name in: {msg}"
        );
        // Optional vars are not part of the required-missing report.
        assert!(
            !msg.contains("REACHPAD_IDP_API_KEY"),
            "optional listed: {msg}"
        );
        assert!(msg.contains("testd"));
        // Values never printed.
        assert!(!msg.contains(canary), "value leaked: {msg}");
    }

    #[test]
    fn prod_missing_error_lists_exactly_the_required_missing_set() {
        let spec = Spec {
            bin: "testd",
            required: &["REACHPAD_A", "REACHPAD_B", "REACHPAD_C"],
            optional: &["REACHPAD_OPT"],
        };
        let lookup = |name: &str| (name == MODE_VAR).then(|| "prod".to_owned());
        let err = load_with(&spec, lookup).unwrap_err();
        match err {
            ConfigError::MissingRequired { bin, names } => {
                assert_eq!(bin, "testd");
                assert_eq!(names, vec!["REACHPAD_A", "REACHPAD_B", "REACHPAD_C"]);
            }
            other => panic!("wrong error: {other}"),
        }
    }

    #[test]
    fn prod_with_everything_set_loads_and_optional_missing_is_none() {
        let lookup = |name: &str| match name {
            MODE_VAR => Some("prod".to_owned()),
            "REACHPAD_PG_URL" | "REACHPAD_STORE_URL" | "REACHPAD_KMS_KEY_ID" => {
                Some(format!("value-of-{name}"))
            }
            _ => None,
        };
        let cfg = load_with(&SPEC, lookup).unwrap();
        assert_eq!(cfg.mode(), Mode::Prod);
        assert_eq!(cfg.get("REACHPAD_PG_URL"), "value-of-REACHPAD_PG_URL");
        assert_eq!(cfg.status("REACHPAD_PG_URL"), Some(VarStatus::Set));
        assert_eq!(cfg.try_get("REACHPAD_IDP_API_KEY"), None);
        assert_eq!(cfg.status("REACHPAD_IDP_API_KEY"), Some(VarStatus::Missing));
    }

    #[test]
    fn bad_mode_is_rejected_without_echoing_the_value() {
        let secret_mode = "prodd-oops-with-secret-af01";
        let lookup = |name: &str| (name == MODE_VAR).then(|| secret_mode.to_owned());
        let err = load_with(&SPEC, lookup).unwrap_err();
        assert!(matches!(err, ConfigError::BadMode));
        assert!(!err.to_string().contains(secret_mode));
    }

    #[test]
    fn debug_renders_statuses_never_values() {
        let canary = "super-secret-canary-9e3f";
        let lookup = |name: &str| match name {
            MODE_VAR => Some("prod".to_owned()),
            _ => Some(canary.to_owned()),
        };
        let cfg = load_with(&SPEC, lookup).unwrap();
        let rendered = format!("{cfg:?}");
        assert!(
            !rendered.contains(canary),
            "Debug leaked a value: {rendered}"
        );
        assert!(rendered.contains("<set>"));
        assert!(rendered.contains("REACHPAD_PG_URL"));

        let dev = load_with(&SPEC, none).unwrap();
        let rendered = format!("{dev:?}");
        assert!(!rendered.contains("mock://pg"), "Debug leaked a mock value");
        assert!(rendered.contains("<mocked>"));
    }

    #[test]
    fn debug_renders_missing_for_absent_optional_in_prod() {
        let lookup = |name: &str| match name {
            "REACHPAD_IDP_API_KEY" => None,
            MODE_VAR => Some("prod".to_owned()),
            _ => Some("x".to_owned()),
        };
        let cfg = load_with(&SPEC, lookup).unwrap();
        assert!(format!("{cfg:?}").contains("<missing>"));
    }

    #[test]
    fn duplicate_name_in_required_and_optional_stays_required() {
        let spec = Spec {
            bin: "testd",
            required: &["REACHPAD_DUP"],
            optional: &["REACHPAD_DUP"],
        };
        let lookup = |name: &str| (name == MODE_VAR).then(|| "prod".to_owned());
        let err = load_with(&spec, lookup).unwrap_err();
        assert!(err.to_string().contains("REACHPAD_DUP"));
    }

    #[test]
    #[should_panic(expected = "REACHPAD_IDP_API_KEY")]
    fn get_on_absent_var_panics_with_the_name() {
        let lookup = |name: &str| match name {
            "REACHPAD_IDP_API_KEY" => None,
            MODE_VAR => Some("prod".to_owned()),
            _ => Some("x".to_owned()),
        };
        let cfg = load_with(&SPEC, lookup).unwrap();
        let _ = cfg.get("REACHPAD_IDP_API_KEY");
    }
}
