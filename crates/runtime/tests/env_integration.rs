//! Integration tests that exercise the REAL process environment through the
//! public API (`load`, `run_startup`).
//!
//! `std::env::set_var` is process-global and `cargo test` runs tests on
//! parallel threads, so every test here (a) takes a shared mutex and
//! (b) uses variable names unique to that test. (Under cargo-nextest each
//! test is its own process, which makes this doubly safe.)

use std::sync::Mutex;

use runtime::{run_startup, Config, ConfigError, Mode, Spec, Startup};

static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Runs `f` with the given vars applied (`Some` = set, `None` = removed),
/// restoring the previous environment afterwards even on panic-free paths.
fn with_env<R>(vars: &[(&str, Option<&str>)], f: impl FnOnce() -> R) -> R {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let saved: Vec<(String, Option<String>)> = vars
        .iter()
        .map(|(k, _)| ((*k).to_owned(), std::env::var(k).ok()))
        .collect();
    for (k, v) in vars {
        match v {
            Some(v) => std::env::set_var(k, v),
            None => std::env::remove_var(k),
        }
    }
    let result = f();
    for (k, v) in saved {
        match v {
            Some(v) => std::env::set_var(&k, v),
            None => std::env::remove_var(&k),
        }
    }
    result
}

#[test]
fn prod_load_from_real_env_lists_all_three_missing_names_and_no_values() {
    const SPEC: Spec = Spec {
        bin: "envtestd",
        required: &[
            "REACHPAD_ENVT1_A",
            "REACHPAD_ENVT1_B",
            "REACHPAD_ENVT1_C",
            "REACHPAD_ENVT1_PRESENT",
        ],
        optional: &[],
    };
    let canary = "real-env-canary-1d4e";
    with_env(
        &[
            ("REACHPAD_MODE", Some("prod")),
            ("REACHPAD_ENVT1_A", None),
            ("REACHPAD_ENVT1_B", None),
            ("REACHPAD_ENVT1_C", None),
            ("REACHPAD_ENVT1_PRESENT", Some(canary)),
        ],
        || {
            let err = runtime::config::load(&SPEC).unwrap_err();
            let msg = err.to_string();
            assert!(msg.contains("REACHPAD_ENVT1_A"), "in: {msg}");
            assert!(msg.contains("REACHPAD_ENVT1_B"), "in: {msg}");
            assert!(msg.contains("REACHPAD_ENVT1_C"), "in: {msg}");
            assert!(!msg.contains(canary), "value leaked: {msg}");
            assert!(matches!(err, ConfigError::MissingRequired { .. }));
        },
    );
}

#[test]
fn dev_load_from_real_env_yields_mocks() {
    const SPEC: Spec = Spec {
        bin: "envtestd",
        required: &[
            "REACHPAD_PG_URL",
            "REACHPAD_STORE_URL",
            "REACHPAD_ENVT2_KEY",
        ],
        optional: &[],
    };
    with_env(
        &[
            ("REACHPAD_MODE", None), // unset => dev (documented default)
            ("REACHPAD_PG_URL", None),
            ("REACHPAD_STORE_URL", None),
            ("REACHPAD_ENVT2_KEY", None),
        ],
        || {
            let cfg = runtime::config::load(&SPEC).unwrap();
            assert_eq!(cfg.mode(), Mode::Dev);
            assert_eq!(cfg.get("REACHPAD_PG_URL"), "mock://pg");
            assert_eq!(cfg.get("REACHPAD_STORE_URL"), "mem://");
            assert_eq!(cfg.get("REACHPAD_ENVT2_KEY"), "dev-mock-REACHPAD_ENVT2_KEY");
        },
    );
}

#[test]
fn debug_of_config_from_real_env_never_contains_the_canary_secret() {
    const SPEC: Spec = Spec {
        bin: "envtestd",
        required: &["REACHPAD_ENVT3_SECRET"],
        optional: &[],
    };
    let canary = "canary-secret-value-b7c2e9-must-never-render";
    with_env(
        &[
            ("REACHPAD_MODE", Some("prod")),
            ("REACHPAD_ENVT3_SECRET", Some(canary)),
        ],
        || {
            let cfg: Config = runtime::config::load(&SPEC).unwrap();
            let rendered = format!("{cfg:?}");
            assert!(
                !rendered.contains(canary),
                "Debug leaked the canary: {rendered}"
            );
            assert!(rendered.contains("REACHPAD_ENVT3_SECRET"));
            assert!(rendered.contains("<set>"));
            // The value is still reachable through the accessor.
            assert_eq!(cfg.get("REACHPAD_ENVT3_SECRET"), canary);
        },
    );
}

#[test]
fn run_startup_with_check_config_flag_reports_done_ok_in_dev() {
    const SPEC: Spec = Spec {
        bin: "envtestd",
        required: &["REACHPAD_ENVT4_KEY"],
        optional: &[],
    };
    with_env(
        &[("REACHPAD_MODE", None), ("REACHPAD_ENVT4_KEY", None)],
        || {
            let argv = ["envtestd", "--check-config"];
            match run_startup(&SPEC, argv).unwrap() {
                Startup::CheckConfigDone { ok } => assert!(ok),
                Startup::Run(_) => panic!("expected CheckConfigDone"),
            }
        },
    );
}

#[test]
fn run_startup_with_check_config_flag_reports_not_ok_when_prod_missing() {
    const SPEC: Spec = Spec {
        bin: "envtestd",
        required: &["REACHPAD_ENVT5_KEY"],
        optional: &[],
    };
    with_env(
        &[
            ("REACHPAD_MODE", Some("prod")),
            ("REACHPAD_ENVT5_KEY", None),
        ],
        || {
            let argv = ["envtestd", "--check-config"];
            match run_startup(&SPEC, argv).unwrap() {
                Startup::CheckConfigDone { ok } => assert!(!ok),
                Startup::Run(_) => panic!("expected CheckConfigDone"),
            }
        },
    );
}

#[test]
fn run_startup_without_flag_returns_run_with_env_values() {
    const SPEC: Spec = Spec {
        bin: "envtestd",
        required: &["REACHPAD_ENVT6_KEY"],
        optional: &[],
    };
    with_env(
        &[
            ("REACHPAD_MODE", Some("prod")),
            ("REACHPAD_ENVT6_KEY", Some("v6")),
        ],
        || match run_startup(&SPEC, ["envtestd"]).unwrap() {
            Startup::Run(cfg) => {
                assert_eq!(cfg.get("REACHPAD_ENVT6_KEY"), "v6");
                assert_eq!(cfg.bin(), "envtestd");
            }
            Startup::CheckConfigDone { .. } => panic!("expected Run"),
        },
    );
}
