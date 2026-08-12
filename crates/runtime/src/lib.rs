//! `runtime` — shared binary plumbing (ADR-0002, INFRA_SPEC §15).
//!
//! Every reachpad binary boots through this crate:
//!
//! 1. Declare a [`Spec`]: which `REACHPAD_*` variables the binary requires
//!    and which are optional.
//! 2. Call [`run_startup`] with the process argv. If `--check-config` is
//!    present, per-variable status (never values) is printed to stdout and
//!    the caller exits with the returned `ok` flag. Otherwise a validated
//!    [`Config`] is returned.
//! 3. Call [`init_tracing`] once.
//!
//! Design rules this crate enforces (§15 conventions):
//!
//! - **Fail fast, all at once:** in `prod` mode, every missing required
//!   variable is collected and reported in a single error.
//! - **Values never printed:** [`Config`]'s `Debug` impl, all error
//!   messages, and `--check-config` output render only variable *names*
//!   and statuses (`<set>` / `<mocked>` / `<missing>`).
//! - **Zero real secrets in dev/sim:** in `dev` mode (the default) missing
//!   variables are filled with deterministic mocks.
//!
//! This crate contains no domain logic and depends on no other workspace
//! crate.

pub mod config;
pub mod startup;
pub mod telemetry;

pub use config::{Config, ConfigError, Mode, Spec, VarStatus};
pub use startup::{run_startup, Startup};
pub use telemetry::init_tracing;
