//! reachpad — the CLI, and the product interface (INFRA_SPEC §5.8).
//!
//! A thin client of the §6 protocol and controld's public HTTP API — and,
//! since the agent-native pivot, the way customers drive their hosted
//! workspaces with their own agents. It remains an ordinary client bound by
//! I6 — **there is no privileged interface**: anything the API can do, the
//! CLI can do, and nothing more. The integration test
//! `tests/no_privileged_interface.rs` boots controld and hub in-process and
//! drives create → attach → share → tail → refused-mutation entirely
//! through the public surfaces.
//!
//! §15: the CLI is a *client* — it holds ZERO platform secrets. Its
//! [`SPEC`] has empty required and optional lists; the only credentials it
//! touches are the user's own (Biscuit + operator credential), kept in 0600
//! files (`~/.config/reachpad/` by default; the pre-rename `~/.config/reach/`
//! keeps working via a read-through fallback).
//!
//! The crate keeps the package name `reach` so `-p reach` and `use reach::`
//! stay stable; only the SHIPPED BINARY is named `reachpad` (`[[bin]]` in
//! Cargo.toml).
//!
//! Layout (thin `main.rs` shell over this lib):
//! - [`cli`] — clap surface + duration parsing.
//! - [`http_min`] — hand-rolled minimal HTTP/1.1 JSON client over tokio
//!   `TcpStream` (deliberately no reqwest/hyper — §10 anti-bloat).
//! - [`api`] — typed calls to controld's public endpoints.
//! - [`tokenfile`] — token file read/write (0600) + attach state.
//! - [`inspect`] — offline token fact printing (no verification, no root
//!   key: `UnverifiedBiscuit` parse only).
//! - [`transport`] — the frozen §6 frames over WebSocket (ADR-0007
//!   fallback) or QUIC (ADR-0026, ALPN `reachpad/1`).
//! - [`tail`] — the tail session: handshake, capability consumption,
//!   events + durable watermarks, over either transport.
//! - [`attach`] — the interactive PTY session (ADR-0033): raw mode, resize,
//!   ctrl-c passthrough, clean detach. The felt test of the whole system.
//! - [`commands`] — command dispatch; all printing lives here.

pub mod api;
pub mod attach;
pub mod cli;
pub mod commands;
pub mod http_min;
pub mod inspect;
pub mod tail;
pub mod tokenfile;
pub mod transport;

/// §15 registry for reach: a pure client — no platform secrets, ever.
/// Client credentials (the user's Biscuit) live in the token file instead.
pub const SPEC: runtime::Spec = runtime::Spec {
    bin: "reachpad",
    required: &[],
    optional: &[],
};

pub use commands::run;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_holds_zero_platform_secrets() {
        // §15 structural rule for clients: nothing required, nothing
        // optional — a stolen laptop image contains no platform secret.
        assert_eq!(SPEC.bin, "reachpad");
        assert!(SPEC.required.is_empty());
        assert!(SPEC.optional.is_empty());
    }

    #[test]
    fn dev_mode_boots_with_zero_env() {
        // §15 dev convention: a bare checkout loads config with no
        // provisioning at all.
        let cfg = runtime::config::load_with(&SPEC, |_| None).unwrap();
        assert_eq!(cfg.mode(), runtime::Mode::Dev);
    }
}
