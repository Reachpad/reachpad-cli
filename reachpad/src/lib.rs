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
//! §15: the CLI is a *client* — it holds ZERO platform secrets. It reads no
//! platform environment at all; the only credentials it touches are the
//! user's own, kept in 0600 files under `~/.config/reachpad/` and
//! `~/.local/state/reachpad/` (see [`conf`] and [`state`]).
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
//! - [`errors`] — wire code → sentence, exit code, `--json` envelope.
//! - [`privatefile`] — 0700 dirs, 0600 files, atomic writes, checked reads.
//! - [`conf`] — `config.toml` / `credentials.toml` and their strict parser.
//! - [`render`] — the one place wire spellings become surface ones.
//! - [`state`] — cached workspace tokens and identity, per profile.
//! - [`tokenfile`] — v0.1.0 token file read/write (0600) + attach state.
//! - [`inspect`] — offline token fact printing (no verification, no root
//!   key: `UnverifiedBiscuit` parse only).
//! - [`transport`] — the frozen §6 frames over WebSocket (ADR-0007
//!   fallback) or QUIC (ADR-0026, ALPN `reachpad/1`).
//! - [`tail`] — the tail session: handshake, capability consumption,
//!   events + durable watermarks, over either transport.
//! - [`attach`] — the interactive PTY session (ADR-0033): raw mode, resize,
//!   ctrl-c passthrough, clean detach. The felt test of the whole system.
//! - [`commands`] — command dispatch; all printing lives here.
//! - [`doctor`] — local installation, credential, and connectivity checks.
//! - [`self_update`] — package-manager-aware native updates.

pub mod api;
pub mod attach;
pub mod cli;
pub mod cli_auth;
pub mod commands;
pub mod conf;
pub mod doctor;
pub mod errors;
pub mod http_min;
pub mod inspect;
pub mod privatefile;
pub mod render;
pub mod self_update;
pub mod state;
pub mod tail;
pub mod tokenfile;
pub mod transport;

pub use commands::run;
