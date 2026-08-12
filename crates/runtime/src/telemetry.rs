//! Tracing initialization shared by all binaries (§9.5).
//!
//! M0 scope: `tracing-subscriber` fmt output with an `EnvFilter` from
//! `RUST_LOG` (default `"info"`). OTLP export is M1 — the dependency is
//! deliberately not added here.

use tracing_subscriber::EnvFilter;

/// Initializes the global tracing subscriber for `bin_name`.
///
/// Filter comes from `RUST_LOG`; when unset (or invalid) it defaults to
/// `"info"`. Idempotent: a second call (e.g. in tests) is a no-op rather
/// than a panic.
///
/// **Diagnostics go to stderr.** `tracing_subscriber::fmt()` defaults to
/// stdout, and for `reach` that put a `reach ready` line into the same stream
/// the workspace's PTY bytes come out of. A harness measuring time to first
/// PTY byte then measured the CLI starting up — 208 ms against a node with no
/// guest at all, reported as "the workspace is usable". Everything a human
/// reads about the program goes to stderr; stdout is the workspace's own
/// bytes and nothing else. Every service here already logs to a journal, so
/// this changes nothing for them.
pub fn init_tracing(bin_name: &str) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let fresh = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init()
        .is_ok();
    if fresh {
        tracing::debug!(bin = bin_name, "tracing initialized");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_tracing_is_idempotent() {
        init_tracing("testd");
        init_tracing("testd"); // must not panic
    }
}
