//! Printing that survives the reader hanging up — the ONE place this CLI
//! writes to fd 1 and fd 2.
//!
//! `reachpad events ws-430 --json | head -6` is how an agent reads an event
//! stream, and it is the shape that killed the CLI: `head` closes the pipe
//! after its sixth line, the next `println!` gets `EPIPE`, and std's
//! `println!` **panics** — `failed printing to stdout: Broken pipe`, a
//! backtrace note, exit 101. A tool that panics when someone pipes it into
//! `head` is a tool an agent cannot compose (issue #56).
//!
//! Standard Unix tools do not do that, because they die on `SIGPIPE`. Rust
//! disarms `SIGPIPE` before `main` and turns the write error into a panic
//! instead, and the usual fix — restoring the default disposition with
//! `libc::signal` — needs `unsafe`, which §12 rejects outside blockd and the
//! UFFD handler (the workspace denies `unsafe_code` outright). So this crate
//! takes the other half of the same idea: **a closed reader is not an error,
//! it is the end of the output.** The write returns `BrokenPipe`, we stop,
//! and the process exits 0 — the documented exit-code table
//! (docs/API.md §13.4) is left exactly as it was, including `run`'s
//! pass-through of the guest's own code.
//!
//! Every caller reaches this through the `println!` / `eprintln!` macros
//! **shadowed in `lib.rs`**, so the human renderers, the `--json` envelopes,
//! the NDJSON streams from `run` and `events`, and any line a future verb
//! prints all land here without anyone remembering to. The two paths that do
//! not go through a macro — `run`'s verbatim guest bytes and the completions
//! dump — call [`out_bytes`] / [`err_bytes`] directly.
//!
//! `attach` keeps writing the guest's bytes itself, and should: it already
//! turns a failed write into an ordinary error rather than a panic, and that
//! path unwinds through the `Drop` that puts the terminal back out of raw
//! mode — which exiting from here would skip.

use std::fmt;
use std::io::{self, Write as _};

use crate::errors::EXIT_OK;

/// One line to stdout, `println!`-style.
pub fn out_line(args: fmt::Arguments<'_>) {
    let mut w = io::stdout().lock();
    finish("stdout", writeln!(w, "{args}").and_then(|()| w.flush()));
}

/// One line to stderr, `eprintln!`-style.
pub fn err_line(args: fmt::Arguments<'_>) {
    let mut w = io::stderr().lock();
    finish("stderr", writeln!(w, "{args}").and_then(|()| w.flush()));
}

/// Bytes to stdout, verbatim and flushed: the guest's own output under
/// `run`, and the completion script.
pub fn out_bytes(bytes: &[u8]) {
    let mut w = io::stdout().lock();
    finish("stdout", w.write_all(bytes).and_then(|()| w.flush()));
}

/// Bytes to stderr, verbatim and flushed: the guest's fd 2 under `run`,
/// unmerged from fd 1 all the way to the terminal.
pub fn err_bytes(bytes: &[u8]) {
    let mut w = io::stderr().lock();
    finish("stderr", w.write_all(bytes).and_then(|()| w.flush()));
}

/// A write that ended: nothing to say, the reader left, or a real failure.
///
/// The reader leaving ends the process at [`EXIT_OK`] — there is nobody to
/// tell, and telling them is what the panic was trying to do. Anything else
/// still panics, with the message std would have used, because a full disk
/// under `> file` is a genuine failure and losing it silently is worse.
fn finish(which: &str, result: io::Result<()>) {
    match result {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => std::process::exit(EXIT_OK),
        Err(e) => panic!("failed printing to {which}: {e}"),
    }
}
