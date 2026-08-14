#!/usr/bin/env node
// The `reachpad` command, when reachpad was installed from npm.
//
// This is a launcher and nothing else. Every verb, flag and exit code belongs
// to the Rust binary in the platform package — there is no second
// implementation to drift, which is the entire reason this package exists in
// this shape.
//
// Three properties the CLI depends on, and how each is kept:
//
//   exit codes   `reachpad run` exits with the GUEST's exit code, so a wrapper
//                that returns its own status silently breaks every `&&` in
//                every script. The child's status is propagated verbatim, and
//                a child killed by a signal re-raises that signal here so the
//                calling shell sees `Terminated`, not `exit 1`.
//   the terminal `reachpad attach` puts the tty in raw mode. stdio is
//                inherited, never piped: a pipe would hand the guest a
//                non-tty and turn an interactive session into a dead prompt.
//   signals      Ctrl-C must reach the guest, not kill the launcher out from
//                under it. The no-op handlers below stop Node's default
//                terminate-on-SIGINT; the child shares this process group, so
//                the terminal delivers the signal to it directly and we still
//                get to report how it died.

"use strict";

const { spawnSync } = require("child_process");
const { resolveBinary } = require("../lib/binary.js");

let binary;
try {
  binary = resolveBinary();
} catch (error) {
  process.stderr.write(error.message + "\n");
  process.exit(1);
}

for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) {
  process.on(signal, () => {});
}

const result = spawnSync(binary, process.argv.slice(2), { stdio: "inherit" });

if (result.error) {
  process.stderr.write(`reachpad: cannot run ${binary}: ${result.error.message}\n`);
  process.exit(1);
}

if (result.signal) {
  // Die the way the child died. Restoring the default disposition first is
  // what makes this a death rather than a no-op against our own handler.
  process.removeAllListeners(result.signal);
  process.kill(process.pid, result.signal);
}

process.exit(result.status === null ? 1 : result.status);
