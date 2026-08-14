// What this suite is defending: the npm packages are a DISTRIBUTION of the
// Rust binary, so almost nothing here is about behaviour. It is about the four
// lists that describe the same set of platforms staying the same list — the
// release matrix, the staging table, the launcher's lookup, and the optional
// dependencies — plus the two things a launcher can get wrong that no unit
// test of the CLI would ever notice: exit codes and signals.

import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { PLATFORMS, PACKAGE_DIRS, identify, parseChecksums, stampManifest } from "../prepare.mjs";

const NPM_DIR = dirname(dirname(fileURLToPath(import.meta.url)));
const REPO = dirname(NPM_DIR);
const require = createRequire(import.meta.url);
const { PACKAGES, packageFor, resolveBinary } = require("../cli/lib/binary.js");

const manifest = (dir) => JSON.parse(readFileSync(join(NPM_DIR, dir, "package.json"), "utf8"));

test("every list of platforms is the same list", () => {
  const staged = PLATFORMS.map((p) => `@reachpad/cli-${p.dir}`).sort();

  // The launcher's lookup table.
  assert.deepEqual(Object.values(PACKAGES).sort(), staged);

  // What `npm install -g @reachpad/cli` will actually fetch. A package staged
  // and published but never depended on is a binary nobody can install.
  assert.deepEqual(Object.keys(manifest("cli").optionalDependencies).sort(), staged);

  // The release matrix. Parsed rather than restated: this is the list that
  // decides which tarballs exist at all, so it is the one with the last word.
  const workflow = readFileSync(join(REPO, ".github/workflows/release.yml"), "utf8");
  const built = [...workflow.matchAll(/^\s*- target:\s*(\S+)/gm)].map((m) => m[1]).sort();
  assert.deepEqual(
    PLATFORMS.map((p) => p.target).sort(),
    built,
    "release.yml builds a different set of targets than npm/prepare.mjs stages"
  );
});

test("each platform package declares the os/cpu npm selects it by", () => {
  for (const platform of PLATFORMS) {
    const pkg = manifest(platform.dir);
    const [os, cpu] = platform.dir.split("-");
    assert.deepEqual(pkg.os, [os], `${platform.dir} os`);
    assert.deepEqual(pkg.cpu, [cpu], `${platform.dir} cpu`);
    assert.equal(pkg.reachpadTarget, platform.target, `${platform.dir} target triple`);
    // Yarn Berry zips packages into its cache, and an executable inside a zip
    // cannot be exec'd.
    assert.equal(pkg.preferUnplugged, true, `${platform.dir} preferUnplugged`);
    // A published binary that says which repo built it is the provenance
    // claim npm attaches; a missing one fails the publish AFTER the
    // attestation is logged, which is a bad place to find out.
    assert.match(pkg.repository.url, /Reachpad\/reachpad-cli/);
  }
});

test("the launcher maps this machine, and refuses the ones we do not ship", () => {
  assert.equal(packageFor("darwin", "arm64"), "@reachpad/cli-darwin-arm64");
  assert.equal(packageFor("linux", "x64"), "@reachpad/cli-linux-x64");
  assert.equal(packageFor("win32", "x64"), undefined);

  assert.throws(() => resolveBinary("win32", "x64"), /no prebuilt binary for win32\/x64[\s\S]*WSL/);
  assert.throws(() => resolveBinary("sunos", "sparc"), /no prebuilt binary for sunos\/sparc/);
});

test("a skipped optional dependency explains itself instead of stack-tracing", () => {
  const boom = () => {
    throw Object.assign(new Error("Cannot find module"), { code: "MODULE_NOT_FOUND" });
  };
  assert.throws(() => resolveBinary("linux", "x64", boom), (error) => {
    assert.match(error.message, /@reachpad\/cli-linux-x64 is not installed/);
    assert.match(error.message, /--omit=optional/);
    assert.match(error.message, /reachpad\.dev\/install/);
    return true;
  });
});

test("object headers are identified, and a downloaded error page is not one", () => {
  const elf = (machine) => {
    const b = Buffer.alloc(64);
    b.write("\x7fELF", 0, "latin1");
    b.writeUInt16LE(machine, 18);
    return b;
  };
  const macho = (cputype) => {
    const b = Buffer.alloc(64);
    b.writeUInt32LE(0xfeedfacf, 0);
    b.writeUInt32LE(cputype, 4);
    return b;
  };
  assert.deepEqual(identify(elf(0x3e)), { format: "elf", machine: "x86_64" });
  assert.deepEqual(identify(elf(0xb7)), { format: "elf", machine: "arm64" });
  assert.deepEqual(identify(macho(0x01000007)), { format: "macho", machine: "x86_64" });
  assert.deepEqual(identify(macho(0x0100000c)), { format: "macho", machine: "arm64" });
  assert.equal(identify(Buffer.from("<html>404: Not Found</html>")), null);
  assert.equal(identify(Buffer.alloc(4)), null);
});

test("checksums are read the way shasum writes them", () => {
  const sums = parseChecksums(
    "abc  not-a-sha\n" +
      "1".repeat(64) + "  reachpad-x86_64-unknown-linux-musl.tar.gz\n" +
      "2".repeat(64) + " *reachpad-aarch64-apple-darwin.tar.gz\n"
  );
  assert.equal(sums.get("reachpad-x86_64-unknown-linux-musl.tar.gz"), "1".repeat(64));
  assert.equal(sums.get("reachpad-aarch64-apple-darwin.tar.gz"), "2".repeat(64));
  assert.equal(sums.get("not-a-sha"), undefined);
});

test("stamping a version reaches the pins, not just the package's own version", () => {
  const stamped = stampManifest(manifest("cli"), "1.2.3");
  assert.equal(stamped.version, "1.2.3");
  for (const [name, pin] of Object.entries(stamped.optionalDependencies)) {
    assert.equal(pin, "1.2.3", `${name} pin`);
  }
});

test("the repo carries no real version: the tag is the only source", () => {
  for (const dir of PACKAGE_DIRS) {
    assert.equal(manifest(dir).version, "0.0.0-dev", `${dir} version`);
  }
});

// --- prepare.mjs, end to end on a throwaway copy -----------------------------

function fakeRelease(dir, { corrupt = null, wrongArch = false } = {}) {
  mkdirSync(dir, { recursive: true });
  const sums = [];
  for (const platform of PLATFORMS) {
    const header = Buffer.alloc(256);
    const machine = wrongArch && platform.dir === "darwin-x64" ? "arm64" : platform.machine;
    if (platform.format === "elf") {
      header.write("\x7fELF", 0, "latin1");
      header.writeUInt16LE(machine === "x86_64" ? 0x3e : 0xb7, 18);
    } else {
      header.writeUInt32LE(0xfeedfacf, 0);
      header.writeUInt32LE(machine === "x86_64" ? 0x01000007 : 0x0100000c, 4);
    }
    const stage = mkdtempSync(join(tmpdir(), "rp-stage-"));
    writeFileSync(join(stage, "reachpad"), header);
    const asset = `reachpad-${platform.target}.tar.gz`;
    execFileSync("tar", ["czf", join(dir, asset), "-C", stage, "reachpad"]);
    const sum = execFileSync("sha256sum", [join(dir, asset)]).toString().slice(0, 64);
    sums.push(`${corrupt === platform.dir ? "0".repeat(64) : sum}  ${asset}`);
  }
  writeFileSync(join(dir, "SHA256SUMS"), sums.join("\n") + "\n");
}

function runPrepare(options = {}) {
  const work = mkdtempSync(join(tmpdir(), "rp-npm-"));
  cpSync(NPM_DIR, join(work, "npm"), { recursive: true });
  cpSync(join(REPO, ".github"), join(work, ".github"), { recursive: true });
  const artifacts = join(work, "artifacts");
  fakeRelease(artifacts, options);
  const result = spawnSync(
    process.execPath,
    [join(work, "npm/prepare.mjs"), "--version", "9.9.9", "--artifacts", artifacts],
    { encoding: "utf8" }
  );
  return { work, result };
}

test("prepare stamps the tag's version and stages every platform", () => {
  const { work, result } = runPrepare();
  assert.equal(result.status, 0, result.stderr);

  for (const dir of PACKAGE_DIRS) {
    const pkg = JSON.parse(readFileSync(join(work, "npm", dir, "package.json"), "utf8"));
    assert.equal(pkg.version, "9.9.9", `${dir} version`);
  }
  const cli = JSON.parse(readFileSync(join(work, "npm/cli/package.json"), "utf8"));
  for (const pin of Object.values(cli.optionalDependencies)) assert.equal(pin, "9.9.9");

  for (const platform of PLATFORMS) {
    const binary = join(work, "npm", platform.dir, "bin", "reachpad");
    const found = identify(readFileSync(binary));
    assert.deepEqual(found, { format: platform.format, machine: platform.machine });
  }
});

test("prepare refuses a tarball whose checksum does not match the release", () => {
  const { result } = runPrepare({ corrupt: "linux-x64" });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /checksum mismatch/);
});

test("prepare refuses a binary built for the wrong architecture", () => {
  const { result } = runPrepare({ wrongArch: true });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /darwin-x64 was staged with the wrong binary/);
});

test("prepare refuses a tag name where a version belongs", () => {
  // `cli-v0.3.0` is the tag; `0.3.0` is the version. Publishing the former
  // would put a package on npm that no `@latest` range can ever resolve.
  const run = spawnSync(
    process.execPath,
    [join(NPM_DIR, "prepare.mjs"), "--version", "cli-v0.3.0", "--artifacts", "/nonexistent"],
    { encoding: "utf8" }
  );
  assert.equal(run.status, 2);
  assert.match(run.stderr, /not a semver release version/);
});

// --- the launcher, against a real child process ------------------------------

function launcherFixture(script) {
  const work = mkdtempSync(join(tmpdir(), "rp-run-"));
  const cli = join(work, "node_modules/@reachpad/cli");
  cpSync(join(NPM_DIR, "cli"), cli, { recursive: true });
  const platform = packageFor(process.platform, process.arch);
  assert.ok(platform, `this test host (${process.platform}/${process.arch}) is not a target`);
  const bin = join(work, "node_modules", platform, "bin");
  mkdirSync(bin, { recursive: true });
  writeFileSync(join(bin, "reachpad"), script);
  chmodSync(join(bin, "reachpad"), 0o755);
  return join(cli, "bin/reachpad.js");
}

test("the guest's exit code is the launcher's exit code", () => {
  const launcher = launcherFixture("#!/bin/sh\nexit 42\n");
  const run = spawnSync(process.execPath, [launcher], { encoding: "utf8" });
  assert.equal(run.status, 42, "`reachpad run` returns the guest's status; a wrapper must not eat it");
});

test("argv and both output streams pass through unmangled", () => {
  const launcher = launcherFixture(
    "#!/bin/sh\nprintf 'out:%s' \"$*\"\nprintf 'err:%s' \"$1\" >&2\n"
  );
  const run = spawnSync(process.execPath, [launcher, "run", "ws-1", "--", "ls", "-la"], {
    encoding: "utf8",
  });
  assert.equal(run.stdout, "out:run ws-1 -- ls -la");
  assert.equal(run.stderr, "err:run");
  assert.equal(run.status, 0);
});

test("a guest killed by a signal kills the launcher the same way", () => {
  const launcher = launcherFixture("#!/bin/sh\nkill -TERM $$\n");
  const run = spawnSync(process.execPath, [launcher], { encoding: "utf8" });
  assert.equal(run.signal, "SIGTERM", "the shell must see Terminated, not exit 1");
});

test("no platform package at all is a paragraph on stderr, not a stack", () => {
  const work = mkdtempSync(join(tmpdir(), "rp-bare-"));
  const cli = join(work, "node_modules/@reachpad/cli");
  cpSync(join(NPM_DIR, "cli"), cli, { recursive: true });
  const run = spawnSync(process.execPath, [join(cli, "bin/reachpad.js")], { encoding: "utf8" });
  assert.equal(run.status, 1);
  assert.doesNotMatch(run.stderr, /at Object|MODULE_NOT_FOUND/);
  assert.match(run.stderr, /is not installed/);
});
