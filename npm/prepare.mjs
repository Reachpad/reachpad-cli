// Turn the release tarballs into publishable npm packages.
//
//   node npm/prepare.mjs --version 0.3.0 --artifacts /path/to/release/assets
//
// Two jobs, both of which exist because the alternative is a silent wrong
// answer:
//
//   version   The repo carries `0.0.0-dev` in every package.json. The real
//             version comes from the git tag, stamped here into all five
//             manifests AND into the exact pins in optionalDependencies. A
//             version committed to the repo instead would drift the day
//             someone bumps the Rust workspace and not this directory, and
//             the drift is invisible until a user installs a CLI whose
//             `--version` disagrees with the package they asked for.
//
//   staging   Each platform package gets `bin/reachpad` unpacked from the
//             matching release tarball, after its SHA256 is checked against
//             the release's own SHA256SUMS. The unpacked file is then read
//             back and its object header compared to the platform it claims:
//             a matrix mix-up that ships the arm64 binary to Intel Macs is
//             the failure this catches, and it is one that no test outside
//             that machine would ever hit.

import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, readdirSync, writeFileSync, chmodSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));

/** The five packages, and what each platform one must contain. */
export const PLATFORMS = [
  { dir: "darwin-arm64", target: "aarch64-apple-darwin", format: "macho", machine: "arm64" },
  { dir: "darwin-x64", target: "x86_64-apple-darwin", format: "macho", machine: "x86_64" },
  { dir: "linux-x64", target: "x86_64-unknown-linux-musl", format: "elf", machine: "x86_64" },
  { dir: "linux-arm64", target: "aarch64-unknown-linux-musl", format: "elf", machine: "arm64" },
];

export const PACKAGE_DIRS = ["cli", ...PLATFORMS.map((p) => p.dir)];

/**
 * Read an executable's header and say which (format, machine) it is really
 * for. Returns null for anything that is not an object file at all — which is
 * what a downloaded HTML error page looks like.
 */
export function identify(bytes) {
  if (bytes.length < 20) return null;
  // ELF: 0x7f 'E' 'L' 'F', then e_machine at offset 18 (little-endian here;
  // every target we ship is LE).
  if (bytes[0] === 0x7f && bytes[1] === 0x45 && bytes[2] === 0x4c && bytes[3] === 0x46) {
    const machine = bytes.readUInt16LE(18);
    if (machine === 0x3e) return { format: "elf", machine: "x86_64" };
    if (machine === 0xb7) return { format: "elf", machine: "arm64" };
    return { format: "elf", machine: `unknown(${machine})` };
  }
  // Mach-O 64-bit little-endian (MH_MAGIC_64), cputype in the next word.
  if (bytes.readUInt32LE(0) === 0xfeedfacf) {
    const cputype = bytes.readUInt32LE(4);
    if (cputype === 0x01000007) return { format: "macho", machine: "x86_64" };
    if (cputype === 0x0100000c) return { format: "macho", machine: "arm64" };
    return { format: "macho", machine: `unknown(${cputype})` };
  }
  return null;
}

/** `<sha>  <name>` lines, as `shasum -a 256` writes them. */
export function parseChecksums(text) {
  const sums = new Map();
  for (const line of text.split("\n")) {
    const match = line.match(/^([0-9a-f]{64})\s+\*?(\S+)$/);
    if (match) sums.set(match[2], match[1]);
  }
  return sums;
}

/** Stamp `version` through one package.json's own version and its exact pins. */
export function stampManifest(manifest, version) {
  const stamped = { ...manifest, version };
  if (stamped.optionalDependencies) {
    stamped.optionalDependencies = Object.fromEntries(
      Object.entries(stamped.optionalDependencies).map(([name, pin]) =>
        name.startsWith("@reachpad/cli-") ? [name, version] : [name, pin]
      )
    );
  }
  return stamped;
}

function stampVersions(version) {
  for (const dir of PACKAGE_DIRS) {
    const path = join(HERE, dir, "package.json");
    const manifest = JSON.parse(readFileSync(path, "utf8"));
    writeFileSync(path, JSON.stringify(stampManifest(manifest, version), null, 2) + "\n");
  }
  console.log(`version ${version} stamped into ${PACKAGE_DIRS.length} manifests`);
}

function stageBinaries(artifacts) {
  const names = readdirSync(artifacts);
  const sums = new Map();
  for (const name of names) {
    if (name === "SHA256SUMS" || name.endsWith(".sha256")) {
      for (const [file, sum] of parseChecksums(readFileSync(join(artifacts, name), "utf8"))) {
        sums.set(file, sum);
      }
    }
  }

  for (const platform of PLATFORMS) {
    const asset = `reachpad-${platform.target}.tar.gz`;
    const tarball = join(artifacts, asset);
    const expected = sums.get(asset);
    if (!expected) {
      throw new Error(
        `${asset} has no SHA256SUMS entry. Publishing an unverified binary is ` +
          `worse than not publishing: the release's own checksum file is the ` +
          `only thing tying these bytes to that workflow run.`
      );
    }
    const bytes = readFileSync(tarball);
    const actual = createHash("sha256").update(bytes).digest("hex");
    if (actual !== expected) {
      throw new Error(`${asset} checksum mismatch\n  expected ${expected}\n  got      ${actual}`);
    }

    const bin = join(HERE, platform.dir, "bin");
    mkdirSync(bin, { recursive: true });
    execFileSync("tar", ["xzf", tarball, "-C", bin, "reachpad"]);
    chmodSync(join(bin, "reachpad"), 0o755);

    const header = readFileSync(join(bin, "reachpad")).subarray(0, 64);
    const found = identify(header);
    if (!found || found.format !== platform.format || found.machine !== platform.machine) {
      throw new Error(
        `${platform.dir} was staged with the wrong binary: expected ` +
          `${platform.format}/${platform.machine}, found ` +
          `${found ? `${found.format}/${found.machine}` : "not an object file"}`
      );
    }
    console.log(`staged ${platform.dir}: ${asset} (${found.format}/${found.machine})`);
  }
}

function main(argv) {
  const args = new Map();
  for (let i = 0; i < argv.length; i += 2) args.set(argv[i], argv[i + 1]);
  const version = args.get("--version");
  const artifacts = args.get("--artifacts");
  if (!version || !artifacts) {
    console.error("usage: node npm/prepare.mjs --version <x.y.z> --artifacts <dir>");
    process.exit(2);
  }
  if (!/^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(version)) {
    console.error(`refusing to publish "${version}": not a semver release version`);
    process.exit(2);
  }
  stampVersions(version);
  stageBinaries(artifacts);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2));
}
