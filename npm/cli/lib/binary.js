// Where the real CLI is. `@reachpad/cli` ships no code of its own: it resolves
// the one platform package npm installed for this machine and hands over.
//
// The binary rides in optionalDependencies rather than a postinstall download,
// and that choice is the whole design:
//
//   - `npm ci --ignore-scripts` is the default posture of every hardened CI
//     runner and of most agent sandboxes. A postinstall downloader is simply
//     absent there; an optional dependency is already unpacked.
//   - The lockfile pins the binary's integrity hash, so the bytes are the same
//     on every machine and every replay of a build.
//   - It works offline from a warm cache.
//
// The cost is that npm resolves optional deps by `os`/`cpu` and says nothing
// when it skips them all, so an unsupported platform surfaces here — which is
// why the failure below is a paragraph and not a MODULE_NOT_FOUND stack.

"use strict";

// One row per release target. This table and the `release.yml` build matrix
// are the same list said twice; `npm/test/packages.test.mjs` fails when they
// stop agreeing, because the way this breaks in production is a new target
// that ships tarballs nobody can install.
const PACKAGES = {
  "darwin arm64": "@reachpad/cli-darwin-arm64",
  "darwin x64": "@reachpad/cli-darwin-x64",
  "linux x64": "@reachpad/cli-linux-x64",
  "linux arm64": "@reachpad/cli-linux-arm64",
};

/** The platform package for a given `process.platform`/`process.arch` pair. */
function packageFor(platform, arch) {
  return PACKAGES[`${platform} ${arch}`];
}

/** Every package this release publishes, for the CI cross-check. */
function allPackages() {
  return Object.values(PACKAGES);
}

/**
 * The path of the `reachpad` executable, or a thrown error whose message tells
 * the reader what to do next.
 *
 * `resolve` is injected so the tests can drive both failure shapes without
 * uninstalling anything.
 */
function resolveBinary(
  platform = process.platform,
  arch = process.arch,
  resolve = (specifier) => require.resolve(specifier)
) {
  const pkg = packageFor(platform, arch);
  if (!pkg) {
    throw new Error(unsupportedPlatform(platform, arch));
  }
  try {
    return resolve(`${pkg}/bin/reachpad`);
  } catch {
    throw new Error(missingPackage(pkg));
  }
}

function unsupportedPlatform(platform, arch) {
  return [
    `reachpad: no prebuilt binary for ${platform}/${arch}.`,
    "",
    "Supported: " + Object.keys(PACKAGES).join(", ") + ".",
    "Windows is not a target yet — run the CLI inside WSL, or tell us you need",
    "it at https://github.com/Reachpad/reachpad-cli/issues.",
  ].join("\n");
}

// The reachable causes, in the order they actually happen. `--omit=optional`
// is first because it is the one a person types on purpose and then forgets.
function missingPackage(pkg) {
  return [
    `reachpad: ${pkg} is not installed, so there is no binary to run.`,
    "",
    "This package carries the CLI itself as an optional dependency. It goes",
    "missing when the install skipped optional dependencies:",
    "",
    "  npm install -g @reachpad/cli          # not --omit=optional, not --no-optional",
    "",
    "If that does not fix it, install without npm at all:",
    "",
    "  curl -fsSL https://reachpad.dev/install | sh",
  ].join("\n");
}

module.exports = { PACKAGES, packageFor, allPackages, resolveBinary };
