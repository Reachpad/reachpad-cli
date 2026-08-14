# The npm distribution

Five packages, published by `.github/workflows/release.yml` on every `cli-v*`
tag, carrying the same binaries as the GitHub release:

| Directory | Package | Contents |
| --- | --- | --- |
| `cli/` | `@reachpad/cli` | the `reachpad` launcher, and the only one anybody installs |
| `darwin-arm64/` | `@reachpad/cli-darwin-arm64` | `bin/reachpad` for `aarch64-apple-darwin` |
| `darwin-x64/` | `@reachpad/cli-darwin-x64` | `bin/reachpad` for `x86_64-apple-darwin` |
| `linux-x64/` | `@reachpad/cli-linux-x64` | `bin/reachpad` for `x86_64-unknown-linux-musl` |
| `linux-arm64/` | `@reachpad/cli-linux-arm64` | `bin/reachpad` for `aarch64-unknown-linux-musl` |

## Why this exists

**Gatekeeper.** Release binaries are ad-hoc signed by the linker, not
Developer ID signed and notarized. Ad-hoc is enough to *execute* on Apple
silicon, so the curl installer and the Homebrew formula both work. It is not
enough for anything that stamps `com.apple.quarantine` — a browser download
from the releases page hits "Apple could not verify reachpad is free of
malware", and so did the Homebrew *cask* we shipped until 2026-08-13, because
casks quarantine everything they stage. npm never sets that attribute.

The durable fix is notarization, and `release.yml` has the step waiting behind
six repository secrets. This directory is the fix that needed no Apple account.

**Node is already installed** on machines that run coding agents, and
`npx @reachpad/cli` needs no install at all.

## Parity

There is nothing to keep in parity. `@reachpad/cli` contains no
reimplementation of any verb: `bin/reachpad.js` resolves the platform package
and execs the same Rust binary every other install path delivers. Verbs, flags,
exit codes and output are identical because they are the same program.

The launcher is only allowed to get three things wrong, and each has a test in
`test/packages.test.mjs` that runs a real child process:

- **exit codes** — `reachpad run` exits with the *guest's* status, so a wrapper
  that returns its own breaks every `&&` in every script.
- **signals** — a guest killed by `SIGTERM` must make the launcher die of
  `SIGTERM`, not `exit 1`.
- **the terminal** — stdio is inherited, never piped, or `reachpad attach`
  gets a non-tty and raw mode has nothing to put in raw mode.

## Versions

Every `package.json` here carries `0.0.0-dev`. The real version comes from the
tag: `npm/prepare.mjs --version <x.y.z>` stamps all five manifests and the
exact pins in `optionalDependencies`, then unpacks each release tarball into
its platform package after checking the release's own SHA256 and reading the
object header back to confirm it is the architecture it claims.

A version committed here instead would drift the first time somebody bumped
the Rust workspace and not this directory — and the drift is invisible until a
user installs a CLI whose `--version` disagrees with the package they asked
for.

```sh
node --test npm/test/*.test.mjs        # the whole suite, no network, no build
```

## First publish (one-time, manual)

npm Trusted Publishing (OIDC) is how these packages are published — there is no
npm token in this repository, exactly as in `Reachpad/reachpad-mcp`. But a
trusted publisher can only be configured on a package that already exists, so
the very first version of each of the five has to be pushed by hand:

```sh
git checkout cli-v<version>
gh release download cli-v<version> --dir /tmp/rp-assets
node npm/prepare.mjs --version <version> --artifacts /tmp/rp-assets
for d in darwin-arm64 darwin-x64 linux-x64 linux-arm64 cli; do npm publish "npm/$d"; done
```

Then, at npmjs.com, for **each** of the five packages:

> Settings → Trusted Publisher → GitHub Actions
> org `Reachpad` · repo `reachpad-cli` · workflow `release.yml` · environment blank

After that every `cli-v*` tag publishes on its own, and the publish step is
idempotent: a version already on npm is skipped, so a tag whose fourth publish
failed can simply be re-run.
