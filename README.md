# reachpad CLI

Run coding agents in durable cloud workspaces: the disk survives the machine
underneath, so a paused workspace costs nothing and picks up from its last
save. Files survive a pause; running processes do not.

## Install

With Homebrew on Apple silicon macOS or x86_64/arm64 Linux:

```sh
brew install reachpad/tap/reachpad
```

With npm, anywhere Node 18+ runs:

```sh
npm install -g @reachpad/cli
```

Or with the checksum-verifying installer:

```sh
curl -fsSL https://reachpad.dev/install | sh
```

Linux x86_64/arm64 (musl, static) and macOS arm64/x86_64. The script fetches
the latest release from this repository, verifies its checksum against
SHA256SUMS, and installs to `~/.local/bin/reachpad` (override with
`REACHPAD_INSTALL_DIR`).

All three deliver the same binary. `@reachpad/cli` is a launcher around it, not
a second implementation — see [`npm/README.md`](npm/README.md), which also
explains the macOS quarantine problem npm sidesteps.

## Get started

Run Reachpad:

```sh
reachpad
```

On first use, the CLI shows a short code, opens WorkOS hosted sign-in, and then
lists your workspaces. WorkOS handles the account login and any required MFA or
SSO. After approval, Reachpad exchanges the short-lived WorkOS token once and
saves a user-scoped Reachpad credential and the production endpoint with mode
0600. No password or authentication factor is entered into Reachpad.

On a remote machine without a usable browser, run `reachpad auth login
--no-browser` and open the displayed URL on another device. The manual
credential flow remains available from
[reachpad.dev/connect](https://reachpad.dev/connect) as a recovery path.

Then create a workspace, work in it, and put it away:

```sh
reachpad create scratch
reachpad list
reachpad attach <workspace-id>
reachpad run <workspace-id> -- cargo test
reachpad pause <workspace-id>
```

`create` prints the workspace id the other verbs take. The name is only a
label; there is no lookup by name.

Useful maintenance commands:

```sh
reachpad doctor
reachpad update
reachpad completions bash
reachpad completions zsh
reachpad completions fish
```

`reachpad update` respects how Reachpad was installed: Homebrew installs are
directed to `brew upgrade reachpad` and npm installs to `npm install -g
@reachpad/cli@latest`, while installer-managed binaries are updated in place
after the release checksum is verified. Whoever installed the binary owns it —
a second writer is how a working install becomes a broken one.

Docs: [reachpad.dev/docs/cli](https://reachpad.dev/docs/cli)

## Source and provenance

This repository carries the full CLI source: the `reach` package (shipped
binary name `reachpad`) and its two library crates (`proto`, the frozen wire
protocol, and `authz`, Biscuit verify and offline attenuation). Release
binaries are built from this source by
[the release workflow](.github/workflows/release.yml) on GitHub's runners, and
every release carries a SHA256SUMS the install script verifies. To build it
yourself (needs Rust and `protoc`):

```sh
cargo build --release -p reach
./target/release/reachpad --version
```

Every release tarball also carries a signed build-provenance attestation, so
the chain is checkable without trusting us:

```sh
gh attestation verify reachpad-<target>.tar.gz --repo Reachpad/reachpad-cli
```

That proves the bytes came out of this repository's release workflow at the
commit the tag names. It rests on no key of ours — the signing identity is a
short-lived credential minted for that one workflow run, and the record is in
a public transparency log.

The snapshot is synced from a private monorepo on every release, so file an
issue rather than a PR for changes; a PR here would be overwritten by the
next sync (the sync script and its header in `Cargo.toml` say the same).
The CLI is an ordinary client of a public API: it holds no platform secrets
and nothing it does is privileged (the server refuses anything a stranger
could not do).

Source-available; copyright Tako Research, all rights reserved.
