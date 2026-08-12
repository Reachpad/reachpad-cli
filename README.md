# reachpad CLI

Run coding agents in durable cloud workspaces: disk and memory survive the
machine underneath, so a paused workspace resumes mid-session.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/Reachpad/reachpad-cli/main/install.sh | sh
```

Linux x86_64/arm64 (musl, static) and macOS arm64. The script fetches the
latest release from this repository, verifies its checksum against
SHA256SUMS, and installs to `~/.local/bin/reachpad` (override with
`REACHPAD_INSTALL_DIR`).

## Connect

Get your credential at [reachpad.dev/connect](https://reachpad.dev/connect),
then:

```sh
reachpad --endpoint m1.reachpad.dev auth login --operator-token -
reachpad --endpoint m1.reachpad.dev ws create --name scratch
reachpad --endpoint m1.reachpad.dev attach <workspace-id>
```

Docs: [reachpad.dev/docs/cli](https://reachpad.dev/docs/cli)

## Source and provenance

This repository carries the full CLI source: the `reach` package (shipped
binary name `reachpad`) and its three library crates (`proto`, the frozen
wire protocol; `authz`, Biscuit verify and offline attenuation; `runtime`,
the config and tracing shell). Release binaries are built from this source
by [the release workflow](.github/workflows/release.yml) on GitHub's
runners, and every release carries a SHA256SUMS the install script verifies.
To build it yourself (needs Rust and `protoc`):

```sh
cargo build --release -p reach
./target/release/reachpad --version
```

The snapshot is synced from a private monorepo on every release, so file an
issue rather than a PR for changes; a PR here would be overwritten by the
next sync (the sync script and its header in `Cargo.toml` say the same).
The CLI is an ordinary client of a public API: it holds no platform secrets
and nothing it does is privileged (the server refuses anything a stranger
could not do).

Source-available; copyright Tako Research, all rights reserved.
