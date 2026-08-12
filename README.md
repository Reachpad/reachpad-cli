# reachpad CLI

Run coding agents in durable cloud workspaces: disk and memory survive the
machine underneath, so a paused workspace resumes mid-session.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/Tako-Research/reachpad-cli/main/install.sh | sh
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

This repository carries the installer and release binaries only; the source
lives in a private repository and releases are published here.
