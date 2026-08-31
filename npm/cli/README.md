# @reachpad/cli

Durable cloud workspaces for coding agents. Create one, run commands in it,
pause it, fork it from its last save.

```sh
npm install -g @reachpad/cli
reachpad
```

The guided first run signs you in through WorkOS and lists your workspaces.

## Why npm

This package contains no JavaScript implementation of anything. It is a
launcher for the same Rust binary that `brew install reachpad/tap/reachpad`
and `curl -fsSL https://reachpad.dev/install | sh` put on your PATH — same
verbs, same flags, same exit codes, because it is the same executable.

npm is here for two reasons:

- **No Gatekeeper dialog on macOS.** Our release binaries are ad-hoc signed,
  not notarized, so macOS blocks them whenever a download stamps them with
  `com.apple.quarantine` — which a browser download from the releases page
  does. npm never sets that attribute, so an `npm install` binary just runs.
- **Node is already there.** On a machine that runs coding agents, it is one
  command with no new toolchain.

The binary arrives as a platform-specific optional dependency
(`@reachpad/cli-darwin-arm64` and friends), so it survives `--ignore-scripts`,
it is pinned by integrity hash in your lockfile, and it installs offline from a
warm cache.

## Use it without installing

```sh
ws=$(npx @reachpad/cli create scratch)
npx @reachpad/cli run "$ws" -- cargo test
```

`create` prints the workspace id `run` takes. There is no lookup by name.

## The surface

```
reachpad create [name]        make a workspace, print its id
reachpad list                 your workspaces and what each is doing
reachpad status <ws>          state, save, lease, limits (--wait to block)
reachpad run <ws> -- <argv>   run one command, waking a paused workspace
reachpad attach <ws>          an interactive terminal in the workspace
reachpad pause <ws>           save the disk, stop the meter
reachpad fork <ws>            branch new workspaces from the last save
reachpad archive <ws>         free the slot; deletes nothing
reachpad events <ws>          live event stream

reachpad auth login|whoami|logout
reachpad keys mint|list|revoke        rpak1 keys for agents and CI
reachpad doctor                       check this installation
reachpad update                       update the way you installed
reachpad completions bash|zsh|fish
```

`--json` on any command prints one JSON object instead of prose, and
`REACHPAD_JSON=1` sets it for a whole session. `reachpad run` without `--json`
is byte-exact: guest stdout to stdout, guest stderr to stderr, and this process
exits with the guest's own exit code.

## Updating

```sh
npm install -g @reachpad/cli@latest
```

`reachpad update` knows it was installed by npm and prints that command rather
than writing into `node_modules` behind npm's back.

## Platforms

| Platform | Arch | Package |
| --- | --- | --- |
| macOS | Apple silicon | `@reachpad/cli-darwin-arm64` |
| macOS | Intel | `@reachpad/cli-darwin-x64` |
| Linux | x86-64 | `@reachpad/cli-linux-x64` |
| Linux | arm64 | `@reachpad/cli-linux-arm64` |

Linux builds are static musl binaries, so they run on glibc and musl distros
alike. Windows is not a target yet; use WSL, or open an issue.

## Source

The full CLI source is public at
[Reachpad/reachpad-cli](https://github.com/Reachpad/reachpad-cli), and the
binaries in these packages are built from that source by its release workflow
on GitHub's runners — tag to readable source to workflow run to `SHA256SUMS`.

Docs: <https://reachpad.dev/docs/cli>
