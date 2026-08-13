#!/bin/sh
# reachpad installer — fetches the latest release binary for this machine,
# verifies its checksum, and installs it to ~/.local/bin (or
# $REACHPAD_INSTALL_DIR). POSIX sh: this runs on machines we know nothing
# about, so no bashisms.
#
#   curl -fsSL https://raw.githubusercontent.com/Reachpad/reachpad-cli/main/install.sh | sh
#
# Nothing here needs root, and the script refuses to guess: an unsupported
# platform is an error naming the platform, never a wrong binary.
set -eu

REPO="Reachpad/reachpad-cli"
INSTALL_DIR="${REACHPAD_INSTALL_DIR:-$HOME/.local/bin}"

os=$(uname -s)
arch=$(uname -m)
case "$os/$arch" in
    Linux/x86_64)           target="x86_64-unknown-linux-musl" ;;
    Linux/aarch64)          target="aarch64-unknown-linux-musl" ;;
    Darwin/arm64)           target="aarch64-apple-darwin" ;;
    *)
        echo "reachpad: no prebuilt binary for $os/$arch." >&2
        echo "Open an issue at https://github.com/Reachpad/reachpad-cli and we will add the target." >&2
        exit 1
        ;;
esac

asset="reachpad-$target.tar.gz"
base="https://github.com/$REPO/releases/latest/download"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "fetching $asset (latest release)..."
curl -fsSL -o "$tmp/$asset" "$base/$asset"
curl -fsSL -o "$tmp/SHA256SUMS" "$base/SHA256SUMS"

# Verify before anything is executed or installed. The SHA256SUMS file covers
# every asset; check only ours.
(
    cd "$tmp"
    grep " $asset\$" SHA256SUMS > checksum.expected
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum -c checksum.expected
    else
        shasum -a 256 -c checksum.expected
    fi
) >/dev/null

tar xzf "$tmp/$asset" -C "$tmp"
mkdir -p "$INSTALL_DIR"
install -m 0755 "$tmp/reachpad" "$INSTALL_DIR/reachpad"

echo "installed: $INSTALL_DIR/reachpad ($("$INSTALL_DIR/reachpad" --version 2>/dev/null || echo 'version unknown'))"
case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *)
        echo "NOTE: $INSTALL_DIR is not on your PATH. Add it, e.g.:"
        echo "  export PATH=\"$INSTALL_DIR:\$PATH\""
        ;;
esac
echo "next: sign in through WorkOS:"
echo "  reachpad auth login"
echo "on a remote machine, use 'reachpad auth login --no-browser' and open the displayed URL elsewhere"
