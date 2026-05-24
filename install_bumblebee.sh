#!/bin/bash
# install_bumblebee.sh
# Builds bumblebee from source and installs it system-wide at /usr/local/bin/bumblebee
# so the RemoteOps service account (root) can run bumblebee_deep_scan.sh without
# any per-user setup.
#
# Run once per endpoint (as root or via sudo).
#
# Usage:
#   sudo ./install_bumblebee.sh                       # clone fresh and build
#   sudo BUMBLEBEE_SRC_DIR=/path/to/src ./install_bumblebee.sh   # build existing src
#   sudo BUMBLEBEE_REF=v0.1.2 ./install_bumblebee.sh  # pin to a specific git ref
set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/perplexityai/bumblebee.git}"
REF="${BUMBLEBEE_REF:-main}"
DEST="${DEST:-/usr/local/bin/bumblebee}"
SRC_DIR="${BUMBLEBEE_SRC_DIR:-}"

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: must run as root (use sudo)"; exit 1
fi

# Ensure go and git are available
need_go=0
command -v go  >/dev/null 2>&1 || need_go=1
command -v git >/dev/null 2>&1 || need_go=1
if [ "$need_go" -eq 1 ]; then
    if command -v dnf >/dev/null 2>&1; then
        dnf install -y golang git
    elif command -v yum >/dev/null 2>&1; then
        yum install -y golang git
    elif command -v apt-get >/dev/null 2>&1; then
        apt-get update && apt-get install -y golang git
    else
        echo "ERROR: install 'go' and 'git' manually and retry"; exit 2
    fi
fi

# Acquire source
cleanup=0
if [ -z "$SRC_DIR" ]; then
    SRC_DIR="$(mktemp -d -t bumblebee-src-XXXXXX)"
    cleanup=1
    echo "Cloning $REPO_URL @ $REF into $SRC_DIR"
    git clone --depth 1 --branch "$REF" "$REPO_URL" "$SRC_DIR" 2>/dev/null \
      || git clone "$REPO_URL" "$SRC_DIR"
    if [ "$REF" != "main" ]; then
        ( cd "$SRC_DIR" && git fetch --tags --depth 1 origin "$REF" && git checkout "$REF" ) || true
    fi
fi

[ -f "$SRC_DIR/go.mod" ] && [ -d "$SRC_DIR/cmd" ] \
    || { echo "ERROR: $SRC_DIR does not look like the bumblebee source"; exit 3; }

echo "Building bumblebee..."
( cd "$SRC_DIR" && GOFLAGS="-trimpath" go build -o "$SRC_DIR/bumblebee" ./cmd/bumblebee )

install -m 0755 "$SRC_DIR/bumblebee" "$DEST"
echo "Installed: $DEST"
"$DEST" version || true

[ "$cleanup" -eq 1 ] && rm -rf "$SRC_DIR"
echo "Done. The Agent can now run bumblebee_deep_scan.sh; it will find $DEST on PATH."
