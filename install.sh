#!/bin/sh
set -e

REPO="vandot/zlodev"
INSTALL_DIR="/usr/local/bin"

# Detect OS
OS="$(uname -s)"
case "$OS" in
    Linux)  os="linux" ;;
    Darwin) os="darwin" ;;
    *)      echo "Unsupported OS: $OS"; exit 1 ;;
esac

# Detect architecture
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|amd64)  arch="amd64" ;;
    aarch64|arm64) arch="arm64" ;;
    *)             echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

# fetch URL DEST
fetch() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$1" -o "$2"
    else
        wget -qO "$2" "$1"
    fi
}

# Get latest version
if command -v curl >/dev/null 2>&1; then
    LATEST=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/')
elif command -v wget >/dev/null 2>&1; then
    LATEST=$(wget -qO- "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/')
else
    echo "curl or wget is required"; exit 1
fi

if [ -z "$LATEST" ]; then
    echo "Failed to determine latest version"; exit 1
fi

ARTIFACT="zlodev-${os}-${arch}"
URL="https://github.com/${REPO}/releases/download/v${LATEST}/${ARTIFACT}.tar.gz"

echo "Downloading zlodev v${LATEST} for ${os}/${arch}..."

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

fetch "$URL" "${TMPDIR}/zlodev.tar.gz"

# Verify the download against the release's SHA256SUMS. Releases before
# checksums were published have no such file; those install unverified.
SUMS_URL="https://github.com/${REPO}/releases/download/v${LATEST}/SHA256SUMS"
if fetch "$SUMS_URL" "${TMPDIR}/SHA256SUMS" 2>/dev/null; then
    expected=$(awk -v f="${ARTIFACT}.tar.gz" '$2 == f || $2 == "*" f { print $1 }' "${TMPDIR}/SHA256SUMS")
    if [ -z "$expected" ]; then
        echo "Checksum for ${ARTIFACT}.tar.gz not found in SHA256SUMS"; exit 1
    fi
    if command -v sha256sum >/dev/null 2>&1; then
        actual=$(sha256sum "${TMPDIR}/zlodev.tar.gz" | awk '{ print $1 }')
    elif command -v shasum >/dev/null 2>&1; then
        actual=$(shasum -a 256 "${TMPDIR}/zlodev.tar.gz" | awk '{ print $1 }')
    else
        echo "sha256sum or shasum is required to verify the download"; exit 1
    fi
    if [ "$actual" != "$expected" ]; then
        echo "Checksum mismatch for ${ARTIFACT}.tar.gz"
        echo "  expected: $expected"
        echo "  actual:   $actual"
        exit 1
    fi
    echo "Checksum verified."
else
    echo "Warning: v${LATEST} has no SHA256SUMS; skipping checksum verification."
fi

tar -xzf "${TMPDIR}/zlodev.tar.gz" -C "$TMPDIR"

if [ -w "$INSTALL_DIR" ]; then
    mv "${TMPDIR}/zlodev" "${INSTALL_DIR}/zlodev"
else
    echo "Installing to ${INSTALL_DIR} (requires sudo)..."
    sudo mv "${TMPDIR}/zlodev" "${INSTALL_DIR}/zlodev"
fi

chmod +x "${INSTALL_DIR}/zlodev"

# On Linux, grant the binary permission to bind to privileged ports (53, 80,
# 443) without requiring root. This uses file capabilities instead of running as root.
if [ "$os" = "linux" ]; then
    echo "Setting network capabilities (allows binding to ports 53/80/443 without root)..."
    if command -v setcap >/dev/null 2>&1; then
        sudo setcap cap_net_bind_service=+eip "${INSTALL_DIR}/zlodev"
    else
        echo "Warning: setcap not found. You will need to run zlodev with sudo on Linux."
    fi
fi

echo "zlodev v${LATEST} installed to ${INSTALL_DIR}/zlodev"
