#!/bin/sh
set -eu

# Socket Patch installer
# Usage: curl -fsSL https://raw.githubusercontent.com/SocketDev/socket-patch/main/scripts/install.sh | sh

REPO="SocketDev/socket-patch"
BINARY="socket-patch"

# Detect platform
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Darwin)
    case "$ARCH" in
      arm64)  TARGET="aarch64-apple-darwin" ;;
      x86_64) TARGET="x86_64-apple-darwin" ;;
      *)      echo "Error: unsupported architecture: $ARCH" >&2; exit 1 ;;
    esac
    ;;
  Linux)
    # Detect libc: musl or glibc
    detect_libc() {
      if ldd --version 2>&1 | grep -qi musl; then
        echo "musl"
      elif [ -e /lib/ld-musl-*.so.1 ] 2>/dev/null; then
        echo "musl"
      else
        echo "gnu"
      fi
    }
    LIBC="$(detect_libc)"
    case "$ARCH" in
      x86_64)
        if [ "$LIBC" = "musl" ]; then TARGET="x86_64-unknown-linux-musl"
        else TARGET="x86_64-unknown-linux-gnu"; fi ;;
      aarch64)
        if [ "$LIBC" = "musl" ]; then TARGET="aarch64-unknown-linux-musl"
        else TARGET="aarch64-unknown-linux-gnu"; fi ;;
      armv7l)
        if [ "$LIBC" = "musl" ]; then TARGET="arm-unknown-linux-musleabihf"
        else TARGET="arm-unknown-linux-gnueabihf"; fi ;;
      i686)
        if [ "$LIBC" = "musl" ]; then TARGET="i686-unknown-linux-musl"
        else TARGET="i686-unknown-linux-gnu"; fi ;;
      *) echo "Error: unsupported architecture: $ARCH" >&2; exit 1 ;;
    esac
    ;;
  *)
    echo "Error: unsupported OS: $OS" >&2
    exit 1
    ;;
esac

# Detect downloader
if command -v curl >/dev/null 2>&1; then
  download() { curl -fsSL -o "$1" "$2"; }
elif command -v wget >/dev/null 2>&1; then
  download() { wget -qO "$1" "$2"; }
else
  echo "Error: curl or wget is required" >&2
  exit 1
fi

# Pick install directory
if [ -w /usr/local/bin ]; then
  INSTALL_DIR="/usr/local/bin"
else
  INSTALL_DIR="${HOME}/.local/bin"
  mkdir -p "$INSTALL_DIR"
fi

# Create temp dir with cleanup
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

# Download and extract
URL="https://github.com/${REPO}/releases/latest/download/${BINARY}-${TARGET}.tar.gz"
echo "Downloading ${BINARY} for ${TARGET}..."
download "$TMPDIR/${BINARY}.tar.gz" "$URL"
tar xzf "$TMPDIR/${BINARY}.tar.gz" -C "$TMPDIR"

# Install
install -m 755 "$TMPDIR/${BINARY}" "${INSTALL_DIR}/${BINARY}"
echo "Installed ${BINARY} to ${INSTALL_DIR}/${BINARY}"

# Print version
"${INSTALL_DIR}/${BINARY}" --version 2>/dev/null || true

# Warn if not on PATH
case ":${PATH}:" in
  *":${INSTALL_DIR}:"*) ;;
  *)
    echo ""
    echo "Warning: ${INSTALL_DIR} is not on your PATH."
    echo "Add it with:"
    echo "  export PATH=\"${INSTALL_DIR}:\$PATH\""
    ;;
esac
