#!/bin/sh
set -eu

# Socket Patch installer
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/SocketDev/socket-patch/main/scripts/install.sh | sh
#
# Override the version that gets installed by exporting SOCKET_PATCH_VERSION:
#   curl -fsSL .../install.sh | SOCKET_PATCH_VERSION=3.0.0 sh

REPO="SocketDev/socket-patch"
BINARY="socket-patch"
VERSION="${SOCKET_PATCH_VERSION:-latest}"

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
        return
      fi
      # `[ -e ]` cannot take a glob (SC2144): with several matches it is a
      # syntax error, with none it tests the literal pattern. Loop instead.
      for loader in /lib/ld-musl-*.so.1; do
        if [ -e "$loader" ]; then
          echo "musl"
          return
        fi
      done
      echo "gnu"
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

# Locate a SHA-256 implementation. shasum and sha256sum cover macOS + Linux.
if command -v shasum >/dev/null 2>&1; then
  sha256() { shasum -a 256 "$1" | awk '{print $1}'; }
elif command -v sha256sum >/dev/null 2>&1; then
  sha256() { sha256sum "$1" | awk '{print $1}'; }
else
  echo "Error: shasum or sha256sum is required for integrity verification" >&2
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

# Pick the release path. "latest" resolves on GitHub's side; tagged versions are
# served from /releases/download/v<version>/.
if [ "$VERSION" = "latest" ]; then
  BASE_URL="https://github.com/${REPO}/releases/latest/download"
else
  BASE_URL="https://github.com/${REPO}/releases/download/v${VERSION#v}"
fi

ARCHIVE="${BINARY}-${TARGET}.tar.gz"
ARCHIVE_URL="${BASE_URL}/${ARCHIVE}"
SHA_URL="${BASE_URL}/SHA256SUMS"

echo "Downloading ${ARCHIVE}..."
download "${TMPDIR}/${ARCHIVE}" "${ARCHIVE_URL}"

echo "Downloading SHA256SUMS..."
download "${TMPDIR}/SHA256SUMS" "${SHA_URL}"

# Verify the tarball matches the published checksum before extraction. The
# SHA256SUMS file follows the standard "<hex>  <filename>" format, one line
# per release artifact.
EXPECTED="$(awk -v a="${ARCHIVE}" '$2 == a || $2 == "*"a {print $1; exit}' "${TMPDIR}/SHA256SUMS")"
if [ -z "${EXPECTED}" ]; then
  echo "Error: no checksum entry for ${ARCHIVE} in SHA256SUMS" >&2
  exit 1
fi
ACTUAL="$(sha256 "${TMPDIR}/${ARCHIVE}")"
if [ "${EXPECTED}" != "${ACTUAL}" ]; then
  echo "Error: checksum mismatch for ${ARCHIVE}" >&2
  echo "  expected: ${EXPECTED}" >&2
  echo "  actual:   ${ACTUAL}" >&2
  exit 1
fi

tar xzf "${TMPDIR}/${ARCHIVE}" -C "${TMPDIR}"

# Install
install -m 755 "${TMPDIR}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
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
