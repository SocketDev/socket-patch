#!/bin/sh
set -eu

# Socket Patch installer
# Usage:
#   curl -fsSL https://install.socket.dev/patch | sh
#
# install.socket.dev/patch serves a byte-for-byte copy of this file; the URL
# above and the raw.githubusercontent.com path to this script are
# interchangeable. See docs/installer-hosting.md for how the copy is published.
#
# Override the version that gets installed by exporting SOCKET_PATCH_VERSION:
#   curl -fsSL https://install.socket.dev/patch | SOCKET_PATCH_VERSION=3.0.0 sh
#
# Override where the archives come from with SOCKET_PATCH_BASE_URL — a releases
# base that answers GitHub's two asset paths, `<base>/latest/download/<file>`
# and `<base>/download/v<ver>/<file>`. Use it to install without reaching
# github.com at all:
#
#   … | SOCKET_PATCH_BASE_URL=https://install.socket.dev/SocketDev/socket-patch/releases sh
#
# install.socket.dev relays those exact paths from the GitHub release, which is
# why one template covers both origins. Whichever origin is used, the archive is
# still verified against the SHA256SUMS fetched from that same origin.
#
# Override where the binary is installed with SOCKET_PATCH_INSTALL_DIR.

REPO="SocketDev/socket-patch"
BINARY="socket-patch"
VERSION="${SOCKET_PATCH_VERSION:-latest}"
# Releases base. Default is GitHub; see the SOCKET_PATCH_BASE_URL note above for
# installing through install.socket.dev instead. Trailing slashes are trimmed so
# a base with one does not produce `//download`.
RELEASES_BASE="${SOCKET_PATCH_BASE_URL:-https://github.com/${REPO}/releases}"
while :; do
  case "$RELEASES_BASE" in
    */) RELEASES_BASE="${RELEASES_BASE%/}" ;;
    *) break ;;
  esac
done

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

# Pick install directory. An explicit SOCKET_PATCH_INSTALL_DIR wins over both
# defaults — needed for unprivileged installs into a toolchain-managed prefix,
# and for testing the script without writing to a system path.
if [ -n "${SOCKET_PATCH_INSTALL_DIR:-}" ]; then
  INSTALL_DIR="$SOCKET_PATCH_INSTALL_DIR"
  mkdir -p "$INSTALL_DIR"
elif [ -w /usr/local/bin ]; then
  INSTALL_DIR="/usr/local/bin"
else
  INSTALL_DIR="${HOME}/.local/bin"
  mkdir -p "$INSTALL_DIR"
fi

# Create temp dir with cleanup
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

# Pick the release path. "latest" is resolved by the origin (GitHub redirects;
# install.socket.dev resolves it against the upstream release), so the script
# never has to know the version number. Tagged versions are served from
# <base>/download/v<version>/.
if [ "$VERSION" = "latest" ]; then
  BASE_URL="${RELEASES_BASE}/latest/download"
else
  BASE_URL="${RELEASES_BASE}/download/v${VERSION#v}"
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
