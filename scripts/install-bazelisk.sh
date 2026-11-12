#!/usr/bin/env bash
# Install the pinned bazelisk and one pinned Bazel release binary for the
# real-Bazel suite (`e2e_bazel_build`), then print the variables a CI step
# appends to $GITHUB_ENV.
#
#   scripts/install-bazelisk.sh <bazel-version> <dir>
#
# Both files are single binaries from the GitHub release (for Bazel,
# releases.bazel.build is tried second). Each must match the sha256 pinned
# for this platform in scripts/bazel-pins.txt; a version or platform with no
# pin fails closed before anything is downloaded, and a download that does
# not match is deleted, never installed. A file already in <dir> that
# matches its pin (CI restores <dir> from the actions cache) is used without
# any download.
#
# The tests drive the verified Bazel binary directly, so no `.bazelversion`,
# `tools/bazel` or network version lookup is involved; bazelisk is only for
# the launcher cell, which runs it with USE_BAZEL_VERSION=<the binary>.
#
# Prints (stdout):
#   SOCKET_PATCH_BAZEL_E2E_BAZEL=<bazel binary>
#   SOCKET_PATCH_BAZEL_E2E_BINARY=<bazel binary>
#   SOCKET_PATCH_BAZEL_E2E_BAZELISK=<bazelisk binary>
#   SOCKET_PATCH_BAZEL_E2E_VERSION=<bazel-version>
set -euo pipefail

BAZELISK_VERSION=v1.30.0

die() {
  echo "install-bazelisk.sh: $*" >&2
  exit 1
}

if [ $# -ne 2 ]; then
  sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//' >&2
  exit 2
fi
VERSION="$1"
DIR="$2"
PINS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/bazel-pins.txt"

# The version becomes part of two URLs and an awk variable.
if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(rc[0-9]+)?$ ]]; then
  die "'$VERSION' is not a Bazel version (expected e.g. 9.3.2 or 10.0.0rc3)"
fi
[ -f "$PINS" ] || die "the pins file $PINS is missing"

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  MINGW* | MSYS* | CYGWIN*) os=windows ;;
  *) os="$(uname -s)" ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch=x86_64 ;;
  arm64 | aarch64) arch=arm64 ;;
  *) arch="$(uname -m)" ;;
esac
platform="$os-$arch"
exe=""
if [ "$os" = windows ]; then exe=".exe"; fi

# Read from stdin: given a path with a backslash, GNU sha256sum escapes its
# whole output line. The macOS runners have only shasum.
if command -v sha256sum >/dev/null 2>&1; then
  sha256_of() { sha256sum <"$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
  sha256_of() { shasum -a 256 <"$1" | cut -d' ' -f1; }
else
  die "need sha256sum or shasum to verify downloads"
fi

# pin <tool> <version>: the one sha256 pinned for this platform. Anything
# else (no line, two lines, a malformed digest) is no pin.
pin() {
  local sha
  sha="$(awk -v t="$1" -v v="$2" -v p="$platform" \
    '{ sub(/\r$/, "") } $1 == t && $2 == v && $3 == p { print $4 }' "$PINS")"
  if ! [[ "$sha" =~ ^[0-9a-f]{64}$ ]]; then
    die "no pinned sha256 for $1 $2 on $platform; add it to scripts/bazel-pins.txt from the release's .sha256 file"
  fi
  echo "$sha"
}

# fetch <dest> <sha256> <url>...: leave a verified file at <dest>.
fetch() {
  local dest="$1" sha="$2" url got
  shift 2
  if [ -f "$dest" ]; then
    if [ "$(sha256_of "$dest")" = "$sha" ]; then
      echo "install-bazelisk.sh: using the cached $(basename "$dest")" >&2
      return 0
    fi
    rm -f "$dest"
  fi
  # Downloaded beside the final name and renamed only once verified, so an
  # interrupted or tampered download never sits where a later run (or a
  # cache save) would pick it up.
  local tmp="$dest.download"
  for url in "$@"; do
    rm -f "$tmp"
    # --ssl-revoke-best-effort: Windows curl (schannel) otherwise fails when
    # the CA's revocation endpoint is unreachable.
    if curl -fsSL --retry 5 --retry-all-errors --ssl-revoke-best-effort "$url" -o "$tmp"; then
      got="$(sha256_of "$tmp")"
      if [ "$got" = "$sha" ]; then
        mv -f "$tmp" "$dest"
        return 0
      fi
      echo "install-bazelisk.sh: sha256 mismatch for $url: got $got, pinned $sha" >&2
    else
      echo "install-bazelisk.sh: download from $url failed" >&2
    fi
    rm -f "$tmp"
  done
  die "no origin served a $(basename "$dest") that matches its pin"
}

# Both pins are resolved before the first download: an unpinned version or
# platform costs no network and leaves <dir> untouched. The Bazel pin first,
# so the message names the version that was asked for on every platform,
# also on one that has no bazelisk pin either.
bazel_sha="$(pin bazel "$VERSION")"
bazelisk_sha="$(pin bazelisk "$BAZELISK_VERSION")"

mkdir -p "$DIR"
DIR="$(cd "$DIR" && pwd)"
# The printed paths are read by native programs (the test binary, bazelisk),
# not by this shell.
if [ "$os" = windows ] && command -v cygpath >/dev/null 2>&1; then
  DIR="$(cygpath -m "$DIR")"
fi

bazelisk_arch="$arch"
if [ "$arch" = x86_64 ]; then bazelisk_arch=amd64; fi
bazelisk="$DIR/bazelisk-$BAZELISK_VERSION-$platform$exe"
fetch "$bazelisk" "$bazelisk_sha" \
  "https://github.com/bazelbuild/bazelisk/releases/download/$BAZELISK_VERSION/bazelisk-$os-$bazelisk_arch$exe"

file="bazel-$VERSION-$platform$exe"
case "$VERSION" in
  *rc*) mirror="https://releases.bazel.build/${VERSION%%rc*}/rc${VERSION##*rc}/$file" ;;
  *) mirror="https://releases.bazel.build/$VERSION/release/$file" ;;
esac
bazel="$DIR/$file"
fetch "$bazel" "$bazel_sha" \
  "https://github.com/bazelbuild/bazel/releases/download/$VERSION/$file" \
  "$mirror"

chmod +x "$bazelisk" "$bazel"

echo "SOCKET_PATCH_BAZEL_E2E_BAZEL=$bazel"
echo "SOCKET_PATCH_BAZEL_E2E_BINARY=$bazel"
echo "SOCKET_PATCH_BAZEL_E2E_BAZELISK=$bazelisk"
echo "SOCKET_PATCH_BAZEL_E2E_VERSION=$VERSION"
