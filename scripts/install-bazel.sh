#!/usr/bin/env bash
# Install one pinned Bazel release binary for the real-Bazel tests
# (`e2e_bazel_build`) and print where it is.
#
#   scripts/install-bazel.sh <bazel-version> <dir>
#
# The release binary is one file from the GitHub release
# (releases.bazel.build is tried second). It must match the sha256 pinned for
# this platform in scripts/bazel-pins.txt: a version or platform with no pin
# fails before anything is downloaded, and a download that does not match is
# deleted, never installed. A file already in <dir> that matches its pin (CI
# restores <dir> from the actions cache) is used without any download.
#
# The tests run the verified binary directly, so no bazelisk, `.bazelversion`
# or network version lookup is involved.
#
# Prints one line on stdout, and everything else on stderr:
#   SOCKET_PATCH_BAZEL_E2E_BAZEL=<bazel binary>
# A CI step appends that line to $GITHUB_ENV, and a shell takes it with
#   export "$(scripts/install-bazel.sh <bazel-version> <dir>)"
# Both keep a space in <dir>.
set -euo pipefail

die() {
  echo "install-bazel.sh: $*" >&2
  exit 1
}

if [ $# -ne 2 ]; then
  sed -n '2,21p' "$0" | sed 's/^# \{0,1\}//' >&2
  exit 2
fi
VERSION="$1"
DIR="$2"
# What is printed is one line.
case "$DIR" in *$'\n'*) die "<dir> must not hold a newline" ;; esac
PINS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/bazel-pins.txt"

# The version becomes part of two URLs and an awk variable.
if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  die "'$VERSION' is not a Bazel release (expected e.g. 9.3.2)"
fi
[ -f "$PINS" ] || die "the pins file $PINS is missing"

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  *) os="$(uname -s)" ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch=x86_64 ;;
  arm64 | aarch64) arch=arm64 ;;
  *) arch="$(uname -m)" ;;
esac
platform="$os-$arch"

# The macOS runners have only shasum.
if command -v sha256sum >/dev/null 2>&1; then
  sha256_of() { sha256sum <"$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
  sha256_of() { shasum -a 256 <"$1" | cut -d' ' -f1; }
else
  die "need sha256sum or shasum to verify the download"
fi

# The one sha256 pinned for this version and platform. Anything else (no
# line, two lines, a malformed digest) is no pin. Resolved before the
# download, so an unpinned version or platform costs no network and leaves
# <dir> untouched.
sha="$(awk -v v="$VERSION" -v p="$platform" \
  '{ sub(/\r$/, "") } $1 == "bazel" && $2 == v && $3 == p { print $4 }' "$PINS")"
if ! [[ "$sha" =~ ^[0-9a-f]{64}$ ]]; then
  die "no pinned sha256 for bazel $VERSION on $platform; add it to scripts/bazel-pins.txt from the release's .sha256 file"
fi

mkdir -p "$DIR"
DIR="$(cd "$DIR" && pwd)"
file="bazel-$VERSION-$platform"
bazel="$DIR/$file"

# Leave a verified file at $bazel.
fetch() {
  local url got
  if [ -f "$bazel" ]; then
    if [ "$(sha256_of "$bazel")" = "$sha" ]; then
      echo "install-bazel.sh: using the cached $file" >&2
      return 0
    fi
    rm -f "$bazel"
  fi
  # Downloaded beside the final name and renamed only once verified, so an
  # interrupted or tampered download never sits where a later run (or a
  # cache save) would pick it up.
  local tmp="$bazel.download"
  # A stalled transfer must not sit until the job times out, and a file an
  # origin does not have must not be asked for again. Per attempt: 20 s to
  # connect, an end after 30 s below 30 kB/s, and 10 minutes in all (the
  # binary is about 60 MB, so that is a link of 1 Mbit/s). curl retries only
  # what it calls transient (a timeout, HTTP 408, 429, 500, 502, 503 and
  # 504) and starts no retry after 5 minutes. Any other failure, a 404
  # included, goes to the next origin at once.
  for url in "$@"; do
    rm -f "$tmp"
    if curl -fsSL --connect-timeout 20 --speed-limit 30000 --speed-time 30 \
      --max-time 600 --retry 3 --retry-max-time 300 "$url" -o "$tmp"; then
      got="$(sha256_of "$tmp")"
      if [ "$got" = "$sha" ]; then
        mv -f "$tmp" "$bazel"
        return 0
      fi
      echo "install-bazel.sh: sha256 mismatch for $url: got $got, pinned $sha" >&2
    else
      echo "install-bazel.sh: download from $url failed" >&2
    fi
    rm -f "$tmp"
  done
  die "no origin served a $file that matches its pin"
}

fetch \
  "https://github.com/bazelbuild/bazel/releases/download/$VERSION/$file" \
  "https://releases.bazel.build/$VERSION/release/$file"
chmod +x "$bazel"

echo "SOCKET_PATCH_BAZEL_E2E_BAZEL=$bazel"
