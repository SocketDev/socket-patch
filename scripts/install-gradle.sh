#!/usr/bin/env bash
# Install one pinned Gradle distribution for the real-Gradle suites, then
# print the variable a CI step appends to $GITHUB_ENV.
#
#   scripts/install-gradle.sh <version> <dir>
#
# The zip comes straight from the gradle/gradle-distributions GitHub
# release, the host services.gradle.org redirects to anyway; the redirector
# alone answering HTTP 500 for ~30 s used to fail a merge-queue leg. It is
# only tried after the release download fails. The sha256 is pinned below
# (from https://gradle.org/release-checksums/), so no checksum fetch can fail
# either; a version without a pin fails closed.
#
# Prints (stdout):
#   SOCKET_PATCH_GRADLE_E2E_GRADLE=<launcher path>
set -euo pipefail

if [ $# -ne 2 ]; then
  sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//' >&2
  exit 2
fi
VERSION="$1"
DIR="$2"

case "$VERSION" in
  6.9.4) sha=3e240228538de9f18772a574e99a0ba959e83d6ef351014381acd9631781389a ;;
  7.6.6) sha=673d9776f303bc7048fc3329d232d6ebf1051b07893bd9d11616fad9a8673be0 ;;
  8.14.3) sha=bd71102213493060956ec229d946beee57158dbd89d0e62b91bca0fa2c5f3531 ;;
  9.8.0) sha=bafd5ce9cfaea0fbccfdc8439a1ac42fbd4cd9c89dc9a988228d8a2639a58e6c ;;
  *)
    echo "install-gradle.sh: no pinned sha256 for Gradle $VERSION; add it from https://gradle.org/release-checksums/" >&2
    exit 1
    ;;
esac

mkdir -p "$DIR"
zip="$DIR/gradle-$VERSION-bin.zip"
file="gradle-$VERSION-bin.zip"
fetched=""
# --ssl-revoke-best-effort: Windows curl (schannel) otherwise fails when the
# CA's revocation endpoint is unreachable.
for url in \
  "https://github.com/gradle/gradle-distributions/releases/download/v$VERSION/$file" \
  "https://services.gradle.org/distributions/$file"; do
  if curl -fsSL --retry 5 --retry-all-errors --ssl-revoke-best-effort "$url" -o "$zip"; then
    fetched=1
    break
  fi
  echo "install-gradle.sh: download from $url failed" >&2
done
if [ -z "$fetched" ]; then
  echo "install-gradle.sh: every origin failed for Gradle $VERSION" >&2
  exit 1
fi

# python, not sha256sum: the macOS runners have only shasum.
python -c 'import hashlib, sys; d = hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest(); sys.exit(0 if d == sys.argv[2] else "sha256 mismatch: got " + d)' "$zip" "$sha"
unzip -q "$zip" -d "$DIR"
launcher="$DIR/gradle-$VERSION/bin/gradle"
case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) launcher="$launcher.bat" ;; esac
echo "SOCKET_PATCH_GRADLE_E2E_GRADLE=$launcher"
