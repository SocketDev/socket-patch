#!/usr/bin/env bash
# Install one pinned Apache Maven release for the real-Maven suites, then
# print the variable a CI step appends to $GITHUB_ENV.
#
#   scripts/install-maven.sh <version> <dir>
#
# The tarball comes from Maven Central's CDN (well under a second);
# archive.apache.org throttles bulk downloads to 1.5-5.5 minutes, so it is
# only the fallback. Whichever origin answers, the archive must match the
# SHA512 pinned in scripts/maven-sha512.json before it is unpacked: an origin
# cannot replace both the archive and its expected digest. The pins come from
# Apache's release checksums, cross-checked against the Maven Central
# tarballs; a version without a pin fails closed.
#
# Prints (stdout):
#   SOCKET_PATCH_MAVEN_E2E_MVN=<launcher path>
set -euo pipefail

if [ $# -ne 2 ]; then
  sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//' >&2
  exit 2
fi
VERSION="$1"
DIR="$2"
here=$(cd "$(dirname "$0")" && pwd)

mkdir -p "$DIR"
major="${VERSION%%.*}"
file="apache-maven-${VERSION}-bin.tar.gz"
url="https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/${VERSION}/${file}"
archive_url="https://archive.apache.org/dist/maven/maven-${major}/${VERSION}/binaries/${file}"
# --retry-all-errors: plain --retry skips refused connections and TLS
# handshake errors (curl exit 7/35).
# --ssl-revoke-best-effort: Windows curl (schannel) otherwise fails when the
# CA's revocation endpoint is unreachable. A no-op elsewhere.
if ! curl -fsSL --retry 5 --retry-all-errors --ssl-revoke-best-effort "$url" -o "$DIR/maven.tgz"; then
  echo "::warning::Maven Central download failed; falling back to the Apache archive." >&2
  curl -fsSL --retry 5 --retry-all-errors --ssl-revoke-best-effort "$archive_url" -o "$DIR/maven.tgz"
fi
python - "$VERSION" "$DIR/maven.tgz" "$here/maven-sha512.json" <<'PY' >&2
import hashlib, json, sys
from pathlib import Path
# Add a pin when adding a matrix version.
expected = json.loads(Path(sys.argv[3]).read_text())[sys.argv[1]]
if hashlib.sha512(Path(sys.argv[2]).read_bytes()).hexdigest() != expected:
    raise SystemExit("Maven archive SHA512 mismatch")
PY
# Python accepts native Windows paths for both archive and destination.
python -m tarfile -e "$DIR/maven.tgz" "$DIR" >&2
launcher="$DIR/apache-maven-${VERSION}/bin/mvn"
if [ "${RUNNER_OS:-}" = Windows ]; then launcher="${launcher}.cmd"; fi
echo "SOCKET_PATCH_MAVEN_E2E_MVN=$launcher"
