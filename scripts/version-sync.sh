#!/usr/bin/env bash
# Stamps the release version into every packaging artifact that carries one:
#   - Cargo.toml (workspace version + socket-patch-core exact pin)
#   - Cargo.lock (the source-less workspace-member entries, so --locked builds)
#   - npm/socket-patch/package.json (+ optionalDependencies, package-lock.json)
#   - npm/socket-patch-*/package.json (per-platform packages)
#
# Thin wrapper over `scripts/release.py stamp`, which is offline and
# byte-deterministic: the npm lockfile is edited as JSON (stale platform
# entries are dropped) instead of being re-resolved against the registry,
# so the same version always produces the same bytes. Accepts X.Y.Z and
# X.Y.Z-rc.N.
set -euo pipefail

VERSION="${1:?Usage: version-sync.sh <version>}"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

exec python3 "$REPO_ROOT/scripts/release.py" --root "$REPO_ROOT" stamp "$VERSION"
