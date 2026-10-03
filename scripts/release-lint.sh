#!/usr/bin/env bash
# Release-readiness lint: verifies the version chores are complete before a
# release can publish. Single source of truth for the checks shared by CI
# (`release-readiness` job in ci.yml, on every PR) and the Release workflow
# (`version` job in release.yml, before anything builds or publishes).
#
# Checks (all failures are collected and reported together):
#   1. The version is a release version — X.Y.Z, or X.Y.Z-rc.N (main carries
#      the newest cut rc between release-sync merges; see
#      docs/release-train/DESIGN.md §3.7) — and matches Cargo.toml.
#      With --stable-only an rc version is refused.
#   2. Version coherence: the offline stamp (`scripts/release.py stamp
#      <version> --check`, what `scripts/version-sync.sh` runs) is a no-op —
#      every stamped site (Cargo.toml, Cargo.lock, npm manifests and lock)
#      already carries the version, byte for byte. Catches hand-edited drift
#      in any single site. Offline; writes nothing.
#   3. CHANGELOG.md has a `## [<version>]` section with non-empty release
#      notes, and a stable version has no leftover `[<version>-rc.N]`
#      sections (they fold into it at promotion). Skipped with --sync-only.
#   4. With --tag-check: the tag v<version> does not already exist at a
#      commit other than HEAD (existing at HEAD is allowed — that is a re-run
#      of a release that already tagged; mirrors the Release workflow
#      semantics). With --tag-exists: the tag v<version> must already exist
#      on origin (the release-sync PR only ever moves main to a cut tag).
#
# Usage: release-lint.sh [--sync-only] [--stable-only] [--tag-check|--tag-exists] [<version>]
#   <version> defaults to the workspace version in Cargo.toml.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

SYNC_ONLY=false
STABLE_ONLY=false
TAG_CHECK=false
TAG_EXISTS=false
VERSION=""
for arg in "$@"; do
  case "$arg" in
    --sync-only) SYNC_ONLY=true ;;
    --stable-only) STABLE_ONLY=true ;;
    --tag-check) TAG_CHECK=true ;;
    --tag-exists) TAG_EXISTS=true ;;
    -*)
      echo "release-lint: unknown flag: $arg" >&2
      exit 2
      ;;
    *) VERSION="$arg" ;;
  esac
done

FAILED=0
fail() {
  FAILED=1
  # ::error:: annotates the run + PR when under GitHub Actions.
  if [ "${GITHUB_ACTIONS:-}" = "true" ]; then
    echo "::error title=release-lint::$*"
  else
    echo "release-lint: error: $*" >&2
  fi
}
note() {
  if [ "${GITHUB_ACTIONS:-}" = "true" ]; then
    echo "::notice title=release-lint::$*"
  else
    echo "release-lint: $*"
  fi
}

# ── 1. version shape + Cargo.toml agreement ─────────────────────────────────

CARGO_VERSION="$(grep '^version = ' Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/')"
if [ -z "$VERSION" ]; then
  VERSION="$CARGO_VERSION"
fi

KIND=any
if [ "$STABLE_ONLY" = "true" ]; then
  KIND=stable
fi
if ! SEMVER_ERR="$(python3 scripts/release.py semver validate --kind "$KIND" "$VERSION" 2>&1 >/dev/null)"; then
  fail "${SEMVER_ERR#release.py: error: }"
fi
if [ "$VERSION" != "$CARGO_VERSION" ]; then
  fail "requested version $VERSION != Cargo.toml workspace version $CARGO_VERSION (run scripts/version-sync.sh $VERSION)"
fi

# ── 2. version coherence: the stamp must be a no-op ─────────────────────────

if STAMP_ERR="$(python3 scripts/release.py stamp --check "$VERSION" 2>&1 >/dev/null)"; then
  note "version coherence OK: every stamped site already carries $VERSION"
else
  fail "${STAMP_ERR#release.py: error: } (run scripts/version-sync.sh $VERSION)"
fi

# ── 3. CHANGELOG section + non-empty notes ─────────────────────────────────

if [ "$SYNC_ONLY" = "false" ]; then
  if CHANGELOG_MSG="$(python3 scripts/release.py changelog check --version "$VERSION" 2>&1)"; then
    note "CHANGELOG OK: $CHANGELOG_MSG"
  else
    fail "${CHANGELOG_MSG#release.py: error: } — cut it with scripts/release.py changelog cut --version $VERSION --date <YYYY-MM-DD> (or write the section by hand)"
  fi
fi

# ── 4. tag collision (opt-in: needs the remote) ─────────────────────────────

if [ "$TAG_EXISTS" = "true" ]; then
  if [ -n "$(git ls-remote origin "refs/tags/v${VERSION}")" ]; then
    note "tag v${VERSION} exists"
  else
    fail "tag v${VERSION} does not exist — main's version may only move to a version the release train already cut"
  fi
fi

if [ "$TAG_CHECK" = "true" ]; then
  # HEAD is the release commit in the Release workflow (GITHUB_SHA) and the
  # PR merge commit in CI; in both cases an existing tag at any OTHER commit
  # means this version was already released from different code.
  EXISTING_SHA="$(git ls-remote origin "refs/tags/v${VERSION}" | cut -f1)"
  HEAD_SHA="$(git rev-parse HEAD)"
  if [ -z "$EXISTING_SHA" ]; then
    note "tag v${VERSION} does not exist yet"
  elif [ "$EXISTING_SHA" = "$HEAD_SHA" ]; then
    note "tag v${VERSION} already points at HEAD — a retry of a previous release run"
  else
    fail "tag v${VERSION} already exists at ${EXISTING_SHA} (HEAD is ${HEAD_SHA}) — bump to a new version"
  fi
fi

if [ "$FAILED" -ne 0 ]; then
  exit 1
fi
note "all checks passed for $VERSION"
