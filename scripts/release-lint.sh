#!/usr/bin/env bash
# Release-readiness lint: verifies the version chores are complete before a
# release can publish. Single source of truth for the checks shared by CI
# (`release-readiness` job in ci.yml, on every PR) and the Release workflow
# (`version` job in release.yml, before anything builds or publishes).
#
# Checks (all failures are collected and reported together):
#   1. The version is a plain X.Y.Z release version and matches Cargo.toml.
#   2. Version coherence: `scripts/version-sync.sh <version>` is a no-op —
#      every stamped site (npm/pypi/gem/cargo) already
#      carries the workspace version. Catches hand-edited drift in any single
#      site. NOTE: this runs version-sync, which refreshes the npm lockfile
#      (network); files the sync touches are restored afterwards, so the tree
#      is left as found — but the tree must be CLEAN before the check runs.
#   3. CHANGELOG.md has a `## [X.Y.Z]` heading with non-empty release notes
#      (skipped with --sync-only).
#   4. With --tag-check: the tag v<X.Y.Z> does not already exist at a commit
#      other than HEAD (existing at HEAD is allowed — that is a re-run of a
#      release that already tagged; mirrors the Release workflow semantics).
#
# Usage: release-lint.sh [--sync-only] [--tag-check] [<version>]
#   <version> defaults to the workspace version in Cargo.toml.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

SYNC_ONLY=false
TAG_CHECK=false
VERSION=""
for arg in "$@"; do
  case "$arg" in
    --sync-only) SYNC_ONLY=true ;;
    --tag-check) TAG_CHECK=true ;;
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

if ! printf '%s' "$VERSION" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; then
  fail "'$VERSION' is not a plain X.Y.Z release version"
fi
if [ "$VERSION" != "$CARGO_VERSION" ]; then
  fail "requested version $VERSION != Cargo.toml workspace version $CARGO_VERSION (run scripts/version-sync.sh $VERSION)"
fi

# ── 2. version coherence: version-sync must be a no-op ──────────────────────

if [ -n "$(git status --porcelain)" ]; then
  fail "working tree is not clean — the coherence check runs version-sync and needs a clean tree to compare against"
else
  bash scripts/version-sync.sh "$VERSION" >/dev/null
  DRIFTED="$(git status --porcelain | awk '{print $2}')"
  if [ -n "$DRIFTED" ]; then
    fail "version-sync.sh $VERSION is not a no-op — these files carried a stale version: $(echo "$DRIFTED" | tr '\n' ' ')"
    # The tree was clean before the sync, so restoring exactly the files the
    # sync touched leaves it as found.
    echo "$DRIFTED" | xargs git checkout --
  else
    note "version coherence OK: every stamped site already carries $VERSION"
  fi
fi

# ── 3. CHANGELOG heading + non-empty notes ──────────────────────────────────

if [ "$SYNC_ONLY" = "false" ]; then
  VERSION_RE="$(printf '%s' "$VERSION" | sed 's/\./\\./g')"
  # Accept `## [X.Y.Z] — date` and the bracketless `## X.Y.Z` variant, the
  # same shapes the Release workflow historically accepted.
  if ! grep -qE "^## \[?${VERSION_RE}\]?( |$)" CHANGELOG.md; then
    fail "CHANGELOG.md has no '## [$VERSION]' heading — roll [Unreleased] over with scripts/bump-version.sh $VERSION (or write the section by hand)"
  else
    # Non-empty: at least one non-blank line between the heading and the next
    # `## ` heading (or EOF). The heading is matched by string prefix, not an
    # awk -v regex — awk applies escape processing to -v values, which
    # silently mangles \[ and \. into a wrong pattern.
    BODY_LINES="$(awk -v ver="$VERSION" '
      !found {
        if ($0 == "## [" ver "]" || index($0, "## [" ver "] ") == 1 ||
            $0 == "## " ver     || index($0, "## " ver " ") == 1) {
          found = 1
        }
        next
      }
      /^## / { exit }
      NF > 0 { count++ }
      END { print count + 0 }
    ' CHANGELOG.md)"
    if [ "$BODY_LINES" -eq 0 ]; then
      fail "CHANGELOG.md's [$VERSION] section is empty — a release needs written notes"
    else
      note "CHANGELOG OK: [$VERSION] section present with $BODY_LINES lines of notes"
    fi
  fi
fi

# ── 4. tag collision (opt-in: needs the remote) ─────────────────────────────

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
