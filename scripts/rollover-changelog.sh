#!/usr/bin/env bash
set -euo pipefail

# Roll the CHANGELOG.md `## [Unreleased]` section over to a released version.
#
# Usage: rollover-changelog.sh <version> [date]
#   <version>  the version just published (e.g. 3.3.0)
#   [date]     release date, YYYY-MM-DD (default: today, UTC)
#
# Effect: inserts a `## [<version>] — <date>` heading immediately below the
# `## [Unreleased]` heading. Everything that was under `[Unreleased]` now
# lives under the new versioned heading, and `[Unreleased]` is left empty
# and ready for the next cycle — the standard Keep a Changelog rollover.
#
# Idempotent + safe by design (it runs *after* publish, so it must never
# fail the release):
#   - If a `## [<version>]` heading already exists (a maintainer wrote the
#     release notes by hand), this is a no-op.
#   - If there is no `## [Unreleased]` heading, or it has no content to
#     promote, this is a no-op.
# In every no-op case the file is left byte-for-byte unchanged so the
# caller's `git diff` check sees nothing to commit.

VERSION="${1:?Usage: rollover-changelog.sh <version> [date]}"
DATE="${2:-$(date -u +%Y-%m-%d)}"

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FILE="${CHANGELOG_FILE:-$REPO_ROOT/CHANGELOG.md}"

if [ ! -f "$FILE" ]; then
  echo "::warning::$FILE not found; skipping changelog rollover."
  exit 0
fi

# Already stamped (manual flow) — nothing to do. Matches `## [X.Y.Z]` or
# `## X.Y.Z`, with the version followed by a space or end-of-line, mirroring
# the release workflow's version-check.
if grep -qE "^## \[?${VERSION}\]?( |\$)" "$FILE"; then
  echo "CHANGELOG already has a heading for ${VERSION}; nothing to roll over."
  exit 0
fi

if ! grep -qE '^## \[Unreleased\]' "$FILE"; then
  echo "::warning::No '## [Unreleased]' heading in $FILE; skipping rollover."
  exit 0
fi

# Is there anything under [Unreleased] worth promoting? (any non-blank line
# between the [Unreleased] heading and the next `## ` heading)
unreleased_content="$(awk '
  /^## \[Unreleased\]/ { inblock=1; next }
  inblock && /^## / { inblock=0 }
  inblock && NF { print }
' "$FILE")"
if [ -z "$unreleased_content" ]; then
  echo "::warning::[Unreleased] is empty; nothing to roll over for ${VERSION}."
  exit 0
fi

tmp="$(mktemp)"
awk -v ver="$VERSION" -v date="$DATE" '
  /^## \[Unreleased\]/ && !done {
    print
    print ""
    print "## [" ver "] — " date
    done = 1
    next
  }
  { print }
' "$FILE" >"$tmp"
mv "$tmp" "$FILE"

echo "Rolled [Unreleased] over to [${VERSION}] — ${DATE}."
