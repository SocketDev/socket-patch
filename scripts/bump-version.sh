#!/usr/bin/env bash
# One-command version bump: stamps the new version into every packaging site
# (scripts/version-sync.sh), rolls CHANGELOG.md's [Unreleased] section over
# into a dated `## [X.Y.Z]` heading, and (with --pr) opens the release PR.
#
# The Release workflow refuses to publish until these chores are done (see
# scripts/release-lint.sh, run by CI on the bump PR and again by the `version`
# job in release.yml), so this script is the intended way to start a release:
#
#   scripts/bump-version.sh 3.4.0 --pr
#
# or dispatch the "Version Bump" workflow (.github/workflows/version-bump.yml),
# which runs this script on a fresh checkout of main. Running it locally is
# preferred: a PR opened by the workflow's GITHUB_TOKEN does not trigger
# pull_request CI (GitHub suppresses events caused by that token).
#
# Usage: bump-version.sh <X.Y.Z> [--pr] [--base <branch>]
#   --pr    create branch release/vX.Y.Z, commit, push, open the PR (gh CLI)
#   --base  PR base branch (default: the repo's default branch)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

VERSION=""
OPEN_PR=false
BASE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --pr) OPEN_PR=true ;;
    --base)
      shift
      BASE="${1:?--base needs a branch name}"
      ;;
    -*)
      echo "bump-version: unknown flag: $1" >&2
      exit 2
      ;;
    *) VERSION="$1" ;;
  esac
  shift
done
: "${VERSION:?Usage: bump-version.sh <X.Y.Z> [--pr] [--base <branch>]}"

fail() {
  echo "bump-version: error: $*" >&2
  exit 1
}

# ── preconditions ────────────────────────────────────────────────────────────

printf '%s' "$VERSION" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$' \
  || fail "'$VERSION' is not a plain X.Y.Z release version"

CURRENT="$(grep '^version = ' Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/')"
[ "$VERSION" != "$CURRENT" ] || fail "already at version $CURRENT"
# sort -V puts the higher version last; refuse downgrades so a typo like
# bumping 3.3.0 -> 3.1.0 is caught here rather than at the release gate.
HIGHEST="$(printf '%s\n%s\n' "$CURRENT" "$VERSION" | sort -V | tail -1)"
[ "$HIGHEST" = "$VERSION" ] || fail "$VERSION is lower than the current version $CURRENT"

[ -z "$(git status --porcelain)" ] \
  || fail "working tree is not clean — commit or discard changes first"

grep -qE '^## \[Unreleased\]$' CHANGELOG.md \
  || fail "CHANGELOG.md has no '## [Unreleased]' heading to roll over"
VERSION_RE="$(printf '%s' "$VERSION" | sed 's/\./\\./g')"
! grep -qE "^## \[?${VERSION_RE}\]?( |$)" CHANGELOG.md \
  || fail "CHANGELOG.md already has a section for $VERSION"

# The release notes come from what accumulated under [Unreleased]; an empty
# section means nobody wrote any, and the release gate would (rightly) refuse
# an empty notes section anyway.
UNRELEASED_LINES="$(awk '
  /^## \[Unreleased\]$/ { in_section = 1; next }
  in_section && /^## / { exit }
  in_section && NF > 0 { count++ }
  END { print count + 0 }
' CHANGELOG.md)"
[ "$UNRELEASED_LINES" -gt 0 ] \
  || fail "CHANGELOG.md's [Unreleased] section is empty — write the release notes first"

# ── the chores ───────────────────────────────────────────────────────────────

TODAY="$(date +%Y-%m-%d)"

# Roll [Unreleased] over: the accumulated notes become the new version's
# section, and an empty [Unreleased] heading stays on top for the next cycle.
awk -v heading="## [$VERSION] — $TODAY" '
  /^## \[Unreleased\]$/ {
    print
    print ""
    print heading
    next
  }
  { print }
' CHANGELOG.md > CHANGELOG.md.tmp
mv CHANGELOG.md.tmp CHANGELOG.md

bash scripts/version-sync.sh "$VERSION"

echo
echo "Bumped $CURRENT -> $VERSION:"
git diff --stat

# ── the PR ───────────────────────────────────────────────────────────────────

if [ "$OPEN_PR" = "false" ]; then
  echo
  echo "Review the diff, then commit and open the PR (or re-run with --pr)."
  exit 0
fi

command -v gh >/dev/null || fail "--pr needs the gh CLI"
if [ -z "$BASE" ]; then
  BASE="$(gh repo view --json defaultBranchRef -q .defaultBranchRef.name)"
fi

BRANCH="release/v${VERSION}"
git checkout -b "$BRANCH"
git add -A
git commit -m "chore(release): bump version to ${VERSION}"
git push -u origin "$BRANCH"

# The PR body carries the release notes that just rolled over, plus the
# operator playbook for after the merge. Matched by string prefix, not an
# awk -v regex — awk escape-processes -v values, mangling \[ and \. patterns.
NOTES="$(awk -v ver="$VERSION" '
  !found {
    if (index($0, "## [" ver "] ") == 1) found = 1
    next
  }
  /^## / { exit }
  { print }
' CHANGELOG.md)"

gh pr create --base "$BASE" --title "chore(release): bump version to ${VERSION}" --body "$(cat <<EOF
Stamps ${VERSION} into every packaging site (\`scripts/version-sync.sh\`) and
rolls CHANGELOG.md's \`[Unreleased]\` notes into the \`## [${VERSION}]\` section.
CI's \`release-readiness\` job verifies the chores on this PR; the \`Release\`
workflow re-verifies them before anything publishes.

## Release notes (rolled over from [Unreleased])
${NOTES}

## After merging

1. Dispatch the **Release** workflow on the default branch (optionally with
   \`dry-run: true\` first). It builds all targets, tags \`v${VERSION}\`, creates
   the GitHub release, and publishes every ecosystem package.
2. Approve the staged npm versions with 2FA — platform packages first, then
   \`@socketsecurity/socket-patch\` (link in the run's step summary).
3. On a partial failure: fix the cause and use "Re-run failed jobs" on the
   same run — every publish job is idempotent.

See docs/releasing.md for the full playbook.
EOF
)"
