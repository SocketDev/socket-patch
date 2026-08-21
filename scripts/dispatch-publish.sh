#!/usr/bin/env bash
# Dispatches one registry publish workflow (publish-*.yml) at the release tag
# and waits for the dispatched run to finish, propagating its conclusion.
# Used by the publish fan-out jobs in release.yml — see that file's header
# for why the legs run as separate workflow_dispatch runs rather than
# reusable-workflow calls (registry trusted publishers match the TOP-LEVEL
# workflow filename on npm/crates.io, and npm allows only one publisher per
# package).
#
# Usage: dispatch-publish.sh <workflow-file> <version>
#   <workflow-file>  e.g. publish-npm.yml (must have a workflow_dispatch
#                    trigger with `version` and `distinct-id` inputs)
#   <version>        X.Y.Z; the tag v<version> must exist (the dispatch runs
#                    the workflow file as of that tag)
#
# Requires: gh authenticated via GH_TOKEN with actions:write on
# $GITHUB_REPOSITORY; GITHUB_RUN_ID/GITHUB_RUN_ATTEMPT for run correlation.
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: dispatch-publish.sh <workflow-file> <version>" >&2
  exit 2
fi
WORKFLOW="$1"
VERSION="$2"

# The workflow_dispatch API returns nothing identifying the run it creates,
# so embed a correlation id in the run's name (via the distinct-id input,
# rendered by the publish workflows' run-name) and find it by title.
DISTINCT="${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"

gh workflow run "$WORKFLOW" \
  --repo "$GITHUB_REPOSITORY" \
  --ref "v${VERSION}" \
  -f "version=${VERSION}" \
  -f "distinct-id=${DISTINCT}"

# Run creation is asynchronous; poll briefly for the correlated run.
RUN_ID=""
for _ in $(seq 1 30); do
  sleep 2
  RUN_ID="$(gh run list \
    --repo "$GITHUB_REPOSITORY" \
    --workflow "$WORKFLOW" \
    --json databaseId,displayTitle \
    --jq "[.[] | select(.displayTitle | contains(\"[${DISTINCT}]\"))][0].databaseId // empty")"
  if [ -n "$RUN_ID" ]; then
    break
  fi
done
if [ -z "$RUN_ID" ]; then
  echo "::error::dispatched ${WORKFLOW} for v${VERSION} but could not find the created run (correlation id ${DISTINCT}) — check the Actions tab; the publish may still be running there"
  exit 1
fi

RUN_URL="${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY}/actions/runs/${RUN_ID}"
echo "Dispatched ${WORKFLOW} v${VERSION}: ${RUN_URL}"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  echo "- [\`${WORKFLOW}\` v${VERSION} run](${RUN_URL})" >> "$GITHUB_STEP_SUMMARY"
fi

# --exit-status: this job fails iff the dispatched run fails, so the release
# run's job graph reflects each registry's real outcome and "Re-run failed
# jobs" re-dispatches exactly the failed legs (every leg is idempotent).
# NOTE: a re-dispatch from the release run executes the leg's workflow file
# as of the TAG; a fix to a publish workflow on the default branch is picked
# up by dispatching that workflow manually instead (docs/releasing.md).
gh run watch "$RUN_ID" --repo "$GITHUB_REPOSITORY" --exit-status --interval 15
