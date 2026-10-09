#!/usr/bin/env bash
# `python -m pip install` that survives a PyPI download blip.
#
#   scripts/pip-install-retry.sh <pip install args...>
#
# pip's own `--retries` covers failed connections, not a body cut off
# mid-download: an `IncompleteRead` from files.pythonhosted.org aborts the
# install at once ("Could not install packages due to an OSError:
# Connection broken: IncompleteRead"). One such cut evicted a merge-queue
# entry in hosted-e2e, so the CI tool installs go through here: up to 4
# attempts with a growing pause. The args are passed through unchanged, so
# a pinned `pkg==X.Y.Z` stays pinned.
set -euo pipefail

if [ "$#" -eq 0 ]; then
  echo "usage: $0 <pip install args...>" >&2
  exit 2
fi

attempts=4
for attempt in $(seq 1 "$attempts"); do
  if python -m pip install --disable-pip-version-check "$@"; then
    exit 0
  fi
  if [ "$attempt" = "$attempts" ]; then
    echo "::error::pip install $* failed on all $attempts attempts"
    exit 1
  fi
  echo "::warning::pip install $* attempt $attempt failed; retrying"
  sleep $((attempt * 10))
done
