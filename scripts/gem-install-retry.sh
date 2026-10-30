#!/usr/bin/env bash
# `gem install` that survives a rubygems.org connection blip.
#
#   scripts/gem-install-retry.sh <gem install args...>
#
# RubyGems has no retry of its own: one failed TCP connect to rubygems.org
# ("SocketError: Failed to open TCP connection to rubygems.org:443") aborts
# the install at once. ruby/setup-ruby's `bundler:` input runs exactly such
# a bare `gem install bundler`, and one blip there evicted a merge-queue
# entry in hosted-e2e, so the CI bundler installs go through here: up to 4
# attempts with a growing pause. The args are passed through unchanged, so
# a pinned `-v X.Y.Z` stays pinned.
set -euo pipefail

if [ "$#" -eq 0 ]; then
  echo "usage: $0 <gem install args...>" >&2
  exit 2
fi

attempts=4
for attempt in $(seq 1 "$attempts"); do
  if gem install "$@"; then
    exit 0
  fi
  if [ "$attempt" = "$attempts" ]; then
    echo "::error::gem install $* failed on all $attempts attempts"
    exit 1
  fi
  echo "::warning::gem install $* attempt $attempt failed; retrying"
  sleep $((attempt * 10))
done
