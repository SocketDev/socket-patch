#!/usr/bin/env bash
# `rustup` that survives a static.rust-lang.org download blip.
#
#   scripts/rustup-retry.sh toolchain install            # rust-toolchain.toml
#   scripts/rustup-retry.sh toolchain install 1.82.0 --profile minimal
#   scripts/rustup-retry.sh component add llvm-tools-preview
#
# rustup makes one attempt per download: a DNS lookup that fails on a fresh
# runner ("dns error: failed to lookup address information") fails the
# install at once. One such blip on a macOS runner evicted a merge-queue
# entry in a cargo-vex-matrix leg, so CI's toolchain installs go through
# here: up to 4 attempts with a growing pause. The args are passed through
# unchanged.
#
# CI installs with `toolchain install`, not `rustup show`: since rustup
# 1.28, `rustup show` reports a failed download of the rust-toolchain.toml
# channel and still exits 0, leaving the install to the job's first cargo
# command, which gets no retry.
set -euo pipefail

if [ "$#" -eq 0 ]; then
  echo "usage: $0 <rustup args...>" >&2
  exit 2
fi

attempts=4
for attempt in $(seq 1 "$attempts"); do
  if rustup "$@"; then
    exit 0
  fi
  if [ "$attempt" = "$attempts" ]; then
    echo "::error::rustup $* failed on all $attempts attempts"
    exit 1
  fi
  echo "::warning::rustup $* attempt $attempt failed; retrying"
  sleep $((attempt * 10))
done
