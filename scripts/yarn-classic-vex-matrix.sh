#!/usr/bin/env bash
# Replay every real-yarn-classic hosted + vendored e2e flow (each ending in the
# manifest-less VEX matrix) across yarn 1.x releases, and print the
# per-release x {hosted, vendored} x cell results table.
#
#   scripts/yarn-classic-vex-matrix.sh                 # default release list
#   scripts/yarn-classic-vex-matrix.sh 1.0.2 1.22.22   # chosen releases
#   YARN_CLASSIC_MATRIX_PRODUCTION=1 scripts/...       # + the live-production legs
#
# Each suite runs with SOCKET_PATCH_YARN_CLASSIC_E2E_VERSION=<release> and
# SOCKET_PATCH_YARN_E2E_REQUIRED=1, so a release corepack cannot fetch fails
# instead of skipping. Releases are fetched by corepack into the tests' cache
# sandbox (tests/common/cache_env.rs), never the caller's COREPACK_HOME.
#
# Release list: 1.0.2 (oldest 1.x) · 1.6.0 (last release that cannot install
# a `file:` tarball lock entry — vendored flows assert that limitation) ·
# 1.7.0 (oldest vendored-capable) · 1.9.4 (last release without the
# `integrity` lock field) · 1.10.1 (first with it) · 1.22.22 (latest).
set -uo pipefail

releases=("$@")
if [ ${#releases[@]} -eq 0 ]; then
  releases=(1.0.2 1.6.0 1.7.0 1.9.4 1.10.1 1.22.22)
fi

suites=(
  "e2e_redirect_yarn_classic_build:"
  "e2e_vendor_yarn_classic_build:"
  "e2e_vendor_yarn_classic_dev_flow:"
  "mode_migration_npm:classic"
)
if [ "${YARN_CLASSIC_MATRIX_PRODUCTION:-}" = 1 ]; then
  suites+=("e2e_hosted_production:yarn_classic:--ignored" "e2e_vendored_production:yarn_classic:--ignored")
fi

root="$(cd "$(dirname "$0")/.." && pwd)"
log="$(mktemp -t yarn-classic-vex-matrix.XXXXXX)"
status=0

for release in "${releases[@]}"; do
  for entry in "${suites[@]}"; do
    IFS=: read -r suite filter ignored <<<"$entry"
    echo "== yarn@$release $suite ${filter:-}" >&2
    if ! (cd "$root" && SOCKET_PATCH_YARN_CLASSIC_E2E_VERSION="$release" \
      SOCKET_PATCH_YARN_E2E_REQUIRED=1 \
      cargo test -q -p socket-patch-cli --test "$suite" -- ${filter:+"$filter"} \
      ${ignored:+"$ignored"} --nocapture --test-threads=1 >>"$log" 2>&1); then
      echo "FAIL yarn@$release $suite (log: $log)" >&2
      echo "VEXCELL leg=$suite yarn=$release mode=- cell=SUITE FAIL" >>"$log"
      status=1
    fi
  done
done

echo
printf '%-9s %-38s %-9s %-58s %s\n' release leg mode cell result
# `cargo test -q` prints its progress dots on the same line as a test's
# first output line, so match anywhere in the line.
grep -ohE '(VEXCELL|N/A|KNOWN LIMITATION) .*' "$log" | sed 's/^VEXCELL //' | while read -r line; do
  case "$line" in
    N/A*|KNOWN*) printf '%s\n' "$line" ;;
    *)
      leg=$(sed -n 's/.*leg=\([^ ]*\).*/\1/p' <<<"$line")
      rel=$(sed -n 's/.*yarn=\([^ ]*\).*/\1/p' <<<"$line")
      mode=$(sed -n 's/.*mode=\([^ ]*\).*/\1/p' <<<"$line")
      cell=$(sed -n 's/.*cell=\([^ ]*\).*/\1/p' <<<"$line")
      res=${line##* }
      printf '%-9s %-38s %-9s %-58s %s\n' "$rel" "$leg" "$mode" "$cell" "$res"
      ;;
  esac
done
echo "full log: $log" >&2
exit $status
