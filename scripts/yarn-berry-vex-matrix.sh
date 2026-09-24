#!/usr/bin/env bash
# Run the real-yarn-berry hosted + vendored e2e suites — each ending in the
# manifest-less VEX matrix (tests/yarn_berry_common) — once per yarn 4
# release, plus the yarn 2 / 3 refusal suite, and print a
# release × flow × mode × cell results table.
#
#   scripts/yarn-berry-vex-matrix.sh                 # default release list
#   scripts/yarn-berry-vex-matrix.sh 4.0.0 4.18.0    # explicit releases
#
# Needs node + corepack (each release is fetched by corepack into the test
# cache sandbox, see tests/common/cache_env.rs) and registry access for the
# fixture installs. SOCKET_PATCH_YARN_E2E_REQUIRED=1 is exported so a
# toolchain/registry problem FAILS instead of soft-skipping.
set -euo pipefail

cd "$(dirname "$0")/.."
releases=("$@")
if [ ${#releases[@]} -eq 0 ]; then
  releases=(4.0.0 4.6.0 4.9.4 4.12.0 4.18.0)
fi
suites=(
  e2e_redirect_yarn_berry_build
  e2e_vendor_yarn_berry_build
  e2e_yarn4_pnpm_linker_build
  e2e_yarn4_workspaces_build
)
export SOCKET_PATCH_YARN_E2E_REQUIRED=1
export COREPACK_ENABLE_DOWNLOAD_PROMPT=0

log="$(mktemp -t yarn-berry-vex-matrix.XXXXXX)"
status=0
test_args=()
for s in "${suites[@]}"; do test_args+=(--test "$s"); done

for v in "${releases[@]}"; do
  echo "::group::yarn@$v" >&2
  if ! SOCKET_PATCH_YARN_BERRY_VERSION="$v" cargo test -p socket-patch-cli \
      --no-fail-fast "${test_args[@]}" -- --nocapture 2>&1 | tee -a "$log" >&2; then
    echo "FAIL yarn@$v" | tee -a "$log" >&2
    status=1
  fi
  echo "::endgroup::" >&2
done

echo "::group::yarn 2 / 3 refusal" >&2
if ! cargo test -p socket-patch-cli --test e2e_yarn_legacy_cachekey_refusal_build \
    -- --nocapture 2>&1 | tee -a "$log" >&2; then
  echo "FAIL legacy refusal" | tee -a "$log" >&2
  status=1
fi
echo "::endgroup::" >&2

echo
echo "| yarn | flow | mode | cell | result |"
echo "|---|---|---|---|---|"
grep -a '^VEX-MATRIX|' "$log" | sort -u | awk -F'|' '{printf "| %s | %s | %s | %s | %s |\n", $2, $3, $4, $5, $6}'
grep -a '^FAIL ' "$log" || true
rm -f "$log"
exit "$status"
