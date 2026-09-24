#!/usr/bin/env bash
# Replay every real-uv hosted + vendored e2e flow (each ending in the
# manifest-less VEX matrix) across uv releases, and print the per-release x
# {hosted, vendored} x lane x step results table.
#
#   scripts/uv-vex-matrix.sh                       # one release per 0.N line
#   scripts/uv-vex-matrix.sh 0.5.5 0.5.6           # chosen releases
#   UV_VEX_MATRIX_BIN_DIR=/tmp/uvbins scripts/...  # reuse downloaded binaries
#   UV_VEX_MATRIX_PYTHON=/path/to/python3.12 ...   # interpreter for `--python`
#   UV_VEX_MATRIX_PRODUCTION=1 scripts/...         # + the live-production uv legs
#
# uv is pre-1.0, so every 0.N line is a major: the default list is the latest
# release of each line from 0.1 (the first `uv lock`) through the newest, plus
# every 0.5 release around the documented 0.5.6 override/constraints boundary
# (0.5.3 = last documented-bad, 0.5.4 / 0.5.5 measured, 0.5.6): below it a
# plain `uv sync` re-resolves a transitive override to the registry and `uv
# sync --locked` rejects a repointed constraint — the lanes assert VEX
# follows what uv actually installs.
#
# Binaries come from the PyPI `uv` wheels (sha256-verified, the way
# scripts/backtest-uv.py fetches them) into UV_VEX_MATRIX_BIN_DIR (default: a
# temp dir, removed afterwards). Each suite runs with
# SOCKET_PATCH_UV_E2E_BIN / _VERSION / _PYTHON and
# SOCKET_PATCH_UV_E2E_REQUIRED=1, so a release that cannot run fails instead
# of skipping; flows a release lacks print `n/a`.
set -uo pipefail

releases=("$@")
if [ ${#releases[@]} -eq 0 ]; then
  releases=(0.1.45 0.2.37 0.3.5 0.4.30 0.5.3 0.5.4 0.5.5 0.5.6 0.6.17 0.7.22 0.8.24 0.9.30 0.10.12 0.11.33 0.12.17)
fi

root="$(cd "$(dirname "$0")/.." && pwd)"
bins="${UV_VEX_MATRIX_BIN_DIR:-}"
cleanup_bins=0
if [ -z "$bins" ]; then
  bins="$(mktemp -d -t uv-vex-bins.XXXXXX)"
  cleanup_bins=1
fi
log="$(mktemp -t uv-vex-matrix.XXXXXX)"
# The production legs drive uv through their own helpers: pin the
# interpreter for them via UV_PYTHON (the hermetic suites scrub UV_* and pass
# `--python` from SOCKET_PATCH_UV_E2E_PYTHON instead).
if [ -n "${UV_VEX_MATRIX_PYTHON:-}" ]; then
  export UV_PYTHON="$UV_VEX_MATRIX_PYTHON"
fi
status=0

python3 - "$bins" "${releases[@]}" <<'EOF' || exit 1
import hashlib, io, json, os, platform, sys, urllib.request, zipfile
root, versions = sys.argv[1], sys.argv[2:]
system, machine = platform.system(), platform.machine().lower()
arm = machine in ("arm64", "aarch64")
if system == "Darwin":
    marker, arch = "macosx", "arm64" if arm else "x86_64"
elif system == "Linux":
    marker, arch = "manylinux", "aarch64" if arm else "x86_64"
else:
    sys.exit("uv-vex-matrix: macOS or Linux only")
registry = json.load(urllib.request.urlopen("https://pypi.org/pypi/uv/json", timeout=90))
for v in versions:
    exe = os.path.join(root, v, "uv")
    if os.path.isfile(exe):
        continue
    f = next(f for f in registry["releases"][v] if marker in f["filename"] and arch in f["filename"])
    data = urllib.request.urlopen(f["url"], timeout=180).read()
    if hashlib.sha256(data).hexdigest() != f["digests"]["sha256"]:
        sys.exit("hash mismatch: " + f["filename"])
    z = zipfile.ZipFile(io.BytesIO(data))
    os.makedirs(os.path.dirname(exe), exist_ok=True)
    with open(exe, "wb") as out:
        out.write(z.read(next(n for n in z.namelist() if n.endswith("/uv"))))
    os.chmod(exe, 0o755)
    print("fetched uv", v, file=sys.stderr)
EOF

# suite:filters (space-separated):test selector
suites=(
  "e2e_redirect_uv_build:hosted_:--ignored"
  "e2e_vendor_pypi_build:uv_ vendored_:--include-ignored"
)
if [ "${UV_VEX_MATRIX_PRODUCTION:-}" = 1 ]; then
  suites+=(
    "e2e_hosted_production:pypi_uv_lock:--ignored"
    "e2e_vendored_production:pypi_uv_lock:--ignored"
  )
fi

for release in "${releases[@]}"; do
  for entry in "${suites[@]}"; do
    IFS=: read -r suite filter ignored <<<"$entry"
    # A lane can name several space-separated test-name filters.
    read -ra filters <<<"$filter"
    echo "== uv@$release $suite ${filter}" >&2
    if ! (cd "$root" && SOCKET_PATCH_UV_E2E_BIN="$bins/$release/uv" \
      SOCKET_PATCH_UV_E2E_VERSION="$release" \
      SOCKET_PATCH_UV_E2E_PYTHON="${UV_VEX_MATRIX_PYTHON:-}" \
      SOCKET_PATCH_UV_E2E_REQUIRED=1 \
      cargo test -q -p socket-patch-cli --all-features --test "$suite" -- "${filters[@]}" \
      "$ignored" --nocapture --test-threads=4 >>"$log" 2>&1); then
      echo "FAIL uv@$release $suite (log: $log)" >&2
      echo "UV-VEX uv=$release mode=- lane=$suite step=SUITE result=FAIL" >>"$log"
      status=1
    fi
  done
done

echo
printf '%-8s %-9s %-24s %-36s %s\n' uv mode lane step result
# `cargo test -q` prints progress dots on the same line as a test's first
# output line, so match anywhere in the line.
grep -ohE 'UV-VEX .*' "$log" | sort -V -u | while read -r line; do
  rel=$(sed -n 's/.* uv=\([^ ]*\).*/\1/p' <<<"$line")
  mode=$(sed -n 's/.* mode=\([^ ]*\).*/\1/p' <<<"$line")
  lane=$(sed -n 's/.* lane=\([^ ]*\).*/\1/p' <<<"$line")
  step=$(sed -n 's/.* step=\(.*\) result=.*/\1/p' <<<"$line")
  res=${line##* result=}
  printf '%-8s %-9s %-24s %-36s %s\n' "$rel" "$mode" "$lane" "$step" "$res"
done
echo "full log: $log" >&2
if [ "$cleanup_bins" = 1 ]; then
  rm -rf "$bins"
fi
exit $status
