#!/usr/bin/env bash
# Deterministic socket-patch network benchmark driver (see scripts/perf/README.md).
#
#   bench.sh record STORE -- <socket-patch args...>
#   bench.sh replay STORE [LATENCY_MS|recorded] [RUNS]  -- <socket-patch args...>
#   bench.sh ab     STORE [LATENCY_MS|recorded] [PAIRS] -- <socket-patch args...>
#
# record  runs BIN once against the real services through replay.py, filling
#         STORE with every response.
# replay  runs BIN RUNS times against STORE only (no network).
# ab      runs BASE and NEW interleaved (BASE, NEW, BASE, NEW, ...) PAIRS times
#         against STORE and fails unless every run's exit code and stdout
#         sha256 equal the first BASE run's.
#
# Env knobs:
#   CWD=/path/to/project   (required; passed as --cwd)
#   BIN=/path/to/binary    (record/replay; default: <repo>/target/release/socket-patch)
#   BASE=... NEW=...       (ab; the two binaries to compare)
#   PORT=18080             (api.socket.dev stand-in; PORT+1 = patch.socket.dev,
#                           PORT+2 = patches-api.socket.dev public proxy)
#   CONN_MS=0              (replay/ab: extra latency per new TCP connection)
#   FILL=1                 (replay/ab: forward + record misses instead of 599)
#   PRE_RUN='cmd'          (shell command run before every CLI invocation,
#                           e.g. restoring a wet-run copy of the project)
#   OUT=dir                (per-run stdout/stderr/stats; default STORE/runs)
#
# The CLI is pointed at the stand-ins with SOCKET_API_URL, SOCKET_PROXY_URL and
# SOCKET_PATCH_SERVER_URL; the API token / org come from the usual config, and
# must match between record and replay (they choose the routes the CLI takes).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"

usage() { awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0" >&2; exit 2; }
[[ $# -ge 2 ]] || usage
MODE="$1"; STORE="$2"; shift 2
case "$MODE" in record|replay|ab) ;; *) usage ;; esac
LAT=0; RUNS=1
if [[ "$MODE" != record ]]; then
  if [[ $# -gt 0 && "$1" != -- ]]; then LAT="$1"; shift; fi
  if [[ $# -gt 0 && "$1" != -- ]]; then RUNS="$1"; shift; fi
fi
if [[ $# -gt 0 && "$1" == -- ]]; then shift; fi
[[ $# -gt 0 ]] || usage

: "${CWD:?set CWD to the project directory to scan}"
if [[ "$MODE" == ab ]]; then
  : "${BASE:?set BASE to the baseline binary}"; : "${NEW:?set NEW to the candidate binary}"
  BINS=()
  for _ in $(seq "$RUNS"); do BINS+=("$BASE" "$NEW"); done
else
  BIN="${BIN:-$REPO/target/release/socket-patch}"
  BINS=()
  for _ in $(seq "$RUNS"); do BINS+=("$BIN"); done
fi
for b in "${BINS[@]}"; do [[ -x "$b" ]] || { echo "not an executable: $b" >&2; exit 2; }; done

# Recorded responses may carry paid-patch data: never let a store land in git.
realpath_() { python3 -c 'import os, sys; print(os.path.realpath(sys.argv[1]))' "$1"; }
STORE="$(realpath_ "$STORE")"
case "$STORE/" in
  "$(realpath_ "$REPO")/"*) echo "refusing a STORE inside the repository: $STORE" >&2; exit 2 ;;
esac
mkdir -p "$STORE"

PORT="${PORT:-18080}"; PATCH_PORT="$((PORT + 1))"; PROXY_PORT="$((PORT + 2))"
OUT="${OUT:-$STORE/runs}"; mkdir -p "$OUT"

lat_args=(--latency-ms 0); lat_tag="${LAT}ms"
if [[ "$MODE" != record ]]; then
  if [[ "$LAT" == recorded ]]; then lat_args=(--latency recorded); lat_tag=recorded; else lat_args=(--latency-ms "$LAT"); fi
fi
proxy_mode=replay; [[ "$MODE" == record ]] && proxy_mode=record
fill_args=(); [[ -n "${FILL:-}" ]] && fill_args=(--fill)

python3 "$HERE/replay.py" "$proxy_mode" --store "$STORE" "${lat_args[@]}" \
  --conn-latency-ms "${CONN_MS:-0}" \
  --route "$PORT=https://api.socket.dev" \
  --route "$PATCH_PORT=https://patch.socket.dev" \
  --route "$PROXY_PORT=https://patches-api.socket.dev" \
  ${fill_args[@]+"${fill_args[@]}"} --stats-file "$OUT/last-proxy-stats.json" 2>"$OUT/proxy.log" &
PROXY=$!
trap 'kill $PROXY 2>/dev/null; wait $PROXY 2>/dev/null || true' EXIT
up=0
for _ in $(seq 200); do
  kill -0 $PROXY 2>/dev/null || { echo "replay.py died:"; cat "$OUT/proxy.log"; exit 1; } >&2
  grep -q "127.0.0.1:$PROXY_PORT" "$OUT/proxy.log" 2>/dev/null && { up=1; break; }
  sleep 0.05
done
[[ $up == 1 ]] || { echo "replay.py did not start (see $OUT/proxy.log)" >&2; exit 1; }

now() { perl -MTime::HiRes=time -e 'printf "%.3f", time'; }
sha() { shasum -a 256 "$1" | cut -c1-64; }

ref_sha=; ref_rc=; mismatches=0; i=0
summary="$OUT/$MODE-summary.tsv"
printf 'tag\tbin\trc\twall_s\tstdout_sha256\tstderr_sha256\n' >"$summary"
for b in "${BINS[@]}"; do
  i=$((i + 1))
  label=run; [[ "$MODE" == ab ]] && { [[ $((i % 2)) == 1 ]] && label=base || label=new; }
  tag="$MODE-$lat_tag-$i-$label"
  [[ -n "${PRE_RUN:-}" ]] && bash -c "$PRE_RUN"
  curl -sf -X POST "http://127.0.0.1:$PORT/__reset" >/dev/null
  start=$(now)
  set +e
  SOCKET_API_URL="http://127.0.0.1:$PORT" \
  SOCKET_PROXY_URL="http://127.0.0.1:$PROXY_PORT" \
  SOCKET_PATCH_SERVER_URL="http://127.0.0.1:$PATCH_PORT" \
  SOCKET_NO_UPDATE_CHECK=1 SOCKET_TELEMETRY_DISABLED=1 \
    "$b" "$@" --cwd "$CWD" >"$OUT/$tag.stdout" 2>"$OUT/$tag.stderr"
  rc=$?
  set -e
  end=$(now)
  curl -sf "http://127.0.0.1:$PORT/__stats" >"$OUT/$tag.stats.json"
  out_sha=$(sha "$OUT/$tag.stdout"); err_sha=$(sha "$OUT/$tag.stderr")
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$tag" "$b" "$rc" \
    "$(python3 -c 'import sys; print("%.3f" % (float(sys.argv[2]) - float(sys.argv[1])))' "$start" "$end")" \
    "$out_sha" "$err_sha" >>"$summary"
  same=
  if [[ "$MODE" == ab ]]; then
    if [[ -z "$ref_sha" ]]; then ref_sha=$out_sha; ref_rc=$rc; same=ref
    elif [[ "$out_sha" == "$ref_sha" && "$rc" == "$ref_rc" ]]; then same=same
    else same=DIFFERS; mismatches=$((mismatches + 1)); fi
  fi
  python3 - "$OUT/$tag.stats.json" "$start" "$end" "$rc" "$tag" "$out_sha" "$same" <<'EOF'
import json, sys
s = json.load(open(sys.argv[1])); wall = float(sys.argv[3]) - float(sys.argv[2])
same = f" vs_base={sys.argv[7]}" if sys.argv[7] else ""
print(f"{sys.argv[5]:<24} rc={sys.argv[4]} wall={wall:6.2f}s stdout={sys.argv[6][:12]}{same} "
      f"requests={s['requests']:4d} max_inflight={s['max_inflight']:2d} conns={s['connections']:3d} "
      f"misses={s['misses']} unknown_purls={s['batch_unknown_purls']} net_span={s['network_span_s']}s "
      f"first_req={s['first_request_s']}s par={s['avg_parallelism']} by_kind={s['by_kind']}")
EOF
done

if [[ "$MODE" == ab ]]; then
  python3 - "$summary" <<'EOF'
import csv, statistics, sys
rows = list(csv.DictReader(open(sys.argv[1]), delimiter="\t"))
for label in ("base", "new"):
    walls = [float(r["wall_s"]) for r in rows if r["tag"].endswith("-" + label)]
    print(f"{label:<4} median wall {statistics.median(walls):6.2f}s  runs={len(walls)}  "
          f"min={min(walls):.2f}s max={max(walls):.2f}s")
errs = {r["stderr_sha256"] for r in rows}
print("stderr: identical across runs" if len(errs) == 1 else
      f"stderr: {len(errs)} distinct outputs across runs (diff the .stderr files under the OUT dir)")
EOF
  if [[ $mismatches -gt 0 ]]; then
    echo "FAIL: $mismatches run(s) differ from the first BASE run (stdout sha256 or exit code)" >&2
    exit 1
  fi
  echo "OK: every run's stdout sha256 and exit code match the first BASE run"
fi
