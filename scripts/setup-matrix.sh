#!/usr/bin/env bash
# =====================================================================
# setup-matrix.sh — orchestrate and query the `socket-patch setup`
# end-to-end test matrix.
#
# The matrix asks, for every supported ecosystem/package-manager:
# "does `socket-patch setup` configure things so that a normal install
# applies the project's patches?" Each case runs the flow driver
# (tests/setup_matrix/run-case.sh) which prepares a project + committed
# patch set, optionally runs `socket-patch setup`, runs the native
# install, and checks whether the patch landed on disk.
#
# Results are classified against the recorded baseline in matrix.json:
#   pass        meets the ideal AND matches the recorded baseline
#   known_gap   fails the ideal but exactly as recorded (expected today)
#   progress    better than the recorded baseline (update baseline!)
#   regression  diverged from the baseline the wrong way (this is the
#               only thing that makes `run` exit non-zero)
#   error       the driver could not produce a result
#
# Subcommands:
#   build  [--ecosystem E]...                 build base + per-ecosystem images
#   run    [--ecosystem E] [--pm P] [--scenario S] [--host] [--out FILE] [--verbose]
#   list   [--json]                           enumerate every matrix case
#   query  [--status S] [--ecosystem E] [--pm P] [--scenario S]   filter latest results
#   results                                   print the latest aggregate
#
# CLI/agent-friendly: `list`/`query`/`results` emit JSON; `run` writes a
# machine-readable report to tests/setup_matrix/results/latest.json.
# =====================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SM_DIR="$REPO_ROOT/tests/setup_matrix"
MATRIX="$SM_DIR/matrix.json"
DRIVER="$SM_DIR/run-case.sh"
RESULTS_DIR="$SM_DIR/results"
LATEST="$RESULTS_DIR/latest.json"

ALL_ECOSYSTEMS=(npm pypi cargo gem golang maven composer nuget deno)

die() { echo "error: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "'$1' is required but not on PATH"; }

usage() { sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'; }

need jq
[ -f "$MATRIX" ] || die "matrix spec not found: $MATRIX"

# Emit one TSV row per case, honoring filters. Covers all three layouts:
# single (targets x scenarios), workspace (workspace_targets x
# workspace_scenarios) and monorepo (monorepo_targets x monorepo_scenarios).
# Columns: id eco pm image hook_family baseline_supported package version
#          purl manifest_key apply_ecosystems scenario patchset run_setup
#          expect_applied layout
cases_tsv() { # $1=eco-filter ("" = all)  $2=pm-filter  $3=scenario-filter
  jq -r --arg eco "${1:-}" --arg pm "${2:-}" --arg scn "${3:-}" '
    def rows($targets; $scenarios; $layout):
      $targets[] as $t | $scenarios[] as $s
      | select($eco == "" or $t.ecosystem == $eco)
      | select($pm  == "" or $t.pm        == $pm)
      | select($scn == "" or $s.id        == $scn)
      | [ ($t.ecosystem + "/" + $t.pm + "/" + $s.id),
          $t.ecosystem, $t.pm, $t.image, ($t.hook_family // ""),
          ($t.baseline_supported|tostring),
          $t.package, $t.version, $t.purl, $t.manifest_key, $t.apply_ecosystems,
          $s.id, $s.patchset, ($s.run_setup|tostring), ($s.expect_applied|tostring),
          $layout ]
      | @tsv;
    rows(.targets; .scenarios; "single"),
    rows((.workspace_targets // []); (.workspace_scenarios // []); "workspace"),
    rows((.monorepo_targets // []);  (.monorepo_scenarios // []);  "monorepo")
  ' "$MATRIX"
}

marker()     { jq -r '.marker' "$MATRIX"; }
alt_marker() { jq -r '.alt_marker' "$MATRIX"; }

# --------------------------------------------------------------------- build
cmd_build() {
  local ecos=();
  while [ $# -gt 0 ]; do case "$1" in
    --ecosystem) ecos+=("$2"); shift 2;;
    *) die "build: unknown arg '$1'";;
  esac; done
  [ ${#ecos[@]} -eq 0 ] && ecos=("${ALL_ECOSYSTEMS[@]}")
  need docker
  echo ">> building base image" >&2
  docker build -f "$REPO_ROOT/tests/docker/Dockerfile.base" -t socket-patch-test-base:latest "$REPO_ROOT" \
    || die "base image build failed"
  local e
  for e in "${ecos[@]}"; do
    echo ">> building $e image" >&2
    docker build -f "$REPO_ROOT/tests/docker/Dockerfile.$e" -t "socket-patch-test-$e:latest" "$REPO_ROOT" \
      || die "$e image build failed"
  done
  echo ">> done" >&2
}

# --------------------------------------------------------------------- list
cmd_list() {
  local as_json=0
  while [ $# -gt 0 ]; do case "$1" in --json) as_json=1; shift;; *) die "list: unknown arg '$1'";; esac; done
  if [ "$as_json" = 1 ]; then
    jq '[ .targets[] as $t | .scenarios[] as $s |
          { id: ($t.ecosystem+"/"+$t.pm+"/"+$s.id), ecosystem:$t.ecosystem, pm:$t.pm,
            scenario:$s.id, image:$t.image, hook_family:$t.hook_family,
            baseline_supported:$t.baseline_supported, expect_applied:$s.expect_applied } ]' "$MATRIX"
  else
    printf '%-46s %-9s %-8s %-11s %-22s %s\n' ID ECO PM LAYOUT SCENARIO EXPECT
    cases_tsv "" "" "" | while IFS=$'\t' read -r id eco pm image hook bsup pkg ver purl key aeco scn pset rsetup expect layout; do
      printf '%-46s %-9s %-8s %-11s %-22s %s\n' "$id" "$eco" "$pm" "$layout" "$scn" "$expect"
    done
  fi
}

# --------------------------------------------------------------------- run
resolve_host_bin() {
  if [ -n "${SOCKET_PATCH_BIN:-}" ]; then echo "$SOCKET_PATCH_BIN"; return; fi
  for c in "$REPO_ROOT/target/release/socket-patch" "$REPO_ROOT/target/debug/socket-patch"; do
    [ -x "$c" ] && { echo "$c"; return; }
  done
  command -v socket-patch 2>/dev/null || echo ""
}

cmd_run() {
  local eco="" pm="" scn="" host=0 out="$LATEST" verbose=0
  while [ $# -gt 0 ]; do case "$1" in
    --ecosystem) eco="$2"; shift 2;;
    --pm)        pm="$2"; shift 2;;
    --scenario)  scn="$2"; shift 2;;
    --host)      host=1; shift;;
    --out)       out="$2"; shift 2;;
    --verbose)   verbose=1; shift;;
    *) die "run: unknown arg '$1'";;
  esac; done

  local MARK ALT; MARK="$(marker)"; ALT="$(alt_marker)"
  mkdir -p "$RESULTS_DIR"
  local jsonl; jsonl="$(mktemp)"

  if [ "$host" = 0 ]; then need docker; fi
  local host_bin=""
  if [ "$host" = 1 ]; then
    host_bin="$(resolve_host_bin)"
    [ -n "$host_bin" ] || die "host mode: no socket-patch binary found (build it or set SOCKET_PATCH_BIN)"
    echo ">> host mode, binary: $host_bin" >&2
  fi

  local total=0
  while IFS=$'\t' read -r id eco_ pm_ image hook bsup pkg ver purl key aeco scn_ pset rsetup expect layout; do
    [ -z "$id" ] && continue
    total=$((total+1))
    echo ">> [$total] $id (layout=$layout)" >&2

    # Common SM_* env for the driver.
    local -a base_env=(
      "SM_ID=$id" "SM_ECOSYSTEM=$eco_" "SM_PM=$pm_" "SM_SCENARIO=$scn_"
      "SM_LAYOUT=$layout"
      "SM_PATCHSET=$pset" "SM_RUN_SETUP=$([ "$rsetup" = true ] && echo 1 || echo 0)"
      "SM_EXPECT_APPLIED=$([ "$expect" = true ] && echo 1 || echo 0)"
      "SM_PACKAGE=$pkg" "SM_VERSION=$ver" "SM_PURL=$purl"
      "SM_MANIFEST_KEY=$key" "SM_APPLY_ECOSYSTEMS=$aeco"
      "SM_MARKER=$MARK" "SM_ALT_MARKER=$ALT"
    )

    local raw="" rc=0
    if [ "$host" = 1 ]; then
      if [ "$verbose" = 1 ]; then
        raw="$(env "${base_env[@]}" "SOCKET_PATCH_BIN=$host_bin" bash "$DRIVER")"; rc=$?
      else
        raw="$(env "${base_env[@]}" "SOCKET_PATCH_BIN=$host_bin" bash "$DRIVER" 2>/dev/null)"; rc=$?
      fi
    else
      local -a docker_env=()
      local kv; for kv in "${base_env[@]}"; do docker_env+=(-e "$kv"); done
      if [ "$verbose" = 1 ]; then
        raw="$(docker run --rm "${docker_env[@]}" "socket-patch-test-$image:latest" bash -c "$(cat "$DRIVER")")"; rc=$?
      else
        raw="$(docker run --rm "${docker_env[@]}" "socket-patch-test-$image:latest" bash -c "$(cat "$DRIVER")" 2>/dev/null)"; rc=$?
      fi
    fi

    # The driver prints the result JSON as the last line of stdout.
    local result; result="$(printf '%s\n' "$raw" | grep -E '^\{.*"actual_applied"' | tail -n1)"

    # baseline_applied = expect_applied AND baseline_supported.
    local bl=false
    if [ "$expect" = true ] && [ "$bsup" = true ]; then bl=true; fi

    if [ -n "$result" ] && printf '%s' "$result" | jq -e . >/dev/null 2>&1; then
      printf '%s\n' "$result" | jq -c --argjson bl "$bl" --arg img "$image" --arg hk "$hook" --arg lay "$layout" '
        . as $r |
        ($r.actual_applied == $r.expect_applied) as $ideal |
        ($r.actual_applied == $bl) as $base |
        (if $ideal and $base then "pass"
         elif $ideal and ($base|not) then "progress"
         elif ($ideal|not) and $base then "known_gap"
         else "regression" end) as $cls |
        $r + {baseline_applied:$bl, classification:$cls, layout:$lay, image:$img, hook_family:$hk, driver_rc:'"$rc"'}
      ' >> "$jsonl"
    else
      # No parseable result — surface as an error case.
      jq -nc --arg id "$id" --arg eco "$eco_" --arg pm "$pm_" --arg scn "$scn_" \
             --arg pset "$pset" --arg img "$image" --arg hk "$hook" --arg lay "$layout" --argjson bl "$bl" '
        { id:$id, ecosystem:$eco, pm:$pm, scenario:$scn, patchset:$pset,
          expect_applied:null, actual_applied:null, baseline_applied:$bl,
          classification:"error", layout:$lay, image:$img, hook_family:$hk, driver_rc:'"$rc"',
          notes:"driver produced no parseable result" }' >> "$jsonl"
    fi
  done < <(cases_tsv "$eco" "$pm" "$scn")

  # Aggregate + summarize.
  jq -s --arg generated "$(date -u +%FT%TZ)" '
    { generated:$generated,
      summary: ( reduce .[] as $c (
                   {total:0,pass:0,known_gap:0,progress:0,regression:0,error:0};
                   .total += 1 | .[$c.classification] += 1 ) ),
      cases: . }' "$jsonl" > "$out"
  rm -f "$jsonl"
  [ "$out" != "$LATEST" ] && cp "$out" "$LATEST"

  print_summary "$out"
  local regressions; regressions="$(jq -r '.summary.regression' "$out")"
  if [ "$regressions" -gt 0 ]; then
    echo "!! $regressions regression(s) — a case that should work no longer does" >&2
    return 1
  fi
  return 0
}

print_summary() { # $1 = results file
  local f="$1"
  echo "" >&2
  printf '%-44s %-8s %-6s %-6s %s\n' CASE PM APPLIED EXPECT STATUS >&2
  jq -r '.cases[] | [ .id, .pm, (.actual_applied|tostring), (.expect_applied|tostring), .classification ] | @tsv' "$f" \
    | while IFS=$'\t' read -r id pm act exp cls; do
        printf '%-44s %-8s %-6s %-6s %s\n' "$id" "$pm" "$act" "$exp" "$cls" >&2
      done
  echo "" >&2
  jq -r '.summary | "total=\(.total) pass=\(.pass) known_gap=\(.known_gap) progress=\(.progress) regression=\(.regression) error=\(.error)"' "$f" >&2
  local prog; prog="$(jq -r '.summary.progress' "$f")"
  [ "$prog" -gt 0 ] && echo ">> $prog case(s) now BETTER than baseline — consider updating baseline_supported in matrix.json" >&2
  echo ">> full report: $f" >&2
}

# --------------------------------------------------------------------- query / results
cmd_query() {
  local status="" eco="" pm="" scn="" lay=""
  while [ $# -gt 0 ]; do case "$1" in
    --status) status="$2"; shift 2;;
    --ecosystem) eco="$2"; shift 2;;
    --pm) pm="$2"; shift 2;;
    --scenario) scn="$2"; shift 2;;
    --layout) lay="$2"; shift 2;;
    *) die "query: unknown arg '$1'";;
  esac; done
  [ -f "$LATEST" ] || die "no results yet — run '$0 run' first"
  jq --arg st "$status" --arg eco "$eco" --arg pm "$pm" --arg scn "$scn" --arg lay "$lay" '
    [ .cases[]
      | select($st  == "" or .classification == $st)
      | select($eco == "" or .ecosystem == $eco)
      | select($pm  == "" or .pm == $pm)
      | select($scn == "" or .scenario == $scn)
      | select($lay == "" or .layout == $lay) ]' "$LATEST"
}

cmd_results() {
  [ -f "$LATEST" ] || die "no results yet — run '$0 run' first"
  cat "$LATEST"
}

# --------------------------------------------------------------------- dispatch
[ $# -ge 1 ] || { usage; exit 1; }
sub="$1"; shift || true
case "$sub" in
  build)   cmd_build "$@";;
  run)     cmd_run "$@";;
  list)    cmd_list "$@";;
  query)   cmd_query "$@";;
  results) cmd_results "$@";;
  -h|--help|help) usage;;
  *) die "unknown subcommand '$sub' (try: build run list query results)";;
esac
