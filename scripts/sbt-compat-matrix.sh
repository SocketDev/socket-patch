#!/usr/bin/env bash
# sbt / Mill / scala-cli compatibility matrix: one entry point for local runs
# and CI legs (docs/testing/sbt-compatibility.md).
#
#   scripts/sbt-compat-matrix.sh --group <agent|hosted|vendored|scala-cli|mill>
#       [--version <tool version>] [--jdk <8|17|21>] [--filter <test name substring>]
#       [--rebuild-image] [--skip-build] [--list]
#   scripts/sbt-compat-matrix.sh --build-only
#
# 1. Builds the Linux socket-patch binary and the real-tool test binaries
#    (docker_e2e_sbt's host side included) ONCE, in a pinned rust
#    container, into $SBT_MATRIX_TARGET
#    (default <repo>/target/linux; cargo's own incremental checks make
#    later runs cheap). The repository is mounted at its own absolute path,
#    so the test binaries' compiled-in paths (CARGO_MANIFEST_DIR,
#    CARGO_BIN_EXE_socket-patch) are valid in the run containers too.
# 2. Uses (or builds) the tests/docker/Dockerfile.sbt image.
# 3. Runs one group for one tool version and JDK, printing PASS / FAIL /
#    SKIP per test, and exits non-zero when any test failed.
#
# --build-only stops after step 1 and prints the absolute paths of what it
# built (the binary, the test binaries and their index), one per line, so a
# CI job can build once and hand the files to every leg (`--skip-build`).
#
# Groups:
#   agent      docker_e2e_sbt agent_sbt_* cells (on the host: the prebuilt
#              test binary on Linux, else cargo test with feature
#              docker-e2e; each cell runs `scan` / `rollback` inside the
#              image with the Linux binary from step 1 mounted).
#   hosted     e2e_sbt_build (real sbt, hosted socket-patch.sbt), whole test
#              binary inside the image, sbt native there.
#   vendored   e2e_sbt_vendor_build (real sbt, socket-patch-vendor.sbt),
#              likewise inside the image.
#   scala-cli  the scala-cli agent cell (host) + e2e_scala_cli_vendor's
#              real-tool test (inside the image). The image pins one
#              scala-cli (1.17.1); --version must match it.
#   mill       the Mill agent cell (host): --version 0.11.13, 0.12.17 or
#              1.1.10 (the image's Mill launchers; default 1.1.10).
#
# Defaults: --version 1.13.0 for sbt groups; --jdk 8 for sbt <= 1.3.x, else
# 17 (Mill and scala-cli: 17).
#
# Environment:
#   SBT_MATRIX_IMAGE       image tag (default socket-patch-test-sbt:latest)
#   SBT_MATRIX_TARGET      Linux cargo target dir (default <repo>/target/linux)
#   SBT_MATRIX_RUST_IMAGE  build image (default: the pinned rust 1.93.1)
#   SBT_MATRIX_JOBS        CARGO_BUILD_JOBS for the Linux build (default 4)
#   SBT_MATRIX_MEMORY      docker -m for every container (default 2g; the
#                          Linux build gets SBT_MATRIX_BUILD_MEMORY, default 4g)
#   SBT_MATRIX_LOG_DIR     where raw logs go (default $SBT_MATRIX_TARGET/sbt-matrix-logs)
#   SBT_MATRIX_SEED        a warm cache for the in-image groups (default
#                          /root, the image's baked caches; "none" = cold)
set -uo pipefail

usage() { sed -n '2,/^# Defaults:/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit "${1:-2}"; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GROUP=""
VERSION=""
JDK=""
FILTER=""
REBUILD_IMAGE=""
SKIP_BUILD=""
LIST=""
BUILD_ONLY=""
while [ $# -gt 0 ]; do
  case "$1" in
    --group) GROUP="${2:-}"; shift 2 ;;
    --version) VERSION="${2:-}"; shift 2 ;;
    --jdk) JDK="${2:-}"; shift 2 ;;
    --filter) FILTER="${2:-}"; shift 2 ;;
    --rebuild-image) REBUILD_IMAGE=1; shift ;;
    --skip-build) SKIP_BUILD=1; shift ;;
    --list) LIST=1; shift ;;
    --build-only) BUILD_ONLY=1; shift ;;
    -h|--help) usage 0 ;;
    *) echo "unknown argument: $1" >&2; usage ;;
  esac
done

IMAGE="${SBT_MATRIX_IMAGE:-socket-patch-test-sbt:latest}"
TARGET="${SBT_MATRIX_TARGET:-$ROOT/target/linux}"
RUST_IMAGE="${SBT_MATRIX_RUST_IMAGE:-rust@sha256:5b9332190bb3b9ece73b810cd1f1e9f06343b294ce184bcb067f0747d7d333ea}"
JOBS="${SBT_MATRIX_JOBS:-4}"
MEMORY="${SBT_MATRIX_MEMORY:-2g}"
BUILD_MEMORY="${SBT_MATRIX_BUILD_MEMORY:-4g}"
LOG_DIR="${SBT_MATRIX_LOG_DIR:-$TARGET/sbt-matrix-logs}"
SEED="${SBT_MATRIX_SEED:-/root}"
SCALA_CLI_IMAGE_VERSION=1.17.1
MILL_IMAGE_VERSION=1.1.10
MILL_IMAGE_VERSIONS="0.11.13 0.12.17 1.1.10"

if [ -n "$LIST" ]; then
  cat <<EOF
groups:    agent hosted vendored scala-cli mill
sbt:       any sbt.version the launcher can fetch; probed: 0.13.18 1.2.8 1.3.13 1.9.9 1.13.0 2.0.9
scala-cli: $SCALA_CLI_IMAGE_VERSION (the image's)
mill:      $MILL_IMAGE_VERSIONS (the image's Mill launchers)
jdk:       8 17 21 (/opt/jdk<N> in the image)
EOF
  exit 0
fi

case "$GROUP" in
  agent|hosted|vendored) VERSION="${VERSION:-1.13.0}" ;;
  scala-cli) VERSION="${VERSION:-$SCALA_CLI_IMAGE_VERSION}"
    [ "$VERSION" = "$SCALA_CLI_IMAGE_VERSION" ] || { echo "scala-cli $VERSION: the image pins $SCALA_CLI_IMAGE_VERSION" >&2; exit 2; } ;;
  mill) VERSION="${VERSION:-$MILL_IMAGE_VERSION}"
    case " $MILL_IMAGE_VERSIONS " in *" $VERSION "*) ;; *) echo "mill $VERSION: the image has $MILL_IMAGE_VERSIONS" >&2; exit 2 ;; esac ;;
  "") [ -n "$BUILD_ONLY" ] || { echo "--group is required" >&2; usage; } ;;
  *) echo "unknown group: $GROUP" >&2; usage ;;
esac
if [ -z "$JDK" ]; then
  case "$GROUP:$VERSION" in
    agent:0.*|agent:1.[0-3].*|hosted:0.*|hosted:1.[0-3].*|vendored:0.*|vendored:1.[0-3].*) JDK=8 ;;
    *) JDK=17 ;;
  esac
fi
case "$JDK" in 8|17|21) ;; *) echo "--jdk must be 8, 17 or 21" >&2; exit 2 ;; esac

mkdir -p "$TARGET" "$LOG_DIR"
command -v docker >/dev/null || { echo "docker is required" >&2; exit 2; }

# ── 1. the Linux binaries ────────────────────────────────────────────────
TESTS_JSON="$TARGET/sbt-matrix-tests.json"
if [ -z "$SKIP_BUILD" ]; then
  echo "== building the Linux socket-patch and test binaries into $TARGET" >&2
  docker run --rm -m "$BUILD_MEMORY" \
    -v "$ROOT:$ROOT" -w "$ROOT" \
    -v socket-patch-sbt-matrix-cargo:/usr/local/cargo/registry \
    -e CARGO_TARGET_DIR="$TARGET" -e CARGO_BUILD_JOBS="$JOBS" -e CARGO_INCREMENTAL=0 \
    -e CARGO_PROFILE_DEV_DEBUG=0 \
    "$RUST_IMAGE" bash -c '
      set -euo pipefail
      cargo build --locked -p socket-patch-cli --bin socket-patch
      cargo test --locked -p socket-patch-cli --no-run --message-format=json \
        --test e2e_sbt_build --test e2e_sbt_vendor_build --test e2e_scala_cli_vendor \
        > "$CARGO_TARGET_DIR/sbt-matrix-tests.json"
      cargo test --locked -p socket-patch-cli --no-run --message-format=json \
        --features docker-e2e --test docker_e2e_sbt \
        >> "$CARGO_TARGET_DIR/sbt-matrix-tests.json"' \
    || { echo "FAIL linux-build" >&2; exit 1; }
  if [ "$(uname -s)" = Linux ]; then
    # The build container runs as root; hand the cache back.
    docker run --rm -v "$TARGET:$TARGET" "$RUST_IMAGE" chown -R "$(id -u):$(id -g)" "$TARGET" || true
  fi
fi
BIN="$TARGET/debug/socket-patch"
[ -x "$BIN" ] || { echo "no Linux binary at $BIN (drop --skip-build)" >&2; exit 2; }

test_exe() {
  # The executable cargo built for integration test $1.
  grep '"executable":"' "$TESTS_JSON" 2>/dev/null \
    | sed -nE 's/^.*"target":\{[^}]*"name":"([^"]+)".*"executable":"([^"]+)".*$/\1 \2/p' \
    | awk -v t="$1" '$1 == t { print $2 }' | tail -1
}

if [ -n "$BUILD_ONLY" ]; then
  echo "$BIN"
  echo "$TESTS_JSON"
  for t in e2e_sbt_build e2e_sbt_vendor_build e2e_scala_cli_vendor docker_e2e_sbt; do
    exe=$(test_exe "$t")
    [ -n "$exe" ] && [ -x "$exe" ] || { echo "FAIL linux-build: no $t test binary" >&2; exit 1; }
    echo "$exe"
  done
  exit 0
fi

# ── 2. the image ─────────────────────────────────────────────────────────
if [ -n "$REBUILD_IMAGE" ] || ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "== building $IMAGE" >&2
  docker image inspect socket-patch-test-base:latest >/dev/null 2>&1 \
    || docker build -t socket-patch-test-base:latest -f "$ROOT/tests/docker/Dockerfile.base" "$ROOT" \
    || { echo "FAIL image-base" >&2; exit 1; }
  docker build -t "$IMAGE" -f "$ROOT/tests/docker/Dockerfile.sbt" "$ROOT/tests/docker" \
    || { echo "FAIL image" >&2; exit 1; }
fi

# ── 3. the group ─────────────────────────────────────────────────────────
STATUS=0
report() {
  # PASS / FAIL / SKIP per `test <name> ... <result>` line of log $1.
  local log="$1" label="$2"
  local lines
  lines=$(grep -E '^test [^ ]+ \.\.\. ' "$log" || true)
  if [ -z "$lines" ]; then
    echo "FAIL $label (no test ran; see $log)"
    STATUS=1
    return
  fi
  while IFS= read -r line; do
    name=$(echo "$line" | awk '{print $2}')
    case "$line" in
      *"... ok") echo "PASS $label $name" ;;
      *"... ignored"*) echo "SKIP $label $name" ;;
      *) echo "FAIL $label $name"; STATUS=1 ;;
    esac
  done <<< "$lines"
  if grep -q '^SKIP ' "$log"; then
    grep '^SKIP ' "$log" | sed "s/^/NOTE $label /"
  fi
  if ! grep -qE '^test result: ok\.' "$log"; then
    STATUS=1
  fi
}

# In-image: the whole test binary $1 inside the image, sbt native there.
in_image() {
  local test="$1"; shift
  local exe
  exe=$(test_exe "$test")
  [ -n "$exe" ] && [ -x "$exe" ] || { echo "FAIL $test (no test binary; drop --skip-build)"; STATUS=1; return; }
  local log="$LOG_DIR/$GROUP-$test-$VERSION-jdk$JDK.log"
  local seed_env=()
  [ "$SEED" = none ] || seed_env=(-e "SOCKET_PATCH_SBT_E2E_SEED=$SEED")
  echo "== $test: $GROUP $VERSION, JDK $JDK (log: $log)" >&2
  docker run --rm -m "$MEMORY" \
    -v "$ROOT:$ROOT" -w "$ROOT/crates/socket-patch-cli" \
    -e JAVA_HOME="/opt/jdk$JDK" \
    -e PATH="/opt/jdk$JDK/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    -e SOCKET_PATCH_SBT_E2E_SBT=/opt/sbt/bin/sbt \
    -e SOCKET_PATCH_SBT_E2E_VERSION="$VERSION" \
    -e SOCKET_PATCH_SBT_E2E_REQUIRED=1 \
    -e SOCKET_PATCH_SCALA_CLI_E2E_BIN=/usr/local/bin/scala-cli \
    -e SOCKET_PATCH_SCALA_CLI_E2E_REQUIRED=1 \
    -e SOCKET_PATCH_SCALA_CLI_E2E_CACHE=/root/.cache/coursier/v1 \
    -e TMPDIR=/tmp -e RUST_BACKTRACE=1 \
    ${seed_env[@]+"${seed_env[@]}"} \
    "$IMAGE" "$exe" --ignored --test-threads=1 ${1+"$@"} > "$log" 2>&1
  report "$log" "${test}[$VERSION,jdk$JDK]"
}

# On the host: docker_e2e_sbt cells matching $1 (each cell is a container).
# On Linux the test binary step 1 built runs directly (no host toolchain,
# no recompile per CI leg); elsewhere cargo builds it for the host.
host_cells() {
  local filter="$1"
  local log="$LOG_DIR/$GROUP-docker_e2e_sbt-$VERSION-jdk$JDK.log"
  local exe=""
  [ "$(uname -s)" = Linux ] && exe=$(test_exe docker_e2e_sbt)
  local mill_versions=""
  [ "$GROUP" = mill ] && mill_versions="$VERSION"
  echo "== docker_e2e_sbt $filter: $VERSION, JDK $JDK (log: $log)" >&2
  export SOCKET_PATCH_DOCKER_E2E_REQUIRED=1 \
    SOCKET_PATCH_DOCKER_BIN="$BIN" \
    SOCKET_PATCH_SBT_DOCKER_IMAGE="$IMAGE" \
    SOCKET_PATCH_SBT_DOCKER_VERSIONS="$VERSION" \
    SOCKET_PATCH_MILL_DOCKER_VERSIONS="$mill_versions" \
    SOCKET_PATCH_SBT_DOCKER_JDK="$JDK"
  if [ -n "$exe" ] && [ -x "$exe" ]; then
    "$exe" --test-threads=1 "$filter" > "$log" 2>&1
  else
    cargo test --manifest-path "$ROOT/Cargo.toml" -p socket-patch-cli --features docker-e2e \
      --test docker_e2e_sbt -- --test-threads=1 "$filter" > "$log" 2>&1
  fi
  report "$log" "docker_e2e_sbt[$VERSION,jdk$JDK]"
}

filter_args=()
[ -n "$FILTER" ] && filter_args=("$FILTER")
case "$GROUP" in
  agent) host_cells "${FILTER:-agent_sbt_}" ;;
  hosted) in_image e2e_sbt_build ${filter_args[@]+"${filter_args[@]}"} ;;
  vendored) in_image e2e_sbt_vendor_build ${filter_args[@]+"${filter_args[@]}"} ;;
  scala-cli)
    host_cells "${FILTER:-scala_tools_agent_scala_cli}"
    in_image e2e_scala_cli_vendor "${FILTER:-real_tool}" ;;
  mill) host_cells "${FILTER:-scala_tools_agent_mill}" ;;
esac

if [ "$STATUS" = 0 ]; then
  echo "RESULT PASS $GROUP $VERSION jdk$JDK"
else
  echo "RESULT FAIL $GROUP $VERSION jdk$JDK"
fi
exit "$STATUS"
