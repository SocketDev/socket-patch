#!/usr/bin/env bash
# =====================================================================
# setup-matrix flow driver — runs ONE (ecosystem, pm, scenario) case of
# the `socket-patch setup` end-to-end matrix and emits a JSON result.
#
# This script is the single source of truth for the flow:
#   0. prepare a project with the dependency + a committed patch set
#   1. (optionally) run `socket-patch setup` to configure install hooks
#   2. run the native install command for the package manager
#   3. check whether the patch was applied (marker present on disk)
#
# It is invoked by BOTH scripts/setup-matrix.sh (orchestrator) and the
# Rust wrappers (crates/socket-patch-cli/tests/setup_matrix_<eco>.rs),
# either inside a Docker container (script piped to `bash -c`) or on the
# host. It is fully self-contained: it generates the npx/pnpm shims
# inline so no extra files need to be copied into the container.
#
# The driver only REPORTS (expected vs actual). Pass/fail/known-gap/
# regression classification is done by the caller against the recorded
# baseline in matrix.json.
#
# Inputs (environment, all SM_*-prefixed):
#   SM_ID                stable case id (for the JSON result)
#   SM_ECOSYSTEM         npm|pypi|cargo|gem|golang|maven|composer|nuget|deno
#   SM_PM                npm|yarn|pnpm|bun|pip|uv|poetry|pdm|hatch|cargo|
#                        bundler|go|mvn|composer|dotnet|deno
#   SM_SCENARIO          scenario id (echoed back)
#   SM_PATCHSET          primary|alt|empty|wrong
#   SM_RUN_SETUP         1|0  — run `socket-patch setup` before install
#   SM_EXPECT_APPLIED    1|0  — the aspirational expectation
#   SM_PACKAGE           dependency name (e.g. minimist, six, cfg-if)
#   SM_VERSION           dependency version (e.g. 1.2.2)
#   SM_PURL              manifest key PURL (e.g. pkg:npm/minimist@1.2.2)
#   SM_MANIFEST_KEY      file key in the patch record (e.g. package/index.js,
#                        or `six.py` for pypi — NO package/ prefix)
#   SM_APPLY_ECOSYSTEMS  ecosystem token used to build the "wrong" PURL
#   SM_MARKER            primary marker string spliced into the patched blob
#   SM_ALT_MARKER        alternate marker (alt_content_patchset)
#   SOCKET_PATCH_BIN     path to the binary under test (default: socket-patch on PATH)
#   SM_WORKDIR           scratch dir (default: a fresh mktemp -d)
# =====================================================================

set -uo pipefail

# Route all ordinary output to stderr; the final JSON goes to the saved
# stdout (fd 3) so the result line is the ONLY thing on real stdout.
exec 3>&1 1>&2

SM_ID="${SM_ID:-unknown}"
SM_ECOSYSTEM="${SM_ECOSYSTEM:-}"
SM_PM="${SM_PM:-}"
SM_SCENARIO="${SM_SCENARIO:-}"
SM_PATCHSET="${SM_PATCHSET:-primary}"
SM_RUN_SETUP="${SM_RUN_SETUP:-1}"
SM_EXPECT_APPLIED="${SM_EXPECT_APPLIED:-0}"
SM_PACKAGE="${SM_PACKAGE:-}"
SM_VERSION="${SM_VERSION:-}"
SM_PURL="${SM_PURL:-}"
SM_MANIFEST_KEY="${SM_MANIFEST_KEY:-package/index.js}"
SM_APPLY_ECOSYSTEMS="${SM_APPLY_ECOSYSTEMS:-npm}"
SM_MARKER="${SM_MARKER:-SOCKET-PATCH-SETUP-MATRIX-MARKER}"
SM_ALT_MARKER="${SM_ALT_MARKER:-SOCKET-PATCH-SETUP-MATRIX-ALT-MARKER}"

ZEROHASH="0000000000000000000000000000000000000000000000000000000000000000"
UUID="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
WRONG_PURL="pkg:${SM_APPLY_ECOSYSTEMS}/sm-setup-matrix-absent@9.9.9"

SP_BIN="${SOCKET_PATCH_BIN:-$(command -v socket-patch 2>/dev/null || echo socket-patch)}"
export SOCKET_PATCH_BIN="$SP_BIN"

NOTES=""
note() { NOTES="${NOTES}${NOTES:+; }$*"; }
log()  { printf '[setup-matrix:%s] %s\n' "$SM_ID" "$*"; }

# --- JSON emit (hand-rolled; values are simple, sanitized) ------------
json_str() { printf '%s' "$1" | tr -d '\r' | tr '\n' ' ' | sed 's/\\/\\\\/g; s/"/\\"/g'; }
emit_result() {
  local actual="$1" primary_present="$2" setup_exit="$3" install_exit="$4" target="$5" status="$6"
  printf '{"id":"%s","ecosystem":"%s","pm":"%s","scenario":"%s","patchset":"%s","run_setup":%s,"expect_applied":%s,"actual_applied":%s,"primary_marker_present":%s,"setup_exit":%s,"install_exit":%s,"target":"%s","status":"%s","notes":"%s"}\n' \
    "$(json_str "$SM_ID")" "$(json_str "$SM_ECOSYSTEM")" "$(json_str "$SM_PM")" \
    "$(json_str "$SM_SCENARIO")" "$(json_str "$SM_PATCHSET")" \
    "$([ "$SM_RUN_SETUP" = 1 ] && echo true || echo false)" \
    "$([ "$SM_EXPECT_APPLIED" = 1 ] && echo true || echo false)" \
    "$actual" "$primary_present" "$setup_exit" "$install_exit" \
    "$(json_str "$target")" "$(json_str "$status")" "$(json_str "$NOTES")" >&3
}

# --- git-sha256 (blob <len>\0 + content) ------------------------------
git_sha256() { # $1 = file
  local len; len="$(wc -c < "$1")"
  { printf 'blob %d\0' "$len"; cat "$1"; } | sha256sum | cut -d' ' -f1
}

# --- inline npx/pnpm shims (kept in sync with tests/setup_matrix/shims/) --
write_shims() { # $1 = shim dir
  local d="$1"; mkdir -p "$d"
  cat > "$d/npx" <<'SHIM'
#!/usr/bin/env bash
set -uo pipefail
sp_bin="${SOCKET_PATCH_BIN:-socket-patch}"
shim_dir="${SETUP_MATRIX_SHIM_DIR:-}"
clean_path="$PATH"
[ -n "$shim_dir" ] && clean_path="$(printf '%s' "$PATH" | tr ':' '\n' | grep -vxF "$shim_dir" | paste -sd: -)"
real_npx="$(PATH="$clean_path" command -v npx 2>/dev/null || true)"
i=0
for arg in "$@"; do
  case "$arg" in
    @socketsecurity/socket-patch|@socketsecurity/socket-patch@*|@socketsecurity/socket-patch/*)
      shift "$((i + 1))"; exec "$sp_bin" "$@" ;;
  esac
  i=$((i + 1))
done
[ -n "$real_npx" ] && exec "$real_npx" "$@"
echo "setup-matrix npx shim: real npx not found: $*" >&2; exit 127
SHIM
  cat > "$d/pnpm" <<'SHIM'
#!/usr/bin/env bash
set -uo pipefail
sp_bin="${SOCKET_PATCH_BIN:-socket-patch}"
shim_dir="${SETUP_MATRIX_SHIM_DIR:-}"
clean_path="$PATH"
[ -n "$shim_dir" ] && clean_path="$(printf '%s' "$PATH" | tr ':' '\n' | grep -vxF "$shim_dir" | paste -sd: -)"
real_pnpm="$(PATH="$clean_path" command -v pnpm 2>/dev/null || true)"
if [ "${1:-}" = "dlx" ] || [ "${1:-}" = "exec" ]; then
  case "${2:-}" in
    @socketsecurity/socket-patch|@socketsecurity/socket-patch@*) shift 2; exec "$sp_bin" "$@" ;;
  esac
fi
[ -n "$real_pnpm" ] && exec "$real_pnpm" "$@"
echo "setup-matrix pnpm shim: real pnpm not found: $*" >&2; exit 127
SHIM
  chmod +x "$d/npx" "$d/pnpm"
}

# --- committed patch fixture ------------------------------------------
write_manifest() { # $1=purl $2=key $3=afterHash
  cat > .socket/manifest.json <<EOF
{
  "patches": {
    "$1": {
      "uuid": "$UUID",
      "exportedAt": "2026-01-01T00:00:00Z",
      "files": { "$2": { "beforeHash": "$ZEROHASH", "afterHash": "$3" } },
      "vulnerabilities": {},
      "description": "setup-matrix synthetic patch",
      "license": "MIT",
      "tier": "free"
    }
  }
}
EOF
}

build_fixture() {
  mkdir -p .socket/blobs
  case "$SM_PATCHSET" in
    empty)
      printf '{"patches":{}}\n' > .socket/manifest.json
      note "empty manifest" ;;
    wrong)
      # A patch for a package that is NOT installed: nothing should match.
      local body="/* $SM_MARKER */"; printf '%s\n' "$body" > /tmp/sm_blob
      local h; h="$(git_sha256 /tmp/sm_blob)"; cp /tmp/sm_blob ".socket/blobs/$h"
      write_manifest "$WRONG_PURL" "$SM_MANIFEST_KEY" "$h"
      note "manifest targets absent purl $WRONG_PURL" ;;
    alt)
      local body="/* $SM_ALT_MARKER */"; printf '%s\n' "$body" > /tmp/sm_blob
      local h; h="$(git_sha256 /tmp/sm_blob)"; cp /tmp/sm_blob ".socket/blobs/$h"
      write_manifest "$SM_PURL" "$SM_MANIFEST_KEY" "$h" ;;
    *) # primary
      local body="/* $SM_MARKER */"; printf '%s\n' "$body" > /tmp/sm_blob
      local h; h="$(git_sha256 /tmp/sm_blob)"; cp /tmp/sm_blob ".socket/blobs/$h"
      write_manifest "$SM_PURL" "$SM_MANIFEST_KEY" "$h" ;;
  esac
}

# --- per-PM project scaffold (must exist before setup runs) -----------
scaffold_project() {
  case "$SM_PM" in
    npm|yarn|bun)
      printf '{"name":"sm-proj","version":"0.0.0","private":true}\n' > package.json ;;
    pnpm)
      # pnpm only runs the ROOT postinstall on `pnpm install` (not on
      # `pnpm add`), so the dependency is declared up front and installed
      # via a bare `pnpm install`. The stub lockfile is the pnpm marker
      # that makes `setup` detect pnpm and write the `pnpm dlx` hook.
      cat > package.json <<EOF
{ "name": "sm-proj", "version": "0.0.0", "private": true, "dependencies": { "$SM_PACKAGE": "$SM_VERSION" } }
EOF
      printf "lockfileVersion: '9.0'\n" > pnpm-lock.yaml ;;
    deno)
      cat > package.json <<EOF
{ "name": "sm-proj", "version": "0.0.0", "private": true, "dependencies": { "$SM_PACKAGE": "$SM_VERSION" } }
EOF
      cat > deno.json <<EOF
{ "name": "sm-proj", "version": "0.0.0", "nodeModulesDir": "auto" }
EOF
      ;;
    pip|uv) : ;;
    poetry)
      cat > pyproject.toml <<EOF
[tool.poetry]
name = "sm-proj"
version = "0.0.0"
description = ""
authors = ["t <t@example.com>"]
package-mode = false

[build-system]
requires = ["poetry-core"]
build-backend = "poetry.core.masonry.api"
EOF
      ;;
    pdm)
      cat > pyproject.toml <<EOF
[project]
name = "sm-proj"
version = "0.0.0"
requires-python = ">=3.9"
dependencies = []

[tool.pdm]
distribution = false
EOF
      ;;
    hatch)
      # `skip-install = true` so hatch does NOT try to build the (empty)
      # project; the dependency is installed as an env dependency instead.
      cat > pyproject.toml <<EOF
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "sm-proj"
version = "0.0.0"
requires-python = ">=3.9"

[tool.hatch.envs.default]
skip-install = true
dependencies = ["$SM_PACKAGE==$SM_VERSION"]
EOF
      ;;
    cargo)
      cat > Cargo.toml <<EOF
[package]
name = "sm-proj"
version = "0.0.0"
edition = "2021"

[dependencies]
$SM_PACKAGE = "=$SM_VERSION"
EOF
      mkdir -p src; printf 'fn main() {}\n' > src/main.rs ;;
    bundler)
      cat > Gemfile <<EOF
source 'https://rubygems.org'
gem '$SM_PACKAGE', '$SM_VERSION'
EOF
      ;;
    go)
      printf 'module sm-proj\n\ngo 1.21\n' > go.mod ;;
    mvn|composer|dotnet) : ;;
  esac
}

# --- per-PM native install (the hook, if configured, fires here) ------
run_install() {
  case "$SM_PM" in
    npm)   npm install --silent --no-audit --no-fund "$SM_PACKAGE@$SM_VERSION" ;;
    yarn)  yarn add --silent "$SM_PACKAGE@$SM_VERSION" ;;
    pnpm)  pnpm install --no-frozen-lockfile ;;
    bun)   bun add "$SM_PACKAGE@$SM_VERSION" ;;
    deno)  deno install --allow-scripts ;;
    pip)   python3 -m venv venv && ./venv/bin/pip install --disable-pip-version-check --quiet --no-cache-dir "$SM_PACKAGE==$SM_VERSION" ;;
    uv)    uv venv venv && uv pip install --python venv/bin/python --quiet "$SM_PACKAGE==$SM_VERSION" ;;
    poetry) poetry config virtualenvs.in-project true --local && poetry add --no-interaction "$SM_PACKAGE@$SM_VERSION" ;;
    pdm)   pdm config python.use_venv true >/dev/null 2>&1; pdm add "$SM_PACKAGE==$SM_VERSION" ;;
    hatch) HATCH_DATA_DIR="$PWD/.hatch" hatch env create && HATCH_DATA_DIR="$PWD/.hatch" hatch run python -c "import ${SM_PACKAGE//-/_}" ;;
    cargo) cargo fetch ;;
    bundler) bundle config set --local path vendor/bundle && bundle install ;;
    go)    GOFLAGS=-mod=mod go mod download "$SM_PACKAGE@$SM_VERSION" ;;
    mvn)   mvn -q -B dependency:get -Dartifact="$SM_PACKAGE:$SM_VERSION" ;;
    composer) composer require --quiet --no-interaction "$SM_PACKAGE:$SM_VERSION" ;;
    dotnet) dotnet new classlib -o . --force >/dev/null 2>&1 && dotnet add package "$SM_PACKAGE" --version "$SM_VERSION" ;;
    *) echo "unknown pm: $SM_PM"; return 2 ;;
  esac
}

# --- resolve the on-disk file the patch would land in -----------------
resolve_target() {
  local rel="${SM_MANIFEST_KEY#package/}"
  local base; base="$(basename "$rel")"
  case "$SM_ECOSYSTEM" in
    npm|deno)  printf '%s\n' "$PWD/node_modules/$SM_PACKAGE/$rel" ;;
    pypi)      find "$PWD" -name "$base" 2>/dev/null | head -1 ;;
    cargo)     find "${CARGO_HOME:-$HOME/.cargo}/registry/src" -path "*/${SM_PACKAGE}-${SM_VERSION}/${rel}" 2>/dev/null | head -1 ;;
    gem)       find "$PWD/vendor" -path "*/${SM_PACKAGE}-${SM_VERSION}/${rel}" 2>/dev/null | head -1 ;;
    golang)    local gmc; gmc="$(go env GOMODCACHE 2>/dev/null || echo "${GOPATH:-$HOME/go}/pkg/mod")"; find "$gmc" -path "*/$(basename "$SM_PACKAGE")@${SM_VERSION}/${rel}" 2>/dev/null | head -1 ;;
    maven)     find "$HOME/.m2/repository" -name "$base" 2>/dev/null | head -1 ;;
    composer)  printf '%s\n' "$PWD/vendor/${SM_PACKAGE}/${rel}" ;;
    nuget)     local lc; lc="$(printf '%s' "$SM_PACKAGE" | tr '[:upper:]' '[:lower:]')"; find "${NUGET_PACKAGES:-$HOME/.nuget/packages}" -path "*/${lc}/${SM_VERSION}/${rel}" 2>/dev/null | head -1 ;;
  esac
}

# ============================ main ====================================
log "binary: $SP_BIN ($("$SP_BIN" --version 2>/dev/null || echo '??'))"

WORKDIR="${SM_WORKDIR:-$(mktemp -d)}"
PROJ="$WORKDIR/proj"
mkdir -p "$PROJ"
cd "$PROJ" || { emit_result false null null null "" fail; exit 0; }
note "proj=$PROJ"

# 0. dependencies + committed patch set
scaffold_project
build_fixture

# npm-family (incl. deno-via-npm) need the runner shim so the hook's
# `npx`/`pnpm dlx @socketsecurity/socket-patch` resolves to $SP_BIN.
case "$SM_PM" in
  npm|yarn|pnpm|bun|deno)
    SHIM_DIR="$PROJ/.sp-shims"
    write_shims "$SHIM_DIR"
    export SETUP_MATRIX_SHIM_DIR="$SHIM_DIR"
    export PATH="$SHIM_DIR:$PATH"
    log "shims installed at $SHIM_DIR (PATH prepended)" ;;
esac

# Hermetic apply env inherited by the install hook's `socket-patch apply`.
# NOTE: SOCKET_OFFLINE/SOCKET_FORCE must be "true"/"false" — the apply
# `--force` flag (unlike its siblings) has no boolish value parser, so
# SOCKET_FORCE=1 is rejected with "invalid value '1' for '--force'".
# The SOCKET_EXPERIMENTAL_* gates are read directly from the env and use
# "1".
export SOCKET_OFFLINE=true SOCKET_FORCE=true SOCKET_API_TOKEN=fake SOCKET_ORG_SLUG=test-org
export SOCKET_TELEMETRY_DISABLED=1 SOCKET_EXPERIMENTAL_MAVEN=1 SOCKET_EXPERIMENTAL_NUGET=1
export SOCKET_CWD="$PROJ"

# 1. setup (configures hooks; no-op where there is no package.json)
SETUP_EXIT="null"
if [ "$SM_RUN_SETUP" = 1 ]; then
  log "running: socket-patch setup --yes"
  "$SP_BIN" setup --yes --json; SETUP_EXIT=$?
  log "setup exit=$SETUP_EXIT"
  [ -f package.json ] && { log "package.json scripts after setup:"; grep -A6 '"scripts"' package.json || true; }
fi

# 2. native install (this is where a configured hook fires)
log "running install for pm=$SM_PM"
run_install; INSTALL_EXIT=$?
log "install exit=$INSTALL_EXIT"

# 3. verify
TARGET="$(resolve_target || true)"
log "resolved target: ${TARGET:-<none>}"
APPLIED=false
PRIMARY_PRESENT=null
if [ -n "$TARGET" ] && [ -f "$TARGET" ]; then
  # The marker we expect depends on the patch set.
  check_marker="$SM_MARKER"
  [ "$SM_PATCHSET" = alt ] && check_marker="$SM_ALT_MARKER"
  if grep -q "$check_marker" "$TARGET" 2>/dev/null; then APPLIED=true; fi
  if grep -q "$SM_MARKER" "$TARGET" 2>/dev/null; then PRIMARY_PRESENT=true; else PRIMARY_PRESENT=false; fi
  log "marker '$check_marker' present: $APPLIED"
else
  note "target file not found"
fi

# Driver-level status: did actual match the aspirational expectation?
want=$([ "$SM_EXPECT_APPLIED" = 1 ] && echo true || echo false)
STATUS=fail
[ "$APPLIED" = "$want" ] && STATUS=pass

emit_result "$APPLIED" "$PRIMARY_PRESENT" "$SETUP_EXIT" "$INSTALL_EXIT" "${TARGET:-}" "$STATUS"
exit 0
