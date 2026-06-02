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
SM_LAYOUT="${SM_LAYOUT:-single}"

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
  printf '{"id":"%s","ecosystem":"%s","pm":"%s","scenario":"%s","patchset":"%s","run_setup":%s,"expect_applied":%s,"actual_applied":%s,"applied_before_setup":%s,"applied_after_remove":%s,"primary_marker_present":%s,"setup_exit":%s,"install_exit":%s,"check_before_setup_exit":%s,"check_after_setup_exit":%s,"remove_exit":%s,"check_after_remove_exit":%s,"target":"%s","status":"%s","notes":"%s"}\n' \
    "$(json_str "$SM_ID")" "$(json_str "$SM_ECOSYSTEM")" "$(json_str "$SM_PM")" \
    "$(json_str "$SM_SCENARIO")" "$(json_str "$SM_PATCHSET")" \
    "$([ "$SM_RUN_SETUP" = 1 ] && echo true || echo false)" \
    "$([ "$SM_EXPECT_APPLIED" = 1 ] && echo true || echo false)" \
    "$actual" "${APPLIED_BEFORE_SETUP:-null}" "${APPLIED_AFTER_REMOVE:-null}" "$primary_present" \
    "$setup_exit" "$install_exit" \
    "${CHECK_BEFORE_SETUP_EXIT:-null}" "${CHECK_AFTER_SETUP_EXIT:-null}" "${REMOVE_EXIT:-null}" "${CHECK_AFTER_REMOVE_EXIT:-null}" \
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
# The patched blob is RUNNABLE code that emits the marker on stdout when the
# file is executed, so verification can RUN the patched module with the
# ecosystem's standard runner (node/bun/python) and observe the marker at
# runtime — not merely scan the file for the string. Compiled/loaded
# ecosystems we can't execute keep an inert comment (verified by reading the
# file; see `run_file`).
marker_blob() { # $1 = marker  -> runnable payload on stdout
  case "$SM_ECOSYSTEM" in
    npm|deno|monorepo) printf 'console.log("%s");\n' "$1" ;;
    pypi)              printf 'print("%s")\n' "$1" ;;
    *)                 printf '/* %s */\n' "$1" ;;
  esac
}

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
  # Ablation: no patch set committed at all (no .socket/). Even with a
  # working install hook, apply finds no manifest and no-ops, so the
  # install must run unpatched. Distinct from `empty` (manifest present
  # but with zero patches).
  if [ "$SM_PATCHSET" = none ]; then
    note "no patch fixture committed (ablation: patch missing)"
    return
  fi
  mkdir -p .socket/blobs
  # Per-case scratch file for the blob. MUST NOT be a fixed path like
  # /tmp/sm_blob: the Rust matrix wrappers run the package-manager test fns in
  # parallel, so a shared path races (one case hashes a blob another just
  # overwrote → afterHash mismatch → apply no-ops).
  local blob_tmp; blob_tmp="$(mktemp)"
  case "$SM_PATCHSET" in
    empty)
      printf '{"patches":{}}\n' > .socket/manifest.json
      note "empty manifest" ;;
    wrong)
      # A patch for a package that is NOT installed: nothing should match.
      marker_blob "$SM_MARKER" > "$blob_tmp"
      local h; h="$(git_sha256 "$blob_tmp")"; cp "$blob_tmp" ".socket/blobs/$h"
      write_manifest "$WRONG_PURL" "$SM_MANIFEST_KEY" "$h"
      note "manifest targets absent purl $WRONG_PURL" ;;
    alt)
      marker_blob "$SM_ALT_MARKER" > "$blob_tmp"
      local h; h="$(git_sha256 "$blob_tmp")"; cp "$blob_tmp" ".socket/blobs/$h"
      write_manifest "$SM_PURL" "$SM_MANIFEST_KEY" "$h" ;;
    *) # primary
      marker_blob "$SM_MARKER" > "$blob_tmp"
      local h; h="$(git_sha256 "$blob_tmp")"; cp "$blob_tmp" ".socket/blobs/$h"
      write_manifest "$SM_PURL" "$SM_MANIFEST_KEY" "$h" ;;
  esac
  rm -f "$blob_tmp"
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

# --- workspace scaffold (root + nested members) ----------------------
# Models a real monorepo where multiple (incl. deeply-nested) workspace
# members depend on the package being patched, plus a member that does
# NOT — so `setup`'s workspace handling (npm: every member; pnpm: root
# only) and the root install's cross-workspace apply are both exercised.
ws_member_js() { # $1=dir $2=name (declares the dep)
  mkdir -p "$1"
  cat > "$1/package.json" <<EOF
{ "name": "$2", "version": "0.0.0", "dependencies": { "$SM_PACKAGE": "$SM_VERSION" } }
EOF
}

scaffold_workspace() {
  case "$SM_PM" in
    npm|yarn)
      cat > package.json <<'EOF'
{ "name": "sm-root", "version": "0.0.0", "private": true,
  "workspaces": ["packages/*", "packages/group/*"] }
EOF
      ws_member_js packages/app "@sm/app"
      ws_member_js packages/lib "@sm/lib"
      ws_member_js packages/group/nested "@sm/nested"
      mkdir -p packages/util   # member with NO dependency on the patched pkg
      printf '{ "name": "@sm/util", "version": "0.0.0", "private": true }\n' > packages/util/package.json ;;
    pnpm)
      printf '{ "name": "sm-root", "version": "0.0.0", "private": true }\n' > package.json
      cat > pnpm-workspace.yaml <<'EOF'
packages:
  - 'packages/*'
  - 'packages/group/*'
EOF
      ws_member_js packages/app "@sm/app"
      ws_member_js packages/lib "@sm/lib"
      ws_member_js packages/group/nested "@sm/nested"
      mkdir -p packages/util
      printf '{ "name": "@sm/util", "version": "0.0.0", "private": true }\n' > packages/util/package.json ;;
    uv)
      # uv workspace: virtual root + members; the shared dep is installed
      # into one root .venv by `uv sync`.
      cat > pyproject.toml <<EOF
[project]
name = "sm-root"
version = "0.0.0"
requires-python = ">=3.9"
dependencies = ["$SM_PACKAGE==$SM_VERSION"]

[tool.uv.workspace]
members = ["packages/*"]

[tool.uv]
package = false
EOF
      for m in app lib; do
        mkdir -p "packages/$m"
        cat > "packages/$m/pyproject.toml" <<EOF
[project]
name = "sm-$m"
version = "0.0.0"
requires-python = ">=3.9"
dependencies = []

[tool.uv]
package = false
EOF
      done ;;
    pip)
      # pip "workspace" = nested requirements files installed into one venv.
      mkdir -p packages/app packages/lib
      echo "$SM_PACKAGE==$SM_VERSION" > packages/app/requirements.txt
      echo "$SM_PACKAGE==$SM_VERSION" > packages/lib/requirements.txt
      printf -- '-r packages/app/requirements.txt\n-r packages/lib/requirements.txt\n' > requirements.txt ;;
  esac
}

run_install_workspace() {
  case "$SM_PM" in
    npm)  npm install --silent --no-audit --no-fund ;;
    yarn) yarn install --silent ;;
    pnpm) pnpm install --no-frozen-lockfile ;;
    uv)   uv sync ;;
    pip)  python3 -m venv venv && ./venv/bin/pip install --disable-pip-version-check --quiet --no-cache-dir -r requirements.txt ;;
  esac
}

# --- all-ecosystem monorepo scaffold ---------------------------------
# A polyglot repo: an npm workspace (the slice `setup` supports AND the
# npm image can install) alongside python/rust/go/php/ruby/nuget/deno
# manifests. The point is to confirm `setup` works in this environment —
# it must configure the npm hooks and NOT choke on the foreign manifests.
scaffold_monorepo() {
  cat > package.json <<'EOF'
{ "name": "sm-monorepo", "version": "0.0.0", "private": true,
  "workspaces": ["packages/js-*"] }
EOF
  ws_member_js packages/js-app "@mono/js-app"
  ws_member_js packages/js-nested "@mono/js-nested"
  mkdir -p packages/py-svc
  cat > packages/py-svc/pyproject.toml <<'EOF'
[project]
name = "py-svc"
version = "0.0.0"
requires-python = ">=3.9"
dependencies = ["six==1.16.0"]
EOF
  printf 'six==1.16.0\n' > packages/py-svc/requirements.txt
  mkdir -p packages/rust-lib/src
  printf '[package]\nname = "rust-lib"\nversion = "0.0.0"\nedition = "2021"\n\n[dependencies]\ncfg-if = "=1.0.0"\n' > packages/rust-lib/Cargo.toml
  printf '// lib\n' > packages/rust-lib/src/lib.rs
  mkdir -p packages/go-mod && printf 'module mono/go\n\ngo 1.21\n' > packages/go-mod/go.mod
  mkdir -p packages/php-web && printf '{ "name": "mono/php", "require": { "monolog/monolog": "3.5.0" } }\n' > packages/php-web/composer.json
  mkdir -p packages/ruby-gem && printf "source 'https://rubygems.org'\ngem 'colorize', '1.1.0'\n" > packages/ruby-gem/Gemfile
  mkdir -p packages/deno-app && printf '{ "name": "mono/deno", "version": "0.0.0" }\n' > packages/deno-app/deno.json
  mkdir -p packages/nuget-app && printf '<Project Sdk="Microsoft.NET.Sdk"></Project>\n' > packages/nuget-app/app.csproj
}

run_install_monorepo() {
  npm install --silent --no-audit --no-fund
}

# --- resolve candidate on-disk file(s) for verification --------------
# For single layout: one path. For workspace/monorepo: search the tree
# (hoisted root node_modules, pnpm store, member dirs, shared venv).
resolve_targets() {
  local rel="${SM_MANIFEST_KEY#package/}"
  local base; base="$(basename "$rel")"
  if [ "$SM_LAYOUT" = single ]; then
    resolve_target
    return
  fi
  case "$SM_ECOSYSTEM" in
    npm|deno|monorepo) find "$PWD" -path "*/node_modules/$SM_PACKAGE/$rel" 2>/dev/null ;;
    pypi)              find "$PWD" -name "$base" 2>/dev/null ;;
    *)                 resolve_target ;;
  esac
}

# --- native install dispatch (layout-aware) --------------------------
do_install() {
  case "$SM_LAYOUT" in
    workspace) run_install_workspace ;;
    monorepo)  run_install_monorepo ;;
    *)         run_install ;;
  esac
}

# Wipe installed modules so the NEXT install re-fetches a pristine copy and
# re-fires the lifecycle hook. This is what lets us observe the patch-apply
# BEHAVIOR (marker present/absent on a freshly installed file) at each stage
# of the (setup)·(install) sequence, rather than inspecting package.json.
reset_modules() {
  rm -rf node_modules packages/*/node_modules 2>/dev/null || true
}

# Execute a single patched file with the ecosystem's STANDARD runner so the
# patched code actually runs; its stdout/stderr (where the marker would be
# printed) is emitted for the caller to inspect. npm→node, bun→bun, deno→deno,
# pip→the venv's python3, uv→uv run, poetry/pdm/hatch→their `run`. For
# compiled/loaded ecosystems we cannot execute (cargo/go/maven/nuget/gem/
# composer) we `cat` the file so its inert marker comment is still observed —
# matching the previous file-based behavior for those gaps.
run_file() { # $1 = absolute path to the resolved package file
  case "$SM_ECOSYSTEM" in
    npm|monorepo)
      case "$SM_PM" in
        bun) bun "$1" ;;
        *)   node "$1" ;;
      esac ;;
    deno) deno run -A "$1" ;;
    pypi)
      case "$SM_PM" in
        uv)     uv run python "$1" ;;
        poetry) poetry run python "$1" ;;
        pdm)    pdm run python "$1" ;;
        hatch)  hatch run python "$1" ;;
        pip)    ./venv/bin/python "$1" ;;
        *)      python3 "$1" ;;
      esac ;;
    *) cat "$1" ;;
  esac
}

# Decide whether the patch was applied by RUNNING every on-disk copy of the
# patched file and checking whether the marker appears in its runtime output.
# Sets APPLIED / PRIMARY_PRESENT / TARGET.
verify_applied() {
  local check_marker="$SM_MARKER"
  [ "$SM_PATCHSET" = alt ] && check_marker="$SM_ALT_MARKER"
  APPLIED=false
  PRIMARY_PRESENT=null
  TARGET=""
  local n_found=0 cand out
  while IFS= read -r cand; do
    [ -n "$cand" ] && [ -f "$cand" ] || continue
    n_found=$((n_found + 1))
    [ -z "$TARGET" ] && TARGET="$cand"
    out="$(run_file "$cand" 2>&1)"
    if printf '%s' "$out" | grep -q "$check_marker"; then APPLIED=true; TARGET="$cand"; fi
    if printf '%s' "$out" | grep -q "$SM_MARKER"; then PRIMARY_PRESENT=true; fi
  done < <(resolve_targets)
  [ "$PRIMARY_PRESENT" = null ] && [ "$n_found" -gt 0 ] && PRIMARY_PRESENT=false
  log "verify(run): marker '$check_marker' in runtime output=$APPLIED (candidates=$n_found, target=${TARGET:-<none>})"
}

# npm-family is the surface `setup` actually configures today — the only place
# the behavioral check/remove round-trip is expected to do real work.
is_npm_family() {
  [[ "$SM_PM" =~ ^(npm|yarn|pnpm|bun)$ ]] || [ "$SM_LAYOUT" = monorepo ]
}

# ============================ main ====================================
log "binary: $SP_BIN ($("$SP_BIN" --version 2>/dev/null || echo '??'))  layout=$SM_LAYOUT"

WORKDIR="${SM_WORKDIR:-$(mktemp -d)}"
PROJ="$WORKDIR/proj"
mkdir -p "$PROJ"
cd "$PROJ" || { emit_result false null null null "" fail; exit 0; }
note "proj=$PROJ"

# 0. dependencies + committed patch set
case "$SM_LAYOUT" in
  workspace) scaffold_workspace ;;
  monorepo)  scaffold_monorepo ;;
  *)         scaffold_project ;;
esac
build_fixture

# npm-family (incl. deno-via-npm and the monorepo's npm slice) need the
# runner shim so the hook's `npx`/`pnpm dlx @socketsecurity/socket-patch`
# resolves to $SP_BIN instead of the npm registry.
if [[ "$SM_PM" =~ ^(npm|yarn|pnpm|bun|deno)$ ]] || [ "$SM_LAYOUT" = monorepo ]; then
  SHIM_DIR="$PROJ/.sp-shims"
  write_shims "$SHIM_DIR"
  export SETUP_MATRIX_SHIM_DIR="$SHIM_DIR"
  export PATH="$SHIM_DIR:$PATH"
  log "shims installed at $SHIM_DIR (PATH prepended)"
fi

# Hermetic apply env inherited by the install hook's `socket-patch apply`.
# NOTE: SOCKET_OFFLINE/SOCKET_FORCE must be "true"/"false" — the apply
# `--force` flag (unlike its siblings) has no boolish value parser, so
# SOCKET_FORCE=1 is rejected with "invalid value '1' for '--force'".
# The SOCKET_EXPERIMENTAL_* gates are read directly from the env and use
# "1".
export SOCKET_OFFLINE=true SOCKET_FORCE=true SOCKET_API_TOKEN=fake SOCKET_ORG_SLUG=test-org
export SOCKET_TELEMETRY_DISABLED=1 SOCKET_EXPERIMENTAL_MAVEN=1 SOCKET_EXPERIMENTAL_NUGET=1
# NOTE: deliberately do NOT export SOCKET_CWD. The install hook's apply
# must run with whatever cwd the package manager sets for the lifecycle
# script — the project root for a single project, and the *member* dir
# for each workspace member. In a workspace, member postinstalls thus
# find no manifest in their own dir and no-op (exit 0), while the root
# postinstall (manifest present) applies. Forcing SOCKET_CWD=root would
# make every member apply target the root manifest and fail with "no
# packages found on disk" mid-install, breaking `npm install`.

# 1-3. Configure + install + verify.
#
# For npm-family cases that run setup we exercise the FULL behavioral sequence
# — (install)·(setup)·(install)·(remove)·(install) — observing both the patch
# marker and `setup --check` at each stage. A clean reinstall precedes every
# observation so the lifecycle hook acts on a pristine package. This verifies
# behavior end-to-end rather than reading package.json:
#   * patch: NOT applied before setup → applied after setup → NOT applied after remove
#   * check: fails before setup → passes after setup → fails after remove
#
# Every other case (run_setup=0, or non-npm-family ecosystems) keeps the simple
# single-install flow, preserving the existing aspirational expect_applied
# classification untouched.
SETUP_EXIT="null"
CHECK_BEFORE_SETUP_EXIT="null"
CHECK_AFTER_SETUP_EXIT="null"
REMOVE_EXIT="null"
CHECK_AFTER_REMOVE_EXIT="null"
APPLIED_BEFORE_SETUP=null
APPLIED_AFTER_REMOVE=null
INSTALL_EXIT="null"

if is_npm_family && [ "$SM_RUN_SETUP" = 1 ]; then
  # (1) BEFORE setup: no hook configured → install must NOT apply the patch.
  log "[before-setup] install for pm=$SM_PM (layout=$SM_LAYOUT)"
  do_install; log "[before-setup] install exit=$?"
  verify_applied; APPLIED_BEFORE_SETUP="$APPLIED"

  # (2) check must report "needs configuration" (non-zero) before setup.
  "$SP_BIN" setup --check --json; CHECK_BEFORE_SETUP_EXIT=$?
  log "check-before-setup exit=$CHECK_BEFORE_SETUP_EXIT"

  # (3) setup, then check must report "configured" (zero).
  log "running: socket-patch setup --yes"
  "$SP_BIN" setup --yes --json; SETUP_EXIT=$?
  log "setup exit=$SETUP_EXIT"
  [ -f package.json ] && { log "package.json scripts after setup:"; grep -A6 '"scripts"' package.json || true; }
  "$SP_BIN" setup --check --json; CHECK_AFTER_SETUP_EXIT=$?
  log "check-after-setup exit=$CHECK_AFTER_SETUP_EXIT"

  # (4) AFTER setup: clean reinstall → the hook fires → MAIN applied result.
  reset_modules
  log "[after-setup] install for pm=$SM_PM (layout=$SM_LAYOUT)"
  do_install; INSTALL_EXIT=$?
  log "[after-setup] install exit=$INSTALL_EXIT"
  verify_applied   # sets the canonical APPLIED / PRIMARY_PRESENT / TARGET

  # (5) remove, then check must report "needs configuration" (non-zero) again.
  log "running: socket-patch setup --remove --yes"
  "$SP_BIN" setup --remove --yes --json; REMOVE_EXIT=$?
  log "remove exit=$REMOVE_EXIT"
  [ -f package.json ] && { log "package.json scripts after remove:"; grep -A6 '"scripts"' package.json || true; }
  "$SP_BIN" setup --check --json; CHECK_AFTER_REMOVE_EXIT=$?
  log "check-after-remove exit=$CHECK_AFTER_REMOVE_EXIT"

  # (6) AFTER remove: clean reinstall → no hook → must NOT apply the patch.
  # Preserve the main (after-setup) result while re-probing the disk.
  _MAIN_APPLIED="$APPLIED"; _MAIN_PRIMARY="$PRIMARY_PRESENT"; _MAIN_TARGET="$TARGET"
  reset_modules
  log "[after-remove] install for pm=$SM_PM (layout=$SM_LAYOUT)"
  do_install; log "[after-remove] install exit=$?"
  verify_applied; APPLIED_AFTER_REMOVE="$APPLIED"
  APPLIED="$_MAIN_APPLIED"; PRIMARY_PRESENT="$_MAIN_PRIMARY"; TARGET="$_MAIN_TARGET"
else
  # Simple flow: optional setup (no-op where there is no package.json), one
  # install, one verify.
  if [ "$SM_RUN_SETUP" = 1 ]; then
    log "running: socket-patch setup --yes"
    "$SP_BIN" setup --yes --json; SETUP_EXIT=$?
    log "setup exit=$SETUP_EXIT"
    [ -f package.json ] && { log "package.json scripts after setup:"; grep -A6 '"scripts"' package.json || true; }
  fi
  log "running install for pm=$SM_PM (layout=$SM_LAYOUT)"
  do_install; INSTALL_EXIT=$?
  log "install exit=$INSTALL_EXIT"
  verify_applied
fi

# Driver-level status: did actual match the aspirational expectation?
want=$([ "$SM_EXPECT_APPLIED" = 1 ] && echo true || echo false)
STATUS=fail
[ "$APPLIED" = "$want" ] && STATUS=pass

emit_result "$APPLIED" "$PRIMARY_PRESENT" "$SETUP_EXIT" "$INSTALL_EXIT" "${TARGET:-}" "$STATUS"
exit 0
