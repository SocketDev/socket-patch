//! Docker build-proof capstones for `socket-patch vendor` — pypi
//! package-manager v2 flavors (poetry, pdm, pipenv).
//!
//! Each test proves the CLI_CONTRACT "Vendor command contract" pypi row end
//! to end for one Python tool against the REAL tool baked into
//! `socket-patch-test-pypi:latest` (Poetry 2.x, PDM 2.27, pipenv 2026.x;
//! Python 3.11), with state carried across containers via a bind-mounted host
//! tempdir (see `docker_vendor_common/mod.rs`):
//!
//!   stage 1 (networked): create a real single-dep project on `six==1.16.0`
//!     (poetry: `poetry add`; pdm: `pdm add`; pipenv: `pipenv install`) with
//!     an IN-PROJECT venv so the crawler finds the installed `six.py` →
//!     hand-stage a marker patch on `six.py` (manifest + blob; git-blob
//!     sha256 from the ACTUAL installed bytes) → `socket-patch vendor --json
//!     --offline` (the binary baked into the image) → assert: the wheel
//!     artifact at `.socket/vendor/pypi/<uuid>/<wheel>` (files[] hash ==
//!     wheel sha256), the LOCK-ONLY rewiring per flavor, `state.json`, and
//!     that the tool MANIFEST (pyproject/Pipfile) was left byte-untouched.
//!   stage 2 (`--network none`, cold cache dir): ONLY the committable files
//!     (lock + pyproject/Pipfile + .socket/) are copied to a fresh dir; the
//!     tool's STRICTEST install runs cold+offline and a Python import probe
//!     proves `six.py` is the PATCHED bytes.
//!   stage 2b (poetry, `--network none`, then the host): manifest-less VEX
//!     over copies of the installed fresh checkout — manifest deleted →
//!     attested offline from the ledger (standalone + `apply --vex`);
//!     ledgers deleted → attested from the poetry.lock wiring + a wiremock
//!     patch API (host side), `record_unavailable` under `--offline`; lock
//!     reverted with ledger + artifact kept → `vendor_unwired`, `--no-verify`
//!     too.
//!   stage 3 (`--network none`): re-vendor is idempotent (already_vendored,
//!     lock byte-stable) → `vendor --revert` restores the lock byte-identical
//!     to the pre-vendor snapshot and removes `.socket/vendor` → re-vendor
//!     succeeds again.
//!
//! Anti-vacuity: every stage echoes `===<NAME> VERIFIED===` markers behind
//! its asserts (gated by `assert_stage_markers`), and stage 2 additionally
//! RED-PROBES — it first deletes `.socket/vendor` from the fresh copy and
//! requires the strictest install to FAIL, proving the install genuinely
//! depends on the vendored artifact, then restores it and requires green.
//!
//! pipenv caveat (spike V4, lock-only NOT hash-enforced): pipenv installs
//! file-ref lock entries through a pip phase with no `--require-hashes`, so a
//! tampered wheel installs silently. The committable proof here is therefore
//! "the patched bytes get imported", not "tamper fails"; the suite also
//! asserts the `vendor_integrity_unverified` warning surfaces in the vendor
//! `--json` envelope (a `skipped` event carrying that `errorCode`).

#![cfg(feature = "docker-e2e")]

#[path = "docker_vendor_common/mod.rs"]
mod docker_vendor_common;
#[path = "vex_e2e_common/mod.rs"]
mod vex_e2e_common;

use docker_vendor_common::{
    assert_stage_markers, bash_prelude, json_assert_fns, run_in_image, run_in_image_network_none,
    skip_if_no_image, stage_patch_fn,
};

const IMAGE: &str = "socket-patch-test-pypi:latest";

/// Glue the shared bash helpers onto a stage body and pin the uuid.
fn render(stage_body: &str, uuid: &str) -> String {
    format!(
        "{}{}{}{}",
        bash_prelude(),
        stage_patch_fn(),
        json_assert_fns(),
        stage_body
    )
    .replace("__UUID__", uuid)
}

// Distinct lowercase uuids per flavor so a stray cross-suite artifact dir
// can't satisfy another suite's path assert.
const UUID_POETRY: &str = "41414141-4141-4141-8141-414141414141";
const UUID_PDM: &str = "42424242-4242-4242-8242-424242424242";
const UUID_PIPENV: &str = "43434343-4343-4343-8343-434343434343";

/// Shared bash that stages the six.py marker patch from the installed bytes.
/// `$ORIG` must already point at the in-project venv's `six.py`. Defines
/// `$PURL`, `$WHEEL`-independent snapshots in /workspace/snap, and runs the
/// offline vendor producing /tmp/vendor.json. Caller asserts wiring after.
const STAGE1_VENDOR_COMMON: &str = r#"
[ -f "$ORIG" ] || fail "$ORIG missing after the fixture install"
# Pristine pre-check: without this the post-vendor marker asserts are circular.
grep -q 'SOCKET-PATCH-VENDOR-E2E-MARKER' "$ORIG" \
  && fail "marker already in $ORIG BEFORE patching — fixture not pristine"

# Marker patch = the ACTUAL installed six.py + a trailing marker comment
# (still valid python). before/after git-blob hashes computed in-container.
cp "$ORIG" /tmp/patched.py
printf '\n# SOCKET-PATCH-VENDOR-E2E-MARKER patch=__UUID__\nSOCKET_PATCH_VENDOR_E2E = "__UUID__"\n' >> /tmp/patched.py
PURL="pkg:pypi/six@1.16.0"
stage_patch "$PURL" "__UUID__" "six.py" "$ORIG" /tmp/patched.py

# Pre-vendor snapshots: consumed by stage 2/3 byte-identity asserts.
mkdir -p /workspace/snap
sha256sum /tmp/patched.py | cut -d' ' -f1 > /workspace/snap/patched.sha

# Vendor (fully offline: the blob is staged locally).
socket-patch vendor --json --offline > /tmp/vendor.json 2>/tmp/vendor.err
RC=$?; cat /tmp/vendor.err >&2
[ "$RC" -eq 0 ] || { cat /tmp/vendor.json >&2; fail "vendor exited $RC (expected 0)"; }
assert_json_field /tmp/vendor.json '"status": "success"'
assert_json_field /tmp/vendor.json '"action": "applied"'
assert_json_field /tmp/vendor.json "$PURL"
assert_summary /tmp/vendor.json applied 1
assert_summary /tmp/vendor.json failed 0
echo "===VENDOR RUN VERIFIED==="

# Artifact: wheel under the stable path convention, files[] hash == wheel
# sha256 (the same hash the lock entry carries), plus marker + ledger.
WHEEL=$(ls ".socket/vendor/pypi/__UUID__"/*.whl 2>/dev/null | head -1)
[ -n "$WHEEL" ] || { ls -R .socket/vendor >&2 || true; fail "no wheel under .socket/vendor/pypi/__UUID__/"; }
WHEEL_NAME=$(basename "$WHEEL")
WHEEL_SHA=$(sha256sum "$WHEEL" | cut -d' ' -f1)
echo "$WHEEL_NAME" > /workspace/snap/wheel-name
echo "$WHEEL_SHA" > /workspace/snap/wheel-sha
# six is pure-python → a portable py2.py3-none-any wheel name.
case "$WHEEL_NAME" in six-1.16.0-py2.py3-none-any.whl) ;; *) fail "unexpected wheel name $WHEEL_NAME" ;; esac
[ -f ".socket/vendor/pypi/__UUID__/socket-patch.vendor.json" ] \
  || fail "informational socket-patch.vendor.json marker missing"
[ -f ".socket/vendor/state.json" ] || fail "vendor ledger (.socket/vendor/state.json) missing"
echo "===ARTIFACT VERIFIED==="
"#;

// ── poetry ────────────────────────────────────────────────────────────────

/// Poetry stage 1 (in-project venv): `poetry add six==1.16.0`, marker patch,
/// offline vendor, the lock-only splice asserts, then fresh staging. Poetry's
/// wiring (spike P1/P2) reduces the `files` array to the single patched-wheel
/// `{file, hash}` element and appends a `package.source` table
/// (`type = "file"`); pyproject and content-hash stay untouched.
const POETRY_STAGE1: &str = r#"
mkdir -p /workspace/proj && cd /workspace/proj
export SOCKET_OFFLINE=1
# In-project venv so the crawler finds .venv/lib/pythonX/site-packages/six.py.
export POETRY_VIRTUALENVS_IN_PROJECT=true
export POETRY_CACHE_DIR=/tmp/poetry-cache-warm

# REAL fixture: poetry add resolves + installs six from pypi into .venv.
poetry init -n --name socket-vendor-capstone >/dev/null 2>&1 || fail "poetry init"
poetry add six==1.16.0 > /tmp/add.log 2>&1 || { cat /tmp/add.log >&2; fail "poetry add six failed"; }
[ -d .venv ] || { ls -la >&2; fail "no in-project .venv after poetry add"; }
ORIG=$(ls .venv/lib/python*/site-packages/six.py 2>/dev/null | head -1)
[ -n "$ORIG" ] || fail "six.py not found in the in-project venv"

mkdir -p /workspace/snap
cp pyproject.toml /workspace/snap/pyproject.prevendor
cp poetry.lock /workspace/snap/poetry.lock.prevendor

# The staged record carries one advisory so the manifest-less VEX stage has
# a statement to attest (a poetry-only wrapper; the shared body is as-is).
eval "stage_patch_without_vuln() $(declare -f stage_patch | tail -n +2)"
stage_patch() { stage_patch_without_vuln "$@" __GHSA__ __CVE__; }

__VENDOR_COMMON__

# Lock wiring (poetry row): the six [[package]] unit now carries the single
# patched-wheel files[] entry whose hash == WHEEL_SHA, plus a
# [package.source] type="file" url pointing at the vendored wheel.
URL=".socket/vendor/pypi/__UUID__/$WHEEL_NAME"
grep -qF "hash = \"sha256:$WHEEL_SHA\"" poetry.lock \
  || { cat poetry.lock >&2; fail "poetry.lock files[] hash != vendored wheel sha256"; }
grep -qF 'type = "file"' poetry.lock || { cat poetry.lock >&2; fail "no [package.source] type=file in poetry.lock"; }
grep -qF "url = \"$URL\"" poetry.lock || { cat poetry.lock >&2; fail "poetry.lock source url is not the vendored wheel"; }
# Single files[] entry for six (the tar.gz + registry wheel were dropped):
N=$(awk '/^name = "six"$/{f=1} f&&/^files = \[/{infiles=1;next} infiles&&/^\]/{infiles=0;f=0} infiles&&/file = /{c++} END{print c+0}' poetry.lock)
[ "$N" = "1" ] || { cat poetry.lock >&2; fail "six files[] has $N entries, expected exactly 1"; }
# pyproject + content-hash are NEVER touched by the poetry lock-only splice.
cmp -s pyproject.toml /workspace/snap/pyproject.prevendor \
  || { diff /workspace/snap/pyproject.prevendor pyproject.toml >&2 || true; fail "vendor must NOT touch pyproject.toml"; }
echo "===LOCK WIRING VERIFIED==="

# Fresh-checkout staging: ONLY the committable files.
rm -rf /workspace/fresh && mkdir -p /workspace/fresh
cp pyproject.toml poetry.lock /workspace/fresh/
cp -R .socket /workspace/fresh/.socket
echo "===STAGE1 VERIFIED==="
exit 0
"#;

/// Poetry stage 2 (`--network none`): strictest install proof + RED probe.
/// Strictest (spike P2/P7): `poetry check --lock && poetry sync` with a fresh
/// `POETRY_CACHE_DIR` and in-project venv. The RED probe deletes
/// `.socket/vendor` first and requires `poetry sync` to FAIL.
const POETRY_STAGE2: &str = r#"
cd /workspace/fresh
export POETRY_VIRTUALENVS_IN_PROJECT=true

[ ! -e .venv ] || fail "fresh checkout already has .venv (test bug: uncommittable file copied)"

# RED PROBE: with the vendored artifact removed, the strictest install MUST
# fail (the relative file:// source resolves to a now-missing wheel).
mv .socket/vendor /tmp/vendor-stash
export POETRY_CACHE_DIR=/tmp/poetry-cache-red
poetry sync --no-root --no-interaction > /tmp/red.log 2>&1
RED_RC=$?
rm -rf .venv
[ "$RED_RC" -ne 0 ] || { cat /tmp/red.log >&2; fail "RED PROBE VACUOUS: poetry sync SUCCEEDED with .socket/vendor removed"; }
mv /tmp/vendor-stash .socket/vendor
echo "===RED PROBE VERIFIED==="

# GREEN: cold cache, network cut, the vendored wheel is the only six source.
# `--no-root` because `poetry init` makes a packaged project with no source
# layout; we only care about the dependency (six) install, not the root.
export POETRY_CACHE_DIR=/tmp/poetry-cache-cold
poetry check --lock > /tmp/check.log 2>&1 || { cat /tmp/check.log >&2; fail "poetry check --lock failed"; }
poetry sync --no-root --no-interaction > /tmp/sync.log 2>&1 || { cat /tmp/sync.log >&2; fail "cold-cache offline poetry sync failed"; }
cat /tmp/sync.log >&2
echo "===FRESH INSTALL VERIFIED==="

# Runtime proof: six.py installed into the venv is the PATCHED bytes.
SIX=$(ls .venv/lib/python*/site-packages/six.py 2>/dev/null | head -1)
[ -n "$SIX" ] || fail "six.py not installed into the venv"
grep -q 'SOCKET-PATCH-VENDOR-E2E-MARKER' "$SIX" || { head -3 "$SIX" >&2; fail "installed six.py is not patched"; }
[ "$(sha256sum "$SIX" | cut -d' ' -f1)" = "$(cat /workspace/snap/patched.sha)" ] \
  || fail "installed six.py not byte-identical to the patched blob"
OUT=$(poetry run python -c 'import six; print(six.SOCKET_PATCH_VENDOR_E2E)' 2>&1) \
  || { echo "$OUT" >&2; fail "import six probe failed"; }
echo "$OUT" | grep -qF "__UUID__" || { echo "$OUT" >&2; fail "import six did not carry the patch uuid"; }
echo "===RUNTIME MARKER VERIFIED==="
exit 0
"#;

/// Advisory the poetry capstone's staged record carries (VEX statement id).
const POETRY_GHSA: &str = "GHSA-poet-ryvx-dk01";
const POETRY_CVE: &str = "CVE-2026-7301";

/// Poetry stage 2b (`--network none`): manifest-less VEX over copies of the
/// installed fresh checkout (`/workspace/fresh`, patched six installed from
/// the vendored wheel), with the IMAGE's binary and no network at all:
///   (1) `.socket/manifest.json` deleted, ledger kept → attested `(vendored)`
///       offline from the ledger's embedded record (standalone `vex` and
///       embedded `apply --vex`);
///   (3) both ledgers deleted, `--offline` → `record_unavailable`, no doc;
///   (4) the lock reverted to the registry version, ledger + artifact kept →
///       `vendor_unwired`, under `--no-verify` too.
/// Step (2) — no ledgers, record from the patch API — runs on the HOST
/// against `/workspace/vex-noledger` (a wiremock API needs a network).
/// Every copy is made world-writable at the end so the host can clean up.
const POETRY_STAGE2_VEX: &str = r#"
export SOCKET_TELEMETRY_DISABLED=1
PRODUCT="pkg:pypi/socket-vendor-capstone@0.1.0"
fresh_copy() {
  rm -rf "/workspace/$1" && cp -R /workspace/fresh "/workspace/$1" || fail "copy $1"
  rm -f "/workspace/$1/.socket/manifest.json"
}

fresh_copy vex-ledger
cd /workspace/vex-ledger
[ -f .socket/vendor/state.json ] || fail "vendor ledger missing from the committed state"
socket-patch vex --json --offline --output /tmp/v1.json --product "$PRODUCT" > /tmp/v1.env 2>/tmp/v1.err
RC=$?
[ "$RC" -eq 0 ] || { cat /tmp/v1.env /tmp/v1.err >&2; fail "manifest-less vex (ledger, offline) exited $RC"; }
assert_json_field /tmp/v1.json "Patched via Socket patch __UUID__ (vendored)"
assert_json_field /tmp/v1.json '"__GHSA__"'
assert_json_field /tmp/v1.json '"__CVE__"'
assert_json_field /tmp/v1.json 'pkg:pypi/six@1.16.0'
[ ! -e .socket/manifest.json ] || fail "vex wrote a manifest"
socket-patch apply --json --offline --vex /tmp/va.json --vex-product "$PRODUCT" > /tmp/va.env 2>/tmp/va.err
RC=$?
[ "$RC" -eq 0 ] || { cat /tmp/va.env /tmp/va.err >&2; fail "manifest-less apply --vex exited $RC"; }
assert_json_field /tmp/va.env '"noManifest"'
assert_json_field /tmp/va.json "Patched via Socket patch __UUID__ (vendored)"
echo "===VEX LEDGER VERIFIED==="

fresh_copy vex-noledger
cd /workspace/vex-noledger
rm -f .socket/vendor/state.json .socket/vendor/redirect-state.json
socket-patch vex --json --offline --output /tmp/v3.json --product "$PRODUCT" > /tmp/v3.env 2>/tmp/v3.err
RC=$?
[ "$RC" -eq 1 ] || { cat /tmp/v3.env /tmp/v3.err >&2; fail "offline ledger-less vex exited $RC (expected 1)"; }
assert_json_field /tmp/v3.env '"record_unavailable"'
[ ! -e /tmp/v3.json ] || fail "offline ledger-less vex wrote a document"
echo "===VEX OFFLINE VERIFIED==="

fresh_copy vex-reverted
cd /workspace/vex-reverted
cp /workspace/snap/poetry.lock.prevendor poetry.lock
[ -d .socket/vendor/pypi/__UUID__ ] || fail "artifact must stay behind"
for NV in "" "--no-verify"; do
  rm -f /tmp/v4.json
  socket-patch vex --json --offline --output /tmp/v4.json --product "$PRODUCT" $NV > /tmp/v4.env 2>/tmp/v4.err
  RC=$?
  [ "$RC" -eq 1 ] || { cat /tmp/v4.env /tmp/v4.err >&2; fail "reverted-lock vex $NV exited $RC (expected 1)"; }
  assert_json_field /tmp/v4.env '"vendor_unwired"'
  [ ! -e /tmp/v4.json ] || fail "reverted-lock vex $NV wrote a document"
done
echo "===VEX REVERTED VERIFIED==="
chmod -R a+rwX /workspace/vex-ledger /workspace/vex-noledger /workspace/vex-reverted
exit 0
"#;

/// Poetry stage 3 (`--network none`): idempotent re-vendor → revert
/// (byte-identical lock restore + full `.socket/vendor` removal) → re-vendor.
const POETRY_STAGE3: &str = r#"
cd /workspace/proj
export SOCKET_OFFLINE=1

LOCK_SHA_BEFORE=$(sha256sum poetry.lock | cut -d' ' -f1)
socket-patch vendor --json --offline > /tmp/revendor.json 2>/tmp/revendor.err
RC=$?; cat /tmp/revendor.err >&2
[ "$RC" -eq 0 ] || { cat /tmp/revendor.json >&2; fail "re-vendor exited $RC"; }
assert_summary /tmp/revendor.json failed 0
assert_json_field /tmp/revendor.json '"already_vendored"'
[ "$LOCK_SHA_BEFORE" = "$(sha256sum poetry.lock | cut -d' ' -f1)" ] || fail "re-vendor churned poetry.lock"
echo "===IDEMPOTENT VERIFIED==="

socket-patch vendor --revert --json --offline > /tmp/revert.json 2>/tmp/revert.err
RC=$?; cat /tmp/revert.err >&2
[ "$RC" -eq 0 ] || { cat /tmp/revert.json >&2; fail "revert exited $RC"; }
assert_json_field /tmp/revert.json '"status": "success"'
assert_summary /tmp/revert.json removed 1
cmp -s poetry.lock /workspace/snap/poetry.lock.prevendor \
  || { diff /workspace/snap/poetry.lock.prevendor poetry.lock >&2 || true; fail "revert did not byte-restore poetry.lock"; }
[ ! -e .socket/vendor ] || fail ".socket/vendor must be fully removed after revert"
echo "===REVERT VERIFIED==="

socket-patch vendor --json --offline > /tmp/revendor2.json 2>/tmp/revendor2.err
RC=$?; cat /tmp/revendor2.err >&2
[ "$RC" -eq 0 ] || { cat /tmp/revendor2.json >&2; fail "post-revert re-vendor exited $RC"; }
assert_summary /tmp/revendor2.json applied 1
assert_summary /tmp/revendor2.json failed 0
[ -d ".socket/vendor/pypi/__UUID__" ] || fail "re-vendor did not recreate the artifact dir"
grep -qF 'type = "file"' poetry.lock || fail "re-vendor did not rewire poetry.lock"
echo "===REVENDOR VERIFIED==="
exit 0
"#;

// ── pdm ───────────────────────────────────────────────────────────────────

/// PDM stage 1 (in-project venv): `pdm init -n`, `pdm add six==1.16.0`,
/// marker patch, offline vendor, the lock-only splice asserts, then fresh
/// staging. PDM's wiring (spike D1) inserts a relative `path = "./…"` key
/// after `requires_python` and reduces the `files` array to the single
/// patched-wheel hash; pyproject and content_hash stay untouched.
const PDM_STAGE1: &str = r#"
mkdir -p /workspace/proj && cd /workspace/proj
export SOCKET_OFFLINE=1
export PDM_CACHE_DIR=/tmp/pdm-cache-warm
# In-project venv so the crawler finds .venv/.../site-packages/six.py.
pdm config python.use_venv true >/dev/null 2>&1

pdm init -n > /tmp/init.log 2>&1 || { cat /tmp/init.log >&2; fail "pdm init failed"; }
pdm add six==1.16.0 > /tmp/add.log 2>&1 || { cat /tmp/add.log >&2; fail "pdm add six failed"; }
[ -d .venv ] || { ls -la >&2; fail "no in-project .venv after pdm add"; }
ORIG=$(ls .venv/lib/python*/site-packages/six.py 2>/dev/null | head -1)
[ -n "$ORIG" ] || fail "six.py not found in the in-project venv"

mkdir -p /workspace/snap
cp pyproject.toml /workspace/snap/pyproject.prevendor
cp pdm.lock /workspace/snap/pdm.lock.prevendor

# The PDM record carries one vulnerability (the shared staging leaves it
# empty) so stage 2's manifest-less VEX has a statement to attest: wrap the
# shared `stage_patch` for this flavor only.
eval "orig_$(declare -f stage_patch)"
stage_patch() { orig_stage_patch "$@" GHSA-pdmv-dock-0001 CVE-2026-7301; }

__VENDOR_COMMON__

# Lock wiring (pdm row): a relative path key on six pointing at the vendored
# wheel, and files[] reduced to the single patched-wheel hash == WHEEL_SHA.
grep -qF "path = \"./.socket/vendor/pypi/__UUID__/$WHEEL_NAME\"" pdm.lock \
  || { cat pdm.lock >&2; fail "pdm.lock six entry has no relative path= to the vendored wheel"; }
grep -qF "hash = \"sha256:$WHEEL_SHA\"" pdm.lock \
  || { cat pdm.lock >&2; fail "pdm.lock files[] hash != vendored wheel sha256"; }
N=$(awk '/^name = "six"$/{f=1} f&&/files = \[/{infiles=1} infiles{c+=gsub(/file = /,"&")} infiles&&/\]/{infiles=0;f=0} END{print c+0}' pdm.lock)
[ "$N" = "1" ] || { cat pdm.lock >&2; fail "six files[] has $N entries, expected exactly 1"; }
# pyproject + content_hash are NEVER touched by the pdm lock-only splice.
cmp -s pyproject.toml /workspace/snap/pyproject.prevendor \
  || { diff /workspace/snap/pyproject.prevendor pyproject.toml >&2 || true; fail "vendor must NOT touch pyproject.toml"; }
echo "===LOCK WIRING VERIFIED==="

rm -rf /workspace/fresh && mkdir -p /workspace/fresh
cp pyproject.toml pdm.lock /workspace/fresh/
cp -R .socket /workspace/fresh/.socket
echo "===STAGE1 VERIFIED==="
exit 0
"#;

/// PDM stage 2 (`--network none`): strictest install proof + RED probe.
/// Strictest (spike D2): `pdm install --check && pdm sync` with a fresh
/// `PDM_CACHE_DIR` and in-project venv. The `.pdm-python` venv pointer is
/// gitignored in real checkouts and not copied here, so the fresh dir
/// re-creates its own venv. RED probe deletes `.socket/vendor` first.
const PDM_STAGE2: &str = r#"
cd /workspace/fresh
pdm config python.use_venv true >/dev/null 2>&1

[ ! -e .venv ] || fail "fresh checkout already has .venv (test bug: uncommittable file copied)"
[ ! -e .pdm-python ] || fail "fresh checkout carried a .pdm-python venv pointer (gitignored; should not be committed)"

# RED PROBE: with the vendored wheel removed, sync MUST fail (path source gone).
mv .socket/vendor /tmp/vendor-stash
export PDM_CACHE_DIR=/tmp/pdm-cache-red
pdm sync > /tmp/red.log 2>&1
RED_RC=$?
rm -rf .venv .pdm-python
[ "$RED_RC" -ne 0 ] || { cat /tmp/red.log >&2; fail "RED PROBE VACUOUS: pdm sync SUCCEEDED with .socket/vendor removed"; }
mv /tmp/vendor-stash .socket/vendor
echo "===RED PROBE VERIFIED==="

# GREEN: cold cache, network cut, the vendored wheel is the only six source.
export PDM_CACHE_DIR=/tmp/pdm-cache-cold
pdm install --check > /tmp/check.log 2>&1 || { cat /tmp/check.log >&2; fail "pdm install --check failed"; }
pdm sync > /tmp/sync.log 2>&1 || { cat /tmp/sync.log >&2; fail "cold-cache offline pdm sync failed"; }
cat /tmp/sync.log >&2
echo "===FRESH INSTALL VERIFIED==="

SIX=$(ls .venv/lib/python*/site-packages/six.py 2>/dev/null | head -1)
[ -n "$SIX" ] || fail "six.py not installed into the venv"
grep -q 'SOCKET-PATCH-VENDOR-E2E-MARKER' "$SIX" || { head -3 "$SIX" >&2; fail "installed six.py is not patched"; }
[ "$(sha256sum "$SIX" | cut -d' ' -f1)" = "$(cat /workspace/snap/patched.sha)" ] \
  || fail "installed six.py not byte-identical to the patched blob"
OUT=$(pdm run python -c 'import six; print(six.SOCKET_PATCH_VENDOR_E2E)' 2>&1) \
  || { echo "$OUT" >&2; fail "import six probe failed"; }
echo "$OUT" | grep -qF "__UUID__" || { echo "$OUT" >&2; fail "import six did not carry the patch uuid"; }
echo "===RUNTIME MARKER VERIFIED==="

# Manifest-less VEX on the installed fresh checkout (`--offline`: the
# container has no network; the online record fetch is covered by the host
# suites e2e_vex_lockfile::pdm / e2e_vex_build::pdm).
vex_run() {  # vex_run <tag> [flags...] -> RC, /tmp/<tag>.env, /tmp/<tag>.vex
  local tag="$1"; shift
  rm -f "/tmp/$tag.vex"
  socket-patch vex --json --offline --output "/tmp/$tag.vex" --product pkg:pypi/app@0.1.0 "$@" \
    > "/tmp/$tag.env" 2> "/tmp/$tag.err"
  RC=$?
}
attests() {  # attests <doc>
  [ -f "$1" ] && grep -qF 'pkg:pypi/six@1.16.0' "$1" && grep -qF 'GHSA-pdmv-dock-0001' "$1" \
    && grep -qF 'Patched via Socket patch __UUID__ (vendored)' "$1"
}
[ -f .socket/manifest.json ] || fail "stage 1 staged a manifest; the fresh copy must carry it"
rm .socket/manifest.json
vex_run ledger
[ "$RC" -eq 0 ] && attests /tmp/ledger.vex \
  || { cat /tmp/ledger.env /tmp/ledger.err >&2; fail "manifest-less vex (ledger kept) did not attest"; }
socket-patch apply --json --offline --vex /tmp/apply.vex --vex-product pkg:pypi/app@0.1.0 > /tmp/apply.env 2>&1 \
  && attests /tmp/apply.vex \
  || { cat /tmp/apply.env >&2; fail "manifest-less apply --vex did not attest"; }
[ ! -e .socket/manifest.json ] || fail "vex/apply must never write a manifest"
echo "===VEX MANIFEST DELETED VERIFIED==="
mv .socket/vendor/state.json /tmp/state.json.stash
vex_run noledger
[ "$RC" -eq 1 ] && [ ! -e /tmp/noledger.vex ] && grep -qF '"errorCode": "record_unavailable"' /tmp/noledger.env \
  || { cat /tmp/noledger.env /tmp/noledger.err >&2; fail "offline vex with no ledger must omit record_unavailable"; }
echo "===VEX OFFLINE NO LEDGER VERIFIED==="
mv /tmp/state.json.stash .socket/vendor/state.json
cp pdm.lock /tmp/pdm.lock.wired
cp /workspace/snap/pdm.lock.prevendor pdm.lock
for nv in "" --no-verify; do
  vex_run reverted $nv
  [ "$RC" -eq 1 ] && [ ! -e /tmp/reverted.vex ] && grep -qF '"errorCode": "vendor_unwired"' /tmp/reverted.env \
    || { cat /tmp/reverted.env /tmp/reverted.err >&2; fail "reverted lock must omit vendor_unwired ($nv)"; }
done
cp /tmp/pdm.lock.wired pdm.lock
echo "===VEX REVERTED VERIFIED==="
exit 0
"#;

/// PDM stage 3 (`--network none`): idempotent → revert → re-vendor.
const PDM_STAGE3: &str = r#"
cd /workspace/proj
export SOCKET_OFFLINE=1

LOCK_SHA_BEFORE=$(sha256sum pdm.lock | cut -d' ' -f1)
socket-patch vendor --json --offline > /tmp/revendor.json 2>/tmp/revendor.err
RC=$?; cat /tmp/revendor.err >&2
[ "$RC" -eq 0 ] || { cat /tmp/revendor.json >&2; fail "re-vendor exited $RC"; }
assert_summary /tmp/revendor.json failed 0
assert_json_field /tmp/revendor.json '"already_vendored"'
[ "$LOCK_SHA_BEFORE" = "$(sha256sum pdm.lock | cut -d' ' -f1)" ] || fail "re-vendor churned pdm.lock"
echo "===IDEMPOTENT VERIFIED==="

socket-patch vendor --revert --json --offline > /tmp/revert.json 2>/tmp/revert.err
RC=$?; cat /tmp/revert.err >&2
[ "$RC" -eq 0 ] || { cat /tmp/revert.json >&2; fail "revert exited $RC"; }
assert_json_field /tmp/revert.json '"status": "success"'
assert_summary /tmp/revert.json removed 1
cmp -s pdm.lock /workspace/snap/pdm.lock.prevendor \
  || { diff /workspace/snap/pdm.lock.prevendor pdm.lock >&2 || true; fail "revert did not byte-restore pdm.lock"; }
[ ! -e .socket/vendor ] || fail ".socket/vendor must be fully removed after revert"
echo "===REVERT VERIFIED==="

socket-patch vendor --json --offline > /tmp/revendor2.json 2>/tmp/revendor2.err
RC=$?; cat /tmp/revendor2.err >&2
[ "$RC" -eq 0 ] || { cat /tmp/revendor2.json >&2; fail "post-revert re-vendor exited $RC"; }
assert_summary /tmp/revendor2.json applied 1
assert_summary /tmp/revendor2.json failed 0
[ -d ".socket/vendor/pypi/__UUID__" ] || fail "re-vendor did not recreate the artifact dir"
grep -qF "path = \"./.socket/vendor/pypi/__UUID__/" pdm.lock || fail "re-vendor did not rewire pdm.lock"
echo "===REVENDOR VERIFIED==="
exit 0
"#;

// ── pipenv ──────────────────────────────────────────────────────────────────

/// pipenv stage 1 (in-project venv): `pipenv install six==1.16.0`, marker
/// patch, offline vendor, the lock-only entry-rewrite asserts, then fresh
/// staging. pipenv's wiring (spike V1/V2) rewrites `default.six` to
/// `{file: "./<wheel>", hashes: [sha256:<patched>], markers}` (dropping
/// index and version); Pipfile stays untouched. The suite also asserts the
/// `vendor_integrity_unverified` warning surfaces in the vendor envelope.
const PIPENV_STAGE1: &str = r#"
mkdir -p /workspace/proj && cd /workspace/proj
export SOCKET_OFFLINE=1
export PIPENV_VENV_IN_PROJECT=1
export PIPENV_CACHE_DIR=/tmp/pipenv-cache-warm
export PIP_CACHE_DIR=/tmp/pip-cache-warm

# REAL fixture: pipenv install resolves + installs six from pypi into .venv.
pipenv install six==1.16.0 > /tmp/install.log 2>&1 || { cat /tmp/install.log >&2; fail "pipenv install six failed"; }
[ -d .venv ] || { ls -la >&2; fail "no in-project .venv after pipenv install"; }
ORIG=$(ls .venv/lib/python*/site-packages/six.py 2>/dev/null | head -1)
[ -n "$ORIG" ] || fail "six.py not found in the in-project venv"

mkdir -p /workspace/snap
cp Pipfile /workspace/snap/Pipfile.prevendor
cp Pipfile.lock /workspace/snap/Pipfile.lock.prevendor

__VENDOR_COMMON__

# pipenv has NO hash enforcement on file entries (spike V4) — the vendor run
# MUST surface the documented warning as a skipped event in the envelope.
assert_json_field /tmp/vendor.json '"errorCode": "vendor_integrity_unverified"'
echo "===INTEGRITY WARNING VERIFIED==="

# Lock wiring (pipenv row): default.six is now {file, hashes:[patched], markers}
# with index + version dropped; the recorded hash is WHEEL_SHA; Pipfile is
# untouched.
python3 - "$WHEEL_SHA" "$WHEEL_NAME" <<'PYEOF' || { cat Pipfile.lock >&2; fail "Pipfile.lock six entry wiring wrong"; }
import json, sys
sha, wheel = sys.argv[1], sys.argv[2]
d = json.load(open("Pipfile.lock"))
e = d["default"]["six"]
assert e.get("file") == f"./.socket/vendor/pypi/__UUID__/{wheel}", e
assert e.get("hashes") == [f"sha256:{sha}"], e
assert "index" not in e, e
assert "version" not in e, e
assert "markers" in e, "markers must be preserved"
PYEOF
cmp -s Pipfile /workspace/snap/Pipfile.prevendor \
  || { diff /workspace/snap/Pipfile.prevendor Pipfile >&2 || true; fail "vendor must NOT touch Pipfile"; }
echo "===LOCK WIRING VERIFIED==="

rm -rf /workspace/fresh && mkdir -p /workspace/fresh
cp Pipfile Pipfile.lock /workspace/fresh/
cp -R .socket /workspace/fresh/.socket
echo "===STAGE1 VERIFIED==="
exit 0
"#;

/// pipenv stage 2 (`--network none`): strictest install proof + RED probe.
/// Strictest (spike V2): `pipenv install --deploy && pipenv verify` with a
/// fresh cache + `PIPENV_VENV_IN_PROJECT=1`. pipenv does NOT hash-verify file
/// entries (spike V4), so the committable proof is "the patched bytes get
/// imported"; the RED probe (delete .socket/vendor) still fails because the
/// referenced wheel is gone (a missing path is a hard pip error, distinct
/// from the hash gap).
const PIPENV_STAGE2: &str = r#"
cd /workspace/fresh
export PIPENV_VENV_IN_PROJECT=1

[ ! -e .venv ] || fail "fresh checkout already has .venv (test bug: uncommittable file copied)"

# RED PROBE: with the vendored wheel removed, --deploy MUST fail (the file ref
# resolves to a missing wheel — a pip "file does not exist" error).
mv .socket/vendor /tmp/vendor-stash
export PIPENV_CACHE_DIR=/tmp/pipenv-cache-red
export PIP_CACHE_DIR=/tmp/pip-cache-red
pipenv install --deploy > /tmp/red.log 2>&1
RED_RC=$?
rm -rf .venv
[ "$RED_RC" -ne 0 ] || { cat /tmp/red.log >&2; fail "RED PROBE VACUOUS: pipenv install --deploy SUCCEEDED with .socket/vendor removed"; }
mv /tmp/vendor-stash .socket/vendor
echo "===RED PROBE VERIFIED==="

# GREEN: cold cache, network cut, the vendored wheel is the only six source.
export PIPENV_CACHE_DIR=/tmp/pipenv-cache-cold
export PIP_CACHE_DIR=/tmp/pip-cache-cold
pipenv install --deploy > /tmp/deploy.log 2>&1 || { cat /tmp/deploy.log >&2; fail "cold-cache offline pipenv install --deploy failed"; }
cat /tmp/deploy.log >&2
pipenv verify > /tmp/verify.log 2>&1 || { cat /tmp/verify.log >&2; fail "pipenv verify failed"; }
echo "===FRESH INSTALL VERIFIED==="

# Runtime proof: pipenv does NOT enforce the recorded hash, so the proof is
# that the imported six IS the patched bytes (marker present).
SIX=$(ls .venv/lib/python*/site-packages/six.py 2>/dev/null | head -1)
[ -n "$SIX" ] || fail "six.py not installed into the venv"
grep -q 'SOCKET-PATCH-VENDOR-E2E-MARKER' "$SIX" || { head -3 "$SIX" >&2; fail "installed six.py is not patched"; }
[ "$(sha256sum "$SIX" | cut -d' ' -f1)" = "$(cat /workspace/snap/patched.sha)" ] \
  || fail "installed six.py not byte-identical to the patched blob"
OUT=$(pipenv run python -c 'import six; print(six.SOCKET_PATCH_VENDOR_E2E)' 2>&1) \
  || { echo "$OUT" >&2; fail "import six probe failed"; }
echo "$OUT" | grep -qF "__UUID__" || { echo "$OUT" >&2; fail "import six did not carry the patch uuid"; }
echo "===RUNTIME MARKER VERIFIED==="
exit 0
"#;

/// pipenv stage 2b (`--network none`): manifest-less VEX over the
/// INSTALLED fresh checkout stage 2 left behind (each step on its own copy):
/// manifest deleted, vendor ledger kept → attested `(vendored)` offline from
/// the ledger record; ledger deleted too → `--offline` is
/// `record_unavailable` (no API in this sandbox — the online ledger-less
/// step is covered by `e2e_vex_build/pipenv.rs` / `e2e_vex_lockfile/pipenv.rs`);
/// Pipfile.lock reverted to the registry with ledger + wheel kept →
/// `vendor_unwired`, `--no-verify` too; `apply --vex` on the manifest-less
/// checkout attests.
const PIPENV_STAGE_VEX: &str = r#"
PRODUCT="pkg:pypi/app@0.1.0"
checkout() {
  rm -rf "/workspace/vex-$1" && cp -R /workspace/fresh "/workspace/vex-$1" && cd "/workspace/vex-$1" \
    || fail "copying the fresh checkout"
  [ -d .venv ] || fail "stage 2 left no installed venv"
  [ -f .socket/manifest.json ] || fail "fixture: the committed state carries the manifest"
  rm -f .socket/manifest.json
}
# vex_json <envelope> <doc> [flags...]: standalone vex, exit code in $RC.
vex_json() {
  local env="$1" doc="$2"; shift 2
  rm -f "$doc"
  socket-patch vex --json --output "$doc" --product "$PRODUCT" "$@" > "$env" 2>"$env.err"
  RC=$?
}
# attested <doc>: exactly one not_affected six statement via the patch.
attested() {
  python3 - "$1" <<'PYEOF' || { cat "$1" >&2; fail "$1 does not attest six via __UUID__ (vendored)"; }
import json, sys
d = json.load(open(sys.argv[1]))
st = d["statements"]
assert len(st) == 1, st
s = st[0]
assert s["status"] == "not_affected", s
assert s["vulnerability"]["name"] == "GHSA-dock-pipv-0001", s
assert "CVE-2026-7501" in s["vulnerability"].get("aliases", []), s
subs = [c["@id"] for p in s["products"] for c in p.get("subcomponents", [])]
assert [x.split("?")[0] for x in subs] == ["pkg:pypi/six@1.16.0"], subs
assert "Patched via Socket patch __UUID__ (vendored)" in s["impact_statement"], s
PYEOF
}
# omitted <envelope> <reason>: six skipped with that errorCode, not verified.
omitted() {
  python3 - "$1" "$2" <<'PYEOF' || { cat "$1" >&2; fail "$1 does not omit six as $2"; }
import json, sys
e = json.load(open(sys.argv[1]))
ev = [x for x in e.get("events", []) if x.get("purl", "").split("?")[0] == "pkg:pypi/six@1.16.0"]
assert not any(x["action"] == "verified" for x in ev), ev
assert any(x["action"] == "skipped" and x.get("errorCode") == sys.argv[2] for x in ev), ev
PYEOF
}

checkout manifest
vex_json /tmp/vex1.json /tmp/vex1.doc --offline
[ "$RC" -eq 0 ] || { cat /tmp/vex1.json /tmp/vex1.json.err >&2; fail "manifest-less vex exited $RC"; }
attested /tmp/vex1.doc
[ ! -e .socket/manifest.json ] || fail "vex must never write the manifest"
echo "===VEX MANIFEST-DELETED VERIFIED==="

checkout offline
rm -f .socket/vendor/state.json .socket/vendor/redirect-state.json
vex_json /tmp/vex2.json /tmp/vex2.doc --offline
[ "$RC" -eq 1 ] || { cat /tmp/vex2.json >&2; fail "ledger-less offline vex exited $RC (expected 1)"; }
[ ! -e /tmp/vex2.doc ] || fail "no document without a record"
omitted /tmp/vex2.json record_unavailable
echo "===VEX OFFLINE VERIFIED==="

checkout reverted
cp /workspace/snap/Pipfile.lock.prevendor Pipfile.lock
[ -f .socket/vendor/state.json ] || fail "fixture: the ledger stays"
for flag in "" --no-verify; do
  vex_json /tmp/vex3.json /tmp/vex3.doc --offline $flag
  [ "$RC" -eq 1 ] || { cat /tmp/vex3.json >&2; fail "reverted vex $flag exited $RC (expected 1)"; }
  [ ! -e /tmp/vex3.doc ] || fail "reverted $flag: no document"
  omitted /tmp/vex3.json vendor_unwired
done
echo "===VEX REVERTED VERIFIED==="

checkout apply
socket-patch apply --json --offline --vex /tmp/vex4.doc --vex-product "$PRODUCT" > /tmp/vex4.json 2>/tmp/vex4.err
RC=$?
[ "$RC" -eq 0 ] || { cat /tmp/vex4.json /tmp/vex4.err >&2; fail "apply --vex exited $RC"; }
attested /tmp/vex4.doc
echo "===VEX APPLY VERIFIED==="
exit 0
"#;

/// pipenv stage 3 (`--network none`): idempotent → revert → re-vendor.
const PIPENV_STAGE3: &str = r#"
cd /workspace/proj
export SOCKET_OFFLINE=1

LOCK_SHA_BEFORE=$(sha256sum Pipfile.lock | cut -d' ' -f1)
socket-patch vendor --json --offline > /tmp/revendor.json 2>/tmp/revendor.err
RC=$?; cat /tmp/revendor.err >&2
[ "$RC" -eq 0 ] || { cat /tmp/revendor.json >&2; fail "re-vendor exited $RC"; }
assert_summary /tmp/revendor.json failed 0
assert_json_field /tmp/revendor.json '"already_vendored"'
[ "$LOCK_SHA_BEFORE" = "$(sha256sum Pipfile.lock | cut -d' ' -f1)" ] || fail "re-vendor churned Pipfile.lock"
echo "===IDEMPOTENT VERIFIED==="

socket-patch vendor --revert --json --offline > /tmp/revert.json 2>/tmp/revert.err
RC=$?; cat /tmp/revert.err >&2
[ "$RC" -eq 0 ] || { cat /tmp/revert.json >&2; fail "revert exited $RC"; }
assert_json_field /tmp/revert.json '"status": "success"'
assert_summary /tmp/revert.json removed 1
cmp -s Pipfile.lock /workspace/snap/Pipfile.lock.prevendor \
  || { diff /workspace/snap/Pipfile.lock.prevendor Pipfile.lock >&2 || true; fail "revert did not byte-restore Pipfile.lock"; }
[ ! -e .socket/vendor ] || fail ".socket/vendor must be fully removed after revert"
echo "===REVERT VERIFIED==="

socket-patch vendor --json --offline > /tmp/revendor2.json 2>/tmp/revendor2.err
RC=$?; cat /tmp/revendor2.err >&2
[ "$RC" -eq 0 ] || { cat /tmp/revendor2.json >&2; fail "post-revert re-vendor exited $RC"; }
assert_summary /tmp/revendor2.json applied 1
assert_summary /tmp/revendor2.json failed 0
[ -d ".socket/vendor/pypi/__UUID__" ] || fail "re-vendor did not recreate the artifact dir"
grep -qF '.socket/vendor/pypi/__UUID__/' Pipfile.lock || fail "re-vendor did not rewire Pipfile.lock"
echo "===REVENDOR VERIFIED==="
exit 0
"#;

/// Splice the shared vendor body into a flavor stage-1 template, then render.
fn render_stage1(template: &str, uuid: &str) -> String {
    render(
        &template.replace("__VENDOR_COMMON__", STAGE1_VENDOR_COMMON),
        uuid,
    )
}

/// Render a poetry stage that names the capstone advisory.
fn render_poetry(stage: &str) -> String {
    render(stage, UUID_POETRY)
        .replace("__GHSA__", POETRY_GHSA)
        .replace("__CVE__", POETRY_CVE)
}

/// Step (2) of the manifest-less VEX matrix, on the HOST (stage 2b left the
/// copies world-readable): the ledger-less copy of the installed fresh
/// checkout attests `(vendored)` from the poetry.lock wiring + the record a
/// patch API serves (the committed wheel is hash-verified), while the
/// reverted copy stays unattested online too. The record is the one stage 1
/// staged (`proj/.socket/manifest.json`).
fn poetry_manifestless_vex_online(host: &std::path::Path) {
    use vex_e2e_common::{
        assert_attested, assert_not_attested, binary, run_vex, Marker, PatchApi, VexRun,
    };
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(host.join("proj/.socket/manifest.json")).expect("stage-1 manifest"),
    )
    .unwrap();
    let record = &manifest["patches"]["pkg:pypi/six@1.16.0"];
    assert_eq!(record["uuid"], UUID_POETRY, "{manifest}");
    let mut view = record.clone();
    view["purl"] = "pkg:pypi/six@1.16.0".into();
    view["publishedAt"] = "Tue, 01 Sep 2026 00:00:00 GMT".into();
    let api = PatchApi::start(vec![(UUID_POETRY.into(), view)]);
    let out_dir = tempfile::tempdir().unwrap();
    let run = |project: &str, offline: bool, extra: &[&str]| {
        let mut run = VexRun {
            offline,
            proxy_url: Some(api.uri()),
            product: Some("pkg:pypi/socket-vendor-capstone@0.1.0".into()),
            output: Some(out_dir.path().join(format!("{project}.vex.json"))),
            ..VexRun::default()
        };
        for arg in extra {
            run = run.arg(*arg);
        }
        let _ = std::fs::remove_file(out_dir.path().join(format!("{project}.vex.json")));
        run_vex(&binary(), &host.join(project), &run)
    };
    let out = run("vex-noledger", false, &[]);
    assert_eq!(out.code, Some(0), "host vex, no ledgers, online: {out}");
    assert_attested(
        out.doc(),
        "pkg:pypi/six@1.16.0",
        UUID_POETRY,
        Marker::Vendored,
        &[(POETRY_GHSA, &[POETRY_CVE])],
    );
    assert!(
        api.view_requests(UUID_POETRY) >= 1,
        "record came from the API"
    );
    let seen = api.request_count();
    let out = run("vex-noledger", true, &[]);
    assert_eq!(out.code, Some(1), "{out}");
    assert_not_attested(&out.envelope, "pkg:pypi/six@1.16.0", "record_unavailable");
    assert_eq!(api.request_count(), seen, "--offline made a request");
    for extra in [&[][..], &["--no-verify"][..]] {
        let out = run("vex-reverted", false, extra);
        assert_eq!(out.code, Some(1), "reverted {extra:?}: {out}");
        assert_not_attested(&out.envelope, "pkg:pypi/six@1.16.0", "vendor_unwired");
    }
}

fn host_dir() -> (tempfile::TempDir, std::path::PathBuf) {
    let tmp = tempfile::tempdir().expect("tempdir");
    // Canonicalize so the macOS `/var` → `/private/var` symlink doesn't
    // confuse Docker Desktop's file-sharing allowlist.
    let dir = tmp.path().canonicalize().expect("canonicalize tempdir");
    (tmp, dir)
}

#[test]
fn poetry_vendor_fresh_checkout_install_and_revert() {
    if skip_if_no_image(IMAGE) {
        return;
    }
    let (_tmp, host) = host_dir();

    let out = run_in_image(
        IMAGE,
        &host,
        &render_stage1(POETRY_STAGE1, UUID_POETRY)
            .replace("__GHSA__", POETRY_GHSA)
            .replace("__CVE__", POETRY_CVE),
    );
    assert_stage_markers(
        "poetry stage 1 (install+vendor)",
        &out,
        &["VENDOR RUN", "ARTIFACT", "LOCK WIRING", "STAGE1"],
    );

    let out = run_in_image_network_none(IMAGE, &host, &render(POETRY_STAGE2, UUID_POETRY));
    assert_stage_markers(
        "poetry stage 2 (fresh checkout, --network none)",
        &out,
        &["RED PROBE", "FRESH INSTALL", "RUNTIME MARKER"],
    );

    let out = run_in_image_network_none(IMAGE, &host, &render_poetry(POETRY_STAGE2_VEX));
    assert_stage_markers(
        "poetry stage 2b (manifest-less vex, --network none)",
        &out,
        &["VEX LEDGER", "VEX OFFLINE", "VEX REVERTED"],
    );
    poetry_manifestless_vex_online(&host);

    let out = run_in_image_network_none(IMAGE, &host, &render(POETRY_STAGE3, UUID_POETRY));
    assert_stage_markers(
        "poetry stage 3 (idempotent+revert+re-vendor)",
        &out,
        &["IDEMPOTENT", "REVERT", "REVENDOR"],
    );
}

#[test]
fn pdm_vendor_fresh_checkout_install_and_revert() {
    if skip_if_no_image(IMAGE) {
        return;
    }
    let (_tmp, host) = host_dir();

    let out = run_in_image(IMAGE, &host, &render_stage1(PDM_STAGE1, UUID_PDM));
    assert_stage_markers(
        "pdm stage 1 (install+vendor)",
        &out,
        &["VENDOR RUN", "ARTIFACT", "LOCK WIRING", "STAGE1"],
    );

    let out = run_in_image_network_none(IMAGE, &host, &render(PDM_STAGE2, UUID_PDM));
    assert_stage_markers(
        "pdm stage 2 (fresh checkout, --network none)",
        &out,
        &[
            "RED PROBE",
            "FRESH INSTALL",
            "RUNTIME MARKER",
            "VEX MANIFEST DELETED",
            "VEX OFFLINE NO LEDGER",
            "VEX REVERTED",
        ],
    );

    let out = run_in_image_network_none(IMAGE, &host, &render(PDM_STAGE3, UUID_PDM));
    assert_stage_markers(
        "pdm stage 3 (idempotent+revert+re-vendor)",
        &out,
        &["IDEMPOTENT", "REVERT", "REVENDOR"],
    );
}

#[test]
fn pipenv_vendor_fresh_checkout_install_and_revert() {
    if skip_if_no_image(IMAGE) {
        return;
    }
    let (_tmp, host) = host_dir();

    // The staged patch carries one advisory, so the manifest-less VEX stage
    // has a statement to attest.
    let stage_call = r#""six.py" "$ORIG" /tmp/patched.py
"#;
    let stage1 = render_stage1(PIPENV_STAGE1, UUID_PIPENV);
    assert!(stage1.contains(stage_call), "stage_patch call moved");
    let stage1 = stage1.replace(
        stage_call,
        r#""six.py" "$ORIG" /tmp/patched.py GHSA-dock-pipv-0001 CVE-2026-7501
"#,
    );
    let out = run_in_image(IMAGE, &host, &stage1);
    assert_stage_markers(
        "pipenv stage 1 (install+vendor)",
        &out,
        &[
            "VENDOR RUN",
            "ARTIFACT",
            "INTEGRITY WARNING",
            "LOCK WIRING",
            "STAGE1",
        ],
    );

    let out = run_in_image_network_none(IMAGE, &host, &render(PIPENV_STAGE2, UUID_PIPENV));
    assert_stage_markers(
        "pipenv stage 2 (fresh checkout, --network none)",
        &out,
        &["RED PROBE", "FRESH INSTALL", "RUNTIME MARKER"],
    );

    let out = run_in_image_network_none(IMAGE, &host, &render(PIPENV_STAGE_VEX, UUID_PIPENV));
    assert_stage_markers(
        "pipenv stage 2b (manifest-less vex, --network none)",
        &out,
        &[
            "VEX MANIFEST-DELETED",
            "VEX OFFLINE",
            "VEX REVERTED",
            "VEX APPLY",
        ],
    );

    let out = run_in_image_network_none(IMAGE, &host, &render(PIPENV_STAGE3, UUID_PIPENV));
    assert_stage_markers(
        "pipenv stage 3 (idempotent+revert+re-vendor)",
        &out,
        &["IDEMPOTENT", "REVERT", "REVENDOR"],
    );
}
