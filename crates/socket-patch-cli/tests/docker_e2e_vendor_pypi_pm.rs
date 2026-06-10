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

/// Poetry stage 1: `poetry add six==1.16.0` (in-project venv) + marker patch
/// + offline vendor + the lock-only `[[package]]` splice asserts + fresh
/// staging. Poetry's wiring (spike P1/P2): files[] reduced to the single
/// patched-wheel `{file, hash}`, a `[package.source] type="file"` table
/// appended; pyproject.toml + content-hash untouched.
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

/// PDM stage 1: `pdm init -n` + `pdm add six==1.16.0` (in-project venv) +
/// marker patch + offline vendor + the lock-only `[[package]]` splice asserts
/// + fresh staging. PDM's wiring (spike D1): a relative `path = "./…"` key
/// inserted after `requires_python`, files[] reduced to the single
/// patched-wheel hash; pyproject.toml + content_hash untouched.
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

__VENDOR_COMMON__

# Lock wiring (pdm row): a relative path key on six pointing at the vendored
# wheel, and files[] reduced to the single patched-wheel hash == WHEEL_SHA.
grep -qF "path = \"./.socket/vendor/pypi/__UUID__/$WHEEL_NAME\"" pdm.lock \
  || { cat pdm.lock >&2; fail "pdm.lock six entry has no relative path= to the vendored wheel"; }
grep -qF "hash = \"sha256:$WHEEL_SHA\"" pdm.lock \
  || { cat pdm.lock >&2; fail "pdm.lock files[] hash != vendored wheel sha256"; }
N=$(awk '/^name = "six"$/{f=1} f&&/^files = \[/{infiles=1;next} infiles&&/^\]/{infiles=0;f=0} infiles&&/file = /{c++} END{print c+0}' pdm.lock)
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

/// pipenv stage 1: `pipenv install six==1.16.0` (in-project venv) + marker
/// patch + offline vendor + the lock-only entry rewrite asserts + fresh
/// staging. pipenv's wiring (spike V1/V2): `default.six` becomes
/// `{file: "./<wheel>", hashes: [sha256:<patched>], markers}` (index +
/// version dropped); Pipfile untouched. Also asserts the
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
    render(&template.replace("__VENDOR_COMMON__", STAGE1_VENDOR_COMMON), uuid)
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

    let out = run_in_image(IMAGE, &host, &render_stage1(POETRY_STAGE1, UUID_POETRY));
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
        &["RED PROBE", "FRESH INSTALL", "RUNTIME MARKER"],
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

    let out = run_in_image(IMAGE, &host, &render_stage1(PIPENV_STAGE1, UUID_PIPENV));
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

    let out = run_in_image_network_none(IMAGE, &host, &render(PIPENV_STAGE3, UUID_PIPENV));
    assert_stage_markers(
        "pipenv stage 3 (idempotent+revert+re-vendor)",
        &out,
        &["IDEMPOTENT", "REVERT", "REVENDOR"],
    );
}
