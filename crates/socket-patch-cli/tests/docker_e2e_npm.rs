//! Docker-driven end-to-end test for the npm ecosystem.
//!
//! Installs `minimist@1.2.2` (a real, historically-vulnerable package) via
//! `npm install` inside a Linux container, then drives the full
//! `socket-patch scan` → `apply` → `rollback` chain against a wiremock-
//! served patch fixture. Asserts scan discovers the patch, apply writes
//! the patched bytes to disk, and rollback stays consistent (it may not
//! claim success while leaving the patch on disk, nor destroy the file
//! when it fails). NOTE: because the fixture uses a placeholder all-zero
//! beforeHash and serves no before-blob, an --offline rollback cannot
//! actually restore the original bytes here — that path is the offline
//! guard, not a genuine restore. See the summary in the audit notes.
//!
//! Run modes:
//!   - Default (Docker): requires Docker daemon. Pulls `socket-patch-test-
//!     npm:latest` (built from `tests/docker/Dockerfile.npm` — base built
//!     from `tests/docker/Dockerfile.base`). If the image isn't present
//!     the test fails with a clear build-instruction error.
//!   - Host mode: set `SOCKET_PATCH_TEST_HOST=1`. Skips Docker; runs npm
//!     and socket-patch on the host. Requires host-installed npm + a
//!     debug socket-patch binary at `target/debug/socket-patch`.
//!
//! Run command:
//!   `cargo test -p socket-patch-cli --features docker-e2e --test docker_e2e_npm`

#![cfg(feature = "docker-e2e")]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use sha2::{Digest, Sha256};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";
const PURL: &str = "pkg:npm/minimist@1.2.2";
const UUID: &str = "11111111-1111-4111-8111-111111111111";
/// The vulnerability the staged manifest carries, so the agent-mode VEX leg
/// has something to attest. Plain agent provenance (no vendored/redirected
/// marker) is what the host oracle asserts.
const GHSA: &str = "GHSA-agent-npm-real";

/// Marker we splice into the patched bytes so the test can assert
/// post-apply that the file has been overwritten.
const PATCHED_BYTES: &[u8] =
    b"/* SOCKET-PATCH-E2E-MARKER */\nmodule.exports = function () { return {}; };\n";

/// Git-SHA256: SHA256("blob <len>\0" ++ content). Matches the binary's
/// content-addressable hashing for fetched blobs.
fn git_sha256(content: &[u8]) -> String {
    let header = format!("blob {}\0", content.len());
    let mut hasher = Sha256::new();
    hasher.update(header.as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

/// Coverage instrumentation hook. The CI coverage-docker job sets
/// SOCKET_PATCH_COV_BIN (host path to an llvm-cov-instrumented
/// socket-patch binary) and SOCKET_PATCH_COV_PROFRAW_DIR (host dir
/// for in-container *.profraw output). When both are set, the docker
/// run mounts the instrumented binary over the image's baked-in
/// /usr/local/bin/socket-patch and points LLVM_PROFILE_FILE into a
/// host-visible volume so the in-container code paths contribute to
/// the host's lcov merge. Empty Vec when unset → tests use the
/// image's stock binary.
fn cov_docker_args() -> Vec<String> {
    let Ok(bin) = std::env::var("SOCKET_PATCH_COV_BIN") else {
        return Vec::new();
    };
    let Ok(dir) = std::env::var("SOCKET_PATCH_COV_PROFRAW_DIR") else {
        return Vec::new();
    };
    vec![
        "-v".into(),
        format!("{bin}:/usr/local/bin/socket-patch:ro"),
        "-v".into(),
        format!("{dir}:/coverage"),
        "-e".into(),
        "LLVM_PROFILE_FILE=/coverage/docker-e2e-%p-%14m.profraw".into(),
    ]
}

fn host_mode() -> bool {
    std::env::var("SOCKET_PATCH_TEST_HOST")
        .map(|v| v == "1")
        .unwrap_or(false)
}

fn workspace_root() -> PathBuf {
    // tests/ -> crate dir -> workspace root is up two levels from the
    // test binary's CARGO_MANIFEST_DIR (which is the CLI crate).
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .to_path_buf()
}

/// Build the wiremock that serves a synthetic patch fixture for
/// `pkg:npm/minimist@1.2.2`. Returns the server (which keeps the mocks
/// alive for the lifetime of the returned value).
async fn make_mock_server(after_hash: &str) -> MockServer {
    // Bind to 0.0.0.0 so the container can reach the host via the
    // `host.docker.internal` alias (added with `--add-host` in
    // `run_in_container`). Random port chosen by the kernel.
    let listener = std::net::TcpListener::bind("0.0.0.0:0").expect("bind wiremock to 0.0.0.0:0");
    let server = MockServer::builder().listener(listener).start().await;

    // 1. Batch search → returns one patch for the installed PURL.
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": PURL,
                "patches": [{
                    "uuid": UUID,
                    "purl": PURL,
                    "tier": "free",
                    "cveIds": ["CVE-2021-44906"],
                    "ghsaIds": ["GHSA-xvch-5gv4-984h"],
                    "severity": "high",
                    "title": "Synthetic prototype pollution patch (e2e fixture)"
                }]
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(&server)
        .await;

    // 2. By-package lookup (used by scan --apply for full PatchSearchResult).
    Mock::given(method("GET"))
        .and(path_regex(format!(
            "^/v0/orgs/{ORG}/patches/by-package/.+$"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [{
                "uuid": UUID,
                "purl": PURL,
                "publishedAt": "2024-01-01T00:00:00Z",
                "description": "E2E test fixture",
                "license": "MIT",
                "tier": "free",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(&server)
        .await;

    // 3. Full patch view with inline blobContent (base64). The CLI
    //    decodes + writes the bytes to .socket/blobs/<after_hash>.
    use base64::Engine;
    let blob_b64 = base64::engine::general_purpose::STANDARD.encode(PATCHED_BYTES);
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": UUID,
            "purl": PURL,
            "publishedAt": "2024-01-01T00:00:00Z",
            "files": {
                "package/index.js": {
                    // Placeholder beforeHash: doesn't match real minimist
                    // bytes, so apply's hash-verify reports HashMismatch.
                    // We pass --force to the apply step to override and
                    // exercise the blob-write path against real on-disk
                    // content. (`get.rs::download_and_apply_patches`
                    // requires both hashes to be Some, so we can't send
                    // null here.)
                    "beforeHash": "0000000000000000000000000000000000000000000000000000000000000000",
                    "afterHash":  after_hash,
                    "blobContent": blob_b64,
                }
            },
            // Recorded into the manifest so the agent-mode VEX leg attests it.
            "vulnerabilities": {
                (GHSA): {
                    "cves": ["CVE-2021-44906"],
                    "summary": "Synthetic prototype pollution (agent e2e fixture)",
                    "severity": "high",
                    "description": "Agent-mode VEX leg fixture vulnerability"
                }
            },
            "description": "E2E test fixture",
            "license": "MIT",
            "tier": "free",
        })))
        .mount(&server)
        .await;

    // 4. Raw blob endpoint (fallback for non-inline mode).
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/blob/{after_hash}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(PATCHED_BYTES.to_vec()))
        .mount(&server)
        .await;

    server
}

/// The wiremock URL as seen from inside the Docker container. The
/// `--add-host=host.docker.internal:host-gateway` flag we pass to
/// `docker run` makes the alias work on Linux too.
fn api_url_for_container(server: &MockServer) -> String {
    let port = server.address().port();
    format!("http://host.docker.internal:{port}")
}

/// Synthesize a small shell script that drives the full install →
/// scan → apply → rollback cycle inside the container. The script
/// exits 0 only if every step succeeds and the final read confirms
/// the rollback.
fn make_container_script(api_url: &str) -> String {
    // Note: no `set -e` so we capture every stage's stdout/stderr even
    // when an intermediate command fails. The final `grep` is the gate.
    format!(
        r#"#!/usr/bin/env bash
set -uo pipefail
COMMON_ARGS=(--api-url '{api_url}' --api-token fake --org {ORG})

# 1. Install the real package via real npm.
mkdir -p /workspace/proj && cd /workspace/proj
echo '{{ "name": "e2e-proj", "version": "0.0.0" }}' > package.json
npm install --silent --no-audit --no-fund minimist@1.2.2

# Pre-seed setup.manual so the agent-mode VEX leg (step 5b) keeps the npm
# patch through property 7: this project isn't `socket-patch setup`-configured,
# and an agent patch is applied by hand/CI — exactly what `manual` declares.
# scan --sync merges the downloaded patch into this manifest and preserves the
# setup block, so the manifest the VEX leg reads carries both.
mkdir -p .socket
cat > .socket/manifest.json <<'MANIFEST'
{{ "patches": {{}}, "setup": {{ "manual": ["npm"] }} }}
MANIFEST

# 2. scan --json: must discover the patch via the real batch API. A
#    clean exit alone proves nothing (a no-op scan also exits 0), so we
#    gate on exit==0 AND on the installed PURL and the available patch
#    UUID actually appearing in the JSON. If scan stops finding the
#    package or the patch, this fails loud instead of sailing through.
echo "===SCAN OUTPUT===" >&2
socket-patch scan --json "${{COMMON_ARGS[@]}}" >/tmp/scan.out 2>/tmp/scan.err
SCAN_RC=$?
echo "scan exit=$SCAN_RC" >&2
cat /tmp/scan.err >&2 || true
if [ "$SCAN_RC" -ne 0 ]; then
  echo "FAIL: scan exited $SCAN_RC (expected 0)" >&2
  cat /tmp/scan.out >&2
  exit 1
fi
if ! grep -q '{PURL}' /tmp/scan.out; then
  echo "FAIL: scan --json did not report the installed PURL {PURL}" >&2
  cat /tmp/scan.out >&2
  exit 1
fi
if ! grep -q '{UUID}' /tmp/scan.out; then
  echo "FAIL: scan --json did not report available patch UUID {UUID}" >&2
  cat /tmp/scan.out >&2
  exit 1
fi
echo "===SCAN VERIFIED===" >&2

# 3. scan --sync writes the manifest and applies the patch in one go.
echo "===SCAN/SYNC OUTPUT===" >&2
socket-patch scan --json --sync --yes "${{COMMON_ARGS[@]}}" >/tmp/sync.out 2>/tmp/sync.err
SYNC_RC=$?
echo "sync exit=$SYNC_RC" >&2
cat /tmp/sync.out >&2 || true
cat /tmp/sync.err >&2 || true

# 4. scan --sync may end up with "no installed package" (unmatched)
#    because the fixture's installed minimist has different bytes than
#    our synthetic patch expects. Force-apply via the manifest written
#    by scan above. apply must report success (exit 0) — not merely
#    leave a marker behind while reporting partial failure.
echo "===APPLY OUTPUT===" >&2
socket-patch apply --json --force --offline >/tmp/apply.out 2>/tmp/apply.err
APPLY_RC=$?
echo "apply exit=$APPLY_RC" >&2
cat /tmp/apply.out >&2 || true
cat /tmp/apply.err >&2 || true
if [ "$APPLY_RC" -ne 0 ]; then
  echo "FAIL: apply exited $APPLY_RC (expected 0 on a forced apply)" >&2
  exit 1
fi
# Exit 0 is necessary but not sufficient: a regression could exit 0 while
# emitting status="partial_failure"/"error" in the JSON. The guarantee is a
# clean success, so gate on the structured status too.
if ! grep -q '"status": *"success"' /tmp/apply.out; then
  echo "FAIL: apply exit 0 but JSON status is not success (partial_failure/error masked behind a clean exit?)" >&2
  cat /tmp/apply.out >&2
  exit 1
fi

echo "===POST-APPLY STATE===" >&2
echo "manifest:" >&2
cat .socket/manifest.json 2>&1 >&2 || echo "no manifest" >&2
echo "blobs:" >&2
ls -la .socket/blobs/ 2>&1 >&2 || echo "no blobs" >&2
echo "first bytes of patched file:" >&2
head -2 node_modules/minimist/index.js >&2 || echo "no file" >&2

# 5. Assert the patched marker is in the on-disk file.
if ! grep -q 'SOCKET-PATCH-E2E-MARKER' node_modules/minimist/index.js; then
  echo "FAIL: marker not found in node_modules/minimist/index.js after apply" >&2
  exit 1
fi
echo "===PATCH VERIFIED===" >&2

# 5b. Agent-mode VEX leg. The manifest scan --sync wrote now carries
#     {GHSA} (served in the patch view); vex verifies the patched file
#     still on disk (this runs BEFORE rollback) and attests it. --offline keeps
#     vex fully local (no telemetry/API). The doc is emitted between markers so
#     the host oracle can parse it (no bind mount in these agent suites).
echo "===VEX OUTPUT===" >&2
socket-patch vex --offline --cwd "$PWD" --output /tmp/out.vex.json \
  --product 'pkg:npm/e2e-app@1.0.0' --ecosystems npm >/tmp/vex.out 2>/tmp/vex.err
VEX_RC=$?
echo "vex exit=$VEX_RC" >&2
cat /tmp/vex.err >&2 || true
if [ "$VEX_RC" -ne 0 ]; then
  echo "FAIL: vex exited $VEX_RC (expected 0)" >&2
  cat /tmp/vex.out >&2
  exit 1
fi
[ -s /tmp/out.vex.json ] || {{ echo "FAIL: vex did not write out.vex.json" >&2; exit 1; }}
echo "===VEX VERIFIED===" >&2
echo "===VEX DOC BEGIN==="
cat /tmp/out.vex.json
echo ""
echo "===VEX DOC END==="

# 6. rollback. The fixture's manifest records a placeholder all-zero
#    beforeHash and serves no matching before-blob, so an --offline
#    rollback cannot legitimately restore the file. Whatever it does,
#    it MUST stay consistent: it may NOT report success while leaving
#    the patched bytes on disk, and a failed rollback may NOT silently
#    destroy/alter the file. This catches a "fake success" rollback that
#    claims to restore without touching the file.
echo "===ROLLBACK OUTPUT===" >&2
socket-patch rollback --json --offline >/tmp/rb.out 2>/tmp/rb.err
RB_RC=$?
echo "rollback exit=$RB_RC" >&2
cat /tmp/rb.out >&2 || true
cat /tmp/rb.err >&2 || true

MARKER_PRESENT=0
grep -q 'SOCKET-PATCH-E2E-MARKER' node_modules/minimist/index.js && MARKER_PRESENT=1

if [ "$RB_RC" -eq 0 ]; then
  # Rollback claims success → the patch marker MUST be gone (real restore).
  if [ "$MARKER_PRESENT" -eq 1 ]; then
    echo "FAIL: rollback reported success (exit 0) but the patch marker is still on disk — file NOT restored" >&2
    exit 1
  fi
  if ! grep -q '"status": *"success"' /tmp/rb.out; then
    echo "FAIL: rollback exit 0 but JSON status is not success" >&2
    cat /tmp/rb.out >&2
    exit 1
  fi
else
  # Rollback failed (expected here: offline guard, before-blob missing).
  # A failed rollback must be a no-op — the patched bytes stay intact —
  # and it must surface a structured failure, not crash unannounced.
  if [ "$MARKER_PRESENT" -eq 0 ]; then
    echo "FAIL: rollback failed (exit $RB_RC) yet the patched bytes vanished — corrupting/partial rollback" >&2
    head -3 node_modules/minimist/index.js >&2 || echo "no file" >&2
    exit 1
  fi
  if ! grep -Eq '"status": *"(partial_failure|error)"' /tmp/rb.out; then
    echo "FAIL: rollback exit $RB_RC but emitted no partial_failure/error JSON status" >&2
    cat /tmp/rb.out >&2
    exit 1
  fi
fi
echo "===ROLLBACK CHECKED===" >&2

echo "===E2E PASS==="
exit 0
"#
    )
}

/// Driver script for the `npm install -g` variant. Installs minimist
/// globally (into `$(npm root -g)`), runs scan + apply with `--global`,
/// and verifies the marker landed in the global node_modules tree.
fn make_global_script(api_url: &str) -> String {
    format!(
        r#"#!/usr/bin/env bash
set -uo pipefail
COMMON_ARGS=(--api-url '{api_url}' --api-token fake --org {ORG})

# Global install — populates $(npm root -g)/minimist/.
npm install -g --silent --no-audit --no-fund minimist@1.2.2 > /tmp/install.log 2>&1 || {{
  cat /tmp/install.log >&2; exit 1
}}

NPM_GLOBAL_ROOT=$(npm root -g)
GLOBAL_FILE="$NPM_GLOBAL_ROOT/minimist/index.js"
[ -f "$GLOBAL_FILE" ] || {{ echo "FAIL: $GLOBAL_FILE missing" >&2; ls "$NPM_GLOBAL_ROOT" >&2 || true; exit 1; }}
echo "Global-installed at: $GLOBAL_FILE" >&2

# scan + apply run from an empty workspace; --global tells the crawler
# to look at $(npm root -g) instead of cwd-relative node_modules.
mkdir -p /workspace/proj && cd /workspace/proj

socket-patch scan --json --sync --yes --global "${{COMMON_ARGS[@]}}" \
  --ecosystems npm >/tmp/sync.out 2>/tmp/sync.err
echo "scan --sync exit=$?" >&2
cat /tmp/sync.err >&2

# Force-apply must succeed cleanly: a non-zero exit, or exit 0 with a
# partial_failure/error status, means the apply pipeline regressed. The
# marker grep alone is not enough — apply could write the bytes yet report
# failure, and we must reject that.
socket-patch apply --json --force --offline --global --ecosystems npm >/tmp/apply.out 2>/tmp/apply.err
APPLY_RC=$?
echo "apply exit=$APPLY_RC" >&2
cat /tmp/apply.out >&2 || true
cat /tmp/apply.err >&2
if [ "$APPLY_RC" -ne 0 ]; then
  echo "FAIL: global apply exited $APPLY_RC (expected 0 on a forced apply)" >&2
  exit 1
fi
if ! grep -q '"status": *"success"' /tmp/apply.out; then
  echo "FAIL: global apply exit 0 but JSON status is not success" >&2
  cat /tmp/apply.out >&2
  exit 1
fi

if ! grep -q 'SOCKET-PATCH-E2E-MARKER' "$GLOBAL_FILE"; then
  echo "FAIL: marker not in $GLOBAL_FILE" >&2
  head -3 "$GLOBAL_FILE" >&2
  exit 1
fi

echo "===PATCH VERIFIED===" >&2
echo "===E2E PASS==="
exit 0
"#
    )
}

/// Driver script for the `bun install` variant. Distinct from
/// `make_container_script` because bun hard-links from
/// `~/.bun/install/cache/` into `node_modules/` by default (Linux
/// backend), and this test additionally proves the apply pipeline's
/// CoW guard (`break_hardlink_if_needed`) preserves cache integrity.
///
/// Mirror of `pypi_uv_venv_install_full_apply_chain`'s assertion
/// pattern: prewarm cache → install → snapshot inode + cache twin
/// SHA256 → apply → assert (a) venv file got the marker AND (b)
/// cache twin's bytes are unchanged.
fn make_bun_script(api_url: &str) -> String {
    format!(
        r#"#!/usr/bin/env bash
set -uo pipefail
COMMON_ARGS=(--api-url '{api_url}' --api-token fake --org {ORG})

# 1. Pre-warm bun's cache (~/.bun/install/cache/) by installing the
#    target package in a throwaway project first. Guarantees the
#    cache contains minimist before the test install, so the test
#    install can hard-link from it.
mkdir -p /tmp/prewarm && cd /tmp/prewarm
echo '{{"name":"prewarm","version":"0.0.0"}}' > package.json
bun install --silent --no-summary minimist@1.2.2 >/dev/null 2>&1 || true

# 2. Real install into the test project. By default bun's Linux
#    backend hard-links from ~/.bun/install/cache/ into node_modules.
mkdir -p /workspace/proj && cd /workspace/proj
echo '{{"name":"e2e-proj","version":"0.0.0"}}' > package.json
bun install --silent --no-summary minimist@1.2.2

# 3. Locate the installed file and record inode + nlink.
TARGET=node_modules/minimist/index.js
TARGET_INODE_BEFORE=$(stat -c %i "$TARGET")
TARGET_NLINK_BEFORE=$(stat -c %h "$TARGET")
echo "bun target inode_before=$TARGET_INODE_BEFORE nlink_before=$TARGET_NLINK_BEFORE" >&2

# Locate the cache copy of minimist by NAME (independent of whether bun
# hard-linked or copied). prewarm guarantees it exists, so a missing cache
# copy is itself a failure — and locating it by name means the cache
# integrity assertion below can never silently no-op just because bun chose
# to copy rather than hard-link in this environment.
CACHE_FILE=$(find /root/.bun/install/cache -type f -path '*minimist*' -name 'index.js' 2>/dev/null | head -1 || true)
if [ -z "$CACHE_FILE" ] || [ ! -f "$CACHE_FILE" ]; then
  echo "FAIL: bun cache copy of minimist/index.js not found under ~/.bun/install/cache (prewarm should have populated it)" >&2
  find /root/.bun/install/cache -maxdepth 4 -type d 2>/dev/null >&2 || true
  exit 1
fi
CACHE_FILE_HASH_BEFORE=$(sha256sum "$CACHE_FILE" | cut -d' ' -f1)
echo "bun cache file: $CACHE_FILE hash=$CACHE_FILE_HASH_BEFORE" >&2

# Also record the inode twin when hard-linked, for the extra nlink signal.
CACHE_TWIN=""
if [ "$TARGET_NLINK_BEFORE" -gt 1 ]; then
  CACHE_TWIN=$(find /root/.bun/install/cache -inum "$TARGET_INODE_BEFORE" 2>/dev/null | head -1 || true)
  echo "bun cache twin (by inode): $CACHE_TWIN" >&2
fi

# 4. scan --sync.
socket-patch scan --json --sync --yes "${{COMMON_ARGS[@]}}" 2>/tmp/sync.err
echo "sync exit=$?" >&2
cat /tmp/sync.err >&2 || true

# 5. apply --force --offline. Must succeed cleanly — reject a non-zero exit
#    or a partial_failure/error status hidden behind exit 0.
socket-patch apply --json --force --offline >/tmp/apply.out 2>/tmp/apply.err
APPLY_RC=$?
echo "apply exit=$APPLY_RC" >&2
cat /tmp/apply.out >&2 || true
cat /tmp/apply.err >&2 || true
if [ "$APPLY_RC" -ne 0 ]; then
  echo "FAIL: bun apply exited $APPLY_RC (expected 0 on a forced apply)" >&2
  exit 1
fi
if ! grep -q '"status": *"success"' /tmp/apply.out; then
  echo "FAIL: bun apply exit 0 but JSON status is not success" >&2
  cat /tmp/apply.out >&2
  exit 1
fi

# 6. Marker must be in the on-disk file.
if ! grep -q 'SOCKET-PATCH-E2E-MARKER' "$TARGET"; then
  echo "FAIL: marker not in $TARGET" >&2
  head -3 "$TARGET" >&2
  exit 1
fi

# 7. CoW isolation — UNCONDITIONAL. Whether bun hard-linked or copied, the
#    apply must never mutate the shared cache copy: its bytes must be
#    byte-for-byte unchanged and it must never gain the patch marker. This
#    runs regardless of nlink so it can't silently no-op.
CACHE_FILE_HASH_AFTER=$(sha256sum "$CACHE_FILE" | cut -d' ' -f1)
if [ "$CACHE_FILE_HASH_AFTER" != "$CACHE_FILE_HASH_BEFORE" ]; then
  echo "FAIL: bun cache content CORRUPTED by apply — CoW/isolation failed!" >&2
  echo "  before=$CACHE_FILE_HASH_BEFORE" >&2
  echo "  after =$CACHE_FILE_HASH_AFTER" >&2
  echo "  path  =$CACHE_FILE" >&2
  head -3 "$CACHE_FILE" >&2
  exit 1
fi
if grep -q 'SOCKET-PATCH-E2E-MARKER' "$CACHE_FILE"; then
  echo "FAIL: bun cache copy contains the marker — patch leaked into ~/.bun/install/cache/" >&2
  exit 1
fi
echo "bun cache integrity PRESERVED: $CACHE_FILE unchanged" >&2

# Extra assurance when bun hard-linked: the apply must have BROKEN the link
# so the target no longer shares the cache twin's inode.
if [ "$TARGET_NLINK_BEFORE" -gt 1 ]; then
  TARGET_INODE_AFTER=$(stat -c %i "$TARGET")
  echo "bun target inode_after=$TARGET_INODE_AFTER (was $TARGET_INODE_BEFORE)" >&2
  if [ "$TARGET_INODE_AFTER" = "$TARGET_INODE_BEFORE" ]; then
    echo "FAIL: target still shares the cache inode after apply — hard link was NOT broken (CoW skipped)" >&2
    exit 1
  fi
fi

echo "===PATCH VERIFIED===" >&2
echo "===E2E PASS==="
exit 0
"#
    )
}

fn run_in_container(script: &str) -> std::process::Output {
    let mut cmd = Command::new("docker");
    cmd.args([
        "run",
        "--rm",
        "--add-host=host.docker.internal:host-gateway",
        "-i",
    ])
    .args(cov_docker_args())
    .args(["socket-patch-test-npm:latest", "bash", "-c", script]);
    cmd.output().expect("docker run failed to spawn")
}

fn run_on_host(script: &str) -> std::process::Output {
    // Host mode: write the script to a tempfile under a fresh tmp workspace
    // and execute it. Requires npm + socket-patch on PATH.
    let tmp = tempfile::tempdir().expect("tempdir");
    let script_path = tmp.path().join("run.sh");
    let mut f = std::fs::File::create(&script_path).unwrap();
    f.write_all(script.as_bytes()).unwrap();
    drop(f);
    // Rewrite the script's `/workspace/proj` paths to a host-tmp dir so we
    // don't need root or write access to `/workspace`.
    let host_proj = tmp.path().join("proj");
    let host_script = script.replace("/workspace/proj", host_proj.to_str().unwrap());
    Command::new("bash")
        .arg("-c")
        .arg(host_script)
        .output()
        .expect("bash failed to spawn")
}

/// Returns `true` when the test should skip (docker missing, image
/// missing). Prints a skip notice to stderr — the test still reports as
/// `ok` because Rust integration tests have no native "skipped" outcome.
///
/// Note that npm e2e also supports `SOCKET_PATCH_TEST_HOST=1` (see
/// [`host_mode`]) to run the test against host toolchains instead of
/// Docker; that's checked independently in the test body before this
/// helper runs.
#[must_use]
fn skip_if_no_docker_image() -> bool {
    let Ok(out) = Command::new("docker")
        .args(["image", "inspect", "socket-patch-test-npm:latest"])
        .output()
    else {
        eprintln!(
            "skipping: `docker` not on PATH (set SOCKET_PATCH_TEST_HOST=1 to run on the host)"
        );
        return true;
    };
    if !out.status.success() {
        eprintln!("skipping: docker image `socket-patch-test-npm:latest` not present");
        return true;
    }
    false
}

#[tokio::test]
async fn npm_install_scan_apply_rollback_cycle() {
    let after_hash = git_sha256(PATCHED_BYTES);
    let server = make_mock_server(&after_hash).await;

    let output = if host_mode() {
        let api = format!("http://127.0.0.1:{}", server.address().port());
        run_on_host(&make_container_script(&api))
    } else {
        if skip_if_no_docker_image() {
            return;
        }
        let api = api_url_for_container(&server);
        run_in_container(&make_container_script(&api))
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "container script failed:\nstdout=\n{stdout}\nstderr=\n{stderr}"
    );
    // Each stage marker is emitted only after that stage's in-script
    // gate passed. Requiring all four proves the full chain ran and
    // every gate held — not just that the script reached its tail.
    assert!(
        stderr.contains("===SCAN VERIFIED==="),
        "scan did not discover the patch (===SCAN VERIFIED=== missing).\nstdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(
        stderr.contains("===PATCH VERIFIED==="),
        "expected post-apply marker grep to succeed (===PATCH VERIFIED=== in stderr).\nstdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(
        stderr.contains("===ROLLBACK CHECKED==="),
        "rollback consistency check did not run/pass (===ROLLBACK CHECKED=== missing).\nstdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(
        stdout.contains("===E2E PASS==="),
        "PASS marker missing from stdout:\n{stdout}\nstderr:\n{stderr}"
    );

    // Agent-mode VEX leg: the manifest patch was attested with plain
    // (non-vendored, non-redirected) provenance against the installed tree.
    assert!(
        stderr.contains("===VEX VERIFIED==="),
        "agent-mode VEX leg did not run/pass (===VEX VERIFIED=== missing).\nstdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert_vex_agent_attested(&stdout, PURL);

    // Keep the workspace_root reference alive — used by host mode to
    // resolve the in-tree binary. Without this clippy warns unused.
    let _ = workspace_root();

    // The mock must have served BOTH the metadata discovery (batch) and
    // an actual blob fetch (inline view or raw-blob fallback). Without
    // the latter, the full download→apply pipeline never ran the
    // content path even if a marker somehow appeared.
    assert_real_api_pipeline_ran(&server).await;
}

#[tokio::test]
async fn npm_global_install_full_apply_chain() {
    // PURL must be the lowercased form scan's crawler emits — see the
    // nuget docker test for the same constraint. (npm names are already
    // lowercase in practice; we use the canonical form here for clarity.)
    let after_hash = git_sha256(PATCHED_BYTES);
    let server = make_mock_server(&after_hash).await;
    if host_mode() {
        // Host mode doesn't have a global npm prefix we can safely
        // mutate, so skip silently. Docker mode is the canonical run.
        return;
    }
    if skip_if_no_docker_image() {
        return;
    }
    let api = api_url_for_container(&server);
    let out = run_in_container(&make_global_script(&api));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "npm global apply failed:\nstdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(stderr.contains("===PATCH VERIFIED==="), "stderr=\n{stderr}");
    assert!(stdout.contains("===E2E PASS==="), "stdout=\n{stdout}");
    assert_real_api_pipeline_ran(&server).await;
}

/// Host-side oracle over the VEX document the container emitted between the
/// `===VEX DOC BEGIN===` / `===VEX DOC END===` markers. These agent suites run
/// the workspace inside the container with no bind mount (unlike the vendor
/// capstones), so the doc is parsed straight from captured stdout. Asserts
/// exactly one statement attesting the agent patch: the fixture GHSA,
/// `not_affected`, the installed-package subcomponent purl, and a PLAIN impact
/// statement with NO `(vendored)`/`(redirected)` marker — the marker's absence
/// is precisely what distinguishes agent provenance from the vendored/hosted
/// modes.
fn assert_vex_agent_attested(stdout: &str, subcomponent_purl: &str) {
    const BEGIN: &str = "===VEX DOC BEGIN===";
    const END: &str = "===VEX DOC END===";
    let start = stdout
        .find(BEGIN)
        .unwrap_or_else(|| panic!("VEX DOC BEGIN marker missing from stdout:\n{stdout}"))
        + BEGIN.len();
    let stop = stdout[start..]
        .find(END)
        .unwrap_or_else(|| panic!("VEX DOC END marker missing from stdout:\n{stdout}"))
        + start;
    let doc: serde_json::Value = serde_json::from_str(stdout[start..stop].trim())
        .expect("emitted VEX document must be valid JSON");
    let stmts = doc["statements"]
        .as_array()
        .expect("VEX document must have a statements array");
    assert_eq!(stmts.len(), 1, "exactly one VEX statement expected: {doc}");
    let st = &stmts[0];
    assert_eq!(st["vulnerability"]["name"], GHSA, "attested GHSA mismatch");
    assert_eq!(st["status"], "not_affected");
    assert_eq!(
        st["products"][0]["subcomponents"][0]["@id"], subcomponent_purl,
        "subcomponent must be the patched package purl"
    );
    let impact = st["impact_statement"]
        .as_str()
        .expect("statement must carry an impact_statement");
    assert!(
        impact.contains("Patched via Socket patch")
            && !impact.contains("(vendored)")
            && !impact.contains("(redirected)"),
        "agent-mode attestation must carry a PLAIN impact statement (no vendored/redirected marker): {impact}"
    );
}

/// Shared check: the mock must have served BOTH the metadata discovery
/// (batch) and an actual blob fetch (inline view or raw-blob fallback).
/// Without the latter the full download→apply pipeline never ran the
/// content path even if a marker somehow appeared on disk.
async fn assert_real_api_pipeline_ran(server: &MockServer) {
    let received = server.received_requests().await.unwrap_or_default();
    let paths: Vec<&str> = received.iter().map(|r| r.url.path()).collect();
    assert!(
        paths.iter().any(|p| p.contains("/patches/batch")),
        "scan should have called /patches/batch; received={paths:#?}"
    );
    assert!(
        paths
            .iter()
            .any(|p| p.contains("/patches/view/") || p.contains("/patches/blob/")),
        "scan --sync should have fetched patch content via /patches/view/ or /patches/blob/; received={paths:#?}"
    );
}

/// Bun-managed install + apply, with CoW-isolation assertion. See
/// `make_bun_script` for the inode/cache-twin/SHA256 gate that proves
/// `break_hardlink_if_needed` in `patch/cow.rs` correctly isolates
/// the test venv's copy of the package from `~/.bun/install/cache/`.
#[tokio::test]
async fn npm_bun_install_full_apply_chain() {
    let after_hash = git_sha256(PATCHED_BYTES);
    let server = make_mock_server(&after_hash).await;
    if host_mode() {
        // Host mode would need bun installed locally; skip for now.
        return;
    }
    if skip_if_no_docker_image() {
        return;
    }
    let api = api_url_for_container(&server);
    let out = run_in_container(&make_bun_script(&api));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "bun install apply failed:\nstdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(stderr.contains("===PATCH VERIFIED==="), "stderr=\n{stderr}");
    assert!(stdout.contains("===E2E PASS==="), "stdout=\n{stdout}");
    assert_real_api_pipeline_ran(&server).await;
}

/// Smoke test: verify the test infrastructure starts up correctly. This
/// runs even without Docker so the test binary itself compiles + the
/// wiremock listener path works.
#[tokio::test]
async fn npm_test_infrastructure_smoke() {
    let after_hash = git_sha256(PATCHED_BYTES);
    let server = make_mock_server(&after_hash).await;
    // Just hit one of the mock endpoints to confirm wiremock is up.
    // Connect via 127.0.0.1, not the server's bound IP — wiremock
    // binds to 0.0.0.0 (the wildcard), which is a valid bind address
    // but is NOT a valid destination address on Windows (WSAEADDRNOTAVAIL
    // / WSA error 10049). Linux/macOS quietly route 0.0.0.0 → loopback;
    // Windows doesn't.
    let url = format!(
        "http://127.0.0.1:{}/v0/orgs/{ORG}/patches/blob/{after_hash}",
        server.address().port()
    );
    let body = reqwest::get(&url)
        .await
        .expect("GET mock")
        .bytes()
        .await
        .expect("read body");
    assert_eq!(body.as_ref(), PATCHED_BYTES);
}

// Suppress the unused-import warning when SOCKET_PATCH_TEST_HOST=1 (host
// mode doesn't need Duration or workspace_root). Keep both functions
// available; the helper signatures are simple enough to keep cheap.
const _: Option<Duration> = None;
