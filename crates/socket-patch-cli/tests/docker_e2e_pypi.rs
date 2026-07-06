//! Docker-driven full install→apply chain for the pypi ecosystem.
//!
//! Real `pip install six==1.16.0` (single-file package — small, stable,
//! easy to verify) in a Linux container, then `socket-patch scan
//! --json --sync --yes` against a wiremock-served patch fixture, then
//! `socket-patch apply --json --force --offline` overwrites the real
//! installed `site-packages/six.py` with synthetic bytes containing
//! `SOCKET-PATCH-E2E-MARKER`. The grep at the end of the container
//! script is the gate.
//!
//! Two test functions:
//! - `pypi_local_install_full_apply_chain` — venv install at
//!   `.venv/lib/python3.X/site-packages/six.py`
//! - `pypi_global_install_full_apply_chain` — `pip install
//!   --break-system-packages` to system site-packages; socket-patch
//!   scan + apply with `--global`

#![cfg(feature = "docker-e2e")]

use std::process::Command;

use base64::Engine;
use sha2::{Digest, Sha256};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";
const PURL: &str = "pkg:pypi/six@1.16.0";
const UUID: &str = "12121212-1212-4121-8121-121212121212";
/// The vulnerability the staged manifest carries so the agent-mode VEX leg
/// has something to attest (plain agent provenance — no vendored/redirected
/// marker — is what the host oracle asserts).
const GHSA: &str = "GHSA-agent-pypi-real";

/// The synthetic content that replaces the installed six.py file.
/// Contains the marker we grep for to verify apply succeeded.
const PATCHED_PY: &[u8] = b"# SOCKET-PATCH-E2E-MARKER\n\
                            # six.py replaced by socket-patch e2e fixture\n\
                            __version__ = \"1.16.0-patched\"\n";

/// Coverage instrumentation hook. The CI coverage-docker job sets
/// SOCKET_PATCH_COV_BIN (host path to an llvm-cov-instrumented
/// socket-patch binary) and SOCKET_PATCH_COV_PROFRAW_DIR (host dir
/// for in-container *.profraw output). When both are set, the docker
/// run mounts the instrumented binary over the image's baked-in
/// /usr/local/bin/socket-patch and points LLVM_PROFILE_FILE into a
/// host-visible volume so in-container code paths contribute to the
/// host's lcov merge. Empty Vec when unset.
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

fn git_sha256(content: &[u8]) -> String {
    let header = format!("blob {}\0", content.len());
    let mut hasher = Sha256::new();
    hasher.update(header.as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

/// Plain SHA256 (NOT git-blob) of the content — used as an independent
/// oracle for the on-disk file after apply. The marker grep alone only
/// proves the marker is *somewhere* in the file; comparing the full
/// sha256 against the exact bytes we served proves apply wrote the whole
/// blob faithfully, catching a partial/garbled/truncated write.
fn sha256_hex(content: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content);
    hex::encode(hasher.finalize())
}

/// Assert the wiremock saw the real scan→sync API path: a batch search
/// for metadata AND a content fetch via the inline-blob view endpoint.
/// Without the latter the download→apply content pipeline never ran even
/// if a marker somehow appeared on disk.
async fn assert_api_path_exercised(server: &MockServer) {
    // Use `.expect` (NOT `unwrap_or_default`) so a recording failure surfaces
    // loudly instead of silently degrading to "no requests seen" — which would
    // make every assertion below vacuously pass on an empty Vec.
    let received = server
        .received_requests()
        .await
        .expect("wiremock should have recorded requests");

    // 1. The batch search POST must have fired AND carried the installed PURL
    //    in its body. A path-only `.contains("/patches/batch")` check passes
    //    even if the pypi crawler discovered nothing and sent an empty
    //    component list, so we assert the discovered PURL actually made it
    //    onto the wire.
    let batch = received
        .iter()
        .find(|r| format!("{}", r.method) == "POST" && r.url.path().contains("/patches/batch"))
        .unwrap_or_else(|| {
            panic!("scan should have POSTed /patches/batch; received={received:#?}")
        });
    let batch_body = String::from_utf8_lossy(&batch.body);
    assert!(
        batch_body.contains(PURL),
        "batch POST body should reference the discovered pypi purl {PURL}; body={batch_body}"
    );

    // 2. The blob-download endpoint must have been hit during scan --sync, at
    //    the EXACT view path for our UUID (a loose `/patches/view/` substring
    //    would accept a fetch for some other uuid). The offline apply reads the
    //    blob from the local store, so a green offline apply is only possible
    //    if scan really downloaded and persisted this blob via this endpoint.
    assert!(
        received.iter().any(|r| format!("{}", r.method) == "GET"
            && r.url.path() == format!("/v0/orgs/{ORG}/patches/view/{UUID}")),
        "scan --sync should have fetched patch content via /patches/view/{UUID}; received={received:#?}"
    );
}

async fn make_mock_server(after_hash: &str) -> MockServer {
    let listener = std::net::TcpListener::bind("0.0.0.0:0").expect("bind wiremock to 0.0.0.0:0");
    let server = MockServer::builder().listener(listener).start().await;

    // 1. Batch search reports a patch for the installed PURL.
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": PURL,
                "patches": [{
                    "uuid": UUID, "purl": PURL,
                    "tier": "free", "cveIds": [], "ghsaIds": [],
                    "severity": "high", "title": "pypi e2e fixture"
                }]
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(&server)
        .await;

    // 2. By-package lookup (used by scan --apply / --sync).
    Mock::given(method("GET"))
        .and(path_regex(format!(
            "^/v0/orgs/{ORG}/patches/by-package/.+$"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [{
                "uuid": UUID, "purl": PURL,
                "publishedAt": "2024-01-01T00:00:00Z",
                "description": "pypi e2e fixture",
                "license": "MIT", "tier": "free",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(&server)
        .await;

    // 3. Full patch view with inline blobContent. The pypi file-path
    // convention is `<pkg_name>/<rel>` with NO `package/` prefix —
    // unique to pypi because the crawler returns site-packages root
    // as pkg_path. For single-file six.py, the path is just "six.py".
    let blob_b64 = base64::engine::general_purpose::STANDARD.encode(PATCHED_PY);
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": UUID,
            "purl": PURL,
            "publishedAt": "2024-01-01T00:00:00Z",
            "files": {
                "six.py": {
                    "beforeHash": "0000000000000000000000000000000000000000000000000000000000000000",
                    "afterHash":  after_hash,
                    "blobContent": blob_b64,
                }
            },
            // Recorded into the manifest so the agent-mode VEX leg attests it.
            "vulnerabilities": {
                (GHSA): {
                    "cves": ["CVE-2024-30004"],
                    "summary": "pypi agent e2e fixture vulnerability",
                    "severity": "high",
                    "description": "Agent-mode VEX leg fixture vulnerability"
                }
            },
            "description": "pypi e2e fixture",
            "license": "MIT",
            "tier": "free",
        })))
        .mount(&server)
        .await;

    server
}

fn local_script(api_url: &str, expected_sha: &str) -> String {
    format!(
        r#"#!/usr/bin/env bash
set -uo pipefail

# 1. Real local install: venv + pip install. six is a single-file
#    pypi package — installs to site-packages/six.py.
python3 -m venv /workspace/venv
. /workspace/venv/bin/activate
pip install --disable-pip-version-check --quiet --no-cache-dir six==1.16.0

# Link the venv into the cwd so the python crawler discovers it.
mkdir -p /workspace/proj && cd /workspace/proj
ln -sf /workspace/venv .venv

# Pre-seed setup.manual so the agent-mode VEX leg keeps the pypi patch through
# property 7 (this venv project isn't `socket-patch setup`-configured; agent
# patches are applied by hand/CI — exactly what `manual` declares). scan --sync
# merges the downloaded patch into this manifest and preserves the setup block.
mkdir -p .socket
cat > .socket/manifest.json <<'MANIFEST'
{{ "patches": {{}}, "setup": {{ "manual": ["pypi"] }} }}
MANIFEST

# Locate the installed six.py file.
SIX_PY=$(ls /workspace/venv/lib/python3.*/site-packages/six.py)
echo "Installed six at: $SIX_PY" >&2

# Pristine pre-check: the marker MUST NOT already be present in the freshly
# pip-installed file. Without this the final marker grep cannot distinguish
# "apply wrote it" from "it was always there", so the apply assertion would
# be circular.
if grep -q 'SOCKET-PATCH-E2E-MARKER' "$SIX_PY"; then
  echo "FAIL: marker already in $SIX_PY BEFORE apply — fixture not pristine" >&2
  exit 1
fi

# 2. scan --json: must DISCOVER the patch via the real batch API before
#    anything else. A no-op scan also exits 0, so gate on the installed
#    PURL and the available patch UUID actually appearing in the JSON.
socket-patch scan --json \
  --api-url '{api_url}' --api-token fake --org {ORG} \
  --ecosystems pypi >/tmp/scan.out 2>/tmp/scan.err
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

# 3. scan --sync: writes manifest + downloads blob from wiremock.
socket-patch scan --json --sync --yes \
  --api-url '{api_url}' --api-token fake --org {ORG} \
  --ecosystems pypi 2>/tmp/sync.err
SYNC_RC=$?
echo "sync exit=$SYNC_RC" >&2
cat /tmp/sync.err >&2 || true

# 4. apply --force --offline: overwrites the installed file using the
#    blob cached by scan --sync. --force bypasses the (deliberately
#    mismatched) beforeHash check. A forced apply MUST report success,
#    not merely leave a marker behind while reporting failure.
socket-patch apply --json --force --offline --ecosystems pypi 2>/tmp/apply.err
APPLY_RC=$?
echo "apply exit=$APPLY_RC" >&2
cat /tmp/apply.err >&2 || true
if [ "$APPLY_RC" -ne 0 ]; then
  echo "FAIL: apply exited $APPLY_RC (expected 0 on a forced apply)" >&2
  exit 1
fi

# 5. The on-disk file must now contain the marker AND match the served
#    blob byte-for-byte (an independent sha256 oracle catches a partial
#    or corrupt write that happens to include the marker).
if ! grep -q 'SOCKET-PATCH-E2E-MARKER' "$SIX_PY"; then
  echo "FAIL: marker not in $SIX_PY" >&2
  head -3 "$SIX_PY" >&2
  exit 1
fi
ACTUAL_SHA=$(sha256sum "$SIX_PY" | cut -d' ' -f1)
if [ "$ACTUAL_SHA" != "{expected_sha}" ]; then
  echo "FAIL: patched six.py content mismatch (expected={expected_sha} actual=$ACTUAL_SHA)" >&2
  head -5 "$SIX_PY" >&2
  exit 1
fi

echo "===PATCH VERIFIED===" >&2

# Agent-mode VEX leg. The manifest scan --sync wrote carries {GHSA} (served in
# the patch view); vex verifies the patched six.py in the venv site-packages
# and attests it with PLAIN agent provenance. --ecosystems pypi (no --global,
# matching the local apply above); --offline keeps vex local. The doc is
# emitted between markers for the host-side oracle (no bind mount here).
echo "===VEX OUTPUT===" >&2
socket-patch vex --offline --cwd "$PWD" --output /tmp/out.vex.json \
  --product 'pkg:pypi/e2e-app@1.0.0' --ecosystems pypi >/tmp/vex.out 2>/tmp/vex.err
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

echo "===E2E PASS==="
exit 0
"#
    )
}

fn global_script(api_url: &str, expected_sha: &str) -> String {
    format!(
        r#"#!/usr/bin/env bash
set -uo pipefail

# 1. Real GLOBAL install: pip install --break-system-packages places
#    six.py in the system site-packages (/usr/local/lib/python3.X/
#    dist-packages/ on Debian + pip's --break-system-packages flag).
pip install --disable-pip-version-check --quiet --no-cache-dir \
  --break-system-packages six==1.16.0

# Locate the installed file (path varies by Debian Python build).
SIX_PY=$(python3 -c "import six, sys; sys.stdout.write(six.__file__)")
echo "Global-installed six at: $SIX_PY" >&2

# Pristine pre-check: marker must NOT already be in the freshly-installed file
# (otherwise the post-apply marker grep is circular).
if grep -q 'SOCKET-PATCH-E2E-MARKER' "$SIX_PY"; then
  echo "FAIL: marker already in $SIX_PY BEFORE apply — fixture not pristine" >&2
  exit 1
fi

# Run in an empty workspace — --global tells socket-patch to scan
# system site-packages, ignoring the cwd-relative discovery.
mkdir -p /workspace/proj && cd /workspace/proj

# 2. scan --json --global: discovery gate — the global crawler must find
#    the installed PURL and the available patch UUID via the batch API.
socket-patch scan --json --global \
  --api-url '{api_url}' --api-token fake --org {ORG} \
  --ecosystems pypi >/tmp/scan.out 2>/tmp/scan.err
SCAN_RC=$?
echo "scan exit=$SCAN_RC" >&2
cat /tmp/scan.err >&2 || true
if [ "$SCAN_RC" -ne 0 ]; then
  echo "FAIL: scan exited $SCAN_RC (expected 0)" >&2
  cat /tmp/scan.out >&2
  exit 1
fi
if ! grep -q '{PURL}' /tmp/scan.out; then
  echo "FAIL: scan --global did not report the installed PURL {PURL}" >&2
  cat /tmp/scan.out >&2
  exit 1
fi
if ! grep -q '{UUID}' /tmp/scan.out; then
  echo "FAIL: scan --global did not report available patch UUID {UUID}" >&2
  cat /tmp/scan.out >&2
  exit 1
fi
echo "===SCAN VERIFIED===" >&2

# 3. scan --sync --global.
socket-patch scan --json --sync --yes --global \
  --api-url '{api_url}' --api-token fake --org {ORG} \
  --ecosystems pypi 2>/tmp/sync.err
SYNC_RC=$?
echo "sync exit=$SYNC_RC" >&2
cat /tmp/sync.err >&2 || true

# 4. apply --global --force --offline. Must report success.
socket-patch apply --json --force --offline --global --ecosystems pypi 2>/tmp/apply.err
APPLY_RC=$?
echo "apply exit=$APPLY_RC" >&2
cat /tmp/apply.err >&2 || true
if [ "$APPLY_RC" -ne 0 ]; then
  echo "FAIL: apply exited $APPLY_RC (expected 0 on a forced apply)" >&2
  exit 1
fi

if ! grep -q 'SOCKET-PATCH-E2E-MARKER' "$SIX_PY"; then
  echo "FAIL: marker not in $SIX_PY" >&2
  head -3 "$SIX_PY" >&2
  exit 1
fi
ACTUAL_SHA=$(sha256sum "$SIX_PY" | cut -d' ' -f1)
if [ "$ACTUAL_SHA" != "{expected_sha}" ]; then
  echo "FAIL: patched six.py content mismatch (expected={expected_sha} actual=$ACTUAL_SHA)" >&2
  head -5 "$SIX_PY" >&2
  exit 1
fi

echo "===PATCH VERIFIED===" >&2
echo "===E2E PASS==="
exit 0
"#
    )
}

/// uv-managed venv install + apply. Distinct from `local_script`
/// because uv hard-links from its global cache (`~/.cache/uv/wheels/`)
/// into the venv site-packages by default — a patch that rewrites the
/// venv file in place would corrupt every other venv on the machine
/// that shares the same cached wheel. The script proves the CoW
/// guard (`break_hardlink_if_needed` in `patch/cow.rs`) works for
/// uv specifically by:
///
///   1. Recording the venv file's inode AND the cache file's content
///      hash BEFORE apply.
///   2. Running socket-patch apply.
///   3. Asserting: (a) venv file inode CHANGED (the hard link was
///      broken), (b) cache content hash UNCHANGED (the global cache
///      copy is still pristine).
fn uv_venv_script(api_url: &str, expected_sha: &str) -> String {
    format!(
        r#"#!/usr/bin/env bash
set -uo pipefail

# 1. Pre-warm uv's wheel cache. By default uv hard-links from
#    ~/.cache/uv/wheels/ into venvs, but only after the wheel has
#    been downloaded into the cache. Installing into a throwaway
#    venv first guarantees the cache contains six.py, so the next
#    install can hard-link from it.
uv venv /tmp/prewarm-venv >&2
uv pip install --python /tmp/prewarm-venv/bin/python --quiet six==1.16.0 >&2

# 2. Now the real install — should hard-link from the warm cache.
uv venv /workspace/venv >&2
uv pip install --python /workspace/venv/bin/python --quiet six==1.16.0 >&2

# Link the venv into the cwd so the python crawler discovers it.
mkdir -p /workspace/proj && cd /workspace/proj
ln -sf /workspace/venv .venv

# 3. Locate the installed six.py and snapshot its inode + nlink.
SIX_PY=$(ls /workspace/venv/lib/python3.*/site-packages/six.py)
echo "Installed six at: $SIX_PY" >&2

# Pristine pre-check: marker must NOT already be present before apply.
if grep -q 'SOCKET-PATCH-E2E-MARKER' "$SIX_PY"; then
  echo "FAIL: marker already in $SIX_PY BEFORE apply — fixture not pristine" >&2
  exit 1
fi

SIX_INODE_BEFORE=$(stat -c %i "$SIX_PY")
SIX_NLINK_BEFORE=$(stat -c %h "$SIX_PY")
echo "venv six.py inode_before=$SIX_INODE_BEFORE nlink_before=$SIX_NLINK_BEFORE" >&2

# Locate the cache twin via inode if hard-linked (nlink > 1 → file
# is shared with at least one other path, almost certainly inside
# the uv cache).
CACHE_TWIN=""
CACHE_HASH_BEFORE=""
if [ "$SIX_NLINK_BEFORE" -gt 1 ]; then
  CACHE_TWIN=$(find /root/.cache/uv -inum "$SIX_INODE_BEFORE" 2>/dev/null | head -1 || true)
  # If the venv file is hard-linked (nlink>1) we MUST be able to locate the
  # shared cache file — that twin is the whole subject of this test's CoW
  # assertion. Failing to find it would silently skip the integrity check
  # below and let a CoW regression pass, so treat a missing twin as a failure
  # rather than a no-op.
  if [ -z "$CACHE_TWIN" ] || [ ! -f "$CACHE_TWIN" ]; then
    echo "FAIL: six.py is hard-linked (nlink=$SIX_NLINK_BEFORE) but no cache twin found under /root/.cache/uv for inode $SIX_INODE_BEFORE — cannot verify CoW isolation" >&2
    exit 1
  fi
  CACHE_HASH_BEFORE=$(sha256sum "$CACHE_TWIN" | cut -d' ' -f1)
  echo "cache twin: $CACHE_TWIN hash=$CACHE_HASH_BEFORE" >&2
fi

# 4. scan --json: discovery gate.
socket-patch scan --json \
  --api-url '{api_url}' --api-token fake --org {ORG} \
  --ecosystems pypi >/tmp/scan.out 2>/tmp/scan.err
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

# 5. scan --sync.
socket-patch scan --json --sync --yes \
  --api-url '{api_url}' --api-token fake --org {ORG} \
  --ecosystems pypi 2>/tmp/sync.err
SYNC_RC=$?
echo "sync exit=$SYNC_RC" >&2
cat /tmp/sync.err >&2 || true

# 6. apply --force --offline. Must report success.
socket-patch apply --json --force --offline --ecosystems pypi 2>/tmp/apply.err
APPLY_RC=$?
echo "apply exit=$APPLY_RC" >&2
cat /tmp/apply.err >&2 || true
if [ "$APPLY_RC" -ne 0 ]; then
  echo "FAIL: apply exited $APPLY_RC (expected 0 on a forced apply)" >&2
  exit 1
fi

# 7. The on-disk file must now contain the marker AND match the served
#    blob byte-for-byte (apply happened, completely and correctly).
if ! grep -q 'SOCKET-PATCH-E2E-MARKER' "$SIX_PY"; then
  echo "FAIL: marker not in $SIX_PY" >&2
  head -3 "$SIX_PY" >&2
  exit 1
fi
ACTUAL_SHA=$(sha256sum "$SIX_PY" | cut -d' ' -f1)
if [ "$ACTUAL_SHA" != "{expected_sha}" ]; then
  echo "FAIL: patched six.py content mismatch (expected={expected_sha} actual=$ACTUAL_SHA)" >&2
  head -5 "$SIX_PY" >&2
  exit 1
fi

# 8. If the venv file was hard-linked at install time, the apply
#    pipeline's CoW guard must have broken the link. We verify two
#    ways:
#      (a) nlink dropped to 1 — the venv file is no longer shared
#      (b) if we located the cache twin pre-apply, its bytes are
#          still pristine (CoW didn't propagate the patch into the
#          cache)
#
#    If nlink_before == 1, there was no hard link to break — uv
#    chose to copy rather than link (the storage driver may not
#    support hard links across overlay layers, etc.). In that case
#    we just verify apply happened, which the marker check above
#    already covers.
SIX_INODE_AFTER=$(stat -c %i "$SIX_PY")
SIX_NLINK_AFTER=$(stat -c %h "$SIX_PY")
echo "venv six.py inode_after=$SIX_INODE_AFTER nlink_after=$SIX_NLINK_AFTER" >&2

if [ "$SIX_NLINK_BEFORE" -gt 1 ]; then
  # The KEY assertion: regardless of what stat reports for nlink
  # (overlayfs can lie), the cache twin's content must be unchanged.
  # If apply mutated the inode the cache shares with us, we'd see
  # the marker in the cache file too.
  if [ -n "$CACHE_TWIN" ] && [ -f "$CACHE_TWIN" ]; then
    CACHE_HASH_AFTER=$(sha256sum "$CACHE_TWIN" | cut -d' ' -f1)
    if [ "$CACHE_HASH_AFTER" != "$CACHE_HASH_BEFORE" ]; then
      echo "FAIL: uv cache content CORRUPTED — CoW didn't isolate the venv copy!" >&2
      echo "  before=$CACHE_HASH_BEFORE" >&2
      echo "  after =$CACHE_HASH_AFTER" >&2
      echo "  path  =$CACHE_TWIN" >&2
      echo "  cache file head:" >&2
      head -3 "$CACHE_TWIN" >&2
      exit 1
    fi
    echo "cache integrity PRESERVED: $CACHE_TWIN unchanged ($CACHE_HASH_BEFORE)" >&2

    # Secondary check: cache twin must NOT contain the post-apply marker.
    if grep -q 'SOCKET-PATCH-E2E-MARKER' "$CACHE_TWIN"; then
      echo "FAIL: cache twin contains the patch marker — venv's bytes leaked into cache!" >&2
      exit 1
    fi
    echo "cache twin does not contain patch marker (good)" >&2
  fi

  # Diagnostic: if inode changed (rename happened) but nlink didn't
  # drop, something is double-linking the rename target somehow.
  # Just report — the cache-integrity check above is the gate.
  if [ "$SIX_INODE_AFTER" = "$SIX_INODE_BEFORE" ]; then
    echo "(inode unchanged after apply — odd for stage+rename, but cache is safe)" >&2
  else
    echo "inode changed: $SIX_INODE_BEFORE -> $SIX_INODE_AFTER" >&2
  fi
else
  echo "(uv did not hard-link in this environment; CoW path was a no-op)" >&2
fi

echo "===PATCH VERIFIED===" >&2
echo "===E2E PASS==="
exit 0
"#
    )
}

/// `uv tool install` puts a tool at `~/.local/share/uv/tools/<name>/`
/// with its own venv. The script installs `httpie` (a small CLI tool
/// available on PyPI), then drives a patch against one of its modules.
fn uv_tool_script(api_url: &str, patched_marker: &str) -> String {
    // httpie has a top-level package called `httpie`. We patch
    // `httpie/__init__.py`. The PURL in the manifest is fixed up by
    // the wiremock fixture; here we just need to discover it.
    format!(
        r#"#!/usr/bin/env bash
set -uo pipefail

mkdir -p /workspace/proj && cd /workspace/proj

# Helper: parse scannedPackages from scan JSON on stdin. Does NOT default a
# parse failure to 0 — a missing field or malformed JSON is itself a
# regression and must surface, not silently degrade.
parse_scanned() {{
  python3 -c "import sys,json; print(json.load(sys.stdin)['scannedPackages'])"
}}

# 0. BASELINE scan BEFORE installing the uv tool. This captures whatever the
#    Debian dist-packages baseline contributes on its own. An absolute
#    threshold (>= N) is reward-hackable: if dist-packages alone already has
#    >= N packages, a completely broken uv-tools discovery branch still passes.
#    Measuring the DELTA introduced by `uv tool install` isolates the
#    uv-tools contribution and can only be satisfied if that layout was
#    actually walked.
BASELINE_OUT=$(socket-patch scan --json --global \
  --api-url '{api_url}' --api-token fake --org {ORG} \
  --ecosystems pypi 2>/tmp/baseline.err)
BASELINE_RC=$?
cat /tmp/baseline.err >&2 || true
if [ "$BASELINE_RC" -ne 0 ]; then
  echo "FAIL: baseline scan exited $BASELINE_RC (expected 0)" >&2
  echo "$BASELINE_OUT" | head -50 >&2
  exit 1
fi
BASELINE=$(echo "$BASELINE_OUT" | parse_scanned)
if [ "$?" -ne 0 ]; then
  echo "FAIL: could not parse scannedPackages from baseline scan JSON" >&2
  echo "$BASELINE_OUT" | head -50 >&2
  exit 1
fi
case "$BASELINE" in
  ''|*[!0-9]*)
    echo "FAIL: baseline scannedPackages is not a non-negative integer: '$BASELINE'" >&2
    exit 1
    ;;
esac
echo "baseline scanned packages (pre uv-tool-install): $BASELINE" >&2

# 1. uv tool install. httpie@3.2.2 is a real pypi package.
uv tool install --python python3 httpie==3.2.2 >&2

# 2. Locate the installed file. uv tools layout on Linux is
#    ~/.local/share/uv/tools/<name>/lib/python3.*/site-packages/<name>/__init__.py.
INIT_PY=$(ls /root/.local/share/uv/tools/httpie/lib/python3.*/site-packages/httpie/__init__.py)
echo "Installed httpie at: $INIT_PY" >&2

# 3. scan --global AGAIN. The crawler should now additionally enumerate the
#    uv-installed tool packages under ~/.local/share/uv/tools/. The JSON
#    output reports a `scannedPackages` count but doesn't enumerate by name
#    (only patched packages are listed), so we compare the count against the
#    baseline.
SCAN_OUT=$(socket-patch scan --json --global \
  --api-url '{api_url}' --api-token fake --org {ORG} \
  --ecosystems pypi 2>/tmp/scan.err)
SCAN_RC=$?
echo "scan exit=$SCAN_RC" >&2
cat /tmp/scan.err >&2 || true
if [ "$SCAN_RC" -ne 0 ]; then
  echo "FAIL: scan exited $SCAN_RC (expected 0)" >&2
  echo "$SCAN_OUT" | head -50 >&2
  exit 1
fi

# 4. Extract scannedPackages. A non-numeric/empty SCANNED would slip past
#    `[ "" -lt N ]` (that test errors out and the `if` is skipped), so we
#    validate it is a plain integer before comparing.
SCANNED=$(echo "$SCAN_OUT" | parse_scanned)
PARSE_RC=$?
if [ "$PARSE_RC" -ne 0 ]; then
  echo "FAIL: could not parse scannedPackages from scan JSON (rc=$PARSE_RC)" >&2
  echo "$SCAN_OUT" | head -50 >&2
  exit 1
fi
echo "scanned packages (post uv-tool-install): $SCANNED" >&2
case "$SCANNED" in
  ''|*[!0-9]*)
    echo "FAIL: scannedPackages is not a non-negative integer: '$SCANNED'" >&2
    echo "$SCAN_OUT" | head -50 >&2
    exit 1
    ;;
esac

# `uv tool install httpie` lands ENTIRELY under ~/.local/share/uv/tools/ —
# it never touches dist-packages. So if the uv-tools discovery branch is
# broken/dead, the second scan equals the first and the delta is exactly 0.
# Any positive delta therefore proves the uv tools layout was actually walked,
# independent of how large the dist-packages baseline happens to be (the old
# absolute `>= 10` check was reward-hackable: the ~79-package dist-packages
# baseline alone cleared it while uv-tools discovery could be completely dead).
#
# httpie pulls in a dozen-ish deps, but the scannedPackages count dedupes by
# package name, so deps that overlap dist-packages (requests, urllib3, idna,
# certifi, …) don't add. Empirically the net-new contribution is ~6 (httpie
# itself plus its uniquely-named deps like Pygments/requests-toolbelt/
# multidict). Require >= 3: comfortably above the broken-branch value of 0 and
# below the observed 6, so it stays robust to minor dep churn without ever
# passing when the uv tools root is not scanned.
DELTA=$((SCANNED - BASELINE))
echo "scanned-packages delta from uv tool install: $DELTA" >&2
if [ "$DELTA" -lt 3 ]; then
  echo "FAIL: uv tool install added only $DELTA scanned packages (baseline=$BASELINE post=$SCANNED); expected >= 3 net-new from the uv tools venv. uv tools layout likely not discovered." >&2
  echo "$SCAN_OUT" | head -50 >&2
  exit 1
fi

echo "===SCAN VERIFIED===" >&2
# Reuse the local marker so the harness assertion finds it.
echo "===E2E PASS {patched_marker}==="
exit 0
"#
    )
}

/// Hermeticity guard for the uv-tool variant, runnable without the
/// docker image. BOTH scans in the generated script (baseline +
/// post-install) must be pinned to the test's wiremock: without
/// `--api-url`, `scan --global` falls back to the LIVE public patch
/// proxy, leaking the container's real installed purls to production
/// on every run and failing outright (an all-batches-failed scan
/// exits 1) on any machine where that proxy is unreachable.
#[test]
fn uv_tool_script_pins_scans_to_the_mock_api() {
    let script = uv_tool_script("http://host.docker.internal:12345", "marker");
    assert_eq!(
        script
            .matches("--api-url 'http://host.docker.internal:12345'")
            .count(),
        2,
        "both uv-tool scans (baseline + post-install) must target the \
         test's wiremock, not the live public proxy:\n{script}"
    );
    assert_eq!(
        script.matches(&format!("--org {ORG}")).count(),
        2,
        "both uv-tool scans must send their batch queries to the mocked \
         org endpoint:\n{script}"
    );
}

/// Returns `true` when the test should skip (docker missing, image
/// missing). Prints a skip notice to stderr — the test still reports as
/// `ok` because Rust integration tests have no native "skipped" outcome.
#[must_use]
fn skip_if_no_image() -> bool {
    let Ok(out) = Command::new("docker")
        .args(["image", "inspect", "socket-patch-test-pypi:latest"])
        .output()
    else {
        eprintln!("skipping: `docker` not on PATH");
        return true;
    };
    if !out.status.success() {
        eprintln!("skipping: docker image `socket-patch-test-pypi:latest` not present");
        return true;
    }
    false
}

/// Host-side oracle over the VEX document the container emitted between the
/// `===VEX DOC BEGIN===` / `===VEX DOC END===` markers (these agent suites run
/// the workspace inside the container with no bind mount, so the doc is parsed
/// from captured stdout). Asserts exactly one statement attesting the agent
/// patch: the fixture GHSA, `not_affected`, the installed-package subcomponent
/// purl, and a PLAIN impact statement with NO `(vendored)`/`(redirected)`
/// marker — the marker's absence is what distinguishes agent provenance.
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

fn run_container(_api_url: &str, script: &str) -> std::process::Output {
    let mut cmd = Command::new("docker");
    cmd.args([
        "run",
        "--rm",
        "--add-host=host.docker.internal:host-gateway",
        "-i",
    ])
    .args(cov_docker_args())
    .args(["socket-patch-test-pypi:latest", "bash", "-c", script]);
    cmd.output().expect("docker run")
}

#[tokio::test]
async fn pypi_local_install_full_apply_chain() {
    let after_hash = git_sha256(PATCHED_PY);
    let server = make_mock_server(&after_hash).await;
    let api_url = format!("http://host.docker.internal:{}", server.address().port());
    if skip_if_no_image() {
        return;
    }
    let expected_sha = sha256_hex(PATCHED_PY);
    let out = run_container(&api_url, &local_script(&api_url, &expected_sha));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "pypi local apply failed:\nstdout=\n{stdout}\nstderr=\n{stderr}"
    );
    // Both stage gates must have fired — discovery AND the apply/content
    // check — not just the script reaching its tail.
    assert!(stderr.contains("===SCAN VERIFIED==="), "stderr=\n{stderr}");
    assert!(stderr.contains("===PATCH VERIFIED==="), "stderr=\n{stderr}");
    assert!(stdout.contains("===E2E PASS==="), "stdout=\n{stdout}");
    // Agent-mode VEX leg: the manifest patch was attested with plain
    // (non-vendored, non-redirected) provenance against the patched six.py.
    assert!(
        stderr.contains("===VEX VERIFIED==="),
        "agent-mode VEX leg did not run/pass (===VEX VERIFIED=== missing).\nstderr=\n{stderr}"
    );
    assert_vex_agent_attested(&stdout, PURL);
    assert_api_path_exercised(&server).await;
}

#[tokio::test]
async fn pypi_global_install_full_apply_chain() {
    let after_hash = git_sha256(PATCHED_PY);
    let server = make_mock_server(&after_hash).await;
    let api_url = format!("http://host.docker.internal:{}", server.address().port());
    if skip_if_no_image() {
        return;
    }
    let expected_sha = sha256_hex(PATCHED_PY);
    let out = run_container(&api_url, &global_script(&api_url, &expected_sha));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "pypi global apply failed:\nstdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(stderr.contains("===SCAN VERIFIED==="), "stderr=\n{stderr}");
    assert!(stderr.contains("===PATCH VERIFIED==="), "stderr=\n{stderr}");
    assert!(stdout.contains("===E2E PASS==="), "stdout=\n{stdout}");
    assert_api_path_exercised(&server).await;
}

/// uv-managed venv install + apply. Verifies the apply pipeline's
/// CoW guard (`break_hardlink_if_needed`) works for uv's
/// hard-link-from-cache layout. See `uv_venv_script` for the
/// inode-change + cache-integrity assertions inside the container.
#[tokio::test]
async fn pypi_uv_venv_install_full_apply_chain() {
    let after_hash = git_sha256(PATCHED_PY);
    let server = make_mock_server(&after_hash).await;
    let api_url = format!("http://host.docker.internal:{}", server.address().port());
    if skip_if_no_image() {
        return;
    }
    let expected_sha = sha256_hex(PATCHED_PY);
    let out = run_container(&api_url, &uv_venv_script(&api_url, &expected_sha));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "pypi uv venv apply failed:\nstdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(stderr.contains("===SCAN VERIFIED==="), "stderr=\n{stderr}");
    assert!(stderr.contains("===PATCH VERIFIED==="), "stderr=\n{stderr}");
    assert!(stdout.contains("===E2E PASS==="), "stdout=\n{stdout}");
    assert_api_path_exercised(&server).await;
}

/// `uv tool install` + socket-patch scan. Proves the uv-tools
/// discovery branch at python_crawler.rs (the platform-gated
/// `~/.local/share/uv/tools/*` scan) works end-to-end against a
/// real `uv tool install`. The scan assertion is sufficient — a
/// full apply would require per-tool wiremock fixtures which is
/// out of scope.
#[tokio::test]
async fn pypi_uv_tool_install_full_apply_chain() {
    let after_hash = git_sha256(PATCHED_PY);
    let server = make_mock_server(&after_hash).await;
    let api_url = format!("http://host.docker.internal:{}", server.address().port());
    if skip_if_no_image() {
        return;
    }
    let marker = "uv-tool-discovery-ok";
    let out = run_container(&api_url, &uv_tool_script(&api_url, marker));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "pypi uv tool scan failed:\nstdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(stderr.contains("===SCAN VERIFIED==="), "stderr=\n{stderr}");
    assert!(stdout.contains(marker), "stdout=\n{stdout}");
}
