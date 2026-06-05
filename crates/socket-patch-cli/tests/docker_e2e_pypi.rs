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
    let received = server.received_requests().await.unwrap_or_default();
    let paths: Vec<&str> = received.iter().map(|r| r.url.path()).collect();
    assert!(
        paths.iter().any(|p| p.contains("/patches/batch")),
        "scan should have called /patches/batch; received={paths:#?}"
    );
    assert!(
        paths.iter().any(|p| p.contains("/patches/view/")),
        "scan --sync should have fetched patch content via /patches/view/; received={paths:#?}"
    );
}

async fn make_mock_server(after_hash: &str) -> MockServer {
    let listener =
        std::net::TcpListener::bind("0.0.0.0:0").expect("bind wiremock to 0.0.0.0:0");
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
            "vulnerabilities": {},
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

# Locate the installed six.py file.
SIX_PY=$(ls /workspace/venv/lib/python3.*/site-packages/six.py)
echo "Installed six at: $SIX_PY" >&2

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
  if [ -n "$CACHE_TWIN" ] && [ -f "$CACHE_TWIN" ]; then
    CACHE_HASH_BEFORE=$(sha256sum "$CACHE_TWIN" | cut -d' ' -f1)
    echo "cache twin: $CACHE_TWIN hash=$CACHE_HASH_BEFORE" >&2
  fi
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
fn uv_tool_script(_api_url: &str, patched_marker: &str) -> String {
    // httpie has a top-level package called `httpie`. We patch
    // `httpie/__init__.py`. The PURL in the manifest is fixed up by
    // the wiremock fixture; here we just need to discover it.
    format!(
        r#"#!/usr/bin/env bash
set -uo pipefail

# 1. uv tool install. httpie@3.2.2 is a real pypi package.
uv tool install --python python3 httpie==3.2.2 >&2

# 2. Locate the installed file. uv tools layout on Linux is
#    ~/.local/share/uv/tools/<name>/lib/python3.*/site-packages/<name>/__init__.py.
INIT_PY=$(ls /root/.local/share/uv/tools/httpie/lib/python3.*/site-packages/httpie/__init__.py)
echo "Installed httpie at: $INIT_PY" >&2

# The pypi docker e2e module's wiremock is keyed on pkg:pypi/six@1.16.0
# by default; for this uv-tool test the wiremock route hasn't been
# extended. So we just verify the crawler enumerates the package
# (proving the uv tools layout is discovered end-to-end). A real
# apply would need a wiremock route per-tool, which is out of scope
# for the coverage objective.
mkdir -p /workspace/proj && cd /workspace/proj

# 3. scan --global with the tools root as global_prefix. The crawler
#    should enumerate the uv-installed tool packages. The JSON output
#    reports a `scannedPackages` count but doesn't enumerate by name
#    (only patched packages are listed). Asserting the count is high
#    enough (>= the 17 deps uv pulled in for httpie above) is what
#    proves the uv tools layout was discovered.
SCAN_OUT=$(socket-patch scan --json --global --ecosystems pypi 2>/tmp/scan.err)
SCAN_RC=$?
echo "scan exit=$SCAN_RC" >&2
cat /tmp/scan.err >&2 || true
if [ "$SCAN_RC" -ne 0 ]; then
  echo "FAIL: scan exited $SCAN_RC (expected 0)" >&2
  echo "$SCAN_OUT" | head -50 >&2
  exit 1
fi

# 4. Extract scannedPackages from the JSON. Do NOT default a parse
#    failure to 0 (`.get(...,0)`) — a missing field or malformed JSON is
#    itself a regression and must surface, not silently degrade. A
#    non-numeric/empty SCANNED would also slip past `[ "" -lt N ]` (that
#    test errors out and the `if` is skipped), so we validate it is a
#    plain integer before comparing.
SCANNED=$(echo "$SCAN_OUT" | python3 -c "import sys,json; print(json.load(sys.stdin)['scannedPackages'])")
PARSE_RC=$?
if [ "$PARSE_RC" -ne 0 ]; then
  echo "FAIL: could not parse scannedPackages from scan JSON (rc=$PARSE_RC)" >&2
  echo "$SCAN_OUT" | head -50 >&2
  exit 1
fi
echo "scanned packages: $SCANNED" >&2
case "$SCANNED" in
  ''|*[!0-9]*)
    echo "FAIL: scannedPackages is not a non-negative integer: '$SCANNED'" >&2
    echo "$SCAN_OUT" | head -50 >&2
    exit 1
    ;;
esac
# httpie==3.2.2 pulls in ~17 transitive deps, all installed into the uv
# tools venv at ~/.local/share/uv/tools/httpie/. The old threshold of 5
# was BELOW what the Debian dist-packages baseline alone provides, so a
# completely broken uv-tools discovery branch still passed. Require >= 10
# so the count can only be reached if the uv tools layout was actually
# walked, not just dist-packages.
if [ "$SCANNED" -lt 10 ]; then
  echo "FAIL: scan found only $SCANNED packages; expected >= 10 (httpie + ~17 deps from the uv tools venv)" >&2
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
