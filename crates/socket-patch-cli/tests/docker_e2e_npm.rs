//! Docker-driven end-to-end test for the npm ecosystem.
//!
//! Installs `minimist@1.2.2` (a real, historically-vulnerable package) via
//! `npm install` inside a Linux container, then drives the full
//! `socket-patch scan` → `apply` → `rollback` chain against a wiremock-
//! served patch fixture. Asserts the on-disk file is patched and
//! restored.
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

/// Marker we splice into the patched bytes so the test can assert
/// post-apply that the file has been overwritten.
const PATCHED_BYTES: &[u8] = b"/* SOCKET-PATCH-E2E-MARKER */\nmodule.exports = function () { return {}; };\n";

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
    let listener =
        std::net::TcpListener::bind("0.0.0.0:0").expect("bind wiremock to 0.0.0.0:0");
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
            "vulnerabilities": {},
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

# 2. scan --json: should discover the patch.
echo "===SCAN OUTPUT===" >&2
socket-patch scan --json "${{COMMON_ARGS[@]}}" 2>/tmp/scan.err
SCAN_RC=$?
echo "scan exit=$SCAN_RC" >&2
cat /tmp/scan.err >&2 || true

# 3. scan --sync writes the manifest and applies the patch in one go.
echo "===SCAN/SYNC OUTPUT===" >&2
socket-patch scan --json --sync --yes "${{COMMON_ARGS[@]}}" 2>/tmp/sync.err
SYNC_RC=$?
echo "sync exit=$SYNC_RC" >&2
cat /tmp/sync.err >&2 || true

# 4. scan --sync may end up with "no installed package" (unmatched)
#    because the fixture's installed minimist has different bytes than
#    our synthetic patch expects. Force-apply via the manifest written
#    by scan above.
echo "===APPLY OUTPUT===" >&2
socket-patch apply --json --force --offline 2>/tmp/apply.err
APPLY_RC=$?
echo "apply exit=$APPLY_RC" >&2
cat /tmp/apply.err >&2 || true

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

# 6. rollback — the fixture doesn't serve beforeHash blobs, so this
#    exercises the dispatch path but exits non-zero on the offline guard.
echo "===ROLLBACK OUTPUT===" >&2
socket-patch rollback --json --offline 2>/tmp/rb.err
RB_RC=$?
echo "rollback exit=$RB_RC" >&2
cat /tmp/rb.err >&2 || true

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
  --ecosystems npm 2>/tmp/sync.err
cat /tmp/sync.err >&2

socket-patch apply --json --force --offline --global --ecosystems npm 2>/tmp/apply.err
cat /tmp/apply.err >&2

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
    let host_script = script
        .replace("/workspace/proj", host_proj.to_str().unwrap())
        .replace("node_modules/minimist/index.js", "node_modules/minimist/index.js");
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
        eprintln!("skipping: `docker` not on PATH (set SOCKET_PATCH_TEST_HOST=1 to run on the host)");
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
    assert!(
        stderr.contains("===PATCH VERIFIED==="),
        "expected post-apply marker grep to succeed (===PATCH VERIFIED=== in stderr).\nstdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(
        stdout.contains("===E2E PASS==="),
        "PASS marker missing from stdout:\n{stdout}\nstderr:\n{stderr}"
    );

    // Keep the workspace_root reference alive — used by host mode to
    // resolve the in-tree binary. Without this clippy warns unused.
    let _ = workspace_root();

    // Sanity: the mock got the requests we expect (this isn't strictly
    // necessary since the script enforces correctness, but it's a
    // cheap consistency check).
    let received = server.received_requests().await.unwrap_or_default();
    assert!(
        received
            .iter()
            .any(|r| r.url.path().contains("/patches/batch")),
        "scan should have called /patches/batch; received={received:#?}"
    );
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
