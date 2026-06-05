//! Docker-driven full install→apply chain for the gem (Ruby) ecosystem.
//!
//! Two test functions:
//! - `gem_local_install_full_apply_chain` — `gem install --install-dir
//!   vendor/bundle/ruby/<ver>` (project-local layout, like `bundle
//!   install --path vendor/bundle`); socket-patch scans the
//!   project-local vendor/bundle, applies, marker verified in the
//!   installed `lib/colorize.rb`.
//! - `gem_global_install_full_apply_chain` — `gem install` without
//!   --install-dir, installs to the system gem directory; socket-patch
//!   scans + applies with `--global`.

#![cfg(feature = "docker-e2e")]

use std::process::Command;

use base64::Engine;
use sha2::{Digest, Sha256};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";
const PURL: &str = "pkg:gem/colorize@1.1.0";
const UUID: &str = "13131313-1313-4131-8131-131313131313";

const PATCHED_RB: &[u8] = b"# SOCKET-PATCH-E2E-MARKER\n\
                            # colorize.rb replaced by socket-patch e2e fixture\n\
                            module Colorize\n  VERSION = '1.1.0-patched'\nend\n";

/// See docker_e2e_npm.rs::cov_docker_args for the coverage hook
/// semantics. The CI coverage-docker job sets the env vars; locally
/// they're unset and this returns an empty Vec.
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

/// Plain SHA-256 of the bytes (no git blob header) — matches what
/// `sha256sum` reports inside the container, so the test can assert the
/// installed file is byte-identical to the patch blob, not merely that
/// it contains the marker substring.
fn plain_sha256(content: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content);
    hex::encode(hasher.finalize())
}

/// Shared verification block for both scripts. Expects `GEM_FILE`,
/// `EXPECTED_SHA`, and `APPLY_EXIT` to be set, plus the JSON captured in
/// `/tmp/scan.json` and `/tmp/apply.json`.
///
/// This asserts on the *real structured output* of the run, not just a
/// substring marker:
///   - scan's JSON shows the colorize patch was discovered AND synced
///     (`"action": "added"`). NOTE: scan's process exit code is
///     deliberately NOT gated — a non-zero scan exit from an unrelated
///     transitive package without a patch must not fail a pipeline whose
///     target patch was found and synced.
///   - apply exited 0 and its JSON reports the patch was actually
///     `"applied"`, hash-`"verified": true`, with `summary.applied == 1`
///     — this rejects a no-op "success" that patches nothing.
///   - the installed file contains the marker AND is byte-for-byte
///     identical to the patch blob the API served (exact sha256), so
///     truncated/garbled/appended writes can't slip through.
fn verify_snippet() -> &'static str {
    r#"
# --- scan: must have discovered and synced the colorize patch ---
grep -qF 'pkg:gem/colorize@1.1.0' /tmp/scan.json || {
  echo "FAIL: scan json missing colorize purl" >&2; cat /tmp/scan.json >&2; exit 1; }
grep -qF '"action": "added"' /tmp/scan.json || {
  echo "FAIL: scan did not sync (add) the patch" >&2; cat /tmp/scan.json >&2; exit 1; }

# --- apply: must exit 0 and report a real applied+verified patch ---
if [ "${APPLY_EXIT:-1}" != "0" ]; then
  echo "FAIL: apply exited non-zero (${APPLY_EXIT:-unset})" >&2; cat /tmp/apply.json >&2; exit 1
fi
for needle in '"status": "success"' '"action": "applied"' '"verified": true' '"applied": 1' 'pkg:gem/colorize@1.1.0'; do
  grep -qF "$needle" /tmp/apply.json || {
    echo "FAIL: apply json missing [$needle]" >&2; cat /tmp/apply.json >&2; exit 1; }
done

# --- installed file: marker present AND byte-identical to the patch blob ---
if ! grep -q 'SOCKET-PATCH-E2E-MARKER' "$GEM_FILE"; then
  echo "FAIL: marker not in $GEM_FILE" >&2
  head -3 "$GEM_FILE" >&2
  exit 1
fi
ACTUAL_SHA=$(sha256sum "$GEM_FILE" | cut -d' ' -f1)
if [ "$ACTUAL_SHA" != "$EXPECTED_SHA" ]; then
  echo "FAIL: $GEM_FILE content sha256 ($ACTUAL_SHA) != expected ($EXPECTED_SHA)" >&2
  echo "---- actual file ----" >&2
  cat "$GEM_FILE" >&2
  exit 1
fi

echo "===PATCH VERIFIED===" >&2
echo "===E2E PASS==="
exit 0
"#
}

async fn make_mock_server(after_hash: &str) -> MockServer {
    let listener =
        std::net::TcpListener::bind("0.0.0.0:0").expect("bind wiremock");
    let server = MockServer::builder().listener(listener).start().await;

    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": PURL,
                "patches": [{
                    "uuid": UUID, "purl": PURL,
                    "tier": "free", "cveIds": [], "ghsaIds": [],
                    "severity": "medium", "title": "gem e2e fixture"
                }]
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path_regex(format!("^/v0/orgs/{ORG}/patches/by-package/.+$")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [{
                "uuid": UUID, "purl": PURL,
                "publishedAt": "2024-01-01T00:00:00Z",
                "description": "gem e2e fixture",
                "license": "MIT", "tier": "free",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(&server)
        .await;

    let blob_b64 = base64::engine::general_purpose::STANDARD.encode(PATCHED_RB);
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": UUID,
            "purl": PURL,
            "publishedAt": "2024-01-01T00:00:00Z",
            "files": {
                // gem uses `package/<rel>` (npm-style) — apply strips
                // the prefix and joins with the gem dir.
                "package/lib/colorize.rb": {
                    "beforeHash": "0000000000000000000000000000000000000000000000000000000000000000",
                    "afterHash":  after_hash,
                    "blobContent": blob_b64,
                }
            },
            "vulnerabilities": {},
            "description": "gem e2e fixture",
            "license": "MIT",
            "tier": "free",
        })))
        .mount(&server)
        .await;

    server
}

fn local_script(api_url: &str, expected_sha: &str) -> String {
    let verify = verify_snippet();
    format!(
        r#"#!/usr/bin/env bash
set -uo pipefail
EXPECTED_SHA='{expected_sha}'

mkdir -p /workspace/proj && cd /workspace/proj
RUBY_VER=$(ruby -e 'puts RUBY_VERSION.split(".").take(2).join(".") + ".0"')
INSTALL_DIR="vendor/bundle/ruby/$RUBY_VER"
mkdir -p "$INSTALL_DIR"
gem install --no-document --install-dir "$INSTALL_DIR" colorize -v 1.1.0 > /tmp/install.log 2>&1 || {{
  cat /tmp/install.log >&2; exit 1
}}

GEM_FILE="$INSTALL_DIR/gems/colorize-1.1.0/lib/colorize.rb"
[ -f "$GEM_FILE" ] || {{ echo "FAIL: $GEM_FILE missing" >&2; exit 1; }}
echo "Installed to: $GEM_FILE" >&2

# scan exit code is intentionally not gated (see verify_snippet); capture JSON.
socket-patch scan --json --sync --yes \
  --api-url '{api_url}' --api-token fake --org {ORG} \
  --ecosystems gem > /tmp/scan.json 2>/tmp/sync.err
cat /tmp/sync.err >&2

socket-patch apply --json --force --offline --ecosystems gem > /tmp/apply.json 2>/tmp/apply.err
APPLY_EXIT=$?
cat /tmp/apply.err >&2
{verify}"#
    )
}

fn global_script(api_url: &str, expected_sha: &str) -> String {
    let verify = verify_snippet();
    format!(
        r#"#!/usr/bin/env bash
set -uo pipefail
EXPECTED_SHA='{expected_sha}'

# gem install without --install-dir uses the system gem dir.
gem install --no-document colorize -v 1.1.0 > /tmp/install.log 2>&1 || {{
  cat /tmp/install.log >&2; exit 1
}}

GEM_DIR=$(gem env gemdir)
GEM_FILE="$GEM_DIR/gems/colorize-1.1.0/lib/colorize.rb"
[ -f "$GEM_FILE" ] || {{ echo "FAIL: $GEM_FILE missing" >&2; exit 1; }}
echo "Global-installed at: $GEM_FILE" >&2

mkdir -p /workspace/proj && cd /workspace/proj

# scan exit code is intentionally not gated (see verify_snippet); capture JSON.
socket-patch scan --json --sync --yes --global \
  --api-url '{api_url}' --api-token fake --org {ORG} \
  --ecosystems gem > /tmp/scan.json 2>/tmp/sync.err
cat /tmp/sync.err >&2

socket-patch apply --json --force --offline --global --ecosystems gem > /tmp/apply.json 2>/tmp/apply.err
APPLY_EXIT=$?
cat /tmp/apply.err >&2
{verify}"#
    )
}

/// Returns `true` when the test should skip (docker missing, image
/// missing). Prints a skip notice to stderr — the test still reports
/// as `ok` because Rust integration tests have no native "skipped"
/// outcome. Build locally with
/// `docker build -f tests/docker/Dockerfile.gem -t socket-patch-test-gem:latest .`
#[must_use]
fn skip_if_no_image() -> bool {
    let Ok(out) = Command::new("docker")
        .args(["image", "inspect", "socket-patch-test-gem:latest"])
        .output()
    else {
        eprintln!("skipping: `docker` not on PATH");
        return true;
    };
    if !out.status.success() {
        eprintln!("skipping: docker image `socket-patch-test-gem:latest` not present");
        return true;
    }
    false
}

fn run_container(script: &str) -> std::process::Output {
    let mut cmd = Command::new("docker");
    cmd.args([
        "run",
        "--rm",
        "--add-host=host.docker.internal:host-gateway",
        "-i",
    ])
    .args(cov_docker_args())
    .args(["socket-patch-test-gem:latest", "bash", "-c", script]);
    cmd.output().expect("docker run")
}

/// Assert the wiremock actually served BOTH the metadata discovery
/// (batch) AND the patch-content fetch (view). The in-container `echo`
/// markers alone can't prove the real network path ran — a build that
/// short-circuits the API (cached layer, stubbed fetch, or a marker
/// written by some unrelated mechanism) could still emit them. Requiring
/// the server to have observed the batch POST and the per-UUID blob GET
/// proves the genuine scan→download→apply code path executed end to end.
async fn assert_api_path_exercised(server: &MockServer) {
    let received = server.received_requests().await.unwrap_or_default();
    let paths: Vec<String> = received.iter().map(|r| r.url.path().to_string()).collect();
    assert!(
        paths.iter().any(|p| p.contains("/patches/batch")),
        "scan should have called /patches/batch; received={paths:#?}"
    );
    assert!(
        paths.iter().any(|p| p.contains(&format!("/patches/view/{UUID}"))),
        "scan --sync should have fetched patch content via /patches/view/{UUID}; received={paths:#?}"
    );
}

#[tokio::test]
async fn gem_local_install_full_apply_chain() {
    let after_hash = git_sha256(PATCHED_RB);
    let server = make_mock_server(&after_hash).await;
    let api_url = format!("http://host.docker.internal:{}", server.address().port());
    if skip_if_no_image() {
        return;
    }
    let expected_sha = plain_sha256(PATCHED_RB);
    let out = run_container(&local_script(&api_url, &expected_sha));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "gem local apply failed:\nstdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(stderr.contains("===PATCH VERIFIED==="), "stderr=\n{stderr}");
    assert!(stdout.contains("===E2E PASS==="), "stdout=\n{stdout}");
    assert_api_path_exercised(&server).await;
}

#[tokio::test]
async fn gem_global_install_full_apply_chain() {
    let after_hash = git_sha256(PATCHED_RB);
    let server = make_mock_server(&after_hash).await;
    let api_url = format!("http://host.docker.internal:{}", server.address().port());
    if skip_if_no_image() {
        return;
    }
    let expected_sha = plain_sha256(PATCHED_RB);
    let out = run_container(&global_script(&api_url, &expected_sha));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "gem global apply failed:\nstdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(stderr.contains("===PATCH VERIFIED==="), "stderr=\n{stderr}");
    assert!(stdout.contains("===E2E PASS==="), "stdout=\n{stdout}");
    assert_api_path_exercised(&server).await;
}
