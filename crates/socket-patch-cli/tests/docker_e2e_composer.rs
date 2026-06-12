//! Docker-driven full install→apply chain for the composer (PHP) ecosystem.
//!
//! Two test functions:
//! - `composer_local_install_full_apply_chain` — `composer require`
//!   installs into `vendor/<vendor>/<name>/`. socket-patch scans the
//!   project-local vendor dir, applies, marker verified in the
//!   installed `src/Logger.php`.
//! - `composer_global_install_full_apply_chain` — `composer global
//!   require` installs into `$COMPOSER_HOME/vendor/...`. socket-patch
//!   scans + applies with `--global`.

#![cfg(feature = "docker-e2e")]

use std::process::Command;

use base64::Engine;
use sha2::{Digest, Sha256};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";
const PURL: &str = "pkg:composer/monolog/monolog@3.5.0";
const UUID: &str = "17171717-1717-4171-8171-171717171717";

const PATCHED_PHP: &[u8] = b"<?php\n\
                             // SOCKET-PATCH-E2E-MARKER\n\
                             // Logger.php replaced by socket-patch e2e fixture\n\
                             namespace Monolog;\n\
                             class Logger {\n  public const VERSION = '3.5.0-patched';\n}\n";

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

/// Shared verification block for both scripts. Expects `PHP_FILE`,
/// `EXPECTED_SHA`, `PRE_SHA`, and `APPLY_EXIT` to be set, plus the JSON
/// captured in `/tmp/scan.json` and `/tmp/apply.json`.
///
/// This asserts on the *real structured output* of the run, not just a
/// substring marker:
///   - scan's JSON shows the monolog patch was discovered AND synced
///     (`"action": "added"`). NOTE: scan's process exit code is
///     deliberately NOT gated — with a transitive dep that has no patch,
///     scan reports `"status": "partial_failure"` / exit 1 even though
///     the monolog patch is found and synced. Gating exit==0 would fail a
///     genuinely-working pipeline.
///   - apply exited 0 and its JSON reports the patch was actually
///     `"applied"`, hash-`"verified": true`, with `summary.applied == 1`
///     (matched with a word boundary so `"applied": 10` can't sneak past)
///     — this rejects a no-op "success" that patches nothing.
///   - the installed file contains the marker AND is byte-for-byte
///     identical to the patch blob the API served (exact sha256), so
///     truncated/garbled/appended writes can't slip through.
///   - the file's sha actually CHANGED from its freshly-installed state
///     (`PRE_SHA`), so a fixture that was pre-patched (marker already
///     present before apply ran) can't make the post-checks pass
///     vacuously.
fn verify_snippet() -> &'static str {
    r#"
# --- scan: must have discovered and synced the monolog patch ---
grep -qF 'pkg:composer/monolog/monolog@3.5.0' /tmp/scan.json || {
  echo "FAIL: scan json missing monolog purl" >&2; cat /tmp/scan.json >&2; exit 1; }
grep -qF '"action": "added"' /tmp/scan.json || {
  echo "FAIL: scan did not sync (add) the patch" >&2; cat /tmp/scan.json >&2; exit 1; }

# --- apply: must exit 0 and report a real applied+verified patch ---
if [ "${APPLY_EXIT:-1}" != "0" ]; then
  echo "FAIL: apply exited non-zero (${APPLY_EXIT:-unset})" >&2; cat /tmp/apply.json >&2; exit 1
fi
for needle in '"status": "success"' '"action": "applied"' '"verified": true' 'pkg:composer/monolog/monolog@3.5.0'; do
  grep -qF "$needle" /tmp/apply.json || {
    echo "FAIL: apply json missing [$needle]" >&2; cat /tmp/apply.json >&2; exit 1; }
done
# exactly one applied patch — word-boundary match so "applied": 10/15/... can't pass.
grep -qE '"applied": 1([^0-9]|$)' /tmp/apply.json || {
  echo "FAIL: apply json does not report summary.applied == 1" >&2; cat /tmp/apply.json >&2; exit 1; }

# --- installed file: marker present AND byte-identical to the patch blob ---
if ! grep -q 'SOCKET-PATCH-E2E-MARKER' "$PHP_FILE"; then
  echo "FAIL: marker not in $PHP_FILE" >&2
  head -3 "$PHP_FILE" >&2
  exit 1
fi
ACTUAL_SHA=$(sha256sum "$PHP_FILE" | cut -d' ' -f1)
if [ "$ACTUAL_SHA" != "$EXPECTED_SHA" ]; then
  echo "FAIL: $PHP_FILE content sha256 ($ACTUAL_SHA) != expected ($EXPECTED_SHA)" >&2
  echo "---- actual file ----" >&2
  cat "$PHP_FILE" >&2
  exit 1
fi
# apply must have actually MUTATED the file from its installed state.
if [ "$ACTUAL_SHA" = "${PRE_SHA:-}" ]; then
  echo "FAIL: $PHP_FILE unchanged by apply (sha still ${PRE_SHA:-unset}); patch was a no-op" >&2
  exit 1
fi

echo "===PATCH VERIFIED===" >&2
echo "===E2E PASS==="
exit 0
"#
}

async fn make_mock_server(after_hash: &str) -> MockServer {
    let listener = std::net::TcpListener::bind("0.0.0.0:0").expect("bind wiremock");
    let server = MockServer::builder().listener(listener).start().await;

    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": PURL,
                "patches": [{
                    "uuid": UUID, "purl": PURL,
                    "tier": "free", "cveIds": [], "ghsaIds": [],
                    "severity": "low", "title": "composer e2e fixture"
                }]
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path_regex(format!(
            "^/v0/orgs/{ORG}/patches/by-package/.+$"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [{
                "uuid": UUID, "purl": PURL,
                "publishedAt": "2024-01-01T00:00:00Z",
                "description": "composer e2e fixture",
                "license": "MIT", "tier": "free",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(&server)
        .await;

    let blob_b64 = base64::engine::general_purpose::STANDARD.encode(PATCHED_PHP);
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": UUID,
            "purl": PURL,
            "publishedAt": "2024-01-01T00:00:00Z",
            "files": {
                // composer uses `package/<rel>`; apply strips and
                // joins with the package's vendor dir.
                "package/src/Monolog/Logger.php": {
                    "beforeHash": "0000000000000000000000000000000000000000000000000000000000000000",
                    "afterHash":  after_hash,
                    "blobContent": blob_b64,
                }
            },
            "vulnerabilities": {},
            "description": "composer e2e fixture",
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
cat > composer.json <<'EOF'
{{ "name": "test/e2e", "type": "project", "require": {{}} }}
EOF
composer require --quiet --no-interaction monolog/monolog:3.5.0 > /tmp/install.log 2>&1 || {{
  cat /tmp/install.log >&2; exit 1
}}

PHP_FILE="vendor/monolog/monolog/src/Monolog/Logger.php"
[ -f "$PHP_FILE" ] || {{ echo "FAIL: $PHP_FILE missing" >&2; ls vendor/monolog/monolog/src/Monolog/ >&2 || true; exit 1; }}
echo "Installed to: $PHP_FILE" >&2

# pristine pre-check: the freshly-installed upstream file must NOT already
# carry our marker, else a no-op apply would satisfy the post-checks vacuously.
if grep -q 'SOCKET-PATCH-E2E-MARKER' "$PHP_FILE"; then
  echo "FAIL: marker present in $PHP_FILE before apply (fixture not pristine)" >&2; exit 1
fi
PRE_SHA=$(sha256sum "$PHP_FILE" | cut -d' ' -f1)

# scan exit code is intentionally not gated (see verify_snippet); capture JSON.
socket-patch scan --json --sync --strict --yes \
  --api-url '{api_url}' --api-token fake --org {ORG} \
  --ecosystems composer > /tmp/scan.json 2>/tmp/sync.err
cat /tmp/sync.err >&2

socket-patch apply --json --force --offline --ecosystems composer > /tmp/apply.json 2>/tmp/apply.err
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

# composer global require installs into $COMPOSER_HOME/vendor/.
composer global require --quiet --no-interaction monolog/monolog:3.5.0 > /tmp/install.log 2>&1 || {{
  cat /tmp/install.log >&2; exit 1
}}

COMPOSER_DIR=$(composer config --global home)
PHP_FILE="$COMPOSER_DIR/vendor/monolog/monolog/src/Monolog/Logger.php"
[ -f "$PHP_FILE" ] || {{ echo "FAIL: $PHP_FILE missing" >&2; ls "$COMPOSER_DIR/vendor/monolog/monolog/src/Monolog/" >&2 || true; exit 1; }}
echo "Global-installed at: $PHP_FILE" >&2

# pristine pre-check: the freshly-installed upstream file must NOT already
# carry our marker, else a no-op apply would satisfy the post-checks vacuously.
if grep -q 'SOCKET-PATCH-E2E-MARKER' "$PHP_FILE"; then
  echo "FAIL: marker present in $PHP_FILE before apply (fixture not pristine)" >&2; exit 1
fi
PRE_SHA=$(sha256sum "$PHP_FILE" | cut -d' ' -f1)

mkdir -p /workspace/proj && cd /workspace/proj

# scan exit code is intentionally not gated (see verify_snippet); capture JSON.
socket-patch scan --json --sync --strict --yes --global \
  --api-url '{api_url}' --api-token fake --org {ORG} \
  --ecosystems composer > /tmp/scan.json 2>/tmp/sync.err
cat /tmp/sync.err >&2

socket-patch apply --json --force --offline --global --ecosystems composer > /tmp/apply.json 2>/tmp/apply.err
APPLY_EXIT=$?
cat /tmp/apply.err >&2
{verify}"#
    )
}

/// Returns `true` when the test should skip (docker missing, image
/// missing). Prints a skip notice to stderr — the test still reports
/// as `ok` because Rust integration tests have no native "skipped"
/// outcome. Build locally with
/// `docker build -f tests/docker/Dockerfile.composer -t socket-patch-test-composer:latest .`
#[must_use]
fn skip_if_no_image() -> bool {
    let Ok(out) = Command::new("docker")
        .args(["image", "inspect", "socket-patch-test-composer:latest"])
        .output()
    else {
        eprintln!("skipping: `docker` not on PATH");
        return true;
    };
    if !out.status.success() {
        eprintln!("skipping: docker image `socket-patch-test-composer:latest` not present");
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
    .args(["socket-patch-test-composer:latest", "bash", "-c", script]);
    cmd.output().expect("docker run")
}

/// Independent (Rust-side) proof that the container exercised the real
/// scan→sync network path against our mock — not a pre-baked/cached patch
/// store. `scan --sync` must POST batch discovery and GET the full patch
/// blob via `/patches/view/<uuid>`. If neither fired, the in-container
/// marker/sha checks would be meaningless, so this rejects a
/// short-circuited run even if the file somehow ended up patched.
async fn assert_real_pipeline_hit_the_api(server: &MockServer) {
    let reqs = server
        .received_requests()
        .await
        .expect("wiremock recorded requests");
    let hit = |needle: &str| reqs.iter().any(|r| r.url.path().contains(needle));
    let paths: Vec<String> = reqs.iter().map(|r| r.url.path().to_string()).collect();
    assert!(
        hit("/patches/batch"),
        "scan never POSTed batch discovery to the mock; recorded paths={paths:?}"
    );
    assert!(
        hit(&format!("/patches/view/{UUID}")),
        "sync never fetched the patch blob via /patches/view/{UUID}; recorded paths={paths:?}"
    );
}

#[tokio::test]
async fn composer_local_install_full_apply_chain() {
    let after_hash = git_sha256(PATCHED_PHP);
    let server = make_mock_server(&after_hash).await;
    let api_url = format!("http://host.docker.internal:{}", server.address().port());
    if skip_if_no_image() {
        return;
    }
    let expected_sha = plain_sha256(PATCHED_PHP);
    let out = run_container(&local_script(&api_url, &expected_sha));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "composer local apply failed:\nstdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(stderr.contains("===PATCH VERIFIED==="), "stderr=\n{stderr}");
    assert!(stdout.contains("===E2E PASS==="), "stdout=\n{stdout}");
    assert_real_pipeline_hit_the_api(&server).await;
}

#[tokio::test]
async fn composer_global_install_full_apply_chain() {
    let after_hash = git_sha256(PATCHED_PHP);
    let server = make_mock_server(&after_hash).await;
    let api_url = format!("http://host.docker.internal:{}", server.address().port());
    if skip_if_no_image() {
        return;
    }
    let expected_sha = plain_sha256(PATCHED_PHP);
    let out = run_container(&global_script(&api_url, &expected_sha));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "composer global apply failed:\nstdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(stderr.contains("===PATCH VERIFIED==="), "stderr=\n{stderr}");
    assert!(stdout.contains("===E2E PASS==="), "stdout=\n{stdout}");
}
