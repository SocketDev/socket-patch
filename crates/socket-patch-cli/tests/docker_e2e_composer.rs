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

fn git_sha256(content: &[u8]) -> String {
    let header = format!("blob {}\0", content.len());
    let mut hasher = Sha256::new();
    hasher.update(header.as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
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
                    "severity": "low", "title": "composer e2e fixture"
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

fn local_script(api_url: &str) -> String {
    format!(
        r#"#!/usr/bin/env bash
set -uo pipefail

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

socket-patch scan --json --sync --yes \
  --api-url '{api_url}' --api-token fake --org {ORG} \
  --ecosystems composer 2>/tmp/sync.err
cat /tmp/sync.err >&2

socket-patch apply --json --force --offline --ecosystems composer 2>/tmp/apply.err
cat /tmp/apply.err >&2

if ! grep -q 'SOCKET-PATCH-E2E-MARKER' "$PHP_FILE"; then
  echo "FAIL: marker not in $PHP_FILE" >&2
  head -3 "$PHP_FILE" >&2
  exit 1
fi

echo "===PATCH VERIFIED===" >&2
echo "===E2E PASS==="
exit 0
"#
    )
}

fn global_script(api_url: &str) -> String {
    format!(
        r#"#!/usr/bin/env bash
set -uo pipefail

# composer global require installs into $COMPOSER_HOME/vendor/.
composer global require --quiet --no-interaction monolog/monolog:3.5.0 > /tmp/install.log 2>&1 || {{
  cat /tmp/install.log >&2; exit 1
}}

COMPOSER_DIR=$(composer config --global home)
PHP_FILE="$COMPOSER_DIR/vendor/monolog/monolog/src/Monolog/Logger.php"
[ -f "$PHP_FILE" ] || {{ echo "FAIL: $PHP_FILE missing" >&2; ls "$COMPOSER_DIR/vendor/monolog/monolog/src/Monolog/" >&2 || true; exit 1; }}
echo "Global-installed at: $PHP_FILE" >&2

mkdir -p /workspace/proj && cd /workspace/proj

socket-patch scan --json --sync --yes --global \
  --api-url '{api_url}' --api-token fake --org {ORG} \
  --ecosystems composer 2>/tmp/sync.err
cat /tmp/sync.err >&2

socket-patch apply --json --force --offline --global --ecosystems composer 2>/tmp/apply.err
cat /tmp/apply.err >&2

if ! grep -q 'SOCKET-PATCH-E2E-MARKER' "$PHP_FILE"; then
  echo "FAIL: marker not in $PHP_FILE" >&2
  head -3 "$PHP_FILE" >&2
  exit 1
fi

echo "===PATCH VERIFIED===" >&2
echo "===E2E PASS==="
exit 0
"#
    )
}

fn assert_image() {
    let out = Command::new("docker")
        .args(["image", "inspect", "socket-patch-test-composer:latest"])
        .output()
        .expect("docker");
    if !out.status.success() {
        panic!(
            "socket-patch-test-composer:latest missing. Build: \
             docker build -f tests/docker/Dockerfile.composer \
             -t socket-patch-test-composer:latest ."
        );
    }
}

fn run_container(script: &str) -> std::process::Output {
    Command::new("docker")
        .args([
            "run",
            "--rm",
            "--add-host=host.docker.internal:host-gateway",
            "-i",
            "socket-patch-test-composer:latest",
            "bash",
            "-c",
            script,
        ])
        .output()
        .expect("docker run")
}

#[tokio::test]
async fn composer_local_install_full_apply_chain() {
    let after_hash = git_sha256(PATCHED_PHP);
    let server = make_mock_server(&after_hash).await;
    let api_url = format!("http://host.docker.internal:{}", server.address().port());
    assert_image();
    let out = run_container(&local_script(&api_url));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "composer local apply failed:\nstdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(stderr.contains("===PATCH VERIFIED==="), "stderr=\n{stderr}");
    assert!(stdout.contains("===E2E PASS==="), "stdout=\n{stdout}");
}

#[tokio::test]
async fn composer_global_install_full_apply_chain() {
    let after_hash = git_sha256(PATCHED_PHP);
    let server = make_mock_server(&after_hash).await;
    let api_url = format!("http://host.docker.internal:{}", server.address().port());
    assert_image();
    let out = run_container(&global_script(&api_url));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "composer global apply failed:\nstdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(stderr.contains("===PATCH VERIFIED==="), "stderr=\n{stderr}");
    assert!(stdout.contains("===E2E PASS==="), "stdout=\n{stdout}");
}
