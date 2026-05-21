//! Docker-driven full install→apply chain for the golang ecosystem.
//!
//! `go mod download` populates `$GOMODCACHE/<encoded-module-path>@
//! <version>/`. The go crawler scans that cache. Single test (no
//! global variant) because golang's module cache IS the only cache —
//! local-vs-global is a no-op.

#![cfg(feature = "docker-e2e")]

use std::process::Command;

use base64::Engine;
use sha2::{Digest, Sha256};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";
const PURL: &str = "pkg:golang/github.com/gin-gonic/gin@v1.9.1";
const UUID: &str = "15151515-1515-4151-8151-151515151515";

const PATCHED_GO: &[u8] = b"// SOCKET-PATCH-E2E-MARKER\n\
                            // gin.go replaced by socket-patch e2e fixture\n\
                            package gin\n\nconst Version = \"v1.9.1-patched\"\n";

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
                    "severity": "high", "title": "golang e2e fixture"
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
                "description": "golang e2e fixture",
                "license": "MIT", "tier": "free",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(&server)
        .await;

    let blob_b64 = base64::engine::general_purpose::STANDARD.encode(PATCHED_GO);
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": UUID,
            "purl": PURL,
            "publishedAt": "2024-01-01T00:00:00Z",
            "files": {
                "package/gin.go": {
                    "beforeHash": "0000000000000000000000000000000000000000000000000000000000000000",
                    "afterHash":  after_hash,
                    "blobContent": blob_b64,
                }
            },
            "vulnerabilities": {},
            "description": "golang e2e fixture",
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
go mod init e2e-test > /dev/null 2>&1
go mod download github.com/gin-gonic/gin@v1.9.1 > /tmp/download.log 2>&1 || {{
  cat /tmp/download.log >&2; exit 1
}}

GIN_GO="$GOMODCACHE/github.com/gin-gonic/gin@v1.9.1/gin.go"
[ -f "$GIN_GO" ] || {{ echo "FAIL: $GIN_GO missing" >&2; ls "$GOMODCACHE/github.com/gin-gonic/" >&2 || true; exit 1; }}
echo "Downloaded to: $GIN_GO" >&2

# Module cache files are read-only by default; apply's chmod logic
# handles it but we pre-chmod for robustness.
chmod u+w "$GIN_GO" || true

socket-patch scan --json --sync --yes --global \
  --api-url '{api_url}' --api-token fake --org {ORG} \
  --ecosystems golang 2>/tmp/sync.err
cat /tmp/sync.err >&2

socket-patch apply --json --force --offline --global --ecosystems golang 2>/tmp/apply.err
cat /tmp/apply.err >&2

if ! grep -q 'SOCKET-PATCH-E2E-MARKER' "$GIN_GO"; then
  echo "FAIL: marker not in $GIN_GO" >&2
  head -3 "$GIN_GO" >&2
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
        .args(["image", "inspect", "socket-patch-test-golang:latest"])
        .output()
        .expect("docker");
    if !out.status.success() {
        panic!(
            "socket-patch-test-golang:latest missing. Build: \
             docker build -f tests/docker/Dockerfile.golang \
             -t socket-patch-test-golang:latest ."
        );
    }
}

#[tokio::test]
async fn golang_download_full_apply_chain() {
    let after_hash = git_sha256(PATCHED_GO);
    let server = make_mock_server(&after_hash).await;
    let api_url = format!("http://host.docker.internal:{}", server.address().port());
    assert_image();
    let out = Command::new("docker")
        .args([
            "run",
            "--rm",
            "--add-host=host.docker.internal:host-gateway",
            "-i",
            "socket-patch-test-golang:latest",
            "bash",
            "-c",
            &local_script(&api_url),
        ])
        .output()
        .expect("docker run");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "golang apply failed:\nstdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(stderr.contains("===PATCH VERIFIED==="), "stderr=\n{stderr}");
    assert!(stdout.contains("===E2E PASS==="), "stdout=\n{stdout}");
}
