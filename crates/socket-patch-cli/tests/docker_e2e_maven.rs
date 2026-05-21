//! Docker-driven full install→apply chain for the maven ecosystem.
//!
//! `mvn dependency:get` downloads an artifact into `~/.m2/repository/
//! <group_path>/<artifact>/<version>/`. The maven crawler scans the
//! m2 repo. Single test (no global variant) — `~/.m2/repository` IS
//! the cache for both modes.
//!
//! We overwrite the artifact's .pom file with synthetic content
//! containing the marker. The .pom is just metadata — apply replaces
//! it byte-for-byte and the grep verifies on disk.

#![cfg(feature = "docker-e2e")]

use std::process::Command;

use base64::Engine;
use sha2::{Digest, Sha256};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";
const PURL: &str = "pkg:maven/org.apache.commons/commons-lang3@3.12.0";
const UUID: &str = "16161616-1616-4161-8161-161616161616";

const PATCHED_POM: &[u8] = b"<!-- SOCKET-PATCH-E2E-MARKER -->\n\
                             <!-- pom overwritten by socket-patch e2e fixture -->\n\
                             <project xmlns=\"http://maven.apache.org/POM/4.0.0\">\n\
                             <modelVersion>4.0.0</modelVersion>\n\
                             <groupId>org.apache.commons</groupId>\n\
                             <artifactId>commons-lang3</artifactId>\n\
                             <version>3.12.0-patched</version>\n\
                             </project>\n";

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
                    "severity": "medium", "title": "maven e2e fixture"
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
                "description": "maven e2e fixture",
                "license": "MIT", "tier": "free",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(&server)
        .await;

    let blob_b64 = base64::engine::general_purpose::STANDARD.encode(PATCHED_POM);
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": UUID,
            "purl": PURL,
            "publishedAt": "2024-01-01T00:00:00Z",
            "files": {
                // maven uses `package/<rel>`; apply strips and joins
                // with the version dir (group_path/artifact/version/).
                "package/commons-lang3-3.12.0.pom": {
                    "beforeHash": "0000000000000000000000000000000000000000000000000000000000000000",
                    "afterHash":  after_hash,
                    "blobContent": blob_b64,
                }
            },
            "vulnerabilities": {},
            "description": "maven e2e fixture",
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
# pom.xml acts as a Java-project marker that the maven crawler needs
# even in --global mode, since the crawler honors --global by reading
# ~/.m2 directly. We pass --global below to short-circuit the local
# marker check.
cat > pom.xml <<'EOF'
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>test</groupId>
  <artifactId>e2e</artifactId>
  <version>1.0.0</version>
</project>
EOF

# Download the real artifact into ~/.m2/repository.
mvn -q dependency:get \
  -Dartifact=org.apache.commons:commons-lang3:3.12.0 \
  -DremoteRepositories=https://repo.maven.apache.org/maven2 \
  > /tmp/install.log 2>&1 || {{ cat /tmp/install.log >&2; exit 1; }}

POM_FILE="$HOME/.m2/repository/org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.pom"
[ -f "$POM_FILE" ] || {{ echo "FAIL: $POM_FILE missing" >&2; exit 1; }}
echo "Downloaded to: $POM_FILE" >&2

socket-patch scan --json --sync --yes --global \
  --api-url '{api_url}' --api-token fake --org {ORG} \
  --ecosystems maven 2>/tmp/sync.err
cat /tmp/sync.err >&2

socket-patch apply --json --force --offline --global --ecosystems maven 2>/tmp/apply.err
cat /tmp/apply.err >&2

if ! grep -q 'SOCKET-PATCH-E2E-MARKER' "$POM_FILE"; then
  echo "FAIL: marker not in $POM_FILE" >&2
  head -3 "$POM_FILE" >&2
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
        .args(["image", "inspect", "socket-patch-test-maven:latest"])
        .output()
        .expect("docker");
    if !out.status.success() {
        panic!(
            "socket-patch-test-maven:latest missing. Build: \
             docker build -f tests/docker/Dockerfile.maven \
             -t socket-patch-test-maven:latest ."
        );
    }
}

#[tokio::test]
async fn maven_install_full_apply_chain() {
    let after_hash = git_sha256(PATCHED_POM);
    let server = make_mock_server(&after_hash).await;
    let api_url = format!("http://host.docker.internal:{}", server.address().port());
    assert_image();
    let out = Command::new("docker")
        .args([
            "run",
            "--rm",
            "--add-host=host.docker.internal:host-gateway",
            "-i",
            "socket-patch-test-maven:latest",
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
        "maven apply failed:\nstdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(stderr.contains("===PATCH VERIFIED==="), "stderr=\n{stderr}");
    assert!(stdout.contains("===E2E PASS==="), "stdout=\n{stdout}");
}
