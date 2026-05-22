//! Docker-driven full install→apply chain for the cargo (Rust) ecosystem.
//!
//! `cargo fetch` downloads the crate source into `$CARGO_HOME/
//! registry/src/<index>/<crate>-<ver>/`. The cargo crawler scans
//! that registry-src layout when the project has a Cargo.toml.
//! Single test (local mode); there's no meaningful local-vs-global
//! distinction for cargo because the registry IS the only cache.

#![cfg(feature = "docker-e2e")]

use std::process::Command;

use base64::Engine;
use sha2::{Digest, Sha256};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";
const PURL: &str = "pkg:cargo/cfg-if@1.0.0";
const UUID: &str = "14141414-1414-4141-8141-141414141414";

const PATCHED_RS: &[u8] = b"// SOCKET-PATCH-E2E-MARKER\n\
                            // cfg-if/src/lib.rs replaced by socket-patch e2e fixture\n\
                            #[macro_export]\n\
                            macro_rules! cfg_if {\n    ($($t:tt)*) => {};\n}\n";

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
                    "severity": "low", "title": "cargo e2e fixture"
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
                "description": "cargo e2e fixture",
                "license": "MIT", "tier": "free",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(&server)
        .await;

    let blob_b64 = base64::engine::general_purpose::STANDARD.encode(PATCHED_RS);
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": UUID,
            "purl": PURL,
            "publishedAt": "2024-01-01T00:00:00Z",
            "files": {
                // cargo uses `package/<rel>`; apply strips the prefix
                // and joins with the crate's source directory.
                "package/src/lib.rs": {
                    "beforeHash": "0000000000000000000000000000000000000000000000000000000000000000",
                    "afterHash":  after_hash,
                    "blobContent": blob_b64,
                }
            },
            "vulnerabilities": {},
            "description": "cargo e2e fixture",
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

# Minimal Rust project depending on cfg-if at a pinned version.
mkdir -p /workspace/proj/src && cd /workspace/proj
cat > Cargo.toml <<'EOF'
[package]
name = "e2e"
version = "0.0.1"
edition = "2021"

[dependencies]
cfg-if = "=1.0.0"
EOF
echo 'fn main() {{}}' > src/main.rs

# cargo fetch populates $CARGO_HOME/registry/src/<index>/cfg-if-1.0.0/.
cargo fetch > /tmp/fetch.log 2>&1 || {{ cat /tmp/fetch.log >&2; exit 1; }}

LIB_RS=$(ls "$CARGO_HOME/registry/src/"*/cfg-if-1.0.0/src/lib.rs 2>/dev/null | head -1)
[ -f "$LIB_RS" ] || {{ echo "FAIL: cfg-if lib.rs not in registry/src" >&2; exit 1; }}
echo "Fetched to: $LIB_RS" >&2

# Cargo registry source files are read-only by default. Apply's unix
# fix-permissions code makes them writable, but we chmod up-front
# too in case anything else stomps on it.
chmod u+w "$LIB_RS" || true

# scan --sync writes manifest + blob; the cargo crawler with --global
# probes $CARGO_HOME/registry/src/.
socket-patch scan --json --sync --yes --global \
  --api-url '{api_url}' --api-token fake --org {ORG} \
  --ecosystems cargo 2>/tmp/sync.err
cat /tmp/sync.err >&2

socket-patch apply --json --force --offline --global --ecosystems cargo 2>/tmp/apply.err
cat /tmp/apply.err >&2

if ! grep -q 'SOCKET-PATCH-E2E-MARKER' "$LIB_RS"; then
  echo "FAIL: marker not in $LIB_RS" >&2
  head -3 "$LIB_RS" >&2
  exit 1
fi

echo "===PATCH VERIFIED===" >&2
echo "===E2E PASS==="
exit 0
"#
    )
}

/// Returns `true` when the test should skip (docker missing, image
/// missing). Prints a skip notice to stderr in that case so the test
/// log shows *why* the test did nothing — the test still reports as
/// `ok` because Rust integration tests have no native "skipped" outcome.
///
/// Local devs: build the image with
/// `docker build -f tests/docker/Dockerfile.base -t socket-patch-test-base:latest .`
/// then
/// `docker build -f tests/docker/Dockerfile.cargo -t socket-patch-test-cargo:latest .`
#[must_use]
fn skip_if_no_image() -> bool {
    let Ok(out) = Command::new("docker")
        .args(["image", "inspect", "socket-patch-test-cargo:latest"])
        .output()
    else {
        eprintln!("skipping: `docker` not on PATH");
        return true;
    };
    if !out.status.success() {
        eprintln!("skipping: docker image `socket-patch-test-cargo:latest` not present");
        return true;
    }
    false
}

#[tokio::test]
async fn cargo_fetch_full_apply_chain() {
    let after_hash = git_sha256(PATCHED_RS);
    let server = make_mock_server(&after_hash).await;
    let api_url = format!("http://host.docker.internal:{}", server.address().port());
    if skip_if_no_image() {
        return;
    }
    let mut cmd = Command::new("docker");
    cmd.args([
        "run",
        "--rm",
        "--add-host=host.docker.internal:host-gateway",
        "-i",
    ])
    .args(cov_docker_args())
    .args([
        "socket-patch-test-cargo:latest",
        "bash",
        "-c",
        &local_script(&api_url),
    ]);
    let out = cmd.output().expect("docker run");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "cargo apply failed:\nstdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(stderr.contains("===PATCH VERIFIED==="), "stderr=\n{stderr}");
    assert!(stdout.contains("===E2E PASS==="), "stdout=\n{stdout}");
}
