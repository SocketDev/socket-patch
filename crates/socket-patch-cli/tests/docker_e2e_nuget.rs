//! Docker-driven full install→apply chain for the nuget (.NET) ecosystem.
//!
//! Two test functions:
//! - `nuget_local_install_full_apply_chain` — `NUGET_PACKAGES=./packages
//!   dotnet add package` redirects writes to the project-local
//!   `./packages/<lowercase-name>/<version>/` directory (still the
//!   global-cache layout, just relocated). socket-patch scans the
//!   project-local `./packages/`, applies, marker verified.
//! - `nuget_global_install_full_apply_chain` — plain `dotnet add
//!   package` populates `~/.nuget/packages/<lowercase-name>/<version>/`.
//!   socket-patch scans + applies with `--global`.
//!
//! Both tests overwrite the package's `LICENSE.md` file with synthetic
//! bytes containing the marker.

#![cfg(feature = "docker-e2e")]

use std::process::Command;

use base64::Engine;
use sha2::{Digest, Sha256};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";
// The nuget crawler reports installed packages with the lowercased
// directory name (because ~/.nuget/packages stores them as lowercase
// dirs). The wiremock fixture must return the same casing so scan's
// GC pass doesn't prune the freshly-saved manifest entry as
// "not-in-scanned-purls".
const PURL: &str = "pkg:nuget/newtonsoft.json@13.0.3";
const UUID: &str = "18181818-1818-4181-8181-181818181818";

const PATCHED_LICENSE: &[u8] = b"SOCKET-PATCH-E2E-MARKER\n\
                                 LICENSE.md replaced by socket-patch e2e fixture\n\
                                 The MIT License (MIT)\n\
                                 Copyright (c) 2024 socket-patch e2e\n";

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
                    "severity": "medium", "title": "nuget e2e fixture"
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
                "description": "nuget e2e fixture",
                "license": "MIT", "tier": "free",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(&server)
        .await;

    let blob_b64 = base64::engine::general_purpose::STANDARD.encode(PATCHED_LICENSE);
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": UUID,
            "purl": PURL,
            "publishedAt": "2024-01-01T00:00:00Z",
            "files": {
                // nuget uses `package/<rel>`; apply strips and joins
                // with the package's version dir.
                "package/LICENSE.md": {
                    "beforeHash": "0000000000000000000000000000000000000000000000000000000000000000",
                    "afterHash":  after_hash,
                    "blobContent": blob_b64,
                }
            },
            "vulnerabilities": {},
            "description": "nuget e2e fixture",
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
dotnet new console --force --output . > /dev/null 2>&1

# NUGET_PACKAGES redirects `dotnet add package` writes into ./packages
# (still global-cache layout — the crawler recognizes that layout when
# it appears inside <cwd>/packages/).
export NUGET_PACKAGES=$(pwd)/packages
mkdir -p "$NUGET_PACKAGES"
dotnet add package Newtonsoft.Json --version 13.0.3 > /tmp/install.log 2>&1 || {{
  cat /tmp/install.log >&2; exit 1
}}

LICENSE_FILE="$NUGET_PACKAGES/newtonsoft.json/13.0.3/LICENSE.md"
[ -f "$LICENSE_FILE" ] || {{ echo "FAIL: $LICENSE_FILE missing" >&2; ls "$NUGET_PACKAGES/newtonsoft.json/13.0.3/" >&2 || true; exit 1; }}
echo "Installed to: $LICENSE_FILE" >&2

socket-patch scan --json --sync --yes \
  --api-url '{api_url}' --api-token fake --org {ORG} \
  --ecosystems nuget 2>/tmp/sync.err
cat /tmp/sync.err >&2

socket-patch apply --json --force --offline --ecosystems nuget 2>/tmp/apply.err
cat /tmp/apply.err >&2

if ! grep -q 'SOCKET-PATCH-E2E-MARKER' "$LICENSE_FILE"; then
  echo "FAIL: marker not in $LICENSE_FILE" >&2
  head -3 "$LICENSE_FILE" >&2
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

# Default `dotnet add package` populates ~/.nuget/packages.
mkdir -p /workspace/proj && cd /workspace/proj
dotnet new console --force --output . > /dev/null 2>&1
dotnet add package Newtonsoft.Json --version 13.0.3 > /tmp/install.log 2>&1 || {{
  cat /tmp/install.log >&2; exit 1
}}

LICENSE_FILE="$HOME/.nuget/packages/newtonsoft.json/13.0.3/LICENSE.md"
[ -f "$LICENSE_FILE" ] || {{ echo "FAIL: $LICENSE_FILE missing" >&2; ls "$HOME/.nuget/packages/newtonsoft.json/13.0.3/" >&2 || true; exit 1; }}
echo "Global-installed at: $LICENSE_FILE" >&2

# Empty cwd — --global tells socket-patch to scan the global cache,
# ignoring cwd-relative discovery.
mkdir -p /workspace/empty && cd /workspace/empty

socket-patch scan --json --sync --yes --global \
  --api-url '{api_url}' --api-token fake --org {ORG} \
  --ecosystems nuget 2>/tmp/sync.err
cat /tmp/sync.err >&2

socket-patch apply --json --force --offline --global --ecosystems nuget 2>/tmp/apply.err
cat /tmp/apply.err >&2

if ! grep -q 'SOCKET-PATCH-E2E-MARKER' "$LICENSE_FILE"; then
  echo "FAIL: marker not in $LICENSE_FILE" >&2
  head -3 "$LICENSE_FILE" >&2
  exit 1
fi

echo "===PATCH VERIFIED===" >&2
echo "===E2E PASS==="
exit 0
"#
    )
}

/// Returns `true` when the test should skip (docker missing, image
/// missing). Prints a skip notice to stderr — the test still reports
/// as `ok` because Rust integration tests have no native "skipped"
/// outcome. Build locally with
/// `docker build -f tests/docker/Dockerfile.nuget -t socket-patch-test-nuget:latest .`
#[must_use]
fn skip_if_no_image() -> bool {
    let Ok(out) = Command::new("docker")
        .args(["image", "inspect", "socket-patch-test-nuget:latest"])
        .output()
    else {
        eprintln!("skipping: `docker` not on PATH");
        return true;
    };
    if !out.status.success() {
        eprintln!("skipping: docker image `socket-patch-test-nuget:latest` not present");
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
    .args(["socket-patch-test-nuget:latest", "bash", "-c", script]);
    cmd.output().expect("docker run")
}

#[tokio::test]
async fn nuget_local_install_full_apply_chain() {
    let after_hash = git_sha256(PATCHED_LICENSE);
    let server = make_mock_server(&after_hash).await;
    let api_url = format!("http://host.docker.internal:{}", server.address().port());
    if skip_if_no_image() {
        return;
    }
    let out = run_container(&local_script(&api_url));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "nuget local apply failed:\nstdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(stderr.contains("===PATCH VERIFIED==="), "stderr=\n{stderr}");
    assert!(stdout.contains("===E2E PASS==="), "stdout=\n{stdout}");
}

#[tokio::test]
async fn nuget_global_install_full_apply_chain() {
    let after_hash = git_sha256(PATCHED_LICENSE);
    let server = make_mock_server(&after_hash).await;
    let api_url = format!("http://host.docker.internal:{}", server.address().port());
    if skip_if_no_image() {
        return;
    }
    let out = run_container(&global_script(&api_url));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "nuget global apply failed:\nstdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(stderr.contains("===PATCH VERIFIED==="), "stderr=\n{stderr}");
    assert!(stdout.contains("===E2E PASS==="), "stdout=\n{stdout}");
}
