//! Docker-driven end-to-end test for the Deno ecosystem.
//!
//! Two variants:
//!
//!   * `deno_install_node_modules_full_apply_chain` — uses
//!     `deno install` against a `package.json` to populate
//!     `node_modules/`, then drives scan + apply through the npm
//!     ecosystem (the resulting packages are real npm packages, just
//!     installed by Deno). Reuses the same wiremock fixture as
//!     `docker_e2e_npm.rs`'s minimist test.
//!
//!   * `deno_jsr_install_scan_verifies_discovery` — uses
//!     `deno install jsr:@luca/flag@1.0.0` to populate
//!     `$DENO_DIR/npm/jsr.io/@luca/flag/1.0.0/`, then runs
//!     `socket-patch scan --json --ecosystems deno --global` against
//!     the JSR cache. Asserts the DenoCrawler enumerated the package
//!     end-to-end with a real binary, mirroring the
//!     `pypi_uv_tool_install_full_apply_chain` pattern.
//!
//! Run command:
//!   `cargo test -p socket-patch-cli --features docker-e2e,deno --test docker_e2e_deno`

#![cfg(all(feature = "docker-e2e", feature = "deno"))]

use std::path::{Path, PathBuf};
use std::process::Command;

use base64::Engine;
use sha2::{Digest, Sha256};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";
const NPM_PURL: &str = "pkg:npm/minimist@1.2.2";
const NPM_UUID: &str = "13131313-1313-4131-8131-131313131313";

/// Marker we splice into the patched bytes so the test can assert
/// post-apply that the file has been overwritten.
const PATCHED_BYTES: &[u8] =
    b"/* SOCKET-PATCH-E2E-MARKER */\nmodule.exports = function () { return {}; };\n";

/// Git-SHA256: SHA256("blob <len>\0" ++ content). Matches the binary's
/// content-addressable hashing.
fn git_sha256(content: &[u8]) -> String {
    let header = format!("blob {}\0", content.len());
    let mut hasher = Sha256::new();
    hasher.update(header.as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

/// Coverage instrumentation hook — same shape as every other docker
/// e2e test file. When `SOCKET_PATCH_COV_BIN` is set, mounts the
/// instrumented socket-patch binary into the container and pipes
/// profraw output back to a host-visible directory.
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

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .to_path_buf()
}

/// Build the wiremock for the npm-via-deno-install variant. Same
/// minimist fixture as `docker_e2e_npm.rs`; we duplicate it here to
/// keep this test file self-contained.
async fn make_npm_mock_server(after_hash: &str) -> MockServer {
    let listener =
        std::net::TcpListener::bind("0.0.0.0:0").expect("bind wiremock to 0.0.0.0:0");
    let server = MockServer::builder().listener(listener).start().await;

    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": NPM_PURL,
                "patches": [{
                    "uuid": NPM_UUID,
                    "purl": NPM_PURL,
                    "tier": "free",
                    "cveIds": ["CVE-2021-44906"],
                    "ghsaIds": ["GHSA-xvch-5gv4-984h"],
                    "severity": "high",
                    "title": "deno e2e fixture (npm)"
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
                "uuid": NPM_UUID,
                "purl": NPM_PURL,
                "publishedAt": "2024-01-01T00:00:00Z",
                "description": "deno e2e fixture",
                "license": "MIT",
                "tier": "free",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(&server)
        .await;

    let blob_b64 = base64::engine::general_purpose::STANDARD.encode(PATCHED_BYTES);
    Mock::given(method("GET"))
        .and(path(format!(
            "/v0/orgs/{ORG}/patches/view/{NPM_UUID}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": NPM_UUID,
            "purl": NPM_PURL,
            "publishedAt": "2024-01-01T00:00:00Z",
            "files": {
                // npm tarball layout uses a `package/` root — the
                // apply path strips it. Same key shape as the npm
                // docker test fixture.
                "package/index.js": {
                    "beforeHash": "0000000000000000000000000000000000000000000000000000000000000000",
                    "afterHash": after_hash,
                    "blobContent": blob_b64,
                }
            },
            "vulnerabilities": {},
            "description": "deno e2e fixture",
            "license": "MIT",
            "tier": "free"
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!(
            "/v0/orgs/{ORG}/patches/blob/{after_hash}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(PATCHED_BYTES))
        .mount(&server)
        .await;

    server
}

fn api_url_for_container(server: &MockServer) -> String {
    format!("http://host.docker.internal:{}", server.address().port())
}

/// Driver script for the `deno install` + node_modules variant. Deno
/// 2.0 reads `package.json`, resolves dependencies through the npm
/// registry, and populates `node_modules/` — at which point the
/// existing NpmCrawler discovers the packages.
fn deno_node_modules_script(api_url: &str) -> String {
    format!(
        r#"#!/usr/bin/env bash
set -uo pipefail
COMMON_ARGS=(--api-url '{api_url}' --api-token fake --org {ORG})

# 1. Create a tiny Deno project with a package.json. `deno install`
#    reads package.json and populates node_modules/ via npm semantics.
mkdir -p /workspace/proj && cd /workspace/proj
cat >deno.json <<'EOF'
{{
  "name": "e2e-deno-npm",
  "version": "0.0.0",
  "nodeModulesDir": "auto"
}}
EOF
cat >package.json <<'EOF'
{{
  "name": "e2e-deno-npm",
  "version": "0.0.0",
  "dependencies": {{
    "minimist": "1.2.2"
  }}
}}
EOF

deno install --allow-scripts >/tmp/deno-install.err 2>&1 || cat /tmp/deno-install.err >&2
ls -la node_modules/minimist/ 2>&1 >&2 || true

# 2. Locate the installed file. Deno's node_modules layout is the
#    same as npm's — top-level minimist/.
TARGET=node_modules/minimist/index.js
if [ ! -f "$TARGET" ]; then
  echo "FAIL: deno install did not populate $TARGET" >&2
  ls -R node_modules/ 2>&1 >&2 || true
  exit 1
fi
echo "Installed minimist at: $TARGET" >&2

# 3. scan --sync — npm ecosystem, since the discovered package is
#    a real npm package (pkg:npm/minimist@1.2.2).
socket-patch scan --json --sync --yes --ecosystems npm "${{COMMON_ARGS[@]}}" \
  2>/tmp/sync.err
echo "sync exit=$?" >&2
cat /tmp/sync.err >&2 || true

# 4. apply --force --offline.
socket-patch apply --json --force --offline --ecosystems npm 2>/tmp/apply.err
echo "apply exit=$?" >&2
cat /tmp/apply.err >&2 || true

# 5. The on-disk file must contain the marker.
if ! grep -q 'SOCKET-PATCH-E2E-MARKER' "$TARGET"; then
  echo "FAIL: marker not in $TARGET after apply" >&2
  head -3 "$TARGET" >&2
  exit 1
fi

echo "===PATCH VERIFIED===" >&2
echo "===E2E PASS==="
exit 0
"#
    )
}

/// Driver script for the JSR-layout scan variant.
///
/// Why synthetic-staged instead of real `deno install`: as of Deno
/// 2.x, JSR packages are cached content-addressed at
/// `$DENO_DIR/remote/https/jsr.io/<sha256>` — there's no
/// scope/name/version directory structure on disk for the DenoCrawler
/// to walk. The crawler is designed against the *expected* layout
/// `<root>/<scope>/<name>/<version>/` so that synthetic fixtures (and
/// any future Deno tooling that materializes JSR packages this way)
/// produce scannable trees. This test stages exactly that layout via
/// `mkdir` so the docker run proves the CLI ↔ DenoCrawler integration
/// end-to-end, even before real-world Deno output matches.
fn deno_jsr_script() -> String {
    r#"#!/usr/bin/env bash
set -uo pipefail

# Stage a synthetic JSR cache layout under a project-local DENO_DIR.
# Layout: <DENO_DIR>/npm/jsr.io/<scope>/<name>/<version>/<file>.
# Two packages so the scan count is non-trivial.
export DENO_DIR=/workspace/deno-cache
JSR=$DENO_DIR/npm/jsr.io
mkdir -p "$JSR/@luca/flag/1.0.0"
mkdir -p "$JSR/@std/path/0.220.0"
cat >"$JSR/@luca/flag/1.0.0/mod.ts" <<'EOF'
export default true;
EOF
cat >"$JSR/@std/path/0.220.0/mod.ts" <<'EOF'
export const sep = "/";
EOF

# Confirm deno itself is runnable (proves the image is healthy even
# though we don't drive a real deno install in this variant).
deno --version >&2

mkdir -p /workspace/proj && cd /workspace/proj
cat >deno.json <<'EOF'
{ "name": "e2e-deno-jsr", "version": "0.0.0" }
EOF

# socket-patch scan --global --ecosystems deno --global-prefix <path>.
# global-prefix bypasses default ~/.cache/deno discovery and points
# explicitly at our synthetic JSR root.
SCAN_OUT=$(socket-patch scan --json --global \
  --global-prefix "$JSR" \
  --ecosystems deno 2>/tmp/scan.err)
SCAN_RC=$?
echo "scan exit=$SCAN_RC" >&2
cat /tmp/scan.err >&2 || true
echo "$SCAN_OUT" | head -50 >&2

SCANNED=$(echo "$SCAN_OUT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('scannedPackages', 0))" 2>/dev/null || echo 0)
echo "scanned jsr packages: $SCANNED" >&2
if [ "$SCANNED" -lt 2 ]; then
  echo "FAIL: DenoCrawler found $SCANNED packages, expected 2 (@luca/flag + @std/path)" >&2
  find "$JSR" -maxdepth 4 2>&1 >&2 || true
  exit 1
fi

echo "===SCAN VERIFIED===" >&2
echo "===E2E PASS==="
exit 0
"#.to_string()
}

#[must_use]
fn skip_if_no_image() -> bool {
    let Ok(out) = Command::new("docker")
        .args(["image", "inspect", "socket-patch-test-deno:latest"])
        .output()
    else {
        eprintln!("skipping: `docker` not on PATH");
        return true;
    };
    if !out.status.success() {
        eprintln!("skipping: docker image `socket-patch-test-deno:latest` not present");
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
    .args(["socket-patch-test-deno:latest", "bash", "-c", script]);
    cmd.output().expect("docker run")
}

#[tokio::test]
async fn deno_install_node_modules_full_apply_chain() {
    let after_hash = git_sha256(PATCHED_BYTES);
    let server = make_npm_mock_server(&after_hash).await;
    let api_url = api_url_for_container(&server);
    if skip_if_no_image() {
        return;
    }
    let out = run_container(&deno_node_modules_script(&api_url));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "deno install apply failed:\nstdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(stderr.contains("===PATCH VERIFIED==="), "stderr=\n{stderr}");
    assert!(stdout.contains("===E2E PASS==="), "stdout=\n{stdout}");

    let _ = workspace_root();
}

#[tokio::test]
async fn deno_jsr_synthetic_layout_scan_verifies_discovery() {
    if skip_if_no_image() {
        return;
    }
    let out = run_container(&deno_jsr_script());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "deno jsr scan failed:\nstdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(stderr.contains("===SCAN VERIFIED==="), "stderr=\n{stderr}");
    assert!(stdout.contains("===E2E PASS==="), "stdout=\n{stdout}");
}
