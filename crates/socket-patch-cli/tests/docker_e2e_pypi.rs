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

fn git_sha256(content: &[u8]) -> String {
    let header = format!("blob {}\0", content.len());
    let mut hasher = Sha256::new();
    hasher.update(header.as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
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

fn local_script(api_url: &str) -> String {
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

# 2. scan --sync: writes manifest + downloads blob from wiremock.
socket-patch scan --json --sync --yes \
  --api-url '{api_url}' --api-token fake --org {ORG} \
  --ecosystems pypi 2>/tmp/sync.err
SYNC_RC=$?
echo "sync exit=$SYNC_RC" >&2
cat /tmp/sync.err >&2 || true

# 3. apply --force --offline: overwrites the installed file using the
#    blob cached by scan --sync. --force bypasses the (deliberately
#    mismatched) beforeHash check.
socket-patch apply --json --force --offline --ecosystems pypi 2>/tmp/apply.err
APPLY_RC=$?
echo "apply exit=$APPLY_RC" >&2
cat /tmp/apply.err >&2 || true

# 4. The on-disk file must now contain the marker.
if ! grep -q 'SOCKET-PATCH-E2E-MARKER' "$SIX_PY"; then
  echo "FAIL: marker not in $SIX_PY" >&2
  head -3 "$SIX_PY" >&2
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

# 2. scan --sync --global.
socket-patch scan --json --sync --yes --global \
  --api-url '{api_url}' --api-token fake --org {ORG} \
  --ecosystems pypi 2>/tmp/sync.err
SYNC_RC=$?
echo "sync exit=$SYNC_RC" >&2
cat /tmp/sync.err >&2 || true

# 3. apply --global --force --offline.
socket-patch apply --json --force --offline --global --ecosystems pypi 2>/tmp/apply.err
APPLY_RC=$?
echo "apply exit=$APPLY_RC" >&2
cat /tmp/apply.err >&2 || true

if ! grep -q 'SOCKET-PATCH-E2E-MARKER' "$SIX_PY"; then
  echo "FAIL: marker not in $SIX_PY" >&2
  head -3 "$SIX_PY" >&2
  exit 1
fi

echo "===PATCH VERIFIED===" >&2
echo "===E2E PASS==="
exit 0
"#
    )
}

fn assert_image_present() {
    let out = Command::new("docker")
        .args(["image", "inspect", "socket-patch-test-pypi:latest"])
        .output()
        .expect("docker not on PATH");
    if !out.status.success() {
        panic!(
            "docker image `socket-patch-test-pypi:latest` not found.\n\
             Build it: docker build -f tests/docker/Dockerfile.pypi \
             -t socket-patch-test-pypi:latest ."
        );
    }
}

fn run_container(_api_url: &str, script: &str) -> std::process::Output {
    Command::new("docker")
        .args([
            "run",
            "--rm",
            "--add-host=host.docker.internal:host-gateway",
            "-i",
            "socket-patch-test-pypi:latest",
            "bash",
            "-c",
            script,
        ])
        .output()
        .expect("docker run")
}

#[tokio::test]
async fn pypi_local_install_full_apply_chain() {
    let after_hash = git_sha256(PATCHED_PY);
    let server = make_mock_server(&after_hash).await;
    let api_url = format!("http://host.docker.internal:{}", server.address().port());
    assert_image_present();
    let out = run_container(&api_url, &local_script(&api_url));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "pypi local apply failed:\nstdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(stderr.contains("===PATCH VERIFIED==="), "stderr=\n{stderr}");
    assert!(stdout.contains("===E2E PASS==="), "stdout=\n{stdout}");
}

#[tokio::test]
async fn pypi_global_install_full_apply_chain() {
    let after_hash = git_sha256(PATCHED_PY);
    let server = make_mock_server(&after_hash).await;
    let api_url = format!("http://host.docker.internal:{}", server.address().port());
    assert_image_present();
    let out = run_container(&api_url, &global_script(&api_url));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "pypi global apply failed:\nstdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(stderr.contains("===PATCH VERIFIED==="), "stderr=\n{stderr}");
    assert!(stdout.contains("===E2E PASS==="), "stdout=\n{stdout}");
}
