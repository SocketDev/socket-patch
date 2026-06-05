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

/// Compute the git-blob SHA256 of a file the same way the binary does:
/// `SHA256("blob <len>\0" ++ content)`. Emitted as a bash snippet so the
/// container can verify on-disk bytes against an *independently* computed
/// expected hash (passed in from the Rust side via [`git_sha256`]).
const GIT_SHA256_FN: &str = r#"
git_sha256() {
  # $1 = path. Prints the git-blob sha256 of the file's exact bytes.
  local p="$1" size
  size=$(stat -c%s "$p")
  { printf 'blob %s\0' "$size"; cat "$p"; } | sha256sum | awk '{print $1}'
}
"#;

fn local_script(api_url: &str, expected_hash: &str) -> String {
    format!(
        r#"#!/usr/bin/env bash
set -uo pipefail
{git_sha256_fn}
EXPECTED_HASH='{expected_hash}'

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

# Pre-apply guard: the freshly-fetched upstream file must NOT already be
# the patched content. This proves apply does the work rather than the
# fixture (or a previous run) having pre-seeded the marker/bytes.
HASH_BEFORE=$(git_sha256 "$LIB_RS")
echo "hash_before=$HASH_BEFORE expected=$EXPECTED_HASH" >&2
if [ "$HASH_BEFORE" = "$EXPECTED_HASH" ]; then
  echo "FAIL: pristine cfg-if lib.rs already equals patched content (test would be vacuous)" >&2
  exit 1
fi
if grep -q 'SOCKET-PATCH-E2E-MARKER' "$LIB_RS"; then
  echo "FAIL: pristine cfg-if lib.rs already contains the marker before apply" >&2
  exit 1
fi

# Cargo registry source files are read-only by default. Apply's unix
# fix-permissions code makes them writable, but we chmod up-front
# too in case anything else stomps on it.
chmod u+w "$LIB_RS" || true

# scan --sync writes manifest + blob; the cargo crawler with --global
# probes $CARGO_HOME/registry/src/. Note: in this fixture scan's own
# apply pass matches 0 files (the all-zeros beforeHash doesn't match the
# real cfg-if bytes), so scan exits non-zero (partial_failure) BY DESIGN
# — the dedicated `apply --force` step below does the real patching.
# Exit code is logged for diagnostics, not gated; the gate is the exact
# content-hash check at the end.
socket-patch scan --json --sync --yes --global \
  --api-url '{api_url}' --api-token fake --org {ORG} \
  --ecosystems cargo > /tmp/sync.out 2>/tmp/sync.err
SCAN_RC=$?
cat /tmp/sync.err >&2
echo "scan exit=$SCAN_RC" >&2

# scan must have written the manifest the offline apply reads; if it
# didn't, the apply below would be a no-op and the hash check would not
# catch a missing-manifest regression cleanly.
[ -f /workspace/proj/.socket/manifest.json ] || {{ echo "FAIL: scan did not write .socket/manifest.json" >&2; exit 1; }}

socket-patch apply --json --force --offline --global --ecosystems cargo > /tmp/apply.out 2>/tmp/apply.err
APPLY_RC=$?
cat /tmp/apply.err >&2
echo "apply exit=$APPLY_RC" >&2
if [ "$APPLY_RC" -ne 0 ]; then
  echo "FAIL: apply --force --offline exited $APPLY_RC" >&2
  cat /tmp/apply.out >&2
  exit 1
fi

# The apply JSON must report exactly one file applied — not skipped,
# not failed. This catches a regression where apply reports success
# while silently no-op'ing (the failure mode the marker grep alone
# would miss if the file were patched by some other path).
#
# Anchor on the trailing comma (the summary is pretty-printed and
# `applied` is followed by `updated`, so it is never the last field):
# a bare `"applied": 1` substring would also match `"applied": 10`,
# `"applied": 11`, etc. and let a multi-apply regression slip through.
grep -q '"applied": 1,' /tmp/apply.out || {{
  echo "FAIL: apply JSON did not report applied:1" >&2
  cat /tmp/apply.out >&2
  exit 1
}}

# A clean apply must report zero failures/skips and an overall success
# status. Without these, apply could report `applied: 1` while ALSO
# failing or skipping other files and still look green to the grep above.
grep -q '"failed": 0,' /tmp/apply.out || {{
  echo "FAIL: apply JSON did not report failed:0" >&2
  cat /tmp/apply.out >&2
  exit 1
}}
grep -q '"skipped": 0,' /tmp/apply.out || {{
  echo "FAIL: apply JSON did not report skipped:0" >&2
  cat /tmp/apply.out >&2
  exit 1
}}
grep -q '"status": "success"' /tmp/apply.out || {{
  echo "FAIL: apply JSON status was not success" >&2
  cat /tmp/apply.out >&2
  exit 1
}}

# Strong verification: the patched file must be byte-for-byte identical
# to the fixture blob. A substring grep would tolerate corrupt/partial/
# concatenated output that merely happens to contain the marker, so we
# compare the full git-blob hash against the independently-computed
# expected value.
HASH_AFTER=$(git_sha256 "$LIB_RS")
echo "hash_after=$HASH_AFTER expected=$EXPECTED_HASH" >&2
if [ "$HASH_AFTER" != "$EXPECTED_HASH" ]; then
  echo "FAIL: patched $LIB_RS content hash mismatch" >&2
  echo "  expected=$EXPECTED_HASH" >&2
  echo "  actual  =$HASH_AFTER" >&2
  head -5 "$LIB_RS" >&2
  exit 1
fi

# Belt-and-suspenders: the marker must also be literally present (guards
# against an accidentally-matching hash from an empty/zeroed file).
if ! grep -q 'SOCKET-PATCH-E2E-MARKER' "$LIB_RS"; then
  echo "FAIL: marker not in $LIB_RS" >&2
  head -3 "$LIB_RS" >&2
  exit 1
fi

echo "===PATCH VERIFIED===" >&2
echo "===E2E PASS==="
exit 0
"#,
        git_sha256_fn = GIT_SHA256_FN,
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
        &local_script(&api_url, &after_hash),
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

    // The script gates on an exact git-blob-hash match; confirm the
    // expected hash actually appears in the log so a future edit that
    // accidentally drops the hash comparison (reverting to a substring
    // grep) is caught here too.
    assert!(
        stderr.contains(&format!("hash_after={after_hash}")),
        "expected post-apply hash to equal independently-computed fixture hash {after_hash};\nstderr=\n{stderr}"
    );

    // The scan must have actually called the patch API — proves the test
    // exercised the real network/scan path, not a short-circuit. Use
    // `.expect` (not `unwrap_or_default`) so a recording failure surfaces
    // loudly instead of silently degrading to "no requests seen".
    let received = server
        .received_requests()
        .await
        .expect("wiremock should have recorded requests");

    // 1. The batch search POST must have fired AND carried the cargo PURL
    //    in its body. A path-only check would pass even if the cargo
    //    crawler discovered nothing and sent an empty component list, so
    //    we assert the discovered purl actually made it onto the wire.
    let batch = received
        .iter()
        .find(|r| format!("{}", r.method) == "POST" && r.url.path().contains("/patches/batch"))
        .unwrap_or_else(|| panic!("scan should have POSTed /patches/batch; received={received:#?}"));
    let batch_body = String::from_utf8_lossy(&batch.body);
    assert!(
        batch_body.contains(PURL),
        "batch POST body should reference the discovered cargo purl {PURL}; body={batch_body}"
    );

    // 2. The blob-download endpoint (`patches/view/<uuid>`) must have been
    //    hit during scan --sync. The offline apply reads the blob from the
    //    local store rather than the network, so a green offline apply is
    //    only possible if scan really downloaded and persisted the blob via
    //    this endpoint — asserting it pins the full download→offline-apply
    //    chain rather than just the manifest write.
    assert!(
        received
            .iter()
            .any(|r| format!("{}", r.method) == "GET"
                && r.url.path() == format!("/v0/orgs/{ORG}/patches/view/{UUID}")),
        "scan should have downloaded the patch blob via /patches/view/{UUID}; received={received:#?}"
    );
}
