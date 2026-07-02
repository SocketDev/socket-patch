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
/// The vulnerability the staged manifest carries so the agent-mode VEX leg
/// has something to attest (plain agent provenance — no vendored/redirected
/// marker — is what the host oracle asserts).
const GHSA: &str = "GHSA-agent-golang-real";

const PATCHED_GO: &[u8] = b"// SOCKET-PATCH-E2E-MARKER\n\
                            // gin.go replaced by socket-patch e2e fixture\n\
                            package gin\n\nconst Version = \"v1.9.1-patched\"\n";

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
                    "severity": "high", "title": "golang e2e fixture"
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
            // Recorded into the manifest so the agent-mode VEX leg attests it.
            "vulnerabilities": {
                (GHSA): {
                    "cves": ["CVE-2024-30002"],
                    "summary": "golang agent e2e fixture vulnerability",
                    "severity": "high",
                    "description": "Agent-mode VEX leg fixture vulnerability"
                }
            },
            "description": "golang e2e fixture",
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

mkdir -p /workspace/proj && cd /workspace/proj
go mod init e2e-test > /dev/null 2>&1
go mod download github.com/gin-gonic/gin@v1.9.1 > /tmp/download.log 2>&1 || {{
  cat /tmp/download.log >&2; exit 1
}}

GIN_GO="$GOMODCACHE/github.com/gin-gonic/gin@v1.9.1/gin.go"
[ -f "$GIN_GO" ] || {{ echo "FAIL: $GIN_GO missing" >&2; ls "$GOMODCACHE/github.com/gin-gonic/" >&2 || true; exit 1; }}
echo "Downloaded to: $GIN_GO" >&2

# Pre-apply guard: the freshly-downloaded upstream file must NOT already
# be the patched content. This proves apply does the work rather than the
# fixture (or a previous run) having pre-seeded the marker/bytes.
HASH_BEFORE=$(git_sha256 "$GIN_GO")
echo "hash_before=$HASH_BEFORE expected=$EXPECTED_HASH" >&2
if [ "$HASH_BEFORE" = "$EXPECTED_HASH" ]; then
  echo "FAIL: pristine gin.go already equals patched content (test would be vacuous)" >&2
  exit 1
fi
if grep -q 'SOCKET-PATCH-E2E-MARKER' "$GIN_GO"; then
  echo "FAIL: pristine gin.go already contains the marker before apply" >&2
  exit 1
fi

# Module cache files are read-only by default; apply's chmod logic
# handles it but we pre-chmod for robustness.
chmod u+w "$GIN_GO" || true

# Pre-seed setup.manual so the agent-mode VEX leg keeps the golang patch
# through property 7 (golang has no auto-install setup hook; agent patches are
# applied by hand/CI — exactly what `manual` declares). scan --sync merges the
# downloaded patch into this manifest and preserves the setup block.
mkdir -p .socket
cat > .socket/manifest.json <<'MANIFEST'
{{ "patches": {{}}, "setup": {{ "manual": ["golang"] }} }}
MANIFEST

# scan --sync writes manifest + blob; the go crawler with --global probes
# $GOMODCACHE. Note: in this fixture scan's own apply pass matches 0 files
# (the all-zeros beforeHash doesn't match the real gin.go bytes), so scan
# exits non-zero (partial_failure) BY DESIGN — the dedicated `apply
# --force` step below does the real patching. Exit code is logged for
# diagnostics, not gated; the gate is the exact content-hash check below.
socket-patch scan --json --sync --strict --yes --global \
  --api-url '{api_url}' --api-token fake --org {ORG} \
  --ecosystems golang > /tmp/sync.out 2>/tmp/sync.err
SCAN_RC=$?
cat /tmp/sync.err >&2
echo "scan exit=$SCAN_RC" >&2

# scan must have written the manifest the offline apply reads; if it
# didn't, the apply below would be a no-op and the hash check would not
# catch a missing-manifest regression cleanly.
[ -f /workspace/proj/.socket/manifest.json ] || {{ echo "FAIL: scan did not write .socket/manifest.json" >&2; exit 1; }}

socket-patch apply --json --force --offline --global --ecosystems golang > /tmp/apply.out 2>/tmp/apply.err
APPLY_RC=$?
cat /tmp/apply.err >&2
echo "apply exit=$APPLY_RC" >&2
if [ "$APPLY_RC" -ne 0 ]; then
  echo "FAIL: apply --force --offline exited $APPLY_RC" >&2
  cat /tmp/apply.out >&2
  exit 1
fi

# The apply JSON must report exactly one file applied — not skipped, not
# failed. This catches a regression where apply reports success while
# silently no-op'ing (the failure mode the marker grep alone would miss
# if the file were patched by some other path).
#
# Use anchored regexes against the pretty-printed envelope (serde
# to_string_pretty → `  "applied": 1,`). A bare `"applied": 1` substring
# would also match `"applied": 10`/`100`, so require the trailing comma.
# We additionally pin the top-level status and the *other* summary counts:
# a regression that patches our file but corrupts/fails a second one would
# report applied:1 alongside failed:1, and the old check would miss it.
grep -qE '^[[:space:]]*"applied": 1,[[:space:]]*$' /tmp/apply.out || {{
  echo "FAIL: apply JSON did not report exactly applied:1" >&2
  cat /tmp/apply.out >&2
  exit 1
}}
grep -qE '^[[:space:]]*"failed": 0,[[:space:]]*$' /tmp/apply.out || {{
  echo "FAIL: apply JSON reported a non-zero failed count" >&2
  cat /tmp/apply.out >&2
  exit 1
}}
# The --force overwrite of the mismatched baseline surfaces the
# content_mismatch_overwritten warning as a Skipped event (the
# mismatch-warn contract) — exactly that one, nothing else skipped.
grep -qE '^[[:space:]]*"skipped": 1,[[:space:]]*$' /tmp/apply.out || {{
  echo "FAIL: apply JSON did not report skipped:1 (the mismatch-overwrite warning)" >&2
  cat /tmp/apply.out >&2
  exit 1
}}
grep -q '"errorCode": "content_mismatch_overwritten"' /tmp/apply.out || {{
  echo "FAIL: apply JSON missing the content_mismatch_overwritten warning event" >&2
  cat /tmp/apply.out >&2
  exit 1
}}
grep -qE '"status": "success"' /tmp/apply.out || {{
  echo "FAIL: apply JSON status was not success" >&2
  cat /tmp/apply.out >&2
  exit 1
}}

# Strong verification: the patched file must be byte-for-byte identical to
# the fixture blob. A substring grep would tolerate corrupt/partial/
# concatenated output that merely happens to contain the marker, so we
# compare the full git-blob hash against the independently-computed
# expected value.
HASH_AFTER=$(git_sha256 "$GIN_GO")
echo "hash_after=$HASH_AFTER expected=$EXPECTED_HASH" >&2
if [ "$HASH_AFTER" != "$EXPECTED_HASH" ]; then
  echo "FAIL: patched $GIN_GO content hash mismatch" >&2
  echo "  expected=$EXPECTED_HASH" >&2
  echo "  actual  =$HASH_AFTER" >&2
  head -5 "$GIN_GO" >&2
  exit 1
fi

# Belt-and-suspenders: the marker must also be literally present (guards
# against an accidentally-matching hash from an empty/zeroed file).
if ! grep -q 'SOCKET-PATCH-E2E-MARKER' "$GIN_GO"; then
  echo "FAIL: marker not in $GIN_GO" >&2
  head -3 "$GIN_GO" >&2
  exit 1
fi

echo "===PATCH VERIFIED===" >&2

# Agent-mode VEX leg. The manifest scan --sync wrote carries {GHSA} (served in
# the patch view); vex verifies the patched gin.go on disk and attests it with
# PLAIN agent provenance. --global/--ecosystems golang mirror the apply (the go
# crawler probes $GOMODCACHE); --offline keeps vex local. The doc is emitted
# between markers for the host-side oracle (no bind mount here).
echo "===VEX OUTPUT===" >&2
socket-patch vex --offline --cwd "$PWD" --output /tmp/out.vex.json \
  --product 'pkg:golang/e2e-app@1.0.0' --global --ecosystems golang >/tmp/vex.out 2>/tmp/vex.err
VEX_RC=$?
echo "vex exit=$VEX_RC" >&2
cat /tmp/vex.err >&2 || true
if [ "$VEX_RC" -ne 0 ]; then
  echo "FAIL: vex exited $VEX_RC (expected 0)" >&2
  cat /tmp/vex.out >&2
  exit 1
fi
[ -s /tmp/out.vex.json ] || {{ echo "FAIL: vex did not write out.vex.json" >&2; exit 1; }}
echo "===VEX VERIFIED===" >&2
echo "===VEX DOC BEGIN==="
cat /tmp/out.vex.json
echo ""
echo "===VEX DOC END==="

echo "===E2E PASS==="
exit 0
"#,
        git_sha256_fn = GIT_SHA256_FN,
    )
}

/// Host-side oracle over the VEX document the container emitted between the
/// `===VEX DOC BEGIN===` / `===VEX DOC END===` markers (these agent suites run
/// the workspace inside the container with no bind mount, so the doc is parsed
/// from captured stdout). Asserts exactly one statement attesting the agent
/// patch: the fixture GHSA, `not_affected`, the installed-package subcomponent
/// purl, and a PLAIN impact statement with NO `(vendored)`/`(redirected)`
/// marker — the marker's absence is what distinguishes agent provenance.
fn assert_vex_agent_attested(stdout: &str, subcomponent_purl: &str) {
    const BEGIN: &str = "===VEX DOC BEGIN===";
    const END: &str = "===VEX DOC END===";
    let start = stdout
        .find(BEGIN)
        .unwrap_or_else(|| panic!("VEX DOC BEGIN marker missing from stdout:\n{stdout}"))
        + BEGIN.len();
    let stop = stdout[start..]
        .find(END)
        .unwrap_or_else(|| panic!("VEX DOC END marker missing from stdout:\n{stdout}"))
        + start;
    let doc: serde_json::Value = serde_json::from_str(stdout[start..stop].trim())
        .expect("emitted VEX document must be valid JSON");
    let stmts = doc["statements"]
        .as_array()
        .expect("VEX document must have a statements array");
    assert_eq!(stmts.len(), 1, "exactly one VEX statement expected: {doc}");
    let st = &stmts[0];
    assert_eq!(st["vulnerability"]["name"], GHSA, "attested GHSA mismatch");
    assert_eq!(st["status"], "not_affected");
    assert_eq!(
        st["products"][0]["subcomponents"][0]["@id"], subcomponent_purl,
        "subcomponent must be the patched package purl"
    );
    let impact = st["impact_statement"]
        .as_str()
        .expect("statement must carry an impact_statement");
    assert!(
        impact.contains("Patched via Socket patch")
            && !impact.contains("(vendored)")
            && !impact.contains("(redirected)"),
        "agent-mode attestation must carry a PLAIN impact statement (no vendored/redirected marker): {impact}"
    );
}

/// Returns `true` when the test should skip (docker missing, image
/// missing). Prints a skip notice to stderr — the test still reports
/// as `ok` because Rust integration tests have no native "skipped"
/// outcome. Build locally with
/// `docker build -f tests/docker/Dockerfile.golang -t socket-patch-test-golang:latest .`
#[must_use]
fn skip_if_no_image() -> bool {
    let Ok(out) = Command::new("docker")
        .args(["image", "inspect", "socket-patch-test-golang:latest"])
        .output()
    else {
        eprintln!("skipping: `docker` not on PATH");
        return true;
    };
    if !out.status.success() {
        eprintln!("skipping: docker image `socket-patch-test-golang:latest` not present");
        return true;
    }
    false
}

#[tokio::test]
async fn golang_download_full_apply_chain() {
    let after_hash = git_sha256(PATCHED_GO);
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
        "socket-patch-test-golang:latest",
        "bash",
        "-c",
        &local_script(&api_url, &after_hash),
    ]);
    let out = cmd.output().expect("docker run");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "golang apply failed:\nstdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(stderr.contains("===PATCH VERIFIED==="), "stderr=\n{stderr}");
    assert!(stdout.contains("===E2E PASS==="), "stdout=\n{stdout}");

    // Agent-mode VEX leg: the manifest patch was attested with plain
    // (non-vendored, non-redirected) provenance against the patched gin.go.
    assert!(
        stderr.contains("===VEX VERIFIED==="),
        "agent-mode VEX leg did not run/pass (===VEX VERIFIED=== missing).\nstderr=\n{stderr}"
    );
    assert_vex_agent_attested(&stdout, PURL);

    // The script gates on an exact git-blob-hash match; confirm the
    // expected hash actually appears in the log so a future edit that
    // accidentally drops the hash comparison (reverting to a substring
    // grep) is caught here too.
    assert!(
        stderr.contains(&format!("hash_after={after_hash}")),
        "expected post-apply hash to equal independently-computed fixture hash {after_hash};\nstderr=\n{stderr}"
    );

    // The scan must have actually called the patch API — proves the test
    // exercised the real network/scan path, not a short-circuit.
    let received = server
        .received_requests()
        .await
        .expect("wiremock should record requests");
    assert!(
        !received.is_empty(),
        "scan should have made at least one API request; received nothing"
    );

    // The batch call alone isn't enough: an empty/broken go crawler would
    // still POST /patches/batch with an empty component list and the old
    // `.any(path contains batch)` check would stay green. Require that the
    // batch request *body* carried the gin PURL — i.e. the golang crawler
    // actually discovered the package in $GOMODCACHE (the real code path
    // this test is named after). The body is
    // `{"components":[{"purl":"pkg:golang/.../gin@v1.9.1"}]}`.
    let batch_with_purl = received.iter().any(|r| {
        r.url.path().contains("/patches/batch") && String::from_utf8_lossy(&r.body).contains(PURL)
    });
    assert!(
        batch_with_purl,
        "scan should have POSTed /patches/batch containing {PURL} \
         (proves the go crawler discovered the package); received={received:#?}"
    );

    // scan --sync must download the patch blob so the offline apply can use
    // it. The blob is served from /patches/view/{UUID}; if scan skipped it,
    // apply --offline would have had no bytes and the hash check would be
    // testing a pre-seeded file instead of a freshly-fetched one.
    let fetched_blob = received
        .iter()
        .any(|r| r.url.path().contains(&format!("/patches/view/{UUID}")));
    assert!(
        fetched_blob,
        "scan --sync should have fetched the patch blob via /patches/view/{UUID}; \
         received={received:#?}"
    );
}
