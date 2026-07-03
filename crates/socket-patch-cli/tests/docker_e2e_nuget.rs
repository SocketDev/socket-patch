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
/// The vulnerability the staged manifest carries so the agent-mode VEX leg
/// has something to attest (plain agent provenance — no vendored/redirected
/// marker — is what the host oracle asserts).
const GHSA: &str = "GHSA-agent-nuget-real";

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

/// Plain SHA-256 of the bytes (what `sha256sum` in the container
/// reports). Used to verify the patched file's EXACT contents, not just
/// that it contains the marker substring.
fn plain_sha256(content: &[u8]) -> String {
    let mut hasher = Sha256::new();
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
                    "severity": "medium", "title": "nuget e2e fixture"
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
            // Recorded into the manifest so the agent-mode VEX leg attests it.
            "vulnerabilities": {
                (GHSA): {
                    "cves": ["CVE-2024-30006"],
                    "summary": "nuget agent e2e fixture vulnerability",
                    "severity": "medium",
                    "description": "Agent-mode VEX leg fixture vulnerability"
                }
            },
            "description": "nuget e2e fixture",
            "license": "MIT",
            "tier": "free",
        })))
        .mount(&server)
        .await;

    server
}

fn local_script(api_url: &str, expected_sha: &str) -> String {
    format!(
        r#"#!/usr/bin/env bash
# No `set -e`: we capture every stage's exit code and gate on it
# explicitly so a crashing/no-op scan or apply fails loud instead of
# being masked by the final marker grep.
set -uo pipefail
COMMON_ARGS=(--api-url '{api_url}' --api-token fake --org {ORG} --ecosystems nuget)

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

# Pre-seed setup.manual so the agent-mode VEX leg keeps the nuget patch through
# property 7 (nuget has no auto-install setup hook; agent patches are applied
# by hand/CI — exactly what `manual` declares). scan --sync merges the
# downloaded patch into this manifest and preserves the setup block.
mkdir -p .socket
cat > .socket/manifest.json <<'MANIFEST'
{{ "patches": {{}}, "setup": {{ "manual": ["nuget"] }} }}
MANIFEST

# The unpatched LICENSE must NOT already contain our synthetic marker —
# otherwise the post-apply grep would be vacuously true.
if grep -q 'SOCKET-PATCH-E2E-MARKER' "$LICENSE_FILE"; then
  echo "FAIL: pristine LICENSE.md already contains the marker (fixture broken)" >&2
  exit 1
fi

# 1. Discovery scan (no --sync): a clean exit alone proves nothing (a
#    no-op scan also exits 0), so gate on exit==0 AND the installed PURL
#    AND the available patch UUID actually appearing in the JSON.
socket-patch scan --json "${{COMMON_ARGS[@]}}" >/tmp/scan.out 2>/tmp/scan.err
SCAN_RC=$?
echo "scan exit=$SCAN_RC" >&2
cat /tmp/scan.err >&2 || true
if [ "$SCAN_RC" -ne 0 ]; then
  echo "FAIL: scan exited $SCAN_RC (expected 0)" >&2
  cat /tmp/scan.out >&2
  exit 1
fi
if ! grep -q '{PURL}' /tmp/scan.out; then
  echo "FAIL: scan --json did not report the installed PURL {PURL}" >&2
  cat /tmp/scan.out >&2
  exit 1
fi
if ! grep -q '{UUID}' /tmp/scan.out; then
  echo "FAIL: scan --json did not report available patch UUID {UUID}" >&2
  cat /tmp/scan.out >&2
  exit 1
fi
echo "===SCAN VERIFIED===" >&2

# 2. scan --sync writes the manifest and downloads the patch blob. It
#    may exit non-zero here: the un-forced sync-apply hits a HashMismatch
#    because the fixture's placeholder beforeHash doesn't match the real
#    installed bytes. That's expected — the separate forced apply below
#    is what actually writes the patch, so we only log sync's exit code.
socket-patch scan --json --sync --strict --yes "${{COMMON_ARGS[@]}}" >/tmp/sync.out 2>/tmp/sync.err
echo "sync exit=$?" >&2
cat /tmp/sync.out >&2 || true
cat /tmp/sync.err >&2 || true

# 2b. sync must NOT have written the patch to the package file (its
#     un-forced apply hits a HashMismatch). If it had, the marker on disk
#     would be attributable to sync rather than the forced apply below,
#     and a totally no-op `apply` would pass the marker grep vacuously.
#     Pinning the file pristine here makes step 3's `apply` the sole
#     writer, so a broken apply can't ride on sync's coattails.
if grep -q 'SOCKET-PATCH-E2E-MARKER' "$LICENSE_FILE"; then
  echo "FAIL: scan --sync already wrote the marker; apply is no longer the verified writer" >&2
  exit 1
fi

# 3. apply must report success (exit 0) — not merely leave a marker
#    behind while reporting partial failure.
socket-patch apply --json --force --offline --ecosystems nuget >/tmp/apply.out 2>/tmp/apply.err
APPLY_RC=$?
echo "apply exit=$APPLY_RC" >&2
cat /tmp/apply.out >&2 || true
cat /tmp/apply.err >&2 || true
if [ "$APPLY_RC" -ne 0 ]; then
  echo "FAIL: apply exited $APPLY_RC (expected 0 on a forced apply)" >&2
  exit 1
fi

# 3b. exit 0 alone does not prove anything was applied: a no-op apply
#     (applied:0) also exits 0. The apply JSON must report exactly one
#     file applied, zero skipped, zero failed, status success. The
#     trailing comma anchors `"applied": 1` so it can't match `10`/`11`.
grep -q '"applied": 1,' /tmp/apply.out || {{
  echo "FAIL: apply JSON did not report applied:1 (no-op apply?)" >&2
  cat /tmp/apply.out >&2
  exit 1
}}
grep -q '"failed": 0,' /tmp/apply.out || {{
  echo "FAIL: apply JSON did not report failed:0" >&2
  cat /tmp/apply.out >&2
  exit 1
}}
# The --force overwrite of the mismatched baseline surfaces the
# content_mismatch_overwritten warning as a Skipped event (the
# mismatch-warn contract) — exactly that one, nothing else skipped.
grep -q '"skipped": 1,' /tmp/apply.out || {{
  echo "FAIL: apply JSON did not report skipped:1 (the mismatch-overwrite warning)" >&2
  cat /tmp/apply.out >&2
  exit 1
}}
grep -q '"errorCode": "content_mismatch_overwritten"' /tmp/apply.out || {{
  echo "FAIL: apply JSON missing the content_mismatch_overwritten warning event" >&2
  cat /tmp/apply.out >&2
  exit 1
}}
grep -q '"status": "success"' /tmp/apply.out || {{
  echo "FAIL: apply JSON status was not success" >&2
  cat /tmp/apply.out >&2
  exit 1
}}

# 4. The on-disk file must EXACTLY equal the served blob — not merely
#    contain the marker substring (which a partial/corrupt write could).
if ! grep -q 'SOCKET-PATCH-E2E-MARKER' "$LICENSE_FILE"; then
  echo "FAIL: marker not in $LICENSE_FILE" >&2
  head -3 "$LICENSE_FILE" >&2
  exit 1
fi
ACTUAL_SHA=$(sha256sum "$LICENSE_FILE" | cut -d' ' -f1)
if [ "$ACTUAL_SHA" != "{expected_sha}" ]; then
  echo "FAIL: patched LICENSE.md bytes differ from served blob" >&2
  echo "  expected={expected_sha}" >&2
  echo "  actual  =$ACTUAL_SHA" >&2
  exit 1
fi

echo "===PATCH VERIFIED===" >&2

# Agent-mode VEX leg. The manifest scan --sync wrote carries {GHSA} (served in
# the patch view); vex verifies the patched LICENSE.md in the NUGET_PACKAGES
# tree and attests it with PLAIN agent provenance. --ecosystems nuget (no
# --global, matching the local apply; the crawler honors NUGET_PACKAGES exported
# above and is gated by SOCKET_EXPERIMENTAL_NUGET=1 from the docker run env);
# --offline keeps vex local. The doc is emitted between markers for the host
# oracle (no bind mount here).
echo "===VEX OUTPUT===" >&2
socket-patch vex --offline --cwd "$PWD" --output /tmp/out.vex.json \
  --product 'pkg:nuget/e2e-app@1.0.0' --ecosystems nuget >/tmp/vex.out 2>/tmp/vex.err
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
"#
    )
}

fn global_script(api_url: &str, expected_sha: &str) -> String {
    format!(
        r#"#!/usr/bin/env bash
# No `set -e`: exit codes are gated explicitly (see local_script).
set -uo pipefail
COMMON_ARGS=(--api-url '{api_url}' --api-token fake --org {ORG} --global --ecosystems nuget)

# Default `dotnet add package` populates ~/.nuget/packages.
mkdir -p /workspace/proj && cd /workspace/proj
dotnet new console --force --output . > /dev/null 2>&1
dotnet add package Newtonsoft.Json --version 13.0.3 > /tmp/install.log 2>&1 || {{
  cat /tmp/install.log >&2; exit 1
}}

LICENSE_FILE="$HOME/.nuget/packages/newtonsoft.json/13.0.3/LICENSE.md"
[ -f "$LICENSE_FILE" ] || {{ echo "FAIL: $LICENSE_FILE missing" >&2; ls "$HOME/.nuget/packages/newtonsoft.json/13.0.3/" >&2 || true; exit 1; }}
echo "Global-installed at: $LICENSE_FILE" >&2

# Pristine LICENSE must not already carry the marker.
if grep -q 'SOCKET-PATCH-E2E-MARKER' "$LICENSE_FILE"; then
  echo "FAIL: pristine LICENSE.md already contains the marker (fixture broken)" >&2
  exit 1
fi

# Empty cwd — --global tells socket-patch to scan the global cache,
# ignoring cwd-relative discovery.
mkdir -p /workspace/empty && cd /workspace/empty

# 1. Discovery scan: gate exit==0 and PURL + UUID present in JSON.
socket-patch scan --json "${{COMMON_ARGS[@]}}" >/tmp/scan.out 2>/tmp/scan.err
SCAN_RC=$?
echo "scan exit=$SCAN_RC" >&2
cat /tmp/scan.err >&2 || true
if [ "$SCAN_RC" -ne 0 ]; then
  echo "FAIL: scan exited $SCAN_RC (expected 0)" >&2
  cat /tmp/scan.out >&2
  exit 1
fi
if ! grep -q '{PURL}' /tmp/scan.out; then
  echo "FAIL: scan --json --global did not report the installed PURL {PURL}" >&2
  cat /tmp/scan.out >&2
  exit 1
fi
if ! grep -q '{UUID}' /tmp/scan.out; then
  echo "FAIL: scan --json --global did not report available patch UUID {UUID}" >&2
  cat /tmp/scan.out >&2
  exit 1
fi
echo "===SCAN VERIFIED===" >&2

# 2. scan --sync. May exit non-zero (un-forced sync-apply HashMismatch
#    against the fixture's placeholder beforeHash); the forced apply
#    below is what writes the patch, so only log sync's exit code.
socket-patch scan --json --sync --strict --yes "${{COMMON_ARGS[@]}}" >/tmp/sync.out 2>/tmp/sync.err
echo "sync exit=$?" >&2
cat /tmp/sync.out >&2 || true
cat /tmp/sync.err >&2 || true

# 2b. sync must NOT have written the patch (HashMismatch on un-forced
#     apply). Pinning the file pristine here makes step 3's forced apply
#     the sole writer, so a no-op apply can't pass on sync's coattails.
if grep -q 'SOCKET-PATCH-E2E-MARKER' "$LICENSE_FILE"; then
  echo "FAIL: scan --sync already wrote the marker; apply is no longer the verified writer" >&2
  exit 1
fi

# 3. apply must exit 0.
socket-patch apply --json --force --offline --global --ecosystems nuget >/tmp/apply.out 2>/tmp/apply.err
APPLY_RC=$?
echo "apply exit=$APPLY_RC" >&2
cat /tmp/apply.out >&2 || true
cat /tmp/apply.err >&2 || true
if [ "$APPLY_RC" -ne 0 ]; then
  echo "FAIL: apply exited $APPLY_RC (expected 0 on a forced apply)" >&2
  exit 1
fi

# 3b. exit 0 does not prove a write happened. The apply JSON must report
#     exactly one file applied, zero skipped, zero failed, status success.
grep -q '"applied": 1,' /tmp/apply.out || {{
  echo "FAIL: apply JSON did not report applied:1 (no-op apply?)" >&2
  cat /tmp/apply.out >&2
  exit 1
}}
grep -q '"failed": 0,' /tmp/apply.out || {{
  echo "FAIL: apply JSON did not report failed:0" >&2
  cat /tmp/apply.out >&2
  exit 1
}}
# The --force overwrite of the mismatched baseline surfaces the
# content_mismatch_overwritten warning as a Skipped event (the
# mismatch-warn contract) — exactly that one, nothing else skipped.
grep -q '"skipped": 1,' /tmp/apply.out || {{
  echo "FAIL: apply JSON did not report skipped:1 (the mismatch-overwrite warning)" >&2
  cat /tmp/apply.out >&2
  exit 1
}}
grep -q '"errorCode": "content_mismatch_overwritten"' /tmp/apply.out || {{
  echo "FAIL: apply JSON missing the content_mismatch_overwritten warning event" >&2
  cat /tmp/apply.out >&2
  exit 1
}}
grep -q '"status": "success"' /tmp/apply.out || {{
  echo "FAIL: apply JSON status was not success" >&2
  cat /tmp/apply.out >&2
  exit 1
}}

# 4. Exact-bytes verification, not just substring.
if ! grep -q 'SOCKET-PATCH-E2E-MARKER' "$LICENSE_FILE"; then
  echo "FAIL: marker not in $LICENSE_FILE" >&2
  head -3 "$LICENSE_FILE" >&2
  exit 1
fi
ACTUAL_SHA=$(sha256sum "$LICENSE_FILE" | cut -d' ' -f1)
if [ "$ACTUAL_SHA" != "{expected_sha}" ]; then
  echo "FAIL: patched LICENSE.md bytes differ from served blob" >&2
  echo "  expected={expected_sha}" >&2
  echo "  actual  =$ACTUAL_SHA" >&2
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

fn run_container(script: &str) -> std::process::Output {
    let mut cmd = Command::new("docker");
    cmd.args([
        "run",
        "--rm",
        "--add-host=host.docker.internal:host-gateway",
        "-i",
        // NuGet crawler is gated by `SOCKET_EXPERIMENTAL_NUGET=1` at
        // runtime (see ecosystem_dispatch::nuget_runtime_enabled).
        // Signed .nupkg packages carry a `.nupkg.sha512` tamper-marker
        // the sidecar can't honestly rewrite without the original
        // `.nupkg` bytes; the gate makes operators opt in to that
        // tradeoff. Tests opt in explicitly so docker actually
        // exercises the nuget scan / apply path.
        "-e",
        "SOCKET_EXPERIMENTAL_NUGET=1",
    ])
    .args(cov_docker_args())
    .args(["socket-patch-test-nuget:latest", "bash", "-c", script]);
    cmd.output().expect("docker run")
}

/// Assert the wiremock actually served BOTH the metadata discovery
/// (batch) AND the patch-content fetch (view). Without the latter, the
/// download→apply content path never ran even if a marker somehow
/// appeared on disk, so this proves the real network code path executed.
async fn assert_api_path_exercised(server: &MockServer) {
    let received = server.received_requests().await.unwrap_or_default();
    let paths: Vec<String> = received.iter().map(|r| r.url.path().to_string()).collect();
    assert!(
        paths.iter().any(|p| p.contains("/patches/batch")),
        "scan should have called /patches/batch; received={paths:#?}"
    );
    assert!(
        paths.iter().any(|p| p.contains("/patches/view/")),
        "scan --sync should have fetched patch content via /patches/view/; received={paths:#?}"
    );
}

#[tokio::test]
async fn nuget_local_install_full_apply_chain() {
    let after_hash = git_sha256(PATCHED_LICENSE);
    let expected_sha = plain_sha256(PATCHED_LICENSE);
    let server = make_mock_server(&after_hash).await;
    let api_url = format!("http://host.docker.internal:{}", server.address().port());
    if skip_if_no_image() {
        return;
    }
    let out = run_container(&local_script(&api_url, &expected_sha));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "nuget local apply failed:\nstdout=\n{stdout}\nstderr=\n{stderr}"
    );
    // Each marker is emitted only after its in-script gate passed.
    assert!(
        stderr.contains("===SCAN VERIFIED==="),
        "scan did not discover the patch (===SCAN VERIFIED=== missing).\nstdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(stderr.contains("===PATCH VERIFIED==="), "stderr=\n{stderr}");
    assert!(stdout.contains("===E2E PASS==="), "stdout=\n{stdout}");
    // Agent-mode VEX leg: the manifest patch was attested with plain
    // (non-vendored, non-redirected) provenance against the patched LICENSE.md.
    assert!(
        stderr.contains("===VEX VERIFIED==="),
        "agent-mode VEX leg did not run/pass (===VEX VERIFIED=== missing).\nstderr=\n{stderr}"
    );
    assert_vex_agent_attested(&stdout, PURL);
    assert_api_path_exercised(&server).await;
}

#[tokio::test]
async fn nuget_global_install_full_apply_chain() {
    let after_hash = git_sha256(PATCHED_LICENSE);
    let expected_sha = plain_sha256(PATCHED_LICENSE);
    let server = make_mock_server(&after_hash).await;
    let api_url = format!("http://host.docker.internal:{}", server.address().port());
    if skip_if_no_image() {
        return;
    }
    let out = run_container(&global_script(&api_url, &expected_sha));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "nuget global apply failed:\nstdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(
        stderr.contains("===SCAN VERIFIED==="),
        "scan did not discover the patch (===SCAN VERIFIED=== missing).\nstdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(stderr.contains("===PATCH VERIFIED==="), "stderr=\n{stderr}");
    assert!(stdout.contains("===E2E PASS==="), "stdout=\n{stdout}");
    assert_api_path_exercised(&server).await;
}
