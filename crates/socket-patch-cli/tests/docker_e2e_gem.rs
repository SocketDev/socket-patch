//! Docker-driven full install→apply chain for the gem (Ruby) ecosystem.
//!
//! Two test functions:
//! - `gem_local_install_full_apply_chain` — `gem install --install-dir
//!   vendor/bundle/ruby/<ver>` (project-local layout, like `bundle
//!   install --path vendor/bundle`); socket-patch scans the
//!   project-local vendor/bundle, applies, marker verified in the
//!   installed `lib/colorize.rb`.
//! - `gem_global_install_full_apply_chain` — `gem install` without
//!   --install-dir, installs to the system gem directory; socket-patch
//!   scans + applies with `--global`.

#![cfg(feature = "docker-e2e")]

use std::process::Command;

use base64::Engine;
use sha2::{Digest, Sha256};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";
const PURL: &str = "pkg:gem/colorize@1.1.0";
const UUID: &str = "13131313-1313-4131-8131-131313131313";
/// The vulnerability the staged manifest carries so the agent-mode VEX leg
/// has something to attest (plain agent provenance — no vendored/redirected
/// marker — is what the host oracle asserts).
const GHSA: &str = "GHSA-agent-gem-real";

const PATCHED_RB: &[u8] = b"# SOCKET-PATCH-E2E-MARKER\n\
                            # colorize.rb replaced by socket-patch e2e fixture\n\
                            module Colorize\n  VERSION = '1.1.0-patched'\nend\n";

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

/// Plain SHA-256 of the bytes (no git blob header) — matches what
/// `sha256sum` reports inside the container, so the test can assert the
/// installed file is byte-identical to the patch blob, not merely that
/// it contains the marker substring.
fn plain_sha256(content: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content);
    hex::encode(hasher.finalize())
}

/// Shared verification block for both scripts. Expects `GEM_FILE`,
/// `EXPECTED_SHA`, and `APPLY_EXIT` to be set, plus the JSON captured in
/// `/tmp/scan.json` and `/tmp/apply.json`.
///
/// This asserts on the *real structured output* of the run, not just a
/// substring marker:
///   - scan's JSON shows the colorize patch was discovered AND synced
///     (`"action": "added"`). NOTE: scan's process exit code is
///     deliberately NOT gated — a non-zero scan exit from an unrelated
///     transitive package without a patch must not fail a pipeline whose
///     target patch was found and synced.
///   - apply exited 0 and its JSON reports the patch was actually
///     `"applied"`, hash-`"verified": true`, with `summary.applied == 1`
///     — this rejects a no-op "success" that patches nothing.
///   - the installed file contains the marker AND is byte-for-byte
///     identical to the patch blob the API served (exact sha256), so
///     truncated/garbled/appended writes can't slip through.
fn verify_snippet() -> &'static str {
    r#"
# --- scan: must have discovered and synced the colorize patch ---
grep -qF 'pkg:gem/colorize@1.1.0' /tmp/scan.json || {
  echo "FAIL: scan json missing colorize purl" >&2; cat /tmp/scan.json >&2; exit 1; }
grep -qF '"action": "added"' /tmp/scan.json || {
  echo "FAIL: scan did not sync (add) the patch" >&2; cat /tmp/scan.json >&2; exit 1; }

# --- apply: must exit 0 and report a real applied+verified patch ---
if [ "${APPLY_EXIT:-1}" != "0" ]; then
  echo "FAIL: apply exited non-zero (${APPLY_EXIT:-unset})" >&2; cat /tmp/apply.json >&2; exit 1
fi
for needle in '"status": "success"' '"action": "applied"' '"verified": true' '"applied": 1' 'pkg:gem/colorize@1.1.0'; do
  grep -qF "$needle" /tmp/apply.json || {
    echo "FAIL: apply json missing [$needle]" >&2; cat /tmp/apply.json >&2; exit 1; }
done

# --- installed file: marker present AND byte-identical to the patch blob ---
if ! grep -q 'SOCKET-PATCH-E2E-MARKER' "$GEM_FILE"; then
  echo "FAIL: marker not in $GEM_FILE" >&2
  head -3 "$GEM_FILE" >&2
  exit 1
fi
ACTUAL_SHA=$(sha256sum "$GEM_FILE" | cut -d' ' -f1)
if [ "$ACTUAL_SHA" != "$EXPECTED_SHA" ]; then
  echo "FAIL: $GEM_FILE content sha256 ($ACTUAL_SHA) != expected ($EXPECTED_SHA)" >&2
  echo "---- actual file ----" >&2
  cat "$GEM_FILE" >&2
  exit 1
fi

echo "===PATCH VERIFIED===" >&2
echo "===E2E PASS==="
exit 0
"#
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
                    "severity": "medium", "title": "gem e2e fixture"
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
                "description": "gem e2e fixture",
                "license": "MIT", "tier": "free",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(&server)
        .await;

    let blob_b64 = base64::engine::general_purpose::STANDARD.encode(PATCHED_RB);
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": UUID,
            "purl": PURL,
            "publishedAt": "2024-01-01T00:00:00Z",
            "files": {
                // gem uses `package/<rel>` (npm-style) — apply strips
                // the prefix and joins with the gem dir.
                "package/lib/colorize.rb": {
                    "beforeHash": "0000000000000000000000000000000000000000000000000000000000000000",
                    "afterHash":  after_hash,
                    "blobContent": blob_b64,
                }
            },
            // Recorded into the manifest so the agent-mode VEX leg attests it.
            "vulnerabilities": {
                (GHSA): {
                    "cves": ["CVE-2024-30005"],
                    "summary": "gem agent e2e fixture vulnerability",
                    "severity": "medium",
                    "description": "Agent-mode VEX leg fixture vulnerability"
                }
            },
            "description": "gem e2e fixture",
            "license": "MIT",
            "tier": "free",
        })))
        .mount(&server)
        .await;

    server
}

fn local_script(api_url: &str, expected_sha: &str) -> String {
    let verify = verify_snippet();
    format!(
        r#"#!/usr/bin/env bash
set -uo pipefail
EXPECTED_SHA='{expected_sha}'

mkdir -p /workspace/proj && cd /workspace/proj
RUBY_VER=$(ruby -e 'puts RUBY_VERSION.split(".").take(2).join(".") + ".0"')
INSTALL_DIR="vendor/bundle/ruby/$RUBY_VER"
mkdir -p "$INSTALL_DIR"
gem install --no-document --install-dir "$INSTALL_DIR" colorize -v 1.1.0 > /tmp/install.log 2>&1 || {{
  cat /tmp/install.log >&2; exit 1
}}

GEM_FILE="$INSTALL_DIR/gems/colorize-1.1.0/lib/colorize.rb"
[ -f "$GEM_FILE" ] || {{ echo "FAIL: $GEM_FILE missing" >&2; exit 1; }}
echo "Installed to: $GEM_FILE" >&2

# Pre-seed setup.manual so the agent-mode VEX leg keeps the gem patch through
# property 7 (this project isn't `socket-patch setup`-configured; agent patches
# are applied by hand/CI — exactly what `manual` declares). scan --sync merges
# the downloaded patch into this manifest and preserves the setup block.
mkdir -p .socket
cat > .socket/manifest.json <<'MANIFEST'
{{ "patches": {{}}, "setup": {{ "manual": ["gem"] }} }}
MANIFEST

# scan exit code is intentionally not gated (see verify_snippet); capture JSON.
socket-patch scan --json --sync --yes \
  --api-url '{api_url}' --api-token fake --org {ORG} \
  --ecosystems gem > /tmp/scan.json 2>/tmp/sync.err
cat /tmp/sync.err >&2

socket-patch apply --json --force --offline --ecosystems gem > /tmp/apply.json 2>/tmp/apply.err
APPLY_EXIT=$?
cat /tmp/apply.err >&2

# Agent-mode VEX leg (runs after the apply stage above; the file is patched by
# now). The manifest scan --sync wrote carries {GHSA}; vex verifies the patched
# colorize.rb in vendor/bundle and attests it with PLAIN agent provenance.
# --ecosystems gem (no --global, matching the local apply); --offline keeps vex
# local. The doc is emitted between markers for the host-side oracle (no bind
# mount here). The interpolated verify_snippet then runs its own file asserts.
echo "===VEX OUTPUT===" >&2
socket-patch vex --offline --cwd "$PWD" --output /tmp/out.vex.json \
  --product 'pkg:gem/e2e-app@1.0.0' --ecosystems gem >/tmp/vex.out 2>/tmp/vex.err
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
{verify}"#
    )
}

fn global_script(api_url: &str, expected_sha: &str) -> String {
    let verify = verify_snippet();
    format!(
        r#"#!/usr/bin/env bash
set -uo pipefail
EXPECTED_SHA='{expected_sha}'

# gem install without --install-dir uses the system gem dir.
gem install --no-document colorize -v 1.1.0 > /tmp/install.log 2>&1 || {{
  cat /tmp/install.log >&2; exit 1
}}

GEM_DIR=$(gem env gemdir)
GEM_FILE="$GEM_DIR/gems/colorize-1.1.0/lib/colorize.rb"
[ -f "$GEM_FILE" ] || {{ echo "FAIL: $GEM_FILE missing" >&2; exit 1; }}
echo "Global-installed at: $GEM_FILE" >&2

mkdir -p /workspace/proj && cd /workspace/proj

# scan exit code is intentionally not gated (see verify_snippet); capture JSON.
socket-patch scan --json --sync --yes --global \
  --api-url '{api_url}' --api-token fake --org {ORG} \
  --ecosystems gem > /tmp/scan.json 2>/tmp/sync.err
cat /tmp/sync.err >&2

socket-patch apply --json --force --offline --global --ecosystems gem > /tmp/apply.json 2>/tmp/apply.err
APPLY_EXIT=$?
cat /tmp/apply.err >&2
{verify}"#
    )
}

/// Returns `true` when the test should skip (docker missing, image
/// missing). Prints a skip notice to stderr — the test still reports
/// as `ok` because Rust integration tests have no native "skipped"
/// outcome. Build locally with
/// `docker build -f tests/docker/Dockerfile.gem -t socket-patch-test-gem:latest .`
#[must_use]
fn skip_if_no_image() -> bool {
    let Ok(out) = Command::new("docker")
        .args(["image", "inspect", "socket-patch-test-gem:latest"])
        .output()
    else {
        eprintln!("skipping: `docker` not on PATH");
        return true;
    };
    if !out.status.success() {
        eprintln!("skipping: docker image `socket-patch-test-gem:latest` not present");
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
    .args(["socket-patch-test-gem:latest", "bash", "-c", script]);
    cmd.output().expect("docker run")
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

/// Assert the wiremock actually served BOTH the metadata discovery
/// (batch) AND the patch-content fetch (view). The in-container `echo`
/// markers alone can't prove the real network path ran — a build that
/// short-circuits the API (cached layer, stubbed fetch, or a marker
/// written by some unrelated mechanism) could still emit them. Requiring
/// the server to have observed the batch POST and the per-UUID blob GET
/// proves the genuine scan→download→apply code path executed end to end.
async fn assert_api_path_exercised(server: &MockServer) {
    let received = server.received_requests().await.unwrap_or_default();
    let paths: Vec<String> = received.iter().map(|r| r.url.path().to_string()).collect();
    assert!(
        paths.iter().any(|p| p.contains("/patches/batch")),
        "scan should have called /patches/batch; received={paths:#?}"
    );
    assert!(
        paths.iter().any(|p| p.contains(&format!("/patches/view/{UUID}"))),
        "scan --sync should have fetched patch content via /patches/view/{UUID}; received={paths:#?}"
    );
}

#[tokio::test]
async fn gem_local_install_full_apply_chain() {
    let after_hash = git_sha256(PATCHED_RB);
    let server = make_mock_server(&after_hash).await;
    let api_url = format!("http://host.docker.internal:{}", server.address().port());
    if skip_if_no_image() {
        return;
    }
    let expected_sha = plain_sha256(PATCHED_RB);
    let out = run_container(&local_script(&api_url, &expected_sha));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "gem local apply failed:\nstdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(stderr.contains("===PATCH VERIFIED==="), "stderr=\n{stderr}");
    assert!(stdout.contains("===E2E PASS==="), "stdout=\n{stdout}");
    // Agent-mode VEX leg: the manifest patch was attested with plain
    // (non-vendored, non-redirected) provenance against the patched colorize.rb.
    assert!(
        stderr.contains("===VEX VERIFIED==="),
        "agent-mode VEX leg did not run/pass (===VEX VERIFIED=== missing).\nstderr=\n{stderr}"
    );
    assert_vex_agent_attested(&stdout, PURL);
    assert_api_path_exercised(&server).await;
}

#[tokio::test]
async fn gem_global_install_full_apply_chain() {
    let after_hash = git_sha256(PATCHED_RB);
    let server = make_mock_server(&after_hash).await;
    let api_url = format!("http://host.docker.internal:{}", server.address().port());
    if skip_if_no_image() {
        return;
    }
    let expected_sha = plain_sha256(PATCHED_RB);
    let out = run_container(&global_script(&api_url, &expected_sha));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "gem global apply failed:\nstdout=\n{stdout}\nstderr=\n{stderr}"
    );
    assert!(stderr.contains("===PATCH VERIFIED==="), "stderr=\n{stderr}");
    assert!(stdout.contains("===E2E PASS==="), "stdout=\n{stdout}");
    assert_api_path_exercised(&server).await;
}
