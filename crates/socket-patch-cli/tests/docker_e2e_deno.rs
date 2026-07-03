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
//!   * `deno_jsr_synthetic_layout_scan_verifies_discovery` — stages a
//!     *synthetic* JSR cache layout under
//!     `$DENO_DIR/npm/jsr.io/<scope>/<name>/<version>/` with `mkdir`
//!     (real Deno 2.x caches JSR content-addressed, with no
//!     scope/name/version tree for the crawler to walk — see the
//!     `deno_jsr_script` comment), then runs
//!     `socket-patch scan --json --ecosystems deno --global` against
//!     that root. The fixture stages four packages whose scope/name/
//!     version cardinalities all differ (2 scopes, 3 names, 4 versions)
//!     plus decoys, then asserts the DenoCrawler count matches a
//!     filesystem-derived oracle *exactly* — so a crawler that counts
//!     the wrong tree level cannot pass. End-to-end through the real CLI
//!     binary. The `deno` binary is exercised only to prove the image is
//!     healthy; it does not produce the scanned layout.
//!
//! Run command:
//!   `cargo test -p socket-patch-cli --features docker-e2e --test docker_e2e_deno`

#![cfg(feature = "docker-e2e")]

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

/// Build the wiremock for the npm-via-deno-install variant. Same
/// minimist fixture as `docker_e2e_npm.rs`; we duplicate it here to
/// keep this test file self-contained.
async fn make_npm_mock_server(after_hash: &str) -> MockServer {
    let listener = std::net::TcpListener::bind("0.0.0.0:0").expect("bind wiremock to 0.0.0.0:0");
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
        .and(path(format!("/v0/orgs/{ORG}/patches/blob/{after_hash}")))
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
fn deno_node_modules_script(api_url: &str, expected_blob_b64: &str) -> String {
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

# Snapshot the pre-apply content so we can prove apply actually
# rewrote the file (not that the marker happened to be there already).
PRE_APPLY_SHA=$(sha256sum "$TARGET" | cut -d' ' -f1)
echo "pre-apply sha: $PRE_APPLY_SHA" >&2

# 3. scan --sync — npm ecosystem, since the discovered package is
#    a real npm package (pkg:npm/minimist@1.2.2). The sync step may
#    itself exit non-zero (it tries to apply, and the installed bytes
#    don't match our synthetic patch's beforeHash) — that's expected
#    and tolerated, exactly as in docker_e2e_npm.rs. What MUST happen,
#    regardless of its exit code, is that scan writes the manifest that
#    the offline apply below consumes. We assert on that side-effect.
socket-patch scan --json --sync --yes --ecosystems npm "${{COMMON_ARGS[@]}}" \
  >/tmp/sync.out 2>/tmp/sync.err
echo "sync exit=$?" >&2
cat /tmp/sync.err >&2 || true

# The manifest is the real artifact that drives the offline apply. It
# must exist and must record the minimist patch the mock served;
# otherwise apply --offline has nothing to do and the marker check
# below would be vacuous.
MANIFEST=.socket/manifest.json
if [ ! -f "$MANIFEST" ]; then
  echo "FAIL: scan --sync did not write $MANIFEST" >&2
  ls -la .socket/ 2>&1 >&2 || true
  exit 1
fi
echo "--- manifest ---" >&2; cat "$MANIFEST" >&2
python3 - "$MANIFEST" <<'PY' || exit 1
import json, sys
m = json.load(open(sys.argv[1]))
blob = json.dumps(m)
assert "{NPM_PURL}" in blob, "manifest missing purl {NPM_PURL}"
assert "{NPM_UUID}" in blob, "manifest missing patch uuid {NPM_UUID}"
print("manifest records minimist patch", file=sys.stderr)
PY

# 4. apply --force --offline. MUST succeed (exit 0): the manifest and
#    blob are present locally, so there is no excuse for a failure.
socket-patch apply --json --force --offline --ecosystems npm \
  >/tmp/apply.out 2>/tmp/apply.err
APPLY_RC=$?
echo "apply exit=$APPLY_RC" >&2
cat /tmp/apply.err >&2 || true
if [ "$APPLY_RC" -ne 0 ]; then
  echo "FAIL: apply exited $APPLY_RC (expected 0)" >&2
  exit 1
fi

# 5. The on-disk file must now byte-for-byte equal the patched blob the
#    mock served — not merely "contain a marker" (which a partial or
#    corrupt write could still satisfy).
EXPECTED=/tmp/expected-index.js
echo '{expected_blob_b64}' | base64 -d > "$EXPECTED"
if ! cmp -s "$EXPECTED" "$TARGET"; then
  echo "FAIL: $TARGET does not byte-match the patched blob after apply" >&2
  echo "--- expected ---" >&2; cat "$EXPECTED" >&2
  echo "--- actual ---" >&2; cat "$TARGET" >&2
  exit 1
fi
# And the content must actually have changed from the pre-apply state.
POST_APPLY_SHA=$(sha256sum "$TARGET" | cut -d' ' -f1)
echo "post-apply sha: $POST_APPLY_SHA" >&2
if [ "$PRE_APPLY_SHA" = "$POST_APPLY_SHA" ]; then
  echo "FAIL: $TARGET unchanged by apply ($POST_APPLY_SHA)" >&2
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
#
# CRITICAL: the staged tree deliberately makes the scope / name / version
# cardinalities all DIFFERENT, so a correct per-(scope,name,version)
# enumeration is the ONLY thing that yields the expected count. With the
# old "one package per scope" fixture, a crawler that mistakenly counted
# scopes (or names, or versions) would produce the same number as a
# correct one and pass — masking a real enumeration bug.
#
#   scope:           @std, @luca                         -> 2 distinct
#   scope/name:      @std/path, @std/fs, @luca/flag      -> 3 distinct
#   scope/name/ver:  +0.220.0 +0.225.0 +1.0.0 +1.0.0     -> 4 packages
#
# Only the correct crawler reports 4. A scope-counter reports 2, a
# name-counter 3 — both now fail.
export DENO_DIR=/workspace/deno-cache
JSR=$DENO_DIR/npm/jsr.io
mkdir -p "$JSR/@std/path/0.220.0"
mkdir -p "$JSR/@std/path/0.225.0"   # 2nd version of @std/path -> exercises the version layer
mkdir -p "$JSR/@std/fs/1.0.0"       # 2nd name under @std      -> exercises the name layer
mkdir -p "$JSR/@luca/flag/1.0.0"    # 2nd scope                -> exercises the scope layer
cat >"$JSR/@std/path/0.220.0/mod.ts" <<'EOF'
export const sep = "/";
EOF
cat >"$JSR/@std/path/0.225.0/mod.ts" <<'EOF'
export const sep = "/";
EOF
cat >"$JSR/@std/fs/1.0.0/mod.ts" <<'EOF'
export const exists = true;
EOF
cat >"$JSR/@luca/flag/1.0.0/mod.ts" <<'EOF'
export default true;
EOF

# Noise that the crawler MUST ignore, so over-counting is caught too:
#  - a non-`@`-prefixed top-level dir (not a JSR scope)
#  - a stray file where a version dir would sit (not a directory)
mkdir -p "$JSR/noscope/pkg/9.9.9"
cat >"$JSR/noscope/pkg/9.9.9/mod.ts" <<'EOF'
export const ignore = true;
EOF
echo "not a version dir" >"$JSR/@std/path/README.txt"

# Confirm deno itself is runnable (proves the image is healthy even
# though we don't drive a real deno install in this variant).
if ! deno --version >/tmp/deno-version.out 2>&1; then
  echo "FAIL: deno --version did not run" >&2
  cat /tmp/deno-version.out >&2 || true
  exit 1
fi
cat /tmp/deno-version.out >&2
grep -qi '^deno ' /tmp/deno-version.out || {
  echo "FAIL: 'deno --version' output did not identify the deno binary" >&2
  exit 1
}

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
if [ "$SCAN_RC" -ne 0 ]; then
  echo "FAIL: scan exited $SCAN_RC (expected 0)" >&2
  exit 1
fi

# Parse scannedPackages. Do NOT swallow a parse failure with `|| echo 0`
# — malformed JSON or a missing field is itself a regression and must
# surface, not silently degrade to "found 0".
SCANNED=$(echo "$SCAN_OUT" | python3 -c "import sys,json; print(json.load(sys.stdin)['scannedPackages'])")
PARSE_RC=$?
if [ "$PARSE_RC" -ne 0 ]; then
  echo "FAIL: could not parse scannedPackages from scan JSON (rc=$PARSE_RC)" >&2
  echo "$SCAN_OUT" >&2
  exit 1
fi
echo "scanned jsr packages: $SCANNED" >&2

# Independent oracle: count the real leaf (scope,name,version) dirs on
# disk WITHOUT going through the crawler. JSR packages live at depth 3
# under $JSR (@scope/name/version) and the scope segment must start with
# `@` — this excludes the `noscope/...` decoy. Deriving the expected
# value from the filesystem (not a copied-from-output constant) means the
# test disagrees with the implementation whenever the crawler miscounts.
EXPECTED=$(find "$JSR" -mindepth 3 -maxdepth 3 -type d -path "$JSR/@*/*/*" | wc -l | tr -d ' ')
echo "expected (find-derived) jsr packages: $EXPECTED" >&2
# Sanity-check the fixture itself staged the disambiguating layout, so a
# botched edit to the staging block can't quietly collapse the oracle.
if [ "$EXPECTED" -ne 4 ]; then
  echo "FAIL: fixture staging is wrong; find counted $EXPECTED leaf dirs, expected 4" >&2
  find "$JSR" -maxdepth 4 2>&1 >&2 || true
  exit 1
fi
# The crawler must agree with the filesystem oracle exactly: neither fewer
# (missed a package / stopped at the wrong level) nor more (walked the
# `@*` decoy, counted the README file, or double-counted a level).
if [ "$SCANNED" -ne "$EXPECTED" ]; then
  echo "FAIL: DenoCrawler found $SCANNED packages, filesystem has $EXPECTED (@std/path@0.220.0, @std/path@0.225.0, @std/fs@1.0.0, @luca/flag@1.0.0)" >&2
  find "$JSR" -maxdepth 4 2>&1 >&2 || true
  exit 1
fi

echo "scanned jsr packages count matches oracle: $SCANNED" >&2
echo "===SCAN VERIFIED===" >&2
echo "===E2E PASS==="
exit 0
"#.to_string()
}

/// Returns `true` when the test must skip because the docker image is
/// absent. Rust integration tests have no native "skipped" outcome, so a
/// missing image silently makes the whole test vacuous — that is itself a
/// loophole. To make the skip auditable, set `SOCKET_PATCH_REQUIRE_DOCKER=1`
/// (CI does this): the helper then PANICS instead of skipping, so a green
/// run proves the assertions actually executed rather than no-op'd.
#[must_use]
fn skip_if_no_image() -> bool {
    let require = std::env::var("SOCKET_PATCH_REQUIRE_DOCKER")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let out = Command::new("docker")
        .args(["image", "inspect", "socket-patch-test-deno:latest"])
        .output();
    match out {
        Ok(o) if o.status.success() => false,
        Ok(_) => {
            assert!(
                !require,
                "SOCKET_PATCH_REQUIRE_DOCKER=1 but image \
                 `socket-patch-test-deno:latest` is not present"
            );
            eprintln!("skipping: docker image `socket-patch-test-deno:latest` not present");
            true
        }
        Err(_) => {
            assert!(
                !require,
                "SOCKET_PATCH_REQUIRE_DOCKER=1 but `docker` is not on PATH"
            );
            eprintln!("skipping: `docker` not on PATH");
            true
        }
    }
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
    let blob_b64 = base64::engine::general_purpose::STANDARD.encode(PATCHED_BYTES);
    let out = run_container(&deno_node_modules_script(&api_url, &blob_b64));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "deno install apply failed:\nstdout=\n{stdout}\nstderr=\n{stderr}"
    );
    // The real `deno install` populated node_modules/.
    assert!(
        stderr.contains("Installed minimist at:"),
        "deno install did not populate node_modules:\nstderr=\n{stderr}"
    );
    // scan --sync wrote a manifest recording the mocked minimist patch
    // (its own exit code is allowed to be non-zero, like docker_e2e_npm).
    assert!(
        stderr.contains("manifest records minimist patch"),
        "scan --sync did not write a manifest with the minimist patch:\nstderr=\n{stderr}"
    );
    // The offline apply itself must succeed cleanly.
    assert!(
        stderr.contains("apply exit=0"),
        "apply did not exit 0:\nstderr=\n{stderr}"
    );
    // The byte-for-byte + sha-changed checks in the script gate this marker.
    assert!(stderr.contains("===PATCH VERIFIED==="), "stderr=\n{stderr}");
    assert!(stdout.contains("===E2E PASS==="), "stdout=\n{stdout}");
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
    // The DenoCrawler enumerated exactly the 4 staged (scope,name,version)
    // packages — verified in-script against a filesystem-derived oracle, so
    // a crawler that counts the wrong tree level (scopes=2, names=3) fails.
    assert!(
        stderr.contains("scanned jsr packages: 4"),
        "DenoCrawler did not enumerate exactly 4 packages:\nstderr=\n{stderr}"
    );
    assert!(
        stderr.contains("scanned jsr packages count matches oracle: 4"),
        "DenoCrawler count did not match the filesystem oracle:\nstderr=\n{stderr}"
    );
    assert!(stderr.contains("===SCAN VERIFIED==="), "stderr=\n{stderr}");
    assert!(stdout.contains("===E2E PASS==="), "stdout=\n{stdout}");
}
