//! End-to-end tests for API client error paths — exercises 4xx/5xx/
//! malformed responses + connection failure paths via wiremock.
//!
//! Hardening note (audit/test-review): every test in this file previously
//! asserted only `code == 0 || code == 1`, which is satisfied by *both* a
//! correct error-handling impl AND a broken one that silently swallows the
//! failure and reports success. That is a disjoint-outcome loophole: it can
//! never distinguish "handled the 401 gracefully" from "ignored the 401".
//! Each test below now pins the *exact* exit code and inspects the JSON
//! envelope (`status`/`error`) emitted on stdout, so a regression that turns
//! a real API failure into a fake success fails the test loudly.

use std::path::{Path, PathBuf};
use std::process::Command;

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

const ORG_SLUG: &str = "test-org";
const UUID: &str = "11111111-1111-4111-8111-111111111111";

fn write_root(root: &Path) {
    std::fs::write(
        root.join("package.json"),
        r#"{ "name": "api-err-test", "version": "0.0.0" }"#,
    )
    .unwrap();
}

fn write_npm_package(root: &Path, name: &str) {
    let pkg_dir = root.join("node_modules").join(name);
    std::fs::create_dir_all(&pkg_dir).unwrap();
    std::fs::write(
        pkg_dir.join("package.json"),
        format!(r#"{{ "name": "{name}", "version": "1.0.0" }}"#),
    )
    .unwrap();
}

/// Parse the command's stdout as JSON, failing with the raw bytes on error
/// so a regression that prints a non-JSON crash dump is diagnosable.
fn json_stdout(out: &std::process::Output) -> serde_json::Value {
    let stdout = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!(
            "expected valid JSON on stdout, got parse error {e}; \
             stdout={stdout:?} stderr={:?}",
            String::from_utf8_lossy(&out.stderr)
        )
    })
}

/// Assert the JSON envelope is the canonical CLI error shape:
/// `{"status":"error","error":"<non-empty message containing `needle`>"}`.
/// This is what `report_error`/`report_fetch_failure` emit, and it is the
/// behavior these error-path tests exist to protect.
fn assert_error_envelope(v: &serde_json::Value, needle: &str) {
    assert_eq!(
        v["status"], "error",
        "expected status=error envelope, got: {v}"
    );
    let msg = v["error"]
        .as_str()
        .unwrap_or_else(|| panic!("error field must be a string, got: {v}"));
    assert!(!msg.is_empty(), "error message must not be empty: {v}");
    assert!(
        msg.to_ascii_lowercase()
            .contains(&needle.to_ascii_lowercase()),
        "error message {msg:?} must mention {needle:?}"
    );
}

/// Assert the mock actually received a request whose path contains `needle`.
/// This proves the CLI exercised the *real* network path under test rather
/// than short-circuiting (e.g. erroring out before the HTTP call, or hitting
/// a different/cached code path) and incidentally producing the right
/// envelope. Without this, an error/not_found envelope alone cannot
/// distinguish "the API was called and failed as mocked" from "the call
/// never happened".
async fn assert_path_hit(mock: &MockServer, needle: &str) {
    let reqs = mock
        .received_requests()
        .await
        .expect("wiremock must record received requests");
    let paths: Vec<String> = reqs.iter().map(|r| r.url.path().to_string()).collect();
    assert!(
        paths.iter().any(|p| p.contains(needle)),
        "expected the real endpoint containing {needle:?} to be queried; \
         recorded request paths = {paths:?}"
    );
}

// ---------------------------------------------------------------------------
// 401 / 403 / 404 / 5xx error handling — every command that hits the API
// ---------------------------------------------------------------------------

/// A 401 from the authenticated endpoint must trigger the public-proxy
/// fallback (free patches only), NOT a crash and NOT a swallowed success.
/// The proxy is pinned at the same mock (returning 404 for this fake UUID)
/// so the outcome is deterministic instead of hitting the real
/// `patches-api.socket.dev` over the network.
#[tokio::test]
async fn get_uuid_with_401_falls_back_to_proxy() {
    let mock = MockServer::start().await;
    // Authenticated endpoint: 401.
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(401).set_body_string("Unauthorized"))
        .mount(&mock)
        .await;
    // Public-proxy endpoint (use_public_proxy => `/patch/view/<uuid>`):
    // the fake UUID is genuinely not found.
    Mock::given(method("GET"))
        .and(path(format!("/patch/view/{UUID}")))
        .respond_with(ResponseTemplate::new(404))
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let out = Command::new(binary())
        .args([
            "get",
            UUID,
            "--json",
            "--save-only",
            "--yes",
            "--api-url",
            &mock.uri(),
            "--proxy-url",
            &mock.uri(),
            "--api-token",
            "fake-token",
            "--org",
            ORG_SLUG,
        ])
        .current_dir(tmp.path())
        .output()
        .expect("run");

    let code = out.status.code().unwrap_or(-1);
    let stderr = String::from_utf8_lossy(&out.stderr);
    // The fallback path must actually run — proves the 401 was detected and
    // handled, not ignored. A broken impl that swallows the 401 would skip
    // this warning and report `status:"error"` (or success) instead.
    assert!(
        stderr.contains("falling back to public patch API proxy"),
        "401 must trigger the documented proxy fallback; stderr={stderr}"
    );
    // ...but the stderr log line is only an *incidental* signal: a regression
    // could emit it without actually querying the proxy, or query the proxy
    // without logging. Pin the behavior at the network layer — the auth
    // endpoint must have been tried (and returned 401) AND the proxy endpoint
    // must have actually been queried as a consequence.
    assert_path_hit(&mock, &format!("/v0/orgs/{ORG_SLUG}/patches/view/{UUID}")).await;
    assert_path_hit(&mock, &format!("/patch/view/{UUID}")).await;
    // ...and crucially the proxy must be queried *after* the authenticated
    // endpoint returned 401 — that ordering is what makes this a fallback and
    // not two independent requests. A regression that queries the proxy
    // unconditionally (without first trying — and failing — auth) would pass
    // the two membership checks above but violate this ordering.
    {
        let reqs = mock
            .received_requests()
            .await
            .expect("wiremock must record received requests");
        let paths: Vec<String> = reqs.iter().map(|r| r.url.path().to_string()).collect();
        let auth_idx = paths
            .iter()
            .position(|p| p.contains(&format!("/v0/orgs/{ORG_SLUG}/patches/view/{UUID}")))
            .expect("auth endpoint must have been queried");
        let proxy_idx = paths
            .iter()
            .position(|p| p.contains(&format!("/patch/view/{UUID}")))
            .expect("proxy endpoint must have been queried");
        assert!(
            auth_idx < proxy_idx,
            "the proxy must be queried only after the auth 401; \
             recorded request paths = {paths:?}"
        );
    }
    // Proxy returned 404 → graceful "not found", exit 0.
    assert_eq!(code, 0, "graceful fallback must exit 0; stderr={stderr}");
    let v = json_stdout(&out);
    assert_eq!(
        v["status"], "not_found",
        "after proxy 404 the patch is not found, got: {v}"
    );
    assert_eq!(v["found"], 0, "not_found envelope reports zero found: {v}");
}

/// A 500 is NOT a fallback candidate: it must surface as a hard error
/// (exit 1) with the upstream status in the message.
#[tokio::test]
async fn get_uuid_with_500_reports_error() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(500).set_body_string("internal error"))
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let out = Command::new(binary())
        .args([
            "get",
            UUID,
            "--json",
            "--save-only",
            "--yes",
            "--api-url",
            &mock.uri(),
            "--api-token",
            "fake-token",
            "--org",
            ORG_SLUG,
        ])
        .current_dir(tmp.path())
        .output()
        .expect("run");
    let code = out.status.code().unwrap_or(-1);
    assert_path_hit(&mock, &format!("/v0/orgs/{ORG_SLUG}/patches/view/{UUID}")).await;
    assert_eq!(code, 1, "500 must surface as a non-zero failure");
    let v = json_stdout(&out);
    assert_error_envelope(&v, "500");
}

/// A 200 with an unparseable body must surface as an error (exit 1), not a
/// silent success or a panic.
#[tokio::test]
async fn get_uuid_with_malformed_json_reports_parse_error() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/view/{UUID}")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("{ this is not valid json")
                .insert_header("content-type", "application/json"),
        )
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let out = Command::new(binary())
        .args([
            "get",
            UUID,
            "--json",
            "--save-only",
            "--yes",
            "--api-url",
            &mock.uri(),
            "--api-token",
            "fake-token",
            "--org",
            ORG_SLUG,
        ])
        .current_dir(tmp.path())
        .output()
        .expect("run");
    let code = out.status.code().unwrap_or(-1);
    assert_path_hit(&mock, &format!("/v0/orgs/{ORG_SLUG}/patches/view/{UUID}")).await;
    assert_eq!(code, 1, "malformed JSON must surface as a non-zero failure");
    let v = json_stdout(&out);
    assert_error_envelope(&v, "parse");
}

/// A scan whose only API batch is rejected (400) must NOT report success.
/// A clean `status:"success"`/exit-0 here would tell a CI gate the project
/// is fully scanned and patch-free when in fact the scan never reached the
/// API — exactly the silent-zero failure the production comment at
/// scan.rs:598-611 claims to prevent.
#[tokio::test]
async fn scan_with_400_bad_request_reports_failure() {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/batch")))
        .respond_with(ResponseTemplate::new(400).set_body_string("Bad request"))
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    write_root(tmp.path());
    write_npm_package(tmp.path(), "foo");

    let out = Command::new(binary())
        .args([
            "scan",
            "--json",
            "--api-url",
            &mock.uri(),
            "--api-token",
            "fake-token",
            "--org",
            ORG_SLUG,
        ])
        .current_dir(tmp.path())
        .output()
        .expect("run");
    let code = out.status.code().unwrap_or(-1);
    // Prove the batch endpoint was genuinely reached and returned the 400 —
    // otherwise a regression that simply discovers zero packages (and never
    // calls the API) could also avoid "success" for the wrong reason.
    assert_path_hit(&mock, &format!("/v0/orgs/{ORG_SLUG}/patches/batch")).await;
    let v = json_stdout(&out);
    // KNOWN PRODUCTION BUG (left red intentionally — see file summary):
    // `scan` currently emits `status:"success"`/exit 0 even when every
    // batch failed. The intended contract is that a fully-failed scan is
    // surfaced, so a CI gate does not mistake it for "no vulnerabilities".
    assert_ne!(
        v["status"], "success",
        "a scan where the only batch returned 400 must not report success; got: {v}"
    );
    assert_eq!(
        code, 1,
        "a fully-failed scan must exit non-zero so CI gates catch it; got code={code}, json={v}"
    );
}

// ---------------------------------------------------------------------------
// Network failure — unreachable host
// ---------------------------------------------------------------------------

/// A connection refused on `get` (not a fallback candidate) must surface as
/// a hard error envelope, exit 1.
#[tokio::test]
async fn get_with_unreachable_api_url_reports_error() {
    let tmp = tempfile::tempdir().unwrap();
    // Port 1 is reserved and reliably refuses connections.
    let out = Command::new(binary())
        .args([
            "get",
            UUID,
            "--json",
            "--save-only",
            "--yes",
            "--api-url",
            "http://127.0.0.1:1",
            "--api-token",
            "fake-token",
            "--org",
            ORG_SLUG,
        ])
        .current_dir(tmp.path())
        .output()
        .expect("run");
    let code = out.status.code().unwrap_or(-1);
    assert_eq!(code, 1, "network error must surface as non-zero");
    let v = json_stdout(&out);
    assert_error_envelope(&v, "network");
}

/// A scan against an unreachable host must NOT report success (same masked
/// bug as the 400 case — see `scan_with_400_bad_request_reports_failure`).
#[tokio::test]
async fn scan_with_unreachable_api_url_reports_failure() {
    let tmp = tempfile::tempdir().unwrap();
    write_root(tmp.path());
    write_npm_package(tmp.path(), "bar");

    let out = Command::new(binary())
        .args([
            "scan",
            "--json",
            "--api-url",
            "http://127.0.0.1:1",
            "--api-token",
            "fake-token",
            "--org",
            ORG_SLUG,
        ])
        .current_dir(tmp.path())
        .output()
        .expect("run");
    let code = out.status.code().unwrap_or(-1);
    let v = json_stdout(&out);
    // KNOWN PRODUCTION BUG (left red intentionally — see file summary).
    assert_ne!(
        v["status"], "success",
        "a scan where the only batch was unreachable must not report success; got: {v}"
    );
    assert_eq!(
        code, 1,
        "a fully-failed scan must exit non-zero; got code={code}, json={v}"
    );
}

// ---------------------------------------------------------------------------
// CVE / GHSA search errors
// ---------------------------------------------------------------------------

/// A 500 on the CVE search endpoint (no proxy fallback for search) must
/// surface as a hard error, exit 1.
#[tokio::test]
async fn get_by_cve_with_500_reports_error() {
    let mock = MockServer::start().await;
    let cve = "CVE-2024-12345";
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/by-cve/{cve}")))
        .respond_with(ResponseTemplate::new(500))
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let out = Command::new(binary())
        .args([
            "get",
            cve,
            "--json",
            "--save-only",
            "--yes",
            "--api-url",
            &mock.uri(),
            "--api-token",
            "fake-token",
            "--org",
            ORG_SLUG,
        ])
        .current_dir(tmp.path())
        .output()
        .expect("run");
    let code = out.status.code().unwrap_or(-1);
    assert_path_hit(&mock, &format!("/v0/orgs/{ORG_SLUG}/patches/by-cve/{cve}")).await;
    assert_eq!(code, 1, "CVE 500 must surface as non-zero");
    let v = json_stdout(&out);
    assert_error_envelope(&v, "500");
}

/// A 404 on the GHSA search endpoint is "no patches found", a graceful
/// not_found (exit 0) — NOT an error and NOT a crash.
#[tokio::test]
async fn get_by_ghsa_with_404_reports_not_found() {
    let mock = MockServer::start().await;
    let ghsa = "GHSA-aaaa-bbbb-cccc";
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/by-ghsa/{ghsa}")))
        .respond_with(ResponseTemplate::new(404))
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let out = Command::new(binary())
        .args([
            "get",
            ghsa,
            "--json",
            "--save-only",
            "--yes",
            "--api-url",
            &mock.uri(),
            "--api-token",
            "fake-token",
            "--org",
            ORG_SLUG,
        ])
        .current_dir(tmp.path())
        .output()
        .expect("run");
    let code = out.status.code().unwrap_or(-1);
    assert_path_hit(
        &mock,
        &format!("/v0/orgs/{ORG_SLUG}/patches/by-ghsa/{ghsa}"),
    )
    .await;
    assert_eq!(code, 0, "GHSA 404 is a graceful not-found, exit 0");
    let v = json_stdout(&out);
    assert_eq!(
        v["status"], "not_found",
        "404 search must map to not_found, got: {v}"
    );
    assert_eq!(v["found"], 0, "not_found envelope reports zero found: {v}");
}

// ---------------------------------------------------------------------------
// Repair fetch errors
// ---------------------------------------------------------------------------

#[tokio::test]
async fn repair_with_blob_404_marks_failure_in_summary() {
    let after_hash = "1111111111111111111111111111111111111111111111111111111111111111";
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!(
            "/v0/orgs/{ORG_SLUG}/patches/blob/{after_hash}"
        )))
        .respond_with(ResponseTemplate::new(404))
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    std::fs::write(
        socket.join("manifest.json"),
        format!(
            r#"{{
  "patches": {{
    "pkg:npm/repair404@1.0.0": {{
      "uuid": "11111111-1111-4111-8111-111111111111",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {{
        "package/x.js": {{
          "beforeHash": "0000000000000000000000000000000000000000000000000000000000000000",
          "afterHash": "{after_hash}"
        }}
      }},
      "vulnerabilities": {{}},
      "description": "x",
      "license": "MIT",
      "tier": "free"
    }}
  }}
}}"#
        ),
    )
    .unwrap();

    let out = Command::new(binary())
        .args([
            "repair",
            "--json",
            "--download-mode",
            "file",
            "--download-only",
        ])
        .current_dir(tmp.path())
        .env("SOCKET_API_URL", mock.uri())
        .env("SOCKET_API_TOKEN", "fake-token")
        .env("SOCKET_ORG_SLUG", ORG_SLUG)
        .output()
        .expect("run");
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    // Prove the blob download was actually attempted against the mock (and
    // returned 404) — the failure must come from the real fetch path, not
    // from repair bailing out before it ever tried to download.
    assert_path_hit(
        &mock,
        &format!("/v0/orgs/{ORG_SLUG}/patches/blob/{after_hash}"),
    )
    .await;
    assert_eq!(
        code, 1,
        "repair must exit non-zero when an artifact download fails so CI guarding on \
         the exit code doesn't treat a half-finished repair as success; stdout={stdout}"
    );
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("must be JSON");
    // The repair envelope's summary tracks failures. Require BOTH the
    // summary counter AND a per-event `failed` record so a regression that
    // drops one but not the other is still caught (the original test
    // tolerated either, which masks a partial-reporting regression).
    let summary_failed = v["summary"]["failed"].as_u64();
    assert_eq!(
        summary_failed,
        Some(1),
        "repair summary must record exactly the one failed download; got: {v}"
    );
    // The 404'd blob must NOT also be counted as a success anywhere in the
    // summary. A regression that records the artifact as both `failed` and
    // `downloaded`/`applied` would still satisfy the `failed==1` check above,
    // so pin the success counters to zero to catch double-counting.
    assert_eq!(
        v["summary"]["downloaded"].as_u64(),
        Some(0),
        "a 404'd blob must not be counted as downloaded; got: {v}"
    );
    assert_eq!(
        v["summary"]["applied"].as_u64(),
        Some(0),
        "a failed download must not be counted as applied; got: {v}"
    );
    let has_failed_event = v
        .get("events")
        .and_then(|e| e.as_array())
        .is_some_and(|a| a.iter().any(|e| e["action"] == "failed"));
    assert!(
        has_failed_event,
        "repair must emit a per-artifact `failed` event for the 404; got: {v}"
    );
}
