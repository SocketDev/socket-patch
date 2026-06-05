//! End-to-end coverage that the new `track_patch_*` instrumentation
//! actually fires HTTP POSTs against the configured telemetry endpoint
//! for the apply/scan/get commands, and that `SOCKET_OFFLINE=1`
//! (airgap mode) suppresses every one of them.
//!
//! Wiremock fronts both the patches endpoints (so scan/get succeed)
//! and the telemetry endpoint (so we can assert the POST shape +
//! count). Each test runs the released binary in a tempdir against
//! the mock URI.

use std::path::{Path, PathBuf};
use std::process::Command;

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG_SLUG: &str = "telemetry-test-org";

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_socket-patch"))
}

fn write_root_package_json(root: &Path) {
    std::fs::write(
        root.join("package.json"),
        r#"{"name":"telemetry-test","version":"0.0.0"}"#,
    )
    .unwrap();
}

fn write_npm_package(root: &Path, name: &str, version: &str) {
    let pkg = root.join("node_modules").join(name);
    std::fs::create_dir_all(&pkg).unwrap();
    let manifest = format!(r#"{{"name":"{name}","version":"{version}"}}"#);
    std::fs::write(pkg.join("package.json"), manifest).unwrap();
}

/// Run the binary with the standard auth+url args plumbed through to a
/// wiremock URI. `extra_args` is appended after the base flags. `env`
/// is applied as additional process env on top of the inherited
/// environment.
fn run_cmd(
    cwd: &Path,
    api_url: &str,
    subcommand: &str,
    extra_args: &[&str],
    extra_env: &[(&str, &str)],
) -> (i32, String, String) {
    let mut args = vec![
        subcommand,
        "--json",
        "--api-url",
        api_url,
        "--api-token",
        "fake-token-for-test",
        "--org",
        ORG_SLUG,
    ];
    args.extend_from_slice(extra_args);
    let mut cmd = Command::new(binary());
    cmd.args(&args).current_dir(cwd);
    // Default: disable the test-environment short-circuit
    // (`is_telemetry_disabled()` flips on `VITEST=true`).
    cmd.env_remove("VITEST");
    cmd.env_remove("SOCKET_TELEMETRY_DISABLED");
    cmd.env_remove("SOCKET_PATCH_TELEMETRY_DISABLED");
    cmd.env_remove("SOCKET_OFFLINE");
    // `send_telemetry_event` reads SOCKET_API_URL from the environment
    // directly (not the clap arg), so pointing it at the mock here is
    // how the telemetry POST also lands on our recorder.
    cmd.env("SOCKET_API_URL", api_url);
    cmd.env("SOCKET_PROXY_URL", api_url);
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("run socket-patch");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

/// Count POSTs the wiremock server received against the telemetry
/// path, optionally narrowed to a specific `event_type` in the body.
async fn telemetry_post_count(mock: &MockServer, event_type: Option<&str>) -> usize {
    let received = mock
        .received_requests()
        .await
        .expect("wiremock allows recording");
    received
        .iter()
        .filter(|req| {
            req.method == wiremock::http::Method::POST
                && req
                    .url
                    .path()
                    .ends_with(&format!("/v0/orgs/{ORG_SLUG}/telemetry"))
        })
        .filter(|req| match event_type {
            None => true,
            Some(want) => match serde_json::from_slice::<serde_json::Value>(&req.body) {
                Ok(v) => v.get("event_type").and_then(|t| t.as_str()) == Some(want),
                Err(_) => false,
            },
        })
        .count()
}

/// Standard wiremock surface for the scan/get/telemetry endpoints.
/// `batch_response`/`fetch_response` are stubbed bodies; `telemetry`
/// always returns 201. Returns the mock server so the test can call
/// `received_requests()` after invocation.
async fn setup_mock(
    batch_response: serde_json::Value,
    fetch_uuid_response: Option<serde_json::Value>,
) -> MockServer {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(batch_response))
        .mount(&mock)
        .await;
    if let Some(body) = fetch_uuid_response {
        // Match the real fetch_patch endpoint:
        // GET /v0/orgs/{slug}/patches/view/{uuid}. (An earlier version of
        // this regex omitted the `view/` segment, so it never matched and
        // the "success" test silently exercised the not_found failure path.)
        Mock::given(method("GET"))
            .and(wiremock::matchers::path_regex(format!(
                "^/v0/orgs/{ORG_SLUG}/patches/view/[0-9a-f-]+$"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&mock)
            .await;
    }
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/telemetry")))
        .respond_with(ResponseTemplate::new(201))
        .mount(&mock)
        .await;
    mock
}

// ---------------------------------------------------------------------------
// scan
// ---------------------------------------------------------------------------

#[tokio::test]
async fn scan_emits_patch_scanned_telemetry_on_success() {
    let mock = setup_mock(
        serde_json::json!({ "packages": [], "canAccessPaidPatches": false }),
        None,
    )
    .await;

    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "minimist", "1.2.2");

    let (code, _stdout, _stderr) = run_cmd(tmp.path(), &mock.uri(), "scan", &[], &[]);
    assert_eq!(code, 0);

    let count = telemetry_post_count(&mock, Some("patch_scanned")).await;
    assert_eq!(
        count, 1,
        "scan must POST exactly one patch_scanned telemetry event"
    );
    // The batch succeeded (200), so no failure event may be emitted —
    // guards against a regression that fires both the success and the
    // all-batches-failed event.
    let failed = telemetry_post_count(&mock, Some("patch_scan_failed")).await;
    assert_eq!(failed, 0, "successful scan must not POST patch_scan_failed");
    // Prove the scan actually queried the batch endpoint (not a vacuous
    // pass on an empty crawl).
    let batch_hits = mock
        .received_requests()
        .await
        .expect("recording enabled")
        .iter()
        .filter(|r| {
            r.method == wiremock::http::Method::POST
                && r.url.path().ends_with(&format!("/v0/orgs/{ORG_SLUG}/patches/batch"))
        })
        .count();
    assert!(batch_hits >= 1, "scan must POST to the patches/batch endpoint");
}

#[tokio::test]
async fn scan_skips_telemetry_in_airgap_mode() {
    let mock = setup_mock(
        serde_json::json!({ "packages": [], "canAccessPaidPatches": false }),
        None,
    )
    .await;

    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "minimist", "1.2.2");

    let (code, stdout, stderr) =
        run_cmd(tmp.path(), &mock.uri(), "scan", &[], &[("SOCKET_OFFLINE", "1")]);

    // Guard against a vacuous pass: prove scan actually ran its body (it
    // crawled node_modules and reported the one package) rather than
    // crashing before the telemetry-suppression point, which would also
    // yield zero POSTs.
    assert_eq!(code, 0, "offline scan must still succeed; stderr={stderr}");
    let v: serde_json::Value =
        serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("scan stdout not JSON: {e}\n{stdout}"));
    assert_eq!(v["status"], "success", "offline scan status; stdout={stdout}");
    assert_eq!(v["scannedPackages"], 1, "offline scan must crawl the one package; stdout={stdout}");

    let count = telemetry_post_count(&mock, None).await;
    assert_eq!(
        count, 0,
        "SOCKET_OFFLINE=1 must suppress every telemetry POST during scan"
    );
}

// ---------------------------------------------------------------------------
// get (UUID path)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_emits_patch_fetched_telemetry_on_uuid_lookup_success() {
    const UUID: &str = "12345678-1234-4123-8123-123456789abc";
    let patch_response = serde_json::json!({
        "uuid": UUID,
        "purl": "pkg:npm/lodash@4.17.20",
        "tier": "free",
        "publishedAt": "2024-06-01T00:00:00Z",
        "license": "MIT",
        "description": "test patch",
        "files": {},
        "vulnerabilities": {},
    });
    let mock = setup_mock(
        serde_json::json!({ "packages": [], "canAccessPaidPatches": false }),
        Some(patch_response),
    )
    .await;

    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "lodash", "4.17.20");

    let (code, stdout, stderr) = run_cmd(
        tmp.path(),
        &mock.uri(),
        "get",
        &["--id", UUID],
        &[],
    );

    // The mock serves the patch on the real `patches/view/{uuid}` endpoint,
    // so this is a genuine SUCCESS: get must fire exactly one
    // `patch_fetched` event and zero `patch_fetch_failed` events. (A
    // disjoint "fetched OR failed >= 1" assert would silently pass on the
    // not_found failure path — which is what happened while the mock regex
    // omitted the `view/` segment.)
    assert_eq!(
        code, 0,
        "get --id of a served free patch must exit 0 (stdout={stdout} stderr={stderr})"
    );
    let fetched = telemetry_post_count(&mock, Some("patch_fetched")).await;
    let failed = telemetry_post_count(&mock, Some("patch_fetch_failed")).await;
    assert_eq!(
        fetched, 1,
        "get --id UUID success must POST exactly one patch_fetched event \
         (saw fetched={fetched} failed={failed}); stdout={stdout}"
    );
    assert_eq!(
        failed, 0,
        "get --id UUID success must NOT POST any patch_fetch_failed event \
         (saw fetched={fetched} failed={failed}); stdout={stdout}"
    );
    // Prove the mock actually served the patch (i.e. the view endpoint was
    // matched), so patch_fetched reflects a real fetch rather than a stub.
    let received = mock.received_requests().await.expect("recording enabled");
    let view_hits = received
        .iter()
        .filter(|r| {
            r.method == wiremock::http::Method::GET
                && r.url.path().contains(&format!("/v0/orgs/{ORG_SLUG}/patches/view/"))
        })
        .count();
    assert!(
        view_hits >= 1,
        "get must GET the patches/view/{{uuid}} endpoint; saw paths: {:?}",
        received.iter().map(|r| r.url.path().to_string()).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn get_skips_telemetry_in_airgap_mode() {
    const UUID: &str = "deadbeef-dead-4eef-8eef-deadbeefdead";
    let mock = setup_mock(
        serde_json::json!({ "packages": [], "canAccessPaidPatches": false }),
        Some(serde_json::json!({
            "uuid": UUID,
            "purl": "pkg:npm/lodash@4.17.20",
            "tier": "free",
            "publishedAt": "2024-06-01T00:00:00Z",
            "license": "MIT",
            "description": "test patch",
            "files": {},
            "vulnerabilities": {},
        })),
    )
    .await;

    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "lodash", "4.17.20");

    let (_code, stdout, _stderr) = run_cmd(
        tmp.path(),
        &mock.uri(),
        "get",
        &["--id", UUID],
        &[("SOCKET_OFFLINE", "1")],
    );

    // Anti-vacuous guard: get must have reached the fetch step (it queries
    // the view endpoint regardless of airgap) — proving it ran far enough
    // to hit the telemetry-suppression point. A crash before that would
    // also produce zero telemetry POSTs and falsely "pass".
    let received = mock.received_requests().await.expect("recording enabled");
    let view_hits = received
        .iter()
        .filter(|r| {
            r.method == wiremock::http::Method::GET
                && r.url.path().contains(&format!("/v0/orgs/{ORG_SLUG}/patches/view/"))
        })
        .count();
    assert!(
        view_hits >= 1,
        "offline get must still query the view endpoint; saw paths: {:?}; stdout={stdout}",
        received.iter().map(|r| r.url.path().to_string()).collect::<Vec<_>>()
    );

    let count = telemetry_post_count(&mock, None).await;
    assert_eq!(
        count, 0,
        "SOCKET_OFFLINE=1 must suppress every telemetry POST during get"
    );
}

// ---------------------------------------------------------------------------
// apply — exercises an empty manifest path that exits early but still
// fires `track_patch_applied` (or, in airgap mode, suppresses it)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn apply_skips_telemetry_in_airgap_mode() {
    let mock = setup_mock(
        serde_json::json!({ "packages": [], "canAccessPaidPatches": false }),
        None,
    )
    .await;

    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    // Create a no-patches manifest so apply has nothing to do but still
    // runs the command body (and would normally fire telemetry).
    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    std::fs::write(
        socket.join("manifest.json"),
        r#"{"patches":{}}"#,
    )
    .unwrap();

    let (_code, stdout, _stderr) = run_cmd(
        tmp.path(),
        &mock.uri(),
        "apply",
        &[],
        &[("SOCKET_OFFLINE", "1")],
    );

    // Anti-vacuous guard: apply must have run its command body and emitted
    // its JSON result envelope (with a summary), proving the suppression
    // wasn't a side effect of an early crash. (Apply on an empty manifest
    // currently reports partialFailure — a separately tracked design gap —
    // so we assert on the envelope shape, not the status string.)
    let v: serde_json::Value =
        serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("apply stdout not JSON: {e}\n{stdout}"));
    assert_eq!(v["command"], "apply", "apply must emit its command envelope; stdout={stdout}");
    assert!(v.get("summary").is_some(), "apply envelope must carry a summary; stdout={stdout}");

    let count = telemetry_post_count(&mock, None).await;
    assert_eq!(
        count, 0,
        "SOCKET_OFFLINE=1 must suppress patch_applied telemetry"
    );
}

// ---------------------------------------------------------------------------
// list — local-only command; telemetry should still flow when enabled
// and stay quiet when airgap is set.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_emits_patch_listed_telemetry_when_telemetry_enabled() {
    let mock = setup_mock(
        serde_json::json!({ "packages": [], "canAccessPaidPatches": false }),
        None,
    )
    .await;

    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    std::fs::write(
        socket.join("manifest.json"),
        r#"{"patches":{}}"#,
    )
    .unwrap();

    let (code, _stdout, _stderr) = run_cmd(tmp.path(), &mock.uri(), "list", &[], &[]);
    assert_eq!(code, 0);

    let count = telemetry_post_count(&mock, Some("patch_listed")).await;
    assert_eq!(count, 1, "list must POST exactly one patch_listed event");
}

// ---------------------------------------------------------------------------
// Fallback: 401/403 from the auth endpoint downgrades to public proxy.
// ---------------------------------------------------------------------------

/// Spin up two mock servers: one returns 401 on `/v0/orgs/{slug}/patches/batch`
/// (the auth endpoint), the other serves the public proxy (per-package GETs
/// at `/patch/by-package/{purl}`). After the fallback, scan must succeed
/// against the proxy and emit a `patch_scanned` event tagged
/// `fallback_to_proxy: true` in its metadata.
#[tokio::test]
async fn scan_falls_back_to_proxy_on_401_and_tags_telemetry() {
    let auth_mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/batch")))
        .respond_with(ResponseTemplate::new(401).set_body_string("invalid token"))
        .mount(&auth_mock)
        .await;
    // Telemetry POST from the auth-mode try lands here (auth client
    // still has token+slug at the moment the telemetry endpoint is
    // chosen — but with `fallback_to_proxy: true` in the body once we
    // re-enter telemetry after the swap).
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/telemetry")))
        .respond_with(ResponseTemplate::new(201))
        .mount(&auth_mock)
        .await;

    let proxy_mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(wiremock::matchers::path_regex(r"^/patch/by-package/.*$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [],
            "canAccessPaidPatches": false,
        })))
        .mount(&proxy_mock)
        .await;

    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "minimist", "1.2.2");

    // Auth URL → 401 mock. Proxy URL → success mock.
    let (code, _stdout, stderr) = run_cmd(
        tmp.path(),
        &auth_mock.uri(),
        "scan",
        &[],
        &[("SOCKET_PROXY_URL", &proxy_mock.uri())],
    );
    assert_eq!(code, 0, "scan must succeed after falling back to proxy");
    assert!(
        stderr.contains("falling back to public patch API proxy"),
        "stderr must carry the fallback warning; got: {stderr}"
    );
    // The retry must actually reach the proxy — otherwise the fallback
    // "succeeded" only because the crawl was empty.
    let proxy_hits = proxy_mock
        .received_requests()
        .await
        .expect("recording enabled")
        .iter()
        .filter(|r| {
            r.method == wiremock::http::Method::GET && r.url.path().starts_with("/patch/by-package/")
        })
        .count();
    assert!(
        proxy_hits >= 1,
        "fallback must query the proxy by-package endpoint"
    );

    // The post-fallback telemetry POST must include `fallback_to_proxy: true`.
    let received = auth_mock
        .received_requests()
        .await
        .expect("recording enabled");
    let telemetry_bodies: Vec<serde_json::Value> = received
        .iter()
        .filter(|r| {
            r.method == wiremock::http::Method::POST
                && r.url
                    .path()
                    .ends_with(&format!("/v0/orgs/{ORG_SLUG}/telemetry"))
        })
        .filter_map(|r| serde_json::from_slice(&r.body).ok())
        .collect();
    let scanned = telemetry_bodies
        .iter()
        .find(|v| v.get("event_type").and_then(|t| t.as_str()) == Some("patch_scanned"))
        .expect("a patch_scanned event must reach the recorder");
    assert_eq!(
        scanned["metadata"]["fallback_to_proxy"],
        serde_json::Value::Bool(true),
        "fallback must be reflected in telemetry metadata; got {scanned}"
    );
}

/// 404/5xx must NOT trigger fallback — they surface as scan errors so
/// upstream backend issues stay visible. Guards against an
/// over-eager classifier.
#[tokio::test]
async fn scan_does_not_fall_back_on_500() {
    let auth_mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/batch")))
        .respond_with(ResponseTemplate::new(500).set_body_string("backend on fire"))
        .mount(&auth_mock)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/telemetry")))
        .respond_with(ResponseTemplate::new(201))
        .mount(&auth_mock)
        .await;

    // Proxy mock that would accept the call if fallback fired. We
    // assert below that it receives ZERO requests, proving no
    // fallback happened.
    let proxy_mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(wiremock::matchers::path_regex(r"^/patch/by-package/.*$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [],
            "canAccessPaidPatches": false,
        })))
        .mount(&proxy_mock)
        .await;

    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "minimist", "1.2.2");

    let (_code, _stdout, stderr) = run_cmd(
        tmp.path(),
        &auth_mock.uri(),
        "scan",
        &[],
        &[("SOCKET_PROXY_URL", &proxy_mock.uri())],
    );
    assert!(
        !stderr.contains("falling back"),
        "5xx must NOT trigger fallback; stderr was: {stderr}"
    );
    // Prove the auth batch endpoint was actually exercised (returned 500),
    // so the zero-proxy-hits assertion below isn't a vacuous pass caused by
    // an empty crawl that never queried anything at all.
    let auth_batch_hits = auth_mock
        .received_requests()
        .await
        .expect("recording enabled")
        .iter()
        .filter(|r| {
            r.method == wiremock::http::Method::POST
                && r.url.path().ends_with(&format!("/v0/orgs/{ORG_SLUG}/patches/batch"))
        })
        .count();
    assert!(
        auth_batch_hits >= 1,
        "scan must have queried the auth batch endpoint (which returned 500)"
    );
    let proxy_hits = proxy_mock
        .received_requests()
        .await
        .expect("recording enabled")
        .len();
    assert_eq!(
        proxy_hits, 0,
        "proxy must not be queried after a 500 from the auth endpoint"
    );
}

#[tokio::test]
async fn list_skips_telemetry_in_airgap_mode() {
    let mock = setup_mock(
        serde_json::json!({ "packages": [], "canAccessPaidPatches": false }),
        None,
    )
    .await;

    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    std::fs::write(
        socket.join("manifest.json"),
        r#"{"patches":{}}"#,
    )
    .unwrap();

    let (code, stdout, stderr) = run_cmd(
        tmp.path(),
        &mock.uri(),
        "list",
        &[],
        &[("SOCKET_OFFLINE", "1")],
    );

    // Anti-vacuous guard: list must have run to a successful completion
    // (it's a local command) rather than crashing before the telemetry
    // decision, which would also yield zero POSTs.
    assert_eq!(code, 0, "offline list must succeed; stderr={stderr}");
    let v: serde_json::Value =
        serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("list stdout not JSON: {e}\n{stdout}"));
    assert_eq!(v["command"], "list", "list must emit its command envelope; stdout={stdout}");
    assert_eq!(v["status"], "success", "offline list status; stdout={stdout}");

    let count = telemetry_post_count(&mock, None).await;
    assert_eq!(count, 0, "SOCKET_OFFLINE=1 must suppress patch_listed");
}
