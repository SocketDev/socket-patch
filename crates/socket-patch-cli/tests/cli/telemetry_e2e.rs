//! End-to-end coverage that the `track_patch_*` instrumentation actually
//! fires HTTP POSTs against the configured telemetry endpoint for the
//! apply/scan/get commands, that `SOCKET_OFFLINE=1` (airgap mode)
//! suppresses every one of them, and that telemetry never holds a command
//! back: output comes first, and an endpoint that stalls costs only the
//! short exit grace.
//!
//! Wiremock fronts both the patches endpoints (so scan/get succeed)
//! and the telemetry endpoint (so we can assert the POST shape +
//! count). Each test runs the released binary in a tempdir against
//! the mock URI.

use crate::common::{binary, hermetic_command};

use std::path::Path;
use std::process::Command;

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG_SLUG: &str = "telemetry-test-org";

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
    let out = build_cmd(cwd, api_url, subcommand, extra_args, extra_env)
        .output()
        .expect("run socket-patch");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

/// [`run_cmd`] without `--json`: the output a person gets.
fn run_human(
    cwd: &Path,
    api_url: &str,
    subcommand: &str,
    extra_args: &[&str],
) -> (i32, String, String) {
    let out = build_cmd_as(cwd, api_url, subcommand, false, extra_args, &[])
        .output()
        .expect("run socket-patch");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

/// The [`run_cmd`] invocation, unstarted (for tests that wire its stdio).
fn build_cmd(
    cwd: &Path,
    api_url: &str,
    subcommand: &str,
    extra_args: &[&str],
    extra_env: &[(&str, &str)],
) -> Command {
    build_cmd_as(cwd, api_url, subcommand, true, extra_args, extra_env)
}

/// [`build_cmd`], with `--json` or without.
fn build_cmd_as(
    cwd: &Path,
    api_url: &str,
    subcommand: &str,
    json: bool,
    extra_args: &[&str],
    extra_env: &[(&str, &str)],
) -> Command {
    let mut args = vec![subcommand];
    if json {
        args.push("--json");
    }
    args.extend_from_slice(&[
        "--api-url",
        api_url,
        "--api-token",
        "fake-token-for-test",
        "--org",
        ORG_SLUG,
    ]);
    args.extend_from_slice(extra_args);
    // The binary binds a wide `SOCKET_*` env surface; an ambient value
    // silently changes what these tests exercise — SOCKET_ECOSYSTEMS=cargo
    // makes scan skip the npm fixture (scannedPackages 0), SOCKET_CWD aims
    // the crawl outside the tempdir, SOCKET_GLOBAL flips to global mode. The
    // hermetic builder scrubs all of them.
    let mut cmd = hermetic_command(&binary());
    cmd.args(&args).current_dir(cwd);
    // This suite's entire point is asserting telemetry POSTs against a
    // local wiremock, so undo the builder's forced opt-out (an opted-out
    // dev shell must not vacuously green the count-0 asserts), and disable
    // the test-environment short-circuit (`is_telemetry_disabled()` flips
    // on `VITEST=true`).
    cmd.env_remove("VITEST");
    cmd.env_remove("SOCKET_TELEMETRY_DISABLED");
    // An ambient VIRTUAL_ENV hijacks the python crawler (its site-packages
    // get crawled as project packages), breaking the exact
    // `scannedPackages` oracles below.
    cmd.env_remove("VIRTUAL_ENV");
    // `send_telemetry_event` reads SOCKET_API_URL from the environment
    // directly (not the clap arg), so pointing it at the mock here is
    // how the telemetry POST also lands on our recorder.
    cmd.env("SOCKET_API_URL", api_url);
    cmd.env("SOCKET_PROXY_URL", api_url);
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd
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
                && r.url
                    .path()
                    .ends_with(&format!("/v0/orgs/{ORG_SLUG}/patches/batch"))
        })
        .count();
    assert!(
        batch_hits >= 1,
        "scan must POST to the patches/batch endpoint"
    );
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

    let (code, stdout, stderr) = run_cmd(
        tmp.path(),
        &mock.uri(),
        "scan",
        &[],
        &[("SOCKET_OFFLINE", "1")],
    );

    // Strict airgap (CLI_CONTRACT.md `--offline`: "never contact the
    // network — operations that need remote data fail loudly"): scan's
    // patch discovery IS remote data, so offline scan must refuse loudly
    // up front instead of POSTing the crawled package inventory to the
    // batch endpoint. The error envelope doubles as the anti-vacuous
    // guard — a crash before the offline gate would exit nonzero too,
    // but couldn't emit the refusal envelope.
    assert_eq!(
        code, 1,
        "offline scan must fail loudly; stdout={stdout} stderr={stderr}"
    );
    let v: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("scan stdout not JSON: {e}\n{stdout}"));
    assert_eq!(
        v["status"], "error",
        "offline scan must report an error envelope; stdout={stdout}"
    );
    assert!(
        v["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("offline"),
        "offline scan's error must name the offline gate; stdout={stdout}"
    );

    // The airgap core: ZERO requests of any kind — no batch POST (which
    // would exfiltrate the crawled package inventory), no telemetry.
    let received = mock.received_requests().await.expect("recording enabled");
    assert!(
        received.is_empty(),
        "SOCKET_OFFLINE=1 must suppress every network request during scan; saw: {:?}",
        received
            .iter()
            .map(|r| format!("{} {}", r.method, r.url.path()))
            .collect::<Vec<_>>()
    );
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
        // A recordable new-file patch (afterHash is the git-blob sha256 of
        // the decoded blobContent "patched\n"). A patch whose
        // applicable-files map is empty is a hard failure ("no applicable
        // files"), so the success path this test asserts needs a real file.
        "files": {
            "package/index.js": {
                "afterHash": "d2802877eb1c2f442d30d18abcb281cb2830875571624544f2f1acb36480997e",
                "blobContent": "cGF0Y2hlZAo=",
            }
        },
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

    let (code, stdout, stderr) = run_cmd(tmp.path(), &mock.uri(), "get", &["--id", UUID], &[]);

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
                && r.url
                    .path()
                    .contains(&format!("/v0/orgs/{ORG_SLUG}/patches/view/"))
        })
        .count();
    assert!(
        view_hits >= 1,
        "get must GET the patches/view/{{uuid}} endpoint; saw paths: {:?}",
        received
            .iter()
            .map(|r| r.url.path().to_string())
            .collect::<Vec<_>>()
    );
}

/// A `get` for a patch that does not exist reports the failure with the
/// code its `--json` output carries, like every other failure event.
#[tokio::test]
async fn get_of_an_unknown_patch_reports_not_found() {
    const UUID: &str = "12345678-1234-4123-8123-123456789abc";
    // No view endpoint is mounted: the lookup is a 404.
    let mock = setup_mock(
        serde_json::json!({ "packages": [], "canAccessPaidPatches": false }),
        None,
    )
    .await;
    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());

    let (_code, stdout, stderr) = run_cmd(tmp.path(), &mock.uri(), "get", &["--id", UUID], &[]);
    let bodies = telemetry_bodies(&mock).await;
    assert_eq!(
        bodies.len(),
        1,
        "stdout:\n{stdout}\nstderr:\n{stderr}\n{bodies:#?}"
    );
    let failed = &bodies[0];
    assert_eq!(failed["event_type"], "patch_fetch_failed");
    assert_eq!(failed["metadata"]["error_code"], "not_found");
    assert_eq!(failed["metadata"]["uuid"], UUID);
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

    let (code, stdout, stderr) = run_cmd(
        tmp.path(),
        &mock.uri(),
        "get",
        &["--id", UUID],
        &[("SOCKET_OFFLINE", "1")],
    );

    // Strict airgap (CLI_CONTRACT.md `--offline`: "never contact the
    // network — operations that need remote data fail loudly"): every
    // `get` mode fetches remote patch data, so offline get must refuse
    // loudly before touching the view endpoint. The error envelope is
    // the anti-vacuous guard — a crash before the offline gate exits
    // nonzero too, but couldn't emit the refusal envelope.
    assert_eq!(
        code, 1,
        "offline get must fail loudly; stdout={stdout} stderr={stderr}"
    );
    let v: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("get stdout not JSON: {e}\n{stdout}"));
    assert_eq!(
        v["status"], "error",
        "offline get must report an error envelope; stdout={stdout}"
    );
    assert!(
        v["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("offline"),
        "offline get's error must name the offline gate; stdout={stdout}"
    );

    // The airgap core: ZERO requests of any kind — no view GET, no
    // telemetry.
    let received = mock.received_requests().await.expect("recording enabled");
    assert!(
        received.is_empty(),
        "SOCKET_OFFLINE=1 must suppress every network request during get; saw: {:?}",
        received
            .iter()
            .map(|r| format!("{} {}", r.method, r.url.path()))
            .collect::<Vec<_>>()
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
    std::fs::write(socket.join("manifest.json"), r#"{"patches":{}}"#).unwrap();

    let (_code, stdout, _stderr) = run_cmd(
        tmp.path(),
        &mock.uri(),
        "apply",
        &[],
        &[("SOCKET_OFFLINE", "1")],
    );

    // Anti-vacuous guard: apply must have run its command body and emitted
    // its JSON result envelope (with a summary), proving the suppression
    // wasn't a side effect of an early crash.
    let v: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("apply stdout not JSON: {e}\n{stdout}"));
    assert_eq!(
        v["command"], "apply",
        "apply must emit its command envelope; stdout={stdout}"
    );
    assert!(
        v.get("summary").is_some(),
        "apply envelope must carry a summary; stdout={stdout}"
    );

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
    std::fs::write(socket.join("manifest.json"), r#"{"patches":{}}"#).unwrap();

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
            r.method == wiremock::http::Method::GET
                && r.url.path().starts_with("/patch/by-package/")
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
                && r.url
                    .path()
                    .ends_with(&format!("/v0/orgs/{ORG_SLUG}/patches/batch"))
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
    std::fs::write(socket.join("manifest.json"), r#"{"patches":{}}"#).unwrap();

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
    let v: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("list stdout not JSON: {e}\n{stdout}"));
    assert_eq!(
        v["command"], "list",
        "list must emit its command envelope; stdout={stdout}"
    );
    assert_eq!(
        v["status"], "success",
        "offline list status; stdout={stdout}"
    );

    let count = telemetry_post_count(&mock, None).await;
    assert_eq!(count, 0, "SOCKET_OFFLINE=1 must suppress patch_listed");
}

// ---------------------------------------------------------------------------
// scan: sends still in flight get the exit grace
// ---------------------------------------------------------------------------

/// Telemetry is sent beside the command, and the exit gives a send still
/// in flight its grace to finish. Against a telemetry endpoint that
/// answers only after `TELEMETRY_DELAY` — inside the grace this harness
/// lifts — each scan terminal (success, empty crawl, all-batches-failed)
/// must deliver exactly its one event AND stay alive until the response
/// arrives (the lower bound on wall time cannot flake under load: load
/// only makes a run slower). The production grace is pinned by
/// `a_stalled_telemetry_endpoint_costs_only_the_exit_grace`.
#[tokio::test]
async fn scan_waits_out_the_exit_grace_for_telemetry_in_flight() {
    const TELEMETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(1500);

    struct Case {
        label: &'static str,
        batch_status: u16,
        install_package: bool,
        want_event: &'static str,
        want_code: i32,
    }
    let cases = [
        Case {
            label: "success",
            batch_status: 200,
            install_package: true,
            want_event: "patch_scanned",
            want_code: 0,
        },
        Case {
            label: "empty crawl",
            batch_status: 200,
            install_package: false,
            want_event: "patch_scanned",
            want_code: 0,
        },
        Case {
            label: "all batches failed",
            batch_status: 500,
            install_package: true,
            want_event: "patch_scan_failed",
            want_code: 1,
        },
    ];

    for case in cases {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/batch")))
            .respond_with(ResponseTemplate::new(case.batch_status).set_body_json(
                serde_json::json!({ "packages": [], "canAccessPaidPatches": false }),
            ))
            .mount(&mock)
            .await;
        Mock::given(method("POST"))
            .and(path(format!("/v0/orgs/{ORG_SLUG}/telemetry")))
            .respond_with(ResponseTemplate::new(201).set_delay(TELEMETRY_DELAY))
            .mount(&mock)
            .await;

        let tmp = tempfile::tempdir().expect("tempdir");
        write_root_package_json(tmp.path());
        if case.install_package {
            write_npm_package(tmp.path(), "minimist", "1.2.2");
        }

        let started = std::time::Instant::now();
        let (code, stdout, stderr) = run_cmd(tmp.path(), &mock.uri(), "scan", &[], &[]);
        let elapsed = started.elapsed();
        assert_eq!(
            code, case.want_code,
            "{}: stdout={stdout} stderr={stderr}",
            case.label
        );
        assert_eq!(
            telemetry_post_count(&mock, Some(case.want_event)).await,
            1,
            "{}: exactly one {} event must be delivered",
            case.label,
            case.want_event
        );
        assert_eq!(
            telemetry_post_count(&mock, None).await,
            1,
            "{}: no other telemetry event",
            case.label
        );
        assert!(
            elapsed >= TELEMETRY_DELAY,
            "{}: scan exited after {elapsed:?}, before its telemetry send completed",
            case.label
        );
    }
}

// ---------------------------------------------------------------------------
// hosted mode (the v5 `scan` default)
// ---------------------------------------------------------------------------

const HOSTED_NAME: &str = "telemetry-hosted";
const HOSTED_PURL: &str = "pkg:npm/telemetry-hosted@1.0.0";
const HOSTED_UUID: &str = "11111111-1111-4111-8111-111111111111";
const HOSTED_URL: &str = "https://patch.socket.dev/patch/npm/telemetry-hosted/1.0.0/22222222-2222-4222-8222-222222222222/11111111-1111-4111-8111-111111111111/telemetry-hosted-1.0.0.tgz";

/// An npm project whose lockfile resolves [`HOSTED_NAME`] upstream (the
/// `scan/hosted_fixture.rs` `write_npm_project` shape).
fn write_hosted_npm_project(root: &Path) {
    std::fs::write(
        root.join("package.json"),
        format!(
            r#"{{ "name": "consumer", "version": "0.0.0", "dependencies": {{ "{HOSTED_NAME}": "1.0.0" }} }}"#
        ),
    )
    .unwrap();
    write_npm_package(root, HOSTED_NAME, "1.0.0");
    std::fs::write(
        root.join("package-lock.json"),
        format!(
            r#"{{
  "name": "consumer",
  "version": "0.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {{
    "": {{ "name": "consumer", "version": "0.0.0", "dependencies": {{ "{HOSTED_NAME}": "1.0.0" }} }},
    "node_modules/{HOSTED_NAME}": {{
      "version": "1.0.0",
      "resolved": "https://registry.npmjs.org/{HOSTED_NAME}/-/{HOSTED_NAME}-1.0.0.tgz",
      "integrity": "sha512-UPSTREAMupstream=="
    }}
  }}
}}
"#
        ),
    )
    .unwrap();
}

/// The API surface a hosted scan of [`write_hosted_npm_project`] reads:
/// batch discovery, the per-package search, the reference grant (answered
/// with `reference_status`) and the patch record. Telemetry answers 201.
async fn setup_hosted_mock(reference_status: u16) -> MockServer {
    let batch = serde_json::json!({
        "packages": [{
            "purl": HOSTED_PURL,
            "patches": [{
                "uuid": HOSTED_UUID, "purl": HOSTED_PURL, "tier": "free",
                "cveIds": [], "ghsaIds": [], "severity": "high",
                "title": "telemetry hosted fixture"
            }]
        }],
        "canAccessPaidPatches": false,
    });
    let mock = setup_mock(batch, None).await;
    Mock::given(method("GET"))
        .and(wiremock::matchers::path_regex(format!(
            "^/v0/orgs/{ORG_SLUG}/patches/by-package/.+$"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [{
                "uuid": HOSTED_UUID, "purl": HOSTED_PURL,
                "publishedAt": "2024-01-01T00:00:00Z",
                "description": "x", "license": "MIT", "tier": "free",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(&mock)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/package")))
        .respond_with(
            ResponseTemplate::new(reference_status).set_body_json(serde_json::json!({
                "results": {
                    HOSTED_UUID: {
                        "status": "granted",
                        "url": HOSTED_URL,
                        "purl": HOSTED_PURL,
                        "artifacts": [{
                            "kind": "tarball",
                            "url": HOSTED_URL,
                            "integrity": { "sha512": "sha512-PATCHEDpatchedPATCHEDpatched0123456789==" }
                        }],
                        "registryOverride": null
                    }
                }
            })),
        )
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path(format!(
            "/v0/orgs/{ORG_SLUG}/patches/view/{HOSTED_UUID}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": HOSTED_UUID,
            "purl": HOSTED_PURL,
            "publishedAt": "2024-01-01T00:00:00Z",
            "files": {},
            "vulnerabilities": {},
            "description": "x", "license": "MIT", "tier": "free"
        })))
        .mount(&mock)
        .await;
    mock
}

/// Every telemetry body the mock received, in the order the events fired.
/// Sends run side by side, so arrival order is not firing order: the
/// bodies are sorted by the timestamp each event was built with (a stable
/// sort, so events of the same millisecond keep their arrival order).
async fn telemetry_bodies(mock: &MockServer) -> Vec<serde_json::Value> {
    let mut bodies: Vec<serde_json::Value> = mock
        .received_requests()
        .await
        .expect("wiremock allows recording")
        .iter()
        .filter(|req| {
            req.url
                .path()
                .ends_with(&format!("/v0/orgs/{ORG_SLUG}/telemetry"))
        })
        .map(|req| serde_json::from_slice(&req.body).expect("telemetry body is JSON"))
        .collect();
    bodies.sort_by_key(|body| {
        body["event_sender_created_at"]
            .as_str()
            .expect("every event is timestamped")
            .to_string()
    });
    bodies
}

/// v5's default `scan` pins patched dependencies to the hosted patch
/// server. That IS the patch adoption, so besides `patch_scanned` (with
/// the ecosystems the crawl found) it reports `patch_applied` tagged
/// `mode: "hosted"` — the event the backend's adoption views count.
#[tokio::test]
async fn hosted_scan_reports_patch_applied_with_hosted_mode() {
    let mock = setup_hosted_mock(200).await;
    let tmp = tempfile::tempdir().expect("tempdir");
    write_hosted_npm_project(tmp.path());

    let (code, stdout, stderr) = run_cmd(tmp.path(), &mock.uri(), "scan", &[], &[]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    let lock = std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap();
    assert!(lock.contains(HOSTED_URL), "the lockfile is pinned: {lock}");
    let doc: serde_json::Value = serde_json::from_str(&stdout).expect("JSON envelope");

    let bodies = telemetry_bodies(&mock).await;
    let types: Vec<&str> = bodies
        .iter()
        .map(|b| b["event_type"].as_str().unwrap())
        .collect();
    assert_eq!(types, ["patch_scanned", "patch_applied"], "{bodies:#?}");

    let scanned = &bodies[0];
    assert_eq!(
        scanned["metadata"]["ecosystems"],
        serde_json::json!(["npm"])
    );
    // Default mode, on a project nothing is wired into yet.
    assert_eq!(scanned["metadata"]["mode"], "hosted");
    assert_eq!(scanned["metadata"]["project_modes"], serde_json::json!([]));
    assert_eq!(scanned["metadata"]["free_patches"], 1);

    let applied = &bodies[1];
    assert_eq!(applied["context"]["command"], "scan");
    assert_eq!(applied["metadata"]["mode"], "hosted");
    // The pin is named: by patch UUID, never by package.
    assert_eq!(
        only_patch(applied),
        &serde_json::json!({
            "uuid": HOSTED_UUID,
            "ecosystem": "npm",
            "mode": "hosted",
            "outcome": "applied",
        })
    );
    // v5.0 records each confirmed pin as an `applied` event tagged
    // `details.mode: "hosted"` (v4's `redirect.redirected` count).
    let hosted_applied = doc["events"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|e| e["details"]["mode"] == "hosted" && e["action"] == "applied")
        .count();
    assert_eq!(
        applied["metadata"]["patches_count"], hosted_applied,
        "patches_count is the envelope's hosted applied events: {doc:#}"
    );
    assert_eq!(applied["metadata"]["patches_count"], 1);
    assert_eq!(
        applied["metadata"]["files_count"],
        doc["redirect"]["rewrittenFiles"].as_array().unwrap().len(),
        "files_count is the envelope's rewrittenFiles: {doc:#}"
    );
    assert_eq!(applied["metadata"]["dry_run"], false);
    assert_eq!(
        applied["session_id"], scanned["session_id"],
        "one run, one session"
    );

    // A re-scan sees the hosted pins the first run wrote.
    let (code, stdout, stderr) = run_cmd(tmp.path(), &mock.uri(), "scan", &[], &[]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    let bodies = telemetry_bodies(&mock).await;
    let rescanned = bodies
        .iter()
        .filter(|b| b["event_type"] == "patch_scanned")
        .nth(1)
        .expect("the re-scan's patch_scanned");
    assert_eq!(
        rescanned["metadata"]["project_modes"],
        serde_json::json!(["hosted"])
    );
    assert_ne!(rescanned["session_id"], scanned["session_id"]);
}

/// `patch_scanned` carries the requested mode and the modes the project is
/// already wired for: here an agent manifest, scanned with `--mode agent`.
#[tokio::test]
async fn scan_reports_requested_and_project_modes() {
    let mock = setup_mock(
        serde_json::json!({ "packages": [], "canAccessPaidPatches": false }),
        None,
    )
    .await;
    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "minimist", "1.2.2");
    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::json!({
            "patches": {
                "pkg:npm/minimist@1.2.2": {
                    "uuid": "33333333-3333-4333-8333-333333333333",
                    "exportedAt": "2024-01-01T00:00:00Z",
                    "files": {},
                    "vulnerabilities": {},
                    "description": "x",
                    "license": "MIT",
                    "tier": "free"
                }
            }
        })
        .to_string(),
    )
    .unwrap();

    let (code, stdout, stderr) = run_cmd(
        tmp.path(),
        &mock.uri(),
        "scan",
        &["--mode", "agent", "--dry-run"],
        &[],
    );
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");

    let bodies = telemetry_bodies(&mock).await;
    let scanned = bodies
        .iter()
        .find(|b| b["event_type"] == "patch_scanned")
        .unwrap_or_else(|| panic!("no patch_scanned: {bodies:#?}"));
    assert_eq!(scanned["metadata"]["mode"], "agent");
    assert_eq!(
        scanned["metadata"]["project_modes"],
        serde_json::json!(["agent"])
    );
    assert_eq!(
        scanned["context"]["version"],
        env!("CARGO_PKG_VERSION"),
        "every event carries the client version"
    );
    // Where the binary under test sits decides the channel (a build
    // directory no package manager owns is `standalone`), so only the
    // shape is pinned here: one of the six ids, never a path.
    let channel = scanned["context"]["channel"]
        .as_str()
        .expect("every event says how the binary was installed");
    assert!(
        [
            "standalone",
            "npm",
            "pypi",
            "cargo",
            "launcher_cache",
            "homebrew"
        ]
        .contains(&channel),
        "unexpected channel id {channel}"
    );
}

/// A hosted run that fails after selecting patches reports
/// `patch_apply_failed` (`mode: "hosted"`) and leaves the lockfile alone.
#[tokio::test]
async fn hosted_scan_failure_reports_patch_apply_failed() {
    let mock = setup_hosted_mock(500).await;
    let tmp = tempfile::tempdir().expect("tempdir");
    write_hosted_npm_project(tmp.path());

    let (code, stdout, stderr) = run_cmd(tmp.path(), &mock.uri(), "scan", &[], &[]);
    assert_eq!(code, 1, "stdout:\n{stdout}\nstderr:\n{stderr}");

    let bodies = telemetry_bodies(&mock).await;
    let types: Vec<&str> = bodies
        .iter()
        .map(|b| b["event_type"].as_str().unwrap())
        .collect();
    assert_eq!(
        types,
        ["patch_scanned", "patch_apply_failed"],
        "{bodies:#?}"
    );
    let failed = &bodies[1];
    assert_eq!(failed["context"]["command"], "scan");
    assert_eq!(failed["metadata"]["mode"], "hosted");
    assert_eq!(failed["error"]["type"], "Error");
    // The event carries the code the `--json` envelope reports, and names
    // the patch the run could not pin.
    let doc: serde_json::Value = serde_json::from_str(&stdout).expect("JSON envelope");
    assert_eq!(
        failed["metadata"]["error_code"], doc["error"]["code"],
        "{failed:#}\n{doc:#}"
    );
    assert_eq!(
        only_patch(failed),
        &serde_json::json!({
            "uuid": HOSTED_UUID,
            "ecosystem": "npm",
            "mode": "hosted",
            "outcome": "failed",
            "code": doc["error"]["code"],
        })
    );
}

/// The failure event's code does not depend on `--json`: a human run
/// reports the same one.
#[tokio::test]
async fn a_hosted_failure_is_coded_the_same_without_json() {
    let mock = setup_hosted_mock(500).await;
    let tmp = tempfile::tempdir().expect("tempdir");
    write_hosted_npm_project(tmp.path());

    let (code, stdout, stderr) = run_human(tmp.path(), &mock.uri(), "scan", &["--yes"]);
    assert_eq!(code, 1, "stdout:\n{stdout}\nstderr:\n{stderr}");

    let bodies = telemetry_bodies(&mock).await;
    let failed = bodies
        .iter()
        .find(|b| b["event_type"] == "patch_apply_failed")
        .unwrap_or_else(|| panic!("a patch_apply_failed event: {bodies:#?}"));
    assert_eq!(failed["metadata"]["error_code"], "reference_resolve_failed");
    assert_eq!(only_patch(failed)["uuid"], HOSTED_UUID);
}

/// `get --mode hosted` reports through the same path, under its own
/// command name.
#[tokio::test]
async fn hosted_get_reports_patch_applied_under_get() {
    let mock = setup_hosted_mock(200).await;
    let tmp = tempfile::tempdir().expect("tempdir");
    write_hosted_npm_project(tmp.path());

    let (code, stdout, stderr) = run_cmd(
        tmp.path(),
        &mock.uri(),
        "get",
        &[HOSTED_PURL, "--mode", "hosted", "--yes"],
        &[],
    );
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");

    let bodies = telemetry_bodies(&mock).await;
    let applied: Vec<&serde_json::Value> = bodies
        .iter()
        .filter(|b| b["event_type"] == "patch_applied")
        .collect();
    assert_eq!(applied.len(), 1, "{bodies:#?}");
    assert_eq!(applied[0]["context"]["command"], "get");
    assert_eq!(applied[0]["metadata"]["mode"], "hosted");
    assert_eq!(applied[0]["metadata"]["patches_count"], 1);
}

// ---------------------------------------------------------------------------
// hosted mode, pnpm: the registry route
// ---------------------------------------------------------------------------

/// The name of [`HOSTED_UUID`]'s registry, and its address: the directory
/// [`HOSTED_URL`] is served from.
const ROUTE_ALIAS: &str = "socket-11111111";
const ROUTE_ADDRESS: &str = "https://patch.socket.dev/patch/npm/telemetry-hosted/1.0.0/22222222-2222-4222-8222-222222222222/11111111-1111-4111-8111-111111111111/";

/// A lockfileVersion 9 lock whose `.` importer depends on `name@1.0.0`
/// from the default registry, recording `overrides` (whole lines).
fn pnpm_v9_lock(overrides: &[&str], name: &str) -> String {
    let overrides = match overrides {
        [] => String::new(),
        lines => format!("overrides:\n  {}\n\n", lines.join("\n  ")),
    };
    format!(
        "lockfileVersion: '9.0'\n\n{overrides}importers:\n\n  .:\n    dependencies:\n      \
         {name}:\n        specifier: 1.0.0\n        version: 1.0.0\n\npackages:\n\n  \
         {name}@1.0.0:\n    resolution: {{integrity: sha512-UPSTREAMupstream==}}\n\n\
         snapshots:\n\n  {name}@1.0.0: {{}}\n"
    )
}

/// A pnpm project, pinned to a pnpm that takes the registry route, that
/// depends on `name@1.0.0`.
fn write_pnpm_project(root: &Path, name: &str, lock: &str) {
    std::fs::write(
        root.join("package.json"),
        format!(
            r#"{{ "name": "consumer", "version": "0.0.0", "packageManager": "pnpm@12.22.0", "dependencies": {{ "{name}": "1.0.0" }} }}"#
        ),
    )
    .unwrap();
    write_npm_package(root, name, "1.0.0");
    std::fs::write(root.join("pnpm-lock.yaml"), lock).unwrap();
}

/// [`setup_hosted_mock`] with a reference grant that carries the patch's
/// registry address, and the default registry's version document of the
/// package (what a rollback restores the pin from).
async fn setup_routed_mock() -> MockServer {
    let mock = setup_hosted_mock(200).await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/package")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "results": {
                HOSTED_UUID: {
                    "status": "granted",
                    "url": HOSTED_URL,
                    "purl": HOSTED_PURL,
                    "artifacts": [{
                        "kind": "tarball",
                        "url": HOSTED_URL,
                        "integrity": { "sha512": "sha512-PATCHEDpatchedPATCHEDpatched0123456789==" }
                    }],
                    "registryOverride": null,
                    "npmRegistryUrl": ROUTE_ADDRESS
                }
            }
        })))
        .with_priority(1)
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/npm-registry/{HOSTED_NAME}/1.0.0")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": HOSTED_NAME,
            "version": "1.0.0",
            "dist": {
                "tarball": format!("{}/npm-registry/{HOSTED_NAME}/-/{HOSTED_NAME}-1.0.0.tgz", mock.uri()),
                "integrity": "sha512-UPSTREAMupstream==",
            }
        })))
        .mount(&mock)
        .await;
    mock
}

/// The events of `event_type` among `bodies`, in firing order.
fn telemetry_of<'b>(
    bodies: &'b [serde_json::Value],
    event_type: &str,
) -> Vec<&'b serde_json::Value> {
    bodies
        .iter()
        .filter(|body| body["event_type"] == event_type)
        .collect()
}

/// A pin routed through its patch's pnpm registry is hosted work like any
/// other pin, and is counted the same: one `applied` outcome for its
/// patch in `patch_applied`, by UUID, when the run writes the route and
/// again when a re-run finds it in place, and one `rolled_back` outcome
/// when `rollback` takes the pin and its route out. The registry and the
/// override are how the pin is wired, not patches: they add no outcome and
/// no count of their own, and only the files they are in are counted.
#[tokio::test]
async fn a_pin_on_the_pnpm_registry_route_is_counted_as_one_hosted_patch() {
    let mock = setup_routed_mock().await;
    let tmp = tempfile::tempdir().expect("tempdir");
    write_pnpm_project(tmp.path(), HOSTED_NAME, &pnpm_v9_lock(&[], HOSTED_NAME));
    let workspace = tmp.path().join("pnpm-workspace.yaml");
    let the_pin = serde_json::json!({
        "uuid": HOSTED_UUID,
        "ecosystem": "npm",
        "mode": "hosted",
        "outcome": "applied",
    });

    // The run that writes the route.
    let (code, stdout, stderr) = run_cmd(tmp.path(), &mock.uri(), "scan", &[], &[]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    let routed = std::fs::read_to_string(&workspace).expect("the route's workspace file");
    assert!(
        routed.contains(&format!("  {ROUTE_ALIAS}: {ROUTE_ADDRESS}\n")),
        "{routed}"
    );
    let doc: serde_json::Value = serde_json::from_str(&stdout).expect("JSON envelope");
    let bodies = telemetry_bodies(&mock).await;
    let applied = telemetry_of(&bodies, "patch_applied");
    assert_eq!(applied.len(), 1, "{bodies:#?}");
    assert_eq!(applied[0]["metadata"]["mode"], "hosted");
    assert_eq!(only_patch(applied[0]), &the_pin);
    assert_eq!(applied[0]["metadata"]["patches_count"], 1);
    assert_eq!(
        applied[0]["metadata"]["files_count"],
        doc["redirect"]["rewrittenFiles"].as_array().unwrap().len(),
        "{doc:#}"
    );
    assert_eq!(
        doc["redirect"]["rewrittenFiles"],
        serde_json::json!(["pnpm-lock.yaml", "pnpm-workspace.yaml"])
    );

    // The run that finds the route in place.
    let (code, stdout, stderr) = run_cmd(tmp.path(), &mock.uri(), "scan", &[], &[]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert_eq!(std::fs::read_to_string(&workspace).unwrap(), routed);
    let bodies = telemetry_bodies(&mock).await;
    let applied = telemetry_of(&bodies, "patch_applied");
    assert_eq!(applied.len(), 2, "{bodies:#?}");
    assert_eq!(only_patch(applied[1]), &the_pin);
    assert_eq!(applied[1]["metadata"]["patches_count"], 1);
    assert_eq!(applied[1]["metadata"]["files_count"], 0);

    // The rollback that takes the pin and its route out.
    let registry = format!("{}/npm-registry", mock.uri());
    let (code, stdout, stderr) = run_cmd(
        tmp.path(),
        &mock.uri(),
        "rollback",
        &["--yes"],
        &[("SOCKET_NPM_REGISTRY", &registry)],
    );
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        !workspace.exists(),
        "the route's file goes with its last pin"
    );
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("pnpm-lock.yaml")).unwrap(),
        pnpm_v9_lock(&[], HOSTED_NAME)
    );
    let bodies = telemetry_bodies(&mock).await;
    let rolled_back = telemetry_of(&bodies, "patch_rolled_back");
    assert_eq!(rolled_back.len(), 1, "{bodies:#?}");
    assert_eq!(rolled_back[0]["metadata"]["rolled_back_count"], 1);
    assert_eq!(
        only_patch(rolled_back[0]),
        &serde_json::json!({
            "uuid": HOSTED_UUID,
            "ecosystem": "npm",
            "mode": "hosted",
            "outcome": "rolled_back",
        })
    );
    // Nothing a run reported names the registry, its address or the grant.
    for body in &bodies {
        let text = body.to_string();
        assert!(
            !text.contains(ROUTE_ALIAS) && !text.contains("22222222-2222-4222-8222-222222222222"),
            "{body:#}"
        );
    }
}

/// A hosted scan that only tidies a route (the patched dependency left
/// the project, and its registry, its override and the lock's record of
/// it go) acted on no patch: it reports the scan, and no `patch_applied`.
/// The entries it took out are in the `--json` envelope as artifact-level
/// events that name no patch, which is why they are no patch outcomes.
#[tokio::test]
async fn tidying_a_pnpm_registry_route_reports_no_patch() {
    let mock = setup_mock(
        serde_json::json!({ "packages": [], "canAccessPaidPatches": false }),
        None,
    )
    .await;
    let tmp = tempfile::tempdir().expect("tempdir");
    let stale = format!("{HOSTED_NAME}@1.0.0: {ROUTE_ALIAS}:1.0.0");
    write_pnpm_project(tmp.path(), "other", &pnpm_v9_lock(&[&stale], "other"));
    let workspace = tmp.path().join("pnpm-workspace.yaml");
    std::fs::write(
        &workspace,
        format!(
            "packages:\n  - '.'\nnamedRegistries:\n  {ROUTE_ALIAS}: {ROUTE_ADDRESS}\noverrides:\n  \
             '{HOSTED_NAME}@1.0.0': '{ROUTE_ALIAS}:1.0.0'\n"
        ),
    )
    .unwrap();

    let (code, stdout, stderr) =
        run_cmd(tmp.path(), &mock.uri(), "scan", &["--mode", "hosted"], &[]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(!workspace.exists(), "the file the route created is gone");
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("pnpm-lock.yaml")).unwrap(),
        pnpm_v9_lock(&[], "other")
    );
    let doc: serde_json::Value = serde_json::from_str(&stdout).expect("JSON envelope");
    let removed: Vec<&serde_json::Value> = doc["events"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|e| e["errorCode"] == "registry_entry_unused")
        .collect();
    assert_eq!(removed.len(), 3, "{doc:#}");
    for event in &removed {
        assert!(
            event.get("purl").is_none() && event.get("uuid").is_none(),
            "{event:#}"
        );
    }

    let bodies = telemetry_bodies(&mock).await;
    let types: Vec<&str> = bodies
        .iter()
        .map(|b| b["event_type"].as_str().unwrap())
        .collect();
    assert_eq!(types, ["patch_scanned"], "{bodies:#?}");
}

// ---------------------------------------------------------------------------
// Telemetry never holds a command back
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// per-patch outcomes: apply / rollback / remove / agent-mode downloads
// ---------------------------------------------------------------------------

const PATCHED_PURL: &str = "pkg:npm/tpkg@1.0.0";
const PATCHED_UUID: &str = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa";
const ORIGINAL: &[u8] = b"module.exports = 'original';\n";
const PATCHED: &[u8] = b"module.exports = 'patched';\n";

/// An agent-mode npm project with one patch recorded for `tpkg`
/// (manifest record and both blobs) and the installed file holding
/// `installed`. Returns the installed file's path.
fn write_agent_project(root: &Path, installed: &[u8]) -> std::path::PathBuf {
    write_root_package_json(root);
    write_npm_package(root, "tpkg", "1.0.0");
    let file = root.join("node_modules/tpkg/index.js");
    std::fs::write(&file, installed).unwrap();
    crate::common::write_in_place_patch_record(
        &root.join(".socket"),
        PATCHED_PURL,
        PATCHED_UUID,
        "package/index.js",
        ORIGINAL,
        PATCHED,
    );
    file
}

/// A mock that only records telemetry: the runs below need no patch API.
async fn telemetry_only_mock() -> MockServer {
    setup_mock(
        serde_json::json!({ "packages": [], "canAccessPaidPatches": false }),
        None,
    )
    .await
}

/// The one patch entry an event names, asserting it is the only one.
fn only_patch(event: &serde_json::Value) -> &serde_json::Value {
    let patches = event["metadata"]["patches"]
        .as_array()
        .unwrap_or_else(|| panic!("the event names its patches: {event:#}"));
    assert_eq!(patches.len(), 1, "{event:#}");
    &patches[0]
}

/// `apply` names the patches it acted on: the patch UUID with its
/// ecosystem, mode and outcome. A second run, with nothing left to do,
/// reports the same patch as skipped and applies none.
#[tokio::test]
async fn apply_reports_the_patches_it_applied() {
    let mock = telemetry_only_mock().await;
    let tmp = tempfile::tempdir().expect("tempdir");
    let file = write_agent_project(tmp.path(), ORIGINAL);

    let (code, stdout, stderr) = run_cmd(tmp.path(), &mock.uri(), "apply", &[], &[]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert_eq!(std::fs::read(&file).unwrap(), PATCHED);
    let (code, stdout, stderr) = run_cmd(tmp.path(), &mock.uri(), "apply", &[], &[]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");

    let bodies = telemetry_bodies(&mock).await;
    let types: Vec<&str> = bodies
        .iter()
        .map(|b| b["event_type"].as_str().unwrap())
        .collect();
    assert_eq!(types, ["patch_applied", "patch_applied"], "{bodies:#?}");

    let applied = &bodies[0];
    assert_eq!(applied["context"]["command"], "apply");
    assert_eq!(applied["metadata"]["mode"], "agent");
    assert_eq!(applied["metadata"]["dry_run"], false);
    assert_eq!(applied["metadata"]["patches_count"], 1);
    assert_eq!(
        only_patch(applied),
        &serde_json::json!({
            "uuid": PATCHED_UUID,
            "ecosystem": "npm",
            "mode": "agent",
            "outcome": "applied",
        })
    );
    assert_eq!(
        applied["metadata"]["outcomes"],
        serde_json::json!({ "applied": 1 })
    );
    // No package name anywhere in the event.
    assert!(!applied.to_string().contains("tpkg"), "{applied:#}");

    let again = &bodies[1];
    assert_eq!(again["metadata"]["patches_count"], 0);
    assert_eq!(only_patch(again)["outcome"], "skipped");
    assert_eq!(only_patch(again)["code"], "already_patched");
}

/// A rollback names the patch it rolled back, and says whether the user
/// asked for that patch or rolled the whole project back.
#[tokio::test]
async fn rollback_reports_the_patches_it_rolled_back() {
    let mock = telemetry_only_mock().await;
    let tmp = tempfile::tempdir().expect("tempdir");
    let file = write_agent_project(tmp.path(), PATCHED);

    let (code, stdout, stderr) = run_cmd(tmp.path(), &mock.uri(), "rollback", &[], &[]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert_eq!(std::fs::read(&file).unwrap(), ORIGINAL);

    let bodies = telemetry_bodies(&mock).await;
    assert_eq!(bodies.len(), 1, "{bodies:#?}");
    let event = &bodies[0];
    assert_eq!(event["event_type"], "patch_rolled_back");
    assert_eq!(event["context"]["command"], "rollback");
    assert_eq!(
        event["metadata"],
        serde_json::json!({
            "rolled_back_count": 1,
            "dry_run": false,
            "targeted": false,
            "patches": [{
                "uuid": PATCHED_UUID,
                "ecosystem": "npm",
                "mode": "agent",
                "outcome": "rolled_back",
            }],
            "outcomes": { "rolled_back": 1 },
            "ecosystems": ["npm"],
            "modes": ["agent"],
        })
    );
    // The envelope's count and the event's agree.
    let doc: serde_json::Value = serde_json::from_str(&stdout).expect("JSON envelope");
    assert_eq!(doc["summary"]["rolledBack"], 1, "{doc:#}");
    assert!(!event.to_string().contains("tpkg"), "{event:#}");
}

/// A rollback of a named patch is `targeted`; a dry run is flagged, and
/// its patch is `verified` (restorable), not rolled back.
#[tokio::test]
async fn a_targeted_dry_run_rollback_is_flagged_as_both() {
    let mock = telemetry_only_mock().await;
    let tmp = tempfile::tempdir().expect("tempdir");
    let file = write_agent_project(tmp.path(), PATCHED);

    let (code, stdout, stderr) = run_cmd(
        tmp.path(),
        &mock.uri(),
        "rollback",
        &[PATCHED_PURL, "--dry-run"],
        &[],
    );
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert_eq!(
        std::fs::read(&file).unwrap(),
        PATCHED,
        "a dry run restores nothing"
    );

    let bodies = telemetry_bodies(&mock).await;
    assert_eq!(bodies.len(), 1, "{bodies:#?}");
    let event = &bodies[0];
    assert_eq!(event["event_type"], "patch_rolled_back");
    assert_eq!(event["metadata"]["dry_run"], true);
    assert_eq!(event["metadata"]["targeted"], true);
    assert_eq!(only_patch(event)["uuid"], PATCHED_UUID);
    assert_eq!(only_patch(event)["outcome"], "verified");
}

/// A rollback whose target matches nothing is a failure of the command,
/// not of a patch: the event carries the run's error code and names none.
#[tokio::test]
async fn a_rollback_that_matches_nothing_reports_its_error_code() {
    let mock = telemetry_only_mock().await;
    let tmp = tempfile::tempdir().expect("tempdir");
    write_agent_project(tmp.path(), PATCHED);

    let (code, stdout, stderr) = run_cmd(
        tmp.path(),
        &mock.uri(),
        "rollback",
        &["pkg:npm/not-patched@9.9.9"],
        &[],
    );
    assert_eq!(code, 1, "stdout:\n{stdout}\nstderr:\n{stderr}");

    let bodies = telemetry_bodies(&mock).await;
    assert_eq!(bodies.len(), 1, "{bodies:#?}");
    let event = &bodies[0];
    assert_eq!(event["event_type"], "patch_rollback_failed");
    assert_eq!(event["metadata"]["error_code"], "patch_not_found");
    assert_eq!(event["metadata"]["targeted"], true);
    assert_eq!(event["metadata"]["rolled_back_count"], 0);
    assert!(event["metadata"].get("patches").is_none(), "{event:#}");
    // The envelope reports the same code.
    let doc: serde_json::Value = serde_json::from_str(&stdout).expect("JSON envelope");
    assert_eq!(doc["error"]["code"], "patch_not_found", "{doc:#}");
}

/// `remove` names the patch it took out. One event per run: a removal
/// that happened is never also reported as a failure.
#[tokio::test]
async fn remove_reports_the_patch_it_removed() {
    let mock = telemetry_only_mock().await;
    let tmp = tempfile::tempdir().expect("tempdir");
    let file = write_agent_project(tmp.path(), PATCHED);

    let (code, stdout, stderr) = run_cmd(tmp.path(), &mock.uri(), "remove", &[PATCHED_PURL], &[]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert_eq!(std::fs::read(&file).unwrap(), ORIGINAL);

    let bodies = telemetry_bodies(&mock).await;
    assert_eq!(bodies.len(), 1, "{bodies:#?}");
    let event = &bodies[0];
    assert_eq!(event["event_type"], "patch_removed");
    assert_eq!(event["context"]["command"], "remove");
    assert_eq!(
        event["metadata"],
        serde_json::json!({
            "removed_count": 1,
            "patches": [{
                "uuid": PATCHED_UUID,
                "ecosystem": "npm",
                "mode": "agent",
                "outcome": "removed",
            }],
            "outcomes": { "removed": 1 },
            "ecosystems": ["npm"],
            "modes": ["agent"],
        })
    );
}

/// A `remove --dry-run` changes nothing and reports nothing; a `remove`
/// of something that is not patched reports the failure with its code.
#[tokio::test]
async fn remove_reports_no_dry_run_and_codes_its_failures() {
    let mock = telemetry_only_mock().await;
    let tmp = tempfile::tempdir().expect("tempdir");
    let file = write_agent_project(tmp.path(), PATCHED);

    let (code, stdout, stderr) = run_cmd(
        tmp.path(),
        &mock.uri(),
        "remove",
        &[PATCHED_PURL, "--dry-run"],
        &[],
    );
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert_eq!(std::fs::read(&file).unwrap(), PATCHED);
    assert!(
        telemetry_bodies(&mock).await.is_empty(),
        "a dry-run remove reports nothing"
    );

    let (code, stdout, stderr) = run_cmd(
        tmp.path(),
        &mock.uri(),
        "remove",
        &["pkg:npm/not-patched@9.9.9"],
        &[],
    );
    assert_eq!(code, 1, "stdout:\n{stdout}\nstderr:\n{stderr}");
    let bodies = telemetry_bodies(&mock).await;
    assert_eq!(bodies.len(), 1, "{bodies:#?}");
    assert_eq!(bodies[0]["event_type"], "patch_remove_failed");
    assert_eq!(bodies[0]["metadata"]["error_code"], "not_found");
    assert!(bodies[0]["metadata"].get("patches").is_none());
}

/// An agent-mode `scan` downloads the patch records it selects and
/// applies them. Both steps report, under the command the user ran, and
/// name the patch: the download as `patch_fetched` (it was counted only
/// for `get <uuid>` before), the apply as `patch_applied`.
#[tokio::test]
async fn an_agent_mode_scan_reports_its_downloads_and_its_applies() {
    const PURL: &str = "pkg:npm/lodash@4.17.20";
    const UUID: &str = "12345678-1234-4123-8123-123456789abc";
    let batch = serde_json::json!({
        "packages": [{
            "purl": PURL,
            "patches": [{
                "uuid": UUID, "purl": PURL, "tier": "free",
                "cveIds": [], "ghsaIds": [], "severity": "high",
                "title": "telemetry agent fixture"
            }]
        }],
        "canAccessPaidPatches": false,
    });
    // A new-file patch: afterHash is the git-blob sha256 of "patched\n".
    let view = serde_json::json!({
        "uuid": UUID,
        "purl": PURL,
        "tier": "free",
        "publishedAt": "2024-06-01T00:00:00Z",
        "license": "MIT",
        "description": "test patch",
        "files": {
            "package/index.js": {
                "afterHash": "d2802877eb1c2f442d30d18abcb281cb2830875571624544f2f1acb36480997e",
                "blobContent": "cGF0Y2hlZAo=",
            }
        },
        "vulnerabilities": {},
    });
    // With `--json` and without: the two take different paths through the
    // download engine, and both report under `scan`.
    for json in [true, false] {
        let mock = setup_mock(batch.clone(), Some(view.clone())).await;
        // The detail query the selection runs for each package the batch
        // found a patch for.
        Mock::given(method("GET"))
            .and(wiremock::matchers::path_regex(format!(
                "^/v0/orgs/{ORG_SLUG}/patches/by-package/.+$"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "patches": [{
                    "uuid": UUID, "purl": PURL,
                    "publishedAt": "2024-06-01T00:00:00Z",
                    "description": "test patch", "license": "MIT", "tier": "free",
                    "vulnerabilities": {}
                }],
                "canAccessPaidPatches": false,
            })))
            .mount(&mock)
            .await;
        let tmp = tempfile::tempdir().expect("tempdir");
        write_root_package_json(tmp.path());
        write_npm_package(tmp.path(), "lodash", "4.17.20");

        let flags = ["--mode", "agent", "--yes"];
        let (code, stdout, stderr) = if json {
            run_cmd(tmp.path(), &mock.uri(), "scan", &flags, &[])
        } else {
            run_human(tmp.path(), &mock.uri(), "scan", &flags)
        };
        assert_eq!(code, 0, "json={json}\nstdout:\n{stdout}\nstderr:\n{stderr}");
        assert_eq!(
            std::fs::read(tmp.path().join("node_modules/lodash/index.js")).ok(),
            Some(b"patched\n".to_vec()),
            "json={json}\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );

        let bodies = telemetry_bodies(&mock).await;
        let types: Vec<&str> = bodies
            .iter()
            .map(|b| b["event_type"].as_str().unwrap())
            .collect();
        assert_eq!(
            types,
            ["patch_scanned", "patch_fetched", "patch_applied"],
            "json={json}: {bodies:#?}"
        );

        let scanned = &bodies[0];
        assert_eq!(scanned["metadata"]["mode"], "agent");
        assert_eq!(scanned["metadata"]["dry_run"], false);
        assert_eq!(scanned["metadata"]["packages_scanned"], 1);
        assert_eq!(
            scanned["metadata"]["packages_by_ecosystem"],
            serde_json::json!({ "npm": 1 })
        );
        assert_eq!(
            scanned["metadata"]["patches_by_ecosystem"],
            serde_json::json!({ "npm": 1 })
        );

        let fetched = &bodies[1];
        assert_eq!(fetched["context"]["command"], "scan", "json={json}");
        assert_eq!(fetched["metadata"]["mode"], "agent");
        assert_eq!(fetched["metadata"]["patches_count"], 1);
        assert_eq!(
            only_patch(fetched),
            &serde_json::json!({
                "uuid": UUID,
                "ecosystem": "npm",
                "mode": "agent",
                "outcome": "downloaded",
            })
        );

        let applied = &bodies[2];
        assert_eq!(applied["context"]["command"], "scan", "json={json}");
        assert_eq!(applied["metadata"]["mode"], "agent");
        assert_eq!(applied["metadata"]["patches_count"], 1);
        assert_eq!(only_patch(applied)["uuid"], UUID);
        assert_eq!(only_patch(applied)["outcome"], "applied");

        // One run, one session: the three events are linked.
        let sessions: std::collections::HashSet<&str> = bodies
            .iter()
            .map(|b| b["session_id"].as_str().unwrap())
            .collect();
        assert_eq!(sessions.len(), 1);
    }
}

/// A telemetry endpoint the test answers by hand. It accepts one
/// connection and reads one request, whose JSON body arrives on
/// `received`; the `201` goes out only when the test sends on `answer`.
/// Dropping the endpoint closes the connection unanswered.
struct HeldEndpoint {
    uri: String,
    received: std::sync::mpsc::Receiver<serde_json::Value>,
    answer: std::sync::mpsc::Sender<()>,
}

fn held_endpoint() -> HeldEndpoint {
    use std::io::{Read, Write};

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let uri = format!("http://{}", listener.local_addr().expect("local addr"));
    let (received_tx, received) = std::sync::mpsc::channel();
    let (answer, answer_rx) = std::sync::mpsc::channel::<()>();
    std::thread::spawn(move || {
        let Ok((mut conn, _)) = listener.accept() else {
            return;
        };
        // One HTTP/1.1 request: the head, then `content-length` bytes.
        let mut raw = Vec::new();
        let mut chunk = [0u8; 4096];
        let body = loop {
            match conn.read(&mut chunk) {
                Ok(n) if n > 0 => raw.extend_from_slice(&chunk[..n]),
                _ => return,
            }
            let Some(head_end) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
                continue;
            };
            let head = String::from_utf8_lossy(&raw[..head_end]).to_ascii_lowercase();
            let length: usize = head
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .and_then(|value| value.trim().parse().ok())
                .unwrap_or(0);
            let body_start = head_end + 4;
            if raw.len() >= body_start + length {
                break raw[body_start..body_start + length].to_vec();
            }
        };
        let _ = received_tx.send(serde_json::from_slice(&body).unwrap_or_default());
        if answer_rx.recv().is_ok() {
            let _ = conn.write_all(
                b"HTTP/1.1 201 Created\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
            );
        }
    });
    HeldEndpoint {
        uri,
        received,
        answer,
    }
}

/// A project with an empty manifest and nothing installed: `list` has
/// nothing to list and `scan` nothing to query, so each command's only
/// request is its telemetry event.
fn write_empty_project(root: &Path) {
    write_root_package_json(root);
    let socket = root.join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    std::fs::write(socket.join("manifest.json"), r#"{"patches":{}}"#).unwrap();
}

/// A command prints its result first and sends telemetry beside it: the
/// whole `--json` document is on stdout while the telemetry request is
/// still waiting for its answer, and the event is delivered once the
/// answer comes. The endpoint answers only after the test has read the
/// document, so this measures the order of events, never a duration: a
/// command that waited for telemetry before printing could only print
/// after its send had given up, and would report the send failed.
#[test]
fn commands_print_before_their_telemetry_is_answered() {
    use std::io::Read;

    for (command, event_type) in [("list", "patch_listed"), ("scan", "patch_scanned")] {
        let endpoint = held_endpoint();
        let tmp = tempfile::tempdir().expect("tempdir");
        write_empty_project(tmp.path());

        // `--debug` reports the send's outcome on stderr.
        let mut child = build_cmd(tmp.path(), &endpoint.uri, command, &["--debug"], &[])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn socket-patch");

        // The process stays alive until its telemetry is answered, so read
        // stdout as it is written rather than to EOF.
        let mut stdout = child.stdout.take().expect("piped stdout");
        let mut printed = Vec::new();
        let mut chunk = [0u8; 4096];
        let envelope: serde_json::Value = loop {
            let n = stdout.read(&mut chunk).expect("read stdout");
            assert!(
                n > 0,
                "{command}: stdout closed before a whole envelope: {}",
                String::from_utf8_lossy(&printed)
            );
            printed.extend_from_slice(&chunk[..n]);
            if let Ok(doc) = serde_json::from_slice(&printed) {
                break doc;
            }
        };
        assert_eq!(envelope["command"], command, "{envelope}");

        let event = endpoint
            .received
            .recv_timeout(std::time::Duration::from_secs(30))
            .unwrap_or_else(|e| panic!("{command}: no telemetry request arrived: {e}"));
        assert_eq!(event["event_type"], event_type, "{command}: {event}");
        endpoint.answer.send(()).expect("the endpoint is waiting");

        let out = child.wait_with_output().expect("wait socket-patch");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(0), "{command}: stderr={stderr}");
        assert!(
            stderr.contains("Telemetry sent successfully"),
            "{command}: the event must be delivered after the result is printed; \
             stderr={stderr}"
        );
    }
}

/// A telemetry endpoint that takes the event and never answers costs a
/// command its short exit grace and nothing else: stdout, stderr and the
/// exit code are those of a run with telemetry off, and the run ends long
/// before the 5 s the send itself is allowed.
#[test]
fn a_stalled_telemetry_endpoint_costs_only_the_exit_grace() {
    let tmp = tempfile::tempdir().expect("tempdir");
    write_empty_project(tmp.path());
    let run = |uri: &str, extra_env: &[(&str, &str)]| {
        let mut cmd = build_cmd(tmp.path(), uri, "list", &[], extra_env);
        // The production grace, not the one the harness lifts.
        cmd.env_remove("SOCKET_TELEMETRY_GRACE_MS");
        let started = std::time::Instant::now();
        let out = cmd.output().expect("run socket-patch");
        (started.elapsed(), out)
    };

    let (_, quiet) = run("http://127.0.0.1:9", &[("SOCKET_TELEMETRY_DISABLED", "1")]);
    assert_eq!(quiet.status.code(), Some(0));

    // A stall is the same on every run and machine load is not, so the
    // best of three runs decides.
    let limit = std::time::Duration::from_millis(2500);
    let mut best = std::time::Duration::MAX;
    let mut sent = false;
    for _ in 0..3 {
        let endpoint = held_endpoint();
        let (elapsed, out) = run(&endpoint.uri, &[]);
        assert_eq!(out.status.code(), quiet.status.code());
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&quiet.stdout),
            "a stalled endpoint must not change stdout"
        );
        assert_eq!(
            String::from_utf8_lossy(&out.stderr),
            String::from_utf8_lossy(&quiet.stderr),
            "a stalled endpoint must not change stderr"
        );
        sent |= endpoint
            .received
            .recv_timeout(std::time::Duration::from_millis(500))
            .is_ok();
        best = best.min(elapsed);
        if best < limit {
            break;
        }
    }
    assert!(
        best < limit,
        "list took {best:?} against a stalled telemetry endpoint"
    );
    assert!(sent, "telemetry was on: the event must have been sent");
}

// ---------------------------------------------------------------------------
// Every opt-out
// ---------------------------------------------------------------------------

/// Each documented opt-out, on its own, keeps `list` from sending anything
/// at all; the same variables set to an explicit "off" do not (the
/// anti-vacuous half: the event the opt-outs suppress is really sent).
#[tokio::test]
async fn every_opt_out_keeps_list_from_sending() {
    let empty_batch = || serde_json::json!({ "packages": [], "canAccessPaidPatches": false });
    let tmp = tempfile::tempdir().expect("tempdir");
    write_empty_project(tmp.path());

    let opt_outs: [(&[&str], &[(&str, &str)]); 7] = [
        (&["--no-telemetry"], &[]),
        (&[], &[("SOCKET_TELEMETRY_DISABLED", "1")]),
        // The CLI's boolean vocabulary, not only `1` / `true`.
        (&[], &[("SOCKET_TELEMETRY_DISABLED", "yes")]),
        // The v3/v4 name: an opt-out made before v5 still holds.
        (&[], &[("SOCKET_PATCH_TELEMETRY_DISABLED", "1")]),
        (&[], &[("DO_NOT_TRACK", "1")]),
        (&[], &[("DO_NOT_TRACK", "true")]),
        (&["--offline"], &[]),
    ];
    for (args, env) in opt_outs {
        let mock = setup_mock(empty_batch(), None).await;
        let (code, _stdout, stderr) = run_cmd(tmp.path(), &mock.uri(), "list", args, env);
        assert_eq!(code, 0, "list {args:?} {env:?}: stderr={stderr}");
        let requests = mock.received_requests().await.expect("recording enabled");
        assert!(
            requests.is_empty(),
            "list {args:?} {env:?} must send nothing; saw {} request(s)",
            requests.len()
        );
    }

    let not_opt_outs: [&[(&str, &str)]; 3] = [
        &[("SOCKET_TELEMETRY_DISABLED", "false")],
        &[("SOCKET_PATCH_TELEMETRY_DISABLED", "0")],
        &[("DO_NOT_TRACK", "0")],
    ];
    for env in not_opt_outs {
        let mock = setup_mock(empty_batch(), None).await;
        let (code, _stdout, stderr) = run_cmd(tmp.path(), &mock.uri(), "list", &[], env);
        assert_eq!(code, 0, "list {env:?}: stderr={stderr}");
        assert_eq!(
            telemetry_post_count(&mock, Some("patch_listed")).await,
            1,
            "list {env:?} is not opted out and must send its event"
        );
    }
}
