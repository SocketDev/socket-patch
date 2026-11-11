//! Token-less `scan` against a public proxy whose `POST /patch/batch` is
//! refused, so the client degrades to one `GET /patch/by-package/<purl>`
//! per package.
//!
//! "No patches available" may only be reported when the patch service
//! answered that question. A host that is not the patch service (a
//! mistyped `--proxy-url`, a captive portal, a corporate forward proxy), or
//! a service that fails every lookup, is a failed query: exit 1,
//! `api_batch_failed`. A lookup that fails for some packages only is a
//! partial failure that names them. The legacy fallback itself, and its
//! honest "no patches" answers, keep working.
//!
//! Subprocess runs use the hermetic `SOCKET_*` environment
//! (`common/hermetic.rs`). The one throttled answer carries
//! `Retry-After: 0`, so its retries wait only the minimum backoff step.

use std::path::Path;
use std::process::Command;

use crate::common::hermetic::{self, Extra};

use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const NAMES: [&str; 3] = ["fallback-alpha", "fallback-bravo", "fallback-charlie"];
const VERSION: &str = "1.0.0";

fn purl(name: &str) -> String {
    format!("pkg:npm/{name}@{VERSION}")
}

fn uuid(idx: usize) -> String {
    format!("0000000f-0000-4000-8000-{idx:012x}")
}

fn by_package_route(name: &str) -> String {
    format!(
        "/patch/by-package/{}",
        purl(name)
            .replace(':', "%3A")
            .replace('/', "%2F")
            .replace('@', "%40")
    )
}

fn scrubbed_cli() -> Command {
    let mut cmd = hermetic::binary_command();
    hermetic::scrub_extra(&mut cmd, &[Extra::Venv]);
    cmd
}

/// Token-less `socket-patch scan <args>` in `cwd` with the public proxy at
/// `proxy` (the authenticated base is unroutable: a stray authenticated
/// request fails the run).
fn run_scan(cwd: &Path, proxy: &str, args: &[&str]) -> (i32, String, String) {
    let out = scrubbed_cli()
        .arg("scan")
        .args([
            "--cwd",
            cwd.to_str().unwrap(),
            "--api-url",
            "http://127.0.0.1:9",
            "--proxy-url",
            proxy,
        ])
        .args(args)
        .output()
        .expect("run socket-patch scan");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// An npm project with every name in `NAMES` installed and locked.
fn write_project(root: &Path) {
    let deps: Vec<String> = NAMES
        .iter()
        .map(|n| format!(r#""{n}": "{VERSION}""#))
        .collect();
    let deps = deps.join(", ");
    std::fs::write(
        root.join("package.json"),
        format!(r#"{{ "name": "consumer", "version": "0.0.0", "dependencies": {{ {deps} }} }}"#),
    )
    .unwrap();
    let mut entries = vec![format!(
        r#"    "": {{ "name": "consumer", "version": "0.0.0", "dependencies": {{ {deps} }} }}"#
    )];
    for name in NAMES {
        let pkg = root.join("node_modules").join(name);
        std::fs::create_dir_all(&pkg).unwrap();
        std::fs::write(
            pkg.join("package.json"),
            format!(r#"{{ "name": "{name}", "version": "{VERSION}" }}"#),
        )
        .unwrap();
        std::fs::write(pkg.join("index.js"), b"module.exports = 1;\n").unwrap();
        entries.push(format!(
            r#"    "node_modules/{name}": {{
      "version": "{VERSION}",
      "resolved": "https://registry.npmjs.org/{name}/-/{name}-{VERSION}.tgz",
      "integrity": "sha512-UPSTREAM{name}=="
    }}"#
        ));
    }
    std::fs::write(
        root.join("package-lock.json"),
        format!(
            "{{\n  \"name\": \"consumer\",\n  \"version\": \"0.0.0\",\n  \"lockfileVersion\": 3,\n  \
             \"requires\": true,\n  \"packages\": {{\n{}\n  }}\n}}\n",
            entries.join(",\n")
        ),
    )
    .unwrap();
}

/// What a host that is not the patch service answers.
fn html_page(status: u16) -> ResponseTemplate {
    ResponseTemplate::new(status).set_body_raw(
        "<!doctype html><html><head><title>Error</title></head><body>nginx</body></html>",
        "text/html",
    )
}

/// A legacy proxy's answer to the batch POST: its catch-all 400.
async fn mount_legacy_batch(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/patch/batch"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "error": "Unsupported endpoint",
            "message": "Endpoint POST /patch/batch is not supported."
        })))
        .mount(server)
        .await;
}

/// The per-package answer for package `idx`: one free patch.
fn one_patch(idx: usize) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(serde_json::json!({
        "patches": [{
            "uuid": uuid(idx),
            "purl": purl(NAMES[idx]),
            "publishedAt": "2024-01-01T00:00:00Z",
            "description": format!("patch for {}", NAMES[idx]),
            "license": "MIT",
            "tier": "free",
            "vulnerabilities": {}
        }],
        "canAccessPaidPatches": false
    }))
}

/// The service's "nothing for this package".
fn no_patches() -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(serde_json::json!({
        "patches": [],
        "canAccessPaidPatches": false
    }))
}

async fn mount_package(server: &MockServer, idx: usize, answer: ResponseTemplate) {
    Mock::given(method("GET"))
        .and(path(by_package_route(NAMES[idx])))
        .respond_with(answer)
        .mount(server)
        .await;
}

fn json(stdout: &str) -> serde_json::Value {
    serde_json::from_str(stdout).unwrap_or_else(|e| panic!("{e}: {stdout}"))
}

/// The run reported a failed query, in both output modes: exit 1, the
/// `api_batch_failed` error envelope, and never a "no patches" line.
fn assert_query_failed(tmp: &Path, proxy: &str, needle: &str) -> String {
    let (code, stdout, stderr) = run_scan(tmp, proxy, &["--json", "--dry-run"]);
    assert_eq!(code, 1, "{stdout}\n{stderr}");
    let v = json(&stdout);
    assert_eq!(v["status"], "error", "{v:#}");
    assert_eq!(v["error"]["code"], "api_batch_failed", "{v:#}");
    let message = v["error"]["message"].as_str().unwrap().to_string();
    assert!(message.contains(needle), "{message}");
    assert!(v.get("packages").is_none(), "{v:#}");

    let (code, stdout, stderr) = run_scan(tmp, proxy, &["--dry-run"]);
    assert_eq!(code, 1, "{stdout}\n{stderr}");
    assert!(
        !stdout.contains("No patches available"),
        "a failed query must never read as a clean scan: {stdout}"
    );
    assert!(
        stderr.contains("Error: The API query failed:") && stderr.contains(needle),
        "{stderr}"
    );
    message
}

/// (a) The batch POST is refused and every per-package GET answers 500.
#[tokio::test]
async fn every_lookup_failing_is_a_failed_query() {
    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    let server = MockServer::start().await;
    mount_legacy_batch(&server).await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/patch/by-package/.*$"))
        .respond_with(ResponseTemplate::new(500).set_body_string("upstream exploded"))
        .mount(&server)
        .await;

    assert_query_failed(tmp.path(), &server.uri(), "upstream exploded");
}

/// (b) A host that is not the patch service: its own 404 page for the
/// batch POST and for every per-package GET.
#[tokio::test]
async fn a_host_that_is_not_the_patch_service_is_a_failed_query() {
    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    let server = MockServer::start().await;
    Mock::given(wiremock::matchers::any())
        .respond_with(html_page(404))
        .mount(&server)
        .await;

    let message = assert_query_failed(tmp.path(), &server.uri(), "--proxy-url");
    assert!(
        message.contains(&server.address().to_string()),
        "the error must name the host that answered: {message}"
    );
    assert!(message.contains("SOCKET_PROXY_URL"), "{message}");
}

/// What a forward proxy or WAF answers for anything: a 400 with its own
/// page. One request, then the failure — no per-package fan-out.
#[tokio::test]
async fn a_foreign_400_page_is_a_failed_query_after_one_request() {
    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    let server = MockServer::start().await;
    Mock::given(wiremock::matchers::any())
        .respond_with(html_page(400))
        .mount(&server)
        .await;

    let (code, stdout, stderr) = run_scan(tmp.path(), &server.uri(), &["--json", "--dry-run"]);
    assert_eq!(code, 1, "{stdout}\n{stderr}");
    let v = json(&stdout);
    assert_eq!(v["error"]["code"], "api_batch_failed", "{v:#}");
    let requests = server.received_requests().await.unwrap();
    assert_eq!(
        requests.len(),
        1,
        "a foreign answer to the batch POST must not fan out per package"
    );
}

fn warnings(v: &serde_json::Value, code: &str) -> Vec<String> {
    v["warnings"]
        .as_array()
        .map(|w| {
            w.iter()
                .filter(|w| w["code"] == code)
                .map(|w| w["detail"].as_str().unwrap().to_string())
                .collect()
        })
        .unwrap_or_default()
}

/// (c) The batch POST is refused; two packages answer (one with a patch,
/// one with none) and the third is still 503 after its retries. The
/// answered ones are used, and the third is named and counted: a partial
/// failure, never a package silently treated as patch-free.
#[tokio::test]
async fn one_unanswered_package_is_a_partial_failure_that_names_it() {
    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    let server = MockServer::start().await;
    mount_legacy_batch(&server).await;
    mount_package(&server, 0, one_patch(0)).await;
    mount_package(&server, 1, no_patches()).await;
    mount_package(
        &server,
        2,
        ResponseTemplate::new(503)
            .insert_header("Retry-After", "0")
            .set_body_string("Service temporarily over capacity"),
    )
    .await;
    let stuck = purl(NAMES[2]);
    let detail = format!(
        "1 of 3 packages could not be checked for patches ({stuck}): API request failed with \
         status 503: Service temporarily over capacity (gave up after 3 retries)"
    );

    let (code, stdout, stderr) = run_scan(tmp.path(), &server.uri(), &["--json", "--dry-run"]);
    assert_eq!(code, 1, "{stdout}\n{stderr}");
    let v = json(&stdout);
    assert_eq!(v["status"], "partialFailure", "{v:#}");
    assert!(v.get("error").is_none(), "{v:#}");
    let packages = v["packages"].as_array().unwrap();
    assert_eq!(packages.len(), 1, "{v:#}");
    assert_eq!(packages[0]["purl"], purl(NAMES[0]));
    assert_eq!(
        warnings(&v, "patch_lookup_failed"),
        vec![detail.clone()],
        "{v:#}"
    );
    let failed: Vec<&serde_json::Value> = v["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["action"] == "failed")
        .collect();
    assert_eq!(failed.len(), 1, "{v:#}");
    assert_eq!(failed[0]["purl"], stuck);
    assert_eq!(failed[0]["errorCode"], "patch_lookup_failed");
    assert!(
        failed[0]["error"]
            .as_str()
            .unwrap()
            .ends_with("(gave up after 3 retries)"),
        "{v:#}"
    );
    assert_eq!(v["summary"]["failed"], 1, "{v:#}");

    // The human run uses the answered packages too, names the unanswered
    // one on stderr and exits 1.
    let (code, stdout, stderr) = run_scan(tmp.path(), &server.uri(), &["--dry-run"]);
    assert_eq!(code, 1, "{stdout}\n{stderr}");
    assert!(stderr.contains(&format!("Warning: {detail}")), "{stderr}");
    assert!(stdout.contains(NAMES[0]), "{stdout}");
    assert!(!stdout.contains("No patches available"), "{stdout}");
}

/// A partial failure whose answered packages have no patch: the result
/// line may only speak for the packages that were checked, in every output
/// mode, and `--silent` still says why the run exits 1.
#[tokio::test]
async fn a_partial_failure_with_no_patch_found_never_reads_as_clean() {
    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    let server = MockServer::start().await;
    mount_legacy_batch(&server).await;
    mount_package(&server, 0, no_patches()).await;
    mount_package(&server, 1, no_patches()).await;
    mount_package(
        &server,
        2,
        ResponseTemplate::new(500).set_body_string("upstream exploded"),
    )
    .await;
    let warning = format!(
        "Warning: 1 of 3 packages could not be checked for patches ({}): API request failed \
         with status 500: upstream exploded",
        purl(NAMES[2])
    );

    let (code, stdout, stderr) = run_scan(tmp.path(), &server.uri(), &["--dry-run"]);
    assert_eq!(code, 1, "{stdout}\n{stderr}");
    assert!(stderr.contains(&warning), "{stderr}");
    assert!(!stdout.contains("No patches available"), "{stdout}");
    assert!(
        stdout.contains("No patches found for the packages that could be checked"),
        "{stdout}"
    );

    let (code, stdout, stderr) = run_scan(tmp.path(), &server.uri(), &["--dry-run", "--silent"]);
    assert_eq!(code, 1, "{stdout}\n{stderr}");
    assert!(stderr.contains(&warning), "{stderr}");
    assert_eq!(stdout, "");

    let (code, stdout, stderr) = run_scan(tmp.path(), &server.uri(), &["--json", "--dry-run"]);
    assert_eq!(code, 1, "{stdout}\n{stderr}");
    let v = json(&stdout);
    assert_eq!(v["status"], "partialFailure", "{v:#}");
    assert_eq!(v["packages"], serde_json::json!([]));
    assert_eq!(v["summary"]["failed"], 1, "{v:#}");
    assert_eq!(warnings(&v, "patch_lookup_failed").len(), 1, "{v:#}");
}

/// One failed batch of several keeps its documented channel (a warning,
/// `status: success`, exit 0), but the result line of a scan that found no
/// patch may still only speak for the batches that were answered.
#[tokio::test]
async fn a_failed_batch_with_no_patch_found_does_not_say_no_patches_available() {
    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/patch/batch"))
        .and(wiremock::matchers::body_string_contains(format!(
            "\"{}\"",
            purl(NAMES[2])
        )))
        .respond_with(ResponseTemplate::new(500).set_body_string("upstream exploded"))
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/patch/batch"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [],
            "canAccessPaidPatches": false
        })))
        .mount(&server)
        .await;

    let (code, stdout, stderr) = run_scan(
        tmp.path(),
        &server.uri(),
        &["--dry-run", "--batch-size", "1"],
    );
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert!(
        stderr.contains("of 3 failed: API request failed with status 500: upstream exploded"),
        "{stderr}"
    );
    assert!(!stdout.contains("No patches available"), "{stdout}");
    assert!(
        stdout.contains("No patches found for the packages that could be checked"),
        "{stdout}"
    );
}

/// (d) The documented legacy fallback: the batch POST answers the proxy's
/// catch-all 400 and the per-package GETs answer — one with a patch, the
/// others with the service's own "nothing for this package".
#[tokio::test]
async fn the_legacy_fallback_and_its_no_patch_answers_still_succeed() {
    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    let server = MockServer::start().await;
    mount_legacy_batch(&server).await;
    mount_package(&server, 0, one_patch(0)).await;
    mount_package(&server, 1, no_patches()).await;
    // The service refusing the purl itself (its own 400) is an answer too:
    // it has nothing for a purl it does not serve.
    mount_package(
        &server,
        2,
        ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "error": { "message": "Invalid PURL format.", "details": null }
        })),
    )
    .await;

    let (code, stdout, stderr) = run_scan(tmp.path(), &server.uri(), &["--json", "--dry-run"]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    let v = json(&stdout);
    assert_eq!(v["status"], "success", "{v:#}");
    assert!(v.get("warnings").is_none(), "{v:#}");
    let packages = v["packages"].as_array().unwrap();
    assert_eq!(packages.len(), 1, "{v:#}");
    assert_eq!(packages[0]["purl"], purl(NAMES[0]));

    // Every package clean: the service answered, so "no patches" is true.
    let clean = MockServer::start().await;
    mount_legacy_batch(&clean).await;
    for idx in 0..NAMES.len() {
        mount_package(&clean, idx, no_patches()).await;
    }
    let (code, stdout, stderr) = run_scan(tmp.path(), &clean.uri(), &["--dry-run"]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert!(
        stdout.contains("No patches available for installed packages."),
        "{stdout}"
    );
    let (code, stdout, stderr) = run_scan(tmp.path(), &clean.uri(), &["--json", "--dry-run"]);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    let v = json(&stdout);
    assert_eq!(v["status"], "success", "{v:#}");
    assert_eq!(v["packages"], serde_json::json!([]));
}
