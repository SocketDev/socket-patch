//! End-to-end tests for API client error paths — exercises 4xx/5xx/
//! malformed responses + connection failure paths via wiremock.

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

// ---------------------------------------------------------------------------
// 401 / 403 / 404 / 5xx error handling — every command that hits the API
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_uuid_with_401_handles_gracefully() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(401).set_body_string("Unauthorized"))
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
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        code == 0 || code == 1,
        "401 must not crash; got {code}; stdout={stdout}"
    );
    let _: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("must emit valid JSON on 401");
}

#[tokio::test]
async fn get_uuid_with_500_handles_gracefully() {
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
    assert!(code == 0 || code == 1, "500 must not crash; code={code}");
}

#[tokio::test]
async fn get_uuid_with_malformed_json_handles_gracefully() {
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
    assert!(
        code == 0 || code == 1,
        "malformed JSON must not crash; code={code}"
    );
}

#[tokio::test]
async fn scan_with_400_bad_request_handles_gracefully() {
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
    assert!(code == 0 || code == 1, "scan 400 must not crash; code={code}");
}

// ---------------------------------------------------------------------------
// Network failure — unreachable host
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_with_unreachable_api_url_handles_gracefully() {
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
    assert!(code == 0 || code == 1, "network err must not crash; code={code}");
}

#[tokio::test]
async fn scan_with_unreachable_api_url_handles_gracefully() {
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
    assert!(code == 0 || code == 1, "scan w/ unreachable must not crash");
}

// ---------------------------------------------------------------------------
// CVE / GHSA search errors
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_by_cve_with_500_handles_gracefully() {
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
    assert!(code == 0 || code == 1, "CVE 500 must not crash; code={code}");
}

#[tokio::test]
async fn get_by_ghsa_with_404_handles_gracefully() {
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
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(code == 0 || code == 1, "GHSA 404 must not crash");
    let v: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("must be JSON");
    assert!(v.get("status").is_some());
}

// ---------------------------------------------------------------------------
// Repair fetch errors
// ---------------------------------------------------------------------------

#[tokio::test]
async fn repair_with_blob_404_marks_failure_in_summary() {
    let after_hash = "1111111111111111111111111111111111111111111111111111111111111111";
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/blob/{after_hash}")))
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
        .env("SOCKET_API_URL", &mock.uri())
        .env("SOCKET_API_TOKEN", "fake-token")
        .env("SOCKET_ORG_SLUG", ORG_SLUG)
        .output()
        .expect("run");
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert_eq!(
        code, 1,
        "repair must exit non-zero when an artifact download fails so CI guarding on \
         the exit code doesn't treat a half-finished repair as success; stdout={stdout}"
    );
    let v: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("must be JSON");
    // The repair envelope's summary tracks failures.
    assert!(
        v["summary"]["failed"].as_u64().unwrap_or(0) > 0
            || v.get("events").and_then(|e| e.as_array()).map_or(false, |a| {
                a.iter().any(|e| e["action"] == "failed")
            }),
        "repair must record the download failure; got: {v}"
    );
}
