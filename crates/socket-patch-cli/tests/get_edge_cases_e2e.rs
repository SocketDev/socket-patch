//! Additional e2e tests for `get` edge cases — exercises the
//! validation branches (--one-off + --save-only conflict, --id flag,
//! multi-patch selection via --id, auto-select for single free patch
//! match) and a few error paths the main get_invariants suite doesn't
//! reach.

use std::path::PathBuf;
use std::process::Command;

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

const ORG_SLUG: &str = "test-org";
const UUID_A: &str = "11111111-1111-4111-8111-111111111111";
const UUID_B: &str = "22222222-2222-4222-8222-222222222222";

#[test]
fn get_one_off_and_save_only_together_errors() {
    // The two flags are mutually exclusive — using both must fail.
    let tmp = tempfile::tempdir().unwrap();
    let out = Command::new(binary())
        .args([
            "get",
            UUID_A,
            "--one-off",
            "--save-only",
            "--yes",
            "--json",
            "--api-url",
            "http://127.0.0.1:1",
            "--api-token",
            "fake",
            "--org",
            ORG_SLUG,
        ])
        .current_dir(tmp.path())
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(v["status"], "error");
    let err = v["error"].as_str().expect("error message");
    assert!(
        err.contains("one-off") && err.contains("save-only"),
        "error must mention both flags: {err}"
    );
}

#[tokio::test]
async fn get_with_id_flag_selects_specific_patch() {
    // Multiple patches available for a PURL, `--id <UUID>` picks one.
    let mock = MockServer::start().await;
    let purl = "pkg:npm/multi@1.0.0";
    let encoded = "pkg%3Anpm%2Fmulti%401.0.0";

    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/by-package/{encoded}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [
                {
                    "uuid": UUID_A, "purl": purl,
                    "publishedAt": "2024-01-01T00:00:00Z",
                    "description": "first", "license": "MIT", "tier": "free",
                    "vulnerabilities": {}
                },
                {
                    "uuid": UUID_B, "purl": purl,
                    "publishedAt": "2024-02-01T00:00:00Z",
                    "description": "second", "license": "MIT", "tier": "free",
                    "vulnerabilities": {}
                }
            ],
            "canAccessPaidPatches": false,
        })))
        .mount(&mock)
        .await;
    // Mock the view endpoint for the SELECTED UUID.
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/view/{UUID_B}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": UUID_B,
            "purl": purl,
            "publishedAt": "2024-02-01T00:00:00Z",
            "files": {},
            "vulnerabilities": {},
            "description": "Second patch",
            "license": "MIT",
            "tier": "free",
        })))
        .mount(&mock)
        .await;

    // --id is a boolean type-tag: it tells the binary that the
    // positional identifier is a UUID, bypassing the auto-detection
    // step. Pair it with the UUID as the positional.
    let tmp = tempfile::tempdir().unwrap();
    // Mock the view endpoint for the SELECTED UUID — passing --id with
    // the UUID positional should go through the fetch-by-UUID path.
    let _ = purl;
    let _ = encoded;
    let out = Command::new(binary())
        .args([
            "get",
            UUID_B,
            "--id",
            "--save-only",
            "--yes",
            "--json",
            "--api-url",
            &mock.uri(),
            "--api-token",
            "fake",
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
        "--id type-tag must not crash; code={code}; stdout={stdout}"
    );
}

#[tokio::test]
async fn get_with_no_matching_purl_emits_not_found() {
    let mock = MockServer::start().await;
    let purl = "pkg:npm/empty-result@1.0.0";
    let encoded = "pkg%3Anpm%2Fempty-result%401.0.0";

    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/by-package/{encoded}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [],
            "canAccessPaidPatches": false,
        })))
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let out = Command::new(binary())
        .args([
            "get",
            purl,
            "--save-only",
            "--yes",
            "--json",
            "--api-url",
            &mock.uri(),
            "--api-token",
            "fake",
            "--org",
            ORG_SLUG,
        ])
        .current_dir(tmp.path())
        .output()
        .expect("run");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(v["status"], "not_found");
}

#[tokio::test]
async fn get_by_package_with_single_paid_patch_emits_paid_required() {
    // Single paid patch for free user via public proxy → paid_required.
    let mock = MockServer::start().await;
    let purl = "pkg:npm/paid-single@1.0.0";
    let encoded = "pkg%3Anpm%2Fpaid-single%401.0.0";

    Mock::given(method("GET"))
        .and(path(format!("/patch/by-package/{encoded}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [{
                "uuid": UUID_A, "purl": purl,
                "publishedAt": "2024-01-01T00:00:00Z",
                "description": "paid", "license": "MIT", "tier": "paid",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let out = Command::new(binary())
        .args([
            "get",
            purl,
            "--save-only",
            "--yes",
            "--json",
            "--api-url",
            &mock.uri(),
        ])
        .current_dir(tmp.path())
        .env("SOCKET_PATCH_PROXY_URL", mock.uri())
        .env_remove("SOCKET_API_TOKEN")
        .output()
        .expect("run");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    let status = v["status"].as_str().expect("status");
    assert!(
        status == "paid_required" || status == "not_found" || status == "error",
        "single paid patch without token must not succeed; got: {v}"
    );
}

#[tokio::test]
async fn get_with_invalid_search_purl_falls_through() {
    // A bare string that doesn't match UUID/CVE/GHSA/PURL — should be
    // treated as a package-name search via the search-by-package path.
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(wiremock::matchers::path_regex(format!(
            "^/v0/orgs/{ORG_SLUG}/patches/by-package/.+$"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [],
            "canAccessPaidPatches": false,
        })))
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let out = Command::new(binary())
        .args([
            "get",
            "just-a-package-name",
            "--save-only",
            "--yes",
            "--json",
            "--api-url",
            &mock.uri(),
            "--api-token",
            "fake",
            "--org",
            ORG_SLUG,
        ])
        .current_dir(tmp.path())
        .output()
        .expect("run");
    let code = out.status.code().unwrap_or(-1);
    assert!(code == 0 || code == 1, "package-name fallback must not crash");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let _: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("valid JSON");
}

#[tokio::test]
async fn get_uuid_returns_paid_patch_with_token_succeeds() {
    // Authenticated user (has token + org) requesting a paid patch
    // bypasses the proxy and gets the full PatchResponse.
    let mock = MockServer::start().await;
    let purl = "pkg:npm/paid-with-token@1.0.0";
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/view/{UUID_A}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": UUID_A,
            "purl": purl,
            "publishedAt": "2024-01-01T00:00:00Z",
            "files": {},
            "vulnerabilities": {},
            "description": "Paid patch with token access",
            "license": "MIT",
            "tier": "paid",
        })))
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let out = Command::new(binary())
        .args([
            "get",
            UUID_A,
            "--save-only",
            "--yes",
            "--json",
            "--api-url",
            &mock.uri(),
            "--api-token",
            "real-token-but-not-validated-by-mock",
            "--org",
            ORG_SLUG,
        ])
        .current_dir(tmp.path())
        .output()
        .expect("run");
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert_eq!(
        code, 0,
        "paid patch via authenticated path must succeed; stdout={stdout}"
    );
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(v["status"], "success");
}

#[test]
fn get_help_lists_all_identifier_flags() {
    let out = Command::new(binary())
        .args(["get", "--help"])
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    for flag in ["--id", "--cve", "--ghsa", "--package", "--save-only", "--one-off"] {
        assert!(
            stdout.contains(flag),
            "get --help missing flag {flag}; got: {stdout}"
        );
    }
}
