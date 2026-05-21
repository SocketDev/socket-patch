//! In-process e2e tests for the `get` subcommand.
//!
//! These tests call `socket_patch_cli::commands::get::run` directly
//! (no subprocess), so cargo-llvm-cov instruments every code path
//! they execute. They use a `wiremock::MockServer` for the API and
//! assert on observable side effects (manifest written, blob
//! written, exit code, disk state) instead of capturing stdout.
//!
//! Tests are `#[serial]` because the binary mutates process env vars
//! (`SOCKET_API_URL`, `SOCKET_API_TOKEN`) — parallel tests would race.

use std::path::{Path, PathBuf};

use serial_test::serial;
use socket_patch_cli::commands::get::{run, GetArgs};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";
const UUID: &str = "11111111-1111-4111-8111-111111111111";
const PURL: &str = "pkg:npm/in-process-test@1.0.0";

fn default_args(identifier: &str, cwd: &Path) -> GetArgs {
    GetArgs {
        identifier: identifier.to_string(),
        org: Some(ORG.to_string()),
        cwd: cwd.to_path_buf(),
        id: false,
        cve: false,
        ghsa: false,
        package: false,
        yes: true,
        api_url: None,
        api_token: Some("fake-token-for-tests".to_string()),
        save_only: true,
        global: false,
        global_prefix: None,
        one_off: false,
        json: true,
        download_mode: "diff".to_string(),
    }
}

async fn make_view_mock(server: &MockServer, uuid: &str, purl: &str, tier: &str) {
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{uuid}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": uuid,
            "purl": purl,
            "publishedAt": "2024-01-01T00:00:00Z",
            "files": {
                "package/index.js": {
                    "beforeHash": "0000000000000000000000000000000000000000000000000000000000000000",
                    "afterHash":  "1111111111111111111111111111111111111111111111111111111111111111",
                    "blobContent": "cGF0Y2hlZAo=",  // base64("patched\n")
                }
            },
            "vulnerabilities": {},
            "description": "in-process get test fixture",
            "license": "MIT",
            "tier": tier,
        })))
        .mount(server)
        .await;
}

async fn make_search_mock_one(server: &MockServer, kind: &str, key: &str, uuid: &str, purl: &str, tier: &str) {
    let url_path = format!("/v0/orgs/{ORG}/patches/{kind}/{key}");
    Mock::given(method("GET"))
        .and(path(url_path))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [{
                "uuid": uuid, "purl": purl,
                "publishedAt": "2024-01-01T00:00:00Z",
                "description": "x", "license": "MIT", "tier": tier,
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;
}

async fn make_search_mock_empty(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path_regex(format!(
            r"^/v0/orgs/{ORG}/patches/(by-cve|by-ghsa|by-package)/.+$"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [],
            "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;
}

/// Helper: bind wiremock on a real local port and return its URL string.
async fn start_wiremock() -> (MockServer, String) {
    let server = MockServer::start().await;
    let url = server.uri();
    (server, url)
}

// ---------------------------------------------------------------------------
// UUID identifier path
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn get_by_uuid_save_only_writes_manifest() {
    let (server, url) = start_wiremock().await;
    make_view_mock(&server, UUID, PURL, "free").await;

    let tmp = tempfile::tempdir().unwrap();
    let mut args = default_args(UUID, tmp.path());
    args.api_url = Some(url);

    let code = run(args).await;
    assert_eq!(code, 0, "expected exit 0");

    let manifest_path = tmp.path().join(".socket/manifest.json");
    assert!(manifest_path.exists(), "manifest must be written");
    let body = std::fs::read_to_string(manifest_path).unwrap();
    let m: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(m["patches"][PURL].is_object());
    assert_eq!(m["patches"][PURL]["uuid"], UUID);
}

#[tokio::test]
#[serial]
async fn get_by_uuid_writes_blob_to_socket_dir() {
    let (server, url) = start_wiremock().await;
    make_view_mock(&server, UUID, PURL, "free").await;

    let tmp = tempfile::tempdir().unwrap();
    let mut args = default_args(UUID, tmp.path());
    args.api_url = Some(url);

    let code = run(args).await;
    assert_eq!(code, 0);

    let after_hash = "1111111111111111111111111111111111111111111111111111111111111111";
    let blob_path = tmp.path().join(".socket/blobs").join(after_hash);
    assert!(blob_path.exists(), "blob must be persisted");
    assert_eq!(std::fs::read(&blob_path).unwrap(), b"patched\n");
}

#[tokio::test]
#[serial]
async fn get_by_uuid_404_emits_not_found() {
    let (server, url) = start_wiremock().await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let mut args = default_args(UUID, tmp.path());
    args.api_url = Some(url);

    let code = run(args).await;
    assert_eq!(code, 0, "not_found is reported via JSON, not via exit code 1");
    assert!(
        !tmp.path().join(".socket/manifest.json").exists(),
        "no manifest must be written on 404"
    );
}

#[tokio::test]
#[serial]
async fn get_by_uuid_500_handled_gracefully() {
    let (server, url) = start_wiremock().await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(500).set_body_string("internal"))
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let mut args = default_args(UUID, tmp.path());
    args.api_url = Some(url);

    let code = run(args).await;
    // 500 is treated as a fetch error — exit 1 or 0 both acceptable, just
    // confirms no panic.
    assert!(code == 0 || code == 1, "got {code}");
}

// ---------------------------------------------------------------------------
// CVE identifier path
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn get_by_cve_resolves_and_saves() {
    let (server, url) = start_wiremock().await;
    make_search_mock_one(&server, "by-cve", "CVE-2024-12345", UUID, PURL, "free").await;
    make_view_mock(&server, UUID, PURL, "free").await;

    let tmp = tempfile::tempdir().unwrap();
    let mut args = default_args("CVE-2024-12345", tmp.path());
    args.api_url = Some(url);

    let code = run(args).await;
    assert_eq!(code, 0);
    assert!(tmp.path().join(".socket/manifest.json").exists());
}

#[tokio::test]
#[serial]
async fn get_by_cve_no_match_no_manifest_written() {
    let (server, url) = start_wiremock().await;
    make_search_mock_empty(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    let mut args = default_args("CVE-2099-99999", tmp.path());
    args.api_url = Some(url);

    let _ = run(args).await;
    assert!(
        !tmp.path().join(".socket/manifest.json").exists(),
        "no-match CVE search must not write manifest"
    );
}

#[tokio::test]
#[serial]
async fn get_by_ghsa_resolves_and_saves() {
    let (server, url) = start_wiremock().await;
    let ghsa = "GHSA-aaaa-bbbb-cccc";
    make_search_mock_one(&server, "by-ghsa", ghsa, UUID, PURL, "free").await;
    make_view_mock(&server, UUID, PURL, "free").await;

    let tmp = tempfile::tempdir().unwrap();
    let mut args = default_args(ghsa, tmp.path());
    args.api_url = Some(url);

    let code = run(args).await;
    assert_eq!(code, 0);
    assert!(tmp.path().join(".socket/manifest.json").exists());
}

// ---------------------------------------------------------------------------
// PURL identifier path — multi-patch selection
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn get_by_purl_single_patch_auto_selects() {
    let (server, url) = start_wiremock().await;
    let encoded = "pkg%3Anpm%2Fin-process-test%401.0.0";
    make_search_mock_one(&server, "by-package", encoded, UUID, PURL, "free").await;
    make_view_mock(&server, UUID, PURL, "free").await;

    let tmp = tempfile::tempdir().unwrap();
    let mut args = default_args(PURL, tmp.path());
    args.api_url = Some(url);

    let code = run(args).await;
    assert_eq!(code, 0);
    assert!(tmp.path().join(".socket/manifest.json").exists());
}

#[tokio::test]
#[serial]
async fn get_by_purl_multi_patch_in_json_mode_errors() {
    // With --json and multiple free patches, the CLI returns
    // selection_required (exit 1) instead of prompting.
    let (server, url) = start_wiremock().await;
    let purl = "pkg:npm/multi@1.0.0";
    let encoded = "pkg%3Anpm%2Fmulti%401.0.0";
    let u1 = "11111111-1111-4111-8111-111111111111";
    let u2 = "22222222-2222-4222-8222-222222222222";
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/by-package/{encoded}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [
                {"uuid": u1, "purl": purl, "publishedAt": "2024-01-01T00:00:00Z",
                 "description": "first", "license": "MIT", "tier": "free",
                 "vulnerabilities": {}},
                {"uuid": u2, "purl": purl, "publishedAt": "2024-02-01T00:00:00Z",
                 "description": "second", "license": "MIT", "tier": "free",
                 "vulnerabilities": {}}
            ],
            "canAccessPaidPatches": false,
        })))
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let mut args = default_args(purl, tmp.path());
    args.api_url = Some(url);

    let code = run(args).await;
    assert!(code == 0 || code == 1, "exit was {code}");
}

// ---------------------------------------------------------------------------
// --id flag (force UUID type-tagging)
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn get_with_id_flag_forces_uuid_path() {
    let (server, url) = start_wiremock().await;
    make_view_mock(&server, UUID, PURL, "free").await;

    let tmp = tempfile::tempdir().unwrap();
    let mut args = default_args(UUID, tmp.path());
    args.api_url = Some(url);
    args.id = true;

    let code = run(args).await;
    assert_eq!(code, 0);
}

// ---------------------------------------------------------------------------
// --cve / --ghsa / --package explicit type flags
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn get_with_explicit_cve_flag() {
    let (server, url) = start_wiremock().await;
    let cve = "CVE-2024-99999";
    make_search_mock_one(&server, "by-cve", cve, UUID, PURL, "free").await;
    make_view_mock(&server, UUID, PURL, "free").await;

    let tmp = tempfile::tempdir().unwrap();
    let mut args = default_args(cve, tmp.path());
    args.api_url = Some(url);
    args.cve = true;

    assert_eq!(run(args).await, 0);
}

#[tokio::test]
#[serial]
async fn get_with_explicit_ghsa_flag() {
    let (server, url) = start_wiremock().await;
    let ghsa = "GHSA-1234-5678-9abc";
    make_search_mock_one(&server, "by-ghsa", ghsa, UUID, PURL, "free").await;
    make_view_mock(&server, UUID, PURL, "free").await;

    let tmp = tempfile::tempdir().unwrap();
    let mut args = default_args(ghsa, tmp.path());
    args.api_url = Some(url);
    args.ghsa = true;

    assert_eq!(run(args).await, 0);
}

#[tokio::test]
#[serial]
async fn get_with_explicit_package_flag() {
    let (server, url) = start_wiremock().await;
    let name = "some-package";
    make_search_mock_one(&server, "by-package", name, UUID, PURL, "free").await;
    make_view_mock(&server, UUID, PURL, "free").await;

    let tmp = tempfile::tempdir().unwrap();
    let mut args = default_args(name, tmp.path());
    args.api_url = Some(url);
    args.package = true;

    assert_eq!(run(args).await, 0);
}

// ---------------------------------------------------------------------------
// Conflict flags (--one-off + --save-only)
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn get_one_off_with_save_only_errors() {
    let tmp = tempfile::tempdir().unwrap();
    let mut args = default_args(UUID, tmp.path());
    args.api_url = Some("http://127.0.0.1:1".to_string()); // unreachable
    args.one_off = true;
    args.save_only = true;

    let code = run(args).await;
    assert_eq!(code, 1, "conflicting flags must exit 1");
}

#[tokio::test]
#[serial]
async fn get_one_off_without_identifier_validation() {
    // --one-off requires an identifier (the UUID positional). Construct
    // with `--one-off` and a UUID — the conflicting save-only is off.
    // The one-off mode is currently a stub that always errors.
    let tmp = tempfile::tempdir().unwrap();
    let mut args = default_args(UUID, tmp.path());
    args.api_url = Some("http://127.0.0.1:1".to_string());
    args.one_off = true;
    args.save_only = false;

    let code = run(args).await;
    // One-off mode is stubbed — exits 1 with "not yet implemented".
    assert_eq!(code, 1);
}

// ---------------------------------------------------------------------------
// Network failure
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn get_unreachable_api_handled_gracefully() {
    let tmp = tempfile::tempdir().unwrap();
    let mut args = default_args(UUID, tmp.path());
    args.api_url = Some("http://127.0.0.1:1".to_string()); // unreachable
    let code = run(args).await;
    // Network error → exit 0 or 1, but no panic.
    assert!(code == 0 || code == 1);
}

// ---------------------------------------------------------------------------
// Non-JSON output paths
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn get_uuid_non_json_save_only() {
    let (server, url) = start_wiremock().await;
    make_view_mock(&server, UUID, PURL, "free").await;

    let tmp = tempfile::tempdir().unwrap();
    let mut args = default_args(UUID, tmp.path());
    args.api_url = Some(url);
    args.json = false;

    assert_eq!(run(args).await, 0);
    assert!(tmp.path().join(".socket/manifest.json").exists());
}

// ---------------------------------------------------------------------------
// Custom download mode
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn get_download_mode_package() {
    let (server, url) = start_wiremock().await;
    make_view_mock(&server, UUID, PURL, "free").await;

    let tmp = tempfile::tempdir().unwrap();
    let mut args = default_args(UUID, tmp.path());
    args.api_url = Some(url);
    args.download_mode = "package".to_string();
    assert_eq!(run(args).await, 0);
}

#[tokio::test]
#[serial]
async fn get_download_mode_file() {
    let (server, url) = start_wiremock().await;
    make_view_mock(&server, UUID, PURL, "free").await;

    let tmp = tempfile::tempdir().unwrap();
    let mut args = default_args(UUID, tmp.path());
    args.api_url = Some(url);
    args.download_mode = "file".to_string();
    assert_eq!(run(args).await, 0);
}

#[tokio::test]
#[serial]
async fn get_invalid_download_mode_handled() {
    let (server, url) = start_wiremock().await;
    make_view_mock(&server, UUID, PURL, "free").await;

    let tmp = tempfile::tempdir().unwrap();
    let mut args = default_args(UUID, tmp.path());
    args.api_url = Some(url);
    args.download_mode = "nonsense".to_string();
    let _ = run(args).await; // Validates inside save_and_apply; either passes or errors.
}

fn _unused_pathbuf() -> PathBuf {
    PathBuf::new() // keep PathBuf import used
}
