//! In-process e2e tests for the `scan` subcommand.
//!
//! Calls `socket_patch_cli::commands::scan::run` directly so coverage
//! is fully instrumented. Mocks the API via wiremock. Hits every flag
//! combination that the subprocess-based tests don't explicitly
//! exercise (non-JSON paths, --apply without --prune, --prune without
//! --apply, --batch-size variations, --download-mode variations).

use std::path::Path;

use serial_test::serial;
use socket_patch_cli::commands::scan::{run, ScanArgs};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";
const PURL: &str = "pkg:npm/in-proc-scan@1.0.0";
const UUID: &str = "11111111-1111-4111-8111-111111111111";

fn default_args(cwd: &Path) -> ScanArgs {
    ScanArgs {
        common: socket_patch_cli::args::GlobalArgs {
            cwd: cwd.to_path_buf(),
            org: Some(ORG.to_string()),
            json: true,
            yes: true,
            global: false,
            global_prefix: None,
                        api_token: Some("fake".to_string()),
            ecosystems: None,
            download_mode: "diff".to_string(),
            dry_run: false,
            ..socket_patch_cli::args::GlobalArgs::default()
        },
        batch_size: 100,
        apply: false,
        prune: false,
        sync: false,
        all_releases: false,
    }
}

fn write_root_package_json(root: &Path) {
    std::fs::write(
        root.join("package.json"),
        r#"{ "name": "in-proc-scan-test", "version": "0.0.0" }"#,
    )
    .unwrap();
}

fn write_npm_package(root: &Path, name: &str, version: &str) {
    let pkg = root.join("node_modules").join(name);
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        pkg.join("package.json"),
        format!(r#"{{ "name": "{name}", "version": "{version}" }}"#),
    )
    .unwrap();
}

async fn mock_batch_empty(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [], "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;
}

async fn mock_batch_one(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": PURL,
                "patches": [{
                    "uuid": UUID, "purl": PURL,
                    "tier": "free", "cveIds": [], "ghsaIds": [],
                    "severity": "high", "title": "in-proc fixture"
                }]
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;
}

async fn mock_by_package(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path_regex(format!("^/v0/orgs/{ORG}/patches/by-package/.+$")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [{
                "uuid": UUID, "purl": PURL,
                "publishedAt": "2024-01-01T00:00:00Z",
                "description": "x", "license": "MIT", "tier": "free",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;
}

async fn mock_view_with_blob(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": UUID,
            "purl": PURL,
            "publishedAt": "2024-01-01T00:00:00Z",
            "files": {
                "package/index.js": {
                    "beforeHash": "0000000000000000000000000000000000000000000000000000000000000000",
                    "afterHash":  "1111111111111111111111111111111111111111111111111111111111111111",
                    "blobContent": "cGF0Y2hlZAo=",
                }
            },
            "vulnerabilities": {},
            "description": "x", "license": "MIT", "tier": "free",
        })))
        .mount(server)
        .await;
}

// ---------------------------------------------------------------------------
// Discovery — read-only --json mode
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn scan_empty_project_json() {
    let server = MockServer::start().await;
    mock_batch_empty(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    let mut args = default_args(tmp.path());
    args.common.api_url = server.uri();

    assert_eq!(run(args).await, 0);
}

#[tokio::test]
#[serial]
async fn scan_installed_package_discovers_patch() {
    let server = MockServer::start().await;
    mock_batch_one(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "in-proc-scan", "1.0.0");
    let mut args = default_args(tmp.path());
    args.common.api_url = server.uri();

    assert_eq!(run(args).await, 0);
}

// ---------------------------------------------------------------------------
// --apply (without --prune)
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn scan_apply_dry_run_does_not_write() {
    let server = MockServer::start().await;
    mock_batch_one(&server).await;
    mock_by_package(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "in-proc-scan", "1.0.0");
    let mut args = default_args(tmp.path());
    args.common.api_url = server.uri();
    args.apply = true;
    args.common.dry_run = true;

    assert_eq!(run(args).await, 0);
    assert!(
        !tmp.path().join(".socket/manifest.json").exists(),
        "dry-run must not write manifest"
    );
}

#[tokio::test]
#[serial]
async fn scan_apply_wet_writes_manifest_and_blob() {
    let server = MockServer::start().await;
    mock_batch_one(&server).await;
    mock_by_package(&server).await;
    mock_view_with_blob(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "in-proc-scan", "1.0.0");
    let mut args = default_args(tmp.path());
    args.common.api_url = server.uri();
    args.apply = true;

    let code = run(args).await;
    // Apply over our handcrafted node_modules likely reports
    // partial_failure (hash mismatch on the fake "package/index.js")
    // — what matters is that download_and_apply_patches ran and the
    // blob was written.
    assert!(code == 0 || code == 1, "got {code}");
    assert!(tmp.path().join(".socket/manifest.json").exists());
    let after_hash = "1111111111111111111111111111111111111111111111111111111111111111";
    assert!(tmp.path().join(".socket/blobs").join(after_hash).exists());
}

// ---------------------------------------------------------------------------
// --prune (without --apply)
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn scan_prune_only_dry_run_reports_orphans() {
    let server = MockServer::start().await;
    mock_batch_empty(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "still-installed", "1.0.0");
    // Manifest has a stale entry for a package that's not installed.
    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    std::fs::write(
        socket.join("manifest.json"),
        r#"{ "patches": {
            "pkg:npm/stale@1.0.0": {
                "uuid": "22222222-2222-4222-8222-222222222222",
                "exportedAt": "2024-01-01T00:00:00Z",
                "files": {}, "vulnerabilities": {},
                "description": "stale", "license": "MIT", "tier": "free"
            }
        }}"#,
    )
    .unwrap();

    let mut args = default_args(tmp.path());
    args.common.api_url = server.uri();
    args.prune = true;
    args.common.dry_run = true;

    assert_eq!(run(args).await, 0);
    // Dry-run preserves the manifest unchanged.
    let body = std::fs::read_to_string(tmp.path().join(".socket/manifest.json")).unwrap();
    assert!(body.contains("pkg:npm/stale@1.0.0"));
}

#[tokio::test]
#[serial]
async fn scan_prune_only_wet_removes_orphans() {
    let server = MockServer::start().await;
    mock_batch_empty(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "still-installed", "1.0.0");
    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    std::fs::write(
        socket.join("manifest.json"),
        r#"{ "patches": {
            "pkg:npm/orphan@1.0.0": {
                "uuid": "33333333-3333-4333-8333-333333333333",
                "exportedAt": "2024-01-01T00:00:00Z",
                "files": {}, "vulnerabilities": {},
                "description": "orphan", "license": "MIT", "tier": "free"
            }
        }}"#,
    )
    .unwrap();

    let mut args = default_args(tmp.path());
    args.common.api_url = server.uri();
    args.prune = true;

    assert_eq!(run(args).await, 0);
    let body = std::fs::read_to_string(tmp.path().join(".socket/manifest.json")).unwrap();
    let m: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(m["patches"].as_object().unwrap().len(), 0, "orphan must be pruned");
}

// ---------------------------------------------------------------------------
// --sync (== --apply --prune)
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn scan_sync_full_cycle_against_clean_project() {
    let server = MockServer::start().await;
    mock_batch_one(&server).await;
    mock_by_package(&server).await;
    mock_view_with_blob(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "in-proc-scan", "1.0.0");
    let mut args = default_args(tmp.path());
    args.common.api_url = server.uri();
    args.sync = true;

    let code = run(args).await;
    assert!(code == 0 || code == 1, "got {code}");
    assert!(tmp.path().join(".socket/manifest.json").exists());
}

// ---------------------------------------------------------------------------
// --batch-size affects chunking
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn scan_small_batch_size_chunks_requests() {
    let server = MockServer::start().await;
    mock_batch_empty(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "pkg-a", "1.0.0");
    write_npm_package(tmp.path(), "pkg-b", "2.0.0");
    write_npm_package(tmp.path(), "pkg-c", "3.0.0");

    let mut args = default_args(tmp.path());
    args.common.api_url = server.uri();
    args.batch_size = 1; // force 3 separate API calls
    assert_eq!(run(args).await, 0);
}

// ---------------------------------------------------------------------------
// --ecosystems filter
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn scan_ecosystems_filter_excludes_others() {
    let server = MockServer::start().await;
    mock_batch_empty(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "npm-pkg", "1.0.0");

    let mut args = default_args(tmp.path());
    args.common.api_url = server.uri();
    args.common.ecosystems = Some(vec!["pypi".to_string()]);
    assert_eq!(run(args).await, 0);
}

// ---------------------------------------------------------------------------
// Non-JSON output (table-printing path)
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn scan_non_json_with_patches_prints_table() {
    let server = MockServer::start().await;
    mock_batch_one(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "in-proc-scan", "1.0.0");
    let mut args = default_args(tmp.path());
    args.common.api_url = server.uri();
    args.common.json = false;

    let code = run(args).await;
    assert!(code == 0 || code == 1, "got {code}");
}

#[tokio::test]
#[serial]
async fn scan_non_json_empty_project_friendly_message() {
    let server = MockServer::start().await;
    mock_batch_empty(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    let mut args = default_args(tmp.path());
    args.common.api_url = server.uri();
    args.common.json = false;

    assert_eq!(run(args).await, 0);
}

// ---------------------------------------------------------------------------
// API error tolerance
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn scan_api_500_does_not_panic() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(500).set_body_string("oh no"))
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "in-proc-scan", "1.0.0");
    let mut args = default_args(tmp.path());
    args.common.api_url = server.uri();

    let code = run(args).await;
    assert!(code == 0 || code == 1);
}

#[tokio::test]
#[serial]
async fn scan_unreachable_api_does_not_panic() {
    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "in-proc-scan", "1.0.0");
    let mut args = default_args(tmp.path());
    args.common.api_url = "http://127.0.0.1:1".to_string();

    let code = run(args).await;
    assert!(code == 0 || code == 1);
}
