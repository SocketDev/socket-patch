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

use std::path::Path;

use serial_test::serial;
use socket_patch_cli::commands::get::{run, GetArgs};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";
const UUID: &str = "11111111-1111-4111-8111-111111111111";
const PURL: &str = "pkg:npm/in-process-test@1.0.0";

fn default_args(identifier: &str, cwd: &Path) -> GetArgs {
    GetArgs {
        common: socket_patch_cli::args::GlobalArgs {
            org: Some(ORG.to_string()),
            cwd: cwd.to_path_buf(),
            yes: true,
                        api_token: Some("fake-token-for-tests".to_string()),
            global: false,
            global_prefix: None,
            json: true,
            download_mode: "diff".to_string(),
            ..socket_patch_cli::args::GlobalArgs::default()
        },
        identifier: identifier.to_string(),
        id: false,
        cve: false,
        ghsa: false,
        package: false,
        save_only: true,
        one_off: false,
        all_releases: false,
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

/// The after_hash declared by `make_view_mock` and the exact decoded bytes
/// of its `blobContent` (`base64("patched\n")`). Derived here independently
/// of the production decode path so a regression that mangles the blob shows.
const AFTER_HASH: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const BLOB_BYTES: &[u8] = b"patched\n";

/// Assert that a successful `get` persisted the patch for `purl`/`uuid`:
/// the manifest records the exact uuid, and the after-hash blob holds the
/// exact decoded bytes. This is the full observable contract of a save —
/// asserting only `exit == 0` would let a no-op implementation pass.
fn assert_patch_saved(cwd: &Path, purl: &str, uuid: &str) {
    let manifest_path = cwd.join(".socket/manifest.json");
    assert!(manifest_path.exists(), "manifest must be written");
    let body = std::fs::read_to_string(&manifest_path).unwrap();
    let m: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(
        m["patches"][purl].is_object(),
        "manifest must contain an entry for {purl}, got: {body}"
    );
    assert_eq!(
        m["patches"][purl]["uuid"], uuid,
        "manifest uuid must match the fetched patch"
    );

    let blob_path = cwd.join(".socket/blobs").join(AFTER_HASH);
    assert!(blob_path.exists(), "after-hash blob must be persisted");
    assert_eq!(
        std::fs::read(&blob_path).unwrap(),
        BLOB_BYTES,
        "blob must decode to the exact patched bytes"
    );
}

/// Assert that nothing was persisted to `.socket/` (no manifest written).
fn assert_no_manifest(cwd: &Path) {
    assert!(
        !cwd.join(".socket/manifest.json").exists(),
        "no manifest must be written"
    );
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
    args.common.api_url = url;

    let code = run(args).await;
    assert_eq!(code, 0, "expected exit 0");

    assert_patch_saved(tmp.path(), PURL, UUID);
}

#[tokio::test]
#[serial]
async fn get_by_uuid_writes_blob_to_socket_dir() {
    let (server, url) = start_wiremock().await;
    make_view_mock(&server, UUID, PURL, "free").await;

    let tmp = tempfile::tempdir().unwrap();
    let mut args = default_args(UUID, tmp.path());
    args.common.api_url = url;

    let code = run(args).await;
    assert_eq!(code, 0);

    let blob_path = tmp.path().join(".socket/blobs").join(AFTER_HASH);
    assert!(blob_path.exists(), "blob must be persisted");
    assert_eq!(std::fs::read(&blob_path).unwrap(), BLOB_BYTES);
    // The manifest must also reference the exact uuid we fetched.
    assert_patch_saved(tmp.path(), PURL, UUID);
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
    args.common.api_url = url;

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
    args.common.api_url = url;

    let code = run(args).await;
    // A 500 from the view endpoint is a fetch error: it flows through
    // `report_fetch_failure`, which always returns exit 1. Accepting 0 here
    // (the previous `0 || 1`) would let a regression that silently swallows
    // server errors and reports success pass unnoticed.
    assert_eq!(code, 1, "HTTP 500 must surface as a fetch failure (exit 1)");
    assert_no_manifest(tmp.path());
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
    args.common.api_url = url;

    let code = run(args).await;
    assert_eq!(code, 0);
    assert_patch_saved(tmp.path(), PURL, UUID);
}

#[tokio::test]
#[serial]
async fn get_by_cve_no_match_no_manifest_written() {
    let (server, url) = start_wiremock().await;
    make_search_mock_empty(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    let mut args = default_args("CVE-2099-99999", tmp.path());
    args.common.api_url = url;

    // An empty search result is a clean "nothing to do": exit 0 with no
    // side effects. Asserting the exit code (not `let _ =`) catches a
    // regression that turns no-match into an error or silently saves.
    let code = run(args).await;
    assert_eq!(code, 0, "no-match CVE search must exit 0");
    assert_no_manifest(tmp.path());
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
    args.common.api_url = url;

    let code = run(args).await;
    assert_eq!(code, 0);
    assert_patch_saved(tmp.path(), PURL, UUID);
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
    args.common.api_url = url;

    let code = run(args).await;
    assert_eq!(code, 0);
    assert_patch_saved(tmp.path(), PURL, UUID);
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
    args.common.api_url = url;

    let code = run(args).await;
    // Two distinct free patches for one PURL + --json: `select_patches`
    // returns `Err(1)` (status `selection_required`) because it cannot
    // prompt non-interactively. The previous `0 || 1` accepted the broken
    // case where the CLI silently auto-picks one and reports success — the
    // exact behavior this test exists to forbid.
    assert_eq!(code, 1, "ambiguous multi-patch selection in --json must exit 1");
    // And it must NOT have downloaded/saved an arbitrarily-chosen patch.
    assert_no_manifest(tmp.path());
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
    args.common.api_url = url;
    args.id = true;

    let code = run(args).await;
    assert_eq!(code, 0);
    // --id forces the UUID fetch+save path; verify it actually saved.
    assert_patch_saved(tmp.path(), PURL, UUID);
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
    args.common.api_url = url;
    args.cve = true;

    assert_eq!(run(args).await, 0);
    assert_patch_saved(tmp.path(), PURL, UUID);
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
    args.common.api_url = url;
    args.ghsa = true;

    assert_eq!(run(args).await, 0);
    assert_patch_saved(tmp.path(), PURL, UUID);
}

#[tokio::test]
#[serial]
async fn get_with_explicit_package_flag() {
    // NOTE: `--package` does NOT hit the `by-package/<name>` endpoint with
    // the raw identifier. It routes through `crawl_all_ecosystems` over the
    // cwd, fuzzy-matches the discovered packages, then searches by the best
    // match's PURL. In this empty tempdir there are no installed packages,
    // so the run short-circuits on `no_packages` and exits 0 WITHOUT ever
    // contacting the mounted mock. We assert that contract precisely: exit 0
    // and no manifest. (A previous version asserted only `== 0`, which hid
    // the fact that the mock is never exercised.)
    let (server, url) = start_wiremock().await;
    let name = "some-package";
    make_search_mock_one(&server, "by-package", name, UUID, PURL, "free").await;
    make_view_mock(&server, UUID, PURL, "free").await;

    let tmp = tempfile::tempdir().unwrap();
    let mut args = default_args(name, tmp.path());
    args.common.api_url = url;
    args.package = true;

    let code = run(args).await;
    assert_eq!(code, 0, "no installed packages → no_packages, exit 0");
    assert_no_manifest(tmp.path());
}

// ---------------------------------------------------------------------------
// Conflict flags (--one-off + --save-only)
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn get_one_off_with_save_only_errors() {
    let tmp = tempfile::tempdir().unwrap();
    let mut args = default_args(UUID, tmp.path());
    args.common.api_url = "http://127.0.0.1:1".to_string(); // unreachable
    args.one_off = true;
    args.save_only = true;

    let code = run(args).await;
    assert_eq!(code, 1, "conflicting flags must exit 1");
    // The conflict is rejected up front, before any fetch — nothing saved.
    assert_no_manifest(tmp.path());
}

#[tokio::test]
#[serial]
async fn get_one_off_without_identifier_validation() {
    // CAVEAT: `--one-off` is NOT specially handled in the UUID path — there
    // is no "not yet implemented" stub (the original comment here was wrong).
    // With the API unreachable, the UUID fetch fails and `report_fetch_failure`
    // returns exit 1. So this test really exercises the network-failure path
    // with one_off set, not a one-off stub. We pin the observable contract:
    // exit 1 and nothing written.
    let tmp = tempfile::tempdir().unwrap();
    let mut args = default_args(UUID, tmp.path());
    args.common.api_url = "http://127.0.0.1:1".to_string();
    args.one_off = true;
    args.save_only = false;

    let code = run(args).await;
    assert_eq!(code, 1, "unreachable API fetch must exit 1");
    assert_no_manifest(tmp.path());
}

// ---------------------------------------------------------------------------
// Network failure
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn get_unreachable_api_handled_gracefully() {
    let tmp = tempfile::tempdir().unwrap();
    let mut args = default_args(UUID, tmp.path());
    args.common.api_url = "http://127.0.0.1:1".to_string(); // unreachable
    let code = run(args).await;
    // A connection refused on the view endpoint is a fetch error and must
    // surface as exit 1 (via `report_fetch_failure`). The previous
    // `0 || 1` would also have accepted a silent success on a dead network.
    assert_eq!(code, 1, "unreachable API must exit 1");
    assert_no_manifest(tmp.path());
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
    args.common.api_url = url;
    args.common.json = false;

    assert_eq!(run(args).await, 0);
    assert_patch_saved(tmp.path(), PURL, UUID);
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
    args.common.api_url = url;
    args.common.download_mode = "package".to_string();
    assert_eq!(run(args).await, 0);
    // save_only short-circuits before apply, so download_mode is not
    // consumed here; we still verify the patch was actually persisted.
    assert_patch_saved(tmp.path(), PURL, UUID);
}

#[tokio::test]
#[serial]
async fn get_download_mode_file() {
    let (server, url) = start_wiremock().await;
    make_view_mock(&server, UUID, PURL, "free").await;

    let tmp = tempfile::tempdir().unwrap();
    let mut args = default_args(UUID, tmp.path());
    args.common.api_url = url;
    args.common.download_mode = "file".to_string();
    assert_eq!(run(args).await, 0);
    assert_patch_saved(tmp.path(), PURL, UUID);
}

#[tokio::test]
#[serial]
async fn get_invalid_download_mode_handled() {
    let (server, url) = start_wiremock().await;
    make_view_mock(&server, UUID, PURL, "free").await;

    let tmp = tempfile::tempdir().unwrap();
    let mut args = default_args(UUID, tmp.path());
    args.common.api_url = url;
    args.common.download_mode = "nonsense".to_string();

    // FINDING: an invalid download mode is NOT validated on the save_only
    // UUID path. `save_and_apply_patch` only parses download_mode when it
    // actually runs apply (`!save_only && added`), so with save_only=true the
    // bogus "nonsense" mode is silently accepted: the run still exits 0 and
    // saves the patch. We assert that exact (current) behavior rather than
    // the original `let _ = run(...)` no-op, so any change to validation here
    // is caught. This is a latent gap, deliberately left for the maintainers.
    let code = run(args).await;
    assert_eq!(
        code, 0,
        "invalid download_mode is not validated under --save-only (exits 0)"
    );
    assert_patch_saved(tmp.path(), PURL, UUID);
}
