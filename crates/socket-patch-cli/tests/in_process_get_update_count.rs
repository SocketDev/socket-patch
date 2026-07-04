//! In-process tests for the `updated` accounting in
//! `get::download_and_apply_patches`.
//!
//! Regression guard: the manifest-update count used to be tallied from a
//! pre-fetch scan of the manifest (`existing.uuid != search_result.uuid`),
//! so a patch whose detail fetch subsequently FAILED was still reported as
//! `updated`, and the misleading `[update] … (replacing …)` line printed
//! for a replacement that never happened. The count must now reflect only
//! patches whose record was actually replaced in the manifest.

use std::path::Path;

use serial_test::serial;
use socket_patch_cli::commands::get::{download_and_apply_patches, DownloadParams};
use socket_patch_core::api::client::ApiClientEnvOverrides;
use socket_patch_core::api::types::PatchSearchResult;
use std::collections::HashMap;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";
const PURL: &str = "pkg:npm/upd-pkg@1.0.0";
const OLD_UUID: &str = "00000000-0000-4000-8000-000000000000";
const NEW_UUID: &str = "11111111-1111-4111-8111-111111111111";

fn seed_manifest_with(root: &Path, purl: &str, uuid: &str) {
    let socket = root.join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    std::fs::write(
        socket.join("manifest.json"),
        format!(
            r#"{{ "patches": {{
                "{purl}": {{
                    "uuid": "{uuid}",
                    "exportedAt": "2024-01-01T00:00:00Z",
                    "files": {{}}, "vulnerabilities": {{}},
                    "description": "old", "license": "MIT", "tier": "free"
                }}
            }}}}"#
        ),
    )
    .unwrap();
}

fn search_result(uuid: &str, purl: &str) -> PatchSearchResult {
    PatchSearchResult {
        uuid: uuid.into(),
        purl: purl.into(),
        published_at: "2024-06-01T00:00:00Z".into(),
        description: "new".into(),
        license: "MIT".into(),
        tier: "free".into(),
        vulnerabilities: HashMap::new(),
    }
}

fn params(root: &Path, server: &MockServer) -> DownloadParams {
    DownloadParams {
        cwd: root.to_path_buf(),
        manifest_path: root.join(".socket/manifest.json"),
        org: Some(ORG.to_string()),
        // save_only isolates download bookkeeping from the apply step.
        save_only: true,
        global: false,
        global_prefix: None,
        json: true,
        silent: true,
        download_mode: "diff".to_string(),
        api_overrides: ApiClientEnvOverrides {
            api_url: Some(server.uri()),
            api_token: Some("fake".to_string()),
            org_slug: Some(ORG.to_string()),
            proxy_url: None,
        },
        strict: false,
        persist_blobs: true,
        // Skip release-narrowing; npm has no variants anyway.
        all_releases: true,
    }
}

/// A fetch error on a would-be update must NOT be counted as `updated`:
/// the manifest entry is untouched, so the run reports `failed: 1`,
/// `updated: 0`, and `partial_failure` (exit 1).
#[tokio::test]
#[serial]
async fn failed_update_fetch_is_not_counted_as_updated() {
    let server = MockServer::start().await;
    // The patch-view (detail) fetch fails outright.
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{NEW_UUID}")))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    // Manifest already has the PURL under a DIFFERENT uuid -> a naive
    // pre-fetch scan would classify this as an update before the fetch.
    seed_manifest_with(tmp.path(), PURL, OLD_UUID);

    let selected = vec![search_result(NEW_UUID, PURL)];
    let (code, json) = download_and_apply_patches(&selected, &params(tmp.path(), &server)).await;

    assert_eq!(code, 1, "a failed detail fetch must exit 1; json={json}");
    assert_eq!(json["status"], "partial_failure", "json={json}");
    assert_eq!(
        json["failed"], 1,
        "the fetch failure must be counted; json={json}"
    );
    assert_eq!(
        json["updated"], 0,
        "a patch that never downloaded must not be counted as updated; json={json}"
    );
    assert_eq!(json["downloaded"], 0, "json={json}");

    // The manifest entry must be left at the OLD uuid — nothing was replaced.
    let body = std::fs::read_to_string(tmp.path().join(".socket/manifest.json")).unwrap();
    let manifest: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        manifest["patches"][PURL]["uuid"], OLD_UUID,
        "a failed update must not mutate the existing manifest record; manifest={manifest}"
    );
}

/// A successful update IS counted exactly once, and the replaced record
/// carries the prior uuid as `oldUuid`.
#[tokio::test]
#[serial]
async fn successful_update_is_counted_once() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{NEW_UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": NEW_UUID,
            "purl": PURL,
            "publishedAt": "2024-06-01T00:00:00Z",
            "files": {
                "package/index.js": {
                    "beforeHash": "0000000000000000000000000000000000000000000000000000000000000000",
                    "afterHash":  "1111111111111111111111111111111111111111111111111111111111111111",
                    "blobContent": "cGF0Y2hlZAo=",
                    "beforeBlobContent": "b3JpZ2luYWwK",
                }
            },
            "vulnerabilities": {},
            "description": "new", "license": "MIT", "tier": "free",
        })))
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    seed_manifest_with(tmp.path(), PURL, OLD_UUID);

    let selected = vec![search_result(NEW_UUID, PURL)];
    let (code, json) = download_and_apply_patches(&selected, &params(tmp.path(), &server)).await;

    // save_only => no apply step => clean success.
    assert_eq!(code, 0, "save-only update should succeed; json={json}");
    assert_eq!(json["status"], "success", "json={json}");
    assert_eq!(
        json["updated"], 1,
        "the replacement must be counted once; json={json}"
    );
    assert_eq!(json["downloaded"], 1, "json={json}");
    assert_eq!(json["failed"], 0, "json={json}");

    // The per-patch record is an `updated` action carrying the prior uuid.
    let patches = json["patches"].as_array().unwrap();
    assert_eq!(patches.len(), 1);
    assert_eq!(patches[0]["action"], "updated", "json={json}");
    assert_eq!(patches[0]["oldUuid"], OLD_UUID, "json={json}");

    // The manifest record was actually replaced with the new uuid.
    let body = std::fs::read_to_string(tmp.path().join(".socket/manifest.json")).unwrap();
    let manifest: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        manifest["patches"][PURL]["uuid"], NEW_UUID,
        "manifest={manifest}"
    );
}
