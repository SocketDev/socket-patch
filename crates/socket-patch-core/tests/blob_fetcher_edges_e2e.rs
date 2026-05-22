//! Integration coverage for `api::blob_fetcher`'s early-return /
//! filesystem-error branches the existing apply/scan e2e tests
//! never drive (those tests stage all blobs in advance so the
//! fetcher only sees the "nothing to do" path through the inner
//! loop).

use socket_patch_core::api::blob_fetcher::{
    fetch_blobs_by_hash, fetch_missing_blobs, get_missing_blobs,
};
use socket_patch_core::api::client::{ApiClient, ApiClientOptions};
use socket_patch_core::manifest::schema::PatchManifest;
use std::collections::HashSet;

/// Build an `ApiClient` that never actually performs network I/O.
/// Tests below use it only to satisfy the `&ApiClient` parameter
/// of fetcher functions whose early-return paths short-circuit
/// before any HTTP call.
fn dummy_client() -> ApiClient {
    ApiClient::new(ApiClientOptions {
        api_url: "http://127.0.0.1:1".to_string(),
        api_token: None,
        use_public_proxy: true,
        org_slug: None,
    })
}

/// `fetch_missing_blobs` with a fresh manifest reports `total=0`
/// downloaded=0 without touching the API — there's nothing to do.
#[tokio::test]
async fn fetch_missing_blobs_empty_manifest_short_circuits() {
    let tmp = tempfile::tempdir().unwrap();
    let blobs = tmp.path().join("blobs");
    std::fs::create_dir(&blobs).unwrap();
    let manifest = PatchManifest::new();
    let client = dummy_client();

    let result = fetch_missing_blobs(&manifest, &blobs, &client, None).await;
    assert_eq!(result.total, 0);
    assert_eq!(result.downloaded, 0);
    assert_eq!(result.failed, 0);
    assert!(result.results.is_empty());
}

/// `fetch_blobs_by_hash` with an empty set returns the empty-result
/// envelope without I/O.
#[tokio::test]
async fn fetch_blobs_by_hash_empty_set_short_circuits() {
    let tmp = tempfile::tempdir().unwrap();
    let blobs = tmp.path().join("blobs");
    std::fs::create_dir(&blobs).unwrap();
    let hashes: HashSet<String> = HashSet::new();
    let client = dummy_client();

    let result = fetch_blobs_by_hash(&hashes, &blobs, &client, None).await;
    assert_eq!(result.total, 0);
    assert_eq!(result.downloaded, 0);
    assert_eq!(result.failed, 0);
    assert!(result.results.is_empty());
}

/// `fetch_blobs_by_hash` with a hash whose blob is already on disk
/// short-circuits the network call and reports `skipped: 1`. Covers
/// the `skip if already on disk` branch (~L200-220).
#[tokio::test]
async fn fetch_blobs_by_hash_skips_existing_blobs() {
    use std::collections::HashSet;
    let tmp = tempfile::tempdir().unwrap();
    let blobs = tmp.path().join("blobs");
    std::fs::create_dir(&blobs).unwrap();
    let hash = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
    std::fs::write(blobs.join(hash), b"already here").unwrap();
    let mut hashes = HashSet::new();
    hashes.insert(hash.to_string());

    let client = dummy_client();
    let result = fetch_blobs_by_hash(&hashes, &blobs, &client, None).await;
    assert_eq!(result.total, 1, "one hash requested");
    assert_eq!(result.downloaded, 0, "already-on-disk needs no download");
    assert_eq!(result.skipped, 1, "exactly one skipped");
    assert_eq!(result.failed, 0);
    assert!(result.results.iter().any(|r| r.success && r.hash == hash));
}

/// `get_missing_blobs` against a manifest that lists no patches
/// returns the empty set. Covers the early-return inside the
/// function — the existing apply tests always stage at least one
/// patch, so this branch needed its own driver.
#[tokio::test]
async fn get_missing_blobs_empty_manifest_returns_empty_set() {
    let tmp = tempfile::tempdir().unwrap();
    let blobs = tmp.path().join("blobs");
    std::fs::create_dir(&blobs).unwrap();
    let manifest = PatchManifest::new();

    let missing = get_missing_blobs(&manifest, &blobs).await;
    assert!(missing.is_empty());
}
