//! Integration coverage for `api::blob_fetcher`'s early-return /
//! filesystem-error branches the existing apply/scan e2e tests
//! never drive (those tests stage all blobs in advance so the
//! fetcher only sees the "nothing to do" path through the inner
//! loop).

use socket_patch_core::api::blob_fetcher::{
    fetch_blobs_by_hash, fetch_missing_blobs, fetch_missing_sources, get_missing_archives,
    get_missing_blobs, DownloadMode,
};
use socket_patch_core::api::client::{ApiClient, ApiClientOptions};
use socket_patch_core::manifest::schema::PatchManifest;
use socket_patch_core::patch::apply::PatchSources;
use std::collections::HashSet;
use std::path::Path;

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

/// `get_missing_archives` against an empty manifest returns empty
/// — no patches means no archives to look for.
#[tokio::test]
async fn get_missing_archives_empty_manifest_returns_empty_set() {
    let tmp = tempfile::tempdir().unwrap();
    let archives_dir = tmp.path().join("archives");
    std::fs::create_dir(&archives_dir).unwrap();
    let manifest = PatchManifest::new();
    let missing = get_missing_archives(&manifest, &archives_dir).await;
    assert!(missing.is_empty());
}

/// `fetch_missing_sources` with a `None` packages_path while
/// requesting `DownloadMode::Package` returns the empty-result
/// envelope without I/O — covers the "no path configured" fallback
/// hint documented in the function's rustdoc.
#[tokio::test]
async fn fetch_missing_sources_package_mode_with_no_packages_path() {
    let tmp = tempfile::tempdir().unwrap();
    let blobs = tmp.path().join("blobs");
    std::fs::create_dir(&blobs).unwrap();
    let sources = PatchSources {
        blobs_path: &blobs,
        packages_path: None,
        diffs_path: None,
    };
    let manifest = PatchManifest::new();
    let client = dummy_client();
    let result =
        fetch_missing_sources(&manifest, &sources, DownloadMode::Package, &client, None).await;
    assert_eq!(result.total, 0);
    assert_eq!(result.downloaded, 0);
    assert_eq!(result.failed, 0);
}

/// Same with `DownloadMode::Diff` and no diffs_path.
#[tokio::test]
async fn fetch_missing_sources_diff_mode_with_no_diffs_path() {
    let tmp = tempfile::tempdir().unwrap();
    let blobs = tmp.path().join("blobs");
    std::fs::create_dir(&blobs).unwrap();
    let sources = PatchSources {
        blobs_path: &blobs,
        packages_path: None,
        diffs_path: None,
    };
    let manifest = PatchManifest::new();
    let client = dummy_client();
    let result =
        fetch_missing_sources(&manifest, &sources, DownloadMode::Diff, &client, None).await;
    assert_eq!(result.total, 0);
}

/// `DownloadMode::parse` accepts all documented values plus the
/// `"blob"` synonym for `File`, and rejects unknown strings.
#[test]
fn download_mode_parse_covers_all_branches() {
    assert!(matches!(DownloadMode::parse("diff"), Ok(DownloadMode::Diff)));
    assert!(matches!(
        DownloadMode::parse("package"),
        Ok(DownloadMode::Package)
    ));
    assert!(matches!(DownloadMode::parse("file"), Ok(DownloadMode::File)));
    assert!(matches!(DownloadMode::parse("blob"), Ok(DownloadMode::File)));
    // Case-insensitive.
    assert!(matches!(DownloadMode::parse("DIFF"), Ok(DownloadMode::Diff)));
    assert!(matches!(
        DownloadMode::parse("Package"),
        Ok(DownloadMode::Package)
    ));
    // Unknown value → Err.
    assert!(DownloadMode::parse("invalid").is_err());
    assert!(DownloadMode::parse("").is_err());
}

/// `DownloadMode::as_tag` round-trips with `parse` for all variants.
#[test]
fn download_mode_as_tag_round_trips_with_parse() {
    for mode in [DownloadMode::Diff, DownloadMode::Package, DownloadMode::File] {
        let tag = mode.as_tag();
        assert_eq!(DownloadMode::parse(tag).unwrap(), mode);
    }
}

// Marker so `Path` import isn't unused.
#[allow(dead_code)]
fn _path_marker(_p: &Path) {}

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
