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
use socket_patch_core::manifest::schema::{PatchFileInfo, PatchManifest, PatchRecord};
use socket_patch_core::patch::apply::PatchSources;
use std::collections::HashMap;
use std::collections::HashSet;
use std::path::Path;

/// Build an `ApiClient` pointed at a closed port so any *actual* HTTP
/// call fails fast (connection refused). The short-circuit tests rely
/// on this: if a branch that is supposed to do zero I/O ever regresses
/// into making a request, the call fails and shows up as `failed > 0`
/// rather than silently passing.
fn dummy_client() -> ApiClient {
    ApiClient::new(ApiClientOptions {
        api_url: "http://127.0.0.1:1".to_string(),
        api_token: None,
        use_public_proxy: true,
        org_slug: None,
    })
}

/// A manifest carrying real `afterHash` blobs and a patch UUID, so that
/// the various "missing work" code paths have something to find. Used to
/// make the short-circuit assertions *discriminating*: with a non-empty
/// manifest, `total == 0` can only come from the branch under test
/// short-circuiting — not from there being nothing to do at all.
fn manifest_with_after_hashes(after: &[&str]) -> PatchManifest {
    let mut files = HashMap::new();
    for (i, h) in after.iter().enumerate() {
        files.insert(
            format!("package/file{i}.js"),
            PatchFileInfo {
                before_hash: format!("{:0>64}", format!("be{i}")),
                after_hash: (*h).to_string(),
            },
        );
    }
    let mut patches = HashMap::new();
    patches.insert(
        "pkg:npm/test@1.0.0".to_string(),
        PatchRecord {
            uuid: "11111111-1111-4111-8111-111111111111".to_string(),
            exported_at: "2024-01-01T00:00:00Z".to_string(),
            files,
            vulnerabilities: HashMap::new(),
            description: "test".to_string(),
            license: "MIT".to_string(),
            tier: "free".to_string(),
        },
    );
    PatchManifest { patches }
}

/// Count the directory entries under `dir` (used to prove a short-circuit
/// did zero filesystem writes).
fn dir_entry_count(dir: &Path) -> usize {
    std::fs::read_dir(dir).unwrap().count()
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
    assert_eq!(result.skipped, 0);
    assert!(result.results.is_empty());
    // The short-circuit must not have written anything to disk.
    assert_eq!(dir_entry_count(&blobs), 0, "no blobs should be created");
}

/// Discriminator for the test above: a NON-empty manifest with a missing
/// `afterHash` blob is genuinely actionable, so `fetch_missing_blobs`
/// must attempt a download (which fails against the closed-port client)
/// rather than reporting "nothing to do". This proves the empty-manifest
/// `total == 0` above comes from the short-circuit, not from the function
/// always returning a default result.
#[tokio::test]
async fn fetch_missing_blobs_nonempty_manifest_attempts_download() {
    let tmp = tempfile::tempdir().unwrap();
    let blobs = tmp.path().join("blobs");
    std::fs::create_dir(&blobs).unwrap();
    let manifest = manifest_with_after_hashes(&[&"a".repeat(64)]);
    let client = dummy_client();

    let result = fetch_missing_blobs(&manifest, &blobs, &client, None).await;
    assert_eq!(result.total, 1, "one missing afterHash blob");
    assert_eq!(result.downloaded, 0, "closed-port client cannot download");
    assert_eq!(result.failed, 1, "the download attempt must be recorded as failed");
    assert_eq!(result.results.len(), 1);
    assert!(!result.results[0].success);
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
    assert_eq!(result.skipped, 0);
    assert!(result.results.is_empty());
    assert_eq!(dir_entry_count(&blobs), 0, "no blobs should be created");
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

/// Discriminator: a non-empty manifest whose archive is absent from disk
/// must be reported as missing — proving `get_missing_archives` actually
/// inspects manifest+disk rather than being a constant-empty stub.
#[tokio::test]
async fn get_missing_archives_reports_missing_archive() {
    let tmp = tempfile::tempdir().unwrap();
    let archives_dir = tmp.path().join("archives");
    std::fs::create_dir(&archives_dir).unwrap();
    let manifest = manifest_with_after_hashes(&[&"a".repeat(64)]);
    let uuid = "11111111-1111-4111-8111-111111111111";

    // Archive absent → reported missing.
    let missing = get_missing_archives(&manifest, &archives_dir).await;
    assert_eq!(missing.len(), 1);
    assert!(missing.contains(uuid));

    // Stage the archive → no longer missing.
    std::fs::write(archives_dir.join(format!("{uuid}.tar.gz")), b"data").unwrap();
    let missing = get_missing_archives(&manifest, &archives_dir).await;
    assert!(
        missing.is_empty(),
        "archive present on disk must not be reported missing"
    );
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
    // Non-empty manifest: there IS work to do. So `total == 0` below can
    // only mean the None-packages_path branch short-circuited — not that
    // the manifest was empty or that the call silently fell through to
    // File mode (which would attempt — and fail — a download here).
    let manifest = manifest_with_after_hashes(&[&"a".repeat(64)]);
    let client = dummy_client();

    // Control: File mode against the same manifest genuinely tries to work.
    let file_mode =
        fetch_missing_sources(&manifest, &sources, DownloadMode::File, &client, None).await;
    assert_eq!(file_mode.total, 1, "File mode must find the missing blob");
    assert_eq!(file_mode.failed, 1, "and attempt (failing) to download it");

    let result =
        fetch_missing_sources(&manifest, &sources, DownloadMode::Package, &client, None).await;
    assert_eq!(result.total, 0, "Package mode w/o packages_path must short-circuit");
    assert_eq!(result.downloaded, 0);
    assert_eq!(result.failed, 0);
    assert_eq!(result.skipped, 0);
    assert!(result.results.is_empty());
    // The short-circuit must not have written any blob.
    assert_eq!(dir_entry_count(&blobs), 0, "Package-mode short-circuit did zero I/O");
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
    let manifest = manifest_with_after_hashes(&[&"a".repeat(64)]);
    let client = dummy_client();

    // Control: File mode against the same manifest genuinely tries to work.
    let file_mode =
        fetch_missing_sources(&manifest, &sources, DownloadMode::File, &client, None).await;
    assert_eq!(file_mode.total, 1, "File mode must find the missing blob");
    assert_eq!(file_mode.failed, 1, "and attempt (failing) to download it");

    let result =
        fetch_missing_sources(&manifest, &sources, DownloadMode::Diff, &client, None).await;
    assert_eq!(result.total, 0, "Diff mode w/o diffs_path must short-circuit");
    assert_eq!(result.downloaded, 0);
    assert_eq!(result.failed, 0);
    assert_eq!(result.skipped, 0);
    assert!(result.results.is_empty());
    assert_eq!(dir_entry_count(&blobs), 0, "Diff-mode short-circuit did zero I/O");
}

/// `DownloadMode::parse` accepts all documented values plus the
/// `"blob"` synonym for `File`, and rejects unknown strings.
#[test]
fn download_mode_parse_covers_all_branches() {
    assert_eq!(DownloadMode::parse("diff").unwrap(), DownloadMode::Diff);
    assert_eq!(DownloadMode::parse("package").unwrap(), DownloadMode::Package);
    assert_eq!(DownloadMode::parse("file").unwrap(), DownloadMode::File);
    assert_eq!(DownloadMode::parse("blob").unwrap(), DownloadMode::File);
    // Case-insensitive.
    assert_eq!(DownloadMode::parse("DIFF").unwrap(), DownloadMode::Diff);
    assert_eq!(DownloadMode::parse("Package").unwrap(), DownloadMode::Package);
    assert_eq!(DownloadMode::parse("FILE").unwrap(), DownloadMode::File);
    assert_eq!(DownloadMode::parse("Blob").unwrap(), DownloadMode::File);
    // Unknown value → Err, and the message names the offending input.
    let err = DownloadMode::parse("invalid").unwrap_err();
    assert!(err.contains("invalid"), "error should echo the bad value: {err}");
    assert!(DownloadMode::parse("").is_err());
    // A near-miss must not be silently coerced to a valid mode.
    assert!(DownloadMode::parse("diffs").is_err());
    assert!(DownloadMode::parse("files").is_err());
}

/// `DownloadMode::as_tag` round-trips with `parse` for all variants, and
/// each variant maps to a *distinct* tag.
#[test]
fn download_mode_as_tag_round_trips_with_parse() {
    let variants = [DownloadMode::Diff, DownloadMode::Package, DownloadMode::File];
    let mut seen_tags = HashSet::new();
    for mode in variants {
        let tag = mode.as_tag();
        assert!(seen_tags.insert(tag), "tag {tag:?} must be unique per variant");
        assert_eq!(DownloadMode::parse(tag).unwrap(), mode);
    }
    // Pin the exact tag strings so a silent rename is caught.
    assert_eq!(DownloadMode::Diff.as_tag(), "diff");
    assert_eq!(DownloadMode::Package.as_tag(), "package");
    assert_eq!(DownloadMode::File.as_tag(), "file");
}

/// `fetch_blobs_by_hash` with a hash whose blob is already on disk
/// short-circuits the network call and reports `skipped: 1`, leaving the
/// existing file byte-for-byte untouched. Covers the `skip if already on
/// disk` branch (~L184-206).
#[tokio::test]
async fn fetch_blobs_by_hash_skips_existing_blobs() {
    let tmp = tempfile::tempdir().unwrap();
    let blobs = tmp.path().join("blobs");
    std::fs::create_dir(&blobs).unwrap();
    let hash = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
    let original = b"already here";
    std::fs::write(blobs.join(hash), original).unwrap();
    let mut hashes = HashSet::new();
    hashes.insert(hash.to_string());

    let client = dummy_client();
    let result = fetch_blobs_by_hash(&hashes, &blobs, &client, None).await;
    assert_eq!(result.total, 1, "one hash requested");
    assert_eq!(result.downloaded, 0, "already-on-disk needs no download");
    assert_eq!(result.skipped, 1, "exactly one skipped");
    assert_eq!(result.failed, 0);
    assert_eq!(result.results.len(), 1, "exactly one result entry");
    let entry = &result.results[0];
    assert!(entry.success && entry.hash == hash);
    assert!(entry.error.is_none(), "skip is not an error");

    // The skip must not have re-fetched or rewritten the file: its bytes
    // are exactly what we staged, and the dir holds only that one blob.
    let on_disk = std::fs::read(blobs.join(hash)).unwrap();
    assert_eq!(on_disk, original, "existing blob must be left untouched");
    assert_eq!(dir_entry_count(&blobs), 1, "no extra files written");
}

/// The skip is *selective*, not a blanket "report everything as skipped":
/// when one requested hash is on disk and another is not, the present one
/// is skipped while the absent one drives a (failing, closed-port)
/// download attempt.
#[tokio::test]
async fn fetch_blobs_by_hash_mixes_skip_and_download_attempt() {
    let tmp = tempfile::tempdir().unwrap();
    let blobs = tmp.path().join("blobs");
    std::fs::create_dir(&blobs).unwrap();
    let present = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
    let absent = "feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface";
    std::fs::write(blobs.join(present), b"present").unwrap();
    let mut hashes = HashSet::new();
    hashes.insert(present.to_string());
    hashes.insert(absent.to_string());

    let client = dummy_client();
    let result = fetch_blobs_by_hash(&hashes, &blobs, &client, None).await;
    assert_eq!(result.total, 2);
    assert_eq!(result.skipped, 1, "only the present blob is skipped");
    assert_eq!(result.downloaded, 0, "closed-port client downloads nothing");
    assert_eq!(result.failed, 1, "the absent blob's download attempt fails");
    assert_eq!(result.results.len(), 2);

    // The skipped entry is a success for the present hash; the failed entry
    // is a failure for the absent hash.
    let skipped = result
        .results
        .iter()
        .find(|r| r.hash == present)
        .expect("present hash in results");
    assert!(skipped.success && skipped.error.is_none());
    let failed = result
        .results
        .iter()
        .find(|r| r.hash == absent)
        .expect("absent hash in results");
    assert!(!failed.success && failed.error.is_some());

    // The absent blob was never written (download failed); the present one
    // is untouched.
    assert!(!blobs.join(absent).exists(), "failed download must not leave a file");
    assert_eq!(std::fs::read(blobs.join(present)).unwrap(), b"present");
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

/// Discriminator: a non-empty manifest whose `afterHash` blob is absent
/// must be reported missing, and once staged must drop out of the set —
/// proving the empty-set result above is real logic, not a stub.
#[tokio::test]
async fn get_missing_blobs_reports_missing_afterhash() {
    let tmp = tempfile::tempdir().unwrap();
    let blobs = tmp.path().join("blobs");
    std::fs::create_dir(&blobs).unwrap();
    let hash = "a".repeat(64);
    let manifest = manifest_with_after_hashes(&[&hash]);

    let missing = get_missing_blobs(&manifest, &blobs).await;
    assert_eq!(missing.len(), 1);
    assert!(missing.contains(&hash));

    std::fs::write(blobs.join(&hash), b"data").unwrap();
    let missing = get_missing_blobs(&manifest, &blobs).await;
    assert!(missing.is_empty(), "staged blob must not be reported missing");
}
