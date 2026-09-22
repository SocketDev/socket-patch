//! Coverage-gap tests for `api::blob_fetcher`'s never-executed error
//! branches (audit of commit d5e1815):
//!
//! * an uncreatable cache directory — the dir is created by the first
//!   verified download inside `write_cache_entry_atomic`, never up front,
//!   so the failure is a per-entry "Failed to write ... to disk" and a
//!   fetch that lands nothing leaves no `.socket/blobs/` husk — driven
//!   cross-platform via ENOTDIR (the target directory is routed *through
//!   a regular file*, which fails even as root, unlike permission tricks);
//! * the blob-download loop's progress callback (~471) — the diff-loop
//!   twin is tested in `blob_fetcher_edges_e2e.rs`, this one never ran;
//! * the "Failed to write blob/archive to disk" arms (~501-508,
//!   ~306-313) where the download succeeded but the atomic cache write
//!   failed (unix-only, read-only directory);
//! * mixed-outcome aggregation across `download_hashes` arms — each arm
//!   is individually covered by the sibling suite, but a single run
//!   combining success + 404 + hash-mismatch never was.
//!
//! Helper fns are deliberate twins of `blob_fetcher_edges_e2e.rs`'s
//! (integration-test binaries cannot share code except via
//! `tests/common/`, and these are api-suite-specific).

use socket_patch_core::api::blob_fetcher::{
    fetch_blobs_by_hash, fetch_missing_blobs, fetch_missing_sources, format_fetch_result,
    DownloadMode, OnProgress,
};
use socket_patch_core::api::client::{ApiClient, ApiClientOptions};
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use socket_patch_core::manifest::schema::{PatchFileInfo, PatchManifest, PatchRecord};
use socket_patch_core::patch::apply::PatchSources;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{Arc, Mutex};
use wiremock::matchers::{method, path as path_matcher};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Closed-port client: any *actual* HTTP call fails fast (connection
/// refused), so a branch that is supposed to return before any I/O
/// shows up as a wrong error message / `failed` count if it regresses
/// into fetching.
fn dummy_client() -> ApiClient {
    ApiClient::new(ApiClientOptions {
        api_url: "http://127.0.0.1:1".to_string(),
        api_token: None,
        use_public_proxy: true,
        org_slug: None,
    })
}

/// Public-proxy client pointed at a mock server `base` (binary fetches
/// go to `<base>/patch/blob/<hash>` and `<base>/patch/diff/<uuid>`).
fn proxy_client(base: &str) -> ApiClient {
    ApiClient::new(ApiClientOptions {
        api_url: base.to_string(),
        api_token: None,
        use_public_proxy: true,
        org_slug: None,
    })
}

/// Manifest with one patch whose files carry the given `afterHash`es.
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
    PatchManifest {
        patches,
        setup: None,
    }
}

/// Manifest carrying a set of patch UUIDs (each as its own PURL).
fn manifest_with_uuids(uuids: &[&str]) -> PatchManifest {
    let mut patches = HashMap::new();
    for (i, uuid) in uuids.iter().enumerate() {
        patches.insert(
            format!("pkg:npm/test-{i}@1.0.0"),
            PatchRecord {
                uuid: (*uuid).to_string(),
                exported_at: "2024-01-01T00:00:00Z".to_string(),
                files: HashMap::new(),
                vulnerabilities: HashMap::new(),
                description: "test".to_string(),
                license: "MIT".to_string(),
                tier: "free".to_string(),
            },
        );
    }
    PatchManifest {
        patches,
        setup: None,
    }
}

/// Count the directory entries under `dir` (proves an error path wrote
/// nothing — neither a final entry nor `.socket-dl-*` staging litter).
fn dir_entry_count(dir: &Path) -> usize {
    std::fs::read_dir(dir).unwrap().count()
}

// ── uncreatable cache directory → per-entry write failure ───────────
//
// The target directory path is routed through a REGULAR FILE
// (`tmp/notadir/<dir>`), so the writer's on-demand `create_dir_all` fails
// with ENOTDIR on every platform, even as root. The presence probes that
// run first (`get_missing_blobs` / `get_missing_archives`) also fail to
// stat through the file, so everything is reported missing and every
// entry is fetched. Each download succeeds and hash-verifies; only the
// disk write fails — so the outcome is the ordinary per-entry
// "Failed to write ... to disk" arm, and the blocking file survives.

/// `fetch_missing_blobs` when the blobs directory cannot be created:
/// every blob is fetched (the mocks pin one call each) and reported as a
/// per-blob disk-write failure; nothing is downloaded or skipped.
#[tokio::test]
async fn fetch_missing_blobs_uncreatable_blobs_dir_is_per_blob_write_failure() {
    let tmp = tempfile::tempdir().unwrap();
    let notadir = tmp.path().join("notadir");
    std::fs::write(&notadir, b"a regular file, not a directory").unwrap();
    let blobs = notadir.join("blobs");

    let c1 = b"first blob body";
    let c2 = b"second blob body";
    let h1 = compute_git_sha256_from_bytes(c1);
    let h2 = compute_git_sha256_from_bytes(c2);
    let server = MockServer::start().await;
    for (hash, body) in [(&h1, c1.to_vec()), (&h2, c2.to_vec())] {
        Mock::given(method("GET"))
            .and(path_matcher(format!("/patch/blob/{hash}")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
            .expect(1)
            .mount(&server)
            .await;
    }
    let manifest = manifest_with_after_hashes(&[&h1, &h2]);
    let client = proxy_client(&server.uri());

    let result = fetch_missing_blobs(&manifest, &blobs, &client, None).await;
    assert_eq!(result.total, 2, "both missing blobs are accounted for");
    assert_eq!(result.failed, 2, "every entry fails on the dir error");
    assert_eq!(result.downloaded, 0);
    assert_eq!(result.skipped, 0);
    assert_eq!(result.results.len(), 2);
    let seen: HashSet<&str> = result.results.iter().map(|r| r.hash.as_str()).collect();
    assert_eq!(seen, HashSet::from([h1.as_str(), h2.as_str()]));
    for entry in &result.results {
        assert!(!entry.success);
        let err = entry.error.as_deref().unwrap();
        assert!(
            err.contains("Failed to write blob to disk"),
            "per-blob disk-write message expected: {err}"
        );
    }
    // The path through the file is untouched: still a regular file.
    assert!(notadir.is_file(), "the blocking file must be left alone");
}

/// `fetch_blobs_by_hash` (the rollback-path beforeHash fetcher) with an
/// uncreatable blobs directory: the skip bookkeeping sees nothing present,
/// every hash is fetched, and each is a per-blob disk-write failure —
/// `total == failed == results.len()`, `downloaded == skipped == 0`.
#[tokio::test]
async fn fetch_blobs_by_hash_uncreatable_blobs_dir_is_per_blob_write_failure() {
    let tmp = tempfile::tempdir().unwrap();
    let notadir = tmp.path().join("notadir");
    std::fs::write(&notadir, b"file blocking the path").unwrap();
    let blobs = notadir.join("blobs");

    let c1 = b"rollback blob one";
    let c2 = b"rollback blob two";
    let h1 = compute_git_sha256_from_bytes(c1);
    let h2 = compute_git_sha256_from_bytes(c2);
    let server = MockServer::start().await;
    for (hash, body) in [(&h1, c1.to_vec()), (&h2, c2.to_vec())] {
        Mock::given(method("GET"))
            .and(path_matcher(format!("/patch/blob/{hash}")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
            .expect(1)
            .mount(&server)
            .await;
    }
    let hashes: HashSet<String> = [h1.clone(), h2.clone()].into_iter().collect();
    let client = proxy_client(&server.uri());

    let result = fetch_blobs_by_hash(&hashes, &blobs, &client, None).await;
    assert_eq!(result.total, 2);
    assert_eq!(result.failed, 2);
    assert_eq!(result.results.len(), 2);
    assert_eq!(result.downloaded, 0);
    assert_eq!(
        result.skipped, 0,
        "nothing can be present under a path that is not a directory"
    );
    let seen: HashSet<&str> = result.results.iter().map(|r| r.hash.as_str()).collect();
    assert_eq!(seen, HashSet::from([h1.as_str(), h2.as_str()]));
    for entry in &result.results {
        assert!(!entry.success);
        assert!(entry
            .error
            .as_deref()
            .unwrap()
            .contains("Failed to write blob to disk"));
    }
    assert!(notadir.is_file(), "the blocking file must be left alone");
}

/// `fetch_missing_sources` in Diff mode when the archives directory
/// cannot be created: `get_missing_archives` reports the uuid missing
/// through the broken path, the archive is fetched, and the write is a
/// per-archive "Failed to write archive to disk" failure. The blobs dir
/// is not involved and stays empty.
#[tokio::test]
async fn fetch_missing_sources_diff_uncreatable_archives_dir_is_per_archive_write_failure() {
    let tmp = tempfile::tempdir().unwrap();
    let blobs = tmp.path().join("blobs");
    std::fs::create_dir(&blobs).unwrap();
    let notadir = tmp.path().join("notadir");
    std::fs::write(&notadir, b"file blocking the path").unwrap();
    let diffs = notadir.join("diffs");
    let sources = PatchSources {
        blobs_path: &blobs,
        packages_path: None,
        diffs_path: Some(&diffs),
        mem_blobs: None,
    };

    let uuid = "11111111-1111-4111-8111-111111111111";
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_matcher(format!("/patch/diff/{uuid}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"payload".to_vec()))
        .expect(1)
        .mount(&server)
        .await;
    let manifest = manifest_with_uuids(&[uuid]);
    let client = proxy_client(&server.uri());

    let result =
        fetch_missing_sources(&manifest, &sources, DownloadMode::Diff, &client, None).await;
    assert_eq!(result.total, 1);
    assert_eq!(result.failed, 1);
    assert_eq!(result.downloaded, 0);
    assert_eq!(result.skipped, 0);
    assert_eq!(result.results.len(), 1);
    let entry = &result.results[0];
    assert_eq!(entry.hash, uuid, "diff-mode results carry the patch uuid");
    assert!(!entry.success);
    let err = entry.error.as_deref().unwrap();
    assert!(
        err.contains("Failed to write archive to disk"),
        "per-archive disk-write message expected: {err}"
    );
    assert!(notadir.is_file(), "the blocking file must be left alone");
    // Diff mode never touches the blobs dir.
    assert_eq!(dir_entry_count(&blobs), 0);
}

/// A fetch that lands nothing creates nothing: with every blob 404 the
/// blobs directory — and the `.socket/` above it — must not come into
/// existence. The dir is the writer's to create, on the first verified
/// download only.
#[tokio::test]
async fn fetch_missing_blobs_all_not_found_leaves_blobs_dir_absent() {
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join(".socket");
    let blobs = socket.join("blobs");

    let h1 = "a".repeat(64);
    let h2 = "b".repeat(64);
    let server = MockServer::start().await;
    for hash in [&h1, &h2] {
        Mock::given(method("GET"))
            .and(path_matcher(format!("/patch/blob/{hash}")))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&server)
            .await;
    }
    let manifest = manifest_with_after_hashes(&[&h1, &h2]);
    let client = proxy_client(&server.uri());

    let result = fetch_missing_blobs(&manifest, &blobs, &client, None).await;
    assert_eq!(result.total, 2);
    assert_eq!(result.failed, 2);
    assert_eq!(result.downloaded, 0);
    for entry in &result.results {
        assert!(!entry.success);
        assert!(entry.error.as_deref().unwrap().contains("not found"));
    }
    assert!(
        !blobs.exists() && !socket.exists(),
        "a fetch that lands nothing must leave no .socket/blobs/ residue"
    );
}

// ── Blob-loop progress callback ──────────────────────────────────────

/// The blob-download loop invokes the progress callback once per blob
/// with `(hash, 1-based index, total)`, BEFORE the fetch attempt — the
/// closed-port client makes every fetch fail, yet the callbacks must
/// all have fired with the documented 1-based sequential indices.
/// (The diff-loop twin is covered in `blob_fetcher_edges_e2e.rs`; this
/// loop's callback had never run under test.)
#[tokio::test]
async fn fetch_missing_blobs_progress_callback_is_one_based_and_pre_fetch() {
    let tmp = tempfile::tempdir().unwrap();
    let blobs = tmp.path().join("blobs");
    std::fs::create_dir(&blobs).unwrap();
    let h1 = "a".repeat(64);
    let h2 = "b".repeat(64);
    let manifest = manifest_with_after_hashes(&[&h1, &h2]);
    let client = dummy_client();

    let calls: Arc<Mutex<Vec<(String, usize, usize)>>> = Arc::new(Mutex::new(Vec::new()));
    let calls_cb = calls.clone();
    let cb: OnProgress = Box::new(move |h: &str, idx: usize, total: usize| {
        calls_cb.lock().unwrap().push((h.to_string(), idx, total));
    });

    let result = fetch_missing_blobs(&manifest, &blobs, &client, Some(&cb)).await;
    assert_eq!(result.total, 2);
    assert_eq!(result.downloaded, 0, "closed-port client downloads nothing");
    assert_eq!(result.failed, 2);

    let recorded = calls.lock().unwrap().clone();
    assert_eq!(
        recorded.len(),
        2,
        "callback fires exactly once per blob even when every fetch fails \
         (i.e. it fires before the attempt): {recorded:?}"
    );
    // 1-based, sequential indices with the full total each time. The hash
    // order is HashSet-nondeterministic, so match hashes as a set.
    assert_eq!(recorded[0].1, 1, "first callback index is 1, not 0");
    assert_eq!(recorded[1].1, 2);
    assert!(recorded.iter().all(|(_, _, t)| *t == 2));
    let seen: HashSet<&str> = recorded.iter().map(|(h, _, _)| h.as_str()).collect();
    assert_eq!(seen, HashSet::from([h1.as_str(), h2.as_str()]));
}

// ── Disk-write failure arms (download OK, atomic write fails) ────────
//
// unix-only: the pre-created cache directory is chmod'd 0o555 (readable
// + traversable, not writable), so `create_dir_all` still succeeds on
// the existing dir and execution reaches the write. A probe write
// verifies the mode bits actually deny writes (root / CAP_DAC_OVERRIDE
// would make the test vacuous) — checked BEFORE mounting any
// `.expect(1)` mock so a skip cannot trip drop-verification.

/// Returns true when writing into `dir` is denied. Removes its probe on
/// the (privileged) success path.
#[cfg(unix)]
fn write_into_dir_denied(dir: &Path) -> bool {
    let probe = dir.join(".write-probe");
    match std::fs::write(&probe, b"") {
        Ok(()) => {
            let _ = std::fs::remove_file(&probe);
            false
        }
        Err(_) => true,
    }
}

/// Content downloads and hash-verifies, but the blob cannot be written:
/// a per-blob "Failed to write blob to disk" failure, not a panic, and
/// nothing — no final file, no `.socket-dl-*` stage — lands in the dir.
#[cfg(unix)]
#[tokio::test]
async fn fetch_missing_blobs_disk_write_failure_is_per_blob_failure() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = tempfile::tempdir().unwrap();
    let blobs = tmp.path().join("blobs");
    std::fs::create_dir(&blobs).unwrap();
    std::fs::set_permissions(&blobs, std::fs::Permissions::from_mode(0o555)).unwrap();
    if !write_into_dir_denied(&blobs) {
        eprintln!("skipping: directory mode bits do not deny writes here (root?)");
        return;
    }

    let content = b"verified content that cannot be persisted";
    let hash = compute_git_sha256_from_bytes(content);

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_matcher(format!("/patch/blob/{hash}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(content.to_vec()))
        .expect(1)
        .mount(&server)
        .await;

    let manifest = manifest_with_after_hashes(&[&hash]);
    let client = proxy_client(&server.uri());

    let result = fetch_missing_blobs(&manifest, &blobs, &client, None).await;
    assert_eq!(result.total, 1);
    assert_eq!(result.downloaded, 0, "an unwritable blob is not 'downloaded'");
    assert_eq!(result.failed, 1);
    assert_eq!(result.skipped, 0);
    let err = result.results[0].error.as_deref().unwrap();
    assert!(
        err.contains("Failed to write blob to disk"),
        "disk-write arm message expected: {err}"
    );
    // Integrity: nothing may sit at the content-addressed path (a later
    // run's presence check would trust it), and no staging turd either —
    // the stage was never created, which is the invariant callers need.
    assert!(!blobs.join(&hash).exists());
    assert_eq!(dir_entry_count(&blobs), 0, "no partial file, no stage litter");

    // Restore so tempdir teardown can't mask a failure.
    std::fs::set_permissions(&blobs, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// Diff-archive twin: `fetch_diff` succeeds but the archive write
/// fails → "Failed to write archive to disk", uuid carried in `hash`,
/// no `<uuid>.tar.gz` and no stage litter.
#[cfg(unix)]
#[tokio::test]
async fn fetch_missing_sources_diff_disk_write_failure_is_per_archive_failure() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = tempfile::tempdir().unwrap();
    let blobs = tmp.path().join("blobs");
    let diffs = tmp.path().join("diffs");
    std::fs::create_dir(&blobs).unwrap();
    std::fs::create_dir(&diffs).unwrap();
    std::fs::set_permissions(&diffs, std::fs::Permissions::from_mode(0o555)).unwrap();
    if !write_into_dir_denied(&diffs) {
        eprintln!("skipping: directory mode bits do not deny writes here (root?)");
        return;
    }

    let uuid = "55555555-5555-4555-8555-555555555555";

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_matcher(format!("/patch/diff/{uuid}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"payload".to_vec()))
        .expect(1)
        .mount(&server)
        .await;

    let sources = PatchSources {
        blobs_path: &blobs,
        packages_path: None,
        diffs_path: Some(&diffs),
        mem_blobs: None,
    };
    let manifest = manifest_with_uuids(&[uuid]);
    let client = proxy_client(&server.uri());

    let result =
        fetch_missing_sources(&manifest, &sources, DownloadMode::Diff, &client, None).await;
    assert_eq!(result.total, 1);
    assert_eq!(result.downloaded, 0);
    assert_eq!(result.failed, 1);
    assert_eq!(result.results[0].hash, uuid);
    let err = result.results[0].error.as_deref().unwrap();
    assert!(
        err.contains("Failed to write archive to disk"),
        "archive disk-write arm message expected: {err}"
    );
    assert!(!diffs.join(format!("{uuid}.tar.gz")).exists());
    assert_eq!(dir_entry_count(&diffs), 0, "no partial file, no stage litter");

    std::fs::set_permissions(&diffs, std::fs::Permissions::from_mode(0o755)).unwrap();
}

// ── Mixed-outcome aggregation ────────────────────────────────────────

/// One run combining all three `download_hashes` arms: a good blob, a
/// 404, and a hash-mismatch. Counters aggregate per-arm, each entry
/// carries its own arm's error, only the good blob lands on disk, and
/// `format_fetch_result` renders the genuinely mixed result.
#[tokio::test]
async fn fetch_missing_blobs_mixed_outcomes_aggregate_and_format() {
    let content_ok = b"the one genuine blob body";
    let h_ok = compute_git_sha256_from_bytes(content_ok);
    let h_404 = "a".repeat(64);
    let h_bad = compute_git_sha256_from_bytes(b"content the server will not send");
    let tampered = b"tampered payload".to_vec();
    assert_ne!(compute_git_sha256_from_bytes(&tampered), h_bad);

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_matcher(format!("/patch/blob/{h_ok}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(content_ok.to_vec()))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path_matcher(format!("/patch/blob/{h_404}")))
        .respond_with(ResponseTemplate::new(404))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path_matcher(format!("/patch/blob/{h_bad}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(tampered))
        .expect(1)
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let blobs = tmp.path().join("blobs");
    std::fs::create_dir(&blobs).unwrap();
    let manifest = manifest_with_after_hashes(&[&h_ok, &h_404, &h_bad]);
    let client = proxy_client(&server.uri());

    let result = fetch_missing_blobs(&manifest, &blobs, &client, None).await;
    assert_eq!(result.total, 3);
    assert_eq!(result.downloaded, 1);
    assert_eq!(result.failed, 2);
    assert_eq!(result.skipped, 0);
    assert_eq!(result.results.len(), 3);

    // HashSet iteration order is nondeterministic — match by hash.
    let by_hash = |h: &str| {
        result
            .results
            .iter()
            .find(|r| r.hash == h)
            .unwrap_or_else(|| panic!("{h} missing from results"))
    };
    let ok = by_hash(&h_ok);
    assert!(ok.success && ok.error.is_none());
    let nf = by_hash(&h_404);
    assert!(!nf.success);
    assert!(nf.error.as_deref().unwrap().contains("not found"));
    let bad = by_hash(&h_bad);
    assert!(!bad.success);
    assert!(bad.error.as_deref().unwrap().contains("mismatch"));

    // Only the verified blob was persisted, byte-for-byte, nothing else.
    assert_eq!(std::fs::read(blobs.join(&h_ok)).unwrap(), content_ok);
    assert!(!blobs.join(&h_404).exists());
    assert!(!blobs.join(&h_bad).exists());
    assert_eq!(dir_entry_count(&blobs), 1);

    // End-to-end formatter exercise with a genuinely mixed result.
    let rendered = format_fetch_result(&result);
    assert!(rendered.contains("Downloaded 1 blob(s)"), "{rendered}");
    assert!(
        rendered.contains("Failed to download 2 blob(s)"),
        "{rendered}"
    );
}
