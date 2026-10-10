//! Integration coverage for `api::blob_fetcher`'s early-return /
//! filesystem-error branches the existing apply/scan e2e tests
//! never drive (those tests stage all blobs in advance so the
//! fetcher only sees the "nothing to do" path through the inner
//! loop).

use socket_patch_core::api::blob_fetcher::{
    fetch_blobs_by_hash, fetch_missing_blobs, get_missing_blobs,
};
use socket_patch_core::api::client::{ApiClient, ApiClientOptions};
use socket_patch_core::manifest::schema::{PatchFileInfo, PatchManifest, PatchRecord};
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
        route: socket_patch_core::api::client::ApiRoute::Proxy,
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
    PatchManifest {
        patches,
        setup: None,
    }
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
    assert_eq!(
        result.failed, 1,
        "the download attempt must be recorded as failed"
    );
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

/// `fetch_blobs_by_hash` with a hash whose blob is already on disk
/// short-circuits the network call and reports `skipped: 1`, leaving the
/// existing file byte-for-byte untouched. Covers the `skip if already on
/// disk` branch.
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
    assert!(
        !blobs.join(absent).exists(),
        "failed download must not leave a file"
    );
    assert_eq!(std::fs::read(blobs.join(present)).unwrap(), b"present");
}

// ── Content-hash verification (mock-server driven) ──────────────────
//
// These drive the success and mismatch branches of `download_entries`'s
// content verification, which the closed-port tests above can never reach
// (they fail before any body is returned). The blob's name IS its
// git-sha256, so the server must serve bytes that hash to the requested
// name for the download to be accepted.

use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use wiremock::matchers::{method, path as path_matcher};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A public-proxy client pointed at `base` (so binary fetches go to
/// `<base>/patch/blob/<hash>`).
fn proxy_client(base: &str) -> ApiClient {
    ApiClient::new(ApiClientOptions {
        api_url: base.to_string(),
        api_token: None,
        route: socket_patch_core::api::client::ApiRoute::Proxy,
    })
}

/// A blob whose content hashes to the requested name is written to disk
/// and counted as downloaded. Proves the happy path of `download_entries`'s
/// verify-then-write logic end to end.
#[tokio::test]
async fn fetch_missing_blobs_accepts_and_writes_matching_content() {
    let content = b"the genuine patched file body";
    let hash = compute_git_sha256_from_bytes(content);

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_matcher(format!("/patch/blob/{hash}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(content.to_vec()))
        .expect(1)
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let blobs = tmp.path().join("blobs");
    std::fs::create_dir(&blobs).unwrap();
    let manifest = manifest_with_after_hashes(&[&hash]);
    let client = proxy_client(&server.uri());

    let result = fetch_missing_blobs(&manifest, &blobs, &client, None).await;
    assert_eq!(result.total, 1);
    assert_eq!(result.downloaded, 1, "matching content must be accepted");
    assert_eq!(result.failed, 0);
    // Written under its content-addressed name, byte-for-byte.
    assert_eq!(std::fs::read(blobs.join(&hash)).unwrap(), content);
    // No staging litter survived the atomic write.
    let names: Vec<String> = std::fs::read_dir(&blobs)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        names,
        vec![hash],
        "exactly the blob, no temp files: {names:?}"
    );
}

/// A server that returns bytes NOT matching the requested hash must be
/// rejected as a content mismatch — and crucially must NOT leave a file at
/// the content-addressed path (which a later run would trust as valid).
#[tokio::test]
async fn fetch_missing_blobs_rejects_content_hash_mismatch_and_writes_nothing() {
    // Ask for the hash of `expected`, but have the server send `tampered`.
    let expected = b"the genuine patched file body";
    let hash = compute_git_sha256_from_bytes(expected);
    let tampered = b"surprise! malicious or corrupted payload";
    assert_ne!(
        compute_git_sha256_from_bytes(tampered),
        hash,
        "fixture sanity: tampered bytes must hash differently"
    );

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_matcher(format!("/patch/blob/{hash}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(tampered.to_vec()))
        .expect(1)
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let blobs = tmp.path().join("blobs");
    std::fs::create_dir(&blobs).unwrap();
    let manifest = manifest_with_after_hashes(&[&hash]);
    let client = proxy_client(&server.uri());

    let result = fetch_missing_blobs(&manifest, &blobs, &client, None).await;
    assert_eq!(result.total, 1);
    assert_eq!(result.downloaded, 0, "mismatched content must be refused");
    assert_eq!(result.failed, 1);
    assert!(result.results[0]
        .error
        .as_deref()
        .unwrap()
        .contains("mismatch"));

    // The integrity invariant: nothing — not even a partial/tampered file —
    // may sit at the content-addressed path, or a subsequent run's presence
    // check would silently trust it without re-verifying.
    assert!(
        !blobs.join(&hash).exists(),
        "rejected content must not be persisted at its claimed hash path"
    );
    assert_eq!(
        dir_entry_count(&blobs),
        0,
        "no blob and no staging litter after a rejected download"
    );
}

/// `fetch_blob` returning `Ok(None)` (a 404 from the server) is recorded
/// as a failure with the "not found" message, and writes no file. The
/// closed-port tests can only reach the transport-error arm, never this
/// "server answered, but with 404" arm.
#[tokio::test]
async fn fetch_missing_blobs_records_404_as_not_found() {
    let hash = "a".repeat(64);

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_matcher(format!("/patch/blob/{hash}")))
        .respond_with(ResponseTemplate::new(404))
        .expect(1)
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let blobs = tmp.path().join("blobs");
    std::fs::create_dir(&blobs).unwrap();
    let manifest = manifest_with_after_hashes(&[&hash]);
    let client = proxy_client(&server.uri());

    let result = fetch_missing_blobs(&manifest, &blobs, &client, None).await;
    assert_eq!(result.total, 1);
    assert_eq!(result.downloaded, 0);
    assert_eq!(result.failed, 1);
    assert!(result.results[0]
        .error
        .as_deref()
        .unwrap()
        .contains("not found"));
    assert!(!blobs.join(&hash).exists(), "a 404 must not leave a file");
    assert_eq!(dir_entry_count(&blobs), 0);
}

/// A manifest whose `afterHash` is uppercase hex must still be accepted
/// when the server serves byte-for-byte correct content (whose computed
/// git-sha256 is lowercase). Exercises the case-insensitive verification
/// end to end — a case-sensitive comparison would wrongly reject it.
#[tokio::test]
async fn fetch_missing_blobs_accepts_uppercase_manifest_hash() {
    let content = b"content addressed by an uppercase manifest hash";
    let hash_lower = compute_git_sha256_from_bytes(content);
    let hash_upper = hash_lower.to_ascii_uppercase();
    assert_ne!(
        hash_lower, hash_upper,
        "fixture: hash must have hex letters"
    );

    let server = MockServer::start().await;
    // The request path carries the manifest's (uppercase) hash verbatim.
    Mock::given(method("GET"))
        .and(path_matcher(format!("/patch/blob/{hash_upper}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(content.to_vec()))
        .expect(1)
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let blobs = tmp.path().join("blobs");
    std::fs::create_dir(&blobs).unwrap();
    let manifest = manifest_with_after_hashes(&[&hash_upper]);
    let client = proxy_client(&server.uri());

    let result = fetch_missing_blobs(&manifest, &blobs, &client, None).await;
    assert_eq!(
        result.downloaded, 1,
        "uppercase-hash content must be accepted"
    );
    assert_eq!(result.failed, 0);
    assert_eq!(std::fs::read(blobs.join(&hash_upper)).unwrap(), content);
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
    assert!(
        missing.is_empty(),
        "staged blob must not be reported missing"
    );
}

// ── Streaming (#571) ─────────────────────────────────────────────────

/// A one-response-per-connection server answering every request with
/// `200` and `Content-Length: head.len() + tail.len()`. It sends `head`,
/// then waits for `release` before sending `tail` (or, with `tail: None`,
/// closes the connection after `head`, cutting the body short).
async fn split_body_server(
    head: Vec<u8>,
    tail: Option<Vec<u8>>,
    declared: usize,
    release: std::sync::Arc<tokio::sync::Notify>,
) -> String {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let (head, tail, release) = (head.clone(), tail.clone(), release.clone());
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut buf = [0u8; 4096];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => request.extend_from_slice(&buf[..n]),
                    }
                }
                let headers = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/octet-stream\r\n\
                     content-length: {declared}\r\nconnection: close\r\n\r\n"
                );
                if sock.write_all(headers.as_bytes()).await.is_err()
                    || sock.write_all(&head).await.is_err()
                    || sock.flush().await.is_err()
                {
                    return;
                }
                if let Some(tail) = tail {
                    release.notified().await;
                    let _ = sock.write_all(&tail).await;
                }
                let _ = sock.shutdown().await;
            });
        }
    });
    format!("http://{addr}")
}

/// The size of the `.socket-dl-*` stage file in `dir`, if one exists.
///
/// Sized through `std::fs::metadata(path)`, not `DirEntry::metadata`: on
/// Windows the latter reports the directory entry's cached size, which
/// NTFS does not update while the writer's handle is still open.
fn stage_len(dir: &Path) -> Option<u64> {
    std::fs::read_dir(dir).ok()?.find_map(|e| {
        let e = e.ok()?;
        e.file_name()
            .to_string_lossy()
            .starts_with(".socket-dl-")
            .then(|| std::fs::metadata(e.path()).ok().map(|m| m.len()))
            .flatten()
    })
}

/// Blob downloads stream to disk: the first part of a body is already in
/// the stage file while the server is still holding back the rest. Before
/// #571 `fetch_binary` buffered the whole body in memory, so nothing
/// reached disk until the response completed.
#[tokio::test]
async fn blob_bodies_reach_disk_before_the_response_completes() {
    let head = vec![b'a'; 256 * 1024];
    let tail = vec![b'b'; 256 * 1024];
    let content = [head.clone(), tail.clone()].concat();
    let hash = compute_git_sha256_from_bytes(&content);

    let release = std::sync::Arc::new(tokio::sync::Notify::new());
    let uri = split_body_server(
        head.clone(),
        Some(tail.clone()),
        content.len(),
        release.clone(),
    )
    .await;
    let tmp = tempfile::tempdir().unwrap();
    let blobs = tmp.path().join("blobs");
    let manifest = manifest_with_after_hashes(&[&hash]);
    let client = proxy_client(&uri);

    let watch = async {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut streamed = false;
        while std::time::Instant::now() < deadline {
            if stage_len(&blobs) == Some(head.len() as u64) {
                streamed = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        // Release the tail either way so the download can finish.
        release.notify_one();
        streamed
    };
    let (result, streamed) =
        tokio::join!(fetch_missing_blobs(&manifest, &blobs, &client, None), watch);
    assert!(
        streamed,
        "the first {} bytes must be on disk while the rest is held back",
        head.len()
    );
    assert_eq!(result.downloaded, 1, "{:?}", result.results);
    assert_eq!(std::fs::read(blobs.join(&hash)).unwrap(), content);
    assert_eq!(dir_entry_count(&blobs), 1, "no stage litter");
}

/// A body cut short mid-stream fails that entry with the body-read error
/// and leaves nothing behind: no entry, no stage, and no cache directory
/// the download created. Same for a blob whose streamed content does not
/// hash to its name.
#[tokio::test]
async fn failed_streams_leave_no_stage_and_no_created_cache_dir() {
    let content = vec![b'c'; 64 * 1024];
    let hash = compute_git_sha256_from_bytes(&content);
    let release = std::sync::Arc::new(tokio::sync::Notify::new());

    // Cut short: the server declares twice what it sends, then closes.
    let uri = split_body_server(content.clone(), None, content.len() * 2, release.clone()).await;
    let tmp = tempfile::tempdir().unwrap();
    let blobs = tmp.path().join("blobs");
    let result = fetch_missing_blobs(
        &manifest_with_after_hashes(&[&hash]),
        &blobs,
        &proxy_client(&uri),
        None,
    )
    .await;
    assert_eq!(result.failed, 1);
    let error = result.results[0].error.as_deref().unwrap();
    assert!(error.contains("Error reading"), "{error}");
    assert!(!blobs.exists(), "no cache dir");

    // Mismatch: the full body arrives but hashes to something else.
    let wrong = compute_git_sha256_from_bytes(b"something else");
    let uri = split_body_server(content.clone(), None, content.len(), release).await;
    let tmp = tempfile::tempdir().unwrap();
    let blobs = tmp.path().join(".socket").join("blobs");
    let result = fetch_missing_blobs(
        &manifest_with_after_hashes(&[&wrong]),
        &blobs,
        &proxy_client(&uri),
        None,
    )
    .await;
    assert_eq!(result.failed, 1);
    let error = result.results[0].error.as_deref().unwrap();
    assert_eq!(
        error,
        format!("Content hash mismatch: expected {wrong}, got {hash}")
    );
    assert_eq!(
        dir_entry_count(tmp.path()),
        0,
        "a rejected blob must leave neither .socket/ nor .socket/blobs/ behind"
    );
}

/// A cache directory `create_dir_all` only partly creates (here a new
/// `.socket/` under which the 300-byte leaf name is too long for the
/// filesystem) is removed again, like any other failed download's.
#[tokio::test]
async fn partly_created_cache_dirs_are_removed_on_failure() {
    let content = b"the genuine patched file body";
    let hash = compute_git_sha256_from_bytes(content);
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_matcher(format!("/patch/blob/{hash}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(content.to_vec()))
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let blobs = tmp.path().join(".socket").join("x".repeat(300));
    let result = fetch_missing_blobs(
        &manifest_with_after_hashes(&[&hash]),
        &blobs,
        &proxy_client(&server.uri()),
        None,
    )
    .await;
    assert_eq!(result.failed, 1, "{:?}", result.results);
    let error = result.results[0].error.as_deref().unwrap();
    assert!(error.starts_with("Failed to write blob to disk"), "{error}");
    assert_eq!(
        dir_entry_count(tmp.path()),
        0,
        "the .socket/ that create_dir_all made before failing must be removed"
    );
}
