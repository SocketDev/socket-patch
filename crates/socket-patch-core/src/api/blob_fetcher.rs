use std::collections::HashSet;
use std::path::Path;

use crate::api::client::{ApiClient, ApiError, BinaryBody};
use crate::hash::git_sha256::compute_git_sha256_from_reader;
use crate::manifest::operations::get_after_hash_blobs;
use crate::manifest::schema::PatchManifest;

/// Result of fetching a single blob.
#[derive(Debug, Clone)]
pub struct BlobFetchResult {
    pub hash: String,
    pub success: bool,
    pub error: Option<String>,
}

/// Aggregate result of a blob-fetch operation.
#[derive(Debug, Clone, Default)]
pub struct FetchMissingBlobsResult {
    pub total: usize,
    pub downloaded: usize,
    pub failed: usize,
    pub skipped: usize,
    pub results: Vec<BlobFetchResult>,
}

/// Progress callback signature.
///
/// Called with `(hash, one_based_index, total)` for each blob.
pub type OnProgress = Box<dyn Fn(&str, usize, usize) + Send + Sync>;

// ── Public API ────────────────────────────────────────────────────────

/// Determine which `afterHash` blobs referenced in the manifest are
/// missing from disk.
///
/// Only checks `afterHash` blobs because those are the patched file
/// contents needed for applying patches. `beforeHash` blobs are
/// downloaded on-demand during rollback.
pub async fn get_missing_blobs(manifest: &PatchManifest, blobs_path: &Path) -> HashSet<String> {
    let after_hash_blobs = get_after_hash_blobs(manifest);
    let mut missing = HashSet::new();

    for hash in after_hash_blobs {
        let blob_path = blobs_path.join(&hash);
        if tokio::fs::metadata(&blob_path).await.is_err() {
            missing.insert(hash);
        }
    }

    missing
}

/// Download all missing `afterHash` blobs referenced in the manifest.
///
/// Creates the `blobs_path` directory if it does not exist.
///
/// # Arguments
///
/// * `manifest`    – Patch manifest whose `afterHash` blobs to check.
/// * `blobs_path`  – Directory where blob files are stored (one file per
///   hash).
/// * `client`      – [`ApiClient`] used to fetch blobs from the server.
/// * `on_progress` – Optional callback invoked before each download with
///   `(hash, 1-based index, total)`.
pub async fn fetch_missing_blobs(
    manifest: &PatchManifest,
    blobs_path: &Path,
    client: &ApiClient,
    on_progress: Option<&OnProgress>,
) -> FetchMissingBlobsResult {
    let missing = get_missing_blobs(manifest, blobs_path).await;

    if missing.is_empty() {
        return FetchMissingBlobsResult::default();
    }

    // `blobs_path` is created by the first successful write
    // (`stream_cache_entry_atomic`), never up front: a fetch that lands
    // nothing leaves no `.socket/blobs/` husk behind.
    let hashes: Vec<String> = missing.into_iter().collect();
    download_entries(&hashes, blobs_path, client, on_progress).await
}

/// Download specific blobs identified by their hashes.
///
/// Useful for fetching `beforeHash` blobs during rollback, where only a
/// subset of hashes is required.
///
/// Blobs that already exist on disk are skipped (counted in `skipped`).
pub async fn fetch_blobs_by_hash(
    hashes: &HashSet<String>,
    blobs_path: &Path,
    client: &ApiClient,
    on_progress: Option<&OnProgress>,
) -> FetchMissingBlobsResult {
    if hashes.is_empty() {
        return FetchMissingBlobsResult::default();
    }

    // Filter out hashes that already exist on disk (an absent `blobs_path`
    // simply means none do; the dir is created by the first successful
    // write, never up front).
    let mut to_download: Vec<String> = Vec::new();
    let mut skipped: usize = 0;
    let mut results: Vec<BlobFetchResult> = Vec::new();

    for hash in hashes {
        let blob_path = blobs_path.join(hash);
        if tokio::fs::metadata(&blob_path).await.is_ok() {
            skipped += 1;
            results.push(BlobFetchResult {
                hash: hash.clone(),
                success: true,
                error: None,
            });
        } else {
            to_download.push(hash.clone());
        }
    }

    if to_download.is_empty() {
        return FetchMissingBlobsResult {
            total: hashes.len(),
            downloaded: 0,
            failed: 0,
            skipped,
            results,
        };
    }

    let download_result = download_entries(&to_download, blobs_path, client, on_progress).await;
    results.extend(download_result.results);

    FetchMissingBlobsResult {
        total: hashes.len(),
        downloaded: download_result.downloaded,
        failed: download_result.failed,
        skipped,
        results,
    }
}

/// What kind of artifact a fetch or cleanup result counts, for human
/// output: the singular/plural noun and whether ids are long enough to be
/// worth abbreviating (64-hex blob hashes are; patch UUIDs are the lookup
/// key a user greps for, so they print in full).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArtifactNoun {
    pub one: &'static str,
    pub many: &'static str,
    pub abbreviate_ids: bool,
}

impl ArtifactNoun {
    /// `"1 blob"` / `"2 blobs"` / `"0 blobs"`.
    pub fn count(&self, n: usize) -> String {
        format!("{n} {}", if n == 1 { self.one } else { self.many })
    }

    /// An id as listed under a result: abbreviated to 12 characters plus
    /// `...` only when that actually shortens it. Counts characters, not
    /// bytes: ids are unvalidated manifest strings, and a byte slice
    /// panics when index 12 lands inside a multibyte char.
    pub fn display_id(&self, id: &str) -> String {
        const SHORT: usize = 12;
        if self.abbreviate_ids && id.chars().count() > SHORT {
            format!("{}...", id.chars().take(SHORT).collect::<String>())
        } else {
            id.to_string()
        }
    }
}

/// Per-file content blobs (`.socket/blobs/<hash>`).
pub const BLOB: ArtifactNoun = ArtifactNoun {
    one: "blob",
    many: "blobs",
    abbreviate_ids: true,
};

/// Legacy per-patch diff archives (`.socket/diffs/<uuid>.tar.gz`). v5
/// removed the diff download path, so nothing writes or reads them any
/// more; only the cleanup sweeps name them.
pub const DIFF_ARCHIVE: ArtifactNoun = ArtifactNoun {
    one: "diff archive",
    many: "diff archives",
    abbreviate_ids: false,
};

/// Legacy per-patch package archives (`.socket/packages/<uuid>.tar.gz`),
/// which nothing writes or reads any more; only the cleanup sweeps name them.
pub const PACKAGE_ARCHIVE: ArtifactNoun = ArtifactNoun {
    one: "package archive",
    many: "package archives",
    abbreviate_ids: false,
};

/// How many failures a fetch result lists before "... and N more".
const MAX_LISTED_FAILURES: usize = 5;

/// Format a [`FetchMissingBlobsResult`] of per-file blobs as a
/// human-readable string (see [`format_fetch_result_for`]).
pub fn format_fetch_result(result: &FetchMissingBlobsResult) -> String {
    format_fetch_result_for(result, BLOB)
}

/// Format a [`FetchMissingBlobsResult`] counting `noun`s: the success
/// counts first, then the failures sorted by id (the result's order comes
/// from a `HashSet`), at most five listed.
pub fn format_fetch_result_for(result: &FetchMissingBlobsResult, noun: ArtifactNoun) -> String {
    let mut lines = format_fetch_successes(result, noun);
    lines.extend(format_fetch_failures(result, noun));
    if lines.is_empty() {
        // `total > 0` with nothing downloaded, skipped, or failed should
        // not be reachable; never emit a misleading blank string.
        return format!("All {} are present locally.", noun.many);
    }
    lines.join("\n")
}

/// The success half of [`format_fetch_result_for`] ("Downloaded 2 blobs",
/// "1 blob already present locally"), for callers that route failures to
/// a different stream. Empty when nothing succeeded.
pub fn format_fetch_successes(result: &FetchMissingBlobsResult, noun: ArtifactNoun) -> Vec<String> {
    let mut lines = Vec::new();
    if result.downloaded > 0 {
        lines.push(format!("Downloaded {}", noun.count(result.downloaded)));
    }
    if result.skipped > 0 {
        lines.push(format!(
            "{} already present locally",
            noun.count(result.skipped)
        ));
    }
    lines
}

/// The failure half of [`format_fetch_result_for`]: a "Failed to download
/// N <noun>s" header and up to five `  - <id>: <error>` lines, sorted by
/// id. Empty when nothing failed.
pub fn format_fetch_failures(result: &FetchMissingBlobsResult, noun: ArtifactNoun) -> Vec<String> {
    if result.failed == 0 {
        return Vec::new();
    }
    let mut lines = vec![format!("Failed to download {}", noun.count(result.failed))];
    let mut failed: Vec<&BlobFetchResult> = result.results.iter().filter(|r| !r.success).collect();
    failed.sort_by(|a, b| a.hash.cmp(&b.hash));
    for r in failed.iter().take(MAX_LISTED_FAILURES) {
        let err = r.error.as_deref().unwrap_or("unknown error");
        lines.push(format!(
            "  - {}: {}",
            noun.display_id(&r.hash),
            concise_fetch_error(err, &r.hash)
        ));
    }
    if failed.len() > MAX_LISTED_FAILURES {
        lines.push(format!(
            "  ... and {} more",
            failed.len() - MAX_LISTED_FAILURES
        ));
    }
    lines
}

/// Drop the id the client's error repeats: the line already starts with
/// it, so `Network error fetching blob <hash>: <cause>` reads as
/// `network error: <cause>`. Anything else is returned unchanged.
fn concise_fetch_error<'a>(err: &'a str, id: &str) -> std::borrow::Cow<'a, str> {
    if let Some(rest) = err.strip_prefix("Network error fetching ") {
        // `<kind> <id>: <cause>`
        if let Some((_kind, tail)) = rest.split_once(' ') {
            if let Some(cause) = tail.strip_prefix(id).and_then(|t| t.strip_prefix(": ")) {
                return format!("network error: {cause}").into();
            }
        }
    }
    err.into()
}

// ── Internal helpers ──────────────────────────────────────────────────

/// Stream `body` to `dest` atomically: copy it chunk by chunk into a temp
/// file in the same directory, check it against `expected_hash` (a blob's
/// git-sha256 name) when given, then `rename(2)` it over `dest`. The body is
/// never held in memory whole (#571).
///
/// The destinations here are *content-addressed* cache entries —
/// `blobs/<hash>`. A plain `tokio::fs::write`
/// truncates-then-writes in place, so an interrupted write (ENOSPC, crash,
/// killed process) can leave a partial file at the final path. Because the
/// "is it already downloaded?" check ([`get_missing_blobs`]) only tests
/// for presence, such a truncated file
/// is then trusted forever — its content no longer hashes to its name, yet
/// it is never re-downloaded. Staging in the same directory and renaming
/// makes the final path always either the complete bytes or absent, never a
/// torn intermediate, matching the stage+rename discipline used by the
/// patch-apply and copy-on-write write paths.
///
/// Deliberately LIGHTER than [`crate::utils::fs::atomic_write_bytes`] (no
/// file fsync, no dir fsync, `.socket-dl-` prefix): these are re-downloadable
/// content-addressed cache entries, not user-owned files — post-crash loss
/// of a cache entry is harmless, so the extra durability isn't worth the
/// I/O. Do not "consolidate" this into the hardened writer.
async fn stream_cache_entry_atomic(
    dest: &Path,
    body: &mut BinaryBody,
    expected_hash: Option<&str>,
) -> Result<(), EntryError> {
    let parent = dest.parent().ok_or_else(|| {
        EntryError::Write(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "cache entry path has no parent directory",
        ))
    })?;
    // The cache directory (`.socket/blobs/`) is created
    // here, by the first download, and nowhere earlier. A fetch that lands
    // nothing (all 404, offline, every hash mismatched, every body cut
    // short) must not leave an empty directory behind for the user to
    // commit, so a failure removes the directories this call created, while
    // they are still empty. An uncreatable parent surfaces as this entry's
    // write failure, like any other disk error.
    let mut created_dirs = Vec::new();
    for dir in parent.ancestors() {
        if dir.as_os_str().is_empty() || tokio::fs::symlink_metadata(dir).await.is_ok() {
            break;
        }
        created_dirs.push(dir);
    }
    let stage = crate::utils::fs::stage_path(dest, ".socket-dl-");

    let result = async {
        // Inside the cleanup scope: a `create_dir_all` that makes some
        // ancestors and then fails must not leave them behind either.
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(EntryError::Write)?;
        let size = stage_body(&stage, body).await?;
        if let Some(expected) = expected_hash {
            let file = tokio::fs::File::open(&stage)
                .await
                .map_err(EntryError::Write)?;
            let actual = compute_git_sha256_from_reader(size, file)
                .await
                .map_err(EntryError::Write)?;
            if !blob_hash_matches(expected, &actual) {
                return Err(EntryError::HashMismatch(actual));
            }
        }
        tokio::fs::rename(&stage, dest)
            .await
            .map_err(EntryError::Write)
    }
    .await;
    if result.is_err() {
        // A partial stage would otherwise leak as a `.socket-dl-*` turd.
        let _ = tokio::fs::remove_file(&stage).await;
        // Deepest first; `remove_dir` only succeeds while a dir is empty.
        for dir in created_dirs {
            let _ = tokio::fs::remove_dir(dir).await;
        }
    }
    result
}

/// Copy `body` chunk by chunk into a new file at `stage`, returning the
/// byte count. Only one chunk is held in memory at a time.
async fn stage_body(stage: &Path, body: &mut BinaryBody) -> Result<u64, EntryError> {
    use tokio::io::AsyncWriteExt;
    let mut file = tokio::fs::File::create(stage)
        .await
        .map_err(EntryError::Write)?;
    let mut size: u64 = 0;
    while let Some(chunk) = body.chunk().await.map_err(EntryError::Body)? {
        let chunk = chunk.as_ref();
        file.write_all(chunk).await.map_err(EntryError::Write)?;
        size += chunk.len() as u64;
    }
    file.flush().await.map_err(EntryError::Write)?;
    Ok(size)
}

/// Why one cache entry was not stored.
#[derive(Debug)]
enum EntryError {
    /// The response body failed or stalled mid-read.
    Body(ApiError),
    /// A disk error while staging, hashing or renaming.
    Write(std::io::Error),
    /// The blob's content hashed to this, not to its name.
    HashMismatch(String),
}

/// Compare an expected blob hash against the hash computed from the
/// downloaded bytes.
///
/// Git object hashes are hex, and hex is case-insensitive. The content
/// hasher ([`compute_git_sha256_from_reader`]) always emits lowercase, but
/// [`ApiClient::fetch_blob`]'s validator accepts uppercase hex too — so a
/// manifest (or server) that uses uppercase would download byte-for-byte
/// correct content and then be wrongly rejected by a case-sensitive
/// comparison. Compare ignoring ASCII case to keep the two consistent.
///
/// [`compute_git_sha256_from_reader`]: crate::hash::git_sha256::compute_git_sha256_from_reader
fn blob_hash_matches(expected: &str, actual: &str) -> bool {
    expected.eq_ignore_ascii_case(actual)
}

/// Download the blobs `ids` sequentially, streaming each into
/// `dir/<hash>` and verifying it against its git-sha256 name (see
/// [`stream_cache_entry_atomic`]). The one download loop behind
/// [`fetch_missing_blobs`] and [`fetch_blobs_by_hash`].
async fn download_entries(
    ids: &[String],
    dir: &Path,
    client: &ApiClient,
    on_progress: Option<&OnProgress>,
) -> FetchMissingBlobsResult {
    let total = ids.len();
    let mut downloaded: usize = 0;
    let mut failed: usize = 0;
    let mut results: Vec<BlobFetchResult> = Vec::with_capacity(total);

    for (i, id) in ids.iter().enumerate() {
        if let Some(ref cb) = on_progress {
            cb(id, i + 1, total);
        }

        let error = match client.fetch_blob(id).await {
            Ok(Some(mut body)) => {
                match stream_cache_entry_atomic(&dir.join(id), &mut body, Some(id)).await {
                    Ok(()) => None,
                    Err(EntryError::Body(e)) => Some(e.to_string()),
                    Err(EntryError::Write(e)) => {
                        Some(format!("Failed to write blob to disk: {}", e))
                    }
                    Err(EntryError::HashMismatch(actual)) => Some(format!(
                        "Content hash mismatch: expected {}, got {}",
                        id, actual
                    )),
                }
            }
            Ok(None) => Some("Blob not found on server".to_string()),
            Err(e) => Some(e.to_string()),
        };
        if error.is_none() {
            downloaded += 1;
        } else {
            failed += 1;
        }
        results.push(BlobFetchResult {
            hash: id.clone(),
            success: error.is_none(),
            error,
        });
    }

    FetchMissingBlobsResult {
        total,
        downloaded,
        failed,
        skipped: 0,
        results,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::schema::{PatchFileInfo, PatchManifest, PatchRecord};
    use std::collections::HashMap;

    fn make_manifest_with_hashes(after_hashes: &[&str]) -> PatchManifest {
        let mut files = HashMap::new();
        for (i, ah) in after_hashes.iter().enumerate() {
            files.insert(
                format!("package/file{}.js", i),
                PatchFileInfo {
                    before_hash: format!("before{}{:06}", "0".repeat(58), i),
                    after_hash: ah.to_string(),
                },
            );
        }

        let mut patches = HashMap::new();
        patches.insert(
            "pkg:npm/test@1.0.0".to_string(),
            PatchRecord {
                uuid: "test-uuid".to_string(),
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

    #[tokio::test]
    async fn test_get_missing_blobs_all_missing() {
        let dir = tempfile::tempdir().unwrap();
        let blobs_path = dir.path().join("blobs");
        tokio::fs::create_dir_all(&blobs_path).await.unwrap();

        let h1 = "a".repeat(64);
        let h2 = "b".repeat(64);
        let manifest = make_manifest_with_hashes(&[&h1, &h2]);

        let missing = get_missing_blobs(&manifest, &blobs_path).await;
        assert_eq!(missing.len(), 2);
        assert!(missing.contains(&h1));
        assert!(missing.contains(&h2));
    }

    #[tokio::test]
    async fn test_get_missing_blobs_some_present() {
        let dir = tempfile::tempdir().unwrap();
        let blobs_path = dir.path().join("blobs");
        tokio::fs::create_dir_all(&blobs_path).await.unwrap();

        let h1 = "a".repeat(64);
        let h2 = "b".repeat(64);

        // Write h1 to disk so it is NOT missing
        tokio::fs::write(blobs_path.join(&h1), b"data")
            .await
            .unwrap();

        let manifest = make_manifest_with_hashes(&[&h1, &h2]);
        let missing = get_missing_blobs(&manifest, &blobs_path).await;
        assert_eq!(missing.len(), 1);
        assert!(missing.contains(&h2));
        assert!(!missing.contains(&h1));
    }

    #[tokio::test]
    async fn test_get_missing_blobs_empty_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let blobs_path = dir.path().join("blobs");
        tokio::fs::create_dir_all(&blobs_path).await.unwrap();

        let manifest = PatchManifest::new();
        let missing = get_missing_blobs(&manifest, &blobs_path).await;
        assert!(missing.is_empty());
    }

    #[test]
    fn test_format_fetch_result_all_present() {
        let result = FetchMissingBlobsResult {
            total: 0,
            downloaded: 0,
            failed: 0,
            skipped: 0,
            results: Vec::new(),
        };
        assert_eq!(
            format_fetch_result(&result),
            "All blobs are present locally."
        );
    }

    #[test]
    fn test_format_fetch_result_some_downloaded() {
        let result = FetchMissingBlobsResult {
            total: 3,
            downloaded: 2,
            failed: 1,
            skipped: 0,
            results: vec![
                BlobFetchResult {
                    hash: "a".repeat(64),
                    success: true,
                    error: None,
                },
                BlobFetchResult {
                    hash: "b".repeat(64),
                    success: true,
                    error: None,
                },
                BlobFetchResult {
                    hash: "c".repeat(64),
                    success: false,
                    error: Some("Blob not found on server".to_string()),
                },
            ],
        };
        let output = format_fetch_result(&result);
        assert_eq!(
            output,
            "Downloaded 2 blobs\nFailed to download 1 blob\n  - cccccccccccc...: Blob not found on server"
        );
    }

    #[test]
    fn test_format_fetch_result_truncates_at_5() {
        let results: Vec<BlobFetchResult> = (0..8)
            .map(|i| BlobFetchResult {
                hash: format!("{:0>64}", i),
                success: false,
                error: Some(format!("error {}", i)),
            })
            .collect();

        let result = FetchMissingBlobsResult {
            total: 8,
            downloaded: 0,
            failed: 8,
            skipped: 0,
            results,
        };
        let output = format_fetch_result(&result);
        assert!(output.contains("... and 3 more"));
    }

    // ── Group 8: format edge cases ───────────────────────────────────

    #[test]
    fn test_format_only_downloaded() {
        let result = FetchMissingBlobsResult {
            total: 3,
            downloaded: 3,
            failed: 0,
            skipped: 0,
            results: vec![
                BlobFetchResult {
                    hash: "a".repeat(64),
                    success: true,
                    error: None,
                },
                BlobFetchResult {
                    hash: "b".repeat(64),
                    success: true,
                    error: None,
                },
                BlobFetchResult {
                    hash: "c".repeat(64),
                    success: true,
                    error: None,
                },
            ],
        };
        let output = format_fetch_result(&result);
        assert_eq!(output, "Downloaded 3 blobs");
        assert!(!output.contains("Failed"));
    }

    #[test]
    fn test_format_short_hash() {
        let result = FetchMissingBlobsResult {
            total: 1,
            downloaded: 0,
            failed: 1,
            skipped: 0,
            results: vec![BlobFetchResult {
                hash: "abc".into(),
                success: false,
                error: Some("not found".into()),
            }],
        };
        let output = format_fetch_result(&result);
        // Hash is < 12 chars: shown in full, with no false ellipsis.
        assert_eq!(output, "Failed to download 1 blob\n  - abc: not found");
    }

    #[test]
    fn test_format_multibyte_hash_does_not_panic() {
        // Regression: the failed-blob detail line truncated `hash` with a
        // byte slice (`&r.hash[..12]`). The hash field carries arbitrary
        // manifest strings (afterHash / patch uuid); when byte 12 falls
        // inside a multibyte char the slice panicked ("byte index 12 is not
        // a char boundary"), crashing apply/repair/rollback human output
        // instead of reporting the failed download.
        let hash = format!("{}→tail-of-corrupted-hash", "a".repeat(11));
        let result = FetchMissingBlobsResult {
            total: 1,
            downloaded: 0,
            failed: 1,
            skipped: 0,
            results: vec![BlobFetchResult {
                hash,
                success: false,
                error: Some("Invalid hash format".into()),
            }],
        };
        let output = format_fetch_result(&result);
        assert!(output.contains("Failed to download 1 blob\n"));
        assert!(
            output.contains("aaaaaaaaaaa→..."),
            "12-char prefix expected: {output:?}"
        );
    }

    #[test]
    fn test_format_error_none() {
        let result = FetchMissingBlobsResult {
            total: 1,
            downloaded: 0,
            failed: 1,
            skipped: 0,
            results: vec![BlobFetchResult {
                hash: "d".repeat(64),
                success: false,
                error: None,
            }],
        };
        let output = format_fetch_result(&result);
        assert!(output.contains("unknown error"));
    }

    // ── Regression: skipped accounting in format ─────────────────────

    #[test]
    fn test_format_all_skipped_is_not_blank() {
        // Regression: `fetch_blobs_by_hash` can return total>0 with every
        // blob already on disk (downloaded=0, failed=0, skipped=N). The
        // formatter must surface that rather than returning a blank line.
        let result = FetchMissingBlobsResult {
            total: 2,
            downloaded: 0,
            failed: 0,
            skipped: 2,
            results: vec![
                BlobFetchResult {
                    hash: "a".repeat(64),
                    success: true,
                    error: None,
                },
                BlobFetchResult {
                    hash: "b".repeat(64),
                    success: true,
                    error: None,
                },
            ],
        };
        let output = format_fetch_result(&result);
        assert!(!output.trim().is_empty(), "must not be blank: {:?}", output);
        assert_eq!(output, "2 blobs already present locally");
        assert!(!output.contains("Downloaded"));
        assert!(!output.contains("Failed"));
    }

    #[test]
    fn test_format_downloaded_and_skipped_mix() {
        let result = FetchMissingBlobsResult {
            total: 3,
            downloaded: 1,
            failed: 0,
            skipped: 2,
            results: vec![
                BlobFetchResult {
                    hash: "a".repeat(64),
                    success: true,
                    error: None,
                },
                BlobFetchResult {
                    hash: "b".repeat(64),
                    success: true,
                    error: None,
                },
                BlobFetchResult {
                    hash: "c".repeat(64),
                    success: true,
                    error: None,
                },
            ],
        };
        let output = format_fetch_result(&result);
        assert_eq!(output, "Downloaded 1 blob\n2 blobs already present locally");
    }

    // ── Regression: hash comparison is case-insensitive ──────────────

    #[test]
    fn test_blob_hash_matches_is_case_insensitive() {
        // Hex is case-insensitive. `compute_git_sha256_from_bytes` emits
        // lowercase, but `is_valid_sha256_hex` accepts uppercase, so the
        // verification must treat the two as equal (otherwise valid
        // uppercase-hash content is wrongly rejected as a mismatch).
        let lower = "abc123".to_string() + &"0".repeat(58);
        let upper = lower.to_ascii_uppercase();
        assert!(blob_hash_matches(&upper, &lower));
        assert!(blob_hash_matches(&lower, &upper));
        assert!(blob_hash_matches(&lower, &lower));
    }

    #[test]
    fn test_blob_hash_matches_rejects_genuine_mismatch() {
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        assert!(!blob_hash_matches(&a, &b));
        // Differing length is still a mismatch.
        assert!(!blob_hash_matches(&a, "aa"));
    }

    // ── Atomic cache-entry write ─────────────────────────────────────

    /// A [`BinaryBody`] streaming `bytes` from a local mock server. The
    /// server is returned so it outlives the read.
    async fn served_body(bytes: &[u8]) -> (wiremock::MockServer, BinaryBody) {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::any())
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_bytes(bytes.to_vec()))
            .mount(&server)
            .await;
        let client = ApiClient::new(crate::api::client::ApiClientOptions {
            api_url: server.uri(),
            api_token: None,
            use_public_proxy: true,
            org_slug: None,
        });
        let body = client
            .fetch_blob(&"a".repeat(64))
            .await
            .unwrap()
            .expect("200 serves a body");
        (server, body)
    }

    /// [`stream_cache_entry_atomic`] with no hash check, over `bytes`.
    async fn write_cache_entry_atomic(dest: &Path, bytes: &[u8]) -> Result<(), EntryError> {
        let (_server, mut body) = served_body(bytes).await;
        stream_cache_entry_atomic(dest, &mut body, None).await
    }

    #[tokio::test]
    async fn test_write_cache_entry_atomic_writes_exact_bytes_no_litter() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("a".repeat(64));
        write_cache_entry_atomic(&dest, b"blob-content")
            .await
            .unwrap();

        assert_eq!(tokio::fs::read(&dest).await.unwrap(), b"blob-content");
        // The stage file must have been renamed away, not left behind: the
        // directory holds exactly the final entry and nothing dot-prefixed.
        let entries: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            entries.len(),
            1,
            "only the final entry should remain: {entries:?}"
        );
        assert!(
            !entries[0].starts_with(".socket-dl-"),
            "no staging turd should survive: {entries:?}"
        );
    }

    #[tokio::test]
    async fn test_write_cache_entry_atomic_replaces_existing_completely() {
        // A torn rewrite must not be observable: writing over an existing
        // entry leaves the new bytes whole, never a prefix-of-old + new mix.
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("entry");
        tokio::fs::write(&dest, b"old-and-longer-content")
            .await
            .unwrap();

        write_cache_entry_atomic(&dest, b"new").await.unwrap();
        assert_eq!(tokio::fs::read(&dest).await.unwrap(), b"new");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[tokio::test]
    async fn test_write_cache_entry_atomic_rename_failure_removes_stage() {
        // Rename-failure arm: the stage write succeeds, but `dest` is an
        // existing DIRECTORY, so the rename(file -> dir) fails on unix and
        // Windows alike (no perms tricks needed; works as root too). The
        // stage must be removed, leaving the directory exactly as it was.
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("entry");
        std::fs::create_dir(&dest).unwrap();

        let result = write_cache_entry_atomic(&dest, b"bytes").await;
        assert!(
            result.is_err(),
            "rename over an existing directory must fail"
        );
        assert!(dest.is_dir(), "dest must still be the original directory");
        let entries: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            entries,
            vec!["entry".to_string()],
            "no .socket-dl-* stage may survive the failed rename: {entries:?}"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_write_cache_entry_atomic_stage_write_failure_no_litter() {
        // Stage-write-failure arm: the parent directory denies writes, so
        // the stage file itself cannot be created. The error propagates and
        // the directory stays empty — no stage, no dest.
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let ro = dir.path().join("ro");
        std::fs::create_dir(&ro).unwrap();
        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o555)).unwrap();

        // Precondition probe: under root / CAP_DAC_OVERRIDE the mode bits
        // do not deny writes and the Err arm under test cannot fire — skip
        // rather than pass vacuously.
        let probe = ro.join(".probe");
        if std::fs::write(&probe, b"").is_ok() {
            let _ = std::fs::remove_file(&probe);
            eprintln!("skipping: directory mode bits do not deny writes here (root?)");
            return;
        }

        let result = write_cache_entry_atomic(&ro.join("x"), b"bytes").await;
        let err = result.expect_err("stage write into a read-only dir must fail");
        assert!(
            matches!(&err, EntryError::Write(e) if e.kind() == std::io::ErrorKind::PermissionDenied),
            "{err:?}"
        );

        // Restore before asserting/teardown so cleanup cannot mask failure.
        std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(!ro.join("x").exists(), "dest must not exist");
        assert_eq!(
            std::fs::read_dir(&ro).unwrap().count(),
            0,
            "no stage litter may survive the failed stage write"
        );
    }

    #[test]
    fn test_format_only_failed() {
        let result = FetchMissingBlobsResult {
            total: 2,
            downloaded: 0,
            failed: 2,
            skipped: 0,
            results: vec![
                BlobFetchResult {
                    hash: "a".repeat(64),
                    success: false,
                    error: Some("timeout".into()),
                },
                BlobFetchResult {
                    hash: "b".repeat(64),
                    success: false,
                    error: Some("timeout".into()),
                },
            ],
        };
        let output = format_fetch_result(&result);
        assert!(!output.contains("Downloaded"));
        assert!(
            output.starts_with("Failed to download 2 blobs\n"),
            "{output}"
        );
    }

    fn failure(id: &str, error: &str) -> BlobFetchResult {
        BlobFetchResult {
            hash: id.to_string(),
            success: false,
            error: Some(error.to_string()),
        }
    }

    fn failed_result(results: Vec<BlobFetchResult>) -> FetchMissingBlobsResult {
        FetchMissingBlobsResult {
            total: results.len(),
            failed: results.len(),
            results,
            ..Default::default()
        }
    }

    #[test]
    fn artifact_noun_counts_singular_and_plural() {
        assert_eq!(BLOB.count(0), "0 blobs");
        assert_eq!(BLOB.count(1), "1 blob");
        assert_eq!(BLOB.count(2), "2 blobs");
        assert_eq!(DIFF_ARCHIVE.count(1), "1 diff archive");
        assert_eq!(DIFF_ARCHIVE.count(3), "3 diff archives");
        assert_eq!(PACKAGE_ARCHIVE.count(1), "1 package archive");
    }

    #[test]
    fn display_id_abbreviates_only_long_blob_hashes() {
        assert_eq!(BLOB.display_id(&"a".repeat(64)), "aaaaaaaaaaaa...");
        // Exactly 12 characters: nothing cut, so no ellipsis.
        assert_eq!(BLOB.display_id("abcdefabcdef"), "abcdefabcdef");
        assert_eq!(BLOB.display_id("22"), "22");
        assert_eq!(BLOB.display_id(""), "");
        // Multibyte: counted in chars, never sliced mid-char.
        assert_eq!(
            BLOB.display_id(&"é".repeat(13)),
            format!("{}...", "é".repeat(12))
        );
        // UUIDs are the lookup key: always in full.
        let uuid = "11111111-1111-4111-8111-111111111111";
        assert_eq!(DIFF_ARCHIVE.display_id(uuid), uuid);
    }

    #[test]
    fn failures_are_listed_in_sorted_order_regardless_of_input_order() {
        let ids = ["e", "b", "a", "d", "c", "g", "f"];
        let result = failed_result(ids.iter().map(|id| failure(id, "x")).collect());
        assert_eq!(
            format_fetch_failures(&result, BLOB),
            vec![
                "Failed to download 7 blobs",
                "  - a: x",
                "  - b: x",
                "  - c: x",
                "  - d: x",
                "  - e: x",
                "  ... and 2 more",
            ]
        );
    }

    #[test]
    fn successes_and_failures_split_cleanly() {
        let mut result = failed_result(vec![failure("abc", "boom")]);
        result.total = 3;
        result.downloaded = 1;
        result.skipped = 1;
        assert_eq!(
            format_fetch_successes(&result, BLOB),
            vec!["Downloaded 1 blob", "1 blob already present locally"]
        );
        assert_eq!(
            format_fetch_failures(&result, BLOB),
            vec!["Failed to download 1 blob", "  - abc: boom"]
        );
        assert!(format_fetch_failures(&FetchMissingBlobsResult::default(), BLOB).is_empty());
        assert!(format_fetch_successes(&FetchMissingBlobsResult::default(), BLOB).is_empty());
    }

    #[test]
    fn concise_fetch_error_drops_only_the_repeated_id() {
        assert_eq!(
            concise_fetch_error("Network error fetching blob abc: timed out", "abc"),
            "network error: timed out"
        );
        // A different id (or any other shape) is left alone.
        assert_eq!(
            concise_fetch_error("Network error fetching blob zzz: timed out", "abc"),
            "Network error fetching blob zzz: timed out"
        );
        assert_eq!(
            concise_fetch_error("Blob not found on server", "abc"),
            "Blob not found on server"
        );
        assert_eq!(
            concise_fetch_error("Network error fetching ", "abc"),
            "Network error fetching "
        );
    }
}
