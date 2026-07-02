use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::api::client::ApiClient;
use crate::manifest::operations::get_after_hash_blobs;
use crate::manifest::schema::PatchManifest;
use crate::patch::apply::PatchSources;

/// Selects which kind of patch artifact `fetch_missing_sources` downloads.
///
/// * `File` — per-file blobs (legacy, largest, always applicable).
/// * `Diff` — per-patch tar.gz of bsdiff deltas (smallest, only useful
///   when the original file is on disk).
/// * `Package` — per-patch tar.gz of patched files (mid-size, applicable
///   even when the original file is missing).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DownloadMode {
    Diff,
    Package,
    File,
}

impl DownloadMode {
    /// Short lowercase tag, suitable for JSON output and `--download-mode`
    /// flag values.
    pub fn as_tag(&self) -> &'static str {
        match self {
            DownloadMode::Diff => "diff",
            DownloadMode::Package => "package",
            DownloadMode::File => "file",
        }
    }

    /// Parse `--download-mode` flag values.
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "diff" => Ok(DownloadMode::Diff),
            "package" => Ok(DownloadMode::Package),
            "file" | "blob" => Ok(DownloadMode::File),
            other => Err(format!(
                "unknown download mode '{}'. Expected diff, package, or file.",
                other
            )),
        }
    }
}

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

    // Ensure blobs directory exists
    if let Err(e) = tokio::fs::create_dir_all(blobs_path).await {
        return all_failed_result(missing.iter(), |h| {
            (h.clone(), format!("Cannot create blobs directory: {}", e))
        });
    }

    let hashes: Vec<String> = missing.into_iter().collect();
    download_hashes(&hashes, blobs_path, client, on_progress).await
}

/// Build a [`FetchMissingBlobsResult`] whose entries are all failures
/// for the same reason. Used by the early-return branches that hit a
/// blocker (e.g. cannot create blobs dir) before any download attempt.
fn all_failed_result<'a, I, F>(items: I, mut into_pair: F) -> FetchMissingBlobsResult
where
    I: IntoIterator<Item = &'a String>,
    F: FnMut(&'a String) -> (String, String),
{
    let results: Vec<BlobFetchResult> = items
        .into_iter()
        .map(|item| {
            let (hash, error) = into_pair(item);
            BlobFetchResult {
                hash,
                success: false,
                error: Some(error),
            }
        })
        .collect();
    let failed = results.len();
    FetchMissingBlobsResult {
        total: failed,
        failed,
        results,
        ..FetchMissingBlobsResult::default()
    }
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

    // Ensure blobs directory exists
    if let Err(e) = tokio::fs::create_dir_all(blobs_path).await {
        return all_failed_result(hashes.iter(), |h| {
            (h.clone(), format!("Cannot create blobs directory: {}", e))
        });
    }

    // Filter out hashes that already exist on disk
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

    let download_result = download_hashes(&to_download, blobs_path, client, on_progress).await;

    FetchMissingBlobsResult {
        total: hashes.len(),
        downloaded: download_result.downloaded,
        failed: download_result.failed,
        skipped,
        results: {
            let mut combined = results;
            combined.extend(download_result.results);
            combined
        },
    }
}

/// Return the set of patch UUIDs whose archive at
/// `<archives_dir>/<uuid>.tar.gz` is missing from disk. Used as the
/// "what do I need to download" query for diff and package modes.
pub async fn get_missing_archives(
    manifest: &PatchManifest,
    archives_dir: &Path,
) -> HashSet<String> {
    let mut missing = HashSet::new();
    for record in manifest.patches.values() {
        let archive_path = archives_dir.join(format!("{}.tar.gz", record.uuid));
        if tokio::fs::metadata(&archive_path).await.is_err() {
            missing.insert(record.uuid.clone());
        }
    }
    missing
}

/// Download all missing archives for the chosen [`DownloadMode`].
///
/// * [`DownloadMode::File`] delegates to [`fetch_missing_blobs`].
/// * [`DownloadMode::Diff`] downloads each missing `<uuid>.tar.gz` into
///   `sources.diffs_path` via [`ApiClient::fetch_diff`].
/// * [`DownloadMode::Package`] does the same with `sources.packages_path`
///   and [`ApiClient::fetch_package`].
///
/// Returns a [`FetchMissingBlobsResult`] in which each `BlobFetchResult`'s
/// `hash` field carries the patch UUID (not a blob hash) for diff and
/// package modes. A `sources.packages_path` / `sources.diffs_path` of
/// `None` while requesting that mode yields an immediate empty result —
/// the caller is expected to fall back to a different mode in that case.
pub async fn fetch_missing_sources(
    manifest: &PatchManifest,
    sources: &PatchSources<'_>,
    mode: DownloadMode,
    client: &ApiClient,
    on_progress: Option<&OnProgress>,
) -> FetchMissingBlobsResult {
    match mode {
        DownloadMode::File => {
            fetch_missing_blobs(manifest, sources.blobs_path, client, on_progress).await
        }
        DownloadMode::Diff => match sources.diffs_path {
            Some(dir) => {
                fetch_missing_archives_inner(manifest, dir, ArchiveKind::Diff, client, on_progress)
                    .await
            }
            None => FetchMissingBlobsResult::default(),
        },
        DownloadMode::Package => match sources.packages_path {
            Some(dir) => {
                fetch_missing_archives_inner(
                    manifest,
                    dir,
                    ArchiveKind::Package,
                    client,
                    on_progress,
                )
                .await
            }
            None => FetchMissingBlobsResult::default(),
        },
    }
}

#[derive(Debug, Clone, Copy)]
enum ArchiveKind {
    Diff,
    Package,
}

async fn fetch_missing_archives_inner(
    manifest: &PatchManifest,
    archives_dir: &Path,
    kind: ArchiveKind,
    client: &ApiClient,
    on_progress: Option<&OnProgress>,
) -> FetchMissingBlobsResult {
    let missing = get_missing_archives(manifest, archives_dir).await;
    if missing.is_empty() {
        return FetchMissingBlobsResult::default();
    }

    if let Err(e) = tokio::fs::create_dir_all(archives_dir).await {
        return all_failed_result(missing.iter(), |u| {
            (
                u.clone(),
                format!("Cannot create archives directory: {}", e),
            )
        });
    }

    let uuids: Vec<String> = missing.into_iter().collect();
    let total = uuids.len();
    let mut downloaded = 0usize;
    let mut failed = 0usize;
    let mut results = Vec::with_capacity(total);

    for (i, uuid) in uuids.iter().enumerate() {
        if let Some(ref cb) = on_progress {
            cb(uuid, i + 1, total);
        }

        let fetch_result = match kind {
            ArchiveKind::Diff => client.fetch_diff(uuid).await,
            ArchiveKind::Package => client.fetch_package(uuid).await,
        };

        match fetch_result {
            Ok(Some(data)) => {
                let archive_path: PathBuf = archives_dir.join(format!("{}.tar.gz", uuid));
                match write_cache_entry_atomic(&archive_path, &data).await {
                    Ok(()) => {
                        results.push(BlobFetchResult {
                            hash: uuid.clone(),
                            success: true,
                            error: None,
                        });
                        downloaded += 1;
                    }
                    Err(e) => {
                        results.push(BlobFetchResult {
                            hash: uuid.clone(),
                            success: false,
                            error: Some(format!("Failed to write archive to disk: {}", e)),
                        });
                        failed += 1;
                    }
                }
            }
            Ok(None) => {
                results.push(BlobFetchResult {
                    hash: uuid.clone(),
                    success: false,
                    error: Some(format!(
                        "{} archive not found on server",
                        match kind {
                            ArchiveKind::Diff => "Diff",
                            ArchiveKind::Package => "Package",
                        }
                    )),
                });
                failed += 1;
            }
            Err(e) => {
                results.push(BlobFetchResult {
                    hash: uuid.clone(),
                    success: false,
                    error: Some(e.to_string()),
                });
                failed += 1;
            }
        }
    }

    FetchMissingBlobsResult {
        total,
        downloaded,
        failed,
        skipped: 0,
        results,
    }
}

/// Format a [`FetchMissingBlobsResult`] as a human-readable string.
pub fn format_fetch_result(result: &FetchMissingBlobsResult) -> String {
    if result.total == 0 {
        return "All blobs are present locally.".to_string();
    }

    let mut lines: Vec<String> = Vec::new();

    if result.downloaded > 0 {
        lines.push(format!("Downloaded {} blob(s)", result.downloaded));
    }

    if result.skipped > 0 {
        lines.push(format!(
            "{} blob(s) already present locally",
            result.skipped
        ));
    }

    if result.failed > 0 {
        lines.push(format!("Failed to download {} blob(s)", result.failed));

        let failed_results: Vec<&BlobFetchResult> =
            result.results.iter().filter(|r| !r.success).collect();

        for r in failed_results.iter().take(5) {
            // Truncate by characters, not bytes: the hash field carries
            // arbitrary manifest strings, and a byte slice panics when index
            // 12 lands inside a multibyte char.
            let short_hash: String = r.hash.chars().take(12).collect();
            let err = r.error.as_deref().unwrap_or("unknown error");
            lines.push(format!("  - {}...: {}", short_hash, err));
        }

        if failed_results.len() > 5 {
            lines.push(format!("  ... and {} more", failed_results.len() - 5));
        }
    }

    // `total > 0` but nothing downloaded, skipped, or failed should not be
    // reachable, but guard against emitting a misleading blank string.
    if lines.is_empty() {
        return "All blobs are present locally.".to_string();
    }

    lines.join("\n")
}

// ── Internal helpers ──────────────────────────────────────────────────

/// Write `bytes` to `dest` atomically: stage a temp file in the same
/// directory, then `rename(2)` it over `dest`.
///
/// The destinations here are *content-addressed* cache entries —
/// `blobs/<hash>` and `archives/<uuid>.tar.gz`. A plain `tokio::fs::write`
/// truncates-then-writes in place, so an interrupted write (ENOSPC, crash,
/// killed process) can leave a partial file at the final path. Because the
/// "is it already downloaded?" check ([`get_missing_blobs`] /
/// [`get_missing_archives`]) only tests for presence, such a truncated file
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
async fn write_cache_entry_atomic(dest: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = dest.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "cache entry path has no parent directory",
        )
    })?;
    let stem = dest
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "blob".to_string());
    // Leading dot keeps the stage out of editor/glob views; the uuid suffix
    // keeps concurrent writers of the same entry from colliding.
    let stage: PathBuf = parent.join(format!(".socket-dl-{}-{}", stem, uuid::Uuid::new_v4()));

    if let Err(e) = tokio::fs::write(&stage, bytes).await {
        // A partial stage would otherwise leak as a `.socket-dl-*` turd.
        let _ = tokio::fs::remove_file(&stage).await;
        return Err(e);
    }
    if let Err(e) = tokio::fs::rename(&stage, dest).await {
        let _ = tokio::fs::remove_file(&stage).await;
        return Err(e);
    }
    Ok(())
}

/// Compare an expected blob hash against the hash computed from the
/// downloaded bytes.
///
/// Git object hashes are hex, and hex is case-insensitive. The content
/// hasher ([`compute_git_sha256_from_bytes`]) always emits lowercase, but
/// [`ApiClient::fetch_blob`]'s validator accepts uppercase hex too — so a
/// manifest (or server) that uses uppercase would download byte-for-byte
/// correct content and then be wrongly rejected by a case-sensitive
/// comparison. Compare ignoring ASCII case to keep the two consistent.
///
/// [`compute_git_sha256_from_bytes`]: crate::hash::git_sha256::compute_git_sha256_from_bytes
fn blob_hash_matches(expected: &str, actual: &str) -> bool {
    expected.eq_ignore_ascii_case(actual)
}

/// Download a list of blob hashes sequentially, writing each to
/// `blobs_path/<hash>`.
async fn download_hashes(
    hashes: &[String],
    blobs_path: &Path,
    client: &ApiClient,
    on_progress: Option<&OnProgress>,
) -> FetchMissingBlobsResult {
    let total = hashes.len();
    let mut downloaded: usize = 0;
    let mut failed: usize = 0;
    let mut results: Vec<BlobFetchResult> = Vec::with_capacity(total);

    for (i, hash) in hashes.iter().enumerate() {
        if let Some(ref cb) = on_progress {
            cb(hash, i + 1, total);
        }

        match client.fetch_blob(hash).await {
            Ok(Some(data)) => {
                // Verify content hash matches expected hash before writing
                let actual_hash = crate::hash::git_sha256::compute_git_sha256_from_bytes(&data);
                if !blob_hash_matches(hash, &actual_hash) {
                    results.push(BlobFetchResult {
                        hash: hash.clone(),
                        success: false,
                        error: Some(format!(
                            "Content hash mismatch: expected {}, got {}",
                            hash, actual_hash
                        )),
                    });
                    failed += 1;
                    continue;
                }

                let blob_path: PathBuf = blobs_path.join(hash);
                match write_cache_entry_atomic(&blob_path, &data).await {
                    Ok(()) => {
                        results.push(BlobFetchResult {
                            hash: hash.clone(),
                            success: true,
                            error: None,
                        });
                        downloaded += 1;
                    }
                    Err(e) => {
                        results.push(BlobFetchResult {
                            hash: hash.clone(),
                            success: false,
                            error: Some(format!("Failed to write blob to disk: {}", e)),
                        });
                        failed += 1;
                    }
                }
            }
            Ok(None) => {
                results.push(BlobFetchResult {
                    hash: hash.clone(),
                    success: false,
                    error: Some("Blob not found on server".to_string()),
                });
                failed += 1;
            }
            Err(e) => {
                results.push(BlobFetchResult {
                    hash: hash.clone(),
                    success: false,
                    error: Some(e.to_string()),
                });
                failed += 1;
            }
        }
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
        assert!(output.contains("Downloaded 2 blob(s)"));
        assert!(output.contains("Failed to download 1 blob(s)"));
        assert!(output.contains("cccccccccccc..."));
        assert!(output.contains("Blob not found on server"));
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
        assert!(output.contains("Downloaded 3 blob(s)"));
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
        // Hash is < 12 chars, should show full hash
        assert!(output.contains("abc..."));
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
        assert!(output.contains("Failed to download 1 blob(s)"));
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

    // ── DownloadMode + archive helpers ──────────────────────────────

    #[test]
    fn test_download_mode_parse() {
        assert_eq!(DownloadMode::parse("diff").unwrap(), DownloadMode::Diff);
        assert_eq!(DownloadMode::parse("DIFF").unwrap(), DownloadMode::Diff);
        assert_eq!(
            DownloadMode::parse("package").unwrap(),
            DownloadMode::Package
        );
        assert_eq!(DownloadMode::parse("file").unwrap(), DownloadMode::File);
        // `blob` aliases to `file` so users can think in pre-2.2 terms.
        assert_eq!(DownloadMode::parse("blob").unwrap(), DownloadMode::File);
        assert!(DownloadMode::parse("nope").is_err());
    }

    #[test]
    fn test_download_mode_tag() {
        assert_eq!(DownloadMode::Diff.as_tag(), "diff");
        assert_eq!(DownloadMode::Package.as_tag(), "package");
        assert_eq!(DownloadMode::File.as_tag(), "file");
    }

    fn make_manifest_with_uuids(uuids: &[&str]) -> PatchManifest {
        let mut patches = HashMap::new();
        for (i, uuid) in uuids.iter().enumerate() {
            let key = format!("pkg:npm/test-{}@1.0.0", i);
            patches.insert(
                key,
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

    #[tokio::test]
    async fn test_get_missing_archives_all_missing() {
        let dir = tempfile::tempdir().unwrap();
        let archives = dir.path().join("packages");
        tokio::fs::create_dir_all(&archives).await.unwrap();

        let u1 = "11111111-1111-4111-8111-111111111111";
        let u2 = "22222222-2222-4222-8222-222222222222";
        let manifest = make_manifest_with_uuids(&[u1, u2]);

        let missing = get_missing_archives(&manifest, &archives).await;
        assert_eq!(missing.len(), 2);
        assert!(missing.contains(u1));
        assert!(missing.contains(u2));
    }

    #[tokio::test]
    async fn test_get_missing_archives_some_present() {
        let dir = tempfile::tempdir().unwrap();
        let archives = dir.path().join("packages");
        tokio::fs::create_dir_all(&archives).await.unwrap();

        let u1 = "11111111-1111-4111-8111-111111111111";
        let u2 = "22222222-2222-4222-8222-222222222222";

        tokio::fs::write(archives.join(format!("{u1}.tar.gz")), b"data")
            .await
            .unwrap();

        let manifest = make_manifest_with_uuids(&[u1, u2]);
        let missing = get_missing_archives(&manifest, &archives).await;
        assert_eq!(missing.len(), 1);
        assert!(missing.contains(u2));
        assert!(!missing.contains(u1));
    }

    #[tokio::test]
    async fn test_fetch_missing_sources_unsupported_mode_returns_empty() {
        // Asking for Diff mode without a diffs_path yields an empty result
        // rather than panicking. Same for Package mode.
        let dir = tempfile::tempdir().unwrap();
        let blobs = dir.path().join("blobs");
        tokio::fs::create_dir_all(&blobs).await.unwrap();
        let sources = PatchSources::blobs_only(&blobs);

        let manifest = make_manifest_with_uuids(&["11111111-1111-4111-8111-111111111111"]);
        let (client, _) = crate::api::client::get_api_client_from_env(None).await;

        let res =
            fetch_missing_sources(&manifest, &sources, DownloadMode::Diff, &client, None).await;
        assert_eq!(res.total, 0);
        assert_eq!(res.downloaded, 0);
        assert_eq!(res.failed, 0);

        let res =
            fetch_missing_sources(&manifest, &sources, DownloadMode::Package, &client, None).await;
        assert_eq!(res.total, 0);
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
        assert!(output.contains("2 blob(s) already present"));
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
        assert!(output.contains("Downloaded 1 blob(s)"));
        assert!(output.contains("2 blob(s) already present"));
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
        assert!(output.contains("Failed to download 2 blob(s)"));
    }
}
