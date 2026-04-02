use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::api::client::ApiClient;
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
#[derive(Debug, Clone)]
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
pub async fn get_missing_blobs(
    manifest: &PatchManifest,
    blobs_path: &Path,
) -> HashSet<String> {
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
        return FetchMissingBlobsResult {
            total: 0,
            downloaded: 0,
            failed: 0,
            skipped: 0,
            results: Vec::new(),
        };
    }

    // Ensure blobs directory exists
    if let Err(e) = tokio::fs::create_dir_all(blobs_path).await {
        // If we cannot create the directory, every blob will fail.
        let results: Vec<BlobFetchResult> = missing
            .iter()
            .map(|h| BlobFetchResult {
                hash: h.clone(),
                success: false,
                error: Some(format!("Cannot create blobs directory: {}", e)),
            })
            .collect();
        let failed = results.len();
        return FetchMissingBlobsResult {
            total: failed,
            downloaded: 0,
            failed,
            skipped: 0,
            results,
        };
    }

    let hashes: Vec<String> = missing.into_iter().collect();
    download_hashes(&hashes, blobs_path, client, on_progress).await
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
        return FetchMissingBlobsResult {
            total: 0,
            downloaded: 0,
            failed: 0,
            skipped: 0,
            results: Vec::new(),
        };
    }

    // Ensure blobs directory exists
    if let Err(e) = tokio::fs::create_dir_all(blobs_path).await {
        let results: Vec<BlobFetchResult> = hashes
            .iter()
            .map(|h| BlobFetchResult {
                hash: h.clone(),
                success: false,
                error: Some(format!("Cannot create blobs directory: {}", e)),
            })
            .collect();
        let failed = results.len();
        return FetchMissingBlobsResult {
            total: failed,
            downloaded: 0,
            failed,
            skipped: 0,
            results,
        };
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

    let download_result =
        download_hashes(&to_download, blobs_path, client, on_progress).await;

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

/// Format a [`FetchMissingBlobsResult`] as a human-readable string.
pub fn format_fetch_result(result: &FetchMissingBlobsResult) -> String {
    if result.total == 0 {
        return "All blobs are present locally.".to_string();
    }

    let mut lines: Vec<String> = Vec::new();

    if result.downloaded > 0 {
        lines.push(format!("Downloaded {} blob(s)", result.downloaded));
    }

    if result.failed > 0 {
        lines.push(format!("Failed to download {} blob(s)", result.failed));

        let failed_results: Vec<&BlobFetchResult> =
            result.results.iter().filter(|r| !r.success).collect();

        for r in failed_results.iter().take(5) {
            let short_hash = if r.hash.len() >= 12 {
                &r.hash[..12]
            } else {
                &r.hash
            };
            let err = r.error.as_deref().unwrap_or("unknown error");
            lines.push(format!("  - {}...: {}", short_hash, err));
        }

        if failed_results.len() > 5 {
            lines.push(format!("  ... and {} more", failed_results.len() - 5));
        }
    }

    lines.join("\n")
}

// ── Internal helpers ──────────────────────────────────────────────────

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
                if actual_hash != *hash {
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
                match tokio::fs::write(&blob_path, &data).await {
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
                    before_hash: format!(
                        "before{}{}",
                        "0".repeat(58),
                        format!("{:06}", i)
                    ),
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

        PatchManifest { patches }
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
        tokio::fs::write(blobs_path.join(&h1), b"data").await.unwrap();

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
        assert_eq!(format_fetch_result(&result), "All blobs are present locally.");
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
                BlobFetchResult { hash: "a".repeat(64), success: true, error: None },
                BlobFetchResult { hash: "b".repeat(64), success: true, error: None },
                BlobFetchResult { hash: "c".repeat(64), success: true, error: None },
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
