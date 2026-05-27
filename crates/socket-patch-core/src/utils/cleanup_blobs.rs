use std::collections::HashSet;
use std::path::Path;

use crate::manifest::operations::get_after_hash_blobs;
use crate::manifest::schema::PatchManifest;

/// Result of a blob cleanup operation.
#[derive(Debug, Clone, Default)]
pub struct CleanupResult {
    pub blobs_checked: usize,
    pub blobs_removed: usize,
    pub bytes_freed: u64,
    pub removed_blobs: Vec<String>,
}

/// Shared core for `cleanup_unused_blobs` / `cleanup_unused_archives`.
///
/// Walks `dir`, treats it as authoritative socket-patch state (so any
/// regular non-hidden file is considered for removal), and asks
/// `is_used(filename) -> bool` whether each file should be kept.
async fn cleanup_dir<F: Fn(&str) -> bool>(
    dir: &Path,
    dry_run: bool,
    is_used: F,
) -> Result<CleanupResult, std::io::Error> {
    if tokio::fs::metadata(dir).await.is_err() {
        return Ok(CleanupResult::default());
    }

    let mut read_dir = tokio::fs::read_dir(dir).await?;
    let mut entries = Vec::new();
    while let Some(entry) = read_dir.next_entry().await? {
        entries.push(entry);
    }

    let mut result = CleanupResult {
        blobs_checked: entries.len(),
        ..CleanupResult::default()
    };

    for entry in &entries {
        let file_name_str = entry.file_name().to_string_lossy().to_string();
        if file_name_str.starts_with('.') {
            continue;
        }
        let path = dir.join(&file_name_str);
        let metadata = tokio::fs::metadata(&path).await?;
        if !metadata.is_file() {
            continue;
        }
        if is_used(&file_name_str) {
            continue;
        }
        result.blobs_removed += 1;
        result.bytes_freed += metadata.len();
        result.removed_blobs.push(file_name_str);
        if !dry_run {
            tokio::fs::remove_file(&path).await?;
        }
    }

    Ok(result)
}

/// Cleans up unused blob files from the blobs directory.
///
/// Analyzes the manifest to determine which afterHash blobs are needed for applying patches,
/// then removes any blob files that are not needed.
///
/// Note: beforeHash blobs are considered "unused" because they are downloaded on-demand
/// during rollback operations. This saves disk space since beforeHash blobs are only
/// needed for rollback, not for applying patches.
pub async fn cleanup_unused_blobs(
    manifest: &PatchManifest,
    blobs_dir: &Path,
    dry_run: bool,
) -> Result<CleanupResult, std::io::Error> {
    // Only keep afterHash blobs - beforeHash blobs are downloaded on-demand during rollback
    let used_blobs = get_after_hash_blobs(manifest);
    cleanup_dir(blobs_dir, dry_run, |name| used_blobs.contains(name)).await
}

/// Cleans up unused per-patch archive files from `archives_dir`.
///
/// Archives are named `<patch_uuid>.tar.gz`. Any file matching that
/// pattern whose UUID is not present in the manifest is removed. Files
/// that do *not* end in `.tar.gz` are treated as orphans and also
/// removed — these directories are managed exclusively by socket-patch,
/// so any stray non-archive file is assumed to be left over from an
/// older socket-patch version. Subdirectories and hidden files are
/// left untouched.
pub async fn cleanup_unused_archives(
    manifest: &PatchManifest,
    archives_dir: &Path,
    dry_run: bool,
) -> Result<CleanupResult, std::io::Error> {
    let used_uuids: HashSet<String> =
        manifest.patches.values().map(|r| r.uuid.clone()).collect();
    cleanup_dir(archives_dir, dry_run, |name| {
        // Strip the .tar.gz suffix to recover the UUID; if it doesn't
        // end in .tar.gz, treat the entry as orphaned (not "used").
        let uuid_part = name.strip_suffix(".tar.gz").unwrap_or(name);
        used_uuids.contains(uuid_part)
    })
    .await
}

/// Formats the cleanup result for human-readable output.
pub fn format_cleanup_result(result: &CleanupResult, dry_run: bool) -> String {
    if result.blobs_checked == 0 {
        return "No blobs directory found, nothing to clean up.".to_string();
    }

    if result.blobs_removed == 0 {
        return format!(
            "Checked {} blob(s), all are in use.",
            result.blobs_checked
        );
    }

    let action = if dry_run { "Would remove" } else { "Removed" };
    let bytes_formatted = format_bytes(result.bytes_freed);

    let mut output = format!(
        "{} {} unused blob(s) ({} freed)",
        action, result.blobs_removed, bytes_formatted
    );

    if dry_run && !result.removed_blobs.is_empty() {
        output.push_str("\nUnused blobs:");
        for blob in &result.removed_blobs {
            output.push_str(&format!("\n  - {}", blob));
        }
    }

    output
}

/// Formats bytes into a human-readable string.
pub fn format_bytes(bytes: u64) -> String {
    if bytes == 0 {
        return "0 B".to_string();
    }

    const KB: u64 = 1024;
    const MB: u64 = 1024 * 1024;
    const GB: u64 = 1024 * 1024 * 1024;

    if bytes < KB {
        format!("{} B", bytes)
    } else if bytes < MB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else if bytes < GB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::schema::{PatchFileInfo, PatchManifest, PatchRecord};
    use std::collections::HashMap;

    const TEST_UUID: &str = "11111111-1111-4111-8111-111111111111";
    const BEFORE_HASH_1: &str =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1111";
    const AFTER_HASH_1: &str =
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb1111";
    const BEFORE_HASH_2: &str =
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc2222";
    const AFTER_HASH_2: &str =
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd2222";
    const ORPHAN_HASH: &str =
        "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo";

    fn create_test_manifest() -> PatchManifest {
        let mut files = HashMap::new();
        files.insert(
            "package/index.js".to_string(),
            PatchFileInfo {
                before_hash: BEFORE_HASH_1.to_string(),
                after_hash: AFTER_HASH_1.to_string(),
            },
        );
        files.insert(
            "package/lib/utils.js".to_string(),
            PatchFileInfo {
                before_hash: BEFORE_HASH_2.to_string(),
                after_hash: AFTER_HASH_2.to_string(),
            },
        );

        let mut patches = HashMap::new();
        patches.insert(
            "pkg:npm/pkg-a@1.0.0".to_string(),
            PatchRecord {
                uuid: TEST_UUID.to_string(),
                exported_at: "2024-01-01T00:00:00Z".to_string(),
                files,
                vulnerabilities: HashMap::new(),
                description: "Test patch".to_string(),
                license: "MIT".to_string(),
                tier: "free".to_string(),
            },
        );

        PatchManifest { patches }
    }

    #[tokio::test]
    async fn test_cleanup_keeps_after_hash_removes_orphan() {
        let dir = tempfile::tempdir().unwrap();
        let blobs_dir = dir.path().join("blobs");
        tokio::fs::create_dir_all(&blobs_dir).await.unwrap();

        let manifest = create_test_manifest();

        // Create blobs on disk
        tokio::fs::write(blobs_dir.join(AFTER_HASH_1), "after content 1")
            .await
            .unwrap();
        tokio::fs::write(blobs_dir.join(AFTER_HASH_2), "after content 2")
            .await
            .unwrap();
        tokio::fs::write(blobs_dir.join(ORPHAN_HASH), "orphan content")
            .await
            .unwrap();

        let result = cleanup_unused_blobs(&manifest, &blobs_dir, false)
            .await
            .unwrap();

        // Should remove only the orphan blob
        assert_eq!(result.blobs_removed, 1);
        assert!(result.removed_blobs.contains(&ORPHAN_HASH.to_string()));

        // afterHash blobs should still exist
        assert!(tokio::fs::metadata(blobs_dir.join(AFTER_HASH_1))
            .await
            .is_ok());
        assert!(tokio::fs::metadata(blobs_dir.join(AFTER_HASH_2))
            .await
            .is_ok());

        // Orphan blob should be removed
        assert!(tokio::fs::metadata(blobs_dir.join(ORPHAN_HASH))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_cleanup_removes_before_hash_blobs() {
        let dir = tempfile::tempdir().unwrap();
        let blobs_dir = dir.path().join("blobs");
        tokio::fs::create_dir_all(&blobs_dir).await.unwrap();

        let manifest = create_test_manifest();

        // Create both beforeHash and afterHash blobs
        tokio::fs::write(blobs_dir.join(BEFORE_HASH_1), "before content 1")
            .await
            .unwrap();
        tokio::fs::write(blobs_dir.join(BEFORE_HASH_2), "before content 2")
            .await
            .unwrap();
        tokio::fs::write(blobs_dir.join(AFTER_HASH_1), "after content 1")
            .await
            .unwrap();
        tokio::fs::write(blobs_dir.join(AFTER_HASH_2), "after content 2")
            .await
            .unwrap();

        let result = cleanup_unused_blobs(&manifest, &blobs_dir, false)
            .await
            .unwrap();

        // Should remove the beforeHash blobs
        assert_eq!(result.blobs_removed, 2);
        assert!(result.removed_blobs.contains(&BEFORE_HASH_1.to_string()));
        assert!(result.removed_blobs.contains(&BEFORE_HASH_2.to_string()));

        // afterHash blobs should still exist
        assert!(tokio::fs::metadata(blobs_dir.join(AFTER_HASH_1))
            .await
            .is_ok());
        assert!(tokio::fs::metadata(blobs_dir.join(AFTER_HASH_2))
            .await
            .is_ok());

        // beforeHash blobs should be removed
        assert!(tokio::fs::metadata(blobs_dir.join(BEFORE_HASH_1))
            .await
            .is_err());
        assert!(tokio::fs::metadata(blobs_dir.join(BEFORE_HASH_2))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_cleanup_dry_run_does_not_delete() {
        let dir = tempfile::tempdir().unwrap();
        let blobs_dir = dir.path().join("blobs");
        tokio::fs::create_dir_all(&blobs_dir).await.unwrap();

        let manifest = create_test_manifest();

        tokio::fs::write(blobs_dir.join(BEFORE_HASH_1), "before content 1")
            .await
            .unwrap();
        tokio::fs::write(blobs_dir.join(AFTER_HASH_1), "after content 1")
            .await
            .unwrap();

        let result = cleanup_unused_blobs(&manifest, &blobs_dir, true)
            .await
            .unwrap();

        // Should report beforeHash as would-be-removed
        assert_eq!(result.blobs_removed, 1);
        assert!(result.removed_blobs.contains(&BEFORE_HASH_1.to_string()));

        // But both blobs should still exist
        assert!(tokio::fs::metadata(blobs_dir.join(BEFORE_HASH_1))
            .await
            .is_ok());
        assert!(tokio::fs::metadata(blobs_dir.join(AFTER_HASH_1))
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn test_cleanup_empty_manifest_removes_all() {
        let dir = tempfile::tempdir().unwrap();
        let blobs_dir = dir.path().join("blobs");
        tokio::fs::create_dir_all(&blobs_dir).await.unwrap();

        let manifest = PatchManifest::new();

        tokio::fs::write(blobs_dir.join(AFTER_HASH_1), "content 1")
            .await
            .unwrap();
        tokio::fs::write(blobs_dir.join(BEFORE_HASH_1), "content 2")
            .await
            .unwrap();

        let result = cleanup_unused_blobs(&manifest, &blobs_dir, false)
            .await
            .unwrap();

        assert_eq!(result.blobs_removed, 2);
    }

    #[tokio::test]
    async fn test_cleanup_nonexistent_blobs_dir() {
        let dir = tempfile::tempdir().unwrap();
        let non_existent = dir.path().join("non-existent");

        let manifest = create_test_manifest();

        let result = cleanup_unused_blobs(&manifest, &non_existent, false)
            .await
            .unwrap();

        assert_eq!(result.blobs_checked, 0);
        assert_eq!(result.blobs_removed, 0);
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(1023), "1023 B");
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1536), "1.50 KB");
        assert_eq!(format_bytes(1048576), "1.00 MB");
        assert_eq!(format_bytes(1073741824), "1.00 GB");
    }

    #[test]
    fn test_format_cleanup_result_no_blobs_dir() {
        let result = CleanupResult {
            blobs_checked: 0,
            blobs_removed: 0,
            bytes_freed: 0,
            removed_blobs: vec![],
        };
        assert_eq!(
            format_cleanup_result(&result, false),
            "No blobs directory found, nothing to clean up."
        );
    }

    #[test]
    fn test_format_cleanup_result_all_in_use() {
        let result = CleanupResult {
            blobs_checked: 5,
            blobs_removed: 0,
            bytes_freed: 0,
            removed_blobs: vec![],
        };
        assert_eq!(
            format_cleanup_result(&result, false),
            "Checked 5 blob(s), all are in use."
        );
    }

    #[test]
    fn test_format_cleanup_result_removed() {
        let result = CleanupResult {
            blobs_checked: 5,
            blobs_removed: 2,
            bytes_freed: 2048,
            removed_blobs: vec!["aaa".to_string(), "bbb".to_string()],
        };
        assert_eq!(
            format_cleanup_result(&result, false),
            "Removed 2 unused blob(s) (2.00 KB freed)"
        );
    }

    // ── cleanup_unused_archives tests ──────────────────────────────

    const SECOND_UUID: &str = "22222222-2222-4222-8222-222222222222";

    #[tokio::test]
    async fn test_cleanup_archives_keeps_referenced_uuid() {
        let dir = tempfile::tempdir().unwrap();
        let archives = dir.path().join("packages");
        tokio::fs::create_dir_all(&archives).await.unwrap();

        let manifest = create_test_manifest();
        tokio::fs::write(archives.join(format!("{TEST_UUID}.tar.gz")), b"keep")
            .await
            .unwrap();
        tokio::fs::write(archives.join(format!("{SECOND_UUID}.tar.gz")), b"orphan")
            .await
            .unwrap();

        let result = cleanup_unused_archives(&manifest, &archives, false)
            .await
            .unwrap();

        assert_eq!(result.blobs_removed, 1);
        assert!(result
            .removed_blobs
            .contains(&format!("{SECOND_UUID}.tar.gz")));
        assert!(tokio::fs::metadata(archives.join(format!("{TEST_UUID}.tar.gz")))
            .await
            .is_ok());
        assert!(tokio::fs::metadata(archives.join(format!("{SECOND_UUID}.tar.gz")))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_cleanup_archives_dry_run_does_not_delete() {
        let dir = tempfile::tempdir().unwrap();
        let archives = dir.path().join("packages");
        tokio::fs::create_dir_all(&archives).await.unwrap();

        let manifest = create_test_manifest();
        tokio::fs::write(archives.join(format!("{SECOND_UUID}.tar.gz")), b"orphan")
            .await
            .unwrap();

        let result = cleanup_unused_archives(&manifest, &archives, true)
            .await
            .unwrap();

        assert_eq!(result.blobs_removed, 1);
        assert!(tokio::fs::metadata(archives.join(format!("{SECOND_UUID}.tar.gz")))
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn test_cleanup_archives_removes_non_archive_files() {
        // Stray files (no .tar.gz suffix, or wrong UUID) are treated as
        // orphans. This keeps the directory tidy when the on-disk format
        // changes in the future.
        let dir = tempfile::tempdir().unwrap();
        let archives = dir.path().join("packages");
        tokio::fs::create_dir_all(&archives).await.unwrap();

        let manifest = create_test_manifest();
        tokio::fs::write(archives.join("stray.txt"), b"junk")
            .await
            .unwrap();
        tokio::fs::write(archives.join(format!("{TEST_UUID}.tar.gz")), b"keep")
            .await
            .unwrap();

        let result = cleanup_unused_archives(&manifest, &archives, false)
            .await
            .unwrap();

        assert_eq!(result.blobs_removed, 1);
        assert!(result.removed_blobs.contains(&"stray.txt".to_string()));
    }

    #[tokio::test]
    async fn test_cleanup_archives_nonexistent_dir() {
        let dir = tempfile::tempdir().unwrap();
        let archives = dir.path().join("does-not-exist");
        let manifest = create_test_manifest();

        let result = cleanup_unused_archives(&manifest, &archives, false)
            .await
            .unwrap();
        assert_eq!(result.blobs_checked, 0);
        assert_eq!(result.blobs_removed, 0);
    }

    #[test]
    fn test_format_cleanup_result_dry_run_lists_blobs() {
        let result = CleanupResult {
            blobs_checked: 5,
            blobs_removed: 2,
            bytes_freed: 2048,
            removed_blobs: vec!["aaa".to_string(), "bbb".to_string()],
        };
        let formatted = format_cleanup_result(&result, true);
        assert!(formatted.starts_with("Would remove 2 unused blob(s)"));
        assert!(formatted.contains("Unused blobs:"));
        assert!(formatted.contains("  - aaa"));
        assert!(formatted.contains("  - bbb"));
    }
}
