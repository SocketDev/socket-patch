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

    let mut result = CleanupResult::default();

    for entry in &entries {
        let file_name_str = entry.file_name().to_string_lossy().to_string();
        if file_name_str.starts_with('.') {
            continue;
        }
        // Use the entry's real path: joining the lossy display name back onto
        // `dir` breaks for names that are not valid UTF-8 (the mangled path
        // does not exist on disk), silently exempting such files from cleanup.
        let path = entry.path();
        // Use symlink_metadata (lstat) rather than metadata (stat) so we never
        // follow symlinks: a symlink is not a real socket-patch blob, and a
        // dangling symlink would otherwise return an error. Tolerate any stat
        // error (e.g. the entry was removed concurrently) by skipping that
        // entry instead of aborting cleanup of every other orphan.
        let metadata = match tokio::fs::symlink_metadata(&path).await {
            Ok(m) => m,
            Err(_) => continue,
        };
        if !metadata.is_file() {
            continue;
        }
        // Only regular, non-hidden files are actually considered/checked.
        result.blobs_checked += 1;
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
    let used_uuids: HashSet<String> = manifest.patches.values().map(|r| r.uuid.clone()).collect();
    cleanup_dir(archives_dir, dry_run, |name| {
        // Strip the .tar.gz suffix to recover the UUID. A file that does
        // not end in .tar.gz is never a valid archive, so it is always an
        // orphan -- even if its bare name happens to equal a manifest UUID
        // (e.g. a stray `<uuid>` file with no extension). Returning false
        // here keeps that contract: only well-formed `<uuid>.tar.gz` files
        // whose UUID is referenced are kept.
        match name.strip_suffix(".tar.gz") {
            Some(uuid_part) => used_uuids.contains(uuid_part),
            None => false,
        }
    })
    .await
}

/// Formats the cleanup result for human-readable output.
pub fn format_cleanup_result(result: &CleanupResult, dry_run: bool) -> String {
    if result.blobs_checked == 0 {
        return "No blobs directory found, nothing to clean up.".to_string();
    }

    if result.blobs_removed == 0 {
        return format!("Checked {} blob(s), all are in use.", result.blobs_checked);
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
    const BEFORE_HASH_1: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1111";
    const AFTER_HASH_1: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb1111";
    const BEFORE_HASH_2: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc2222";
    const AFTER_HASH_2: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd2222";
    const ORPHAN_HASH: &str = "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo";

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

        PatchManifest {
            patches,
            setup: None,
        }
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
        assert!(
            tokio::fs::metadata(archives.join(format!("{TEST_UUID}.tar.gz")))
                .await
                .is_ok()
        );
        assert!(
            tokio::fs::metadata(archives.join(format!("{SECOND_UUID}.tar.gz")))
                .await
                .is_err()
        );
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
        assert!(
            tokio::fs::metadata(archives.join(format!("{SECOND_UUID}.tar.gz")))
                .await
                .is_ok()
        );
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
    async fn test_cleanup_archives_removes_bare_uuid_without_extension() {
        // Regression: a stray file whose *bare* name equals a referenced
        // manifest UUID but lacks the `.tar.gz` extension is NOT a valid
        // archive and must be removed as an orphan. The previous
        // `strip_suffix(..).unwrap_or(name)` form fell back to matching the
        // whole filename against the UUID set and incorrectly KEPT it.
        let dir = tempfile::tempdir().unwrap();
        let archives = dir.path().join("packages");
        tokio::fs::create_dir_all(&archives).await.unwrap();

        let manifest = create_test_manifest();
        // Bare UUID, no extension -- must be treated as an orphan.
        tokio::fs::write(archives.join(TEST_UUID), b"not an archive")
            .await
            .unwrap();
        // The legitimate archive for the same UUID must survive.
        tokio::fs::write(archives.join(format!("{TEST_UUID}.tar.gz")), b"keep")
            .await
            .unwrap();

        let result = cleanup_unused_archives(&manifest, &archives, false)
            .await
            .unwrap();

        assert_eq!(result.blobs_removed, 1);
        assert!(result.removed_blobs.contains(&TEST_UUID.to_string()));
        assert!(tokio::fs::metadata(archives.join(TEST_UUID)).await.is_err());
        assert!(
            tokio::fs::metadata(archives.join(format!("{TEST_UUID}.tar.gz")))
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn test_cleanup_archives_removes_wrong_suffix_with_uuid_stem() {
        // A file named `<uuid>.tar.gz.bak` (or any non-`.tar.gz` suffix) does
        // not end in `.tar.gz`, so it is an orphan regardless of its stem.
        let dir = tempfile::tempdir().unwrap();
        let archives = dir.path().join("packages");
        tokio::fs::create_dir_all(&archives).await.unwrap();

        let manifest = create_test_manifest();
        tokio::fs::write(archives.join(format!("{TEST_UUID}.tar.gz.bak")), b"junk")
            .await
            .unwrap();

        let result = cleanup_unused_archives(&manifest, &archives, false)
            .await
            .unwrap();

        assert_eq!(result.blobs_removed, 1);
        assert!(result
            .removed_blobs
            .contains(&format!("{TEST_UUID}.tar.gz.bak")));
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

    #[tokio::test]
    async fn test_cleanup_does_not_count_subdirs_or_hidden_files() {
        // Regression: blobs_checked must only count regular, non-hidden files
        // that are actually considered -- not subdirectories or dotfiles. This
        // count is surfaced to users (human-readable + JSON in `repair`), so an
        // inflated number is a real reporting bug.
        let dir = tempfile::tempdir().unwrap();
        let blobs_dir = dir.path().join("blobs");
        tokio::fs::create_dir_all(&blobs_dir).await.unwrap();

        let manifest = create_test_manifest();

        // One real (used) blob, plus noise that must be ignored entirely.
        tokio::fs::write(blobs_dir.join(AFTER_HASH_1), "after content 1")
            .await
            .unwrap();
        tokio::fs::create_dir_all(blobs_dir.join("subdir"))
            .await
            .unwrap();
        tokio::fs::write(blobs_dir.join(".hidden"), "hidden")
            .await
            .unwrap();

        let result = cleanup_unused_blobs(&manifest, &blobs_dir, false)
            .await
            .unwrap();

        // Only the single regular, non-hidden file is checked; nothing removed.
        assert_eq!(result.blobs_checked, 1);
        assert_eq!(result.blobs_removed, 0);

        // The subdirectory and hidden file are left untouched.
        assert!(tokio::fs::metadata(blobs_dir.join("subdir")).await.is_ok());
        assert!(tokio::fs::metadata(blobs_dir.join(".hidden")).await.is_ok());
    }

    #[tokio::test]
    async fn test_cleanup_empty_existing_dir_checks_nothing() {
        // An existing-but-empty directory must report zero checked (no entries
        // to consider), distinct from a populated one.
        let dir = tempfile::tempdir().unwrap();
        let blobs_dir = dir.path().join("blobs");
        tokio::fs::create_dir_all(&blobs_dir).await.unwrap();

        let result = cleanup_unused_blobs(&create_test_manifest(), &blobs_dir, false)
            .await
            .unwrap();

        assert_eq!(result.blobs_checked, 0);
        assert_eq!(result.blobs_removed, 0);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_cleanup_dangling_symlink_does_not_abort() {
        // Regression: a single dangling symlink must not abort cleanup of every
        // other orphan. Previously `tokio::fs::metadata(..)?` followed the link,
        // hit a NotFound error, and propagated it out of the whole operation.
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let blobs_dir = dir.path().join("blobs");
        tokio::fs::create_dir_all(&blobs_dir).await.unwrap();

        let manifest = create_test_manifest();

        // A real orphan that should still be removed despite the bad symlink.
        tokio::fs::write(blobs_dir.join(ORPHAN_HASH), "orphan content")
            .await
            .unwrap();
        // A dangling symlink (target does not exist).
        symlink(
            blobs_dir.join("missing-target"),
            blobs_dir.join("dangling-link"),
        )
        .unwrap();

        let result = cleanup_unused_blobs(&manifest, &blobs_dir, false)
            .await
            .unwrap();

        // The orphan is removed; the symlink is counted as neither checked nor
        // removed (it is not a regular file) and is left in place.
        assert_eq!(result.blobs_removed, 1);
        assert!(result.removed_blobs.contains(&ORPHAN_HASH.to_string()));
        assert!(tokio::fs::metadata(blobs_dir.join(ORPHAN_HASH))
            .await
            .is_err());
        assert!(tokio::fs::symlink_metadata(blobs_dir.join("dangling-link"))
            .await
            .is_ok());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_cleanup_does_not_follow_symlink_to_used_target() {
        // A symlink is never treated as a blob, so its target's size is never
        // attributed to bytes_freed and the link is never removed.
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let blobs_dir = dir.path().join("blobs");
        tokio::fs::create_dir_all(&blobs_dir).await.unwrap();

        let manifest = create_test_manifest();

        // A real file outside the managed set, plus a symlink pointing at it.
        let outside = dir.path().join("outside.bin");
        tokio::fs::write(&outside, vec![0u8; 4096]).await.unwrap();
        symlink(&outside, blobs_dir.join("link-to-outside")).unwrap();

        let result = cleanup_unused_blobs(&manifest, &blobs_dir, false)
            .await
            .unwrap();

        assert_eq!(result.blobs_checked, 0);
        assert_eq!(result.blobs_removed, 0);
        assert_eq!(result.bytes_freed, 0);
        // The symlink and its target both survive.
        assert!(
            tokio::fs::symlink_metadata(blobs_dir.join("link-to-outside"))
                .await
                .is_ok()
        );
        assert!(tokio::fs::metadata(&outside).await.is_ok());
    }

    // Linux-only: APFS/HFS+ (macOS) and NTFS reject file names that are not
    // valid Unicode, so the scenario can only arise on byte-string
    // filesystems like ext4.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_cleanup_removes_non_utf8_named_orphan() {
        // Regression: a stray file whose name is not valid UTF-8 must still
        // be considered and removed as an orphan. Joining the *lossy*
        // display name back onto the directory produced a path that does not
        // exist on disk, so the stat failed and the file was silently
        // skipped -- leaked forever despite the "any regular non-hidden file
        // is considered for removal" contract.
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let dir = tempfile::tempdir().unwrap();
        let blobs_dir = dir.path().join("blobs");
        tokio::fs::create_dir_all(&blobs_dir).await.unwrap();

        let manifest = create_test_manifest();

        // 0xFF can never appear in valid UTF-8, so to_string_lossy() mangles
        // this name into something that does not exist on disk.
        let bad_path = blobs_dir.join(OsStr::from_bytes(b"orphan-\xff\xfe"));
        tokio::fs::write(&bad_path, "junk").await.unwrap();

        let result = cleanup_unused_blobs(&manifest, &blobs_dir, false)
            .await
            .unwrap();

        assert_eq!(result.blobs_checked, 1);
        assert_eq!(result.blobs_removed, 1);
        assert!(tokio::fs::symlink_metadata(&bad_path).await.is_err());
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
