use std::collections::HashSet;
use std::path::Path;

use crate::api::blob_fetcher::ArtifactNoun;
use crate::manifest::schema::{PatchManifest, PatchRecord};

/// Result of a blob cleanup operation.
#[derive(Debug, Default)]
pub struct CleanupResult {
    pub blobs_checked: usize,
    pub blobs_removed: usize,
    pub bytes_freed: u64,
    pub removed_blobs: Vec<String>,
    /// Orphans the wet sweep could not unlink, as `<file name>: <error>`.
    /// The pass keeps going past each failure, so the counts above are
    /// what was actually reclaimed; a non-empty list is the caller's cue
    /// to warn (`cleanup_failed`) without discarding them.
    pub failed: Vec<String>,
}

/// The blob hashes a cleanup pass must preserve.
/// These are references, not synthetic patch records: filenames and patch
/// metadata cannot change which original or patched bytes remain reachable.
pub struct ArtifactReferences {
    blobs: HashSet<String>,
}

impl ArtifactReferences {
    /// The one retention policy for a manifest's patches: the afterHash and
    /// beforeHash blobs of every patch in it. `repair` and `scan --prune`
    /// keep exactly this. The beforeHash blobs are the only local restore
    /// data: an offline rollback needs them, and `repair` downloads afterHash
    /// blobs only, so it can never restore an original it swept.
    pub fn active(manifest: &PatchManifest) -> Self {
        let mut references = Self {
            blobs: HashSet::new(),
        };
        for record in manifest.patches.values() {
            references.retain(record);
        }
        references
    }

    /// Remove and rollback keep [`Self::active`] for the remaining
    /// manifest, plus the originals of every removed-but-not-installed
    /// patch: a crawler miss must not destroy the only local restore data.
    /// Other removed patches become collectible.
    pub fn after_removal<'a>(
        previous: &PatchManifest,
        remaining: &PatchManifest,
        removed_not_installed: impl IntoIterator<Item = &'a str>,
    ) -> Self {
        let mut references = Self::active(remaining);
        for record in removed_not_installed
            .into_iter()
            .filter_map(|purl| previous.patches.get(purl))
        {
            for file in record.files.values() {
                if !file.before_hash.is_empty() {
                    references.blobs.insert(file.before_hash.clone());
                }
            }
        }
        references
    }

    fn retain(&mut self, record: &PatchRecord) {
        for file in record.files.values() {
            for hash in [&file.after_hash, &file.before_hash] {
                // Empty beforeHash is the created-by-patch sentinel.
                if !hash.is_empty() {
                    self.blobs.insert(hash.clone());
                }
            }
        }
    }

    /// Sweep each artifact directory independently so a failed pass does not
    /// stop another. Callers report partial counts and cleanup warnings.
    pub async fn sweep(&self, socket_dir: &Path, dry_run: bool) -> ArtifactSweep {
        ArtifactSweep {
            blobs: cleanup_dir(&socket_dir.join("blobs"), dry_run, |name| {
                self.blobs.contains(name)
            })
            .await,
            // Nothing writes or reads legacy diff or package archives any
            // more (v5 fetches patch content as per-file blobs only), so
            // every file in either directory is an orphan.
            diffs: cleanup_dir(&socket_dir.join("diffs"), dry_run, |_| false).await,
            packages: cleanup_dir(&socket_dir.join("packages"), dry_run, |_| false).await,
        }
    }
}

/// Results from the independent blob and legacy diff/package sweeps.
pub struct ArtifactSweep {
    pub blobs: std::io::Result<CleanupResult>,
    pub diffs: std::io::Result<CleanupResult>,
    pub packages: std::io::Result<CleanupResult>,
}

/// Shared core of every [`ArtifactReferences::sweep`] pass.
///
/// Walks `dir`, treats it as authoritative socket-patch state (so any
/// regular non-hidden file is considered for removal), and asks
/// `is_used(filename) -> bool` whether each file should be kept. A missing
/// `dir` yields an empty result; every other I/O error on the directory
/// itself propagates. A wet sweep that empties the directory removes it too
/// (non-recursively — kept files, hidden files or subdirectories keep it), so
/// a fully rolled-back project leaves no empty `blobs/`, `diffs/` or
/// `packages/` husk behind.
///
/// Per-file unlink failures do not abort the sweep: every other orphan is
/// still attempted, only files actually removed are counted, and each
/// failure is recorded in [`CleanupResult::failed`] so the partial counts
/// survive alongside it.
async fn cleanup_dir<F: Fn(&str) -> bool>(
    dir: &Path,
    dry_run: bool,
    is_used: F,
) -> Result<CleanupResult, std::io::Error> {
    let mut read_dir = match tokio::fs::read_dir(dir).await {
        Ok(read_dir) => read_dir,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(CleanupResult::default());
        }
        Err(e) => return Err(e),
    };
    let mut entries = Vec::new();
    while let Some(entry) = read_dir.next_entry().await? {
        entries.push(entry);
    }
    // Close the enumeration handle before the directory itself may be
    // removed below (Windows refuses to delete a directory with one open).
    drop(read_dir);

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
        if !dry_run {
            if let Err(e) = tokio::fs::remove_file(&path).await {
                result.failed.push(format!("{file_name_str}: {e}"));
                continue;
            }
        }
        result.blobs_removed += 1;
        result.bytes_freed += metadata.len();
        result.removed_blobs.push(file_name_str);
    }

    if !dry_run {
        // Best-effort: a directory still holding kept files, hidden files,
        // subdirectories or the orphans that failed to unlink stays.
        let _ = tokio::fs::remove_dir(dir).await;
    }
    Ok(result)
}

/// Formats a cleanup result counting `noun`s: "Removed 2 unused diff
/// archives (3 B freed)", and under a dry run the sorted list of what
/// would go ("Unused diff archives:" then `  - <name>` lines; the
/// directory walk's order is not stable).
pub fn format_cleanup_result_for(
    result: &CleanupResult,
    dry_run: bool,
    noun: ArtifactNoun,
) -> String {
    if result.blobs_checked == 0 {
        // Absent directory, or one holding no regular non-hidden files.
        return format!("No {} to clean up.", noun.many);
    }

    if result.blobs_removed == 0 {
        return format_all_in_use(&[noun.count(result.blobs_checked)], result.blobs_checked);
    }

    let action = if dry_run { "Would remove" } else { "Removed" };
    let bytes_formatted = format_bytes(result.bytes_freed);
    let unused = noun
        .count(result.blobs_removed)
        .replacen(' ', " unused ", 1);

    let mut output = format!("{action} {unused} ({bytes_formatted} freed)");

    if dry_run && !result.removed_blobs.is_empty() {
        let mut names: Vec<&String> = result.removed_blobs.iter().collect();
        names.sort();
        output.push_str(&format!("\nUnused {}:", noun.many));
        for name in names {
            output.push_str(&format!("\n  - {name}"));
        }
    }

    output
}

/// The "nothing unused" line, shared by every cleanup caller so the wording
/// matches across commands: `parts` are the counted kinds checked ("2
/// blobs", "1 diff archive"), joined as "a, b and c"; `total` is the item
/// count across all of them, which picks "in use" (one item) or "all in
/// use". "Checked 1 blob: in use." / "Checked 5 blobs: all in use."
pub fn format_all_in_use(parts: &[String], total: usize) -> String {
    let list = match parts {
        [] => String::new(),
        [one] => one.clone(),
        [init @ .., last] => format!("{} and {last}", init.join(", ")),
    };
    let state = if total == 1 { "in use" } else { "all in use" };
    format!("Checked {list}: {state}.")
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
    use crate::api::blob_fetcher::BLOB;
    use crate::manifest::schema::{PatchFileInfo, PatchManifest, PatchRecord};
    use std::collections::HashMap;

    const TEST_UUID: &str = "11111111-1111-4111-8111-111111111111";
    const BEFORE_HASH_1: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1111";
    const AFTER_HASH_1: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb1111";
    const BEFORE_HASH_2: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc2222";
    const AFTER_HASH_2: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd2222";
    const ORPHAN_HASH: &str = "oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo";

    /// The blob pass of [`ArtifactReferences::active`]'s sweep alone.
    async fn sweep_blobs(
        manifest: &PatchManifest,
        dir: &Path,
        dry_run: bool,
    ) -> std::io::Result<CleanupResult> {
        let references = ArtifactReferences::active(manifest);
        cleanup_dir(dir, dry_run, |name| references.blobs.contains(name)).await
    }

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
    async fn artifact_retention_covers_active_removed_and_uninstalled_patches() {
        for policy in [
            "active",
            "remaining",
            "not-installed",
            "created-only",
            "removed",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let mut manifest = create_test_manifest();
            let purl = "pkg:npm/pkg-a@1.0.0";
            let record = manifest.patches.get_mut(purl).unwrap();
            // This is a real filename. Synthetic beforeHash-pin records used
            // to overwrite its afterHash, making its patched bytes collectible.
            record.files.insert(
                "package/index.js#beforeHash-pin".into(),
                PatchFileInfo {
                    before_hash: String::new(),
                    after_hash: "created-file".into(),
                },
            );
            if policy == "created-only" {
                for file in record.files.values_mut() {
                    file.before_hash.clear();
                }
            }
            let empty = PatchManifest::default();
            let references = match policy {
                "active" => ArtifactReferences::active(&manifest),
                "remaining" => ArtifactReferences::after_removal(&manifest, &manifest, []),
                "removed" => ArtifactReferences::after_removal(&manifest, &empty, []),
                _ => ArtifactReferences::after_removal(&manifest, &empty, ["missing-purl", purl]),
            };
            let blobs = dir.path().join("blobs");
            let diffs = dir.path().join("diffs");
            let packages = dir.path().join("packages");
            for path in [&blobs, &diffs, &packages] {
                std::fs::create_dir(path).unwrap();
            }
            let hashes = [
                BEFORE_HASH_1,
                BEFORE_HASH_2,
                AFTER_HASH_1,
                AFTER_HASH_2,
                "created-file",
                ORPHAN_HASH,
            ];
            for hash in hashes {
                std::fs::write(blobs.join(hash), b"blob").unwrap();
            }
            let archive = format!("{TEST_UUID}.tar.gz");
            std::fs::write(diffs.join(&archive), b"diff").unwrap();
            std::fs::write(diffs.join("orphan.tar.gz"), b"orphan").unwrap();
            std::fs::write(packages.join(&archive), b"legacy").unwrap();
            let keep_original = matches!(policy, "active" | "remaining" | "not-installed");
            let keep_patched = matches!(policy, "active" | "remaining");
            let kept = 2 * usize::from(keep_original) + 3 * usize::from(keep_patched);

            let preview = references.sweep(dir.path(), true).await;
            assert_eq!(
                preview.blobs.unwrap().blobs_removed,
                hashes.len() - kept,
                "{policy}"
            );
            // Diff archives are obsolete: even a referenced UUID's goes.
            assert_eq!(preview.diffs.unwrap().blobs_removed, 2, "{policy}");
            assert_eq!(preview.packages.unwrap().blobs_removed, 1);
            assert_eq!(std::fs::read_dir(&blobs).unwrap().count(), hashes.len());
            assert_eq!(std::fs::read_dir(&diffs).unwrap().count(), 2);
            assert!(packages.join(&archive).exists());

            let swept = references.sweep(dir.path(), false).await;
            assert_eq!(
                swept.blobs.unwrap().blobs_removed,
                hashes.len() - kept,
                "{policy}"
            );
            assert_eq!(swept.diffs.unwrap().blobs_removed, 2, "{policy}");
            assert_eq!(swept.packages.unwrap().blobs_removed, 1);
            for hash in [BEFORE_HASH_1, BEFORE_HASH_2] {
                assert_eq!(blobs.join(hash).exists(), keep_original, "{policy}");
            }
            for hash in [AFTER_HASH_1, AFTER_HASH_2, "created-file"] {
                assert_eq!(blobs.join(hash).exists(), keep_patched, "{policy}");
            }
            assert!(!blobs.join(ORPHAN_HASH).exists());
            assert!(!diffs.exists(), "{policy}");
            assert!(!packages.exists());
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

        let result = sweep_blobs(&manifest, &blobs_dir, false).await.unwrap();

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

    /// #893: the beforeHash blobs of a patch still in the manifest are its
    /// only local restore data, so the sweep keeps them beside the
    /// afterHash blobs; only unreferenced files go.
    #[tokio::test]
    async fn test_cleanup_keeps_before_hash_blobs_of_active_patches() {
        let dir = tempfile::tempdir().unwrap();
        let blobs_dir = dir.path().join("blobs");
        tokio::fs::create_dir_all(&blobs_dir).await.unwrap();

        let manifest = create_test_manifest();
        for hash in [
            BEFORE_HASH_1,
            BEFORE_HASH_2,
            AFTER_HASH_1,
            AFTER_HASH_2,
            ORPHAN_HASH,
        ] {
            tokio::fs::write(blobs_dir.join(hash), hash).await.unwrap();
        }

        let result = sweep_blobs(&manifest, &blobs_dir, false).await.unwrap();

        assert_eq!(result.blobs_removed, 1);
        assert_eq!(result.removed_blobs, vec![ORPHAN_HASH.to_string()]);
        for hash in [BEFORE_HASH_1, BEFORE_HASH_2, AFTER_HASH_1, AFTER_HASH_2] {
            assert!(blobs_dir.join(hash).exists(), "{hash} must be kept");
        }
        assert!(!blobs_dir.join(ORPHAN_HASH).exists());
    }

    #[tokio::test]
    async fn test_cleanup_dry_run_does_not_delete() {
        let dir = tempfile::tempdir().unwrap();
        let blobs_dir = dir.path().join("blobs");
        tokio::fs::create_dir_all(&blobs_dir).await.unwrap();

        let manifest = create_test_manifest();

        tokio::fs::write(blobs_dir.join(ORPHAN_HASH), "orphan content")
            .await
            .unwrap();
        tokio::fs::write(blobs_dir.join(AFTER_HASH_1), "after content 1")
            .await
            .unwrap();

        let result = sweep_blobs(&manifest, &blobs_dir, true).await.unwrap();

        // Should report the orphan as would-be-removed
        assert_eq!(result.blobs_removed, 1);
        assert!(result.removed_blobs.contains(&ORPHAN_HASH.to_string()));

        // But both blobs should still exist
        assert!(tokio::fs::metadata(blobs_dir.join(ORPHAN_HASH))
            .await
            .is_ok());
        assert!(tokio::fs::metadata(blobs_dir.join(AFTER_HASH_1))
            .await
            .is_ok());

        // A dry run never touches the directory either, even when every
        // file in it would go.
        let result = sweep_blobs(&PatchManifest::new(), &blobs_dir, true)
            .await
            .unwrap();
        assert_eq!(result.blobs_removed, 2);
        assert!(blobs_dir.is_dir(), "dry run keeps the directory");
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

        let result = sweep_blobs(&manifest, &blobs_dir, false).await.unwrap();

        assert_eq!(result.blobs_removed, 2);
        // A wet sweep that orphaned everything leaves no empty `blobs/` husk
        // behind.
        assert!(
            !blobs_dir.exists(),
            "an emptied store directory is removed with its last orphan"
        );
        assert!(dir.path().exists(), "only the store dir itself goes");
    }

    /// A per-file unlink failure must not abort the sweep: the remaining
    /// orphans are still attempted, and every failure is recorded in
    /// `failed` beside the counts of what WAS reclaimed (the pass is `Ok`).
    /// Pinned on Unix by a read-only store dir — every unlink fails, so
    /// both orphans land in `failed` and nothing is counted as removed.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_cleanup_unlink_failures_are_recorded_after_the_pass() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let blobs_dir = dir.path().join("blobs");
        tokio::fs::create_dir_all(&blobs_dir).await.unwrap();
        tokio::fs::write(blobs_dir.join(ORPHAN_HASH), "orphan")
            .await
            .unwrap();
        tokio::fs::write(blobs_dir.join(BEFORE_HASH_1), "orphan too")
            .await
            .unwrap();
        std::fs::set_permissions(&blobs_dir, std::fs::Permissions::from_mode(0o555)).unwrap();
        if std::fs::File::create(blobs_dir.join("probe")).is_ok() {
            let _ = std::fs::set_permissions(&blobs_dir, std::fs::Permissions::from_mode(0o755));
            eprintln!("skipping: running as root, 0555 does not block unlinks");
            return;
        }

        let result = sweep_blobs(&PatchManifest::new(), &blobs_dir, false).await;
        std::fs::set_permissions(&blobs_dir, std::fs::Permissions::from_mode(0o755)).unwrap();

        let result = result.expect("unlink failures do not fail the pass");
        assert_eq!(result.blobs_checked, 2, "both orphans were considered");
        assert_eq!(
            result.blobs_removed, 0,
            "a failed unlink is not counted as removed"
        );
        assert_eq!(result.bytes_freed, 0);
        assert!(result.removed_blobs.is_empty());
        let mut failed = result.failed.clone();
        failed.sort();
        assert_eq!(
            failed.len(),
            2,
            "every failed unlink is recorded: {failed:?}"
        );
        let mut expected = [ORPHAN_HASH, BEFORE_HASH_1];
        expected.sort();
        for (entry, name) in failed.iter().zip(expected) {
            assert!(
                entry.starts_with(&format!("{name}: ")),
                "each failure names its file: {entry}"
            );
            assert!(
                entry.to_lowercase().contains("permission denied"),
                "each failure carries the OS error: {entry}"
            );
        }
        assert!(blobs_dir.join(ORPHAN_HASH).exists());
        assert!(blobs_dir.join(BEFORE_HASH_1).exists());
        assert!(blobs_dir.is_dir(), "a non-empty store dir is never removed");
    }

    #[tokio::test]
    async fn test_cleanup_nonexistent_blobs_dir() {
        let dir = tempfile::tempdir().unwrap();
        let non_existent = dir.path().join("non-existent");

        let manifest = create_test_manifest();

        let result = sweep_blobs(&manifest, &non_existent, false).await.unwrap();

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

    /// Zero checked covers BOTH an absent store dir and an existing one that
    /// holds no regular non-hidden files, so the wording must be true for
    /// either — it never claims the directory was not found.
    #[test]
    fn test_format_cleanup_result_nothing_checked() {
        let result = CleanupResult {
            blobs_checked: 0,
            blobs_removed: 0,
            bytes_freed: 0,
            removed_blobs: vec![],
            ..Default::default()
        };
        assert_eq!(
            format_cleanup_result_for(&result, false, BLOB),
            "No blobs to clean up."
        );
    }

    #[test]
    fn test_format_cleanup_result_all_in_use() {
        let result = CleanupResult {
            blobs_checked: 5,
            blobs_removed: 0,
            bytes_freed: 0,
            removed_blobs: vec![],
            ..Default::default()
        };
        assert_eq!(
            format_cleanup_result_for(&result, false, BLOB),
            "Checked 5 blobs: all in use."
        );
    }

    #[test]
    fn test_format_cleanup_result_removed() {
        let result = CleanupResult {
            blobs_checked: 5,
            blobs_removed: 2,
            bytes_freed: 2048,
            removed_blobs: vec!["aaa".to_string(), "bbb".to_string()],
            ..Default::default()
        };
        assert_eq!(
            format_cleanup_result_for(&result, false, BLOB),
            "Removed 2 unused blobs (2.00 KB freed)"
        );
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

        let result = sweep_blobs(&manifest, &blobs_dir, false).await.unwrap();

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
        // to consider), distinct from a populated one — and, being an empty
        // husk, a wet sweep removes it.
        let dir = tempfile::tempdir().unwrap();
        let blobs_dir = dir.path().join("blobs");
        tokio::fs::create_dir_all(&blobs_dir).await.unwrap();

        let result = sweep_blobs(&create_test_manifest(), &blobs_dir, false)
            .await
            .unwrap();

        assert_eq!(result.blobs_checked, 0);
        assert_eq!(result.blobs_removed, 0);
        assert!(!blobs_dir.exists(), "an empty store dir is pruned");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_cleanup_dangling_symlink_does_not_abort() {
        // Regression: a single dangling symlink must not abort cleanup of every
        // other orphan (following the link would hit NotFound and propagate it
        // out of the whole operation).
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

        let result = sweep_blobs(&manifest, &blobs_dir, false).await.unwrap();

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

        let result = sweep_blobs(&manifest, &blobs_dir, false).await.unwrap();

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

        let result = sweep_blobs(&manifest, &blobs_dir, false).await.unwrap();

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
            ..Default::default()
        };
        let formatted = format_cleanup_result_for(&result, true, BLOB);
        assert_eq!(
            formatted,
            "Would remove 2 unused blobs (2.00 KB freed)\nUnused blobs:\n  - aaa\n  - bbb"
        );
    }

    #[test]
    fn format_cleanup_result_for_archives_uses_the_noun_everywhere() {
        use crate::api::blob_fetcher::{DIFF_ARCHIVE, PACKAGE_ARCHIVE};
        let result = CleanupResult {
            blobs_checked: 2,
            blobs_removed: 1,
            bytes_freed: 2,
            removed_blobs: vec!["3333.tar.gz".to_string()],
            ..Default::default()
        };
        assert_eq!(
            format_cleanup_result_for(&result, true, DIFF_ARCHIVE),
            "Would remove 1 unused diff archive (2 B freed)\nUnused diff archives:\n  - 3333.tar.gz"
        );
        assert_eq!(
            format_cleanup_result_for(&result, false, PACKAGE_ARCHIVE),
            "Removed 1 unused package archive (2 B freed)"
        );
        let none = CleanupResult::default();
        assert_eq!(
            format_cleanup_result_for(&none, false, DIFF_ARCHIVE),
            "No diff archives to clean up."
        );
    }

    #[test]
    fn format_cleanup_result_singular_and_sorted() {
        let one_in_use = CleanupResult {
            blobs_checked: 1,
            ..Default::default()
        };
        assert_eq!(
            format_cleanup_result_for(&one_in_use, false, BLOB),
            "Checked 1 blob: in use."
        );
        // Unsorted input (directory-walk order) prints sorted.
        let result = CleanupResult {
            blobs_checked: 3,
            blobs_removed: 3,
            bytes_freed: 3,
            removed_blobs: vec!["c".into(), "a".into(), "b".into()],
            ..Default::default()
        };
        assert_eq!(
            format_cleanup_result_for(&result, true, BLOB),
            "Would remove 3 unused blobs (3 B freed)\nUnused blobs:\n  - a\n  - b\n  - c"
        );
    }

    #[test]
    fn all_in_use_wording_counts_items_not_kinds() {
        assert_eq!(
            format_all_in_use(&["1 blob".into()], 1),
            "Checked 1 blob: in use."
        );
        assert_eq!(
            format_all_in_use(&["2 blobs".into()], 2),
            "Checked 2 blobs: all in use."
        );
        assert_eq!(
            format_all_in_use(&["1 blob".into(), "1 diff archive".into()], 2),
            "Checked 1 blob and 1 diff archive: all in use."
        );
        assert_eq!(
            format_all_in_use(
                &[
                    "2 blobs".into(),
                    "1 diff archive".into(),
                    "3 package archives".into()
                ],
                6
            ),
            "Checked 2 blobs, 1 diff archive and 3 package archives: all in use."
        );
    }
}
