use std::collections::HashMap;
use std::path::Path;

use crate::manifest::schema::PatchFileInfo;
use crate::patch::file_hash::compute_file_git_sha256;

/// Status of a file rollback verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyRollbackStatus {
    /// File is ready to be rolled back (current hash matches afterHash).
    Ready,
    /// File is already in the original state (current hash matches beforeHash).
    AlreadyOriginal,
    /// File hash does not match the expected afterHash.
    HashMismatch,
    /// File was not found on disk.
    NotFound,
    /// The before-hash blob needed for rollback is missing from the blobs directory.
    MissingBlob,
}

/// Result of verifying whether a single file can be rolled back.
#[derive(Debug, Clone)]
pub struct VerifyRollbackResult {
    pub file: String,
    pub status: VerifyRollbackStatus,
    pub message: Option<String>,
    pub current_hash: Option<String>,
    pub expected_hash: Option<String>,
    pub target_hash: Option<String>,
}

/// Result of rolling back patches for a single package.
#[derive(Debug, Clone)]
pub struct RollbackResult {
    pub package_key: String,
    pub package_path: String,
    pub success: bool,
    pub files_verified: Vec<VerifyRollbackResult>,
    pub files_rolled_back: Vec<String>,
    pub error: Option<String>,
    /// Ecosystem sidecar resync outcome — the rollback-side twin of
    /// [`ApplyResult::sidecar`](crate::patch::apply::ApplyResult::sidecar).
    /// `Some` when the ecosystem's integrity sidecar was resynced after
    /// the restore (today: cargo's `.cargo-checksum.json`) or when that
    /// resync failed (an `Error`-severity advisory; the files themselves
    /// are still rolled back). `None` when no sidecar applied or no
    /// files were rolled back (dry run, already original).
    pub sidecar: Option<crate::patch::sidecars::SidecarRecord>,
}

/// Normalize file path by removing the "package/" prefix if present.
fn normalize_file_path(file_name: &str) -> &str {
    const PACKAGE_PREFIX: &str = "package/";
    if let Some(stripped) = file_name.strip_prefix(PACKAGE_PREFIX) {
        stripped
    } else {
        file_name
    }
}

/// Verify a single file can be rolled back.
///
/// A file is ready for rollback if:
/// 1. The file exists on disk.
/// 2. Its current hash matches the afterHash (patched state).
/// 3. The before-hash blob exists in the blobs directory.
///
/// A file whose current hash already matches the beforeHash is reported
/// `AlreadyOriginal` *before* the blob is checked — a finished rollback is
/// a no-op and must not be blocked by a missing (e.g. GC'd) blob it would
/// never need to read.
pub async fn verify_file_rollback(
    pkg_path: &Path,
    file_name: &str,
    file_info: &PatchFileInfo,
    blobs_path: &Path,
) -> VerifyRollbackResult {
    let normalized = normalize_file_path(file_name);
    // SECURITY: never resolve a key that escapes the package directory.
    // A poisoned `.socket/manifest.json` key like `../../home/u/.bashrc`
    // or `/etc/cron.d/x` must not be hashed, restored, or (for new files)
    // deleted. Mirror the apply path's guard — returning a blocking status
    // aborts the whole package rollback before the delete loop runs.
    if !crate::patch::apply::is_safe_relative_subpath(normalized) {
        return VerifyRollbackResult {
            file: file_name.to_string(),
            status: VerifyRollbackStatus::NotFound,
            message: Some("Unsafe patch path (escapes package directory)".to_string()),
            current_hash: None,
            expected_hash: None,
            target_hash: None,
        };
    }
    let filepath = pkg_path.join(normalized);

    let is_new_file = file_info.before_hash.is_empty();

    // For new files (empty beforeHash), rollback means deleting the file.
    if is_new_file {
        // Probe the directory ENTRY (`symlink_metadata`), not the symlink
        // target: a dangling symlink left where the patch-added file was
        // makes `metadata` report ENOENT, which mis-classified the entry
        // as already rolled back — the package rollback claimed success
        // while silently leaving the stray entry behind. Only a true
        // NotFound means already-gone; any other stat error (ELOOP,
        // EACCES) is an unverifiable state and must fail closed.
        match tokio::fs::symlink_metadata(&filepath).await {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // File already doesn't exist — already rolled back.
                return VerifyRollbackResult {
                    file: file_name.to_string(),
                    status: VerifyRollbackStatus::AlreadyOriginal,
                    message: None,
                    current_hash: None,
                    expected_hash: None,
                    target_hash: None,
                };
            }
            Err(e) => {
                return VerifyRollbackResult {
                    file: file_name.to_string(),
                    status: VerifyRollbackStatus::NotFound,
                    message: Some(format!("Failed to stat file: {}", e)),
                    current_hash: None,
                    expected_hash: None,
                    target_hash: None,
                };
            }
            Ok(_) => {}
        }
        let current_hash = compute_file_git_sha256(&filepath).await.unwrap_or_default();
        if current_hash == file_info.after_hash {
            return VerifyRollbackResult {
                file: file_name.to_string(),
                status: VerifyRollbackStatus::Ready,
                message: None,
                current_hash: Some(current_hash),
                expected_hash: None,
                target_hash: None,
            };
        }
        return VerifyRollbackResult {
            file: file_name.to_string(),
            status: VerifyRollbackStatus::HashMismatch,
            message: Some(
                "File has been modified after patching. Cannot safely rollback.".to_string(),
            ),
            current_hash: Some(current_hash),
            expected_hash: Some(file_info.after_hash.clone()),
            target_hash: None,
        };
    }

    // Check if file exists
    if tokio::fs::metadata(&filepath).await.is_err() {
        return VerifyRollbackResult {
            file: file_name.to_string(),
            status: VerifyRollbackStatus::NotFound,
            message: Some("File not found".to_string()),
            current_hash: None,
            expected_hash: None,
            target_hash: None,
        };
    }

    // Compute current hash
    let current_hash = match compute_file_git_sha256(&filepath).await {
        Ok(h) => h,
        Err(e) => {
            return VerifyRollbackResult {
                file: file_name.to_string(),
                status: VerifyRollbackStatus::NotFound,
                message: Some(format!("Failed to hash file: {}", e)),
                current_hash: None,
                expected_hash: None,
                target_hash: None,
            };
        }
    };

    // Check if already in original state. This must be tested BEFORE the
    // before-blob existence check: a file that is already rolled back
    // needs no blob to restore, so a garbage-collected blob must not turn
    // a finished, no-op rollback into a spurious `MissingBlob` failure
    // (which would otherwise block the whole package's rollback).
    if current_hash == file_info.before_hash {
        return VerifyRollbackResult {
            file: file_name.to_string(),
            status: VerifyRollbackStatus::AlreadyOriginal,
            message: None,
            current_hash: Some(current_hash),
            expected_hash: None,
            target_hash: None,
        };
    }

    // SECURITY: `beforeHash` comes from the same untrusted manifest as the
    // file keys, but is used as a path component under the blobs directory.
    // `Path::join` discards the base on an absolute "hash" and `..` walks
    // out, so an unvalidated value would turn the blob probe — and the
    // rollback loop's blob read — into an out-of-tree existence oracle, a
    // content-hash leak via the mismatch error, or an unbounded-read DoS
    // (`/dev/zero`, FIFO hang). Real blob hashes are plain hex and always
    // pass; anything path-unsafe is refused fail-closed.
    if !crate::patch::apply::is_safe_relative_subpath(&file_info.before_hash) {
        return VerifyRollbackResult {
            file: file_name.to_string(),
            status: VerifyRollbackStatus::MissingBlob,
            message: Some(format!(
                "Unsafe before-blob hash (escapes blobs directory): {}",
                file_info.before_hash
            )),
            current_hash: Some(current_hash),
            expected_hash: None,
            target_hash: None,
        };
    }

    // Check if before blob exists (required to actually restore the file)
    let before_blob_path = blobs_path.join(&file_info.before_hash);
    if tokio::fs::metadata(&before_blob_path).await.is_err() {
        return VerifyRollbackResult {
            file: file_name.to_string(),
            status: VerifyRollbackStatus::MissingBlob,
            message: Some(format!(
                "Before blob not found: {}. Re-download the patch to enable rollback.",
                file_info.before_hash
            )),
            current_hash: Some(current_hash),
            expected_hash: None,
            target_hash: Some(file_info.before_hash.clone()),
        };
    }

    // Check if matches expected patched hash (afterHash)
    if current_hash != file_info.after_hash {
        return VerifyRollbackResult {
            file: file_name.to_string(),
            status: VerifyRollbackStatus::HashMismatch,
            message: Some(
                "File has been modified after patching. Cannot safely rollback.".to_string(),
            ),
            current_hash: Some(current_hash),
            expected_hash: Some(file_info.after_hash.clone()),
            target_hash: Some(file_info.before_hash.clone()),
        };
    }

    VerifyRollbackResult {
        file: file_name.to_string(),
        status: VerifyRollbackStatus::Ready,
        message: None,
        current_hash: Some(current_hash),
        expected_hash: None,
        target_hash: Some(file_info.before_hash.clone()),
    }
}

/// Rollback a single file to its original state by writing
/// `original_content` (whose Git SHA256 must equal `expected_hash`).
///
/// This delegates to [`apply_file_patch`](crate::patch::apply::apply_file_patch),
/// the hardened write path shared with apply. Rolling a file back is the
/// exact same operation as patching it forward — "safely overwrite this
/// file with these hash-verified bytes" — so it must get the exact same
/// guarantees:
///
/// * **Atomic** — the bytes are staged in the parent directory, fsync'd,
///   and `rename(2)`d over the target. A crash or `ENOSPC` mid-write
///   leaves either the old or the new content, never a truncated file.
/// * **Copy-on-write safe** — a symlink/hardlink into a shared content
///   store (pnpm, Nix, the Go module cache) is broken into a private
///   inode first, so a rollback never bleeds into a sibling project's
///   copy or the store entry.
/// * **Validate-before-write** — `original_content` is hash-checked in
///   memory *before* any disk write, so a corrupt blob is refused
///   instead of being committed over the file and only then flagged.
/// * **Permission-faithful** — the file's mode + uid/gid are restored
///   afterward. Because apply preserves a file's original permissions
///   when patching, the on-disk patched file already carries the
///   pre-patch mode (e.g. a read-only `0o444` Go-cache source), and
///   that exact mode is re-applied to the rolled-back inode.
///
/// The previous implementation used a bare in-place `tokio::fs::write`,
/// which had none of these properties: it could corrupt a hardlinked
/// sibling, leave a half-written file on a crash, write a bad blob over
/// the file *before* discovering the hash mismatch, and leave a
/// read-only file writable.
pub async fn rollback_file_patch(
    pkg_path: &Path,
    file_name: &str,
    original_content: &[u8],
    expected_hash: &str,
) -> Result<(), std::io::Error> {
    crate::patch::apply::apply_file_patch(pkg_path, file_name, original_content, expected_hash)
        .await
}

/// Verify and rollback patches for a single package.
///
/// For each file in `files`, this function:
/// 1. Verifies the file is ready to be rolled back (or already original).
/// 2. If not dry_run, reads the before-hash blob and writes it back.
/// 3. Returns a summary of what happened.
pub async fn rollback_package_patch(
    package_key: &str,
    pkg_path: &Path,
    files: &HashMap<String, PatchFileInfo>,
    blobs_path: &Path,
    dry_run: bool,
) -> RollbackResult {
    let mut result = RollbackResult {
        package_key: package_key.to_string(),
        package_path: pkg_path.display().to_string(),
        success: false,
        files_verified: Vec::new(),
        files_rolled_back: Vec::new(),
        error: None,
        sidecar: None,
    };

    // First, verify all files
    for (file_name, file_info) in files {
        let verify_result = verify_file_rollback(pkg_path, file_name, file_info, blobs_path).await;

        // If any file has issues (not ready and not already original), we can't proceed
        if verify_result.status != VerifyRollbackStatus::Ready
            && verify_result.status != VerifyRollbackStatus::AlreadyOriginal
        {
            let msg = verify_result
                .message
                .clone()
                .unwrap_or_else(|| format!("{:?}", verify_result.status));
            result.error = Some(format!("Cannot rollback: {} - {}", verify_result.file, msg));
            result.files_verified.push(verify_result);
            return result;
        }

        result.files_verified.push(verify_result);
    }

    // Check if all files are already in original state
    let all_original = result
        .files_verified
        .iter()
        .all(|v| v.status == VerifyRollbackStatus::AlreadyOriginal);
    if all_original {
        result.success = true;
        return result;
    }

    // If dry run, stop here
    if dry_run {
        result.success = true;
        return result;
    }

    // Rollback files that need it
    for (file_name, file_info) in files {
        let verify_result = result.files_verified.iter().find(|v| v.file == *file_name);
        if let Some(vr) = verify_result {
            if vr.status == VerifyRollbackStatus::AlreadyOriginal {
                continue;
            }
        }

        // New files (empty beforeHash): delete instead of restoring.
        if file_info.before_hash.is_empty() {
            let normalized = normalize_file_path(file_name);
            // SECURITY: this delete path constructs the target itself and
            // does NOT go through `apply_file_patch`, so it must enforce the
            // same path-escape guard. Without it a poisoned manifest entry
            // (empty beforeHash + a `../../`/absolute key) would unlink an
            // arbitrary file outside the package directory. Verify already
            // blocks such keys, but defense-in-depth: never trust an
            // unvalidated key at the syscall.
            if !crate::patch::apply::is_safe_relative_subpath(normalized) {
                result.error = Some(format!(
                    "Unsafe patch path (escapes package directory): {}",
                    file_name
                ));
                return result;
            }
            let filepath = pkg_path.join(normalized);
            // Unlinking a directory entry requires write permission on the
            // *parent directory*, not the file. Go's module cache marks
            // package directories read-only (0o555), so — exactly as the
            // apply write path does — temporarily grant owner-write on the
            // parent and restore its exact mode afterward, whether the
            // delete succeeds or fails.
            let dir_guard = crate::patch::apply::DirWriteGuard::acquire(filepath.parent()).await;
            let remove_result = tokio::fs::remove_file(&filepath).await;
            dir_guard.restore().await;
            if let Err(e) = remove_result {
                result.error = Some(format!("Failed to delete {}: {}", file_name, e));
                return result;
            }
            result.files_rolled_back.push(file_name.clone());
            continue;
        }

        // SECURITY: defense-in-depth twin of the verify-time guard — never
        // join an unvalidated manifest hash onto the blobs directory at the
        // read syscall either (mirrors the delete branch above). Verify
        // already blocks unsafe hashes, but this read must not depend on it.
        if !crate::patch::apply::is_safe_relative_subpath(&file_info.before_hash) {
            result.error = Some(format!(
                "Unsafe before-blob hash (escapes blobs directory): {}",
                file_info.before_hash
            ));
            return result;
        }

        // Read original content from blobs
        let blob_path = blobs_path.join(&file_info.before_hash);
        let original_content = match tokio::fs::read(&blob_path).await {
            Ok(content) => content,
            Err(e) => {
                result.error = Some(format!(
                    "Failed to read blob {}: {}",
                    file_info.before_hash, e
                ));
                return result;
            }
        };

        // Rollback the file
        if let Err(e) = rollback_file_patch(
            pkg_path,
            file_name,
            &original_content,
            &file_info.before_hash,
        )
        .await
        {
            result.error = Some(e.to_string());
            return result;
        }

        result.files_rolled_back.push(file_name.clone());
    }

    // Ecosystem sidecar resync — the rollback-side twin of apply's
    // `dispatch_fixup` boundary. Apply rewrote integrity sidecars to the
    // patched hashes; with the original bytes now restored those hashes
    // are stale in the other direction (cargo refuses to build a vendored
    // crate whose `.cargo-checksum.json` disagrees with its sources).
    // Best-effort, exactly like apply: a failing resync does NOT undo the
    // rollback — the restored bytes are already committed — it surfaces
    // as an `Error`-severity `sidecar_fixup_failed` advisory instead.
    if !result.files_rolled_back.is_empty() {
        use crate::patch::sidecars::{
            dispatch_rollback_fixup, SidecarAdvisory, SidecarAdvisoryCode, SidecarRecord,
            SidecarSeverity,
        };
        // Include files verified `AlreadyOriginal` alongside the ones
        // restored this run: a previous rollback that failed partway
        // restored them but returned before this boundary, so their
        // sidecar entries still carry the PATCHED hashes apply's fixup
        // wrote — and this retry is the only chance to resync them.
        // They exist at their before-hash (or, for patch-added files,
        // are already deleted, which the resync handles by dropping the
        // entry), so the rehash is a no-op rewrite in the common
        // already-synced case.
        let resync_files: Vec<String> = result
            .files_rolled_back
            .iter()
            .cloned()
            .chain(
                result
                    .files_verified
                    .iter()
                    .filter(|v| v.status == VerifyRollbackStatus::AlreadyOriginal)
                    .map(|v| v.file.clone()),
            )
            .collect();
        match dispatch_rollback_fixup(package_key, pkg_path, &resync_files).await {
            Ok(Some(record)) => result.sidecar = Some(record),
            Ok(None) => {}
            Err(e) => {
                let ecosystem = crate::crawlers::Ecosystem::from_purl(package_key)
                    .map(|eco| eco.cli_name().to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                result.sidecar = Some(SidecarRecord {
                    purl: package_key.to_string(),
                    ecosystem,
                    files: Vec::new(),
                    advisory: Some(SidecarAdvisory {
                        code: SidecarAdvisoryCode::SidecarFixupFailed,
                        severity: SidecarSeverity::Error,
                        message: format!("sidecar resync failed (files still rolled back): {}", e),
                    }),
                });
            }
        }
    }

    result.success = true;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::git_sha256::compute_git_sha256_from_bytes;

    #[tokio::test]
    async fn test_verify_file_rollback_not_found() {
        let pkg_dir = tempfile::tempdir().unwrap();
        let blobs_dir = tempfile::tempdir().unwrap();

        let file_info = PatchFileInfo {
            before_hash: "aaa".to_string(),
            after_hash: "bbb".to_string(),
        };

        let result = verify_file_rollback(
            pkg_dir.path(),
            "nonexistent.js",
            &file_info,
            blobs_dir.path(),
        )
        .await;
        assert_eq!(result.status, VerifyRollbackStatus::NotFound);
    }

    #[tokio::test]
    async fn test_verify_file_rollback_missing_blob() {
        let pkg_dir = tempfile::tempdir().unwrap();
        let blobs_dir = tempfile::tempdir().unwrap();

        let content = b"patched content";
        tokio::fs::write(pkg_dir.path().join("index.js"), content)
            .await
            .unwrap();

        let file_info = PatchFileInfo {
            before_hash: "missing_blob_hash".to_string(),
            after_hash: compute_git_sha256_from_bytes(content),
        };

        let result =
            verify_file_rollback(pkg_dir.path(), "index.js", &file_info, blobs_dir.path()).await;
        assert_eq!(result.status, VerifyRollbackStatus::MissingBlob);
        assert!(result.message.unwrap().contains("Before blob not found"));
    }

    #[tokio::test]
    async fn test_verify_file_rollback_ready() {
        let pkg_dir = tempfile::tempdir().unwrap();
        let blobs_dir = tempfile::tempdir().unwrap();

        let original = b"original content";
        let patched = b"patched content";
        let before_hash = compute_git_sha256_from_bytes(original);
        let after_hash = compute_git_sha256_from_bytes(patched);

        // File is in patched state
        tokio::fs::write(pkg_dir.path().join("index.js"), patched)
            .await
            .unwrap();

        // Before blob exists
        tokio::fs::write(blobs_dir.path().join(&before_hash), original)
            .await
            .unwrap();

        let file_info = PatchFileInfo {
            before_hash: before_hash.clone(),
            after_hash: after_hash.clone(),
        };

        let result =
            verify_file_rollback(pkg_dir.path(), "index.js", &file_info, blobs_dir.path()).await;
        assert_eq!(result.status, VerifyRollbackStatus::Ready);
        assert_eq!(result.current_hash.unwrap(), after_hash);
    }

    #[tokio::test]
    async fn test_verify_file_rollback_already_original() {
        let pkg_dir = tempfile::tempdir().unwrap();
        let blobs_dir = tempfile::tempdir().unwrap();

        let original = b"original content";
        let before_hash = compute_git_sha256_from_bytes(original);

        // File is already in original state
        tokio::fs::write(pkg_dir.path().join("index.js"), original)
            .await
            .unwrap();

        // Before blob exists
        tokio::fs::write(blobs_dir.path().join(&before_hash), original)
            .await
            .unwrap();

        let file_info = PatchFileInfo {
            before_hash: before_hash.clone(),
            after_hash: "bbbb".to_string(),
        };

        let result =
            verify_file_rollback(pkg_dir.path(), "index.js", &file_info, blobs_dir.path()).await;
        assert_eq!(result.status, VerifyRollbackStatus::AlreadyOriginal);
    }

    #[tokio::test]
    async fn test_verify_file_rollback_hash_mismatch() {
        let pkg_dir = tempfile::tempdir().unwrap();
        let blobs_dir = tempfile::tempdir().unwrap();

        let original = b"original content";
        let before_hash = compute_git_sha256_from_bytes(original);

        // File has been modified to something unexpected
        tokio::fs::write(pkg_dir.path().join("index.js"), b"something unexpected")
            .await
            .unwrap();

        // Before blob exists
        tokio::fs::write(blobs_dir.path().join(&before_hash), original)
            .await
            .unwrap();

        let file_info = PatchFileInfo {
            before_hash,
            after_hash: "expected_after_hash".to_string(),
        };

        let result =
            verify_file_rollback(pkg_dir.path(), "index.js", &file_info, blobs_dir.path()).await;
        assert_eq!(result.status, VerifyRollbackStatus::HashMismatch);
        assert!(result.message.unwrap().contains("modified after patching"));
    }

    #[tokio::test]
    async fn test_rollback_file_patch_success() {
        let dir = tempfile::tempdir().unwrap();
        let original = b"original content";
        let original_hash = compute_git_sha256_from_bytes(original);

        // File currently has patched content
        tokio::fs::write(dir.path().join("index.js"), b"patched")
            .await
            .unwrap();

        rollback_file_patch(dir.path(), "index.js", original, &original_hash)
            .await
            .unwrap();

        let written = tokio::fs::read(dir.path().join("index.js")).await.unwrap();
        assert_eq!(written, original);
    }

    #[tokio::test]
    async fn test_rollback_file_patch_hash_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("index.js"), b"patched")
            .await
            .unwrap();

        let result =
            rollback_file_patch(dir.path(), "index.js", b"original content", "wrong_hash").await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Hash verification failed"));
    }

    /// Validate-before-write: a corrupt/mismatched rollback blob must be
    /// refused *before* any disk write, leaving the on-disk file
    /// byte-identical to its pre-call (patched) state and dropping no
    /// `.socket-stage-*` litter. Regression: the old in-place
    /// `tokio::fs::write` committed the bad bytes over the file and only
    /// then hashed, leaving the file corrupted on the error path.
    #[tokio::test]
    async fn test_rollback_file_patch_hash_mismatch_leaves_file_intact() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("index.js");
        tokio::fs::write(&path, b"patched bytes on disk")
            .await
            .unwrap();

        let result =
            rollback_file_patch(dir.path(), "index.js", b"original content", "wrong_hash").await;
        assert!(result.is_err());

        // The file must NOT have been overwritten with the bad blob.
        assert_eq!(
            tokio::fs::read(&path).await.unwrap(),
            b"patched bytes on disk"
        );

        // No staged temp file leaked into the directory.
        let mut entries = tokio::fs::read_dir(dir.path()).await.unwrap();
        while let Some(entry) = entries.next_entry().await.unwrap() {
            let name = entry.file_name().to_string_lossy().to_string();
            assert!(
                !name.starts_with(".socket-stage-") && !name.starts_with(".socket-cow-"),
                "stage/cow litter leaked: {name}"
            );
        }
    }

    /// Copy-on-write safety: rolling back a file that shares an inode
    /// with a sibling (the pnpm / Go-cache hardlink case) must only
    /// restore *our* copy. The sibling — another project's view or the
    /// shared store entry — must keep its bytes. Regression: the old
    /// in-place write mutated the shared inode and corrupted the sibling.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_rollback_file_patch_does_not_propagate_to_hardlinked_sibling() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("project").join("foo.js");
        let sibling = dir.path().join("sibling.js");
        tokio::fs::create_dir_all(project.parent().unwrap())
            .await
            .unwrap();

        // Both paths point at the same inode, both currently "patched".
        tokio::fs::write(&sibling, b"patched bytes").await.unwrap();
        tokio::fs::hard_link(&sibling, &project).await.unwrap();

        let original = b"original bytes";
        let original_hash = compute_git_sha256_from_bytes(original);
        rollback_file_patch(
            project.parent().unwrap(),
            "foo.js",
            original,
            &original_hash,
        )
        .await
        .unwrap();

        // Our project view is rolled back...
        assert_eq!(tokio::fs::read(&project).await.unwrap(), original);
        // ...but the sibling inode is untouched.
        assert_eq!(tokio::fs::read(&sibling).await.unwrap(), b"patched bytes");
    }

    /// Permission fidelity: rolling back a read-only file (Go module
    /// cache marks sources `0o444`) must restore the original content
    /// AND leave the file read-only afterward. Regression: the old code
    /// relaxed the mode to `0o644` to write and never restored it,
    /// silently leaving rolled-back cache files writable.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_rollback_file_patch_preserves_readonly_mode() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("index.js");
        let original = b"original content";
        let original_hash = compute_git_sha256_from_bytes(original);

        tokio::fs::write(&path, b"patched content").await.unwrap();
        // Read-only patched file, as apply would have left a Go-cache source.
        tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444))
            .await
            .unwrap();

        rollback_file_patch(dir.path(), "index.js", original, &original_hash)
            .await
            .unwrap();

        assert_eq!(tokio::fs::read(&path).await.unwrap(), original);
        let mode = tokio::fs::metadata(&path)
            .await
            .unwrap()
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(
            mode, 0o444,
            "rollback must restore the read-only mode, not leave the file writable"
        );
    }

    /// End-to-end rollback against a fully read-only package directory
    /// (Go cache: `0o444` files inside a `0o555` directory). The atomic
    /// stage+rename path must temporarily grant directory write, restore
    /// content, and put the directory mode back. Regression: the old
    /// in-place write could not stage inside a read-only directory.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_rollback_package_patch_in_readonly_dir() {
        use std::os::unix::fs::PermissionsExt;

        let pkg_dir = tempfile::tempdir().unwrap();
        let blobs_dir = tempfile::tempdir().unwrap();

        let original = b"original content";
        let patched = b"patched content";
        let before_hash = compute_git_sha256_from_bytes(original);
        let after_hash = compute_git_sha256_from_bytes(patched);

        tokio::fs::write(pkg_dir.path().join("index.js"), patched)
            .await
            .unwrap();
        tokio::fs::write(blobs_dir.path().join(&before_hash), original)
            .await
            .unwrap();
        // Lock the file and directory down, Go-cache style.
        tokio::fs::set_permissions(
            pkg_dir.path().join("index.js"),
            std::fs::Permissions::from_mode(0o444),
        )
        .await
        .unwrap();
        tokio::fs::set_permissions(pkg_dir.path(), std::fs::Permissions::from_mode(0o555))
            .await
            .unwrap();

        let mut files = HashMap::new();
        files.insert(
            "index.js".to_string(),
            PatchFileInfo {
                before_hash,
                after_hash,
            },
        );

        let result = rollback_package_patch(
            "pkg:golang/example.com/x@1.0.0",
            pkg_dir.path(),
            &files,
            blobs_dir.path(),
            false,
        )
        .await;

        assert!(result.success, "expected success: {:?}", result.error);
        assert_eq!(result.files_rolled_back.len(), 1);
        assert_eq!(
            tokio::fs::read(pkg_dir.path().join("index.js"))
                .await
                .unwrap(),
            original
        );
        // Directory mode restored to exactly 0o555.
        assert_eq!(
            tokio::fs::metadata(pkg_dir.path())
                .await
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o555,
        );

        // Re-grant write so the TempDir can clean itself up.
        tokio::fs::set_permissions(pkg_dir.path(), std::fs::Permissions::from_mode(0o755))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_rollback_package_patch_success() {
        let pkg_dir = tempfile::tempdir().unwrap();
        let blobs_dir = tempfile::tempdir().unwrap();

        let original = b"original content";
        let patched = b"patched content";
        let before_hash = compute_git_sha256_from_bytes(original);
        let after_hash = compute_git_sha256_from_bytes(patched);

        // File is in patched state
        tokio::fs::write(pkg_dir.path().join("index.js"), patched)
            .await
            .unwrap();

        // Before blob exists
        tokio::fs::write(blobs_dir.path().join(&before_hash), original)
            .await
            .unwrap();

        let mut files = HashMap::new();
        files.insert(
            "index.js".to_string(),
            PatchFileInfo {
                before_hash: before_hash.clone(),
                after_hash,
            },
        );

        let result = rollback_package_patch(
            "pkg:npm/test@1.0.0",
            pkg_dir.path(),
            &files,
            blobs_dir.path(),
            false,
        )
        .await;

        assert!(result.success);
        assert_eq!(result.files_rolled_back.len(), 1);
        assert!(result.error.is_none());

        // Verify file was restored
        let content = tokio::fs::read(pkg_dir.path().join("index.js"))
            .await
            .unwrap();
        assert_eq!(content, original);
    }

    #[tokio::test]
    async fn test_rollback_package_patch_dry_run() {
        let pkg_dir = tempfile::tempdir().unwrap();
        let blobs_dir = tempfile::tempdir().unwrap();

        let original = b"original content";
        let patched = b"patched content";
        let before_hash = compute_git_sha256_from_bytes(original);
        let after_hash = compute_git_sha256_from_bytes(patched);

        tokio::fs::write(pkg_dir.path().join("index.js"), patched)
            .await
            .unwrap();
        tokio::fs::write(blobs_dir.path().join(&before_hash), original)
            .await
            .unwrap();

        let mut files = HashMap::new();
        files.insert(
            "index.js".to_string(),
            PatchFileInfo {
                before_hash,
                after_hash,
            },
        );

        let result = rollback_package_patch(
            "pkg:npm/test@1.0.0",
            pkg_dir.path(),
            &files,
            blobs_dir.path(),
            true, // dry run
        )
        .await;

        assert!(result.success);
        assert_eq!(result.files_rolled_back.len(), 0); // dry run

        // File should still be patched
        let content = tokio::fs::read(pkg_dir.path().join("index.js"))
            .await
            .unwrap();
        assert_eq!(content, patched);
    }

    #[tokio::test]
    async fn test_rollback_package_patch_all_original() {
        let pkg_dir = tempfile::tempdir().unwrap();
        let blobs_dir = tempfile::tempdir().unwrap();

        let original = b"original content";
        let before_hash = compute_git_sha256_from_bytes(original);

        // File is already original
        tokio::fs::write(pkg_dir.path().join("index.js"), original)
            .await
            .unwrap();
        tokio::fs::write(blobs_dir.path().join(&before_hash), original)
            .await
            .unwrap();

        let mut files = HashMap::new();
        files.insert(
            "index.js".to_string(),
            PatchFileInfo {
                before_hash,
                after_hash: "bbbb".to_string(),
            },
        );

        let result = rollback_package_patch(
            "pkg:npm/test@1.0.0",
            pkg_dir.path(),
            &files,
            blobs_dir.path(),
            false,
        )
        .await;

        assert!(result.success);
        assert_eq!(result.files_rolled_back.len(), 0);
    }

    #[tokio::test]
    async fn test_rollback_package_patch_missing_blob_blocks() {
        let pkg_dir = tempfile::tempdir().unwrap();
        let blobs_dir = tempfile::tempdir().unwrap();

        tokio::fs::write(pkg_dir.path().join("index.js"), b"patched content")
            .await
            .unwrap();

        let mut files = HashMap::new();
        files.insert(
            "index.js".to_string(),
            PatchFileInfo {
                before_hash: "missing_hash".to_string(),
                after_hash: "bbbb".to_string(),
            },
        );

        let result = rollback_package_patch(
            "pkg:npm/test@1.0.0",
            pkg_dir.path(),
            &files,
            blobs_dir.path(),
            false,
        )
        .await;

        assert!(!result.success);
        assert!(result.error.is_some());
    }

    /// Regression (blob-vs-already-original ordering): a file already at
    /// its original (`beforeHash`) state must verify as `AlreadyOriginal`
    /// even when the before-blob is gone. A finished rollback needs no
    /// blob to restore, so a GC'd blob must NOT downgrade it to
    /// `MissingBlob`. Before the fix the blob check ran first and a
    /// re-run rollback (or one after blob cleanup) reported a spurious
    /// missing-blob failure.
    #[tokio::test]
    async fn test_verify_file_rollback_already_original_without_blob() {
        let pkg_dir = tempfile::tempdir().unwrap();
        let blobs_dir = tempfile::tempdir().unwrap();

        let original = b"original content";
        let before_hash = compute_git_sha256_from_bytes(original);

        // File is already at its original state, but NO before-blob exists.
        tokio::fs::write(pkg_dir.path().join("index.js"), original)
            .await
            .unwrap();

        let file_info = PatchFileInfo {
            before_hash,
            after_hash: "some_after_hash".to_string(),
        };

        let result =
            verify_file_rollback(pkg_dir.path(), "index.js", &file_info, blobs_dir.path()).await;
        assert_eq!(result.status, VerifyRollbackStatus::AlreadyOriginal);
    }

    /// Package-level consequence of the ordering fix: an already-original
    /// file whose blob was GC'd must not block its sibling's real
    /// rollback. The whole package should succeed and the ready file
    /// should be restored. Before the fix the missing blob on the
    /// no-op file aborted the entire package rollback.
    #[tokio::test]
    async fn test_rollback_package_patch_already_original_missing_blob_does_not_block() {
        let pkg_dir = tempfile::tempdir().unwrap();
        let blobs_dir = tempfile::tempdir().unwrap();

        // File A: already at original state; its before-blob is absent.
        let a_original = b"a original";
        let a_before = compute_git_sha256_from_bytes(a_original);
        tokio::fs::write(pkg_dir.path().join("a.js"), a_original)
            .await
            .unwrap();

        // File B: still patched; before-blob present, ready to roll back.
        let b_original = b"b original";
        let b_patched = b"b patched";
        let b_before = compute_git_sha256_from_bytes(b_original);
        let b_after = compute_git_sha256_from_bytes(b_patched);
        tokio::fs::write(pkg_dir.path().join("b.js"), b_patched)
            .await
            .unwrap();
        tokio::fs::write(blobs_dir.path().join(&b_before), b_original)
            .await
            .unwrap();

        let mut files = HashMap::new();
        files.insert(
            "a.js".to_string(),
            PatchFileInfo {
                before_hash: a_before,
                after_hash: "a_after".to_string(),
            },
        );
        files.insert(
            "b.js".to_string(),
            PatchFileInfo {
                before_hash: b_before,
                after_hash: b_after,
            },
        );

        let result = rollback_package_patch(
            "pkg:npm/test@1.0.0",
            pkg_dir.path(),
            &files,
            blobs_dir.path(),
            false,
        )
        .await;

        assert!(result.success, "expected success: {:?}", result.error);
        assert_eq!(result.files_rolled_back, vec!["b.js".to_string()]);
        assert_eq!(
            tokio::fs::read(pkg_dir.path().join("b.js")).await.unwrap(),
            b_original
        );
        // A was already original and untouched.
        assert_eq!(
            tokio::fs::read(pkg_dir.path().join("a.js")).await.unwrap(),
            a_original
        );
    }

    /// SECURITY (verify path-escape guard): a manifest key that escapes
    /// the package directory must be refused at verification — never
    /// hashed or stat'd through `pkg_path.join`. Returns a blocking
    /// status (not Ready/AlreadyOriginal) so the package rollback aborts.
    /// Regression: verify joined the raw key with no safety check, the
    /// same hole the apply path closes with `is_safe_relative_subpath`.
    #[tokio::test]
    async fn test_verify_file_rollback_rejects_path_escape() {
        let pkg_dir = tempfile::tempdir().unwrap();
        let blobs_dir = tempfile::tempdir().unwrap();

        let file_info = PatchFileInfo {
            before_hash: "aaa".to_string(),
            after_hash: "bbb".to_string(),
        };

        for escape in ["package/../../escape.js", "../escape.js", "/etc/passwd"] {
            let result =
                verify_file_rollback(pkg_dir.path(), escape, &file_info, blobs_dir.path()).await;
            assert_ne!(result.status, VerifyRollbackStatus::Ready, "key: {escape}");
            assert_ne!(
                result.status,
                VerifyRollbackStatus::AlreadyOriginal,
                "key: {escape}"
            );
            assert!(result.message.unwrap().contains("Unsafe patch path"));
        }
    }

    /// SECURITY (new-file delete path-escape): the new-file deletion
    /// branch builds the path itself and calls `remove_file` directly,
    /// bypassing `apply_file_patch`'s guard. A poisoned manifest with an
    /// empty `beforeHash` and an escaping key must NOT unlink a file
    /// outside the package dir. Regression: the bare `remove_file` would
    /// delete an arbitrary host file.
    #[tokio::test]
    async fn test_rollback_package_patch_new_file_path_escape_blocked() {
        let root = tempfile::tempdir().unwrap();
        let pkg_dir = root.path().join("pkg");
        let blobs_dir = root.path().join("blobs");
        tokio::fs::create_dir_all(&pkg_dir).await.unwrap();
        tokio::fs::create_dir_all(&blobs_dir).await.unwrap();

        // A sentinel file OUTSIDE the package directory that must survive.
        let sentinel_content = b"do not delete me\n";
        let sentinel = root.path().join("sentinel.txt");
        tokio::fs::write(&sentinel, sentinel_content).await.unwrap();

        let mut files = HashMap::new();
        files.insert(
            // Empty beforeHash => "new file", delete branch. afterHash matches
            // the sentinel so a missing guard would let the delete through.
            "package/../sentinel.txt".to_string(),
            PatchFileInfo {
                before_hash: String::new(),
                after_hash: compute_git_sha256_from_bytes(sentinel_content),
            },
        );

        let result =
            rollback_package_patch("pkg:npm/test@1.0.0", &pkg_dir, &files, &blobs_dir, false).await;

        assert!(!result.success, "escaping delete must be refused");
        assert!(result.files_rolled_back.is_empty());
        // The out-of-tree sentinel must be untouched.
        assert_eq!(
            tokio::fs::read(&sentinel).await.unwrap(),
            sentinel_content,
            "rollback must not delete a file outside the package directory"
        );
    }

    /// New-file rollback (empty `beforeHash`): the file the patch added
    /// is deleted when its content still matches `afterHash`.
    #[tokio::test]
    async fn test_rollback_package_patch_new_file_deleted() {
        let pkg_dir = tempfile::tempdir().unwrap();
        let blobs_dir = tempfile::tempdir().unwrap();

        let added = b"file added by the patch\n";
        let after_hash = compute_git_sha256_from_bytes(added);
        let path = pkg_dir.path().join("added.js");
        tokio::fs::write(&path, added).await.unwrap();

        let mut files = HashMap::new();
        files.insert(
            "added.js".to_string(),
            PatchFileInfo {
                before_hash: String::new(),
                after_hash,
            },
        );

        let result = rollback_package_patch(
            "pkg:npm/test@1.0.0",
            pkg_dir.path(),
            &files,
            blobs_dir.path(),
            false,
        )
        .await;

        assert!(result.success, "expected success: {:?}", result.error);
        assert_eq!(result.files_rolled_back, vec!["added.js".to_string()]);
        assert!(
            tokio::fs::metadata(&path).await.is_err(),
            "the patch-added file must be deleted on rollback"
        );
    }

    /// New-file rollback is a no-op (success, nothing deleted) when the
    /// added file is already gone — e.g. the operator removed it by hand.
    #[tokio::test]
    async fn test_rollback_package_patch_new_file_already_gone() {
        let pkg_dir = tempfile::tempdir().unwrap();
        let blobs_dir = tempfile::tempdir().unwrap();

        let mut files = HashMap::new();
        files.insert(
            "added.js".to_string(),
            PatchFileInfo {
                before_hash: String::new(),
                after_hash: compute_git_sha256_from_bytes(b"whatever"),
            },
        );

        let result = rollback_package_patch(
            "pkg:npm/test@1.0.0",
            pkg_dir.path(),
            &files,
            blobs_dir.path(),
            false,
        )
        .await;

        assert!(result.success, "expected success: {:?}", result.error);
        assert_eq!(result.files_rolled_back.len(), 0);
    }

    /// Regression (read-only-dir delete): deleting a patch-added file
    /// requires write permission on the *parent directory*. A Go-cache
    /// style read-only directory (0o555) must be temporarily relaxed for
    /// the unlink and restored to its exact prior mode afterward. Before
    /// the fix the bare `remove_file` failed with EACCES.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_rollback_package_patch_new_file_delete_in_readonly_dir() {
        use std::os::unix::fs::PermissionsExt;

        let pkg_dir = tempfile::tempdir().unwrap();
        let blobs_dir = tempfile::tempdir().unwrap();

        let added = b"added by patch\n";
        let after_hash = compute_git_sha256_from_bytes(added);
        let path = pkg_dir.path().join("added.js");
        tokio::fs::write(&path, added).await.unwrap();
        // Read-only file inside a read-only directory (Go cache layout).
        tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444))
            .await
            .unwrap();
        tokio::fs::set_permissions(pkg_dir.path(), std::fs::Permissions::from_mode(0o555))
            .await
            .unwrap();

        let mut files = HashMap::new();
        files.insert(
            "added.js".to_string(),
            PatchFileInfo {
                before_hash: String::new(),
                after_hash,
            },
        );

        let result = rollback_package_patch(
            "pkg:golang/example.com/x@1.0.0",
            pkg_dir.path(),
            &files,
            blobs_dir.path(),
            false,
        )
        .await;

        assert!(result.success, "expected success: {:?}", result.error);
        assert_eq!(result.files_rolled_back, vec!["added.js".to_string()]);
        assert!(tokio::fs::metadata(&path).await.is_err());
        // Directory mode restored to exactly 0o555.
        assert_eq!(
            tokio::fs::metadata(pkg_dir.path())
                .await
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o555,
        );

        // Re-grant write so the TempDir can clean itself up.
        tokio::fs::set_permissions(pkg_dir.path(), std::fs::Permissions::from_mode(0o755))
            .await
            .unwrap();
    }

    /// SECURITY (before-blob hash path-escape at verify): `beforeHash`
    /// comes from the same untrusted manifest as the file keys, but is
    /// joined onto the blobs directory as a path component. A traversal
    /// (`../x`) or absolute "hash" must be refused at verification —
    /// `Path::join` discards the base on an absolute string and `..`
    /// walks out, so an escaping hash that resolved to any existing file
    /// verified `Ready` and the rollback loop then read an arbitrary
    /// out-of-tree path (existence oracle, unbounded read of `/dev/zero`,
    /// FIFO hang).
    #[tokio::test]
    async fn test_verify_file_rollback_rejects_blob_hash_escape() {
        let root = tempfile::tempdir().unwrap();
        let pkg_dir = root.path().join("pkg");
        let blobs_dir = root.path().join("blobs");
        tokio::fs::create_dir_all(&pkg_dir).await.unwrap();
        tokio::fs::create_dir_all(&blobs_dir).await.unwrap();

        // An out-of-tree file the escaping "hash" resolves to.
        let secret = root.path().join("secret.txt");
        tokio::fs::write(&secret, b"out of tree").await.unwrap();

        let patched = b"patched content";
        tokio::fs::write(pkg_dir.join("index.js"), patched)
            .await
            .unwrap();

        let escapes = [
            "../secret.txt".to_string(),
            // Absolute path: Path::join discards the blobs-dir base entirely.
            secret.to_string_lossy().into_owned(),
        ];
        for before_hash in escapes {
            let file_info = PatchFileInfo {
                before_hash: before_hash.clone(),
                after_hash: compute_git_sha256_from_bytes(patched),
            };
            let result = verify_file_rollback(&pkg_dir, "index.js", &file_info, &blobs_dir).await;
            assert_ne!(
                result.status,
                VerifyRollbackStatus::Ready,
                "hash: {before_hash}"
            );
            assert_ne!(
                result.status,
                VerifyRollbackStatus::AlreadyOriginal,
                "hash: {before_hash}"
            );
        }
    }

    /// SECURITY (before-blob escape at the read site): a poisoned manifest
    /// whose `beforeHash` escapes the blobs directory must fail the
    /// package rollback with the path-safety error. Regression: the
    /// unguarded code read the out-of-tree file and leaked its git-sha256
    /// into the error message ("Got: <hash>") — an existence +
    /// content-hash oracle over any host file readable by the user.
    #[tokio::test]
    async fn test_rollback_package_patch_blob_hash_escape_blocked() {
        let root = tempfile::tempdir().unwrap();
        let pkg_dir = root.path().join("pkg");
        let blobs_dir = root.path().join("blobs");
        tokio::fs::create_dir_all(&pkg_dir).await.unwrap();
        tokio::fs::create_dir_all(&blobs_dir).await.unwrap();

        let secret_content = b"top secret contents\n";
        tokio::fs::write(root.path().join("secret.txt"), secret_content)
            .await
            .unwrap();

        let patched = b"patched content";
        tokio::fs::write(pkg_dir.join("index.js"), patched)
            .await
            .unwrap();

        let mut files = HashMap::new();
        files.insert(
            "index.js".to_string(),
            PatchFileInfo {
                before_hash: "../secret.txt".to_string(),
                after_hash: compute_git_sha256_from_bytes(patched),
            },
        );

        let result =
            rollback_package_patch("pkg:npm/test@1.0.0", &pkg_dir, &files, &blobs_dir, false).await;

        assert!(!result.success, "escaping blob hash must be refused");
        assert!(result.files_rolled_back.is_empty());
        let err = result.error.unwrap();
        let secret_hash = compute_git_sha256_from_bytes(secret_content);
        assert!(
            !err.contains(&secret_hash),
            "error must not leak the out-of-tree file's content hash: {err}"
        );
        assert!(
            err.contains("Unsafe before-blob hash"),
            "unexpected error: {err}"
        );
        // The patched file must be untouched.
        assert_eq!(
            tokio::fs::read(pkg_dir.join("index.js")).await.unwrap(),
            patched
        );
    }

    /// Regression (new-file dangling symlink): `metadata()` follows
    /// symlinks, so a dangling symlink left where the patch-added file
    /// was reported ENOENT → `AlreadyOriginal`, and the package rollback
    /// claimed success while silently leaving the stray entry behind.
    /// The entry probe must be `symlink_metadata`: a path occupied by
    /// something that is neither the added file nor absent is a modified
    /// state and must fail closed, like every other modified state.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_rollback_package_patch_new_file_dangling_symlink_blocks() {
        let pkg_dir = tempfile::tempdir().unwrap();
        let blobs_dir = tempfile::tempdir().unwrap();

        let path = pkg_dir.path().join("added.js");
        std::os::unix::fs::symlink("does-not-exist", &path).unwrap();

        let mut files = HashMap::new();
        files.insert(
            "added.js".to_string(),
            PatchFileInfo {
                before_hash: String::new(),
                after_hash: compute_git_sha256_from_bytes(b"added by patch\n"),
            },
        );

        let result = rollback_package_patch(
            "pkg:npm/test@1.0.0",
            pkg_dir.path(),
            &files,
            blobs_dir.path(),
            false,
        )
        .await;

        assert!(
            !result.success,
            "a dangling symlink at the added path is a modified state and must block"
        );
        assert!(result.files_rolled_back.is_empty());
        // The stray entry is still there — it must not be silently ignored.
        assert!(tokio::fs::symlink_metadata(&path).await.is_ok());
    }

    /// Regression (cargo sidecar resync): apply rewrites
    /// `.cargo-checksum.json` to the *patched* SHA256s (and inserts
    /// entries for patch-added files). Rolling the package back restores
    /// the original bytes but used to leave the checksum file untouched —
    /// original sources verified against patched hashes, so the very next
    /// `cargo build` of the vendored crate refused with "checksum ...
    /// has changed" (proven by `cargo_check_fails_without_sidecar_fixup`
    /// in the cargo-build e2e). Rollback must resync the sidecar:
    /// restored files get their original hash back, and the entry for a
    /// patch-added (now deleted) file is removed entirely.
    #[tokio::test]
    async fn test_rollback_package_patch_cargo_resyncs_checksum_sidecar() {
        use sha2::{Digest, Sha256};
        fn sha256_hex(bytes: &[u8]) -> String {
            let mut h = Sha256::new();
            h.update(bytes);
            format!("{:x}", h.finalize())
        }

        let pkg_dir = tempfile::tempdir().unwrap();
        let blobs_dir = tempfile::tempdir().unwrap();
        let pkg = pkg_dir.path();

        let original = b"pub fn hello() {}\n";
        let patched = b"pub fn hello() { /* patched */ }\n";
        let added = b"pub fn added() {}\n";
        let before_hash = compute_git_sha256_from_bytes(original);
        let after_hash = compute_git_sha256_from_bytes(patched);

        // On-disk state is post-apply: patched source + patch-added file.
        tokio::fs::create_dir_all(pkg.join("src")).await.unwrap();
        tokio::fs::write(pkg.join("src/lib.rs"), patched)
            .await
            .unwrap();
        tokio::fs::write(pkg.join("src/new.rs"), added)
            .await
            .unwrap();
        tokio::fs::write(blobs_dir.path().join(&before_hash), original)
            .await
            .unwrap();

        // `.cargo-checksum.json` as apply's sidecar fixup left it: patched
        // hashes for the patched file, a fresh entry for the added file,
        // untouched entries and the `package` field preserved.
        let checksum_path = pkg.join(".cargo-checksum.json");
        let post_apply_checksum = serde_json::json!({
            "files": {
                "src/lib.rs": sha256_hex(patched),
                "src/new.rs": sha256_hex(added),
                "Cargo.toml": "ff".repeat(32),
            },
            "package": "tarball-hash-preserved",
        });
        tokio::fs::write(
            &checksum_path,
            serde_json::to_string_pretty(&post_apply_checksum).unwrap(),
        )
        .await
        .unwrap();

        let mut files = HashMap::new();
        files.insert(
            "src/lib.rs".to_string(),
            PatchFileInfo {
                before_hash: before_hash.clone(),
                after_hash,
            },
        );
        files.insert(
            "src/new.rs".to_string(),
            PatchFileInfo {
                before_hash: String::new(),
                after_hash: compute_git_sha256_from_bytes(added),
            },
        );

        let result =
            rollback_package_patch("pkg:cargo/demo@1.0.0", pkg, &files, blobs_dir.path(), false)
                .await;

        assert!(result.success, "rollback failed: {:?}", result.error);
        assert_eq!(result.files_rolled_back.len(), 2);
        assert_eq!(
            tokio::fs::read(pkg.join("src/lib.rs")).await.unwrap(),
            original
        );
        assert!(tokio::fs::metadata(pkg.join("src/new.rs")).await.is_err());

        // The sidecar must reflect the rolled-back (original) state.
        let post: serde_json::Value =
            serde_json::from_str(&tokio::fs::read_to_string(&checksum_path).await.unwrap())
                .unwrap();
        let entries = post["files"].as_object().unwrap();
        assert_eq!(
            entries["src/lib.rs"].as_str().unwrap(),
            sha256_hex(original),
            "rollback must restore the original hash in .cargo-checksum.json \
             or cargo refuses to build the rolled-back crate"
        );
        assert!(
            entries.get("src/new.rs").is_none(),
            "the entry apply added for the patch-added file must be removed \
             once rollback deletes that file"
        );
        // Untouched entries and the package field survive the resync.
        assert_eq!(entries["Cargo.toml"].as_str().unwrap(), "ff".repeat(32));
        assert_eq!(post["package"].as_str().unwrap(), "tarball-hash-preserved");

        // And the result reports the resync as a sidecar record, the
        // rollback-side twin of `ApplyResult::sidecar`.
        let sidecar = result
            .sidecar
            .expect("cargo rollback must report a sidecar resync");
        assert_eq!(sidecar.ecosystem, "cargo");
        assert_eq!(sidecar.purl, "pkg:cargo/demo@1.0.0");
        assert_eq!(sidecar.files.len(), 1);
        assert_eq!(sidecar.files[0].path, ".cargo-checksum.json");
        assert!(sidecar.advisory.is_none());
    }

    /// Best-effort boundary: a malformed `.cargo-checksum.json` must not
    /// fail the rollback (the bytes are already restored) — it surfaces
    /// as an `Error`-severity `sidecar_fixup_failed` advisory, mirroring
    /// apply's boundary in `apply_package_patch`.
    #[tokio::test]
    async fn test_rollback_package_patch_cargo_sidecar_failure_is_best_effort() {
        use crate::patch::sidecars::{SidecarAdvisoryCode, SidecarSeverity};

        let pkg_dir = tempfile::tempdir().unwrap();
        let blobs_dir = tempfile::tempdir().unwrap();
        let pkg = pkg_dir.path();

        let original = b"original content";
        let patched = b"patched content";
        let before_hash = compute_git_sha256_from_bytes(original);

        tokio::fs::write(pkg.join("lib.rs"), patched).await.unwrap();
        tokio::fs::write(blobs_dir.path().join(&before_hash), original)
            .await
            .unwrap();
        tokio::fs::write(pkg.join(".cargo-checksum.json"), b"not json")
            .await
            .unwrap();

        let mut files = HashMap::new();
        files.insert(
            "lib.rs".to_string(),
            PatchFileInfo {
                before_hash: before_hash.clone(),
                after_hash: compute_git_sha256_from_bytes(patched),
            },
        );

        let result =
            rollback_package_patch("pkg:cargo/demo@1.0.0", pkg, &files, blobs_dir.path(), false)
                .await;

        assert!(
            result.success,
            "sidecar resync failure must not fail the rollback"
        );
        assert_eq!(
            tokio::fs::read(pkg.join("lib.rs")).await.unwrap(),
            original,
            "the file restore itself must have happened"
        );
        let sidecar = result
            .sidecar
            .expect("failure must surface as a sidecar record");
        let advisory = sidecar
            .advisory
            .expect("failure record carries an advisory");
        assert_eq!(advisory.code, SidecarAdvisoryCode::SidecarFixupFailed);
        assert_eq!(advisory.severity, SidecarSeverity::Error);
    }

    /// Regression (retried partial rollback wedges cargo): a previous
    /// rollback that failed partway restored a.rs to its ORIGINAL bytes
    /// but returned before the resync boundary, leaving a.rs's
    /// `.cargo-checksum.json` entry at the PATCHED hash apply's fixup
    /// wrote. On the retry a.rs verifies `AlreadyOriginal` and is skipped
    /// by the restore loop — but it must still be included in the sidecar
    /// resync, or its entry stays patched-hash over original bytes and
    /// `cargo build` refuses the crate even though the retry reported
    /// success.
    #[tokio::test]
    async fn test_rollback_retry_resyncs_already_original_checksum_entries() {
        fn plain_sha256(b: &[u8]) -> String {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(b);
            format!("{:x}", h.finalize())
        }

        let pkg_dir = tempfile::tempdir().unwrap();
        let blobs_dir = tempfile::tempdir().unwrap();
        let pkg = pkg_dir.path();

        // State left by the interrupted run: a.rs already restored to its
        // original bytes (no before-blob needed — AlreadyOriginal
        // short-circuits), b.rs still patched. The checksum carries the
        // PATCHED hashes apply's fixup wrote for both.
        tokio::fs::write(pkg.join("a.rs"), b"original a")
            .await
            .unwrap();
        tokio::fs::write(pkg.join("b.rs"), b"patched b")
            .await
            .unwrap();
        let checksum = serde_json::json!({
            "files": {
                "a.rs": plain_sha256(b"patched a"),
                "b.rs": plain_sha256(b"patched b"),
            },
            "package": "x",
        });
        tokio::fs::write(
            pkg.join(".cargo-checksum.json"),
            serde_json::to_string_pretty(&checksum).unwrap(),
        )
        .await
        .unwrap();

        // The retry has b's before-blob available.
        let b_before = compute_git_sha256_from_bytes(b"original b");
        tokio::fs::write(blobs_dir.path().join(&b_before), b"original b")
            .await
            .unwrap();

        let mut files = HashMap::new();
        files.insert(
            "a.rs".to_string(),
            PatchFileInfo {
                before_hash: compute_git_sha256_from_bytes(b"original a"),
                after_hash: compute_git_sha256_from_bytes(b"patched a"),
            },
        );
        files.insert(
            "b.rs".to_string(),
            PatchFileInfo {
                before_hash: b_before,
                after_hash: compute_git_sha256_from_bytes(b"patched b"),
            },
        );

        let result = rollback_package_patch(
            "pkg:cargo/mycrate@1.0.0",
            pkg,
            &files,
            blobs_dir.path(),
            false,
        )
        .await;

        assert!(result.success, "retry must succeed: {:?}", result.error);
        assert_eq!(result.files_rolled_back, vec!["b.rs".to_string()]);

        let post: serde_json::Value = serde_json::from_str(
            &tokio::fs::read_to_string(pkg.join(".cargo-checksum.json"))
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            post["files"]["b.rs"].as_str().unwrap(),
            plain_sha256(b"original b"),
            "the freshly restored file's entry must be resynced"
        );
        assert_eq!(
            post["files"]["a.rs"].as_str().unwrap(),
            plain_sha256(b"original a"),
            "an AlreadyOriginal file from the interrupted run must be \
             resynced too — a stale patched-hash entry wedges cargo build"
        );
    }
}
