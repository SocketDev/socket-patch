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
    let filepath = pkg_path.join(normalized);

    let is_new_file = file_info.before_hash.is_empty();

    // For new files (empty beforeHash), rollback means deleting the file.
    if is_new_file {
        if tokio::fs::metadata(&filepath).await.is_err() {
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
}
