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
    if file_name.starts_with(PACKAGE_PREFIX) {
        &file_name[PACKAGE_PREFIX.len()..]
    } else {
        file_name
    }
}

/// Verify a single file can be rolled back.
///
/// A file is ready for rollback if:
/// 1. The file exists on disk.
/// 2. The before-hash blob exists in the blobs directory.
/// 3. Its current hash matches the afterHash (patched state).
pub async fn verify_file_rollback(
    pkg_path: &Path,
    file_name: &str,
    file_info: &PatchFileInfo,
    blobs_path: &Path,
) -> VerifyRollbackResult {
    let normalized = normalize_file_path(file_name);
    let filepath = pkg_path.join(normalized);

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

    // Check if before blob exists (required for rollback)
    let before_blob_path = blobs_path.join(&file_info.before_hash);
    if tokio::fs::metadata(&before_blob_path).await.is_err() {
        return VerifyRollbackResult {
            file: file_name.to_string(),
            status: VerifyRollbackStatus::MissingBlob,
            message: Some(format!(
                "Before blob not found: {}. Re-download the patch to enable rollback.",
                file_info.before_hash
            )),
            current_hash: None,
            expected_hash: None,
            target_hash: Some(file_info.before_hash.clone()),
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

    // Check if already in original state
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

/// Rollback a single file to its original state.
/// Writes the original content and verifies the resulting hash.
pub async fn rollback_file_patch(
    pkg_path: &Path,
    file_name: &str,
    original_content: &[u8],
    expected_hash: &str,
) -> Result<(), std::io::Error> {
    let normalized = normalize_file_path(file_name);
    let filepath = pkg_path.join(normalized);

    // Write the original content
    tokio::fs::write(&filepath, original_content).await?;

    // Verify the hash after writing
    let verify_hash = compute_file_git_sha256(&filepath).await?;
    if verify_hash != expected_hash {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "Hash verification failed after rollback. Expected: {}, Got: {}",
                expected_hash, verify_hash
            ),
        ));
    }

    Ok(())
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
        let verify_result =
            verify_file_rollback(pkg_path, file_name, file_info, blobs_path).await;

        // If any file has issues (not ready and not already original), we can't proceed
        if verify_result.status != VerifyRollbackStatus::Ready
            && verify_result.status != VerifyRollbackStatus::AlreadyOriginal
        {
            let msg = verify_result
                .message
                .clone()
                .unwrap_or_else(|| format!("{:?}", verify_result.status));
            result.error = Some(format!(
                "Cannot rollback: {} - {}",
                verify_result.file, msg
            ));
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
        let verify_result = result
            .files_verified
            .iter()
            .find(|v| v.file == *file_name);
        if let Some(vr) = verify_result {
            if vr.status == VerifyRollbackStatus::AlreadyOriginal {
                continue;
            }
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
        if let Err(e) =
            rollback_file_patch(pkg_path, file_name, &original_content, &file_info.before_hash)
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

        let result =
            verify_file_rollback(pkg_dir.path(), "nonexistent.js", &file_info, blobs_dir.path())
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
        assert!(result
            .message
            .unwrap()
            .contains("modified after patching"));
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
        let content = tokio::fs::read(pkg_dir.path().join("index.js")).await.unwrap();
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
        let content = tokio::fs::read(pkg_dir.path().join("index.js")).await.unwrap();
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
}
