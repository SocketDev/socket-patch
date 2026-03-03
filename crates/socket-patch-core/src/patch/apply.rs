use std::collections::HashMap;
use std::path::Path;

use crate::manifest::schema::PatchFileInfo;
use crate::patch::file_hash::compute_file_git_sha256;

/// Status of a file patch verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyStatus {
    /// File is ready to be patched (current hash matches beforeHash).
    Ready,
    /// File is already in the patched state (current hash matches afterHash).
    AlreadyPatched,
    /// File hash does not match either beforeHash or afterHash.
    HashMismatch,
    /// File was not found on disk.
    NotFound,
}

/// Result of verifying whether a single file can be patched.
#[derive(Debug, Clone)]
pub struct VerifyResult {
    pub file: String,
    pub status: VerifyStatus,
    pub message: Option<String>,
    pub current_hash: Option<String>,
    pub expected_hash: Option<String>,
    pub target_hash: Option<String>,
}

/// Result of applying patches to a single package.
#[derive(Debug, Clone)]
pub struct ApplyResult {
    pub package_key: String,
    pub package_path: String,
    pub success: bool,
    pub files_verified: Vec<VerifyResult>,
    pub files_patched: Vec<String>,
    pub error: Option<String>,
}

/// Normalize file path by removing the "package/" prefix if present.
/// Patch files come from the API with paths like "package/lib/file.js"
/// but we need relative paths like "lib/file.js" for the actual package directory.
pub fn normalize_file_path(file_name: &str) -> &str {
    const PACKAGE_PREFIX: &str = "package/";
    if file_name.starts_with(PACKAGE_PREFIX) {
        &file_name[PACKAGE_PREFIX.len()..]
    } else {
        file_name
    }
}

/// Verify a single file can be patched.
pub async fn verify_file_patch(
    pkg_path: &Path,
    file_name: &str,
    file_info: &PatchFileInfo,
) -> VerifyResult {
    let normalized = normalize_file_path(file_name);
    let filepath = pkg_path.join(normalized);

    // Check if file exists
    if tokio::fs::metadata(&filepath).await.is_err() {
        return VerifyResult {
            file: file_name.to_string(),
            status: VerifyStatus::NotFound,
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
            return VerifyResult {
                file: file_name.to_string(),
                status: VerifyStatus::NotFound,
                message: Some(format!("Failed to hash file: {}", e)),
                current_hash: None,
                expected_hash: None,
                target_hash: None,
            };
        }
    };

    // Check if already patched
    if current_hash == file_info.after_hash {
        return VerifyResult {
            file: file_name.to_string(),
            status: VerifyStatus::AlreadyPatched,
            message: None,
            current_hash: Some(current_hash),
            expected_hash: None,
            target_hash: None,
        };
    }

    // Check if matches expected before hash
    if current_hash != file_info.before_hash {
        return VerifyResult {
            file: file_name.to_string(),
            status: VerifyStatus::HashMismatch,
            message: Some("File hash does not match expected value".to_string()),
            current_hash: Some(current_hash),
            expected_hash: Some(file_info.before_hash.clone()),
            target_hash: Some(file_info.after_hash.clone()),
        };
    }

    VerifyResult {
        file: file_name.to_string(),
        status: VerifyStatus::Ready,
        message: None,
        current_hash: Some(current_hash),
        expected_hash: None,
        target_hash: Some(file_info.after_hash.clone()),
    }
}

/// Apply a patch to a single file.
/// Writes the patched content and verifies the resulting hash.
pub async fn apply_file_patch(
    pkg_path: &Path,
    file_name: &str,
    patched_content: &[u8],
    expected_hash: &str,
) -> Result<(), std::io::Error> {
    let normalized = normalize_file_path(file_name);
    let filepath = pkg_path.join(normalized);

    // Write the patched content
    tokio::fs::write(&filepath, patched_content).await?;

    // Verify the hash after writing
    let verify_hash = compute_file_git_sha256(&filepath).await?;
    if verify_hash != expected_hash {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "Hash verification failed after patch. Expected: {}, Got: {}",
                expected_hash, verify_hash
            ),
        ));
    }

    Ok(())
}

/// Verify and apply patches for a single package.
///
/// For each file in `files`, this function:
/// 1. Verifies the file is ready to be patched (or already patched).
/// 2. If not dry_run, reads the blob from `blobs_path` and writes it.
/// 3. Returns a summary of what happened.
pub async fn apply_package_patch(
    package_key: &str,
    pkg_path: &Path,
    files: &HashMap<String, PatchFileInfo>,
    blobs_path: &Path,
    dry_run: bool,
) -> ApplyResult {
    let mut result = ApplyResult {
        package_key: package_key.to_string(),
        package_path: pkg_path.display().to_string(),
        success: false,
        files_verified: Vec::new(),
        files_patched: Vec::new(),
        error: None,
    };

    // First, verify all files
    for (file_name, file_info) in files {
        let verify_result = verify_file_patch(pkg_path, file_name, file_info).await;

        // If any file is not ready or already patched, we can't proceed
        if verify_result.status != VerifyStatus::Ready
            && verify_result.status != VerifyStatus::AlreadyPatched
        {
            let msg = verify_result
                .message
                .clone()
                .unwrap_or_else(|| format!("{:?}", verify_result.status));
            result.error = Some(format!(
                "Cannot apply patch: {} - {}",
                verify_result.file, msg
            ));
            result.files_verified.push(verify_result);
            return result;
        }

        result.files_verified.push(verify_result);
    }

    // Check if all files are already patched
    let all_patched = result
        .files_verified
        .iter()
        .all(|v| v.status == VerifyStatus::AlreadyPatched);
    if all_patched {
        result.success = true;
        return result;
    }

    // If dry run, stop here
    if dry_run {
        result.success = true;
        return result;
    }

    // Apply patches to files that need it
    for (file_name, file_info) in files {
        let verify_result = result.files_verified.iter().find(|v| v.file == *file_name);
        if let Some(vr) = verify_result {
            if vr.status == VerifyStatus::AlreadyPatched {
                continue;
            }
        }

        // Read patched content from blobs
        let blob_path = blobs_path.join(&file_info.after_hash);
        let patched_content = match tokio::fs::read(&blob_path).await {
            Ok(content) => content,
            Err(e) => {
                result.error = Some(format!(
                    "Failed to read blob {}: {}",
                    file_info.after_hash, e
                ));
                return result;
            }
        };

        // Apply the patch
        if let Err(e) = apply_file_patch(pkg_path, file_name, &patched_content, &file_info.after_hash).await {
            result.error = Some(e.to_string());
            return result;
        }

        result.files_patched.push(file_name.clone());
    }

    result.success = true;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::git_sha256::compute_git_sha256_from_bytes;

    #[test]
    fn test_normalize_file_path_with_prefix() {
        assert_eq!(normalize_file_path("package/lib/server.js"), "lib/server.js");
    }

    #[test]
    fn test_normalize_file_path_without_prefix() {
        assert_eq!(normalize_file_path("lib/server.js"), "lib/server.js");
    }

    #[test]
    fn test_normalize_file_path_just_prefix() {
        assert_eq!(normalize_file_path("package/"), "");
    }

    #[test]
    fn test_normalize_file_path_package_not_prefix() {
        // "package" without trailing "/" should NOT be stripped
        assert_eq!(normalize_file_path("packagefoo/bar.js"), "packagefoo/bar.js");
    }

    #[tokio::test]
    async fn test_verify_file_patch_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let file_info = PatchFileInfo {
            before_hash: "aaa".to_string(),
            after_hash: "bbb".to_string(),
        };

        let result = verify_file_patch(dir.path(), "nonexistent.js", &file_info).await;
        assert_eq!(result.status, VerifyStatus::NotFound);
    }

    #[tokio::test]
    async fn test_verify_file_patch_ready() {
        let dir = tempfile::tempdir().unwrap();
        let content = b"original content";
        let before_hash = compute_git_sha256_from_bytes(content);
        let after_hash = "bbbbbbbb".to_string();

        tokio::fs::write(dir.path().join("index.js"), content)
            .await
            .unwrap();

        let file_info = PatchFileInfo {
            before_hash: before_hash.clone(),
            after_hash,
        };

        let result = verify_file_patch(dir.path(), "index.js", &file_info).await;
        assert_eq!(result.status, VerifyStatus::Ready);
        assert_eq!(result.current_hash.unwrap(), before_hash);
    }

    #[tokio::test]
    async fn test_verify_file_patch_already_patched() {
        let dir = tempfile::tempdir().unwrap();
        let content = b"patched content";
        let after_hash = compute_git_sha256_from_bytes(content);

        tokio::fs::write(dir.path().join("index.js"), content)
            .await
            .unwrap();

        let file_info = PatchFileInfo {
            before_hash: "aaaa".to_string(),
            after_hash: after_hash.clone(),
        };

        let result = verify_file_patch(dir.path(), "index.js", &file_info).await;
        assert_eq!(result.status, VerifyStatus::AlreadyPatched);
    }

    #[tokio::test]
    async fn test_verify_file_patch_hash_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("index.js"), b"something else")
            .await
            .unwrap();

        let file_info = PatchFileInfo {
            before_hash: "aaaa".to_string(),
            after_hash: "bbbb".to_string(),
        };

        let result = verify_file_patch(dir.path(), "index.js", &file_info).await;
        assert_eq!(result.status, VerifyStatus::HashMismatch);
    }

    #[tokio::test]
    async fn test_verify_with_package_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let content = b"original content";
        let before_hash = compute_git_sha256_from_bytes(content);

        // File is at lib/server.js but patch refers to package/lib/server.js
        tokio::fs::create_dir_all(dir.path().join("lib")).await.unwrap();
        tokio::fs::write(dir.path().join("lib/server.js"), content)
            .await
            .unwrap();

        let file_info = PatchFileInfo {
            before_hash: before_hash.clone(),
            after_hash: "bbbb".to_string(),
        };

        let result = verify_file_patch(dir.path(), "package/lib/server.js", &file_info).await;
        assert_eq!(result.status, VerifyStatus::Ready);
    }

    #[tokio::test]
    async fn test_apply_file_patch_success() {
        let dir = tempfile::tempdir().unwrap();
        let original = b"original";
        let patched = b"patched content";
        let patched_hash = compute_git_sha256_from_bytes(patched);

        tokio::fs::write(dir.path().join("index.js"), original)
            .await
            .unwrap();

        apply_file_patch(dir.path(), "index.js", patched, &patched_hash)
            .await
            .unwrap();

        let written = tokio::fs::read(dir.path().join("index.js")).await.unwrap();
        assert_eq!(written, patched);
    }

    #[tokio::test]
    async fn test_apply_file_patch_hash_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("index.js"), b"original")
            .await
            .unwrap();

        let result =
            apply_file_patch(dir.path(), "index.js", b"patched content", "wrong_hash").await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Hash verification failed"));
    }

    #[tokio::test]
    async fn test_apply_package_patch_success() {
        let pkg_dir = tempfile::tempdir().unwrap();
        let blobs_dir = tempfile::tempdir().unwrap();

        let original = b"original content";
        let patched = b"patched content";
        let before_hash = compute_git_sha256_from_bytes(original);
        let after_hash = compute_git_sha256_from_bytes(patched);

        // Write original file
        tokio::fs::write(pkg_dir.path().join("index.js"), original)
            .await
            .unwrap();

        // Write blob
        tokio::fs::write(blobs_dir.path().join(&after_hash), patched)
            .await
            .unwrap();

        let mut files = HashMap::new();
        files.insert(
            "index.js".to_string(),
            PatchFileInfo {
                before_hash,
                after_hash: after_hash.clone(),
            },
        );

        let result =
            apply_package_patch("pkg:npm/test@1.0.0", pkg_dir.path(), &files, blobs_dir.path(), false)
                .await;

        assert!(result.success);
        assert_eq!(result.files_patched.len(), 1);
        assert!(result.error.is_none());
    }

    #[tokio::test]
    async fn test_apply_package_patch_dry_run() {
        let pkg_dir = tempfile::tempdir().unwrap();
        let blobs_dir = tempfile::tempdir().unwrap();

        let original = b"original content";
        let before_hash = compute_git_sha256_from_bytes(original);

        tokio::fs::write(pkg_dir.path().join("index.js"), original)
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

        let result =
            apply_package_patch("pkg:npm/test@1.0.0", pkg_dir.path(), &files, blobs_dir.path(), true)
                .await;

        assert!(result.success);
        assert_eq!(result.files_patched.len(), 0); // dry run: nothing actually patched

        // File should still have original content
        let content = tokio::fs::read(pkg_dir.path().join("index.js")).await.unwrap();
        assert_eq!(content, original);
    }

    #[tokio::test]
    async fn test_apply_package_patch_all_already_patched() {
        let pkg_dir = tempfile::tempdir().unwrap();
        let blobs_dir = tempfile::tempdir().unwrap();

        let patched = b"patched content";
        let after_hash = compute_git_sha256_from_bytes(patched);

        tokio::fs::write(pkg_dir.path().join("index.js"), patched)
            .await
            .unwrap();

        let mut files = HashMap::new();
        files.insert(
            "index.js".to_string(),
            PatchFileInfo {
                before_hash: "aaaa".to_string(),
                after_hash,
            },
        );

        let result =
            apply_package_patch("pkg:npm/test@1.0.0", pkg_dir.path(), &files, blobs_dir.path(), false)
                .await;

        assert!(result.success);
        assert_eq!(result.files_patched.len(), 0);
    }

    #[tokio::test]
    async fn test_apply_package_patch_hash_mismatch_blocks() {
        let pkg_dir = tempfile::tempdir().unwrap();
        let blobs_dir = tempfile::tempdir().unwrap();

        tokio::fs::write(pkg_dir.path().join("index.js"), b"something unexpected")
            .await
            .unwrap();

        let mut files = HashMap::new();
        files.insert(
            "index.js".to_string(),
            PatchFileInfo {
                before_hash: "aaaa".to_string(),
                after_hash: "bbbb".to_string(),
            },
        );

        let result =
            apply_package_patch("pkg:npm/test@1.0.0", pkg_dir.path(), &files, blobs_dir.path(), false)
                .await;

        assert!(!result.success);
        assert!(result.error.is_some());
    }
}
