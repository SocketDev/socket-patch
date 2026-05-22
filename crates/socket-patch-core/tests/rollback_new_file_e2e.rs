//! Integration coverage for the rare rollback paths the apply-CLI
//! suite doesn't naturally drive — specifically the
//! empty-`before_hash` ("file created by the patch") branch of
//! `verify_file_rollback`, which is reachable in production when
//! a patch adds a new file rather than mutating an existing one.

use socket_patch_core::manifest::schema::PatchFileInfo;
use socket_patch_core::patch::rollback::{verify_file_rollback, VerifyRollbackStatus};
use std::path::Path;

/// Helper: compute the git-flavoured SHA-256 (`blob <len>\0` framing)
/// that the manifest records under `before_hash` / `after_hash`.
fn git_sha256(content: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let header = format!("blob {}\0", content.len());
    let mut hasher = Sha256::new();
    hasher.update(header.as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

/// New-file rollback: file exists with `after_hash` content, no
/// `before_hash`. `verify_file_rollback` returns `Ready` because
/// rolling back means deleting the file (no blob restore needed).
#[tokio::test]
async fn verify_new_file_rollback_ready_when_after_hash_matches() {
    let tmp = tempfile::tempdir().unwrap();
    let pkg = tmp.path();
    let blobs = tmp.path().join("blobs");
    std::fs::create_dir(&blobs).unwrap();

    let patched = b"this file was created by the patch\n";
    let after = git_sha256(patched);
    std::fs::write(pkg.join("new_file.txt"), patched).unwrap();

    let file_info = PatchFileInfo {
        before_hash: String::new(),
        after_hash: after.clone(),
    };
    let result = verify_file_rollback(pkg, "package/new_file.txt", &file_info, &blobs).await;
    assert_eq!(result.status, VerifyRollbackStatus::Ready);
    assert_eq!(result.current_hash.as_deref(), Some(after.as_str()));
}

/// New-file rollback already-original: the file the patch was
/// supposed to add is already gone (e.g., the operator deleted it
/// manually). `verify_file_rollback` reports AlreadyOriginal so
/// the rollback path can short-circuit.
#[tokio::test]
async fn verify_new_file_rollback_already_original_when_missing() {
    let tmp = tempfile::tempdir().unwrap();
    let pkg = tmp.path();
    let blobs = tmp.path().join("blobs");
    std::fs::create_dir(&blobs).unwrap();

    let file_info = PatchFileInfo {
        before_hash: String::new(),
        after_hash: git_sha256(b"never written"),
    };
    let result =
        verify_file_rollback(pkg, "package/never_existed.txt", &file_info, &blobs).await;
    assert_eq!(result.status, VerifyRollbackStatus::AlreadyOriginal);
}

/// New-file rollback mismatch: the file was added by the patch but
/// has since been modified to neither the empty-before nor the
/// post-patch content. Rollback can't safely proceed — the user
/// may have local edits that would be lost by a simple delete.
#[tokio::test]
async fn verify_new_file_rollback_hash_mismatch_when_user_modified() {
    let tmp = tempfile::tempdir().unwrap();
    let pkg = tmp.path();
    let blobs = tmp.path().join("blobs");
    std::fs::create_dir(&blobs).unwrap();

    // Manifest claims this is the post-patch content...
    let after = git_sha256(b"patched content the file should have had");
    // ...but the on-disk content has been mutated since.
    std::fs::write(pkg.join("user_modified.txt"), b"user wrote something different").unwrap();

    let file_info = PatchFileInfo {
        before_hash: String::new(),
        after_hash: after,
    };
    let result =
        verify_file_rollback(pkg, "package/user_modified.txt", &file_info, &blobs).await;
    assert_eq!(result.status, VerifyRollbackStatus::HashMismatch);
    assert!(result.message.as_ref().unwrap().contains("modified"));
}

/// Pre-existing file rollback: file is missing on disk. The
/// non-new-file branch reports NotFound rather than treating it as
/// already-original (which only applies to the new-file path).
#[tokio::test]
async fn verify_existing_file_rollback_not_found_when_missing() {
    let tmp = tempfile::tempdir().unwrap();
    let pkg = tmp.path();
    let blobs = tmp.path().join("blobs");
    std::fs::create_dir(&blobs).unwrap();

    let file_info = PatchFileInfo {
        before_hash: git_sha256(b"original"),
        after_hash: git_sha256(b"patched"),
    };
    let result = verify_file_rollback(
        pkg,
        "package/does_not_exist.txt",
        &file_info,
        &blobs,
    )
    .await;
    assert_eq!(result.status, VerifyRollbackStatus::NotFound);
    assert!(result.message.as_ref().unwrap().contains("not found"));
}

/// Pre-existing file rollback MissingBlob: file exists on disk but
/// the `before_hash` blob isn't staged. Rollback can't fabricate
/// the original content — surfaces as MissingBlob.
#[tokio::test]
async fn verify_existing_file_rollback_missing_blob() {
    let tmp = tempfile::tempdir().unwrap();
    let pkg = tmp.path();
    let blobs = tmp.path().join("blobs");
    std::fs::create_dir(&blobs).unwrap();
    // File exists, blob doesn't.
    std::fs::write(pkg.join("patched.txt"), b"current patched bytes").unwrap();

    let file_info = PatchFileInfo {
        before_hash: git_sha256(b"original content we cannot recover"),
        after_hash: git_sha256(b"current patched bytes"),
    };
    let result = verify_file_rollback(pkg, "package/patched.txt", &file_info, &blobs).await;
    assert_eq!(result.status, VerifyRollbackStatus::MissingBlob);
}

// Marker so `Path` import isn't unused on platforms that gate
// helper code differently.
#[allow(dead_code)]
fn _path_marker(_p: &Path) {}
