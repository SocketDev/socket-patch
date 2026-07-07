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
    // The reported current hash must be the production hash of the on-disk
    // bytes, cross-checked against the independent oracle — not merely
    // echoed back from the manifest's after_hash.
    assert_eq!(result.current_hash.as_deref(), Some(after.as_str()));
    // The unchanged file name (incl. the `package/` prefix) is echoed back.
    assert_eq!(result.file, "package/new_file.txt");
    // New-file rollback is a delete: no blob is read, so the verify result
    // must carry no message and no expected/target blob hashes. A regression
    // that fell through to the blob-restore branch would populate these.
    assert_eq!(result.message, None);
    assert_eq!(result.expected_hash, None);
    assert_eq!(result.target_hash, None);
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
    let result = verify_file_rollback(pkg, "package/never_existed.txt", &file_info, &blobs).await;
    assert_eq!(result.status, VerifyRollbackStatus::AlreadyOriginal);
    assert_eq!(result.file, "package/never_existed.txt");
    // The file is gone, so there is no current content to hash and nothing to
    // restore — every hash field and the message must be empty. (Distinct
    // from the pre-existing-file branch, which reports NotFound for a missing
    // file; see the sibling test below.)
    assert_eq!(result.current_hash, None);
    assert_eq!(result.expected_hash, None);
    assert_eq!(result.target_hash, None);
    assert_eq!(result.message, None);
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
    let on_disk = b"user wrote something different";
    let on_disk_hash = git_sha256(on_disk);
    std::fs::write(pkg.join("user_modified.txt"), on_disk).unwrap();

    let file_info = PatchFileInfo {
        before_hash: String::new(),
        after_hash: after.clone(),
    };
    let result = verify_file_rollback(pkg, "package/user_modified.txt", &file_info, &blobs).await;
    assert_eq!(result.status, VerifyRollbackStatus::HashMismatch);
    assert_eq!(result.file, "package/user_modified.txt");
    // The diagnostic must name the actual failure mode, not just any string
    // containing "modified".
    assert_eq!(
        result.message.as_deref(),
        Some("File has been modified after patching. Cannot safely rollback.")
    );
    // The reported current hash must be the production hash of the *mutated*
    // on-disk bytes (proving it re-hashed disk, not echoed the manifest), and
    // the expected hash must be the manifest's after_hash. They must differ —
    // that difference is the whole reason for the mismatch verdict.
    assert_eq!(result.current_hash.as_deref(), Some(on_disk_hash.as_str()));
    assert_eq!(result.expected_hash.as_deref(), Some(after.as_str()));
    assert_ne!(result.current_hash, result.expected_hash);
    // New-file path: there is no before blob to target.
    assert_eq!(result.target_hash, None);
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
    let result = verify_file_rollback(pkg, "package/does_not_exist.txt", &file_info, &blobs).await;
    // Non-empty before_hash → pre-existing-file branch. A missing file here is
    // NotFound, NOT AlreadyOriginal (which is reserved for the new-file path).
    assert_eq!(result.status, VerifyRollbackStatus::NotFound);
    assert_eq!(result.file, "package/does_not_exist.txt");
    assert_eq!(result.message.as_deref(), Some("File not found"));
    // Nothing on disk to hash, nothing resolved.
    assert_eq!(result.current_hash, None);
    assert_eq!(result.expected_hash, None);
    assert_eq!(result.target_hash, None);
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
    let current = b"current patched bytes";
    let current_hash = git_sha256(current);
    std::fs::write(pkg.join("patched.txt"), current).unwrap();

    let before_hash = git_sha256(b"original content we cannot recover");
    let file_info = PatchFileInfo {
        before_hash: before_hash.clone(),
        // after_hash matches the on-disk content, so the file is genuinely in
        // the patched state: the MissingBlob verdict must come from the absent
        // before-blob, NOT from an after-hash mismatch. A regression that
        // checked after_hash before the blob would (wrongly) return Ready here.
        after_hash: current_hash.clone(),
    };
    let result = verify_file_rollback(pkg, "package/patched.txt", &file_info, &blobs).await;
    assert_eq!(result.status, VerifyRollbackStatus::MissingBlob);
    assert_eq!(result.file, "package/patched.txt");
    // The message must point the operator at the specific absent blob.
    let msg = result.message.as_deref().unwrap_or("");
    assert!(
        msg.contains("Before blob not found") && msg.contains(&before_hash),
        "message should name the missing before-blob: {msg:?}"
    );
    // current_hash = production hash of the on-disk bytes; target_hash = the
    // before-blob we failed to find.
    assert_eq!(result.current_hash.as_deref(), Some(current_hash.as_str()));
    assert_eq!(result.target_hash.as_deref(), Some(before_hash.as_str()));
    assert_eq!(result.expected_hash, None);
}

/// New-file rollback fail-closed: the patch-added path is occupied by
/// something unhashable (here: a directory). The hash error must surface
/// as a blocking status carrying the real error — not be swallowed into
/// an empty-string "hash" that gets misreported as "modified after
/// patching" with a fabricated `current_hash: Some("")`.
#[tokio::test]
async fn verify_new_file_rollback_unhashable_entry_fails_closed() {
    let tmp = tempfile::tempdir().unwrap();
    let pkg = tmp.path();
    let blobs = tmp.path().join("blobs");
    std::fs::create_dir(&blobs).unwrap();

    // A directory sits where the patch-added file should be.
    std::fs::create_dir(pkg.join("added.txt")).unwrap();

    let file_info = PatchFileInfo {
        before_hash: String::new(),
        after_hash: git_sha256(b"content the patch added"),
    };
    let result = verify_file_rollback(pkg, "package/added.txt", &file_info, &blobs).await;
    // Same convention as the pre-existing-file branch and this branch's own
    // stat-failure arm: unverifiable state → NotFound + the underlying error.
    assert_eq!(result.status, VerifyRollbackStatus::NotFound);
    let msg = result.message.as_deref().unwrap_or("");
    assert!(
        msg.starts_with("Failed to hash file:"),
        "must surface the hash error, not claim the file was modified: {msg:?}"
    );
    // No hash was computed — a fabricated Some("") must never be reported.
    assert_eq!(result.current_hash, None);
    assert_eq!(result.expected_hash, None);
    assert_eq!(result.target_hash, None);
}

/// Fail-open twin of the test above: when a malformed manifest carries an
/// empty `after_hash` alongside the empty `before_hash`, a swallowed hash
/// error ("") compares equal to the empty `after_hash` — verify reported
/// `Ready` and cleared an entry it could not read for deletion. An
/// unverifiable entry must never verify `Ready`.
#[tokio::test]
async fn verify_new_file_rollback_unhashable_entry_empty_after_hash_not_ready() {
    let tmp = tempfile::tempdir().unwrap();
    let pkg = tmp.path();
    let blobs = tmp.path().join("blobs");
    std::fs::create_dir(&blobs).unwrap();

    std::fs::create_dir(pkg.join("added.txt")).unwrap();

    let file_info = PatchFileInfo {
        before_hash: String::new(),
        after_hash: String::new(),
    };
    let result = verify_file_rollback(pkg, "package/added.txt", &file_info, &blobs).await;
    assert_ne!(
        result.status,
        VerifyRollbackStatus::Ready,
        "an entry that cannot be hashed must never be cleared for deletion"
    );
    assert_eq!(result.status, VerifyRollbackStatus::NotFound);
    assert_eq!(result.current_hash, None);
}

// Marker so `Path` import isn't unused on platforms that gate
// helper code differently.
#[allow(dead_code)]
fn _path_marker(_p: &Path) {}
