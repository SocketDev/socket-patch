//! Staged, fail-closed file I/O shared by the hosted-redirect reverts — the
//! per-purl takeover ([`super::takeover`]) and the whole-ledger replay
//! ([`super::replay`]).
//!
//! Both reverts resolve every inverse against a STAGED view of the project
//! and let nothing reach disk until all of them have resolved, so a drift
//! refusal leaves the project byte-identical. This module is that staging
//! layer: FIFO-safe reads of untrusted project files, the staged view, and
//! one flush with the same guards on both sides (a symlink or FIFO squatting
//! a path refuses; every write is atomic and keeps the file's mode).

use std::collections::BTreeMap;
use std::path::Path;

/// Files a revert has decided but not yet written: `Some(content)` to
/// write, `None` to delete.
pub(super) type Staged = BTreeMap<String, Option<String>>;

/// Native binary lockfiles staged after restoring their package snapshots.
pub(super) type StagedBytes = BTreeMap<String, Vec<u8>>;

/// Read a project file, distinguishing missing (`Ok(None)`) from unreadable.
///
/// FIFO-guarded: a planted FIFO, directory or device squatting a lockfile
/// path fails fast (`InvalidInput`) instead of wedging the revert on a
/// blocking open — the same posture as every other raw read in the patch
/// engine. Errors read `read <rel>: <cause>`.
pub(super) async fn read_rel(project_root: &Path, rel: &str) -> Result<Option<String>, String> {
    match crate::utils::fs::read_regular_to_string(&project_root.join(rel)).await {
        Ok(content) => Ok(Some(content)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("read {rel}: {e}")),
    }
}

/// Read a project file through the staged writes, so each unwind step sees
/// what the earlier steps decided. Both the re-redirect chain (a step's
/// `original` is the previous step's `new`) and the cargo registry block's
/// still-referenced probe depend on that view, and neither may depend on the
/// bytes having landed.
pub(super) async fn staged_read(
    staged: &Staged,
    project_root: &Path,
    rel: &str,
) -> Result<Option<String>, String> {
    match staged.get(rel) {
        Some(pending) => Ok(pending.clone()),
        None => read_rel(project_root, rel).await,
    }
}

/// Commit the staged files. Only reached once every inverse resolved, so a
/// drift refusal never gets here; an I/O fault partway through is the one
/// remaining way to stop mid-set, and it surfaces as `Err` naming the path
/// (`write <rel>: …` / `remove <rel>: …`) — some files may already have
/// landed, the residual exposure both reverts document.
///
/// Every path is guarded on the write side too: a symlink or FIFO squatting
/// it refuses (`<rel> is not a regular file`) — a rename-over would replace
/// the link with a detached regular file, and writing into a FIFO blocks
/// forever — while a missing target is fine (the write creates it). Text and
/// binary content go through the atomic mode-preserving writer, so a crash
/// or `ENOSPC` mid-flush never leaves a torn lockfile and a `0600` lock keeps
/// its bits. A deleted file's now-empty parent directory (the `.cargo/` a
/// registry block was written into) is pruned best-effort; the project root
/// itself is never touched.
pub(super) async fn flush_staged(
    project_root: &Path,
    staged: &Staged,
    staged_bytes: &StagedBytes,
) -> Result<(), String> {
    for (rel, pending) in staged {
        let path = project_root.join(rel);
        refuse_non_regular(&path, rel).await?;
        match pending {
            Some(content) => {
                crate::utils::fs::atomic_write_bytes_preserving_mode(&path, content.as_bytes())
                    .await
                    .map_err(|e| format!("write {rel}: {e}"))?;
            }
            None => {
                match tokio::fs::remove_file(&path).await {
                    Ok(()) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(format!("remove {rel}: {e}")),
                }
                let in_subdir = Path::new(rel)
                    .parent()
                    .is_some_and(|parent| !parent.as_os_str().is_empty());
                if in_subdir {
                    if let Some(parent) = path.parent() {
                        // `remove_dir` refuses a non-empty directory, so this
                        // only ever removes the husk the revert emptied.
                        let _ = tokio::fs::remove_dir(parent).await;
                    }
                }
            }
        }
    }
    for (rel, bytes) in staged_bytes {
        let path = project_root.join(rel);
        refuse_non_regular(&path, rel).await?;
        crate::utils::fs::atomic_write_bytes_preserving_mode(&path, bytes)
            .await
            .map_err(|e| format!("write {rel}: {e}"))?;
    }
    Ok(())
}

/// The write-side guard: `symlink_metadata` (never following a link) must
/// either fail — the target does not exist and the write creates it — or
/// describe a regular file.
async fn refuse_non_regular(path: &Path, rel: &str) -> Result<(), String> {
    if let Ok(meta) = tokio::fs::symlink_metadata(path).await {
        if !meta.is_file() {
            return Err(format!("{rel} is not a regular file"));
        }
    }
    Ok(())
}
