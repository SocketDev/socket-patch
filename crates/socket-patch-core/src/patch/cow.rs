//! Copy-on-write defense against package-manager hardlink farms.
//!
//! Several package managers (pnpm, bazel mirrors, nix store overlays,
//! npm linked workspaces) point multiple project trees at a single
//! content-addressed inode via symlinks or hardlinks. A naive patch
//! that opens the path in a workspace and rewrites it would mutate the
//! shared inode — corrupting every other project that references the
//! same package.
//!
//! [`break_hardlink_if_needed`] is the pre-write hook that turns these
//! shared-inode references into private file copies before any patch
//! bytes touch disk. After the call, mutating the path is safe: only
//! this project's copy changes; the store entry and every other
//! project's link survive untouched.
//!
//! The function is idempotent and fast on the common case (regular
//! file with `nlink == 1`): a single `symlink_metadata` syscall, no
//! I/O beyond that. CoW only runs when there is something to break.
//!
//! **Windows note:** we always handle symlinks the same on Windows
//! (replace with private regular file) but skip the `nlink > 1`
//! check — `std::fs::Metadata` on Windows does not expose the file
//! information that carries it, and pnpm-on-Windows typically uses
//! reflinks/copies rather than hardlinks. A follow-up could call
//! `GetFileInformationByHandle` via `windows-sys` for full Windows
//! parity.

use std::path::{Path, PathBuf};

/// Outcome of [`break_hardlink_if_needed`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CowAction {
    /// Path didn't exist — nothing to break, caller will create fresh.
    NoFile,
    /// Path was a regular private file (one link, not a symlink).
    /// Caller can mutate it directly.
    AlreadyPrivate,
    /// Path was a symlink. We removed the link and put a fresh
    /// regular file with the same content in its place. The link
    /// target is untouched.
    BrokeSymlink,
    /// Path was a hardlinked regular file (`nlink > 1`). We copied
    /// the content into a new inode and atomically renamed it over
    /// the original. Sibling links are untouched.
    BrokeHardlink,
}

/// Ensure `path` (if it exists) points at a private inode this
/// project alone owns, so a subsequent in-place write only mutates
/// our copy.
///
/// See module docs for the failure mode this protects against.
pub async fn break_hardlink_if_needed(path: &Path) -> std::io::Result<CowAction> {
    // `symlink_metadata` does NOT follow symlinks — that's what we
    // want, since the symlink-vs-regular branch is the whole point.
    let lstat = match tokio::fs::symlink_metadata(path).await {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(CowAction::NoFile),
        Err(e) => return Err(e),
    };

    if lstat.file_type().is_symlink() {
        // Read through the symlink (this DOES follow it) to grab the
        // current target content. We need it on disk as a regular
        // file at `path` so the patch write lands on our copy.
        let target_bytes = tokio::fs::read(path).await?;
        // Remove the symlink. This only deletes the link itself; the
        // target file (in the store, in a sibling project, wherever)
        // is unaffected.
        tokio::fs::remove_file(path).await?;
        write_via_stage_rename(path, &target_bytes).await?;
        return Ok(CowAction::BrokeSymlink);
    }

    // Regular file. Hardlink defense is Unix-only — see module docs.
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if lstat.nlink() > 1 {
            // Atomic-rename-over-self pattern: copy our content into
            // a fresh inode, then rename over the original. The other
            // links keep pointing at the original inode (which now
            // has one fewer link but otherwise unchanged content).
            let content = tokio::fs::read(path).await?;
            write_via_stage_rename(path, &content).await?;
            return Ok(CowAction::BrokeHardlink);
        }
    }

    Ok(CowAction::AlreadyPrivate)
}

/// Write `bytes` to a temp file in `path.parent()` then rename over
/// `path`. Cross-FS-safe because the stage lives in the same
/// directory as the target, so `rename(2)` is intra-filesystem.
async fn write_via_stage_rename(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    // Stage filename: leading dot so editors / globs don't pick it
    // up as a real file; uuid suffix so concurrent calls don't
    // collide. (The apply lock makes that practically impossible,
    // but defense in depth.)
    let stem = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "anon".to_string());
    let stage: PathBuf = parent.join(format!(
        ".socket-cow-{}-{}",
        stem,
        uuid::Uuid::new_v4()
    ));
    tokio::fs::write(&stage, bytes).await?;
    // `rename` over the target is atomic on POSIX and best-effort on
    // Windows (`MoveFileExW` with REPLACE_EXISTING via std).
    match tokio::fs::rename(&stage, path).await {
        Ok(()) => Ok(()),
        Err(e) => {
            // Clean up the stage on rename failure so we don't leave
            // litter in the package directory.
            let _ = tokio::fs::remove_file(&stage).await;
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn missing_file_is_noop() {
        let dir = tempfile::tempdir().unwrap();
        let action = break_hardlink_if_needed(&dir.path().join("nope.txt"))
            .await
            .unwrap();
        assert_eq!(action, CowAction::NoFile);
    }

    #[tokio::test]
    async fn regular_file_with_one_link_is_already_private() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.txt");
        tokio::fs::write(&p, b"hello").await.unwrap();
        let action = break_hardlink_if_needed(&p).await.unwrap();
        assert_eq!(action, CowAction::AlreadyPrivate);
        // Content untouched.
        assert_eq!(tokio::fs::read(&p).await.unwrap(), b"hello");
    }

    /// Hardlink case (Unix only — see module docs).
    ///
    /// Create file A, hardlink B → A. Run CoW on B. After:
    /// - A's content is unchanged (the canonical store entry).
    /// - B has the same bytes but lives in a new inode.
    /// - Mutating B does NOT change A (the core invariant pnpm
    ///   safety depends on).
    #[cfg(unix)]
    #[tokio::test]
    async fn hardlink_is_broken_and_sibling_survives_mutation() {
        use std::os::unix::fs::MetadataExt;

        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("store-a.txt");
        let b = dir.path().join("project-b.txt");
        tokio::fs::write(&a, b"original").await.unwrap();
        tokio::fs::hard_link(&a, &b).await.unwrap();

        // Sanity: both report nlink == 2.
        let a_meta_before = tokio::fs::metadata(&a).await.unwrap();
        assert_eq!(a_meta_before.nlink(), 2);

        let action = break_hardlink_if_needed(&b).await.unwrap();
        assert_eq!(action, CowAction::BrokeHardlink);

        // A is now a single-link inode.
        let a_meta_after = tokio::fs::metadata(&a).await.unwrap();
        assert_eq!(a_meta_after.nlink(), 1);
        // B has the same content but a different inode.
        assert_eq!(tokio::fs::read(&b).await.unwrap(), b"original");
        assert_ne!(
            a_meta_after.ino(),
            tokio::fs::metadata(&b).await.unwrap().ino()
        );

        // Mutate B — A must NOT change.
        tokio::fs::write(&b, b"patched").await.unwrap();
        assert_eq!(tokio::fs::read(&a).await.unwrap(), b"original");
        assert_eq!(tokio::fs::read(&b).await.unwrap(), b"patched");
    }

    /// Symlink case (cross-platform). The symlink → target relation
    /// is what pnpm's `node_modules/<pkg>` typically looks like. We
    /// must replace the link with a private regular file and leave
    /// the target alone.
    #[cfg(unix)]
    #[tokio::test]
    async fn symlink_is_replaced_with_private_file() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("store-entry.txt");
        let link = dir.path().join("project-link.txt");
        tokio::fs::write(&target, b"shared bytes").await.unwrap();
        tokio::fs::symlink(&target, &link).await.unwrap();

        let action = break_hardlink_if_needed(&link).await.unwrap();
        assert_eq!(action, CowAction::BrokeSymlink);

        // Link path is now a regular file with the target's content.
        let link_meta = tokio::fs::symlink_metadata(&link).await.unwrap();
        assert!(link_meta.file_type().is_file());
        assert!(!link_meta.file_type().is_symlink());
        assert_eq!(tokio::fs::read(&link).await.unwrap(), b"shared bytes");

        // Target is untouched.
        let target_meta = tokio::fs::symlink_metadata(&target).await.unwrap();
        assert!(target_meta.file_type().is_file());
        assert_eq!(tokio::fs::read(&target).await.unwrap(), b"shared bytes");

        // Mutate the link path; target stays put.
        tokio::fs::write(&link, b"patched").await.unwrap();
        assert_eq!(tokio::fs::read(&target).await.unwrap(), b"shared bytes");
    }

    /// Idempotency: calling twice in a row on a regular file is fine
    /// and reports `AlreadyPrivate` both times.
    #[tokio::test]
    async fn idempotent_on_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("x.txt");
        tokio::fs::write(&p, b"hi").await.unwrap();
        let a1 = break_hardlink_if_needed(&p).await.unwrap();
        let a2 = break_hardlink_if_needed(&p).await.unwrap();
        assert_eq!(a1, CowAction::AlreadyPrivate);
        assert_eq!(a2, CowAction::AlreadyPrivate);
    }
}
