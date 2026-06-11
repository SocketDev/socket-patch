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
    /// Path was a symlink. We atomically replaced the link with a
    /// fresh regular file holding the same content (staged in the same
    /// directory and renamed over the link in one step). The link
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
        // Stage the private copy in the same directory, then
        // atomically rename it OVER the symlink. `rename(2)` operates
        // on the final path component itself — it never follows the
        // symlink — so this replaces the link with our regular file
        // while leaving the link's *target* (the store entry / sibling
        // project) untouched.
        //
        // We deliberately do NOT `remove_file(path)` first. Unlinking
        // the symlink before the replacement is committed would open a
        // window in which the package file simply does not exist: if
        // the staged write then failed (ENOSPC, EPERM on an immutable
        // target, a crash), the original would be gone with nothing to
        // roll back to. The rename-over-symlink is a single atomic
        // step — on any failure `path` still holds the original link.
        // This mirrors the hardlink branch below and `write_atomic`.
        write_via_stage_rename(path, &target_bytes).await?;
        return Ok(CowAction::BrokeSymlink);
    }

    // Hardlink defense is Unix-only — see module docs. The break only
    // makes sense for regular files: a directory always has nlink >= 2
    // (read() would fail EISDIR), and read() on a hardlinked FIFO blocks
    // forever waiting for a writer. Non-regular inodes are not cow's
    // problem — leave them untouched.
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if lstat.is_file() && lstat.nlink() > 1 {
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
    // Preconditions: cow callers always pass a real file path
    // inside a package directory, so `path.parent()` and
    // `path.file_name()` are guaranteed `Some`. The previous
    // `unwrap_or_else` defaults only fired on `path == "/"`,
    // which cow can never reach (lstat on "/" returns a directory,
    // and the hardlink branch's `read("/")` errors out long
    // before we get here). Using `.expect()` documents the
    // invariant and eliminates the dead defensive default.
    let parent = path
        .parent()
        .expect("cow stage path always has a parent — callers pass package-internal files");
    // Stage filename: leading dot so editors / globs don't pick it
    // up as a real file; uuid suffix so concurrent calls don't
    // collide. (The apply lock makes that practically impossible,
    // but defense in depth.)
    let stem = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .expect("cow stage path always has a file_name — callers pass package-internal files");
    let stage: PathBuf = parent.join(format!(".socket-cow-{}-{}", stem, uuid::Uuid::new_v4()));
    // Stage write. If this fails *after* creating the file (e.g. a
    // mid-write ENOSPC), the partial stage would otherwise leak as a
    // `.socket-cow-*` turd, so clean it up before propagating — same
    // discipline as `apply::write_atomic`'s write arm.
    if let Err(e) = tokio::fs::write(&stage, bytes).await {
        let _ = tokio::fs::remove_file(&stage).await;
        return Err(e);
    }
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

    /// Helper: count `.socket-cow-*` stage files left in a directory.
    #[cfg(unix)]
    fn leftover_stage_count(dir: &Path) -> usize {
        std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with(".socket-cow-"))
            .count()
    }

    /// Realistic pnpm shape: `node_modules/<pkg>` is a *symlink* into
    /// the content store, and the store entry is itself *hardlinked*
    /// across projects. Breaking the symlink must:
    ///   - leave the project path a private, single-link regular file,
    ///   - leave the store entry's content AND its sibling hardlink
    ///     completely untouched (the whole point of CoW),
    ///   - leave no `.socket-cow-*` stage litter behind.
    #[cfg(unix)]
    #[tokio::test]
    async fn symlink_to_hardlinked_store_entry_is_fully_isolated() {
        use std::os::unix::fs::MetadataExt;

        let dir = tempfile::tempdir().unwrap();
        // The content store entry + a sibling project's hardlink to it.
        let store = dir.path().join("store-entry.txt");
        let sibling = dir.path().join("other-project-hardlink.txt");
        tokio::fs::write(&store, b"shared bytes").await.unwrap();
        tokio::fs::hard_link(&store, &sibling).await.unwrap();
        // Our project links to the store entry via a symlink.
        let link = dir.path().join("our-project-link.txt");
        tokio::fs::symlink(&store, &link).await.unwrap();
        assert_eq!(tokio::fs::metadata(&store).await.unwrap().nlink(), 2);

        let action = break_hardlink_if_needed(&link).await.unwrap();
        assert_eq!(action, CowAction::BrokeSymlink);

        // Our path is now a private regular file (not a symlink), and
        // its inode is distinct from the store entry.
        let link_meta = tokio::fs::symlink_metadata(&link).await.unwrap();
        assert!(link_meta.file_type().is_file());
        assert!(!link_meta.file_type().is_symlink());
        assert_ne!(
            link_meta.ino(),
            tokio::fs::metadata(&store).await.unwrap().ino()
        );

        // Store entry + its sibling hardlink are byte-for-byte intact,
        // and still share their inode (nlink unchanged at 2).
        assert_eq!(tokio::fs::metadata(&store).await.unwrap().nlink(), 2);
        assert_eq!(tokio::fs::read(&store).await.unwrap(), b"shared bytes");
        assert_eq!(tokio::fs::read(&sibling).await.unwrap(), b"shared bytes");

        // Mutating our copy must not bleed into the store or its sibling.
        tokio::fs::write(&link, b"patched").await.unwrap();
        assert_eq!(tokio::fs::read(&store).await.unwrap(), b"shared bytes");
        assert_eq!(tokio::fs::read(&sibling).await.unwrap(), b"shared bytes");

        // No stage litter survives the successful break.
        assert_eq!(leftover_stage_count(dir.path()), 0);
    }

    /// Success-path litter check: neither the symlink break nor the
    /// hardlink break may leave a `.socket-cow-*` stage file behind.
    #[cfg(unix)]
    #[tokio::test]
    async fn break_leaves_no_stage_litter() {
        let dir = tempfile::tempdir().unwrap();

        let target = dir.path().join("t.txt");
        tokio::fs::write(&target, b"x").await.unwrap();
        let link = dir.path().join("l.txt");
        tokio::fs::symlink(&target, &link).await.unwrap();
        break_hardlink_if_needed(&link).await.unwrap();

        let a = dir.path().join("a.txt");
        tokio::fs::write(&a, b"y").await.unwrap();
        let b = dir.path().join("b.txt");
        tokio::fs::hard_link(&a, &b).await.unwrap();
        break_hardlink_if_needed(&b).await.unwrap();

        assert_eq!(leftover_stage_count(dir.path()), 0);
    }

    /// Idempotency: breaking a symlink yields a private regular file,
    /// and a second call on the now-regular path is a clean
    /// `AlreadyPrivate` no-op (no re-break, no litter).
    #[cfg(unix)]
    #[tokio::test]
    async fn idempotent_after_breaking_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("store.txt");
        let link = dir.path().join("link.txt");
        tokio::fs::write(&target, b"bytes").await.unwrap();
        tokio::fs::symlink(&target, &link).await.unwrap();

        assert_eq!(
            break_hardlink_if_needed(&link).await.unwrap(),
            CowAction::BrokeSymlink
        );
        assert_eq!(
            break_hardlink_if_needed(&link).await.unwrap(),
            CowAction::AlreadyPrivate
        );
        assert_eq!(leftover_stage_count(dir.path()), 0);
    }

    /// Non-regular inodes must never be routed into the hardlink
    /// break: `read()` on a FIFO blocks forever waiting for a writer,
    /// so a hardlinked FIFO (`nlink == 2`) at a patched path would
    /// hang the whole apply. It must come back promptly as
    /// `AlreadyPrivate` — content-copying only makes sense for
    /// regular files.
    #[cfg(unix)]
    #[tokio::test]
    async fn hardlinked_fifo_is_not_routed_into_hardlink_break() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("pipe");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(status.success());
        let link = dir.path().join("pipe-link");
        tokio::fs::hard_link(&fifo, &link).await.unwrap();

        let action = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            break_hardlink_if_needed(&link),
        )
        .await
        .expect("must not block reading the FIFO")
        .unwrap();
        assert_eq!(action, CowAction::AlreadyPrivate);
        assert_eq!(leftover_stage_count(dir.path()), 0);
    }

    /// A directory always has `nlink >= 2` on Unix, which a bare
    /// `nlink > 1` check misreads as a hardlinked file — `read()` then
    /// fails EISDIR instead of the documented no-op. Directories are
    /// not cow's problem; report `AlreadyPrivate` and leave them
    /// untouched.
    #[tokio::test]
    async fn directory_is_not_routed_into_hardlink_break() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().join("pkg-subdir");
        tokio::fs::create_dir(&d).await.unwrap();
        tokio::fs::create_dir(d.join("child")).await.unwrap();

        let action = break_hardlink_if_needed(&d).await.unwrap();
        assert_eq!(action, CowAction::AlreadyPrivate);
        assert!(tokio::fs::metadata(&d).await.unwrap().is_dir());
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
