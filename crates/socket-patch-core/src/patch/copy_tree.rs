//! Shared tree-copy helpers for the project-local Go `replace`-redirect backend
//! ([`crate::patch::go_redirect`]). It materialises a project-local **patched
//! copy** of a module by copying its pristine source out of the read-only,
//! checksum-verified module cache into a writable dir under `.socket/`, then
//! patching the copy in place.
//!
//! Only compiled when the Go redirect backend is enabled (gated in `mod.rs`).

use std::path::Path;

fn to_io<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

/// Fresh-copy `src` → `dst` (removing `dst` first), optionally skipping any
/// file whose final name component equals `skip_file_name` (at any depth — e.g.
/// cargo's `.cargo-checksum.json`, which must not survive into a path-dep copy).
///
/// Runs on the blocking pool (registry/module-cache sources are bounded).
/// Directories are created fresh (writable, subject to umask) rather than
/// mirroring the cache's read-only modes, so the copy can be patched and later
/// removed without a chmod dance. File *contents* are copied via
/// `std::fs::copy`, which also carries the source's mode bits (often `0o444` in
/// the cache); the downstream apply pipeline grants write as needed, and
/// [`remove_tree`] relaxes perms on cleanup. Symlinks / specials are skipped —
/// crates.io registry and Go module-cache sources contain none, and copying a
/// dangling link would be unsafe.
pub(crate) async fn fresh_copy(
    src: &Path,
    dst: &Path,
    skip_file_name: Option<&'static str>,
) -> std::io::Result<()> {
    let src = src.to_path_buf();
    let dst = dst.to_path_buf();
    tokio::task::spawn_blocking(move || {
        force_remove_dir_all(&dst)?;
        std::fs::create_dir_all(&dst)?;
        for entry in walkdir::WalkDir::new(&src).follow_links(false) {
            let entry = entry.map_err(to_io)?;
            let rel = entry.path().strip_prefix(&src).map_err(to_io)?;
            if rel.as_os_str().is_empty() {
                continue;
            }
            if let Some(skip) = skip_file_name {
                if entry.file_name() == skip {
                    continue;
                }
            }
            let target = dst.join(rel);
            let ft = entry.file_type();
            if ft.is_dir() {
                std::fs::create_dir_all(&target)?;
            } else if ft.is_file() {
                if let Some(p) = target.parent() {
                    std::fs::create_dir_all(p)?;
                }
                std::fs::copy(entry.path(), &target)?;
            }
        }
        Ok(())
    })
    .await
    .map_err(|e| std::io::Error::other(e.to_string()))?
}

/// Recursively remove a tree, retrying once after relaxing perms (a previously
/// patched copy may carry read-only file modes copied from the registry/cache).
pub(crate) fn force_remove_dir_all(dir: &Path) -> std::io::Result<()> {
    match std::fs::remove_dir_all(dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                for entry in walkdir::WalkDir::new(dir).into_iter().flatten() {
                    let ft = entry.file_type();
                    // Never chmod a symlink: `set_permissions` follows the link
                    // and would mutate its *target's* mode — which may live
                    // outside the tree. A symlink is unlinked via the write bit
                    // on its (relaxed) parent dir; its own mode is irrelevant.
                    if ft.is_symlink() {
                        continue;
                    }
                    let mode = if ft.is_dir() { 0o755 } else { 0o644 };
                    let _ = std::fs::set_permissions(
                        entry.path(),
                        std::fs::Permissions::from_mode(mode),
                    );
                }
            }
            std::fs::remove_dir_all(dir)
        }
    }
}

/// Async wrapper over [`force_remove_dir_all`].
pub(crate) async fn remove_tree(dir: &Path) -> std::io::Result<()> {
    let dir = dir.to_path_buf();
    tokio::task::spawn_blocking(move || force_remove_dir_all(&dir))
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[tokio::test]
    async fn copies_nested_and_empty_dirs() {
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        let d = dst.path().join("copy");
        fs::create_dir_all(src.path().join("a/b")).unwrap();
        fs::create_dir_all(src.path().join("empty")).unwrap();
        fs::write(src.path().join("a/b/file.txt"), b"hello").unwrap();
        fs::write(src.path().join("top.txt"), b"top").unwrap();

        fresh_copy(src.path(), &d, None).await.unwrap();

        assert_eq!(fs::read(d.join("a/b/file.txt")).unwrap(), b"hello");
        assert_eq!(fs::read(d.join("top.txt")).unwrap(), b"top");
        assert!(d.join("empty").is_dir(), "empty dir not preserved");
    }

    #[tokio::test]
    async fn skips_named_file_at_any_depth() {
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        let d = dst.path().join("copy");
        fs::create_dir_all(src.path().join("sub")).unwrap();
        fs::write(src.path().join(".cargo-checksum.json"), b"{}").unwrap();
        fs::write(src.path().join("sub/.cargo-checksum.json"), b"{}").unwrap();
        fs::write(src.path().join("sub/keep.rs"), b"code").unwrap();

        fresh_copy(src.path(), &d, Some(".cargo-checksum.json")).await.unwrap();

        assert!(!d.join(".cargo-checksum.json").exists());
        assert!(!d.join("sub/.cargo-checksum.json").exists());
        assert!(d.join("sub/keep.rs").exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn skips_symlinks() {
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        let d = dst.path().join("copy");
        fs::write(src.path().join("real.txt"), b"x").unwrap();
        std::os::unix::fs::symlink("real.txt", src.path().join("link.txt")).unwrap();
        // symlink to outside dir
        std::os::unix::fs::symlink("/etc/passwd", src.path().join("escape")).unwrap();

        fresh_copy(src.path(), &d, None).await.unwrap();

        assert!(d.join("real.txt").exists());
        assert!(!d.join("link.txt").exists(), "symlink should be skipped");
        assert!(!d.join("escape").exists(), "escaping symlink should be skipped");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn remove_tree_handles_readonly_files_and_dirs() {
        let base = tempfile::tempdir().unwrap();
        let root = base.path().join("tree");
        fs::create_dir_all(root.join("ro_dir/inner")).unwrap();
        fs::write(root.join("ro_dir/inner/f.txt"), b"x").unwrap();
        fs::write(root.join("ro_dir/g.txt"), b"y").unwrap();
        // Make files read-only then dirs read-only (bottom-up).
        fs::set_permissions(root.join("ro_dir/inner/f.txt"), fs::Permissions::from_mode(0o444)).unwrap();
        fs::set_permissions(root.join("ro_dir/g.txt"), fs::Permissions::from_mode(0o444)).unwrap();
        fs::set_permissions(root.join("ro_dir/inner"), fs::Permissions::from_mode(0o555)).unwrap();
        fs::set_permissions(root.join("ro_dir"), fs::Permissions::from_mode(0o555)).unwrap();

        remove_tree(&root).await.unwrap();
        assert!(!root.exists(), "read-only tree should be fully removed");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn remove_tree_handles_no_execute_dirs() {
        let base = tempfile::tempdir().unwrap();
        let root = base.path().join("tree");
        fs::create_dir_all(root.join("d")).unwrap();
        fs::write(root.join("d/f.txt"), b"x").unwrap();
        // 0o444: read but NO execute -> cannot descend without relax
        fs::set_permissions(root.join("d"), fs::Permissions::from_mode(0o444)).unwrap();

        remove_tree(&root).await.unwrap();
        assert!(!root.exists(), "no-execute dir tree should be removed");
    }

    #[tokio::test]
    async fn fresh_copy_overwrites_existing_dst() {
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        let d = dst.path().join("copy");
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join("stale.txt"), b"old").unwrap();
        fs::write(src.path().join("new.txt"), b"new").unwrap();

        fresh_copy(src.path(), &d, None).await.unwrap();

        assert!(!d.join("stale.txt").exists(), "stale file should be gone");
        assert!(d.join("new.txt").exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn fresh_copy_dirs_are_writable_even_from_readonly_source() {
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        let d = dst.path().join("copy");
        fs::create_dir_all(src.path().join("ro")).unwrap();
        fs::write(src.path().join("ro/f.txt"), b"x").unwrap();
        fs::set_permissions(src.path().join("ro/f.txt"), fs::Permissions::from_mode(0o444)).unwrap();
        fs::set_permissions(src.path().join("ro"), fs::Permissions::from_mode(0o555)).unwrap();

        fresh_copy(src.path(), &d, None).await.unwrap();

        let dir_mode = fs::metadata(d.join("ro")).unwrap().permissions().mode() & 0o777;
        assert!(dir_mode & 0o200 != 0, "copied dir should be writable, got {:o}", dir_mode);
        // cleanup readonly src
        fs::set_permissions(src.path().join("ro"), fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn remove_tree_does_not_follow_symlink_out_of_tree() {
        // Safety: removing a tree must never delete the symlink *target*.
        let base = tempfile::tempdir().unwrap();
        let outside = base.path().join("outside.txt");
        fs::write(&outside, b"precious").unwrap();
        let root = base.path().join("tree");
        fs::create_dir_all(&root).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();

        remove_tree(&root).await.unwrap();
        assert!(!root.exists());
        assert!(outside.exists(), "symlink target outside tree must survive");
        assert_eq!(fs::read(&outside).unwrap(), b"precious");
    }

    /// Regression: the perm-relax retry in [`force_remove_dir_all`] must not
    /// chmod *through* a symlink. `set_permissions` follows links, so a symlink
    /// entry would silently mutate its target's mode — which can live outside
    /// the tree. (Copy trees are symlink-free today, but this is a general
    /// pub(crate) helper and the safety property must hold regardless.)
    #[cfg(unix)]
    #[tokio::test]
    async fn relax_loop_must_not_chmod_external_symlink_target() {
        let base = tempfile::tempdir().unwrap();
        // An external precious file with restrictive perms.
        let outside = base.path().join("secret.txt");
        fs::write(&outside, b"secret").unwrap();
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o600)).unwrap();

        // A tree whose FIRST remove_dir_all will FAIL (read-only dir) so the
        // perm-relax retry path runs, and which contains a symlink to `outside`.
        let root = base.path().join("tree");
        fs::create_dir_all(&root).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();
        fs::write(root.join("f.txt"), b"x").unwrap();
        fs::set_permissions(root.join("f.txt"), fs::Permissions::from_mode(0o444)).unwrap();
        // Read-only (no write) dir -> first remove_dir_all fails -> relax runs.
        fs::set_permissions(&root, fs::Permissions::from_mode(0o555)).unwrap();

        remove_tree(&root).await.unwrap();

        let mode = fs::metadata(&outside).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "external symlink target perms were changed to {:o}", mode);
        assert!(outside.exists());
    }
}

