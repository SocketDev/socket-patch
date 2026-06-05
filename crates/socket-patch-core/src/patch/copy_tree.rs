//! Shared tree-copy helpers for the project-local redirect backends — the
//! cargo `[patch]`-redirect ([`crate::patch::cargo_redirect`]) and the Go
//! `replace`-redirect ([`crate::patch::go_redirect`]). Both materialise a
//! project-local **patched copy** of a package by copying its pristine source
//! out of a read-only registry/module cache into a writable dir under
//! `.socket/`, then patching the copy in place.
//!
//! Only compiled when a redirect backend is enabled.
#![cfg(any(feature = "cargo", feature = "golang"))]

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
                    let mode = if entry.file_type().is_dir() {
                        0o755
                    } else {
                        0o644
                    };
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
