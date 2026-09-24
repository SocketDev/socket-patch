//! Shared tree-copy helpers used by the Go `replace`-redirect backend
//! ([`crate::patch::redirect::golang_local`]) and the vendor backends. They materialise a
//! project-local **patched copy** of a package by copying its pristine source
//! out of a read-only registry/module cache into a writable dir under
//! `.socket/`, then patching the copy in place.

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
    tokio::task::spawn_blocking(move || copy_tree_blocking(&src, &dst, skip_file_name))
        .await
        .map_err(to_io)?
}

/// The body of [`fresh_copy`].
///
/// WalkDir yields a directory before its contents, and every copied
/// directory is created when it is yielded, so a file's parent already
/// exists — except under a directory whose name matched `skip_file_name`:
/// the skip is not pruned, so its contents are still copied and must create
/// the skipped directory on demand (it then exists in the copy only when it
/// has contents, as it always has).
fn copy_tree_blocking(
    src: &Path,
    dst: &Path,
    skip_file_name: Option<&'static str>,
) -> std::io::Result<()> {
    force_remove_dir_all(dst)?;
    std::fs::create_dir_all(dst)?;
    // Depth of the outermost skipped directory the walk is inside.
    let mut skipped_dir_depth: Option<usize> = None;
    for entry in walkdir::WalkDir::new(src).follow_links(false) {
        let entry = entry.map_err(to_io)?;
        let rel = entry.path().strip_prefix(src).map_err(to_io)?;
        if rel.as_os_str().is_empty() {
            continue;
        }
        if skipped_dir_depth.is_some_and(|depth| entry.depth() <= depth) {
            skipped_dir_depth = None;
        }
        let ft = entry.file_type();
        if let Some(skip) = skip_file_name {
            if entry.file_name() == skip {
                if ft.is_dir() && skipped_dir_depth.is_none() {
                    skipped_dir_depth = Some(entry.depth());
                }
                continue;
            }
        }
        let target = dst.join(rel);
        if ft.is_dir() {
            std::fs::create_dir_all(&target)?;
        } else if ft.is_file() {
            if skipped_dir_depth.is_some() {
                if let Some(p) = target.parent() {
                    std::fs::create_dir_all(p)?;
                }
            }
            std::fs::copy(entry.path(), &target)?;
        }
    }
    Ok(())
}

/// The previous [`copy_tree_blocking`], which created every file's parent,
/// kept as the equivalence oracle.
#[cfg(test)]
fn copy_tree_blocking_reference(
    src: &Path,
    dst: &Path,
    skip_file_name: Option<&'static str>,
) -> std::io::Result<()> {
    force_remove_dir_all(dst)?;
    std::fs::create_dir_all(dst)?;
    for entry in walkdir::WalkDir::new(src).follow_links(false) {
        let entry = entry.map_err(to_io)?;
        let rel = entry.path().strip_prefix(src).map_err(to_io)?;
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
}

/// Recursively remove a tree, retrying once after relaxing *directory* perms
/// (a previously patched copy may carry read-only dir modes copied from the
/// registry/cache; on unix file modes never gate unlinking).
fn force_remove_dir_all(dir: &Path) -> std::io::Result<()> {
    match std::fs::remove_dir_all(dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                // `follow_root_links` defaults to true: a symlink *at* `dir`
                // would otherwise be followed and the external target tree
                // chmod'd. Disabled, a symlink root is yielded as a symlink
                // and hits the skip below.
                for entry in walkdir::WalkDir::new(dir)
                    .follow_root_links(false)
                    .into_iter()
                    .flatten()
                {
                    // Only directory modes gate removal on unix: unlinking an
                    // entry needs write+execute on its (relaxed) parent dir,
                    // never a mode on the entry itself. Never chmod anything
                    // else: `set_permissions` follows a symlink and would
                    // mutate its *target's* mode, and a regular file may be a
                    // hard link to an inode outside the tree — chmod'ing it
                    // mutates that shared inode. (Links aren't followed, so a
                    // symlinked dir reports !is_dir and is skipped too.)
                    if !entry.file_type().is_dir() {
                        continue;
                    }
                    let _ = std::fs::set_permissions(
                        entry.path(),
                        std::fs::Permissions::from_mode(0o755),
                    );
                }
            }
            std::fs::remove_dir_all(dir)
        }
    }
}

/// Async wrapper over [`force_remove_dir_all`].
pub async fn remove_tree(dir: &Path) -> std::io::Result<()> {
    let dir = dir.to_path_buf();
    tokio::task::spawn_blocking(move || force_remove_dir_all(&dir))
        .await
        .map_err(to_io)?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    /// Every entry under `root` as (relative path, kind, bytes, mode), in
    /// sorted walk order.
    fn tree_snapshot(root: &Path) -> Vec<(String, &'static str, Vec<u8>, u32)> {
        walkdir::WalkDir::new(root)
            .follow_links(false)
            .sort_by_file_name()
            .into_iter()
            .map(|e| {
                let e = e.unwrap();
                let rel = e
                    .path()
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();
                let meta = e.path().symlink_metadata().unwrap();
                #[cfg(unix)]
                let mode = meta.permissions().mode();
                #[cfg(not(unix))]
                let mode = u32::from(meta.permissions().readonly());
                if meta.is_dir() {
                    (rel, "dir", Vec::new(), mode)
                } else if meta.is_file() {
                    (rel, "file", fs::read(e.path()).unwrap(), mode)
                } else {
                    (rel, "other", Vec::new(), mode)
                }
            })
            .collect()
    }

    /// Deterministic xorshift64* — no `rand` dev-dependency.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
    }

    const SKIP: &str = ".cargo-checksum.json";

    /// A random tree under `dir`: nested and empty dirs, files (some
    /// read-only, some named [`SKIP`]), directories named [`SKIP`] holding
    /// files and subdirectories, and (unix) file and dir symlinks.
    fn synth_tree(rng: &mut Rng, dir: &Path, depth: usize) {
        for i in 0..rng.below(6) {
            let name = match rng.below(8) {
                0 => SKIP.to_string(),
                _ => format!("e{i}"),
            };
            let path = dir.join(&name);
            if path.symlink_metadata().is_ok() {
                continue; // a second [`SKIP`] in this directory
            }
            match rng.below(6) {
                0 | 1 if depth < 4 => {
                    fs::create_dir(&path).unwrap();
                    synth_tree(rng, &path, depth + 1);
                }
                #[cfg(unix)]
                2 => {
                    let target = if rng.below(2) == 0 { "e0" } else { ".." };
                    std::os::unix::fs::symlink(target, &path).unwrap();
                }
                _ => {
                    fs::write(&path, format!("{name}:{}", rng.next())).unwrap();
                    #[cfg(unix)]
                    if rng.below(3) == 0 {
                        fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();
                    }
                }
            }
        }
    }

    #[test]
    fn copy_matches_reference_on_random_trees() {
        let mut rng = Rng(0x94D0_49BB_1331_11EB);
        for case in 0..150 {
            let src = tempfile::tempdir().unwrap();
            synth_tree(&mut rng, src.path(), 0);
            let out = tempfile::tempdir().unwrap();
            for skip in [None, Some(SKIP)] {
                let (want, got) = (out.path().join("want"), out.path().join("got"));
                let want_result = copy_tree_blocking_reference(src.path(), &want, skip);
                let got_result = copy_tree_blocking(src.path(), &got, skip);
                assert_eq!(
                    got_result.as_ref().map_err(|e| e.kind()),
                    want_result.as_ref().map_err(|e| e.kind()),
                    "case {case} skip={skip:?}: result"
                );
                assert_eq!(
                    tree_snapshot(&got),
                    tree_snapshot(&want),
                    "case {case} skip={skip:?}: copied tree"
                );
            }
        }
    }

    /// The one shape where a file's parent is not created by the walk: a
    /// directory named like the skipped file. Its contents are copied and
    /// recreate it; an empty one stays absent.
    #[tokio::test]
    async fn skipped_name_directory_contents_are_still_copied() {
        let src = tempfile::tempdir().unwrap();
        let dst = tempfile::tempdir().unwrap();
        let d = dst.path().join("copy");
        fs::create_dir_all(src.path().join("a").join(SKIP).join("deep")).unwrap();
        fs::write(src.path().join("a").join(SKIP).join("f.txt"), b"f").unwrap();
        fs::write(src.path().join("a").join(SKIP).join("deep/g.txt"), b"g").unwrap();
        fs::create_dir_all(src.path().join("b").join(SKIP)).unwrap();
        fs::write(src.path().join("b/after.txt"), b"after").unwrap();

        fresh_copy(src.path(), &d, Some(SKIP)).await.unwrap();

        assert_eq!(
            fs::read(d.join("a").join(SKIP).join("f.txt")).unwrap(),
            b"f"
        );
        assert_eq!(
            fs::read(d.join("a").join(SKIP).join("deep/g.txt")).unwrap(),
            b"g"
        );
        assert!(!d.join("b").join(SKIP).exists());
        assert_eq!(fs::read(d.join("b/after.txt")).unwrap(), b"after");
        let reference = dst.path().join("reference");
        copy_tree_blocking_reference(src.path(), &reference, Some(SKIP)).unwrap();
        assert_eq!(tree_snapshot(&d), tree_snapshot(&reference));
    }

    /// A skip-named directory holding only plain files: nothing the walk
    /// yields creates it, so each file must create it on demand, whatever
    /// the readdir order.
    #[test]
    fn skipped_name_directory_with_only_files_is_created_on_demand() {
        let src = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        fs::create_dir_all(src.path().join("c").join(SKIP)).unwrap();
        for i in 0..8 {
            fs::write(
                src.path().join("c").join(SKIP).join(format!("f{i}.txt")),
                [i],
            )
            .unwrap();
        }
        let d = out.path().join("copy");
        copy_tree_blocking(src.path(), &d, Some(SKIP)).unwrap();
        for i in 0..8u8 {
            assert_eq!(
                fs::read(d.join("c").join(SKIP).join(format!("f{i}.txt"))).unwrap(),
                [i]
            );
        }
        let reference = out.path().join("reference");
        copy_tree_blocking_reference(src.path(), &reference, Some(SKIP)).unwrap();
        assert_eq!(tree_snapshot(&d), tree_snapshot(&reference));
    }

    /// A skip-named directory nested in another keeps the OUTER depth: were
    /// the inner one to take over, leaving it (at a sibling file of the
    /// outer's contents) would end the on-demand parent creation while
    /// still inside the outer. Many small trees with different sibling
    /// names, so some readdir order yields the inner directory first.
    #[test]
    fn nested_skipped_name_directory_keeps_the_outer_depth() {
        let out = tempfile::tempdir().unwrap();
        for variant in 0..64 {
            let files = 1 + variant % 3;
            let src = tempfile::tempdir().unwrap();
            let outer = src.path().join(SKIP);
            fs::create_dir_all(outer.join(SKIP)).unwrap();
            for i in 0..files {
                fs::write(outer.join(format!("v{variant}-{i}")), format!("{i}")).unwrap();
            }
            let (want, got) = (out.path().join("want"), out.path().join("got"));
            let want_result = copy_tree_blocking_reference(src.path(), &want, Some(SKIP));
            let got_result = copy_tree_blocking(src.path(), &got, Some(SKIP));
            assert_eq!(
                got_result.as_ref().map_err(|e| e.kind()),
                want_result.as_ref().map_err(|e| e.kind()),
                "variant {variant}: result"
            );
            assert!(want_result.is_ok(), "variant {variant}");
            assert_eq!(
                tree_snapshot(&got),
                tree_snapshot(&want),
                "variant {variant}"
            );
            assert_eq!(fs::read_dir(got.join(SKIP)).unwrap().count(), files);
        }
    }

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

        fresh_copy(src.path(), &d, Some(".cargo-checksum.json"))
            .await
            .unwrap();

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
        assert!(
            !d.join("escape").exists(),
            "escaping symlink should be skipped"
        );
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
        fs::set_permissions(
            root.join("ro_dir/inner/f.txt"),
            fs::Permissions::from_mode(0o444),
        )
        .unwrap();
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
        fs::set_permissions(
            src.path().join("ro/f.txt"),
            fs::Permissions::from_mode(0o444),
        )
        .unwrap();
        fs::set_permissions(src.path().join("ro"), fs::Permissions::from_mode(0o555)).unwrap();

        fresh_copy(src.path(), &d, None).await.unwrap();

        let dir_mode = fs::metadata(d.join("ro")).unwrap().permissions().mode() & 0o777;
        assert!(
            dir_mode & 0o200 != 0,
            "copied dir should be writable, got {:o}",
            dir_mode
        );
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
    /// the tree. (Copy trees are symlink-free today, but [`remove_tree`] is a
    /// general pub helper and the safety property must hold regardless.)
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
        assert_eq!(
            mode, 0o600,
            "external symlink target perms were changed to {:o}",
            mode
        );
        assert!(outside.exists());
    }

    /// Regression: the perm-relax retry must not chmod regular files at all.
    /// On unix, unlinking needs write on the *parent dir*, never a mode on the
    /// file itself — so the file chmod had no benefit, and a file inside the
    /// tree may be a *hard link* to an inode outside it (dedupe tools,
    /// store-linked installs; vendored copies live in the user's project
    /// indefinitely). chmod'ing it mutates the shared inode's mode
    /// (0o600 secret → 0o644 world-readable).
    #[cfg(unix)]
    #[tokio::test]
    async fn relax_loop_must_not_chmod_hardlinked_external_inode() {
        let base = tempfile::tempdir().unwrap();
        // An external precious file with restrictive perms.
        let outside = base.path().join("secret.txt");
        fs::write(&outside, b"secret").unwrap();
        fs::set_permissions(&outside, fs::Permissions::from_mode(0o600)).unwrap();

        // A tree whose FIRST remove_dir_all will FAIL (read-only dir) so the
        // perm-relax retry runs, containing a HARD link to `outside`.
        let root = base.path().join("tree");
        fs::create_dir_all(&root).unwrap();
        fs::hard_link(&outside, root.join("link.txt")).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o555)).unwrap();

        remove_tree(&root).await.unwrap();

        assert!(!root.exists(), "tree should still be removed");
        let mode = fs::metadata(&outside).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "external hardlinked inode mode was changed to {:o}",
            mode
        );
        assert_eq!(fs::read(&outside).unwrap(), b"secret");
    }

    /// Regression: the perm-relax retry must not traverse *through* a
    /// symlinked root either. walkdir follows root symlinks by default
    /// (`follow_root_links`), so if the tree path itself is a symlink and the
    /// first remove fails (e.g. its parent dir is unwritable), the relax loop
    /// would descend into the external target and chmod everything in it to
    /// 0o755/0o644 — mutating a tree entirely outside `.socket/`.
    #[cfg(unix)]
    #[tokio::test]
    async fn relax_loop_must_not_traverse_symlinked_root() {
        let base = tempfile::tempdir().unwrap();
        // External target tree with restrictive perms.
        let target = base.path().join("target");
        fs::create_dir_all(&target).unwrap();
        fs::write(target.join("secret.txt"), b"secret").unwrap();
        fs::set_permissions(target.join("secret.txt"), fs::Permissions::from_mode(0o600)).unwrap();

        // Symlink at the tree path; read-only parent so the first
        // remove_dir_all (an unlink of the symlink) fails and the relax
        // retry path runs.
        let parent = base.path().join("parent");
        fs::create_dir_all(&parent).unwrap();
        let root = parent.join("tree");
        std::os::unix::fs::symlink(&target, &root).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o555)).unwrap();

        let result = remove_tree(&root).await;

        // Restore parent so tempdir cleanup works.
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o755)).unwrap();

        assert!(
            result.is_err(),
            "removal cannot succeed under a read-only parent"
        );
        let mode = fs::metadata(target.join("secret.txt"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o600,
            "file behind symlinked root was chmod'd to {:o}",
            mode
        );
        assert_eq!(fs::read(target.join("secret.txt")).unwrap(), b"secret");
    }
}
