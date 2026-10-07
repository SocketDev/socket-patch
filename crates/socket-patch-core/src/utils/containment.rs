//! The one containment rule for every write and delete socket-patch makes
//! in a tree it does not fully own.
//!
//! Two questions recur wherever socket-patch touches the disk:
//!
//! * **Is any level of this path a link?** ([`linked_level`]) socket-patch
//!   creates `.socket/` and everything under it itself and never writes a
//!   symlink or junction there. A linked level is therefore never its own:
//!   the target may be another project's `.socket/` (#887), another
//!   project's vendor store (#664) or a file outside the repository that a
//!   committed link points at (a planted `.socket/blobs/<hash>`). Writing
//!   or deleting through it reaches that other tree. Every writer and
//!   deleter of socket-patch state asks this before touching anything.
//! * **Does this directory really live inside the tree it was found in?**
//!   ([`resolves_within`]) An installed package is patched in place, so its
//!   directory must resolve inside the install tree the crawler found it
//!   under. A package directory that is a link out of that tree (a
//!   Composer path repository, a `flit install --symlink` package, a
//!   workspace member) is first-party source or a shared store, and a write
//!   would land there.
//!
//! Levels at or above `root` (the project path itself, `/tmp ->
//! /private/tmp`, a symlinked home directory) are the user's business and
//! are never checked.

use std::path::{Path, PathBuf};

/// The outermost level of `path` strictly below `root` that is a symlink or
/// a Windows junction (lstat), or `None`. `path` itself counts as a level;
/// `root` and its ancestors do not. A level that does not exist (yet) is
/// not a link, so a tree the caller is about to create passes. When `path`
/// is not below `root`, only `path` itself is checked.
pub fn linked_level(root: &Path, path: &Path) -> Option<PathBuf> {
    let levels: Vec<&Path> = if path.starts_with(root) && path != root {
        path.ancestors().take_while(|a| *a != root).collect()
    } else {
        vec![path]
    };
    levels
        .into_iter()
        .rev()
        .find(|level| is_link(level))
        .map(Path::to_path_buf)
}

/// Whether `path` is itself a symlink or a Windows junction (lstat; a
/// missing path is not).
pub fn is_link(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_symlink())
}

/// The refusal text for writing or deleting `what` through the linked
/// `link`. Every guarded writer and deleter shares it, so callers and tests
/// can match on [`LINKED_LEVEL_MARKER`].
pub fn linked_level_refusal(action: &str, what: &Path, link: &Path) -> std::io::Error {
    std::io::Error::other(format!(
        "refusing to {action} {}: {} {LINKED_LEVEL_MARKER}, and its target is not \
         socket-patch's to change",
        what.display(),
        link.display()
    ))
}

/// The substring every [`linked_level_refusal`] carries.
pub const LINKED_LEVEL_MARKER: &str = "is a symlink";

/// Err with [`linked_level_refusal`] when any level of `path` below `root`
/// is a link, before the caller writes or deletes anything.
pub fn ensure_unlinked(root: &Path, path: &Path, action: &str) -> std::io::Result<()> {
    match linked_level(root, path) {
        Some(link) => Err(linked_level_refusal(action, path, &link)),
        None => Ok(()),
    }
}

/// The nearest ancestor of `path` (inclusive) literally named `.socket`.
pub fn nearest_socket_dir(path: &Path) -> Option<&Path> {
    path.ancestors().find(|a| {
        a.file_name()
            .is_some_and(|n| n == crate::constants::SOCKET_DIR)
    })
}

/// The project root a path under `.socket/` belongs to: the parent of
/// [`nearest_socket_dir`]. `None` when `path` is not under a `.socket/`.
pub fn socket_project_root(path: &Path) -> Option<&Path> {
    nearest_socket_dir(path).and_then(Path::parent)
}

/// Whether `dir` really (canonically) lives inside `root`. Both must
/// exist; an unresolvable path is reported as contained, so the caller's
/// own missing-file handling runs instead of a spurious refusal.
pub fn resolves_within(root: &Path, dir: &Path) -> bool {
    match (std::fs::canonicalize(root), std::fs::canonicalize(dir)) {
        (Ok(root), Ok(dir)) => dir.starts_with(root),
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_and_missing_levels_are_not_links() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("p");
        std::fs::create_dir_all(p.join(".socket/vendor")).unwrap();
        assert_eq!(linked_level(&p, &p.join(".socket/vendor/npm/x")), None);
        assert_eq!(linked_level(&p, &p), None);
        assert!(ensure_unlinked(&p, &p.join(".socket/blobs/h"), "write").is_ok());
    }

    /// The outermost link wins, `.socket` itself counts (#887), and links
    /// at or above `root` are ignored.
    #[cfg(unix)]
    #[test]
    fn finds_the_outermost_link_below_root_only() {
        use std::os::unix::fs::symlink;
        let tmp = tempfile::tempdir().unwrap();
        let shared = tmp.path().join("shared");
        std::fs::create_dir_all(shared.join("vendor/npm")).unwrap();
        let real = tmp.path().join("real");
        std::fs::create_dir_all(&real).unwrap();
        symlink(&shared, real.join(".socket")).unwrap();
        symlink(&real, tmp.path().join("alias")).unwrap();

        let path = real.join(".socket/vendor/npm");
        assert_eq!(linked_level(&real, &path), Some(real.join(".socket")));
        let alias = tmp.path().join("alias");
        assert_eq!(
            linked_level(&alias, &alias.join(".socket/vendor")),
            Some(alias.join(".socket")),
            "the project path being a link is fine; .socket below it is not"
        );
        let err = ensure_unlinked(&real, &path, "delete").unwrap_err();
        assert!(err.to_string().contains(LINKED_LEVEL_MARKER), "{err}");

        // A leaf link counts too (a planted `.socket/blobs/<hash>`).
        let q = tmp.path().join("q");
        std::fs::create_dir_all(q.join(".socket/blobs")).unwrap();
        symlink(tmp.path().join("victim"), q.join(".socket/blobs/h")).unwrap();
        assert_eq!(
            linked_level(&q.join(".socket"), &q.join(".socket/blobs/h")),
            Some(q.join(".socket/blobs/h"))
        );
        // Not below root: only the path itself is checked.
        assert_eq!(linked_level(&tmp.path().join("elsewhere"), &path), None);
        assert!(is_link(&real.join(".socket")));
    }

    #[test]
    fn socket_project_root_is_the_parent_of_the_nearest_socket_dir() {
        let p = Path::new("/a/b/.socket/vendor/state.json");
        assert_eq!(socket_project_root(p), Some(Path::new("/a/b")));
        assert_eq!(
            socket_project_root(Path::new("/a/b/.socket")),
            Some(Path::new("/a/b"))
        );
        assert_eq!(socket_project_root(Path::new("/a/b/state.json")), None);
    }

    #[cfg(unix)]
    #[test]
    fn resolves_within_follows_links() {
        use std::os::unix::fs::symlink;
        let tmp = tempfile::tempdir().unwrap();
        let vendor = tmp.path().join("vendor/acme");
        let source = tmp.path().join("packages/pkg");
        std::fs::create_dir_all(&vendor).unwrap();
        std::fs::create_dir_all(&source).unwrap();
        symlink(&source, vendor.join("pkg")).unwrap();
        std::fs::create_dir_all(vendor.join("real")).unwrap();
        let root = tmp.path().join("vendor");
        assert!(!resolves_within(&root, &vendor.join("pkg")));
        assert!(resolves_within(&root, &vendor.join("real")));
        assert!(
            resolves_within(&root, &vendor.join("missing")),
            "unresolvable passes"
        );
    }
}
