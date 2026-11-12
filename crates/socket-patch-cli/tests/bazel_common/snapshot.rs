//! A whole tree as a map, taken before and after a run.

use std::collections::BTreeMap;
use std::path::Path;

/// One entry of a tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    /// A file's bytes and its permission bits: `st_mode & 0o7777` on Unix;
    /// elsewhere 1 for a read-only file and 0 for any other. A write by
    /// stage and rename swaps in a new inode, so it can drop the
    /// executable bit or reset a private 0600 file to 0644 with the bytes
    /// unchanged.
    File { bytes: Vec<u8>, mode: u32 },
    /// Recorded so that a leftover empty directory fails a rollback check.
    Dir,
    /// The link's target as written. Links are never followed: Bazel's
    /// convenience links point into the output base, which is not the
    /// workspace and may be gigabytes.
    Link(String),
}

impl Entry {
    /// The mode of an ordinary writable file.
    pub const PLAIN: u32 = if cfg!(unix) { 0o644 } else { 0 };

    /// An ordinary writable file, for a tree built in memory.
    pub fn file(bytes: impl Into<Vec<u8>>) -> Self {
        Self::File {
            bytes: bytes.into(),
            mode: Self::PLAIN,
        }
    }
}

/// `/`-joined path relative to the root -> entry.
pub type Snapshot = BTreeMap<String, Entry>;

/// Every file, directory and link under `root`, except `.git`: git
/// rewrites its own index whenever a test asks it for status.
pub fn snapshot(root: &Path) -> Snapshot {
    let mut out = Snapshot::new();
    walk(root, "", &mut out);
    out
}

fn walk(dir: &Path, rel: &str, out: &mut Snapshot) {
    for entry in std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display())) {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == ".git" {
            continue;
        }
        let path = entry.path();
        let child = if rel.is_empty() {
            name
        } else {
            format!("{rel}/{name}")
        };
        // `symlink_metadata`, so a link (or a Windows junction, which Rust
        // reports as one) is recorded and not entered.
        let meta = std::fs::symlink_metadata(&path).unwrap();
        if meta.file_type().is_symlink() {
            let target = std::fs::read_link(&path).unwrap();
            out.insert(child, Entry::Link(target.to_string_lossy().into_owned()));
        } else if meta.is_dir() {
            walk(&path, &child, out);
            out.insert(child, Entry::Dir);
        } else {
            let bytes = std::fs::read(&path).unwrap();
            let mode = mode_of(&meta);
            out.insert(child, Entry::File { bytes, mode });
        }
    }
}

#[cfg(unix)]
fn mode_of(meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o7777
}

#[cfg(not(unix))]
fn mode_of(meta: &std::fs::Metadata) -> u32 {
    u32::from(meta.permissions().readonly())
}

/// What happened to one path between two snapshots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    Created,
    Removed,
    Modified,
}

/// Every path whose entry differs, in path order. A file whose mode alone
/// changed is `Modified`.
pub fn changes(before: &Snapshot, after: &Snapshot) -> Vec<(String, Change)> {
    let mut out: Vec<(String, Change)> = Vec::new();
    for (path, old) in before {
        match after.get(path) {
            None => out.push((path.clone(), Change::Removed)),
            Some(new) if new != old => out.push((path.clone(), Change::Modified)),
            Some(_) => {}
        }
    }
    let created = after.keys().filter(|path| !before.contains_key(*path));
    out.extend(created.map(|path| (path.clone(), Change::Created)));
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// Byte-exact equality of two trees, modes included: what a rollback must
/// restore. The message lists paths, not contents.
pub fn assert_same_tree(before: &Snapshot, after: &Snapshot) {
    let diff = changes(before, after);
    assert!(diff.is_empty(), "the tree is not byte-identical: {diff:?}");
}

/// The file Bazel 7 and later write into a workspace that has no
/// `MODULE.bazel`, on the first build or query (399 bytes, sha256
/// `0e3e315145ac7ee7...`; the same bytes on 7.7.2, 8.8.2, 9.3.2 and
/// 10.0.0rc3).
pub const PLACEHOLDER_MODULE_BAZEL: &str = "\
###############################################################################
# Bazel now uses Bzlmod by default to manage external dependencies.
# Please consider migrating your external dependencies from WORKSPACE to MODULE.bazel.
#
# For more details, please check https://github.com/bazelbuild/bazel/issues/18958
###############################################################################
";

/// A convenience link, whatever `--symlink_prefix` named it: all four
/// point into `<output base>/execroot`.
fn convenience_link(entry: &Entry) -> bool {
    matches!(entry, Entry::Link(target) if target.split(['/', '\\']).any(|s| s == "execroot"))
}

/// `tree` without what Bazel itself writes into a workspace it builds
/// (design 9.3, step 4): `MODULE.bazel.lock`, the convenience links (and a
/// `--symlink_prefix=dist/` directory that holds nothing else), and the
/// placeholder `MODULE.bazel` of a WORKSPACE-only workspace.
pub fn without_bazel_owned(tree: &Snapshot) -> Snapshot {
    let owned = |path: &str, entry: &Entry| {
        let leaf = path.rsplit('/').next().unwrap_or(path);
        let placeholder = matches!(entry, Entry::File { bytes, .. }
            if leaf == "MODULE.bazel" && bytes == PLACEHOLDER_MODULE_BAZEL.as_bytes());
        leaf == "MODULE.bazel.lock" || placeholder || convenience_link(entry)
    };
    let mut out: Snapshot = tree
        .iter()
        .filter(|(path, entry)| !owned(path, entry))
        .map(|(path, entry)| (path.clone(), entry.clone()))
        .collect();
    let links = tree.iter().filter(|(_, entry)| convenience_link(entry));
    for (dir, _) in links.filter_map(|(path, _)| path.rsplit_once('/')) {
        if !out.keys().any(|path| path.starts_with(&format!("{dir}/"))) {
            out.remove(dir);
        }
    }
    out
}

/// [`assert_same_tree`] for a comparison made after Bazel ran in either
/// tree. Bazel rewrites its own files on every build, so they are left out
/// of both sides; a test that needs the lock equal asserts that itself,
/// after `bazel shutdown`.
pub fn assert_same_tree_but_bazel_owned(before: &Snapshot, after: &Snapshot) {
    assert_same_tree(&without_bazel_owned(before), &without_bazel_owned(after));
}
