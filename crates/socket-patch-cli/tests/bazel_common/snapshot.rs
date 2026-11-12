//! A whole tree as a map, taken before and after a run.

use std::collections::BTreeMap;
use std::path::Path;

/// One entry of a tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    File(Vec<u8>),
    /// Recorded so that a leftover empty directory fails a rollback check.
    Dir,
    /// The link's target as written. Links are never followed: Bazel's
    /// convenience links point into the output base, which is not the
    /// workspace and may be gigabytes.
    Link(String),
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
        let kind = std::fs::symlink_metadata(&path).unwrap().file_type();
        if kind.is_symlink() {
            let target = std::fs::read_link(&path).unwrap();
            out.insert(child, Entry::Link(target.to_string_lossy().into_owned()));
        } else if kind.is_dir() {
            walk(&path, &child, out);
            out.insert(child, Entry::Dir);
        } else {
            out.insert(child, Entry::File(std::fs::read(&path).unwrap()));
        }
    }
}

/// What happened to one path between two snapshots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    Created,
    Removed,
    Modified,
}

/// Every path whose entry differs, in path order.
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

/// Byte-exact equality of two trees: what a rollback must restore. The
/// message lists paths, not contents.
pub fn assert_same_tree(before: &Snapshot, after: &Snapshot) {
    let diff = changes(before, after);
    assert!(diff.is_empty(), "the tree is not byte-identical: {diff:?}");
}
