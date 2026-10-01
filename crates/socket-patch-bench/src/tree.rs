//! Restore a fixture between runs without re-copying it.
//!
//! A wet scan rewrites lockfiles and configs, so every timed run must start
//! from the pristine fixture. Copying a few-thousand-package `node_modules`
//! per run would dominate the job, so the work tree is compared against a
//! metadata snapshot instead and only the entries a run added, removed or
//! modified are put back from the pristine copy. The check covers the
//! whole tree, installed packages included: a run that unexpectedly writes
//! into `node_modules` is still undone before the next one.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Kind {
    Dir,
    File { len: u64, mtime: Option<SystemTime> },
    Symlink(PathBuf),
}

/// Every entry under a root, keyed by its path relative to that root.
#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    entries: BTreeMap<PathBuf, Kind>,
}

impl Snapshot {
    pub fn take(root: &Path) -> io::Result<Self> {
        let mut entries = BTreeMap::new();
        walk(root, Path::new(""), &mut entries)?;
        Ok(Self { entries })
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

fn walk(root: &Path, rel: &Path, out: &mut BTreeMap<PathBuf, Kind>) -> io::Result<()> {
    for entry in std::fs::read_dir(root.join(rel))? {
        let entry = entry?;
        let rel = rel.join(entry.file_name());
        let ty = entry.file_type()?;
        if ty.is_symlink() {
            out.insert(
                rel.clone(),
                Kind::Symlink(std::fs::read_link(entry.path())?),
            );
        } else if ty.is_dir() {
            out.insert(rel.clone(), Kind::Dir);
            walk(root, &rel, out)?;
        } else {
            let meta = entry.metadata()?;
            out.insert(
                rel,
                Kind::File {
                    len: meta.len(),
                    mtime: meta.modified().ok(),
                },
            );
        }
    }
    Ok(())
}

/// What one restore had to undo.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Drift {
    pub added: Vec<PathBuf>,
    pub removed: Vec<PathBuf>,
    pub modified: Vec<PathBuf>,
}

impl Drift {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.modified.is_empty()
    }

    /// Every path the run touched, sorted.
    pub fn touched(&self) -> Vec<PathBuf> {
        let mut all: Vec<PathBuf> = self
            .added
            .iter()
            .chain(&self.removed)
            .chain(&self.modified)
            .cloned()
            .collect();
        all.sort();
        all
    }
}

/// Bring `work` back to `pristine` (whose layout `snapshot` recorded for
/// `work` right after the last restore) and return what had drifted. The
/// snapshot is updated to the restored state.
pub fn restore(work: &Path, pristine: &Path, snapshot: &mut Snapshot) -> io::Result<Drift> {
    let now = Snapshot::take(work)?;
    let mut drift = Drift::default();

    // Remove what the run added (deepest first, so a new directory's
    // contents go before it) and what it turned into another kind.
    for (rel, kind) in now.entries.iter().rev() {
        match snapshot.entries.get(rel) {
            None => {
                drift.added.push(rel.clone());
                remove(&work.join(rel), kind)?;
            }
            Some(old) if std::mem::discriminant(old) != std::mem::discriminant(kind) => {
                drift.modified.push(rel.clone());
                remove(&work.join(rel), kind)?;
            }
            _ => {}
        }
    }
    // Put back what is missing or changed (shallowest first).
    for (rel, old) in &snapshot.entries {
        let current = now.entries.get(rel);
        let same_kind =
            current.is_some_and(|k| std::mem::discriminant(k) == std::mem::discriminant(old));
        let changed = match (old, current) {
            (_, None) => {
                drift.removed.push(rel.clone());
                true
            }
            _ if !same_kind => true, // already counted and removed above
            (Kind::Dir, _) => false,
            (old, Some(cur)) if old != cur => {
                drift.modified.push(rel.clone());
                true
            }
            _ => false,
        };
        if changed {
            copy_entry(&pristine.join(rel), &work.join(rel), old)?;
        }
    }
    drift.added.sort();
    drift.removed.sort();
    drift.modified.sort();
    drift.modified.dedup();
    if !drift.is_empty() {
        *snapshot = Snapshot::take(work)?;
    }
    Ok(drift)
}

fn remove(path: &Path, kind: &Kind) -> io::Result<()> {
    let result = match kind {
        Kind::Dir => std::fs::remove_dir_all(path),
        Kind::File { .. } | Kind::Symlink(_) => std::fs::remove_file(path),
    };
    match result {
        // A parent removed earlier took it already.
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

fn copy_entry(from: &Path, to: &Path, kind: &Kind) -> io::Result<()> {
    if let Some(parent) = to.parent() {
        std::fs::create_dir_all(parent)?;
    }
    match kind {
        Kind::Dir => std::fs::create_dir_all(to),
        Kind::File { .. } => {
            // Replace, never write through: the run may have left a
            // hardlink to the pristine copy.
            let _ = std::fs::remove_file(to);
            std::fs::copy(from, to).map(|_| ())
        }
        Kind::Symlink(target) => {
            let _ = std::fs::remove_file(to);
            symlink(target, to)
        }
    }
}

#[cfg(unix)]
pub fn symlink(target: &Path, link: &Path) -> io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(windows)]
pub fn symlink(target: &Path, link: &Path) -> io::Result<()> {
    std::os::windows::fs::symlink_dir(target, link)
}

/// Recursively copy `from` to `to` (symlinks are recreated, not followed).
pub fn copy_tree(from: &Path, to: &Path) -> io::Result<()> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let src = entry.path();
        let dst = to.join(entry.file_name());
        let ty = entry.file_type()?;
        if ty.is_symlink() {
            symlink(&std::fs::read_link(&src)?, &dst)?;
        } else if ty.is_dir() {
            copy_tree(&src, &dst)?;
        } else {
            std::fs::copy(&src, &dst)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(root: &Path, rel: &str, body: &str) {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, body).unwrap();
    }

    #[test]
    fn restore_undoes_adds_removes_and_edits() {
        let tmp = tempfile::tempdir().unwrap();
        let pristine = tmp.path().join("pristine");
        let work = tmp.path().join("work");
        write(&pristine, "package-lock.json", "{}");
        write(&pristine, "node_modules/a/package.json", "a");
        write(&pristine, "node_modules/b/package.json", "b");
        copy_tree(&pristine, &work).unwrap();
        let mut snap = Snapshot::take(&work).unwrap();
        assert_eq!(snap.len(), 6);

        // Nothing changed: nothing to do.
        assert!(restore(&work, &pristine, &mut snap).unwrap().is_empty());

        std::fs::write(work.join("package-lock.json"), "{\"rewritten\":true}").unwrap();
        write(&work, ".npmrc", "allow-remote=all\n");
        write(&work, ".socket/state/x.json", "{}");
        std::fs::remove_dir_all(work.join("node_modules/b")).unwrap();

        let drift = restore(&work, &pristine, &mut snap).unwrap();
        assert_eq!(
            drift.added,
            vec![
                PathBuf::from(".npmrc"),
                PathBuf::from(".socket"),
                PathBuf::from(".socket/state"),
                PathBuf::from(".socket/state/x.json"),
            ]
        );
        assert_eq!(
            drift.removed,
            vec![
                PathBuf::from("node_modules/b"),
                PathBuf::from("node_modules/b/package.json"),
            ]
        );
        assert_eq!(drift.modified, vec![PathBuf::from("package-lock.json")]);

        assert_eq!(
            std::fs::read_to_string(work.join("package-lock.json")).unwrap(),
            "{}"
        );
        assert_eq!(
            std::fs::read_to_string(work.join("node_modules/b/package.json")).unwrap(),
            "b"
        );
        assert!(!work.join(".npmrc").exists());
        assert!(!work.join(".socket").exists());
        // And the refreshed snapshot sees a clean tree.
        assert!(restore(&work, &pristine, &mut snap).unwrap().is_empty());
    }

    #[test]
    fn restore_handles_a_file_replaced_by_a_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let pristine = tmp.path().join("pristine");
        let work = tmp.path().join("work");
        write(&pristine, "x", "file");
        copy_tree(&pristine, &work).unwrap();
        let mut snap = Snapshot::take(&work).unwrap();
        std::fs::remove_file(work.join("x")).unwrap();
        write(&work, "x/inner", "dir now");
        let drift = restore(&work, &pristine, &mut snap).unwrap();
        assert!(drift.added.contains(&PathBuf::from("x/inner")));
        assert_eq!(std::fs::read_to_string(work.join("x")).unwrap(), "file");
    }
}
