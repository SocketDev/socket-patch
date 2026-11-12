//! The IO side of the workspace model (design 2.1, 2.2): one Bazel root
//! on disk behind the pure layer's [`FileView`], and the entry that reads
//! a root into a [`BazelWorkspace`].
//!
//! A [`DiskView`] is made per root and kept for the run. Every answer is
//! remembered, so the readers, the recognizers and later the gates of one
//! root read each file once, and a file that changes during the run is
//! seen as it first was. Nothing is read before somebody asks.
//!
//! What a view will not do:
//!
//! - leave the read boundary. A path with more leading `..` than the
//!   boundary allows, and a path that a link carries outside it, is
//!   `Unreadable` and cannot be listed. It is never `Absent`: socket-patch
//!   does not look there, so it cannot know;
//! - block. Files are opened through `read_regular_*`, so a FIFO planted
//!   in a checkout fails fast, and a directory of the name is `Unreadable`;
//! - read without bound. A file over [`MAX_FILE_BYTES`], and anything
//!   past [`MAX_TOTAL_BYTES`] for one root, is `Unreadable`, and a
//!   directory with more than [`MAX_LISTED`] entries cannot be listed.
//!
//! The calls block: run them where `crawlers::bazel_output` runs its own.

use std::collections::HashMap;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

use super::bazel_output::vendor_dirs_at;
use crate::bazel::model::{BazelWorkspace, CommittedVendorDirs, FileText, FileView, Gap, RootRef};
use crate::utils::fs::read_regular_to_bytes_sync;
use crate::utils::repo_root::ReadBoundary;

/// The largest file a view reads. The Starlark readers stop at 1 MiB by
/// themselves; this is for the locks, of which a `MODULE.bazel.lock` or a
/// monorepo's `pnpm-lock.yaml` runs to tens of megabytes.
pub const MAX_FILE_BYTES: u64 = 64 << 20;
/// The most one view reads in all: what it has read stays in memory.
pub const MAX_TOTAL_BYTES: u64 = 256 << 20;
/// How many entries of one directory are listed.
pub const MAX_LISTED: usize = 1 << 16;

#[derive(Default)]
struct Memo {
    reads: HashMap<String, FileText>,
    lists: HashMap<String, Option<Vec<String>>>,
    bytes_read: u64,
}

/// One Bazel root on disk, as the pure layer reads files.
pub struct DiskView {
    root: PathBuf,
    boundary: ReadBoundary,
    boundary_levels: usize,
    max_file_bytes: u64,
    memo: Mutex<Memo>,
}

/// Whether `err` says that nothing is there: a missing entry, or a parent
/// that is a file.
fn is_absent(err: &std::io::Error) -> bool {
    matches!(err.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory)
}

impl DiskView {
    /// A view of the root the probe found. Its read boundary lies
    /// `root.boundary_levels` directories above the root.
    pub fn new(root: &RootRef) -> Self {
        // The probe reports roots resolved; a caller's own path may not be.
        let resolved = std::fs::canonicalize(&root.root).unwrap_or_else(|_| root.root.clone());
        let top = resolved.ancestors().nth(root.boundary_levels);
        let top = top
            .or_else(|| resolved.ancestors().last())
            .unwrap_or(&resolved);
        Self {
            boundary: ReadBoundary::Workspace {
                root: top.to_path_buf(),
            },
            root: resolved,
            boundary_levels: root.boundary_levels,
            max_file_bytes: MAX_FILE_BYTES,
            memo: Mutex::default(),
        }
    }

    /// The root, resolved.
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn memo(&self) -> MutexGuard<'_, Memo> {
        self.memo.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The file a [`FileView`] path names, when the path is one this view
    /// follows: normalised, with `..` only in front and no more of them
    /// than the boundary allows, and resolving inside the boundary.
    fn locate(&self, rel: &str) -> Option<PathBuf> {
        let mut path = self.root.clone();
        let (mut above, mut below) = (0, false);
        for segment in rel.split('/').filter(|_| !rel.is_empty()) {
            match segment {
                ".." if !below => {
                    above += 1;
                    path.pop();
                }
                "" | "." | ".." => return None,
                name => {
                    below = true;
                    path.push(name);
                }
            }
        }
        (above <= self.boundary_levels && self.boundary.contains(&path)).then_some(path)
    }

    fn read_file(&self, path: &Path, bytes_read: &mut u64) -> FileText {
        let room = self
            .max_file_bytes
            .min(MAX_TOTAL_BYTES.saturating_sub(*bytes_read));
        // Asked first, so that a file over the cap is never loaded.
        if std::fs::metadata(path).is_ok_and(|meta| meta.is_file() && meta.len() > room) {
            return FileText::Unreadable;
        }
        match read_regular_to_bytes_sync(path) {
            Ok(bytes) if bytes.len() as u64 <= room => {
                *bytes_read += bytes.len() as u64;
                FileText::Bytes(bytes)
            }
            Ok(_) => FileText::Unreadable,
            Err(err) if is_absent(&err) => FileText::Absent,
            Err(_) => FileText::Unreadable,
        }
    }
}

/// The entries of `dir`: bare names, a directory (or a link to one) with a
/// trailing `/`, sorted. A directory that is not there has none. `None`
/// when the listing fails, is cut by the cap, or holds a name that is not
/// UTF-8, which no [`FileView`] path can spell: what was not listed is
/// not absent.
fn list_dir(dir: &Path) -> Option<Vec<String>> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) if is_absent(&err) => return Some(Vec::new()),
        Err(_) => return None,
    };
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry.ok().filter(|_| names.len() < MAX_LISTED)?;
        let name = entry.file_name().into_string().ok()?;
        let kind = entry.file_type().ok()?;
        let is_dir = kind.is_dir() || (kind.is_symlink() && entry.path().is_dir());
        names.push(match is_dir {
            true => format!("{name}/"),
            false => name,
        });
    }
    names.sort();
    Some(names)
}

impl FileView for DiskView {
    fn read(&self, rel: &str) -> FileText {
        let mut memo = self.memo();
        if let Some(known) = memo.reads.get(rel) {
            return known.clone();
        }
        let text = match self.locate(rel) {
            Some(path) => self.read_file(&path, &mut memo.bytes_read),
            None => FileText::Unreadable,
        };
        memo.reads.insert(rel.to_string(), text.clone());
        text
    }

    fn list(&self, dir: &str) -> Option<Vec<String>> {
        let mut memo = self.memo();
        if let Some(known) = memo.lists.get(dir) {
            return known.clone();
        }
        let listed = self.locate(dir).and_then(|path| list_dir(&path));
        memo.lists.insert(dir.to_string(), listed.clone());
        listed
    }
}

/// Reads the Bazel root behind `view` into its model: the pure reader over
/// the view, and the vendor directories committed at the root, which only
/// the disk shows (a `VENDOR.bazel` below a first-level directory, a link
/// to one included; `bazel_output` owns that test).
///
/// `Err` when the root holds no boundary file that can be read. The view
/// outlives the call on purpose: the gates of the same root read lock
/// files through it later and find what is already in memory.
pub fn read_workspace(root: &RootRef, view: &DiskView) -> Result<BazelWorkspace, Gap> {
    let mut workspace = crate::bazel::detect(root, view)?;
    let found = vendor_dirs_at(view.root());
    let name = |dir: &PathBuf| Some(dir.file_name()?.to_string_lossy().into_owned());
    workspace.vendor_dirs = CommittedVendorDirs {
        dirs: found.dirs.iter().filter_map(name).collect(),
        cannot_tell: found.cannot_tell,
    };
    Ok(workspace)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bazel::govern;
    use crate::bazel::model::FlagState;

    /// A root at `<tmp>/repo/ws` whose read boundary is `<tmp>/repo`.
    fn staged(files: &[(&str, &str)]) -> (tempfile::TempDir, RootRef) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let top = std::fs::canonicalize(tmp.path()).expect("resolve the tempdir");
        for (rel, text) in files {
            let path = top.join(rel);
            std::fs::create_dir_all(path.parent().expect("a parent")).expect("mkdir");
            std::fs::write(&path, text).expect("write");
        }
        let root = RootRef {
            root: top.join("repo/ws"),
            project_rel: String::new(),
            boundary_levels: 1,
        };
        (tmp, root)
    }

    fn bytes(text: &str) -> FileText {
        FileText::Bytes(text.as_bytes().to_vec())
    }

    #[test]
    fn a_read_is_remembered_and_absent_is_told_from_unreadable() {
        let (tmp, root) = staged(&[
            ("repo/ws/MODULE.bazel", "module()\n"),
            ("repo/ws/pkg/BUILD", ""),
        ]);
        let view = DiskView::new(&root);
        assert_eq!(view.read("MODULE.bazel"), bytes("module()\n"));
        assert_eq!(view.read("WORKSPACE"), FileText::Absent);
        // A directory of the name is not a file, and not absent either.
        assert_eq!(view.read("pkg"), FileText::Unreadable);
        // A path below a file names nothing.
        assert_eq!(view.read("MODULE.bazel/x"), FileText::Absent);
        assert_eq!(
            view.list(""),
            Some(vec!["MODULE.bazel".to_string(), "pkg/".to_string()])
        );
        assert_eq!(view.list("pkg"), Some(vec!["BUILD".to_string()]));
        assert_eq!(view.list("missing"), Some(Vec::new()));

        // The run sees each file as it first was.
        let ws = tmp.path().join("repo/ws");
        std::fs::write(ws.join("MODULE.bazel"), "changed\n").unwrap();
        std::fs::write(ws.join("WORKSPACE"), "").unwrap();
        assert_eq!(view.read("MODULE.bazel"), bytes("module()\n"));
        assert_eq!(view.read("WORKSPACE"), FileText::Absent);
        assert_eq!(view.list("").map(|names| names.len()), Some(2));
        assert_eq!(
            DiskView::new(&root).read("MODULE.bazel"),
            bytes("changed\n")
        );
    }

    #[test]
    fn nothing_is_read_past_the_read_boundary() {
        let (_tmp, root) = staged(&[
            ("repo/ws/MODULE.bazel", ""),
            ("repo/.bazelversion", "7.7.2\n"),
            ("outside/.bazelversion", "9.3.2\n"),
            (".bazelversion", "8.8.2\n"),
        ]);
        let view = DiskView::new(&root);
        // One level up is the boundary: a launcher file there is read.
        assert_eq!(view.read("../.bazelversion"), bytes("7.7.2\n"));
        assert!(view
            .list("..")
            .is_some_and(|names| names.contains(&"ws/".to_string())));
        // Two levels up is past it: unreadable, never absent.
        assert_eq!(view.read("../../.bazelversion"), FileText::Unreadable);
        assert_eq!(view.read("../../missing"), FileText::Unreadable);
        assert_eq!(view.list("../.."), None);
        // Only a normalised path is followed.
        for odd in [
            "pkg/../../../.bazelversion",
            "./MODULE.bazel",
            "pkg//x",
            "/etc/hosts",
        ] {
            assert_eq!(view.read(odd), FileText::Unreadable, "{odd}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_link_out_of_the_boundary_and_a_fifo_are_unreadable() {
        let (tmp, root) = staged(&[
            ("repo/ws/MODULE.bazel", ""),
            ("outside/secret.bzl", "X = 1\n"),
        ]);
        let ws = tmp.path().join("repo/ws");
        std::os::unix::fs::symlink(tmp.path().join("outside"), ws.join("linked")).unwrap();
        std::os::unix::fs::symlink(ws.join("MODULE.bazel"), ws.join("inside.bazel")).unwrap();
        let view = DiskView::new(&root);
        assert_eq!(view.read("linked/secret.bzl"), FileText::Unreadable);
        assert_eq!(view.list("linked"), None);
        // A link that stays inside is followed, as Bazel follows it.
        assert_eq!(view.read("inside.bazel"), bytes(""));

        let fifo = std::ffi::CString::new(ws.join(".bazelrc").to_str().unwrap()).unwrap();
        // SAFETY: `fifo` is a NUL-terminated path that outlives the call.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert_eq!(view.read(".bazelrc"), FileText::Unreadable);
    }

    #[test]
    fn a_file_over_the_cap_is_unreadable() {
        let (_tmp, root) = staged(&[
            ("repo/ws/MODULE.bazel", "module()\n"),
            ("repo/ws/big.lock", "0123456789"),
        ]);
        let view = DiskView {
            max_file_bytes: 9,
            ..DiskView::new(&root)
        };
        assert_eq!(view.read("big.lock"), FileText::Unreadable);
        assert_eq!(view.read("MODULE.bazel"), bytes("module()\n"));
    }

    /// Design 2.6: a committed vendor directory is evidence of
    /// `--vendor_dir` with no rc line that names it (probe C11).
    #[test]
    fn a_committed_vendor_directory_makes_vendor_dir_possible() {
        let module = ("repo/ws/MODULE.bazel", "module(name = \"m\")\n");
        let (_tmp, root) = staged(&[
            module,
            ("repo/ws/.bazelversion", "9.3.2\n"),
            ("repo/ws/third_party/VENDOR.bazel", ""),
            ("repo/ws/src/BUILD.bazel", ""),
        ]);
        let ws = read_workspace(&root, &DiskView::new(&root)).expect("a workspace");
        assert_eq!(ws.vendor_dirs.dirs, ["third_party"]);
        assert!(!ws.vendor_dirs.cannot_tell);
        let FlagState::Possible(readings) = govern::vendor_dir(&ws) else {
            panic!("a committed vendor directory is `Possible`");
        };
        assert_eq!(readings.values().collect::<Vec<_>>(), ["third_party"]);

        let (_tmp, root) = staged(&[module, ("repo/ws/.bazelversion", "9.3.2\n")]);
        let ws = read_workspace(&root, &DiskView::new(&root)).expect("a workspace");
        assert_eq!(govern::vendor_dir(&ws), FlagState::NotSeen);

        // No boundary file can be read: there is no model, and that is an
        // error, never an empty workspace.
        let (_tmp, root) = staged(&[("repo/ws/README.md", "")]);
        let gap = read_workspace(&root, &DiskView::new(&root)).expect_err("no root");
        assert_eq!(gap.token, govern::WORKSPACE_UNREADABLE);
    }
}
