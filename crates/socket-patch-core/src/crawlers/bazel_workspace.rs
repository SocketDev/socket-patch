//! The IO side of the workspace model (design 2.1, 2.2): one Bazel root
//! on disk behind the pure layer's [`FileView`], and the entry that reads
//! a root into a [`BazelWorkspace`].
//!
//! A [`DiskView`] is made per root and kept while the run changes
//! nothing under it. Every answer is remembered, so the readers, the
//! recognizers and later the gates of one root read each file once, and
//! a file that changes during the run is seen as it first was: after a
//! commit of the run itself a new view is made (the CLI's loader drops
//! the old one when it is told of the commit), and no transaction is
//! based on a view from before one. Nothing is read before somebody asks.
//!
//! That makes a view a read cache, and a cache alone is no snapshot: a
//! path nobody asked for before a commit would be read after it, and a
//! model of before the commit would be judged with bytes of after it. So
//! the view that a commit leaves behind is frozen ([`DiskView::freeze`]):
//! it goes on answering what it had read, and what it had not read it
//! cannot read any more, which is `Unreadable` and never `Absent`. Whoever
//! still holds it decides from the root as it was, or refuses.
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
//!   directory with more than [`MAX_LISTED`] entries cannot be listed;
//! - list a link into a tree Bazel owns as a directory. A convenience
//!   link, under any `--symlink_prefix`, is a bare name in a listing
//!   (the rule of [`FileView::list`]), so a recognizer's scan of the
//!   packages never walks the output tree.
//!
//! The calls block: run them where `crawlers::bazel_output` runs its own.

use std::collections::{BTreeMap, HashMap};
use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

use super::bazel_output::{vendor_dirs_at, Classifier};
use super::bazel_root::RootProbe;
use crate::bazel::model::{
    BazelLine, BazelWorkspace, CommittedVendorDirs, FileText, FileView, Gap, PathClass, RootRef,
};
use crate::bazel::{govern, rc};
use crate::utils::fs::read_regular_to_bytes_sync;
use crate::utils::repo_root::{ReadBoundary, ReadScope};

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
    /// Set by [`DiskView::freeze`]: nothing more is read from the disk.
    frozen: bool,
}

/// One Bazel root on disk, as the pure layer reads files.
///
/// A view is a read cache until it is frozen, and a snapshot of what it
/// had read from then on ([`DiskView::freeze`]). The decision of ROUTED
/// R-136: a view held across a commit of the run must not hand out bytes
/// of after the commit beside a model of before it, and "do not read a
/// held view" is a rule nothing else enforces.
pub struct DiskView {
    root: PathBuf,
    boundary: ReadBoundary,
    boundary_levels: usize,
    max_file_bytes: u64,
    memo: Mutex<Memo>,
    /// Judges the links a listing meets. It remembers the directories it
    /// walked, so the links of one root cost their targets once.
    trees: Classifier,
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
            trees: Classifier::new(),
        }
    }

    /// The root, resolved.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Closes the view to the disk, for good: what was read or listed
    /// before the call is answered as before, and every other path is
    /// `Unreadable` and cannot be listed. Neither is `Absent` or empty:
    /// the view did not look, so it cannot know.
    ///
    /// The owner of a view calls this when the run changed a file under
    /// the root (the CLI's loader does, for every view it drops on
    /// `Loader::committed`). A caller that still holds the view then sees
    /// the root as it was before the change and nothing of after it. A
    /// read that is under way when the call is made may still return what
    /// it found; every read that starts after it is of the memo alone.
    ///
    /// [`DiskView::real_dir`] is no part of this. It reads no file: it
    /// resolves links for the one caller that reads a model
    /// ([`read_workspace`]), and a model is read before a commit, not
    /// across one.
    pub fn freeze(&self) {
        self.memo().frozen = true;
    }

    /// Whether [`DiskView::freeze`] was called.
    pub fn is_frozen(&self) -> bool {
        self.memo().frozen
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

    /// The directory that holds the file `rel` once every link on the way
    /// to it is resolved, relative to the root, where that is another
    /// directory than the path spells: a file that a label reaches through
    /// a linked directory, or that is a link itself. `None` where the two
    /// are one directory, where the file lies outside the root, and where
    /// nothing can be resolved.
    ///
    /// The root is kept resolved, so both sides of the comparison are
    /// resolved paths; the answer is built from the components and never
    /// from a displayed path.
    pub fn real_dir(&self, rel: &str) -> Option<String> {
        let path = self.locate(rel)?;
        let real = std::fs::canonicalize(&path).ok().or_else(|| {
            // A file that is not there yet lies where its directory is.
            let dir = std::fs::canonicalize(path.parent()?).ok()?;
            Some(dir.join(path.file_name()?))
        })?;
        let below = real.parent()?.strip_prefix(&self.root).ok()?;
        let mut names = Vec::new();
        for component in below.components() {
            match component {
                Component::Normal(name) => names.push(name.to_str()?),
                _ => return None,
            }
        }
        let dir = names.join("/");
        let spelled = rel.rsplit_once('/').map_or("", |(dir, _)| dir);
        (dir != spelled).then_some(dir)
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
///
/// A link that `trees` judges to lead into a tree Bazel owns is a bare
/// name ([`FileView::list`]): the convenience links, whatever
/// `--symlink_prefix` names them, `bazel-external`, a link to a vendor
/// directory. Bazel's package walk skips its own links by the same test,
/// the target under the output base (`isConvenienceSymlink`, 7.7.2
/// `ProcessPackageDirectory.java:196`). A link whose target shows no
/// marker stays a directory, as does a real directory of any name.
fn list_dir(dir: &Path, trees: &Classifier) -> Option<Vec<String>> {
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
        let is_dir = match kind.is_symlink() {
            false => kind.is_dir(),
            true => {
                let path = entry.path();
                path.is_dir() && trees.classify(&path).class != PathClass::Link
            }
        };
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
        if memo.frozen {
            return FileText::Unreadable;
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
        if memo.frozen {
            return None;
        }
        let listed = self
            .locate(dir)
            .and_then(|path| list_dir(&path, &self.trees));
        memo.lists.insert(dir.to_string(), listed.clone());
        listed
    }
}

/// Reads the Bazel root behind `view` into its model: the pure reader over
/// the view, and what only the disk shows of the vendor directories
/// committed at the root (`bazel_output` owns that test).
///
/// The pure reader lists the vendor directories the view shows by their
/// marker files. The disk test adds a link to a vendor directory, which a
/// view will not follow out of the read boundary, and it is the one that
/// says whether every marker was looked for: a `bazel-bin` link out of
/// the boundary is a question the view cannot answer and the disk can. So
/// the directories of both count, and "cannot tell" is the disk's.
///
/// The disk also resolves links: a lock that a hub's label reaches through
/// a linked directory lies in two directories, the one the label spells
/// and the real one, and the project a crawler finds at the real one is
/// governed by the hub like the other (`BazelWorkspace::lock_real_dirs`).
///
/// `Err` when the root holds no boundary file that can be read. The view
/// outlives the call on purpose: the gates of the same root read lock
/// files through it later and find what is already in memory. That is
/// also what makes a model per project cheap (`govern::governance` answers
/// for the project a model was read for): each further read of the same
/// root through the same view opens no file twice.
pub fn read_workspace(root: &RootRef, view: &DiskView) -> Result<BazelWorkspace, Gap> {
    let mut workspace = crate::bazel::detect(root, view)?;
    let found = vendor_dirs_at(view.root());
    let name = |dir: &PathBuf| Some(dir.file_name()?.to_string_lossy().into_owned());
    let mut dirs = std::mem::take(&mut workspace.vendor_dirs.dirs);
    dirs.extend(found.dirs.iter().filter_map(name));
    dirs.sort();
    dirs.dedup();
    workspace.vendor_dirs = CommittedVendorDirs {
        dirs,
        cannot_tell: found.cannot_tell,
    };
    let locks = workspace.hubs.iter().flat_map(|hub| &hub.locks);
    let paths = locks.filter_map(|lock| lock.path.as_deref());
    let real: BTreeMap<String, String> = paths
        .filter_map(|path| Some((path.to_string(), view.real_dir(path)?)))
        .collect();
    workspace.lock_real_dirs = real;
    Ok(workspace)
}

/// The vendor directories that tracked rc files name for the Bazel roots
/// at and above `dir` (design 2.6, 2.11): each `--vendor_dir` value of any
/// command chain or config that lies below its root
/// (`govern::vendor_dir_below`), as an absolute path under the resolved
/// root.
///
/// Such a directory is Bazel's before `bazel vendor` has written a marker
/// into it, and where git does not track the marker. Without this the
/// classifier knows a vendor directory by its marker alone.
///
/// The cost where no Bazel root lies above `dir`, which is every project
/// that does not build with Bazel: the stat-only root probe, once, and
/// nothing else. No file is opened, no directory listed and no checkout
/// looked for. Under a root, the checkout that bounds the read is found,
/// and each root's `.bazelrc` and what it imports inside that boundary
/// are read; an rc file outside it is never opened.
///
/// A relative `dir` is read from the working directory. The calls block.
pub fn tracked_vendor_dirs(dir: &Path) -> Vec<PathBuf> {
    let probe = RootProbe::new();
    // Asked without a boundary first: only names are stat'ed, and "no
    // boundary file up to the top of the disk" needs no checkout to be
    // found. The roots that count are the ones inside the read boundary.
    if probe.survey(dir, &ReadBoundary::Unbounded).roots.is_empty() {
        return Vec::new();
    }
    let from = match dir.as_os_str().is_empty() {
        true => Path::new("."),
        false => dir,
    };
    let boundary = ReadBoundary::upward(ReadScope::Workspace, from);
    let mut dirs = Vec::new();
    for root in &probe.survey(dir, &boundary).roots {
        let view = DiskView::new(root);
        let flags = rc::read(&view).effective(&BazelLine::unknown());
        for value in govern::tracked_vendor_dirs(&flags) {
            let Some(below) = govern::vendor_dir_below(&value) else {
                continue;
            };
            // Component by component: one `join("a/b")` would leave a
            // `/` inside a component on Windows.
            let mut path = view.root().to_path_buf();
            path.extend(below.split('/'));
            dirs.push(path);
        }
    }
    dirs
}

/// The output-tree classifier for work at or below `dir`: the markers
/// Bazel writes, and the vendor directories the tracked rc files name
/// ([`tracked_vendor_dirs`]). Every guard that keeps a walk or a write out
/// of Bazel's trees makes its classifier here, so that all of them know
/// the same trees.
pub fn tree_classifier(dir: &Path) -> Classifier {
    Classifier::with_vendor_dirs(tracked_vendor_dirs(dir))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bazel::model::{BoundaryFiles, Completeness, FlagState, Governance, HubId};
    use crate::crawlers::types::Ecosystem;

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

    /// ROUTED R-136: a view held across a commit is a snapshot of what it
    /// had read. What it reads for the first time after the commit would
    /// be bytes of after it, beside a model of before it, so a frozen view
    /// reads nothing more: such a path is unreadable, never absent.
    #[test]
    fn a_frozen_view_answers_only_what_it_read_before() {
        let (tmp, root) = staged(&[
            ("repo/ws/MODULE.bazel", "module()\n"),
            ("repo/ws/pnpm-lock.yaml", "lockfileVersion: '9.0'\n"),
            ("repo/ws/pkg/BUILD", ""),
            ("repo/ws/pkg/sub/BUILD", ""),
            ("repo/.bazelversion", "9.3.2\n"),
        ]);
        let view = DiskView::new(&root);
        assert!(!view.is_frozen());
        // Read before the commit: a file, a file that is not there, and
        // two listings.
        assert_eq!(view.read("MODULE.bazel"), bytes("module()\n"));
        assert_eq!(view.read("WORKSPACE"), FileText::Absent);
        let top = view.list("").expect("a listing");
        assert_eq!(top, ["MODULE.bazel", "pkg/", "pnpm-lock.yaml"]);
        assert_eq!(view.list("gone"), Some(Vec::new()));

        // The commit: every file changes, and new ones appear.
        let ws = tmp.path().join("repo").join("ws");
        let put = |rel: &[&str], text: &str| {
            let path = rel.iter().fold(ws.clone(), |at, part| at.join(part));
            std::fs::create_dir_all(path.parent().expect("a parent")).expect("mkdir");
            std::fs::write(path, text).expect("write");
        };
        put(&["MODULE.bazel"], "module(name = \"after\")\n");
        put(&["WORKSPACE"], "workspace(name = \"after\")\n");
        put(&["pnpm-lock.yaml"], "lockfileVersion: 'after'\n");
        put(&[".bazelignore"], "pkg/.socket\n");
        put(&["gone", "BUILD"], "");
        view.freeze();
        assert!(view.is_frozen());

        // What was read is answered as it was read.
        assert_eq!(view.read("MODULE.bazel"), bytes("module()\n"));
        assert_eq!(view.read("WORKSPACE"), FileText::Absent);
        assert_eq!(view.list(""), Some(top));
        assert_eq!(view.list("gone"), Some(Vec::new()));
        // What was not read is not read now: no byte of after the commit
        // leaves the view, and nothing is taken for missing. That holds
        // for a file that changed, one that is new, one that was never
        // there, one above the root, and for every listing.
        for unread in [
            "pnpm-lock.yaml",
            ".bazelignore",
            "gone/BUILD",
            "never/there.bzl",
            "pkg/BUILD",
            "../.bazelversion",
        ] {
            assert_eq!(view.read(unread), FileText::Unreadable, "{unread}");
        }
        for unlisted in ["pkg", "pkg/sub", "never", ".."] {
            assert_eq!(view.list(unlisted), None, "{unlisted}");
        }
        // Asking twice changes nothing, and nothing thaws a view.
        assert_eq!(view.read("pnpm-lock.yaml"), FileText::Unreadable);
        assert_eq!(view.list("pkg"), None);

        // A model over the frozen view is not a model of the new files:
        // the lock a hub would name was never read, so nothing is decided
        // from it. A view made after the commit reads the root as it is.
        let fresh = DiskView::new(&root);
        assert_eq!(
            fresh.read("pnpm-lock.yaml"),
            bytes("lockfileVersion: 'after'\n")
        );
        assert_eq!(fresh.read(".bazelignore"), bytes("pkg/.socket\n"));
        assert_eq!(fresh.list("pkg"), Some(vec!["BUILD".into(), "sub/".into()]));
    }

    /// A model read through a view is the root of before the freeze: the
    /// readers find every file they asked for in the memo, and a second
    /// read of the same root and project through the frozen view gives
    /// the same model, whatever the disk holds by then.
    #[test]
    fn a_model_read_again_through_a_frozen_view_is_the_model_of_before() {
        let (tmp, root) = staged(&[
            ("repo/ws/MODULE.bazel", JS_MODULE),
            ("repo/ws/.bazelversion", "9.3.2\n"),
            ("repo/ws/pnpm-lock.yaml", "lockfileVersion: '9.0'\n"),
        ]);
        let view = DiskView::new(&root);
        let before = read_workspace(&root, &view).expect("a workspace");
        let governed = Governance::Governed(vec![HubId(0)]);
        assert_eq!(govern::governance(&before, Ecosystem::Npm, ""), governed);

        // The run takes the hub out of `MODULE.bazel`.
        let module = tmp.path().join("repo").join("ws").join("MODULE.bazel");
        std::fs::write(module, "module(name = \"after\")\n").expect("write");
        view.freeze();
        let again = read_workspace(&root, &view).expect("a workspace");
        assert_eq!(again, before);
        let after = read_workspace(&root, &DiskView::new(&root)).expect("a workspace");
        assert!(after.hubs.is_empty(), "{:?}", after.hubs);

        // A project the view was not read for has launcher files nobody
        // asked for. A view that reads the disk finds none in `sub` and
        // takes the root's pin; the frozen one cannot say that there is
        // none, so the pin is not this project's and its line is open.
        let sub = RootRef {
            project_rel: "sub".to_string(),
            ..root.clone()
        };
        let bounds = |ws: &BazelWorkspace| (ws.line.lo, ws.line.hi);
        let read = read_workspace(&sub, &DiskView::new(&root)).expect("a workspace");
        assert_eq!(bounds(&read), bounds(&before));
        let held = read_workspace(&sub, &view).expect("a workspace");
        assert_eq!(bounds(&held), (None, None), "an unread file is no pin");
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

    /// What the disk adds to the directories the view shows, and what it
    /// answers that the view cannot: the convenience links of a built
    /// workspace lead out of the read boundary, where a view reads
    /// nothing, and they must not make every built workspace one whose
    /// vendor directories nobody could look for.
    #[cfg(unix)]
    #[test]
    fn links_at_the_root_are_judged_by_the_disk() {
        let module = ("repo/ws/MODULE.bazel", "module(name = \"m\")\n");
        let pin = ("repo/ws/.bazelversion", "9.3.2\n");
        let (tmp, root) = staged(&[module, pin, ("outside/out/bin/x", "")]);
        let ws_dir = tmp.path().join("repo/ws");
        let link = |target: &str, name: &str| {
            std::os::unix::fs::symlink(tmp.path().join(target), ws_dir.join(name)).unwrap();
        };
        link("outside/out/bin", "bazel-bin");
        link("outside/out", "bazel-out");
        let view = DiskView::new(&root);
        // The view cannot say what is behind the link.
        assert_eq!(view.read("bazel-bin/VENDOR.bazel"), FileText::Unreadable);
        let ws = read_workspace(&root, &view).expect("a workspace");
        assert_eq!(ws.vendor_dirs, CommittedVendorDirs::default());
        assert_eq!(govern::vendor_dir(&ws), FlagState::NotSeen);

        // A link to a vendor directory is one, inside the boundary or out
        // of it, and a plain directory with the marker is found by both.
        let (tmp, root) = staged(&[
            module,
            pin,
            ("repo/vendored/VENDOR.bazel", ""),
            ("outside/vendored/VENDOR.bazel", ""),
            ("repo/ws/third_party/.vendorignore", ""),
        ]);
        let ws_dir = tmp.path().join("repo/ws");
        let link = |target: &str, name: &str| {
            std::os::unix::fs::symlink(tmp.path().join(target), ws_dir.join(name)).unwrap();
        };
        link("repo/vendored", "deps");
        link("outside/vendored", "ext");
        let ws = read_workspace(&root, &DiskView::new(&root)).expect("a workspace");
        assert_eq!(ws.vendor_dirs.dirs, ["deps", "ext", "third_party"]);
        assert!(!ws.vendor_dirs.cannot_tell);
        assert!(matches!(govern::vendor_dir(&ws), FlagState::Possible(_)));
    }

    const JS_MODULE: &str = "bazel_dep(name = \"aspect_rules_js\", version = \"3.6.0\")\n\
        npm = use_extension(\"@aspect_rules_js//npm:extensions.bzl\", \"npm\")\n\
        npm.npm_translate_lock(name = \"npm\", pnpm_lock = \"//:pnpm-lock.yaml\")\n\
        use_repo(npm, \"npm\")\n";

    /// A link into a tree Bazel owns is listed as no directory, so that a
    /// scan of the packages never walks the output tree: the convenience
    /// links of the default prefix, and the ones `--symlink_prefix=dist/`
    /// makes, which no list of names knows. Every other link to a
    /// directory, and a real directory named like a link, is a directory.
    #[cfg(unix)]
    #[test]
    fn a_convenience_link_is_listed_as_no_directory() {
        let (tmp, root) = staged(&[
            ("repo/ws/MODULE.bazel", "module(name = \"app\")\n"),
            ("repo/ws/pkg/BUILD.bazel", ""),
            ("repo/ws/bazel-tools/BUILD.bazel", ""),
            ("repo/ws/dist/README.md", ""),
            // An output base, outside the repository as Bazel keeps it.
            ("base/DO_NOT_BUILD_HERE", "/repo/ws"),
            (
                "base/execroot/_main/bazel-out/k8-fastbuild/bin/pkg/BUILD.bazel",
                "",
            ),
            ("base/execroot/_main/bazel-out/k8-fastbuild/testlogs/x", ""),
            ("base/external/dep/BUILD.bazel", ""),
            ("elsewhere/docs/BUILD.bazel", ""),
        ]);
        let top = std::fs::canonicalize(tmp.path()).expect("resolve the tempdir");
        let ws = top.join("repo").join("ws");
        let out = top.join("base").join("execroot").join("_main");
        let link = |target: PathBuf, name: &[&str]| {
            let at = name.iter().fold(ws.clone(), |at, part| at.join(part));
            std::os::unix::fs::symlink(target, at).unwrap();
        };
        let fastbuild = out.join("bazel-out").join("k8-fastbuild");
        // The default prefix.
        link(fastbuild.join("bin"), &["bazel-bin"]);
        link(out.join("bazel-out"), &["bazel-out"]);
        link(out.clone(), &["bazel-ws"]);
        // `--symlink_prefix=dist/`.
        link(fastbuild.join("bin"), &["dist", "bin"]);
        link(fastbuild.join("testlogs"), &["dist", "testlogs"]);
        link(out.clone(), &["dist", "ws"]);
        // Links that lead into no Bazel tree: inside the repository, and
        // out of the read boundary.
        link(ws.join("pkg"), &["alias"]);
        link(top.join("elsewhere").join("docs"), &["docs"]);

        let view = DiskView::new(&root);
        let listed = |dir: &str| view.list(dir).expect("a listing");
        assert_eq!(
            listed(""),
            [
                "MODULE.bazel",
                "alias/",
                "bazel-bin",
                "bazel-out",
                "bazel-tools/",
                "bazel-ws",
                "dist/",
                "docs/",
                "pkg/",
            ]
        );
        assert_eq!(listed("dist"), ["README.md", "bin", "testlogs", "ws"]);
        // The link inside the repository is followed; the one out of the
        // read boundary is a directory nobody can list.
        assert_eq!(listed("alias"), ["BUILD.bazel"]);
        assert_eq!(view.list("docs"), None);
        // A walk that follows the listing reads no file of the output
        // tree.
        let mut pending = vec![String::new()];
        let mut files = Vec::new();
        while let Some(dir) = pending.pop() {
            for name in view.list(&dir).unwrap_or_default() {
                let below = |name: &str| match dir.as_str() {
                    "" => name.to_string(),
                    dir => format!("{dir}/{name}"),
                };
                match name.strip_suffix('/') {
                    Some(child) => pending.push(below(child)),
                    None => files.push(below(&name)),
                }
            }
        }
        files.sort();
        let builds: Vec<&str> = files
            .iter()
            .map(String::as_str)
            .filter(|path| path.ends_with("BUILD.bazel"))
            .collect();
        assert_eq!(
            builds,
            [
                "alias/BUILD.bazel",
                "bazel-tools/BUILD.bazel",
                "pkg/BUILD.bazel"
            ]
        );
    }

    /// A lock label that reaches its file through a linked directory names
    /// the lock of two directories: the one the label spells, and the real
    /// one, where a crawler finds the project. Left ungoverned there, the
    /// native writer would edit a lock Bazel builds from.
    #[cfg(unix)]
    #[test]
    fn a_lock_behind_a_directory_link_governs_the_project_at_both_paths() {
        let module = JS_MODULE.replace("//:pnpm-lock.yaml", "//pkg:pnpm-lock.yaml");
        let lock = "lockfileVersion: '9.0'\n";
        let (tmp, root) = staged(&[
            ("repo/ws/MODULE.bazel", module.as_str()),
            ("repo/ws/.bazelversion", "9.3.2\n"),
            ("repo/ws/real/pkg/pnpm-lock.yaml", lock),
            ("repo/ws/real/pkg/BUILD.bazel", ""),
            ("repo/ws/other/pnpm-lock.yaml", lock),
        ]);
        let ws_dir = std::fs::canonicalize(tmp.path())
            .expect("resolve the tempdir")
            .join("repo")
            .join("ws");
        let real = ws_dir.join("real").join("pkg");
        std::os::unix::fs::symlink(&real, ws_dir.join("pkg")).unwrap();
        let view = DiskView::new(&root);
        assert_eq!(
            view.real_dir("pkg/pnpm-lock.yaml").as_deref(),
            Some("real/pkg")
        );
        // A file that is where its path says has no other directory, and
        // neither has one that is not there yet behind no link.
        assert_eq!(view.real_dir("real/pkg/pnpm-lock.yaml"), None);
        assert_eq!(view.real_dir("MODULE.bazel"), None);
        assert_eq!(view.real_dir("other/yarn.lock"), None);
        // One that is not there yet lies where its directory is.
        assert_eq!(view.real_dir("pkg/yarn.lock").as_deref(), Some("real/pkg"));

        let at = |project: &str| {
            let root = RootRef {
                project_rel: project.to_string(),
                ..root.clone()
            };
            let ws = read_workspace(&root, &view).expect("a workspace");
            // The hub keeps the path its label spells; the model holds the
            // real directory beside it.
            let mut spelled = ws.hubs[0].locks.iter().filter_map(|l| l.path.as_deref());
            assert!(spelled.all(|path| path.starts_with("pkg/")));
            let real = ws.lock_real_dirs.get("pkg/pnpm-lock.yaml");
            assert_eq!(real.map(String::as_str), Some("real/pkg"));
            govern::governance(&ws, Ecosystem::Npm, project)
        };
        let governed = Governance::Governed(vec![HubId(0)]);
        assert_eq!(at("pkg"), governed);
        assert_eq!(at("real/pkg"), governed);
        // No other directory is the lock's.
        for elsewhere in ["", "real", "other", "real/pkg/sub"] {
            assert_eq!(at(elsewhere), Governance::NotGoverned, "`{elsewhere}`");
        }

        // A lock that is itself a link lies where its target is, too.
        let module = JS_MODULE.replace("//:pnpm-lock.yaml", "//app:pnpm-lock.yaml");
        let (tmp, root) = staged(&[
            ("repo/ws/MODULE.bazel", module.as_str()),
            ("repo/ws/.bazelversion", "9.3.2\n"),
            ("repo/ws/shared/pnpm-lock.yaml", lock),
            ("repo/ws/app/BUILD.bazel", ""),
        ]);
        let ws_dir = std::fs::canonicalize(tmp.path())
            .expect("resolve the tempdir")
            .join("repo")
            .join("ws");
        let shared = ws_dir.join("shared").join("pnpm-lock.yaml");
        std::os::unix::fs::symlink(shared, ws_dir.join("app").join("pnpm-lock.yaml")).unwrap();
        let view = DiskView::new(&root);
        for project in ["app", "shared"] {
            let root = RootRef {
                project_rel: project.to_string(),
                ..root.clone()
            };
            let ws = read_workspace(&root, &view).expect("a workspace");
            assert_eq!(
                govern::governance(&ws, Ecosystem::Npm, project),
                governed,
                "`{project}`"
            );
        }
    }

    /// With no link on the way, a model holds no second directory.
    #[test]
    fn a_lock_behind_no_link_has_one_directory() {
        let module = JS_MODULE.replace("//:pnpm-lock.yaml", "//pkg:pnpm-lock.yaml");
        let (_tmp, root) = staged(&[
            ("repo/ws/MODULE.bazel", module.as_str()),
            ("repo/ws/.bazelversion", "9.3.2\n"),
            ("repo/ws/pkg/pnpm-lock.yaml", "lockfileVersion: '9.0'\n"),
        ]);
        let ws = read_workspace(&root, &DiskView::new(&root)).expect("a workspace");
        assert_eq!(ws.hubs.len(), 1);
        assert!(ws.lock_real_dirs.is_empty(), "{:?}", ws.lock_real_dirs);
    }

    /// A directory named like a file of the `WORKSPACE` family is no
    /// boundary file, however the disk folds its name: real Bazel 9.3.2
    /// builds beside `WORKSPACE/` and `workspace/`, and nothing there may
    /// refuse every ecosystem of the workspace.
    #[test]
    fn a_directory_named_like_a_workspace_file_holds_nothing_up() {
        let lock = ("repo/ws/pnpm-lock.yaml", "lockfileVersion: '9.0'\n");
        let module = ("repo/ws/MODULE.bazel", JS_MODULE);
        let governed = Governance::Governed(vec![HubId(0)]);
        let only_module = BoundaryFiles {
            module_bazel: true,
            ..BoundaryFiles::default()
        };
        for dir in [
            "docs",
            "WORKSPACE",
            "workspace",
            "workspace.bzlmod",
            "Workspace.Bazel",
        ] {
            let inside = format!("repo/ws/{dir}/README.md");
            let pin = ("repo/ws/.bazelversion", "9.3.2\n");
            let (_tmp, root) = staged(&[module, pin, lock, (inside.as_str(), "")]);
            let ws = read_workspace(&root, &DiskView::new(&root)).expect("a workspace");
            assert_eq!(ws.boundary, only_module, "`{dir}/`");
            assert_eq!(ws.workspace_files, [], "`{dir}/`");
            assert_eq!(ws.completeness, Completeness::Exact, "`{dir}/`");
            assert_eq!(
                govern::governance(&ws, Ecosystem::Npm, ""),
                governed,
                "`{dir}/`"
            );
            assert_eq!(
                govern::governance(&ws, Ecosystem::Pypi, ""),
                Governance::NotGoverned,
                "`{dir}/`"
            );
        }
        // Where Bazel reads the `WORKSPACE` family and nothing outranks
        // the path, it opens the directory and stops (7.7.2): that one
        // case stays undetermined. `workspace/` is that path only on a
        // disk that folds case.
        for dir in ["WORKSPACE", "workspace"] {
            let inside = format!("repo/ws/{dir}/README.md");
            let pin = ("repo/ws/.bazelversion", "7.7.2\n");
            let (_tmp, root) = staged(&[module, pin, lock, (inside.as_str(), "")]);
            let opened = root.root.join("WORKSPACE").is_dir();
            let ws = read_workspace(&root, &DiskView::new(&root)).expect("a workspace");
            assert_eq!(ws.boundary, only_module, "`{dir}/`");
            let found = govern::governance(&ws, Ecosystem::Npm, "");
            match opened {
                true => {
                    let Governance::Undetermined(gaps) = &found else {
                        panic!("`{dir}/`: {found:?}");
                    };
                    assert_eq!(gaps[0].token, govern::WORKSPACE_UNREADABLE);
                    assert!(gaps[0].detail.contains("is a directory"), "{:?}", gaps[0]);
                }
                false => assert_eq!(found, governed, "`{dir}/`"),
            }
            assert_eq!(opened, dir == "WORKSPACE" || folds_case(&root.root));
        }
    }

    /// Whether the disk under `dir` takes two spellings of a name for one.
    fn folds_case(dir: &Path) -> bool {
        dir.join("module.bazel").is_file() && dir.join("MODULE.bazel").is_file()
    }
    /// Design 2.11 and HZ-03: the classifier of a run knows the vendor
    /// directories the tracked rc files name, and a project that does not
    /// build with Bazel is asked for nothing but names.
    #[test]
    fn the_tracked_vendor_dirs_of_the_roots_above_reach_the_classifier() {
        let (tmp, root) = staged(&[
            ("repo/ws/MODULE.bazel", ""),
            (
                "repo/ws/.bazelrc",
                "common:ci --vendor_dir=third_party/bazel\nimport %workspace%/extra.bazelrc\n",
            ),
            (
                "repo/ws/extra.bazelrc",
                "vendor --vendor_dir=./deps/\nbuild:x --vendor_dir=\n",
            ),
            ("repo/ws/app/package.json", "{}"),
            ("repo/ws/third_party/bazel/+npm+dep/package.json", "{}"),
            ("repo/plain/package.json", "{}"),
        ]);
        // Level by level from the resolved root, as the reader builds them.
        let ws = &std::fs::canonicalize(&root.root).expect("the staged root");
        let below = |rel: &str| rel.split('/').fold(ws.clone(), |dir, name| dir.join(name));
        let expected = [below("deps"), below("third_party/bazel")];
        // From the root, from a project below it and from inside the
        // vendor directory, also one nobody created yet.
        for from in ["", "app", "third_party/bazel/+npm+dep", "deps/not/yet"] {
            let from = match from {
                "" => ws.clone(),
                rel => below(rel),
            };
            assert_eq!(tracked_vendor_dirs(&from), expected, "{}", from.display());
        }
        let trees = tree_classifier(&below("app"));
        let class = |path: PathBuf| trees.classify(&path).class;
        assert_eq!(
            class(below("third_party/bazel/+npm+dep")),
            PathClass::VendorDir
        );
        assert_eq!(class(below("deps")), PathClass::VendorDir);
        assert_eq!(class(below("app")), PathClass::Plain);
        // The empty value names the root itself, and the root is not made
        // a tree by a flag.
        assert_eq!(class(ws.clone()), PathClass::Plain);
        // What a walker of the root is told to stay out of.
        let at_root: Vec<PathBuf> = trees
            .tracked_at(ws)
            .into_iter()
            .map(|tree| tree.root)
            .collect();
        assert_eq!(at_root, [ws.join("deps")]);
        let third_party: Vec<PathBuf> = trees
            .tracked_at(&ws.join("third_party"))
            .into_iter()
            .map(|tree| tree.root)
            .collect();
        assert_eq!(third_party, [below("third_party/bazel")]);
        assert!(trees.tracked_at(&below("app")).is_empty());

        // No Bazel root above: nothing is read and nothing is tracked.
        let plain = std::fs::canonicalize(tmp.path())
            .unwrap()
            .join("repo")
            .join("plain");
        assert!(tracked_vendor_dirs(&plain).is_empty());
        assert_eq!(
            tree_classifier(&plain).classify(&plain).class,
            PathClass::Plain
        );
    }
}
