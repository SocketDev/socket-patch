//! The IO side of the output-tree classifier (design 2.11): the disk
//! behind the rules of `bazel::output_tree`, a memo per directory, the
//! link route and the default output roots.
//!
//! Everything here is a read: `stat`, `read_link`, `canonicalize`,
//! directory listings, and one bounded read of a marker through the guard
//! behind `read_regular_*`. A path this module classifies is never written
//! and never crawled, and the module is never used to choose a place to
//! write or a tree to crawl. Its calls block: run them where
//! `patch::shared_store` runs its own, on the blocking pool.
//!
//! No rc file is read here. What tracked rc files say (`--vendor_dir`,
//! `--symlink_prefix`, `startup --output_base`) arrives from the caller,
//! through [`Classifier::with_vendor_dirs`] and [`Candidates`].

use std::ffi::{OsStr, OsString};
use std::io::{ErrorKind, Read as _};
use std::path::{Component, Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use super::coursier_cache::TargetOs;
use crate::bazel::output_tree::{
    self, Candidate, Entry, Found, LinkRoute, Located, Memo, PathClass, Tree, TreeFs, Unsure,
    Verdict, OUTPUT_BASE_MARKER,
};
use crate::utils::fs::open_regular_file_sync;

/// The most that is read of a marker. A marker holds one path, far below
/// this. A larger `DO_NOT_BUILD_HERE` is not Bazel's: this much of it is
/// read and compared like any other, and it names nothing.
const MAX_MARKER_BYTES: u64 = 1 << 16;

/// How many entries of one directory are read when looking for links and
/// output bases. A directory with more is reported as not listed in full.
const MAX_LISTED: usize = 1 << 16;

/// How many links with a missing target one path is followed through. The
/// kernel stops a chain of live links at about this many.
const MAX_LINK_HOPS: usize = 40;

/// Whether `err` says that nothing is there: a missing entry, a parent
/// that is a file, a name too long to exist.
fn is_absent(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        ErrorKind::NotFound | ErrorKind::NotADirectory | ErrorKind::InvalidFilename
    )
}

/// The disk behind [`TreeFs`].
struct Disk;

impl TreeFs for Disk {
    fn stat(&self, path: &Path) -> Entry {
        match std::fs::metadata(path) {
            Ok(meta) if meta.is_file() => Entry::File,
            Ok(meta) if meta.is_dir() => Entry::Dir,
            Ok(_) => Entry::Neither,
            Err(err) if is_absent(&err) => Entry::Neither,
            Err(_) => Entry::Unknown,
        }
    }

    fn read_link(&self, path: &Path) -> Option<PathBuf> {
        std::fs::read_link(path).ok()
    }
}

/// The classifier for one run. It remembers each directory it judged, so
/// the package directories of one install tree cost a few `stat`s each
/// and their shared ancestors are walked once. Make one per run: a
/// directory judged `Plain` stays so for as long as the classifier lives.
#[derive(Debug)]
pub struct Classifier {
    vendor_dirs: Vec<PathBuf>,
    memo: Mutex<Memo>,
}

impl Default for Classifier {
    fn default() -> Self {
        Self::new()
    }
}

impl Classifier {
    pub fn new() -> Self {
        Self::with_vendor_dirs(Vec::new())
    }

    /// A classifier that also knows the directories tracked rc files name
    /// with `--vendor_dir` (absolute paths). Such a directory is a vendor
    /// directory before `bazel vendor` has written a marker into it, and
    /// before it exists.
    pub fn with_vendor_dirs(dirs: impl IntoIterator<Item = PathBuf>) -> Self {
        let mut vendor_dirs = Vec::new();
        for dir in dirs {
            // Compared by identity: a query is judged as spelled and as
            // resolved, so the directory is kept both ways. `resolve` and
            // not `canonicalize`, which has no answer for a directory
            // `bazel vendor` has yet to create.
            if let Some(real) = resolve(&dir, MAX_LINK_HOPS).filter(|real| *real != dir) {
                vendor_dirs.push(real);
            }
            vendor_dirs.push(dir);
        }
        Self {
            memo: Mutex::new(Memo::new(vendor_dirs.clone())),
            vendor_dirs,
        }
    }

    /// Classify `path`, as found and as resolved. A relative path is read
    /// from the working directory. A path that does not exist yet (a file
    /// a patch would add) is judged by where it would be created.
    ///
    /// A path spelled with `..` is first placed by the disk: the directory
    /// that holds the entry is resolved and the entry keeps its own name.
    /// So `<workspace>/app/../bazel-bin` is the link
    /// `<workspace>/bazel-bin` and answers `Link`, as it does without the
    /// `..`, and no caller has to spell the path another way first. A path
    /// that ends in `..` names no entry and is judged where it resolves.
    pub fn classify(&self, path: &Path) -> Verdict {
        let Ok(found) = std::path::absolute(path) else {
            return Verdict {
                class: PathClass::Plain,
                tree: None,
                resolves_into: None,
                cannot_tell: true,
            };
        };
        // One spelling per path: `absolute` keeps a trailing separator,
        // and `<link>/` is not a link to `read_link`. `..` is kept.
        let found: PathBuf = found.components().collect();
        let canonical = resolve(&found, MAX_LINK_HOPS);
        // Where `a/b/../c` is, only the disk knows, and the rules walk no
        // path that holds `..`. The entry is placed by its directory, so
        // that a link stays a link; failing that, by the resolved form
        // alone, which for a link is the place it leads to.
        let found = if has_parent_dir(&found) {
            let placed = in_resolved_dir(&found).or_else(|| canonical.clone());
            placed.unwrap_or(found)
        } else {
            found
        };
        let mut verdict = {
            // Held across the marker tests: they are a few `stat`s, and
            // two callers that walked the same ancestors at once would
            // only repeat them.
            let mut memo = self.memo.lock().unwrap_or_else(PoisonError::into_inner);
            output_tree::classify(&Disk, &found, canonical.as_deref(), &mut memo)
        };
        // The rules compare the two roots as paths. One tree spelled two
        // ways is not "another tree": a base reached through a link above
        // it or a link to its root, `/tmp` and `/private/tmp`, `C:\` and
        // `\\?\C:\`.
        if let (Some(tree), Some(other)) = (&verdict.tree, &verdict.resolves_into) {
            if same_tree(tree, other) {
                verdict.resolves_into = None;
            }
        }
        verdict
    }

    /// The tree `dir` itself is the root of, by its own markers: the test
    /// a walker makes before it enters a directory. For a real directory
    /// it costs a `readlink` and a few `stat`s, walks nowhere and
    /// remembers nothing, because a walker meets each directory once and
    /// came down from one it already entered. With a tracked
    /// `--vendor_dir` a directory that holds no marker is also resolved,
    /// to compare it with the tracked ones however the walker spells it.
    ///
    /// A link is judged in full, by [`Classifier::classify`], and the
    /// answer is the tree it leads into: the markers of a directory do not
    /// say that it lies inside a tree, and every convenience link of a
    /// built workspace leads to such a place, with no marker anywhere
    /// below it. The root of the walk is `classify`'s to judge as well.
    pub fn tree_at(&self, dir: &Path) -> Found {
        // As in `classify`: `<link>/` is not a link to `read_link`.
        let dir: PathBuf = dir.components().collect();
        if Disk.read_link(&dir).is_some() {
            let verdict = self.classify(&dir);
            return Found {
                tree: verdict.tree,
                cannot_tell: verdict.cannot_tell,
            };
        }
        let own = output_tree::tree_at(&Disk, &dir, &self.vendor_dirs);
        if own.tree.is_some() || self.vendor_dirs.is_empty() {
            return own;
        }
        // The rules compared `dir` with the tracked directories as it is
        // spelled. They are kept absolute, as declared and as resolved.
        let tracked = |at: &PathBuf| self.vendor_dirs.contains(at);
        let spelled = std::path::absolute(&dir).ok();
        let real = spelled.as_deref().and_then(|at| resolve(at, MAX_LINK_HOPS));
        let is_tracked = [&spelled, &real].into_iter().flatten().any(tracked);
        Found {
            cannot_tell: !is_tracked && (own.cannot_tell || real.is_none()),
            tree: is_tracked.then_some(Tree {
                class: PathClass::VendorDir,
                root: dir,
            }),
        }
    }

    /// The trees the entries of `dir` give away, for a walker that holds
    /// its listing: `dir` itself when it holds a marker, and each child
    /// directory a marker beside it names (`<entry>.recorded_inputs`).
    /// `names` are the entries of `dir` that are not directories.
    ///
    /// Each name is first asked whether it can be a marker at all
    /// ([`output_tree::marked_dir`]), so a directory that holds none, which
    /// is every directory outside a Bazel tree, costs no `stat`; the ones
    /// a name points at are judged by [`Classifier::tree_at`]. The walker
    /// neither enters a returned root nor looks at anything in it.
    ///
    /// A directory only a tracked `--vendor_dir` names has no marker to
    /// list. It is returned all the same when it is `dir` or an entry of
    /// `dir` ([`Classifier::tracked_at`]), so that a walker keeps out of
    /// a vendor directory `bazel vendor` has yet to mark. A classifier
    /// that was told of none, which is every classifier outside a Bazel
    /// workspace, pays nothing for it.
    pub fn trees_marked_by<'a>(
        &self,
        dir: &Path,
        names: impl IntoIterator<Item = &'a OsStr>,
    ) -> Vec<Tree> {
        let mut trees: Vec<Tree> = Vec::new();
        for name in names {
            let Some(marked) = output_tree::marked_dir(dir, name) else {
                continue;
            };
            if trees.iter().any(|tree| tree.root == marked) {
                continue;
            }
            // A link is judged by where it leads, and a walker follows
            // none: only a tree rooted at the directory itself counts.
            let own = self.tree_at(&marked).tree;
            trees.extend(own.filter(|tree| tree.root == marked));
        }
        for tracked in self.tracked_at(dir) {
            if !trees.iter().any(|tree| tree.root == tracked.root) {
                trees.push(tracked);
            }
        }
        trees
    }

    /// The tracked vendor directories that are `dir` itself or entries of
    /// it, each spelled the way the caller spells `dir`: the roots a
    /// walker that lists `dir` must stay out of. The tracked directories
    /// are kept absolute, as declared and as resolved, so `dir` is
    /// compared both ways too, and only when there is one to compare with.
    pub fn tracked_at(&self, dir: &Path) -> Vec<Tree> {
        if self.vendor_dirs.is_empty() {
            return Vec::new();
        }
        let spelled = std::path::absolute(dir).ok();
        let real = spelled.as_deref().and_then(|at| resolve(at, MAX_LINK_HOPS));
        let here = |at: &Path| [&spelled, &real].into_iter().flatten().any(|d| d == at);
        let mut roots: Vec<PathBuf> = Vec::new();
        for tracked in &self.vendor_dirs {
            let root = match (here(tracked), tracked.parent(), tracked.file_name()) {
                (true, _, _) => dir.to_path_buf(),
                (false, Some(parent), Some(name)) if here(parent) => dir.join(name),
                _ => continue,
            };
            if !roots.contains(&root) {
                roots.push(root);
            }
        }
        let class = PathClass::VendorDir;
        let tree = |root| Tree { class, root };
        roots.into_iter().map(tree).collect()
    }
}

/// What [`vendor_dirs_at`] found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VendorDirs {
    /// The first-level entries of the root that are Bazel vendor
    /// directories, sorted.
    pub dirs: Vec<PathBuf>,
    /// The root could not be listed to its end, or a marker test went
    /// unanswered: the list may be short, and an empty one does not say
    /// that the root holds no vendor directory.
    pub cannot_tell: bool,
}

/// The first-level directories of the Bazel root `root` that are vendor
/// directories by what `bazel vendor` wrote into them: `VENDOR.bazel`, or
/// `.vendorignore` alone on 7.1.2, 7.2.0 and 7.2.1 (probe C11). A link to
/// such a directory counts as one.
///
/// A committed vendor directory is evidence that some command line passes
/// `--vendor_dir` even where no tracked rc file does (design 2.6): Bazel
/// then builds from it and a pin in the lock is a silent no-op. The
/// directory a tracked flag names needs no marker and is the caller's to
/// add. Only the first level is listed: that is where the flag's
/// customary values put it, and a deeper one is found by its marker when
/// a path into it is classified.
pub fn vendor_dirs_at(root: &Path) -> VendorDirs {
    let classifier = Classifier::new();
    let mut listed_all = true;
    let mut dirs = Vec::new();
    for entry in list(root, MAX_LISTED, &mut listed_all) {
        // A regular file is no directory; a link may lead to one.
        if entry.file_type().is_ok_and(|kind| kind.is_file()) {
            continue;
        }
        let found = classifier.tree_at(&entry.path());
        listed_all &= !found.cannot_tell;
        if found
            .tree
            .is_some_and(|tree| tree.class == PathClass::VendorDir)
        {
            dirs.push(entry.path());
        }
    }
    dirs.sort();
    VendorDirs {
        dirs,
        cannot_tell: !listed_all,
    }
}

/// Whether two trees the rules told apart by their roots' spelling are one
/// directory of one kind. Where the disk will not resolve a root they stay
/// two: naming a second tree is the careful answer.
fn same_tree(one: &Tree, other: &Tree) -> bool {
    let real = |tree: &Tree| resolve(&tree.root, MAX_LINK_HOPS);
    one.class == other.class && real(one).zip(real(other)).is_some_and(|(a, b)| a == b)
}

/// Classify one path with a fresh memo and no tracked vendor directory.
pub fn classify(path: &Path) -> Verdict {
    Classifier::new().classify(path)
}

/// `path` with every link followed, as far as the disk goes. For a path
/// that does not exist yet, its nearest existing ancestor is resolved and
/// the rest appended: that is where it would be created. A link whose
/// target is gone is followed by hand (at most `hops` of them), so a path
/// below a stale link into a live output base is still seen to lead there.
/// `None` when the disk refused to resolve the path, which is not the same
/// as resolving to itself.
fn resolve(path: &Path, hops: usize) -> Option<PathBuf> {
    for dir in path.ancestors() {
        let rest = path.strip_prefix(dir).ok()?;
        let with_rest = |real: PathBuf| {
            let whole = rest.as_os_str().is_empty();
            if whole {
                real
            } else {
                real.join(rest)
            }
        };
        match std::fs::canonicalize(dir) {
            Ok(real) => return Some(with_rest(real)),
            Err(err) if !is_absent(&err) => return None,
            Err(_) => {}
        }
        if let Some(target) = Disk.read_link(dir) {
            let target = dir.parent().map_or(target.clone(), |up| up.join(&target));
            return resolve(&with_rest(target), hops.checked_sub(1)?);
        }
    }
    None
}

/// Whether `path` is spelled with a `..` segment.
fn has_parent_dir(path: &Path) -> bool {
    path.components().any(|c| c == Component::ParentDir)
}

/// `path`, which is spelled with `..`, as the same entry spelled without:
/// the directory that holds it with every link followed, and its own name.
/// The name is kept because the entry may be a link, and a link is judged
/// as one ([`PathClass::Link`]) only while the path still names it; with
/// every link followed the path names the place the link leads to.
///
/// `None` when the path ends in `..` and so names no entry of its own, and
/// when the disk does not place the directory: it would not resolve it, or
/// a segment before a `..` is missing, which [`resolve`] appends as it is
/// spelled.
fn in_resolved_dir(path: &Path) -> Option<PathBuf> {
    let name = path.file_name()?;
    let dir = resolve(path.parent()?, MAX_LINK_HOPS)?;
    (!has_parent_dir(&dir)).then(|| dir.join(name))
}

/// Where a workspace's output base may be, beyond what its links in the
/// workspace root say. Relative paths are ignored: they would be read from
/// socket-patch's working directory, not from Bazel's.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Candidates {
    /// Output roots: each holds `_bazel_<user>` directories of bases.
    pub output_roots: Vec<PathBuf>,
    /// Values of `startup --output_user_root`: each holds bases.
    pub output_user_roots: Vec<PathBuf>,
    /// Values of `startup --output_base`.
    pub output_bases: Vec<PathBuf>,
    /// Directories other than the workspace root that hold convenience
    /// links: `<workspace>/dist` under `--symlink_prefix=dist/`.
    pub link_dirs: Vec<PathBuf>,
}

impl Candidates {
    /// What this process can name with no rc file read: the default roots
    /// under its own environment. A base moved by a `startup` line of the
    /// home rc file, or by a command line, is then found by its links or
    /// not at all.
    pub fn of_process() -> Self {
        #[cfg(unix)]
        let passwd_home = crate::utils::fs::passwd_home();
        #[cfg(not(unix))]
        let passwd_home: Option<PathBuf> = None;
        // The bytes, as the Bazel client reads them: a value that is not
        // UTF-8 is still a path.
        let env = |name: &str| std::env::var_os(name);
        Self {
            output_roots: default_output_roots(TargetOs::host(), &env, passwd_home.as_deref()),
            ..Self::default()
        }
    }
}

/// Every directory in which some Bazel release from 5.4.1 to 10 puts its
/// `_bazel_<user>` directory by default on `os` (gap-output-tree-recognition
/// 1.3; probe C6 on Linux and macOS, source only on Windows). The default
/// moved between releases, so one workspace can own a base under several
/// of them, and the order is no preference. An empty variable counts as
/// unset. `passwd_home` is the account's home from the user database,
/// which the client falls back to when `$HOME` is empty.
///
/// One empty variable is not unset to Bazel, and no root is listed for
/// it. The client asks only whether `TEST_TMPDIR` exists
/// (`IsRunningWithinTest`, `blaze_util.cc`), and an empty one names no
/// directory. Through 8.0.0 the server is then handed the relative root
/// `_bazel_<user>` and refuses to start (run on 5.4.1;
/// `startup_options.cc` reads the same through 8.0.0). From 8.1.0 the
/// client resolves that name in the directory the command was typed in,
/// the workspace root or a directory below it, and leaves a user root
/// there (probe C6 cell E11, run on 9.3.2 from a workspace root;
/// `startup_options.cc` reads the same from 8.1.0 to 10.0.0rc3, not run).
/// That directory is Bazel's working directory, not this process's, so it
/// cannot be named here. [`locate_output_base`] looks for such a user root
/// in the workspace root whatever the environment says; one that a
/// command typed further down left is found by a link or not at all.
/// Classifying a path needs none of this: the base is known by its marker
/// wherever it lies.
pub fn default_output_roots(
    os: TargetOs,
    env: &dyn Fn(&str) -> Option<OsString>,
    passwd_home: Option<&Path>,
) -> Vec<PathBuf> {
    let var = |name: &str| env(name).filter(|v| !v.is_empty()).map(PathBuf::from);
    let unix_home = || var("HOME").or_else(|| passwd_home.map(Path::to_path_buf));
    // `$XDG_CACHE_HOME/bazel`: Linux from 7.2.0, macOS from 8.4.0, Windows
    // from 10.0.0.
    let mut roots: Vec<PathBuf> = var("XDG_CACHE_HOME")
        .map(|xdg| xdg.join("bazel"))
        .into_iter()
        .collect();
    match os {
        // With no home at all (a uid with no passwd entry in a container)
        // the client uses `/tmp`.
        TargetOs::Linux => roots.push(unix_home().map_or_else(
            || PathBuf::from("/tmp"),
            |home| home.join(".cache").join("bazel"),
        )),
        TargetOs::MacOs => {
            // Through 8.x, and later with no home.
            roots.push(PathBuf::from("/var/tmp"));
            // From 9.0.0.
            roots.extend(unix_home().map(|home| home.join("Library/Caches/bazel")));
        }
        // No `bazel` segment: the user root is `<home>\_bazel_<user>`. The
        // profile folder the client asks the shell for when both are empty
        // is not looked up.
        TargetOs::Windows => roots.extend(var("HOME").or_else(|| var("USERPROFILE"))),
    }
    // A client that sees `TEST_TMPDIR` uses it whatever else is set. An
    // empty one names no directory this function knows: see above.
    roots.extend(var("TEST_TMPDIR"));
    let mut seen = std::collections::HashSet::new();
    roots.retain(|root| seen.insert(root.clone()));
    roots
}

/// The first `cap` entries of `dir`. `listed_all` is cleared when the
/// directory could not be read to its end; a directory that is not there
/// lists as empty.
fn list(dir: &Path, cap: usize, listed_all: &mut bool) -> Vec<std::fs::DirEntry> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) => {
            *listed_all &= is_absent(&err);
            return Vec::new();
        }
    };
    let mut listed = Vec::new();
    for entry in entries {
        match entry {
            Ok(entry) if listed.len() < cap => listed.push(entry),
            _ => {
                *listed_all = false;
                break;
            }
        }
    }
    listed
}

/// What the marker of an output base says about a workspace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Marker {
    /// Its bytes are the workspace's path.
    Names,
    /// It was read and they are not: another workspace's path, this path
    /// in another encoding, an oversized file. Or there is no regular file
    /// to read. Either way nothing is known about the base.
    Other,
    /// A regular file that could not be opened or read to its end. It may
    /// name the workspace.
    Unread,
}

/// What the marker of `base` says about `workspace` (canonical).
fn marker_names_workspace(base: &Path, workspace: &Path) -> Marker {
    let marker = base.join(OUTPUT_BASE_MARKER);
    let mut bytes = Vec::new();
    let read = open_regular_file_sync(&marker)
        .and_then(|(file, _)| file.take(MAX_MARKER_BYTES).read_to_end(&mut bytes));
    match read {
        Ok(_) if output_tree::marker_names(&bytes, workspace) => Marker::Names,
        Ok(_) => Marker::Other,
        // The guard's own refusal has no kind of its own and opening a
        // directory fails by OS, so the entry says which failure this was.
        Err(_) => match Disk.stat(&marker) {
            Entry::File | Entry::Unknown => Marker::Unread,
            Entry::Dir | Entry::Neither => Marker::Other,
        },
    }
}

/// The absolute paths among `dirs`. A relative one would be read from
/// socket-patch's working directory, not from Bazel's.
fn absolute_only(dirs: &[PathBuf]) -> Vec<PathBuf> {
    let kept = dirs.iter().filter(|dir| dir.is_absolute());
    kept.cloned().collect()
}

/// Locate the output base of the Bazel workspace rooted at `workspace`
/// without running Bazel, to word a message. No lane reads evidence from
/// the answer.
///
/// The links in the workspace root (and in `candidates.link_dirs`) are
/// read first: only they name the base of the last build. With no link,
/// every base under the candidate roots is asked whether its marker names
/// this workspace, and two that do make the answer `CannotTell`. A user
/// name with `/` in it nests the bases one level deeper on Bazel 9 and
/// earlier; those are not listed and are found by a link or not at all.
///
/// The workspace root is itself a candidate root, with no caller naming
/// it: a `_bazel_<user>` directory lies there when Bazel 8.1.0 or later
/// ran from the root under an empty `TEST_TMPDIR` (probe C6 cell E11; see
/// [`default_output_roots`]), and no environment this process reads
/// later says so.
///
/// What the disk would not show is never read as absent: a directory that
/// could not be listed, a link target or a candidate base that could not
/// be read, and a marker that could not be opened each leave the answer
/// at `CannotTell` where it would have been `NotFound` or the one base
/// that could be read.
pub fn locate_output_base(workspace: &Path, candidates: &Candidates) -> Located {
    let Ok(workspace) = std::fs::canonicalize(workspace) else {
        return Located::CannotTell(Unsure::Unlisted);
    };
    // Cleared by everything the disk kept back, not only by a listing.
    let mut listed_all = true;
    let candidate = |base: PathBuf, listed_all: &mut bool| {
        let marker = marker_names_workspace(&base, &workspace);
        *listed_all &= marker != Marker::Unread;
        Candidate {
            names_workspace: marker == Marker::Names,
            // One spelling per base, so `/var/tmp` and `/private/var/tmp`
            // count once.
            base: std::fs::canonicalize(&base).unwrap_or(base),
        }
    };

    let mut linked = Vec::new();
    for dir in std::iter::once(workspace.clone()).chain(absolute_only(&candidates.link_dirs)) {
        for entry in list(&dir, MAX_LISTED, &mut listed_all) {
            if !entry.file_type().is_ok_and(|kind| kind.is_symlink()) {
                continue;
            }
            let Some(target) = Disk.read_link(&entry.path()) else {
                continue;
            };
            match output_tree::base_of_link_target(&Disk, &dir.join(target)) {
                LinkRoute::Base(base) => linked.push(candidate(base, &mut listed_all)),
                LinkRoute::Unanswered => listed_all = false,
                LinkRoute::NoBase => {}
            }
        }
    }
    if !linked.is_empty() {
        return output_tree::locate(&linked, &[], listed_all);
    }

    let mut user_roots = absolute_only(&candidates.output_user_roots);
    // The workspace root first: see above. It is listed a second time
    // only here, where no link named a base.
    let output_roots = absolute_only(&candidates.output_roots);
    for root in std::iter::once(workspace.clone()).chain(output_roots) {
        let entries = list(&root, MAX_LISTED, &mut listed_all).into_iter();
        let users = entries.filter(|e| e.file_name().as_encoded_bytes().starts_with(b"_bazel_"));
        user_roots.extend(users.map(|entry| entry.path()));
    }
    let mut bases = absolute_only(&candidates.output_bases);
    for user_root in user_roots {
        let entries = list(&user_root, MAX_LISTED, &mut listed_all);
        bases.extend(entries.iter().map(|entry| entry.path()));
    }
    let mut enumerated = Vec::new();
    for dir in bases {
        let own = output_tree::tree_at(&Disk, &dir, &[]);
        listed_all &= !own.cannot_tell;
        let class = own.tree.map(|tree| tree.class);
        if class == Some(PathClass::OutputBase) {
            enumerated.push(candidate(dir, &mut listed_all));
        }
    }
    output_tree::locate(&[], &enumerated, listed_all)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use crate::bazel::output_tree::PathClass::{
        Link, OutputBase, Plain, RepoContentsCache, RepositoryCache, VendorDir,
    };
    use crate::bazel::output_tree::Route;

    /// An output base as a server and a build leave it (probe C7).
    const BASE: &str = "
        {base}/DO_NOT_BUILD_HERE
        {base}/external/rules_x+/
        {base}/execroot/_main/bazel-out/k8/bin/node_modules/left-pad/";

    /// An output base as `bazel clean --async` leaves it until the next
    /// server starts (Bazel 9.3.2): `execroot` is renamed away and deleted
    /// in the background, and the marker, `external/`, `server/` and
    /// `sandbox/` stay, with `install`, a link to the install base.
    const CLEANED_ASYNC: &str = "
        {base}/DO_NOT_BUILD_HERE
        {base}/external/rules_x+/pnpm-lock.yaml
        {base}/server/
        {base}/sandbox/";

    /// The second marker. `bazel clean` deletes it and only a new server
    /// writes it again, so a base that was cleaned and built has none.
    const EXECROOT_MARKER: &str = "{base}/execroot/DO_NOT_BUILD_HERE";

    /// The convenience links of a build.
    #[cfg(unix)]
    const LINKS: &str = "
        {ws}/bazel-out -> {base}/execroot/_main/bazel-out
        {ws}/bazel-bin -> {base}/execroot/_main/bazel-out/k8/bin
        {ws}/bazel-testlogs -> {base}/execroot/_main/bazel-out/k8/testlogs
        {ws}/bazel-proj -> {base}/execroot/_main";

    /// A temporary directory, canonical (`/var/folders` is a link on
    /// macOS), and the layouts written into it.
    struct Scratch {
        _tmp: tempfile::TempDir,
        root: PathBuf,
    }

    impl Scratch {
        fn new() -> Self {
            let tmp = tempfile::tempdir().unwrap();
            let root = fs::canonicalize(tmp.path()).unwrap();
            Self { _tmp: tmp, root }
        }

        fn at(&self, rel: &str) -> PathBuf {
            self.root.join(rel)
        }

        /// Writes `layout`, one entry per line under the root: `path` is a
        /// file, `path/` a directory, `link -> target` a link. `{ws}` and
        /// `{base}` stand for a workspace and an output base, and a marker
        /// file holds the workspace path the way Bazel writes it.
        fn lay(&self, ws: &str, base: &str, layout: &str) {
            for line in layout.lines().map(str::trim).filter(|l| !l.is_empty()) {
                let line = line.replace("{ws}", ws).replace("{base}", base);
                let (at, target) = match line.split_once(" -> ") {
                    Some((at, target)) => (at, Some(self.at(target))),
                    None => (line.as_str(), None),
                };
                let path = self.at(at);
                if at.ends_with('/') {
                    fs::create_dir_all(&path).unwrap();
                    continue;
                }
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                let marker = self.at(ws);
                match target {
                    Some(target) => symlink(&target, &path),
                    None if at.ends_with(OUTPUT_BASE_MARKER) => {
                        fs::write(&path, bytes(&marker)).unwrap()
                    }
                    None => fs::write(&path, b"").unwrap(),
                }
            }
        }
    }

    #[cfg(unix)]
    fn symlink(target: &Path, link: &Path) {
        std::os::unix::fs::symlink(target, link).unwrap();
    }

    #[cfg(not(unix))]
    fn symlink(_target: &Path, link: &Path) {
        panic!("{}: this host's tests make no symlink", link.display());
    }

    fn bytes(path: &Path) -> &[u8] {
        path.as_os_str().as_encoded_bytes()
    }

    fn tree(class: PathClass, root: PathBuf) -> Option<Tree> {
        Some(Tree { class, root })
    }

    fn found(base: PathBuf, route: Route) -> Located {
        Located::Base { base, route }
    }

    fn roots(disk: &Scratch, output_roots: &[&str]) -> Candidates {
        Candidates {
            output_roots: output_roots.iter().map(|root| disk.at(root)).collect(),
            ..Candidates::default()
        }
    }

    /// What `read` returns while `path` has no permission bit set, or
    /// `None` where that hides nothing: root reads everything.
    #[cfg(unix)]
    fn while_locked<T>(path: &Path, read: impl FnOnce() -> T) -> Option<T> {
        use std::os::unix::fs::PermissionsExt;
        let before = fs::metadata(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o000)).unwrap();
        let hidden = if before.is_dir() {
            fs::read_dir(path).is_err()
        } else {
            fs::File::open(path).is_err()
        };
        let got = hidden.then(read);
        fs::set_permissions(path, before.permissions()).unwrap();
        got
    }

    #[cfg(unix)]
    #[test]
    fn a_base_is_classified_through_its_links_after_build_and_after_clean() {
        for execroot_marker in [EXECROOT_MARKER, ""] {
            let disk = Scratch::new();
            let more = "
                {ws}/src/package.json
                {ws}/dist/bin -> {base}/execroot/_main/bazel-out/k8/bin";
            let layout = [BASE, execroot_marker, LINKS, more].join("\n");
            disk.lay("ws", "root/_bazel_u/6d82", &layout);
            let classifier = Classifier::new();
            for (path, want) in [
                ("ws/bazel-bin", Link),
                ("ws/bazel-proj", Link),
                // `--symlink_prefix=dist/`.
                ("ws/dist/bin", Link),
                // `scan --cwd bazel-bin`, and a file a patch would add.
                ("ws/bazel-bin/node_modules/left-pad", OutputBase),
                (
                    "ws/bazel-bin/node_modules/left-pad/new/index.js",
                    OutputBase,
                ),
                ("root/_bazel_u/6d82/external/rules_x+", OutputBase),
                ("root/_bazel_u/6d82", OutputBase),
                ("ws", Plain),
                ("ws/src/package.json", Plain),
                ("ws/src/new/file.js", Plain),
            ] {
                let verdict = classifier.classify(&disk.at(path));
                assert_eq!(
                    (verdict.class, verdict.cannot_tell),
                    (want, false),
                    "{path}"
                );
                let base = tree(OutputBase, disk.at("root/_bazel_u/6d82"));
                assert_eq!(verdict.tree, base.filter(|_| want != Plain), "{path}");
                // Stored where it is spelled: no second tree.
                assert_eq!(verdict.resolves_into, None, "{path}");
            }
        }
    }

    #[test]
    fn a_base_whose_execroot_was_renamed_away_is_still_a_base() {
        let disk = Scratch::new();
        let base = "root/_bazel_u/6d82";
        disk.lay("ws", base, &[CLEANED_ASYNC, "{ws}/MODULE.bazel"].join("\n"));
        disk.lay("", "", "root/_bazel_u/install/7b1f/embedded_tools/");
        if cfg!(unix) {
            // `old-bin` is a link an earlier `--symlink_prefix` left, in a
            // checkout of its own so that this workspace has no link.
            let links = "
                {base}/install -> root/_bazel_u/install/7b1f
                {ws}/old-bin -> {base}/execroot/_main/bazel-out/k8/bin";
            disk.lay("stale", base, links);
        }
        let classifier = Classifier::new();
        let root = tree(OutputBase, disk.at(base));
        for path in [
            "root/_bazel_u/6d82",
            "root/_bazel_u/6d82/external/rules_x+",
            "root/_bazel_u/6d82/external/rules_x+/pnpm-lock.yaml",
            "root/_bazel_u/6d82/external/rules_x+/new/file.js",
            "root/_bazel_u/6d82/server",
        ] {
            let verdict = classifier.classify(&disk.at(path));
            assert_eq!(
                (verdict.class, verdict.cannot_tell, verdict.resolves_into),
                (OutputBase, false, None),
                "{path}"
            );
            assert_eq!(verdict.tree, root, "{path}");
        }
        if cfg!(unix) {
            // The link route never needed the directory.
            let stale = classifier.classify(&disk.at("stale/old-bin"));
            assert_eq!((stale.class, stale.tree), (Link, root.clone()));
            let below = classifier.classify(&disk.at("stale/old-bin/node_modules"));
            assert_eq!((below.class, below.tree), (OutputBase, root.clone()));
        }
        assert_eq!(classifier.classify(&disk.at("ws")).class, Plain);
        // A walker stops at it, and it is this workspace's one base.
        assert_eq!(classifier.tree_at(&disk.at(base)).tree, root);
        let located = locate_output_base(&disk.at("ws"), &roots(&disk, &["root"]));
        assert_eq!(located, found(disk.at(base), Route::Enumeration));

        // Any one of the directories beside the marker is enough, and
        // nothing else is: another directory, a file under one of the
        // names.
        let mut cases = vec![
            ("{base}/execroot/", true),
            ("{base}/external/", true),
            ("{base}/server/", true),
            ("{base}/install/", true),
            ("{base}/sandbox/", false),
            ("{base}/server", false),
            ("{base}/external", false),
            ("", false),
        ];
        if cfg!(unix) {
            cases.push(("{base}/install -> root/_bazel_u/install/7b1f", true));
            cases.push(("{base}/install -> root/_bazel_u/install/gone", false));
        }
        for (nth, (beside, is_base)) in cases.into_iter().enumerate() {
            let base = format!("lone/{nth}");
            let layout = ["{base}/DO_NOT_BUILD_HERE", beside].join("\n");
            disk.lay("ws", &base, &layout);
            let own = Classifier::new().tree_at(&disk.at(&base));
            let want = tree(OutputBase, disk.at(&base)).filter(|_| is_base);
            assert_eq!((own.tree, own.cannot_tell), (want, false), "{beside}");
            let class = if is_base { OutputBase } else { Plain };
            let inside = classify(&disk.at(&base).join("external/rules_x+/BUILD"));
            assert_eq!(
                (inside.class, inside.cannot_tell),
                (class, false),
                "{beside}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_repository_stored_outside_the_base_names_both_trees() {
        let disk = Scratch::new();
        // Bazel 9: `external/<repo>` is a link into the contents cache
        // that all of the user's workspaces share (probe C3).
        let more = "
            cache/contents/cd12/6488/package/package.json
            cache/contents/cd12/6488.recorded_inputs
            {base}/external/npm+left-pad -> cache/contents/cd12/6488
            {ws}/bazel-bin -> {base}/execroot/_main/bazel-out/k8/bin
            {ws}/old-bin -> {base}/execroot/_main/bazel-out/k8-opt/bin
            {ws}/older -> {ws}/old-bin
            {ws}/gone -> nowhere/execroot/_main
            {ws}/loop-a -> {ws}/loop-b
            {ws}/loop-b -> {ws}/loop-a
            {ws}/bazel-notes -> cache";
        disk.lay("ws", "base", &[BASE, EXECROOT_MARKER, more].join("\n"));
        let entry = tree(RepoContentsCache, disk.at("cache/contents/cd12/6488"));
        let repo = classify(&disk.at("base/external/npm+left-pad/package/package.json"));
        assert_eq!(
            (repo.class, repo.resolves_into),
            (OutputBase, entry.clone())
        );
        assert_eq!(
            classify(&disk.at("cache/contents/cd12/6488/package")).tree,
            entry
        );
        // A link left under an old prefix, into a directory `clean` has
        // removed: it resolves to nothing and still leads into the base,
        // and so does a path below it, through one stale link or two.
        let base = tree(OutputBase, disk.at("base"));
        for (path, want) in [
            ("ws/old-bin", Link),
            ("ws/older", Link),
            ("ws/old-bin/node_modules/left-pad", OutputBase),
            ("ws/older/node_modules", OutputBase),
        ] {
            let stale = classify(&disk.at(path));
            assert_eq!((stale.class, stale.tree), (want, base.clone()), "{path}");
        }
        // A trailing separator names the same entry, live or stale: the
        // answer is the one for the path without it.
        for (path, want) in [
            ("ws/bazel-bin/", Link),
            ("ws/old-bin/", Link),
            ("ws/old-bin/.", Link),
            ("ws/bazel-bin//", Link),
            ("ws/old-bin/node_modules/", OutputBase),
            ("base/external/", OutputBase),
            ("ws/", Plain),
        ] {
            let spelled = disk.at(path);
            assert!(bytes(&spelled).ends_with(path.as_bytes()), "{path}");
            let verdict = classify(&spelled);
            let tree = base.clone().filter(|_| want != Plain);
            assert_eq!(
                (verdict.class, verdict.tree, verdict.cannot_tell),
                (want, tree, false),
                "{path}"
            );
        }
        // A link to an ordinary directory is nothing, whatever its name,
        // and so is one to nowhere. Links that never end prove nothing.
        for (path, unproven) in [
            ("ws/bazel-notes", false),
            ("ws/gone/bazel-out", false),
            ("ws/loop-a", true),
        ] {
            let verdict = classify(&disk.at(path));
            assert_eq!(
                (verdict.class, verdict.cannot_tell),
                (Plain, unproven),
                "{path}"
            );
        }
    }

    #[test]
    fn a_path_is_judged_where_it_resolves() {
        // `--output_base=<ws>/out` (probe C8).
        let disk = Scratch::new();
        disk.lay("ws", "ws/out", &[BASE, "{ws}/src/package.json"].join("\n"));
        let classifier = Classifier::new();
        // `out/../src` is not in `out`, and `src/../out` is.
        let beside = classifier.classify(&disk.at("ws/out/../src/package.json"));
        assert_eq!((beside.class, beside.cannot_tell), (Plain, false));
        let inside = classifier.classify(&disk.at("ws/src/../out/external/rules_x+"));
        assert_eq!(inside.tree, tree(OutputBase, disk.at("ws/out")));
        // A missing tail that names `..` cannot be placed by anyone.
        let nowhere = classifier.classify(&disk.at("ws/missing/../out/external"));
        if cfg!(unix) {
            assert_eq!((nowhere.class, nowhere.cannot_tell), (Plain, true));
        }
        // No path at all is no proof of anything.
        let nothing = classify(Path::new(""));
        assert_eq!((nothing.class, nothing.cannot_tell), (Plain, true));
    }

    /// A `..` in the path does not change what the entry is: a link
    /// reached through one is the link, not the place it leads to, and
    /// the `..` is taken by the disk, not by the spelling.
    #[cfg(unix)]
    #[test]
    fn a_link_reached_through_dot_dot_is_still_a_link() {
        let disk = Scratch::new();
        let more = "
            {ws}/app/package.json
            {ws}/dist/bin -> {base}/execroot/_main/bazel-out/k8/bin
            {ws}/old-bin -> {base}/execroot/_main/bazel-out/k8-opt/bin
            {ws}/ob -> {base}
            {ws}/notes -> {ws}/app
            {ws}/gone -> nowhere/execroot/_main";
        disk.lay("ws", "root/_bazel_u/6d82", &[BASE, LINKS, more].join("\n"));
        let classifier = Classifier::new();
        let base = tree(OutputBase, disk.at("root/_bazel_u/6d82"));
        for (dotted, plain, want) in [
            // A project root given as `--cwd ..`, a pattern re-rooted at a
            // parent.
            ("ws/app/../bazel-bin", "ws/bazel-bin", Link),
            ("ws/app/../dist/../bazel-proj", "ws/bazel-proj", Link),
            ("ws/app/../dist/bin", "ws/dist/bin", Link),
            ("ws/dist/../app/../dist/bin", "ws/dist/bin", Link),
            // Stale: its base is live.
            ("ws/app/../old-bin", "ws/old-bin", Link),
            // A link to the root of a tree is that root, as spelled.
            ("ws/app/../ob", "ws/ob", OutputBase),
            // Below a link the path is where it is stored.
            (
                "ws/app/../bazel-bin/node_modules/left-pad",
                "ws/bazel-bin/node_modules/left-pad",
                OutputBase,
            ),
            (
                "ws/app/../old-bin/new/file.js",
                "ws/old-bin/new/file.js",
                OutputBase,
            ),
            // Ordinary links and ordinary files stay what they are.
            ("ws/app/../notes", "ws/notes", Plain),
            ("ws/app/../gone", "ws/gone", Plain),
            ("ws/dist/../app/package.json", "ws/app/package.json", Plain),
        ] {
            let spelled = disk.at(dotted);
            assert!(has_parent_dir(&spelled), "{dotted}");
            let verdict = classifier.classify(&spelled);
            assert_eq!(
                (verdict.class, verdict.cannot_tell),
                (want, false),
                "{dotted}"
            );
            if want == Link {
                assert_eq!(verdict.tree, base, "{dotted}");
            }
            // In full, the answer of the same entry spelled without `..`.
            assert_eq!(verdict, classifier.classify(&disk.at(plain)), "{dotted}");
        }
        // A walker's test of the entry agrees.
        let own = classifier.tree_at(&disk.at("ws/app/../bazel-bin"));
        assert_eq!((own.tree, own.cannot_tell), (base.clone(), false));

        // The disk takes a `..` after a link from where the link leads:
        // `bazel-proj/..` is `<base>/execroot`, not the workspace.
        for (path, want) in [
            ("ws/bazel-proj/../_main/bazel-out", OutputBase),
            ("ws/bazel-bin/..", OutputBase),
            ("ws/notes/..", Plain),
            ("ws/app/..", Plain),
        ] {
            let verdict = classifier.classify(&disk.at(path));
            assert_eq!(
                (verdict.class, verdict.cannot_tell),
                (want, false),
                "{path}"
            );
            assert_eq!(
                verdict.tree,
                base.clone().filter(|_| want != Plain),
                "{path}"
            );
        }
    }

    #[test]
    fn a_walker_prunes_by_a_directory_s_own_markers() {
        let disk = Scratch::new();
        let sha256 = "87d8263a29f202dab6acea9f28262585d34aa0d6fc45683d74d929ffa339a198";
        // An in-tree base, vendor directories of Bazel 7.3+ and of 7.1.2 -
        // 7.2.1 (probe C11), an in-tree repository cache, and a directory
        // only a tracked `--vendor_dir` names.
        let more = format!(
            "{{ws}}/vendor_src/VENDOR.bazel
             {{ws}}/third_party/.vendorignore
             {{ws}}/third_party/rules_x~/go.mod
             {{ws}}/.cache/content_addressable/sha256/{sha256}/file
             {{ws}}/.cache/contents/cd12/1/BUILD.bazel
             {{ws}}/.cache/contents/cd12/1.recorded_inputs
             {{ws}}/deps/+x+y/"
        );
        disk.lay("ws", "ws/out", &[BASE, &more].join("\n"));
        let classifier = Classifier::with_vendor_dirs([disk.at("ws/deps")]);
        let cas = format!("ws/.cache/content_addressable/sha256/{sha256}");
        for (dir, want) in [
            ("ws/out", Some(OutputBase)),
            ("ws/vendor_src", Some(VendorDir)),
            ("ws/third_party", Some(VendorDir)),
            ("ws/deps", Some(VendorDir)),
            ("ws/.cache/contents/cd12/1", Some(RepoContentsCache)),
            (cas.as_str(), Some(RepositoryCache)),
            // Only the directory that holds the marker answers: the walk
            // has stopped at it and never asks below.
            ("ws/out/external", None),
            ("ws/third_party/rules_x~", None),
            ("ws/.cache/contents/cd12", None),
            ("ws", None),
        ] {
            let own = classifier.tree_at(&disk.at(dir));
            let root = want.and_then(|class| tree(class, disk.at(dir)));
            assert_eq!((own.tree, own.cannot_tell), (root, false), "{dir}");
        }
        // The full classifier agrees below each of them.
        let lock = classifier.classify(&disk.at("ws/third_party/rules_x~/go.mod"));
        assert_eq!(lock.tree, tree(VendorDir, disk.at("ws/third_party")));
        let payload = classifier.classify(&disk.at(&cas).join("file"));
        assert_eq!(payload.tree, tree(RepositoryCache, disk.at(&cas)));
        assert_eq!(
            classifier.classify(&disk.at("ws/deps/+x+y")).class,
            VendorDir
        );
        assert_eq!(classify(&disk.at("ws/deps/+x+y")).class, Plain);
        // One classifier serves every task of a run.
        fn shared<T: Send + Sync>(_: &T) {}
        shared(&classifier);
    }

    /// The names of the entries of `dir` that are not directories: what a
    /// walker hands to `trees_marked_by`.
    fn file_names(dir: &Path) -> Vec<OsString> {
        let entries = fs::read_dir(dir).unwrap().map(Result::unwrap);
        let files = entries.filter(|entry| !entry.file_type().unwrap().is_dir());
        files.map(|entry| entry.file_name()).collect()
    }

    #[test]
    fn a_listing_names_the_trees_a_walker_must_not_enter() {
        let disk = Scratch::new();
        let sha256 = "87d8263a29f202dab6acea9f28262585d34aa0d6fc45683d74d929ffa339a198";
        let cas = format!("ws/.cache/content_addressable/sha256/{sha256}");
        // The last two are named like markers and mark nothing: no
        // directory of a base beside the first, and the second is outside
        // a cache entry.
        let more = format!(
            "{{ws}}/package.json
             {{ws}}/vendor_src/VENDOR.bazel
             {{ws}}/third_party/.vendorignore
             {{ws}}/.cache/content_addressable/sha256/{sha256}/file
             {{ws}}/.cache/contents/cd12/1/BUILD.bazel
             {{ws}}/.cache/contents/cd12/1.recorded_inputs
             {{ws}}/.cache/contents/cd12/2/BUILD.bazel
             {{ws}}/notes/DO_NOT_BUILD_HERE
             {{ws}}/docs/file"
        );
        disk.lay("ws", "ws/out", &[BASE, &more].join("\n"));
        let classifier = Classifier::new();
        let marked = |dir: &str, names: &[OsString]| {
            let names = names.iter().map(OsString::as_os_str);
            classifier.trees_marked_by(&disk.at(dir), names)
        };
        for (dir, want) in [
            ("ws/out", vec![(OutputBase, "ws/out")]),
            ("ws/vendor_src", vec![(VendorDir, "ws/vendor_src")]),
            ("ws/third_party", vec![(VendorDir, "ws/third_party")]),
            (cas.as_str(), vec![(RepositoryCache, cas.as_str())]),
            // The marker of a contents-cache entry lies beside it, so its
            // parent's listing is what names it, and only it.
            (
                "ws/.cache/contents/cd12",
                vec![(RepoContentsCache, "ws/.cache/contents/cd12/1")],
            ),
            ("ws/.cache/contents/cd12/1", vec![]),
            ("ws", vec![]),
            ("ws/notes", vec![]),
            ("ws/docs", vec![]),
        ] {
            let want: Vec<Tree> = want
                .into_iter()
                .filter_map(|(class, root)| tree(class, disk.at(root)))
                .collect();
            assert_eq!(marked(dir, &file_names(&disk.at(dir))), want, "{dir}");
        }
        // The names decide what is asked: a marker the listing does not
        // name is never looked for.
        assert_eq!(marked("ws/out", &[]), vec![]);
        assert_eq!(marked("ws/out", &["README".into()]), vec![]);
    }

    #[test]
    fn the_vendor_directories_of_a_root_are_its_marked_first_level_entries() {
        let disk = Scratch::new();
        // Bazel 7.3 and later write `VENDOR.bazel`; 7.1.2, 7.2.0 and 7.2.1
        // only `.vendorignore` (probe C11). Not vendor directories: an
        // in-tree output base, a directory below the first level, a file,
        // and the root's own stray marker.
        let more = "
            {ws}/MODULE.bazel
            {ws}/VENDOR.bazel
            {ws}/notes
            {ws}/src/package.json
            {ws}/vendor_src/VENDOR.bazel
            {ws}/vendor_src/+http+dep/package-lock.json
            {ws}/third_party/.vendorignore
            {ws}/tools/deps/VENDOR.bazel";
        disk.lay("ws", "ws/out", &[BASE, more].join("\n"));
        let found = vendor_dirs_at(&disk.at("ws"));
        let want = vec![disk.at("ws/third_party"), disk.at("ws/vendor_src")];
        assert_eq!((found.dirs, found.cannot_tell), (want, false));

        assert_eq!(vendor_dirs_at(&disk.at("ws/src")), VendorDirs::default());
        // A root that is not there holds none, and that is known.
        assert_eq!(vendor_dirs_at(&disk.at("gone")), VendorDirs::default());
    }

    #[cfg(unix)]
    #[test]
    fn a_link_to_a_vendor_directory_counts_and_an_unread_root_is_not_empty() {
        let disk = Scratch::new();
        let layout = "
            shared/vendor/VENDOR.bazel
            shared/vendor/+http+dep/go.mod
            {ws}/deps -> shared/vendor
            {ws}/one -> shared/vendor/+http+dep
            {ws}/bazel-bin -> {base}/execroot/_main/bazel-out/k8/bin
            {ws}/stale -> nowhere";
        disk.lay("ws", "root/_bazel_u/6d82", &[BASE, layout].join("\n"));
        let found = vendor_dirs_at(&disk.at("ws"));
        // Both lead into the vendor directory; the convenience link leads
        // into an output base, which is another kind of tree.
        let want = vec![disk.at("ws/deps"), disk.at("ws/one")];
        assert_eq!((found.dirs, found.cannot_tell), (want, false));

        let unread = while_locked(&disk.at("ws"), || vendor_dirs_at(&disk.at("ws")));
        if let Some(unread) = unread {
            assert_eq!((unread.dirs, unread.cannot_tell), (vec![], true));
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_walker_is_told_where_a_link_leads() {
        let disk = Scratch::new();
        // Every built workspace holds four links to places inside its
        // base. No marker is at or below any of them, so the markers of
        // the entry alone would send a walker that follows links through
        // the whole output tree.
        let more = "
            {ws}/src/package.json
            {ws}/store/dep/package.json
            {ws}/dist/bin -> {base}/execroot/_main/bazel-out/k8/bin
            {ws}/old-bin -> {base}/execroot/_main/bazel-out/k8-opt/bin
            {ws}/ob -> {base}
            {ws}/node_modules/dep -> {ws}/store/dep
            {ws}/bazel-notes -> {ws}/src
            {ws}/gone -> nowhere/execroot/_main";
        disk.lay("ws", "root/_bazel_u/6d82", &[BASE, LINKS, more].join("\n"));
        let classifier = Classifier::new();
        let base = tree(OutputBase, disk.at("root/_bazel_u/6d82"));
        for link in [
            "ws/bazel-bin",
            "ws/bazel-out",
            "ws/bazel-proj",
            // `--symlink_prefix=dist/`.
            "ws/dist/bin",
            // Stale: a configuration `clean` removed, and one never built.
            "ws/old-bin",
            "ws/bazel-testlogs",
            "ws/bazel-bin/",
        ] {
            let entry = disk.at(link);
            let own = classifier.tree_at(&entry);
            assert_eq!((own.tree, own.cannot_tell), (base.clone(), false), "{link}");
            // What the markers alone say of a link into a tree.
            let by_markers = output_tree::tree_at(&Disk, &entry, &[]);
            assert_eq!(by_markers, Found::default(), "{link}");
        }
        // A link to the root of a tree is that tree's root, as spelled.
        let own = classifier.tree_at(&disk.at("ws/ob"));
        assert_eq!(own.tree, tree(OutputBase, disk.at("ws/ob")));
        // A link that leads nowhere near a tree is entered like the
        // directory it leads to.
        for link in ["ws/node_modules/dep", "ws/bazel-notes", "ws/gone"] {
            assert_eq!(
                classifier.tree_at(&disk.at(link)),
                Found::default(),
                "{link}"
            );
        }
        for dir in ["ws", "ws/src", "ws/dist", "ws/not-there"] {
            assert_eq!(classifier.tree_at(&disk.at(dir)), Found::default(), "{dir}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn one_tree_spelled_two_ways_is_one_tree() {
        let disk = Scratch::new();
        // `alias` stands for a link above everything, as `/tmp` and `/var`
        // are on macOS; `ob` and `vend` are links to the root of a tree.
        let more = "
            alias -> real
            {ws}/ob -> {base}
            {ws}/vendor_src/VENDOR.bazel
            {ws}/vendor_src/+http+dep/package.json
            {ws}/vend -> {ws}/vendor_src
            second/DO_NOT_BUILD_HERE
            second/execroot/_main/
            second/external/rules_y+/
            {base}/external/borrowed -> second/external/rules_y+";
        disk.lay("real/ws", "real/base", &[BASE, more].join("\n"));
        let classifier = Classifier::new();
        let base = |root: &str| tree(OutputBase, disk.at(root));
        for (path, root) in [
            ("real/base/external/rules_x+", "real/base"),
            ("alias/base", "alias/base"),
            ("alias/base/external/rules_x+", "alias/base"),
            ("alias/base/external/rules_x+/new/file.js", "alias/base"),
            ("real/ws/ob", "real/ws/ob"),
            ("real/ws/ob/external/rules_x+", "real/ws/ob"),
            ("alias/ws/ob/external/rules_x+", "alias/ws/ob"),
        ] {
            let verdict = classifier.classify(&disk.at(path));
            assert_eq!(
                (verdict.class, verdict.tree, verdict.resolves_into),
                (OutputBase, base(root), None),
                "{path}"
            );
        }
        for path in ["real/ws/vend", "alias/ws/vend/+http+dep/package.json"] {
            let verdict = classifier.classify(&disk.at(path));
            assert_eq!(
                (verdict.class, verdict.resolves_into),
                (VendorDir, None),
                "{path}"
            );
        }
        // Another base is another tree, however the first one is spelled.
        for path in [
            "real/base/external/borrowed",
            "alias/base/external/borrowed",
        ] {
            let verdict = classifier.classify(&disk.at(path));
            assert_eq!(
                (verdict.class, verdict.resolves_into),
                (OutputBase, base("second")),
                "{path}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_tracked_vendor_dir_matches_however_the_query_spells_it() {
        let disk = Scratch::new();
        disk.lay("", "", "real/ws/deps/+x+y/\n alias -> real");
        // Declared through the link, queried both ways.
        let classifier = Classifier::with_vendor_dirs([disk.at("alias/ws/deps")]);
        for path in ["alias/ws/deps/+x+y", "real/ws/deps/+x+y", "alias/ws/deps"] {
            assert_eq!(
                classifier.classify(&disk.at(path)).class,
                VendorDir,
                "{path}"
            );
        }
        assert_eq!(classifier.classify(&disk.at("real/ws")).class, Plain);

        // A walker's test agrees, whichever spelling was declared and
        // whichever the walker came down by.
        let vendor = |dir: &str| tree(VendorDir, disk.at(dir));
        for declared in ["alias/ws/deps", "real/ws/deps"] {
            let classifier = Classifier::with_vendor_dirs([disk.at(declared)]);
            for dir in ["alias/ws/deps", "real/ws/deps", "real/ws/deps/"] {
                let own = classifier.tree_at(&disk.at(dir));
                let want = vendor(dir.trim_end_matches('/'));
                assert_eq!((own.tree, own.cannot_tell), (want, false), "{dir}");
            }
            for dir in ["alias/ws", "real/ws", "real/ws/deps/+x+y", "real/ws/gone"] {
                assert_eq!(classifier.tree_at(&disk.at(dir)), Found::default(), "{dir}");
            }
        }

        // Declared before `bazel vendor` has made it: there is nothing to
        // canonicalize, and the directory is tracked both ways all the
        // same, before and after it appears.
        let classifier = Classifier::with_vendor_dirs([disk.at("alias/ws/third_party")]);
        for made in [false, true] {
            if made {
                fs::create_dir_all(disk.at("real/ws/third_party/+a+b")).unwrap();
            }
            for path in [
                "alias/ws/third_party/+a+b/go.mod",
                "real/ws/third_party/+a+b/go.mod",
                "real/ws/third_party",
            ] {
                assert_eq!(
                    classifier.classify(&disk.at(path)).class,
                    VendorDir,
                    "{path}, made: {made}"
                );
            }
            for dir in ["alias/ws/third_party", "real/ws/third_party"] {
                let own = classifier.tree_at(&disk.at(dir));
                assert_eq!(own.tree, vendor(dir), "{dir}, made: {made}");
            }
        }
    }

    #[test]
    fn default_roots_cover_every_release_of_each_os() {
        fn roots(os: TargetOs, vars: &[(&str, &str)], passwd_home: Option<&str>) -> Vec<PathBuf> {
            let env = |name: &str| {
                let var = vars.iter().find(|(key, _)| *key == name);
                var.map(|(_, value)| OsString::from(value))
            };
            default_output_roots(os, &env, passwd_home.map(Path::new))
        }
        let paths = |spelled: &[&str]| spelled.iter().map(PathBuf::from).collect::<Vec<_>>();
        let (linux, mac, windows) = (TargetOs::Linux, TargetOs::MacOs, TargetOs::Windows);

        // Linux: `$XDG_CACHE_HOME/bazel` from 7.2.0, `~/.cache/bazel`
        // before it. Both hold a base after an upgrade (probe C8).
        let vars = [("HOME", "/home/u"), ("XDG_CACHE_HOME", "/xdg")];
        let want = paths(&["/xdg/bazel", "/home/u/.cache/bazel"]);
        assert_eq!(roots(linux, &vars, Some("/passwd/u")), want);
        // An empty variable is unset, and the passwd home stands in.
        let vars = [("HOME", ""), ("XDG_CACHE_HOME", "")];
        let want = paths(&["/passwd/u/.cache/bazel"]);
        assert_eq!(roots(linux, &vars, Some("/passwd/u")), want);
        // A uid with no passwd entry (probe C6).
        assert_eq!(roots(linux, &[], None), paths(&["/tmp"]));

        // macOS: `/var/tmp` through 8.x, XDG from 8.4.0, the Library
        // from 9.0.0.
        let vars = [("HOME", "/Users/u"), ("XDG_CACHE_HOME", "/xdg")];
        let want = paths(&["/xdg/bazel", "/var/tmp", "/Users/u/Library/Caches/bazel"]);
        assert_eq!(roots(mac, &vars, None), want);
        assert_eq!(roots(mac, &[], None), paths(&["/var/tmp"]));

        // Windows: the home itself, `%HOME%` before `%USERPROFILE%`; XDG
        // from 10.0.0.
        let vars = [("USERPROFILE", r"C:\Users\me")];
        assert_eq!(roots(windows, &vars, None), paths(&[r"C:\Users\me"]));
        let vars = [
            ("HOME", r"D:\home"),
            ("USERPROFILE", r"C:\Users\me"),
            ("XDG_CACHE_HOME", r"D:\xdg"),
        ];
        let want = vec![
            PathBuf::from(r"D:\xdg").join("bazel"),
            PathBuf::from(r"D:\home"),
        ];
        assert_eq!(roots(windows, &vars, Some("/ignored")), want);
        assert_eq!(roots(windows, &[], None), paths(&[]));

        // `TEST_TMPDIR` is a root on every OS, and a root named twice is
        // listed once.
        let vars = [
            ("HOME", "/home/u"),
            ("TEST_TMPDIR", "/tmp/t"),
            ("XDG_CACHE_HOME", "/home/u/.cache"),
        ];
        let want = paths(&["/home/u/.cache/bazel", "/tmp/t"]);
        assert_eq!(roots(linux, &vars, None), want);
        // An empty `TEST_TMPDIR` is not unset to Bazel and names no
        // directory (probe C6 cell E11): no root is listed for it, on any
        // OS, and the roots of the other variables stay.
        let vars = [("HOME", "/home/u"), ("TEST_TMPDIR", "")];
        assert_eq!(roots(linux, &vars, None), paths(&["/home/u/.cache/bazel"]));
        let want = paths(&["/var/tmp", "/home/u/Library/Caches/bazel"]);
        assert_eq!(roots(mac, &vars, None), want);
        assert_eq!(roots(windows, &vars, None), paths(&["/home/u"]));

        // A value that is not UTF-8 is a path all the same: the client
        // reads the bytes (`GetPathEnv`, `blaze_util_posix.cc`). It is not
        // dropped, and the passwd home does not stand in for it.
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt as _;
            let raw = |bytes: &[u8]| PathBuf::from(OsString::from_vec(bytes.to_vec()));
            let env = |name: &str| match name {
                "HOME" => Some(raw(b"/Users/\xff").into_os_string()),
                "XDG_CACHE_HOME" => Some(raw(b"/xdg\xfe").into_os_string()),
                "TEST_TMPDIR" => Some(raw(b"/tt\xfd").into_os_string()),
                _ => None,
            };
            let passwd = Some(Path::new("/passwd/u"));
            let want = vec![
                raw(b"/xdg\xfe/bazel"),
                PathBuf::from("/var/tmp"),
                raw(b"/Users/\xff/Library/Caches/bazel"),
                raw(b"/tt\xfd"),
            ];
            assert_eq!(default_output_roots(mac, &env, passwd), want);
            let want = vec![
                raw(b"/xdg\xfe/bazel"),
                raw(b"/Users/\xff/.cache/bazel"),
                raw(b"/tt\xfd"),
            ];
            assert_eq!(default_output_roots(linux, &env, passwd), want);
        }

        // This process: the table of this host, and nothing an rc file
        // would have to say.
        let process = Candidates::of_process();
        let only_roots = Candidates {
            output_roots: process.output_roots.clone(),
            ..Candidates::default()
        };
        assert_eq!(process, only_roots);
        // Every Unix table has a root that needs no variable.
        #[cfg(unix)]
        assert!(!process.output_roots.is_empty());
        #[cfg(target_os = "macos")]
        assert!(process.output_roots.contains(&PathBuf::from("/var/tmp")));
    }

    #[test]
    fn with_no_link_one_marked_base_is_found_and_several_cannot_be_told_apart() {
        let disk = Scratch::new();
        disk.lay("ws", "", "{ws}/MODULE.bazel");
        let ws = disk.at("ws");
        let mut candidates = roots(&disk, &["home/.cache/bazel", "xdg/bazel", "missing"]);
        candidates.output_roots.push("relative/root".into());
        // A relative candidate would be read from this process's working
        // directory, not from Bazel's: none is kept, in any of the lists.
        let spelled = ["relative/root", "../ws", "./ws", ""].map(PathBuf::from);
        assert_eq!(absolute_only(&spelled), Vec::<PathBuf>::new());
        let mixed = [spelled[0].clone(), ws.clone(), spelled[1].clone()];
        assert_eq!(absolute_only(&mixed), vec![ws.clone()]);
        // Never built: no base anywhere.
        assert_eq!(locate_output_base(&ws, &candidates), Located::NotFound);

        // One base names the workspace, after `clean` and a build. Beside
        // it: another workspace's base, the install and cache directories
        // of the user root, a marker with no directory beside it, and a
        // base that is not under a `_bazel_<user>` directory.
        let old = "home/.cache/bazel/_bazel_u";
        disk.lay("ws", &format!("{old}/6d82"), BASE);
        disk.lay(
            "other",
            &format!("{old}/aaaa"),
            &[BASE, EXECROOT_MARKER].join("\n"),
        );
        disk.lay(
            "ws",
            old,
            "{base}/install/7b1f/\n {base}/cache/repos/v1/\n {base}/bbbb/DO_NOT_BUILD_HERE",
        );
        disk.lay("ws", "home/.cache/bazel/elsewhere/cccc", BASE);
        let base = disk.at(&format!("{old}/6d82"));
        assert_eq!(
            locate_output_base(&ws, &candidates),
            found(base, Route::Enumeration)
        );

        // An upgrade moved the default root (probe C8): a second base
        // names the workspace, and no link says which one is live.
        disk.lay("ws", "xdg/bazel/_bazel_u/6d82", BASE);
        let several = Located::CannotTell(Unsure::SeveralBases);
        assert_eq!(locate_output_base(&ws, &candidates), several);

        // Roots and bases that rc files name are asked the same way.
        let by_flag = Candidates {
            output_user_roots: vec![disk.at("xdg/bazel/_bazel_u")],
            output_bases: vec![disk.at("flag/base"), "relative/base".into()],
            ..Candidates::default()
        };
        let base = disk.at("xdg/bazel/_bazel_u/6d82");
        assert_eq!(
            locate_output_base(&ws, &by_flag),
            found(base, Route::Enumeration)
        );
        disk.lay("ws", "flag/base", BASE);
        assert_eq!(locate_output_base(&ws, &by_flag), several);
        // A workspace that is not there has no base to name.
        let gone = locate_output_base(&disk.at("gone"), &by_flag);
        assert_eq!(gone, Located::CannotTell(Unsure::Unlisted));
    }

    /// Probe C6 cell E11: under an empty `TEST_TMPDIR`, Bazel 9.3.2 run
    /// from a workspace root left `_bazel_<user>/<md5>` there. No
    /// candidate root names that directory, and no environment read
    /// later tells of it.
    #[test]
    fn a_user_root_in_the_workspace_root_is_found_with_no_candidate() {
        // What that run left in the base, and a directory of the user's
        // that only shares the prefix.
        let left = "
            {ws}/MODULE.bazel
            {ws}/_bazel_notes/readme/
            {base}/DO_NOT_BUILD_HERE
            {base}/execroot/
            {base}/server/
            {base}/lock
            {base}/README";
        let disk = Scratch::new();
        disk.lay("ws", "ws/_bazel_u/6d82", left);
        let (ws, base) = (disk.at("ws"), disk.at("ws/_bazel_u/6d82"));
        let unnamed = Candidates::default();
        let own = found(base.clone(), Route::Enumeration);
        assert_eq!(locate_output_base(&ws, &unnamed), own);
        // A caller that names the workspace root as well names no second
        // base.
        let named = Candidates {
            output_roots: vec![ws.clone()],
            ..Candidates::default()
        };
        assert_eq!(locate_output_base(&ws, &named), own);
        // Locating is for wording: the classifier never needed it.
        let inside = classify(&base.join("execroot"));
        assert_eq!(inside.tree, tree(OutputBase, base));

        // A base there whose marker names another workspace is not this
        // one's, as under any other root.
        let shared = Scratch::new();
        shared.lay("other", "ws/_bazel_u/aaaa", left);
        shared.lay("ws", "", "{ws}/MODULE.bazel");
        assert_eq!(
            locate_output_base(&shared.at("ws"), &unnamed),
            Located::NotFound
        );

        // The limit: a command typed in a directory below the root leaves
        // its user root there, where only a caller's candidate finds it.
        let below = Scratch::new();
        below.lay("ws", "ws/sub/_bazel_u/6d82", left);
        let ws = below.at("ws");
        assert_eq!(locate_output_base(&ws, &unnamed), Located::NotFound);
        let named = Candidates {
            output_roots: vec![below.at("ws/sub")],
            ..Candidates::default()
        };
        let own = found(below.at("ws/sub/_bazel_u/6d82"), Route::Enumeration);
        assert_eq!(locate_output_base(&ws, &named), own);
    }

    /// The install base has no marker and no rule (see the module doc of
    /// `bazel::output_tree`): everything in it is plain, and that is
    /// known. What makes a rule unnecessary is held here: no name real
    /// Bazel puts there is one that makes a directory a root of a run.
    #[test]
    fn an_install_base_in_the_checkout_is_no_tree_and_holds_no_root_marker() {
        use crate::hosted::memory::roots::{marker_ecosystem, UNSUPPORTED_MARKERS};

        // `--output_user_root=<ws>/our` after one command of real Bazel
        // (the layout of 7.7.2, with the lock file 8.8.2 and later put
        // beside the base): the output base, the install base, an empty
        // repository cache.
        let user_root = "
            {ws}/MODULE.bazel
            {base}/DO_NOT_BUILD_HERE
            {base}/execroot/DO_NOT_BUILD_HERE
            {base}/server/cmdline
            {base}/README
            {base}/lock
            {ws}/our/cache/repos/v1/
            {ws}/our/install/7b1f.lock
            {ws}/our/install/7b1f/A-server.jar
            {ws}/our/install/7b1f/build-label.txt
            {ws}/our/install/7b1f/install_base_key
            {ws}/our/install/7b1f/process-wrapper
            {ws}/our/install/7b1f/embedded_tools/MODULE.bazel
            {ws}/our/install/7b1f/embedded_tools/WORKSPACE
            {ws}/our/install/7b1f/embedded_tools/tools/BUILD
            {ws}/our/install/7b1f/embedded_tools/jdk/lib/jrt-fs.jar
            {ws}/our/install/7b1f/embedded_tools/third_party/py/abseil/setup.py
            {ws}/our/install/7b1f/embedded_tools/third_party/py/abseil/PKG-INFO
            {ws}/our/install/7b1f/embedded_tools/third_party/py/abseil/absl_py.egg-info/requires.txt
            {ws}/our/install/7b1f/platforms/WORKSPACE
            {ws}/our/install/7b1f/rules_java/MODULE.bazel";
        let disk = Scratch::new();
        disk.lay("ws", "ws/our/2e6a", user_root);
        let classifier = Classifier::new();
        let base = tree(OutputBase, disk.at("ws/our/2e6a"));
        assert_eq!(classifier.tree_at(&disk.at("ws/our/2e6a")).tree, base);
        for dir in [
            "ws/our",
            "ws/our/cache/repos/v1",
            "ws/our/install",
            "ws/our/install/7b1f",
            "ws/our/install/7b1f/embedded_tools",
            "ws/our/install/7b1f/embedded_tools/third_party/py/abseil",
            "ws/our/install/7b1f/platforms",
        ] {
            let at = disk.at(dir);
            assert_eq!(classifier.tree_at(&at), Found::default(), "{dir}");
            let names = file_names(&at);
            let names = names.iter().map(OsString::as_os_str);
            assert_eq!(classifier.trees_marked_by(&at, names), vec![], "{dir}");
        }
        for path in [
            "ws/our/install/7b1f/A-server.jar",
            "ws/our/install/7b1f/embedded_tools/MODULE.bazel",
            "ws/our/install/7b1f/embedded_tools/third_party/py/abseil/setup.py",
            "ws/our/install/7b1f/new/file.js",
        ] {
            let verdict = classifier.classify(&disk.at(path));
            assert_eq!(
                (verdict.class, verdict.cannot_tell),
                (Plain, false),
                "{path}"
            );
        }
        // The output base's two links into it: a path spelled through the
        // base is in the base.
        if cfg!(unix) {
            let links = "
                {base}/install -> {ws}/our/install/7b1f
                {base}/external/bazel_tools -> {ws}/our/install/7b1f/embedded_tools";
            disk.lay("ws", "ws/our/2e6a", links);
            for path in [
                "ws/our/2e6a/install/A-server.jar",
                "ws/our/2e6a/external/bazel_tools/tools/BUILD",
            ] {
                let verdict = classifier.classify(&disk.at(path));
                assert_eq!(
                    (verdict.class, verdict.tree, verdict.resolves_into),
                    (OutputBase, base.clone(), None),
                    "{path}"
                );
            }
        }

        // The names below the install bases of Bazel 5.4.1, 6.6.0, 7.7.2,
        // 8.8.2, 9.3.2 and 10.0.0rc3 (macOS arm64) that read like a
        // project's files: the top level, the boundary, build and Python
        // packaging files, and every name that ends in `.txt`, `.json`,
        // `.xml`, `.properties`, `.cfg`, `.jar`, `.zip` or `.egg-info`.
        // None ends in `.toml`, `.yaml`, `.lock`, `.mod` or `.sum`. The
        // other 643 are sources, scripts, templates, binaries and the
        // embedded JDK.
        const READ_LIKE_PROJECT_FILES: [&str; 50] = [
            "A-server.jar",
            "build-label.txt",
            "build-runfiles",
            "daemonize",
            "embedded_tools",
            "install_base_key",
            "libcpu_profiler.dylib",
            "linux-sandbox",
            "platforms",
            "process-wrapper",
            "rules_java",
            "xcode-locator",
            "BUILD",
            "BUILD.bazel",
            "MODULE.bazel",
            "WORKSPACE",
            "Makefile",
            "LICENSE",
            "README",
            "PKG-INFO",
            "setup.py",
            "setup.cfg",
            "absl_py.egg-info",
            "six.egg-info",
            "requires.txt",
            "dependency_links.txt",
            "top_level.txt",
            "SOURCES.txt",
            "LICENSE.txt",
            "README.txt",
            "readme.txt",
            "Copyright.txt",
            "Xusage.txt",
            "correct_file_format.txt",
            "duplicated_key.txt",
            "no_separator.txt",
            "java_stub_template.txt",
            "python_bootstrap_template.txt",
            "pywrapper_template.txt",
            "chm_only_desugar_jdk_libs.json",
            "java.xml",
            "win_manifest.xml",
            "jaxp.properties",
            "logging.properties",
            "net.properties",
            "no_se_linux.properties",
            "jvm.cfg",
            "minify_java8_legacy_libs.cfg",
            "jrt-fs.jar",
            "snapshots.img.zip",
        ];
        for name in READ_LIKE_PROJECT_FILES {
            assert_eq!(marker_ecosystem(name), None, "{name}");
            let unsupported = UNSUPPORTED_MARKERS.iter().find(|row| row.1.contains(&name));
            assert_eq!(unsupported, None, "{name}");
            // Nor is any of them a marker of a tree.
            let marked = output_tree::marked_dir(Path::new("install"), OsStr::new(name));
            assert_eq!(marked, None, "{name}");
        }
    }

    #[test]
    fn a_marker_names_a_workspace_only_byte_for_byte() {
        let disk = Scratch::new();
        disk.lay(
            "ws",
            "root/_bazel_u/6d82",
            &[BASE, "{ws}/MODULE.bazel"].join("\n"),
        );
        let (ws, base) = (disk.at("ws"), disk.at("root/_bazel_u/6d82"));
        let candidates = roots(&disk, &["root"]);
        let named = bytes(&ws);
        for (marker, names) in [
            (named.to_vec(), true),
            ([named, b"\n"].concat(), false),
            // Not UTF-8, as Bazel <= 7.7.2 writes a non-ASCII path
            // (probe C7).
            ([named, b"-\xfcn\xef"].concat(), false),
            (bytes(&disk.at("other")).to_vec(), false),
            // Too large to be a path. No more than the limit is read of
            // it, and that much is no path either, whatever it starts
            // with.
            (vec![b'x'; MAX_MARKER_BYTES as usize + 1], false),
            (
                [named, &vec![b'/'; MAX_MARKER_BYTES as usize][..]].concat(),
                false,
            ),
        ] {
            fs::write(base.join(OUTPUT_BASE_MARKER), &marker).unwrap();
            assert_eq!(
                marker_names_workspace(&base, &ws),
                if names { Marker::Names } else { Marker::Other },
                "{} bytes",
                marker.len()
            );
            let located = locate_output_base(&ws, &candidates);
            let want = found(base.clone(), Route::Enumeration);
            assert_eq!(located, if names { want } else { Located::NotFound });
            // Classifying never reads the marker.
            assert_eq!(classify(&base.join("external")).class, OutputBase);
        }
        // A directory where the marker should be is neither read nor a
        // marker.
        fs::remove_file(base.join(OUTPUT_BASE_MARKER)).unwrap();
        fs::create_dir(base.join(OUTPUT_BASE_MARKER)).unwrap();
        assert_eq!(marker_names_workspace(&base, &ws), Marker::Other);
        assert_eq!(classify(&base.join("external")).class, Plain);
        // Nor is a marker that is not there.
        let nowhere = disk.at("nowhere");
        assert_eq!(marker_names_workspace(&nowhere, &ws), Marker::Other);
    }

    #[cfg(unix)]
    #[test]
    fn a_latin_1_marker_of_a_non_ascii_workspace_names_nothing() {
        // Probe C7, workspace `ws-ünï-é`: Bazel 8.8.2 and later write the
        // bytes of the resolved path, and 7.7.2 and earlier write the path
        // as ISO-8859-1, `fc 6e ef 2d e9` for the last five characters.
        let disk = Scratch::new();
        let base = disk.at("root/_bazel_u/95de");
        disk.lay(
            "ws-ünï-é",
            "root/_bazel_u/95de",
            &[BASE, LINKS, "{ws}/MODULE.bazel"].join("\n"),
        );
        // The name as the file system keeps it, which is what both sides
        // of the comparison start from.
        let ws = fs::canonicalize(disk.at("ws-ünï-é")).unwrap();
        let (utf8, name) = (bytes(&ws), ws.file_name().unwrap().len());
        let latin_1 = [&utf8[..utf8.len() - name], b"ws-\xfcn\xef-\xe9"].concat();
        let (linked, listed) = (Candidates::default(), roots(&disk, &["root"]));

        fs::write(base.join(OUTPUT_BASE_MARKER), utf8).unwrap();
        let live = found(base.clone(), Route::Link);
        assert_eq!(locate_output_base(&ws, &linked), live);
        // The same base, as an older Bazel marked it: the links lead into
        // a base that cannot be said to be this workspace's, which is an
        // answer and no error.
        fs::write(base.join(OUTPUT_BASE_MARKER), &latin_1).unwrap();
        let mismatch = Located::CannotTell(Unsure::MarkerMismatch);
        assert_eq!(locate_output_base(&ws, &linked), mismatch);
        assert_eq!(marker_names_workspace(&base, &ws), Marker::Other);
        // Refusing and pruning never read the marker.
        let through = classify(&ws.join("bazel-bin/node_modules"));
        assert_eq!(through.tree, tree(OutputBase, base.clone()));

        // With no link the base is one of many that name something else.
        for link in ["bazel-out", "bazel-bin", "bazel-testlogs", "bazel-proj"] {
            fs::remove_file(ws.join(link)).unwrap();
        }
        assert_eq!(locate_output_base(&ws, &listed), Located::NotFound);
        fs::write(base.join(OUTPUT_BASE_MARKER), utf8).unwrap();
        let only = found(base, Route::Enumeration);
        assert_eq!(locate_output_base(&ws, &listed), only);
    }

    #[cfg(unix)]
    #[test]
    fn the_links_of_a_workspace_name_its_live_base() {
        let disk = Scratch::new();
        let (old, new) = (
            "var-tmp/_bazel_u/9786",
            "Library/Caches/bazel/_bazel_u/9786",
        );
        disk.lay(
            "ws",
            old,
            &[BASE, EXECROOT_MARKER, "{ws}/MODULE.bazel"].join("\n"),
        );
        disk.lay("ws", new, BASE);
        let candidates = roots(&disk, &["var-tmp", "Library/Caches/bazel"]);
        let ws = disk.at("ws");
        let several = Located::CannotTell(Unsure::SeveralBases);
        assert_eq!(locate_output_base(&ws, &candidates), several);
        // Bazel 9 replaced the links Bazel 8 made (probe C8). They name
        // the new base whatever is listed, and `execroot` needs no marker.
        disk.lay("ws", new, LINKS);
        let live = found(disk.at(new), Route::Link);
        assert_eq!(locate_output_base(&ws, &candidates), live);
        // The workspace reached through a link is the same workspace.
        disk.lay("", "", "ws-link -> ws");
        assert_eq!(locate_output_base(&disk.at("ws-link"), &candidates), live);

        // Links under `--symlink_prefix=dist/` are where the caller says.
        disk.lay(
            "ws2/dist",
            "var-tmp/_bazel_u/2222",
            &LINKS.replace("bazel-", ""),
        );
        disk.lay(
            "ws2",
            "var-tmp/_bazel_u/2222",
            &[BASE, EXECROOT_MARKER].join("\n"),
        );
        let dist = Candidates {
            link_dirs: vec![
                disk.at("ws2/dist"),
                disk.at("ws2/no-such-dir"),
                "dist".into(),
            ],
            ..Candidates::default()
        };
        let ws2 = disk.at("ws2");
        assert_eq!(
            locate_output_base(&ws2, &Candidates::default()),
            Located::NotFound
        );
        let base2 = found(disk.at("var-tmp/_bazel_u/2222"), Route::Link);
        assert_eq!(locate_output_base(&ws2, &dist), base2);
        // Stale links into another base beside them: the links disagree.
        disk.lay("ws2", old, LINKS);
        let disagree = Located::CannotTell(Unsure::LinksDisagree);
        assert_eq!(locate_output_base(&ws2, &dist), disagree);
    }

    #[cfg(unix)]
    #[test]
    fn a_link_into_a_base_that_names_another_workspace_is_not_used() {
        // `startup --output_base` shared by two workspaces (probe C8): the
        // marker names the one that last started a server, and the other
        // one's links still lead into the base.
        let disk = Scratch::new();
        disk.lay(
            "beta",
            "shared/base",
            &[BASE, EXECROOT_MARKER, LINKS].join("\n"),
        );
        disk.lay("alpha", "shared/base", LINKS);
        let none = Candidates::default();
        let mismatch = Located::CannotTell(Unsure::MarkerMismatch);
        assert_eq!(locate_output_base(&disk.at("alpha"), &none), mismatch);
        let base = found(disk.at("shared/base"), Route::Link);
        assert_eq!(locate_output_base(&disk.at("beta"), &none), base);
        // Refusing and pruning do not read the marker.
        assert_eq!(classify(&disk.at("alpha/bazel-bin")).class, Link);
        assert_eq!(
            classify(&disk.at("alpha/bazel-bin/node_modules")).class,
            OutputBase
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_directory_that_cannot_be_read_is_not_read_as_empty() {
        let disk = Scratch::new();
        disk.lay(
            "ws",
            "root/_bazel_u/6d82",
            &[BASE, "{ws}/MODULE.bazel"].join("\n"),
        );
        let (ws, user_root) = (disk.at("ws"), disk.at("root/_bazel_u"));
        let candidates = roots(&disk, &["root"]);
        // A listing cut short says so.
        let mut listed_all = true;
        assert_eq!(
            list(&disk.at("root/_bazel_u/6d82"), 2, &mut listed_all).len(),
            2
        );
        assert!(!listed_all);
        let mut listed_all = true;
        assert_eq!(list(&disk.at("missing"), 2, &mut listed_all).len(), 0);
        assert!(listed_all);

        // The user root cannot be listed.
        let unlisted = Located::CannotTell(Unsure::Unlisted);
        let read = || {
            let located = locate_output_base(&ws, &candidates);
            let below = classify(&user_root.join("6d82/external"));
            let own = Classifier::new().tree_at(&user_root);
            (located, below, classify(&user_root), own)
        };
        if let Some((located, below, itself, own)) = while_locked(&user_root, read) {
            assert_eq!(located, unlisted);
            // Nor is a path below it proven plain, which cannot even be
            // resolved; nor the directory itself, which can, and whose
            // markers no `stat` was allowed to see.
            assert_eq!((below.class, below.cannot_tell), (Plain, true));
            assert_eq!((itself.class, itself.cannot_tell), (Plain, true));
            assert_eq!((own.tree, own.cannot_tell), (None, true));
        }
        let base = disk.at("root/_bazel_u/6d82");
        let only = found(base.clone(), Route::Enumeration);
        assert_eq!(locate_output_base(&ws, &candidates), only);

        // A candidate base that cannot be read, or whose marker cannot,
        // may be this workspace's own. Alone, it is not "never built
        // here"; beside a base that does name the workspace, that one is
        // not "the only base".
        let marker = base.join(OUTPUT_BASE_MARKER);
        if let Some(says) = while_locked(&marker, || marker_names_workspace(&base, &ws)) {
            assert_eq!(says, Marker::Unread);
        }
        disk.lay("ws", "xdg/bazel/_bazel_u/6d82", BASE);
        let both = roots(&disk, &["root", "xdg/bazel"]);
        let several = Located::CannotTell(Unsure::SeveralBases);
        assert_eq!(locate_output_base(&ws, &both), several);
        for locked in [&base, &marker] {
            for listed in [&candidates, &both] {
                let located = while_locked(locked, || locate_output_base(&ws, listed));
                let roots = listed.output_roots.len();
                if let Some(located) = located {
                    assert_eq!(located, unlisted, "{locked:?}, {roots} root(s)");
                }
            }
        }
        assert_eq!(locate_output_base(&ws, &both), several);

        // A link whose target cannot be read may lead into a base.
        disk.lay("built", "locked/base", &[BASE, LINKS].join("\n"));
        let (built, none) = (disk.at("built"), Candidates::default());
        let linked = found(disk.at("locked/base"), Route::Link);
        assert_eq!(locate_output_base(&built, &none), linked);
        let read = || {
            let link = classify(&built.join("bazel-bin"));
            (locate_output_base(&built, &none), link)
        };
        if let Some((located, link)) = while_locked(&disk.at("locked"), read) {
            assert_eq!(located, unlisted);
            assert_eq!((link.class, link.cannot_tell), (Plain, true));
        }
        assert_eq!(locate_output_base(&built, &none), linked);
    }

    // ── What real Bazel left on disk (probes C1, C3, C7, C8, C11) ────
    //
    // The layouts above are fabricated. These are recorded: the vectors of
    // two probe groups, as `tests/fixtures/bazel/probe_vectors/` holds them
    // (its README, "Output-tree layouts"), rebuilt in a temporary
    // directory.

    #[cfg(unix)]
    macro_rules! probe_vector {
        ($path:literal) => {
            include_str!(concat!("../../tests/fixtures/bazel/probe_vectors/", $path))
        };
    }

    /// Ten layouts a build left, each with the answers of the probe's
    /// reference detector for four or five paths.
    #[cfg(unix)]
    const LAYOUTS: [&str; 10] = [
        probe_vector!("core-external-edits/vectors/detect/5.4.1-default.json"),
        probe_vector!("core-external-edits/vectors/detect/6.6.0-default.json"),
        probe_vector!("core-external-edits/vectors/detect/7.7.2-default.json"),
        probe_vector!("core-external-edits/vectors/detect/7.7.2-vendor.json"),
        probe_vector!("core-external-edits/vectors/detect/8.3.1-cc.json"),
        probe_vector!("core-external-edits/vectors/detect/8.8.2-cc.json"),
        probe_vector!("core-external-edits/vectors/detect/8.8.2-default.json"),
        probe_vector!("core-external-edits/vectors/detect/9.3.2-cc.json"),
        probe_vector!("core-external-edits/vectors/detect/9.3.2-vendor.json"),
        probe_vector!("core-external-edits/vectors/detect/10.0.0rc3-cc.json"),
    ];
    /// The convenience links of five built workspaces.
    #[cfg(unix)]
    const LINK_ROUTE: &str = probe_vector!("core-output-base/proto/vectors/link_route.json");

    /// Where each token of a recorded path stands under the scratch root.
    #[cfg(unix)]
    const TOKENS: [(&str, &str); 5] = [
        ("<WS>", "ws"),
        ("<OB>", "out/ob"),
        ("<CACHE>", "cache/contents"),
        ("<INSTALL>", "install"),
        ("<CAMPAIGN>", "campaign"),
    ];

    #[cfg(unix)]
    fn vector(text: &str) -> serde_json::Value {
        serde_json::from_str(text).expect("probe vector")
    }

    #[cfg(unix)]
    fn text<'a>(row: &'a serde_json::Value, key: &str) -> &'a str {
        row[key].as_str().unwrap_or_else(|| panic!("{key}: {row}"))
    }

    #[cfg(unix)]
    impl Scratch {
        /// A recorded path under the root. A recorded link target with no
        /// token is relative and stays so.
        fn recorded(&self, path: &str) -> PathBuf {
            let token = TOKENS.iter().find(|(token, _)| path.starts_with(token));
            match token {
                Some((token, dir)) => self.at(&path.replacen(token, dir, 1)),
                None => PathBuf::from(path),
            }
        }

        /// Rebuilds the `tree` of a recorded `detect` vector, without the
        /// entries `left_out` names: every directory, file and link the
        /// probe recorded, each link with its stored target. A marker
        /// holds the workspace path, as it did on the real disk. A vector
        /// may list an entry twice; the first one is made.
        fn rebuild(&self, tree: &[serde_json::Value], left_out: &[&str]) {
            let mut made = std::collections::HashSet::new();
            for row in tree {
                let recorded = text(row, "path");
                if left_out.contains(&recorded) || !made.insert(recorded) {
                    continue;
                }
                let path = self.recorded(recorded);
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                let content = row["content"].as_str().unwrap_or("");
                match text(row, "type") {
                    "dir" => fs::create_dir_all(&path).unwrap(),
                    "symlink" => symlink(&self.recorded(text(row, "target")), &path),
                    "file" if content == "<WS>" => {
                        fs::write(&path, bytes(&self.recorded(content))).unwrap()
                    }
                    "file" => fs::write(&path, content).unwrap(),
                    other => panic!("{recorded}: {other}"),
                }
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn the_recorded_layouts_classify_on_disk_as_the_probe_recorded() {
        let mut queries = 0;
        for layout in LAYOUTS.map(vector) {
            let id = format!("{}-{}", text(&layout, "bazel"), text(&layout, "cfg"));
            // As the build left it, which is what every vector records,
            // and as `clean` and a build leave it: without the second
            // marker (probe C7).
            for left_out in [&[][..], &["<OB>/execroot/DO_NOT_BUILD_HERE"][..]] {
                let disk = Scratch::new();
                disk.rebuild(layout["tree"].as_array().expect("tree"), left_out);
                // The source file the probe asked about is not in its tree.
                disk.lay("ws", "", "{ws}/BUILD.bazel");
                let classifier = Classifier::new();
                for row in layout["expect"].as_array().expect("expect") {
                    let query = disk.recorded(text(row, "query"));
                    // The trees the probe's detector named on the live
                    // disk, the output base first.
                    let mut trees = Vec::new();
                    for (class, key) in [
                        (OutputBase, "output_base"),
                        (RepoContentsCache, "cache_entry"),
                        (VendorDir, "vendor_dir"),
                    ] {
                        let root = row[key].as_str().map(|root| disk.recorded(root));
                        trees.extend(root.map(|root| Tree { class, root }));
                    }
                    let class = trees.first().map_or(Plain, |tree| tree.class);
                    let verdict = classifier.classify(&query);
                    assert_eq!(
                        (verdict.class, verdict.cannot_tell),
                        (class, false),
                        "{id}: {query:?}"
                    );
                    assert_eq!(
                        (verdict.tree, verdict.resolves_into),
                        (trees.first().cloned(), trees.get(1).cloned()),
                        "{id}: {query:?}"
                    );
                    // The resolved path is the one the probe recorded,
                    // through links whose targets the tree does not hold.
                    let canonical = disk.recorded(text(row, "canonical"));
                    assert_eq!(resolve(&query, MAX_LINK_HOPS), Some(canonical), "{id}");
                    queries += 1;
                }
                // The links the build left in the workspace root name the
                // base, and its marker names the workspace.
                let ws = disk.recorded("<WS>");
                let located = locate_output_base(&ws, &Candidates::default());
                assert_eq!(located, found(disk.recorded("<OB>"), Route::Link), "{id}");
            }
        }
        assert_eq!(queries, 2 * 42);
    }

    #[cfg(unix)]
    #[test]
    fn the_recorded_links_locate_their_base_on_disk() {
        let links = vector(LINK_ROUTE);
        let links = links.as_array().expect("links");
        assert_eq!(links.len(), 24);
        let disk = Scratch::new();
        // Workspace, output base and the directories that hold its links.
        let mut workspaces: Vec<(PathBuf, PathBuf, Vec<PathBuf>)> = Vec::new();
        for row in links {
            let ws = disk.recorded(text(row, "workspace"));
            let base = disk.recorded(text(row, "expected_output_base"));
            let link = ws.join(text(row, "link"));
            let link_dir = link.parent().unwrap().to_path_buf();
            fs::create_dir_all(&link_dir).unwrap();
            fs::create_dir_all(&base).unwrap();
            let marker = disk.recorded(text(row, "marker"));
            fs::write(base.join(OUTPUT_BASE_MARKER), bytes(&marker)).unwrap();
            symlink(&disk.recorded(text(row, "target")), &link);
            match workspaces.iter_mut().find(|(known, ..)| *known == ws) {
                Some((_, known, dirs)) => {
                    assert_eq!(*known, base, "{ws:?}");
                    dirs.push(link_dir);
                }
                None => workspaces.push((ws, base, vec![link_dir])),
            }
        }
        assert_eq!(workspaces.len(), 5);
        // After `clean` no target is there, and then with the build's
        // output back: the answers are the same.
        for live in [false, true] {
            for row in links.iter().filter(|_| live) {
                fs::create_dir_all(disk.recorded(text(row, "target"))).unwrap();
            }
            for row in links {
                let ws = disk.recorded(text(row, "workspace"));
                let base = tree(OutputBase, disk.recorded(text(row, "expected_output_base")));
                let link = ws.join(text(row, "link"));
                let verdict = classify(&link);
                assert_eq!(
                    (verdict.class, verdict.tree, verdict.cannot_tell),
                    (Link, base, false),
                    "{link:?}, live: {live}"
                );
            }
            for (ws, base, link_dirs) in &workspaces {
                // Links under `--symlink_prefix=dist/` are where the
                // caller says; the workspace root is always read.
                let candidates = Candidates {
                    link_dirs: link_dirs.clone(),
                    ..Candidates::default()
                };
                let located = locate_output_base(ws, &candidates);
                assert_eq!(located, found(base.clone(), Route::Link), "{ws:?}");
            }
        }
    }

    /// A junction is what Bazel makes for every convenience link on
    /// Windows (gap-output-tree-recognition 1.5). It reads as a link whose
    /// target is absolute.
    #[cfg(windows)]
    #[test]
    fn a_windows_junction_into_a_base_is_a_link() {
        // The paths `mklink` is given are not canonical: `cmd` does not
        // take the `\\?\` form.
        let tmp = tempfile::tempdir().unwrap();
        let (ws, base) = (tmp.path().join("ws"), tmp.path().join("base"));
        let bin = base.join("execroot").join("_main").join("bazel-out");
        fs::create_dir_all(&ws).unwrap();
        fs::create_dir_all(bin.join("k8").join("bin").join("node_modules")).unwrap();
        // The marker as a Windows server spells it: the workspace path
        // with forward slashes and no `\\?\` prefix (`BlazeWorkspace`
        // writes `getWorkspace().toString()`). That spelling comes from
        // reading the source and gap-output-tree-recognition, not from a
        // run: no Windows cell has built a base yet. `canonicalize` gives
        // the `\\?\` form with backslashes, so the bytes differ and the
        // links lead into a base that cannot be said to be this
        // workspace's.
        let marker = ws.to_str().unwrap().replace('\\', "/");
        fs::write(base.join(OUTPUT_BASE_MARKER), marker).unwrap();
        let link = ws.join("bazel-bin");
        let made = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(bin.join("k8").join("bin"))
            .status()
            .unwrap();
        assert!(made.success(), "mklink /J failed");
        assert_eq!(classify(&link).class, Link);
        // Neither reads the marker, and neither names a second tree: the
        // base spelled `C:\..` and resolved to `\\?\C:\..` is one tree.
        for inside in [link.join("node_modules"), bin.join("k8")] {
            let verdict = classify(&inside);
            assert_eq!(
                (verdict.class, verdict.resolves_into),
                (OutputBase, None),
                "{}",
                inside.display()
            );
        }
        assert_eq!(classify(&ws).class, Plain);
        let located = locate_output_base(&ws, &Candidates::default());
        assert_eq!(located, Located::CannotTell(Unsure::MarkerMismatch));
    }
}
