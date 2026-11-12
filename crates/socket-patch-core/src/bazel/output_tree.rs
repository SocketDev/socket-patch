//! Output-tree classifier over injected `stat` and `read_link` (design
//! 2.11).
//!
//! Bazel owns four kinds of directory that socket-patch must never write
//! into and never crawl for packages: an output base, an entry of the repo
//! contents cache, an entry of the repository cache and a vendor
//! directory. A patch written there is reverted by the next build, or
//! reaches every workspace that shares the cache, or is kept while Bazel
//! builds something else. In each case a manifest would record a patch the
//! build does not contain.
//!
//! A tree is recognized by a marker Bazel writes, never by a name:
//! `--symlink_prefix` moves the `bazel-*` links, `--output_base` puts a
//! base anywhere (inside the checkout too), and a real directory may be
//! called `bazel-foo`. A path is judged twice, as found and resolved,
//! because links cross the boundary both ways: `bazel-bin` leads into the
//! output base, and `external/<repo>` leads out of it into the contents
//! cache, a vendor directory or the user's own sources.
//!
//! This file holds the rules and asks the disk two questions through
//! [`TreeFs`]; `crawlers::bazel_output` answers them, and [`Listing`]
//! answers them for a list of paths (the in-memory engine). The verdict is
//! used to refuse and to prune, never to choose a place to write or a tree
//! to crawl.

use std::collections::{HashMap, HashSet};
use std::path::{Component, Path, PathBuf};

/// The file a Bazel server writes into its output base. It holds the
/// workspace path, with no newline (`BlazeWorkspace.java`, the same from
/// 5.4.1 to 10.0.0rc3).
pub const OUTPUT_BASE_MARKER: &str = "DO_NOT_BUILD_HERE";

/// The directory of an output base that holds the execution roots, and the
/// segment every convenience link's target passes through.
const EXECROOT: &str = "execroot";

/// `LocalRepoContentsCache.RECORDED_INPUTS_SUFFIX`: a cached repository
/// `<entry>` has the sibling file `<entry>.recorded_inputs`.
const RECORDED_INPUTS_SUFFIX: &str = ".recorded_inputs";

/// What `bazel vendor` writes into a vendor directory. 7.1.2, 7.2.0 and
/// 7.2.1 write only `.vendorignore` (probe C11).
const VENDOR_MARKERS: [&str; 2] = ["VENDOR.bazel", ".vendorignore"];

/// `RepositoryCache.CAS_DIR` and `DownloadCache.DEFAULT_CACHE_FILENAME`.
const CAS_DIR: &str = "content_addressable";
const CAS_FILE: &str = "file";

/// `DownloadCache.KeyType`: the directory of each digest kind and the
/// length of an entry name in it. `blake3` exists from Bazel 7.2.0; the
/// design names the four SHA kinds, and a cache is no less a cache for
/// holding an entry of the fifth.
const CAS_KEY_TYPES: [(&str, usize); 5] = [
    ("sha1", 40),
    ("sha256", 64),
    ("sha384", 96),
    ("sha512", 128),
    ("blake3", 64),
];

/// How many directories a [`Memo`] holds. A run classifies package
/// directories, which share ancestors; past this many the walk still
/// answers and stops remembering.
const MEMO_DIRS: usize = 1 << 16;

/// What kind of Bazel-owned tree a path is in. Everything but `Plain` is
/// never written and never crawled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PathClass {
    /// No marker on the path as found or on its resolved form.
    Plain,
    /// At or below a directory with a regular `DO_NOT_BUILD_HERE` and a
    /// directory `execroot`. The second marker, in `execroot`, is not
    /// asked for: `bazel clean` deletes it and no later build on that
    /// server writes it again (probe C7), so a live base can lack it for
    /// hours. The content is not compared either: a shared `--output_base`
    /// names whichever workspace last started a server (probe C8), and
    /// another workspace's base is no safer to write into.
    OutputBase,
    /// At or below a directory with a sibling `<dir>.recorded_inputs`. The
    /// entry name is a UUID from 8.4 and a counter on 8.3.x, so the name
    /// is not tested.
    RepoContentsCache,
    /// At or below `content_addressable/<kind>/<hex>` that holds a regular
    /// `file`, `<hex>` as long as `<kind>` says. An `id-*` sibling is not
    /// asked for: Bazel 5 and 6 write none, and neither does a download
    /// with no canonical id on 7 and later (probes H1, H3, T3).
    RepositoryCache,
    /// At or below a directory with a regular `VENDOR.bazel` or
    /// `.vendorignore`, or one a tracked `--vendor_dir` names.
    VendorDir,
    /// A link (a junction on Windows) outside those trees that leads into
    /// one: a convenience link under any prefix, `bazel-external`, a stale
    /// or hand-made link.
    Link,
}

/// What is at a path, links followed, as far as a marker test cares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Entry {
    File,
    Dir,
    /// Nothing, or something that is neither (a FIFO, a dangling link).
    Neither,
    /// The disk would not say (no permission, an I/O error). It is never
    /// read as absent: the answer is then [`Verdict::cannot_tell`].
    Unknown,
}

/// The two questions the classifier asks of a tree.
pub trait TreeFs {
    /// The entry at `path`, links followed.
    fn stat(&self, path: &Path) -> Entry;
    /// The stored target of the link at `path`; `None` when the entry is
    /// not a link. A junction's target is absolute, a symlink's may be
    /// relative to the link's directory.
    fn read_link(&self, path: &Path) -> Option<PathBuf>;
}

/// A Bazel-owned tree: its kind (never `Plain` or `Link`) and its root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tree {
    pub class: PathClass,
    pub root: PathBuf,
}

/// The tree a path is in by its markers alone, links not resolved.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Found {
    pub tree: Option<Tree>,
    /// No tree was found and a marker test went unanswered, so "no tree"
    /// is not proven.
    pub cannot_tell: bool,
}

/// One run's memory: the directories already judged, and the vendor
/// directories tracked rc files name (design 2.6), which carry no marker
/// of their own until `bazel vendor` runs.
#[derive(Debug, Default)]
pub struct Memo {
    vendor_dirs: Vec<PathBuf>,
    dirs: HashMap<PathBuf, Found>,
}

impl Memo {
    /// `vendor_dirs` in every spelling a query may use (as declared and
    /// resolved): they are compared with a queried directory as paths.
    pub fn new(vendor_dirs: Vec<PathBuf>) -> Self {
        Self {
            vendor_dirs,
            dirs: HashMap::new(),
        }
    }

    fn remember(&mut self, dir: &Path, found: &Found) {
        if self.dirs.len() < MEMO_DIRS {
            self.dirs.insert(dir.to_path_buf(), found.clone());
        }
    }
}

/// Whether `dir` is spelled `.../content_addressable/<kind>/<hex>`.
fn is_cas_entry(dir: &Path) -> bool {
    let mut names = dir
        .ancestors()
        .map(|d| d.file_name().and_then(|name| name.to_str()));
    let (Some(Some(hex)), Some(Some(kind)), Some(Some(cas))) =
        (names.next(), names.next(), names.next())
    else {
        return false;
    };
    cas == CAS_DIR
        && CAS_KEY_TYPES.contains(&(kind, hex.len()))
        && hex.bytes().all(|b| b.is_ascii_hexdigit())
}

/// `<dir>.recorded_inputs` beside `dir`; none for a root.
fn recorded_inputs_of(dir: &Path) -> Option<PathBuf> {
    let mut name = dir.file_name()?.to_os_string();
    name.push(RECORDED_INPUTS_SUFFIX);
    Some(dir.with_file_name(name))
}

/// The tree `dir` itself is the root of, by its own markers. A walker that
/// came down from a `Plain` directory needs nothing else to decide whether
/// to enter `dir`: at most four `stat`s and no walk up.
pub fn tree_at(fs: &dyn TreeFs, dir: &Path, vendor_dirs: &[PathBuf]) -> Found {
    let mut unanswered = false;
    let mut is = |path: PathBuf, want: Entry| {
        let got = fs.stat(&path);
        unanswered |= got == Entry::Unknown;
        got == want
    };
    let class =
        if is(dir.join(OUTPUT_BASE_MARKER), Entry::File) && is(dir.join(EXECROOT), Entry::Dir) {
            Some(PathClass::OutputBase)
        } else if recorded_inputs_of(dir).is_some_and(|sibling| is(sibling, Entry::File)) {
            Some(PathClass::RepoContentsCache)
        } else if is_cas_entry(dir) && is(dir.join(CAS_FILE), Entry::File) {
            Some(PathClass::RepositoryCache)
        } else if vendor_dirs.iter().any(|tracked| tracked == dir)
            || VENDOR_MARKERS
                .iter()
                .any(|marker| is(dir.join(marker), Entry::File))
        {
            Some(PathClass::VendorDir)
        } else {
            None
        };
    Found {
        cannot_tell: unanswered && class.is_none(),
        tree: class.map(|class| Tree {
            class,
            root: dir.to_path_buf(),
        }),
    }
}

/// The nearest tree at or above `path`, by markers on the path as spelled.
/// Each directory is judged once per [`Memo`].
///
/// A path with a `..` segment is not walked: `a/b/../c` is not below
/// `a/b`, and only the disk knows what `b/..` is when `b` is a link. The
/// answer is then `cannot_tell`, and the caller judges the resolved form.
pub fn enclosing(fs: &dyn TreeFs, path: &Path, memo: &mut Memo) -> Found {
    if path.components().any(|c| c == Component::ParentDir) {
        return Found {
            tree: None,
            cannot_tell: true,
        };
    }
    let mut found = Found::default();
    let mut below: Vec<(&Path, bool)> = Vec::new();
    for dir in path.ancestors() {
        if let Some(known) = memo.dirs.get(dir) {
            found = known.clone();
            break;
        }
        let own = tree_at(fs, dir, &memo.vendor_dirs);
        if own.tree.is_some() {
            memo.remember(dir, &own);
            found = own;
            break;
        }
        below.push((dir, own.cannot_tell));
    }
    // Every directory walked past lies below the one that decided and
    // inherits its answer, plus any doubt met on the way down to it.
    for (dir, unanswered) in below.into_iter().rev() {
        found.cannot_tell |= unanswered && found.tree.is_none();
        memo.remember(dir, &found);
    }
    found
}

/// The classifier's answer for one path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub class: PathClass,
    /// The tree that decided `class`; for `Link`, the tree the link leads
    /// into. `None` for `Plain`.
    pub tree: Option<Tree>,
    /// The other tree the path resolves into when it is spelled through
    /// one tree and stored in another: `external/<repo>` of an output base
    /// is a link into the contents cache or a vendor directory, where a
    /// write would reach every workspace that shares the entry.
    pub resolves_into: Option<Tree>,
    /// `Plain`, but not proven: a marker test went unanswered or the path
    /// could not be resolved. Unreadable is not absent, so the caller can
    /// say so; nothing here turns it into a refusal.
    pub cannot_tell: bool,
}

/// Classify `found`, an absolute path as the caller spelled it, together
/// with `canonical`, the same path with every link followed (`None` when
/// it could not be resolved).
///
/// The spelled path decides first: a path through an output base is
/// `OutputBase` even where a link takes it out again, into the contents
/// cache, a vendor directory or, through `execroot/<workspace>`, the
/// user's own sources. None of those is an installed tree socket-patch
/// may patch, and `resolves_into` says where the write would land.
/// Otherwise the resolved form decides, and the path is `Link` when it is
/// itself the link: a path below `bazel-bin` has the class of the tree it
/// is stored in.
pub fn classify(
    fs: &dyn TreeFs,
    found: &Path,
    canonical: Option<&Path>,
    memo: &mut Memo,
) -> Verdict {
    let spelled = enclosing(fs, found, memo);
    // A link's stored target is judged as well as its resolved form: a
    // stale link into a live base resolves to nothing and still says where
    // it leads. The target passes by the markers above it or by the link
    // route, which needs no `execroot` directory on disk.
    let target = fs.read_link(found);
    let target = target.map(|to| found.parent().map_or(to.clone(), |dir| dir.join(&to)));
    let hop = target.as_deref().map(|target| {
        let mut hop = enclosing(fs, target, memo);
        let by_route = || {
            let root = base_of_link_target(fs, target)?;
            let class = PathClass::OutputBase;
            Some(Tree { class, root })
        };
        hop.tree = hop.tree.or_else(by_route);
        hop
    });
    let resolved = canonical.map(|c| enclosing(fs, c, memo));
    // The hop can only add a tree. Where it cannot be walked (a relative
    // target with `..`, as most package-manager links are), the resolved
    // form has already said where the link leads.
    let unproven = spelled.cannot_tell || resolved.as_ref().is_none_or(|r| r.cannot_tell);
    let leads_to = resolved
        .and_then(|found| found.tree)
        .or(hop.and_then(|found| found.tree));
    let (class, tree, resolves_into) = match (spelled.tree, leads_to) {
        (Some(tree), other) => (tree.class, Some(tree.clone()), other.filter(|o| *o != tree)),
        (None, Some(tree)) if target.is_some() => (PathClass::Link, Some(tree), None),
        (None, Some(tree)) => (tree.class, Some(tree), None),
        (None, None) => (PathClass::Plain, None, None),
    };
    Verdict {
        cannot_tell: unproven && class == PathClass::Plain,
        class,
        tree,
        resolves_into,
    }
}

/// The link route: the output base a convenience link's target implies.
/// The target is cut at the segment named `execroot` and the marker must
/// be in that segment's parent. Bazel's four links end one, two or four
/// segments below `execroot`, whatever the prefix and the workspace name.
///
/// The outermost such segment wins: `<base>/execroot` holds a marker of
/// its own, so under a workspace named `execroot` the inner segment would
/// name `<base>/execroot` as the base.
pub fn base_of_link_target(fs: &dyn TreeFs, target: &Path) -> Option<PathBuf> {
    let dirs: Vec<&Path> = target.ancestors().collect();
    dirs.into_iter().rev().find_map(|dir| {
        let base = dir.parent()?;
        let marked = dir.file_name().is_some_and(|name| name == EXECROOT)
            && fs.stat(&base.join(OUTPUT_BASE_MARKER)) == Entry::File;
        marked.then(|| base.to_path_buf())
    })
}

/// Whether the bytes of an output base's marker name `canonical_workspace`
/// (`std::fs::canonicalize` of the workspace root, the string Bazel's
/// client resolves and its server writes).
///
/// `false` means unknown, never "another workspace" and never an error:
/// Bazel up to 7.7.2 writes the path as ISO-8859-1, so a non-ASCII path
/// does not match its own marker (probe C7), and on Windows the marker is
/// spelled with forward slashes while the canonical path is not. It is
/// asked only to locate this workspace's own base, never to decide whether
/// a path may be written.
pub fn marker_names(marker: &[u8], canonical_workspace: &Path) -> bool {
    marker == canonical_workspace.as_os_str().as_encoded_bytes()
}

/// An output base and whether its marker names the workspace asked about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub base: PathBuf,
    pub names_workspace: bool,
}

/// How an output base was located.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// The workspace's convenience links lead into it: the base of the
    /// last build.
    Link,
    /// The only base under the known output roots whose marker names the
    /// workspace. Weaker: a base moved by a home rc file or a command line
    /// is not seen.
    Enumeration,
}

/// Why an output base cannot be named.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unsure {
    /// The workspace's links lead into more than one base.
    LinksDisagree,
    /// The links lead into a base whose marker does not name this
    /// workspace: a shared `--output_base` last started from another
    /// workspace, or a marker that cannot be compared ([`marker_names`]).
    MarkerMismatch,
    /// No link, and more than one base names this workspace: a Bazel
    /// upgrade moved the default root (7.2 on Linux, 9.0 on macOS), or two
    /// commands differed in a startup option (probe C8).
    SeveralBases,
    /// No link, and a candidate directory could not be listed in full.
    Unlisted,
}

/// Where a workspace's output base is, for wording a message. No lane
/// reads evidence from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Located {
    Base {
        base: PathBuf,
        route: Route,
    },
    /// No link leads to a base and no listed base names the workspace:
    /// never built here, or built under a root socket-patch does not know.
    NotFound,
    CannotTell(Unsure),
}

/// Decide which output base is the workspace's own. `linked` are the bases
/// its links lead into, `enumerated` the bases found under the candidate
/// roots, each base in one spelling (resolved); `listed_all` is false when
/// a candidate directory could not be read to its end.
///
/// Only a link names the live base, so the links decide alone when there
/// are any. A marker match is needed as well, and is not enough without a
/// link once two bases have it.
pub fn locate(linked: &[Candidate], enumerated: &[Candidate], listed_all: bool) -> Located {
    let distinct = |candidates: &[Candidate]| {
        let mut seen = HashSet::new();
        let kept = candidates.iter().filter(|c| seen.insert(c.base.clone()));
        kept.cloned().collect::<Vec<_>>()
    };
    let found = |candidate: &Candidate, route| Located::Base {
        base: candidate.base.clone(),
        route,
    };
    match distinct(linked).as_slice() {
        [one] if one.names_workspace => return found(one, Route::Link),
        [_] => return Located::CannotTell(Unsure::MarkerMismatch),
        [_, _, ..] => return Located::CannotTell(Unsure::LinksDisagree),
        [] => {}
    }
    let mut named = distinct(enumerated);
    named.retain(|candidate| candidate.names_workspace);
    match named.as_slice() {
        [_, _, ..] => Located::CannotTell(Unsure::SeveralBases),
        _ if !listed_all => Located::CannotTell(Unsure::Unlisted),
        [one] => found(one, Route::Enumeration),
        _ => Located::NotFound,
    }
}

/// A tree known only as a list of its files: a repository listing handed
/// to the in-memory engine, or a path list on its way to root detection.
/// Paths are relative with forward slashes, `""` being the root. Root
/// discovery on disk and in memory then prunes the same directories. A
/// listing has no link targets, so nothing in it classifies `Link`.
#[derive(Debug, Default)]
pub struct Listing {
    files: HashSet<PathBuf>,
    dirs: HashSet<PathBuf>,
}

impl Listing {
    pub fn new<'a>(files: impl IntoIterator<Item = &'a str>) -> Self {
        let mut listing = Self::default();
        for file in files {
            let file = Path::new(file);
            // Once a directory is known, so is everything above it.
            for dir in file.ancestors().skip(1) {
                if !listing.dirs.insert(dir.to_path_buf()) {
                    break;
                }
            }
            listing.files.insert(file.to_path_buf());
        }
        listing
    }
}

impl TreeFs for Listing {
    fn stat(&self, path: &Path) -> Entry {
        if self.files.contains(path) {
            Entry::File
        } else if self.dirs.contains(path) {
            Entry::Dir
        } else {
            Entry::Neither
        }
    }

    fn read_link(&self, _path: &Path) -> Option<PathBuf> {
        None
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::PathClass::{
        Link, OutputBase, Plain, RepoContentsCache, RepositoryCache, VendorDir,
    };
    use super::*;

    /// A host path for a path spelled the Unix or the Windows way, so each
    /// fabricated layout is checked on every host: `C:\Users\me` is itself
    /// on Windows and `/C:/Users/me` elsewhere, with the same segments.
    fn p(spelled: &str) -> PathBuf {
        if cfg!(windows) {
            return PathBuf::from(spelled);
        }
        let drive = spelled.as_bytes().get(1) == Some(&b':');
        let root = if drive { "/" } else { "" };
        PathBuf::from(format!("{root}{}", spelled.replace('\\', "/")))
    }

    /// A fabricated disk whose `stat` follows links the way a kernel does.
    /// A layout has one entry per line: `path` is a file, `path/` a
    /// directory and `link -> target` a link. `{ws}` and `{base}` stand for
    /// the workspace and its output base.
    #[derive(Default)]
    struct Fake {
        ws: String,
        base: String,
        files: HashSet<PathBuf>,
        dirs: HashSet<PathBuf>,
        links: HashMap<PathBuf, PathBuf>,
        unknown: HashSet<PathBuf>,
        stats: Cell<usize>,
    }

    impl Fake {
        fn new(ws: &str, base: &str) -> Self {
            Self {
                ws: ws.to_string(),
                base: base.to_string(),
                ..Self::default()
            }
        }

        fn with(mut self, layout: &str) -> Self {
            for line in layout.lines().map(str::trim).filter(|l| !l.is_empty()) {
                let (at, target) = match line.split_once(" -> ") {
                    Some((at, target)) => (at, Some(self.path(target))),
                    None => (line, None),
                };
                let (path, is_dir) = (self.path(at), at.ends_with(['/', '\\']));
                for dir in path.ancestors().skip(usize::from(!is_dir)) {
                    self.dirs.insert(dir.to_path_buf());
                }
                match target {
                    Some(target) => drop(self.links.insert(path, target)),
                    None if is_dir => {}
                    None => drop(self.files.insert(path)),
                }
            }
            self
        }

        fn path(&self, template: &str) -> PathBuf {
            p(&template
                .replace("{ws}", &self.ws)
                .replace("{base}", &self.base))
        }

        /// `path` with every link on it followed and every `..` taken:
        /// what the IO side hands in as the canonical form.
        fn real(&self, path: &Path) -> PathBuf {
            let mut real = path.to_path_buf();
            for _ in 0..16 {
                let mut clean = PathBuf::new();
                for part in real.components() {
                    match part {
                        Component::ParentDir => drop(clean.pop()),
                        part => clean.push(part),
                    }
                }
                real = clean;
                let outermost = real.ancestors().filter(|a| self.links.contains_key(*a));
                let Some(link) = outermost.last().map(Path::to_path_buf) else {
                    break;
                };
                let rest = real.strip_prefix(&link).unwrap().to_path_buf();
                real = link.parent().unwrap().join(&self.links[&link]);
                if !rest.as_os_str().is_empty() {
                    real.push(rest);
                }
            }
            real
        }

        fn verdict(&self, template: &str) -> Verdict {
            let found = self.path(template);
            classify(self, &found, Some(&self.real(&found)), &mut Memo::default())
        }

        fn tree(&self, class: PathClass, root: &str) -> Option<Tree> {
            let root = self.path(root);
            Some(Tree { class, root })
        }

        /// Asserts the class of each path, and that each answer is proven.
        fn expect(&self, cases: &[(&str, PathClass)]) {
            for (path, want) in cases {
                let verdict = self.verdict(path);
                assert_eq!(
                    (verdict.class, verdict.cannot_tell),
                    (*want, false),
                    "{path}"
                );
            }
        }
    }

    impl TreeFs for Fake {
        fn stat(&self, path: &Path) -> Entry {
            self.stats.set(self.stats.get() + 1);
            let real = self.real(path);
            if self.unknown.contains(&real) {
                Entry::Unknown
            } else if self.files.contains(&real) {
                Entry::File
            } else if self.dirs.contains(&real) {
                Entry::Dir
            } else {
                Entry::Neither
            }
        }

        fn read_link(&self, path: &Path) -> Option<PathBuf> {
            let dir = self.real(path.parent()?);
            self.links.get(&dir.join(path.file_name()?)).cloned()
        }
    }

    const WS: &str = "/home/u/src/proj";
    const BASE: &str = "/home/u/.cache/bazel/_bazel_u/6d827872adf1c6bdb16175c74008b7ce";
    // Bazel on Windows: an 8-character base under `<home>\_bazel_<user>`,
    // lower-cased by the client, so a link does not spell the workspace's
    // own case (gap-output-tree-recognition 1.2).
    const WIN_WS: &str = r"C:\Users\Me\src\proj";
    const WIN_BASE: &str = r"c:\users\me\_bazel_me\lsoq762r";

    /// A workspace and its output base as a build leaves them (probe C7).
    const BUILT: &str = "
        {ws}/MODULE.bazel
        {ws}/src/package.json
        {base}/DO_NOT_BUILD_HERE
        {base}/external/rules_x+/
        {base}/execroot/_main/bazel-out/k8/bin/node_modules/left-pad/
        {base}/execroot/_main/bazel-out/k8/testlogs/
        {ws}/bazel-out -> {base}/execroot/_main/bazel-out
        {ws}/bazel-bin -> {base}/execroot/_main/bazel-out/k8/bin
        {ws}/bazel-testlogs -> {base}/execroot/_main/bazel-out/k8/testlogs
        {ws}/bazel-proj -> {base}/execroot/_main";

    /// The second marker. `bazel clean` deletes it and only a new server
    /// writes it again, so a base that was cleaned and built has none.
    const EXECROOT_MARKER: &str = "{base}/execroot/DO_NOT_BUILD_HERE";

    fn built(ws: &str, base: &str) -> Fake {
        Fake::new(ws, base).with(BUILT).with(EXECROOT_MARKER)
    }

    fn cleaned_and_built(ws: &str, base: &str) -> Fake {
        Fake::new(ws, base).with(BUILT)
    }

    #[test]
    fn a_base_is_recognized_in_unix_and_windows_spellings() {
        for (ws, base) in [(WS, BASE), (WIN_WS, WIN_BASE)] {
            for fs in [built(ws, base), cleaned_and_built(ws, base)] {
                fs.expect(&[
                    ("{base}", OutputBase),
                    ("{base}/external/rules_x+/pnpm-lock.yaml", OutputBase),
                    ("{base}/execroot/_main/bazel-out/k8/bin", OutputBase),
                    // Not there yet: a file a patch would add.
                    ("{base}/external/rules_x+/new/dir/file.js", OutputBase),
                    ("{ws}/bazel-out", Link),
                    ("{ws}/bazel-bin", Link),
                    ("{ws}/bazel-testlogs", Link),
                    ("{ws}/bazel-proj", Link),
                    // `--cwd bazel-bin` reaches the rules_js store.
                    ("{ws}/bazel-bin/node_modules/left-pad", OutputBase),
                    ("{ws}", Plain),
                    ("{ws}/src/package.json", Plain),
                    ("{ws}/not/there", Plain),
                ]);
                let base = fs.tree(OutputBase, "{base}");
                for path in [
                    "{base}/external",
                    "{ws}/bazel-bin",
                    "{ws}/bazel-proj/external",
                ] {
                    assert_eq!(fs.verdict(path).tree, base, "{path}");
                }
                assert_eq!(fs.verdict("{ws}/src").tree, None);
            }
        }
    }

    #[test]
    fn a_tree_is_known_by_its_marker_and_never_by_its_name() {
        let fs = built(WS, BASE).with(
            "{ws}/dist/bin -> {base}/execroot/_main/bazel-out/k8/bin
             {ws}/bazel-foo/package.json
             {ws}/bazel-docs -> {ws}/src
             {ws}/store/dep/package.json
             {ws}/node_modules/dep -> ../store/dep
             /srv/a/DO_NOT_BUILD_HERE
             /srv/b/execroot/
             /srv/c/DO_NOT_BUILD_HERE/
             /srv/c/execroot/",
        );
        fs.expect(&[
            // `--symlink_prefix=dist/` (probes B4, C7).
            ("{ws}/dist/bin", Link),
            ("{ws}/dist/bin/node_modules", OutputBase),
            ("{ws}/dist", Plain),
            // A real directory and a link that only look like Bazel's.
            ("{ws}/bazel-foo/package.json", Plain),
            ("{ws}/bazel-docs", Plain),
            // A package manager's relative link: its target is not walked
            // as spelled, and its resolved form proves it plain.
            ("{ws}/node_modules/dep", Plain),
            // Half the markers: the file alone, the directory alone, and a
            // directory where the file should be.
            ("/srv/a/x", Plain),
            ("/srv/b/x", Plain),
            ("/srv/c/x", Plain),
        ]);
    }

    #[test]
    fn a_base_inside_the_checkout_is_a_tree() {
        // `--output_base=<ws>/out` (probe C8): real directories that hold
        // the rulesets' own lock files and the rules_js store.
        let fs = cleaned_and_built(WS, &format!("{WS}/out"))
            .with("{base}/external/rules_x+/pnpm-lock.yaml");
        fs.expect(&[
            ("{ws}/out", OutputBase),
            ("{ws}/out/external/rules_x+/pnpm-lock.yaml", OutputBase),
            ("{ws}/src/package.json", Plain),
        ]);
        // What a walker asks before it enters a directory: only the
        // directory that holds the markers answers.
        let own = |dir: &str| tree_at(&fs, &fs.path(dir), &[]);
        assert_eq!(own("{ws}/out").tree, fs.tree(OutputBase, "{ws}/out"));
        assert_eq!(own("{ws}"), Found::default());
        assert_eq!(own("{ws}/out/external"), Found::default());
    }

    #[test]
    fn a_shared_base_that_names_another_workspace_is_still_a_tree() {
        // `startup --output_base` shared by two workspaces (probe C8): the
        // marker names the one that last started a server. Classifying
        // never reads it; only locating this workspace's own base does.
        let fs = built(WS, "/var/shared/base");
        fs.expect(&[
            ("{ws}/bazel-bin", Link),
            ("{base}/external/rules_x+", OutputBase),
        ]);
        let linked = [Candidate {
            base: fs.path("{base}"),
            names_workspace: marker_names(b"/home/u/src/other", &fs.path("{ws}")),
        }];
        let located = locate(&linked, &[], true);
        assert_eq!(located, Located::CannotTell(Unsure::MarkerMismatch));
    }

    #[test]
    fn a_marker_is_compared_as_bytes_and_a_mismatch_is_unknown() {
        let workspace = Path::new("/src/ws-ünï-é");
        assert!(marker_names("/src/ws-ünï-é".as_bytes(), workspace));
        // Bazel <= 7.7.2 writes the path as ISO-8859-1 (probe C7).
        assert!(!marker_names(b"/src/ws-\xfcn\xef-\xe9", workspace));
        // No newline is written, so none is trimmed.
        assert!(!marker_names("/src/ws-ünï-é\n".as_bytes(), workspace));
        assert!(!marker_names(b"/src/ws", workspace));
        // The Windows server spells the path its own way.
        let canonical = Path::new(r"\\?\C:\Users\Me\src\proj");
        assert!(!marker_names(b"C:/users/me/src/proj", canonical));
    }

    #[test]
    fn a_vendor_directory_is_known_by_either_marker_or_a_tracked_flag() {
        let fs = built(WS, BASE).with(
            "{ws}/vendor_src/VENDOR.bazel
             {ws}/vendor_src/+http+dep/package-lock.json
             {ws}/vendor_src/bazel-external -> {base}/external
             {base}/external/+http+dep -> {ws}/vendor_src/+http+dep
             {ws}/third_party/.vendorignore
             {ws}/third_party/_main~rules~dep/go.mod
             {ws}/deps/+x+y/",
        );
        fs.expect(&[
            // 7.3 and later write `VENDOR.bazel` (probe C11).
            ("{ws}/vendor_src", VendorDir),
            ("{ws}/vendor_src/+http+dep/package-lock.json", VendorDir),
            ("{ws}/vendor_src/bazel-external", VendorDir),
            // 7.1.2 - 7.2.1 write `.vendorignore` only.
            ("{ws}/third_party/_main~rules~dep/go.mod", VendorDir),
            // Named by a tracked `--vendor_dir` alone: unknown without it.
            ("{ws}/deps/+x+y", Plain),
        ]);
        let lock = fs.verdict("{ws}/third_party/_main~rules~dep/go.mod");
        assert_eq!(lock.tree, fs.tree(VendorDir, "{ws}/third_party"));
        // `external/<repo>` of a vendored repository is a link out of the
        // base into the checkout: one tree as spelled, another as stored.
        let vendored = fs.verdict("{base}/external/+http+dep/package-lock.json");
        assert_eq!(vendored.class, OutputBase);
        assert_eq!(
            vendored.resolves_into,
            fs.tree(VendorDir, "{ws}/vendor_src")
        );

        let deps = fs.path("{ws}/deps/+x+y");
        let mut tracked = Memo::new(vec![fs.path("{ws}/deps")]);
        let verdict = classify(&fs, &deps, Some(&deps), &mut tracked);
        assert_eq!(verdict.tree, fs.tree(VendorDir, "{ws}/deps"));
    }

    #[test]
    fn a_contents_cache_entry_is_known_by_its_recorded_inputs_sibling() {
        // 9.3.2 names an entry by UUID; 8.3.1 by a counter, beside a
        // `counter` file (probe C3).
        let fs = built(WS, BASE).with(
            "/cache/contents/cd12716a/64889d38-711a/package/package.json
             /cache/contents/cd12716a/64889d38-711a.recorded_inputs
             /cache/contents/6cee75cc/1/BUILD.bazel
             /cache/contents/6cee75cc/1.recorded_inputs
             /cache/contents/6cee75cc/counter
             /cache/contents/gc_lock
             /cache/contents/_trash/
             {base}/external/npm+left-pad -> /cache/contents/cd12716a/64889d38-711a",
        );
        fs.expect(&[
            ("/cache/contents/cd12716a/64889d38-711a", RepoContentsCache),
            (
                "/cache/contents/cd12716a/64889d38-711a/new/file.js",
                RepoContentsCache,
            ),
            ("/cache/contents/6cee75cc/1/BUILD.bazel", RepoContentsCache),
            // The cache's own bookkeeping is not an entry.
            ("/cache/contents", Plain),
            ("/cache/contents/_trash", Plain),
            ("/cache/contents/6cee75cc/counter", Plain),
            (
                "/cache/contents/cd12716a/64889d38-711a.recorded_inputs",
                Plain,
            ),
        ]);
        // The path every ruleset's repository has on Bazel 9: spelled in
        // the base, stored in the cache all of the user's workspaces share.
        let entry = fs.tree(RepoContentsCache, "/cache/contents/cd12716a/64889d38-711a");
        for path in [
            "{base}/external/npm+left-pad",
            "{base}/external/npm+left-pad/package",
        ] {
            let verdict = fs.verdict(path);
            assert_eq!(verdict.tree, fs.tree(OutputBase, "{base}"), "{path}");
            assert_eq!(verdict.resolves_into, entry, "{path}");
        }
    }

    #[test]
    fn a_repository_cache_entry_is_known_by_its_shape_alone() {
        let cas = "/cache/content_addressable";
        let hex = |len: usize| "A1".repeat(len / 2);
        // One entry of each digest kind with no `id-*` sibling: what Bazel
        // 5 and 6 leave, and rules_python, rules_ruby and rules_dotnet
        // downloads on every version (probe H3).
        let mut fs = Fake::new(WS, BASE);
        for (kind, len) in CAS_KEY_TYPES {
            let (entry, short, empty) = (hex(len), hex(len - 2), "0".repeat(len));
            fs = fs.with(&format!(
                "{cas}/{kind}/{entry}/file
                 {cas}/{kind}/{short}/file
                 {cas}/{kind}/{empty}/
                 /srv/blobs/{kind}/{entry}/file"
            ));
        }
        for (kind, len) in CAS_KEY_TYPES {
            let entry = format!("{cas}/{kind}/{}", hex(len));
            for path in [
                entry.clone(),
                format!("{entry}/file"),
                format!("{entry}/id-37d7"),
            ] {
                assert_eq!(
                    fs.verdict(&path).tree,
                    fs.tree(RepositoryCache, &entry),
                    "{path}"
                );
            }
            fs.expect(&[
                // A name of the wrong length for its kind.
                (&format!("{cas}/{kind}/{}/file", hex(len - 2)), Plain),
                // The right shape with no payload: a download in flight.
                (&format!("{cas}/{kind}/{}", "0".repeat(len)), Plain),
                // The right shape outside `content_addressable`.
                (&format!("/srv/blobs/{kind}/{}/file", hex(len)), Plain),
                (&format!("{cas}/{kind}"), Plain),
            ]);
        }
        // Not a digest kind Bazel has.
        let fs = fs.with(&format!("{cas}/md5/{}/file", hex(32)));
        fs.expect(&[
            (&format!("{cas}/md5/{}/file", hex(32)), Plain),
            (cas, Plain),
        ]);
    }

    #[test]
    fn junction_shaped_entries_classify_by_their_target() {
        // A junction: `stat` sees the target directory and `read_link`
        // gives an absolute target, here in Bazel's lower-cased spelling.
        let fs = cleaned_and_built(WIN_WS, WIN_BASE).with(
            r"c:\users\me\_bazel_me\install\7b1f\embedded_tools\
              {base}\install -> c:\users\me\_bazel_me\install\7b1f
              c:\users\me\_bazel_me\cache\contents\cd12\6488\package.json
              c:\users\me\_bazel_me\cache\contents\cd12\6488.recorded_inputs
              {base}\external\npm+left-pad -> c:\users\me\_bazel_me\cache\contents\cd12\6488
              {ws}\old-bin -> {base}\execroot\_main\bazel-out\x64_windows-opt\bin
              {ws}\tools -> c:\users\me\_bazel_me\install\7b1f
              {ws}\gone -> c:\users\me\_bazel_me\zzzzzzzz\execroot\_main\bazel-out",
        );
        let through = fs.path(r"{ws}\bazel-bin\node_modules");
        assert_eq!(fs.stat(&through), Entry::Dir);
        fs.expect(&[
            (r"{ws}\bazel-bin", Link),
            (r"{ws}\bazel-proj\external", OutputBase),
            // `install` is a junction out of the base, spelled inside it.
            (r"{base}\install\embedded_tools", OutputBase),
            // Hand-made, into the install base: not a tree.
            (r"{ws}\tools", Plain),
            // Dangling: the base it named was expunged.
            (r"{ws}\gone", Plain),
        ]);
        let repo = fs.verdict(r"{base}\external\npm+left-pad\package.json");
        let entry = r"c:\users\me\_bazel_me\cache\contents\cd12\6488";
        assert_eq!(repo.class, OutputBase);
        assert_eq!(repo.resolves_into, fs.tree(RepoContentsCache, entry));
        // A link left under an earlier `--symlink_prefix`, whose target
        // `clean` has removed, resolves to nothing: its canonical form is
        // its own path. Its stored target still leads into the base.
        let stale = fs.path(r"{ws}\old-bin");
        let verdict = classify(&fs, &stale, Some(&stale), &mut Memo::default());
        assert_eq!(verdict.class, Link);
        assert_eq!(verdict.tree, fs.tree(OutputBase, "{base}"));
        // A relative target is read from the directory that holds the link.
        let fs = built(WS, &format!("{WS}/out")).with("{ws}/pkg/out -> ../out/external");
        fs.expect(&[("{ws}/pkg/out", Link)]);
    }

    #[test]
    fn the_link_route_cuts_the_target_at_execroot_and_asks_for_the_marker() {
        for (ws, base) in [(WS, BASE), (WIN_WS, WIN_BASE)] {
            // The marker in `execroot` is not the one the route asks for.
            let fs = cleaned_and_built(ws, base);
            for link in ["bazel-out", "bazel-bin", "bazel-testlogs", "bazel-proj"] {
                let target = fs.read_link(&fs.path("{ws}").join(link)).unwrap();
                assert_eq!(
                    base_of_link_target(&fs, &target),
                    Some(fs.path("{base}")),
                    "{link}"
                );
            }
        }
        // 5.x and 6.x name the execution root after `workspace(name = ..)`.
        // One named `execroot`, below a path that has the segment already,
        // still finds the base and not its `execroot` directory.
        let fs = built(WS, "/data/execroot/_bazel_u/abc").with("{base}/execroot/execroot/out/");
        let route = |target: &str| base_of_link_target(&fs, &fs.path(target));
        assert_eq!(
            route("{base}/execroot/execroot/out"),
            Some(fs.path("{base}"))
        );
        // No `execroot` segment below a base, or no marker beside one.
        for target in [
            "{base}/external",
            "/data/execroot/x",
            "/gone/execroot/_main",
        ] {
            assert_eq!(route(target), None, "{target}");
        }
        // The route is enough to make a link Bazel's: a marker whose
        // `execroot` directory is gone is no base to a path inside it, and
        // a link through that segment still leads into Bazel's tree.
        let fs = Fake::new(WS, "/half").with(
            "{base}/DO_NOT_BUILD_HERE
             {ws}/bazel-out -> {base}/execroot/_main/bazel-out",
        );
        fs.expect(&[("{base}/external", Plain), ("{ws}/bazel-out", Link)]);
        assert_eq!(
            fs.verdict("{ws}/bazel-out").tree,
            fs.tree(OutputBase, "{base}")
        );
    }

    #[test]
    fn locating_a_base_needs_a_link_or_exactly_one_marked_base() {
        let base = |name: &str, names_workspace| Candidate {
            base: p(name),
            names_workspace,
        };
        let found = |candidate: &Candidate, route| Located::Base {
            base: candidate.base.clone(),
            route,
        };
        let cannot_tell = Located::CannotTell;
        // After a Bazel upgrade two bases name the workspace (probe C8):
        // one from 7.1.2 and one from 7.2.0, which reads `XDG_CACHE_HOME`.
        let old = base("/root/.cache/bazel/_bazel_root/6d82", true);
        let new = base("/xdg/bazel/_bazel_root/6d82", true);
        let other = base("/xdg/bazel/_bazel_root/aaaa", false);
        let both = [old.clone(), new.clone()];
        // Four links into the live base name it, whatever else is listed.
        let links = [new.clone(), new.clone(), new.clone(), new.clone()];
        assert_eq!(locate(&links, &both, true), found(&new, Route::Link));
        // Several bases and no link: cannot tell.
        assert_eq!(locate(&[], &both, true), cannot_tell(Unsure::SeveralBases));
        assert_eq!(locate(&[], &both, false), cannot_tell(Unsure::SeveralBases));
        // Links left under an older prefix lead into the other base.
        assert_eq!(locate(&both, &[], true), cannot_tell(Unsure::LinksDisagree));
        // A link into a base that does not name the workspace is not used,
        // and the listed bases are not asked instead.
        let shared = locate(
            std::slice::from_ref(&other),
            std::slice::from_ref(&new),
            true,
        );
        assert_eq!(shared, cannot_tell(Unsure::MarkerMismatch));
        // Other workspaces' bases under the same root are not candidates.
        let listed = [other.clone(), new.clone(), new.clone()];
        assert_eq!(locate(&[], &listed, true), found(&new, Route::Enumeration));
        assert_eq!(locate(&[], &listed, false), cannot_tell(Unsure::Unlisted));
        assert_eq!(locate(&[], &[other], true), Located::NotFound);
        assert_eq!(locate(&[], &[], false), cannot_tell(Unsure::Unlisted));
    }

    #[test]
    fn an_unanswered_question_is_never_read_as_plain() {
        let answer = |verdict: Verdict| (verdict.class, verdict.cannot_tell);
        let mut fs = built(WS, BASE).with("/locked/pkg/");
        fs.unknown.insert(p("/locked/DO_NOT_BUILD_HERE"));
        assert_eq!(answer(fs.verdict("/locked/pkg")), (Plain, true));
        // A proven tree is not put in doubt by a question below or above it.
        let below = fs.path("{base}/external/VENDOR.bazel");
        fs.unknown.extend([below, p("/home/DO_NOT_BUILD_HERE")]);
        assert_eq!(
            answer(fs.verdict("{base}/external/rules_x+")),
            (OutputBase, false)
        );

        // A path that could not be resolved has no canonical form.
        let fs = built(WS, &format!("{WS}/out"));
        let src = fs.path("{ws}/src");
        let classed =
            |found: &Path, canonical| classify(&fs, found, canonical, &mut Memo::default());
        assert_eq!(answer(classed(&src, None)), (Plain, true));
        assert_eq!(answer(classed(&src, Some(&src))), (Plain, false));
        // `out/../src` is not below `out`, and is not walked as if it were.
        let dotted = fs.path("{ws}/out/../src");
        let walked = enclosing(&fs, &dotted, &mut Memo::default());
        assert_eq!((walked.tree, walked.cannot_tell), (None, true));
        assert_eq!(answer(classed(&dotted, Some(&src))), (Plain, true));
    }

    #[test]
    fn each_directory_is_judged_once_per_memo() {
        let fs = built(WS, BASE);
        let mut memo = Memo::default();
        let mut walk = |path: &str| {
            let before = fs.stats.get();
            let found = enclosing(&fs, &fs.path(path), &mut memo);
            (found.tree, fs.stats.get() - before)
        };
        assert_eq!(walk("{ws}/node_modules/a").0, None);
        // A sibling package costs its own directory and nothing above it.
        assert_eq!(walk("{ws}/node_modules/b"), (None, 4));
        assert_eq!(walk("{ws}/node_modules/a"), (None, 0));
        // Below a tree the answer is inherited the same way.
        let base = fs.tree(OutputBase, "{base}");
        assert_eq!(walk("{base}/external/a/b/c").0, base);
        assert_eq!(walk("{base}/external/a/b/d"), (base.clone(), 4));
        assert_eq!(walk("{base}/external/a"), (base, 0));
    }

    #[test]
    fn a_path_list_is_classified_like_a_disk() {
        let listing = Listing::new([
            "MODULE.bazel",
            "pnpm-lock.yaml",
            "vendor_src/VENDOR.bazel",
            "vendor_src/+http+dep/package-lock.json",
            "third_party/.vendorignore",
            "third_party/rules_x~/go.mod",
            "out/DO_NOT_BUILD_HERE",
            "out/execroot/_main/pnpm-lock.yaml",
            "out/external/rules_nodejs~/yarn.lock",
            "services/api/go.mod",
        ]);
        let mut memo = Memo::default();
        for (path, want) in [
            (
                "vendor_src/+http+dep/package-lock.json",
                Some((VendorDir, "vendor_src")),
            ),
            (
                "third_party/rules_x~/go.mod",
                Some((VendorDir, "third_party")),
            ),
            (
                "out/external/rules_nodejs~/yarn.lock",
                Some((OutputBase, "out")),
            ),
            (
                "out/execroot/_main/pnpm-lock.yaml",
                Some((OutputBase, "out")),
            ),
            ("pnpm-lock.yaml", None),
            ("services/api/go.mod", None),
            ("services/missing", None),
            ("", None),
        ] {
            let found = enclosing(&listing, Path::new(path), &mut memo);
            let tree = want.map(|(class, root)| Tree {
                class,
                root: PathBuf::from(root),
            });
            assert_eq!((found.tree, found.cannot_tell), (tree, false), "{path:?}");
        }
        assert_eq!(listing.stat(Path::new("services")), Entry::Dir);
        assert_eq!(listing.stat(Path::new("")), Entry::Dir);
        assert_eq!(listing.stat(Path::new("services/api/go.mod")), Entry::File);
        assert_eq!(listing.stat(Path::new("services/web")), Entry::Neither);
        assert_eq!(listing.read_link(Path::new("vendor_src")), None);
    }
}
