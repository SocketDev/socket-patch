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

use std::io::{ErrorKind, Read as _};
use std::path::{Component, Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use super::coursier_cache::TargetOs;
use crate::bazel::output_tree::{
    self, Candidate, Entry, Found, Located, Memo, PathClass, TreeFs, Unsure, Verdict,
    OUTPUT_BASE_MARKER,
};
use crate::utils::fs::open_regular_file_sync;

/// The longest marker read. A marker holds one path, far below this; a
/// larger `DO_NOT_BUILD_HERE` is not Bazel's and names nothing.
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
    /// directory before `bazel vendor` has written a marker into it.
    pub fn with_vendor_dirs(dirs: impl IntoIterator<Item = PathBuf>) -> Self {
        let mut vendor_dirs = Vec::new();
        for dir in dirs {
            // Compared by identity: a query is judged as spelled and as
            // resolved, so the directory is kept both ways.
            if let Some(real) = std::fs::canonicalize(&dir).ok().filter(|real| *real != dir) {
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
    pub fn classify(&self, path: &Path) -> Verdict {
        let Ok(found) = std::path::absolute(path) else {
            return Verdict {
                class: PathClass::Plain,
                tree: None,
                resolves_into: None,
                cannot_tell: true,
            };
        };
        let canonical = resolve(&found, MAX_LINK_HOPS);
        // Where `a/b/../c` is, only the disk knows, so a path spelled with
        // `..` is judged by its resolved form alone.
        let dotted = found.components().any(|c| c == Component::ParentDir);
        let found = match &canonical {
            Some(real) if dotted => real.clone(),
            _ => found,
        };
        // Held across the marker tests: they are a few `stat`s, and two
        // callers that walked the same ancestors at once would only repeat
        // them.
        let mut memo = self.memo.lock().unwrap_or_else(PoisonError::into_inner);
        output_tree::classify(&Disk, &found, canonical.as_deref(), &mut memo)
    }

    /// The tree `dir` itself is the root of, by its own markers: the test
    /// a walker makes before it enters a directory. It costs at most four
    /// `stat`s, walks nowhere and remembers nothing, because a walker
    /// meets each directory once and came down from one it already
    /// entered. The root of the walk is [`Classifier::classify`]'s to
    /// judge.
    pub fn tree_at(&self, dir: &Path) -> Found {
        output_tree::tree_at(&Disk, dir, &self.vendor_dirs)
    }
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
        let env = |name: &str| std::env::var(name).ok();
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
pub fn default_output_roots(
    os: TargetOs,
    env: &dyn Fn(&str) -> Option<String>,
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
    // A client that sees `TEST_TMPDIR` uses it whatever else is set.
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

/// Whether the marker of `base` names `workspace` (canonical). Anything
/// but a match is unknown: an unreadable marker, an oversized one, another
/// workspace's path, this path in another encoding.
fn marker_names_workspace(base: &Path, workspace: &Path) -> bool {
    let Ok((file, meta)) = open_regular_file_sync(&base.join(OUTPUT_BASE_MARKER)) else {
        return false;
    };
    let mut bytes = Vec::new();
    meta.len() <= MAX_MARKER_BYTES
        && file.take(MAX_MARKER_BYTES).read_to_end(&mut bytes).is_ok()
        && output_tree::marker_names(&bytes, workspace)
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
pub fn locate_output_base(workspace: &Path, candidates: &Candidates) -> Located {
    let Ok(workspace) = std::fs::canonicalize(workspace) else {
        return Located::CannotTell(Unsure::Unlisted);
    };
    let mut listed_all = true;
    let candidate = |base: PathBuf| Candidate {
        names_workspace: marker_names_workspace(&base, &workspace),
        // One spelling per base, so `/var/tmp` and `/private/var/tmp`
        // count once.
        base: std::fs::canonicalize(&base).unwrap_or(base),
    };
    let absolute = |dirs: &[PathBuf]| {
        let kept = dirs.iter().filter(|dir| dir.is_absolute());
        kept.cloned().collect::<Vec<_>>()
    };

    let mut linked = Vec::new();
    for dir in std::iter::once(workspace.clone()).chain(absolute(&candidates.link_dirs)) {
        for entry in list(&dir, MAX_LISTED, &mut listed_all) {
            if !entry.file_type().is_ok_and(|kind| kind.is_symlink()) {
                continue;
            }
            let target = Disk.read_link(&entry.path()).map(|target| dir.join(target));
            let base = target.and_then(|target| output_tree::base_of_link_target(&Disk, &target));
            linked.extend(base.map(&candidate));
        }
    }
    if !linked.is_empty() {
        return output_tree::locate(&linked, &[], listed_all);
    }

    let mut user_roots = absolute(&candidates.output_user_roots);
    for root in absolute(&candidates.output_roots) {
        let entries = list(&root, MAX_LISTED, &mut listed_all).into_iter();
        let users = entries.filter(|e| e.file_name().as_encoded_bytes().starts_with(b"_bazel_"));
        user_roots.extend(users.map(|entry| entry.path()));
    }
    let mut bases = absolute(&candidates.output_bases);
    for user_root in user_roots {
        let entries = list(&user_root, MAX_LISTED, &mut listed_all);
        bases.extend(entries.iter().map(|entry| entry.path()));
    }
    let is_base = |dir: &PathBuf| {
        let own = output_tree::tree_at(&Disk, dir, &[]).tree;
        own.is_some_and(|tree| tree.class == PathClass::OutputBase)
    };
    let enumerated: Vec<Candidate> = bases.into_iter().filter(is_base).map(candidate).collect();
    output_tree::locate(&[], &enumerated, listed_all)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use crate::bazel::output_tree::PathClass::{
        Link, OutputBase, Plain, RepoContentsCache, RepositoryCache, VendorDir,
    };
    use crate::bazel::output_tree::{Route, Tree};

    /// An output base as a server and a build leave it (probe C7).
    const BASE: &str = "
        {base}/DO_NOT_BUILD_HERE
        {base}/external/rules_x+/
        {base}/execroot/_main/bazel-out/k8/bin/node_modules/left-pad/";

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
            }
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
    }

    #[test]
    fn default_roots_cover_every_release_of_each_os() {
        fn roots(os: TargetOs, vars: &[(&str, &str)], passwd_home: Option<&str>) -> Vec<PathBuf> {
            let env = |name: &str| {
                let var = vars.iter().find(|(key, _)| *key == name);
                var.map(|(_, value)| value.to_string())
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
        // Never built: no base anywhere.
        assert_eq!(locate_output_base(&ws, &candidates), Located::NotFound);

        // One base names the workspace, after `clean` and a build. Beside
        // it: another workspace's base, the install and cache directories
        // of the user root, a marker with no `execroot`, and a base that
        // is not under a `_bazel_<user>` directory.
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
            // Too large to be a path: it names nothing.
            (vec![b'x'; MAX_MARKER_BYTES as usize + 1], false),
        ] {
            fs::write(base.join(OUTPUT_BASE_MARKER), &marker).unwrap();
            assert_eq!(
                marker_names_workspace(&base, &ws),
                names,
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
        assert!(!marker_names_workspace(&base, &ws));
        assert_eq!(classify(&base.join("external")).class, Plain);
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
        use std::os::unix::fs::PermissionsExt;
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

        fs::set_permissions(&user_root, fs::Permissions::from_mode(0o000)).unwrap();
        // Root reads everything: nothing to observe then.
        if fs::read_dir(&user_root).is_err() {
            let unlisted = Located::CannotTell(Unsure::Unlisted);
            assert_eq!(locate_output_base(&ws, &candidates), unlisted);
            // Nor is a path below it proven plain.
            let hidden = classify(&user_root.join("6d82/external"));
            assert_eq!((hidden.class, hidden.cannot_tell), (Plain, true));
        }
        fs::set_permissions(&user_root, fs::Permissions::from_mode(0o755)).unwrap();
        let base = found(disk.at("root/_bazel_u/6d82"), Route::Enumeration);
        assert_eq!(locate_output_base(&ws, &candidates), base);
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
        let marker = fs::canonicalize(&ws).unwrap();
        fs::write(base.join(OUTPUT_BASE_MARKER), bytes(&marker)).unwrap();
        let link = ws.join("bazel-bin");
        let made = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(bin.join("k8").join("bin"))
            .status()
            .unwrap();
        assert!(made.success(), "mklink /J failed");
        assert_eq!(classify(&link).class, Link);
        assert_eq!(classify(&link.join("node_modules")).class, OutputBase);
        assert_eq!(classify(&ws).class, Plain);
        let located = locate_output_base(&ws, &Candidates::default());
        assert_eq!(
            located,
            found(fs::canonicalize(&base).unwrap(), Route::Link)
        );
    }
}
