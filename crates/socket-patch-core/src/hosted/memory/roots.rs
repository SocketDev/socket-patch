//! Project-root detection over a repository path list. A root is a
//! directory holding a root LOCK marker (manifests alone never make one),
//! outside vendored / test-fixture trees, and not an internal directory of
//! an enclosing Rush monorepo. A nested Cargo.lock stays a root here: only
//! the enclosing workspace's `members`/`exclude` can say whether it is a
//! member, so the engine demotes members once manifests are readable. A
//! pnpm workspace member's lock is demoted into the workspace root the
//! same way, by the `packages:` globs ([`pnpm_member_candidates`]).
//!
//! Nothing inside a tree Bazel owns is a root either (design 3, HZ-02 and
//! HZ-03): an output base kept in the checkout mirrors the root's own
//! lockfiles and holds those of every fetched ruleset, and a committed
//! Bazel vendor directory holds the lockfiles of the repositories it
//! vendors. Such a tree is known by the marker Bazel wrote into it
//! (`bazel::output_tree`), on disk and in a path list alike.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use crate::bazel::codes::Code;
use crate::bazel::output_tree;
use crate::crawlers::bazel_output::Classifier;
use crate::formats::registry;
use crate::utils::python_lock::is_python_lock_name;

use super::types::IgnoredPath;

/// Marker files of the ecosystems the in-memory engine cannot inventory
/// (disk discovers them only through installed-tree crawlers).
pub const UNSUPPORTED_MARKERS: [(&str, &[&str]); 2] = [
    ("maven", crate::vendor::jvm::layout::JVM_PROJECT_MARKERS),
    (
        "nuget",
        &[
            "packages.lock.json",
            "nuget.config",
            "NuGet.config",
            "NuGet.Config",
        ],
    ),
];

/// Directory names whose subtrees never hold a project root: installed
/// trees, VCS and tool state, and vendored dependencies. Structural, so no
/// policy can negate them. (Test and fixture trees are the socket.yml
/// policy's overridable built-in ignores.) `.socket-auto-manifest` is
/// where socket-cli writes the manifests it generates for a build it
/// cannot read (design 3, HZ-24): they describe the project above them and
/// are regenerated, so a pin written there would patch nothing.
pub(crate) const EXCLUDED_ROOT_SEGMENTS: [&str; 6] = [
    "node_modules",
    ".git",
    ".socket",
    ".yarn",
    "vendor",
    ".socket-auto-manifest",
];

/// The marker basenames of `root` among `paths` (the files the policy's
/// path filters test for that root).
pub(crate) fn root_markers<'a>(
    root: &str,
    paths: impl IntoIterator<Item = &'a str>,
) -> Vec<String> {
    let mut out: Vec<String> = paths
        .into_iter()
        .filter_map(|path| {
            let (dir, base) = split_path(path);
            let marker = marker_ecosystem(base).is_some()
                || UNSUPPORTED_MARKERS
                    .iter()
                    .any(|(_, names)| names.contains(&base));
            (dir == root && marker).then(|| base.to_string())
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

/// The ecosystem a root marker basename belongs to: a [`registry::ROOT`]
/// row (manifests alone never make a root) or a PEP 751 / PEP 723 lock.
pub fn marker_ecosystem(base: &str) -> Option<&'static str> {
    if let Some(row) = registry::root_marker(base) {
        return Some(row.ecosystem);
    }
    is_python_lock_name(base).then_some("pypi")
}

/// `(dir, basename)` of a `/`-separated path.
pub(crate) fn split_path(path: &str) -> (&str, &str) {
    match path.rsplit_once('/') {
        Some((dir, base)) => (dir, base),
        None => ("", path),
    }
}

/// `root`-relative form of `path`, or `None` when `path` is not under it.
pub(crate) fn strip_root<'a>(root: &str, path: &'a str) -> Option<&'a str> {
    if root.is_empty() {
        return Some(path);
    }
    path.strip_prefix(root)?.strip_prefix('/')
}

/// `root/rel` (`rel` alone for the repo root).
pub(crate) fn join_root(root: &str, rel: &str) -> String {
    if root.is_empty() {
        rel.to_string()
    } else {
        format!("{root}/{rel}")
    }
}

/// yarn berry's rc file, which yarn merges from every directory at or
/// above the project (the closest setting winning).
pub(crate) const YARNRC_NAME: &str = ".yarnrc.yml";

/// The directories strictly above `root` inside the repository, nearest
/// first, ending with the repository root (`""`). None for the repository
/// root itself.
pub(crate) fn strict_ancestors(root: &str) -> impl Iterator<Item = &str> {
    let mut next = (!root.is_empty()).then_some(root);
    std::iter::from_fn(move || {
        let dir = next?;
        let parent = split_path(dir).0;
        next = (!parent.is_empty()).then_some(parent);
        Some(parent)
    })
}

fn allowed(ecosystems: Option<&[String]>, eco: &str) -> bool {
    ecosystems.is_none_or(|list| list.iter().any(|e| e == eco))
}

/// Whether `dir` is `tree` or lies below it; `""` is the listing's root.
fn at_or_below(dir: &str, tree: &str) -> bool {
    tree.is_empty() || strip_root(tree, dir).is_some() || dir == tree
}

/// The directories of a path list that are trees Bazel owns (design
/// 2.11), `/`-separated and sorted: an output base, an entry of either
/// cache, a vendor directory. A list knows a directory only by the files
/// in it, so a tree is found as far as its marker is listed.
///
/// The first pass asks each path whether its name can be a marker at all.
/// Almost no list has one, and then nothing more is done; the directories
/// the names point at are judged by the classifier, over the files listed
/// in and beside them.
fn bazel_trees_listed<'a>(paths: impl Iterator<Item = &'a str> + Clone) -> Vec<String> {
    let mut pointed: BTreeSet<String> = BTreeSet::new();
    for path in paths.clone() {
        let (dir, base) = split_path(path);
        if let Some(marked) = output_tree::marked_dir(Path::new(dir), OsStr::new(base)) {
            let segments: Option<Vec<&str>> = marked.iter().map(OsStr::to_str).collect();
            pointed.extend(segments.map(|segments| segments.join("/")));
        }
    }
    if pointed.is_empty() {
        return Vec::new();
    }
    // The marker of a contents-cache entry lies beside it; every other
    // file a rule asks for lies inside the directory.
    let near = |path: &str| {
        pointed.iter().any(|dir| {
            let (parent, _) = split_path(path);
            at_or_below(parent, dir)
                || path
                    .strip_prefix(dir.as_str())
                    .is_some_and(|rest| rest.starts_with('.'))
        })
    };
    let listing = output_tree::Listing::new(paths.filter(|path| near(path)));
    let is_tree = |dir: &String| {
        output_tree::tree_at(&listing, Path::new(dir), &[])
            .tree
            .is_some()
    };
    pointed.into_iter().filter(is_tree).collect()
}

/// The detected roots (sorted) and the marker paths that did not make one.
/// The socket.yml path policy (built-in default ignores included) is the
/// caller's to apply.
pub(crate) fn detect_roots<'a, I>(
    paths: I,
    ecosystems: Option<&[String]>,
) -> (Vec<String>, Vec<IgnoredPath>)
where
    I: IntoIterator<Item = &'a str>,
    I::IntoIter: Clone,
{
    let paths = paths.into_iter();
    let bazel_trees = bazel_trees_listed(paths.clone());
    let mut ignored: Vec<IgnoredPath> = Vec::new();
    let mut markers: BTreeMap<String, BTreeSet<&'static str>> = BTreeMap::new();
    let mut marker_paths: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for path in paths {
        let (dir, base) = split_path(path);
        let Some(eco) = marker_ecosystem(base) else {
            continue;
        };
        let ignore = |reason: &str, ignored: &mut Vec<IgnoredPath>| {
            ignored.push(IgnoredPath {
                path: path.to_string(),
                reason: reason.to_string(),
            });
        };
        if dir
            .split('/')
            .any(|seg| EXCLUDED_ROOT_SEGMENTS.contains(&seg))
        {
            ignore("excluded_dir", &mut ignored);
            continue;
        }
        if bazel_trees.iter().any(|tree| at_or_below(dir, tree)) {
            ignore(Code::WorkspaceOutputTreeSkipped.as_str(), &mut ignored);
            continue;
        }
        if !allowed(ecosystems, eco) {
            ignore("ecosystem_filtered", &mut ignored);
            continue;
        }
        let key: &'static str = registry::root_marker(base).map_or("python-lock", |row| row.path);
        markers.entry(dir.to_string()).or_default().insert(key);
        marker_paths
            .entry(dir.to_string())
            .or_default()
            .push(path.to_string());
    }

    let rush_roots: Vec<String> = markers
        .iter()
        .filter(|(_, m)| m.contains("rush.json"))
        .map(|(d, _)| d.clone())
        .collect();
    let mut roots: Vec<String> = Vec::new();
    for dir in markers.keys() {
        let rush_internal = rush_roots.iter().any(|r| {
            let internal = |sub: &str| join_root(r, sub);
            *dir == internal("common/config/rush")
                || dir.starts_with(&format!("{}/", internal("common/config/subspaces")))
                || *dir == internal("common/temp")
                || dir.starts_with(&format!("{}/", internal("common/temp")))
        });
        if rush_internal {
            for path in marker_paths.get(dir).into_iter().flatten() {
                ignored.push(IgnoredPath {
                    path: path.clone(),
                    reason: "rush_internal".to_string(),
                });
            }
        } else {
            roots.push(dir.clone());
        }
    }
    roots.sort();
    ignored.sort_by(|a, b| a.path.cmp(&b.path));
    (roots, ignored)
}

/// What [`roots_below`] found.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct DiskRoots {
    /// The root directories relative to the walked one, `/`-separated and
    /// sorted; `""` is the walked directory itself.
    pub roots: Vec<String>,
    /// A workspace member below the walked directory was left out because
    /// the walked directory's own run reads its lock, so that run has to
    /// happen even when the directory holds no lock of its own.
    pub governs_members: bool,
    /// The walk stopped at [`MAX_WALKED_ENTRIES`], so `roots` may be
    /// incomplete.
    pub truncated: bool,
    /// The directories the walk did not enter because Bazel owns them (an
    /// output base, a cache entry, a vendor directory), relative to the
    /// walked one, `/`-separated and sorted. A run reports them
    /// (`bazel_workspace_output_tree_skipped`): what it left out of its
    /// search must not look searched.
    pub bazel_trees: Vec<String>,
}

/// What [`marker_paths_below`] found.
#[derive(Debug, Default)]
struct WalkedMarkers {
    /// The marker files, as `/`-separated paths relative to the walked
    /// directory.
    markers: Vec<String>,
    /// The walk was cut short.
    truncated: bool,
    /// [`DiskRoots::bazel_trees`].
    bazel_trees: Vec<String>,
    /// How many entries the walk read: a tree that was not entered adds
    /// its root and its markers, whatever it holds.
    walked: usize,
}

/// Whether `dir` is the root of a tree Bazel owns, by its own markers.
fn is_tree_root(classifier: &Classifier, dir: &Path) -> bool {
    let own = classifier.tree_at(dir).tree;
    own.is_some_and(|tree| tree.root == dir)
}

/// The trees Bazel owns that a walk has met, and how it stays out of them
/// for the price of a few `stat`s per directory that has subdirectories.
///
/// A root is found in two ways. Before the walk enters a subdirectory, the
/// directory that holds it is judged by the classifier, once: so nothing
/// below a root is ever read, in whatever order a directory lists its
/// entries, and an output base larger than the whole walk's budget costs
/// one listing. A root with no subdirectory is never asked about that way;
/// it is known by the marker among its files, whose name points at it
/// ([`output_tree::marked_dir`]) at no cost, and the classifier decides.
#[derive(Debug, Default)]
struct BazelTreesMet {
    /// The roots, as the walk spells them.
    roots: Vec<PathBuf>,
    /// The directories the walk is inside of, outermost first, each with
    /// whether it is a root.
    inside: Vec<(PathBuf, bool)>,
}

impl BazelTreesMet {
    fn note(&mut self, root: PathBuf) {
        if !self.roots.contains(&root) {
            self.roots.push(root);
        }
    }

    /// Whether the walk must not enter `subdir`, an entry of a directory
    /// it is listing: that directory is a root, or `subdir` is one a
    /// marker beside it already named.
    fn keeps_out_of(&mut self, classifier: &Classifier, subdir: &Path) -> bool {
        if self.roots.iter().any(|root| subdir.starts_with(root)) {
            return true;
        }
        let Some(dir) = subdir.parent() else {
            return false;
        };
        // The walk is depth-first: what is not above `dir` has been left.
        while self
            .inside
            .last()
            .is_some_and(|(above, _)| !dir.starts_with(above))
        {
            self.inside.pop();
        }
        if let Some((_, root)) = self.inside.last().filter(|(above, _)| above == dir) {
            return *root;
        }
        let root = is_tree_root(classifier, dir);
        if root {
            self.note(dir.to_path_buf());
        }
        self.inside.push((dir.to_path_buf(), root));
        root
    }
}

/// `path` relative to `dir`, `/`-separated. `None` for a path outside
/// `dir` and for one that is not UTF-8, which names no root a `/`-joined
/// list can hold.
fn relative_slashed(dir: &Path, path: &Path) -> Option<String> {
    let rel = path.strip_prefix(dir).ok()?;
    let segments: Option<Vec<&str>> = rel.iter().map(OsStr::to_str).collect();
    Some(segments?.join("/"))
}

/// How many directory entries [`roots_below`] reads before it gives up.
/// Installed trees and ignored output are never entered, so this is far
/// above any repository's source tree, and a bound on a directory that is
/// not one.
const MAX_WALKED_ENTRIES: usize = 500_000;

/// The marker files at and below `dir`.
///
/// The in-memory engine is handed the files git tracks. On disk the walk
/// stands in for that list: it honours git's ignore rules (a build
/// directory's copy of a lockfile is not a project) and no other tool's
/// (a `.ignore` file hides files from search tools, not from git), never
/// enters an [`EXCLUDED_ROOT_SEGMENTS`] directory, never follows a link,
/// and never enters another repository: a directory below `dir` holding a
/// `.git` entry is a submodule or a nested clone, whose files this
/// repository does not track and whose own policy a run from here has not
/// read. A marker that is itself a symlink still counts, as it does for
/// the root the user names.
///
/// Nor does it enter a tree Bazel owns ([`BazelTreesMet`]): nothing below
/// the root of one is read, and what the root itself holds is dropped.
fn marker_paths_below(dir: &Path) -> WalkedMarkers {
    let classifier = Arc::new(Classifier::new());
    let met: Arc<Mutex<BazelTreesMet>> = Arc::default();
    let (judge, entered) = (Arc::clone(&classifier), Arc::clone(&met));
    let walk = ignore::WalkBuilder::new(dir)
        .hidden(false)
        .ignore(false)
        .follow_links(false)
        .filter_entry(move |entry| {
            if !entry.file_type().is_some_and(|t| t.is_dir()) {
                return true;
            }
            let excluded = entry
                .file_name()
                .to_str()
                .is_some_and(|name| EXCLUDED_ROOT_SEGMENTS.contains(&name));
            let other_repository =
                entry.depth() > 0 && entry.path().join(".git").symlink_metadata().is_ok();
            if excluded || other_repository {
                return false;
            }
            // The walked directory itself is the caller's to judge.
            let mut entered = entered.lock().unwrap_or_else(PoisonError::into_inner);
            entry.depth() == 0 || !entered.keeps_out_of(&judge, entry.path())
        })
        .build();
    let mut found = WalkedMarkers::default();
    for (seen, entry) in walk.flatten().enumerate() {
        if seen >= MAX_WALKED_ENTRIES {
            found.truncated = true;
            break;
        }
        found.walked = seen + 1;
        if entry.file_type().is_none_or(|t| t.is_dir()) {
            continue;
        }
        let marked = entry
            .path()
            .parent()
            .and_then(|parent| output_tree::marked_dir(parent, entry.file_name()));
        if let Some(marked) = marked.filter(|marked| is_tree_root(&classifier, marked)) {
            met.lock()
                .unwrap_or_else(PoisonError::into_inner)
                .note(marked);
        }
        let is_marker = entry
            .file_name()
            .to_str()
            .is_some_and(|base| marker_ecosystem(base).is_some());
        if is_marker {
            found.markers.extend(relative_slashed(dir, entry.path()));
        }
    }
    let met = met.lock().unwrap_or_else(PoisonError::into_inner);
    let trees = met
        .roots
        .iter()
        .filter_map(|tree| relative_slashed(dir, tree));
    found.bazel_trees = trees.collect::<BTreeSet<String>>().into_iter().collect();
    let in_tree = |marker: &String| {
        let (parent, _) = split_path(marker);
        found
            .bazel_trees
            .iter()
            .any(|tree| at_or_below(parent, tree))
    };
    found.markers.retain(|marker| !in_tree(marker));
    found
}

/// The project roots at and below `dir` on disk, so a disk scan and the
/// in-memory engine agree on what a checkout's projects are:
/// [`detect_roots`] over the marker files a walk finds
/// ([`marker_paths_below`]), less the workspace members whose lock another
/// root's run reads.
///
/// The engine takes such a lock away from the member and keeps the member
/// as a root when it holds another one. A disk run cannot be handed a
/// directory without one of its files, so here a member is left out when
/// that lock is all that made it a root, and stays (to be handled as a run
/// from a member directory is) when it holds another. The two cases are the
/// engine's: a Cargo workspace member's `Cargo.lock`, which cargo ignores,
/// and a pnpm workspace member's `pnpm-lock.yaml` that the workspace root
/// accounts for. `admitted(root)` says whether a root will be scanned at
/// all: a lock is only left to a root that is.
pub async fn roots_below(
    dir: &std::path::Path,
    ecosystems: Option<&[String]>,
    admitted: impl Fn(&str) -> bool,
) -> DiskRoots {
    use crate::vendor::lock_inventory::ProjectView;
    let walked = dir.to_path_buf();
    let WalkedMarkers {
        markers,
        truncated,
        bazel_trees,
        walked: _,
    } = tokio::task::spawn_blocking(move || marker_paths_below(&walked))
        .await
        .unwrap_or_default();
    let (mut roots, _) = detect_roots(markers.iter().map(String::as_str), ecosystems);
    let dir_of = |root: &str| {
        if root.is_empty() {
            dir.to_path_buf()
        } else {
            dir.join(root)
        }
    };
    // Whether `base` is the only kind of marker that makes `root` a root.
    let only_marker = |root: &str, bases: &[&str]| {
        !markers.iter().any(|path| {
            let (parent, base) = split_path(path);
            parent == root
                && !bases.contains(&base)
                && marker_ecosystem(base).is_some_and(|eco| allowed(ecosystems, eco))
        })
    };
    let mut dropped: BTreeSet<String> = BTreeSet::new();
    let mut governs_members = false;

    if allowed(ecosystems, "cargo") {
        for workspace in roots.iter().filter(|root| admitted(root)) {
            let has_lock = markers
                .iter()
                .any(|path| *path == join_root(workspace, "Cargo.lock"));
            if !has_lock {
                continue;
            }
            for manifest in crate::utils::cargo_workspace::member_manifests(&dir_of(workspace)) {
                let Some(member) = manifest.strip_suffix("/Cargo.toml") else {
                    continue;
                };
                let member = join_root(workspace, member);
                if roots.contains(&member) && only_marker(&member, &["Cargo.lock"]) {
                    dropped.insert(member);
                }
            }
        }
    }

    let has = |rel: &str| dir.join(rel).is_file();
    for (member, workspace) in pnpm_member_candidates(&roots, has, ecosystems) {
        // The walked directory is scanned whenever it governs a member.
        let scanned = workspace.is_empty() || roots.contains(&workspace);
        if !scanned || !admitted(&workspace) || !only_marker(&member, &["pnpm-lock.yaml"]) {
            continue;
        }
        let Some(rel) = strip_root(&workspace, &member) else {
            continue;
        };
        let root = dir_of(&workspace);
        let view = ProjectView::Disk(&root);
        if crate::utils::pnpm_workspace::root_accounts_for_member_lock(&view, rel).await {
            governs_members |= workspace.is_empty();
            dropped.insert(member);
        }
    }

    roots.retain(|root| !dropped.contains(root));
    DiskRoots {
        roots,
        governs_members,
        truncated,
        bazel_trees,
    }
}

/// The candidate workspace members among the pnpm `roots` (#492): a root
/// holding a `pnpm-lock.yaml` and no `pnpm-workspace.yaml` of its own, with
/// a `pnpm-workspace.yaml` in a strict ancestor, paired with the nearest
/// such file's directory (pnpm never looks past it). Empty when the
/// `ecosystems` filter leaves npm out.
///
/// Decided from paths alone, so a candidate is only that: the engine reads
/// the workspace root's files to confirm that root pins (or knowingly
/// ignores) the member's lock
/// ([`root_accounts_for_member_lock`](crate::utils::pnpm_workspace::root_accounts_for_member_lock))
/// before it demotes the lock into it, the way a Cargo member's lock is.
/// Path selection, which has no content yet, fetches the workspace root of
/// every candidate.
pub(crate) fn pnpm_member_candidates(
    roots: &[String],
    has: impl Fn(&str) -> bool,
    ecosystems: Option<&[String]>,
) -> Vec<(String, String)> {
    use crate::utils::pnpm_workspace::PNPM_WORKSPACE;
    let mut out = Vec::new();
    if !allowed(ecosystems, "npm") {
        return out;
    }
    for root in roots {
        if root.is_empty()
            || !has(&join_root(root, "pnpm-lock.yaml"))
            || has(&join_root(root, PNPM_WORKSPACE))
        {
            continue;
        }
        let mut dir = root.as_str();
        while !dir.is_empty() {
            dir = split_path(dir).0;
            if has(&join_root(dir, PNPM_WORKSPACE)) {
                out.push((root.clone(), dir.to_string()));
                break;
            }
        }
    }
    out
}

/// Whether `root` holds a root marker of an `ecosystems` ecosystem besides
/// its `pnpm-lock.yaml`: a pnpm member demoted into its workspace root
/// ([`pnpm_member_candidates`]) stays a root of its own only then.
pub(crate) fn has_other_root_marker<'a>(
    root: &str,
    paths: impl IntoIterator<Item = &'a str>,
    ecosystems: Option<&[String]>,
) -> bool {
    paths.into_iter().any(|path| {
        let (dir, base) = split_path(path);
        dir == root
            && base != "pnpm-lock.yaml"
            && marker_ecosystem(base).is_some_and(|eco| allowed(ecosystems, eco))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pnpm_member_candidates_sit_below_the_nearest_workspace_file() {
        let paths: BTreeSet<&str> = [
            "pnpm-workspace.yaml",
            "pnpm-lock.yaml",
            "packages/a/pnpm-lock.yaml",
            "packages/b/pnpm-lock.yaml",
            "packages/b/pnpm-workspace.yaml",
            "tools/c/pnpm-lock.yaml",
            "nested/pnpm-workspace.yaml",
            "nested/x/pnpm-lock.yaml",
        ]
        .into_iter()
        .collect();
        let roots: Vec<String> = ["", "nested/x", "packages/a", "packages/b", "tools/c"]
            .iter()
            .map(|r| r.to_string())
            .collect();
        let has = |p: &str| paths.contains(p);
        assert_eq!(
            pnpm_member_candidates(&roots, has, None),
            [
                ("nested/x".to_string(), "nested".to_string()),
                ("packages/a".to_string(), String::new()),
                ("tools/c".to_string(), String::new()),
            ],
            "b has its own file and the repo root is no member; x's nearest file is nested's"
        );
        let cargo_only = ["cargo".to_string()];
        assert!(pnpm_member_candidates(&roots, has, Some(&cargo_only)).is_empty());
        let npm = ["npm".to_string()];
        assert_eq!(pnpm_member_candidates(&roots, has, Some(&npm)).len(), 3);
    }

    #[test]
    fn other_root_markers_are_scoped_to_the_member_directory() {
        let paths = [
            "packages/a/pnpm-lock.yaml",
            "packages/a/package.json",
            "packages/a/sub/package-lock.json",
            "packages/ab/Cargo.lock",
            "packages/package-lock.json",
            "Cargo.lock",
        ];
        assert!(
            !has_other_root_marker("packages/a", paths, None),
            "markers in a parent, a sibling or a subdirectory are not the member's"
        );
        let mut own = paths.to_vec();
        own.push("packages/a/yarn.lock");
        assert!(has_other_root_marker(
            "packages/a",
            own.iter().copied(),
            None
        ));
        let cargo = ["cargo".to_string()];
        assert!(!has_other_root_marker(
            "packages/a",
            own.iter().copied(),
            Some(&cargo)
        ));
        own.push("packages/a/Cargo.lock");
        assert!(has_other_root_marker(
            "packages/a",
            own.iter().copied(),
            Some(&cargo)
        ));
    }

    /// The disk walk finds the roots the path-list detection finds for
    /// the same tree: lockfile directories at any depth, never a manifest
    /// alone, never inside an installed, vendored or git-ignored tree.
    #[tokio::test]
    async fn roots_below_walks_a_checkout_like_the_tracked_file_list() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let write = |rel: &str, text: &str| {
            let path = root.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        };
        // A repository, so the ignore files apply.
        std::fs::create_dir(root.join(".git")).unwrap();
        write(".gitignore", "dist/\n");
        for rel in [
            "web/package-lock.json",
            "web/package.json",
            "api/requirements.txt",
            "services/billing/go.mod",
            "services/billing/go.sum",
            "tools/only-manifest/package.json",
            "web/node_modules/dep/package-lock.json",
            "vendor/thing/Cargo.lock",
            ".socket/vendor/npm/x/package-lock.json",
            "dist/package-lock.json",
            ".config/tool/yarn.lock",
        ] {
            write(rel, "x");
        }
        let all = |_: &str| true;

        let found = roots_below(root, None, all).await;
        assert!(!found.truncated && !found.governs_members);
        assert_eq!(
            found.roots,
            [".config/tool", "api", "services/billing", "web"]
        );

        let only_npm = vec!["npm".to_string()];
        assert_eq!(
            roots_below(root, Some(&only_npm), all).await.roots,
            [".config/tool", "web"]
        );
        // The walked directory itself is the root `""`.
        assert_eq!(roots_below(&root.join("web"), None, all).await.roots, [""]);
        assert_eq!(
            roots_below(&root.join("tools"), None, all).await.roots,
            [""; 0]
        );
    }

    /// A workspace member whose lock the workspace root's run reads is not
    /// a project of its own: a Cargo member's stray `Cargo.lock`, and a
    /// pnpm member's lock under `sharedWorkspaceLockfile: false`. A member
    /// holding another lock stays, and so does every member when the
    /// workspace root is not going to be scanned.
    /// A submodule or nested clone is another repository, and a `.ignore`
    /// file is not one of git's: neither changes what this repository's
    /// projects are.
    #[tokio::test]
    async fn roots_below_stays_in_this_repository_and_reads_only_gits_ignores() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let put = |rel: &str, text: &str| {
            let path = root.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        };
        std::fs::create_dir(root.join(".git")).unwrap();
        put("web/package-lock.json", "{}");
        // A submodule (a `.git` file) and a nested clone (a `.git` dir).
        put("third_party/lib/.git", "gitdir: ../../.git/modules/lib\n");
        put("third_party/lib/package-lock.json", "{}");
        std::fs::create_dir_all(root.join("vendor/clone/.git")).unwrap();
        put("vendor/clone/sub/yarn.lock", "");
        // Hidden from search tools, tracked by git.
        put(".ignore", "*.lock\npackage-lock.json\n");
        put("svc/Cargo.lock", "");
        let found = roots_below(root, None, |_| true).await;
        assert_eq!(found.roots, vec!["svc".to_string(), "web".to_string()]);
        assert!(!found.truncated);
    }

    #[tokio::test]
    async fn roots_below_leaves_member_locks_to_the_workspace_root() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let write = |rel: &str, text: &str| {
            let path = root.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        };
        write("rust/Cargo.toml", "[workspace]\nmembers = [\"crates/*\"]\n");
        write("rust/Cargo.lock", "version = 3\n");
        for member in ["a", "b"] {
            write(
                &format!("rust/crates/{member}/Cargo.toml"),
                &format!("[package]\nname = \"{member}\"\nversion = \"0.1.0\"\n"),
            );
            write(&format!("rust/crates/{member}/Cargo.lock"), "version = 3\n");
        }
        write("rust/crates/b/package-lock.json", "{}");
        write("rust/outside/Cargo.lock", "version = 3\n");

        write(
            "pnpm-workspace.yaml",
            "packages:\n  - packages/*\nsharedWorkspaceLockfile: false\n",
        );
        write("package.json", "{\"name\": \"ws\"}");
        for member in ["x", "y"] {
            write(
                &format!("packages/{member}/package.json"),
                &format!("{{\"name\": \"{member}\"}}"),
            );
            write(
                &format!("packages/{member}/pnpm-lock.yaml"),
                "lockfileVersion: '9.0'\n",
            );
        }
        write("unlisted/pnpm-lock.yaml", "lockfileVersion: '9.0'\n");

        let found = roots_below(root, None, |_| true).await;
        assert_eq!(
            found.roots,
            ["rust", "rust/crates/b", "rust/outside", "unlisted"]
        );
        assert!(found.governs_members, "the pnpm members are the root's");

        let found = roots_below(root, None, |root| !root.is_empty() && root != "rust").await;
        assert_eq!(
            found.roots,
            [
                "packages/x",
                "packages/y",
                "rust",
                "rust/crates/a",
                "rust/crates/b",
                "rust/outside",
                "unlisted"
            ],
            "a workspace root that is not scanned takes no member's lock"
        );
        assert!(!found.governs_members);
    }

    fn roots(paths: &[&str]) -> Vec<String> {
        detect_roots(paths.iter().copied(), None).0
    }

    #[test]
    fn lock_markers_make_roots_and_manifests_do_not() {
        assert_eq!(
            roots(&[
                "package-lock.json",
                "apps/web/pnpm-lock.yaml",
                "libs/a/package.json",
                "svc/Cargo.toml",
                "py/tool.py.lock",
                "py2/pylock.toml"
            ]),
            vec!["", "apps/web", "py", "py2"]
        );
    }

    #[test]
    fn excluded_trees_never_hold_a_root() {
        let (found, ignored) = detect_roots(
            [
                "node_modules/x/package-lock.json",
                "test/fixtures/yarn.lock",
                "a/vendor/b/composer.lock",
                ".socket/vendor/npm/package-lock.json",
                "docs/requirements.txt",
            ],
            None,
        );
        // Test and fixture trees are left to the socket.yml path policy.
        assert_eq!(found, vec!["docs", "test/fixtures"]);
        assert_eq!(ignored.len(), 3);
        assert!(ignored.iter().all(|i| i.reason == "excluded_dir"));
    }

    /// HZ-24: the manifests socket-cli generates describe the project
    /// above them, at any depth.
    #[test]
    fn socket_cli_generated_manifests_never_make_a_root() {
        let (found, ignored) = detect_roots(
            [
                "build.gradle",
                ".socket-auto-manifest/pom.xml",
                ".socket-auto-manifest/requirements.txt",
                "svc/.socket-auto-manifest/app/requirements.txt",
                "svc/go.mod",
            ],
            None,
        );
        assert_eq!(found, vec!["svc"]);
        let ignored: Vec<(&str, &str)> = ignored
            .iter()
            .map(|i| (i.path.as_str(), i.reason.as_str()))
            .collect();
        let generated = [
            ".socket-auto-manifest/requirements.txt",
            "svc/.socket-auto-manifest/app/requirements.txt",
        ];
        assert_eq!(ignored, generated.map(|path| (path, "excluded_dir")));
    }

    /// The trees of [`BAZEL_LAYOUT`]: an output base kept in the checkout
    /// (probe C8), a vendor directory as Bazel 7.3 and later mark it and
    /// one as 7.1.2 to 7.2.1 do (probe C11), an entry of a contents cache
    /// under an in-tree output root (probe C6), and a base two levels down.
    const BAZEL_TREES: [&str; 5] = [
        "_bazel_u/cache/repos/v1/contents/cd12/26ed",
        "apps/web/out",
        "out",
        "third_party",
        "vendor_src",
    ];

    /// A Bazel workspace with those trees, each holding lockfiles, beside
    /// two projects of its own and two directories that only look like a
    /// tree: a marker name with nothing of a base beside it, and a
    /// directory named like a convenience link.
    const BAZEL_LAYOUT: [&str; 22] = [
        "MODULE.bazel",
        "pnpm-lock.yaml",
        "apps/web/package-lock.json",
        "out/DO_NOT_BUILD_HERE",
        "out/execroot/_main/pnpm-lock.yaml",
        "out/external/rules_nodejs~/yarn.lock",
        "out/external/rules_python~/gazelle/go.mod",
        "apps/web/out/DO_NOT_BUILD_HERE",
        "apps/web/out/external/aspect_rules_js~/e2e/pnpm-lock.yaml",
        "vendor_src/VENDOR.bazel",
        "vendor_src/+http_archive+dep/package-lock.json",
        "vendor_src/+http_archive+dep/sub/Cargo.lock",
        "third_party/.vendorignore",
        "third_party/rules_x~/go.mod",
        "_bazel_u/cache/repos/v1/contents/cd12/26ed.recorded_inputs",
        "_bazel_u/cache/repos/v1/contents/cd12/26ed/yarn.lock",
        "_bazel_u/cache/repos/v1/contents/cd12/7220/yarn.lock",
        "notes/DO_NOT_BUILD_HERE",
        "notes/requirements.txt",
        "bazel-notes/go.mod",
        "bazel-notes/go.sum",
        "docs/file",
    ];

    /// What is left: the workspace's own projects, the two look-alikes
    /// and the cache entry no marker names.
    const BAZEL_ROOTS: [&str; 5] = [
        "",
        "_bazel_u/cache/repos/v1/contents/cd12/7220",
        "apps/web",
        "bazel-notes",
        "notes",
    ];

    /// HZ-02 and HZ-03 in a path list: a lockfile inside a tree Bazel owns
    /// makes no root, and each one is reported with the code a disk run
    /// reports the directory under.
    #[test]
    fn nothing_in_a_listed_bazel_tree_is_a_root() {
        let (found, ignored) = detect_roots(BAZEL_LAYOUT, None);
        assert_eq!(found, BAZEL_ROOTS);
        let skipped: Vec<&str> = ignored.iter().map(|i| i.path.as_str()).collect();
        assert_eq!(
            skipped,
            [
                "_bazel_u/cache/repos/v1/contents/cd12/26ed/yarn.lock",
                "apps/web/out/external/aspect_rules_js~/e2e/pnpm-lock.yaml",
                "out/execroot/_main/pnpm-lock.yaml",
                "out/external/rules_nodejs~/yarn.lock",
                "out/external/rules_python~/gazelle/go.mod",
                "third_party/rules_x~/go.mod",
                "vendor_src/+http_archive+dep/package-lock.json",
                "vendor_src/+http_archive+dep/sub/Cargo.lock",
            ]
        );
        let code = Code::WorkspaceOutputTreeSkipped.as_str();
        assert!(ignored.iter().all(|i| i.reason == code), "{ignored:?}");
        assert_eq!(bazel_trees_listed(BAZEL_LAYOUT.into_iter()), BAZEL_TREES);

        // A list of lockfiles alone names no marker, so it prunes nothing
        // (and costs one pass over the names): this is what the disk walk
        // hands over after it has pruned.
        let locks = BAZEL_LAYOUT
            .into_iter()
            .filter(|path| marker_ecosystem(split_path(path).1).is_some());
        assert_eq!(bazel_trees_listed(locks.clone()), [""; 0]);
        assert_eq!(detect_roots(locks, None).1.len(), 0);

        // A vendor directory at the listing's root: the list is one tree.
        let (found, ignored) = detect_roots(["VENDOR.bazel", "+x+y/go.mod", "go.mod"], None);
        assert_eq!((found.len(), ignored.len()), (0, 2));
    }

    /// The same workspace on disk: the walk does not enter the trees, and
    /// says which directories it left out.
    #[tokio::test]
    async fn roots_below_does_not_enter_a_bazel_tree() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        for rel in BAZEL_LAYOUT {
            let path = root.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, "x").unwrap();
        }
        let found = roots_below(root, None, |_| true).await;
        assert_eq!(found.roots, BAZEL_ROOTS);
        assert_eq!(found.bazel_trees, BAZEL_TREES);
        assert!(!found.truncated);

        // Walked from inside the workspace, the trees are named from there.
        let web = roots_below(&root.join("apps/web"), None, |_| true).await;
        assert_eq!(
            (web.roots, web.bazel_trees),
            (vec![String::new()], vec!["out".to_string()])
        );

        // A walk that starts at a tree finds nothing in it.
        let base = roots_below(&root.join("out"), None, |_| true).await;
        assert_eq!(
            (base.roots, base.bazel_trees),
            (vec![], vec![String::new()])
        );

        // The marker gone, the directory is searched like any other.
        std::fs::remove_file(root.join("vendor_src/VENDOR.bazel")).unwrap();
        let found = roots_below(root, None, |_| true).await;
        assert!(found
            .roots
            .contains(&"vendor_src/+http_archive+dep".to_string()));
        assert!(!found.bazel_trees.contains(&"vendor_src".to_string()));
    }

    /// A tree is not entered, which is more than dropping what was found
    /// in it: an output base can hold more entries than the whole walk may
    /// read ([`MAX_WALKED_ENTRIES`]), and the projects after it would then
    /// be missed.
    #[test]
    fn the_walk_reads_nothing_below_a_bazel_marker() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let mut files = vec!["out/DO_NOT_BUILD_HERE".to_string(), "web/yarn.lock".into()];
        files.extend((0..30).map(|i| format!("out/external/rules_{i}/e2e/yarn.lock")));
        for rel in &files {
            let path = root.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, "x").unwrap();
        }
        // The walked directory, `out`, its marker, `web` and its lock.
        let pruned = marker_paths_below(root);
        assert_eq!(
            (pruned.walked, pruned.markers),
            (5, vec!["web/yarn.lock".to_string()])
        );
        std::fs::remove_file(root.join("out/DO_NOT_BUILD_HERE")).unwrap();
        let entered = marker_paths_below(root);
        assert_eq!((entered.walked, entered.markers.len()), (5 + 3 * 30, 31));
    }

    /// A build leaves links into its output base in the workspace. The
    /// walk follows no link, so they need no marker to stay out.
    #[cfg(unix)]
    #[tokio::test]
    async fn roots_below_follows_no_link_into_an_output_base() {
        let tmp = tempfile::tempdir().unwrap();
        let (ws, base) = (tmp.path().join("ws"), tmp.path().join("base"));
        let bin = base.join("execroot/_main/bazel-out/k8/bin");
        for file in [
            ws.join("pnpm-lock.yaml"),
            base.join("DO_NOT_BUILD_HERE"),
            bin.join("app/package-lock.json"),
        ] {
            std::fs::create_dir_all(file.parent().unwrap()).unwrap();
            std::fs::write(file, "x").unwrap();
        }
        std::fs::create_dir(ws.join("dist")).unwrap();
        std::os::unix::fs::symlink(&bin, ws.join("bazel-bin")).unwrap();
        std::os::unix::fs::symlink(&bin, ws.join("dist/bin")).unwrap();
        let found = roots_below(&ws, None, |_| true).await;
        assert_eq!(
            (found.roots, found.bazel_trees),
            (vec![String::new()], vec![])
        );
    }

    #[test]
    fn root_markers_name_every_marker_of_the_root_only() {
        assert_eq!(
            root_markers(
                "a",
                [
                    "a/yarn.lock",
                    "a/package.json",
                    "a/b/yarn.lock",
                    "a/pom.xml"
                ]
            ),
            vec!["pom.xml".to_string(), "yarn.lock".to_string()]
        );
    }

    #[test]
    fn rush_internals_are_not_roots_but_nested_cargo_locks_are() {
        assert_eq!(
            roots(&[
                "rush.json",
                "common/config/rush/pnpm-lock.yaml",
                "common/config/subspaces/web/pnpm-lock.yaml",
                "ws/Cargo.lock",
                "ws/crates/a/Cargo.lock",
                "ws/crates/b/Cargo.lock",
                "ws/crates/b/package-lock.json",
            ]),
            vec!["", "ws", "ws/crates/a", "ws/crates/b"]
        );
    }

    #[test]
    fn ecosystem_filter_limits_markers() {
        let only_npm = vec!["npm".to_string()];
        let (found, ignored) =
            detect_roots(["a/package-lock.json", "b/Cargo.lock"], Some(&only_npm));
        assert_eq!(found, vec!["a"]);
        assert_eq!(ignored[0].reason, "ecosystem_filtered");
    }

    #[test]
    fn strict_ancestors_walk_up_to_the_repo_root() {
        assert_eq!(strict_ancestors("").count(), 0);
        assert_eq!(strict_ancestors("web").collect::<Vec<_>>(), vec![""]);
        assert_eq!(
            strict_ancestors("apps/web/ui").collect::<Vec<_>>(),
            vec!["apps/web", "apps", ""]
        );
    }
}
