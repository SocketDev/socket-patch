//! The manifests of a cargo workspace beside its root `Cargo.toml`: every
//! `[workspace] members` glob (minus `exclude`) plus every path dependency
//! reachable from them, as repo-relative `<dir>/Cargo.toml` keys.
//!
//! The hosted cargo rewriter pins a patched crate in EVERY manifest that
//! declares it — a member's own `cfg-if = "1"` resolves exactly like the
//! root's, so leaving it unpinned makes the repointed Cargo.lock entry
//! unsatisfiable. Only manifests inside the project root, reached without
//! crossing a symbolic link, are returned: a file outside the root is not
//! the project's to rewrite, and a link may lead outside it (the writer
//! would follow it). Cargo still reads those manifests; the rewriter's
//! Cargo.lock dependents check refuses a crate one of them depends on.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::Path;
use std::sync::Arc;

use futures_util::StreamExt;
use toml_edit::{DocumentMut, Item, Table};

use crate::utils::workspace_globs::{bazel_owned, segment_glob_matches, BazelRoots};
use crate::vendor::lock_inventory::view::{MemoryProject, ProjectView};
use crate::vendor::parse_memo::ParseMemo;

/// Upper bound on discovered manifests — a runaway glob (or a hostile tree)
/// must not turn one scan into an unbounded walk.
pub(crate) const MAX_MANIFESTS: usize = 4096;

/// Repo-relative `<dir>/Cargo.toml` keys of the workspace members and
/// in-root path dependencies of the project at `root`, sorted. Empty when
/// `root/Cargo.toml` is absent or unparseable.
pub fn member_manifests(root: &Path) -> Vec<String> {
    member_manifests_with(&DiskTree(root))
}

/// [`member_manifests`] of an in-memory project: the manifests the host
/// supplied, member globs expanded against the supplied paths (a directory
/// exists when some supplied path lives under it; symbolic links are never
/// directories).
pub fn member_manifests_in_memory(project: &MemoryProject) -> Vec<String> {
    member_manifests_with(&MemoryTree(project))
}

/// [`member_manifests`] over a [`ProjectView`], every read, probe and
/// listing going through the view: a snapshot's overlays and content cache
/// apply and its recording notes the walk; in memory it reads the supplied
/// files. The manifests are read concurrently (bounded).
pub async fn member_manifests_in(view: &ProjectView<'_>) -> Vec<String> {
    member_manifest_texts_in(view)
        .await
        .into_iter()
        .map(|(rel, _)| rel)
        .collect()
}

/// In-flight manifest reads of one [`member_manifest_texts_in`] level.
const MEMBER_READ_CONCURRENCY: usize = 16;

/// [`member_manifests_in`], each key with the text the walk read through
/// the view (so a caller need not read it again).
pub(crate) async fn member_manifest_texts_in(view: &ProjectView<'_>) -> Vec<(String, String)> {
    let Some((facts, _)) = view_manifest(view, "Cargo.toml").await else {
        return Vec::new();
    };
    let mut frontier: Vec<String> = Vec::new();
    if let Some((members, exclude)) = &facts.workspace {
        let mut excluded: BTreeSet<String> = BTreeSet::new();
        for pattern in exclude {
            excluded.extend(expand_glob_in(view, pattern, CARGO_SKIP).await);
        }
        for pattern in members {
            for dir in expand_glob_in(view, pattern, CARGO_SKIP).await {
                if !excluded.contains(&dir) {
                    frontier.push(dir);
                }
            }
        }
    }
    frontier.extend(
        facts
            .path_deps
            .iter()
            .filter_map(|dep| normalize_rel("", dep)),
    );
    let mut found: BTreeMap<String, String> = BTreeMap::new();
    let mut tried: BTreeSet<String> = BTreeSet::new();
    let mut bazel = BazelRoots::default();
    while !frontier.is_empty() {
        let mut level: Vec<String> = Vec::new();
        for dir in std::mem::take(&mut frontier) {
            if found.len() + level.len() >= MAX_MANIFESTS {
                break;
            }
            if !walkable(&dir) || tried.contains(&dir) {
                continue;
            }
            tried.insert(dir.clone());
            if every_segment(&dir, |at| view_is_real_dir(view, at))
                && !in_bazel_tree(view, &mut bazel, &dir)
            {
                level.push(dir);
            }
        }
        let read: Vec<(String, Option<ReadManifest>)> =
            crate::utils::concurrent::ordered_concurrent(
                level,
                MEMBER_READ_CONCURRENCY,
                |dir| async move {
                    let manifest = view_manifest(view, &format!("{dir}/Cargo.toml")).await;
                    (dir, manifest)
                },
            )
            .collect()
            .await;
        for (dir, manifest) in read {
            let Some((facts, text)) = manifest else {
                continue;
            };
            frontier.extend(
                facts
                    .path_deps
                    .iter()
                    .filter_map(|dep| normalize_rel(&dir, dep)),
            );
            found.insert(dir, text);
        }
    }
    found
        .into_iter()
        .map(|(dir, text)| (format!("{dir}/Cargo.toml"), text))
        .collect()
}

/// A manifest the view walk read: its walk facts and its text.
type ReadManifest = (Arc<ManifestFacts>, String);

/// A regular (non-symlink) manifest read through the view: its walk facts
/// and its text.
async fn view_manifest(view: &ProjectView<'_>, rel: &str) -> Option<ReadManifest> {
    if view.is_symlink(rel) {
        return None;
    }
    let text = view.read_text(rel).await.ok()?;
    let facts = FACTS_MEMO
        .parse(text.as_bytes(), || {
            text.parse::<DocumentMut>()
                .map(|doc| ManifestFacts::of(&doc))
        })
        .ok()?;
    Some((facts, text))
}

/// [`DirTree::is_real_dir`] through the view's own mediated probes (a
/// snapshot notes each and sees its overlays).
fn view_is_real_dir(view: &ProjectView<'_>, rel: &str) -> bool {
    view.is_dir(rel) && !view.is_symlink(rel)
}

/// [`expand_glob`] over a [`ProjectView`]: the same walk, listing through
/// the view's `list_dir` (a real directory's real sub-directories, as
/// [`DirTree::child_dirs`] answers).
async fn expand_glob_in(view: &ProjectView<'_>, pattern: &str, skip: &[&str]) -> Vec<String> {
    let Some(normalized) = normalize_rel("", pattern.trim_end_matches('/')) else {
        return Vec::new();
    };
    let segments = glob_segments(&normalized);
    let mut out = Vec::new();
    let mut walked = Walked::of(&segments);
    // [`expand_from`]'s recursion as an explicit stack, children pushed in
    // reverse so they are visited in the same order.
    let mut stack: Vec<(String, usize)> = vec![(String::new(), 0)];
    while let Some((at, i)) = stack.pop() {
        if out.len() >= MAX_MANIFESTS {
            break;
        }
        if !walked.first_visit(&at, segments.len() - i) {
            continue;
        }
        let Some(seg) = segments.get(i) else {
            out.push(at);
            continue;
        };
        if !segment_is_pattern(seg) {
            let next = join_rel(&at, seg);
            if view_is_real_dir(view, &next) {
                stack.push((next, i + 1));
            }
            continue;
        }
        let Ok(entries) = view.list_dir(&at).await else {
            continue;
        };
        let children = glob_children(
            entries.into_iter().filter(|e| e.is_dir).map(|e| e.name),
            seg,
            skip,
        );
        let mut next: Vec<(String, usize)> = Vec::new();
        if *seg == "**" {
            next.push((at.clone(), i + 1));
            next.extend(children.iter().map(|child| (join_rel(&at, child), i)));
        } else {
            let pattern = cargo_segment(seg);
            for child in &children {
                let name: Vec<char> = child.chars().collect();
                if segment_glob_matches(&pattern, &name) {
                    next.push((join_rel(&at, child), i + 1));
                }
            }
        }
        stack.extend(next.into_iter().rev());
    }
    out.sort();
    out.dedup();
    out
}

/// The two directory questions a glob walk asks, keyed by `/`-separated
/// root-relative paths (`""` is the root). Shared with the pnpm workspace
/// member walk ([`crate::utils::pnpm_workspace`]).
pub(crate) trait DirTree {
    /// A real directory (not a symbolic link).
    fn is_real_dir(&self, rel: &str) -> bool;
    /// The real sub-directory names of `rel`, or `None` when unreadable.
    fn child_dirs(&self, rel: &str) -> Option<Vec<String>>;
}

/// The member walk's questions: the directory ones plus a manifest read.
trait Tree: DirTree {
    /// A regular (non-symlink) manifest file's walk facts.
    fn read_manifest(&self, rel: &str) -> Option<Arc<ManifestFacts>>;
    /// The tree as a view, which is what the Bazel check reads through
    /// ([`in_bazel_tree`]).
    fn view(&self) -> ProjectView<'_>;
}

/// Whether the root-relative directory `dir` is one of Bazel's own trees
/// or lies inside one: an output base, a cache or a vendor directory in
/// the checkout, or a link into one (`workspace_globs::bazel_owned`).
///
/// Such a tree mirrors the workspace or holds what Bazel fetched: an
/// output base has the manifests of every external crate under
/// `external/`, and a vendor directory has them under its own name. A
/// `members` glob or a path dependency that reaches one names a manifest
/// that is Bazel's to write, and a hosted pin there would edit a file the
/// next build regenerates (ROUTED R-029). The same holds for a pnpm
/// workspace member (`pnpm_workspace`, ROUTED R-027).
///
/// Each directory on the way down to `dir` is asked, because the markers
/// are at a tree's root and say nothing from inside it. And only below a
/// Bazel boundary file, which `bazel` finds at a few `stat`s per
/// directory that holds members: in a project Bazel does not build no
/// candidate costs a marker test, and a directory that merely holds a
/// marker's name is a member like any other.
pub(crate) fn in_bazel_tree(view: &ProjectView<'_>, bazel: &mut BazelRoots, dir: &str) -> bool {
    let mut holder = String::new();
    for name in dir.split('/').filter(|name| !name.is_empty()) {
        let below_boundary = bazel.at(view, &holder, None);
        holder = join_rel(&holder, name);
        if below_boundary && bazel_owned(view, &holder, None) {
            return true;
        }
    }
    false
}

pub(crate) struct DiskTree<'a>(pub(crate) &'a Path);

impl Tree for DiskTree<'_> {
    fn read_manifest(&self, rel: &str) -> Option<Arc<ManifestFacts>> {
        read_manifest(&self.0.join(rel))
    }

    fn view(&self) -> ProjectView<'_> {
        ProjectView::Disk(self.0)
    }
}

impl DirTree for DiskTree<'_> {
    fn is_real_dir(&self, rel: &str) -> bool {
        is_real_dir(&self.0.join(rel))
    }

    fn child_dirs(&self, rel: &str) -> Option<Vec<String>> {
        let entries = std::fs::read_dir(self.0.join(rel)).ok()?;
        Some(
            entries
                .filter_map(Result::ok)
                .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
                .filter_map(|e| e.file_name().to_str().map(str::to_string))
                .collect(),
        )
    }
}

pub(crate) struct MemoryTree<'a>(pub(crate) &'a MemoryProject);

impl Tree for MemoryTree<'_> {
    fn read_manifest(&self, rel: &str) -> Option<Arc<ManifestFacts>> {
        let doc: DocumentMut = self.0.text(rel)?.parse().ok()?;
        Some(Arc::new(ManifestFacts::of(&doc)))
    }

    fn view(&self) -> ProjectView<'_> {
        ProjectView::Memory(self.0)
    }
}

impl DirTree for MemoryTree<'_> {
    fn is_real_dir(&self, rel: &str) -> bool {
        self.0.is_dir(rel)
    }

    fn child_dirs(&self, rel: &str) -> Option<Vec<String>> {
        self.0.is_dir(rel).then(|| {
            self.0
                .children(rel)
                .into_iter()
                .filter(|(_, is_dir)| *is_dir)
                .map(|(name, _)| name)
                .collect()
        })
    }
}

fn join_rel(base: &str, seg: &str) -> String {
    if base.is_empty() {
        seg.to_string()
    } else {
        format!("{base}/{seg}")
    }
}

fn member_manifests_with(tree: &dyn Tree) -> Vec<String> {
    let Some(facts) = tree.read_manifest("Cargo.toml") else {
        return Vec::new();
    };
    let mut dirs: BTreeSet<String> = BTreeSet::new();
    let mut queue: Vec<(String, Arc<ManifestFacts>)> = Vec::new();
    let (view, mut bazel) = (tree.view(), BazelRoots::default());
    let mut bazels = |dir: &str| in_bazel_tree(&view, &mut bazel, dir);

    if let Some((members, exclude)) = &facts.workspace {
        let excluded: BTreeSet<String> = exclude
            .iter()
            .flat_map(|p| expand_glob(tree, p, CARGO_SKIP))
            .collect();
        for pattern in members {
            for dir in expand_glob(tree, pattern, CARGO_SKIP) {
                if !excluded.contains(&dir) {
                    enqueue(tree, dir, &mut dirs, &mut queue, &mut bazels);
                }
            }
        }
    }
    for dep_dir in &facts.path_deps {
        if let Some(dir) = normalize_rel("", dep_dir) {
            enqueue(tree, dir, &mut dirs, &mut queue, &mut bazels);
        }
    }
    while let Some((dir, facts)) = queue.pop() {
        for dep_dir in &facts.path_deps {
            if let Some(dep) = normalize_rel(&dir, dep_dir) {
                enqueue(tree, dep, &mut dirs, &mut queue, &mut bazels);
            }
        }
    }
    dirs.into_iter()
        .map(|dir| format!("{dir}/Cargo.toml"))
        .collect()
}

/// What [`member_manifests`] reads out of one manifest: its `[workspace]`
/// `members` and `exclude` patterns (when it has a `[workspace]` table)
/// and its [`path_dependencies`].
struct ManifestFacts {
    workspace: Option<(Vec<String>, Vec<String>)>,
    path_deps: Vec<String>,
}

impl ManifestFacts {
    fn of(doc: &DocumentMut) -> Self {
        let workspace = doc
            .get("workspace")
            .and_then(Item::as_table_like)
            .map(|ws| {
                let patterns = |key: &str| -> Vec<String> {
                    ws.get(key)
                        .and_then(Item::as_array)
                        .map(|a| {
                            a.iter()
                                .filter_map(|v| v.as_str().map(str::to_string))
                                .collect()
                        })
                        .unwrap_or_default()
                };
                (patterns("members"), patterns("exclude"))
            });
        ManifestFacts {
            workspace,
            path_deps: path_dependencies(doc),
        }
    }
}

/// The manifests' facts, per manifest bytes. The vendored cargo backend
/// asks for the members once per patched crate, and once a project is
/// vendored every `[patch.crates-io]` path copy is a path dependency — so
/// each ask re-parsed every vendored crate's manifest, O(P²) parses over a
/// run. See [`ParseMemo`]: every manifest is still read on every ask, and
/// bytes that moved are parsed afresh. Enough slots for a large workspace
/// plus its vendored copies. Beyond them the oldest-inserted slot is
/// evicted, and since every walk visits the manifests in the same order,
/// a set larger than the slots misses on every read: each then pays the
/// parse PLUS the slot scan and the bytes copy, slightly more than an
/// unmemoized walk (answers stay correct either way).
static FACTS_MEMO: ParseMemo<ManifestFacts, 512> = ParseMemo::new();

fn read_manifest(path: &Path) -> Option<Arc<ManifestFacts>> {
    // A symlinked manifest is not followed; the read itself is the
    // non-blocking regular-file one, so a FIFO swapped in after the
    // `lstat` fails fast instead of wedging in open(2).
    if !std::fs::symlink_metadata(path).is_ok_and(|m| m.is_file()) {
        return None;
    }
    let text = crate::utils::fs::read_regular_to_string_sync(path).ok()?;
    FACTS_MEMO
        .parse(text.as_bytes(), || {
            text.parse::<DocumentMut>()
                .map(|doc| ManifestFacts::of(&doc))
        })
        .ok()
}

/// The pre-memo [`member_manifests`] (a full parse of every manifest per
/// call), kept as the equivalence oracle.
#[cfg(test)]
fn member_manifests_unmemoized(root: &Path) -> Vec<String> {
    struct UnmemoizedDiskTree<'a>(&'a Path);

    impl Tree for UnmemoizedDiskTree<'_> {
        fn read_manifest(&self, rel: &str) -> Option<Arc<ManifestFacts>> {
            let path = self.0.join(rel);
            if !std::fs::symlink_metadata(&path).is_ok_and(|m| m.is_file()) {
                return None;
            }
            let doc: DocumentMut = std::fs::read_to_string(path).ok()?.parse().ok()?;
            Some(Arc::new(ManifestFacts::of(&doc)))
        }

        fn view(&self) -> ProjectView<'_> {
            ProjectView::Disk(self.0)
        }
    }

    impl DirTree for UnmemoizedDiskTree<'_> {
        fn is_real_dir(&self, rel: &str) -> bool {
            DiskTree(self.0).is_real_dir(rel)
        }

        fn child_dirs(&self, rel: &str) -> Option<Vec<String>> {
            DiskTree(self.0).child_dirs(rel)
        }
    }

    member_manifests_with(&UnmemoizedDiskTree(root))
}

/// A directory that is not itself a symbolic link.
fn is_real_dir(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.is_dir())
}

/// Every component of repo-relative `dir` is a real directory under
/// the root — none is a symbolic link (which may lead outside the root).
pub(crate) fn is_real_dir_path(tree: &dyn DirTree, dir: &str) -> bool {
    every_segment(dir, |at| tree.is_real_dir(at))
}

/// Whether `real` holds for every ancestor-or-self prefix of `dir`.
fn every_segment(dir: &str, real: impl Fn(&str) -> bool) -> bool {
    let mut at = String::new();
    dir.split('/').all(|seg| {
        at = join_rel(&at, seg);
        real(&at)
    })
}

/// Whether the walk may enter `dir` at all. `target` is cargo's build
/// directory at every level: the glob walk already skips it, and a literal
/// `members = ["target/gen"]` or a path dependency into it names a manifest
/// the next `cargo clean` deletes — pinning it would record a hosted edit
/// whose file can vanish, blocking the rollback of every other cargo edit.
fn walkable(dir: &str) -> bool {
    !dir.is_empty() && !dir.split('/').any(|seg| seg == "target")
}

fn enqueue(
    tree: &dyn Tree,
    dir: String,
    dirs: &mut BTreeSet<String>,
    queue: &mut Vec<(String, Arc<ManifestFacts>)>,
    bazels: &mut dyn FnMut(&str) -> bool,
) {
    // Bazel's trees last: the test is asked only of a directory that
    // would otherwise be read.
    if !walkable(&dir)
        || dirs.len() >= MAX_MANIFESTS
        || dirs.contains(&dir)
        || !is_real_dir_path(tree, &dir)
        || bazels(&dir)
    {
        return;
    }
    let Some(facts) = tree.read_manifest(&format!("{dir}/Cargo.toml")) else {
        return;
    };
    dirs.insert(dir.clone());
    queue.push((dir, facts));
}

/// Every `path = "…"` of a dependency declaration: the dependency tables
/// (plain and per-target), `[workspace.dependencies]` and `[patch.*]`.
fn path_dependencies(doc: &DocumentMut) -> Vec<String> {
    fn dep_paths(table: Option<&Item>, out: &mut Vec<String>) {
        let Some(table) = table.and_then(Item::as_table_like) else {
            return;
        };
        for (_, entry) in table.iter() {
            let path = match entry {
                Item::Table(t) => t.get("path").and_then(Item::as_str),
                Item::Value(v) => v
                    .as_inline_table()
                    .and_then(|t| t.get("path"))
                    .and_then(|p| p.as_str()),
                _ => None,
            };
            if let Some(path) = path {
                out.push(path.to_string());
            }
        }
    }
    fn dep_tables(table: &Table, out: &mut Vec<String>) {
        for kind in ["dependencies", "dev-dependencies", "build-dependencies"] {
            dep_paths(table.get(kind), out);
        }
    }
    let mut out = Vec::new();
    dep_tables(doc.as_table(), &mut out);
    if let Some(targets) = doc.get("target").and_then(Item::as_table) {
        for (_, target) in targets.iter() {
            if let Some(target) = target.as_table() {
                dep_tables(target, &mut out);
            }
        }
    }
    if let Some(ws) = doc.get("workspace").and_then(Item::as_table) {
        dep_paths(ws.get("dependencies"), &mut out);
    }
    if let Some(patch) = doc.get("patch").and_then(Item::as_table) {
        for (_, source) in patch.iter() {
            dep_paths(Some(source), &mut out);
        }
    }
    out
}

/// `base/rel` lexically normalized to a repo-relative slash path; `None`
/// when it is absolute or climbs out of the root.
pub(crate) fn normalize_rel(base: &str, rel: &str) -> Option<String> {
    if crate::utils::relpath::is_anchored(rel) {
        return None;
    }
    crate::utils::relpath::resolve_rel(base, rel, 0)
}

/// The directory names a cargo glob never descends into: its build
/// directory.
const CARGO_SKIP: &[&str] = &["target"];

/// Expand a cargo `members` / `exclude` glob (`*`, `?`, `[..]` classes,
/// `**`) to the repo-relative directories it names. A wildcard segment
/// never matches a dot-directory (unless the segment itself starts with
/// `.`, as `.*` does) or a name in `skip`; a literal segment names any
/// real directory. A segment matches as `workspace_globs` reads one, so a
/// `[` that never closes is a literal character.
pub(crate) fn expand_glob(tree: &dyn DirTree, pattern: &str, skip: &[&str]) -> Vec<String> {
    expand_glob_bounded(tree, pattern, skip).0
}

/// [`expand_glob`], plus whether the walk stopped at [`MAX_MANIFESTS`]
/// before it was done, so a caller that must list every match can refuse
/// a truncated answer rather than act on part of it.
pub(crate) fn expand_glob_bounded(
    tree: &dyn DirTree,
    pattern: &str,
    skip: &[&str],
) -> (Vec<String>, bool) {
    let Some(normalized) = normalize_rel("", pattern.trim_end_matches('/')) else {
        return (Vec::new(), false);
    };
    let segments = glob_segments(&normalized);
    let mut out = Vec::new();
    let mut walked = Walked::of(&segments);
    expand_from(tree, String::new(), &segments, skip, &mut walked, &mut out);
    let truncated = out.len() >= MAX_MANIFESTS;
    out.sort();
    out.dedup();
    (out, truncated)
}

/// A normalized glob's segments as the walk reads them. A run of `**`
/// segments is one (`**/**` names what `**` names), so the walk nests as
/// deep as the directories go, not as long as the pattern is.
fn glob_segments(normalized: &str) -> Vec<&str> {
    let mut segments: Vec<&str> = normalized.split('/').filter(|s| !s.is_empty()).collect();
    segments.dedup_by(|next, kept| *next == "**" && *kept == "**");
    segments
}

/// The (directory, segments left) pairs a glob walk has been through. A
/// glob with two or more `**` reaches one directory along many routes, one
/// per way to split the levels above it between them, and their number
/// grows exponentially with the `**` count. The walk takes the first route
/// and drops the rest, which name the same directories.
struct Walked(Option<HashSet<(String, usize)>>);

impl Walked {
    fn of(segments: &[&str]) -> Self {
        // With one `**` or none every directory has a single route to it,
        // so there is nothing to remember.
        let globstars = segments.iter().filter(|seg| **seg == "**").count();
        Walked((globstars > 1).then(HashSet::new))
    }

    /// Whether this is the walk's first time at `at` with `left` segments
    /// to go.
    fn first_visit(&mut self, at: &str, left: usize) -> bool {
        self.0
            .as_mut()
            .is_none_or(|seen| seen.insert((at.to_string(), left)))
    }
}

/// Whether a `members` entry is a glob rather than a literal path: some
/// segment holds `*`, `?` or a `[..]` class that closes. A `[` that never
/// closes is not a class.
pub(crate) fn is_member_pattern(pattern: &str) -> bool {
    pattern.split('/').any(segment_is_pattern)
}

fn segment_is_pattern(seg: &str) -> bool {
    seg.contains(['*', '?'])
        // The first `[` decides: a `]` that closes a later one closes it
        // too. (Looking after each `[` reads a run of them once per `[`.)
        || seg.find('[').is_some_and(|at| {
            let body = &seg[at + 1..];
            let body = body.strip_prefix('!').unwrap_or(body);
            body.char_indices().skip(1).any(|(_, c)| c == ']')
        })
}

/// `seg` as [`segment_glob_matches`] should read it for cargo. Cargo's
/// `glob` crate negates a class only on `!`, so a `^` opening a class is a
/// member; the shared matcher also negates on `^`, so a NUL member (which
/// no directory name holds) goes ahead of it.
fn cargo_segment(seg: &str) -> Vec<char> {
    seg.replace("[^", "[\0^").chars().collect()
}

/// The sub-directories a wildcard segment `seg` may match, sorted: never a
/// dot-directory (unless `seg` itself starts with `.`) or a name in `skip`.
fn glob_children(
    entries: impl IntoIterator<Item = String>,
    seg: &str,
    skip: &[&str],
) -> Vec<String> {
    let mut children: Vec<String> = entries
        .into_iter()
        .filter(|name| {
            (!name.starts_with('.') || seg.starts_with('.')) && !skip.contains(&name.as_str())
        })
        .collect();
    children.sort();
    children
}

fn expand_from(
    tree: &dyn DirTree,
    at: String,
    rest: &[&str],
    skip: &[&str],
    walked: &mut Walked,
    out: &mut Vec<String>,
) {
    if out.len() >= MAX_MANIFESTS || !walked.first_visit(&at, rest.len()) {
        return;
    }
    let Some((seg, tail)) = rest.split_first() else {
        out.push(at);
        return;
    };
    if !segment_is_pattern(seg) {
        let next = join_rel(&at, seg);
        if tree.is_real_dir(&next) {
            expand_from(tree, next, tail, skip, walked, out);
        }
        return;
    }
    let Some(entries) = tree.child_dirs(&at) else {
        return;
    };
    let children = glob_children(entries, seg, skip);
    if *seg == "**" {
        expand_from(tree, at.clone(), tail, skip, walked, out);
        for child in children {
            expand_from(tree, join_rel(&at, &child), rest, skip, walked, out);
        }
        return;
    }
    let pattern = cargo_segment(seg);
    for child in children {
        let name: Vec<char> = child.chars().collect();
        if segment_glob_matches(&pattern, &name) {
            expand_from(tree, join_rel(&at, &child), tail, skip, walked, out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// B74: a FIFO at `Cargo.toml` reads as "no manifest" and returns at
    /// once (the lstat rejects it; the read behind it is the non-blocking
    /// regular-file one, so a FIFO swapped in after the lstat fails fast too).
    #[cfg(unix)]
    #[test]
    fn read_manifest_rejects_a_fifo_without_blocking() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("Cargo.toml");
        let c = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        assert!(read_manifest(&path).is_none());
    }

    fn write(root: &Path, rel: &str, content: &str) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
    }

    fn pkg(name: &str) -> String {
        format!("[package]\nname = \"{name}\"\nversion = \"0.1.0\"\n")
    }

    /// Over a tracked snapshot the walk reads through the view: its reads
    /// fill the content cache, so files written just now (racy by stat
    /// alone) — including a `.socket/` copy's manifest the walk follows
    /// through `[patch]` — still leave a read set that holds; a member
    /// added under a glob afterwards breaks it (the listing was recorded).
    #[tokio::test]
    async fn snapshot_walk_records_what_it_reads() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write(
            root,
            "Cargo.toml",
            "[workspace]\nmembers = [\"crates/*\"]\n\n\
             [patch.crates-io]\nserde = { path = \".socket/vendor/cargo/u1/serde-1.0.0\" }\n",
        );
        write(root, "crates/a/Cargo.toml", &pkg("a"));
        write(
            root,
            ".socket/vendor/cargo/u1/serde-1.0.0/Cargo.toml",
            &pkg("serde"),
        );
        let snap = crate::vendor::lock_inventory::DiskSnapshot::tracked(root);
        snap.begin_recording();
        let walked = member_manifests_in(&ProjectView::Snapshot(&snap)).await;
        assert_eq!(walked, member_manifests(root));
        assert!(walked.contains(&".socket/vendor/cargo/u1/serde-1.0.0/Cargo.toml".to_string()));
        let reads = snap.end_recording().expect("the walk keeps the recording");
        assert!(reads.unchanged(), "fresh files read through the view hold");
        write(root, "crates/b/Cargo.toml", &pkg("b"));
        assert!(!reads.unchanged(), "a new member dir changes the listing");
    }

    /// A snapshot's overlays are part of the walk: an overlaid member
    /// manifest (a pending write) is a member before it reaches the disk.
    #[tokio::test]
    async fn snapshot_walk_sees_overlays() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write(
            root,
            "Cargo.toml",
            "[workspace]\nmembers = [\"crates/*\"]\n",
        );
        write(root, "crates/a/Cargo.toml", &pkg("a"));
        let snap = crate::vendor::lock_inventory::DiskSnapshot::new(root);
        snap.overlay("crates/c/Cargo.toml", pkg("c").as_bytes());
        assert_eq!(
            member_manifests_in(&ProjectView::Snapshot(&snap)).await,
            vec!["crates/a/Cargo.toml", "crates/c/Cargo.toml"]
        );
        assert_eq!(member_manifests(root), vec!["crates/a/Cargo.toml"]);
    }

    /// The view walk answers exactly as the disk walk over every shape the
    /// memo test covers (globs, `**`, excludes, nested path dependencies,
    /// `[patch]` copies, unparseable manifests) plus a symlinked member
    /// directory, and returns the text it read for each.
    #[tokio::test]
    async fn view_walk_matches_the_disk_walk() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write(
            root,
            "Cargo.toml",
            "[workspace]\nmembers = [\"crates/*\", \"tools/**\", \"lit\"]\n\
             exclude = [\"crates/x\"]\n\
             [patch.crates-io]\nserde = { path = \".socket/vendor/cargo/u1/serde-1.0.0\" }\n\
             [workspace.dependencies]\nshared = { path = \"libs/shared\" }\n",
        );
        write(
            root,
            "crates/a/Cargo.toml",
            &format!("{}[dependencies.b]\npath = \"../b\"\n", pkg("a")),
        );
        write(root, "crates/b/Cargo.toml", &pkg("b"));
        write(root, "crates/x/Cargo.toml", &pkg("x"));
        write(root, "crates/.hidden/Cargo.toml", &pkg("hidden"));
        write(root, "crates/target/Cargo.toml", &pkg("target"));
        write(root, "crates/bad/Cargo.toml", "not = [toml");
        write(root, "tools/deep/t/Cargo.toml", &pkg("t"));
        write(root, "lit/Cargo.toml", &pkg("lit"));
        write(root, "libs/shared/Cargo.toml", &pkg("shared"));
        write(
            root,
            ".socket/vendor/cargo/u1/serde-1.0.0/Cargo.toml",
            &format!(
                "{}[dependencies]\nderive = {{ path = \"../derive\" }}\n",
                pkg("serde")
            ),
        );
        write(
            root,
            ".socket/vendor/cargo/u1/derive/Cargo.toml",
            &pkg("derive"),
        );
        #[cfg(unix)]
        {
            write(root, "elsewhere/l/Cargo.toml", &pkg("l"));
            std::os::unix::fs::symlink(root.join("elsewhere"), root.join("crates/link")).unwrap();
        }
        let disk = member_manifests(root);
        assert!(disk.contains(&"tools/deep/t/Cargo.toml".to_string()));
        assert!(!disk.iter().any(|k| k.starts_with("crates/link")));
        assert_eq!(member_manifests_in(&ProjectView::Disk(root)).await, disk);
        let snap = crate::vendor::lock_inventory::DiskSnapshot::new(root);
        assert_eq!(
            member_manifests_in(&ProjectView::Snapshot(&snap)).await,
            disk
        );
        for (rel, text) in member_manifest_texts_in(&ProjectView::Disk(root)).await {
            assert_eq!(
                text,
                std::fs::read_to_string(root.join(&rel)).unwrap(),
                "{rel}"
            );
        }
    }

    #[test]
    fn members_globs_excludes_and_path_dependencies() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write(
            root,
            "Cargo.toml",
            "[workspace]\nmembers = [\"app\", \"crates/*\"]\nexclude = [\"crates/skip\"]\n",
        );
        write(
            root,
            "app/Cargo.toml",
            &format!(
                "{}[dependencies]\nhelper = {{ path = \"../libs/helper\" }}\n",
                pkg("app")
            ),
        );
        write(root, "crates/a/Cargo.toml", &pkg("a"));
        write(root, "crates/skip/Cargo.toml", &pkg("skip"));
        write(root, "crates/no-manifest/README", "");
        write(
            root,
            "libs/helper/Cargo.toml",
            &format!(
                "{}[target.'cfg(unix)'.dependencies]\nleaf = {{ path = \"../leaf\" }}\n\
                 outside = {{ path = \"../../../elsewhere\" }}\n",
                pkg("helper")
            ),
        );
        write(root, "libs/leaf/Cargo.toml", &pkg("leaf"));
        assert_eq!(
            member_manifests(root),
            vec![
                "app/Cargo.toml",
                "crates/a/Cargo.toml",
                "libs/helper/Cargo.toml",
                "libs/leaf/Cargo.toml",
            ]
        );
    }

    #[test]
    fn a_package_without_workspace_still_reaches_its_path_dependencies() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write(
            root,
            "Cargo.toml",
            &format!("{}[dependencies.inner]\npath = \"inner\"\n", pkg("root")),
        );
        write(root, "inner/Cargo.toml", &pkg("inner"));
        assert_eq!(member_manifests(root), vec!["inner/Cargo.toml"]);
    }

    #[test]
    fn recursive_globs_and_missing_root() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        assert!(member_manifests(root).is_empty());
        write(root, "Cargo.toml", "[workspace]\nmembers = [\"**/m?\"]\n");
        write(root, "x/y/m1/Cargo.toml", &pkg("m1"));
        write(root, "m2/Cargo.toml", &pkg("m2"));
        write(root, "target/m3/Cargo.toml", &pkg("m3"));
        assert_eq!(
            member_manifests(root),
            vec!["m2/Cargo.toml", "x/y/m1/Cargo.toml"]
        );
    }

    /// A chain of nested directories `a/a/…/a`, `depth` deep, that counts
    /// the listings a walk asks of it.
    struct Chain {
        depth: usize,
        listings: std::cell::Cell<usize>,
    }

    impl Chain {
        fn new(depth: usize) -> Self {
            Chain {
                depth,
                listings: std::cell::Cell::new(0),
            }
        }

        /// How deep `rel` is, when it is a directory of the chain.
        fn depth_of(&self, rel: &str) -> Option<usize> {
            let depth = rel.split('/').filter(|seg| !seg.is_empty()).count();
            (depth <= self.depth && rel.split('/').all(|seg| seg.is_empty() || seg == "a"))
                .then_some(depth)
        }
    }

    impl DirTree for Chain {
        fn is_real_dir(&self, rel: &str) -> bool {
            self.depth_of(rel).is_some()
        }

        fn child_dirs(&self, rel: &str) -> Option<Vec<String>> {
            self.listings.set(self.listings.get() + 1);
            let depth = self.depth_of(rel)?;
            Some(if depth < self.depth {
                vec!["a".to_string()]
            } else {
                Vec::new()
            })
        }
    }

    /// A glob with several `**` reaches one directory along many routes
    /// (each split of the levels between them). The walk lists a directory
    /// once per pattern segment, not once per route: six `**` over a
    /// sixteen-deep chain is at most 17 × 7 listings, where walking every
    /// route asked 74,613 (and 10^11 for twelve `**` over forty levels, a
    /// `members` line and a directory chain that hung the scan).
    #[test]
    fn repeated_globstars_list_a_directory_once_per_segment() {
        for (pattern, segments) in [
            ("**/**/**/**/**/**/zz", 7),
            ("**/a/**/a/**/a/**/a/**/a/**/a/zz", 13),
        ] {
            let chain = Chain::new(16);
            let (dirs, truncated) = expand_glob_bounded(&chain, pattern, &[]);
            assert!(dirs.is_empty() && !truncated, "{pattern}: {dirs:?}");
            assert!(
                chain.listings.get() <= 17 * segments,
                "{pattern}: {} listings",
                chain.listings.get()
            );
        }
        // The answer is the set a single `**` names, and reaching each of
        // its directories along thousands of routes is not "more than
        // MAX_MANIFESTS directories".
        let all: Vec<String> = (0..=40).map(|depth| vec!["a"; depth].join("/")).collect();
        for pattern in ["**", "**/**/**", "**/**/**/**/**/**/**/**"] {
            let (dirs, truncated) = expand_glob_bounded(&Chain::new(40), pattern, &[]);
            assert_eq!(dirs, all, "{pattern}");
            assert!(!truncated, "{pattern}");
        }
        let below: Vec<String> = all[2..].to_vec();
        for pattern in ["**/a/**/a", "**/a/a/**", "a/**/**/a/**"] {
            let (dirs, truncated) = expand_glob_bounded(&Chain::new(40), pattern, &[]);
            assert_eq!(dirs, below, "{pattern}");
            assert!(!truncated, "{pattern}");
        }
    }

    /// The same walk through a [`ProjectView`] (the hosted engine's): a
    /// `members` glob of twelve `**` over a forty-deep directory chain
    /// names nothing, and says so at once.
    #[test]
    fn view_walk_of_repeated_globstars_finishes() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        write(
            &root,
            "Cargo.toml",
            &format!(
                "[workspace]\nmembers = [\"{}zz\", \"**/**/m\"]\n",
                "**/".repeat(12)
            ),
        );
        write(
            &root,
            &format!("{}m/Cargo.toml", "a/".repeat(40)),
            &pkg("m"),
        );
        let (answer, wait) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let walked = runtime.block_on(member_manifests_in(&ProjectView::Disk(&root)));
            let _ = answer.send((walked, member_manifests(&root)));
        });
        let (view, disk) = wait
            .recv_timeout(std::time::Duration::from_secs(60))
            .expect("the member walk did not finish within a minute");
        let member = format!("{}m/Cargo.toml", "a/".repeat(40));
        assert_eq!(view, vec![member.clone()]);
        assert_eq!(disk, vec![member]);
        drop(tmp);
    }

    /// Members and path dependencies behind a symbolic link — whether the
    /// link is a literal member, matched by a glob, a path dependency, an
    /// intermediate directory or the manifest itself — are never returned:
    /// the writer would follow the link, possibly out of the project.
    #[cfg(unix)]
    #[test]
    fn symlinked_members_and_path_dependencies_are_not_returned() {
        use std::os::unix::fs::symlink;
        let tmp = tempfile::tempdir().unwrap();
        let outside = tmp.path().join("outside");
        write(&outside, "shared/Cargo.toml", &pkg("shared"));
        write(&outside, "lone/Cargo.toml", &pkg("lone"));
        let root = tmp.path().join("proj");
        write(
            &root,
            "Cargo.toml",
            &format!(
                "[workspace]\nmembers = [\"crates/*\", \"linked\", \"nested/inner\"]\n\n\
                 {}[dependencies]\nvia = {{ path = \"via\" }}\nreal = {{ path = \"real\" }}\n",
                pkg("root")
            ),
        );
        std::fs::create_dir_all(root.join("crates")).unwrap();
        symlink(outside.join("shared"), root.join("crates/one")).unwrap();
        write(&root, "crates/two/Cargo.toml", &pkg("two"));
        symlink(outside.join("shared"), root.join("linked")).unwrap();
        symlink(&outside, root.join("nested")).unwrap();
        std::fs::create_dir_all(outside.join("inner")).unwrap();
        std::fs::write(outside.join("inner/Cargo.toml"), pkg("inner")).unwrap();
        symlink(outside.join("lone"), root.join("via")).unwrap();
        std::fs::create_dir_all(root.join("real")).unwrap();
        symlink(
            outside.join("lone/Cargo.toml"),
            root.join("real/Cargo.toml"),
        )
        .unwrap();
        assert_eq!(member_manifests(&root), vec!["crates/two/Cargo.toml"]);
    }

    /// ROUTED R-029. An output base inside the checkout holds the
    /// manifest of every crate Bazel fetched, and a vendor directory holds
    /// them under its own name. A `members` glob, a literal member or a
    /// path dependency that reaches one names a manifest that is Bazel's:
    /// below a Bazel boundary file none of them is returned, by the disk
    /// walk and by the view walk alike. The same tree with no boundary
    /// file is not Bazel's, and is listed as it always was.
    #[test]
    fn manifests_inside_a_bazel_tree_are_not_returned() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write(
            root,
            "Cargo.toml",
            &format!(
                "[workspace]\nmembers = [\"*\", \"out/external/*\", \"third_party/crates/dep\"]\n\n\
                 {}[dependencies]\nfetched = {{ path = \"out/external/fetched\" }}\n",
                pkg("root")
            ),
        );
        write(root, "app/Cargo.toml", &pkg("app"));
        // An output base: its marker, and a directory Bazel makes in it.
        write(root, "out/DO_NOT_BUILD_HERE", "");
        write(root, "out/Cargo.toml", &pkg("mirror"));
        write(root, "out/external/fetched/Cargo.toml", &pkg("fetched"));
        // A vendor directory, by the marker `bazel vendor` writes.
        write(root, "third_party/VENDOR.bazel", "");
        write(root, "third_party/crates/dep/Cargo.toml", &pkg("dep"));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let through_view = || runtime.block_on(member_manifests_in(&ProjectView::Disk(root)));

        let all = vec![
            "app/Cargo.toml",
            "out/Cargo.toml",
            "out/external/fetched/Cargo.toml",
            "third_party/crates/dep/Cargo.toml",
        ];
        assert_eq!(member_manifests(root), all, "no Bazel workspace");
        assert_eq!(through_view(), all);

        write(root, "MODULE.bazel", "module(name = \"ws\")\n");
        assert_eq!(member_manifests(root), vec!["app/Cargo.toml"]);
        assert_eq!(through_view(), vec!["app/Cargo.toml"]);
        assert_eq!(member_manifests_unmemoized(root), vec!["app/Cargo.toml"]);
    }

    #[test]
    fn members_and_path_dependencies_outside_the_root_are_not_returned() {
        let tmp = tempfile::tempdir().unwrap();
        write(tmp.path(), "lib/Cargo.toml", &pkg("lib"));
        write(tmp.path(), "shared/Cargo.toml", &pkg("shared"));
        let root = tmp.path().join("app");
        write(
            &root,
            "Cargo.toml",
            &format!(
                "[workspace]\nmembers = [\"../shared\"]\n\n{}[dependencies]\n\
                 lib = {{ path = \"../lib\" }}\n",
                pkg("app")
            ),
        );
        assert!(member_manifests(&root).is_empty());
    }

    /// Cargo's build directory is never a member, whichever way it is
    /// named: the glob walk skips it, and so do a literal `members` entry
    /// and a path dependency pointing into it. `cargo clean` deletes those
    /// manifests, and a recorded hosted edit for a file that no longer
    /// exists blocks the rollback of every other cargo edit.
    #[test]
    fn build_directory_manifests_are_never_members() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write(
            root,
            "Cargo.toml",
            &format!(
                "[workspace]\nmembers = [\"crates/*\", \"target/generated\"]\n\n\
                 {}[dependencies]\ngen2 = {{ path = \"target/gen2\" }}\n\
                 nested = {{ path = \"crates/a/target/gen3\" }}\n",
                pkg("root")
            ),
        );
        write(root, "crates/a/Cargo.toml", &pkg("a"));
        write(root, "crates/a/target/gen3/Cargo.toml", &pkg("gen3"));
        write(root, "target/generated/Cargo.toml", &pkg("generated"));
        write(root, "target/gen2/Cargo.toml", &pkg("gen2"));
        assert_eq!(member_manifests(root), vec!["crates/a/Cargo.toml"]);
    }

    /// #1833: cargo expands `members` with the `glob` crate, so `[ab]`,
    /// `[a-b]` and `[!x]` classes name the directories they match, as `*`
    /// and `?` do. The crate negates only on `!`: `[^x]` is the class of
    /// `^` and `x`.
    #[test]
    fn member_globs_read_character_classes() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        for name in ["alpha", "beta", "gamma"] {
            write(root, &format!("crates/{name}/Cargo.toml"), &pkg(name));
            write(root, &format!("tools/{name}/Cargo.toml"), &pkg(name));
            write(root, &format!("libs/{name}/Cargo.toml"), &pkg(name));
        }
        write(root, "carets/xtra/Cargo.toml", &pkg("xtra"));
        write(root, "carets/^hat/Cargo.toml", &pkg("hat"));
        write(
            root,
            "Cargo.toml",
            "[workspace]\nmembers = [\"crates/[ab]*\", \"tools/[a-b]?*\", \"libs/[!a]*\", \
             \"carets/[^x]*\"]\n",
        );
        assert_eq!(
            member_manifests(root),
            vec![
                "carets/^hat/Cargo.toml",
                "carets/xtra/Cargo.toml",
                "crates/alpha/Cargo.toml",
                "crates/beta/Cargo.toml",
                "libs/beta/Cargo.toml",
                "libs/gamma/Cargo.toml",
                "tools/alpha/Cargo.toml",
                "tools/beta/Cargo.toml",
            ]
        );
    }

    /// A `[[]` class matches a literal `[`.
    #[test]
    fn a_bracket_class_matches_a_literal_bracket() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write(root, "x[1/Cargo.toml", &pkg("x"));
        write(root, "Cargo.toml", "[workspace]\nmembers = [\"x[[]?\"]\n");
        assert_eq!(member_manifests(root), vec!["x[1/Cargo.toml"]);
    }

    #[test]
    fn member_patterns_are_wildcards_or_closed_classes() {
        for pattern in [
            "crates/*",
            "a?",
            "crates/[ab]",
            "x[!a]y",
            "x[^a]",
            "x[^]",
            "[]]",
        ] {
            assert!(is_member_pattern(pattern), "{pattern}");
        }
        for pattern in ["crates/a", "odd[dir", "x[]", "x[!]", "a]b["] {
            assert!(!is_member_pattern(pattern), "{pattern}");
        }
    }

    /// Whether a segment is a pattern is read off its first `[`, with the
    /// answer looking after every `[` gave (20,000 seeded segments), and a
    /// megabyte of unclosed `[` is one read, not one per `[`.
    #[test]
    fn member_pattern_check_reads_the_first_bracket_only() {
        let every_bracket = |seg: &str| {
            seg.contains(['*', '?'])
                || seg.match_indices('[').any(|(at, _)| {
                    let body = &seg[at + 1..];
                    let body = body.strip_prefix('!').unwrap_or(body);
                    body.char_indices().skip(1).any(|(_, c)| c == ']')
                })
        };
        let mut rng = crate::test_rng::Rng::new(0x54);
        let mut patterns = 0;
        for case in 0..20_000 {
            let seg: String = (0..rng.below(8))
                .map(|_| rng.pick(&["[", "[", "]", "]", "!", "^", "a", "é", "-", "*"]))
                .collect();
            let want = every_bracket(&seg);
            assert_eq!(segment_is_pattern(&seg), want, "case {case}: {seg:?}");
            patterns += usize::from(want);
        }
        assert!((4_000..16_000).contains(&patterns), "{patterns}");

        let (answer, wait) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let run = "[".repeat(1_000_000);
            let _ = answer.send((
                is_member_pattern(&run),
                is_member_pattern(&format!("{run}]")),
            ));
        });
        let answers = wait
            .recv_timeout(std::time::Duration::from_secs(60))
            .expect("the pattern check did not finish within a minute");
        assert_eq!(answers, (false, true));
    }

    /// V-7: the memoized member walk returns exactly what the per-call
    /// parse returned — over workspaces with globs, excludes, nested path
    /// dependencies, `[patch]` path copies, unparseable and missing
    /// manifests — and a manifest rewritten between two calls is re-read
    /// (the memo keys on its bytes).
    #[test]
    fn memoized_member_walk_matches_the_per_call_parse() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let check = || {
            assert_eq!(member_manifests(root), member_manifests_unmemoized(root));
            // Twice: the second walk is the one the memo answers.
            assert_eq!(member_manifests(root), member_manifests_unmemoized(root));
        };
        check();
        write(
            root,
            "Cargo.toml",
            "[workspace]\nmembers = [\"crates/*\", \"tools/**\"]\nexclude = [\"crates/x\"]\n\
             [patch.crates-io]\nserde = { path = \".socket/vendor/cargo/u1/serde-1.0.0\" }\n\
             [workspace.dependencies]\nshared = { path = \"libs/shared\" }\n",
        );
        write(
            root,
            "crates/a/Cargo.toml",
            &format!("{}[dependencies.b]\npath = \"../b\"\n", pkg("a")),
        );
        write(root, "crates/b/Cargo.toml", &pkg("b"));
        write(root, "crates/x/Cargo.toml", &pkg("x"));
        write(root, "crates/bad/Cargo.toml", "not = [toml");
        write(root, "tools/deep/t/Cargo.toml", &pkg("t"));
        write(root, "libs/shared/Cargo.toml", &pkg("shared"));
        write(
            root,
            ".socket/vendor/cargo/u1/serde-1.0.0/Cargo.toml",
            &format!(
                "{}[dependencies]\nderive = {{ path = \"../derive\" }}\n",
                pkg("serde")
            ),
        );
        write(
            root,
            ".socket/vendor/cargo/u1/derive/Cargo.toml",
            &pkg("derive"),
        );
        check();
        assert!(member_manifests(root)
            .contains(&".socket/vendor/cargo/u1/derive/Cargo.toml".to_string()));
        // Rewritten between two walks: the new path dependency is followed.
        write(
            root,
            "crates/b/Cargo.toml",
            &format!("{}[dependencies]\nz = {{ path = \"../../z\" }}\n", pkg("b")),
        );
        write(root, "z/Cargo.toml", &pkg("z"));
        check();
        assert!(member_manifests(root).contains(&"z/Cargo.toml".to_string()));
        // The root turned unparseable, then back.
        let good = std::fs::read_to_string(root.join("Cargo.toml")).unwrap();
        write(root, "Cargo.toml", "[workspace\n");
        check();
        write(root, "Cargo.toml", &good);
        check();
    }
}
