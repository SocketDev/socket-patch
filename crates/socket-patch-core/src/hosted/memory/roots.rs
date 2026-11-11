//! Project-root detection over a repository path list. A root is a
//! directory holding a root LOCK marker (manifests alone never make one),
//! outside vendored / test-fixture trees, and not an internal directory of
//! an enclosing Rush monorepo. A nested Cargo.lock stays a root here: only
//! the enclosing workspace's `members`/`exclude` can say whether it is a
//! member, so the engine demotes members once manifests are readable. A
//! pnpm workspace member's lock is demoted into the workspace root the
//! same way, by the `packages:` globs ([`pnpm_member_candidates`]).

use std::collections::{BTreeMap, BTreeSet};

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
/// policy's overridable built-in ignores.)
pub(crate) const EXCLUDED_ROOT_SEGMENTS: [&str; 5] =
    ["node_modules", ".git", ".socket", ".yarn", "vendor"];

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

/// The detected roots (sorted) and the marker paths that did not make one.
/// The socket.yml path policy (built-in default ignores included) is the
/// caller's to apply.
pub(crate) fn detect_roots<'a>(
    paths: impl IntoIterator<Item = &'a str>,
    ecosystems: Option<&[String]>,
) -> (Vec<String>, Vec<IgnoredPath>) {
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
}

/// How many directory entries [`roots_below`] reads before it gives up.
/// Installed trees and ignored output are never entered, so this is far
/// above any repository's source tree, and a bound on a directory that is
/// not one.
const MAX_WALKED_ENTRIES: usize = 500_000;

/// The marker files at and below `dir`, as `/`-separated relative paths,
/// and whether the walk was cut short.
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
fn marker_paths_below(dir: &std::path::Path) -> (Vec<String>, bool) {
    let walk = ignore::WalkBuilder::new(dir)
        .hidden(false)
        .ignore(false)
        .follow_links(false)
        .filter_entry(|entry| {
            if !entry.file_type().is_some_and(|t| t.is_dir()) {
                return true;
            }
            let excluded = entry
                .file_name()
                .to_str()
                .is_some_and(|name| EXCLUDED_ROOT_SEGMENTS.contains(&name));
            let other_repository =
                entry.depth() > 0 && entry.path().join(".git").symlink_metadata().is_ok();
            !excluded && !other_repository
        })
        .build();
    let mut markers: Vec<String> = Vec::new();
    for (seen, entry) in walk.flatten().enumerate() {
        if seen >= MAX_WALKED_ENTRIES {
            return (markers, true);
        }
        if entry.file_type().is_none_or(|t| t.is_dir()) {
            continue;
        }
        let is_marker = entry
            .file_name()
            .to_str()
            .is_some_and(|base| marker_ecosystem(base).is_some());
        if !is_marker {
            continue;
        }
        let Ok(rel) = entry.path().strip_prefix(dir) else {
            continue;
        };
        // A path that is not UTF-8 names no root a `/`-joined list can hold.
        let segments: Option<Vec<&str>> = rel.iter().map(|segment| segment.to_str()).collect();
        if let Some(segments) = segments {
            markers.push(segments.join("/"));
        }
    }
    (markers, false)
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
    let (markers, truncated) = tokio::task::spawn_blocking(move || marker_paths_below(&walked))
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
