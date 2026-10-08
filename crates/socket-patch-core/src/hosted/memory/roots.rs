//! Project-root detection over a repository path list. A root is a
//! directory holding a root LOCK marker (manifests alone never make one),
//! outside vendored / test-fixture trees, and not an internal directory of
//! an enclosing Rush monorepo. A nested Cargo.lock stays a root here: only
//! the enclosing workspace's `members`/`exclude` can say whether it is a
//! member, so the engine demotes members once manifests are readable.

use std::collections::{BTreeMap, BTreeSet};

use crate::formats::registry;
use crate::utils::python_lock::is_python_lock_name;

use super::types::IgnoredPath;

/// Marker files of the ecosystems the in-memory engine cannot inventory
/// (disk discovers them only through installed-tree crawlers).
pub const UNSUPPORTED_MARKERS: [(&str, &[&str]); 2] = [
    ("maven", crate::crawlers::jvm_cache::JVM_PROJECT_MARKERS),
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

#[cfg(test)]
mod tests {
    use super::*;

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
