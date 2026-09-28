//! Project-root detection over a repository path list. A root is a
//! directory holding a root LOCK marker (manifests alone never make one),
//! outside vendored / test-fixture trees, and not an internal directory of
//! an enclosing Rush monorepo. A nested Cargo.lock stays a root here: only
//! the enclosing workspace's `members`/`exclude` can say whether it is a
//! member, so the engine demotes members once manifests are readable.

use std::collections::{BTreeMap, BTreeSet};

use socket_patch_core::utils::python_lock::is_python_lock_name;

use super::types::IgnoredPath;

/// Lock markers that make their directory a project root, with the
/// ecosystem each belongs to.
pub(crate) const ROOT_LOCK_MARKERS: [(&str, &str); 19] = [
    ("package-lock.json", "npm"),
    ("npm-shrinkwrap.json", "npm"),
    ("pnpm-lock.yaml", "npm"),
    ("yarn.lock", "npm"),
    ("bun.lock", "npm"),
    ("bun.lockb", "npm"),
    ("vlt-lock.json", "npm"),
    ("rush.json", "npm"),
    ("uv.lock", "pypi"),
    ("poetry.lock", "pypi"),
    ("pdm.lock", "pypi"),
    ("Pipfile.lock", "pypi"),
    ("requirements.txt", "pypi"),
    ("Cargo.lock", "cargo"),
    ("go.mod", "golang"),
    ("go.sum", "golang"),
    ("composer.lock", "composer"),
    ("Gemfile.lock", "gem"),
    ("gems.locked", "gem"),
];

/// Marker files of the ecosystems the in-memory engine cannot inventory
/// (disk discovers them only through installed-tree crawlers).
pub(crate) const UNSUPPORTED_MARKERS: [(&str, &[&str]); 2] = [
    (
        "maven",
        &[
            "pom.xml",
            "build.gradle",
            "build.gradle.kts",
            "settings.gradle",
            "settings.gradle.kts",
        ],
    ),
    ("nuget", &["packages.lock.json", "nuget.config"]),
];

/// Directory names whose subtrees never hold a project root: installed
/// trees, VCS and tool state, and vendored dependencies. Structural, so no
/// policy can negate them. (Test and fixture trees are the socket.yml
/// policy's overridable built-in ignores: [`default_ignored_dir`].)
pub(crate) const EXCLUDED_ROOT_SEGMENTS: [&str; 5] = ["node_modules", ".git", ".socket", ".yarn", "vendor"];

/// Whether `dir` (repo-relative) is under a built-in default ignore of the
/// socket.yml policy (`test/`, `tests/`, `fixtures/`, …, any case).
pub(crate) fn default_ignored_dir(dir: &str) -> bool {
    !dir.is_empty()
        && socket_patch_core::policy::builtin_defaults()
            .admits_root(&socket_patch_core::policy::Root {
                rel_dir: dir,
                markers: &[],
                explicit: false,
            })
            .is_err()
}

/// The marker basenames of `root` among `paths` (the files the policy's
/// path filters test for that root).
pub(crate) fn root_markers<'a>(root: &str, paths: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    let mut out: Vec<String> = paths
        .into_iter()
        .filter_map(|path| {
            let (dir, base) = split_path(path);
            let marker = marker_ecosystem(base).is_some()
                || UNSUPPORTED_MARKERS.iter().any(|(_, names)| names.contains(&base));
            (dir == root && marker).then(|| base.to_string())
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

/// The ecosystem a root marker basename belongs to.
pub(crate) fn marker_ecosystem(base: &str) -> Option<&'static str> {
    if let Some((_, eco)) = ROOT_LOCK_MARKERS.iter().find(|(name, _)| *name == base) {
        return Some(eco);
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

fn allowed(ecosystems: Option<&[String]>, eco: &str) -> bool {
    ecosystems.is_none_or(|list| list.iter().any(|e| e == eco))
}

/// The detected roots (sorted) and the marker paths that did not make one.
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
        let key: &'static str = ROOT_LOCK_MARKERS
            .iter()
            .find(|(name, _)| *name == base)
            .map_or("python-lock", |(name, _)| name);
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
        let marker_names: Vec<String> = marker_paths
            .get(dir)
            .into_iter()
            .flatten()
            .map(|p| split_path(p).1.to_string())
            .collect();
        let default_ignored = socket_patch_core::policy::builtin_defaults()
            .admits_root(&socket_patch_core::policy::Root {
                rel_dir: dir,
                markers: &marker_names,
                explicit: false,
            })
            .is_err();
        let rush_internal = rush_roots.iter().any(|r| {
            let internal = |sub: &str| join_root(r, sub);
            *dir == internal("common/config/rush")
                || dir.starts_with(&format!("{}/", internal("common/config/subspaces")))
                || *dir == internal("common/temp")
                || dir.starts_with(&format!("{}/", internal("common/temp")))
        });
        let reason = if default_ignored {
            Some("policy_path_excluded")
        } else if rush_internal {
            Some("rush_internal")
        } else {
            None
        };
        match reason {
            Some(reason) => {
                for path in marker_paths.get(dir).into_iter().flatten() {
                    ignored.push(IgnoredPath {
                        path: path.clone(),
                        reason: reason.to_string(),
                    });
                }
            }
            None => roots.push(dir.clone()),
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
        assert_eq!(found, vec!["docs"]);
        assert_eq!(ignored.len(), 4);
        let reason = |path: &str| ignored.iter().find(|i| i.path == path).unwrap().reason.clone();
        assert_eq!(reason("node_modules/x/package-lock.json"), "excluded_dir");
        assert_eq!(reason("a/vendor/b/composer.lock"), "excluded_dir");
        assert_eq!(reason(".socket/vendor/npm/package-lock.json"), "excluded_dir");
        // Test/fixture trees are the policy's overridable built-in ignores.
        assert_eq!(reason("test/fixtures/yarn.lock"), "policy_path_excluded");
    }

    #[test]
    fn default_ignores_are_case_insensitive_and_marker_based() {
        let (found, _) = detect_roots(
            ["Tests/app/yarn.lock", "e2e/testdata/go.mod", "apps/testing/package-lock.json"],
            None,
        );
        assert_eq!(found, vec!["apps/testing"]);
        assert!(default_ignored_dir("a/__fixtures__"));
        assert!(!default_ignored_dir(""));
        assert!(!default_ignored_dir("apps/testing"));
        assert_eq!(
            root_markers("a", ["a/yarn.lock", "a/package.json", "a/b/yarn.lock", "a/pom.xml"]),
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
}
