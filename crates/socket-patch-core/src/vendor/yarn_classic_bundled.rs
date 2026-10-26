//! yarn classic's bundled copies (#758). yarn 1 unpacks a package's
//! `bundleDependencies` from its tarball into the package's own
//! `node_modules` (`node_modules/<parent>/node_modules/<name>`) and
//! records nothing about them in `yarn.lock`: no block, no `inBundle`
//! flag, not even the parent's `bundleDependencies`. So no hosted or
//! vendored rewire of the same `name@version` reaches such a copy, and
//! only the installed tree shows it.
//!
//! A bundle is what `npm pack` puts in the tarball: each named package
//! and, beside it in the parent's `node_modules`, the dependencies it
//! needs, plus everything nested under any of them. Packages yarn itself
//! placed in a parent's `node_modules` (a version the hoist could not
//! share) come from their lock blocks and are not bundled copies.
//!
//! Shared by lockfile discovery (which contests a ref of the same
//! `name@version`, like npm's `inBundle` copies) and the vendored scan
//! (which warns that the copy stays unpatched).

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::Path;

use serde_json::Value;

use super::vlt_bundled::{installed_purl, is_package_name, real_package_dirs};

/// A bundled copy found in the installed tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BundledCopy {
    /// Root-relative directory of the copy.
    pub(crate) location: String,
    /// The bundling package's name and version, as its `package.json`
    /// says.
    pub(crate) parent_name: String,
    pub(crate) parent_version: String,
}

/// Upper bound on the `node_modules` entries one walk inspects, so a huge
/// or hostile tree cannot stall `vex`.
const BUNDLED_WALK_LIMIT: usize = 50_000;

/// purl → the first bundled copy of it installed under the project's
/// `node_modules` (empty without one).
pub(crate) async fn bundled_copies(root: &Path) -> BTreeMap<String, BundledCopy> {
    let root = root.to_path_buf();
    tokio::task::spawn_blocking(move || bundled_copies_sync(&root))
        .await
        .unwrap_or_else(|e| match e.try_into_panic() {
            Ok(payload) => std::panic::resume_unwind(payload),
            Err(e) => panic!("yarn classic bundled-copy walk failed: {e}"),
        })
}

/// The scan warning detail for a bundled copy that a vendored rewire of
/// `name@version` cannot reach.
pub(crate) fn bundled_copy_detail(name: &str, version: &str, copy: &BundledCopy) -> String {
    format!(
        "yarn also installs {name}@{version} as a bundled copy at {:?}, unpacked from the \
         tarball of {}@{} with no yarn.lock block, and it CANNOT be rewired — that copy stays \
         UNPATCHED; vendor or update the bundling package to cover it",
        copy.location, copy.parent_name, copy.parent_version
    )
}

fn bundled_copies_sync(root: &Path) -> BTreeMap<String, BundledCopy> {
    let mut copies = BTreeMap::new();
    let mut budget = BUNDLED_WALK_LIMIT;
    // Directories inside a bundle, recorded with their whole subtree.
    let mut bundled: HashSet<String> = HashSet::new();
    let mut pending = vec!["node_modules".to_string()];
    // A workspace member's own `node_modules` (what the hoist couldn't
    // share) is reached through its link in the root `node_modules`.
    pending.extend(
        linked_members(root)
            .into_iter()
            .map(|member| format!("{member}/node_modules")),
    );
    while let Some(dir) = pending.pop() {
        if !is_real_dir(root, &dir) {
            continue;
        }
        for package in real_package_dirs(root, &dir, &mut budget) {
            if bundled.contains(&package) {
                continue;
            }
            let nested = format!("{package}/node_modules");
            pending.push(nested.clone());
            let Some(manifest) = read_manifest(root, &package) else {
                continue;
            };
            let names = bundled_names(&manifest);
            if names.is_empty() {
                continue;
            }
            let (Some(parent_name), Some(parent_version)) = (
                manifest.get("name").and_then(Value::as_str),
                manifest.get("version").and_then(Value::as_str),
            ) else {
                continue;
            };
            if !is_real_dir(root, &nested) {
                continue;
            }
            for dir in bundle_closure(root, &nested, names) {
                for copy in subtree(root, &dir, &mut budget) {
                    if let Some(purl) = installed_purl(root, &copy) {
                        copies.entry(purl).or_insert_with(|| BundledCopy {
                            location: copy.clone(),
                            parent_name: parent_name.to_string(),
                            parent_version: parent_version.to_string(),
                        });
                    }
                    bundled.insert(copy);
                }
            }
        }
    }
    copies
}

/// The root-relative directories of the bundle in `node_modules` dir
/// `nested`: each of `names` installed there, and each of their
/// dependencies installed there in turn.
fn bundle_closure(root: &Path, nested: &str, names: Vec<String>) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    let mut queue = names;
    while let Some(name) = queue.pop() {
        if !is_package_name(&name) {
            continue;
        }
        let dir = format!("{nested}/{name}");
        let scope_ok = match name.split_once('/') {
            Some((scope, _)) => is_real_dir(root, &format!("{nested}/{scope}")),
            None => true,
        };
        if found.contains(&dir) || !scope_ok || !is_real_dir(root, &dir) {
            continue;
        }
        if let Some(manifest) = read_manifest(root, &dir) {
            queue.extend(dependency_names(&manifest));
        }
        found.insert(dir);
    }
    found
}

/// Root-relative directories of the packages the root `node_modules`
/// links to inside the project (yarn classic links each workspace member
/// there), outside any `node_modules`.
fn linked_members(root: &Path) -> Vec<String> {
    let Ok(canonical_root) = std::fs::canonicalize(root) else {
        return Vec::new();
    };
    let mut links = Vec::new();
    let mut pending = vec![(root.join("node_modules"), true)];
    while let Some((dir, scopes)) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if scopes && file_type.is_dir() && name.to_string_lossy().starts_with('@') {
                pending.push((entry.path(), false));
            } else if file_type.is_symlink() {
                links.push(entry.path());
            }
        }
    }
    let mut members: Vec<String> = links
        .into_iter()
        .filter_map(|link| {
            let real = std::fs::canonicalize(link).ok()?;
            let rel = real.strip_prefix(&canonical_root).ok()?;
            let rel: Vec<&str> = rel
                .components()
                .map(|c| c.as_os_str().to_str())
                .collect::<Option<_>>()?;
            (!rel.is_empty() && !rel.contains(&"node_modules") && real.is_dir())
                .then(|| rel.join("/"))
        })
        .collect();
    members.sort();
    members.dedup();
    members
}

/// `dir` and every real package directory nested in its `node_modules`.
fn subtree(root: &Path, dir: &str, budget: &mut usize) -> Vec<String> {
    let mut out = vec![dir.to_string()];
    let mut pending = vec![format!("{dir}/node_modules")];
    while let Some(nm) = pending.pop() {
        if !is_real_dir(root, &nm) {
            continue;
        }
        for child in real_package_dirs(root, &nm, budget) {
            pending.push(format!("{child}/node_modules"));
            out.push(child);
        }
    }
    out
}

/// The names a manifest bundles: `bundleDependencies` (npm) or its legacy
/// `bundledDependencies` alias. `true` bundles every `dependencies` key,
/// an array names them, and an object bundles its keys (as npm-bundled
/// reads it).
fn bundled_names(manifest: &Value) -> Vec<String> {
    let mut names = Vec::new();
    for key in ["bundleDependencies", "bundledDependencies"] {
        match manifest.get(key) {
            Some(Value::Bool(true)) => names.extend(
                manifest
                    .get("dependencies")
                    .and_then(Value::as_object)
                    .into_iter()
                    .flat_map(|deps| deps.keys().cloned()),
            ),
            Some(Value::Array(list)) => {
                names.extend(list.iter().filter_map(Value::as_str).map(str::to_string))
            }
            Some(Value::Object(map)) => names.extend(map.keys().cloned()),
            _ => {}
        }
    }
    names
}

/// The `dependencies`, `optionalDependencies` and `peerDependencies` keys
/// of a manifest (npm 7+ packs a bundled package's peers into the bundle
/// too).
fn dependency_names(manifest: &Value) -> Vec<String> {
    ["dependencies", "optionalDependencies", "peerDependencies"]
        .iter()
        .filter_map(|k| manifest.get(*k).and_then(Value::as_object))
        .flat_map(|deps| deps.keys().cloned())
        .collect()
}

fn read_manifest(root: &Path, dir: &str) -> Option<Value> {
    let text =
        crate::utils::fs::read_regular_to_string_sync(&root.join(dir).join("package.json")).ok()?;
    serde_json::from_str(&text).ok()
}

/// Whether root-relative `rel` is a directory and not a symlink (a link
/// may point outside the project, and yarn never links a bundled copy).
fn is_real_dir(root: &Path, rel: &str) -> bool {
    std::fs::symlink_metadata(root.join(rel)).is_ok_and(|m| m.is_dir())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(root: &Path, rel: &str, text: &str) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    fn package(root: &Path, dir: &str, manifest: &str) {
        write(root, &format!("{dir}/package.json"), manifest);
    }

    async fn locations(root: &Path) -> Vec<(String, String)> {
        bundled_copies(root)
            .await
            .into_iter()
            .map(|(purl, copy)| (purl, copy.location))
            .collect()
    }

    const LEFT_PAD: &str = r#"{"name":"left-pad","version":"1.3.0"}"#;

    /// A bundled package's peer is packed beside it (npm 7+), so it is part
    /// of the bundle; a sibling the parent merely depends on is not.
    #[tokio::test]
    async fn a_bundled_packages_peer_is_bundled() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        package(
            root,
            "node_modules/bund",
            r#"{"name":"bund","version":"1.0.0","dependencies":{"plugin":"1.0.0","other":"1.0.0"},"bundleDependencies":["plugin"]}"#,
        );
        package(
            root,
            "node_modules/bund/node_modules/plugin",
            r#"{"name":"plugin","version":"1.0.0","peerDependencies":{"left-pad":"^1.3.0"}}"#,
        );
        package(root, "node_modules/bund/node_modules/left-pad", LEFT_PAD);
        package(
            root,
            "node_modules/bund/node_modules/other",
            r#"{"name":"other","version":"1.0.0"}"#,
        );
        assert_eq!(
            locations(root).await,
            [
                (
                    "pkg:npm/left-pad@1.3.0".to_string(),
                    "node_modules/bund/node_modules/left-pad".to_string()
                ),
                (
                    "pkg:npm/plugin@1.0.0".to_string(),
                    "node_modules/bund/node_modules/plugin".to_string()
                ),
            ]
        );
    }

    /// A workspace member's own `node_modules` is walked through the
    /// member's link in the root `node_modules`; a link leaving the project
    /// is not followed.
    #[cfg(unix)]
    #[tokio::test]
    async fn workspace_member_node_modules_are_walked_and_links_stay_inside() {
        use std::os::unix::fs::symlink;
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("project");
        let bund = r#"{"name":"bund","version":"2.0.0","bundleDependencies":["left-pad"]}"#;
        package(
            &root,
            "packages/app",
            r#"{"name":"@ws/app","version":"1.0.0"}"#,
        );
        package(&root, "packages/app/node_modules/bund", bund);
        package(
            &root,
            "packages/app/node_modules/bund/node_modules/left-pad",
            LEFT_PAD,
        );
        std::fs::create_dir_all(root.join("node_modules/@ws")).unwrap();
        symlink(root.join("packages/app"), root.join("node_modules/@ws/app")).unwrap();
        // A link outside the project holding a bundle is never read.
        let outside = tmp.path().join("outside");
        package(&outside, "ext", r#"{"name":"ext","version":"1.0.0"}"#);
        package(&outside, "ext/node_modules/bund", bund);
        package(
            &outside,
            "ext/node_modules/bund/node_modules/left-pad",
            LEFT_PAD,
        );
        symlink(outside.join("ext"), root.join("node_modules/ext")).unwrap();
        assert_eq!(
            locations(&root).await,
            [(
                "pkg:npm/left-pad@1.3.0".to_string(),
                "packages/app/node_modules/bund/node_modules/left-pad".to_string()
            )]
        );
    }
}
