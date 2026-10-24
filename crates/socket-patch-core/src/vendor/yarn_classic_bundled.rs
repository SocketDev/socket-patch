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

/// The `dependencies` and `optionalDependencies` keys of a manifest.
fn dependency_names(manifest: &Value) -> Vec<String> {
    ["dependencies", "optionalDependencies"]
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
