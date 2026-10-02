//! vlt's bundled copies (#471). vlt unpacks a `bundleDependencies` entry
//! from the parent's tarball into the parent's own store entry
//! (`node_modules/.vlt/<parent id>/node_modules/<parent>/node_modules/
//! <name>`) and records no `vlt-lock.json` node for it — the lock carries
//! neither the copy nor the parent's `bundleDependencies` — so no hosted or
//! vendored rewire reaches it, and only the installed store shows it. A
//! dependency vlt links is a SYMLINK beside the package
//! (`.vlt/<id>/node_modules/<dep>`), never a real directory inside it, so
//! every real package directory under the package's own `node_modules` is a
//! bundled copy.
//!
//! Shared by lockfile discovery (which contests a ref of the same
//! `name@version`, like npm's `inBundle` copies) and the hosted and
//! vendored scans (which warn that the copy stays unpatched).

use std::collections::BTreeMap;
use std::path::Path;

use crate::constants::npm_family::{VLT_LOCK, VLT_STORE_DIR};
use crate::utils::purl::npm_purl;
use crate::vendor::lock_inventory::vlt::vlt_lock_model;

/// purl → root-relative directory of every bundled copy installed in the
/// store entries of the project's `vlt-lock.json` nodes (empty without a
/// readable lock or store).
pub async fn bundled_copies(root: &Path) -> BTreeMap<String, String> {
    let Ok(text) = crate::utils::fs::read_regular_to_string(&root.join(VLT_LOCK)).await else {
        return BTreeMap::new();
    };
    let Ok(lock) = vlt_lock_model(&text) else {
        return BTreeMap::new();
    };
    store_bundled_copies(
        root,
        lock.nodes.iter().map(|n| (n.key.as_str(), n.name.as_str())),
    )
    .await
}

/// The scan warning detail for a bundled copy at `location` that a hosted
/// or vendored rewire of `name@version` cannot reach.
pub fn bundled_copy_detail(name: &str, version: &str, location: &str) -> String {
    format!(
        "vlt also installs {name}@{version} as a bundled copy at {location:?}, unpacked from \
         its parent's tarball with no {VLT_LOCK} node, and it CANNOT be rewired — that copy \
         stays UNPATCHED; vendor or update the bundling parent to cover it"
    )
}

/// Upper bound on the store directory entries one discovery inspects for
/// bundled copies, so a huge or hostile `node_modules` cannot stall `vex`.
const BUNDLED_WALK_LIMIT: usize = 20_000;

/// purl → root-relative directory of the first bundled copy of it found in
/// the store entries of `nodes` (`(DepID key, package name)` pairs of
/// `vlt-lock.json`).
pub(crate) async fn store_bundled_copies<'n>(
    root: &Path,
    nodes: impl IntoIterator<Item = (&'n str, &'n str)>,
) -> BTreeMap<String, String> {
    let mut copies = BTreeMap::new();
    let Ok(canonical_root) = tokio::fs::canonicalize(root).await else {
        return copies;
    };
    let mut budget = BUNDLED_WALK_LIMIT;
    for (key, name) in nodes {
        // Both come from the lock: never let them climb out of the store.
        if !is_plain_segment(key) || !is_package_name(name) {
            continue;
        }
        let package = format!("{VLT_STORE_DIR}/{key}/node_modules/{name}");
        // The package itself must be a real directory inside the project.
        match tokio::fs::canonicalize(root.join(&package)).await {
            Ok(real) if real.starts_with(&canonical_root) && real.is_dir() => {}
            _ => continue,
        }
        let mut pending = vec![format!("{package}/node_modules")];
        while let Some(dir) = pending.pop() {
            for child in real_package_dirs(root, &dir, &mut budget).await {
                if let Some(purl) = installed_purl(root, &child).await {
                    copies.entry(purl).or_insert_with(|| child.clone());
                }
                pending.push(format!("{child}/node_modules"));
            }
        }
    }
    copies
}

/// Root-relative paths of the real (not symlinked) package directories in
/// the `node_modules` dir `dir`, one `@scope` level deep.
async fn real_package_dirs(root: &Path, dir: &str, budget: &mut usize) -> Vec<String> {
    let mut found = Vec::new();
    let mut pending = vec![(dir.to_string(), true)];
    while let Some((dir, scopes)) = pending.pop() {
        let Ok(mut entries) = tokio::fs::read_dir(root.join(&dir)).await else {
            continue;
        };
        while let Ok(Some(entry)) = entries.next_entry().await {
            if *budget == 0 {
                return found;
            }
            *budget -= 1;
            let Ok(name) = entry.file_name().into_string() else {
                continue;
            };
            // `DirEntry::file_type` does not follow symlinks.
            if name.starts_with('.') || !entry.file_type().await.is_ok_and(|t| t.is_dir()) {
                continue;
            }
            let rel = format!("{dir}/{name}");
            if scopes && name.starts_with('@') {
                pending.push((rel, false));
            } else {
                found.push(rel);
            }
        }
    }
    found.sort();
    found
}

/// The npm purl a package directory's `package.json` declares.
async fn installed_purl(root: &Path, dir: &str) -> Option<String> {
    let text = crate::utils::fs::read_regular_to_string(&root.join(dir).join("package.json"))
        .await
        .ok()?;
    let manifest: serde_json::Value = serde_json::from_str(&text).ok()?;
    npm_purl(
        manifest.get("name")?.as_str()?,
        manifest.get("version")?.as_str()?,
    )
}

/// One path segment that cannot escape its directory.
fn is_plain_segment(s: &str) -> bool {
    !s.is_empty() && s != "." && s != ".." && !s.contains(['/', '\\', '\0'])
}

/// An npm package name (`name` or `@scope/name`) made of plain segments.
fn is_package_name(name: &str) -> bool {
    match name.split_once('/') {
        Some((scope, bare)) => {
            scope.starts_with('@') && is_plain_segment(scope) && is_plain_segment(bare)
        }
        None => is_plain_segment(name),
    }
}
