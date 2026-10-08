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
    // Collected first: a closure-mapped iterator held across the walk's
    // awaits would keep the caller's future from being `Send`.
    let pairs: Vec<(&str, &str)> = lock
        .nodes
        .iter()
        .map(|n| (n.key.as_str(), n.name.as_str()))
        .collect();
    store_bundled_copies(root, pairs).await
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
/// `vlt-lock.json`). The walk is one blocking task of plain syscalls (a
/// store holds one entry per lock node, each probed several times).
pub(crate) async fn store_bundled_copies<'n>(
    root: &Path,
    nodes: impl IntoIterator<Item = (&'n str, &'n str)>,
) -> BTreeMap<String, String> {
    let root = root.to_path_buf();
    let nodes: Vec<(String, String)> = nodes
        .into_iter()
        .map(|(key, name)| (key.to_string(), name.to_string()))
        .collect();
    tokio::task::spawn_blocking(move || store_bundled_copies_sync(&root, &nodes))
        .await
        .unwrap_or_else(|e| match e.try_into_panic() {
            Ok(payload) => std::panic::resume_unwind(payload),
            Err(e) => panic!("vlt store walk failed: {e}"),
        })
}

fn store_bundled_copies_sync(root: &Path, nodes: &[(String, String)]) -> BTreeMap<String, String> {
    let mut copies = BTreeMap::new();
    let Ok(canonical_root) = std::fs::canonicalize(root) else {
        return copies;
    };
    let mut real_dirs = RealDirs::default();
    let mut budget = BUNDLED_WALK_LIMIT;
    for (key, name) in nodes {
        // Both come from the lock: never let them climb out of the store.
        if !is_plain_segment(key) || !is_package_name(name) {
            continue;
        }
        let package = format!("{VLT_STORE_DIR}/{key}/node_modules/{name}");
        // The package itself must be a real directory inside the project.
        match real_dirs.check(root, &package) {
            Some(true) => {}
            Some(false) => continue,
            None => match std::fs::canonicalize(root.join(&package)) {
                Ok(real) if real.starts_with(&canonical_root) && real.is_dir() => {}
                _ => continue,
            },
        }
        let mut pending = vec![format!("{package}/node_modules")];
        while let Some(dir) = pending.pop() {
            for child in real_package_dirs(root, &dir, &mut budget) {
                if let Some(purl) = installed_purl(root, &child) {
                    copies.entry(purl).or_insert_with(|| child.clone());
                }
                pending.push(format!("{child}/node_modules"));
            }
        }
    }
    copies
}

/// The `lstat` answer to "does root-relative `rel` canonicalize to a
/// directory inside the (canonical) root": `Some(true)` when every
/// component is a real directory (the canonical path is then the canonical
/// root joined with `rel`), `Some(false)` when a component is missing or a
/// non-directory (canonicalizing fails, or ends at a non-directory), and
/// `None` when a component is a symbolic link, for the caller's
/// `canonicalize` to follow. Shared prefixes (`node_modules/.vlt`) are
/// probed once.
#[derive(Default)]
struct RealDirs {
    seen: std::collections::HashMap<String, Option<bool>>,
}

impl RealDirs {
    fn check(&mut self, root: &Path, rel: &str) -> Option<bool> {
        let mut prefix = String::with_capacity(rel.len());
        for segment in rel.split('/') {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(segment);
            let verdict = match self.seen.get(&prefix) {
                Some(verdict) => *verdict,
                None => {
                    let verdict = match std::fs::symlink_metadata(root.join(&prefix)) {
                        Ok(meta) if meta.file_type().is_symlink() => None,
                        Ok(meta) => Some(meta.is_dir()),
                        Err(_) => Some(false),
                    };
                    self.seen.insert(prefix.clone(), verdict);
                    verdict
                }
            };
            if verdict != Some(true) {
                return verdict;
            }
        }
        Some(true)
    }
}

/// Root-relative paths of the real (not symlinked) package directories in
/// the `node_modules` dir `dir`, one `@scope` level deep.
fn real_package_dirs(root: &Path, dir: &str, budget: &mut usize) -> Vec<String> {
    let mut found = Vec::new();
    let mut pending = vec![(dir.to_string(), true)];
    while let Some((dir, scopes)) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(root.join(&dir)) else {
            continue;
        };
        for entry in entries {
            let Ok(entry) = entry else {
                break;
            };
            if *budget == 0 {
                return found;
            }
            *budget -= 1;
            let Ok(name) = entry.file_name().into_string() else {
                continue;
            };
            // `DirEntry::file_type` does not follow symlinks.
            if name.starts_with('.') || !entry.file_type().is_ok_and(|t| t.is_dir()) {
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
fn installed_purl(root: &Path, dir: &str) -> Option<String> {
    let text =
        crate::utils::fs::read_regular_to_string_sync(&root.join(dir).join("package.json")).ok()?;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn write(root: &Path, rel: &str, text: &str) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    /// A bundled copy at `<package>/node_modules/left-pad` of the store
    /// entry `key`.
    fn store_entry(root: &Path, key: &str) -> String {
        let package = format!("{VLT_STORE_DIR}/{key}/node_modules/bund");
        write(
            root,
            &format!("{package}/package.json"),
            r#"{"name":"bund","version":"1.0.0"}"#,
        );
        write(
            root,
            &format!("{package}/node_modules/left-pad/package.json"),
            r#"{"name":"left-pad","version":"1.3.0"}"#,
        );
        package
    }

    async fn copies(root: &Path, key: &str) -> Vec<String> {
        store_bundled_copies(root, [(key, "bund")])
            .await
            .into_keys()
            .collect()
    }

    /// The lstat shortcut answers what `canonicalize` did: real store
    /// directories are walked; a missing entry, a file where the package
    /// directory should be, and anything resolving outside the project are
    /// not; a symlinked component that stays inside the project is followed.
    #[tokio::test]
    async fn the_store_walk_keeps_inside_the_project() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("project");
        store_entry(&root, "real");
        assert_eq!(copies(&root, "real").await, ["pkg:npm/left-pad@1.3.0"]);
        assert!(copies(&root, "missing").await.is_empty());
        write(
            &root,
            &format!("{VLT_STORE_DIR}/file/node_modules/bund"),
            "not a dir",
        );
        assert!(copies(&root, "file").await.is_empty());

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let outside = tmp.path().join("outside");
            store_entry(&outside, "away");
            // A store entry symlinked inside the project is followed ...
            symlink(
                root.join(VLT_STORE_DIR).join("real"),
                root.join(VLT_STORE_DIR).join("linked"),
            )
            .unwrap();
            assert_eq!(copies(&root, "linked").await, ["pkg:npm/left-pad@1.3.0"]);
            // ... one resolving outside it is not.
            symlink(
                outside.join(VLT_STORE_DIR).join("away"),
                root.join(VLT_STORE_DIR).join("away"),
            )
            .unwrap();
            assert!(copies(&root, "away").await.is_empty());
            // Nor is any entry of a store that is itself a link outside.
            let other = tmp.path().join("other");
            store_entry(&other, "real");
            std::fs::create_dir_all(other.join("x")).unwrap();
            symlink(other.join("node_modules"), other.join("x/node_modules")).unwrap();
            assert!(copies(&other.join("x"), "real").await.is_empty());
        }
    }
}
