//! Recognizing package directories that live in a store shared across
//! projects.
//!
//! Agent-mode apply and rollback commit each file with a stage + `rename(2)`
//! in the file's parent directory. That isolates a hardlinked or symlinked
//! *file* (pnpm's content-addressable `files/`, the bun / uv caches, Go's
//! module cache), but not a package *directory* that is itself a symlink
//! into a store every project on the machine links to: the rename then lands
//! inside the shared directory, patching (or, on rollback, unpatching) every
//! other project that uses it. Two package managers install that way:
//!
//! * **PDM's package cache** (`install.cache = true` with
//!   `install.cache_method = symlink`, PDM 2.0–2.12): `site-packages/<pkg>`
//!   is a directory symlink into `<cache>/packages/<wheel-stem>/lib/<pkg>`.
//!   Each cache entry carries a `referrers` file listing the environments
//!   that use it.
//! * **pnpm's global virtual store** (`enableGlobalVirtualStore`):
//!   `node_modules/<dep>` is a symlink (a junction on Windows) into
//!   `<store>/v<N>/links/…/node_modules/<dep>`, beside the store's
//!   `files/` content directory.
//!
//! Detection is positive and marker-based, on the package directory's real
//! path: a per-project store reached through a symlink (pnpm's
//! `node_modules/.pnpm`, a relocated `virtualStoreDir`, a workspace link)
//! carries neither marker and is patched as before.

use std::path::{Path, PathBuf};

/// The substring every shared-store refusal carries, so callers and tests
/// can recognize it without matching the full sentence.
pub const SHARED_STORE_REFUSAL_MARKER: &str = "shared by other projects";

/// A cross-project store a package directory resolves into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SharedStoreKind {
    /// `<cache>/packages/<wheel-stem>/lib`, PDM's symlink install cache.
    PdmPackageCache,
    /// `<store>/v<N>/links`, pnpm's global virtual store.
    PnpmGlobalVirtualStore,
}

/// Where a package directory really lives, when that is a shared store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedStore {
    pub kind: SharedStoreKind,
    /// The package directory's real (canonical) path.
    pub real_path: PathBuf,
}

impl SharedStore {
    /// The refusal message for `action` ("patch" or "roll back"), naming
    /// the store and how to get a private copy instead.
    pub fn refusal(&self, action: &str) -> String {
        let (what, remedy) = match self.kind {
            SharedStoreKind::PdmPackageCache => (
                "PDM's package cache (install.cache with cache_method = symlink)",
                "run `pdm config install.cache_method hardlink` (or turn \
                 install.cache off) and reinstall the package",
            ),
            SharedStoreKind::PnpmGlobalVirtualStore => (
                "pnpm's global virtual store (enableGlobalVirtualStore)",
                "set enableGlobalVirtualStore to false and reinstall",
            ),
        };
        format!(
            "Refusing to {action} {path}: it is in {what}, which is \
             {SHARED_STORE_REFUSAL_MARKER} on this machine, so the change would \
             reach them too. To patch only this project, {remedy}, or use \
             `scan --mode hosted` / `--mode vendored`",
            path = self.real_path.display(),
        )
    }
}

/// Classify `pkg_path`: `Some` when its real location is inside a shared
/// store (see the module docs). A path that does not exist, or cannot be
/// resolved, is `None`; the normal verify step reports a missing package.
pub async fn shared_store_of(pkg_path: &Path) -> Option<SharedStore> {
    let pkg_path = pkg_path.to_path_buf();
    tokio::task::spawn_blocking(move || shared_store_of_blocking(&pkg_path))
        .await
        .ok()
        .flatten()
}

/// Classify every directory a patch writes into: `pkg_path` itself and
/// the parent of each (normalized, package-relative) file key. The package
/// root is not always the package directory: a PyPI patch is rooted at
/// `site-packages` with keys like `urllib3/response.py`, so the directory
/// symlink into PDM's cache sits *below* the root. A parent that does not
/// exist yet (a patch adding a file under a new subdir) is classified by
/// its nearest existing ancestor at or below `pkg_path`. Keys that escape
/// the package dir are skipped; the caller refuses them on its own.
pub async fn shared_store_of_patch_dirs<'a>(
    pkg_path: &Path,
    file_keys: impl IntoIterator<Item = &'a str>,
) -> Option<SharedStore> {
    let pkg_path = pkg_path.to_path_buf();
    let keys: Vec<String> = file_keys
        .into_iter()
        .map(crate::patch::apply::normalize_file_path)
        .filter(|k| crate::patch::apply::is_safe_relative_subpath(k))
        .map(str::to_string)
        .collect();
    tokio::task::spawn_blocking(move || {
        let mut seen = std::collections::HashSet::new();
        let dirs = std::iter::once(pkg_path.clone()).chain(keys.iter().filter_map(|key| {
            let mut dir = pkg_path.join(key).parent()?.to_path_buf();
            while dir != pkg_path && !dir.exists() {
                dir = dir.parent()?.to_path_buf();
            }
            Some(dir)
        }));
        dirs.filter(|dir| seen.insert(dir.clone()))
            .find_map(|dir| shared_store_of_blocking(&dir))
    })
    .await
    .ok()
    .flatten()
}

fn shared_store_of_blocking(pkg_path: &Path) -> Option<SharedStore> {
    let real = std::fs::canonicalize(pkg_path).ok()?;
    for dir in real.ancestors() {
        let Some(name) = dir.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let parent = dir.parent();

        // pnpm: <store>/v<N>/links, with the store's `files/` beside it.
        if is_pnpm_global_virtual_store_dir(dir) {
            return Some(SharedStore {
                kind: SharedStoreKind::PnpmGlobalVirtualStore,
                real_path: real.clone(),
            });
        }

        // PDM: <cache>/packages/<wheel-stem>/lib/…, the entry carrying its
        // `referrers` registry.
        if name == "lib"
            && dir != real
            && parent.is_some_and(|entry| {
                entry.join("referrers").is_file()
                    && entry
                        .parent()
                        .and_then(|p| p.file_name())
                        .is_some_and(|n| n == "packages")
            })
        {
            return Some(SharedStore {
                kind: SharedStoreKind::PdmPackageCache,
                real_path: real.clone(),
            });
        }
    }
    None
}

/// Whether `dir` is the `links` directory of pnpm's global virtual store:
/// `<store>/v<N>/links`, with the store's `files/` content directory
/// beside it. Callers pass a real (canonical) path.
pub(crate) fn is_pnpm_global_virtual_store_dir(dir: &Path) -> bool {
    let parent = dir.parent();
    dir.file_name().is_some_and(|n| n == "links")
        && parent
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .is_some_and(is_pnpm_store_version_dir)
        && parent.is_some_and(|p| p.join("files").is_dir())
}

/// `v3`, `v10`, `v11`, …: the layout-version directory of a pnpm store.
fn is_pnpm_store_version_dir(name: &str) -> bool {
    name.strip_prefix('v')
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::path::{Path, PathBuf};

    /// `<root>/store/v10/{files,links/@/left-pad/1.3.0/<hash>/node_modules/left-pad}`.
    pub(crate) fn make_pnpm_gvs(root: &Path) -> PathBuf {
        let v = root.join("store").join("v10");
        std::fs::create_dir_all(v.join("files")).unwrap();
        std::fs::create_dir_all(v.join("index")).unwrap();
        let pkg = v
            .join("links")
            .join("@")
            .join("left-pad")
            .join("1.3.0")
            .join("abc123")
            .join("node_modules")
            .join("left-pad");
        std::fs::create_dir_all(&pkg).unwrap();
        pkg
    }

    /// `<root>/pdm-cache/packages/urllib3-1.26.18-py2.py3-none-any/{referrers,lib/urllib3}`.
    pub(crate) fn make_pdm_cache_entry(root: &Path) -> PathBuf {
        let entry = root
            .join("pdm-cache")
            .join("packages")
            .join("urllib3-1.26.18-py2.py3-none-any");
        let pkg = entry.join("lib").join("urllib3");
        std::fs::create_dir_all(&pkg).unwrap();
        std::fs::write(entry.join("referrers"), "/somewhere/else\n").unwrap();
        pkg
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;

    #[tokio::test]
    async fn pnpm_global_virtual_store_is_shared() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = make_pnpm_gvs(dir.path());
        let got = shared_store_of(&pkg).await.expect("shared");
        assert_eq!(got.kind, SharedStoreKind::PnpmGlobalVirtualStore);
        assert_eq!(got.real_path, std::fs::canonicalize(&pkg).unwrap());
    }

    #[tokio::test]
    async fn pdm_package_cache_is_shared() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = make_pdm_cache_entry(dir.path());
        let got = shared_store_of(&pkg).await.expect("shared");
        assert_eq!(got.kind, SharedStoreKind::PdmPackageCache);
        // A file-level entry beside the package (a top-level module) is
        // inside the shared `lib/` too.
        let entry_lib = pkg.parent().unwrap().to_path_buf();
        std::fs::write(entry_lib.join("six.py"), "x").unwrap();
        assert!(shared_store_of(&entry_lib.join("six.py")).await.is_some());
    }

    /// pnpm's per-project virtual store and plain directories carry no
    /// shared-store marker.
    #[tokio::test]
    async fn per_project_layouts_are_not_shared() {
        let dir = tempfile::tempdir().unwrap();
        let pnpm = dir
            .path()
            .join("node_modules")
            .join(".pnpm")
            .join("left-pad@1.3.0")
            .join("node_modules")
            .join("left-pad");
        std::fs::create_dir_all(&pnpm).unwrap();
        assert_eq!(shared_store_of(&pnpm).await, None);

        // A `links` dir without the store's `files/` sibling, or under a
        // non-version parent, is an ordinary directory.
        let links = dir.path().join("v10").join("links").join("pkg");
        std::fs::create_dir_all(&links).unwrap();
        assert_eq!(shared_store_of(&links).await, None);
        let other = dir.path().join("vendor").join("links").join("pkg");
        std::fs::create_dir_all(&other).unwrap();
        std::fs::create_dir_all(dir.path().join("vendor").join("files")).unwrap();
        assert_eq!(shared_store_of(&other).await, None);

        // A site-packages `lib/` without the PDM entry markers.
        let venv = dir
            .path()
            .join(".venv")
            .join("lib")
            .join("python3.11")
            .join("site-packages")
            .join("six");
        std::fs::create_dir_all(&venv).unwrap();
        assert_eq!(shared_store_of(&venv).await, None);
        let no_referrers = dir
            .path()
            .join("packages")
            .join("x-1.0-py3-none-any")
            .join("lib")
            .join("x");
        std::fs::create_dir_all(&no_referrers).unwrap();
        assert_eq!(shared_store_of(&no_referrers).await, None);

        // Missing paths are not classified.
        assert_eq!(shared_store_of(&dir.path().join("missing")).await, None);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symlinked_package_dir_resolves_to_the_store() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = make_pnpm_gvs(dir.path());
        let nm = dir.path().join("project").join("node_modules");
        std::fs::create_dir_all(&nm).unwrap();
        std::os::unix::fs::symlink(&pkg, nm.join("left-pad")).unwrap();
        assert!(shared_store_of(&nm.join("left-pad")).await.is_some());

        // A per-project `.pnpm` link is not shared.
        let private = nm
            .join(".pnpm")
            .join("is-odd@3.0.1")
            .join("node_modules")
            .join("is-odd");
        std::fs::create_dir_all(&private).unwrap();
        std::os::unix::fs::symlink(&private, nm.join("is-odd")).unwrap();
        assert_eq!(shared_store_of(&nm.join("is-odd")).await, None);
    }

    /// A PyPI patch is rooted at `site-packages` (keys `<pkg>/<file>`), so
    /// the directory link into PDM's cache sits below the root and is found
    /// through the keys, including a key under a subdir that does not exist
    /// yet. A top-level module key (`six.py`) is classified by its parent,
    /// `site-packages`, which is private.
    #[cfg(unix)]
    #[tokio::test]
    async fn patch_dirs_find_a_link_below_the_package_root() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = make_pdm_cache_entry(dir.path());
        let site = dir.path().join("venv").join("site-packages");
        std::fs::create_dir_all(&site).unwrap();
        std::os::unix::fs::symlink(&pkg, site.join("urllib3")).unwrap();

        assert_eq!(shared_store_of(&site).await, None);
        for key in ["urllib3/response.py", "urllib3/new/dir/added.py"] {
            let got = shared_store_of_patch_dirs(&site, [key]).await;
            assert_eq!(
                got.map(|s| s.kind),
                Some(SharedStoreKind::PdmPackageCache),
                "{key}"
            );
        }
        assert_eq!(shared_store_of_patch_dirs(&site, ["six.py"]).await, None);
        // An escaping key is ignored here (apply refuses it separately).
        assert_eq!(shared_store_of_patch_dirs(&site, ["../x/y.py"]).await, None);
    }

    #[test]
    fn refusal_names_store_and_remedy() {
        let s = SharedStore {
            kind: SharedStoreKind::PdmPackageCache,
            real_path: PathBuf::from("/c/packages/x/lib/x"),
        };
        let msg = s.refusal("patch");
        assert!(msg.contains(SHARED_STORE_REFUSAL_MARKER), "{msg}");
        assert!(msg.contains("/c/packages/x/lib/x"), "{msg}");
        assert!(msg.contains("install.cache_method hardlink"), "{msg}");
        let s = SharedStore {
            kind: SharedStoreKind::PnpmGlobalVirtualStore,
            real_path: PathBuf::from("/s/v10/links/x"),
        };
        assert!(s.refusal("roll back").contains("enableGlobalVirtualStore"));
    }
}
