//! Recognizing package directories that live in a store shared across
//! projects.
//!
//! Agent-mode apply and rollback commit each file with a stage + `rename(2)`
//! in the file's parent directory. That isolates a hardlinked or symlinked
//! *file* (pnpm's content-addressable `files/`, the bun / uv caches, Go's
//! module cache), but not a package *directory* that is itself a symlink
//! into a store every project on the machine links to: the rename then lands
//! inside the shared directory, patching (or, on rollback, unpatching) every
//! other project that uses it. Three package managers install that way:
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
//! * **Bun's global store** (`[install] globalStore = true` in
//!   `bunfig.toml`, or `BUN_INSTALL_GLOBAL_STORE=1`, Bun >= 1.3.14, isolated
//!   linker): each `node_modules/.bun/<entry>` is a symlink into
//!   `<cache>/links/<entry>-<hash>/node_modules/<name>` in Bun's install
//!   cache.
//!
//! Detection is positive and marker-based, on the package directory's real
//! path: a per-project store reached through a symlink (pnpm's
//! `node_modules/.pnpm`, a relocated `virtualStoreDir`, a member's link
//! into the root store) carries neither marker and is patched as before.
//!
//! One more kind of link is not ours to write through, though no other
//! project shares it: a `node_modules/<name>` entry that resolves outside
//! every `node_modules` tree. Package managers link that way only to
//! first-party source (an npm / yarn / pnpm / bun workspace member, a
//! `file:` or `link:` directory dependency, an `npm link` target), never to
//! an installed copy, so writing through it would overwrite the user's own
//! code with upstream bytes that no reinstall gives back (#626). Store links
//! (pnpm's `.pnpm`, Yarn's `.store`, vlt's `.vlt`, bun's `.bun`, npm's
//! linked `.store`) resolve inside a `node_modules` tree; the one exception,
//! Yarn's pnpm-linker store relocated by `pnpmStoreFolder`, is recognized
//! only for an active Yarn pnpm install and a registry entry's layout.

use std::path::{Path, PathBuf};

/// The substring every shared-store refusal carries, so callers and tests
/// can recognize it without matching the full sentence.
pub const SHARED_STORE_REFUSAL_MARKER: &str = "shared by other projects";

/// The substring every linked-source refusal carries (see
/// [`SharedStoreKind::LinkedSource`]).
pub const LINKED_SOURCE_REFUSAL_MARKER: &str = "outside every node_modules tree";

/// A cross-project store a package directory resolves into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SharedStoreKind {
    /// `<cache>/packages/<wheel-stem>/lib`, PDM's symlink install cache.
    PdmPackageCache,
    /// `<store>/v<N>/links`, pnpm's global virtual store.
    PnpmGlobalVirtualStore,
    /// `<cache>/links/<entry>-<hash>`, Bun's global store.
    BunGlobalStore,
    /// A `node_modules` entry linked to first-party source outside every
    /// `node_modules` tree (a workspace member, a `file:` / `link:`
    /// directory dependency, an `npm link` target).
    LinkedSource,
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
            SharedStoreKind::BunGlobalStore => (
                "Bun's global store (install.globalStore / BUN_INSTALL_GLOBAL_STORE)",
                "set `globalStore = false` under `[install]` in bunfig.toml (and unset \
                 BUN_INSTALL_GLOBAL_STORE), then reinstall",
            ),
            SharedStoreKind::LinkedSource => {
                return format!(
                    "Refusing to {action} {path}: node_modules links to it, but it is \
                     {LINKED_SOURCE_REFUSAL_MARKER} (a workspace member, a `file:` or \
                     `link:` directory dependency, or an `npm link` target), so it is \
                     first-party source that no reinstall restores, not an installed \
                     copy of the registry package. Patch that source directly, or \
                     install the package from the registry instead of linking it",
                    path = self.real_path.display(),
                );
            }
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

        // Bun: <cache>/links/<entry>-<hash>/node_modules/<name>/….
        if name == "links" && real.strip_prefix(dir).is_ok_and(is_bun_global_store_path) {
            return Some(SharedStore {
                kind: SharedStoreKind::BunGlobalStore,
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
    linked_source_of(pkg_path, real)
}

/// [`SharedStoreKind::LinkedSource`]: `pkg_path` is spelled as a
/// `node_modules` entry (`node_modules/<name>` or
/// `node_modules/@scope/<name>`), yet its real path `real` is neither below
/// that `node_modules` (a real dir, or a link into its own store) nor below
/// any other `node_modules` (a workspace member's link into the root store).
fn linked_source_of(pkg_path: &Path, real: PathBuf) -> Option<SharedStore> {
    let parent = pkg_path.parent()?;
    let node_modules = if is_node_modules(parent) {
        parent
    } else {
        let scope = parent.file_name()?.to_str()?;
        let grandparent = parent.parent()?;
        if !scope.starts_with('@') || !is_node_modules(grandparent) {
            return None;
        }
        grandparent
    };
    let real_node_modules = std::fs::canonicalize(node_modules).ok()?;
    if real.starts_with(&real_node_modules)
        || real.components().any(|c| c.as_os_str() == "node_modules")
        || in_yarn_pnpm_store(node_modules, &real)
    {
        return None;
    }
    Some(SharedStore {
        kind: SharedStoreKind::LinkedSource,
        real_path: real,
    })
}

/// Whether `real` is an installed registry entry of Yarn's pnpm linker
/// store relocated outside `node_modules` (`nodeLinker: pnpm` with
/// `pnpmStoreFolder: .cache/.store`), not first-party source. Every part of
/// that must hold, so that an inactive or stray `.yarnrc.yml` (an npm
/// workspace carrying `pnpmStoreFolder: packages`) can never admit a
/// workspace member:
///
/// * the project is a Yarn project: a `yarn.lock` at or above it;
/// * the active linker is pnpm: the nearest `.yarnrc.yml` at or above the
///   project that sets `nodeLinker` sets it to `pnpm`;
/// * `<store>` is the `pnpmStoreFolder` of the nearest `.yarnrc.yml` that
///   sets it, resolved against that file's directory as Yarn does, and does
///   not contain the project (`pnpmStoreFolder: .`);
/// * `real` is exactly `<store>/<entry>/package`, where `<entry>` is Yarn's
///   slug of a registry locator ([`is_yarn_copy_slug`]): the layout
///   Yarn gives a hard (installed) package, never a workspace.
fn in_yarn_pnpm_store(node_modules: &Path, real: &Path) -> bool {
    let Some(project) = node_modules.parent() else {
        return false;
    };
    if !project
        .ancestors()
        .any(|dir| dir.join("yarn.lock").is_file())
    {
        return false;
    }
    let rcs: Vec<(&Path, String)> = project
        .ancestors()
        .filter_map(|dir| {
            let rc = crate::utils::fs::read_regular_to_string_sync(&dir.join(".yarnrc.yml"));
            rc.ok().map(|rc| (dir, rc))
        })
        .collect();
    let nearest = |key: &str| {
        rcs.iter().find_map(|(dir, rc)| {
            crate::vendor::yarn_berry_lock::yarnrc_scalar(rc, key).map(|v| (*dir, v.to_string()))
        })
    };
    if nearest("nodeLinker").is_none_or(|(_, linker)| linker != "pnpm") {
        return false;
    }
    let Some((rc_dir, value)) = nearest("pnpmStoreFolder").filter(|(_, v)| !v.is_empty()) else {
        return false;
    };
    let (Ok(store), Ok(project)) = (
        std::fs::canonicalize(rc_dir.join(value)),
        std::fs::canonicalize(project),
    ) else {
        return false;
    };
    if project.starts_with(&store) {
        return false;
    }
    let Ok(rest) = real.strip_prefix(&store) else {
        return false;
    };
    let mut parts = rest.components();
    let entry = parts.next().and_then(|c| c.as_os_str().to_str());
    entry.is_some_and(is_yarn_copy_slug)
        && parts.next().is_some_and(|c| c.as_os_str() == "package")
        && parts.next().is_none()
}

/// Yarn's slug of a hard (installed) package's store entry: the
/// locator's ident, its protocol, and ten hex digits of its hash —
/// `left-pad-npm-1.3.0-0123456789` (an `npm:` locator also carries its
/// version), `react-dom-virtual-685e277730` (instantiated for its peers),
/// `@acme-tool-file-0123456789` (a `file:` tarball). Only protocols Yarn
/// installs as a copy qualify; `workspace:`, `portal:` and `link:` link to
/// their source and never get a store entry, and an unknown protocol is
/// refused.
fn is_yarn_copy_slug(entry: &str) -> bool {
    const COPY_PROTOCOLS: [&str; 7] =
        ["virtual", "file", "patch", "http", "https", "git", "github"];
    let Some((head, hash)) = entry.rsplit_once('-') else {
        return false;
    };
    if hash.len() != 10 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }
    if head
        .split_once("-npm-")
        .is_some_and(|(ident, version)| !ident.is_empty() && !version.is_empty())
    {
        return true;
    }
    head.rsplit_once('-')
        .is_some_and(|(ident, protocol)| !ident.is_empty() && COPY_PROTOCOLS.contains(&protocol))
}

fn is_node_modules(dir: &Path) -> bool {
    dir.file_name().is_some_and(|n| n == "node_modules")
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

/// Whether `rest`, a real path below a `links` dir, is a package inside an
/// entry of Bun's global store: `<entry>-<hash>/node_modules/<name>/…`,
/// where `<entry>` is the `.bun` entry name the project links it under
/// (`<name>@<version>`, a scoped name's `/` written `+`, or `<name>@` and a
/// mangled tarball URL), `<hash>` is hex, and `<name>` is the package the
/// entry name starts with. A bundled dependency nested inside the package
/// is in the same entry, so it is matched too.
fn is_bun_global_store_path(rest: &Path) -> bool {
    let mut parts = rest.components().map(|c| c.as_os_str().to_str());
    let (Some(Some(entry)), Some(Some("node_modules")), Some(Some(first))) =
        (parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    if !entry
        .rsplit_once('-')
        .is_some_and(|(_, hash)| is_bun_store_hash(hash))
    {
        return false;
    }
    let name = if first.starts_with('@') {
        let Some(Some(leaf)) = parts.next() else {
            return false;
        };
        format!("{first}+{leaf}")
    } else {
        first.to_string()
    };
    entry
        .strip_prefix(&name)
        .is_some_and(|tail| tail.starts_with('@'))
}

/// Whether `real`, a real (canonical) directory, is the Bun global store
/// entry a `node_modules/.bun/<entry_name>` link points to:
/// `<cache>/links/<entry_name>-<hash>`.
pub(crate) fn is_bun_global_store_entry(real: &Path, entry_name: &str) -> bool {
    real.parent()
        .and_then(Path::file_name)
        .is_some_and(|n| n == "links")
        && real
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| n.strip_prefix(entry_name))
            .and_then(|tail| tail.strip_prefix('-'))
            .is_some_and(is_bun_store_hash)
}

/// The hex hash Bun appends to a global store entry's name.
fn is_bun_store_hash(hash: &str) -> bool {
    (1..=16).contains(&hash.len()) && hash.bytes().all(|b| b.is_ascii_hexdigit())
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

    /// `<root>/bun-cache/links/<entry>-<hash>/node_modules/<name>`, beside
    /// the cache's own `<name>@<version>@@@1` extraction, for `name`
    /// (`left-pad`, or scoped `@scope/leaf`) at `version`.
    pub(crate) fn make_bun_global_store_entry(root: &Path, name: &str, version: &str) -> PathBuf {
        let cache = root.join("bun-cache");
        let entry = format!("{}@{version}", name.replace('/', "+"));
        std::fs::create_dir_all(cache.join(format!("{entry}@@@1"))).unwrap();
        let pkg = cache
            .join("links")
            .join(format!("{entry}-6a490709ba3c5c8f"))
            .join("node_modules")
            .join(name);
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

    /// #635: with Bun's global store each `node_modules/.bun/<entry>` is a
    /// link into `<cache>/links/<entry>-<hash>`, shared by every project on
    /// the machine. A package reached through that link (the importer's
    /// `node_modules/<name>` or the `.bun` entry itself), scoped or not, a
    /// file below it, and a bundled dependency inside it are all refused.
    #[cfg(unix)]
    #[tokio::test]
    async fn bun_global_store_is_shared() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let nm = dir.path().join("proj").join("node_modules");
        let bun = nm.join(".bun");
        std::fs::create_dir_all(&bun).unwrap();
        std::fs::create_dir_all(nm.join("@isaacs")).unwrap();
        for (name, link) in [
            ("left-pad", nm.join("left-pad")),
            (
                "@isaacs/string-locale-compare",
                nm.join("@isaacs/string-locale-compare"),
            ),
        ] {
            let pkg = make_bun_global_store_entry(dir.path(), name, "1.3.0");
            let entry = pkg
                .ancestors()
                .find(|a| a.parent().and_then(Path::file_name) == Some("links".as_ref()))
                .unwrap();
            let bun_entry = bun.join(format!("{}@1.3.0", name.replace('/', "+")));
            symlink(entry, &bun_entry).unwrap();
            let via_bun = bun_entry.join("node_modules").join(name);
            symlink(&via_bun, &link).unwrap();
            std::fs::create_dir_all(pkg.join("node_modules").join("bundled")).unwrap();
            for path in [
                link.clone(),
                via_bun.clone(),
                pkg.join("node_modules/bundled"),
            ] {
                let got = shared_store_of(&path).await.expect("shared");
                assert_eq!(
                    got.kind,
                    SharedStoreKind::BunGlobalStore,
                    "{}",
                    path.display()
                );
            }
            let got = shared_store_of_patch_dirs(&link, ["lib/new/a.js"]).await;
            assert_eq!(got.map(|s| s.kind), Some(SharedStoreKind::BunGlobalStore));
        }
    }

    /// Bun's per-project isolated store (`node_modules/.bun/<entry>` a real
    /// dir), and `links` dirs that do not hold a store entry's package, are
    /// not shared.
    #[tokio::test]
    async fn bun_per_project_store_is_not_shared() {
        let dir = tempfile::tempdir().unwrap();
        let private = dir
            .path()
            .join("node_modules/.bun/left-pad@1.3.0/node_modules/left-pad");
        std::fs::create_dir_all(&private).unwrap();
        assert_eq!(shared_store_of(&private).await, None);
        for not_entry in [
            // No hex hash after the entry name.
            "links/left-pad@1.3.0/node_modules/left-pad",
            "links/left-pad@1.3.0-xyz/node_modules/left-pad",
            // The package is not the one the entry names.
            "links/is-odd@3.0.1-6a490709ba3c5c8f/node_modules/left-pad",
            "links/left-pad-6a490709ba3c5c8f/node_modules/left-pad",
            // Not under the entry's `node_modules`.
            "links/left-pad@1.3.0-6a490709ba3c5c8f/left-pad",
            // A package that is itself named `links`.
            "node_modules/links/lib",
        ] {
            let path = dir.path().join("x").join(not_entry);
            std::fs::create_dir_all(&path).unwrap();
            assert_eq!(shared_store_of(&path).await, None, "{not_entry}");
        }
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

    /// #626: a `node_modules` entry linked to first-party source (a
    /// workspace member, a `file:` / `link:` dir, an `npm link` target,
    /// scoped or not, global prefix included) is refused.
    #[cfg(unix)]
    #[tokio::test]
    async fn node_modules_link_to_first_party_source_is_refused() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("ws");
        let nm = root.join("node_modules");
        std::fs::create_dir_all(nm.join("@acme")).unwrap();
        let member = root.join("packages").join("left-pad");
        let scoped_member = root.join("packages").join("util");
        let checkout = dir.path().join("dev").join("is-odd");
        for d in [&member, &scoped_member, &checkout] {
            std::fs::create_dir_all(d).unwrap();
        }
        // Workspace member / `file:` dep, a scoped one, an `npm link` target.
        symlink("../packages/left-pad", nm.join("left-pad")).unwrap();
        symlink("../../packages/util", nm.join("@acme").join("util")).unwrap();
        symlink(&checkout, nm.join("is-odd")).unwrap();
        // `npm link` from the global prefix: lib/node_modules/<name> -> checkout.
        let global_nm = dir.path().join("prefix").join("lib").join("node_modules");
        std::fs::create_dir_all(&global_nm).unwrap();
        symlink(&checkout, global_nm.join("is-odd")).unwrap();

        for (pkg, real) in [
            (nm.join("left-pad"), &member),
            (nm.join("@acme").join("util"), &scoped_member),
            (nm.join("is-odd"), &checkout),
            (global_nm.join("is-odd"), &checkout),
        ] {
            let got = shared_store_of(&pkg).await.expect("refused");
            assert_eq!(got.kind, SharedStoreKind::LinkedSource, "{}", pkg.display());
            assert_eq!(got.real_path, std::fs::canonicalize(real).unwrap());
            // Classified through the patch's own file keys too.
            let got = shared_store_of_patch_dirs(&pkg, ["index.js", "lib/a.js"]).await;
            assert_eq!(got.map(|s| s.kind), Some(SharedStoreKind::LinkedSource));
        }
    }

    /// Links into a store inside a `node_modules` tree, and real dirs,
    /// are installed copies and stay patchable.
    #[cfg(unix)]
    #[tokio::test]
    async fn node_modules_store_links_and_real_dirs_are_not_refused() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("ws");
        let nm = root.join("node_modules");
        // A real dir, plain and scoped.
        std::fs::create_dir_all(nm.join("left-pad")).unwrap();
        std::fs::create_dir_all(nm.join("@types").join("node")).unwrap();
        // A member's link into the root `.pnpm` store.
        let store_pkg = nm
            .join(".pnpm")
            .join("is-number@6.0.0")
            .join("node_modules")
            .join("is-number");
        std::fs::create_dir_all(&store_pkg).unwrap();
        let member_nm = root.join("packages").join("a").join("node_modules");
        std::fs::create_dir_all(&member_nm).unwrap();
        symlink(&store_pkg, member_nm.join("is-number")).unwrap();
        // Yarn's pnpm linker: node_modules/<name> -> node_modules/.store/<entry>/package.
        let yarn_pkg = nm.join(".store").join("is-odd-npm-3.0.1-x").join("package");
        std::fs::create_dir_all(&yarn_pkg).unwrap();
        symlink(".store/is-odd-npm-3.0.1-x/package", nm.join("is-odd")).unwrap();
        // A node_modules that is itself a link to a dir not named node_modules.
        let cache_nm = dir.path().join("cache").join("modules");
        let cache_store_pkg = cache_nm.join(".store").join("e").join("package");
        std::fs::create_dir_all(cache_nm.join("six")).unwrap();
        std::fs::create_dir_all(&cache_store_pkg).unwrap();
        symlink(".store/e/package", cache_nm.join("ms")).unwrap();
        let linked_root = dir.path().join("linked");
        std::fs::create_dir_all(&linked_root).unwrap();
        symlink(&cache_nm, linked_root.join("node_modules")).unwrap();

        for pkg in [
            nm.join("left-pad"),
            nm.join("@types").join("node"),
            store_pkg.clone(),
            member_nm.join("is-number"),
            nm.join("is-odd"),
            linked_root.join("node_modules").join("six"),
            linked_root.join("node_modules").join("ms"),
        ] {
            assert_eq!(shared_store_of(&pkg).await, None, "{}", pkg.display());
        }
        // A first-party dir that is not spelled as a node_modules entry
        // (a PyPI site-packages root, a cargo vendor dir) is not classified.
        assert_eq!(shared_store_of(&root.join("packages")).await, None);
    }

    /// Yarn's pnpm linker with a relocated `pnpmStoreFolder` links
    /// `node_modules/<name>` to `<store>/<entry>/package` outside every
    /// `node_modules`: an installed copy, still patchable. Only an active
    /// Yarn pnpm install qualifies, and only a registry entry's `package`
    /// dir, so the setting can never admit first-party source.
    #[cfg(unix)]
    #[tokio::test]
    async fn relocated_yarn_pnpm_store_is_not_refused() {
        use std::os::unix::fs::symlink;
        let is_linked_source = |pkg: PathBuf| async move {
            shared_store_of(&pkg).await.map(|s| s.kind) == Some(SharedStoreKind::LinkedSource)
        };
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("ws");
        let nm = root.join("node_modules");
        std::fs::create_dir_all(&nm).unwrap();
        let store = root.join(".cache").join(".store");
        let entry = store.join("left-pad-npm-1.3.0-0123456789").join("package");
        std::fs::create_dir_all(&entry).unwrap();
        symlink(&entry, nm.join("left-pad")).unwrap();
        // A registry package instantiated for its peers (`virtual:`).
        let virtual_entry = store.join("react-dom-virtual-685e277730").join("package");
        std::fs::create_dir_all(&virtual_entry).unwrap();
        symlink(&virtual_entry, nm.join("react-dom")).unwrap();
        // A scoped `file:` tarball dependency, installed as a copy.
        let tarball = store.join("@acme-tool-file-0123456789").join("package");
        std::fs::create_dir_all(&tarball).unwrap();
        std::fs::create_dir_all(nm.join("@acme")).unwrap();
        symlink(&tarball, nm.join("@acme").join("tool")).unwrap();
        // A workspace member linked beside it stays refused.
        let member = root.join("packages").join("a");
        std::fs::create_dir_all(&member).unwrap();
        symlink(&member, nm.join("a")).unwrap();
        // Store links that are not a registry entry's `package` dir.
        symlink(store.join("left-pad-npm-1.3.0-0123456789"), nm.join("odd")).unwrap();
        let soft = store
            .join("b-workspace-packages-b-0123456789")
            .join("package");
        std::fs::create_dir_all(&soft).unwrap();
        symlink(&soft, nm.join("b")).unwrap();
        let refused = [nm.join("a"), nm.join("odd"), nm.join("b")];

        // Without a Yarn pnpm install, the relocated store is not recognized.
        assert!(is_linked_source(nm.join("left-pad")).await);
        std::fs::write(
            dir.path().join(".yarnrc.yml"),
            "nodeLinker: pnpm\npnpmStoreFolder: \"ws/.cache/.store\"\n",
        )
        .unwrap();
        assert!(is_linked_source(nm.join("left-pad")).await, "no yarn.lock");

        // With a yarn.lock, an ancestor's settings resolve against its dir.
        std::fs::write(root.join("yarn.lock"), "").unwrap();
        assert_eq!(shared_store_of(&nm.join("left-pad")).await, None);
        assert_eq!(shared_store_of(&nm.join("react-dom")).await, None);
        assert_eq!(shared_store_of(&nm.join("@acme").join("tool")).await, None);
        // The project's own `.yarnrc.yml` wins over the ancestor's.
        std::fs::write(
            root.join(".yarnrc.yml"),
            "pnpmStoreFolder: .cache/.store # relocated\n",
        )
        .unwrap();
        assert_eq!(shared_store_of(&nm.join("left-pad")).await, None);
        for pkg in &refused {
            assert!(is_linked_source(pkg.clone()).await, "{}", pkg.display());
        }
        // An inactive linker setting turns the exception off.
        std::fs::write(
            root.join(".yarnrc.yml"),
            "nodeLinker: node-modules\npnpmStoreFolder: .cache/.store\n",
        )
        .unwrap();
        assert!(
            is_linked_source(nm.join("left-pad")).await,
            "node-modules linker"
        );
        // A store that contains the project is not honored.
        std::fs::write(
            root.join(".yarnrc.yml"),
            "nodeLinker: pnpm\npnpmStoreFolder: .\n",
        )
        .unwrap();
        assert!(
            is_linked_source(nm.join("left-pad")).await,
            "store contains project"
        );
    }

    /// The review reproduction: an npm workspace whose stray `.yarnrc.yml`
    /// names its `packages/` dir as a pnpm store. npm ignores the file, and
    /// `node_modules/left-pad` is the first-party member `packages/foo/package`.
    #[cfg(unix)]
    #[tokio::test]
    async fn stray_yarn_store_setting_does_not_admit_an_npm_workspace_member() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let nm = root.join("node_modules");
        std::fs::create_dir_all(&nm).unwrap();
        std::fs::write(root.join("package-lock.json"), "{}").unwrap();
        std::fs::write(
            root.join(".yarnrc.yml"),
            "nodeLinker: node-modules\npnpmStoreFolder: packages\n",
        )
        .unwrap();
        let member = root.join("packages").join("foo").join("package");
        std::fs::create_dir_all(&member).unwrap();
        symlink(&member, nm.join("left-pad")).unwrap();
        let named = root
            .join("packages")
            .join("left-pad-npm-1.3.0-0123456789")
            .join("package");
        std::fs::create_dir_all(&named).unwrap();
        symlink(&named, nm.join("named")).unwrap();
        for pkg in [nm.join("left-pad"), nm.join("named")] {
            assert_eq!(
                shared_store_of(&pkg).await.map(|s| s.kind),
                Some(SharedStoreKind::LinkedSource),
                "{}",
                pkg.display()
            );
        }
        // Even an active-looking setting needs a yarn.lock and a registry slug.
        std::fs::write(
            root.join(".yarnrc.yml"),
            "nodeLinker: pnpm\npnpmStoreFolder: packages\n",
        )
        .unwrap();
        assert_eq!(
            shared_store_of(&nm.join("left-pad")).await.map(|s| s.kind),
            Some(SharedStoreKind::LinkedSource)
        );
    }

    #[test]
    fn yarn_copy_slugs() {
        for ok in [
            "left-pad-npm-1.3.0-0123456789",
            "@types-node-npm-20.1.0-abcdef0123",
            "react-dom-virtual-685e277730",
            "@emotion-react-virtual-0123456789",
            "@acme-tool-file-0123456789",
            "left-pad-patch-0123456789",
            "left-pad-https-0123456789",
        ] {
            assert!(is_yarn_copy_slug(ok), "{ok}");
        }
        for bad in [
            "package",
            "foo",
            "left-pad-npm-1.3.0-x",
            "left-pad-npm-1.3.0-012345678",
            "left-pad-npm-1.3.0-0123456789a",
            "b-workspace-packages-b-0123456789",
            "-npm-1.0.0-0123456789",
            "-virtual-0123456789",
            "react-dom-virtual-x",
            "b-workspace-0123456789",
            "b-portal-0123456789",
            "b-link-0123456789",
            "b-exotic-0123456789",
            "-file-0123456789",
        ] {
            assert!(!is_yarn_copy_slug(bad), "{bad}");
        }
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
        let s = SharedStore {
            kind: SharedStoreKind::BunGlobalStore,
            real_path: PathBuf::from("/c/links/x@1.0.0-abc/node_modules/x"),
        };
        let msg = s.refusal("patch");
        assert!(msg.contains(SHARED_STORE_REFUSAL_MARKER), "{msg}");
        assert!(msg.contains("globalStore = false"), "{msg}");
        let s = SharedStore {
            kind: SharedStoreKind::LinkedSource,
            real_path: PathBuf::from("/ws/packages/left-pad"),
        };
        let msg = s.refusal("patch");
        assert!(msg.contains(LINKED_SOURCE_REFUSAL_MARKER), "{msg}");
        assert!(msg.contains("/ws/packages/left-pad"), "{msg}");
        assert!(!msg.contains(SHARED_STORE_REFUSAL_MARKER), "{msg}");
    }
}
