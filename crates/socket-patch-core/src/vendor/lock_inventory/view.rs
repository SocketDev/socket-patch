//! Where the registry views read a project from: the filesystem
//! ([`ProjectView::Disk`]) or an in-memory file map
//! ([`ProjectView::Memory`]) handed in by a host that never materializes
//! the repository (the hosted in-memory engine). The disk variant calls the
//! plain FIFO-safe filesystem readers; the snapshot variant
//! ([`ProjectView::Snapshot`]) is the disk variant with each file's
//! content read at most once, so every reader of one run (the lock
//! inventory, lockfile discovery) sees the same bytes.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::Path;
use std::sync::Arc;

use crate::constants::npm_family::{BUN_LOCK, BUN_LOCKB, NPM_LOCKS, PNPM_LOCK, VLT_LOCK};
use crate::formats::pnpm::{sniff_lock_grammar, PnpmLockGrammar};
use crate::formats::yarn::{sniff_grammar, YarnLockGrammar, UNIDENTIFIED_DETAIL};
use crate::utils::fs::{read_regular_to_bytes, read_regular_to_string};
use crate::vendor::npm_flavor::NpmLockFlavor;
use crate::vendor::VendorWarning;

/// One in-memory file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemoryEntry {
    /// UTF-8 content.
    Text(Arc<str>),
    /// Raw bytes (e.g. `bun.lockb`).
    Binary(Arc<[u8]>),
    /// Known to exist, content not provided (presence-only markers, files
    /// the host skipped as oversize, binary, or LFS pointers).
    Present,
    /// A symbolic link: exists, never readable, never writable.
    Symlink,
}

/// A project's files, keyed by `/`-separated project-relative path.
/// Directories are implied by the keys.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MemoryProject {
    entries: BTreeMap<String, MemoryEntry>,
}

impl MemoryProject {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, rel: impl Into<String>, entry: MemoryEntry) {
        self.entries.insert(rel.into(), entry);
    }

    #[cfg(test)]
    pub(crate) fn insert_text(&mut self, rel: impl Into<String>, text: impl Into<Arc<str>>) {
        self.insert(rel, MemoryEntry::Text(text.into()));
    }

    #[cfg(test)]
    pub(crate) fn insert_present(&mut self, rel: impl Into<String>) {
        self.insert(rel, MemoryEntry::Present);
    }

    pub fn remove(&mut self, rel: &str) -> Option<MemoryEntry> {
        self.entries.remove(rel)
    }

    pub fn get(&self, rel: &str) -> Option<&MemoryEntry> {
        self.entries.get(rel)
    }

    pub fn contains(&self, rel: &str) -> bool {
        self.entries.contains_key(rel)
    }

    pub fn text(&self, rel: &str) -> Option<&str> {
        match self.entries.get(rel)? {
            MemoryEntry::Text(text) => Some(text),
            _ => None,
        }
    }

    pub fn is_symlink(&self, rel: &str) -> bool {
        matches!(self.entries.get(rel), Some(MemoryEntry::Symlink))
    }

    pub(crate) fn entries(&self) -> impl Iterator<Item = (&str, &MemoryEntry)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v))
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether `rel` is an implied directory (some key lives under it).
    /// The project root (`""`) is always a directory.
    pub fn is_dir(&self, rel: &str) -> bool {
        if rel.is_empty() {
            return true;
        }
        let prefix = format!("{rel}/");
        self.entries
            .range(prefix.clone()..)
            .next()
            .is_some_and(|(k, _)| k.starts_with(&prefix))
    }

    /// The direct children of directory `rel`, sorted: `(name, is_dir)`.
    pub fn children(&self, rel: &str) -> Vec<(String, bool)> {
        let prefix = if rel.is_empty() {
            String::new()
        } else {
            format!("{rel}/")
        };
        let mut files: BTreeSet<String> = BTreeSet::new();
        let mut dirs: BTreeSet<String> = BTreeSet::new();
        for key in self
            .entries
            .range(prefix.clone()..)
            .map(|(k, _)| k)
            .take_while(|k| k.starts_with(&prefix))
        {
            let rest = &key[prefix.len()..];
            match rest.split_once('/') {
                Some((dir, _)) => {
                    dirs.insert(dir.to_string());
                }
                None => {
                    files.insert(rest.to_string());
                }
            }
        }
        let mut out: Vec<(String, bool)> = files
            .into_iter()
            .filter(|f| !dirs.contains(f))
            .map(|f| (f, false))
            .collect();
        out.extend(dirs.into_iter().map(|d| (d, true)));
        out.sort();
        out
    }

    fn read_bytes(&self, rel: &str) -> io::Result<Vec<u8>> {
        match self.entries.get(rel) {
            Some(MemoryEntry::Text(text)) => Ok(text.as_bytes().to_vec()),
            Some(MemoryEntry::Binary(bytes)) => Ok(bytes.to_vec()),
            Some(MemoryEntry::Present) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "file content was not provided",
            )),
            Some(MemoryEntry::Symlink) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "is a symbolic link",
            )),
            None if self.is_dir(rel) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not a regular file",
            )),
            None => Err(io::Error::new(io::ErrorKind::NotFound, "not found")),
        }
    }

    fn read_text(&self, rel: &str) -> io::Result<String> {
        match self.entries.get(rel) {
            Some(MemoryEntry::Text(text)) => Ok(text.to_string()),
            Some(MemoryEntry::Binary(bytes)) => String::from_utf8(bytes.to_vec()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "stream did not contain valid UTF-8",
                )
            }),
            _ => self.read_bytes(rel).map(|_| String::new()),
        }
    }
}

/// A directory entry as the registry views need it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntryInfo {
    pub name: String,
    /// A real directory (a symbolic link to one is not).
    pub is_dir: bool,
}

/// Cached reads by root-relative path: the content, or the error kind and
/// message of the failed read.
type ReadCache = std::collections::HashMap<String, Result<Arc<[u8]>, (io::ErrorKind, String)>>;

/// A read-through cache over the files under `root`: the first read of a
/// path hits the disk, later ones return the same content (or the same
/// error). Everything that is not a content read (existence, file type,
/// directory listings, the disk-only probes) goes to the disk directly.
#[derive(Debug)]
pub struct DiskSnapshot<'a> {
    pub root: &'a Path,
    reads: std::sync::Mutex<ReadCache>,
}

impl<'a> DiskSnapshot<'a> {
    pub fn new(root: &'a Path) -> Self {
        Self {
            root,
            reads: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, ReadCache> {
        self.reads
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn cached(&self, rel: &str) -> Option<io::Result<Arc<[u8]>>> {
        self.lock().get(rel).map(|r| match r {
            Ok(bytes) => Ok(Arc::clone(bytes)),
            Err((kind, msg)) => Err(io::Error::new(*kind, msg.clone())),
        })
    }

    fn remember(&self, rel: &str, read: &io::Result<Vec<u8>>) {
        let entry = match read {
            Ok(bytes) => Ok(Arc::<[u8]>::from(bytes.as_slice())),
            Err(e) => Err((e.kind(), e.to_string())),
        };
        self.lock().insert(rel.to_string(), entry);
    }

    async fn read_bytes(&self, rel: &str) -> io::Result<Vec<u8>> {
        if let Some(hit) = self.cached(rel) {
            return hit.map(|b| b.to_vec());
        }
        let read = read_regular_to_bytes(&self.root.join(rel)).await;
        self.remember(rel, &read);
        read
    }
}

fn utf8(bytes: Vec<u8>) -> io::Result<String> {
    String::from_utf8(bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Where the registry views read the project from.
#[derive(Debug, Clone, Copy)]
pub enum ProjectView<'a> {
    Disk(&'a Path),
    Memory(&'a MemoryProject),
    /// The disk under a per-run read cache.
    Snapshot(&'a DiskSnapshot<'a>),
}

impl ProjectView<'_> {
    /// FIFO-safe regular-file text read.
    pub async fn read_text(&self, rel: &str) -> io::Result<String> {
        match self {
            ProjectView::Disk(root) => read_regular_to_string(&root.join(rel)).await,
            ProjectView::Memory(project) => project.read_text(rel),
            ProjectView::Snapshot(snap) => match snap.cached(rel) {
                Some(hit) => hit.and_then(|b| utf8(b.to_vec())),
                None => {
                    let read = read_regular_to_string(&snap.root.join(rel)).await;
                    snap.remember(
                        rel,
                        &read
                            .as_ref()
                            .map(|t| t.as_bytes().to_vec())
                            .map_err(|e| io::Error::new(e.kind(), e.to_string())),
                    );
                    read
                }
            },
        }
    }

    /// FIFO-safe regular-file byte read.
    pub async fn read_bytes(&self, rel: &str) -> io::Result<Vec<u8>> {
        match self {
            ProjectView::Disk(root) => read_regular_to_bytes(&root.join(rel)).await,
            ProjectView::Memory(project) => project.read_bytes(rel),
            ProjectView::Snapshot(snap) => snap.read_bytes(rel).await,
        }
    }

    /// `metadata` (follows links) succeeds.
    pub async fn exists(&self, rel: &str) -> bool {
        match self {
            ProjectView::Disk(root) | ProjectView::Snapshot(DiskSnapshot { root, .. }) => {
                tokio::fs::metadata(root.join(rel)).await.is_ok()
            }
            ProjectView::Memory(project) => project.contains(rel) || project.is_dir(rel),
        }
    }

    /// `symlink_metadata` (does not follow links) succeeds.
    pub async fn exists_no_follow(&self, rel: &str) -> bool {
        match self {
            ProjectView::Disk(root) | ProjectView::Snapshot(DiskSnapshot { root, .. }) => {
                tokio::fs::symlink_metadata(root.join(rel)).await.is_ok()
            }
            ProjectView::Memory(project) => project.contains(rel) || project.is_dir(rel),
        }
    }

    /// A regular file (following links on disk).
    pub fn is_file(&self, rel: &str) -> bool {
        match self {
            ProjectView::Disk(root) | ProjectView::Snapshot(DiskSnapshot { root, .. }) => {
                root.join(rel).is_file()
            }
            ProjectView::Memory(project) => matches!(
                project.get(rel),
                Some(MemoryEntry::Text(_) | MemoryEntry::Binary(_) | MemoryEntry::Present)
            ),
        }
    }

    /// The path itself is a symbolic link.
    pub fn is_symlink(&self, rel: &str) -> bool {
        match self {
            ProjectView::Disk(root) | ProjectView::Snapshot(DiskSnapshot { root, .. }) => {
                std::fs::symlink_metadata(root.join(rel)).is_ok_and(|m| m.file_type().is_symlink())
            }
            ProjectView::Memory(project) => project.is_symlink(rel),
        }
    }

    /// The UTF-8-named entries of directory `rel`, sorted by name.
    pub async fn list_dir(&self, rel: &str) -> io::Result<Vec<DirEntryInfo>> {
        match self {
            ProjectView::Disk(root) | ProjectView::Snapshot(DiskSnapshot { root, .. }) => {
                let mut dir = tokio::fs::read_dir(root.join(rel)).await?;
                let mut out = Vec::new();
                while let Ok(Some(entry)) = dir.next_entry().await {
                    let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                        continue;
                    };
                    let is_dir = entry.file_type().await.is_ok_and(|t| t.is_dir());
                    out.push(DirEntryInfo { name, is_dir });
                }
                out.sort_by(|a, b| a.name.cmp(&b.name));
                Ok(out)
            }
            ProjectView::Memory(project) => {
                if !project.is_dir(rel) {
                    return Err(io::Error::new(io::ErrorKind::NotFound, "not found"));
                }
                Ok(project
                    .children(rel)
                    .into_iter()
                    .map(|(name, is_dir)| DirEntryInfo { name, is_dir })
                    .collect())
            }
        }
    }
}

/// [`crate::vendor::npm_flavor::detect_npm_lock_flavor`] over a
/// [`ProjectView`]. The disk variant IS the disk probe; the memory variant
/// follows the same decision table, with pnpm's own Plug'n'Play layout
/// never detected (there is no installed store in memory).
pub(crate) async fn detect_npm_lock_flavor_in(
    view: &ProjectView<'_>,
) -> Result<(NpmLockFlavor, Vec<VendorWarning>), (&'static str, String)> {
    let project = match view {
        ProjectView::Disk(root) | ProjectView::Snapshot(DiskSnapshot { root, .. }) => {
            return crate::vendor::npm_flavor::detect_npm_lock_flavor(root).await
        }
        ProjectView::Memory(project) => *project,
    };
    let exists = |name: &str| project.contains(name);
    let read_lock = |name: &str| -> Result<String, (&'static str, String)> {
        project.read_text(name).map_err(|e| {
            (
                "vendor_lockfile_missing",
                format!("cannot read {name}: {e}"),
            )
        })
    };

    // A loader the configured `nodeLinker` disowns is stale (#975). A
    // memory snapshot is the repository alone, not the host it is scanned
    // on: only its own `.yarnrc.yml` counts, never the host's
    // `YARN_NODE_LINKER`, `YARN_RC_FILENAME` or home rc file. A classic lock
    // is yarn 1, which has no `nodeLinker`.
    let linker = || {
        let lock = project.read_text("yarn.lock").ok();
        crate::crawlers::pkg_managers::effective_yarn_linker(lock.as_deref(), || {
            let rc = project.read_text(".yarnrc.yml").ok()?;
            crate::vendor::yarn_berry_lock::yarnrc_scalar(&rc, "nodeLinker")
                .filter(|v| !v.is_empty())
                .map(str::to_string)
        })
    };
    if let Some(marker) = crate::crawlers::pkg_managers::live_pnp_marker_with(linker, exists) {
        return Err((
            "vendor_yarn_berry_unsupported",
            format!(
                "found `{marker}`: this is a yarn berry Plug'n'Play project — packages \
                 live inside .yarn/cache/ zips, not node_modules/, so there is nothing \
                 vendor could stage or rewire; use `yarn patch <pkg>` instead"
            ),
        ));
    }

    let detected = 'flavor: {
        if exists(VLT_LOCK) {
            let text = read_lock(VLT_LOCK)?;
            match crate::vendor::vlt_lock::sniff_vendor_lock(&text) {
                Ok(_) => break 'flavor NpmLockFlavor::Vlt,
                Err(detail) => return Err(("vendor_lockfile_version_unsupported", detail)),
            }
        }
        if exists(BUN_LOCK) || exists(BUN_LOCKB) {
            break 'flavor NpmLockFlavor::Bun;
        }
        if exists(PNPM_LOCK) {
            let text = read_lock(PNPM_LOCK)?;
            match sniff_lock_grammar(&text) {
                Ok(PnpmLockGrammar::V9) => break 'flavor NpmLockFlavor::Pnpm,
                Ok(PnpmLockGrammar::V54 | PnpmLockGrammar::V60) => {
                    break 'flavor NpmLockFlavor::PnpmLegacy
                }
                Err(detail) => return Err(("vendor_lockfile_version_unsupported", detail)),
            }
        }
        if exists("yarn.lock") {
            let text = read_lock("yarn.lock")?;
            match sniff_grammar(&text) {
                Some(YarnLockGrammar::Berry) => break 'flavor NpmLockFlavor::YarnBerry,
                Some(YarnLockGrammar::Classic) => break 'flavor NpmLockFlavor::YarnClassic,
                None => {
                    return Err((
                        "vendor_lockfile_version_unsupported",
                        UNIDENTIFIED_DETAIL.to_string(),
                    ))
                }
            }
        }
        if exists(NPM_LOCKS[0]) || exists(NPM_LOCKS[1]) {
            break 'flavor NpmLockFlavor::PackageLock;
        }
        if exists("rush.json") {
            return Err((
                "vendor_rush_unsupported",
                format!(
                    "found rush.json: this is a Rush monorepo — its single pnpm lockfile \
                     lives at {}; use `socket-patch scan --mode hosted`, which edits it in \
                     place",
                    crate::constants::npm_family::RUSH_COMMON_LOCK_REL
                ),
            ));
        }
        return Err((
            "vendor_lockfile_missing",
            "no package-lock.json, npm-shrinkwrap.json, yarn.lock, pnpm-lock.yaml, bun.lock, \
             bun.lockb, or vlt-lock.json in the project root"
                .to_string(),
        ));
    };
    Ok((detected, Vec::new()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn project(files: &[(&str, MemoryEntry)]) -> MemoryProject {
        let mut p = MemoryProject::new();
        for (k, v) in files {
            p.insert(*k, v.clone());
        }
        p
    }

    fn text(s: &str) -> MemoryEntry {
        MemoryEntry::Text(Arc::from(s))
    }

    #[test]
    fn children_lists_files_and_implied_dirs_sorted() {
        let p = project(&[
            ("b.txt", text("")),
            ("a/x.toml", text("")),
            ("a/y/z.toml", text("")),
            ("c", MemoryEntry::Symlink),
        ]);
        assert_eq!(
            p.children(""),
            vec![
                ("a".to_string(), true),
                ("b.txt".to_string(), false),
                ("c".to_string(), false)
            ]
        );
        assert_eq!(
            p.children("a"),
            vec![("x.toml".to_string(), false), ("y".to_string(), true)]
        );
        assert!(p.is_dir("a/y"));
        assert!(!p.is_dir("a/x.toml"));
        assert!(!p.is_dir("ab"));
    }

    #[tokio::test]
    async fn memory_reads_classify_like_the_disk_reader() {
        let p = project(&[
            ("t", text("hello")),
            ("b", MemoryEntry::Binary(Arc::from(vec![0xffu8, 0xfe]))),
            ("p", MemoryEntry::Present),
            ("s", MemoryEntry::Symlink),
            ("d/f", text("")),
        ]);
        let view = ProjectView::Memory(&p);
        assert_eq!(view.read_text("t").await.unwrap(), "hello");
        assert_eq!(
            view.read_text("b").await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(view.read_bytes("b").await.unwrap(), vec![0xff, 0xfe]);
        assert!(view.read_text("p").await.is_err());
        assert!(view.read_text("s").await.is_err());
        assert_eq!(
            view.read_text("missing").await.unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(
            view.read_text("d").await.unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert!(view.exists("s").await);
        assert!(view.is_symlink("s"));
        assert!(!view.is_file("s"));
        assert!(view.is_file("p"));
    }

    #[tokio::test]
    async fn memory_flavor_probe_follows_the_disk_decision_table() {
        let berry = project(&[("yarn.lock", text("__metadata:\n  version: 8\n"))]);
        assert_eq!(
            detect_npm_lock_flavor_in(&ProjectView::Memory(&berry))
                .await
                .unwrap()
                .0,
            NpmLockFlavor::YarnBerry
        );
        let bun_over_npm = project(&[
            ("package-lock.json", text("{}")),
            ("bun.lockb", MemoryEntry::Present),
        ]);
        assert_eq!(
            detect_npm_lock_flavor_in(&ProjectView::Memory(&bun_over_npm))
                .await
                .unwrap()
                .0,
            NpmLockFlavor::Bun
        );
        let vlt_over_bun = project(&[
            (
                "vlt-lock.json",
                text("{\n  \"lockfileVersion\": 1,\n  \"options\": {},\n  \"nodes\": {},\n  \"edges\": {}\n}\n"),
            ),
            ("bun.lock", text("{}")),
        ]);
        assert_eq!(
            detect_npm_lock_flavor_in(&ProjectView::Memory(&vlt_over_bun))
                .await
                .unwrap()
                .0,
            NpmLockFlavor::Vlt
        );
        // #975: a stale Yarn 2 loader under a non-pnp linker is ignored.
        let stale = project(&[
            (".pnp.js", MemoryEntry::Present),
            (".yarnrc.yml", text("nodeLinker: node-modules\n")),
            ("yarn.lock", text("__metadata:\n  version: 8\n")),
        ]);
        assert_eq!(
            detect_npm_lock_flavor_in(&ProjectView::Memory(&stale))
                .await
                .unwrap()
                .0,
            NpmLockFlavor::YarnBerry
        );
        // Yarn 1 PnP: a classic lock has no `nodeLinker`, so a berry
        // setting beside it does not disown the loader.
        let yarn1_pnp = project(&[
            (".pnp.js", MemoryEntry::Present),
            (".yarnrc.yml", text("nodeLinker: node-modules\n")),
            ("yarn.lock", text("# yarn lockfile v1\n")),
        ]);
        assert_eq!(
            detect_npm_lock_flavor_in(&ProjectView::Memory(&yarn1_pnp))
                .await
                .unwrap_err()
                .0,
            "vendor_yarn_berry_unsupported"
        );
        let pnp = project(&[(".pnp.cjs", MemoryEntry::Present), ("yarn.lock", text(""))]);
        assert_eq!(
            detect_npm_lock_flavor_in(&ProjectView::Memory(&pnp))
                .await
                .unwrap_err()
                .0,
            "vendor_yarn_berry_unsupported"
        );
        let empty = MemoryProject::new();
        assert_eq!(
            detect_npm_lock_flavor_in(&ProjectView::Memory(&empty))
                .await
                .unwrap_err()
                .0,
            "vendor_lockfile_missing"
        );
    }

    #[tokio::test]
    async fn a_snapshot_reads_each_file_once() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("a.lock"), "one").unwrap();
        let snap = DiskSnapshot::new(tmp.path());
        let view = ProjectView::Snapshot(&snap);
        assert_eq!(view.read_text("a.lock").await.unwrap(), "one");
        std::fs::write(tmp.path().join("a.lock"), "two").unwrap();
        assert_eq!(view.read_text("a.lock").await.unwrap(), "one", "cached");
        assert_eq!(view.read_bytes("a.lock").await.unwrap(), b"one");
        let missing = view.read_text("b.lock").await.unwrap_err();
        assert_eq!(missing.kind(), io::ErrorKind::NotFound);
        std::fs::write(tmp.path().join("b.lock"), "late").unwrap();
        assert_eq!(
            view.read_text("b.lock").await.unwrap_err().kind(),
            io::ErrorKind::NotFound,
            "a cached miss stays a miss"
        );
        assert!(view.exists("b.lock").await, "non-read probes go to disk");
    }
}
