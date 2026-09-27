//! Where the registry views read a project from: the filesystem
//! ([`ProjectView::Disk`]) or an in-memory file map
//! ([`ProjectView::Memory`]) handed in by a host that never materializes
//! the repository (the hosted in-memory engine). The disk variant calls the
//! exact readers the views always used, so on-disk behavior is unchanged.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::Path;
use std::sync::Arc;

use crate::constants::npm_family::{
    BUN_LOCK, BUN_LOCKB, NPM_LOCKS, PNPM_LOCK, PNP_MARKERS, VLT_LOCK,
};
use crate::utils::fs::{
    read_regular_to_bytes, read_regular_to_string, read_regular_to_string_sync,
};
use crate::vendor::npm_flavor::NpmLockFlavor;
use crate::vendor::pnpm_lock_legacy::{sniff_lock_grammar, PnpmLockGrammar};
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

    pub fn insert_text(&mut self, rel: impl Into<String>, text: impl Into<Arc<str>>) {
        self.insert(rel, MemoryEntry::Text(text.into()));
    }

    pub fn insert_binary(&mut self, rel: impl Into<String>, bytes: impl Into<Arc<[u8]>>) {
        self.insert(rel, MemoryEntry::Binary(bytes.into()));
    }

    pub fn insert_present(&mut self, rel: impl Into<String>) {
        self.insert(rel, MemoryEntry::Present);
    }

    pub fn insert_symlink(&mut self, rel: impl Into<String>) {
        self.insert(rel, MemoryEntry::Symlink);
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

    pub fn paths(&self) -> impl Iterator<Item = &str> {
        self.entries.keys().map(String::as_str)
    }

    pub fn entries(&self) -> impl Iterator<Item = (&str, &MemoryEntry)> {
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

/// Where the registry views read the project from.
#[derive(Debug, Clone, Copy)]
pub enum ProjectView<'a> {
    Disk(&'a Path),
    Memory(&'a MemoryProject),
}

impl ProjectView<'_> {
    /// FIFO-safe regular-file text read.
    pub async fn read_text(&self, rel: &str) -> io::Result<String> {
        match self {
            ProjectView::Disk(root) => read_regular_to_string(&root.join(rel)).await,
            ProjectView::Memory(project) => project.read_text(rel),
        }
    }

    /// FIFO-safe regular-file byte read.
    pub async fn read_bytes(&self, rel: &str) -> io::Result<Vec<u8>> {
        match self {
            ProjectView::Disk(root) => read_regular_to_bytes(&root.join(rel)).await,
            ProjectView::Memory(project) => project.read_bytes(rel),
        }
    }

    /// Synchronous twin of [`Self::read_text`].
    pub fn read_text_sync(&self, rel: &str) -> io::Result<String> {
        match self {
            ProjectView::Disk(root) => read_regular_to_string_sync(&root.join(rel)),
            ProjectView::Memory(project) => project.read_text(rel),
        }
    }

    /// `metadata` (follows links) succeeds.
    pub async fn exists(&self, rel: &str) -> bool {
        match self {
            ProjectView::Disk(root) => tokio::fs::metadata(root.join(rel)).await.is_ok(),
            ProjectView::Memory(project) => project.contains(rel) || project.is_dir(rel),
        }
    }

    /// `symlink_metadata` (does not follow links) succeeds.
    pub async fn exists_no_follow(&self, rel: &str) -> bool {
        match self {
            ProjectView::Disk(root) => tokio::fs::symlink_metadata(root.join(rel)).await.is_ok(),
            ProjectView::Memory(project) => project.contains(rel) || project.is_dir(rel),
        }
    }

    /// A regular file (following links on disk).
    pub fn is_file(&self, rel: &str) -> bool {
        match self {
            ProjectView::Disk(root) => root.join(rel).is_file(),
            ProjectView::Memory(project) => matches!(
                project.get(rel),
                Some(MemoryEntry::Text(_) | MemoryEntry::Binary(_) | MemoryEntry::Present)
            ),
        }
    }

    /// The path itself is a symbolic link.
    pub fn is_symlink(&self, rel: &str) -> bool {
        match self {
            ProjectView::Disk(root) => {
                std::fs::symlink_metadata(root.join(rel)).is_ok_and(|m| m.file_type().is_symlink())
            }
            ProjectView::Memory(project) => project.is_symlink(rel),
        }
    }

    /// The UTF-8-named entries of directory `rel`, sorted by name.
    pub async fn list_dir(&self, rel: &str) -> io::Result<Vec<DirEntryInfo>> {
        match self {
            ProjectView::Disk(root) => {
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

/// How many head lines the yarn content sniff reads (mirrors the disk
/// probe).
const YARN_SNIFF_HEAD_LINES: usize = 30;

/// [`crate::vendor::npm_flavor::detect_npm_lock_flavor`] over a
/// [`ProjectView`]. The disk variant IS the disk probe; the memory variant
/// follows the same decision table, with pnpm's own Plug'n'Play layout
/// never detected (there is no installed store in memory).
pub(crate) async fn detect_npm_lock_flavor_in(
    view: &ProjectView<'_>,
) -> Result<(NpmLockFlavor, Vec<VendorWarning>), (&'static str, String)> {
    let project = match view {
        ProjectView::Disk(root) => {
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

    if let Some(marker) = PNP_MARKERS.iter().find(|m| exists(m)) {
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
            let head: Vec<&str> = text
                .strip_prefix('\u{feff}')
                .unwrap_or(&text)
                .lines()
                .take(YARN_SNIFF_HEAD_LINES)
                .collect();
            if head.iter().any(|l| l.starts_with("__metadata:")) {
                break 'flavor NpmLockFlavor::YarnBerry;
            }
            if head.iter().any(|l| l.trim() == "# yarn lockfile v1") {
                break 'flavor NpmLockFlavor::YarnClassic;
            }
            return Err((
                "vendor_lockfile_version_unsupported",
                "yarn.lock carries neither the `# yarn lockfile v1` header nor a berry \
                 `__metadata:` key; cannot identify the lockfile version"
                    .to_string(),
            ));
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
}
