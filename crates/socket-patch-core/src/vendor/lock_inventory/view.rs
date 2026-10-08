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

use crate::constants::npm_family::{
    BUN_LOCK, BUN_LOCKB, NPM_LOCKS, PNPM_LOCK, PNP_MARKERS, VLT_LOCK,
};
use crate::utils::fs::{read_regular_to_bytes, read_regular_to_string};
use crate::vendor::npm_flavor::NpmLockFlavor;
use crate::formats::pnpm::{sniff_lock_grammar, PnpmLockGrammar};
use crate::formats::yarn::{sniff_grammar, YarnLockGrammar, UNIDENTIFIED_DETAIL};
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

    #[cfg(test)]
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
    /// Private so that every raw use of the root goes through
    /// [`Self::root`], which a [`ReadSet`] recording counts as an
    /// unrecordable disk access.
    root: &'a Path,
    reads: std::sync::Mutex<ReadCache>,
    /// Paths [`Self::overlay`] put in place of the disk content (they exist
    /// in this view even when the disk has no such file yet).
    overlaid: std::sync::Mutex<std::collections::BTreeSet<String>>,
    /// `Some` for a [`Self::tracked`] snapshot.
    tracking: Option<std::sync::Mutex<Tracking>>,
}

/// What a [`DiskSnapshot::tracked`] snapshot has seen.
#[derive(Debug, Default)]
struct Tracking {
    /// Each root-relative path any access touched, with its fingerprint
    /// taken before that first access.
    seen: std::collections::HashMap<String, Fingerprint>,
    /// The open recording window ([`DiskSnapshot::begin_recording`]): the
    /// paths touched in it, and whether something read the disk around the
    /// view (its fingerprints then cannot cover what was read).
    window: Option<(BTreeSet<String>, bool)>,
}

/// One filesystem entry's identity and version as stats report it: the
/// entry itself (`lstat`) and, for a symbolic link, its target (`stat`).
/// `None` for an entry that does not exist. A directory's own stat is only
/// its kind and identity (its times move whenever any entry in it changes,
/// including socket-patch's own `.socket/` lock); a directory something
/// LISTED also carries its entry names ([`Self::listing`]).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Fingerprint {
    entry: Option<Stat>,
    target: Option<Stat>,
    /// The sorted `(name, is_dir)` entries of a listed directory.
    listing: Option<Vec<(String, bool)>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Stat {
    kind: u8,
    len: u64,
    modified: Option<std::time::SystemTime>,
    /// Unix: `(dev, ino, ctime)`, which any write, rename over or
    /// metadata change moves; elsewhere the creation time. A directory
    /// keeps only `(dev, ino)`.
    identity: (u64, u64, i64, i64),
}

impl Stat {
    fn of(m: &std::fs::Metadata) -> Self {
        let kind = if m.file_type().is_symlink() {
            2
        } else if m.is_dir() {
            1
        } else {
            0
        };
        #[cfg(unix)]
        let identity = {
            use std::os::unix::fs::MetadataExt;
            (m.dev(), m.ino(), m.ctime(), m.ctime_nsec())
        };
        #[cfg(not(unix))]
        let identity = {
            let created = m
                .created()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .unwrap_or_default();
            (
                0,
                0,
                created.as_secs() as i64,
                i64::from(created.subsec_nanos()),
            )
        };
        if kind == 1 {
            return Stat {
                kind,
                len: 0,
                modified: None,
                identity: (identity.0, identity.1, 0, 0),
            };
        }
        Stat {
            kind,
            len: m.len(),
            modified: m.modified().ok(),
            identity,
        }
    }
}

/// How an access uses a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Access {
    /// Content read or existence / type probe.
    Probe,
    /// Directory listing.
    List,
}

impl Fingerprint {
    fn of(root: &Path, rel: &str, access: Access) -> Self {
        let path = root.join(rel);
        let entry = std::fs::symlink_metadata(&path).ok();
        let target = entry
            .as_ref()
            .filter(|m| m.file_type().is_symlink())
            .and_then(|_| std::fs::metadata(&path).ok());
        Fingerprint {
            entry: entry.as_ref().map(Stat::of),
            target: target.as_ref().map(Stat::of),
            listing: (access == Access::List).then(|| listing(&path, rel.is_empty())),
        }
    }

    /// Whether `rel` still has this fingerprint.
    fn holds(&self, root: &Path, rel: &str) -> bool {
        let access = if self.listing.is_some() {
            Access::List
        } else {
            Access::Probe
        };
        Fingerprint::of(root, rel, access) == *self
    }
}

/// The sorted `(name, is_dir)` entries of `dir` (empty when unreadable),
/// leaving out socket-patch's own state directory at the project root:
/// taking the apply lock creates it, no listing consumer selects it, and
/// any read inside it is fingerprinted on its own.
fn listing(dir: &Path, at_root: bool) -> Vec<(String, bool)> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<(String, bool)> = entries
        .filter_map(Result::ok)
        .map(|e| {
            let is_dir = e.file_type().is_ok_and(|t| t.is_dir());
            (e.file_name().to_string_lossy().into_owned(), is_dir)
        })
        .filter(|(name, _)| !(at_root && name == crate::constants::SOCKET_DIR))
        .collect();
    out.sort();
    out
}

/// Every path a [`DiskSnapshot::tracked`] snapshot touched while recording
/// (see [`DiskSnapshot::begin_recording`]), with the fingerprint each had
/// before it was first read. Stats only: checking it never reads a file.
#[derive(Debug, Clone)]
pub struct ReadSet {
    root: std::path::PathBuf,
    paths: BTreeMap<String, Fingerprint>,
}

impl ReadSet {
    /// Whether every recorded path still has the fingerprint it had when it
    /// was first read: no file was written, replaced, created or removed and
    /// no listed directory gained or lost an entry since.
    pub fn unchanged(&self) -> bool {
        self.paths
            .iter()
            .all(|(rel, before)| before.holds(&self.root, rel))
    }

    /// How many paths [`Self::unchanged`] re-stats.
    pub fn len(&self) -> usize {
        self.paths.len()
    }

    /// No path recorded.
    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }
}

impl<'a> DiskSnapshot<'a> {
    pub fn new(root: &'a Path) -> Self {
        Self {
            root,
            reads: std::sync::Mutex::new(std::collections::HashMap::new()),
            overlaid: std::sync::Mutex::new(std::collections::BTreeSet::new()),
            tracking: None,
        }
    }

    /// A snapshot that fingerprints every path before it first touches it,
    /// so a [`ReadSet`] can later tell whether what it read still holds.
    pub fn tracked(root: &'a Path) -> Self {
        Self {
            tracking: Some(std::sync::Mutex::new(Tracking::default())),
            ..Self::new(root)
        }
    }

    /// The project root, for a read the view does not mediate. While a
    /// recording is open this makes it unusable ([`Self::end_recording`]
    /// returns `None`): the fingerprints cannot cover what such a read sees.
    pub fn root(&self) -> &'a Path {
        if let Some(tracking) = &self.tracking {
            if let Some((_, raw)) = &mut lock_tracking(tracking).window {
                *raw = true;
            }
        }
        self.root
    }

    /// The project root, for a read the view does not mediate that reads
    /// exactly `paths` (root-relative, or absolute for a file outside the
    /// project) and nothing else: a recording fingerprints them like the
    /// view's own reads, instead of giving up as [`Self::root`] does.
    pub fn root_reading<P: AsRef<Path>>(&self, paths: impl IntoIterator<Item = P>) -> &'a Path {
        for path in paths {
            self.touch(&path.as_ref().to_string_lossy());
        }
        self.root
    }

    /// Start recording the paths this (tracked) snapshot's reads touch.
    pub fn begin_recording(&self) {
        if let Some(tracking) = &self.tracking {
            lock_tracking(tracking).window = Some((BTreeSet::new(), false));
        }
    }

    /// Stop recording: the paths touched since [`Self::begin_recording`],
    /// or `None` when the snapshot is untracked, nothing was recording, or
    /// something read the disk around the view meanwhile.
    pub fn end_recording(&self) -> Option<ReadSet> {
        let tracking = self.tracking.as_ref()?;
        let mut tracking = lock_tracking(tracking);
        let (touched, raw) = tracking.window.take()?;
        if raw {
            return None;
        }
        let paths = touched
            .into_iter()
            .filter_map(|rel| Some((rel.clone(), tracking.seen.get(&rel)?.clone())))
            .collect();
        Some(ReadSet {
            root: self.root.to_path_buf(),
            paths,
        })
    }

    /// Note that `rel` is about to be read or probed (see [`Self::tracked`]).
    fn touch(&self, rel: &str) {
        self.touch_as(rel, Access::Probe);
    }

    /// Note that directory `rel` is about to be listed.
    fn touch_listing(&self, rel: &str) {
        self.touch_as(rel, Access::List);
    }

    fn touch_as(&self, rel: &str, access: Access) {
        let Some(tracking) = &self.tracking else {
            return;
        };
        let mut tracking = lock_tracking(tracking);
        let known = tracking
            .seen
            .get(rel)
            .is_some_and(|print| access == Access::Probe || print.listing.is_some());
        if !known {
            let print = Fingerprint::of(self.root, rel, access);
            tracking.seen.insert(rel.to_string(), print);
        }
        if let Some((touched, _)) = &mut tracking.window {
            touched.insert(rel.to_string());
        }
    }

    /// Read `rel` as `content` instead of the disk's: the project as a
    /// pending write would leave it. Content reads, existence probes (of
    /// the file and of the directories it implies) and the view's
    /// directory listings (`list_dir`, `python_lock_paths`) see the
    /// overlay, so a file the write would CREATE is there for every read
    /// the view mediates. A read around the view ([`Self::root`]) still
    /// sees the disk alone; a [`Self::tracked`] recording tells whether
    /// one happened.
    pub fn overlay(&self, rel: &str, content: &[u8]) {
        self.remember(rel, &Ok(content.to_vec()));
        self.overlaid
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(rel.to_string());
    }

    fn is_overlaid(&self, rel: &str) -> bool {
        self.overlaid
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(rel)
    }

    /// The direct children of directory `dir` (`""` for the root) that the
    /// overlaid files imply, as `name -> is_dir`.
    fn overlaid_children(&self, dir: &str) -> BTreeMap<String, bool> {
        let overlaid = self
            .overlaid
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut out = BTreeMap::new();
        for path in overlaid.iter() {
            let rest = if dir.is_empty() {
                Some(path.as_str())
            } else {
                path.strip_prefix(dir).and_then(|r| r.strip_prefix('/'))
            };
            let Some(rest) = rest.filter(|r| !r.is_empty()) else {
                continue;
            };
            match rest.split_once('/') {
                Some((name, _)) => {
                    out.insert(name.to_string(), true);
                }
                None => {
                    out.entry(rest.to_string()).or_insert(false);
                }
            }
        }
        out
    }

    /// `rel` is a directory an overlaid file lives under.
    fn is_overlaid_dir(&self, rel: &str) -> bool {
        let prefix = format!("{rel}/");
        self.overlaid
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .any(|path| path.starts_with(&prefix))
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
        self.touch(rel);
        if let Some(hit) = self.cached(rel) {
            return hit.map(|b| b.to_vec());
        }
        let read = read_regular_to_bytes(&self.root.join(rel)).await;
        self.remember(rel, &read);
        read
    }
}

/// The UTF-8-named entries of directory `dir` on disk, sorted by name.
async fn list_disk_dir(dir: &Path) -> io::Result<Vec<DirEntryInfo>> {
    let mut read = tokio::fs::read_dir(dir).await?;
    let mut out = Vec::new();
    while let Ok(Some(entry)) = read.next_entry().await {
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        let is_dir = entry.file_type().await.is_ok_and(|t| t.is_dir());
        out.push(DirEntryInfo { name, is_dir });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

fn lock_tracking(tracking: &std::sync::Mutex<Tracking>) -> std::sync::MutexGuard<'_, Tracking> {
    tracking
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
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

impl<'a> ProjectView<'a> {
    /// The project root on disk; `None` in memory.
    pub fn disk_root(&self) -> Option<&'a Path> {
        match *self {
            ProjectView::Disk(root) => Some(root),
            ProjectView::Snapshot(snap) => Some(snap.root()),
            ProjectView::Memory(_) => None,
        }
    }

    /// [`Self::disk_root`] for a read the view does not mediate that reads
    /// exactly `paths` (see [`DiskSnapshot::root_reading`]).
    pub fn disk_root_reading<P: AsRef<Path>>(
        &self,
        paths: impl IntoIterator<Item = P>,
    ) -> Option<&'a Path> {
        match *self {
            ProjectView::Disk(root) => Some(root),
            ProjectView::Snapshot(snap) => Some(snap.root_reading(paths)),
            ProjectView::Memory(_) => None,
        }
    }

    /// The root-level Python lock names (sorted; see
    /// [`crate::utils::python_lock::python_lock_paths`]).
    pub fn python_lock_paths(&self) -> Vec<String> {
        if let ProjectView::Snapshot(snap) = self {
            // A listing of the root (names only).
            snap.touch_listing("");
        }
        match self {
            ProjectView::Disk(root) => {
                crate::utils::python_lock::python_lock_paths(root).unwrap_or_default()
            }
            ProjectView::Snapshot(snap) => {
                let mut names =
                    crate::utils::python_lock::python_lock_paths(snap.root).unwrap_or_default();
                names.extend(
                    snap.overlaid_children("")
                        .into_iter()
                        .filter(|(name, is_dir)| {
                            !is_dir && crate::utils::python_lock::is_python_lock_name(name)
                        })
                        .map(|(name, _)| name),
                );
                names.sort();
                names.dedup();
                names
            }
            ProjectView::Memory(project) => project
                .children("")
                .into_iter()
                .filter(|(name, is_dir)| {
                    !is_dir && crate::utils::python_lock::is_python_lock_name(name)
                })
                .map(|(name, _)| name)
                .collect(),
        }
    }

    /// FIFO-safe regular-file text read.
    pub async fn read_text(&self, rel: &str) -> io::Result<String> {
        if let ProjectView::Snapshot(snap) = self {
            snap.touch(rel);
        }
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
        if let ProjectView::Snapshot(snap) = self {
            snap.touch(rel);
        }
        match self {
            ProjectView::Snapshot(snap) if snap.is_overlaid(rel) || snap.is_overlaid_dir(rel) => {
                true
            }
            ProjectView::Disk(root) | ProjectView::Snapshot(DiskSnapshot { root, .. }) => {
                tokio::fs::metadata(root.join(rel)).await.is_ok()
            }
            ProjectView::Memory(project) => project.contains(rel) || project.is_dir(rel),
        }
    }

    /// `symlink_metadata` (does not follow links) succeeds.
    pub async fn exists_no_follow(&self, rel: &str) -> bool {
        if let ProjectView::Snapshot(snap) = self {
            snap.touch(rel);
        }
        match self {
            ProjectView::Snapshot(snap) if snap.is_overlaid(rel) || snap.is_overlaid_dir(rel) => {
                true
            }
            ProjectView::Disk(root) | ProjectView::Snapshot(DiskSnapshot { root, .. }) => {
                tokio::fs::symlink_metadata(root.join(rel)).await.is_ok()
            }
            ProjectView::Memory(project) => project.contains(rel) || project.is_dir(rel),
        }
    }

    /// A regular file (following links on disk).
    pub fn is_file(&self, rel: &str) -> bool {
        if let ProjectView::Snapshot(snap) = self {
            snap.touch(rel);
        }
        match self {
            ProjectView::Snapshot(snap) if snap.is_overlaid(rel) => true,
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
        if let ProjectView::Snapshot(snap) = self {
            snap.touch(rel);
        }
        match self {
            ProjectView::Disk(root) | ProjectView::Snapshot(DiskSnapshot { root, .. }) => {
                std::fs::symlink_metadata(root.join(rel)).is_ok_and(|m| m.file_type().is_symlink())
            }
            ProjectView::Memory(project) => project.is_symlink(rel),
        }
    }

    /// The UTF-8-named entries of directory `rel`, sorted by name.
    pub async fn list_dir(&self, rel: &str) -> io::Result<Vec<DirEntryInfo>> {
        if let ProjectView::Snapshot(snap) = self {
            snap.touch_listing(rel);
        }
        match self {
            ProjectView::Disk(root) => list_disk_dir(&root.join(rel)).await,
            ProjectView::Snapshot(snap) => {
                let created = snap.overlaid_children(rel);
                let mut out = match list_disk_dir(&snap.root.join(rel)).await {
                    Ok(out) => out,
                    Err(e) if e.kind() == io::ErrorKind::NotFound && !created.is_empty() => {
                        Vec::new()
                    }
                    Err(e) => return Err(e),
                };
                for (name, is_dir) in created {
                    if !out.iter().any(|e| e.name == name) {
                        out.push(DirEntryInfo { name, is_dir });
                    }
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
        ProjectView::Disk(root) => {
            return crate::vendor::npm_flavor::detect_npm_lock_flavor(root).await
        }
        ProjectView::Snapshot(snap) => {
            return crate::vendor::npm_flavor::detect_npm_lock_flavor(snap.root()).await
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

    /// Record what `read` touches through a tracked snapshot of `root`.
    async fn recorded<F>(root: &Path, read: F) -> Option<ReadSet>
    where
        F: for<'v> FnOnce(
            ProjectView<'v>,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'v>>,
    {
        let snap = DiskSnapshot::tracked(root);
        snap.begin_recording();
        read(ProjectView::Snapshot(&snap)).await;
        snap.end_recording()
    }

    /// The read set holds while nothing changes, and breaks when a file it
    /// read is rewritten (same length, in place or replaced), created after
    /// a miss, or removed.
    #[tokio::test]
    async fn a_read_set_notices_a_changed_file() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(root.join("a.lock"), "one").unwrap();
        fn read(
            view: ProjectView<'_>,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + '_>> {
            Box::pin(async move {
                view.read_text("a.lock").await.unwrap();
                assert!(view.read_text("b.lock").await.is_err());
            })
        }
        let set = recorded(root, read).await.expect("recorded");
        assert_eq!(set.len(), 2);
        assert!(set.unchanged());

        // Rewritten in place with the same length.
        std::fs::write(root.join("a.lock"), "two").unwrap();
        assert!(!set.unchanged(), "an in-place rewrite");
        // Replaced (rename over) with the same bytes.
        let set = recorded(root, read).await.unwrap();
        std::fs::write(root.join("a.tmp"), "two").unwrap();
        std::fs::rename(root.join("a.tmp"), root.join("a.lock")).unwrap();
        assert!(!set.unchanged(), "a replacement");
        // A file that was missing appears.
        let set = recorded(root, read).await.unwrap();
        std::fs::write(root.join("b.lock"), "late").unwrap();
        assert!(!set.unchanged(), "a created file");
        // A file it read is removed.
        let set = recorded(root, |view| {
            Box::pin(async move {
                view.read_text("a.lock").await.unwrap();
            })
        })
        .await
        .unwrap();
        std::fs::remove_file(root.join("a.lock")).unwrap();
        assert!(!set.unchanged(), "a removed file");
    }

    /// A listed directory breaks the read set when it gains or loses an
    /// entry, but not when socket-patch creates its own `.socket/` (the
    /// apply lock) at the root; an unlisted directory is only probed.
    #[tokio::test]
    async fn a_read_set_notices_a_changed_listing() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::create_dir(root.join("sub")).unwrap();
        fn list(
            view: ProjectView<'_>,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + '_>> {
            Box::pin(async move {
                view.python_lock_paths();
                view.list_dir("sub").await.unwrap();
            })
        }
        let set = recorded(root, list).await.unwrap();
        std::fs::create_dir_all(root.join(".socket")).unwrap();
        std::fs::write(root.join(".socket/apply.lock"), "").unwrap();
        assert!(set.unchanged(), "socket-patch's own state dir");
        std::fs::write(root.join("pylock.toml"), "").unwrap();
        assert!(!set.unchanged(), "a new root entry");
        let set = recorded(root, list).await.unwrap();
        std::fs::write(root.join("sub/x"), "").unwrap();
        assert!(!set.unchanged(), "a new entry in a listed dir");
        // Probed, not listed: a new entry inside does not matter.
        let set = recorded(root, |view| {
            Box::pin(async move {
                assert!(view.exists("sub").await);
            })
        })
        .await
        .unwrap();
        std::fs::write(root.join("sub/y"), "").unwrap();
        assert!(set.unchanged());
    }

    /// A raw use of the root while recording makes the read set unusable;
    /// a declared raw read is fingerprinted instead, and nothing outside
    /// the window counts.
    #[tokio::test]
    async fn a_raw_disk_read_makes_the_read_set_unusable() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(root.join("a.lock"), "one").unwrap();
        let snap = DiskSnapshot::tracked(root);
        let _ = snap.root();
        snap.begin_recording();
        ProjectView::Snapshot(&snap)
            .read_text("a.lock")
            .await
            .unwrap();
        assert!(ProjectView::Snapshot(&snap).disk_root().is_some());
        assert!(snap.end_recording().is_none(), "a raw read in the window");

        snap.begin_recording();
        let config = root.join("outside.cfg");
        let _ = snap.root_reading([&config]);
        let set = snap.end_recording().expect("a declared read");
        assert_eq!(set.len(), 1);
        std::fs::write(&config, "x").unwrap();
        assert!(!set.unchanged(), "the declared file appeared");

        // An untracked snapshot records nothing.
        let plain = DiskSnapshot::new(root);
        plain.begin_recording();
        assert!(plain.end_recording().is_none());
    }

    /// A file an overlay CREATES is there for every read the view
    /// mediates: listings (also of a directory the disk lacks), directory
    /// probes and the root Python lock names.
    #[tokio::test]
    async fn an_overlaid_creation_is_listed() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::create_dir(root.join("sub")).unwrap();
        std::fs::write(root.join("sub/old"), "").unwrap();
        let snap = DiskSnapshot::new(root);
        snap.overlay("sub/new", b"x");
        snap.overlay("sub/old", b"y");
        snap.overlay("gone/deep/file", b"z");
        snap.overlay("pylock.toml", b"");
        let view = ProjectView::Snapshot(&snap);
        let names = |entries: Vec<DirEntryInfo>| -> Vec<(String, bool)> {
            entries.into_iter().map(|e| (e.name, e.is_dir)).collect()
        };
        assert_eq!(
            names(view.list_dir("sub").await.unwrap()),
            [("new".to_string(), false), ("old".to_string(), false)]
        );
        assert_eq!(
            names(view.list_dir("gone").await.unwrap()),
            [("deep".to_string(), true)]
        );
        assert!(view.list_dir("absent").await.is_err());
        assert!(view.exists("gone/deep").await);
        assert!(view.exists_no_follow("gone").await);
        assert!(!view.exists("gon").await);
        assert_eq!(view.python_lock_paths(), ["pylock.toml"]);
        let root_names = names(view.list_dir("").await.unwrap());
        assert!(root_names.contains(&("gone".to_string(), true)));
        assert!(root_names.contains(&("pylock.toml".to_string(), false)));
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
