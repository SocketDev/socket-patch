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

use crate::utils::fs::{read_regular_to_bytes, read_regular_to_string};

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
    /// The `.yarnrc.yml` texts of the repository directories above this
    /// project, nearest first. yarn berry merges every rc file at or above
    /// the project, so a `nodeLinker` set only there still decides whether
    /// a `.pnp.*` loader is live (#975).
    ancestor_yarnrcs: Vec<Arc<str>>,
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

    /// Set the `.yarnrc.yml` texts above the project, nearest first.
    pub fn set_ancestor_yarnrcs(&mut self, rcs: Vec<Arc<str>>) {
        self.ancestor_yarnrcs = rcs;
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
    /// When each fingerprint in [`Self::seen`] was taken.
    taken: std::collections::HashMap<String, std::time::SystemTime>,
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
/// before it was first read. Stats only, except for a racily-current file
/// (see [`RACY_WINDOW`]), whose content is compared too.
#[derive(Debug, Clone)]
pub struct ReadSet {
    root: std::path::PathBuf,
    paths: BTreeMap<String, Fingerprint>,
    /// The files modified within [`RACY_WINDOW`] of their fingerprint: a
    /// later write in the same timestamp tick leaves their stats unchanged,
    /// so they hold only while their content is still the content the view
    /// read (`None`: no content the view read to compare, never holds).
    racy: BTreeMap<String, Option<Arc<[u8]>>>,
}

/// How close to its fingerprint a file's modification time may be before
/// the stats alone cannot vouch for it (git's "racily clean" files).
/// Filesystems stamp times in ticks: about 16 ms on Windows, jiffies on
/// Linux, a second on HFS+ and two on FAT, so a rewrite of the same length
/// inside one tick of the write before it keeps every stat.
const RACY_WINDOW: std::time::Duration = std::time::Duration::from_secs(2);

/// Whether a file stamped `modified` may be rewritten unseen after a
/// fingerprint taken at `taken`.
fn racy(modified: Option<std::time::SystemTime>, taken: std::time::SystemTime) -> bool {
    modified.is_none_or(|modified| {
        taken
            .checked_sub(RACY_WINDOW)
            .is_none_or(|horizon| modified >= horizon)
    })
}

impl ReadSet {
    /// Whether every recorded path still has the fingerprint it had when it
    /// was first read: no file was written, replaced, created or removed and
    /// no listed directory gained or lost an entry since.
    pub fn unchanged(&self) -> bool {
        self.paths.iter().all(|(rel, before)| {
            before.holds(&self.root, rel)
                && self.racy.get(rel).is_none_or(|read| {
                    read.as_ref().is_some_and(|read| {
                        crate::utils::fs::read_regular_to_bytes_sync(&self.root.join(rel))
                            .is_ok_and(|now| now[..] == read[..])
                    })
                })
        })
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
        let paths: BTreeMap<String, Fingerprint> = touched
            .into_iter()
            .filter_map(|rel| Some((rel.clone(), tracking.seen.get(&rel)?.clone())))
            .collect();
        let racy_paths: Vec<String> = paths
            .iter()
            .filter(|(rel, print)| {
                let taken = tracking.taken.get(*rel).copied();
                [&print.entry, &print.target]
                    .into_iter()
                    .flatten()
                    .filter(|stat| stat.kind == 0)
                    .any(|stat| taken.is_none_or(|taken| racy(stat.modified, taken)))
            })
            .map(|(rel, _)| rel.clone())
            .collect();
        drop(tracking);
        let reads = self.lock();
        let racy = racy_paths
            .into_iter()
            .map(|rel| {
                let read = match reads.get(&rel) {
                    Some(Ok(bytes)) if !self.is_overlaid(&rel) => Some(Arc::clone(bytes)),
                    _ => None,
                };
                (rel, read)
            })
            .collect();
        Some(ReadSet {
            root: self.root.to_path_buf(),
            paths,
            racy,
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
            let taken = std::time::SystemTime::now();
            let print = Fingerprint::of(self.root, rel, access);
            tracking.seen.insert(rel.to_string(), print);
            tracking.taken.insert(rel.to_string(), taken);
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

    /// A directory (following links on disk; an implied directory in
    /// memory).
    pub fn is_dir(&self, rel: &str) -> bool {
        if let ProjectView::Snapshot(snap) = self {
            snap.touch(rel);
        }
        match self {
            ProjectView::Snapshot(snap) if snap.is_overlaid_dir(rel) => true,
            ProjectView::Disk(root) | ProjectView::Snapshot(DiskSnapshot { root, .. }) => {
                root.join(rel).is_dir()
            }
            ProjectView::Memory(project) => project.is_dir(rel),
        }
    }

    /// The `nodeLinker` yarn would use here, `None` when unset: what
    /// [`crate::crawlers::pkg_managers::live_pnp_marker_with`] asks to tell a
    /// live PnP loader from a stale one (#975). On disk it is the disk
    /// probe (environment, rc files, home rc). A memory snapshot is the
    /// repository alone, not the host it is scanned on: only the
    /// repository's own `.yarnrc.yml` files count (the project's, then those
    /// above it, the closest setting winning, as on disk), never the host's
    /// `YARN_NODE_LINKER`, `YARN_RC_FILENAME` or home rc file. A classic
    /// lock is yarn 1, which has no `nodeLinker`.
    pub(crate) fn yarn_node_linker(&self) -> Option<String> {
        use crate::crawlers::pkg_managers::effective_yarn_linker;
        // The disk probe also reads the environment and the rc files above
        // the project and in the home directory, which no fingerprint
        // covers: a snapshot's read goes through `root()`, opting its
        // recording out of reuse (only a tree holding a PnP loader asks).
        let disk_root = match self {
            ProjectView::Disk(root) => Some(*root),
            ProjectView::Snapshot(snap) => Some(snap.root()),
            ProjectView::Memory(_) => None,
        };
        match self {
            ProjectView::Disk(_) | ProjectView::Snapshot(_) => {
                let root = disk_root.expect("a disk view has a root");
                let lock = crate::utils::fs::read_regular_to_string_sync(&root.join("yarn.lock"));
                effective_yarn_linker(lock.ok().as_deref(), || {
                    crate::crawlers::pkg_managers::yarn_node_linker(root)
                })
            }
            ProjectView::Memory(project) => {
                let lock = project.read_text("yarn.lock").ok();
                effective_yarn_linker(lock.as_deref(), || {
                    let node_linker = |rc: &str| {
                        crate::formats::yarn::berry_gates::yarnrc_scalar(rc, "nodeLinker")
                            .filter(|v| !v.is_empty())
                            .map(str::to_string)
                    };
                    project
                        .read_text(".yarnrc.yml")
                        .ok()
                        .and_then(|rc| node_linker(&rc))
                        .or_else(|| {
                            project
                                .ancestor_yarnrcs
                                .iter()
                                .find_map(|rc| node_linker(rc))
                        })
                })
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vendor::npm_flavor::{detect_npm_lock_flavor_in, NpmLockFlavor};

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
        // The linker set only in a `.yarnrc.yml` above the project (the
        // repository root over a nested yarn project) still counts, the
        // nearest one winning; the project's own rc wins over both.
        let mut parent_rc = stale.clone();
        parent_rc.remove(".yarnrc.yml");
        parent_rc.set_ancestor_yarnrcs(vec![
            Arc::from("enableGlobalCache: false\n"),
            Arc::from("nodeLinker: node-modules\n"),
            Arc::from("nodeLinker: pnp\n"),
        ]);
        assert_eq!(
            detect_npm_lock_flavor_in(&ProjectView::Memory(&parent_rc))
                .await
                .unwrap()
                .0,
            NpmLockFlavor::YarnBerry
        );
        let mut own_rc_wins = parent_rc.clone();
        own_rc_wins.insert_text(".yarnrc.yml", "nodeLinker: pnp\n");
        assert_eq!(
            detect_npm_lock_flavor_in(&ProjectView::Memory(&own_rc_wins))
                .await
                .unwrap_err()
                .0,
            "vendor_yarn_berry_unsupported"
        );
        let mut parent_pnp = parent_rc.clone();
        parent_pnp.set_ancestor_yarnrcs(vec![Arc::from("nodeLinker: pnp\n")]);
        assert_eq!(
            detect_npm_lock_flavor_in(&ProjectView::Memory(&parent_pnp))
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
        // The pnpm-PnP carve-out is shared with disk: a `.pnp.cjs` over an
        // installed pnpm store (either marker) is pnpm's PnP linker, not
        // yarn berry.
        for marker in ["node_modules/.modules.yaml", "node_modules/.pnpm/lock.yaml"] {
            let pnpm_pnp = project(&[
                (".pnp.cjs", MemoryEntry::Present),
                ("pnpm-lock.yaml", text("lockfileVersion: '9.0'\n")),
                (marker, MemoryEntry::Present),
            ]);
            assert_eq!(
                detect_npm_lock_flavor_in(&ProjectView::Memory(&pnpm_pnp))
                    .await
                    .unwrap_err()
                    .0,
                "vendor_pnpm_pnp_unsupported",
                "{marker}"
            );
        }
        // A yarn.lock beside it keeps the yarn berry refusal.
        let yarn_pnp = project(&[
            (".pnp.cjs", MemoryEntry::Present),
            ("pnpm-lock.yaml", text("lockfileVersion: '9.0'\n")),
            ("yarn.lock", text("")),
            ("node_modules/.modules.yaml", MemoryEntry::Present),
        ]);
        assert_eq!(
            detect_npm_lock_flavor_in(&ProjectView::Memory(&yarn_pnp))
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

    /// A file written just before its fingerprint is racily current: its
    /// stats may survive a same-length rewrite in the same timestamp tick,
    /// so its content is compared too: what the view read must still be
    /// there, and a racy file the view only probed (no content to compare)
    /// never holds. An old file is judged by stats alone.
    #[tokio::test]
    async fn a_racily_current_file_is_compared_by_content() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(root.join("a.lock"), "one").unwrap();
        fn read(
            view: ProjectView<'_>,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + '_>> {
            Box::pin(async move {
                view.read_text("a.lock").await.unwrap();
            })
        }
        let set = recorded(root, read).await.unwrap();
        assert_eq!(set.racy.len(), 1, "written just now");
        // The content compared is what the view read.
        assert_eq!(set.racy["a.lock"].as_deref(), Some(&b"one"[..]));
        assert!(set.unchanged());
        let set = recorded(root, read).await.unwrap();
        std::fs::write(root.join("a.lock"), "two").unwrap();
        assert!(!set.unchanged(), "a same-length rewrite");

        let probed = recorded(root, |view| {
            Box::pin(async move {
                assert!(view.exists("a.lock").await);
            })
        })
        .await
        .unwrap();
        assert!(!probed.unchanged(), "nothing read to compare");

        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
        std::fs::File::options()
            .write(true)
            .open(root.join("a.lock"))
            .unwrap()
            .set_modified(old)
            .unwrap();
        let set = recorded(root, read).await.unwrap();
        assert!(set.racy.is_empty(), "an old file");
        assert!(set.unchanged());
        assert!(racy(None, std::time::SystemTime::now()), "no time known");
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

    /// A directory probe is fingerprinted like any other, and the yarn
    /// `nodeLinker` probe, which also reads the environment and rc files
    /// above the project, opts the recording out of reuse.
    #[tokio::test]
    async fn the_dir_and_yarn_linker_probes_keep_the_read_set_honest() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let set = recorded(root, |view| {
            Box::pin(async move {
                assert!(!view.is_dir("node_modules/.vlt"));
            })
        })
        .await
        .expect("recorded");
        assert_eq!(set.len(), 1);
        std::fs::create_dir_all(root.join("node_modules/.vlt")).unwrap();
        assert!(!set.unchanged(), "the probed directory appeared");

        let snap = DiskSnapshot::tracked(root);
        snap.begin_recording();
        let _ = ProjectView::Snapshot(&snap).yarn_node_linker();
        assert!(snap.end_recording().is_none(), "an unfingerprinted read");
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
