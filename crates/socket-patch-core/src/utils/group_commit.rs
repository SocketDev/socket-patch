//! Group commit of a vendored run's commit points.
//!
//! A vendored run used to commit after every package: each backend wrote
//! its lockfile / `package.json` / `pnpm-workspace.yaml` / config edits
//! durably, and the engine rewrote the whole ledger durably behind it. A
//! run over N packages paid N rounds of durable writes of the same few
//! files, each round rewriting whole lockfiles and a ledger that grows with
//! every package.
//!
//! While a [`GroupCommit`] is open for a project root, the durable writers
//! in [`super::fs`] ([`super::fs::atomic_write_bytes`],
//! [`super::fs::atomic_write_bytes_preserving_mode`]) and
//! [`super::fs::remove_file`] capture every commit point under that root in
//! memory instead of writing it, and the readers
//! ([`super::fs::read_regular_to_bytes`] and friends, and
//! [`super::fs::file_exists`]) answer from the captured bytes. Every backend
//! therefore sees exactly the file states it saw before — its own earlier
//! writes, a sibling package's edits, an unwind that restored an original —
//! and [`GroupCommit::commit`] writes the final state once.
//!
//! **What is captured.** Files under the root whose relative path has no
//! `.socket` component, plus the two ledgers (`.socket/vendor/state.json`,
//! `.socket/vendor/redirect-state.json`). Everything else under `.socket/`
//! — the artifacts under `.socket/vendor/<eco>/`, workspace members'
//! `.socket/vendor/` mirrors, blobs, the manifest — is written straight to
//! disk as before: artifacts are read back by path (zip readers, hashing,
//! copies), and they are content-verified anyway (see
//! [`super::durability`]).
//!
//! # Crash semantics
//!
//! A crash before [`GroupCommit::commit`] loses no commit point: the
//! lockfiles and ledgers on disk are the pre-run ones, and the artifacts
//! the run wrote are orphans no ledger entry names (the next run re-vendors
//! over them, `--revert`'s sweep deletes them). The commit itself spans
//! several files, which one rename cannot make atomic, so it is a
//! roll-forward journal:
//!
//! 1. the artifact barrier ([`super::durability::barrier`]) makes every
//!    artifact the new state names durable;
//! 2. `.socket/vendor/.commit-journal.json` is written durably, holding
//!    every changed file's new bytes (or its deletion) and the bytes it
//!    replaces with their sha256 — THIS is the commit point;
//! 3. the files are replaced (stage + rename each, ledgers last), one
//!    barrier syncs them all, and the journal is deleted.
//!
//! A crash between 2 and the journal's deletion leaves a journal that the
//! next command taking the apply lock replays ([`recover`], run by
//! [`crate::patch::apply_lock::acquire`]): each file already at its new
//! bytes is left alone and each still at its recorded old bytes is
//! replaced, so the lockfiles and the ledger are observed all-new by the
//! next locked command; never a half-wired lock with a ledger that
//! disagrees. A replay that fails on I/O keeps the journal and fails the
//! acquire, so no command works over the torn state.
//!
//! A file matching neither side (edited by hand since the crash) is never
//! written over, and the journal is renamed aside once the replay has made
//! the other files agree with that edit where the edit says which side of
//! the commit it was made on: when every such file still carries the
//! commit's own lines (it was replaced, then edited) the rest of the commit
//! is finished around it, so the ledger records the wiring on disk; when
//! none carries any of them (it was edited before the crash reached it)
//! the files already replaced are put back from the journal's recorded
//! bytes; otherwise nothing is written. A journal naming a path outside the
//! captured set, or one that would write through a symbolic link, is set
//! aside unapplied. A single changed file needs no journal: its own atomic
//! rename is the commit.
//!
//! A failed replacement during the commit itself puts the files already
//! replaced back and removes the journal; when putting them back fails as
//! well, the journal is kept for the next locked command ([`is_pending`]).

use std::any::Any;
use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use base64::Engine as _;
use sha2::{Digest, Sha256};

/// Journal location, relative to the project root.
pub const COMMIT_JOURNAL_REL: &str = ".socket/vendor/.commit-journal.json";

/// The two ledgers captured under `.socket/`, committed after every other
/// file.
const LEDGERS: [&str; 2] = [
    ".socket/vendor/state.json",
    ".socket/vendor/redirect-state.json",
];

struct Captured {
    /// The file's bytes, `None` once removed.
    bytes: Option<Content>,
    /// Written through the mode-preserving writer.
    preserve_mode: bool,
}

/// A captured file's content: bytes, or a typed value whose bytes are
/// rendered only when something reads them (see [`capture_value`]).
enum Content {
    Bytes(Vec<u8>),
    Value {
        value: Arc<dyn Any + Send + Sync>,
        render: Render,
        rendered: OnceLock<std::io::Result<Vec<u8>>>,
    },
}

type Render = fn(&(dyn Any + Send + Sync)) -> std::io::Result<Vec<u8>>;

impl Content {
    fn bytes(&self) -> std::io::Result<Vec<u8>> {
        match self {
            Content::Bytes(bytes) => Ok(bytes.clone()),
            Content::Value {
                value,
                render,
                rendered,
            } => match rendered.get_or_init(|| render(value.as_ref())) {
                Ok(bytes) => Ok(bytes.clone()),
                Err(e) => Err(std::io::Error::new(e.kind(), e.to_string())),
            },
        }
    }
}

struct Overlay {
    root: PathBuf,
    canonical_root: Option<PathBuf>,
    files: Mutex<BTreeMap<PathBuf, Captured>>,
    /// Trees to delete once the commit is on disk: `(tree, prune bound)`
    /// (see [`remove_after_commit`]).
    after_commit: Mutex<Vec<(PathBuf, PathBuf)>>,
    /// Directories to remove once the commit is on disk, if empty then
    /// (see [`remove_dir_after_commit`]).
    dirs_after_commit: Mutex<Vec<PathBuf>>,
}

static ACTIVE: Mutex<Vec<Arc<Overlay>>> = Mutex::new(Vec::new());
/// `ACTIVE.len()`, so the readers skip the lock when nothing is open.
static ACTIVE_COUNT: AtomicUsize = AtomicUsize::new(0);

fn active() -> std::sync::MutexGuard<'static, Vec<Arc<Overlay>>> {
    ACTIVE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The project-relative spelling of `path` under `root`, lexically
/// normalized; `None` when it is not under `root` (or climbs out of it).
fn relative_to(root: &Path, path: &Path) -> Option<PathBuf> {
    let rest = path.strip_prefix(root).ok()?;
    let mut out = PathBuf::new();
    for component in rest.components() {
        match component {
            Component::Normal(part) => out.push(part),
            Component::CurDir => {}
            _ => return None,
        }
    }
    Some(out)
}

/// Whether a project-relative path is a captured commit point.
fn is_captured(rel: &Path) -> bool {
    if rel.as_os_str().is_empty() {
        return false;
    }
    let spelled = rel.to_string_lossy().replace('\\', "/");
    if LEDGERS.contains(&spelled.as_str()) {
        return true;
    }
    !rel.components()
        .any(|c| matches!(c, Component::Normal(p) if p == crate::constants::SOCKET_DIR))
}

/// The open overlay capturing `path`, and its key.
fn resolve(path: &Path) -> Option<(Arc<Overlay>, PathBuf)> {
    if ACTIVE_COUNT.load(Ordering::Acquire) == 0 {
        return None;
    }
    let active = active();
    for overlay in active.iter() {
        let rel = relative_to(&overlay.root, path).or_else(|| {
            overlay
                .canonical_root
                .as_deref()
                .and_then(|root| relative_to(root, path))
        });
        if let Some(rel) = rel.filter(|rel| is_captured(rel)) {
            return Some((Arc::clone(overlay), rel));
        }
    }
    None
}

/// The captured bytes of `path`: `None` when `path` is not captured (read
/// the disk), `Some(Err(NotFound))` when the run removed it.
pub(crate) fn read(path: &Path) -> Option<std::io::Result<Vec<u8>>> {
    let (overlay, key) = resolve(path)?;
    let files = overlay
        .files
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let captured = files.get(&key)?;
    Some(match &captured.bytes {
        Some(content) => content.bytes(),
        None => Err(not_found(path)),
    })
}

/// Capture a write of `path` as a typed value — the vendor ledger, which
/// the loop re-saves after every package: holding the value instead of its
/// serialization skips rendering (and later re-parsing) the whole ledger
/// per package. `render` produces the bytes the durable writer would have
/// written, only when a byte reader or the commit needs them; typed readers
/// ([`read_value`]) get the value back. `false` when `path` is not captured.
pub(crate) fn capture_value<T: Any + Send + Sync>(
    path: &Path,
    value: Arc<T>,
    render: Render,
) -> bool {
    let Some((overlay, key)) = resolve(path) else {
        return false;
    };
    overlay
        .files
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(
            key,
            Captured {
                bytes: Some(Content::Value {
                    value,
                    render,
                    rendered: OnceLock::new(),
                }),
                preserve_mode: false,
            },
        );
    true
}

/// The value [`capture_value`] captured for `path`, when it was captured
/// as a `T`.
pub(crate) fn read_value<T: Any + Send + Sync>(path: &Path) -> Option<Arc<T>> {
    let (overlay, key) = resolve(path)?;
    let files = overlay
        .files
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match files.get(&key)?.bytes.as_ref()? {
        Content::Value { value, .. } => Arc::clone(value).downcast::<T>().ok(),
        Content::Bytes(_) => None,
    }
}

/// Whether `path` exists as the run sees it; `None` when not captured.
pub(crate) fn exists(path: &Path) -> Option<bool> {
    let (overlay, key) = resolve(path)?;
    let files = overlay
        .files
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    files.get(&key).map(|c| c.bytes.is_some())
}

/// Capture a write of `path`; `false` when `path` is not captured (write
/// the disk).
pub(crate) fn capture_write(path: &Path, bytes: &[u8], preserve_mode: bool) -> bool {
    let Some((overlay, key)) = resolve(path) else {
        return false;
    };
    overlay
        .files
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(
            key,
            Captured {
                bytes: Some(Content::Bytes(bytes.to_vec())),
                preserve_mode,
            },
        );
    true
}

/// Capture a removal of `path`, with `remove_file`'s semantics (`NotFound`
/// when there is nothing to remove); `None` when `path` is not captured.
pub(crate) fn capture_remove(path: &Path) -> Option<std::io::Result<()>> {
    let (overlay, key) = resolve(path)?;
    let mut files = overlay
        .files
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let present = match files.get(&key) {
        Some(captured) => captured.bytes.is_some(),
        None => std::fs::symlink_metadata(path).is_ok(),
    };
    if !present {
        return Some(Err(not_found(path)));
    }
    files.insert(
        key,
        Captured {
            bytes: None,
            preserve_mode: false,
        },
    );
    Some(Ok(()))
}

fn not_found(path: &Path) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::NotFound,
        format!("{} was removed by this run", path.display()),
    )
}

/// Delete `tree` — something the COMMITTED wiring may still name, such as
/// the `.socket/go-patches/` copy a takeover repoints `go.mod` away from —
/// only once the run's commit is on disk, then prune its now-empty parents
/// up to and including `prune_bound`. Deleting it when the run captured the
/// repoint would leave the on-disk `go.mod` naming a deleted directory
/// until the commit, and for good after a crash or a failed commit. With
/// no group open for `tree` it is deleted now (the caller's edit was
/// already written durably).
pub(crate) async fn remove_after_commit(tree: &Path, prune_bound: &Path) {
    if ACTIVE_COUNT.load(Ordering::Acquire) != 0 {
        let overlay = active()
            .iter()
            .find(|o| {
                tree.starts_with(&o.root)
                    || o.canonical_root
                        .as_deref()
                        .is_some_and(|r| tree.starts_with(r))
            })
            .cloned();
        if let Some(overlay) = overlay {
            overlay
                .after_commit
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((tree.to_path_buf(), prune_bound.to_path_buf()));
            return;
        }
    }
    remove_tree_pruned(tree, prune_bound).await;
}

/// Remove the directory `dir` if it is empty — the `.cargo/` a deleted
/// socket-created `.cargo/config.toml` leaves — once the run's commit is on
/// disk. A captured removal of the file inside it only reaches the disk at
/// the commit, so removing the directory now would find it still holding
/// that file. `remove_dir` is non-recursive: a directory holding anything
/// else (a user's credentials, a file the run wrote back) is kept. With no
/// group open for `dir` it is removed now.
pub(crate) async fn remove_dir_after_commit(dir: &Path) {
    if ACTIVE_COUNT.load(Ordering::Acquire) != 0 {
        let overlay = active()
            .iter()
            .find(|o| {
                dir.starts_with(&o.root)
                    || o.canonical_root
                        .as_deref()
                        .is_some_and(|r| dir.starts_with(r))
            })
            .cloned();
        if let Some(overlay) = overlay {
            overlay
                .dirs_after_commit
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(dir.to_path_buf());
            return;
        }
    }
    let _ = tokio::fs::remove_dir(dir).await;
}

/// Delete `tree` (NotFound is fine) and prune its empty parents up to and
/// including `bound`. `remove_dir` is non-recursive: a parent still holding
/// something else fails and stops the prune; a level already gone is
/// skipped.
async fn remove_tree_pruned(tree: &Path, bound: &Path) {
    let _ = crate::patch::copy_tree::remove_tree(tree).await;
    let mut parent = tree.parent().map(Path::to_path_buf);
    while let Some(dir) = parent {
        if !dir.starts_with(bound) {
            break;
        }
        match tokio::fs::remove_dir(&dir).await {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => break,
        }
        parent = dir.parent().map(Path::to_path_buf);
    }
}

/// The error a commit returns when a file replacement failed AND putting
/// the already-replaced files back failed too: the journal is kept, so the
/// next command taking the apply lock rolls the commit forward (every file
/// is at its recorded old bytes or its new ones). See [`is_pending`].
#[derive(Debug)]
struct CommitPending(std::io::Error);

impl std::fmt::Display for CommitPending {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for CommitPending {}

/// Whether a failed [`GroupCommit::commit`] left its journal for the next
/// locked command to finish, rather than leaving the files as they were.
pub fn is_pending(error: &std::io::Error) -> bool {
    error.get_ref().is_some_and(|e| e.is::<CommitPending>())
}

/// An open group commit (see the module docs). Dropping it without
/// [`Self::commit`] discards every captured write — the crash semantics.
pub struct GroupCommit {
    overlay: Arc<Overlay>,
    open: bool,
}

/// One file the commit changes.
struct Change {
    rel: PathBuf,
    before: Option<Vec<u8>>,
    after: Option<Vec<u8>>,
    preserve_mode: bool,
}

impl GroupCommit {
    /// Start capturing the commit points under `root`.
    pub fn begin(root: &Path) -> Self {
        let overlay = Arc::new(Overlay {
            root: root.to_path_buf(),
            canonical_root: std::fs::canonicalize(root).ok(),
            files: Mutex::new(BTreeMap::new()),
            after_commit: Mutex::new(Vec::new()),
            dirs_after_commit: Mutex::new(Vec::new()),
        });
        let mut active = active();
        active.push(Arc::clone(&overlay));
        ACTIVE_COUNT.store(active.len(), Ordering::Release);
        Self {
            overlay,
            open: true,
        }
    }

    fn close(&mut self) {
        if !self.open {
            return;
        }
        self.open = false;
        let mut active = active();
        active.retain(|o| !Arc::ptr_eq(o, &self.overlay));
        ACTIVE_COUNT.store(active.len(), Ordering::Release);
    }

    /// Write the captured state to disk (see the module docs). Returns the
    /// project-relative paths it changed. On failure nothing the commit
    /// wrote is left half-done: when replacing a file failed outright the
    /// files already replaced are put back and the journal removed, and
    /// when putting them back failed too the journal is kept for the next
    /// locked command to roll forward ([`is_pending`]). The trees queued by
    /// [`remove_after_commit`] (and the empty directories queued by
    /// [`remove_dir_after_commit`]) are deleted only after a commit
    /// succeeded.
    pub async fn commit(mut self) -> std::io::Result<Vec<String>> {
        self.close();
        let changed = self.write().await?;
        let removals = std::mem::take(
            &mut *self
                .overlay
                .after_commit
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        for (tree, bound) in removals {
            remove_tree_pruned(&tree, &bound).await;
        }
        let dirs = std::mem::take(
            &mut *self
                .overlay
                .dirs_after_commit
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        for dir in dirs {
            let _ = tokio::fs::remove_dir(&dir).await;
        }
        Ok(changed)
    }

    async fn write(&mut self) -> std::io::Result<Vec<String>> {
        let root = self.overlay.root.clone();
        let captured = std::mem::take(
            &mut *self
                .overlay
                .files
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        let mut changes = Vec::new();
        for (rel, captured) in captured {
            let path = root.join(&rel);
            let before = match super::fs::read_regular_to_bytes(&path).await {
                Ok(bytes) => Some(bytes),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                Err(e) => return Err(e),
            };
            let after = match &captured.bytes {
                Some(content) => Some(content.bytes()?),
                None => None,
            };
            if before == after {
                continue;
            }
            changes.push(Change {
                rel,
                before,
                after,
                preserve_mode: captured.preserve_mode,
            });
        }
        // The ledgers go last: a reader racing the replay without the lock
        // sees the wiring before the ledger that records it, never a ledger
        // naming wiring that is not there yet.
        changes.sort_by_key(|c| is_ledger(&c.rel));
        let changed: Vec<String> = changes.iter().map(|c| rel_string(&c.rel)).collect();
        // Even with nothing to write: an artifact rebuilt in place (a
        // drifted committed copy healed at its own path) is already named
        // by the committed state, so it is synced before the run returns.
        super::durability::barrier().await?;
        if changes.is_empty() {
            return Ok(changed);
        }
        if let [only] = changes.as_slice() {
            apply_durably(&root, only).await?;
            return Ok(changed);
        }
        let journal = root.join(COMMIT_JOURNAL_REL);
        if let Some(parent) = journal.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        super::fs::atomic_write_bytes(&journal, &journal_bytes(&changes)?).await?;
        crate::utils::failpoint::hit("group_commit_journal");
        for (at, change) in changes.iter().enumerate() {
            if let Err(e) = apply_deferred(&root, change).await {
                // Put the replaced files back, and only then drop the
                // journal. When the restore fails as well (the same full
                // disk, say), the journal is the only thing that can make
                // the files agree again: keep it, so the next locked
                // command rolls the commit forward.
                return match restore(&root, &changes[..at]).await {
                    Ok(()) => {
                        let _ = tokio::fs::remove_file(&journal).await;
                        Err(e)
                    }
                    Err(_) => Err(std::io::Error::new(e.kind(), CommitPending(e))),
                };
            }
            crate::utils::failpoint::hit("group_commit_file");
        }
        // Every file holds its new bytes and the journal is durable, so the
        // commit has happened: a failing final sync (or journal removal)
        // leaves the journal for the next locked command, whose replay finds
        // every file already new and only deletes it.
        if super::durability::barrier().await.is_ok()
            && tokio::fs::remove_file(&journal).await.is_ok()
        {
            sync_dir(journal.parent());
        }
        Ok(changed)
    }
}

impl Drop for GroupCommit {
    fn drop(&mut self) {
        self.close();
    }
}

fn is_ledger(rel: &Path) -> bool {
    LEDGERS.contains(&rel_string(rel).as_str())
}

fn rel_string(rel: &Path) -> String {
    rel.to_string_lossy().replace('\\', "/")
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// A one-file commit: the durable writer's own rename is atomic.
async fn apply_durably(root: &Path, change: &Change) -> std::io::Result<()> {
    let path = root.join(&change.rel);
    ensure_parent(&path, change).await?;
    match &change.after {
        Some(bytes) if change.preserve_mode => {
            super::fs::atomic_write_bytes_preserving_mode(&path, bytes).await
        }
        Some(bytes) => super::fs::atomic_write_bytes(&path, bytes).await,
        None => match tokio::fs::remove_file(&path).await {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
            _ => {
                sync_dir(path.parent());
                Ok(())
            }
        },
    }
}

/// Replace one file for a journaled commit: atomic, synced by the barrier
/// that follows.
async fn apply_deferred(root: &Path, change: &Change) -> std::io::Result<()> {
    let path = root.join(&change.rel);
    ensure_parent(&path, change).await?;
    match &change.after {
        Some(bytes) => {
            super::fs::atomic_write_unsynced(&path, bytes, change.preserve_mode).await?;
            super::durability::record(&path);
            Ok(())
        }
        None => match tokio::fs::remove_file(&path).await {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
            _ => {
                if let Some(parent) = path.parent() {
                    super::durability::record_dir(parent);
                }
                Ok(())
            }
        },
    }
}

/// A captured file's directory may have been created by the run only in
/// intent (a writer that created it on disk is the norm, but nothing
/// guarantees it): create it before writing the file.
async fn ensure_parent(path: &Path, change: &Change) -> std::io::Result<()> {
    match (change.after.as_ref(), path.parent()) {
        (Some(_), Some(parent)) => tokio::fs::create_dir_all(parent).await,
        _ => Ok(()),
    }
}

#[cfg(test)]
thread_local! {
    /// Unit tests: make [`restore`] fail, as a full disk would.
    static FAIL_RESTORE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Put `applied` back to their pre-commit bytes (a failed commit).
async fn restore(root: &Path, applied: &[Change]) -> std::io::Result<()> {
    #[cfg(test)]
    if FAIL_RESTORE.with(std::cell::Cell::get) {
        return Err(std::io::Error::other("injected restore failure"));
    }
    for change in applied.iter().rev() {
        let back = Change {
            rel: change.rel.clone(),
            before: change.after.clone(),
            after: change.before.clone(),
            preserve_mode: change.preserve_mode,
        };
        apply_durably(root, &back).await?;
    }
    Ok(())
}

fn sync_dir(dir: Option<&Path>) {
    #[cfg(unix)]
    if let Some(dir) = dir {
        if let Ok(handle) = std::fs::File::open(dir) {
            let _ = handle.sync_all();
        }
    }
    #[cfg(not(unix))]
    let _ = dir;
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct Journal {
    version: u32,
    files: Vec<JournalFile>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct JournalFile {
    /// Project-relative, forward-slashed.
    path: String,
    /// sha256 of the bytes being replaced; `None` when the file is new.
    before: Option<String>,
    /// base64 of the bytes being replaced (hashing to `before`): what a
    /// replay that must stand down puts back, and what a set-aside journal
    /// keeps for a manual restore.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    original: Option<String>,
    /// base64 of the new bytes; `None` when the file is removed.
    after: Option<String>,
    #[serde(default)]
    preserve_mode: bool,
}

const JOURNAL_VERSION: u32 = 1;

fn journal_bytes(changes: &[Change]) -> std::io::Result<Vec<u8>> {
    let journal = Journal {
        version: JOURNAL_VERSION,
        files: changes
            .iter()
            .map(|c| JournalFile {
                path: rel_string(&c.rel),
                before: c.before.as_deref().map(sha256_hex),
                original: c
                    .before
                    .as_deref()
                    .map(|b| base64::engine::general_purpose::STANDARD.encode(b)),
                after: c
                    .after
                    .as_deref()
                    .map(|b| base64::engine::general_purpose::STANDARD.encode(b)),
                preserve_mode: c.preserve_mode,
            })
            .collect(),
    };
    serde_json::to_vec(&journal).map_err(std::io::Error::other)
}

/// What [`recover`] found.
#[derive(Debug, PartialEq, Eq)]
pub enum Recovery {
    /// No journal: the last group commit completed (or none ran).
    Clean,
    /// An interrupted commit was rolled forward; the paths it rewrote.
    RolledForward(Vec<String>),
    /// The journal could not be replayed as a whole (unreadable, unsafe, or
    /// a file changed since the crash to bytes it records neither side of);
    /// it was renamed to `journal`, and `outcome` says what was done to the
    /// files it covers.
    SetAside {
        journal: PathBuf,
        outcome: SetAsideOutcome,
    },
}

/// What a set-aside replay did to the files the journal covers.
#[derive(Debug, PartialEq, Eq)]
pub enum SetAsideOutcome {
    /// Nothing was written: the journal is unreadable, or names a path it
    /// must never write (outside the lockfiles and ledgers, or through a
    /// symbolic link).
    Refused,
    /// Nothing was written: a file changed since the crash, and its edit
    /// does not say which side of the commit it was made on.
    LeftAsIs,
    /// Every file changed since the crash still carries the commit's own
    /// edit, so the rest of the commit was finished around them (the ledger
    /// then records the wiring those files carry).
    FinishedAround(Vec<String>),
    /// No file changed since the crash carries the commit's edit, so the
    /// files the crash had already replaced were put back to their
    /// pre-commit bytes (the pre-run state, bar the hand edits).
    RolledBack(Vec<String>),
}

/// One journaled file as the replay finds it.
struct Replay {
    path: PathBuf,
    after: Option<Vec<u8>>,
    original: Option<Vec<u8>>,
    before_hash: Option<String>,
    preserve_mode: bool,
    current: Option<Vec<u8>>,
}

impl Replay {
    fn at_new(&self) -> bool {
        self.current == self.after
    }

    fn at_old(&self) -> bool {
        self.current.as_deref().map(sha256_hex) == self.before_hash
    }
}

/// Whether a file that matches neither side of the journal still carries
/// the commit's edit (`Some(true)`: it was replaced, then edited), carries
/// none of it (`Some(false)`: it was edited before the crash reached it),
/// or cannot be told (`None`). Line-level: the lines the commit added are
/// all present / all absent, and the lines it removed all absent / all
/// present.
fn carries_commit(item: &Replay) -> Option<bool> {
    match (&item.original, &item.after, &item.current) {
        // The commit created the file: whatever is there now is an edit
        // of ours. It deleted the file: the file still being there means
        // the deletion never ran.
        (None, Some(_), Some(_)) if item.before_hash.is_none() => Some(true),
        (_, None, Some(_)) => Some(false),
        (Some(before), Some(after), Some(current)) => {
            let lines = |b: &[u8]| -> std::collections::HashSet<Vec<u8>> {
                b.split(|c| *c == b'\n').map(<[u8]>::to_vec).collect()
            };
            let (before, after, current) = (lines(before), lines(after), lines(current));
            let added: Vec<_> = after.difference(&before).collect();
            let removed: Vec<_> = before.difference(&after).collect();
            if added.is_empty() && removed.is_empty() {
                return None;
            }
            let has = |l: &&Vec<u8>| current.contains(*l);
            let new_side = added.iter().all(has) && !removed.iter().any(has);
            let old_side = !added.iter().any(has) && removed.iter().all(has);
            match (new_side, old_side) {
                (true, false) => Some(true),
                (false, true) => Some(false),
                _ => None,
            }
        }
        _ => None,
    }
}

/// Whether any existing level of `rel` below `root` — the file itself
/// included — is a symbolic link: a journal must never write through one
/// (out of the project, or onto a file it does not name).
fn crosses_symlink(root: &Path, rel: &Path) -> std::io::Result<bool> {
    let mut at = root.to_path_buf();
    for component in rel.components() {
        at.push(component);
        match std::fs::symlink_metadata(&at) {
            Ok(meta) if meta.file_type().is_symlink() => return Ok(true),
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(e),
        }
    }
    Ok(false)
}

fn write_sync(path: &Path, bytes: Option<&[u8]>, preserve_mode: bool) -> std::io::Result<()> {
    match bytes {
        Some(bytes) => {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            super::fs::atomic_write_sync(path, bytes, preserve_mode)
        }
        None => match std::fs::remove_file(path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
            _ => {
                sync_dir(path.parent());
                Ok(())
            }
        },
    }
}

/// Finish (or set aside) a group commit a crash interrupted — see the
/// module docs. Synchronous: it runs inside the apply-lock acquire, before
/// the locked command reads any file the journal covers. An `Err` (a file
/// it cannot read or write) leaves the journal in place; the caller must
/// not proceed over the files it covers.
pub fn recover(project_root: &Path) -> std::io::Result<Recovery> {
    let journal_path = project_root.join(COMMIT_JOURNAL_REL);
    let raw = match super::fs::read_regular_to_bytes_sync(&journal_path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Recovery::Clean),
        Err(e) => return Err(e),
    };
    let set_aside = |outcome: SetAsideOutcome| -> std::io::Result<Recovery> {
        let aside = journal_path.with_file_name(format!(
            ".commit-journal.set-aside-{}.json",
            uuid::Uuid::new_v4()
        ));
        std::fs::rename(&journal_path, &aside)?;
        sync_dir(journal_path.parent());
        Ok(Recovery::SetAside {
            journal: aside,
            outcome,
        })
    };
    let Ok(journal) = serde_json::from_slice::<Journal>(&raw) else {
        return set_aside(SetAsideOutcome::Refused);
    };
    if journal.version != JOURNAL_VERSION {
        return set_aside(SetAsideOutcome::Refused);
    }
    let decode = |b64: &Option<String>| -> Result<Option<Vec<u8>>, ()> {
        match b64 {
            Some(b64) => base64::engine::general_purpose::STANDARD
                .decode(b64)
                .map(Some)
                .map_err(|_| ()),
            None => Ok(None),
        }
    };
    let mut items: Vec<Replay> = Vec::with_capacity(journal.files.len());
    for file in &journal.files {
        let rel = Path::new(&file.path);
        if relative_to(Path::new(""), rel).is_none()
            || !is_captured(rel)
            || crosses_symlink(project_root, rel)?
        {
            return set_aside(SetAsideOutcome::Refused);
        }
        let (Ok(after), Ok(original)) = (decode(&file.after), decode(&file.original)) else {
            return set_aside(SetAsideOutcome::Refused);
        };
        // A recorded original must be the bytes the hash names.
        if original
            .as_deref()
            .map(sha256_hex)
            .is_some_and(|h| Some(h) != file.before)
        {
            return set_aside(SetAsideOutcome::Refused);
        }
        let path = project_root.join(rel);
        let current = match super::fs::read_regular_to_bytes_sync(&path) {
            Ok(bytes) => Some(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e),
        };
        items.push(Replay {
            path,
            after,
            original,
            before_hash: file.before.clone(),
            preserve_mode: file.preserve_mode,
            current,
        });
    }
    let rel_of =
        |item: &Replay| rel_string(item.path.strip_prefix(project_root).unwrap_or(&item.path));
    let conflicts: Vec<&Replay> = items
        .iter()
        .filter(|i| !i.at_new() && !i.at_old())
        .collect();
    if conflicts.is_empty() {
        let mut rewritten = Vec::new();
        for item in items.iter().filter(|i| !i.at_new()) {
            write_sync(&item.path, item.after.as_deref(), item.preserve_mode)?;
            rewritten.push(rel_of(item));
        }
        std::fs::remove_file(&journal_path)?;
        sync_dir(journal_path.parent());
        return Ok(Recovery::RolledForward(rewritten));
    }
    // Some file was edited after the crash. Never write over that edit;
    // make every other file agree with it instead, when the edit says
    // which side of the commit it was made on.
    let verdicts: Vec<Option<bool>> = conflicts.iter().map(|i| carries_commit(i)).collect();
    let outcome = if verdicts.iter().all(|v| *v == Some(true)) {
        let mut rewritten = Vec::new();
        for item in items.iter().filter(|i| i.at_old() && !i.at_new()) {
            write_sync(&item.path, item.after.as_deref(), item.preserve_mode)?;
            rewritten.push(rel_of(item));
        }
        SetAsideOutcome::FinishedAround(rewritten)
    } else if verdicts.iter().all(|v| *v == Some(false))
        && items
            .iter()
            .filter(|i| i.at_new() && !i.at_old())
            .all(|i| i.original.is_some() || i.before_hash.is_none())
    {
        let mut rewritten = Vec::new();
        for item in items.iter().filter(|i| i.at_new() && !i.at_old()) {
            write_sync(&item.path, item.original.as_deref(), item.preserve_mode)?;
            rewritten.push(rel_of(item));
        }
        SetAsideOutcome::RolledBack(rewritten)
    } else {
        SetAsideOutcome::LeftAsIs
    };
    set_aside(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_scope_is_the_commit_points() {
        for (rel, captured) in [
            ("package-lock.json", true),
            ("packages/a/package.json", true),
            (".cargo/config.toml", true),
            (".socket/vendor/state.json", true),
            (".socket/vendor/redirect-state.json", true),
            (".socket/vendor/npm/u/left-pad-1.3.0.tgz", false),
            (".socket/manifest.json", false),
            ("packages/a/.socket/vendor/npm/u/a.tgz", false),
            ("", false),
        ] {
            assert_eq!(is_captured(Path::new(rel)), captured, "{rel}");
        }
    }

    #[tokio::test]
    async fn reads_see_the_runs_writes_and_nothing_reaches_disk_until_commit() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let lock = root.join("package-lock.json");
        std::fs::write(&lock, b"old").unwrap();
        let group = GroupCommit::begin(root);
        super::super::fs::atomic_write_bytes_preserving_mode(&lock, b"new")
            .await
            .unwrap();
        assert_eq!(
            super::super::fs::read_regular_to_bytes(&lock)
                .await
                .unwrap(),
            b"new"
        );
        assert_eq!(std::fs::read(&lock).unwrap(), b"old", "nothing on disk yet");
        let ws = root.join("pnpm-workspace.yaml");
        super::super::fs::atomic_write_bytes(&ws, b"overrides: {}\n")
            .await
            .unwrap();
        assert!(super::super::fs::file_exists(&ws).await);
        assert!(!ws.exists());
        super::super::fs::remove_file(&ws).await.unwrap();
        assert!(!super::super::fs::file_exists(&ws).await);
        assert_eq!(
            super::super::fs::remove_file(&ws).await.unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
        // An artifact is never captured.
        let tgz = root.join(".socket/vendor/npm/u/a.tgz");
        std::fs::create_dir_all(tgz.parent().unwrap()).unwrap();
        super::super::fs::atomic_write_artifact(&tgz, b"tgz")
            .await
            .unwrap();
        assert_eq!(std::fs::read(&tgz).unwrap(), b"tgz");

        let changed = group.commit().await.unwrap();
        assert_eq!(changed, vec!["package-lock.json".to_string()]);
        assert_eq!(std::fs::read(&lock).unwrap(), b"new");
        assert!(!ws.exists(), "created then removed: never written");
        assert!(!root.join(COMMIT_JOURNAL_REL).exists());
    }

    fn render_string(value: &(dyn Any + Send + Sync)) -> std::io::Result<Vec<u8>> {
        Ok(value.downcast_ref::<String>().unwrap().as_bytes().to_vec())
    }

    /// A value capture answers typed readers with the value itself, byte
    /// readers with its rendering, and commits the rendering.
    #[tokio::test]
    async fn a_captured_value_renders_only_for_bytes_and_the_commit() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join(".socket/vendor")).unwrap();
        let ledger = root.join(".socket/vendor/state.json");
        let group = GroupCommit::begin(root);
        assert!(capture_value(
            &ledger,
            Arc::new("{\"version\":1}\n".to_string()),
            render_string
        ));
        assert_eq!(
            read_value::<String>(&ledger).as_deref().map(String::as_str),
            Some("{\"version\":1}\n")
        );
        assert!(read_value::<u32>(&ledger).is_none(), "typed by T");
        assert_eq!(
            super::super::fs::read_regular_to_bytes(&ledger)
                .await
                .unwrap(),
            b"{\"version\":1}\n"
        );
        assert!(!ledger.exists());
        group.commit().await.unwrap();
        assert_eq!(std::fs::read(&ledger).unwrap(), b"{\"version\":1}\n");
        assert!(read_value::<String>(&ledger).is_none(), "closed");
    }

    #[tokio::test]
    async fn a_dropped_group_commit_writes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let lock = tmp.path().join("yarn.lock");
        std::fs::write(&lock, b"old").unwrap();
        {
            let _group = GroupCommit::begin(tmp.path());
            super::super::fs::atomic_write_bytes(&lock, b"new")
                .await
                .unwrap();
        }
        assert_eq!(std::fs::read(&lock).unwrap(), b"old");
        assert_eq!(
            super::super::fs::read_regular_to_bytes(&lock)
                .await
                .unwrap(),
            b"old",
            "reads go back to the disk once the group is gone"
        );
    }

    #[tokio::test]
    async fn a_multi_file_commit_goes_through_the_journal_and_recovery_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(root.join("package.json"), b"{}\n").unwrap();
        std::fs::write(root.join("pnpm-lock.yaml"), b"lock-old\n").unwrap();
        let group = GroupCommit::begin(root);
        super::super::fs::atomic_write_bytes(&root.join("package.json"), b"{\"a\":1}\n")
            .await
            .unwrap();
        super::super::fs::atomic_write_bytes(&root.join("pnpm-lock.yaml"), b"lock-new\n")
            .await
            .unwrap();
        std::fs::create_dir_all(root.join(".socket/vendor")).unwrap();
        super::super::fs::atomic_write_bytes(&root.join(".socket/vendor/state.json"), b"{}\n")
            .await
            .unwrap();
        let changed = group.commit().await.unwrap();
        assert_eq!(
            changed,
            vec![
                "package.json".to_string(),
                "pnpm-lock.yaml".to_string(),
                ".socket/vendor/state.json".to_string(),
            ],
            "the ledger is committed last"
        );
        assert_eq!(recover(root).unwrap(), Recovery::Clean);
    }

    /// A journal whose replay finds one file already new, one still old and
    /// one removed-to-be finishes all three; a second recovery is a no-op.
    #[test]
    fn recovery_rolls_a_half_applied_journal_forward() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join(".socket/vendor")).unwrap();
        std::fs::write(root.join("a.lock"), b"a-new").unwrap();
        std::fs::write(root.join("b.lock"), b"b-old").unwrap();
        std::fs::write(root.join("c.json"), b"c-old").unwrap();
        let changes = vec![
            Change {
                rel: "a.lock".into(),
                before: Some(b"a-old".to_vec()),
                after: Some(b"a-new".to_vec()),
                preserve_mode: true,
            },
            Change {
                rel: "b.lock".into(),
                before: Some(b"b-old".to_vec()),
                after: Some(b"b-new".to_vec()),
                preserve_mode: false,
            },
            Change {
                rel: "c.json".into(),
                before: Some(b"c-old".to_vec()),
                after: None,
                preserve_mode: false,
            },
        ];
        std::fs::write(
            root.join(COMMIT_JOURNAL_REL),
            journal_bytes(&changes).unwrap(),
        )
        .unwrap();
        assert_eq!(
            recover(root).unwrap(),
            Recovery::RolledForward(vec!["b.lock".into(), "c.json".into()])
        );
        assert_eq!(std::fs::read(root.join("a.lock")).unwrap(), b"a-new");
        assert_eq!(std::fs::read(root.join("b.lock")).unwrap(), b"b-new");
        assert!(!root.join("c.json").exists());
        assert!(!root.join(COMMIT_JOURNAL_REL).exists());
        assert_eq!(recover(root).unwrap(), Recovery::Clean);
    }

    /// A file edited since the crash matches neither side, and the edit
    /// does not say which side it was made on: the journal is set aside
    /// whole and nothing is applied.
    #[test]
    fn recovery_sets_a_conflicting_journal_aside_without_applying_it() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join(".socket/vendor")).unwrap();
        std::fs::write(root.join("a.lock"), b"a-old").unwrap();
        std::fs::write(root.join("b.lock"), b"edited by hand").unwrap();
        let changes = vec![
            Change {
                rel: "a.lock".into(),
                before: Some(b"a-old".to_vec()),
                after: Some(b"a-new".to_vec()),
                preserve_mode: false,
            },
            Change {
                rel: "b.lock".into(),
                before: Some(b"b-old".to_vec()),
                after: Some(b"b-new".to_vec()),
                preserve_mode: false,
            },
        ];
        std::fs::write(
            root.join(COMMIT_JOURNAL_REL),
            journal_bytes(&changes).unwrap(),
        )
        .unwrap();
        match recover(root).unwrap() {
            Recovery::SetAside {
                journal,
                outcome: SetAsideOutcome::LeftAsIs,
            } => assert!(journal.is_file()),
            other => panic!("expected the journal set aside, got {other:?}"),
        }
        assert_eq!(std::fs::read(root.join("a.lock")).unwrap(), b"a-old");
        assert_eq!(
            std::fs::read(root.join("b.lock")).unwrap(),
            b"edited by hand"
        );
        assert!(!root.join(COMMIT_JOURNAL_REL).exists());
    }

    /// A journal naming a path outside the captured set (a tampered file)
    /// is never replayed.
    #[test]
    fn recovery_refuses_a_journal_naming_an_artifact_or_escaping_the_root() {
        for bad in ["../outside", ".socket/vendor/npm/u/a.tgz", "/etc/passwd"] {
            let tmp = tempfile::tempdir().unwrap();
            let root = tmp.path();
            std::fs::create_dir_all(root.join(".socket/vendor")).unwrap();
            let journal = serde_json::json!({
                "version": 1,
                "files": [{ "path": bad, "before": null, "after": "eA==" }]
            });
            std::fs::write(
                root.join(COMMIT_JOURNAL_REL),
                serde_json::to_vec(&journal).unwrap(),
            )
            .unwrap();
            assert_eq!(
                set_aside_outcome(recover(root).unwrap()),
                SetAsideOutcome::Refused,
                "{bad}"
            );
        }
    }

    fn set_aside_outcome(recovery: Recovery) -> SetAsideOutcome {
        match recovery {
            Recovery::SetAside { journal, outcome } => {
                assert!(journal.is_file(), "the set-aside journal is kept");
                outcome
            }
            other => panic!("expected the journal set aside, got {other:?}"),
        }
    }

    fn write_journal(root: &Path, changes: &[Change]) {
        std::fs::create_dir_all(root.join(".socket/vendor")).unwrap();
        std::fs::write(
            root.join(COMMIT_JOURNAL_REL),
            journal_bytes(changes).unwrap(),
        )
        .unwrap();
    }

    fn change(rel: &str, before: &[u8], after: &[u8]) -> Change {
        Change {
            rel: rel.into(),
            before: Some(before.to_vec()),
            after: Some(after.to_vec()),
            preserve_mode: false,
        }
    }

    /// The crash replaced the lock, the ledger was still old, and the lock
    /// was then edited by hand (it still carries the commit's lines): the
    /// rest of the commit is finished around the edit, so the ledger
    /// records the wiring on disk instead of losing it.
    #[test]
    fn recovery_finishes_the_commit_around_an_edit_of_the_new_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let changes = vec![
            change("pylock.toml", b"a\nb\n", b"a\nWIRED\nb\n"),
            change(".socket/vendor/state.json", b"{}\n", b"{\"entries\":1}\n"),
        ];
        write_journal(root, &changes);
        std::fs::write(root.join("pylock.toml"), b"a\nWIRED\nb\nuser\n").unwrap();
        std::fs::write(root.join(".socket/vendor/state.json"), b"{}\n").unwrap();
        assert_eq!(
            set_aside_outcome(recover(root).unwrap()),
            SetAsideOutcome::FinishedAround(vec![".socket/vendor/state.json".into()])
        );
        assert_eq!(
            std::fs::read(root.join("pylock.toml")).unwrap(),
            b"a\nWIRED\nb\nuser\n",
            "the hand edit is never written over"
        );
        assert_eq!(
            std::fs::read(root.join(".socket/vendor/state.json")).unwrap(),
            b"{\"entries\":1}\n"
        );
        assert!(!root.join(COMMIT_JOURNAL_REL).exists());
    }

    /// The crash replaced one file, and a file it had not reached yet was
    /// edited by hand (none of the commit's lines): the replaced file is
    /// put back from the journal's recorded original, so the project is
    /// the pre-run one plus the hand edit.
    #[test]
    fn recovery_rolls_back_around_an_edit_of_the_old_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let changes = vec![
            change("a.lock", b"a-old\n", b"a-new\n"),
            change("package.json", b"x\ny\n", b"x\nWIRED\ny\n"),
        ];
        write_journal(root, &changes);
        std::fs::write(root.join("a.lock"), b"a-new\n").unwrap();
        std::fs::write(root.join("package.json"), b"x\ny\nuser\n").unwrap();
        assert_eq!(
            set_aside_outcome(recover(root).unwrap()),
            SetAsideOutcome::RolledBack(vec!["a.lock".into()])
        );
        assert_eq!(std::fs::read(root.join("a.lock")).unwrap(), b"a-old\n");
        assert_eq!(
            std::fs::read(root.join("package.json")).unwrap(),
            b"x\ny\nuser\n"
        );
    }

    /// A journal never writes through a symlinked directory (out of the
    /// project) or onto a symlink: it is set aside and nothing is written.
    #[cfg(unix)]
    #[test]
    fn recovery_refuses_a_journal_that_crosses_a_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = tmp.path().join("outside");
        let root = tmp.path().join("proj");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::create_dir_all(&root).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();
        std::fs::write(outside.join("target.json"), b"old").unwrap();
        std::os::unix::fs::symlink(outside.join("target.json"), root.join("package.json")).unwrap();
        for rel in ["link/pwned.txt", "package.json"] {
            let changes = vec![
                Change {
                    rel: rel.into(),
                    before: None,
                    after: Some(b"pwned".to_vec()),
                    preserve_mode: false,
                },
                change("b.lock", b"b", b"b2"),
            ];
            write_journal(&root, &changes);
            assert_eq!(
                set_aside_outcome(recover(&root).unwrap()),
                SetAsideOutcome::Refused,
                "{rel}"
            );
            assert!(!outside.join("pwned.txt").exists(), "{rel}");
            assert_eq!(std::fs::read(outside.join("target.json")).unwrap(), b"old");
            assert!(!root.join("b.lock").exists(), "{rel}: nothing applied");
        }
    }

    /// A project whose second journaled file cannot be written: `d/` is
    /// read-only, so creating `d/sub/` fails after `a.lock` was replaced.
    #[cfg(unix)]
    async fn commit_that_fails_on_its_second_file(root: &Path) -> std::io::Result<Vec<String>> {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::write(root.join("a.lock"), b"a-old").unwrap();
        std::fs::create_dir_all(root.join(".socket/vendor")).unwrap();
        std::fs::create_dir_all(root.join("d")).unwrap();
        std::fs::set_permissions(root.join("d"), std::fs::Permissions::from_mode(0o555)).unwrap();
        let group = GroupCommit::begin(root);
        super::super::fs::atomic_write_bytes(&root.join("a.lock"), b"a-new")
            .await
            .unwrap();
        super::super::fs::atomic_write_bytes(&root.join("d/sub/x.lock"), b"x")
            .await
            .unwrap();
        let result = group.commit().await;
        std::fs::set_permissions(root.join("d"), std::fs::Permissions::from_mode(0o755)).unwrap();
        result
    }

    /// A root process ignores the read-only mode the tests rely on.
    #[cfg(unix)]
    fn running_as_root() -> bool {
        std::process::Command::new("id")
            .arg("-u")
            .output()
            .is_ok_and(|o| o.stdout.starts_with(b"0\n"))
    }

    /// A replacement that fails part-way puts the files already replaced
    /// back to their pre-commit bytes and removes the journal.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_failed_commit_puts_the_replaced_files_back() {
        if running_as_root() {
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let err = commit_that_fails_on_its_second_file(root)
            .await
            .unwrap_err();
        assert!(!is_pending(&err), "{err}");
        assert_eq!(std::fs::read(root.join("a.lock")).unwrap(), b"a-old");
        assert!(!root.join("d/sub").exists());
        assert!(!root.join(COMMIT_JOURNAL_REL).exists());
    }

    /// When putting the replaced files back fails too, the journal is the
    /// only thing that can make the files agree again: it is kept, the
    /// error says so, and the next recovery finishes the commit.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_failed_commit_whose_restore_fails_keeps_the_journal() {
        if running_as_root() {
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        FAIL_RESTORE.with(|f| f.set(true));
        let result = commit_that_fails_on_its_second_file(root).await;
        FAIL_RESTORE.with(|f| f.set(false));
        let err = result.unwrap_err();
        assert!(is_pending(&err), "{err}");
        assert!(
            root.join(COMMIT_JOURNAL_REL).exists(),
            "the journal is kept"
        );
        assert_eq!(std::fs::read(root.join("a.lock")).unwrap(), b"a-new");
        assert_eq!(
            recover(root).unwrap(),
            Recovery::RolledForward(vec!["d/sub/x.lock".into()])
        );
        assert_eq!(std::fs::read(root.join("d/sub/x.lock")).unwrap(), b"x");
    }

    /// A tree queued for removal after the commit survives a commit that
    /// never ran (a crash, a failure) and goes once one succeeds, with its
    /// emptied parents pruned up to the bound.
    #[tokio::test]
    async fn trees_queued_for_after_the_commit_go_only_once_it_succeeds() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let bound = root.join(".socket/go-patches");
        let tree = bound.join("example.com/m@v1.0.0");
        std::fs::create_dir_all(&tree).unwrap();
        std::fs::write(tree.join("go.mod"), b"module m\n").unwrap();

        let dropped = GroupCommit::begin(root);
        remove_after_commit(&tree, &bound).await;
        assert!(tree.exists(), "queued, not removed");
        drop(dropped);
        assert!(tree.exists(), "an abandoned commit removes nothing");

        let group = GroupCommit::begin(root);
        remove_after_commit(&tree, &bound).await;
        assert!(tree.exists());
        group.commit().await.unwrap();
        assert!(!bound.exists(), "removed and pruned up to the bound");
        assert!(root.join(".socket").exists(), "never above the bound");
    }

    /// A captured removal of the only file in a directory reaches the disk
    /// at the commit, so the directory queued behind it is removed then —
    /// not before (it still holds the file), not by an abandoned commit,
    /// and never while it holds anything else.
    #[tokio::test]
    async fn a_directory_emptied_by_the_commit_goes_after_it() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let dir = root.join(".cargo");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("config.toml"), b"[patch]\n").unwrap();

        let dropped = GroupCommit::begin(root);
        super::super::fs::remove_file(&dir.join("config.toml"))
            .await
            .unwrap();
        remove_dir_after_commit(&dir).await;
        drop(dropped);
        assert!(dir.join("config.toml").exists(), "an abandoned commit removes nothing");

        let group = GroupCommit::begin(root);
        super::super::fs::remove_file(&dir.join("config.toml"))
            .await
            .unwrap();
        remove_dir_after_commit(&dir).await;
        assert!(dir.join("config.toml").exists(), "captured, still on disk");
        group.commit().await.unwrap();
        assert!(!dir.exists(), "the emptied directory is removed after the commit");

        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("config.toml"), b"[patch]\n").unwrap();
        std::fs::write(dir.join("credentials.toml"), b"token\n").unwrap();
        let group = GroupCommit::begin(root);
        super::super::fs::remove_file(&dir.join("config.toml"))
            .await
            .unwrap();
        remove_dir_after_commit(&dir).await;
        group.commit().await.unwrap();
        assert!(!dir.join("config.toml").exists());
        assert!(dir.join("credentials.toml").exists(), "a non-empty directory is kept");

        remove_dir_after_commit(&root.join("gone")).await;
        std::fs::remove_file(dir.join("credentials.toml")).unwrap();
        remove_dir_after_commit(&dir).await;
        assert!(!dir.exists(), "with no group open it is removed now");
    }
}
