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
//!    every changed file's new bytes (or its deletion) and a sha256 of the
//!    bytes it replaces — THIS is the commit point;
//! 3. the files are replaced (stage + rename each, ledgers last), one
//!    barrier syncs them all, and the journal is deleted.
//!
//! A crash between 2 and the journal's deletion leaves a journal that the
//! next command taking the apply lock replays ([`recover`], run by
//! [`crate::patch::apply_lock::acquire`]): each file already at its new
//! bytes is left alone, each still at its recorded old bytes is replaced,
//! and a file matching neither (edited by hand since the crash) makes the
//! whole journal stand down — it is renamed aside, never half-applied. So
//! the lockfiles and the ledger are only ever observed all-old or all-new
//! by the next locked command; never a half-wired lock with a ledger that
//! disagrees. A single changed file needs no journal: its own atomic
//! rename is the commit.

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
    /// wrote is left half-done: the journal is replayed by the next locked
    /// command, or — when replacing a file failed outright — the files
    /// already replaced are put back and the journal removed.
    pub async fn commit(mut self) -> std::io::Result<Vec<String>> {
        self.close();
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
                let _ = restore(&root, &changes[..at]).await;
                let _ = tokio::fs::remove_file(&journal).await;
                return Err(e);
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

/// Put `applied` back to their pre-commit bytes (a failed commit).
async fn restore(root: &Path, applied: &[Change]) -> std::io::Result<()> {
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
    /// The journal could not be replayed as a whole (unreadable, or a file
    /// changed since the crash to bytes it records neither side of); it was
    /// renamed to the path given and nothing was applied.
    SetAside(PathBuf),
}

/// Finish (or set aside) a group commit a crash interrupted — see the
/// module docs. Synchronous: it runs inside the apply-lock acquire, before
/// the locked command reads any file the journal covers.
pub fn recover(project_root: &Path) -> std::io::Result<Recovery> {
    let journal_path = project_root.join(COMMIT_JOURNAL_REL);
    let raw = match super::fs::read_regular_to_bytes_sync(&journal_path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Recovery::Clean),
        Err(e) => return Err(e),
    };
    let set_aside = || -> std::io::Result<Recovery> {
        let aside = journal_path.with_file_name(format!(
            ".commit-journal.set-aside-{}.json",
            uuid::Uuid::new_v4()
        ));
        std::fs::rename(&journal_path, &aside)?;
        Ok(Recovery::SetAside(aside))
    };
    let Ok(journal) = serde_json::from_slice::<Journal>(&raw) else {
        return set_aside();
    };
    if journal.version != JOURNAL_VERSION {
        return set_aside();
    }
    let mut pending: Vec<(PathBuf, Option<Vec<u8>>, bool)> = Vec::new();
    for file in &journal.files {
        let rel = Path::new(&file.path);
        if relative_to(Path::new(""), rel).is_none() || !is_captured(rel) {
            return set_aside();
        }
        let after = match &file.after {
            Some(b64) => match base64::engine::general_purpose::STANDARD.decode(b64) {
                Ok(bytes) => Some(bytes),
                Err(_) => return set_aside(),
            },
            None => None,
        };
        let path = project_root.join(rel);
        let current = match super::fs::read_regular_to_bytes_sync(&path) {
            Ok(bytes) => Some(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e),
        };
        if current == after {
            continue;
        }
        let current_hash = current.as_deref().map(sha256_hex);
        if current_hash != file.before {
            return set_aside();
        }
        pending.push((path, after, file.preserve_mode));
    }
    let mut rewritten = Vec::new();
    for (path, after, preserve_mode) in &pending {
        match after {
            Some(bytes) => {
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                super::fs::atomic_write_sync(path, bytes, *preserve_mode)?
            }
            None => match std::fs::remove_file(path) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
                _ => sync_dir(path.parent()),
            },
        }
        rewritten.push(rel_string(path.strip_prefix(project_root).unwrap_or(path)));
    }
    std::fs::remove_file(&journal_path)?;
    sync_dir(journal_path.parent());
    Ok(Recovery::RolledForward(rewritten))
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

    /// A file edited since the crash matches neither side: the journal is
    /// set aside whole and nothing is applied.
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
            Recovery::SetAside(path) => assert!(path.is_file()),
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
            assert!(
                matches!(recover(root).unwrap(), Recovery::SetAside(_)),
                "{bad}"
            );
        }
    }
}
