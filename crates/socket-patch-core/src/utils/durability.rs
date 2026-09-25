//! Deferred durability for content-verified artifacts, and the one
//! durability barrier in front of every durable commit point.
//!
//! # Two classes of write
//!
//! Every file socket-patch writes goes through the stage + rename writer in
//! [`super::fs`], so a reader only ever sees the complete old or the complete
//! new bytes. What differs is whether the bytes must survive a power loss
//! the moment the call returns:
//!
//! * **Durable commit points** — the files that decide what a project
//!   resolves and what `--revert` can restore: lockfiles, `go.mod`/`go.sum`,
//!   `pom.xml`, `nuget.config`, `package.json`, `pnpm-workspace.yaml`,
//!   `.cargo/config.toml`, the requirement/Pipfile/pyproject surfaces, and
//!   the ledgers (`.socket/vendor/state.json`, `redirect-state.json`).
//!   [`super::fs::atomic_write_bytes`] fsyncs the staged file and its
//!   directory, as it always did.
//! * **Content-verified artifacts** — what vendoring produces under
//!   `.socket/vendor/<eco>/<uuid>/`: the patched copy trees, the `.tgz` /
//!   `.whl` / `.gem` / `.crate` / `.nupkg` / `.jar` + `.pom` artifacts and
//!   their `.sha1` sidecars, and the informational marker.
//!   [`super::fs::atomic_write_artifact`] writes and renames them WITHOUT an
//!   fsync and records them here instead.
//!
//! # The barrier
//!
//! [`barrier`] fsyncs every artifact recorded since the last barrier, then
//! each of their directories once (a uuid dir holding the artifact and the
//! marker is synced once, not twice), and — on Apple platforms, where
//! `fsync(2)` stops at the drive's cache — issues ONE `F_FULLFSYNC` per
//! device to flush that cache for everything before it. Every durable
//! commit-point write runs the barrier first, so a lockfile or ledger that
//! names an artifact is never made durable ahead of the artifact itself: the
//! per-file `F_FULLFSYNC` pair each artifact used to pay collapses into one
//! plain `fsync` per file plus one cache flush per commit point.
//!
//! # Why a crash cannot corrupt a project
//!
//! A crash (or power loss) can now lose artifact bytes that a durable write
//! would have kept: a renamed-over artifact may come back empty, truncated,
//! or missing after a reboot. That is safe because nothing trusts an
//! artifact's bytes without re-verifying them, on every run:
//!
//! 1. **Before the barrier nothing new refers to the artifact.** The
//!    commit points still hold their pre-run bytes (the barrier runs before
//!    the first commit-point write; with the group commit the whole run's
//!    commit points are written after it), so a newly built artifact is an
//!    orphan in a uuid dir no ledger entry and no lockfile names. The next
//!    run re-derives everything from the ledger, finds no entry for it, and
//!    re-vendors — each backend rebuilds a uuid dir it does not own the
//!    ledger for — and `vendor --revert` / the orphan sweep delete
//!    unreferenced uuid dirs. The one exception is an artifact REBUILT IN
//!    PLACE (a drifted or missing committed artifact healed at its own
//!    path), which the committed state already names; a rebuild that
//!    changes no lockfile and no ledger byte reaches no commit point, so
//!    the group commit runs the barrier even when it has nothing to write,
//!    and releasing the apply lock runs it once more for every other
//!    command ([`barrier_blocking`]): the command never returns with an
//!    unsynced artifact.
//! 2. **After the barrier the artifact is as durable as before.** Its data
//!    and directory entry were fsynced (and the device cache flushed) before
//!    the commit point that references it was written.
//! 3. **Consumers re-verify.** `repair` rebuilds a missing or drifted
//!    artifact; `vex` and `verify` refuse to attest one that does not match
//!    the ledger (`sha256` for a file artifact, the per-file afterHashes and
//!    the full-tree `fileInventory` for a copy dir); a lockfile integrity
//!    field makes the package manager refuse it; the re-run deferral that
//!    skips the pristine download hashes a file artifact before trusting
//!    it. (Some backends' in-sync checks look only for the artifact's
//!    presence — pypi's among them, unchanged by this module — which is
//!    why point 1 never leaves an artifact the committed state names
//!    unsynced.) The marker is never a trust input at all.
//!
//! So a crash can only lose an artifact nothing durable names yet, which
//! the next run rebuilds exactly as it would one deleted by hand.
//!
//! The patched files the apply engine writes into a vendor stage are
//! artifacts too: [`artifact_writes`] marks the vendor stage's apply calls,
//! and the in-place `apply` of an installed tree (which has no later
//! verifying run to fall back on) keeps its durable writes.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Artifacts written since the last barrier, and their directories.
struct Pending {
    files: Vec<PathBuf>,
    dirs: BTreeSet<PathBuf>,
}

static PENDING: Mutex<Pending> = Mutex::new(Pending {
    files: Vec::new(),
    dirs: BTreeSet::new(),
});

fn pending() -> std::sync::MutexGuard<'static, Pending> {
    PENDING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl Pending {
    fn record(&mut self, path: &Path) {
        if let Some(parent) = path.parent() {
            self.dirs.insert(parent.to_path_buf());
        }
        self.files.push(path.to_path_buf());
    }

    fn moved(&mut self, from: &Path, to: &Path) {
        let mut touched = false;
        for file in self.files.iter_mut() {
            if let Ok(rest) = file.strip_prefix(from) {
                *file = to.join(rest);
                touched = true;
            }
        }
        let dirs: Vec<PathBuf> = self
            .dirs
            .iter()
            .filter(|d| d.starts_with(from))
            .cloned()
            .collect();
        for dir in dirs {
            self.dirs.remove(&dir);
            if let Ok(rest) = dir.strip_prefix(from) {
                self.dirs.insert(to.join(rest));
            }
            touched = true;
        }
        if touched {
            if let Some(parent) = to.parent() {
                self.dirs.insert(parent.to_path_buf());
            }
        }
    }
}

/// Record an artifact written without an fsync: the barrier syncs it and
/// its directory.
pub(crate) fn record(path: &Path) {
    pending().record(path);
}

/// Record a directory whose entries changed without an fsync (a removed
/// file): the barrier syncs it.
pub(crate) fn record_dir(dir: &Path) {
    pending().dirs.insert(dir.to_path_buf());
}

/// A staged tree was renamed from `from` to `to` (the vendor stage swapped
/// into its copy dir): the artifacts recorded inside it now live under
/// `to`, and the rename itself is an entry in `to`'s parent that the
/// barrier must sync.
pub(crate) fn moved(from: &Path, to: &Path) {
    pending().moved(from, to);
}

/// The durability barrier (see the module docs). A no-op when nothing is
/// pending. An artifact removed since it was written (a failed package's
/// unwind) is skipped; any other fsync failure is returned, and the caller
/// — a durable commit point — must not proceed, since what it would name
/// may not be on disk. A directory sync stays best-effort, as it always
/// was for the durable writer. A failed barrier keeps everything it took
/// pending, so the next barrier (a caller that carries on, or the one the
/// apply lock's release runs) syncs it again rather than skipping it.
pub(crate) async fn barrier() -> std::io::Result<()> {
    let Some((files, dirs)) = take_pending() else {
        return Ok(());
    };
    crate::utils::failpoint::hit("durability_barrier");
    let synced = tokio::task::spawn_blocking(move || {
        let result = sync_all_blocking(&files, &dirs);
        (result, files, dirs)
    })
    .await;
    match synced {
        Ok((Ok(()), _, _)) => Ok(()),
        Ok((Err(e), files, dirs)) => {
            restore_pending(files, dirs);
            Err(e)
        }
        Err(_) => Err(std::io::Error::other("background task failed")),
    }
}

/// [`barrier`], blocking — for the apply lock's release, which runs it
/// once more so an artifact rewritten in place without any later commit
/// point (a rebuild that left every lockfile and the ledger unchanged) is
/// synced before the command returns.
pub(crate) fn barrier_blocking() -> std::io::Result<()> {
    let Some((files, dirs)) = take_pending() else {
        return Ok(());
    };
    let result = sync_all_blocking(&files, &dirs);
    if result.is_err() {
        restore_pending(files, dirs);
    }
    result
}

fn take_pending() -> Option<(Vec<PathBuf>, BTreeSet<PathBuf>)> {
    let mut pending = pending();
    if pending.files.is_empty() && pending.dirs.is_empty() {
        return None;
    }
    Some((
        std::mem::take(&mut pending.files),
        std::mem::take(&mut pending.dirs),
    ))
}

fn restore_pending(files: Vec<PathBuf>, dirs: BTreeSet<PathBuf>) {
    let mut pending = pending();
    pending.files.extend(files);
    pending.dirs.extend(dirs);
}

/// Plain-fsync every file and directory, then flush each device's cache
/// once where the platform needs a separate call for that.
pub(crate) fn sync_all_blocking(
    files: &[PathBuf],
    dirs: &BTreeSet<PathBuf>,
) -> std::io::Result<()> {
    // One open handle per device for the final cache flush.
    let mut flush: BTreeMap<u64, std::fs::File> = BTreeMap::new();
    let mut seen: BTreeSet<&Path> = BTreeSet::new();
    for file in files {
        if !seen.insert(file.as_path()) {
            continue;
        }
        let handle = match std::fs::File::open(file) {
            Ok(h) => h,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        plain_fsync(&handle)?;
        keep_for_flush(&mut flush, handle);
    }
    #[cfg(unix)]
    for dir in dirs {
        if let Ok(handle) = std::fs::File::open(dir) {
            let _ = plain_fsync(&handle);
            keep_for_flush(&mut flush, handle);
        }
    }
    #[cfg(not(unix))]
    let _ = dirs;
    for handle in flush.values() {
        device_flush(handle)?;
    }
    Ok(())
}

fn keep_for_flush(flush: &mut BTreeMap<u64, std::fs::File>, handle: std::fs::File) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let Ok(meta) = handle.metadata() {
            flush.entry(meta.dev()).or_insert(handle);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (flush, handle);
    }
}

/// `fsync(2)` without Apple's `F_FULLFSYNC` (std's `sync_all` issues that
/// one on Apple platforms): data and metadata reach the device.
#[cfg(unix)]
fn plain_fsync(handle: &std::fs::File) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;
    // SAFETY: `fsync` on a descriptor this function borrows for the call.
    if unsafe { libc::fsync(handle.as_raw_fd()) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(unix))]
fn plain_fsync(handle: &std::fs::File) -> std::io::Result<()> {
    handle.sync_all()
}

/// Flush the device's write cache: `F_FULLFSYNC` on Apple platforms (what
/// std's `sync_all` issues there), nothing elsewhere — a plain `fsync` is
/// already the durability point on Linux, and Windows' `FlushFileBuffers`
/// ran per file.
#[cfg(target_vendor = "apple")]
fn device_flush(handle: &std::fs::File) -> std::io::Result<()> {
    handle.sync_all()
}

#[cfg(not(target_vendor = "apple"))]
fn device_flush(_handle: &std::fs::File) -> std::io::Result<()> {
    Ok(())
}

tokio::task_local! {
    static ARTIFACT_SCOPE: ();
}

/// Run `f` with the apply engine's patched-file writes classed as artifact
/// writes (see the module docs): the vendor stage's apply, whose output is
/// re-verified on every later run.
pub(crate) async fn artifact_writes<F: Future>(f: F) -> F::Output {
    ARTIFACT_SCOPE.scope((), f).await
}

/// Whether the current task runs inside [`artifact_writes`].
pub(crate) fn in_artifact_scope() -> bool {
    ARTIFACT_SCOPE.try_with(|_| ()).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn moved_rekeys_files_and_dirs_under_the_renamed_tree() {
        let tmp = tempfile::tempdir().unwrap();
        let stage = tmp.path().join("copy.socket-stage");
        let copy = tmp.path().join("copy");
        let mut pending = Pending {
            files: Vec::new(),
            dirs: BTreeSet::new(),
        };
        pending.record(&stage.join("src/lib.rs"));
        pending.record(&tmp.path().join("marker"));
        pending.moved(&stage, &copy);
        assert!(pending.files.contains(&tmp.path().join("marker")));
        assert!(pending.files.contains(&copy.join("src/lib.rs")));
        assert!(!pending.files.iter().any(|f| f.starts_with(&stage)));
        assert!(pending.dirs.contains(&copy.join("src")));
        assert!(pending.dirs.contains(&tmp.path().to_path_buf()));
    }

    #[test]
    fn sync_skips_vanished_files_and_syncs_the_rest() {
        let tmp = tempfile::tempdir().unwrap();
        let kept = tmp.path().join("kept");
        std::fs::write(&kept, b"x").unwrap();
        let gone = tmp.path().join("gone");
        let dirs: BTreeSet<PathBuf> = [tmp.path().to_path_buf()].into();
        sync_all_blocking(&[kept.clone(), gone, kept], &dirs).unwrap();
    }

    #[tokio::test]
    async fn artifact_scope_is_task_local() {
        assert!(!in_artifact_scope());
        artifact_writes(async { assert!(in_artifact_scope()) }).await;
        assert!(!in_artifact_scope());
    }
}
