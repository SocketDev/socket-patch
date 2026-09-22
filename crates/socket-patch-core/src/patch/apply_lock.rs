//! Advisory file lock used to serialize mutating operations against a
//! single `.socket/` directory.
//!
//! Apply, rollback, repair, remove, vendor and the hosted/vendored scan
//! flows can each rewrite manifest state and on-disk package files. Two
//! of them running at once against the same project — common when a dev
//! runs `socket-patch apply` while CI triggers a deploy hook, or when
//! `apply` and a `repair` are stacked by a wrapper script — race on
//! every file write. The lock turns that race into a clean refusal: the
//! second invocation reports `lock_held` and exits non-zero, leaving the
//! first to finish.
//!
//! # Lifecycle
//!
//! The lock file lives at `<.socket>/apply.lock` and exists only while a
//! command holds the lock:
//!
//! * [`acquire`] creates `socket_dir` itself (idempotently, inside the
//!   retry loop), opens-or-creates `apply.lock`, takes the OS lock, and
//!   then verifies that the handle it locked is still the file the path
//!   names ([`same_file::Handle`] identity: device + inode on Unix,
//!   volume serial + file index on Windows). A mismatch means a releaser
//!   unlinked the file between our open and our lock, so the handle is
//!   an orphan: we drop it and retry against whatever the path names now.
//! * [`LockGuard`]'s drop unlinks `apply.lock` WHILE STILL HOLDING the
//!   lock, then closes the handle (releasing the lock), then best-effort
//!   removes an otherwise-empty `.socket/`. Unlinking under the lock is
//!   what makes the unlink safe: any waiter that already opened this
//!   inode fails the identity check once it finally locks it, instead of
//!   becoming a second live holder alongside whoever locked the
//!   replacement file.
//!
//! So no command leaves `apply.lock` behind, and a project that had no
//! `.socket/` before a run has none after it unless the run wrote real
//! state there. A leftover file from a crashed run needs no removal to
//! unblock anything — the kernel released the dead process's advisory
//! lock with its file handle — so the next acquire reclaims it in place
//! and removes it on exit. `Held` therefore always means a live process.
//!
//! # Windows
//!
//! `DeleteFile` on an open file succeeds, but the name stays
//! delete-pending until the last handle closes, and every open of that
//! name in the meantime fails with `ERROR_ACCESS_DENIED` (5),
//! `ERROR_SHARING_VIOLATION` (32) or `ERROR_DELETE_PENDING` (303). Two
//! measures keep that window short and harmless: a waiter never holds
//! the file open across its backoff sleep, and those three codes get a
//! short fixed grace (5 ms × 40, independent of the caller's timeout)
//! before they surface as `Io`. std's default share mode already
//! includes `FILE_SHARE_DELETE`, so a holder can unlink the file while
//! waiters have it open.
//!
//! Locking is advisory (`flock(2)` on Unix, `LockFileEx` on Windows via
//! the `fs2` crate). Non-cooperating writers (a user shelling
//! `rm -rf .socket/`) are not stopped — but every socket-patch mutating
//! command honors the lock, which is what matters in practice.

use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use fs2::FileExt;
use same_file::Handle;
use thiserror::Error;

const LOCK_FILE_NAME: &str = "apply.lock";
const SOCKET_DIR_NAME: &str = ".socket";

/// Longest single backoff sleep while waiting on a live holder.
const BACKOFF_CAP: Duration = Duration::from_millis(100);

/// Consecutive "the file vanished under us" retries (open `NotFound` /
/// `EINVAL`, or a post-lock identity mismatch) before giving up with
/// `Io`. Each one means a releaser pruned `.socket/` between two of our
/// steps — i.e. a competitor completed a whole acquire→release cycle —
/// so they are not contention and are bounded by count rather than by
/// `timeout`. The bound is generous: two processes hammering the lock
/// back-to-back (the unit tests do exactly that) can string dozens of
/// these together, each costing only a `yield_now`.
const VANISHED_LIMIT: u32 = 256;

/// `EINVAL`: macOS reports an `O_CREAT` open inside a directory that was
/// rmdir'd a moment ago with this errno instead of `ENOENT`. Same value
/// on every Unix we build for; unused on Windows.
#[cfg(unix)]
const EINVAL: i32 = 22;

/// Windows delete-pending grace: `attempts × sleep`, independent of
/// `timeout` (a zero-timeout try-once still waits it out, because the
/// name is free, just not reusable yet).
const DELETE_PENDING_ATTEMPTS: u32 = 40;
const DELETE_PENDING_SLEEP: Duration = Duration::from_millis(5);

/// Errors surfaced when acquiring the apply lock.
#[derive(Debug, Error)]
pub enum LockError {
    /// Another `socket-patch` process holds the lock and `timeout`
    /// (possibly zero) elapsed without the lock becoming available.
    #[error("another socket-patch process is operating in this directory")]
    Held,

    /// We could not create `socket_dir`, or could not open or lock the
    /// lock file (a file squatting on `.socket/`, a directory squatting
    /// on `apply.lock`, a permissions problem, a filesystem without
    /// advisory locks, …). `path` is the directory for a `create_dir`
    /// failure and the lock file otherwise.
    #[error("failed to open lock file at {path:?}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// RAII guard for the apply lock.
///
/// Drop unlinks `apply.lock` while still holding the lock, releases the
/// OS-level advisory lock by closing the handle, and then best-effort
/// removes an otherwise-empty `.socket/` (see the module doc). There is
/// no fallible `unlock()` API on purpose — Rust's drop guarantees are
/// simpler to reason about than a `?`-fallible unlock path; [`release`]
/// exists only to name an early drop.
///
/// [`release`]: LockGuard::release
#[derive(Debug)]
#[must_use = "the lock is released when this guard is dropped"]
pub struct LockGuard {
    // `Some` for the guard's whole life. `Drop` clears it so the handle
    // closes (releasing the lock) BETWEEN unlinking the file and pruning
    // the directory: Windows only lets go of the name once the last
    // handle is gone, so the rmdir has to come after the close.
    handle: Option<Handle>,
    path: PathBuf,
    socket_dir: PathBuf,
}

impl LockGuard {
    /// Release the lock now — unlink, close, prune — instead of at the
    /// end of the guard's scope.
    pub fn release(self) {
        drop(self);
    }
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        // R1: unlink while still holding the lock. `NotFound` (a
        // non-cooperating `rm`) and every other error are ignored: a
        // leftover file is harmless and reclaimed by the next acquire.
        let _ = std::fs::remove_file(&self.path);
        // R2: close the handle; the OS releases the advisory lock.
        self.handle = None;
        // R3: prune an otherwise-empty `.socket/`. Non-recursive, so it
        // fails harmlessly when anything else lives there — including a
        // concurrent acquirer's freshly created `apply.lock`.
        prune_empty_socket_dir(&self.socket_dir);
    }
}

/// Best-effort `remove_dir` of `socket_dir`, gated to a directory
/// literally named `.socket`: `--manifest-path` can point the lock at an
/// arbitrary user directory, and the lock must never delete one of those
/// just because it happened to be empty.
fn prune_empty_socket_dir(socket_dir: &Path) {
    if socket_dir
        .file_name()
        .is_some_and(|name| name == SOCKET_DIR_NAME)
    {
        let _ = std::fs::remove_dir(socket_dir);
    }
}

/// Try to acquire the apply lock at `<socket_dir>/apply.lock`.
///
/// `timeout = Duration::ZERO` makes this a non-blocking try-once. Any
/// positive `timeout` re-tries with a 100 ms backoff until the lock
/// becomes available or the budget elapses. Only genuine contention (a
/// live holder) consumes the budget; the transient outcomes of racing a
/// releaser's cleanup — the directory or file vanishing between two of
/// our steps, Windows delete-pending opens — are retried on their own
/// small fixed bounds so a zero-timeout caller still gets its one honest
/// attempt.
///
/// `socket_dir` is created on demand (idempotently, inside the retry
/// loop, because a finished holder prunes an empty `.socket/` on exit).
/// A failed acquire prunes it again if it is still empty, so a refused
/// lock leaves no residue.
pub fn acquire(socket_dir: &Path, timeout: Duration) -> Result<LockGuard, LockError> {
    let path = socket_dir.join(LOCK_FILE_NAME);

    // Use `checked_add` so an astronomically large `timeout` (the flag
    // is a user-supplied `u64` of seconds — e.g. `--lock-timeout` /
    // `SOCKET_LOCK_TIMEOUT` set to `u64::MAX`) does not panic the whole
    // process with "overflow when adding duration to instant". An
    // overflowing deadline is treated as `None` — i.e. wait
    // indefinitely, which is what a near-infinite timeout asks for —
    // while still capping each sleep at 100 ms so the loop stays
    // responsive and `ZERO` keeps its non-blocking try-once semantics.
    let deadline = Instant::now().checked_add(timeout);
    let mut vanished: u32 = 0;
    let mut delete_pending: u32 = 0;
    loop {
        // One mkdir → open → lock → identity-check attempt, in its own
        // function so the file handle is closed before any sleep below:
        // a waiter parked with the file open would prolong a Windows
        // delete-pending window for everyone.
        match attempt(&path, socket_dir) {
            Attempt::Acquired(guard) => return Ok(guard),
            Attempt::Contended => {
                let now = Instant::now();
                // A `None` deadline (timeout overflowed `Instant`) never
                // elapses; otherwise give up once the budget is spent.
                if deadline.is_some_and(|d| now >= d) {
                    return Err(LockError::Held);
                }
                // Never sleep past the deadline: a sub-100 ms budget
                // must not be rounded up to a full 100 ms wait. When
                // there is a deadline the remaining slice is always > 0
                // here (now < deadline); with no deadline, just use the
                // full quantum.
                let sleep_for = match deadline {
                    Some(d) => (d - now).min(BACKOFF_CAP),
                    None => BACKOFF_CAP,
                };
                std::thread::sleep(sleep_for);
            }
            Attempt::Vanished => {
                vanished += 1;
                if vanished > VANISHED_LIMIT {
                    let source = std::io::Error::new(
                        ErrorKind::NotFound,
                        "lock file kept vanishing while acquiring it",
                    );
                    return Err(fail(socket_dir, path, source));
                }
                // Let the releaser finish its unlink → close → rmdir
                // before we mkdir again; spinning straight back in just
                // races the same cleanup a second time.
                std::thread::yield_now();
            }
            Attempt::DeletePending(source) => {
                delete_pending += 1;
                if delete_pending > DELETE_PENDING_ATTEMPTS {
                    return Err(fail(socket_dir, path, source));
                }
                std::thread::sleep(DELETE_PENDING_SLEEP);
            }
            Attempt::Fault { path, source } => return Err(fail(socket_dir, path, source)),
        }
    }
}

/// Outcome of one mkdir → open → lock → identity-check attempt. Every
/// variant but `Acquired` has already closed its file handle.
enum Attempt {
    Acquired(LockGuard),
    /// A live holder has the lock (the `fs2` contention sentinel).
    Contended,
    /// The directory or file disappeared between two of our steps, or
    /// the handle we locked is an orphan: a releaser ran its cleanup.
    Vanished,
    /// Windows: the name is still delete-pending from a releaser's
    /// unlink; free, but not reusable until its last handle closes.
    DeletePending(std::io::Error),
    /// A genuine I/O fault at `path` — surface immediately, never as
    /// `Held`.
    Fault {
        path: PathBuf,
        source: std::io::Error,
    },
}

fn attempt(path: &Path, socket_dir: &Path) -> Attempt {
    // 1. The directory, idempotently. Inside every attempt on purpose:
    // a releaser may have pruned it since the last one.
    match std::fs::create_dir_all(socket_dir) {
        Ok(()) => {}
        // std's `create_dir_all` stats the path after `EEXIST` to decide
        // whether the existing entry is a directory; a releaser pruning
        // it between those two syscalls makes that stat fail and the
        // call report `AlreadyExists` for a directory that is now gone.
        // Re-check: a non-directory squatting on the path is a fault;
        // anything else (still a directory, or vanished again) is left
        // to the open below, which reports a missing parent as
        // `Vanished`.
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {
            if std::fs::metadata(socket_dir).is_ok_and(|md| !md.is_dir()) {
                return Attempt::Fault {
                    path: socket_dir.to_path_buf(),
                    source: e,
                };
            }
        }
        Err(e) if is_delete_pending(&e) => return Attempt::DeletePending(e),
        Err(e) => {
            return Attempt::Fault {
                path: socket_dir.to_path_buf(),
                source: e,
            }
        }
    }

    // 2a. Open (or create) the lock file. `create(true)` is idempotent
    // if it already exists; we never write to the file, only lock it.
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
    {
        Ok(file) => file,
        Err(e) => return open_failure(e, path, socket_dir),
    };

    // 2b. Only a genuine "someone else holds it" signal counts as
    // contention. Any other failure (ENOLCK, EBADF, a filesystem that
    // doesn't support advisory locks, EACCES on a read-only lock file,
    // …) is a real I/O fault: surface it immediately rather than
    // busy-sleeping for the whole budget and then mislabelling it as
    // `Held`. See `is_lock_contended`.
    match file.try_lock_exclusive() {
        Ok(()) => {}
        Err(ref e) if is_lock_contended(e) => return Attempt::Contended,
        Err(source) => {
            return Attempt::Fault {
                path: path.to_path_buf(),
                source,
            }
        }
    }

    // 2c. Identity check: is the handle we locked still the file the
    // path names? `from_file` consumes the `File` (it needs the fstat
    // identity), so the guard keeps the `Handle`; `as_file` would give
    // the `File` back if anyone ever needed it. Dropping `held` on the
    // mismatch arms releases the orphan's lock.
    let held = match Handle::from_file(file) {
        Ok(held) => held,
        Err(source) => {
            return Attempt::Fault {
                path: path.to_path_buf(),
                source,
            }
        }
    };
    match Handle::from_path(path) {
        Ok(now) if now == held => Attempt::Acquired(LockGuard {
            handle: Some(held),
            path: path.to_path_buf(),
            socket_dir: socket_dir.to_path_buf(),
        }),
        // The path names a replacement: a releaser unlinked the inode we
        // locked between our open and our lock, and a newcomer created
        // the next file.
        Ok(_) => Attempt::Vanished,
        Err(e) => open_failure(e, path, socket_dir),
    }
}

/// Classify a failed open (or identity probe) of the lock file. A
/// missing file or parent is a releaser's cleanup racing us (retry);
/// so is any other failure while the parent directory is gone — macOS
/// reports an `O_CREAT` open inside a directory that was rmdir'd a
/// moment ago as `EINVAL` rather than `ENOENT`. Windows delete-pending
/// codes get their grace; everything else is a genuine fault.
fn open_failure(e: std::io::Error, path: &Path, socket_dir: &Path) -> Attempt {
    if e.kind() == ErrorKind::NotFound {
        return Attempt::Vanished;
    }
    // Unconditional, not gated on a "is the parent gone right now" stat:
    // a competitor can recreate the directory between our failed open
    // and that probe, which would misreport this benign race as a fault
    // (seen under full-suite load). We never pass invalid flags, so
    // `EINVAL` on this open has no other cause.
    #[cfg(unix)]
    if e.raw_os_error() == Some(EINVAL) {
        return Attempt::Vanished;
    }
    if is_delete_pending(&e) {
        return Attempt::DeletePending(e);
    }
    if matches!(std::fs::metadata(socket_dir), Err(ref m) if m.kind() == ErrorKind::NotFound) {
        return Attempt::Vanished;
    }
    Attempt::Fault {
        path: path.to_path_buf(),
        source: e,
    }
}

/// Build the `Io` error for a failed acquire, first pruning the empty
/// `.socket/` this call may have created so a refused lock leaves no
/// residue behind. (`remove_dir` is non-recursive: a lock file we
/// created but could not lock keeps the directory, on purpose — we must
/// never unlink a file we do not hold the lock on.)
fn fail(socket_dir: &Path, path: PathBuf, source: std::io::Error) -> LockError {
    prune_empty_socket_dir(socket_dir);
    LockError::Io { path, source }
}

/// Distinguish "the lock is held by someone else" from a real I/O
/// failure of `try_lock_exclusive`.
///
/// `fs2` reports contention via a fixed OS-error sentinel
/// (`EWOULDBLOCK` on Unix, `ERROR_LOCK_VIOLATION` on Windows), exposed
/// as [`fs2::lock_contended_error`]. We compare raw OS codes — an exact
/// match, and portable, because both that sentinel and any genuine
/// `flock(2)`/`LockFileEx` failure are constructed from an OS error
/// code. A non-OS error (`raw_os_error() == None`) can never be
/// contention, so it correctly falls through to `Io`.
pub(crate) fn is_lock_contended(err: &std::io::Error) -> bool {
    err.raw_os_error() == fs2::lock_contended_error().raw_os_error()
}

/// Windows only: is this open/identity-probe error the delete-pending
/// window of a just-released lock (`ERROR_ACCESS_DENIED` 5,
/// `ERROR_SHARING_VIOLATION` 32, `ERROR_DELETE_PENDING` 303)? Always
/// false elsewhere — those numbers mean unrelated errnos on Unix. Only
/// applied to the open and identity-probe paths, never to the lock
/// call: `LockFileEx` contention is a different code (33) and must keep
/// feeding the `Held`/deadline logic.
fn is_delete_pending(err: &std::io::Error) -> bool {
    cfg!(windows) && matches!(err.raw_os_error(), Some(5) | Some(32) | Some(303))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `.socket/` under a fresh tempdir — the shape production uses,
    /// and the name the guard's prune step is gated on.
    fn socket_dir(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join(".socket")
    }

    /// Lock file exists while held and is gone once the guard drops.
    #[test]
    fn first_acquire_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let socket = socket_dir(&dir);
        let guard = acquire(&socket, Duration::ZERO).unwrap();
        assert!(socket.join("apply.lock").is_file());
        drop(guard);
        assert!(
            !socket.join("apply.lock").exists(),
            "drop must unlink the lock file"
        );
    }

    /// Second concurrent acquire returns `LockError::Held` when the
    /// first guard is still alive.
    #[test]
    fn second_concurrent_acquire_is_held() {
        let dir = tempfile::tempdir().unwrap();
        let socket = socket_dir(&dir);
        let _first = acquire(&socket, Duration::ZERO).unwrap();
        let err = acquire(&socket, Duration::ZERO).unwrap_err();
        assert!(matches!(err, LockError::Held));
    }

    /// After the first guard drops (which also unlinks the file and
    /// prunes the directory), a fresh acquire recreates both and
    /// succeeds.
    #[test]
    fn drop_releases_lock() {
        let dir = tempfile::tempdir().unwrap();
        let socket = socket_dir(&dir);
        {
            let _g = acquire(&socket, Duration::ZERO).unwrap();
        } // guard dropped here
        let again = acquire(&socket, Duration::ZERO);
        assert!(again.is_ok());
    }

    /// `acquire` creates a missing `.socket/` itself, and the guard's
    /// drop removes both the lock file and the now-empty directory —
    /// a lock-only run leaves the project exactly as it found it.
    #[test]
    fn acquire_creates_missing_socket_dir_and_prunes_it_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        let socket = socket_dir(&dir);
        assert!(!socket.exists());

        let guard = acquire(&socket, Duration::ZERO).unwrap();
        assert!(socket.join("apply.lock").is_file());

        drop(guard);
        assert!(!socket.join("apply.lock").exists());
        assert!(
            !socket.exists(),
            "an otherwise-empty .socket/ must be pruned on release"
        );
    }

    /// The prune is non-recursive: a `.socket/` holding real state keeps
    /// everything but the lock file.
    #[test]
    fn drop_leaves_non_empty_socket_dir_alone() {
        let dir = tempfile::tempdir().unwrap();
        let socket = socket_dir(&dir);
        std::fs::create_dir_all(&socket).unwrap();
        std::fs::write(socket.join("manifest.json"), b"{}").unwrap();

        let guard = acquire(&socket, Duration::ZERO).unwrap();
        drop(guard);

        assert!(!socket.join("apply.lock").exists());
        assert!(socket.join("manifest.json").is_file());
        assert!(socket.is_dir());
    }

    /// The directory prune is gated to a directory literally named
    /// `.socket`: `--manifest-path` can aim the lock at any user
    /// directory, which the guard must not delete even when empty.
    #[test]
    fn drop_prunes_only_a_dir_named_socket() {
        let dir = tempfile::tempdir().unwrap();
        let custom = dir.path().join("custom");
        let guard = acquire(&custom, Duration::ZERO).unwrap();
        assert!(custom.join("apply.lock").is_file());
        drop(guard);
        assert!(!custom.join("apply.lock").exists());
        assert!(custom.is_dir(), "a user-named lock dir must survive");
    }

    /// A regular file squatting where `.socket/` should be is an `Io`
    /// naming the directory — never `Held`, and the squatter is left
    /// untouched.
    #[test]
    fn file_squatting_on_socket_dir_surfaces_io() {
        let dir = tempfile::tempdir().unwrap();
        let socket = socket_dir(&dir);
        std::fs::write(&socket, b"not a directory").unwrap();

        let err = acquire(&socket, Duration::from_millis(250)).unwrap_err();
        match err {
            LockError::Io { path, .. } => assert_eq!(path, socket),
            LockError::Held => panic!("a squatting file is an I/O fault, not contention"),
        }
        assert_eq!(std::fs::read(&socket).unwrap(), b"not a directory");
    }

    /// Non-zero timeout waits then errors `Held` when the lock never
    /// frees up.
    #[test]
    fn timeout_held() {
        let dir = tempfile::tempdir().unwrap();
        let socket = socket_dir(&dir);
        let _first = acquire(&socket, Duration::ZERO).unwrap();
        let start = Instant::now();
        let err = acquire(&socket, Duration::from_millis(250)).unwrap_err();
        let elapsed = start.elapsed();
        assert!(matches!(err, LockError::Held));
        // We waited at least the budget (with some slack for the
        // sleep granularity). Bound the upper end loosely so a slow
        // CI host doesn't make this flaky.
        assert!(
            elapsed >= Duration::from_millis(200),
            "expected at least 200ms wait, got {:?}",
            elapsed
        );
    }

    /// Regression: `fs2`'s own contended-lock sentinel must be
    /// classified as contention (the `Held` path). If `fs2` ever
    /// changed the sentinel out from under us, this catches it before
    /// the misclassification reaches users.
    #[test]
    fn contended_sentinel_is_classified_as_contention() {
        assert!(is_lock_contended(&fs2::lock_contended_error()));
    }

    /// Regression: genuine I/O failures of `try_lock_exclusive` must
    /// NOT masquerade as contention. Previously every error funnelled
    /// into the retry/`Held` path, so a real fault (e.g. ENOLCK on a
    /// full kernel lock table, or a filesystem without advisory locks)
    /// was reported as "another process is operating here" — and, with
    /// a positive timeout, only after busy-sleeping the entire budget.
    #[test]
    fn genuine_io_errors_are_not_contention() {
        use std::io::{Error, ErrorKind};

        // Kind-only errors carry no OS code, so they can never equal
        // the contended sentinel.
        assert!(!is_lock_contended(&Error::from(ErrorKind::NotFound)));
        assert!(!is_lock_contended(&Error::from(
            ErrorKind::PermissionDenied
        )));

        // A concrete-but-different OS error (EINTR == 4 on Unix) must
        // not look like contention either. Skip the exact code match on
        // the off chance a platform reuses 4 for the contended sentinel.
        let eintr = Error::from_raw_os_error(4);
        if eintr.raw_os_error() != fs2::lock_contended_error().raw_os_error() {
            assert!(!is_lock_contended(&eintr));
        }
    }

    /// The delete-pending grace is Windows-only and never overlaps the
    /// contention sentinel: on Windows codes 5/32/303 qualify and
    /// `ERROR_LOCK_VIOLATION` (33) does not; elsewhere nothing does
    /// (5 is EIO and 32 is EPIPE on Unix).
    #[test]
    fn delete_pending_classifier_is_windows_only_and_excludes_contention() {
        use std::io::Error;

        assert!(!is_delete_pending(&fs2::lock_contended_error()));
        assert!(!is_delete_pending(&Error::from(ErrorKind::NotFound)));
        for code in [5, 32, 303] {
            assert_eq!(
                is_delete_pending(&Error::from_raw_os_error(code)),
                cfg!(windows),
                "os error {code}"
            );
        }
    }

    /// A non-blocking (`ZERO`) acquire on a contended lock returns
    /// `Held` essentially immediately — it must not pay the 100 ms
    /// backoff sleep before giving up.
    #[test]
    fn zero_timeout_does_not_sleep_before_held() {
        let dir = tempfile::tempdir().unwrap();
        let socket = socket_dir(&dir);
        let _first = acquire(&socket, Duration::ZERO).unwrap();
        let start = Instant::now();
        let err = acquire(&socket, Duration::ZERO).unwrap_err();
        let elapsed = start.elapsed();
        assert!(matches!(err, LockError::Held));
        assert!(
            elapsed < Duration::from_millis(100),
            "non-blocking acquire should not sleep, took {:?}",
            elapsed
        );
    }

    /// Regression: a near-infinite, user-supplied timeout must not
    /// panic the process. `--lock-timeout` / `SOCKET_LOCK_TIMEOUT` is a
    /// raw `u64` of seconds, so `Duration::from_secs(u64::MAX)` reaches
    /// `acquire`. `Instant::now() + that` overflows and aborts; the
    /// `checked_add` deadline turns it into an indefinite wait instead.
    /// When the lock is free, acquisition still succeeds immediately.
    #[test]
    fn overflowing_timeout_does_not_panic_when_free() {
        let dir = tempfile::tempdir().unwrap();
        let socket = socket_dir(&dir);
        // Would panic ("overflow when adding duration to instant") under
        // the old `Instant::now() + timeout`.
        let guard = acquire(&socket, Duration::from_secs(u64::MAX)).unwrap();
        assert!(socket.join("apply.lock").is_file());
        drop(guard);
        assert!(!socket.join("apply.lock").exists());
    }

    /// Regression companion: with an overflowing (effectively infinite)
    /// timeout AND a contended lock, `acquire` must *wait* — not panic
    /// and not give up — and then succeed once the holder releases.
    /// Proves both the no-overflow-panic fix and that a `None` deadline
    /// never spuriously elapses into `Held`. The holder's release also
    /// unlinks the file and prunes `.socket/`, so the parked waiter has
    /// to recreate both — the mkdir-inside-the-loop path.
    #[test]
    fn overflowing_timeout_waits_then_acquires_on_release() {
        use std::sync::Arc;

        let dir = Arc::new(tempfile::tempdir().unwrap());
        let socket = socket_dir(&dir);
        let held = acquire(&socket, Duration::ZERO).unwrap();

        // Release the lock a little while after the waiter starts.
        let dir2 = Arc::clone(&dir);
        let releaser = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            drop(held); // unlinks, releases the OS lock, prunes .socket/
                        // Keep the tempdir alive until the waiter has acquired.
            std::thread::sleep(Duration::from_millis(200));
            drop(dir2);
        });

        // u64::MAX seconds == astronomically large; under the bug this
        // panics before ever sleeping. With the fix it waits indefinitely
        // and acquires once `held` drops above.
        let start = Instant::now();
        let guard = acquire(&socket, Duration::from_secs(u64::MAX)).unwrap();
        let waited = start.elapsed();
        assert!(
            waited >= Duration::from_millis(100),
            "should have waited for the holder to release, waited {:?}",
            waited
        );
        assert!(socket.join("apply.lock").is_file());
        drop(guard);
        assert!(!socket.exists(), "last guard out prunes .socket/");
        releaser.join().unwrap();
    }

    /// A waiter parked in the retry loop must never end up holding the
    /// lock alongside the next command once the holder releases.
    ///
    /// The holder's drop unlinks `apply.lock` under the lock and then
    /// releases; a fresh try-once acquire follows at once and takes the
    /// lock on a brand-new inode. The waiter may have opened the OLD
    /// inode before the unlink: if it locks that orphan, the post-lock
    /// identity check must reject it (the path names a different file
    /// now, or nothing) and send it back around the loop, where it either
    /// wins the free window itself or sees the fresh holder and reports
    /// `Held`. Both are correct; two live guards at once is the bug this
    /// pins, and — unlike the pre-identity-check protocol, which merely
    /// called that window "vanishingly rare" — it is now impossible, so
    /// every iteration asserts it outright.
    #[test]
    fn waiter_does_not_lock_orphaned_inode_after_holder_release() {
        use std::sync::mpsc;

        const ATTEMPTS: usize = 5;
        for _ in 0..ATTEMPTS {
            let dir = tempfile::tempdir().unwrap();
            let socket = socket_dir(&dir);
            let lock_path = socket.join("apply.lock");

            // A mutating command holds the lock; this is the inode the
            // waiter will open below.
            let holder = acquire(&socket, Duration::ZERO).unwrap();

            // The waiter: a concurrent `apply --lock-timeout 1` that
            // parks in the retry loop while the holder finishes.
            let (started_tx, started_rx) = mpsc::channel();
            let waiter_dir = socket.clone();
            let waiter = std::thread::spawn(move || {
                started_tx.send(()).unwrap();
                acquire(&waiter_dir, Duration::from_millis(600))
            });

            // Let the waiter burn its first (contended) attempt. Being
            // late here is harmless — it just burns another attempt.
            started_rx.recv().unwrap();
            std::thread::sleep(Duration::from_millis(50));

            // The holder finishes (unlink under the lock, release,
            // prune) and the next command takes the lock immediately.
            drop(holder);
            let fresh = acquire(&socket, Duration::ZERO);

            let waiter_result = waiter.join().unwrap();
            match (&fresh, &waiter_result) {
                // The fresh acquire won and the waiter, re-checking the
                // path every retry, saw the new inode held and gave up.
                (Ok(_), Err(LockError::Held)) => {}
                // The waiter's retry landed in the free window between
                // the release and the fresh acquire: it recreated the
                // file and is the legitimate sole holder, and the fresh
                // try-once correctly reported Held.
                (Err(LockError::Held), Ok(_)) => {}
                (Ok(_), Ok(_)) => panic!(
                    "two live guards on the apply lock at once: the waiter locked \
                     the orphaned pre-release inode and the identity check let it through"
                ),
                // Windows keeps an unlinked name delete-pending until its
                // last handle closes; the grace in `acquire` should absorb
                // that, but if a loaded runner outlasts it, an I/O refusal
                // still grants nobody a second lock.
                #[cfg(windows)]
                (Ok(_) | Err(LockError::Held), Err(LockError::Io { source, .. }))
                | (Err(LockError::Io { source, .. }), Ok(_) | Err(LockError::Held))
                    if is_delete_pending(source) => {}
                (fresh, waiter_result) => panic!(
                    "unexpected lock outcome: fresh={:?} waiter={:?}",
                    fresh.as_ref().map(|_| "Ok(guard)"),
                    waiter_result.as_ref().map(|_| "Ok(guard)")
                ),
            }

            // Whoever held it, releasing leaves nothing behind.
            drop(fresh);
            drop(waiter_result);
            assert!(
                !lock_path.exists(),
                "apply.lock must not outlive its holders"
            );
            assert!(
                !socket.exists(),
                "an otherwise-empty .socket/ must be pruned"
            );
        }
    }

    /// The lock binds to the file the path names NOW: a guard left
    /// holding an orphaned inode (a non-cooperating `rm` + `touch`
    /// replaced the file under it) neither blocks a fresh acquire nor
    /// gets confused on its own drop. Unix-only: Windows cannot replace
    /// a name that another handle keeps delete-pending.
    #[cfg(unix)]
    #[test]
    fn orphaned_inode_holder_does_not_block_the_path() {
        let dir = tempfile::tempdir().unwrap();
        let socket = socket_dir(&dir);
        let lock_path = socket.join("apply.lock");

        let orphan = acquire(&socket, Duration::ZERO).unwrap();
        // Replace the lock file behind the holder's back.
        std::fs::remove_file(&lock_path).unwrap();
        std::fs::File::create(&lock_path).unwrap();

        // The replacement is unlocked, so a fresh acquire takes it even
        // though `orphan` still holds the old inode.
        let fresh = acquire(&socket, Duration::ZERO).unwrap();
        assert!(lock_path.is_file());

        drop(fresh);
        assert!(!lock_path.exists());
        assert!(!socket.exists());
        // The orphan's drop finds nothing to unlink or prune and must not
        // panic.
        drop(orphan);
        assert!(!socket.exists());
    }

    /// Two threads hammering acquire/release on one `.socket/` — every
    /// release unlinking the file and pruning the directory, every
    /// acquire recreating both — must never observe two live guards and
    /// must end with no lock file and no directory. This is the live
    /// stress test of the unlink-under-lock + identity-check protocol
    /// and of the mkdir-inside-the-loop / vanished-file retries.
    #[test]
    fn concurrent_acquire_release_never_double_holds_and_leaves_no_residue() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::sync::Arc;

        const ITERATIONS: usize = 200;

        let dir = tempfile::tempdir().unwrap();
        let socket = socket_dir(&dir);
        let holders = Arc::new(AtomicUsize::new(0));
        let violated = Arc::new(AtomicBool::new(false));

        let workers: Vec<_> = (0..2)
            .map(|_| {
                let socket = socket.clone();
                let holders = Arc::clone(&holders);
                let violated = Arc::clone(&violated);
                std::thread::spawn(move || {
                    let mut faults = Vec::new();
                    for _ in 0..ITERATIONS {
                        match acquire(&socket, Duration::ZERO) {
                            Ok(guard) => {
                                if holders.fetch_add(1, Ordering::SeqCst) != 0 {
                                    violated.store(true, Ordering::SeqCst);
                                }
                                std::thread::yield_now();
                                holders.fetch_sub(1, Ordering::SeqCst);
                                drop(guard);
                            }
                            // Refusal (the other thread holds) is a
                            // correct outcome; only a double hold or an
                            // I/O fault is a failure.
                            Err(LockError::Held) => {}
                            Err(e @ LockError::Io { .. }) => faults.push(e.to_string()),
                        }
                    }
                    faults
                })
            })
            .collect();

        let mut faults = Vec::new();
        for worker in workers {
            faults.extend(worker.join().unwrap());
        }

        assert!(
            !violated.load(Ordering::SeqCst),
            "two threads held the apply lock at once"
        );
        assert!(faults.is_empty(), "acquire hit I/O faults: {faults:?}");
        assert!(!socket.join("apply.lock").exists());
        assert!(!socket.exists(), "the last release must prune .socket/");
    }

    /// mkfifo(2) directly, not the /usr/bin/mkfifo binary: spawning a child
    /// flakes under heavy parallel load (fork/exec starvation) and the
    /// syscall needs no process at all.
    #[cfg(target_os = "macos")]
    fn mkfifo(path: &Path) {
        use std::os::unix::ffi::OsStrExt;
        let c_path =
            std::ffi::CString::new(path.as_os_str().as_bytes()).expect("fifo path has no NUL");
        let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o644) };
        assert_eq!(
            rc,
            0,
            "mkfifo(2) failed: {}",
            std::io::Error::last_os_error()
        );
    }

    /// A non-contention `try_lock_exclusive` fault must surface as
    /// `LockError::Io` immediately — not busy-sleep the whole timeout
    /// budget and then come out mislabelled as `Held` (the documented
    /// contract of the `Fault` arm in `attempt`).
    ///
    /// Induced for real, with no fault-injection seam: a FIFO planted at
    /// `apply.lock` opens fine with `O_RDWR` (the process is both reader
    /// and writer, so the open never blocks), but macOS's fifofs has no
    /// advisory-lock op, so `flock(2)` fails with ENOTSUP — an OS error
    /// distinct from the EWOULDBLOCK contention sentinel. macOS-only:
    /// Linux `flock` has no file-type restriction (a FIFO locks fine
    /// there), so the fault is not inducible on a path without a seam.
    #[cfg(target_os = "macos")]
    #[test]
    fn non_contention_lock_fault_returns_io_immediately() {
        let dir = tempfile::tempdir().unwrap();
        let lock_path = dir.path().join("apply.lock");
        mkfifo(&lock_path);

        let start = Instant::now();
        let err = acquire(dir.path(), Duration::from_secs(5)).unwrap_err();
        let elapsed = start.elapsed();

        match err {
            LockError::Io { path, source } => {
                assert_eq!(path, lock_path);
                // The flock errno must be preserved verbatim (ENOTSUP from
                // fifofs), not swallowed or rewritten — and it is, by
                // construction, not the contended sentinel.
                assert_eq!(source.raw_os_error(), Some(libc::ENOTSUP));
                assert_ne!(
                    source.raw_os_error(),
                    fs2::lock_contended_error().raw_os_error()
                );
            }
            LockError::Held => {
                panic!("a genuine flock fault must not be mislabelled as contention")
            }
        }
        // The fault arm returns without ever entering the retry/backoff
        // path: nowhere near the 5 s budget (the old funnel-everything-
        // into-retry behaviour slept the full budget before erroring).
        assert!(
            elapsed < Duration::from_secs(1),
            "Io fault must not burn the retry budget, took {:?}",
            elapsed
        );
        // A failed acquire never unlinks a file it does not hold the
        // lock on.
        assert!(lock_path.exists(), "the squatting FIFO must survive");
    }

    /// Companion in try-once mode: `timeout = ZERO` on a faulting lock
    /// file is still `Io`, never `Held` — the non-blocking path must not
    /// collapse "the lock is broken" into "someone else holds it".
    #[cfg(target_os = "macos")]
    #[test]
    fn non_contention_lock_fault_is_io_not_held_in_try_once_mode() {
        let dir = tempfile::tempdir().unwrap();
        let lock_path = dir.path().join("apply.lock");
        mkfifo(&lock_path);

        let err = acquire(dir.path(), Duration::ZERO).unwrap_err();
        match err {
            LockError::Io { path, source } => {
                assert_eq!(path, lock_path);
                assert!(source.raw_os_error().is_some());
                assert_ne!(
                    source.raw_os_error(),
                    fs2::lock_contended_error().raw_os_error()
                );
            }
            LockError::Held => {
                panic!("try-once mode must not mislabel a genuine flock fault as Held")
            }
        }
    }

    /// The retry loop must not overshoot the deadline by a full sleep
    /// quantum. A 150 ms budget should resolve well under the old
    /// fixed-100 ms-sleep worst case (~200 ms) — the final sleep is
    /// clamped to the remaining slice.
    #[test]
    fn wait_respects_deadline_without_full_quantum_overshoot() {
        let dir = tempfile::tempdir().unwrap();
        let socket = socket_dir(&dir);
        let _first = acquire(&socket, Duration::ZERO).unwrap();
        let start = Instant::now();
        let err = acquire(&socket, Duration::from_millis(150)).unwrap_err();
        let elapsed = start.elapsed();
        assert!(matches!(err, LockError::Held));
        assert!(
            elapsed >= Duration::from_millis(150),
            "should wait at least the budget, got {:?}",
            elapsed
        );
        // Loose upper bound: clamped sleeps mean we don't blow well past
        // the budget. Generous slack keeps slow CI hosts non-flaky while
        // still failing the old uncapped behaviour's pathological cases.
        assert!(
            elapsed < Duration::from_millis(450),
            "clamped sleep should keep us near the budget, got {:?}",
            elapsed
        );
    }
}
