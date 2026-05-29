//! Advisory file lock used to serialize mutating operations against a
//! single `.socket/` directory.
//!
//! Apply, rollback, repair, and remove can each rewrite manifest state
//! and on-disk package files. Two of them running at once against the
//! same project — common when a dev runs `socket-patch apply` while CI
//! triggers a deploy hook, or when `apply` and a `repair` are stacked
//! by a wrapper script — race on every file write. The lock turns
//! that race into a clean refusal: the second invocation reports
//! `lock_held` and exits non-zero, leaving the first to finish.
//!
//! The lock file lives at `<.socket>/apply.lock`. It is created on
//! demand (the parent `.socket/` directory must exist first; callers
//! get a clear error otherwise) and is **never deleted** — the file
//! handle drop releases the OS-level advisory lock, but the inode
//! sticks around for next time. That keeps the lock idempotent across
//! restarts and avoids a race where two callers create the lock file
//! at the same time.
//!
//! Locking is advisory (`flock(2)` on Unix, `LockFileEx` on Windows
//! via the `fs2` crate). Non-cooperating writers (a user shelling
//! `rm -rf .socket/`) are not stopped — but every socket-patch
//! mutating command honors the lock, which is what matters in
//! practice.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use fs2::FileExt;
use thiserror::Error;

/// Errors surfaced when acquiring the apply lock.
#[derive(Debug, Error)]
pub enum LockError {
    /// Another `socket-patch` process holds the lock and `timeout`
    /// (possibly zero) elapsed without the lock becoming available.
    #[error("another socket-patch process is operating in this directory")]
    Held,

    /// We could not create or open the lock file (typically a missing
    /// `.socket/` directory or a permissions problem).
    #[error("failed to open lock file at {path:?}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// RAII guard for the apply lock.
///
/// Drop releases the OS-level advisory lock. There is no explicit
/// `unlock()` API on purpose — Rust's drop guarantees are simpler to
/// reason about than a `?`-fallible unlock path.
#[derive(Debug)]
#[must_use = "the lock is released when this guard is dropped"]
pub struct LockGuard {
    // The std::fs::File holds the OS handle whose drop releases the
    // lock; we keep it alive for the guard's lifetime. Field is unused
    // by name but its Drop side effect is the entire point.
    _file: std::fs::File,
}

/// Try to acquire the apply lock at `<socket_dir>/apply.lock`.
///
/// `timeout = Duration::ZERO` makes this a non-blocking try-once. Any
/// positive `timeout` re-tries with a 100 ms backoff until the lock
/// becomes available or the budget elapses.
///
/// The lock file is created on demand. Its parent (`socket_dir`) must
/// already exist — apply and friends create `.socket/` separately
/// during `setup`, and we don't want lock acquisition to silently
/// create directories on a misconfigured path.
pub fn acquire(socket_dir: &Path, timeout: Duration) -> Result<LockGuard, LockError> {
    let path = socket_dir.join("apply.lock");

    // Open (or create) the lock file. `create(true)` is idempotent if
    // it already exists; we never write to the file, only flock it.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .map_err(|source| LockError::Io {
            path: path.clone(),
            source,
        })?;

    let deadline = Instant::now() + timeout;
    loop {
        match file.try_lock_exclusive() {
            Ok(()) => return Ok(LockGuard { _file: file }),
            // Only a genuine "someone else holds it" signal counts as
            // contention and feeds the retry/`Held` path. Any other
            // failure (ENOLCK, EBADF, a filesystem that doesn't support
            // advisory locks, EACCES on a pre-existing read-only lock
            // file, …) is a real I/O fault: surface it immediately as
            // `Io` rather than busy-sleeping for the whole budget and
            // then mislabelling it as `Held`. See `is_lock_contended`.
            Err(ref e) if is_lock_contended(e) => {
                let now = Instant::now();
                if now >= deadline {
                    return Err(LockError::Held);
                }
                // Never sleep past the deadline: a sub-100 ms budget
                // must not be rounded up to a full 100 ms wait. The
                // remaining slice is always > 0 here (now < deadline).
                let remaining = deadline - now;
                std::thread::sleep(remaining.min(Duration::from_millis(100)));
            }
            Err(source) => {
                return Err(LockError::Io {
                    path: path.clone(),
                    source,
                });
            }
        }
    }
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
fn is_lock_contended(err: &std::io::Error) -> bool {
    err.raw_os_error() == fs2::lock_contended_error().raw_os_error()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lock file is created on demand and the first acquisition succeeds.
    #[test]
    fn first_acquire_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let guard = acquire(dir.path(), Duration::ZERO).unwrap();
        // Lock file must exist on disk.
        assert!(dir.path().join("apply.lock").is_file());
        drop(guard);
    }

    /// Second concurrent acquire returns `LockError::Held` when the
    /// first guard is still alive.
    #[test]
    fn second_concurrent_acquire_is_held() {
        let dir = tempfile::tempdir().unwrap();
        let _first = acquire(dir.path(), Duration::ZERO).unwrap();
        let err = acquire(dir.path(), Duration::ZERO).unwrap_err();
        assert!(matches!(err, LockError::Held));
    }

    /// After the first guard drops, a fresh acquire succeeds.
    #[test]
    fn drop_releases_lock() {
        let dir = tempfile::tempdir().unwrap();
        {
            let _g = acquire(dir.path(), Duration::ZERO).unwrap();
        } // guard dropped here
        let again = acquire(dir.path(), Duration::ZERO);
        assert!(again.is_ok());
    }

    /// Missing socket directory surfaces as `LockError::Io` with the
    /// original `NotFound` underneath.
    #[test]
    fn missing_socket_dir_surfaces_io() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist");
        let err = acquire(&missing, Duration::ZERO).unwrap_err();
        match err {
            LockError::Io { source, .. } => {
                assert_eq!(source.kind(), std::io::ErrorKind::NotFound);
            }
            _ => panic!("expected Io error, got {:?}", err),
        }
    }

    /// Non-zero timeout waits then errors `Held` when the lock never
    /// frees up.
    #[test]
    fn timeout_held() {
        let dir = tempfile::tempdir().unwrap();
        let _first = acquire(dir.path(), Duration::ZERO).unwrap();
        let start = Instant::now();
        let err = acquire(dir.path(), Duration::from_millis(250)).unwrap_err();
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

    /// A non-blocking (`ZERO`) acquire on a contended lock returns
    /// `Held` essentially immediately — it must not pay the 100 ms
    /// backoff sleep before giving up.
    #[test]
    fn zero_timeout_does_not_sleep_before_held() {
        let dir = tempfile::tempdir().unwrap();
        let _first = acquire(dir.path(), Duration::ZERO).unwrap();
        let start = Instant::now();
        let err = acquire(dir.path(), Duration::ZERO).unwrap_err();
        let elapsed = start.elapsed();
        assert!(matches!(err, LockError::Held));
        assert!(
            elapsed < Duration::from_millis(100),
            "non-blocking acquire should not sleep, took {:?}",
            elapsed
        );
    }

    /// The retry loop must not overshoot the deadline by a full sleep
    /// quantum. A 150 ms budget should resolve well under the old
    /// fixed-100 ms-sleep worst case (~200 ms) — the final sleep is
    /// clamped to the remaining slice.
    #[test]
    fn wait_respects_deadline_without_full_quantum_overshoot() {
        let dir = tempfile::tempdir().unwrap();
        let _first = acquire(dir.path(), Duration::ZERO).unwrap();
        let start = Instant::now();
        let err = acquire(dir.path(), Duration::from_millis(150)).unwrap_err();
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
