//! Envelope-aware wrapper around the
//! `socket_patch_core::patch::apply_lock` advisory lock.
//!
//! Mutating subcommands (`apply`, `rollback`, `repair`, `remove`) all
//! need the same shape: acquire the lock at the top of `run`, on
//! contention emit a JSON envelope with `errorCode: "lock_held"` (or
//! stderr in human mode) and exit 1. This module centralises that
//! emission so the four call sites stay one line each.
//!
//! The lock itself is in `socket-patch-core` (cross-crate, also used
//! by tests). This module is the CLI-side glue that knows how to
//! render the failure through the shared [`crate::json_envelope`].

use std::path::Path;
use std::time::Duration;

use socket_patch_core::patch::apply_lock::{acquire, LockError, LockGuard};

use crate::json_envelope::{
    Command, Envelope, EnvelopeError, PatchAction, PatchEvent,
};

/// Stable `errorCode` tag emitted as a `Skipped` warning event when
/// `--break-lock` actually deletes a pre-existing lock file. Exposed
/// for downstream consumers and integration tests that pattern-match
/// on it.
pub const LOCK_BROKEN_CODE: &str = "lock_broken";

/// Outcome of a successful lock acquisition. Callers attach a
/// `lock_broken` event to their own envelope when [`broke_lock`] is
/// true, so the audit trail follows the same conventions as the
/// rest of the command's output.
///
/// [`broke_lock`]: LockAcquired::broke_lock
#[derive(Debug)]
pub struct LockAcquired {
    pub guard: LockGuard,
    /// True iff `--break-lock` was set AND the helper actually
    /// removed a pre-existing `apply.lock` file before acquiring.
    /// False when the file didn't exist (nothing to break) — the
    /// flag was a no-op in that case so no warning is warranted.
    pub broke_lock: bool,
}

/// Try to acquire `<socket_dir>/apply.lock` and return the guard, or
/// emit a failure envelope and a non-zero exit code.
///
/// `command` selects the envelope's `command` field so downstream
/// consumers see `apply` / `rollback` / `repair` / `remove` rather
/// than a generic "lock failed". `dry_run` is plumbed through to the
/// envelope's `dry_run` field for the (rare) case where lock
/// contention happens during a dry-run apply.
///
/// `timeout = Duration::ZERO` keeps the historical non-blocking
/// try-once shape. Positive values wait with a 100 ms backoff —
/// see `socket_patch_core::patch::apply_lock::acquire`.
///
/// `break_lock = true` deletes `<socket_dir>/apply.lock` before the
/// acquire attempt. The motivating case is a crashed prior run that
/// left the file but no OS lock. When the file exists and is
/// successfully removed the return value's `broke_lock` is true and
/// the caller should attach a `lock_broken` warning event to their
/// envelope.
pub fn acquire_or_emit(
    socket_dir: &Path,
    command: Command,
    json: bool,
    silent: bool,
    dry_run: bool,
    timeout: Duration,
    break_lock: bool,
) -> Result<LockAcquired, i32> {
    let mut broke_lock = false;
    if break_lock {
        let path = socket_dir.join("apply.lock");
        match std::fs::remove_file(&path) {
            Ok(()) => {
                broke_lock = true;
                if !silent && !json {
                    eprintln!(
                        "Warning: --break-lock removed {} before acquisition.",
                        path.display()
                    );
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // No file to break — silently proceed to the normal
                // acquire path. Documented as a no-op so scripts can
                // pass --break-lock unconditionally on retry.
            }
            Err(source) => {
                let msg = format!(
                    "failed to remove lock file at {}: {}",
                    path.display(),
                    source
                );
                emit(command, json, silent, dry_run, "lock_break_failed", &msg, None);
                return Err(1);
            }
        }
    }

    match acquire(socket_dir, timeout) {
        Ok(guard) => Ok(LockAcquired { guard, broke_lock }),
        Err(LockError::Held) => {
            let msg = if timeout > Duration::ZERO {
                format!(
                    "another socket-patch process is operating in this directory (waited {}s)",
                    timeout.as_secs()
                )
            } else {
                "another socket-patch process is operating in this directory".to_string()
            };
            emit(
                command,
                json,
                silent,
                dry_run,
                "lock_held",
                &msg,
                Some(socket_dir),
            );
            Err(1)
        }
        Err(LockError::Io { path, source }) => {
            let msg = format!("failed to open lock file at {}: {}", path.display(), source);
            emit(command, json, silent, dry_run, "lock_io", &msg, None);
            Err(1)
        }
    }
}

/// Build the warning event that callers attach to their envelope
/// when [`LockAcquired::broke_lock`] is true. Artifact-level (no
/// PURL) since the action targets the `.socket/` directory itself,
/// not a specific package.
pub fn lock_broken_event(socket_dir: &Path) -> PatchEvent {
    PatchEvent::artifact(PatchAction::Skipped).with_reason(
        LOCK_BROKEN_CODE,
        format!(
            "--break-lock removed {}/apply.lock before acquisition",
            socket_dir.display()
        ),
    )
}

/// Convenience: record the `lock_broken` warning event on an
/// envelope. Mirrors the inline pattern at each call site so we
/// don't drift on the action / errorCode pair.
pub fn record_lock_broken(env: &mut Envelope, socket_dir: &Path) {
    env.record(lock_broken_event(socket_dir));
}

fn emit(
    command: Command,
    json: bool,
    silent: bool,
    dry_run: bool,
    code: &str,
    message: &str,
    hint_dir: Option<&Path>,
) {
    if json {
        let mut env = Envelope::new(command);
        env.dry_run = dry_run;
        env.mark_error(EnvelopeError::new(code, message));
        println!("{}", env.to_pretty_json());
    } else if !silent {
        eprintln!("Error: {message}.");
        if hint_dir.is_some() {
            eprintln!(
                "  Run `socket-patch unlock` to inspect, or rerun with --break-lock if you're sure no holder exists."
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquire_or_emit_succeeds_on_fresh_dir() {
        let dir = tempfile::tempdir().unwrap();
        let acquired = acquire_or_emit(
            dir.path(),
            Command::Apply,
            false,
            true,
            false,
            Duration::ZERO,
            false,
        )
        .unwrap();
        assert!(!acquired.broke_lock);
        drop(acquired.guard);
    }

    #[test]
    fn acquire_or_emit_returns_one_on_contention() {
        let dir = tempfile::tempdir().unwrap();
        let _first = acquire_or_emit(
            dir.path(),
            Command::Apply,
            false,
            true,
            false,
            Duration::ZERO,
            false,
        )
        .unwrap();
        let code = acquire_or_emit(
            dir.path(),
            Command::Apply,
            false,
            true,
            false,
            Duration::ZERO,
            false,
        )
        .unwrap_err();
        assert_eq!(code, 1);
    }

    #[test]
    fn acquire_or_emit_returns_one_when_socket_dir_missing() {
        let dir = tempfile::tempdir().unwrap();
        let code = acquire_or_emit(
            &dir.path().join("nope"),
            Command::Apply,
            false,
            true,
            false,
            Duration::ZERO,
            false,
        )
        .unwrap_err();
        assert_eq!(code, 1);
    }

    /// Positive timeout waits then errors `lock_held` — confirms the
    /// budget is plumbed through to `acquire`. Mirrors the
    /// `apply_lock::tests::timeout_held` shape so a regression in
    /// either layer surfaces here.
    #[test]
    fn acquire_or_emit_honors_lock_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let _first = acquire_or_emit(
            dir.path(),
            Command::Apply,
            false,
            true,
            false,
            Duration::ZERO,
            false,
        )
        .unwrap();
        let start = std::time::Instant::now();
        let code = acquire_or_emit(
            dir.path(),
            Command::Apply,
            false,
            true,
            false,
            Duration::from_millis(250),
            false,
        )
        .unwrap_err();
        let elapsed = start.elapsed();
        assert_eq!(code, 1);
        assert!(
            elapsed >= Duration::from_millis(200),
            "expected at least 200ms wait, got {:?}",
            elapsed
        );
    }

    /// `break_lock=true` against a pre-existing lock file with no
    /// holder removes the file and acquires fresh. `broke_lock` flag
    /// surfaces so callers can attach the warning event.
    #[test]
    fn acquire_or_emit_break_lock_removes_and_acquires() {
        let dir = tempfile::tempdir().unwrap();
        // Pre-stage a lock file with no holder — simulates the
        // post-crash leftover scenario.
        std::fs::write(dir.path().join("apply.lock"), b"").unwrap();

        let acquired = acquire_or_emit(
            dir.path(),
            Command::Apply,
            false,
            true,
            false,
            Duration::ZERO,
            true,
        )
        .unwrap();
        assert!(
            acquired.broke_lock,
            "broke_lock should be true when a lock file existed and was removed"
        );
        // Lock file has been re-created by `acquire` and we hold it.
        assert!(dir.path().join("apply.lock").is_file());
    }

    /// `break_lock=true` on a clean directory (no lock file) is a
    /// no-op for the warning surface — `broke_lock` stays false so
    /// callers don't emit a spurious event.
    #[test]
    fn acquire_or_emit_break_lock_is_noop_when_no_file() {
        let dir = tempfile::tempdir().unwrap();
        let acquired = acquire_or_emit(
            dir.path(),
            Command::Apply,
            false,
            true,
            false,
            Duration::ZERO,
            true,
        )
        .unwrap();
        assert!(
            !acquired.broke_lock,
            "broke_lock should be false when there was nothing to remove"
        );
    }

    #[test]
    fn lock_broken_event_uses_documented_code() {
        let dir = tempfile::tempdir().unwrap();
        let event = lock_broken_event(dir.path());
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&event).unwrap()).unwrap();
        assert_eq!(v["action"], "skipped");
        assert_eq!(v["errorCode"], LOCK_BROKEN_CODE);
        assert!(
            v.as_object().unwrap().get("purl").is_none(),
            "lock_broken is an artifact-level event — no purl"
        );
    }
}
