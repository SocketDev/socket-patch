//! CLI rendering of the `socket_patch_core::patch::apply_lock` advisory
//! lock: acquire it with a waiting status line, and report a failure as a
//! `lock_held` / `lock_io` JSON envelope or an `Error:` line on stderr.

use std::path::Path;
use std::time::Duration;

use socket_patch_core::patch::apply_lock::{acquire, LockError, LockGuard};

use crate::json_envelope::{Command, Envelope, EnvelopeError};

/// Try to acquire `<socket_dir>/apply.lock` and return the guard, or
/// emit a failure envelope and a non-zero exit code.
///
/// `Duration::ZERO` tries once; a positive `timeout` waits for the lock.
/// The core guard owns the lock file's whole lifecycle (see
/// `socket_patch_core::patch::apply_lock`).
pub(crate) fn acquire_or_emit(
    socket_dir: &Path,
    command: Command,
    json: bool,
    dry_run: bool,
    timeout: Duration,
) -> Result<LockGuard, i32> {
    let err = match acquire_with_status(socket_dir, timeout) {
        Ok(guard) => return Ok(guard),
        Err(err) => err,
    };
    let (code, message) = lock_failure(&err, timeout);
    if json {
        println!(
            "{}",
            error_envelope(command, dry_run, code, &message).to_pretty_json()
        );
    } else {
        // Errors print even under --silent ("errors only", CLI_CONTRACT.md),
        // and the hint is part of the error report.
        let hint = failure_hint(&err, &socket_dir.join("apply.lock"), timeout);
        eprint!("{}", format_human_error(&message, &hint));
    }
    Err(1)
}

/// [`acquire`] with the contended-wait status line: a `--lock-timeout 30`
/// run that finds the lock held says what it is waiting on instead of
/// sitting there silently for 30 s. The status line is terminal-only and
/// quiet under --json/--silent (the process-wide quiet switch). Every
/// lock site goes through this (or [`acquire_or_emit`], which wraps it).
pub(crate) fn acquire_with_status(
    socket_dir: &Path,
    timeout: Duration,
) -> Result<LockGuard, LockError> {
    match acquire(socket_dir, Duration::ZERO) {
        Err(LockError::Held) if timeout > Duration::ZERO => {
            let mut status = crate::ui::StatusLine::stderr(crate::ui::quiet(), false);
            status.set(waiting_message(&socket_dir.join("apply.lock"), timeout));
            let result = acquire(socket_dir, timeout);
            status.finish();
            result
        }
        other => other,
    }
}

/// The remediation line under a human lock error (empty when there is no
/// useful advice).
fn failure_hint(err: &LockError, lock_path: &Path, timeout: Duration) -> String {
    match err {
        // `Held` always means a live process (a leftover file never
        // contends), so the only honest advice is to wait.
        LockError::Held => {
            let how = if timeout > Duration::ZERO {
                "retry with a longer --lock-timeout"
            } else {
                "pass --lock-timeout <secs> to wait for it automatically"
            };
            format!(
                "Wait for it to finish, or {how}. (Lock file: {})",
                lock_path.display()
            )
        }
        LockError::Io { path, source } if source.kind() == std::io::ErrorKind::PermissionDenied => {
            format!(
                "Check that {} is writable.",
                path.parent().unwrap_or(path).display()
            )
        }
        LockError::Io { .. } => String::new(),
    }
}

/// The human (stderr) report of a lock failure, for the sites that build
/// their own JSON envelope: the same `Error: <Message>` line plus hint
/// that [`acquire_or_emit`] prints.
pub(crate) fn format_lock_error(socket_dir: &Path, err: &LockError, timeout: Duration) -> String {
    let (_, message) = lock_failure(err, timeout);
    format_human_error(
        &message,
        &failure_hint(err, &socket_dir.join("apply.lock"), timeout),
    )
}

/// The status line shown while waiting out a contended lock.
fn waiting_message(lock_path: &Path, timeout: Duration) -> String {
    format!(
        "Waiting for another socket-patch process to release {} (up to {})...",
        lock_path.display(),
        fmt_duration(timeout)
    )
}

/// The wait hint under a `lock_held` error from a step that builds its own
/// error line (the scan/get vendor step, hosted scan), which has no lock
/// path to name.
pub(crate) const HELD_RETRY_HINT: &str =
    "Wait for it to finish, or retry with --lock-timeout <secs> to wait for the lock.";

/// The one `LockError` → (`errorCode`, message) mapping every lock site
/// renders, so the contention text cannot drift between commands.
pub(crate) fn lock_failure(err: &LockError, timeout: Duration) -> (&'static str, String) {
    const HELD: &str = "another socket-patch process is operating in this directory";
    match err {
        // A zero budget never waited, so it claims no wait.
        LockError::Held if timeout > Duration::ZERO => (
            "lock_held",
            format!("{HELD} (waited {})", fmt_duration(timeout)),
        ),
        LockError::Held => ("lock_held", HELD.to_string()),
        LockError::Io { path, source } => (
            "lock_io",
            format!("failed to open lock file at {}: {}", path.display(), source),
        ),
    }
}

/// A wait budget for humans: whole seconds as `5s`, a sub-second budget
/// (tests pass them) as milliseconds rather than a misleading `0s`.
fn fmt_duration(d: Duration) -> String {
    if d.subsec_nanos() == 0 {
        format!("{}s", d.as_secs())
    } else {
        format!("{}ms", d.as_millis())
    }
}

/// The `--json` error envelope of a command that fails before doing real
/// work (lock acquisition here; `repair` and `update` reuse it).
pub(crate) fn error_envelope(
    command: Command,
    dry_run: bool,
    code: &str,
    message: &str,
) -> Envelope {
    let mut env = Envelope::new(command);
    env.dry_run = dry_run;
    env.mark_error(EnvelopeError::new(code, message));
    env
}

/// The human-mode error report: `Error: <Message>` (first letter
/// capitalized; the envelope keeps the message verbatim), then the
/// indented hint when there is one.
fn format_human_error(message: &str, hint: &str) -> String {
    let message = crate::ui::sentence_case(message);
    if hint.is_empty() {
        format!("Error: {message}\n")
    } else {
        format!("Error: {message}\n  {hint}\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquire_or_emit_succeeds_on_fresh_dir() {
        let dir = tempfile::tempdir().unwrap();
        let guard =
            acquire_or_emit(dir.path(), Command::Apply, false, false, Duration::ZERO).unwrap();
        drop(guard);
    }

    #[test]
    fn acquire_or_emit_returns_one_on_contention() {
        let dir = tempfile::tempdir().unwrap();
        let _first =
            acquire_or_emit(dir.path(), Command::Apply, false, false, Duration::ZERO).unwrap();
        let code =
            acquire_or_emit(dir.path(), Command::Apply, false, false, Duration::ZERO).unwrap_err();
        assert_eq!(code, 1);
    }

    /// A missing `.socket/` is not an error: `acquire` creates it, and
    /// the guard's drop removes the lock file and the now-empty
    /// directory again, so a lock-only run leaves no trace.
    #[test]
    fn acquire_or_emit_creates_missing_socket_dir_and_prunes_it_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join(".socket");
        assert!(!socket.exists());

        let guard = acquire_or_emit(&socket, Command::Apply, false, false, Duration::ZERO).unwrap();
        assert!(socket.join("apply.lock").is_file());

        drop(guard);
        assert!(!socket.join("apply.lock").exists());
        assert!(!socket.exists(), "empty .socket/ must be pruned on release");
    }

    /// A file squatting where `.socket/` should be is still a failure.
    #[test]
    fn acquire_or_emit_returns_one_when_socket_dir_is_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join(".socket");
        std::fs::write(&socket, b"squatter").unwrap();
        let code =
            acquire_or_emit(&socket, Command::Apply, false, false, Duration::ZERO).unwrap_err();
        assert_eq!(code, 1);
    }

    /// A positive timeout waits before it gives up.
    #[test]
    fn acquire_or_emit_honors_lock_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let _first =
            acquire_or_emit(dir.path(), Command::Apply, false, false, Duration::ZERO).unwrap();
        let start = std::time::Instant::now();
        let code = acquire_or_emit(
            dir.path(),
            Command::Apply,
            false,
            false,
            Duration::from_millis(250),
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

    /// A leftover lock file from a crashed run never contends — the
    /// kernel released the dead holder's advisory lock along with its
    /// file handle, so a plain acquire reclaims the file in place and
    /// the guard's drop removes it.
    #[test]
    fn acquire_or_emit_reclaims_stale_leftover_file() {
        let dir = tempfile::tempdir().unwrap();
        // Pre-stage a lock file with no holder — simulates the
        // post-crash leftover scenario.
        std::fs::write(dir.path().join("apply.lock"), b"leftover").unwrap();

        let guard =
            acquire_or_emit(dir.path(), Command::Apply, false, false, Duration::ZERO).unwrap();
        // The reclaimed file is the live lock while the guard is held: a
        // competitor's acquire is contended.
        assert!(dir.path().join("apply.lock").is_file());
        assert!(matches!(
            acquire(dir.path(), Duration::ZERO),
            Err(LockError::Held)
        ));
        drop(guard);
        assert!(
            !dir.path().join("apply.lock").exists(),
            "the reclaimed leftover is removed on release"
        );
    }

    /// The wrapper must never open a window in which a competitor can be
    /// robbed of a lock it legitimately acquired: a competitor that
    /// flocked (or had merely *opened*) the file before an unlink keeps a
    /// valid lock on the orphaned inode while a re-acquire locks a fresh
    /// one — two live holders at once. Every guard drop unlinks the file,
    /// so this is the live stress test of the core protocol that makes
    /// that safe:
    /// unlink WHILE holding the lock, and re-check the locked handle's
    /// identity against the path after every successful lock.
    ///
    /// The competitor thread increments a shared holder count only
    /// while it genuinely holds the OS lock, as does the main thread
    /// for the guard `acquire_or_emit` hands back. With real mutual
    /// exclusion the count can never exceed 1, so the test is
    /// deterministic-green on correct code; under a buggy unlink window
    /// the hammer lands in the gap within a handful of iterations. The
    /// lock dir is a `.socket/` so every release also prunes the
    /// directory and every acquire recreates it.
    #[test]
    fn acquire_or_emit_preserves_mutual_exclusion() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::sync::Arc;

        let dir = tempfile::tempdir().unwrap();
        let lock_dir = dir.path().join(".socket");
        let holders = Arc::new(AtomicUsize::new(0));
        let violated = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));

        // Competitor: grabs the lock the instant it is free, holds it
        // briefly, releases, retries. Mirrors two concurrent
        // `socket-patch` mutating commands racing in one directory.
        let hammer = {
            let lock_dir = lock_dir.clone();
            let holders = Arc::clone(&holders);
            let violated = Arc::clone(&violated);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    if let Ok(guard) = acquire(&lock_dir, Duration::ZERO) {
                        if holders.fetch_add(1, Ordering::SeqCst) != 0 {
                            violated.store(true, Ordering::SeqCst);
                        }
                        std::thread::sleep(Duration::from_micros(500));
                        holders.fetch_sub(1, Ordering::SeqCst);
                        drop(guard);
                    }
                }
            })
        };

        for _ in 0..2000 {
            if violated.load(Ordering::SeqCst) {
                break;
            }
            // Refusal (the hammer currently holds) is a correct
            // outcome here — only a double-hold is a violation.
            if let Ok(guard) =
                acquire_or_emit(&lock_dir, Command::Apply, false, false, Duration::ZERO)
            {
                if holders.fetch_add(1, Ordering::SeqCst) != 0 {
                    violated.store(true, Ordering::SeqCst);
                }
                holders.fetch_sub(1, Ordering::SeqCst);
                drop(guard);
            }
        }
        stop.store(true, Ordering::SeqCst);
        hammer.join().unwrap();

        assert!(
            !violated.load(Ordering::SeqCst),
            "two processes held the apply lock at once: the acquire path must never \
             unlink, and a release must not orphan a competitor's open handle \
             (unlink under the lock + post-lock identity check)"
        );
        assert!(
            !lock_dir.join("apply.lock").exists() && !lock_dir.exists(),
            "no lock residue may outlive the last holder"
        );
    }

    /// `lock_failure` is the single rendering every lock site shares:
    /// `Held` carries the waited clause, `Io` names the path and the OS
    /// error under `lock_io`.
    #[test]
    fn lock_failure_maps_both_variants() {
        assert_eq!(
            lock_failure(&LockError::Held, Duration::from_secs(2)),
            (
                "lock_held",
                "another socket-patch process is operating in this directory (waited 2s)"
                    .to_string()
            )
        );
        let io = LockError::Io {
            path: std::path::PathBuf::from(".socket/apply.lock"),
            source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied"),
        };
        let (code, message) = lock_failure(&io, Duration::ZERO);
        assert_eq!(code, "lock_io");
        assert_eq!(
            message,
            format!(
                "failed to open lock file at {}: denied",
                std::path::Path::new(".socket/apply.lock").display()
            )
        );
    }

    /// The report the sites with their own envelope print (get, hosted
    /// scan): the same capitalized line and wait hint as acquire_or_emit.
    #[test]
    fn format_lock_error_matches_acquire_or_emit() {
        let dir = std::path::Path::new(".socket");
        let lock = dir.join("apply.lock");
        assert_eq!(
            format_lock_error(dir, &LockError::Held, Duration::from_secs(2)),
            format!(
                "Error: Another socket-patch process is operating in this directory \
                 (waited 2s)\n  Wait for it to finish, or retry with a longer \
                 --lock-timeout. (Lock file: {})\n",
                lock.display()
            )
        );
        assert_eq!(
            format_lock_error(dir, &LockError::Held, Duration::ZERO),
            format!(
                "Error: Another socket-patch process is operating in this directory\n  \
                 Wait for it to finish, or pass --lock-timeout <secs> to wait for it \
                 automatically. (Lock file: {})\n",
                lock.display()
            )
        );
    }

    #[test]
    fn acquire_with_status_takes_a_free_lock_and_reports_a_held_one() {
        let dir = tempfile::tempdir().unwrap();
        let guard = acquire_with_status(dir.path(), Duration::ZERO).unwrap();
        assert!(matches!(
            acquire_with_status(dir.path(), Duration::from_millis(200)),
            Err(LockError::Held)
        ));
        drop(guard);
    }

    #[test]
    fn human_error_is_capitalized_without_forced_period() {
        assert_eq!(
            format_human_error(
                "another socket-patch process is operating in this directory",
                ""
            ),
            "Error: Another socket-patch process is operating in this directory\n"
        );
        assert_eq!(
            format_human_error(
                "failed to open lock file at ro/.socket/apply.lock: Permission denied (os error 13)",
                "Check that ro/.socket is writable."
            ),
            "Error: Failed to open lock file at ro/.socket/apply.lock: Permission denied \
             (os error 13)\n  Check that ro/.socket is writable.\n"
        );
        assert_eq!(format_human_error("", ""), "Error: \n");
    }

    #[test]
    fn waiting_message_names_lock_and_budget() {
        assert_eq!(
            waiting_message(Path::new("p/.socket/apply.lock"), Duration::from_secs(5)),
            "Waiting for another socket-patch process to release p/.socket/apply.lock (up to 5s)..."
        );
        assert_eq!(
            waiting_message(Path::new("p/apply.lock"), Duration::from_millis(250)),
            "Waiting for another socket-patch process to release p/apply.lock (up to 250ms)..."
        );
    }

    /// A sub-second budget renders as milliseconds, not `0s`, and a zero
    /// budget claims no wait.
    #[test]
    fn held_message_renders_the_waited_budget() {
        assert_eq!(
            lock_failure(&LockError::Held, Duration::from_millis(250)).1,
            "another socket-patch process is operating in this directory (waited 250ms)"
        );
        assert_eq!(
            lock_failure(&LockError::Held, Duration::ZERO).1,
            "another socket-patch process is operating in this directory"
        );
    }

    /// The `--json` failure envelope has the stable error shape downstream
    /// consumers pattern-match on: top-level `status: "error"` and
    /// `error.code` carrying the lock reason tag.
    #[test]
    fn error_envelope_has_stable_lock_held_shape() {
        let env = error_envelope(Command::Apply, false, "lock_held", "held by another run");
        let v: serde_json::Value = serde_json::from_str(&env.to_pretty_json()).unwrap();
        assert_eq!(v["command"], "apply");
        assert_eq!(v["status"], "error");
        assert_eq!(v["dryRun"], false);
        assert_eq!(v["error"]["code"], "lock_held");
        assert_eq!(v["error"]["message"], "held by another run");
        // A pre-event failure carries no events.
        assert_eq!(v["events"].as_array().unwrap().len(), 0);
    }

    /// `dry_run` and `command` reach the envelope, so a contention during
    /// a dry-run rollback is still reported as a dry run.
    #[test]
    fn error_envelope_propagates_dry_run_and_command() {
        let env = error_envelope(Command::Rollback, true, "lock_io", "open failed");
        let v: serde_json::Value = serde_json::from_str(&env.to_pretty_json()).unwrap();
        assert_eq!(v["command"], "rollback");
        assert_eq!(v["dryRun"], true);
        assert_eq!(v["error"]["code"], "lock_io");
    }
}
