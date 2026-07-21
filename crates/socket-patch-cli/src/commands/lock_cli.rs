//! Envelope-aware wrapper around the
//! `socket_patch_core::patch::apply_lock` advisory lock.
//!
//! Mutating subcommands (`apply`, `rollback`, `repair`, `remove`,
//! `vendor`) all need the same shape: acquire the lock at the top of
//! `run`, on contention emit a JSON envelope with `errorCode:
//! "lock_held"` (or stderr in human mode) and exit 1. This module
//! centralises that emission so the call sites stay one line each.
//!
//! The lock itself is in `socket-patch-core` (cross-crate, also used
//! by tests). This module is the CLI-side glue that knows how to
//! render the failure through the shared [`crate::json_envelope`].

use std::path::Path;
use std::time::Duration;

use socket_patch_core::patch::apply_lock::{acquire, LockError, LockGuard};

use crate::json_envelope::{Command, Envelope, EnvelopeError};

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
/// A leftover `apply.lock` from a crashed run never contends: the
/// kernel released the dead holder's advisory lock along with its
/// file handle, so the acquire reclaims the file in place. `Held`
/// therefore always means a *live* process. The file is never
/// unlinked here — an unlink defeats mutual exclusion, because a
/// competitor (live holder or mid-acquire racer) can keep or take an
/// advisory lock on the orphaned inode while a fresh acquire locks
/// its replacement. The only sanctioned deletion is `repair`'s final
/// cleanup, which runs after its own guard is released.
pub(crate) fn acquire_or_emit(
    socket_dir: &Path,
    command: Command,
    json: bool,
    dry_run: bool,
    timeout: Duration,
) -> Result<LockGuard, i32> {
    match acquire(socket_dir, timeout) {
        Ok(guard) => Ok(guard),
        Err(LockError::Held) => {
            emit(
                command,
                json,
                dry_run,
                "lock_held",
                &held_message(timeout),
                Hint::Wait,
            );
            Err(1)
        }
        Err(LockError::Io { path, source }) => {
            let msg = format!("failed to open lock file at {}: {}", path.display(), source);
            emit(command, json, dry_run, "lock_io", &msg, Hint::None);
            Err(1)
        }
    }
}

/// Human-readable description of a `lock_held` contention for the given
/// wait budget. A zero budget means the historical non-blocking
/// try-once, so we omit the "(waited …)" clause entirely.
fn held_message(timeout: Duration) -> String {
    if timeout > Duration::ZERO {
        format!(
            "another socket-patch process is operating in this directory (waited {})",
            fmt_duration(timeout)
        )
    } else {
        "another socket-patch process is operating in this directory".to_string()
    }
}

/// Format a wait budget for humans. Whole seconds read naturally
/// (`5s`); sub-second budgets — reachable through the library API even
/// though the CLI only ever passes whole seconds — render as
/// milliseconds rather than truncating to a misleading `0s`.
fn fmt_duration(d: Duration) -> String {
    if d.subsec_nanos() == 0 {
        format!("{}s", d.as_secs())
    } else {
        format!("{}ms", d.as_millis())
    }
}

/// Build the top-level error envelope emitted in `--json` mode when a
/// command fails before doing real work (lock acquisition here; `repair`
/// reuses it for its early error exits). Split out from [`emit`] so the
/// serialized shape (status / error.code / command / dryRun) is
/// unit-testable without capturing stdout.
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

/// Remediation hint appended under the human-mode error line. `Held`
/// always means a live process (leftover files never contend), so the
/// only honest advice is to wait — pointing at another socket-patch
/// command would just hit the same contention.
enum Hint {
    None,
    Wait,
}

fn emit(command: Command, json: bool, dry_run: bool, code: &str, message: &str, hint: Hint) {
    if json {
        println!(
            "{}",
            error_envelope(command, dry_run, code, message).to_pretty_json()
        );
    } else {
        // Errors print even under --silent ("errors only", never "nothing"
        // — CLI_CONTRACT.md): exit 1 with no message would be
        // undiagnosable. The remediation hint is part of the error report,
        // not informational chatter, so it prints with the error.
        eprintln!("Error: {message}.");
        match hint {
            Hint::None => {}
            Hint::Wait => {
                eprintln!(
                    "  Wait for it to finish, or retry with --lock-timeout <secs> to wait for the lock."
                );
            }
        }
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
        let code = acquire_or_emit(dir.path(), Command::Apply, false, false, Duration::ZERO)
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
            false,
            Duration::ZERO,
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
    /// file handle, so a plain acquire reclaims the file in place.
    /// This is the fact that made `--break-lock` redundant (and, with
    /// it, the `unlock` subcommand): there is no stale-lock state a
    /// user ever needs to clear before running a mutating command.
    #[test]
    fn acquire_or_emit_reclaims_stale_leftover_file() {
        let dir = tempfile::tempdir().unwrap();
        // Pre-stage a lock file with no holder — simulates the
        // post-crash leftover scenario.
        std::fs::write(dir.path().join("apply.lock"), b"").unwrap();

        let guard =
            acquire_or_emit(dir.path(), Command::Apply, false, false, Duration::ZERO).unwrap();
        // The file persists (never unlinked here) and we hold the lock:
        // a competitor's acquire is contended while the guard is live.
        assert!(dir.path().join("apply.lock").is_file());
        assert!(matches!(
            acquire(dir.path(), Duration::ZERO),
            Err(LockError::Held)
        ));
        drop(guard);
    }

    /// Regression guard carried over from the `--break-lock` era: the
    /// wrapper must never open a window in which a competitor can be
    /// robbed of a lock it legitimately acquired. The historical buggy
    /// shape probed, then `remove_file`d the lock file, then
    /// re-acquired: a competitor that flocked (or had merely *opened*)
    /// the file before the unlink kept a valid lock on the orphaned
    /// inode while the re-acquire locked a fresh one — two live holders
    /// at once. `acquire_or_emit` never unlinks: the acquire's guard is
    /// the lock.
    ///
    /// The competitor thread increments a shared holder count only
    /// while it genuinely holds the OS lock, as does the main thread
    /// for the guard `acquire_or_emit` hands back. With real mutual
    /// exclusion the count can never exceed 1, so the test is
    /// deterministic-green on correct code; under a buggy unlink window
    /// the hammer lands in the gap within a handful of iterations.
    #[test]
    fn acquire_or_emit_preserves_mutual_exclusion() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::sync::Arc;

        let dir = tempfile::tempdir().unwrap();
        let lock_dir = dir.path().to_path_buf();
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
            "two processes held the apply lock at once: \
             the lock file must never be unlinked by the acquire path"
        );
    }

    /// Whole-second budgets read naturally in the contention message.
    #[test]
    fn held_message_reports_whole_seconds() {
        assert_eq!(
            held_message(Duration::from_secs(5)),
            "another socket-patch process is operating in this directory (waited 5s)"
        );
    }

    /// Regression: `timeout.as_secs()` truncated a 250ms budget to
    /// `(waited 0s)`, which read as "we didn't wait at all". Sub-second
    /// budgets now surface as milliseconds. The 250ms budget mirrors
    /// `acquire_or_emit_honors_lock_timeout`, so the message stays
    /// honest for the exact value that test exercises.
    #[test]
    fn held_message_does_not_truncate_sub_second_to_zero() {
        let msg = held_message(Duration::from_millis(250));
        assert!(msg.contains("250ms"), "expected ms rendering, got: {msg}");
        assert!(
            !msg.contains("0s"),
            "sub-second budget must not collapse to 0s: {msg}"
        );
    }

    /// A zero budget is the non-blocking try-once shape — no "(waited …)"
    /// clause, since we never actually waited.
    #[test]
    fn held_message_zero_timeout_omits_waited_clause() {
        let msg = held_message(Duration::ZERO);
        assert!(
            !msg.contains("waited"),
            "zero budget should not claim a wait: {msg}"
        );
    }

    /// The `--json` failure envelope (previously emitted only via
    /// `println!`, so untested) has the stable error shape downstream
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

    /// `dry_run` and `command` are plumbed through to the envelope so a
    /// contention during a dry-run apply/rollback is still reported as
    /// a dry run. Covers the other two reason tags too.
    #[test]
    fn error_envelope_propagates_dry_run_and_command() {
        let env = error_envelope(Command::Rollback, true, "lock_io", "open failed");
        let v: serde_json::Value = serde_json::from_str(&env.to_pretty_json()).unwrap();
        assert_eq!(v["command"], "rollback");
        assert_eq!(v["dryRun"], true);
        assert_eq!(v["error"]["code"], "lock_io");
    }
}
