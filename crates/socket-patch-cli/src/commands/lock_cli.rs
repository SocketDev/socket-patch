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

use crate::json_envelope::{Command, Envelope, EnvelopeError, PatchAction, PatchEvent};

/// Stable `errorCode` tag emitted as a `Skipped` warning event when
/// `--break-lock` actually reclaims a stale pre-existing lock file.
/// Integration tests and downstream consumers pattern-match on the
/// literal string.
pub(crate) const LOCK_BROKEN_CODE: &str = "lock_broken";

/// Outcome of a successful lock acquisition. Callers attach a
/// `lock_broken` event to their own envelope when [`broke_lock`] is
/// true, so the audit trail follows the same conventions as the
/// rest of the command's output.
///
/// [`broke_lock`]: LockAcquired::broke_lock
#[derive(Debug)]
pub(crate) struct LockAcquired {
    pub(crate) guard: LockGuard,
    /// True iff `--break-lock` was set AND a pre-existing
    /// `apply.lock` file (with no live holder) was reclaimed.
    /// False when the file didn't exist (nothing to break) — the
    /// flag was a no-op in that case so no warning is warranted.
    pub(crate) broke_lock: bool,
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
/// `break_lock = true` reclaims a *stale* `<socket_dir>/apply.lock`
/// via a non-blocking acquire. The motivating case is a crashed prior
/// run that left the file behind — harmless to a fresh acquire (the
/// kernel already released the dead holder's advisory lock), but worth
/// an audit event. It is **not** a force-steal: if a live holder still
/// owns the lock the helper refuses with `lock_held` rather than
/// stealing. The file is deliberately never unlinked — an unlink
/// defeats mutual exclusion, because a competitor (live holder or
/// mid-acquire racer) can keep or take an advisory lock on the
/// orphaned inode while a fresh acquire locks its replacement. When a
/// pre-existing file is reclaimed with no live holder the return
/// value's `broke_lock` is true and the caller should attach a
/// `lock_broken` warning event to their envelope.
pub(crate) fn acquire_or_emit(
    socket_dir: &Path,
    command: Command,
    json: bool,
    silent: bool,
    dry_run: bool,
    timeout: Duration,
    break_lock: bool,
) -> Result<LockAcquired, i32> {
    // `--break-lock` is a *non-blocking* try-once probe (the caller's
    // `timeout` never applies to it) that never unlinks the lock file —
    // see the doc comment for why removal would defeat mutual
    // exclusion. Snapshot whether a lock file existed *before* the
    // acquire: it opens with `create(true)`, so afterwards the file
    // always exists, and only a *pre-existing* leftover counts as
    // "broke a lock" (mirroring `unlock`'s `lock_existed`
    // source-of-truth pattern).
    let lock_existed = break_lock && socket_dir.join("apply.lock").exists();
    let acquire_timeout = if break_lock { Duration::ZERO } else { timeout };

    match acquire(socket_dir, acquire_timeout) {
        Ok(guard) => {
            // No live holder — the acquire's guard IS the lock; a
            // crashed run's leftover needs no removal (the kernel
            // already released the dead holder's advisory lock).
            if lock_existed && !silent && !json {
                eprintln!(
                    "Warning: --break-lock reclaimed stale {} (no live holder).",
                    socket_dir.join("apply.lock").display()
                );
            }
            Ok(LockAcquired {
                guard,
                broke_lock: lock_existed,
            })
        }
        Err(LockError::Held) => {
            // A live holder exists. For `--break-lock` that means
            // refuse rather than steal, with two consequences for the
            // message: the probe never waited, so it must not claim a
            // "(waited …)" (`break_probe_held_message` takes no timeout
            // precisely so the wrong value can't be passed back in);
            // and re-advising --break-lock — which was just refused —
            // would be self-defeating, so only the inspect hint remains.
            let (msg, hint) = if break_lock {
                (break_probe_held_message(), Hint::UnlockOnly)
            } else {
                (held_message(timeout), Hint::UnlockOrBreakLock)
            };
            emit(command, json, dry_run, "lock_held", &msg, hint);
            Err(1)
        }
        Err(LockError::Io { path, source }) => {
            let msg = format!("failed to open lock file at {}: {}", path.display(), source);
            emit(command, json, dry_run, "lock_io", &msg, Hint::None);
            Err(1)
        }
    }
}

/// Build the warning event that callers attach to their envelope
/// when [`LockAcquired::broke_lock`] is true. Artifact-level (no
/// PURL) since the action targets the `.socket/` directory itself,
/// not a specific package.
pub(crate) fn lock_broken_event(socket_dir: &Path) -> PatchEvent {
    PatchEvent::artifact(PatchAction::Skipped).with_reason(
        LOCK_BROKEN_CODE,
        format!(
            "--break-lock reclaimed stale {}/apply.lock (no live holder)",
            socket_dir.display()
        ),
    )
}

/// Contention message for the `--break-lock` pre-acquire probe. That
/// probe is hard-wired to a non-blocking try-once (`Duration::ZERO`), so
/// the message must never claim a wait, regardless of the caller's
/// `--lock-timeout`. Kept timeout-free on purpose: the call site cannot
/// thread the full budget back in and fabricate a "(waited …)" clause
/// for time that was never spent.
fn break_probe_held_message() -> String {
    held_message(Duration::ZERO)
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

/// Remediation hint appended under the human-mode error line. The
/// `--break-lock` advice is only valid when the caller hasn't already
/// tried it — a refused `--break-lock` (live holder) must not advise
/// rerunning with `--break-lock`, which is exactly what just failed.
enum Hint {
    None,
    UnlockOnly,
    UnlockOrBreakLock,
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
            Hint::UnlockOnly => {
                eprintln!("  Run `socket-patch unlock` to inspect.");
            }
            Hint::UnlockOrBreakLock => {
                eprintln!(
                    "  Run `socket-patch unlock` to inspect, or rerun with --break-lock if you're sure no holder exists."
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
    /// holder reclaims the file in place and acquires. `broke_lock`
    /// flag surfaces so callers can attach the warning event.
    #[test]
    fn acquire_or_emit_break_lock_reclaims_stale_file_and_acquires() {
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
            "broke_lock should be true when a stale lock file existed and was reclaimed"
        );
        // The lock file persists (never unlinked) and we hold it.
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

    /// Regression: `--break-lock` must NOT steal a lock from a *live*
    /// holder. A bare `remove_file` + re-`acquire` would unlink the
    /// holder's inode and lock a fresh one, leaving two processes both
    /// "holding" the lock and racing on every file write. With the
    /// probe-before-break guard, contention is refused with exit 1 and
    /// the holder keeps the lock (its file stays on disk).
    #[test]
    fn acquire_or_emit_break_lock_refuses_when_live_holder() {
        let dir = tempfile::tempdir().unwrap();
        // A genuinely live holder: guard stays alive for the test.
        let _held = acquire(dir.path(), Duration::ZERO).unwrap();
        assert!(dir.path().join("apply.lock").is_file());

        let code = acquire_or_emit(
            dir.path(),
            Command::Apply,
            false,
            true,
            false,
            Duration::ZERO,
            true, // break_lock
        )
        .unwrap_err();
        assert_eq!(
            code, 1,
            "break-lock must refuse a live holder, not steal it"
        );
        // The original holder's lock file is untouched.
        assert!(dir.path().join("apply.lock").is_file());
    }

    /// Companion to the refusal test: while a live holder is present,
    /// `--break-lock` must leave the holder's exclusivity intact — i.e.
    /// a follow-up plain acquire still sees the lock as `Held`. This is
    /// the real safety property (no double-acquire), distinct from the
    /// exit code.
    #[test]
    fn acquire_or_emit_break_lock_does_not_break_mutual_exclusion() {
        let dir = tempfile::tempdir().unwrap();
        let _held = acquire(dir.path(), Duration::ZERO).unwrap();

        // The break-lock attempt is refused...
        let _ = acquire_or_emit(
            dir.path(),
            Command::Apply,
            false,
            true,
            false,
            Duration::ZERO,
            true,
        )
        .unwrap_err();

        // ...and the lock is still genuinely exclusive: a fresh acquire
        // is still contended. If break-lock had stolen the lock, the
        // first holder's guard would no longer be authoritative and this
        // would (wrongly) succeed.
        assert!(matches!(
            acquire(dir.path(), Duration::ZERO),
            Err(LockError::Held)
        ));
    }

    /// Regression: the break-lock sequence must not open a window in
    /// which a competitor can be robbed of a lock it legitimately
    /// acquired. The buggy shape probed, then `remove_file`d the lock
    /// file, then re-acquired: a competitor that flocked (or had merely
    /// *opened*) the file before the unlink kept a valid lock on the
    /// orphaned inode while the re-acquire locked a fresh one — two
    /// live holders at once, the exact double-hold the probe exists to
    /// prevent. The fixed shape never unlinks: the probe guard is the
    /// lock.
    ///
    /// The competitor thread increments a shared holder count only
    /// while it genuinely holds the OS lock, as does the main thread
    /// for the guard `acquire_or_emit` hands back. With real mutual
    /// exclusion the count can never exceed 1, so the test is
    /// deterministic-green on correct code; under the buggy window the
    /// hammer lands in the gap within a handful of iterations.
    #[test]
    fn break_lock_window_cannot_defeat_mutual_exclusion() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::sync::Arc;

        let dir = tempfile::tempdir().unwrap();
        let lock_dir = dir.path().to_path_buf();
        let holders = Arc::new(AtomicUsize::new(0));
        let violated = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));

        // Competitor: grabs the lock the instant it is free, holds it
        // briefly, releases, retries. Mirrors a concurrent
        // `socket-patch apply` racing a `--break-lock` invocation.
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
            // silent=true so refused iterations stay quiet; refusal
            // (the hammer currently holds) is a correct outcome here.
            if let Ok(acquired) = acquire_or_emit(
                &lock_dir,
                Command::Apply,
                false,
                true,
                false,
                Duration::ZERO,
                true, // break_lock
            ) {
                if holders.fetch_add(1, Ordering::SeqCst) != 0 {
                    violated.store(true, Ordering::SeqCst);
                }
                holders.fetch_sub(1, Ordering::SeqCst);
                drop(acquired);
            }
        }
        stop.store(true, Ordering::SeqCst);
        hammer.join().unwrap();

        assert!(
            !violated.load(Ordering::SeqCst),
            "--break-lock let two processes hold the apply lock at once: \
             the lock file must never be unlinked"
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

    /// Regression: the `--break-lock` pre-acquire probe is a non-blocking
    /// try-once, so its `lock_held` refusal must NEVER claim a wait — even
    /// when the caller passes a positive `--lock-timeout`. The earlier
    /// code threaded the full `timeout` into the probe's message, so a
    /// `--break-lock --lock-timeout 250ms` against a live holder reported
    /// `(waited 250ms)` despite refusing immediately. The probe message is
    /// now timeout-free by construction; this pins that it carries no wait
    /// clause.
    #[test]
    fn break_probe_held_message_never_claims_a_wait() {
        let msg = break_probe_held_message();
        assert!(
            !msg.contains("waited"),
            "break-lock probe refuses immediately and must not claim a wait: {msg}"
        );
        // It is still the same identity sentence the rest of the code
        // emits for contention, just without the trailing budget clause.
        assert_eq!(msg, held_message(Duration::ZERO));
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
