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

use crate::json_envelope::{Command, Envelope, EnvelopeError, PatchAction, PatchEvent};

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
/// `break_lock = true` clears a *stale* `<socket_dir>/apply.lock`
/// before the acquire attempt. The motivating case is a crashed prior
/// run that left the file behind. It is **not** a force-steal: a
/// non-blocking probe runs first, and if a live holder still owns the
/// lock the helper refuses with `lock_held` rather than removing the
/// file out from under it (which would defeat mutual exclusion — the
/// unlink recreates a fresh inode the holder's advisory lock no longer
/// guards). When a pre-existing file is removed with no live holder the
/// return value's `broke_lock` is true and the caller should attach a
/// `lock_broken` warning event to their envelope.
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

        // Snapshot whether a lock file existed *before* we touch
        // anything. The probe `acquire` below opens with `create(true)`,
        // so afterwards the file always exists — even on a clean tree.
        // We only want to report `broke_lock` (and emit the warning
        // event) when a *pre-existing* leftover was actually removed,
        // mirroring `unlock`'s `lock_existed` source-of-truth pattern.
        let lock_existed = path.exists();

        // CRITICAL: never steal a lock from a *live* holder. A bare
        // `remove_file` + re-`acquire` is unsafe — on Unix the unlink
        // recreates a fresh inode, so a still-running holder keeps its
        // `flock(2)` on the old (unlinked) inode while we lock the new
        // one. Both processes then believe they hold the lock and race
        // on every file write, which is exactly what the lock exists to
        // prevent. So probe with a non-blocking acquire first:
        //   * Ok  => no live holder (a crashed run's flock is already
        //            auto-released by the kernel), so breaking the
        //            leftover file is safe. Drop our probe handle and
        //            fall through to remove + re-acquire below.
        //   * Held => a live holder exists. Refuse rather than steal —
        //            this is the case `--break-lock` was *wrongly*
        //            relied on for, and the only one where it mattered.
        //   * Io   => surface the real fault.
        match acquire(socket_dir, Duration::ZERO) {
            Ok(guard) => drop(guard),
            Err(LockError::Held) => {
                // The probe above is a *non-blocking* try-once
                // (`Duration::ZERO`), so report a zero wait. Threading
                // the caller's `timeout` here would claim a "(waited …)"
                // that never happened — the probe refuses a live holder
                // immediately, it does not wait out the budget first.
                // `break_probe_held_message` takes no timeout precisely so
                // the wrong value can't be passed back in.
                let msg = break_probe_held_message();
                emit(
                    command,
                    json,
                    silent,
                    dry_run,
                    "lock_held",
                    &msg,
                    Some(socket_dir),
                );
                return Err(1);
            }
            Err(LockError::Io { path, source }) => {
                let msg = format!("failed to open lock file at {}: {}", path.display(), source);
                emit(command, json, silent, dry_run, "lock_io", &msg, None);
                return Err(1);
            }
        }

        match std::fs::remove_file(&path) {
            Ok(()) => {
                // Only a *pre-existing* leftover counts as "broke a
                // lock". If the probe itself just created the file on a
                // clean tree, removing it is a no-op for the warning
                // surface — `broke_lock` stays false so callers don't
                // emit a spurious event.
                broke_lock = lock_existed;
                if broke_lock && !silent && !json {
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
                emit(
                    command,
                    json,
                    silent,
                    dry_run,
                    "lock_break_failed",
                    &msg,
                    None,
                );
                return Err(1);
            }
        }
    }

    match acquire(socket_dir, timeout) {
        Ok(guard) => Ok(LockAcquired { guard, broke_lock }),
        Err(LockError::Held) => {
            let msg = held_message(timeout);
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

/// Build the top-level error envelope emitted in `--json` mode when
/// lock acquisition fails. Split out from [`emit`] so the serialized
/// shape (status / error.code / command / dryRun) is unit-testable
/// without capturing stdout.
fn error_envelope(command: Command, dry_run: bool, code: &str, message: &str) -> Envelope {
    let mut env = Envelope::new(command);
    env.dry_run = dry_run;
    env.mark_error(EnvelopeError::new(code, message));
    env
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
        println!(
            "{}",
            error_envelope(command, dry_run, code, message).to_pretty_json()
        );
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
