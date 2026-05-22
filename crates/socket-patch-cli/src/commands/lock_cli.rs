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

use crate::json_envelope::{Command, Envelope, EnvelopeError};

/// Try to acquire `<socket_dir>/apply.lock` and return the guard, or
/// emit a failure envelope and a non-zero exit code.
///
/// `command` selects the envelope's `command` field so downstream
/// consumers see `apply` / `rollback` / `repair` / `remove` rather
/// than a generic "lock failed". `dry_run` is plumbed through to the
/// envelope's `dry_run` field for the (rare) case where lock
/// contention happens during a dry-run apply.
pub fn acquire_or_emit(
    socket_dir: &Path,
    command: Command,
    json: bool,
    silent: bool,
    dry_run: bool,
) -> Result<LockGuard, i32> {
    match acquire(socket_dir, Duration::ZERO) {
        Ok(guard) => Ok(guard),
        Err(LockError::Held) => {
            emit(
                command,
                json,
                silent,
                dry_run,
                "lock_held",
                "another socket-patch process is operating in this directory",
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
        if let Some(dir) = hint_dir {
            eprintln!(
                "  If you are sure no other process is running, remove {}/apply.lock and retry.",
                dir.display()
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
        let guard = acquire_or_emit(dir.path(), Command::Apply, false, true, false).unwrap();
        drop(guard);
    }

    #[test]
    fn acquire_or_emit_returns_one_on_contention() {
        let dir = tempfile::tempdir().unwrap();
        let _first =
            acquire_or_emit(dir.path(), Command::Apply, false, true, false).unwrap();
        let code =
            acquire_or_emit(dir.path(), Command::Apply, false, true, false).unwrap_err();
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
        )
        .unwrap_err();
        assert_eq!(code, 1);
    }
}
