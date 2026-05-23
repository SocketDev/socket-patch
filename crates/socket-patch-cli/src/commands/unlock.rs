//! `socket-patch unlock` — inspect (and optionally release) the
//! `<.socket>/apply.lock` advisory file lock used by mutating
//! subcommands.
//!
//! Default behavior (no flags): probes the lock and prints
//! `status: "free" | "held"`. Returns 0 when free, 1 when held —
//! lets CI gating and monitoring tooling pattern-match the exit
//! code without parsing JSON.
//!
//! With `--release`: when the lock is free, also deletes the lock
//! file. The file is normally retained across runs (see
//! `apply_lock` docs — the inode persists so subsequent acquires
//! don't race on file creation), so `--release` exists for
//! operators who want a true clean slate. Refused when the lock is
//! held — that's the `--break-lock` flag's job on the mutating
//! subcommands, and routing the two through different verbs makes
//! the dangerous override explicit.

use std::path::Path;
use std::time::Duration;

use clap::Args;
use socket_patch_core::patch::apply_lock::{acquire, LockError};

use crate::args::{apply_env_toggles, GlobalArgs};
use crate::json_envelope::{Command, Envelope, EnvelopeError};

#[derive(Args)]
pub struct UnlockArgs {
    #[command(flatten)]
    pub common: GlobalArgs,

    /// When the lock is free, also delete the lock file. Refused if
    /// the lock is currently held — use `--break-lock` on the
    /// mutating subcommand instead for that scenario.
    #[arg(long = "release", env = "SOCKET_UNLOCK_RELEASE", default_value_t = false)]
    pub release: bool,
}

pub async fn run(args: UnlockArgs) -> i32 {
    apply_env_toggles(&args.common);

    let socket_dir = args.common.cwd.join(".socket");
    let lock_file = socket_dir.join("apply.lock");

    // No `.socket/` at all → treat as "free" (no one could be
    // holding a lock that doesn't exist). Useful for fresh repos
    // where the operator wants to confirm no stale state remains.
    if !socket_dir.exists() {
        return emit_free(args.common.json, &lock_file, false, args.release);
    }

    match acquire(&socket_dir, Duration::ZERO) {
        Ok(guard) => {
            // We successfully claimed the lock — nobody else holds
            // it. Release our handle before deleting the file so the
            // delete races nothing.
            drop(guard);

            if args.release {
                match std::fs::remove_file(&lock_file) {
                    Ok(()) => emit_free(args.common.json, &lock_file, true, true),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        // The file was never created (e.g. socket
                        // dir existed but no run has acquired the
                        // lock yet). Treat as success.
                        emit_free(args.common.json, &lock_file, false, true)
                    }
                    Err(e) => {
                        let msg = format!(
                            "failed to remove lock file at {}: {}",
                            lock_file.display(),
                            e
                        );
                        emit_error(args.common.json, args.common.silent, "lock_io", &msg);
                        1
                    }
                }
            } else {
                emit_free(args.common.json, &lock_file, false, false)
            }
        }
        Err(LockError::Held) => {
            if args.common.json {
                let mut env = Envelope::new(Command::Unlock);
                env.mark_error(EnvelopeError::new(
                    "lock_held",
                    format!(
                        "another socket-patch process is operating in {}",
                        socket_dir.display()
                    ),
                ));
                println!("{}", env.to_pretty_json());
            } else if !args.common.silent {
                eprintln!(
                    "Lock is held: another socket-patch process is operating in {}.",
                    socket_dir.display()
                );
                if args.release {
                    eprintln!(
                        "  Refusing to release a held lock. Re-run the failing mutating command with --break-lock if you're sure no holder exists."
                    );
                } else {
                    eprintln!(
                        "  Re-run the failing mutating command with --break-lock if you're sure no holder exists."
                    );
                }
            }
            1
        }
        Err(LockError::Io { path, source }) => {
            let msg = format!(
                "failed to open lock file at {}: {}",
                path.display(),
                source
            );
            emit_error(args.common.json, args.common.silent, "lock_io", &msg);
            1
        }
    }
}

/// Print the "free" success envelope and return exit code 0.
/// `removed` is true when `--release` actually deleted the file
/// (vs. the no-op case where the file didn't exist).
fn emit_free(json: bool, lock_file: &Path, removed: bool, release: bool) -> i32 {
    if json {
        // Build the success body by hand rather than re-using the
        // shared `Envelope` shape — the `events`/`summary` fields
        // don't carry useful information here, and a flat
        // `{status, lockFile, ...}` is friendlier to jq pipelines.
        // We still tag `command: "unlock"` so generic consumers
        // can route on subcommand identity.
        let body = serde_json::json!({
            "command": "unlock",
            "status": "free",
            "lockFile": lock_file.display().to_string(),
            "released": removed,
        });
        println!("{}", serde_json::to_string_pretty(&body).unwrap());
    } else if release && removed {
        println!("Lock is free. Removed {}.", lock_file.display());
    } else if release {
        println!("Lock is free (no lock file to remove).");
    } else {
        println!("Lock is free.");
    }
    0
}

fn emit_error(json: bool, silent: bool, code: &str, message: &str) {
    if json {
        let mut env = Envelope::new(Command::Unlock);
        env.mark_error(EnvelopeError::new(code, message));
        println!("{}", env.to_pretty_json());
    } else if !silent {
        eprintln!("Error: {message}.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use socket_patch_core::patch::apply_lock::acquire as core_acquire;

    /// Build a `UnlockArgs` rooted at a tempdir for the test.
    fn args_in(cwd: &Path, release: bool) -> UnlockArgs {
        UnlockArgs {
            common: GlobalArgs {
                cwd: cwd.to_path_buf(),
                json: true, // exercise the JSON path in unit tests
                silent: true,
                ..GlobalArgs::default()
            },
            release,
        }
    }

    /// No `.socket/` directory at all → report `free`, exit 0.
    /// Mirrors what a fresh `git clone` looks like.
    #[tokio::test]
    async fn run_reports_free_when_socket_dir_missing() {
        let dir = tempfile::tempdir().unwrap();
        let code = run(args_in(dir.path(), false)).await;
        assert_eq!(code, 0);
    }

    /// `.socket/` exists but no run has taken the lock yet — still
    /// `free`. We exercise this by creating the directory ourselves.
    #[tokio::test]
    async fn run_reports_free_when_socket_dir_clean() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".socket")).unwrap();
        let code = run(args_in(dir.path(), false)).await;
        assert_eq!(code, 0);
    }

    /// Active holder (via core `acquire`) → `unlock` reports
    /// `held`, exits 1, and the file remains on disk.
    #[tokio::test]
    async fn run_reports_held_when_lock_actively_held() {
        let dir = tempfile::tempdir().unwrap();
        let socket_dir = dir.path().join(".socket");
        std::fs::create_dir_all(&socket_dir).unwrap();

        // Hold the lock for the duration of this test. `_guard` is
        // bound so its drop doesn't fire until function return.
        let _guard = core_acquire(&socket_dir, Duration::ZERO).unwrap();

        let code = run(args_in(dir.path(), false)).await;
        assert_eq!(code, 1);
        assert!(socket_dir.join("apply.lock").is_file());
    }

    /// `--release` against a free lock with a leftover file removes
    /// the file.
    #[tokio::test]
    async fn run_deletes_lock_file_when_release_and_free() {
        let dir = tempfile::tempdir().unwrap();
        let socket_dir = dir.path().join(".socket");
        std::fs::create_dir_all(&socket_dir).unwrap();
        std::fs::write(socket_dir.join("apply.lock"), b"").unwrap();
        assert!(socket_dir.join("apply.lock").is_file());

        let code = run(args_in(dir.path(), true)).await;
        assert_eq!(code, 0);
        assert!(
            !socket_dir.join("apply.lock").exists(),
            "--release should have deleted the file"
        );
    }

    /// `--release` against a HELD lock refuses (exit 1), file stays.
    #[tokio::test]
    async fn run_refuses_release_when_held() {
        let dir = tempfile::tempdir().unwrap();
        let socket_dir = dir.path().join(".socket");
        std::fs::create_dir_all(&socket_dir).unwrap();
        let _guard = core_acquire(&socket_dir, Duration::ZERO).unwrap();

        let code = run(args_in(dir.path(), true)).await;
        assert_eq!(code, 1);
        assert!(
            socket_dir.join("apply.lock").is_file(),
            "lock file should still exist — --release must refuse when held"
        );
    }
}
