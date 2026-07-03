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
use socket_patch_core::utils::telemetry::{track_patch_unlock_failed, track_patch_unlocked};

use crate::args::{apply_env_toggles, parse_bool_flag, GlobalArgs};
use crate::commands::lock_cli::error_envelope;
use crate::json_envelope::Command;

#[derive(Args)]
pub struct UnlockArgs {
    #[command(flatten)]
    pub common: GlobalArgs,

    /// When the lock is free, also delete the lock file. Refused if
    /// the lock is currently held — use `--break-lock` on the
    /// mutating subcommand instead for that scenario.
    ///
    /// `value_parser = parse_bool_flag` matches the `GlobalArgs` bool
    /// flags: clap's default bool parser accepts only the literal
    /// strings `true`/`false` from the env binding, so
    /// `SOCKET_UNLOCK_RELEASE=1` (or an exported-but-empty
    /// `SOCKET_UNLOCK_RELEASE=`) aborted every `unlock` invocation.
    /// This flag is also outside `GLOBAL_ARG_ENV_VARS`, so `main`'s
    /// empty-var scrub never rescues it.
    #[arg(
        long = "release",
        env = "SOCKET_UNLOCK_RELEASE",
        default_value_t = false,
        value_parser = parse_bool_flag,
    )]
    pub release: bool,
}

pub async fn run(args: UnlockArgs) -> i32 {
    apply_env_toggles(&args.common);

    // Derive the lock directory exactly like the mutating subcommands
    // do (`manifest_path.parent()`) — they're the processes whose lock
    // this command exists to observe. Hardcoding `<cwd>/.socket` here
    // would probe a directory nobody locks whenever `--manifest-path`
    // points elsewhere.
    let manifest_path = args.common.resolved_manifest_path();
    let socket_dir = manifest_path.parent().unwrap_or(Path::new("."));
    let lock_file = socket_dir.join("apply.lock");
    let api_token = args.common.api_token.as_deref();
    let org_slug = args.common.org.as_deref();

    // No `.socket/` at all → treat as "free" (no one could be
    // holding a lock that doesn't exist). Useful for fresh repos
    // where the operator wants to confirm no stale state remains.
    if !socket_dir.exists() {
        // No lock to inspect → was_held=false. Nothing existed to
        // remove, so `released` is false regardless of whether the
        // user passed --release. Telemetry and the emitted envelope
        // must agree on this.
        track_patch_unlocked(false, false, api_token, org_slug).await;
        return emit_free(
            args.common.json,
            args.common.silent,
            &lock_file,
            false,
            args.release,
        );
    }

    // Snapshot whether a lock file already exists *before* acquiring.
    // `acquire` opens the file with `create(true)`, so after the call
    // the file always exists — even when the operator's tree was
    // clean. To honestly report whether `--release` removed a
    // pre-existing leftover (vs. a file the probe itself just
    // created), we have to capture this now.
    let lock_existed = lock_file.exists();

    match acquire(socket_dir, Duration::ZERO) {
        Ok(guard) => {
            // We successfully claimed the lock — nobody else holds
            // it. Release our handle before deleting the file so the
            // delete races nothing.
            drop(guard);

            let removed = if args.release {
                match std::fs::remove_file(&lock_file) {
                    // `remove_file` here almost always returns `Ok`
                    // (the probe's `acquire` ensured the file exists),
                    // so we can't infer from it whether a real leftover
                    // was present — `lock_existed` is the source of
                    // truth for that. We still delete the file (the
                    // operator asked for a clean slate), but only claim
                    // we "released" something when a lock file was there
                    // before we probed.
                    Ok(()) => lock_existed,
                    // NotFound: the file was never created (e.g. socket
                    // dir existed but no run has acquired the lock yet).
                    // Treat as success.
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
                    Err(e) => {
                        let msg = format!(
                            "failed to remove lock file at {}: {}",
                            lock_file.display(),
                            e
                        );
                        track_patch_unlock_failed(&msg, api_token, org_slug).await;
                        emit_error(args.common.json, args.common.silent, "lock_io", &msg);
                        return 1;
                    }
                }
            } else {
                false
            };
            track_patch_unlocked(false, removed, api_token, org_slug).await;
            emit_free(
                args.common.json,
                args.common.silent,
                &lock_file,
                removed,
                args.release,
            )
        }
        Err(LockError::Held) => {
            track_patch_unlock_failed("lock held by another process", api_token, org_slug).await;
            let msg = format!(
                "another socket-patch process is operating in {}",
                socket_dir.display()
            );
            if args.common.json {
                let env = error_envelope(Command::Unlock, false, "lock_held", &msg);
                println!("{}", env.to_pretty_json());
            } else if !args.common.silent {
                eprintln!("Lock is held: {msg}.");
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
            let msg = format!("failed to open lock file at {}: {}", path.display(), source);
            track_patch_unlock_failed(&msg, api_token, org_slug).await;
            emit_error(args.common.json, args.common.silent, "lock_io", &msg);
            1
        }
    }
}

/// Print the "free" success envelope and return exit code 0.
/// `removed` is true when `--release` actually deleted the file
/// (vs. the no-op case where the file didn't exist).
/// `silent` suppresses the human-readable lines (the JSON envelope is
/// machine output and always prints) — same `--silent` contract as the
/// sibling subcommands.
fn emit_free(json: bool, silent: bool, lock_file: &Path, removed: bool, release: bool) -> i32 {
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
    } else if silent {
        // Suppress the informational lines; the exit code carries the verdict.
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
        let env = error_envelope(Command::Unlock, false, code, message);
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

    /// A stale lock *file* left on disk by a crashed run — with **no**
    /// live OS holder — must read as `free` (exit 0), and a plain probe
    /// must leave that file in place. Guards against a regression where
    /// the verdict keys off `apply.lock` merely *existing* rather than
    /// off a live advisory lock. (The e2e suite proves this via a
    /// release-then-reprobe; this pins it at the unit level too.)
    #[tokio::test]
    async fn run_reports_free_when_stale_lock_file_present_but_not_held() {
        let dir = tempfile::tempdir().unwrap();
        let socket_dir = dir.path().join(".socket");
        std::fs::create_dir_all(&socket_dir).unwrap();
        // Leftover file, but nobody holds the OS lock.
        std::fs::write(socket_dir.join("apply.lock"), b"").unwrap();

        let code = run(args_in(dir.path(), false)).await;
        assert_eq!(code, 0, "an unheld leftover lock file must read as free");
        assert!(
            socket_dir.join("apply.lock").is_file(),
            "a plain (no --release) probe must not delete the file"
        );
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

    /// `--release` against a clean `.socket/` (no pre-existing lock
    /// file) succeeds, and does not leave behind the file that the
    /// probe's `acquire` created on demand. Guards the regression
    /// where the probe-created file masqueraded as a released
    /// leftover.
    #[tokio::test]
    async fn run_release_cleans_up_probe_created_file() {
        let dir = tempfile::tempdir().unwrap();
        let socket_dir = dir.path().join(".socket");
        std::fs::create_dir_all(&socket_dir).unwrap();
        assert!(!socket_dir.join("apply.lock").exists());

        let code = run(args_in(dir.path(), true)).await;
        assert_eq!(code, 0);
        assert!(
            !socket_dir.join("apply.lock").exists(),
            "--release must not leave a probe-created lock file behind"
        );
    }

    /// `--release` against a stale (unheld) leftover removes it and
    /// exits 0 — the recovery path. Distinct from
    /// `run_deletes_lock_file_when_release_and_free` only in intent
    /// (post-crash leftover), but kept as a named guard so the
    /// stale-file recovery contract is explicit.
    #[tokio::test]
    async fn run_release_removes_stale_unheld_lock_file() {
        let dir = tempfile::tempdir().unwrap();
        let socket_dir = dir.path().join(".socket");
        std::fs::create_dir_all(&socket_dir).unwrap();
        std::fs::write(socket_dir.join("apply.lock"), b"crashed-run-leftover").unwrap();

        let code = run(args_in(dir.path(), true)).await;
        assert_eq!(code, 0);
        assert!(
            !socket_dir.join("apply.lock").exists(),
            "--release must remove an unheld stale lock file"
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
