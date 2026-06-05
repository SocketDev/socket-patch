//! End-to-end: `socket-patch apply` honors `<.socket>/apply.lock`.
//!
//! Strategy: the test takes the lock itself via `fs2` (the same crate
//! the binary uses) on the same `.socket/apply.lock` path, then
//! spawns `socket-patch apply`. The binary must observe the
//! external lock and exit 1 with `errorCode: lock_held`.
//!
//! This avoids any test-only hook in production code — the test is
//! literally racing the binary for the same OS-level lock file.
//! Cross-platform via `fs2` (flock on Unix, LockFileEx on Windows).
//!
//! Network: no. Toolchain: no. NOT `#[ignore]`.

use std::fs::OpenOptions;
use std::path::Path;
use std::time::Duration;

use fs2::FileExt;

#[path = "common/mod.rs"]
mod common;

use common::{
    envelope_error_code, envelope_error_message, json_string, parse_json_envelope, run,
    write_minimal_manifest, PatchEntry,
};

/// Assert that a parsed apply envelope proves the binary got *past*
/// lock acquisition and ran the real apply pipeline — i.e. it is NOT
/// a lock-contention failure. Centralises the discriminator so the
/// "lock was released / acquired" tests can't silently pass on empty
/// or unrelated output the way a bare `!stdout.contains("lock_held")`
/// substring check would.
///
/// Contract derived from the live binary: a lock_held failure emits
/// `status: "error"` + `error.code: "lock_held"`; a successful
/// acquisition against this fixture (a package that isn't on disk)
/// emits `status: "partialFailure"` with no top-level `error` object.
fn assert_lock_acquired(env: &serde_json::Value) {
    assert_eq!(
        json_string(env, "command"),
        Some("apply"),
        "envelope should be an apply envelope.\nenvelope: {env}"
    );
    assert_ne!(
        envelope_error_code(env),
        Some("lock_held"),
        "apply must NOT report lock_held when the lock is free.\nenvelope: {env}"
    );
    assert!(
        env.get("error").is_none(),
        "a non-lock apply run must carry no top-level error object.\nenvelope: {env}"
    );
    assert_eq!(
        json_string(env, "status"),
        Some("partialFailure"),
        "apply that acquired the lock should run the pipeline to a \
         partialFailure (synthetic package absent), not an error.\nenvelope: {env}"
    );
    assert!(
        env.get("summary").and_then(|s| s.as_object()).is_some(),
        "acquired-lock apply must carry a summary object.\nenvelope: {env}"
    );
}

/// Stage a minimal `.socket/manifest.json` so `apply` gets past the
/// "no manifest, exit 0" early-return. The manifest references a
/// non-existent package, but the lock acquisition happens before
/// the crawler runs — we never get that far.
fn setup_socket_dir(socket_dir: &Path) {
    write_minimal_manifest(
        socket_dir,
        "pkg:npm/lockfixture@1.0.0",
        "22222222-2222-4222-8222-222222222222",
        &[PatchEntry {
            file_name: "package/index.js",
            before_hash: &"a".repeat(64),
            after_hash: &"b".repeat(64),
        }],
    );
}

/// Take an exclusive flock on the binary's lock file path. Returns
/// the open file handle whose drop releases the lock — keep it
/// bound for the duration of the test, otherwise the lock vanishes.
fn take_external_lock(socket_dir: &Path) -> std::fs::File {
    std::fs::create_dir_all(socket_dir).unwrap();
    let path = socket_dir.join("apply.lock");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .expect("open lock file");
    file.try_lock_exclusive()
        .expect("test could not take initial lock");
    file
}

/// Spawn `socket-patch apply --json` against an already-locked
/// `.socket/`. The binary must refuse with `lock_held`. Pinned
/// JSON contract.
#[test]
fn lock_held_returned_to_second_process() {
    let dir = tempfile::tempdir().unwrap();
    let socket_dir = dir.path().join(".socket");
    setup_socket_dir(&socket_dir);

    // Hold the lock for the duration of this test.
    let _external = take_external_lock(&socket_dir);

    let (code, stdout, stderr) = run(dir.path(), &["apply", "--json"]);
    assert_eq!(
        code, 1,
        "expected lock contention to exit 1.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env = parse_json_envelope(&stdout);
    assert_eq!(
        envelope_error_code(&env),
        Some("lock_held"),
        "expected errorCode=lock_held.\nenvelope: {env}"
    );
    assert_eq!(json_string(&env, "status"), Some("error"));
    assert_eq!(json_string(&env, "command"), Some("apply"));
    // The message is part of the contract surface humans/scripts read.
    assert_eq!(
        envelope_error_message(&env),
        Some("another socket-patch process is operating in this directory"),
        "lock_held message must be the stable contention string.\nenvelope: {env}"
    );
    // Under contention the pipeline never ran: zero applied, no events.
    assert_eq!(
        env["summary"]["applied"].as_u64(),
        Some(0),
        "nothing may be applied while the lock is held.\nenvelope: {env}"
    );
    assert_eq!(
        env["events"].as_array().map(|e| e.len()),
        Some(0),
        "a pre-pipeline lock failure must carry no events.\nenvelope: {env}"
    );
}

/// Human-output mode: same contention scenario, no `--json`. The
/// binary exits 1 and prints a stderr line that mentions
/// "operating in this directory" — the user-facing hint surface.
#[test]
fn lock_held_human_mode_mentions_other_process() {
    let dir = tempfile::tempdir().unwrap();
    let socket_dir = dir.path().join(".socket");
    setup_socket_dir(&socket_dir);
    let _external = take_external_lock(&socket_dir);

    let (code, stdout, stderr) = run(dir.path(), &["apply"]);
    assert_eq!(code, 1, "human-mode contention must exit 1.\nstderr:\n{stderr}");
    // Human mode must NOT leak a JSON envelope to stdout — the error
    // is a human line on stderr. A regression that printed JSON here
    // (or emitted nothing) would otherwise slip past a loose
    // substring check.
    assert!(
        stdout.trim().is_empty(),
        "human mode must not print a JSON envelope to stdout, got:\n{stdout}"
    );
    // Pin the actual contention contract phrase rather than just
    // "another"+"process": the binary prints the lock_held message and
    // the actionable unlock/break-lock hint.
    assert!(
        stderr.contains("Error: another socket-patch process is operating in this directory"),
        "stderr should carry the lock_held error line, got:\n{stderr}"
    );
    assert!(
        stderr.contains("--break-lock") && stderr.contains("socket-patch unlock"),
        "stderr should give the actionable unlock/break-lock hint, got:\n{stderr}"
    );
}

/// Release the lock; a fresh apply must succeed (or at least not
/// return `lock_held`). Confirms the binary doesn't get into a
/// stuck state if the lock file already exists from a prior run.
#[test]
fn lock_released_after_external_drop() {
    let dir = tempfile::tempdir().unwrap();
    let socket_dir = dir.path().join(".socket");
    setup_socket_dir(&socket_dir);

    // Take, then drop, the lock.
    {
        let _external = take_external_lock(&socket_dir);
    } // drop releases the OS-level lock

    let (code, stdout, stderr) = run(dir.path(), &["apply", "--json"]);
    // The synthetic manifest targets a package that isn't on disk, so
    // apply runs the pipeline to a partialFailure (exit 1). The point
    // of THIS test is that the released lock is re-acquired: assert the
    // envelope proves we got past the lock (not the old vacuous
    // `!stdout.contains("lock_held")`, which a crash to empty stdout or
    // an unrelated error would also satisfy).
    let env = parse_json_envelope(&stdout);
    assert_lock_acquired(&env);
    assert_eq!(
        code, 1,
        "partialFailure against an absent package exits 1.\nstderr:\n{stderr}"
    );
}

/// The lock file is intentionally not deleted on guard drop —
/// keeping the inode lets subsequent apply runs re-flock without a
/// create race. Verify the file is still there after a successful
/// apply, and that re-acquiring still works.
#[test]
fn lock_file_persists_across_runs() {
    let dir = tempfile::tempdir().unwrap();
    let socket_dir = dir.path().join(".socket");
    setup_socket_dir(&socket_dir);

    // Setup writes only the manifest — the lock file must not exist
    // yet, so we can prove the first run is what creates it.
    assert!(
        !socket_dir.join("apply.lock").exists(),
        "apply.lock must not exist before the first run"
    );

    // First run: must acquire (not lock_held) and create the file.
    let (_code1, stdout1, _stderr1) = run(dir.path(), &["apply", "--json"]);
    assert_lock_acquired(&parse_json_envelope(&stdout1));

    // Lock file should persist after the run completes (inode kept so
    // subsequent acquires don't race on create).
    assert!(
        socket_dir.join("apply.lock").is_file(),
        "apply.lock should persist between runs"
    );

    // Second run must still be able to acquire (file exists, but no
    // one holds the OS lock) — full envelope check, not a substring.
    let (_code2, stdout2, _stderr2) = run(dir.path(), &["apply", "--json"]);
    assert_lock_acquired(&parse_json_envelope(&stdout2));

    // And the file is still there afterwards.
    assert!(
        socket_dir.join("apply.lock").is_file(),
        "apply.lock should still persist after the second run"
    );
}

/// Multiple real `socket-patch apply` subprocesses contending for the
/// same `.socket/` lock must ALL observe the held lock and refuse —
/// exactly the real-world race of a dev running `apply` in several
/// terminals at once.
///
/// Determinism: the synthetic manifest points at no packages on disk,
/// so a free-running apply finishes in tens of ms — too fast to
/// reliably catch two binaries colliding with each other. Instead we
/// pin the contention window by holding the external lock ourselves
/// for the whole duration that the child processes run, then spawn N
/// *real* apply binaries concurrently. Because we hold the lock the
/// entire time they execute, every one of them must report
/// `lock_held`. After we release, a fresh apply must acquire.
#[test]
fn two_apply_subprocesses_serialize() {
    use std::sync::Arc;

    let dir = tempfile::tempdir().unwrap();
    let socket_dir = dir.path().join(".socket");
    setup_socket_dir(&socket_dir);

    // Hold the lock for the entire window the children run in, so the
    // contention is deterministic rather than a ~10ms flake.
    let external = take_external_lock(&socket_dir);

    // Spawn several real apply subprocesses at once. They all run
    // while we hold the lock, so each must fail with lock_held.
    let cwd: Arc<std::path::PathBuf> = Arc::new(dir.path().to_path_buf());
    let handles: Vec<_> = (0..4)
        .map(|_| {
            let cwd = Arc::clone(&cwd);
            std::thread::spawn(move || run(&cwd, &["apply", "--json"]))
        })
        .collect();

    for h in handles {
        let (code, stdout, stderr) = h.join().expect("apply child thread panicked");
        assert_eq!(
            code, 1,
            "every contending apply must exit 1.\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
        let env = parse_json_envelope(&stdout);
        assert_eq!(
            envelope_error_code(&env),
            Some("lock_held"),
            "every contending apply must report lock_held.\nenvelope: {env}"
        );
        assert_eq!(json_string(&env, "status"), Some("error"));
    }

    // Release and re-run — must now succeed in acquiring.
    drop(external);
    let (_code2, stdout2, _) = run(dir.path(), &["apply", "--json"]);
    assert_lock_acquired(&parse_json_envelope(&stdout2));
}

/// Sanity check that doesn't actually depend on the binary: confirm
/// our `take_external_lock` helper does what we think (a second
/// concurrent flock from the test process itself returns Err). If
/// this fails the entire test file is invalid.
#[test]
fn helper_lock_is_actually_exclusive() {
    let dir = tempfile::tempdir().unwrap();
    let socket_dir = dir.path().join(".socket");
    std::fs::create_dir_all(&socket_dir).unwrap();

    let _first = take_external_lock(&socket_dir);

    let path = socket_dir.join("apply.lock");
    let second = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    let result = second.try_lock_exclusive();
    assert!(
        result.is_err(),
        "second flock on same file should fail while first is held"
    );
}

/// `apply --break-lock` against a pre-staged lock file (no live
/// holder) removes the file before acquisition and proceeds with
/// the apply pass. The JSON envelope must surface the
/// `lock_broken` warning event so the action is auditable.
///
/// Setup mirrors the OS-level scenario: a previous run crashed and
/// left `apply.lock` behind, but the OS-level flock was released
/// (so a fresh acquire would succeed even without --break-lock).
/// The --break-lock path is the safe-by-design version of `rm`.
#[test]
fn break_lock_removes_stale_file_and_records_warning() {
    let dir = tempfile::tempdir().unwrap();
    let socket_dir = dir.path().join(".socket");
    setup_socket_dir(&socket_dir);
    // Pre-stage a lock file but DON'T hold an OS lock — simulates
    // the post-crash scenario where the file lingers but flock was
    // released. Without --break-lock the binary would still
    // acquire fine (`acquire` re-opens the file); with --break-lock
    // we additionally get the audit event.
    std::fs::write(socket_dir.join("apply.lock"), b"").unwrap();

    let (code, stdout, stderr) = run(dir.path(), &["apply", "--json", "--break-lock"]);
    let env = parse_json_envelope(&stdout);
    // --break-lock breaks the stale file and then acquires cleanly, so
    // the run must NOT itself be a lock_held failure. Prove the binary
    // genuinely re-acquired the lock and drove the real apply pipeline
    // to completion (partialFailure against the absent synthetic
    // package, no top-level error) — not merely that the errorCode
    // happened to differ from "lock_held". Without this, a regression
    // that emitted the audit event but then bailed before acquiring
    // (or with some other non-lock error) would slip through the
    // `assert_ne!` + event-presence checks below.
    assert_lock_acquired(&env);
    assert_ne!(
        envelope_error_code(&env),
        Some("lock_held"),
        "--break-lock should acquire, not report lock_held.\nenvelope: {env}"
    );
    // Same exit contract as every other acquired-then-pipeline run in
    // this file: partialFailure against an absent package exits 1.
    assert_eq!(
        code, 1,
        "break-lock apply that ran the pipeline to partialFailure must exit 1.\nstderr:\n{stderr}"
    );
    let events = env["events"].as_array().expect("events array");
    // Exactly one lock_broken audit event, carrying the audit reason
    // that names the action and the lock path.
    let lock_broken: Vec<_> = events
        .iter()
        .filter(|e| {
            e.get("action").and_then(|v| v.as_str()) == Some("skipped")
                && e.get("errorCode").and_then(|v| v.as_str()) == Some("lock_broken")
        })
        .collect();
    assert_eq!(
        lock_broken.len(),
        1,
        "apply --break-lock should emit exactly one lock_broken skipped event.\nstdout:\n{stdout}"
    );
    let reason = lock_broken[0]
        .get("reason")
        .and_then(|v| v.as_str())
        .expect("lock_broken event must carry a reason");
    assert!(
        reason.contains("--break-lock") && reason.contains("apply.lock"),
        "lock_broken reason should name the action and the lock file, got: {reason}"
    );
    // The break is also reflected in the skipped tally.
    assert!(
        env["summary"]["skipped"].as_u64().unwrap_or(0) >= 1,
        "lock_broken should be counted in summary.skipped.\nenvelope: {env}"
    );
    // The inode is kept for subsequent acquires.
    assert!(
        socket_dir.join("apply.lock").is_file(),
        "apply.lock should be re-created after --break-lock acquires"
    );
}

/// `apply --lock-timeout=1` against a held lock waits up to 1s
/// before reporting `lock_held`. Confirms the wait knob is wired
/// end-to-end through the CLI surface.
///
/// Lower bound: the apply call must take at least ~700ms because
/// the wait budget is ~1s with 100ms backoff slop. Upper bound is
/// not asserted because CI hosts have varying schedule jitter.
#[test]
fn lock_timeout_waits_then_reports_held() {
    let dir = tempfile::tempdir().unwrap();
    let socket_dir = dir.path().join(".socket");
    setup_socket_dir(&socket_dir);
    let _external = take_external_lock(&socket_dir);

    let start = std::time::Instant::now();
    let (code, stdout, _stderr) = run(dir.path(), &["apply", "--json", "--lock-timeout=1"]);
    let elapsed = start.elapsed();
    assert_eq!(code, 1);
    let env = parse_json_envelope(&stdout);
    assert_eq!(envelope_error_code(&env), Some("lock_held"));
    assert_eq!(json_string(&env, "status"), Some("error"));
    // The message must reflect that we actually waited the budget —
    // this distinguishes a real timeout-plumbed `acquire(timeout)`
    // from an unconditional sleep that ignored the knob.
    assert_eq!(
        envelope_error_message(&env),
        Some("another socket-patch process is operating in this directory (waited 1s)"),
        "timeout contention message must report the 1s wait budget.\nenvelope: {env}"
    );
    assert!(
        elapsed >= Duration::from_millis(700),
        "expected at least ~700ms wait under --lock-timeout=1, got {:?}",
        elapsed
    );
}

/// Compile-time witness: the helper signature stays stable.
/// `fs2::FileExt` import gets pulled in once so failing to import it
/// (e.g. fs2 dev-dep dropped from Cargo.toml) is caught at build
/// time, not at test run time.
#[allow(dead_code)]
fn _compile_witness() -> Duration {
    Duration::from_secs(0)
}
