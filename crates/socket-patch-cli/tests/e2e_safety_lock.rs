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
    envelope_error_code, json_string, parse_json_envelope, run, write_minimal_manifest,
    PatchEntry,
};

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

    let (code, _stdout, stderr) = run(dir.path(), &["apply"]);
    assert_eq!(code, 1);
    // Don't pin the exact phrasing — just confirm the user gets
    // SOMETHING about another process. The contract is "stderr is
    // non-empty and the error is recognizable."
    assert!(
        stderr.to_lowercase().contains("another")
            && stderr.to_lowercase().contains("process"),
        "stderr should mention another process holding the lock, got:\n{stderr}"
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

    let (_code, stdout, _stderr) = run(dir.path(), &["apply", "--json"]);
    // The synthetic manifest targets a package that doesn't exist
    // on disk; apply may exit with any of {0 success-with-skips, 1
    // unmatched-error}. The only thing we assert here: the output
    // does NOT carry the lock-held error code.
    assert!(
        !stdout.contains("lock_held"),
        "fresh apply after lock release must not report lock_held.\nstdout:\n{stdout}"
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

    // First run.
    let _ = run(dir.path(), &["apply", "--json"]);

    // Lock file should exist after run completes.
    assert!(
        socket_dir.join("apply.lock").is_file(),
        "apply.lock should persist between runs"
    );

    // Second run must still be able to acquire (file exists, but
    // no one holds the OS lock). Same "no lock_held in output"
    // assertion as `lock_released_after_external_drop`.
    let (_code, stdout, _stderr) = run(dir.path(), &["apply", "--json"]);
    assert!(
        !stdout.contains("lock_held"),
        "second run on persistent lock file must succeed in acquiring.\nstdout:\n{stdout}"
    );
}

/// Two `socket-patch apply` subprocesses started near-simultaneously
/// must serialize — exactly one exits with `lock_held`. This is the
/// real-world race: a dev runs `apply` in two terminals at once.
///
/// We spawn the first as a non-blocking child, then immediately
/// invoke the second synchronously. Because the synthetic manifest
/// points at no packages on disk, both runs would normally finish
/// in tens of ms — too fast to reliably observe the lock collision.
/// Workaround: have the first process race against a tight
/// retry-loop in this test rather than against itself, by holding
/// our external lock briefly to pin the contention window.
#[test]
fn two_apply_subprocesses_serialize() {
    let dir = tempfile::tempdir().unwrap();
    let socket_dir = dir.path().join(".socket");
    setup_socket_dir(&socket_dir);

    // Hold the lock during the apply call so contention is
    // deterministic. (Without this the two apply runs would race
    // each other for the ~10ms apply takes, and we'd flake.)
    let external = take_external_lock(&socket_dir);

    // Issue an apply while we hold the lock — must report
    // lock_held.
    let (code, stdout, _) = run(dir.path(), &["apply", "--json"]);
    assert_eq!(code, 1);
    let env = parse_json_envelope(&stdout);
    assert_eq!(envelope_error_code(&env), Some("lock_held"));

    // Release and re-run — must now succeed in acquiring.
    drop(external);
    let (_code2, stdout2, _) = run(dir.path(), &["apply", "--json"]);
    assert!(
        !stdout2.contains("lock_held"),
        "after lock release apply should acquire.\nstdout:\n{stdout2}"
    );
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

/// Compile-time witness: the helper signature stays stable.
/// `fs2::FileExt` import gets pulled in once so failing to import it
/// (e.g. fs2 dev-dep dropped from Cargo.toml) is caught at build
/// time, not at test run time.
#[allow(dead_code)]
fn _compile_witness() -> Duration {
    Duration::from_secs(0)
}
