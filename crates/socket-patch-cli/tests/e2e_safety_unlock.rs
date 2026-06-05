//! End-to-end: `socket-patch unlock` reports lock state and
//! optionally releases a free lock.
//!
//! Mirrors `e2e_safety_lock.rs`'s strategy: this test takes the lock
//! externally via `fs2` (same crate the binary uses, same path) and
//! verifies the `unlock` subcommand observes the OS-level lock the
//! same way the mutating subcommands do.
//!
//! Network: no. Toolchain: no. NOT `#[ignore]`.

use std::fs::OpenOptions;
use std::path::Path;

use fs2::FileExt;

#[path = "common/mod.rs"]
mod common;

use common::{json_string, parse_json_envelope, run};

/// Take an exclusive flock on `.socket/apply.lock`. Returns the
/// open file whose Drop releases the lock — keep it bound for the
/// duration of the test.
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

/// `unlock` against a fresh project (no `.socket/`) reports `free`
/// and exits 0. Generic "is the project locked?" probe that CI
/// tooling can call before deciding whether to fire a mutating
/// subcommand.
#[test]
fn unlock_reports_free_when_no_socket_dir() {
    let dir = tempfile::tempdir().unwrap();
    let (code, stdout, stderr) = run(dir.path(), &["unlock", "--json"]);
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    let env = parse_json_envelope(&stdout);
    assert_eq!(json_string(&env, "status"), Some("free"));
    assert_eq!(json_string(&env, "command"), Some("unlock"));
    // No `--release`, nothing existed: `released` must be present and false,
    // not merely absent (an envelope that dropped the field entirely would
    // otherwise read as a pass).
    assert_eq!(
        env.get("released").and_then(|v| v.as_bool()),
        Some(false),
        "free probe without --release must report released=false: {stdout}"
    );
    // The reported lock path must be the real `.socket/apply.lock`, not some
    // placeholder — this is the path the mutating subcommands actually flock.
    let lock_field = json_string(&env, "lockFile").expect("lockFile field present");
    assert!(
        lock_field.ends_with("apply.lock"),
        "lockFile should name the real apply.lock, got {lock_field}"
    );
    // A pure probe must not materialize project state out of thin air.
    assert!(
        !dir.path().join(".socket").exists(),
        "probing a fresh repo must not create .socket/"
    );
}

/// `unlock` while another process holds the lock reports `held`
/// and exits 1. The JSON envelope's `error.code` is `lock_held` —
/// matches the contract emitted by the mutating subcommands so
/// downstream consumers don't need a separate `unlock`-specific
/// branch.
#[test]
fn unlock_reports_held_when_lock_actively_held() {
    let dir = tempfile::tempdir().unwrap();
    let socket_dir = dir.path().join(".socket");
    let _external = take_external_lock(&socket_dir);

    let (code, stdout, stderr) = run(dir.path(), &["unlock", "--json"]);
    assert_eq!(code, 1, "stdout={stdout}\nstderr={stderr}");
    let env = parse_json_envelope(&stdout);
    assert_eq!(json_string(&env, "status"), Some("error"));
    // Must be tagged as an unlock failure, not some other subcommand's
    // envelope leaking through.
    assert_eq!(json_string(&env, "command"), Some("unlock"));
    let code_field = env
        .get("error")
        .and_then(|e| e.get("code"))
        .and_then(|c| c.as_str());
    assert_eq!(code_field, Some("lock_held"));
    // The error must specifically be about a competing process — guards
    // against a generic/empty error message masquerading as lock_held.
    let msg = env
        .get("error")
        .and_then(|e| e.get("message"))
        .and_then(|m| m.as_str())
        .unwrap_or("");
    assert!(
        msg.contains("another socket-patch process"),
        "lock_held message should name the competing process, got: {msg}"
    );
    // Probing a held lock must NOT disturb the file the external holder
    // owns — the probe is read-only.
    assert!(
        socket_dir.join("apply.lock").is_file(),
        "held-probe must leave the externally-locked file intact"
    );
}

/// `unlock --release` against a free lock with a leftover file
/// removes the file. This is the recovery path for the
/// post-crash leftover-file scenario.
#[test]
fn unlock_release_deletes_lock_file_when_free() {
    let dir = tempfile::tempdir().unwrap();
    let socket_dir = dir.path().join(".socket");
    std::fs::create_dir_all(&socket_dir).unwrap();
    let lock_file = socket_dir.join("apply.lock");
    std::fs::write(&lock_file, b"").unwrap();
    assert!(lock_file.is_file(), "pre-stage failed");

    let (code, stdout, stderr) = run(dir.path(), &["unlock", "--json", "--release"]);
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    let env = parse_json_envelope(&stdout);
    assert_eq!(json_string(&env, "command"), Some("unlock"));
    assert_eq!(json_string(&env, "status"), Some("free"));
    assert_eq!(
        env.get("released").and_then(|v| v.as_bool()),
        Some(true),
        "a pre-existing leftover file was removed, so released must be true: {stdout}"
    );
    assert!(
        !lock_file.exists(),
        "--release should have deleted the lock file"
    );
}

/// `unlock --release` against a `.socket/` directory that has no
/// lock file reports `released: false` — there was nothing to
/// release. Regression test: `acquire` creates the lock file on
/// demand, so a naive `remove_file().is_ok()` check would wrongly
/// claim it released a pre-existing leftover. The probe must not
/// leave a lock file behind either (clean slate).
#[test]
fn unlock_release_reports_not_released_when_no_lock_file() {
    let dir = tempfile::tempdir().unwrap();
    let socket_dir = dir.path().join(".socket");
    std::fs::create_dir_all(&socket_dir).unwrap();
    let lock_file = socket_dir.join("apply.lock");
    assert!(!lock_file.exists(), "pre-stage: no lock file expected");

    let (code, stdout, stderr) = run(dir.path(), &["unlock", "--json", "--release"]);
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    let env = parse_json_envelope(&stdout);
    assert_eq!(json_string(&env, "command"), Some("unlock"));
    assert_eq!(json_string(&env, "status"), Some("free"));
    assert_eq!(
        env.get("released").and_then(|v| v.as_bool()),
        Some(false),
        "nothing pre-existed, so released must be false: {stdout}"
    );
    assert!(
        !lock_file.exists(),
        "--release should not leave a probe-created lock file behind"
    );
}

/// `unlock --release` against a completely fresh project (no
/// `.socket/` at all) reports `released: false` and exits 0.
/// Mirrors the missing-dir branch's contract.
#[test]
fn unlock_release_reports_not_released_when_no_socket_dir() {
    let dir = tempfile::tempdir().unwrap();
    let (code, stdout, stderr) = run(dir.path(), &["unlock", "--json", "--release"]);
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    let env = parse_json_envelope(&stdout);
    assert_eq!(json_string(&env, "command"), Some("unlock"));
    assert_eq!(json_string(&env, "status"), Some("free"));
    assert_eq!(
        env.get("released").and_then(|v| v.as_bool()),
        Some(false),
        "no .socket/ existed, so released must be false: {stdout}"
    );
    // `--release` against a missing dir must stay a no-op: it must not
    // create `.socket/` (and therefore no lock file) as a side-effect.
    assert!(
        !dir.path().join(".socket").exists(),
        "--release on a fresh repo must not create .socket/"
    );
}

/// `unlock --release` refuses when the lock is HELD — the file
/// must NOT be removed (otherwise we'd undermine the OS-level
/// exclusion). The user has to use `--break-lock` on the mutating
/// subcommand for that scenario.
#[test]
fn unlock_release_refuses_when_held() {
    let dir = tempfile::tempdir().unwrap();
    let socket_dir = dir.path().join(".socket");
    let _external = take_external_lock(&socket_dir);

    let (code, _stdout, stderr) = run(dir.path(), &["unlock", "--release"]);
    assert_eq!(code, 1, "stderr={stderr}");
    assert!(
        socket_dir.join("apply.lock").is_file(),
        "lock file must survive a refused --release"
    );
    // Exit 1 + surviving file is not enough — a crash or an unrelated I/O
    // error would also satisfy that. Confirm we hit the *held-refusal*
    // branch specifically: the operator is told the release was refused and
    // pointed at --break-lock. This is the distinctive `--release`+held
    // message that no other failure path emits.
    let lower = stderr.to_lowercase();
    assert!(
        lower.contains("lock is held"),
        "stderr should report the held lock, got:\n{stderr}"
    );
    assert!(
        lower.contains("refusing to release"),
        "stderr should explicitly refuse to release a held lock, got:\n{stderr}"
    );
    assert!(
        lower.contains("break-lock"),
        "stderr should point operator at --break-lock, got:\n{stderr}"
    );
}

/// Human-mode (`unlock` without `--json`) emits a stderr hint
/// pointing the user at `--break-lock` when the lock is held.
/// Pinned at the substring level so the helpful guidance survives
/// minor copy edits.
#[test]
fn unlock_human_mode_hints_at_break_lock_when_held() {
    let dir = tempfile::tempdir().unwrap();
    let socket_dir = dir.path().join(".socket");
    let _external = take_external_lock(&socket_dir);

    let (code, _stdout, stderr) = run(dir.path(), &["unlock"]);
    assert_eq!(code, 1, "stderr={stderr}");
    let lower = stderr.to_lowercase();
    assert!(
        lower.contains("lock is held"),
        "stderr should report the held lock, got:\n{stderr}"
    );
    assert!(
        lower.contains("break-lock"),
        "stderr should point operator at --break-lock, got:\n{stderr}"
    );
    // This is the *probe* (no --release) branch, distinct from the
    // release-refusal branch — it must NOT claim it refused to release
    // something the caller never asked to release.
    assert!(
        !lower.contains("refusing to release"),
        "plain held probe must not emit the --release-refusal wording, got:\n{stderr}"
    );
}
