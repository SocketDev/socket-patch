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
use std::process::Command;

use fs2::FileExt;

#[path = "common/mod.rs"]
mod common;

use common::{json_string, parse_json_envelope};

/// Every SOCKET_* env var that the global args / the `unlock`
/// subcommand consult. These have clap `env =` fallbacks, so an
/// ambient value silently overrides the flags the tests *don't* pass
/// — most dangerously `SOCKET_UNLOCK_RELEASE` (turns every plain
/// probe into a `--release`, subverting the no-release tests),
/// `SOCKET_CWD` (redirects the probe to a different tree, making the
/// staged `.socket/` irrelevant), and `SOCKET_JSON` / `SOCKET_SILENT`
/// (which would respectively force JSON on the human-mode tests or
/// blank out the stderr the human-mode tests assert on). The shared
/// `common::run` only scrubs `SOCKET_API_TOKEN`, so this suite owns a
/// fully-scrubbed runner of its own.
const SOCKET_ENV_VARS: &[&str] = &[
    "SOCKET_UNLOCK_RELEASE",
    "SOCKET_CWD",
    "SOCKET_MANIFEST_PATH",
    "SOCKET_API_URL",
    "SOCKET_API_TOKEN",
    "SOCKET_ORG_SLUG",
    "SOCKET_PROXY_URL",
    "SOCKET_ECOSYSTEMS",
    "SOCKET_DOWNLOAD_MODE",
    "SOCKET_OFFLINE",
    "SOCKET_GLOBAL",
    "SOCKET_GLOBAL_PREFIX",
    "SOCKET_JSON",
    "SOCKET_VERBOSE",
    "SOCKET_SILENT",
    "SOCKET_DRY_RUN",
    "SOCKET_YES",
    "SOCKET_LOCK_TIMEOUT",
    "SOCKET_BREAK_LOCK",
    "SOCKET_DEBUG",
    "SOCKET_TELEMETRY_DISABLED",
];

/// Remove every scrub-listed SOCKET_* var from `cmd`'s environment.
/// Shared between [`run`] and the scrub-coverage regression test so the
/// test exercises the exact scrub the whole suite relies on.
fn scrub_socket_env(cmd: &mut Command) {
    for var in SOCKET_ENV_VARS {
        cmd.env_remove(var);
    }
}

/// Run the CLI with `args` in `cwd`, with the entire SOCKET_* env
/// surface scrubbed so the behavior under test is determined solely by
/// the CLI flags — not by whatever the developer/CI happens to export.
/// Returns `(exit_code, stdout, stderr)`. Local shadow of
/// `common::run`, which only removes `SOCKET_API_TOKEN`.
fn run(cwd: &Path, args: &[&str]) -> (i32, String, String) {
    let mut cmd = Command::new(common::binary());
    cmd.args(args).current_dir(cwd);
    scrub_socket_env(&mut cmd);
    let out = cmd.output().expect("failed to execute socket-patch binary");
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    (code, stdout, stderr)
}

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
    // `ends_with("apply.lock")` was too loose: any `foo/apply.lock` would pass,
    // including one outside `.socket/`. Pin the full `.socket/apply.lock`
    // suffix (built via Path so the separator is correct on every platform).
    let lock_field = json_string(&env, "lockFile").expect("lockFile field present");
    let expected_suffix = Path::new(".socket").join("apply.lock");
    let expected_suffix = expected_suffix.to_str().unwrap();
    assert!(
        lock_field.ends_with(expected_suffix),
        "lockFile should name the real .socket/apply.lock, got {lock_field}"
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
    let external = take_external_lock(&socket_dir);

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
    // The error must specifically be about a competing process AND name the
    // `.socket` location it observed — guards against a generic/empty error
    // message (or a hard-coded string with no real path context) masquerading
    // as lock_held.
    let msg = env
        .get("error")
        .and_then(|e| e.get("message"))
        .and_then(|m| m.as_str())
        .unwrap_or("");
    assert!(
        msg.contains("another socket-patch process"),
        "lock_held message should name the competing process, got: {msg}"
    );
    assert!(
        msg.contains(".socket"),
        "lock_held message should name the .socket location it probed, got: {msg}"
    );
    // Probing a held lock must NOT disturb the file the external holder
    // owns — the probe is read-only.
    assert!(
        socket_dir.join("apply.lock").is_file(),
        "held-probe must leave the externally-locked file intact"
    );

    // Positive control: the only thing that distinguishes "held" from "free"
    // must be the live OS lock, NOT the mere existence of the lock file. Drop
    // the external lock (the file stays on disk, byte-for-byte identical) and
    // re-probe: the verdict has to flip to `free`. If production reported
    // `held` just because `apply.lock` exists, this second probe would still
    // report held and the assertion below would fail — closing the
    // file-existence-masquerading-as-a-lock loophole.
    fs2::FileExt::unlock(&external).expect("release external lock");
    assert!(
        socket_dir.join("apply.lock").is_file(),
        "control precondition: the lock file must persist across the release"
    );
    let (code2, stdout2, stderr2) = run(dir.path(), &["unlock", "--json"]);
    assert_eq!(
        code2, 0,
        "free after release: stdout={stdout2}\nstderr={stderr2}"
    );
    let env2 = parse_json_envelope(&stdout2);
    assert_eq!(
        json_string(&env2, "status"),
        Some("free"),
        "the same lock file with no live OS lock must read as free: {stdout2}"
    );
    drop(external);
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

/// Human-mode (`unlock` without `--json`) plain probe of a free lock
/// prints the "Lock is free." line on stdout and exits 0. The JSON
/// suite covers the machine surface; this pins the human surface so a
/// regression in `emit_free`'s non-JSON branch (e.g. printing nothing,
/// or routing to stderr) is caught.
#[test]
fn unlock_human_mode_reports_free() {
    let dir = tempfile::tempdir().unwrap();
    let socket_dir = dir.path().join(".socket");
    std::fs::create_dir_all(&socket_dir).unwrap();

    let (code, stdout, stderr) = run(dir.path(), &["unlock"]);
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    assert!(
        stdout.contains("Lock is free."),
        "human-mode free probe should print the free line, got stdout:\n{stdout}"
    );
    // A plain free probe must NOT claim it removed anything.
    assert!(
        !stdout.to_lowercase().contains("removed"),
        "free probe without --release must not mention removal, got:\n{stdout}"
    );
}

/// Human-mode `--release` against a free lock with a pre-existing
/// leftover file prints the "Removed …" confirmation naming the real
/// lock path. Regression guard for unlock.rs:186 — if the
/// `removed`/`release` message branches were swapped, a genuine removal
/// would silently report "no lock file to remove".
#[test]
fn unlock_human_mode_release_reports_removed_when_leftover() {
    let dir = tempfile::tempdir().unwrap();
    let socket_dir = dir.path().join(".socket");
    std::fs::create_dir_all(&socket_dir).unwrap();
    let lock_file = socket_dir.join("apply.lock");
    std::fs::write(&lock_file, b"").unwrap();

    let (code, stdout, stderr) = run(dir.path(), &["unlock", "--release"]);
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    let lower = stdout.to_lowercase();
    assert!(
        lower.contains("removed"),
        "human-mode --release of a leftover should confirm removal, got:\n{stdout}"
    );
    // Names the actual file it removed, not a placeholder.
    assert!(
        stdout.contains("apply.lock"),
        "removal message should name the lock file, got:\n{stdout}"
    );
    // ...and it must not contradict itself by also saying there was
    // nothing to remove.
    assert!(
        !lower.contains("no lock file to remove"),
        "a real removal must not emit the no-op wording, got:\n{stdout}"
    );
    assert!(
        !lock_file.exists(),
        "--release should have deleted the file"
    );
}

/// Human-mode `--release` against a clean `.socket/` (no pre-existing
/// lock file) prints the "no lock file to remove" no-op wording — the
/// probe-created file doesn't count as a released leftover. Companion
/// to the "Removed" test: together they pin both arms of the
/// `release && removed` branch so neither can be silently swapped.
#[test]
fn unlock_human_mode_release_reports_noop_when_no_leftover() {
    let dir = tempfile::tempdir().unwrap();
    let socket_dir = dir.path().join(".socket");
    std::fs::create_dir_all(&socket_dir).unwrap();
    let lock_file = socket_dir.join("apply.lock");
    assert!(!lock_file.exists(), "pre-stage: no lock file expected");

    let (code, stdout, stderr) = run(dir.path(), &["unlock", "--release"]);
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    let lower = stdout.to_lowercase();
    assert!(
        lower.contains("no lock file to remove"),
        "human-mode --release with nothing to remove should say so, got:\n{stdout}"
    );
    // Must NOT falsely claim a removal happened.
    assert!(
        !lower.contains("removed"),
        "no-leftover --release must not claim a removal, got:\n{stdout}"
    );
    // The probe-created file must not survive (clean slate).
    assert!(
        !lock_file.exists(),
        "--release must not leave a probe-created lock file behind"
    );
}

/// `--silent` ("Suppress non-error output") must blank the human-mode
/// free line. Regression guard: `emit_free` gated its human output on
/// `!json` alone — `unlock --silent` printed "Lock is free." to stdout
/// while the rest of the file (held branch, `emit_error`) honored the
/// flag. Same bug class previously fixed in `list`, `repair`, `get`,
/// `remove`, `scan`, and `setup`.
#[test]
fn unlock_silent_suppresses_free_output() {
    let dir = tempfile::tempdir().unwrap();
    let socket_dir = dir.path().join(".socket");
    std::fs::create_dir_all(&socket_dir).unwrap();

    let (code, stdout, stderr) = run(dir.path(), &["unlock", "--silent"]);
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    assert!(
        stdout.trim().is_empty(),
        "--silent must produce no stdout on a free probe, got:\n{stdout}"
    );

    // Control run: the same probe WITHOUT --silent must print the free
    // line — otherwise the assertion above passes vacuously.
    let (loud_code, loud_stdout, _) = run(dir.path(), &["unlock"]);
    assert_eq!(loud_code, 0);
    assert!(
        loud_stdout.contains("Lock is free."),
        "non-silent free probe must print the free line, got:\n{loud_stdout}"
    );
}

/// `--silent --release` suppresses the output, not the mutation: the
/// leftover lock file must still be deleted, with nothing on stdout.
#[test]
fn unlock_silent_release_still_deletes_but_stays_quiet() {
    let dir = tempfile::tempdir().unwrap();
    let socket_dir = dir.path().join(".socket");
    std::fs::create_dir_all(&socket_dir).unwrap();
    let lock_file = socket_dir.join("apply.lock");
    std::fs::write(&lock_file, b"").unwrap();

    let (code, stdout, stderr) = run(dir.path(), &["unlock", "--silent", "--release"]);
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    assert!(
        stdout.trim().is_empty(),
        "--silent --release must produce no stdout, got:\n{stdout}"
    );
    assert!(
        !lock_file.exists(),
        "--silent must not suppress the release itself"
    );
}

/// `--silent` must NOT blank the JSON envelope — `--json --silent` is
/// the standard scripting combination and the machine output is the
/// whole point of it.
#[test]
fn unlock_silent_keeps_json_output() {
    let dir = tempfile::tempdir().unwrap();
    let socket_dir = dir.path().join(".socket");
    std::fs::create_dir_all(&socket_dir).unwrap();

    let (code, stdout, stderr) = run(dir.path(), &["unlock", "--json", "--silent"]);
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    let env = parse_json_envelope(&stdout);
    assert_eq!(
        json_string(&env, "status"),
        Some("free"),
        "--silent must not suppress the JSON envelope: {stdout}"
    );
}

/// `unlock` must probe the SAME lock the mutating subcommands take.
/// Every mutating command derives the lock directory from
/// `--manifest-path` (`resolved_manifest_path().parent()`); `unlock`
/// hardcoded `<cwd>/.socket` instead, so with a custom manifest path it
/// probed a directory nobody locks — reporting `free` (exit 0) while
/// `apply`/`remove` held their lock. For the CI-gating use case this
/// command exists for, that's the worst possible wrong answer.
#[test]
fn unlock_honors_manifest_path_when_probing() {
    let dir = tempfile::tempdir().unwrap();
    let custom_dir = dir.path().join("custom");
    let _external = take_external_lock(&custom_dir);

    let (code, stdout, stderr) = run(
        dir.path(),
        &[
            "unlock",
            "--json",
            "--manifest-path",
            "custom/manifest.json",
        ],
    );
    assert_eq!(
        code, 1,
        "a held custom-manifest-path lock must read as held; stdout={stdout}\nstderr={stderr}"
    );
    let env = parse_json_envelope(&stdout);
    let code_field = env
        .get("error")
        .and_then(|e| e.get("code"))
        .and_then(|c| c.as_str());
    assert_eq!(code_field, Some("lock_held"), "envelope: {stdout}");
}

/// Companion free-side guard: `--release` with a custom
/// `--manifest-path` must remove the leftover next to THAT manifest,
/// not silently no-op because `<cwd>/.socket` doesn't exist.
#[test]
fn unlock_release_honors_manifest_path() {
    let dir = tempfile::tempdir().unwrap();
    let custom_dir = dir.path().join("custom");
    std::fs::create_dir_all(&custom_dir).unwrap();
    let lock_file = custom_dir.join("apply.lock");
    std::fs::write(&lock_file, b"crashed-run-leftover").unwrap();

    let (code, stdout, stderr) = run(
        dir.path(),
        &[
            "unlock",
            "--json",
            "--release",
            "--manifest-path",
            "custom/manifest.json",
        ],
    );
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    let env = parse_json_envelope(&stdout);
    assert_eq!(
        env.get("released").and_then(|v| v.as_bool()),
        Some(true),
        "the custom-path leftover was removed, so released must be true: {stdout}"
    );
    assert!(
        !lock_file.exists(),
        "--release must delete the leftover next to the resolved manifest path"
    );
}

/// `--release --dry-run` must preview, not mutate: the leftover lock
/// file survives, `released` stays false (nothing was deleted), and
/// the flat envelope reports the dry run (`dryRun: true`,
/// `wouldRelease: true`). Regression guard: `unlock` ignored the
/// global `--dry-run` flag ("Preview, no mutations") and deleted the
/// file anyway.
#[test]
fn unlock_release_dry_run_previews_without_deleting() {
    let dir = tempfile::tempdir().unwrap();
    let socket_dir = dir.path().join(".socket");
    std::fs::create_dir_all(&socket_dir).unwrap();
    let lock_file = socket_dir.join("apply.lock");
    std::fs::write(&lock_file, b"crashed-run-leftover").unwrap();

    let (code, stdout, stderr) = run(dir.path(), &["unlock", "--json", "--release", "--dry-run"]);
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    assert!(
        lock_file.is_file(),
        "--dry-run must not delete the lock file"
    );
    let env = parse_json_envelope(&stdout);
    assert_eq!(json_string(&env, "status"), Some("free"));
    assert_eq!(
        env.get("released").and_then(|v| v.as_bool()),
        Some(false),
        "a dry run deletes nothing, so released must be false: {stdout}"
    );
    assert_eq!(
        env.get("dryRun").and_then(|v| v.as_bool()),
        Some(true),
        "the envelope must report the dry run: {stdout}"
    );
    assert_eq!(
        env.get("wouldRelease").and_then(|v| v.as_bool()),
        Some(true),
        "a real run would have removed the leftover, so wouldRelease must be true: {stdout}"
    );
}

/// Human-mode `--release --dry-run` with a leftover file announces the
/// would-be removal without claiming it happened, and leaves the file
/// on disk.
#[test]
fn unlock_human_mode_release_dry_run_previews_removal() {
    let dir = tempfile::tempdir().unwrap();
    let socket_dir = dir.path().join(".socket");
    std::fs::create_dir_all(&socket_dir).unwrap();
    let lock_file = socket_dir.join("apply.lock");
    std::fs::write(&lock_file, b"crashed-run-leftover").unwrap();

    let (code, stdout, stderr) = run(dir.path(), &["unlock", "--release", "--dry-run"]);
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    let lower = stdout.to_lowercase();
    assert!(
        lower.contains("would remove"),
        "dry-run --release should preview the removal, got:\n{stdout}"
    );
    // Must not claim a removal actually happened.
    assert!(
        !lower.contains("removed"),
        "dry-run --release must not claim a completed removal, got:\n{stdout}"
    );
    assert!(
        lock_file.is_file(),
        "--dry-run must leave the leftover lock file on disk"
    );
}

/// A held probe under `--dry-run` stamps the standard error envelope's
/// `dryRun` field truthfully. Regression guard: `unlock` hardcoded
/// `dry_run = false` into its `error_envelope` calls, so a
/// `--dry-run` invocation's failure envelope misreported itself as a
/// real run.
#[test]
fn unlock_dry_run_held_envelope_reports_dry_run() {
    let dir = tempfile::tempdir().unwrap();
    let socket_dir = dir.path().join(".socket");
    let _external = take_external_lock(&socket_dir);

    let (code, stdout, stderr) = run(dir.path(), &["unlock", "--json", "--release", "--dry-run"]);
    assert_eq!(code, 1, "stdout={stdout}\nstderr={stderr}");
    let env = parse_json_envelope(&stdout);
    let code_field = env
        .get("error")
        .and_then(|e| e.get("code"))
        .and_then(|c| c.as_str());
    assert_eq!(code_field, Some("lock_held"), "envelope: {stdout}");
    assert_eq!(
        env.get("dryRun").and_then(|v| v.as_bool()),
        Some(true),
        "held-lock envelope must carry the invocation's dry-run flag: {stdout}"
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

/// The suite's scrub must cover EVERY flag-bound `SOCKET_*` env var —
/// clap validates env-bound values even for flags the invocation never
/// passes, so a single ambient junk value (e.g. `SOCKET_STRICT=banana`
/// exported in a dev shell) aborts the parse and turns the entire suite
/// red. Seed-then-scrub (pattern from `e2e_golang_redirect.rs`): every
/// var the production parser binds is seeded with a value its parser
/// rejects, then run through the suite's own scrub. Any binding the
/// scrub misses reaches the child and fails the probe. Regression
/// guard: the hand-rolled scrub list drifted from `GlobalArgs`, missing
/// `SOCKET_STRICT`, `SOCKET_VENDOR_SOURCE`, `SOCKET_VENDOR_URL`, and
/// `SOCKET_PATCH_SERVER_URL`.
#[test]
fn run_scrubs_every_flag_bound_socket_env_var() {
    use socket_patch_cli::args::{GLOBAL_ARG_ENV_VARS, LOCAL_ARG_ENV_VARS};

    let dir = tempfile::tempdir().unwrap();
    let mut cmd = Command::new(common::binary());
    cmd.args(["unlock", "--json"]).current_dir(dir.path());
    // Hostile seed: rejected by every restrictive parser in play
    // (parse_bool_flag, parse_vendor_source, the ecosystems validator,
    // the integer flags), so any var that escapes the scrub aborts the
    // command instead of silently parsing.
    for var in GLOBAL_ARG_ENV_VARS.iter().chain(LOCAL_ARG_ENV_VARS) {
        cmd.env(var, "hostile-junk-not-a-valid-value");
    }
    scrub_socket_env(&mut cmd);
    let out = cmd.output().expect("failed to execute socket-patch binary");
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert_eq!(
        code, 0,
        "a fully-scrubbed probe must succeed despite hostile ambient \
         SOCKET_* values; stdout={stdout}\nstderr={stderr}"
    );
    let env = parse_json_envelope(&stdout);
    assert_eq!(
        json_string(&env, "status"),
        Some("free"),
        "envelope: {stdout}"
    );
}
