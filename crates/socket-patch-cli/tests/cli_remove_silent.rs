//! `remove --silent` contract tests.
//!
//! CLI_CONTRACT.md defines `--silent` as "Errors only". Regression
//! guard: `remove` gated all of its human-readable chatter on `!json`
//! alone, and passed only `json` as `rollback_patches`' silent param —
//! so `remove --silent` printed everything. Same bug class previously
//! fixed in `list`, `repair`, and `get`. Runs fully offline: the patch
//! record has no
//! files (so rollback fetches no blobs) and the project dir has no
//! installed packages, so the internal rollback takes the
//! "not installed" path and the manifest mutation needs no network.
//!
//! Stderr assertions ignore the "No SOCKET_API_TOKEN set" client
//! warning: it's printed unconditionally by
//! `get_api_client_with_overrides` in core for every command and is
//! out of scope for `remove`'s `--silent` gating.

use std::path::{Path, PathBuf};
use std::process::Command;

use socket_patch_cli::args::GLOBAL_ARG_ENV_VARS;

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

const ONE_PATCH_MANIFEST: &str = r#"{
  "patches": {
    "pkg:npm/__remove_silent_test__@1.0.0": {
      "uuid": "33333333-3333-4333-8333-333333333333",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {},
      "vulnerabilities": {},
      "description": "synthetic remove --silent test patch",
      "license": "MIT",
      "tier": "free"
    }
  }
}"#;

fn make_socket_dir(root: &Path) -> PathBuf {
    let socket = root.join(".socket");
    std::fs::create_dir_all(&socket).expect("create .socket");
    std::fs::write(socket.join("manifest.json"), ONE_PATCH_MANIFEST).expect("write manifest");
    socket
}

/// Run `socket-patch remove` in `cwd` with a scrubbed SOCKET_* environment
/// so ambient developer/CI configuration (tokens, silent toggles) can't
/// change the branch under test.
fn run_remove(cwd: &Path, args: &[&str]) -> (i32, String, String) {
    let mut cmd = Command::new(binary());
    cmd.arg("remove").args(args).current_dir(cwd);
    for var in GLOBAL_ARG_ENV_VARS {
        cmd.env_remove(var);
    }
    cmd.env_remove("SOCKET_SKIP_ROLLBACK");
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1");
    let out = cmd.output().expect("run socket-patch remove");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

/// A successful `remove --silent --yes` (rollback included — the package
/// is simply not installed) must produce no output on either stream:
/// no "will be removed" listing, no "Rolling back" / "No packages found
/// to rollback" progress, no "Removed N patch(es)" summary.
#[test]
fn remove_silent_produces_no_output_on_success() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = make_socket_dir(tmp.path());

    let (code, stdout, stderr) = run_remove(
        tmp.path(),
        &["pkg:npm/__remove_silent_test__@1.0.0", "--silent", "--yes"],
    );
    assert_eq!(
        code, 0,
        "remove must succeed; stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        stdout.trim().is_empty(),
        "--silent must produce no stdout; got {stdout:?}"
    );
    let stderr_rest: Vec<&str> = stderr
        .lines()
        .filter(|l| !l.contains("SOCKET_API_TOKEN") && !l.trim().is_empty())
        .collect();
    assert!(
        stderr_rest.is_empty(),
        "--silent must produce no stderr chatter on success; got {stderr_rest:?}"
    );

    // The removal must still have happened — silent suppresses output,
    // not the mutation.
    let body = std::fs::read_to_string(socket.join("manifest.json")).expect("read manifest");
    let v: serde_json::Value = serde_json::from_str(&body).expect("parse manifest");
    assert!(
        v["patches"].as_object().expect("patches object").is_empty(),
        "patch entry must be removed from the manifest"
    );

    // Control run: the same scenario WITHOUT --silent must print the
    // human messages — otherwise the assertions above pass vacuously.
    let tmp2 = tempfile::tempdir().expect("tempdir");
    make_socket_dir(tmp2.path());
    let (loud_code, loud_stdout, loud_stderr) = run_remove(
        tmp2.path(),
        &["pkg:npm/__remove_silent_test__@1.0.0", "--yes"],
    );
    assert_eq!(loud_code, 0);
    assert!(
        loud_stdout.contains("Rolling back patch before removal"),
        "non-silent run must print rollback progress; got {loud_stdout:?}"
    );
    assert!(
        loud_stdout.contains("Removed 1 patch(es) from manifest"),
        "non-silent run must print the removal summary; got {loud_stdout:?}"
    );
    assert!(
        loud_stderr.contains("will be removed"),
        "non-silent run must print the pre-removal listing; got {loud_stderr:?}"
    );
}

/// A leftover `apply.lock` with no live holder must not disturb a
/// silent remove: the acquire reclaims it in place with no chatter.
#[test]
fn remove_silent_reclaims_stale_lock_without_output() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = make_socket_dir(tmp.path());
    std::fs::write(socket.join("apply.lock"), b"").expect("write stale lock");

    let (code, stdout, stderr) = run_remove(
        tmp.path(),
        &[
            "pkg:npm/__remove_silent_test__@1.0.0",
            "--silent",
            "--yes",
            "--skip-rollback",
        ],
    );
    assert_eq!(
        code, 0,
        "remove must succeed through a stale lock file; stdout={stdout:?} stderr={stderr:?}"
    );
    let stderr_rest: Vec<&str> = stderr
        .lines()
        .filter(|l| !l.contains("SOCKET_API_TOKEN") && !l.trim().is_empty())
        .collect();
    assert!(
        stderr_rest.is_empty(),
        "--silent must produce no stderr chatter; got {stderr_rest:?}"
    );
}

/// Write a vendor ledger with one npm entry (empty wiring, so the revert
/// is a pure offline artifact-dir delete) plus the artifact dir it names.
/// `manifest_purl` is the ledger key AND base purl; `detached` selects the
/// `remove` code path under test.
fn write_vendor_state(root: &Path, purl: &str, uuid: &str, detached: bool) {
    write_vendor_state_wired(root, purl, uuid, detached, "[]");
}

/// Like [`write_vendor_state`] but with an explicit wiring array, so tests
/// can plant a wiring record that makes the (still offline, still
/// successful) revert emit a backend warning.
fn write_vendor_state_wired(root: &Path, purl: &str, uuid: &str, detached: bool, wiring: &str) {
    let vendor = root.join(".socket/vendor");
    let artifact_dir = vendor.join("npm").join(uuid);
    std::fs::create_dir_all(&artifact_dir).expect("create artifact dir");
    std::fs::write(artifact_dir.join("package.tgz"), b"tgz").expect("write artifact");
    let detached_field = if detached { r#""detached": true,"# } else { "" };
    let state = format!(
        r#"{{
  "version": 1,
  "entries": {{
    "{purl}": {{
      "ecosystem": "npm",
      "basePurl": "{purl}",
      "uuid": "{uuid}",
      "artifact": {{ "path": ".socket/vendor/npm/{uuid}/package.tgz" }},
      {detached_field}
      "wiring": {wiring}
    }}
  }}
}}"#
    );
    std::fs::write(vendor.join("state.json"), state).expect("write vendor state");
}

/// A wiring record naming a file the npm revert backend does not edit:
/// the revert still succeeds (artifact deleted, ledger entry dropped) but
/// emits a `vendor_lock_entry_drifted` warning — fully offline.
const DRIFTED_WIRING: &str = r#"[{ "file": "weird.txt", "kind": "npm_lock_entry", "action": "added", "key": "node_modules/x" }]"#;

/// `--silent` must also gate the vendor-revert chatter on the manifest
/// path: removing a vendored patch printed "Reverted vendoring for ..."
/// (stdout) even under `--silent`, because the vendor block gated its
/// human output on `!json` alone — the same bug class the rest of this
/// file guards, reintroduced with the vendor overhaul. `vendor --revert`
/// itself gates the identical message on `!silent && !json`.
#[test]
fn remove_silent_suppresses_vendored_revert_output() {
    let purl = "pkg:npm/__remove_silent_test__@1.0.0";
    let uuid = "33333333-3333-4333-8333-333333333333";

    let tmp = tempfile::tempdir().expect("tempdir");
    make_socket_dir(tmp.path());
    write_vendor_state(tmp.path(), purl, uuid, false);

    let (code, stdout, stderr) = run_remove(tmp.path(), &[purl, "--silent", "--yes"]);
    assert_eq!(
        code, 0,
        "remove must succeed; stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        stdout.trim().is_empty(),
        "--silent must suppress the vendor-revert stdout chatter; got {stdout:?}"
    );
    let stderr_rest: Vec<&str> = stderr
        .lines()
        .filter(|l| !l.contains("SOCKET_API_TOKEN") && !l.trim().is_empty())
        .collect();
    assert!(
        stderr_rest.is_empty(),
        "--silent must produce no stderr chatter on success; got {stderr_rest:?}"
    );

    // The revert must still have happened — silent suppresses output,
    // not the mutation. An emptied ledger is deleted outright.
    assert!(
        !tmp.path().join(".socket/vendor/state.json").exists(),
        "vendor ledger entry must be reverted (empty ledger deleted)"
    );

    // Control run: without --silent the revert message must print —
    // otherwise the assertions above pass vacuously.
    let tmp2 = tempfile::tempdir().expect("tempdir");
    make_socket_dir(tmp2.path());
    write_vendor_state(tmp2.path(), purl, uuid, false);
    let (loud_code, loud_stdout, _loud_stderr) = run_remove(tmp2.path(), &[purl, "--yes"]);
    assert_eq!(loud_code, 0);
    assert!(
        loud_stdout.contains("Reverted vendoring for"),
        "non-silent run must print the vendor-revert message; got {loud_stdout:?}"
    );
}

/// The `--skip-rollback` "vendor wiring left in place" note is chatter,
/// not an error, so `--silent` must suppress it too.
#[test]
fn remove_silent_suppresses_vendored_skip_rollback_note() {
    let purl = "pkg:npm/__remove_silent_test__@1.0.0";
    let uuid = "33333333-3333-4333-8333-333333333333";

    let tmp = tempfile::tempdir().expect("tempdir");
    make_socket_dir(tmp.path());
    write_vendor_state(tmp.path(), purl, uuid, false);

    let (code, stdout, stderr) =
        run_remove(tmp.path(), &[purl, "--silent", "--yes", "--skip-rollback"]);
    assert_eq!(
        code, 0,
        "remove must succeed; stdout={stdout:?} stderr={stderr:?}"
    );
    let stderr_rest: Vec<&str> = stderr
        .lines()
        .filter(|l| !l.contains("SOCKET_API_TOKEN") && !l.trim().is_empty())
        .collect();
    assert!(
        stderr_rest.is_empty(),
        "--silent must suppress the vendored --skip-rollback note; got {stderr_rest:?}"
    );
    assert!(
        stdout.trim().is_empty(),
        "--silent must produce no stdout; got {stdout:?}"
    );

    // Control run: without --silent the note must print.
    let tmp2 = tempfile::tempdir().expect("tempdir");
    make_socket_dir(tmp2.path());
    write_vendor_state(tmp2.path(), purl, uuid, false);
    let (loud_code, _loud_stdout, loud_stderr) =
        run_remove(tmp2.path(), &[purl, "--yes", "--skip-rollback"]);
    assert_eq!(loud_code, 0);
    assert!(
        loud_stderr.contains("is vendored; --skip-rollback leaves"),
        "non-silent --skip-rollback must print the vendored note; got {loud_stderr:?}"
    );
}

/// The detached-only remove path (`scan --vendor --detached` entries with
/// no manifest record) printed its pre-removal listing (stderr) and
/// "Reverted vendoring for ..." (stdout) even under `--silent`: the whole
/// function gated on `!json` alone.
#[test]
fn remove_silent_suppresses_detached_revert_output() {
    let purl = "pkg:npm/__remove_silent_detached__@1.0.0";
    let uuid = "44444444-4444-4444-8444-444444444444";

    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).expect("create .socket");
    // Empty manifest: the identifier matches only the detached ledger entry.
    std::fs::write(socket.join("manifest.json"), r#"{ "patches": {} }"#).expect("write manifest");
    write_vendor_state(tmp.path(), purl, uuid, true);

    let (code, stdout, stderr) = run_remove(tmp.path(), &[purl, "--silent", "--yes"]);
    assert_eq!(
        code, 0,
        "detached remove must succeed; stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        stdout.trim().is_empty(),
        "--silent must suppress the detached revert stdout chatter; got {stdout:?}"
    );
    let stderr_rest: Vec<&str> = stderr
        .lines()
        .filter(|l| !l.contains("SOCKET_API_TOKEN") && !l.trim().is_empty())
        .collect();
    assert!(
        stderr_rest.is_empty(),
        "--silent must suppress the detached pre-removal listing; got {stderr_rest:?}"
    );

    // The removal must still have happened.
    assert!(
        !tmp.path().join(".socket/vendor/state.json").exists(),
        "detached ledger entry must be reverted (empty ledger deleted)"
    );

    // Control run: without --silent both messages must print.
    let tmp2 = tempfile::tempdir().expect("tempdir");
    let socket2 = tmp2.path().join(".socket");
    std::fs::create_dir_all(&socket2).expect("create .socket");
    std::fs::write(socket2.join("manifest.json"), r#"{ "patches": {} }"#).expect("write manifest");
    write_vendor_state(tmp2.path(), purl, uuid, true);
    let (loud_code, loud_stdout, loud_stderr) = run_remove(tmp2.path(), &[purl, "--yes"]);
    assert_eq!(loud_code, 0);
    assert!(
        loud_stderr.contains("detached vendored patch(es) will be reverted"),
        "non-silent detached run must print the listing; got {loud_stderr:?}"
    );
    assert!(
        loud_stdout.contains("Reverted vendoring for"),
        "non-silent detached run must print the revert message; got {loud_stdout:?}"
    );
}

/// Backend revert warnings are chatter, not errors: `vendor --revert`
/// gates the identical "Warning (code): detail" stderr line on
/// `!silent && !json` (`record_warning`), but remove's vendor block
/// printed it under `--silent` (gated on `!json` alone).
#[test]
fn remove_silent_suppresses_vendor_revert_warnings() {
    let purl = "pkg:npm/__remove_silent_test__@1.0.0";
    let uuid = "33333333-3333-4333-8333-333333333333";

    let tmp = tempfile::tempdir().expect("tempdir");
    make_socket_dir(tmp.path());
    write_vendor_state_wired(tmp.path(), purl, uuid, false, DRIFTED_WIRING);

    let (code, _stdout, stderr) = run_remove(tmp.path(), &[purl, "--silent", "--yes"]);
    assert_eq!(code, 0, "remove must succeed; stderr={stderr:?}");
    assert!(
        !stderr.contains("Warning ("),
        "--silent must suppress backend revert warnings; got {stderr:?}"
    );

    // Control run: without --silent the warning must print.
    let tmp2 = tempfile::tempdir().expect("tempdir");
    make_socket_dir(tmp2.path());
    write_vendor_state_wired(tmp2.path(), purl, uuid, false, DRIFTED_WIRING);
    let (loud_code, _loud_stdout, loud_stderr) = run_remove(tmp2.path(), &[purl, "--yes"]);
    assert_eq!(loud_code, 0);
    assert!(
        loud_stderr.contains("Warning (vendor_lock_entry_drifted)"),
        "non-silent run must print the backend warning; got {loud_stderr:?}"
    );
}

/// The `--dry-run` "Would revert vendoring for ..." preview (stdout) is
/// chatter too: the manifest-path vendor block gated it on `!json` alone.
/// Dry-run skips the confirm prompt, so no `--yes` is needed.
#[test]
fn remove_silent_suppresses_dry_run_revert_preview() {
    let purl = "pkg:npm/__remove_silent_test__@1.0.0";
    let uuid = "33333333-3333-4333-8333-333333333333";

    let tmp = tempfile::tempdir().expect("tempdir");
    make_socket_dir(tmp.path());
    write_vendor_state(tmp.path(), purl, uuid, false);

    let (code, stdout, stderr) = run_remove(tmp.path(), &[purl, "--silent", "--dry-run"]);
    assert_eq!(
        code, 0,
        "dry-run remove must succeed; stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        stdout.trim().is_empty(),
        "--silent must suppress the dry-run revert preview; got {stdout:?}"
    );
    // Dry-run mutates nothing: the ledger must survive.
    assert!(
        tmp.path().join(".socket/vendor/state.json").exists(),
        "dry-run must not touch the vendor ledger"
    );

    // Control run: without --silent the preview must print.
    let tmp2 = tempfile::tempdir().expect("tempdir");
    make_socket_dir(tmp2.path());
    write_vendor_state(tmp2.path(), purl, uuid, false);
    let (loud_code, loud_stdout, _loud_stderr) = run_remove(tmp2.path(), &[purl, "--dry-run"]);
    assert_eq!(loud_code, 0);
    assert!(
        loud_stdout.contains("Would revert vendoring for"),
        "non-silent dry-run must print the revert preview; got {loud_stdout:?}"
    );
}

/// Detached-path twin of the dry-run preview: the listing (stderr) and
/// "Would revert vendoring for ..." (stdout) both printed under `--silent`.
#[test]
fn remove_silent_suppresses_detached_dry_run_preview() {
    let purl = "pkg:npm/__remove_silent_detached__@1.0.0";
    let uuid = "44444444-4444-4444-8444-444444444444";

    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).expect("create .socket");
    std::fs::write(socket.join("manifest.json"), r#"{ "patches": {} }"#).expect("write manifest");
    write_vendor_state(tmp.path(), purl, uuid, true);

    let (code, stdout, stderr) = run_remove(tmp.path(), &[purl, "--silent", "--dry-run"]);
    assert_eq!(
        code, 0,
        "detached dry-run must succeed; stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        stdout.trim().is_empty(),
        "--silent must suppress the detached dry-run preview; got {stdout:?}"
    );
    let stderr_rest: Vec<&str> = stderr
        .lines()
        .filter(|l| !l.contains("SOCKET_API_TOKEN") && !l.trim().is_empty())
        .collect();
    assert!(
        stderr_rest.is_empty(),
        "--silent must suppress the detached listing on dry-run; got {stderr_rest:?}"
    );
    assert!(
        tmp.path().join(".socket/vendor/state.json").exists(),
        "dry-run must not touch the vendor ledger"
    );

    // Control run: without --silent the preview must print.
    let tmp2 = tempfile::tempdir().expect("tempdir");
    let socket2 = tmp2.path().join(".socket");
    std::fs::create_dir_all(&socket2).expect("create .socket");
    std::fs::write(socket2.join("manifest.json"), r#"{ "patches": {} }"#).expect("write manifest");
    write_vendor_state(tmp2.path(), purl, uuid, true);
    let (loud_code, loud_stdout, _loud_stderr) = run_remove(tmp2.path(), &[purl, "--dry-run"]);
    assert_eq!(loud_code, 0);
    assert!(
        loud_stdout.contains("Would revert vendoring for"),
        "non-silent detached dry-run must print the preview; got {loud_stdout:?}"
    );
}

/// Detached-path twin of the backend-warning gate: warnings printed under
/// `--silent` because the whole function gated on `!json` alone.
#[test]
fn remove_silent_suppresses_detached_revert_warnings() {
    let purl = "pkg:npm/__remove_silent_detached__@1.0.0";
    let uuid = "44444444-4444-4444-8444-444444444444";

    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).expect("create .socket");
    std::fs::write(socket.join("manifest.json"), r#"{ "patches": {} }"#).expect("write manifest");
    write_vendor_state_wired(tmp.path(), purl, uuid, true, DRIFTED_WIRING);

    let (code, _stdout, stderr) = run_remove(tmp.path(), &[purl, "--silent", "--yes"]);
    assert_eq!(code, 0, "detached remove must succeed; stderr={stderr:?}");
    assert!(
        !stderr.contains("Warning ("),
        "--silent must suppress detached revert warnings; got {stderr:?}"
    );

    // Control run: without --silent the warning must print.
    let tmp2 = tempfile::tempdir().expect("tempdir");
    let socket2 = tmp2.path().join(".socket");
    std::fs::create_dir_all(&socket2).expect("create .socket");
    std::fs::write(socket2.join("manifest.json"), r#"{ "patches": {} }"#).expect("write manifest");
    write_vendor_state_wired(tmp2.path(), purl, uuid, true, DRIFTED_WIRING);
    let (loud_code, _loud_stdout, loud_stderr) = run_remove(tmp2.path(), &[purl, "--yes"]);
    assert_eq!(loud_code, 0);
    assert!(
        loud_stderr.contains("Warning (vendor_lock_entry_drifted)"),
        "non-silent detached run must print the backend warning; got {loud_stderr:?}"
    );
}

/// Errors must still print under `--silent` ("errors only", not "nothing"):
/// an unknown identifier keeps its stderr message and exit 1.
#[test]
fn remove_silent_keeps_error_output() {
    let tmp = tempfile::tempdir().expect("tempdir");
    make_socket_dir(tmp.path());

    let (code, _stdout, stderr) = run_remove(
        tmp.path(),
        &["pkg:npm/__no_such_package__@9.9.9", "--silent", "--yes"],
    );
    assert_eq!(code, 1, "unknown identifier must exit 1");
    assert!(
        stderr.contains("No patch found matching identifier"),
        "--silent must NOT suppress error output; got {stderr:?}"
    );
}
