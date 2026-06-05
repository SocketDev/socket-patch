//! Coverage for the `--dry-run` paths across multiple commands.
//! Each test runs a command with `--dry-run` against a fixture and
//! asserts the JSON envelope's `dryRun: true` field — covering the
//! dry-run flag-propagation branches each command's `run` has.

use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

fn make_socket_with_empty_manifest(root: &std::path::Path) {
    let socket = root.join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    std::fs::write(
        socket.join("manifest.json"),
        r#"{"patches":{}}"#,
    )
    .unwrap();
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
}

/// `apply --dry-run --json` against an empty manifest reports
/// dryRun:true and success. Covers the dry-run flag propagation
/// in `commands::apply::run`.
#[test]
fn apply_dry_run_empty_manifest_emits_dry_run_envelope() {
    let tmp = tempfile::tempdir().expect("tempdir");
    make_socket_with_empty_manifest(tmp.path());
    let out = Command::new(binary())
        .args(["apply", "--json", "--dry-run"])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .output()
        .expect("run apply");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("invalid JSON: {e}\n{stdout}"));
    assert_eq!(v["command"], "apply");
    assert_eq!(v["dryRun"], true);
    // A dry-run must never mutate anything: every "did work" counter is 0.
    let summary = &v["summary"];
    assert!(summary.is_object(), "expected summary object; got {v}");
    assert_eq!(summary["applied"], 0, "dry-run applied a patch: {v}");
    assert_eq!(summary["updated"], 0, "dry-run updated a patch: {v}");
    assert_eq!(summary["removed"], 0, "dry-run removed a patch: {v}");
    assert_eq!(summary["downloaded"], 0, "dry-run downloaded a blob: {v}");
    // Empty manifest → nothing to do; events stay empty.
    assert_eq!(v["events"], serde_json::json!([]), "unexpected events: {v}");
}

/// `repair --dry-run --offline --json`: dry-run with no patches
/// should succeed with `dryRun:true`.
#[test]
fn repair_dry_run_offline_emits_dry_run_envelope() {
    let tmp = tempfile::tempdir().expect("tempdir");
    make_socket_with_empty_manifest(tmp.path());
    let out = Command::new(binary())
        .args(["repair", "--json", "--dry-run", "--offline"])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .output()
        .expect("run repair");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("invalid JSON: {e}\n{stdout}"));
    assert_eq!(v["command"], "repair");
    assert_eq!(v["dryRun"], true);
    // No patches + offline + dry-run is a clean no-op success.
    assert_eq!(v["status"], "success", "expected success status: {v}");
    let summary = &v["summary"];
    assert!(summary.is_object(), "expected summary object; got {v}");
    assert_eq!(summary["applied"], 0, "dry-run applied a patch: {v}");
    assert_eq!(summary["updated"], 0, "dry-run updated a patch: {v}");
    assert_eq!(summary["removed"], 0, "dry-run removed a patch: {v}");
    assert_eq!(v["events"], serde_json::json!([]), "unexpected events: {v}");
}

/// Rollback with no patches in manifest + --json must not crash.
/// Locks in the manifest-empty-but-valid branch.
#[test]
fn rollback_with_empty_manifest_emits_envelope() {
    let tmp = tempfile::tempdir().expect("tempdir");
    make_socket_with_empty_manifest(tmp.path());
    let out = Command::new(binary())
        .args(["rollback", "--json", "--offline"])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .output()
        .expect("run rollback");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("invalid JSON: {e}\nstdout:\n{stdout}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stderr)));
    // Empty-but-valid manifest: rollback is a clean success that touches nothing.
    assert_eq!(out.status.code(), Some(0), "rollback should exit 0: {v}");
    assert_eq!(v["status"], "success", "expected success status: {v}");
    assert_eq!(v["rolledBack"], 0, "nothing should roll back: {v}");
    assert_eq!(v["alreadyOriginal"], 0, "no files to inspect: {v}");
    assert_eq!(v["failed"], 0, "no rollback should fail: {v}");
    assert_eq!(v["results"], serde_json::json!([]), "unexpected results: {v}");
}

/// `remove --json` with no manifest at all: the early-exit
/// envelope branch with `manifest_not_found` error code. Covered
/// elsewhere too but a redundant lock is cheap.
#[test]
fn remove_with_no_socket_dir_emits_manifest_not_found() {
    let tmp = tempfile::tempdir().expect("tempdir");
    // NO .socket/ directory at all.
    let out = Command::new(binary())
        .args([
            "remove",
            "11111111-1111-4111-8111-111111111111",
            "--json",
            "--yes",
            "--skip-rollback",
        ])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .output()
        .expect("run remove");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(v["command"], "remove");
    assert_eq!(v["status"], "error", "missing manifest must be an error: {v}");
    assert_eq!(out.status.code(), Some(1), "error must exit nonzero: {v}");
    // Must be the *specific* missing-manifest code, not a generic not_found.
    assert_eq!(
        v["error"]["code"], "manifest_not_found",
        "expected manifest_not_found error code; got {v}"
    );
}

/// `list --json` against an empty manifest emits status=success with
/// an all-zero summary and no events. Covers the list-empty path.
#[test]
fn list_with_empty_manifest_emits_empty_envelope() {
    let tmp = tempfile::tempdir().expect("tempdir");
    make_socket_with_empty_manifest(tmp.path());
    let out = Command::new(binary())
        .args(["list", "--json"])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .output()
        .expect("run list");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("invalid JSON: {e}\n{stdout}"));
    assert_eq!(v["command"], "list");
    assert_eq!(v["status"], "success");
    assert_eq!(out.status.code(), Some(0), "list should exit 0: {v}");
    // Empty manifest: nothing discovered, no events emitted.
    let summary = &v["summary"];
    assert!(summary.is_object(), "expected summary object; got {v}");
    assert_eq!(summary["discovered"], 0, "empty manifest discovered patches: {v}");
    assert_eq!(v["events"], serde_json::json!([]), "unexpected events: {v}");
}

/// `--silent` flag suppresses the friendly "no manifest" message
/// in non-JSON mode for `apply`. Covers the silent-flag short-circuit.
#[test]
fn apply_silent_no_manifest_produces_no_output() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let out = Command::new(binary())
        .args(["apply", "--silent"])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .output()
        .expect("run apply");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.trim().is_empty(), "silent mode should produce no stdout");
}
