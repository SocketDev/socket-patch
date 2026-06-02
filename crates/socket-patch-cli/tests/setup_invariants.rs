//! Integration tests for `setup` against handcrafted `package.json`
//! fixtures. `setup` operates entirely on disk (lockfile detection +
//! package.json mutation) so every path is runnable without network.

use std::path::{Path, PathBuf};
use std::process::Command;

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

fn run_setup(cwd: &Path, extra: &[&str]) -> (i32, String) {
    let mut args = vec!["setup", "--json"];
    args.extend_from_slice(extra);
    let out = Command::new(binary())
        .args(&args)
        .current_dir(cwd)
        .env_remove("SOCKET_API_TOKEN")
        .output()
        .expect("run socket-patch");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
    )
}

fn write(path: &Path, content: &str) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create parent");
    }
    std::fs::write(path, content).expect("write file");
}

// ---------------------------------------------------------------------------
// Empty project
// ---------------------------------------------------------------------------

#[test]
fn setup_no_package_json_emits_no_files_status() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (code, stdout) = run_setup(tmp.path(), &[]);
    assert_eq!(code, 0, "no files should still exit 0; stdout=\n{stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["status"], "no_files");
    assert_eq!(v["updated"], 0);
    assert_eq!(v["alreadyConfigured"], 0);
    assert_eq!(v["errors"], 0);
}

// ---------------------------------------------------------------------------
// Single package.json without socket-patch
// ---------------------------------------------------------------------------

#[test]
fn setup_dry_run_does_not_modify_package_json() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pkg = tmp.path().join("package.json");
    let original = r#"{
  "name": "test-proj",
  "version": "1.0.0"
}
"#;
    write(&pkg, original);

    let (code, stdout) = run_setup(tmp.path(), &["--dry-run"]);
    assert_eq!(code, 0, "dry-run should succeed; stdout=\n{stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["status"], "dry_run");
    assert_eq!(v["dryRun"], true);
    assert_eq!(v["wouldUpdate"], 1);

    // package.json must be byte-identical after dry-run.
    let after = std::fs::read_to_string(&pkg).expect("read package.json");
    assert_eq!(after, original, "dry-run must not modify package.json");
}

#[test]
fn setup_yes_writes_postinstall_script() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pkg = tmp.path().join("package.json");
    write(
        &pkg,
        r#"{ "name": "test-proj", "version": "1.0.0" }
"#,
    );

    let (code, stdout) = run_setup(tmp.path(), &["--yes"]);
    assert_eq!(code, 0, "setup should succeed; stdout=\n{stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["status"], "success");
    assert_eq!(v["updated"], 1);

    let after = std::fs::read_to_string(&pkg).expect("read package.json");
    let parsed: serde_json::Value = serde_json::from_str(&after).expect("valid package.json");
    let postinstall = parsed["scripts"]["postinstall"]
        .as_str()
        .expect("postinstall script must be set");
    assert!(
        postinstall.contains("socket-patch"),
        "postinstall must invoke socket-patch; got: {postinstall}"
    );
}

#[test]
fn setup_already_configured_returns_idempotent_status() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pkg = tmp.path().join("package.json");

    // First setup run wires up the scripts.
    write(
        &pkg,
        r#"{ "name": "test-proj", "version": "1.0.0" }
"#,
    );
    let (code1, _) = run_setup(tmp.path(), &["--yes"]);
    assert_eq!(code1, 0);

    // Second run should detect the config is already there.
    let (code2, stdout2) = run_setup(tmp.path(), &["--yes"]);
    assert_eq!(code2, 0, "second run should succeed; stdout=\n{stdout2}");
    let v: serde_json::Value = serde_json::from_str(&stdout2).expect("valid JSON");
    assert_eq!(v["status"], "already_configured");
    assert_eq!(v["updated"], 0);
    assert_eq!(v["alreadyConfigured"], 1);
}

// ---------------------------------------------------------------------------
// Package manager detection
// ---------------------------------------------------------------------------

#[test]
fn setup_detects_pnpm_from_lockfile() {
    let tmp = tempfile::tempdir().expect("tempdir");
    write(
        &tmp.path().join("package.json"),
        r#"{ "name": "test-proj", "version": "1.0.0" }
"#,
    );
    write(&tmp.path().join("pnpm-lock.yaml"), "lockfileVersion: '9.0'\n");

    let (code, stdout) = run_setup(tmp.path(), &["--yes"]);
    assert_eq!(code, 0, "setup should succeed; stdout=\n{stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["packageManager"], "pnpm");

    // pnpm dlx should appear in the generated postinstall.
    let after = std::fs::read_to_string(tmp.path().join("package.json")).unwrap();
    assert!(
        after.contains("pnpm dlx"),
        "pnpm projects should use `pnpm dlx`; got: {after}"
    );
}

#[test]
fn setup_defaults_to_npm_when_no_lockfile() {
    let tmp = tempfile::tempdir().expect("tempdir");
    write(
        &tmp.path().join("package.json"),
        r#"{ "name": "test-proj", "version": "1.0.0" }
"#,
    );

    let (_, stdout) = run_setup(tmp.path(), &["--yes"]);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["packageManager"], "npm");
}

// ---------------------------------------------------------------------------
// Monorepo handling
// ---------------------------------------------------------------------------

#[test]
fn setup_pnpm_monorepo_only_updates_root() {
    // pnpm workspaces: setup intentionally skips workspace-level
    // package.json files (their postinstall would fail because the
    // workspace pkg doesn't depend on @socketsecurity/socket-patch).
    let tmp = tempfile::tempdir().expect("tempdir");
    write(
        &tmp.path().join("package.json"),
        r#"{ "name": "monorepo-root", "version": "1.0.0" }
"#,
    );
    write(
        &tmp.path().join("pnpm-lock.yaml"),
        "lockfileVersion: '9.0'\n",
    );
    write(
        &tmp.path().join("pnpm-workspace.yaml"),
        "packages:\n  - 'packages/*'\n",
    );
    write(
        &tmp.path().join("packages/a/package.json"),
        r#"{ "name": "a", "version": "1.0.0" }
"#,
    );
    write(
        &tmp.path().join("packages/b/package.json"),
        r#"{ "name": "b", "version": "1.0.0" }
"#,
    );

    let (code, stdout) = run_setup(tmp.path(), &["--yes"]);
    assert_eq!(code, 0, "monorepo setup should succeed; stdout=\n{stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(
        v["updated"], 1,
        "only the root package.json should be touched in a pnpm monorepo"
    );

    // Workspace packages must NOT have been modified.
    let a = std::fs::read_to_string(tmp.path().join("packages/a/package.json")).unwrap();
    assert!(
        !a.contains("socket-patch"),
        "workspace package.json must not be touched"
    );
}

// ---------------------------------------------------------------------------
// Per-file JSON shape — locks the schema of `files[*]` entries
// ---------------------------------------------------------------------------

#[test]
fn setup_yes_json_files_entry_has_expected_keys() {
    let tmp = tempfile::tempdir().expect("tempdir");
    write(
        &tmp.path().join("package.json"),
        r#"{ "name": "test-proj", "version": "1.0.0" }
"#,
    );

    let (_, stdout) = run_setup(tmp.path(), &["--yes"]);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    let files = v["files"].as_array().expect("files array");
    assert_eq!(files.len(), 1);
    let entry = &files[0];
    assert!(entry["path"].is_string());
    assert!(entry["status"].is_string());
}

// ---------------------------------------------------------------------------
// Error handling — a malformed package.json must NOT be reported as success.
//
// Regression: when nothing was updatable but a file errored (e.g. invalid
// JSON), `setup` used to emit `status: "already_configured"` with exit 0,
// masking the failure. A parse error must surface as a non-zero exit.
// ---------------------------------------------------------------------------

#[test]
fn setup_malformed_package_json_reports_error_and_exits_nonzero() {
    let tmp = tempfile::tempdir().expect("tempdir");
    write(&tmp.path().join("package.json"), "not valid json!!!");

    let (code, stdout) = run_setup(tmp.path(), &["--yes"]);
    assert_eq!(code, 1, "a malformed package.json must exit non-zero; stdout=\n{stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(
        v["status"], "error",
        "must not be reported as already_configured"
    );
    assert_eq!(v["updated"], 0);
    assert_eq!(v["alreadyConfigured"], 0);
    assert_eq!(v["errors"], 1);
    let files = v["files"].as_array().expect("files array");
    assert_eq!(files[0]["status"], "error");
    assert!(files[0]["error"].is_string());
}

#[test]
fn setup_malformed_does_not_claim_already_configured_in_human_mode() {
    let tmp = tempfile::tempdir().expect("tempdir");
    write(&tmp.path().join("package.json"), "not valid json!!!");

    // Human (non-JSON) mode: the misleading "All package.json files are
    // already configured" line must not appear when a file errored.
    let out = Command::new(binary())
        .args(["setup", "--yes"])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .output()
        .expect("run socket-patch");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(1), "human mode must exit 1; stdout=\n{stdout}");
    assert!(
        !stdout.contains("already configured with socket-patch"),
        "must not falsely claim everything is already configured; stdout=\n{stdout}"
    );
}

#[test]
fn setup_dry_run_with_error_exits_nonzero() {
    // A valid root (would-update) alongside a malformed workspace member:
    // dry-run must still surface the parse error via a non-zero exit rather
    // than masking it behind the `dry_run` status.
    let tmp = tempfile::tempdir().expect("tempdir");
    write(
        &tmp.path().join("package.json"),
        r#"{ "name": "root", "workspaces": ["packages/*"] }
"#,
    );
    write(&tmp.path().join("packages/a/package.json"), "{bad json");

    let (code, stdout) = run_setup(tmp.path(), &["--dry-run"]);
    assert_eq!(code, 1, "dry-run with an error must exit non-zero; stdout=\n{stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["status"], "dry_run");
    assert_eq!(v["errors"], 1);
    assert_eq!(v["wouldUpdate"], 1);

    // dry-run must not have written anything.
    let root = std::fs::read_to_string(tmp.path().join("package.json")).unwrap();
    assert!(!root.contains("socket-patch"), "dry-run must not modify files");
}

#[test]
fn setup_partial_failure_exits_nonzero_when_applying() {
    // One updatable file + one malformed file, applied for real (--yes):
    // the run must report partial_failure and exit 1.
    let tmp = tempfile::tempdir().expect("tempdir");
    write(
        &tmp.path().join("package.json"),
        r#"{ "name": "root", "workspaces": ["packages/*"] }
"#,
    );
    write(&tmp.path().join("packages/a/package.json"), "{bad json");

    let (code, stdout) = run_setup(tmp.path(), &["--yes"]);
    assert_eq!(code, 1, "partial failure must exit non-zero; stdout=\n{stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["status"], "partial_failure");
    assert_eq!(v["updated"], 1);
    assert_eq!(v["errors"], 1);

    // The valid root file should have been written.
    let root = std::fs::read_to_string(tmp.path().join("package.json")).unwrap();
    assert!(root.contains("socket-patch"), "valid file should still be updated");
}

// ---------------------------------------------------------------------------
// `setup --check` — read-only verification
// ---------------------------------------------------------------------------

#[test]
fn setup_check_configured_project_exits_zero() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pkg = tmp.path().join("package.json");
    write(&pkg, r#"{ "name": "x", "version": "1.0.0" }"#);
    // Configure it first.
    let (c, _) = run_setup(tmp.path(), &["--yes"]);
    assert_eq!(c, 0);

    let (code, stdout) = run_setup(tmp.path(), &["--check"]);
    assert_eq!(code, 0, "configured project should pass --check; stdout=\n{stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["status"], "configured");
    assert_eq!(v["needsConfiguration"], 0);
}

#[test]
fn setup_check_unconfigured_project_exits_nonzero() {
    let tmp = tempfile::tempdir().expect("tempdir");
    write(&tmp.path().join("package.json"), r#"{ "name": "x", "scripts": { "build": "tsc" } }"#);

    let (code, stdout) = run_setup(tmp.path(), &["--check"]);
    assert_eq!(code, 1, "unconfigured project must fail --check; stdout=\n{stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["status"], "needs_configuration");
    assert_eq!(v["needsConfiguration"], 1);
}

#[test]
fn setup_check_no_files_exits_zero() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (code, stdout) = run_setup(tmp.path(), &["--check"]);
    assert_eq!(code, 0, "no files should still exit 0; stdout=\n{stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["status"], "no_files");
}

#[test]
fn setup_check_does_not_modify_file() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pkg = tmp.path().join("package.json");
    let original = "{ \"name\": \"x\", \"scripts\": { \"build\": \"tsc\" } }";
    write(&pkg, original);
    run_setup(tmp.path(), &["--check"]);
    assert_eq!(
        std::fs::read_to_string(&pkg).unwrap(),
        original,
        "--check must never write"
    );
}

// ---------------------------------------------------------------------------
// `setup --remove` — revert the install hooks
// ---------------------------------------------------------------------------

#[test]
fn setup_remove_round_trips_and_preserves_other_scripts() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pkg = tmp.path().join("package.json");
    write(&pkg, r#"{ "name": "x", "scripts": { "build": "tsc" } }"#);

    // Configure, then remove.
    let (c1, _) = run_setup(tmp.path(), &["--yes"]);
    assert_eq!(c1, 0);
    let after_setup = std::fs::read_to_string(&pkg).unwrap();
    assert!(after_setup.contains("socket-patch"));

    let (code, stdout) = run_setup(tmp.path(), &["--remove", "--yes"]);
    assert_eq!(code, 0, "remove should succeed; stdout=\n{stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["status"], "success");
    assert_eq!(v["removed"], 1);

    let after = std::fs::read_to_string(&pkg).unwrap();
    assert!(!after.contains("socket-patch"), "socket-patch must be gone; got:\n{after}");
    let parsed: serde_json::Value = serde_json::from_str(&after).expect("valid JSON");
    // Full revert: lifecycle keys gone, sibling script preserved.
    assert_eq!(parsed["scripts"]["build"], "tsc");
    assert!(parsed["scripts"].get("postinstall").is_none());
    assert!(parsed["scripts"].get("dependencies").is_none());

    // And --check now reports it needs configuration again.
    let (c2, _) = run_setup(tmp.path(), &["--check"]);
    assert_eq!(c2, 1, "after remove, --check must fail again");
}

#[test]
fn setup_remove_dry_run_does_not_modify_file() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let pkg = tmp.path().join("package.json");
    write(&pkg, r#"{ "name": "x", "version": "1.0.0" }"#);
    let (c1, _) = run_setup(tmp.path(), &["--yes"]);
    assert_eq!(c1, 0);
    let configured = std::fs::read_to_string(&pkg).unwrap();

    let (code, stdout) = run_setup(tmp.path(), &["--remove", "--dry-run"]);
    assert_eq!(code, 0, "remove dry-run should succeed; stdout=\n{stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["status"], "dry_run");
    assert_eq!(v["dryRun"], true);
    assert_eq!(v["wouldRemove"], 1);

    assert_eq!(
        std::fs::read_to_string(&pkg).unwrap(),
        configured,
        "remove --dry-run must not modify package.json"
    );
}

#[test]
fn setup_remove_nothing_to_remove_exits_zero() {
    let tmp = tempfile::tempdir().expect("tempdir");
    write(&tmp.path().join("package.json"), r#"{ "name": "x", "scripts": { "build": "tsc" } }"#);

    let (code, stdout) = run_setup(tmp.path(), &["--remove", "--yes"]);
    assert_eq!(code, 0, "nothing to remove should exit 0; stdout=\n{stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["status"], "not_configured");
    assert_eq!(v["removed"], 0);
}

#[test]
fn setup_check_and_remove_are_mutually_exclusive() {
    let tmp = tempfile::tempdir().expect("tempdir");
    write(&tmp.path().join("package.json"), r#"{ "name": "x" }"#);

    // clap conflict → usage error (exit 2), not a normal run.
    let out = Command::new(binary())
        .args(["setup", "--check", "--remove"])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .output()
        .expect("run socket-patch");
    assert_ne!(out.status.code(), Some(0), "--check + --remove must be rejected");
}
