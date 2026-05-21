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
