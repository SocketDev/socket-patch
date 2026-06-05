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
    // No lockfile present → npm, which invokes the patch via `npx` and applies
    // the npm ecosystem. Lock the actual command so a no-op/garbage script
    // can't pass on a bare substring.
    assert!(
        postinstall.contains("npx @socketsecurity/socket-patch apply"),
        "npm postinstall must invoke the patch via npx; got: {postinstall}"
    );
    assert!(
        postinstall.contains("--ecosystems npm"),
        "npm postinstall must scope to the npm ecosystem; got: {postinstall}"
    );
    // setup also wires the `dependencies` lifecycle script (covers `npm install
    // <pkg>` which skips postinstall); it must be present and equal.
    let deps = parsed["scripts"]["dependencies"]
        .as_str()
        .expect("dependencies lifecycle script must be set");
    assert_eq!(
        deps, postinstall,
        "the dependencies hook must mirror the postinstall hook; got: {deps}"
    );
    // The original `name`/`version` must be preserved, not clobbered.
    assert_eq!(parsed["name"], "test-proj");
    assert_eq!(parsed["version"], "1.0.0");
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

    let (code, stdout) = run_setup(tmp.path(), &["--yes"]);
    assert_eq!(code, 0, "setup should succeed; stdout=\n{stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["packageManager"], "npm");
    assert_eq!(v["status"], "success");

    // The written script must use npm's `npx`, never `pnpm dlx` — otherwise
    // "detected npm" in the envelope wouldn't match what got written.
    let after = std::fs::read_to_string(tmp.path().join("package.json")).unwrap();
    assert!(
        after.contains("npx @socketsecurity/socket-patch"),
        "npm projects must use `npx`; got: {after}"
    );
    assert!(
        !after.contains("pnpm dlx"),
        "npm projects must NOT use `pnpm dlx`; got: {after}"
    );
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

    // The envelope must list exactly the root entry, not the workspace members.
    let files = v["files"].as_array().expect("files array");
    assert_eq!(
        files.len(),
        1,
        "only the root package.json should appear in files[]; got: {files:?}"
    );
    let touched = files[0]["path"].as_str().unwrap();
    assert!(
        !touched.contains("packages/a") && !touched.contains("packages/b"),
        "the touched file must be the root, not a workspace member; got: {touched}"
    );

    // Both workspace packages must NOT have been modified.
    for member in ["packages/a/package.json", "packages/b/package.json"] {
        let content = std::fs::read_to_string(tmp.path().join(member)).unwrap();
        assert!(
            !content.contains("socket-patch"),
            "workspace package.json {member} must not be touched; got: {content}"
        );
    }
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

    let (code, stdout) = run_setup(tmp.path(), &["--yes"]);
    assert_eq!(code, 0, "setup should succeed; stdout=\n{stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    let files = v["files"].as_array().expect("files array");
    assert_eq!(files.len(), 1);
    let entry = &files[0];
    // Lock the actual values, not just the types — an entry of
    // {"path": "", "status": "error"} would satisfy `is_string()`.
    assert_eq!(entry["kind"], "package_json", "entry: {entry}");
    assert_eq!(
        entry["status"], "updated",
        "the single updated file must report status=updated; entry: {entry}"
    );
    let path = entry["path"].as_str().expect("path string");
    assert!(
        path.ends_with("package.json"),
        "path must point at the package.json we wrote; got: {path}"
    );
    assert!(
        entry["error"].is_null(),
        "a successfully updated file must carry no error; entry: {entry}"
    );
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
    // And it must positively surface that the file could not be processed —
    // otherwise a silent (but still exit-1) run would slip past the negative
    // check above.
    assert!(
        stdout.contains("could not be processed"),
        "human mode must report the unprocessable file; stdout=\n{stdout}"
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
    assert_eq!(v["errors"], 0);
    // The package.json must be counted as configured, not silently absent.
    assert_eq!(v["configured"], 1, "the lone manifest must be counted; stdout=\n{stdout}");
    let files = v["files"].as_array().expect("files array");
    assert_eq!(files.len(), 1);
    assert_eq!(files[0]["status"], "configured");
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
    // The check must actually run and report this unconfigured manifest (exit
    // 1) — discarding the outcome would let a no-op binary pass the
    // "didn't write" assertion vacuously.
    let (code, stdout) = run_setup(tmp.path(), &["--check"]);
    assert_eq!(code, 1, "unconfigured --check must exit 1; stdout=\n{stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["status"], "needs_configuration");
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
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    // Must be a clap *usage* error (exit 2), not a normal run that happened to
    // fail (exit 1) — `assert_ne!(.., 0)` would accept either and mask a
    // dropped `conflicts_with` constraint.
    assert_eq!(
        out.status.code(),
        Some(2),
        "--check + --remove must be a clap usage error (exit 2); stdout=\n{stdout}\nstderr=\n{stderr}"
    );
    // clap reports the conflict on stderr and must not have run setup.
    assert!(
        stderr.contains("--check") && stderr.contains("--remove"),
        "usage error must name the conflicting flags; stderr=\n{stderr}"
    );
    assert!(
        stdout.trim().is_empty(),
        "rejected invocation must not emit a normal result envelope; stdout=\n{stdout}"
    );
}
