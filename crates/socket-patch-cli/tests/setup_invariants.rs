//! Integration tests for `setup` against handcrafted `package.json`
//! fixtures. `setup` operates entirely on disk (lockfile detection +
//! package.json mutation) so every path is runnable without network.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

/// Recursively collect every regular-file path under `dir`, relative to `dir`.
/// Used to prove `setup` writes nothing outside the repo (property 5) and to
/// snapshot a "clone" (property 6).
fn files_under(dir: &Path) -> BTreeSet<String> {
    fn walk(base: &Path, dir: &Path, out: &mut BTreeSet<String>) {
        if let Ok(rd) = std::fs::read_dir(dir) {
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    walk(base, &p, out);
                } else {
                    out.insert(p.strip_prefix(base).unwrap().to_string_lossy().to_string());
                }
            }
        }
    }
    let mut out = BTreeSet::new();
    walk(dir, dir, &mut out);
    out
}

/// Copy every file under `src` into `dst` (recreating directories). Simulates a
/// fresh `git clone` of the committed tree onto another host.
fn copy_tree(src: &Path, dst: &Path) {
    for rel in files_under(src) {
        let from = src.join(&rel);
        let to = dst.join(&rel);
        if let Some(parent) = to.parent() {
            std::fs::create_dir_all(parent).expect("create parent");
        }
        std::fs::copy(&from, &to).expect("copy file");
    }
}

/// Every `SOCKET_*` env var that `setup` (via `GlobalArgs`) honours as a
/// fallback for a CLI flag. These tests drive `setup` purely through flags and
/// on-disk fixtures, so ANY of these leaking in from the developer's shell or
/// CI would let an assertion pass for the wrong reason — e.g. an ambient
/// `SOCKET_DRY_RUN=true` would keep a regressed `--check`/`--yes` path from
/// writing (satisfying the "must not modify" checks vacuously), and an ambient
/// `SOCKET_ECOSYSTEMS`/`SOCKET_YES`/`SOCKET_CWD` would silently change which
/// manifest is touched and how the script is rendered. Scrub the whole set
/// from every child so behaviour is decided by flags alone. Mirrors the
/// hardened helpers in remove_network.rs / repair_invariants.rs.
const SOCKET_ENV_VARS: &[&str] = &[
    "SOCKET_CWD",
    "SOCKET_MANIFEST_PATH",
    "SOCKET_API_URL",
    "SOCKET_API_TOKEN",
    "SOCKET_ORG_SLUG",
    "SOCKET_PROXY_URL",
    "SOCKET_ECOSYSTEMS",
    "SOCKET_DOWNLOAD_MODE",
    "SOCKET_DOWNLOAD_ONLY",
    "SOCKET_OFFLINE",
    "SOCKET_GLOBAL",
    "SOCKET_GLOBAL_PREFIX",
    "SOCKET_JSON",
    "SOCKET_VERBOSE",
    "SOCKET_SILENT",
    "SOCKET_DRY_RUN",
    "SOCKET_YES",
    "SOCKET_FORCE",
    "SOCKET_LOCK_TIMEOUT",
    "SOCKET_BREAK_LOCK",
    "SOCKET_DEBUG",
    "SOCKET_TELEMETRY_DISABLED",
    // Legacy / cargo-backend knobs that also steer setup behaviour.
    "SOCKET_PATCH_ROOT",
    "SOCKET_PATCH_BIN",
    "SOCKET_PATCH_DEBUG",
    "SOCKET_PATCH_PROXY_URL",
    "SOCKET_PATCH_TELEMETRY_DISABLED",
];

/// Build a `setup` invocation with the full `SOCKET_*` environment scrubbed.
fn setup_command(cwd: &Path, args: &[&str]) -> Command {
    let mut cmd = Command::new(binary());
    cmd.args(args).current_dir(cwd);
    for var in SOCKET_ENV_VARS {
        cmd.env_remove(var);
    }
    cmd
}

fn run_setup(cwd: &Path, extra: &[&str]) -> (i32, String) {
    let mut args = vec!["setup", "--json"];
    args.extend_from_slice(extra);
    let out = setup_command(cwd, &args)
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
    let out = setup_command(tmp.path(), &["setup", "--yes"])
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
    // The `no_files` envelope must keep the documented `--check` shape
    // (CLI_CONTRACT "Setup command contract") — the summary counts are
    // always-present, zero-valued fields, NOT dropped. A consumer reading
    // `.needsConfiguration` must see 0, not null.
    assert_eq!(v["configured"], 0, "missing/`null` configured; stdout=\n{stdout}");
    assert_eq!(
        v["needsConfiguration"], 0,
        "missing/`null` needsConfiguration; stdout=\n{stdout}"
    );
    assert_eq!(v["errors"], 0, "missing/`null` errors; stdout=\n{stdout}");
    assert!(v["files"].as_array().is_some_and(|a| a.is_empty()));
}

#[test]
fn setup_remove_no_files_exits_zero_with_full_envelope() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (code, stdout) = run_setup(tmp.path(), &["--remove", "--yes"]);
    assert_eq!(code, 0, "no files should still exit 0; stdout=\n{stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["status"], "no_files");
    // The `no_files` envelope must keep the documented `--remove` shape
    // (removed/notConfigured/errors), present and zero — not dropped. This
    // mirrors the plain-`setup` `no_files` envelope, which already carries its
    // own counts; the `--remove`/`--check` variants must not diverge.
    assert_eq!(v["removed"], 0, "missing/`null` removed; stdout=\n{stdout}");
    assert_eq!(
        v["notConfigured"], 0,
        "missing/`null` notConfigured; stdout=\n{stdout}"
    );
    assert_eq!(v["errors"], 0, "missing/`null` errors; stdout=\n{stdout}");
    assert!(v["files"].as_array().is_some_and(|a| a.is_empty()));
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

// Regression: in human (non-JSON) mode `setup --remove` ends with
// "Nothing removed; N item(s) could not be processed (see errors above)."
// when a manifest fails to parse, but `print_remove_preview` printed NO error
// section at all — so "(see errors above)" pointed at nothing and the user
// never saw *why* the file could not be processed. The preview must surface the
// per-file error so the message is truthful. (The companion setup-path check is
// `setup_malformed_does_not_claim_already_configured_in_human_mode`; this guards
// the remove path, whose preview previously had no error branch whatsoever.)
#[test]
fn remove_human_mode_surfaces_unprocessable_file_error() {
    let tmp = tempfile::tempdir().expect("tempdir");
    write(&tmp.path().join("package.json"), "not valid json!!!");

    let out = setup_command(tmp.path(), &["setup", "--remove", "--yes"])
        .output()
        .expect("run socket-patch");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(1), "a malformed manifest must exit 1; stdout=\n{stdout}");

    // The "(see errors above)" trailer is only honest if the error was actually
    // printed above it.
    assert!(
        stdout.contains("could not be processed (see errors above)"),
        "remove must report the unprocessable file; stdout=\n{stdout}"
    );
    assert!(
        stdout.contains("Errors:"),
        "the preview must include an Errors: section so '(see errors above)' is truthful; stdout=\n{stdout}"
    );
    // The concrete parse error (not just a header) must be shown — a bare
    // "Errors:" header with no detail would still be a regression.
    assert!(
        stdout.contains("Invalid package.json"),
        "the actual per-file error detail must be shown above the trailer; stdout=\n{stdout}"
    );
    // The Errors: section must precede the trailer it references.
    let errors_at = stdout.find("Errors:").expect("Errors header present");
    let trailer_at = stdout.find("see errors above").expect("trailer present");
    assert!(
        errors_at < trailer_at,
        "the Errors: section must appear ABOVE the '(see errors above)' trailer; stdout=\n{stdout}"
    );
}

#[test]
fn setup_check_and_remove_are_mutually_exclusive() {
    let tmp = tempfile::tempdir().expect("tempdir");
    write(&tmp.path().join("package.json"), r#"{ "name": "x" }"#);

    // clap conflict → usage error (exit 2), not a normal run.
    let out = setup_command(tmp.path(), &["setup", "--check", "--remove"])
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

// ---------------------------------------------------------------------------
// Property 5 — in-repo and committable. `setup` writes only inside the working
// tree, never to `$HOME` or any global location.
// (CLI_CONTRACT.md → "Setup command contract", property 5.)
// ---------------------------------------------------------------------------

#[test]
fn setup_writes_only_inside_repo() {
    let proj = tempfile::tempdir().expect("proj");
    let home = tempfile::tempdir().expect("home");
    let pkg = proj.path().join("package.json");
    write(&pkg, r#"{ "name": "x", "version": "1.0.0" }"#);

    // Sentinel HOME starts empty; setup must leave it empty.
    assert!(files_under(home.path()).is_empty(), "sentinel HOME must start empty");

    let mut cmd = Command::new(binary());
    cmd.args(["setup", "--json", "--yes"]).current_dir(proj.path());
    for var in SOCKET_ENV_VARS {
        cmd.env_remove(var);
    }
    // Redirect HOME at the sentinel and disable telemetry so the only writes we
    // could observe are setup's own manifest edits.
    cmd.env("HOME", home.path());
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1");
    let out = cmd.output().expect("run socket-patch");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "setup should succeed; stderr=\n{stderr}");

    // Nothing was written outside the repo.
    assert!(
        files_under(home.path()).is_empty(),
        "setup must not write outside --cwd; HOME gained: {:?}",
        files_under(home.path())
    );
    // The only file in the project is the package.json it edited — no marker or
    // auxiliary files conjured beside it.
    assert_eq!(
        files_under(proj.path()),
        BTreeSet::from(["package.json".to_string()]),
        "setup must touch only in-repo manifests"
    );
    // Not vacuous: it really did wire the hook into that in-repo file.
    assert!(
        std::fs::read_to_string(&pkg).unwrap().contains("socket-patch"),
        "setup must have edited the in-repo package.json"
    );
}

// ---------------------------------------------------------------------------
// Property 6 — clone-portable. Setup state is committed files only, so a fresh
// checkout on another host inherits it; `--check` passes on the clone with no
// re-run and no writes. (CLI_CONTRACT.md → "Setup command contract", property 6.)
// ---------------------------------------------------------------------------

#[test]
fn setup_state_is_clone_portable() {
    let a = tempfile::tempdir().expect("a");
    write(&a.path().join("package.json"), r#"{ "name": "x", "version": "1.0.0" }"#);
    let (c, _) = run_setup(a.path(), &["--yes"]);
    assert_eq!(c, 0, "initial setup must succeed");

    // "Clone": copy the committed tree into a brand-new directory on a notional
    // other host. (node_modules isn't committed, so only manifests travel.)
    let b = tempfile::tempdir().expect("b");
    copy_tree(a.path(), b.path());

    let before = std::fs::read_to_string(b.path().join("package.json")).unwrap();
    let (code, stdout) = run_setup(b.path(), &["--check"]);
    assert_eq!(code, 0, "the clone must already be configured; stdout=\n{stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["status"], "configured");
    assert_eq!(v["needsConfiguration"], 0);
    // `--check` on the clone is read-only.
    assert_eq!(
        std::fs::read_to_string(b.path().join("package.json")).unwrap(),
        before,
        "--check must not modify the clone"
    );
}

// ---------------------------------------------------------------------------
// Property 9 (base case) — nested workspaces. For a non-pnpm npm workspace, the
// root AND every member package.json are configured. (The pnpm root-only carve-
// out is covered by `setup_pnpm_monorepo_only_updates_root`.)
// (CLI_CONTRACT.md → "Setup command contract", property 9.)
// ---------------------------------------------------------------------------

#[test]
fn setup_configures_npm_workspace_members() {
    let tmp = tempfile::tempdir().expect("tempdir");
    write(
        &tmp.path().join("package.json"),
        r#"{ "name": "root", "workspaces": ["packages/*"] }"#,
    );
    write(
        &tmp.path().join("packages/a/package.json"),
        r#"{ "name": "a", "version": "1.0.0" }"#,
    );
    write(
        &tmp.path().join("packages/b/package.json"),
        r#"{ "name": "b", "version": "1.0.0" }"#,
    );

    let (code, stdout) = run_setup(tmp.path(), &["--yes"]);
    assert_eq!(code, 0, "workspace setup should succeed; stdout=\n{stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["status"], "success");
    assert_eq!(
        v["updated"], 3,
        "root + both members must each be configured; stdout=\n{stdout}"
    );
    for member in [
        "package.json",
        "packages/a/package.json",
        "packages/b/package.json",
    ] {
        let content = std::fs::read_to_string(tmp.path().join(member)).unwrap();
        assert!(
            content.contains("socket-patch"),
            "workspace member {member} must gain the hook; got:\n{content}"
        );
    }
}

// ---------------------------------------------------------------------------
// Gem (Bundler) — wires a committed plugin into the Gemfile (property 3).
// The full check/remove round-trip + plugins.rb content lives in
// setup_matrix_gem.rs; these pin the dry-run no-op and the mixed-ecosystem
// dispatch alongside npm.
// ---------------------------------------------------------------------------

const GEMFILE_FIXTURE: &str = "source 'https://rubygems.org'\ngem 'colorize', '1.1.0'\n";

#[test]
fn setup_gem_dry_run_does_not_modify_gemfile() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let gemfile = tmp.path().join("Gemfile");
    write(&gemfile, GEMFILE_FIXTURE);

    let (code, stdout) = run_setup(tmp.path(), &["--dry-run"]);
    assert_eq!(code, 0, "dry-run should succeed; stdout=\n{stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["status"], "dry_run");
    assert_eq!(v["dryRun"], true);

    // The Gemfile must be byte-identical and no plugin dir created.
    assert_eq!(
        std::fs::read_to_string(&gemfile).unwrap(),
        GEMFILE_FIXTURE,
        "dry-run must not modify the Gemfile"
    );
    assert!(
        !tmp.path().join(".socket/bundler-plugin").exists(),
        "dry-run must not generate the plugin dir"
    );
}

#[test]
fn setup_configures_gem_alongside_npm() {
    let tmp = tempfile::tempdir().expect("tempdir");
    write(&tmp.path().join("Gemfile"), GEMFILE_FIXTURE);
    write(
        &tmp.path().join("package.json"),
        r#"{ "name": "mixed", "version": "1.0.0" }
"#,
    );

    let (code, stdout) = run_setup(tmp.path(), &["--yes"]);
    assert_eq!(code, 0, "mixed setup should succeed; stdout=\n{stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["status"], "success");

    // The envelope must carry both an npm package_json entry and the gem
    // entries (gemfile + gem_plugin) — proof gem dispatch runs next to npm.
    let kinds: BTreeSet<&str> = v["files"]
        .as_array()
        .expect("files[]")
        .iter()
        .filter_map(|f| f["kind"].as_str())
        .collect();
    assert!(kinds.contains("package_json"), "npm entry missing; kinds={kinds:?}");
    assert!(kinds.contains("gemfile"), "gem Gemfile entry missing; kinds={kinds:?}");
    assert!(kinds.contains("gem_plugin"), "gem plugin entry missing; kinds={kinds:?}");

    // On disk: both manifests are wired.
    assert!(std::fs::read_to_string(tmp.path().join("Gemfile"))
        .unwrap()
        .contains("plugin 'socket-patch'"));
    assert!(std::fs::read_to_string(tmp.path().join("package.json"))
        .unwrap()
        .contains("socket-patch"));
}
