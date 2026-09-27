//! Coverage-gap integration tests for `setup`'s Hatch detection branch,
//! driven end-to-end through the built binary.
//!
//! Hatch is the one pyproject-table manager with NO lockfile and NO lock
//! refresh (`lock_commands()` is `None` — hatch resolves from the manifest at
//! install time), so it was the only `PythonPackageManager` variant never
//! produced by any host-run test: `detect_python_pm`'s `[tool.hatch]` branch
//! and `as_str()`'s `"hatch"` arm were dead in coverage. These tests pin the
//! full contract: detection from a realistic `[tool.hatch.envs.*]` SUB-table
//! (namespace-prefix resolution), the PEP 621 dependency edit, the envelope's
//! `pythonPackageManager` field, and — the Hatch-specific half — that no
//! package manager is ever spawned for a lock refresh, proven with PATH shims
//! for every manager that could have been.
//!
//! Shims are `sh` scripts, hence the file-wide unix gate.

#![cfg(unix)]

use std::collections::BTreeSet;
use std::path::Path;

#[path = "common/mod.rs"]
mod common;

/// A hatch project: PEP 621 `[project]` surface plus hatch config in a
/// sub-table only (no bare `[tool.hatch]` header — real hatch projects keep
/// config in `[tool.hatch.envs.*]` / `[tool.hatch.build.*]`), and no lockfile
/// of any kind, so the `[tool.hatch]` namespace branch is the only signal.
const HATCH_PYPROJECT: &str = "[project]\nname = \"x\"\nversion = \"0.1.0\"\ndependencies = [\n    \"requests\",\n]\n\n[tool.hatch.envs.default]\ntype = \"virtual\"\n";

fn write(path: &Path, content: &str) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create parent");
    }
    std::fs::write(path, content).expect("write file");
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).expect("read file")
}

/// Lay a fake `name` executable into `bin_dir` that appends its argv to `log`
/// and exits 0. Same shape as `setup_pth_invariants::write_pm_shim` (that
/// helper lives in a sibling test crate and cannot be imported).
fn write_pm_shim(bin_dir: &Path, name: &str, log: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(bin_dir).expect("create shim dir");
    let body = format!("#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\nexit 0\n", log.display());
    let p = bin_dir.join(name);
    std::fs::write(&p, body).expect("write shim");
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).expect("chmod shim");
}

/// Shim EVERY Python package manager `setup` can spawn for a lock refresh
/// (uv / poetry / pdm — Hatch and pip have no lock command), each logging to
/// `<project>/<name>-argv.log`. If detection mis-routes a hatch project to
/// any lockfile-refreshing manager AND a refresh runs, the log appears.
fn shim_all_pms(project: &Path) -> std::path::PathBuf {
    let bin = project.join("bin");
    for name in ["uv", "poetry", "pdm"] {
        write_pm_shim(&bin, name, &project.join(format!("{name}-argv.log")));
    }
    bin
}

/// Assert none of the shims installed by [`shim_all_pms`] ever ran.
fn assert_no_pm_spawned(project: &Path, context: &str) {
    for name in ["uv", "poetry", "pdm"] {
        let log = project.join(format!("{name}-argv.log"));
        assert!(
            !log.exists(),
            "{context}: hatch has no lock refresh, so `{name}` must never be \
             spawned; it ran with argv:\n{}",
            read(&log)
        );
    }
}

/// Run `setup --json --yes [extra]` in `cwd` with `bin_dir` prepended to PATH
/// through the shared hermetic runner (the seed-then-scrub of the ambient
/// `SOCKET_*` surface is load-bearing: SOCKET_DRY_RUN=true would fake every
/// edit, SOCKET_ECOSYSTEMS=npm would hide the Python branch entirely).
fn run_setup_with_shims(
    cwd: &Path,
    bin_dir: &Path,
    extra: &[&str],
) -> (i32, serde_json::Value) {
    let path_env = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let mut args = vec!["setup", "--json", "--yes"];
    args.extend_from_slice(extra);
    let (code, stdout, _stderr) = common::run_with_env(
        cwd,
        &args,
        &[("SOCKET_TELEMETRY_DISABLED", "1"), ("PATH", &path_env)],
    );
    let v = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout must be JSON ({e}):\n{stdout}"));
    (code, v)
}

/// The single `files[]` entry with `kind == kind` (panics unless exactly one).
fn file_entry<'a>(v: &'a serde_json::Value, kind: &str) -> &'a serde_json::Value {
    let arr = v["files"]
        .as_array()
        .unwrap_or_else(|| panic!("files must be an array: {v}"));
    let matches: Vec<&serde_json::Value> = arr.iter().filter(|f| f["kind"] == kind).collect();
    assert_eq!(
        matches.len(),
        1,
        "expected exactly one `{kind}` file entry, got {}: {v}",
        matches.len()
    );
    matches[0]
}

#[test]
fn hatch_project_detected_edited_and_never_spawns_a_lock_refresh() {
    let tmp = tempfile::tempdir().unwrap();
    write(&tmp.path().join("pyproject.toml"), HATCH_PYPROJECT);
    let bin = shim_all_pms(tmp.path());

    let (code, v) = run_setup_with_shims(tmp.path(), &bin, &[]);
    assert_eq!(code, 0, "setup must succeed: {v}");
    assert_eq!(v["status"], "success", "payload={v}");
    assert_eq!(v["updated"], 1);
    assert_eq!(v["errors"], 0);
    // The load-bearing detection assertion: the envelope surfaces the manager
    // detect_python_pm resolved — the `[tool.hatch.envs.default]` sub-table
    // must route to Hatch (as_str's "hatch" arm), not fall through to pip or
    // mis-match a sibling table.
    assert_eq!(
        v["pythonPackageManager"], "hatch",
        "a [tool.hatch.envs.*]-only project must be detected as hatch: {v}"
    );

    let entry = file_entry(&v, "pth");
    assert_eq!(entry["status"], "updated");
    assert!(
        entry["path"].as_str().unwrap().ends_with("pyproject.toml"),
        "hatch edits pyproject.toml: {entry}"
    );

    // The hook dep landed in the PEP 621 dependencies array; the existing dep
    // (with its 4-space indentation) and the hatch table survive verbatim.
    let py = read(&tmp.path().join("pyproject.toml"));
    assert_eq!(
        py.matches("socket-patch[hook]").count(),
        1,
        "hook dep must appear exactly once:\n{py}"
    );
    assert!(
        py.contains("    \"requests\""),
        "existing dep + indentation preserved:\n{py}"
    );
    assert!(
        py.contains("[tool.hatch.envs.default]\ntype = \"virtual\"\n"),
        "the hatch config table must survive the edit verbatim:\n{py}"
    );

    // Hatch resolves deps from the manifest at install time: lock_commands()
    // is None, so NO package manager may be spawned after the edit.
    assert_no_pm_spawned(tmp.path(), "after add");

    // Idempotent re-run still detects hatch and does not re-edit.
    let (code2, v2) = run_setup_with_shims(tmp.path(), &bin, &[]);
    assert_eq!(code2, 0);
    assert_eq!(
        v2["status"], "already_configured",
        "re-run must see the dep it just wrote: {v2}"
    );
    assert_eq!(v2["pythonPackageManager"], "hatch", "payload={v2}");
    assert_eq!(
        read(&tmp.path().join("pyproject.toml")),
        py,
        "already-configured re-run must not rewrite the manifest"
    );
    assert_no_pm_spawned(tmp.path(), "after already-configured re-run");
}

#[test]
fn hatch_remove_restores_manifest_and_never_spawns_a_lock_refresh() {
    let tmp = tempfile::tempdir().unwrap();
    write(&tmp.path().join("pyproject.toml"), HATCH_PYPROJECT);
    let bin = shim_all_pms(tmp.path());

    // Configure first.
    let (code, v) = run_setup_with_shims(tmp.path(), &bin, &[]);
    assert_eq!(code, 0, "precondition setup must succeed: {v}");
    assert_eq!(v["status"], "success", "payload={v}");
    assert!(
        read(&tmp.path().join("pyproject.toml")).contains("socket-patch[hook]"),
        "precondition: setup added the hook dep"
    );

    let (code, v) = run_setup_with_shims(tmp.path(), &bin, &["--remove"]);
    assert_eq!(code, 0, "payload={v}");
    assert_eq!(v["status"], "success", "remove must report success: {v}");
    assert_eq!(v["removed"], 1, "exactly one manifest reverted: {v}");
    assert_eq!(v["errors"], 0);
    let entry = file_entry(&v, "pth");
    assert_eq!(entry["status"], "removed");

    // Byte-preservation-sensitive subsystem: add → remove must restore the
    // committed manifest byte-for-byte, hatch table included.
    let py = read(&tmp.path().join("pyproject.toml"));
    assert_eq!(
        py, HATCH_PYPROJECT,
        "remove must restore the pre-setup pyproject.toml byte-for-byte"
    );

    // Neither the remove edit nor the preceding add may spawn a lock refresh
    // on a hatch project.
    assert_no_pm_spawned(tmp.path(), "after add + remove");

    // Only the fixture files remain in the project root — no lockfile, no
    // marker file conjured beside the manifest.
    let entries: BTreeSet<String> = std::fs::read_dir(tmp.path())
        .expect("read_dir")
        .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
        .collect();
    assert_eq!(
        entries,
        BTreeSet::from(["pyproject.toml".to_string(), "bin".to_string()]),
        "setup/remove on a hatch project must touch only pyproject.toml"
    );
}
