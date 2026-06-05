//! Integration tests for `setup` on heterogeneous / multi-workspace monorepos:
//! multiple ecosystems in one repo (polyglot) and nested-workspace recursion.
//!
//! GREEN pins lock behavior that holds today. GAP pins are `#[ignore]`d — they
//! encode the *intended* behavior for cases that are not implemented yet
//! (nested-workspace recursion), kept off the blocking CI suite and runnable via
//! `-- --ignored`. See CLI_CONTRACT.md "Setup command contract" (property 9 +
//! "Monorepo / multi-project discovery model").
//!
//! Gated on the `cargo` feature (enabled by default): the polyglot all-three
//! test needs the cargo branch.
#![cfg(feature = "cargo")]

use std::path::{Path, PathBuf};
use std::process::Command;

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

/// `SOCKET_*` vars scrubbed from every child so behaviour is decided by flags +
/// fixtures alone (mirrors setup_invariants.rs / setup_cargo_invariants.rs).
const SOCKET_ENV_VARS: &[&str] = &[
    "SOCKET_CWD",
    "SOCKET_MANIFEST_PATH",
    "SOCKET_API_TOKEN",
    "SOCKET_ECOSYSTEMS",
    "SOCKET_OFFLINE",
    "SOCKET_JSON",
    "SOCKET_DRY_RUN",
    "SOCKET_YES",
    "SOCKET_DEBUG",
    "SOCKET_TELEMETRY_DISABLED",
    "SOCKET_PATCH_ROOT",
    "SOCKET_PATCH_BIN",
    "SOCKET_PATCH_DEBUG",
];

/// Run the binary with a scrubbed environment, telemetry off, and HOME pointed
/// at `home` (so we'd notice any out-of-repo write). Returns (exit code, JSON).
fn run(cwd: &Path, home: &Path, args: &[&str]) -> (i32, serde_json::Value) {
    let mut cmd = Command::new(binary());
    cmd.args(args).current_dir(cwd);
    for var in SOCKET_ENV_VARS {
        cmd.env_remove(var);
    }
    cmd.env("HOME", home);
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1");
    let out = cmd.output().expect("run socket-patch");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let v = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout must be JSON ({e}):\n{stdout}"));
    (out.status.code().unwrap_or(-1), v)
}

fn write(path: &Path, content: &str) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create parent");
    }
    std::fs::write(path, content).expect("write file");
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).expect("read file")
}

/// The set of `files[*].kind` values in a setup/check/remove envelope.
fn kinds(v: &serde_json::Value) -> Vec<String> {
    let mut ks: Vec<String> = v["files"]
        .as_array()
        .expect("files array")
        .iter()
        .map(|f| f["kind"].as_str().unwrap_or("").to_string())
        .collect();
    ks.sort();
    ks
}

/// Stage a polyglot repo: npm + python + cargo manifests in one directory.
fn write_polyglot(root: &Path) {
    write(&root.join("package.json"), r#"{ "name": "app", "version": "1.0.0" }"#);
    write(&root.join("requirements.txt"), "requests==2.31.0\n");
    write(
        &root.join("Cargo.toml"),
        "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\n",
    );
}

// ===========================================================================
// GREEN — multiple ecosystems in one repo (property: each ecosystem is detected
// and configured independently). CLI_CONTRACT 'Setup command contract'.
// ===========================================================================

#[test]
fn setup_configures_npm_python_cargo_together() {
    let proj = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    write_polyglot(proj.path());

    let (code, v) = run(proj.path(), home.path(), &["setup", "--json", "--yes"]);
    assert_eq!(code, 0, "polyglot setup should succeed: {v}");
    assert_eq!(v["status"], "success");
    // npm (package.json) + python (.pth dep) + cargo (guard dep) + the one
    // workspace-root [env] entry = four configured files.
    assert_eq!(v["updated"], 4, "all three ecosystems must be configured: {v}");
    assert_eq!(v["errors"], 0);
    assert_eq!(
        kinds(&v),
        vec!["cargo", "cargo_env", "package_json", "pth"],
        "the envelope must carry one entry per ecosystem surface: {v}"
    );

    // Each manifest gained its real hook on disk (not just an envelope claim).
    assert!(
        read(&proj.path().join("package.json")).contains("socket-patch"),
        "package.json must gain the npm hook"
    );
    assert_eq!(
        read(&proj.path().join("requirements.txt")),
        "requests==2.31.0\nsocket-patch[hook]\n",
        "requirements.txt must gain the python hook dep"
    );
    assert!(
        read(&proj.path().join("Cargo.toml")).contains("socket-patch-guard"),
        "Cargo.toml must gain the guard dependency"
    );
    assert!(
        read(&proj.path().join(".cargo/config.toml")).contains("SOCKET_PATCH_ROOT"),
        ".cargo/config.toml must declare [env] SOCKET_PATCH_ROOT"
    );
}

#[test]
fn setup_check_and_remove_handle_all_three_ecosystems() {
    let proj = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    write_polyglot(proj.path());
    let pristine_req = read(&proj.path().join("requirements.txt"));
    let pristine_cargo = read(&proj.path().join("Cargo.toml"));

    let (c0, _) = run(proj.path(), home.path(), &["setup", "--json", "--yes"]);
    assert_eq!(c0, 0);

    // --check: all three ecosystems report configured.
    let (cc, cv) = run(proj.path(), home.path(), &["setup", "--check", "--json"]);
    assert_eq!(cc, 0, "configured polyglot repo must pass --check: {cv}");
    assert_eq!(cv["status"], "configured");
    assert_eq!(cv["configured"], 4, "all four surfaces configured: {cv}");
    assert_eq!(
        kinds(&cv),
        vec!["cargo", "cargo_env", "package_json", "pth"]
    );

    // --remove: the three editable manifests round-trip byte-for-byte. (The
    // empty .cargo/config.toml residue is a known gap, guarded separately in
    // setup_contract_gaps.rs.)
    let (rc, rv) = run(proj.path(), home.path(), &["setup", "--remove", "--json", "--yes"]);
    assert_eq!(rc, 0, "remove should succeed: {rv}");
    assert_eq!(rv["status"], "success");
    // package.json: setup pretty-prints JSON, so the round-trip is semantic (not
    // byte-exact) — the hooks are gone and the user's keys are preserved.
    let pkg = read(&proj.path().join("package.json"));
    assert!(!pkg.contains("socket-patch"), "npm hook removed from package.json:\n{pkg}");
    let parsed: serde_json::Value = serde_json::from_str(&pkg).expect("valid package.json");
    assert_eq!(parsed["name"], "app");
    assert_eq!(parsed["version"], "1.0.0");
    assert!(parsed["scripts"].get("postinstall").is_none(), "postinstall key dropped");
    // requirements.txt + Cargo.toml restore byte-for-byte (line/toml preserving).
    assert_eq!(read(&proj.path().join("requirements.txt")), pristine_req, "requirements.txt restored");
    assert_eq!(read(&proj.path().join("Cargo.toml")), pristine_cargo, "Cargo.toml restored");
}

// ===========================================================================
// GAP — nested npm workspace recursion (property 9). A workspace member that is
// itself a workspace root should have ITS members configured too.
//
// SHIPPED: `find_workspace_packages` now recurses into a member that declares
// its own `workspaces`, so `packages/inner/sub/leaf` is configured. This pin is
// now an active (non-ignored) regression guard.
// ===========================================================================

#[test]
fn setup_recurses_into_nested_npm_workspace() {
    let proj = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    // Root workspace whose member `packages/inner` is ITSELF a workspace root.
    write(
        &proj.path().join("package.json"),
        r#"{ "name": "root", "workspaces": ["packages/*"] }"#,
    );
    write(
        &proj.path().join("packages/inner/package.json"),
        r#"{ "name": "inner", "workspaces": ["sub/*"] }"#,
    );
    write(
        &proj.path().join("packages/inner/sub/leaf/package.json"),
        r#"{ "name": "leaf", "version": "1.0.0" }"#,
    );

    let (code, v) = run(proj.path(), home.path(), &["setup", "--json", "--yes"]);
    assert_eq!(code, 0, "setup should succeed: {v}");
    // The intended behavior: the nested-workspace leaf is also configured.
    assert!(
        read(&proj.path().join("packages/inner/sub/leaf/package.json")).contains("socket-patch"),
        "nested-workspace member `leaf` must be configured (recursion into member workspaces)"
    );
}

// ===========================================================================
// GAP — deeply-nested cargo workspace members via the recursive `**` glob.
// Cargo itself accepts `members = ["crates/**"]` (and forbids true nested
// workspaces), but `discover_cargo_project` only expands a single-level
// `crates/*`, so a member at `crates/group/leaf` is never configured.
//
// SHIPPED: `expand_member` now expands the recursive `crates/**` glob
// (`glob_dir_recursive`), so a member at `crates/group/leaf` is configured.
// This pin is now an active (non-ignored) regression guard.
// ===========================================================================

#[test]
fn setup_expands_recursive_cargo_member_glob() {
    let proj = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    write(
        &proj.path().join("Cargo.toml"),
        "[workspace]\nmembers = [\"crates/**\"]\nresolver = \"2\"\n",
    );
    // A member nested two directories deep — matched by `crates/**` but not by
    // the single-level `crates/*` the discoverer supports today.
    write(
        &proj.path().join("crates/group/leaf/Cargo.toml"),
        "[package]\nname = \"leaf\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\n",
    );

    let (code, v) = run(proj.path(), home.path(), &["setup", "--json", "--yes"]);
    assert_eq!(code, 0, "setup should succeed: {v}");
    assert!(
        read(&proj.path().join("crates/group/leaf/Cargo.toml")).contains("socket-patch-guard"),
        "deeply-nested cargo member (via `crates/**`) must gain the guard dependency"
    );
}
