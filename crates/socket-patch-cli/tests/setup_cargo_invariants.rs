//! Integration tests for `setup`'s cargo branch (the project-local
//! `[patch.crates-io]` redirect guard). Like the npm/python suites these run
//! entirely on disk — `setup` adds the `socket-patch-guard` dependency to each
//! workspace member's `Cargo.toml` and writes `[env] SOCKET_PATCH_ROOT` to the
//! workspace-root `.cargo/config.toml`. No network, no `cargo` invocation.
//!
//! Gated on the `cargo` feature (enabled by default): without it `setup` has no
//! cargo branch and these projects would report `no_files`.
#![cfg(feature = "cargo")]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

/// Every `SOCKET_*` var that steers `setup`; scrubbed from each child so
/// behaviour is decided by flags + on-disk fixtures alone (mirrors
/// setup_invariants.rs). The cargo backend additionally reads
/// `SOCKET_PATCH_ROOT` / `SOCKET_PATCH_BIN`, so those matter here especially.
const SOCKET_ENV_VARS: &[&str] = &[
    "SOCKET_CWD",
    "SOCKET_MANIFEST_PATH",
    "SOCKET_ECOSYSTEMS",
    "SOCKET_OFFLINE",
    "SOCKET_JSON",
    "SOCKET_DRY_RUN",
    "SOCKET_YES",
    "SOCKET_API_TOKEN",
    "SOCKET_DEBUG",
    "SOCKET_TELEMETRY_DISABLED",
    "SOCKET_PATCH_ROOT",
    "SOCKET_PATCH_BIN",
    "SOCKET_PATCH_DEBUG",
];

/// Run `setup --json` with a scrubbed environment and telemetry disabled.
/// `home` is pointed at a sentinel dir so we can assert nothing is written
/// outside the repo.
fn run_setup_in(cwd: &Path, home: &Path, extra: &[&str]) -> (i32, serde_json::Value) {
    let mut args = vec!["setup", "--json"];
    args.extend_from_slice(extra);
    let mut cmd = Command::new(binary());
    cmd.args(&args).current_dir(cwd);
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

const SINGLE_CRATE: &str =
    "[package]\nname = \"demo\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nserde = \"1\"\n";

// ---------------------------------------------------------------------------
// Property 5 — in-repo and committable. The cargo branch writes the guard dep
// into the in-repo Cargo.toml and `[env] SOCKET_PATCH_ROOT` into the in-repo
// `.cargo/config.toml`; it must not touch `$HOME` (notably never `~/.cargo`).
// (CLI_CONTRACT.md → "Setup command contract", property 5.)
// ---------------------------------------------------------------------------

#[test]
fn setup_cargo_writes_only_inside_repo() {
    let proj = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    write(&proj.path().join("Cargo.toml"), SINGLE_CRATE);
    assert!(files_under(home.path()).is_empty(), "sentinel HOME must start empty");

    let (code, v) = run_setup_in(proj.path(), home.path(), &["--yes"]);
    assert_eq!(code, 0, "cargo setup should succeed: {v}");
    assert_eq!(v["status"], "success");

    // Nothing written outside the repo (in particular, no ~/.cargo/config.toml).
    assert!(
        files_under(home.path()).is_empty(),
        "cargo setup must not write outside --cwd; HOME gained: {:?}",
        files_under(home.path())
    );
    // The guard dep + the workspace-root [env] both landed inside the repo.
    assert!(
        read(&proj.path().join("Cargo.toml")).contains("socket-patch-guard"),
        "Cargo.toml must gain the guard dependency"
    );
    let config = read(&proj.path().join(".cargo/config.toml"));
    assert!(
        config.contains("SOCKET_PATCH_ROOT"),
        ".cargo/config.toml must declare [env] SOCKET_PATCH_ROOT; got:\n{config}"
    );
    // All new files are under the repo tree.
    let repo_files = files_under(proj.path());
    assert!(repo_files.contains("Cargo.toml"));
    assert!(repo_files.contains(".cargo/config.toml"));
}

// ---------------------------------------------------------------------------
// Property 8 — graceful remove restores the per-member Cargo.toml byte-for-byte
// (the guard dependency is the only edit). NB: the `.cargo/config.toml` that
// setup creates is NOT fully cleaned up on remove today — that residue is
// guarded separately as a RED pin in setup_contract_gaps.rs.
// (CLI_CONTRACT.md → "Setup command contract", property 8.)
// ---------------------------------------------------------------------------

#[test]
fn setup_cargo_remove_round_trips_cargo_toml() {
    let proj = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let manifest = proj.path().join("Cargo.toml");
    write(&manifest, SINGLE_CRATE);

    let (c1, _) = run_setup_in(proj.path(), home.path(), &["--yes"]);
    assert_eq!(c1, 0);
    assert!(
        read(&manifest).contains("socket-patch-guard"),
        "precondition: setup added the guard dep"
    );

    let (code, v) = run_setup_in(proj.path(), home.path(), &["--remove", "--yes"]);
    assert_eq!(code, 0, "remove should succeed: {v}");
    assert_eq!(v["status"], "success");

    // The member manifest is restored to its exact pre-setup bytes.
    assert_eq!(
        read(&manifest),
        SINGLE_CRATE,
        "remove must restore Cargo.toml byte-for-byte"
    );
    // And the [env] key is gone, so the project no longer registers as set up.
    let (cc, cv) = run_setup_in(proj.path(), home.path(), &["--check"]);
    assert_eq!(cc, 1, "after remove, --check must fail again: {cv}");
    assert_eq!(cv["status"], "needs_configuration");
}

// ---------------------------------------------------------------------------
// Property 9 (base case) — nested workspaces. Every cargo workspace member gets
// the guard dependency and a single workspace-root [env] is written.
// (CLI_CONTRACT.md → "Setup command contract", property 9.)
// ---------------------------------------------------------------------------

#[test]
fn setup_cargo_configures_workspace_members() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    write(
        &tmp.path().join("Cargo.toml"),
        "[workspace]\nmembers = [\"crates/*\"]\nresolver = \"2\"\n",
    );
    let member = "[package]\nname = \"NAME\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\n";
    write(
        &tmp.path().join("crates/a/Cargo.toml"),
        &member.replace("NAME", "a"),
    );
    write(
        &tmp.path().join("crates/b/Cargo.toml"),
        &member.replace("NAME", "b"),
    );

    let (code, v) = run_setup_in(tmp.path(), home.path(), &["--yes"]);
    assert_eq!(code, 0, "workspace setup should succeed: {v}");
    assert_eq!(v["status"], "success");
    // Two members + the one workspace-root [env] entry.
    assert_eq!(
        v["updated"], 3,
        "both members + the root [env] must be configured: {v}"
    );

    for m in ["crates/a/Cargo.toml", "crates/b/Cargo.toml"] {
        assert!(
            read(&tmp.path().join(m)).contains("socket-patch-guard"),
            "workspace member {m} must gain the guard dependency"
        );
    }
    // Exactly one [env] config, at the workspace root.
    let config = read(&tmp.path().join(".cargo/config.toml"));
    assert!(config.contains("SOCKET_PATCH_ROOT"), "root [env] must be written");

    // The cargo_env entry must be reported exactly once.
    let env_entries = v["files"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["kind"] == "cargo_env")
        .count();
    assert_eq!(env_entries, 1, "exactly one cargo_env entry: {v}");
}
