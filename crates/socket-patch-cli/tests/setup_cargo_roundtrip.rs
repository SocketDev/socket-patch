#![cfg(feature = "cargo")]
//! `socket-patch setup` round-trip for the cargo guard, driven through the CLI
//! binary (no Docker, no network, no real `cargo`).
//!
//! Covers, across a 2-member workspace:
//!   * `setup` adds `socket-patch-guard` to every member's `[dependencies]` and
//!     writes `[env] SOCKET_PATCH_ROOT` into `.cargo/config.toml`;
//!   * a member's pre-existing user `build.rs` is left **byte-for-byte
//!     unchanged** (the regression the dedicated guard crate buys us);
//!   * `setup --check` exits 0 when configured;
//!   * `setup --remove` reverts the dep + `[env]`;
//!   * `setup --check` then exits non-zero.

use std::path::Path;

#[path = "common/mod.rs"]
mod common;

use common::run;

const USER_BUILD_RS: &str = "fn main() {\n    println!(\"cargo:rerun-if-changed=build.rs\");\n}\n";

fn stage_workspace(root: &Path) {
    std::fs::create_dir_all(root.join("crates/a/src")).unwrap();
    std::fs::create_dir_all(root.join("crates/b/src")).unwrap();
    std::fs::write(
        root.join("Cargo.toml"),
        "[workspace]\nmembers = [\"crates/*\"]\nresolver = \"2\"\n",
    )
    .unwrap();
    std::fs::write(
        root.join("crates/a/Cargo.toml"),
        "[package]\nname = \"a\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\n",
    )
    .unwrap();
    std::fs::write(
        root.join("crates/b/Cargo.toml"),
        "[package]\nname = \"b\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    std::fs::write(root.join("crates/a/src/main.rs"), "fn main() {}\n").unwrap();
    std::fs::write(root.join("crates/b/src/lib.rs"), "\n").unwrap();
    // A user-authored build.rs that setup must NOT touch.
    std::fs::write(root.join("crates/a/build.rs"), USER_BUILD_RS).unwrap();
}

#[test]
fn setup_check_remove_check_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    stage_workspace(root);
    let root_s = root.to_str().unwrap();

    // ── setup ───────────────────────────────────────────────────────
    let (code, stdout, stderr) = run(root, &["setup", "--cwd", root_s, "--yes"]);
    assert_eq!(
        code, 0,
        "setup failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );

    let a_toml = std::fs::read_to_string(root.join("crates/a/Cargo.toml")).unwrap();
    let b_toml = std::fs::read_to_string(root.join("crates/b/Cargo.toml")).unwrap();
    assert!(
        a_toml.contains("socket-patch-guard"),
        "guard dep missing from a:\n{a_toml}"
    );
    assert!(
        b_toml.contains("socket-patch-guard"),
        "guard dep missing from b:\n{b_toml}"
    );

    let config = std::fs::read_to_string(root.join(".cargo/config.toml")).unwrap();
    assert!(
        config.contains("[env]") && config.contains("SOCKET_PATCH_ROOT"),
        "[env] SOCKET_PATCH_ROOT missing:\n{config}"
    );

    // The user's build.rs is untouched, byte-for-byte.
    assert_eq!(
        std::fs::read_to_string(root.join("crates/a/build.rs")).unwrap(),
        USER_BUILD_RS,
        "setup must never modify a user's build.rs"
    );

    // ── check (configured) ──────────────────────────────────────────
    let (code, _o, _e) = run(root, &["setup", "--check", "--cwd", root_s]);
    assert_eq!(code, 0, "setup --check should pass after setup");

    // ── remove ──────────────────────────────────────────────────────
    let (code, stdout, stderr) = run(root, &["setup", "--remove", "--cwd", root_s, "--yes"]);
    assert_eq!(
        code, 0,
        "setup --remove failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        !std::fs::read_to_string(root.join("crates/a/Cargo.toml"))
            .unwrap()
            .contains("socket-patch-guard"),
        "guard dep should be removed from a"
    );
    assert!(
        !std::fs::read_to_string(root.join("crates/b/Cargo.toml"))
            .unwrap()
            .contains("socket-patch-guard"),
        "guard dep should be removed from b"
    );
    let config = std::fs::read_to_string(root.join(".cargo/config.toml")).unwrap_or_default();
    assert!(
        !config.contains("SOCKET_PATCH_ROOT"),
        "[env] root should be removed:\n{config}"
    );

    // build.rs still untouched after remove.
    assert_eq!(
        std::fs::read_to_string(root.join("crates/a/build.rs")).unwrap(),
        USER_BUILD_RS,
    );

    // ── check (needs configuration) ─────────────────────────────────
    let (code, _o, _e) = run(root, &["setup", "--check", "--cwd", root_s]);
    assert_eq!(code, 1, "setup --check should fail after remove");
}
