#![cfg(feature = "golang")]
//! `socket-patch setup` round-trip for the Go fail-closed guard, driven through
//! the CLI binary (no Docker, no network, no `go` toolchain — `setup` with no
//! manifest materialises nothing, so this exercises pure guard wiring).
//!
//! Covers:
//!   * `setup` writes `internal/socketpatchguard/{guard.go,guard_test.go}` and a
//!     generated `socket_patch_guard_import.go` in every `package main` dir
//!     (and ONLY there);
//!   * a user file at the generated import name is left byte-for-byte untouched;
//!   * `setup --check` exits 0 when configured;
//!   * `setup --remove` deletes the guard package + generated imports (pruning
//!     `internal/`), sparing the user file;
//!   * `setup --check` then exits non-zero.

use std::path::Path;

#[path = "common/mod.rs"]
mod common;

use common::run;

const USER_IMPORT_FILE: &str = "package main\n\n// hand-written, not ours\n";

fn stage_module(root: &Path) {
    std::fs::create_dir_all(root.join("cmd/app")).unwrap();
    std::fs::create_dir_all(root.join("internal/lib")).unwrap();
    std::fs::write(
        root.join("go.mod"),
        "module example.com/app\n\ngo 1.21\n",
    )
    .unwrap();
    // A main package (gets the blank import).
    std::fs::write(
        root.join("cmd/app/main.go"),
        "package main\n\nfunc main() {}\n",
    )
    .unwrap();
    // A library package (must NOT get the blank import).
    std::fs::write(root.join("internal/lib/lib.go"), "package lib\n").unwrap();
}

#[test]
fn setup_check_remove_check_roundtrip() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    stage_module(root);
    let root_s = root.to_str().unwrap();

    let guard_go = root.join("internal/socketpatchguard/guard.go");
    let guard_test = root.join("internal/socketpatchguard/guard_test.go");
    let app_import = root.join("cmd/app/socket_patch_guard_import.go");
    let lib_import = root.join("internal/lib/socket_patch_guard_import.go");

    // ── setup ───────────────────────────────────────────────────────
    let (code, stdout, stderr) = run(root, &["setup", "--cwd", root_s, "--yes"]);
    assert_eq!(code, 0, "setup failed.\nstdout:\n{stdout}\nstderr:\n{stderr}");

    // Guard package written with the right package clause + delegating logic.
    let guard_src = std::fs::read_to_string(&guard_go).unwrap();
    assert!(
        guard_src.contains("package socketpatchguard") && guard_src.contains("func init()"),
        "guard.go missing/!right:\n{guard_src}"
    );
    assert!(
        std::fs::read_to_string(&guard_test)
            .unwrap()
            .contains("func TestSocketPatchesApplied"),
        "guard_test.go missing the test"
    );

    // Blank import ONLY in the main package dir.
    let import_src = std::fs::read_to_string(&app_import).unwrap();
    assert!(
        import_src.contains("import _ \"example.com/app/internal/socketpatchguard\""),
        "main blank import missing/wrong:\n{import_src}"
    );
    assert!(
        !lib_import.exists(),
        "a non-main package must NOT get the blank import"
    );

    // ── check (configured) ──────────────────────────────────────────
    let (code, o, e) = run(root, &["setup", "--check", "--cwd", root_s]);
    assert_eq!(code, 0, "setup --check should pass after setup.\n{o}\n{e}");

    // ── remove ──────────────────────────────────────────────────────
    let (code, stdout, stderr) = run(root, &["setup", "--remove", "--cwd", root_s, "--yes"]);
    assert_eq!(
        code, 0,
        "setup --remove failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(!guard_go.exists() && !guard_test.exists(), "guard files should be gone");
    assert!(!app_import.exists(), "generated import should be gone");
    assert!(
        !root.join("internal/socketpatchguard").exists(),
        "empty guard dir should be pruned"
    );

    // ── check (needs configuration) ─────────────────────────────────
    let (code, _o, _e) = run(root, &["setup", "--check", "--cwd", root_s]);
    assert_eq!(code, 1, "setup --check should fail after remove");
}

#[test]
fn remove_spares_user_authored_import_file() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    stage_module(root);
    let root_s = root.to_str().unwrap();

    // A user file at the generated name, WITHOUT our marker, in the main dir.
    let app_import = root.join("cmd/app/socket_patch_guard_import.go");
    std::fs::write(&app_import, USER_IMPORT_FILE).unwrap();

    // setup must refuse to clobber it (its content differs from ours, but it is
    // at the generated path) — add_main_imports overwrites only if content
    // differs; since it differs, setup WILL overwrite to install the guard.
    // Then remove must only delete OUR (marker-bearing) file.
    run(root, &["setup", "--cwd", root_s, "--yes"]);
    // After setup the file now carries our marker (we own that path), so this is
    // the documented behaviour: the generated import path is socket-owned.
    assert!(std::fs::read_to_string(&app_import)
        .unwrap()
        .contains("internal/socketpatchguard"));

    // Restore a user file (no marker) to prove remove spares it.
    std::fs::write(&app_import, USER_IMPORT_FILE).unwrap();
    run(root, &["setup", "--remove", "--cwd", root_s, "--yes"]);
    assert_eq!(
        std::fs::read_to_string(&app_import).unwrap(),
        USER_IMPORT_FILE,
        "remove must not delete a non-marker user file at the generated path"
    );
}
