#![cfg(unix)]
//! End-to-end for the Go `replace`-redirect backend, driven through the CLI
//! binary. No `go` toolchain needed: `apply`/`--check` only read a pristine
//! extracted module-cache dir and write project-local copies + a `go.mod`
//! `replace` — they never invoke `go`. A fake `GOMODCACHE` supplies the
//! pristine source so the whole flow runs offline and hermetically.
//!
//! Covers: apply materialises the copy + `replace` (cache left pristine);
//! `apply --check` is in sync; and each drift kind (`MissingReplace`,
//! `StaleCopy`, `ResolvedVersionMismatch`) is detected and self-healed.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

#[path = "common/mod.rs"]
mod common;

use common::{binary, git_sha256, git_sha256_file, write_blob, write_minimal_manifest, PatchEntry};

const MODULE: &str = "github.com/foo/bar";
const VERSION: &str = "v1.4.2";
const PURL: &str = "pkg:golang/github.com/foo/bar@v1.4.2";
const PRISTINE: &[u8] = b"package bar\n\nfunc Hello() string { return \"hi\" }\n";
const PATCHED: &[u8] = b"package bar\n\nfunc Hello() string { return \"PATCHED\" }\n";

const COPY_REL: &str = ".socket/go-patches/github.com/foo/bar@v1.4.2";
const REPLACE_LINE: &str =
    "replace github.com/foo/bar v1.4.2 => ./.socket/go-patches/github.com/foo/bar@v1.4.2";

/// Stage a fake extracted module-cache dir + a consumer go.mod + the synthetic
/// patch manifest/blob. Returns (gomodcache, cache_dir).
fn stage(root: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
    // Fake GOMODCACHE with the pristine extracted module.
    let gomodcache = root.join("modcache");
    let cache_dir = gomodcache.join(format!("{MODULE}@{VERSION}"));
    std::fs::create_dir_all(&cache_dir).unwrap();
    std::fs::write(cache_dir.join("bar.go"), PRISTINE).unwrap();
    std::fs::write(
        cache_dir.join("go.mod"),
        "module github.com/foo/bar\n\ngo 1.21\n",
    )
    .unwrap();

    // Consumer module.
    std::fs::write(
        root.join("go.mod"),
        format!("module example.com/app\n\ngo 1.21\n\nrequire {MODULE} {VERSION}\n"),
    )
    .unwrap();

    // Synthetic manifest + after-hash blob.
    let socket = root.join(".socket");
    write_minimal_manifest(
        &socket,
        PURL,
        "go-uuid-0001",
        &[PatchEntry {
            file_name: "bar.go",
            before_hash: &git_sha256(PRISTINE),
            after_hash: &git_sha256(PATCHED),
        }],
    );
    write_blob(&socket, &git_sha256(PATCHED), PATCHED);

    (gomodcache, cache_dir)
}

/// Run the CLI binary with the environment pinned hard (mirrors the
/// seed-then-scrub runner in `e2e_golang.rs`). Each variable below was
/// verified to break this suite when inherited from the ambient shell, so it
/// is seeded with a hostile value and then scrubbed — `env_remove` clears the
/// seed too, so the child never sees it, but if a scrub line is ever dropped
/// the seed (rather than a developer's ambient shell, which this suite can't
/// rely on) turns the tests red immediately. `SOCKET_GLOBAL` /
/// `SOCKET_GLOBAL_PREFIX` take the redirect backend out of local scope
/// (apply patches the fake module cache IN PLACE and `--check` exits 0
/// having checked nothing), `SOCKET_DRY_RUN` makes every apply a no-op, and
/// `SOCKET_MANIFEST_PATH` points apply/check at a manifest that isn't there.
/// `--offline`, `--ecosystems`, and `--cwd` are passed as flags, which
/// outrank env, so their env twins can't bite; `GOMODCACHE` pins the crawl
/// root (so `GOPATH` is never consulted).
fn run_cli(root: &Path, gomodcache: &Path, args: &[&str]) -> (i32, String, String) {
    let out = std::process::Command::new(binary())
        .args(args)
        .current_dir(root)
        .env("GOMODCACHE", gomodcache)
        .env("SOCKET_GLOBAL", "true")
        .env("SOCKET_GLOBAL_PREFIX", "/nonexistent")
        .env("SOCKET_DRY_RUN", "true")
        .env("SOCKET_MANIFEST_PATH", "/nonexistent/manifest.json")
        .env_remove("SOCKET_GLOBAL")
        .env_remove("SOCKET_GLOBAL_PREFIX")
        .env_remove("SOCKET_DRY_RUN")
        .env_remove("SOCKET_MANIFEST_PATH")
        .env_remove("SOCKET_API_TOKEN")
        .env_remove("SOCKET_CLI_API_TOKEN")
        .output()
        .expect("failed to execute socket-patch binary");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

fn apply(root: &Path, gomodcache: &Path) -> (i32, String, String) {
    run_cli(
        root,
        gomodcache,
        &[
            "apply",
            "--offline",
            "--ecosystems",
            "golang",
            "--cwd",
            root.to_str().unwrap(),
        ],
    )
}

fn check(root: &Path, gomodcache: &Path) -> i32 {
    run_cli(
        root,
        gomodcache,
        &[
            "apply",
            "--check",
            "--offline",
            "--ecosystems",
            "golang",
            "--cwd",
            root.to_str().unwrap(),
        ],
    )
    .0
}

#[test]
fn apply_materializes_redirect_and_check_passes() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (gomodcache, cache_dir) = stage(root);

    let (code, stdout, stderr) = apply(root, &gomodcache);
    assert_eq!(
        code, 0,
        "apply failed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );

    // go.mod gained the socket-owned replace.
    let gomod = std::fs::read_to_string(root.join("go.mod")).unwrap();
    assert!(
        gomod.contains(REPLACE_LINE),
        "replace directive missing:\n{gomod}"
    );

    // The copy holds the patched bytes (== afterHash); the module cache is pristine.
    let copy_file = root.join(COPY_REL).join("bar.go");
    assert_eq!(std::fs::read(&copy_file).unwrap(), PATCHED);
    assert_eq!(git_sha256_file(&copy_file), git_sha256(PATCHED));
    assert_eq!(
        std::fs::read(cache_dir.join("bar.go")).unwrap(),
        PRISTINE,
        "the module cache must be left pristine"
    );
    // The copy carries a go.mod (valid replace target).
    assert!(root.join(COPY_REL).join("go.mod").exists());

    // In sync.
    assert_eq!(
        check(root, &gomodcache),
        0,
        "apply --check should be in sync"
    );

    // Idempotent re-apply: still in sync, replace unchanged.
    assert_eq!(apply(root, &gomodcache).0, 0);
    assert_eq!(
        std::fs::read_to_string(root.join("go.mod"))
            .unwrap()
            .matches(REPLACE_LINE)
            .count(),
        1,
        "re-apply must not duplicate the replace"
    );
}

#[test]
fn check_detects_missing_replace_and_heals() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (gomodcache, _cache) = stage(root);
    apply(root, &gomodcache);
    assert_eq!(check(root, &gomodcache), 0);

    // Simulate a `go mod tidy`/`go mod vendor` that wiped our replace.
    let gomod = std::fs::read_to_string(root.join("go.mod")).unwrap();
    let stripped: String = gomod
        .lines()
        .filter(|l| !l.contains("go-patches"))
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(root.join("go.mod"), format!("{stripped}\n")).unwrap();

    assert_eq!(check(root, &gomodcache), 1, "missing replace must be drift");

    // Heal.
    assert_eq!(apply(root, &gomodcache).0, 0);
    assert_eq!(check(root, &gomodcache), 0, "re-apply heals the replace");
    assert!(std::fs::read_to_string(root.join("go.mod"))
        .unwrap()
        .contains(REPLACE_LINE));
}

#[test]
fn check_detects_stale_copy_and_heals() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (gomodcache, _cache) = stage(root);
    apply(root, &gomodcache);

    // Corrupt the committed copy.
    let copy_file = root.join(COPY_REL).join("bar.go");
    let _ = std::fs::set_permissions(&copy_file, std::fs::Permissions::from_mode(0o644));
    std::fs::write(&copy_file, b"package bar\n// tampered\n").unwrap();

    assert_eq!(check(root, &gomodcache), 1, "stale copy must be drift");

    // Heal: re-apply restores the exact patched bytes.
    assert_eq!(apply(root, &gomodcache).0, 0);
    assert_eq!(std::fs::read(&copy_file).unwrap(), PATCHED);
    assert_eq!(check(root, &gomodcache), 0);
}

#[test]
fn check_detects_resolved_version_mismatch() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (gomodcache, _cache) = stage(root);
    apply(root, &gomodcache);
    assert_eq!(check(root, &gomodcache), 0);

    // Bump the required version: the v1.4.2 replace is now unused, so the build
    // would silently link the UNPATCHED v1.5.0 — must be flagged.
    std::fs::write(
        root.join("go.mod"),
        format!("module example.com/app\n\ngo 1.21\n\nrequire {MODULE} v1.5.0\n\n{REPLACE_LINE}\n"),
    )
    .unwrap();
    assert_eq!(
        check(root, &gomodcache),
        1,
        "a resolved-version mismatch must be detected as drift"
    );

    // apply must NOT silently paper over it: a version bump means the manifest
    // is stale (it patches v1.4.2, the build wants v1.5.0). apply re-affirms the
    // v1.4.2 redirect but cannot make the build use it, so check STAYS red until
    // a human re-scans. (Fail-closed stays closed — never a false "in sync".)
    assert_eq!(
        apply(root, &gomodcache).0,
        0,
        "apply itself succeeds (re-affirms v1.4.2)"
    );
    assert_eq!(
        check(root, &gomodcache),
        1,
        "apply must not heal a resolved-version mismatch — it needs a re-scan"
    );
}

#[test]
fn coexists_with_user_replace_at_different_version() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (gomodcache, _cache) = stage(root);

    // Pre-existing user replace for the SAME module at a DIFFERENT version.
    let gomod = std::fs::read_to_string(root.join("go.mod")).unwrap();
    std::fs::write(
        root.join("go.mod"),
        format!("{gomod}\nreplace {MODULE} v1.0.0 => ../my-fork\n"),
    )
    .unwrap();

    let (code, so, se) = apply(root, &gomodcache);
    assert_eq!(
        code, 0,
        "apply must coexist with a user replace.\n{so}\n{se}"
    );

    // Both replaces survive: the user's v1.0.0 fork AND our v1.4.2 redirect.
    let gomod = std::fs::read_to_string(root.join("go.mod")).unwrap();
    assert!(
        gomod.contains(&format!("replace {MODULE} v1.0.0 => ../my-fork")),
        "user replace clobbered:\n{gomod}"
    );
    assert!(
        gomod.contains(REPLACE_LINE),
        "socket replace missing:\n{gomod}"
    );
    assert_eq!(
        check(root, &gomodcache),
        0,
        "check passes with both replaces present"
    );
}
