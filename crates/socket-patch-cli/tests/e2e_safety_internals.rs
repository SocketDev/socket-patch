//! Integration coverage for the handful of `cow` + `sidecars`
//! defensive paths that the apply-CLI path cannot reach.
//!
//! These guards (empty patched list, unknown ecosystem, lstat
//! permission-denied, etc.) live in the public API surface of
//! `socket-patch-core` and gate the engine against caller bugs.
//! Apply's own upstream checks prevent the conditions from ever
//! firing in production, which means the apply-CLI integration
//! tests can't drive them — but `cargo llvm-cov --test` over the
//! pub APIs can.
//!
//! Treating these as integration coverage (rather than `#[cfg(test)]`
//! lib unit tests inside the source files) keeps the lift/burden
//! visible in the test binary list and lets coverage tooling see the
//! same code path one consumer would.
//!
//! No network. No toolchain. Unix-gated for the chmod-based test;
//! the rest are portable.

use std::collections::HashMap;

use socket_patch_core::patch::cow::{break_hardlink_if_needed, CowAction};
use socket_patch_core::patch::sidecars::dispatch_fixup;

// ── dispatch_fixup guards ─────────────────────────────────────────────

/// Empty `patched` list short-circuits with `Ok(None)` — guards
/// against callers that forget to check `files_patched.is_empty()`
/// (apply.rs does, but the guard belongs on the engine side too).
/// Covers `sidecars/mod.rs:110`.
#[tokio::test]
async fn dispatch_fixup_empty_patched_returns_none() {
    let tmp = tempfile::tempdir().unwrap();
    let out = dispatch_fixup(
        "pkg:cargo/anything@1.0.0",
        tmp.path(),
        &[],
        &HashMap::new(),
    )
    .await
    .unwrap();
    assert!(out.is_none(), "empty patched must short-circuit to None");
}

/// Unknown PURL ecosystem (no recognized scheme prefix) also
/// short-circuits with `Ok(None)`. Covers `sidecars/mod.rs:115`.
#[tokio::test]
async fn dispatch_fixup_unknown_ecosystem_returns_none() {
    let tmp = tempfile::tempdir().unwrap();
    let out = dispatch_fixup(
        "pkg:totally-not-an-ecosystem/x@1",
        tmp.path(),
        &["x".to_string()],
        &HashMap::new(),
    )
    .await
    .unwrap();
    assert!(out.is_none(), "unknown ecosystem must short-circuit to None");
}

// ── cow.rs guards ─────────────────────────────────────────────────────

/// `break_hardlink_if_needed` on a path that doesn't exist returns
/// `CowAction::NoFile` (the explicit-NotFound arm). Belt-and-braces
/// case to keep the integration coverage of the lstat arms
/// next to its sibling tests.
#[tokio::test]
async fn cow_missing_path_yields_no_file() {
    let tmp = tempfile::tempdir().unwrap();
    let action =
        break_hardlink_if_needed(&tmp.path().join("does-not-exist.txt"))
            .await
            .expect("lstat NotFound is the explicit early-return arm");
    assert!(matches!(action, CowAction::NoFile));
}

/// `break_hardlink_if_needed` on a path inside a `chmod 0000`
/// parent directory fails the initial `symlink_metadata` call
/// with `EACCES` (search permission denied) — not `NotFound` —
/// hitting the generic `Err(e) => return Err(e)` arm of cow.rs.
/// Covers `cow.rs:59`.
///
/// Skipped under uid 0 because the root user bypasses directory
/// search permission checks, which would silently turn this into
/// a NoFile (NotFound) result and false-pass the test.
#[cfg(unix)]
#[tokio::test]
async fn cow_lstat_permission_denied_propagates_io_error() {
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;
    if Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim() == "0")
        .unwrap_or(false)
    {
        eprintln!("SKIP: root bypasses dir-search permission checks");
        return;
    }

    let tmp = tempfile::tempdir().unwrap();
    let locked = tmp.path().join("locked");
    std::fs::create_dir(&locked).unwrap();
    let target = locked.join("file.txt");
    std::fs::write(&target, b"content").unwrap();

    // Drop search (x) permission so lstat on `target` fails with
    // EACCES rather than NotFound. Keep read for the directory
    // itself just to be defensive — Unix specifies that EACCES on
    // path resolution comes from missing `x` on a parent.
    let mut perms = std::fs::metadata(&locked).unwrap().permissions();
    perms.set_mode(0o000);
    std::fs::set_permissions(&locked, perms).unwrap();

    let result = break_hardlink_if_needed(&target).await;

    // Restore so tempdir cleanup can recurse.
    let mut restore = std::fs::metadata(&locked).unwrap().permissions();
    restore.set_mode(0o755);
    let _ = std::fs::set_permissions(&locked, restore);

    let err = result.expect_err("expected I/O error from locked-dir lstat");
    // Different OSes pick slightly different errno: Linux returns
    // PermissionDenied, macOS may too. The contract is "not
    // NotFound" — if it were, cow would have returned NoFile.
    assert_ne!(
        err.kind(),
        std::io::ErrorKind::NotFound,
        "expected permission-denied class error; got {err:?}"
    );
}

/// `break_hardlink_if_needed` failure-cleanup arm: when the rename
/// step inside `write_via_stage_rename` fails, the function must
/// remove the just-written stage file before propagating the error.
/// Covers `cow.rs:116, 119, 120`.
///
/// To trigger rename failure cleanly: pre-create a directory at the
/// target path. `rename(stage_file, existing_directory)` fails on
/// every Unix because POSIX forbids renaming a regular file onto a
/// non-empty directory (and even an empty one in most kernels).
///
/// We bypass the `if nlink > 1` branch of cow by going through the
/// symlink branch instead: stage a symlink, then `chmod 0000` the
/// target directory below the symlink so the read-through works
/// but the eventual rename target is "the symlink path, which is
/// now a directory" — actually let's take a simpler route. We
/// stage a symlink that resolves to a regular file (so cow takes
/// the symlink branch), then replace the symlink path itself with
/// a directory just before the rename hits. Since cow does
/// `tokio::fs::remove_file(path)` before staging, the directory
/// would be removed by remove_file (which fails on a directory!).
///
/// Simpler: stage a hardlinked file, then between the nlink check
/// and the rename, swap `path` to be a directory. We can't
/// intervene mid-flight in async land, so this test is currently
/// unreachable without a behavior toggle.
///
/// Skip with a `#[ignore]` until we expose a test seam — see
/// follow-up in the commit message.
#[cfg(unix)]
#[tokio::test]
#[ignore = "rename-failure cleanup arm needs a test seam; lib unit tests already cover the write_via_stage_rename function in isolation via cow's tests module"]
async fn cow_rename_failure_runs_stage_cleanup() {
    // Placeholder for the seam-based test. Documented here so the
    // reason the lines remain uncovered from integration is visible
    // alongside the other cow tests.
}
