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

/// `dispatch_fixup` cargo path with a `patched` entry that points
/// at a file that doesn't exist on disk exercises the
/// `sha256_file` error arm inside `update_entries`
/// (cargo.rs:131-133). In the apply-CLI flow this is race-only
/// (apply atomically wrote the file before dispatch_fixup is
/// called), so direct invocation is the only way to drive it
/// from outside the engine.
///
/// The setup: a valid `.cargo-checksum.json` on disk + a `patched`
/// entry naming a file that doesn't exist. cargo::fixup parses the
/// checksum, then `update_entries` walks `patched`, calls
/// `sha256_file(on_disk)`, and the open fails with NotFound. The
/// `.map_err(|source| SidecarError::Io { ... })?` wraps it; the
/// dispatcher returns `Err(SidecarError::Io)`.
#[cfg(feature = "cargo")]
#[tokio::test]
async fn dispatch_fixup_cargo_sha256_file_failure_arm() {
    use socket_patch_core::patch::sidecars::SidecarError;

    let tmp = tempfile::tempdir().unwrap();
    let pkg = tmp.path();
    // Valid checksum so cargo::fixup gets past the parse step.
    std::fs::write(
        pkg.join(".cargo-checksum.json"),
        r#"{"files":{"a.txt":"deadbeef"},"package":"00"}"#,
    )
    .unwrap();
    // Note: we DO NOT create "missing-on-disk.txt" — that's
    // exactly the condition that fires the sha256_file Err arm.

    let result = dispatch_fixup(
        "pkg:cargo/anything@1.0.0",
        pkg,
        &["package/missing-on-disk.txt".to_string()],
        &HashMap::new(),
    )
    .await;

    let err = result.expect_err("missing file in patched list must surface as Err");
    match err {
        SidecarError::Io { path, .. } => {
            assert!(
                path.contains("missing-on-disk.txt"),
                "Io error path must reference the missing file; got {path:?}"
            );
        }
        other => panic!("expected SidecarError::Io, got {other:?}"),
    }
}

/// `dispatch_fixup` against a non-existent `pkg_path` exercises
/// the nuget side: `remove_file(.nupkg.metadata)` returns NotFound
/// (already covered by the success-path tests), then
/// `has_signed_marker` runs and its `read_dir(pkg_path)` ALSO
/// fails — non-existent dir hits the `Err(_) => return false`
/// fallback at nuget.rs:86. The fixup then returns `Ok(None)`.
///
/// Together with the no-metadata + signed-marker tests this nails
/// down every branch in `has_signed_marker`'s setup.
#[cfg(feature = "nuget")]
#[tokio::test]
async fn dispatch_fixup_nuget_with_nonexistent_pkg_path() {
    let tmp = tempfile::tempdir().unwrap();
    let absent = tmp.path().join("does-not-exist");

    let out = dispatch_fixup(
        "pkg:nuget/Anything@1.0.0",
        &absent,
        &["package/file.txt".to_string()],
        &HashMap::new(),
    )
    .await
    .unwrap();
    // No metadata removed (NotFound), no signed marker found
    // (read_dir failed → false), advisory absent → Ok(None).
    assert!(
        out.is_none(),
        "non-existent pkg_path must yield no sidecar record"
    );
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

/// `break_hardlink_if_needed` failure-cleanup arm (cow.rs:116-120):
/// when `rename(stage, path)` inside `write_via_stage_rename`
/// fails, the function must `remove_file(stage)` before
/// propagating the error so we don't leak a `.socket-cow-…`
/// turd in the package directory.
///
/// macOS-only: we use BSD-style `chflags uchg <path>` to set the
/// user-immutable flag on the cow target. The kernel then refuses
/// `rename(stage, target)` with EPERM even though the user owns
/// the file — the cow code's lstat/read/remove flow upstream
/// works fine (reads succeed on immutable files, hardlink creation
/// doesn't touch them), but the final stage→target rename hits the
/// kernel's immutable-bit refusal. After the test, we clear the
/// flag so tempdir cleanup can recurse.
///
/// Linux's analogue is `chattr +i`, but that requires CAP_LINUX_IMMUTABLE
/// (root in most setups), so the Linux variant lives outside the
/// integration suite. On macOS dev/CI uid=0 also bypasses uchg, so
/// skip there too.
#[cfg(target_os = "macos")]
#[tokio::test]
async fn cow_rename_failure_runs_stage_cleanup() {
    use std::os::unix::fs::MetadataExt;
    use std::process::Command;

    if Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim() == "0")
        .unwrap_or(false)
    {
        eprintln!("SKIP: root bypasses chflags uchg restrictions");
        return;
    }

    let tmp = tempfile::tempdir().unwrap();
    let target = tmp.path().join("file.txt");
    std::fs::write(&target, b"original").unwrap();

    // Create a hardlink so cow takes the nlink>1 branch (which
    // calls write_via_stage_rename without first remove_file'ing
    // the target — exactly the rename-collision-into-target
    // shape we want).
    let link = tmp.path().join("hardlink.txt");
    std::fs::hard_link(&target, &link).unwrap();
    assert_eq!(
        std::fs::metadata(&target).unwrap().nlink(),
        2,
        "test setup: target must have nlink=2 to drive cow's hardlink branch"
    );

    // Make `target` immutable so the final rename(stage, target)
    // fails. `chflags` is the only way to set BSD file flags from
    // the shell — there's no portable Rust API.
    let chflags_status = Command::new("chflags")
        .arg("uchg")
        .arg(&target)
        .status()
        .expect("chflags binary must exist on macOS");
    assert!(
        chflags_status.success(),
        "chflags uchg must succeed for a file we own"
    );

    let cow_result = break_hardlink_if_needed(&target).await;

    // Restore the flag so tempdir cleanup can unlink the file.
    let _ = Command::new("chflags").arg("nouchg").arg(&target).status();

    // The cow attempt itself returned the rename error — that's the
    // contract: when stage commit fails, the caller learns of the
    // failure rather than silently succeeding on a half-state.
    let err = cow_result.expect_err("immutable target must cause rename failure");
    assert_ne!(
        err.kind(),
        std::io::ErrorKind::NotFound,
        "expected EPERM-class error, got {err:?}"
    );

    // The cleanup arm (cow.rs:117-119) ran: no `.socket-cow-…`
    // file should be left behind in the package directory.
    let leftover_stages: Vec<_> = std::fs::read_dir(tmp.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with(".socket-cow-")
        })
        .collect();
    assert!(
        leftover_stages.is_empty(),
        "stage cleanup must remove all .socket-cow-* turds; found {leftover_stages:?}"
    );
}
