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
///
/// The PURL MUST name an ecosystem whose non-short-circuited path
/// returns `Some` — otherwise the test is vacuous. A `pkg:cargo/...`
/// PURL against an empty dir would return `None` from `cargo::fixup`
/// too (no `.cargo-checksum.json`), so deleting the `patched.is_empty()`
/// early-return would NOT change the result and the regression would
/// stay green. We use `pkg:pypi/...` because the pypi arm
/// *unconditionally* emits an advisory (`Some`) whenever it is reached
/// — and it is compiled in every feature configuration. So observing
/// `None` here can ONLY mean the empty-patched short-circuit fired
/// before PURL classification. (This mirrors the in-tree lib test
/// `empty_patched_short_circuits_before_advisory`, which the original
/// integration test failed to copy.)
#[tokio::test]
async fn dispatch_fixup_empty_patched_returns_none() {
    let tmp = tempfile::tempdir().unwrap();
    let out = dispatch_fixup(
        "pkg:pypi/requests@2.28.0",
        tmp.path(),
        &[],
        &HashMap::new(),
    )
    .await
    .unwrap();
    assert!(
        out.is_none(),
        "empty patched must short-circuit to None *before* the pypi advisory arm; \
         a Some here means the patched.is_empty() guard was bypassed"
    );
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
        SidecarError::Io { path, source } => {
            assert!(
                path.contains("missing-on-disk.txt"),
                "Io error path must reference the missing file; got {path:?}"
            );
            // The premise of this test is that the file is *absent* and
            // the `read()` in `sha256_file` fails with NotFound. Assert
            // that exact errno so a regression that surfaced some other
            // Io failure (EACCES, EISDIR, a wrapped/mislabeled error)
            // here — i.e. NOT the missing-file arm we claim to cover —
            // cannot masquerade as this test passing.
            assert_eq!(
                source.kind(),
                std::io::ErrorKind::NotFound,
                "sha256_file on an absent path must surface NotFound, got {source:?}"
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
    // EACCES from search-permission denial maps to PermissionDenied on
    // every Unix (and decisively NOT NotFound — if it were, cow would
    // have returned NoFile and the .expect_err above would have fired).
    // Asserting the exact kind closes the loophole where a mis-mapped
    // errno (Other/InvalidInput/wrapped) would slip past a bare
    // `!= NotFound` check.
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::PermissionDenied,
        "lstat on a search-denied parent must surface as PermissionDenied; got {err:?}"
    );
}

/// Symlink branch read-fails-fast (cow.rs:66): when the symlink
/// target doesn't exist, the read-through propagates NotFound
/// rather than entering the remove/rewrite dance. Covers the
/// symlink-branch `?` propagation on the read step.
#[cfg(unix)]
#[tokio::test]
async fn cow_symlink_to_missing_target_propagates_read_error() {
    let tmp = tempfile::tempdir().unwrap();
    let link = tmp.path().join("dangling");
    let absent = tmp.path().join("does-not-exist");
    std::os::unix::fs::symlink(&absent, &link).unwrap();

    let err = break_hardlink_if_needed(&link)
        .await
        .expect_err("read through dangling symlink must propagate the error");
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    // The dangling link itself must still exist — read-fail-fast must
    // never enter the remove/rewrite dance that could destroy it.
    let meta = std::fs::symlink_metadata(&link)
        .expect("dangling symlink must survive a read-fail-fast");
    assert!(
        meta.file_type().is_symlink(),
        "read-through failure must leave the symlink untouched, got {meta:?}"
    );
}

/// Symlink branch rename-fails arm: when the symlink itself carries
/// the `uchg` (user-immutable) flag, `read(path)` follows the link
/// and succeeds and the stage file is created fine, but the atomic
/// `rename(stage, path)` over the immutable symlink is refused with
/// EPERM. The error propagates, the stage is cleaned up, and — the
/// key invariant — the original symlink is left intact (CoW never
/// destructively unlinks before the replacement is committed).
///
/// macOS-only: BSD `chflags -h` is the only userspace tool that
/// can set flags on a symlink without dereferencing. Linux's
/// `chattr +i` only works on regular files and needs root.
#[cfg(target_os = "macos")]
#[tokio::test]
async fn cow_symlink_unremovable_propagates_remove_error() {
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
    let target = tmp.path().join("real-file.txt");
    std::fs::write(&target, b"content").unwrap();
    let link = tmp.path().join("immutable-link");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    // -h applies the flag to the symlink itself, not its target.
    // Without it, chflags follows the link and sets uchg on the
    // regular file — wrong test.
    let status = Command::new("chflags")
        .arg("-h")
        .arg("uchg")
        .arg(&link)
        .status()
        .expect("chflags");
    assert!(status.success());

    let result = break_hardlink_if_needed(&link).await;

    // Clear so tempdir cleanup can recurse.
    let _ = Command::new("chflags").arg("-h").arg("nouchg").arg(&link).status();

    let err = result.expect_err("rename over immutable symlink must propagate EPERM");
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::PermissionDenied,
        "rename over an immutable (uchg) symlink must surface EPERM as PermissionDenied; got {err:?}"
    );

    // Regression (atomicity): the failed break must NOT have destroyed
    // the original. The path still exists and is still the symlink.
    let meta = std::fs::symlink_metadata(&link)
        .expect("failed CoW must leave the original symlink in place");
    assert!(
        meta.file_type().is_symlink(),
        "original symlink must survive a failed break, got {meta:?}"
    );
    // And it must still resolve to the untouched target content — the
    // break neither rewrote nor truncated the link's destination.
    assert_eq!(
        std::fs::read(&link).unwrap(),
        b"content",
        "symlink must still resolve to its original target content"
    );
    // And no stage litter left behind.
    let leftover: Vec<_> = std::fs::read_dir(tmp.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with(".socket-cow-"))
        .collect();
    assert!(leftover.is_empty(), "stage litter left behind: {leftover:?}");
}

/// Hardlink branch read-fails arm (cow.rs:84): a hardlinked file
/// chmod'd to 0000 fails the read step. break_hardlink_if_needed
/// gets past lstat (mode bits don't affect lstat results) and the
/// `nlink > 1` check, then `read(path)` returns EACCES.
///
/// Skipped under uid 0 — root bypasses mode-bit access checks.
#[cfg(unix)]
#[tokio::test]
async fn cow_hardlink_unreadable_propagates_read_error() {
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
        eprintln!("SKIP: root bypasses chmod 0000 restrictions");
        return;
    }

    let tmp = tempfile::tempdir().unwrap();
    let a = tmp.path().join("a.txt");
    std::fs::write(&a, b"data").unwrap();
    let b = tmp.path().join("b.txt");
    std::fs::hard_link(&a, &b).unwrap();

    // chmod 0000 on either link affects the inode (both fail).
    let mut p = std::fs::metadata(&a).unwrap().permissions();
    p.set_mode(0o000);
    std::fs::set_permissions(&a, p).unwrap();

    let result = break_hardlink_if_needed(&b).await;

    // Restore so tempdir cleanup can read+unlink.
    let mut restore = std::fs::metadata(&a).unwrap().permissions();
    restore.set_mode(0o644);
    let _ = std::fs::set_permissions(&a, restore);

    let err = result.expect_err("read of unreadable hardlinked file must propagate");
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::PermissionDenied,
        "read of a chmod-0000 hardlinked file must surface EACCES as PermissionDenied; got {err:?}"
    );
    // Atomicity: the failed read must not have replaced or destroyed
    // either link — both still share the original inode (nlink == 2).
    {
        use std::os::unix::fs::MetadataExt;
        let restored_meta = std::fs::metadata(&a).unwrap();
        assert_eq!(
            restored_meta.nlink(),
            2,
            "a failed CoW read must leave both hardlinks intact, got nlink {}",
            restored_meta.nlink()
        );
        assert_eq!(
            std::fs::read(&a).unwrap(),
            b"data",
            "original content must be untouched after a failed CoW read"
        );
    }
}

/// `write_via_stage_rename` stage-write failure (cow.rs:111): the
/// hardlink branch reads the file content successfully, then
/// `tokio::fs::write(&stage, bytes)` fails because the parent
/// directory is r-x-only (write permission revoked after setup).
///
/// Goes through the nlink>1 path so we don't touch the symlink
/// branch's remove_file (which would also fail on a no-write
/// parent, taking us down a different code path).
///
/// Skipped under uid 0.
#[cfg(unix)]
#[tokio::test]
async fn cow_stage_write_failure_propagates() {
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
        eprintln!("SKIP: root bypasses chmod 0500 restrictions");
        return;
    }

    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("pkg");
    std::fs::create_dir(&dir).unwrap();
    let a = dir.join("orig.txt");
    std::fs::write(&a, b"content").unwrap();
    let b = dir.join("link.txt");
    std::fs::hard_link(&a, &b).unwrap();

    // Drop write permission on the parent so stage-file creation
    // (parent/.socket-cow-*) fails — keeping read+execute so
    // lstat, the nlink check, and `read(path)` all succeed first.
    let mut p = std::fs::metadata(&dir).unwrap().permissions();
    p.set_mode(0o500);
    std::fs::set_permissions(&dir, p).unwrap();

    let result = break_hardlink_if_needed(&b).await;

    // Restore so tempdir cleanup works.
    let mut restore = std::fs::metadata(&dir).unwrap().permissions();
    restore.set_mode(0o755);
    let _ = std::fs::set_permissions(&dir, restore);

    let err = result.expect_err("stage write into read-only parent must fail");
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::PermissionDenied,
        "stage create in a no-write (0o500) parent must surface EACCES as PermissionDenied; got {err:?}"
    );
    // Atomicity: the failed stage write must not have disturbed the
    // original — both hardlinks survive with their original content and
    // no `.socket-cow-*` litter is left behind.
    {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(
            std::fs::metadata(&a).unwrap().nlink(),
            2,
            "failed stage write must leave both hardlinks intact"
        );
        assert_eq!(std::fs::read(&a).unwrap(), b"content");
        assert_eq!(std::fs::read(&b).unwrap(), b"content");
    }
    let leftover: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with(".socket-cow-"))
        .collect();
    assert!(leftover.is_empty(), "stage litter left behind: {leftover:?}");
}

/// Symlink-branch `write_via_stage_rename` stage-create failure arm:
/// after `read(symlink)` succeeds, `write_via_stage_rename` fails to
/// create its `.socket-cow-*` stage file because the parent directory
/// has a macOS ACL that denies `add_file` while still allowing
/// `delete_child` — a state POSIX mode bits can't express (write perm
/// on a dir is monolithic for create+delete).
///
/// This same ACL is what made the old, destructive flow dangerous:
/// the previous code did `remove_file(symlink)` (a `delete_child`,
/// which the ACL *allows*) BEFORE the stage write, so the link was
/// gone the instant the denied stage create failed — destroying the
/// package file with no rollback. The current flow stages first and
/// never pre-unlinks, so this asserts the original symlink survives.
/// macOS-only because BSD extended ACLs (`chmod +a`) are the only
/// userspace mechanism for this kind of fine-grained denial; Linux's
/// POSIX.1e ACLs can't split create-vs-delete on directories.
#[cfg(target_os = "macos")]
#[tokio::test]
async fn cow_symlink_stage_write_failure_propagates() {
    use std::process::Command;

    if Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim() == "0")
        .unwrap_or(false)
    {
        eprintln!("SKIP: root bypasses ACL deny entries");
        return;
    }

    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("pkg");
    std::fs::create_dir(&dir).unwrap();
    let target = dir.join("orig.txt");
    std::fs::write(&target, b"shared bytes").unwrap();
    let link = dir.join("link");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    // Get the current user name for the ACL entry.
    let user = std::env::var("USER").unwrap_or_else(|_| "$(id -un)".to_string());

    // Add a deny-add_file ACL: blocks creation of new files in `dir`
    // while leaving `delete_child` (remove_file) intact. POSIX mode
    // bits couldn't express this — `chmod 0500` would block both.
    let status = Command::new("chmod")
        .arg("+a")
        .arg(format!("{user} deny add_file"))
        .arg(&dir)
        .status()
        .expect("chmod +a");
    assert!(status.success(), "ACL set must succeed");

    let result = break_hardlink_if_needed(&link).await;

    // Strip the ACL so tempdir cleanup works.
    let _ = Command::new("chmod").arg("-a#").arg("0").arg(&dir).status();

    let err = result.expect_err(
        "with deny-add_file ACL, write_via_stage_rename's stage create must fail, \
         surfacing the stage-write `?` Err arm",
    );
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::PermissionDenied,
        "deny-add_file ACL must surface the stage create as PermissionDenied; got {err:?}"
    );

    // Regression (atomicity / rollback): the old code unlinked the
    // symlink before this denied stage write, leaving the package file
    // gone. The current code stages first, so the original symlink must
    // still be present after the failure.
    let meta = std::fs::symlink_metadata(&link)
        .expect("failed CoW must leave the original symlink in place");
    assert!(
        meta.file_type().is_symlink(),
        "original symlink must survive a failed stage write, got {meta:?}"
    );
    assert_eq!(
        std::fs::read(&link).unwrap(),
        b"shared bytes",
        "symlink must still resolve to its original target content"
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
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::PermissionDenied,
        "rename over a uchg-immutable target must surface EPERM as PermissionDenied, got {err:?}"
    );

    // Atomicity / rollback (the contract this test exists to police):
    // a failed stage->target rename must leave the ORIGINAL target
    // completely intact — same inode (no replacement committed), same
    // nlink (sibling hardlink still attached), same bytes. The old
    // litter-only assertion below would stay green even if a regression
    // truncated or replaced the original, so assert the survival
    // explicitly here first.
    let surv = std::fs::symlink_metadata(&target)
        .expect("failed rename must leave the original target in place");
    assert!(
        surv.file_type().is_file(),
        "original target must remain a regular file, got {surv:?}"
    );
    assert_eq!(
        surv.nlink(),
        2,
        "no new inode may be committed on rename failure — both links must survive"
    );
    assert_eq!(
        std::fs::read(&target).unwrap(),
        b"original",
        "failed CoW rename must leave the original target content byte-for-byte intact"
    );
    assert_eq!(
        std::fs::read(&link).unwrap(),
        b"original",
        "the sibling hardlink must also be untouched after a failed CoW"
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
