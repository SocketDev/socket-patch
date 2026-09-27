//! Integration coverage for the handful of `sidecars` defensive paths
//! that the apply-CLI path cannot reach.
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
//! No network. No toolchain. Portable.

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
/// — and it is always compiled in. So observing
/// `None` here can ONLY mean the empty-patched short-circuit fired
/// before PURL classification. (This mirrors the in-tree lib test
/// `empty_patched_short_circuits_before_advisory`, which the original
/// integration test failed to copy.)
#[tokio::test]
async fn dispatch_fixup_empty_patched_returns_none() {
    let tmp = tempfile::tempdir().unwrap();
    let out = dispatch_fixup("pkg:pypi/requests@2.28.0", tmp.path(), &[])
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
    )
    .await
    .unwrap();
    assert!(
        out.is_none(),
        "unknown ecosystem must short-circuit to None"
    );
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
#[tokio::test]
async fn dispatch_fixup_nuget_with_nonexistent_pkg_path() {
    let tmp = tempfile::tempdir().unwrap();
    let absent = tmp.path().join("does-not-exist");

    let out = dispatch_fixup(
        "pkg:nuget/Anything@1.0.0",
        &absent,
        &["package/file.txt".to_string()],
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
