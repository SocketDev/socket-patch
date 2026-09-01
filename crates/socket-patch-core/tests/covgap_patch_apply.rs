//! Coverage-gap integration tests for `patch::apply`: the pnpm
//! peer-variant copy FAILURE aggregation in `apply_package_patch`.
//!
//! The success half (patching/healing every twin) lives in
//! `crawler_npm_e2e.rs`; these exercise the fail-closed branch — a copy
//! that cannot be patched must flip the whole result to failure with a
//! "pnpm store copy ... failed to patch: ..." note, never report the CVE
//! fixed while a physical twin stays divergent.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use socket_patch_core::manifest::schema::PatchFileInfo;
use socket_patch_core::patch::apply::{apply_package_patch, MismatchPolicy, PatchSources};

const ORIGINAL: &[u8] = b"module.exports = 'vulnerable';\n";
const PATCHED: &[u8] = b"module.exports = 'fixed';\n";

/// Stage one pnpm store entry `.pnpm/<entry>/node_modules/foo` holding a
/// package.json and, when `index_content` is `Some`, an `index.js`.
/// Returns the staged package root.
async fn stage_store_entry(store: &Path, entry: &str, index_content: Option<&[u8]>) -> PathBuf {
    let pkg = store.join(entry).join("node_modules").join("foo");
    tokio::fs::create_dir_all(&pkg).await.unwrap();
    tokio::fs::write(
        pkg.join("package.json"),
        r#"{"name":"foo","version":"1.0.0"}"#,
    )
    .await
    .unwrap();
    if let Some(content) = index_content {
        tokio::fs::write(pkg.join("index.js"), content).await.unwrap();
    }
    pkg
}

/// Shared apply invocation: blob-only sources staged under `root`, one
/// patched file `package/index.js` (ORIGINAL → PATCHED), Warn policy.
async fn apply_foo(
    root: &Path,
    primary: &Path,
) -> socket_patch_core::patch::apply::ApplyResult {
    let before_hash = compute_git_sha256_from_bytes(ORIGINAL);
    let after_hash = compute_git_sha256_from_bytes(PATCHED);

    let blobs = root.join("blobs");
    tokio::fs::create_dir_all(&blobs).await.unwrap();
    tokio::fs::write(blobs.join(&after_hash), PATCHED).await.unwrap();

    let mut files = HashMap::new();
    files.insert(
        "package/index.js".to_string(),
        PatchFileInfo {
            before_hash,
            after_hash,
        },
    );
    let sources = PatchSources {
        blobs_path: &blobs,
        packages_path: None,
        diffs_path: None,
        mem_blobs: None,
    };
    apply_package_patch(
        "pkg:npm/foo@1.0.0",
        primary,
        &files,
        &sources,
        None,
        false,
        MismatchPolicy::Warn,
    )
    .await
}

/// Fail-closed invariant: after the primary store copy patches cleanly, a
/// peer-variant twin whose pre-existing file is MISSING (a hard error
/// under Warn) must flip the whole result to failure and surface the
/// aggregated "pnpm store copy ... failed to patch" note — never claim
/// the CVE fixed with a divergent twin left behind.
#[tokio::test]
#[serial_test::parallel]
async fn pnpm_twin_copy_failure_fails_whole_apply_fail_closed() {
    let tmp = tempfile::tempdir().unwrap();
    let store = tmp.path().join("node_modules").join(".pnpm");

    let primary = stage_store_entry(&store, "foo@1.0.0(react@17.0.2)", Some(ORIGINAL)).await;
    // Twin advertises the same foo@1.0.0 but is missing its pre-existing
    // index.js — the copy apply fails with NotFound.
    let twin = stage_store_entry(&store, "foo@1.0.0(react@18.2.0)", None).await;

    let result = apply_foo(tmp.path(), &primary).await;

    assert!(
        !result.success,
        "a failed twin copy must fail the whole apply (got success; error: {:?})",
        result.error
    );
    let err = result.error.as_deref().expect("aggregated error present");
    assert!(
        err.contains("pnpm store copy"),
        "error must carry the store-copy note: {err}"
    );
    assert!(
        err.contains("react@18.2.0"),
        "error must name the failing twin's path: {err}"
    );
    assert!(
        err.contains("File not found"),
        "error must carry the copy's underlying failure: {err}"
    );

    // Fail-closed does NOT roll back the primary: its bytes stay patched
    // and its per-file records are what the envelope carries.
    assert_eq!(
        tokio::fs::read(primary.join("index.js")).await.unwrap(),
        PATCHED,
        "primary copy stays patched"
    );
    assert_eq!(
        result.files_patched,
        vec!["package/index.js".to_string()],
        "the primary's per-file records are preserved"
    );
    // The twin is still missing its file — nothing was fabricated there.
    assert!(!twin.join("index.js").exists());
}

/// Two failing twins: the second note must be CONCATENATED onto the first
/// (`"...; pnpm store copy ..."`), naming both twin paths.
#[tokio::test]
#[serial_test::parallel]
async fn pnpm_multiple_twin_copy_failures_aggregate_with_semicolon() {
    let tmp = tempfile::tempdir().unwrap();
    let store = tmp.path().join("node_modules").join(".pnpm");

    let primary = stage_store_entry(&store, "foo@1.0.0(react@17.0.2)", Some(ORIGINAL)).await;
    stage_store_entry(&store, "foo@1.0.0(react@18.2.0)", None).await;
    stage_store_entry(&store, "foo@1.0.0(react@19.0.0)", None).await;

    let result = apply_foo(tmp.path(), &primary).await;

    assert!(!result.success, "two failed twins must fail the apply");
    let err = result.error.as_deref().expect("aggregated error present");
    assert!(
        err.contains("; pnpm store copy"),
        "second failure must be joined onto the first with '; ': {err}"
    );
    assert!(
        err.contains("react@18.2.0") && err.contains("react@19.0.0"),
        "error must name BOTH failing twins: {err}"
    );
    // Primary still patched; fail-closed, not rolled back.
    assert_eq!(
        tokio::fs::read(primary.join("index.js")).await.unwrap(),
        PATCHED
    );
}
