//! A `bun patch` made after socket-patch rewired the package (#1019),
//! through the built binary. Bun 1.4 keys that patch by the package's
//! current resolution, `left-pad@<hosted url>`, and applies it only while
//! the lock still resolves the package there. A superseding hosted re-run
//! or a hosted → vendored takeover would move the entry and silently drop
//! the user's patch from every install, so both leave the hosted wiring
//! alone and say why, with or without `--allow-patch-conflicts`. A
//! rollback still restores the registry entry the user asked for, and
//! warns that the patch stops applying.

use std::path::Path;

use serde_json::Value;
use wiremock::MockServer;

use super::{
    find_event, hosted_line, lock_line, mock_api, read, run_json, run_warning, scan_mode,
    seed_manifest_and_blob, vendor_cli, vendored_rel_tgz, write_lockfile_only_hosted_project,
    write_vendored_project, HOSTED_URL, NAME, PATCHED_SHA512, PURL, SUPERSEDED_UUID, UUID,
};

/// Add the `patchedDependencies` entry `bun patch --commit` writes for
/// left-pad while it resolves to `url`.
fn add_user_patch_keyed_by(root: &Path, url: &str) -> String {
    let key = format!("{NAME}@{url}");
    let mut manifest: Value = serde_json::from_str(&read(root, "package.json")).unwrap();
    manifest["patchedDependencies"] = serde_json::json!({ &key: "patches/left-pad.patch" });
    std::fs::write(
        root.join("package.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    key
}

/// The scan's `redirect_bun_patched_dependency_skipped` warning detail.
fn skipped_detail(env: &Value) -> Option<String> {
    env["redirect"]["warnings"]
        .as_array()
        .into_iter()
        .chain(env["warnings"].as_array())
        .flatten()
        .find(|w| w["code"] == "redirect_bun_patched_dependency_skipped")
        .and_then(|w| w["detail"].as_str())
        .map(String::from)
}

#[tokio::test(flavor = "multi_thread")]
async fn bun_patch_keyed_by_hosted_url_survives_a_superseding_rerun() {
    let server = MockServer::start().await;
    mock_api(&server).await;
    let superseded_url = HOSTED_URL.replace(UUID, SUPERSEDED_UUID);

    // By default the consent gate (#1646) withholds the package.
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let hosted_lock = write_lockfile_only_hosted_project(root, &superseded_url);
    add_user_patch_keyed_by(root, &superseded_url);
    let (code, env) = scan_mode(root, &server.uri(), "hosted", &[]);
    assert_eq!(code, 0, "{env:#}");
    assert_eq!(read(root, "bun.lock"), hosted_lock, "{env:#}");

    // With the conflict approved, the bun backend still refuses to orphan
    // the user's key: the entry keeps the URL the patch is keyed by.
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let hosted_lock = write_lockfile_only_hosted_project(root, &superseded_url);
    let key = add_user_patch_keyed_by(root, &superseded_url);
    let (code, env) = scan_mode(root, &server.uri(), "hosted", &["--allow-patch-conflicts"]);
    assert_eq!(code, 0, "{env:#}");
    let lock = read(root, "bun.lock");
    assert_eq!(
        lock_line(&lock, NAME),
        hosted_line(NAME, NAME, &superseded_url, PATCHED_SHA512),
        "the entry must keep the URL the user's patch is keyed by: {env:#}"
    );
    assert_eq!(lock, hosted_lock, "{env:#}");
    let detail = skipped_detail(&env).unwrap_or_else(|| panic!("no skip warning: {env:#}"));
    assert!(detail.contains(&key), "{detail}");
}

#[tokio::test(flavor = "multi_thread")]
async fn bun_patch_keyed_by_hosted_url_blocks_the_vendored_takeover() {
    let server = MockServer::start().await;
    mock_api(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let hosted_lock = write_lockfile_only_hosted_project(root, HOSTED_URL);
    let key = add_user_patch_keyed_by(root, HOSTED_URL);

    let (code, env) = scan_mode(
        root,
        &server.uri(),
        "vendored",
        &["--allow-patch-conflicts"],
    );
    assert_ne!(code, 0, "the takeover must refuse: {env:#}");
    let failed = find_event(&env, "failed", Some("vendor_lock_entry_unsupported"));
    assert_eq!(failed["purl"], PURL, "{env:#}");
    assert!(
        failed.to_string().contains(&key),
        "the refusal names the key: {env:#}"
    );
    assert_eq!(
        read(root, "bun.lock"),
        hosted_lock,
        "the hosted wiring must survive the refusal: {env:#}"
    );
    assert!(!root.join(".socket/vendor/npm").exists(), "{env:#}");
}

#[test]
fn bun_rollback_warns_that_a_patch_keyed_by_the_hosted_url_stops_applying() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_lockfile_only_hosted_project(root, HOSTED_URL);
    seed_manifest_and_blob(root);
    let key = add_user_patch_keyed_by(root, HOSTED_URL);

    let (code, env) = run_json(
        root,
        &[
            "rollback",
            "--yes",
            "--json",
            "--cwd",
            root.to_str().unwrap(),
        ],
    );
    assert_eq!(code, 0, "the rollback itself goes ahead: {env:#}");
    assert!(
        !read(root, "bun.lock").contains(HOSTED_URL),
        "the registry entry is restored: {env:#}"
    );
    let detail = run_warning(&env, "redirect_bun_patched_dependency_dropped")
        .unwrap_or_else(|| panic!("no drop warning: {env:#}"));
    assert!(
        detail.contains(&key) && detail.contains("bun patch"),
        "{detail}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn bun_patch_keyed_by_vendored_path_blocks_the_hosted_takeover() {
    let server = MockServer::start().await;
    mock_api(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_vendored_project(root);
    let key = add_user_patch_keyed_by(root, &vendored_rel_tgz());
    let vendored_lock = read(root, "bun.lock");

    let (code, env) = scan_mode(root, &server.uri(), "hosted", &["--allow-patch-conflicts"]);
    assert_eq!(code, 0, "{env:#}");
    assert_eq!(
        read(root, "bun.lock"),
        vendored_lock,
        "the vendored wiring the patch is keyed by must stay: {env:#}"
    );
    let detail = skipped_detail(&env).unwrap_or_else(|| panic!("no skip warning: {env:#}"));
    assert!(detail.contains(&key), "{detail}");
}

#[test]
fn bun_vendor_revert_warns_that_a_patch_keyed_by_the_vendored_path_stops_applying() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_vendored_project(root);
    let key = add_user_patch_keyed_by(root, &vendored_rel_tgz());

    let (code, env) = vendor_cli(root, &["--revert"]);
    assert_eq!(code, 0, "the revert itself goes ahead: {env:#}");
    assert!(
        !read(root, "bun.lock").contains(".socket/vendor/"),
        "the vendored wiring is reverted: {env:#}"
    );
    assert!(
        env.to_string()
            .contains("vendor_bun_patched_dependency_dropped")
            && env.to_string().contains(&key),
        "the revert warns, naming the key: {env:#}"
    );
}
