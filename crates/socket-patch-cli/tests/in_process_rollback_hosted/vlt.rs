//! Hosted vlt round trips: a real `scan --mode hosted` over a vlt project,
//! then `rollback` / `remove` restoring the registry pins slot by slot
//! (after vlt re-laid the line) and invalidating the patched installed
//! copies so the next install extracts the registry bytes.

use std::path::Path;

use serde_json::Value;
use wiremock::MockServer;

use crate::vlt_hosted_common::*;

const RESTORED: &str = "restored registry pins for 1 packages; removed the patched installed \
     copies, so node_modules is incomplete until you run `vlt install` (or `vlt ci`)";

async fn hosted_vlt_project(root: &Path) -> MockServer {
    let server = MockServer::start().await;
    mock_all(&server).await;
    write_vlt_project(root, Era::V1);
    let (_, doc) = scan_hosted(root, &server, &[], &[]);
    assert_eq!(redirected(&doc), 1, "{doc:#}");
    assert_eq!(
        read(root, "vlt-lock.json"),
        vlt_lock(Era::V1, &[pinned_node(TILDE_ID, &server)])
    );
    server
}

/// What `vlt install` leaves after the redirect: the patched store entry
/// and a hidden lock recording the pinned node.
fn vlt_install_patched(root: &Path, server: &MockServer) {
    install_store(root, TILDE_ID, PATCHED);
    write_hidden_lock(root, &[pinned_node(TILDE_ID, server)]);
}

fn run_verb(root: &Path, verb: &str, extra: &[&str]) -> (i32, Value) {
    let cwd = root.to_str().unwrap().to_string();
    let mut args = vec![verb];
    args.extend_from_slice(extra);
    args.extend_from_slice(&["--yes", "--offline", "--cwd", &cwd]);
    let (code, doc, stderr) = run_json(root, &args, &[]);
    assert_eq!(code, 0, "{verb} must succeed: {doc:#}\n{stderr}");
    (code, doc)
}

fn advisory_details(doc: &Value) -> Vec<String> {
    doc["warnings"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|w| w["code"] == ADVISORY)
        .filter_map(|w| w["detail"].as_str().map(str::to_string))
        .collect()
}

#[tokio::test]
async fn vlt_hosted_round_trip() {
    for scoped in [true, false] {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let pristine = vlt_lock(Era::V1, &[registry_node(TILDE_ID)]);
        let server = hosted_vlt_project(root).await;
        vlt_install_patched(root, &server);

        let targets: &[&str] = if scoped { &[PURL] } else { &[] };
        let (_, doc) = run_verb(root, "rollback", targets);

        assert_eq!(read(root, "vlt-lock.json"), pristine, "scoped={scoped}");
        assert_eq!(advisory_details(&doc), [RESTORED], "{doc:#}");
        assert!(!store_dir(root, TILDE_ID).exists());
        assert!(!root.join("node_modules/.vlt-lock.json").exists());
        assert!(
            !ledger_path(root).exists()
                || !read(root, ".socket/vendor/redirect-state.json")
                    .contains("redirect_vlt_lock_node")
        );
    }
}

#[tokio::test]
async fn vlt_hosted_remove_restores_and_emits_the_advisory() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let server = hosted_vlt_project(root).await;
    vlt_install_patched(root, &server);

    let (_, doc) = run_verb(root, "remove", &[PURL]);

    assert_eq!(
        read(root, "vlt-lock.json"),
        vlt_lock(Era::V1, &[registry_node(TILDE_ID)])
    );
    assert!(doc.to_string().contains(ADVISORY), "{doc:#}");
    assert!(!store_dir(root, TILDE_ID).exists());
}

#[tokio::test]
async fn vlt_rollback_after_vlt_update_invalidates_patched_store() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let _server = hosted_vlt_project(root).await;
    let registry = vlt_lock(Era::V1, &[registry_node(TILDE_ID)]);
    std::fs::write(root.join("vlt-lock.json"), &registry).unwrap();
    install_store(root, TILDE_ID, PATCHED);
    write_hidden_lock(root, &[registry_node(TILDE_ID)]);

    let (_, doc) = run_verb(root, "rollback", &[]);

    assert_eq!(read(root, "vlt-lock.json"), registry);
    assert_eq!(advisory_details(&doc), [RESTORED], "{doc:#}");
    assert!(!store_dir(root, TILDE_ID).exists());
}

#[tokio::test]
async fn vlt_rollback_after_comma_move() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let server = hosted_vlt_project(root).await;
    let sibling = "\"~npm~zz@1.0.0\": [0,\"zz\"]".to_string();
    std::fs::write(
        root.join("vlt-lock.json"),
        vlt_lock(Era::V1, &[pinned_node(TILDE_ID, &server), sibling.clone()]),
    )
    .unwrap();

    let (_, doc) = run_verb(root, "rollback", &[PURL]);

    assert_eq!(
        read(root, "vlt-lock.json"),
        vlt_lock(Era::V1, &[registry_node(TILDE_ID), sibling])
    );
    assert!(
        advisory_details(&doc).is_empty(),
        "nothing installed: {doc:#}"
    );
}

#[tokio::test]
async fn vlt_rollback_after_e0_flag_change() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let server = hosted_vlt_project(root).await;
    let relaid = pinned_node(TILDE_ID, &server).replacen("[0,", "[1,", 1);
    std::fs::write(root.join("vlt-lock.json"), vlt_lock(Era::V1, &[relaid])).unwrap();

    run_verb(root, "rollback", &[]);

    assert_eq!(
        read(root, "vlt-lock.json"),
        vlt_lock(
            Era::V1,
            &[registry_node(TILDE_ID).replacen("[0,", "[1,", 1)]
        )
    );
}

#[tokio::test]
async fn vlt_rollback_honors_no_vlt_install_cleanup() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let server = hosted_vlt_project(root).await;
    vlt_install_patched(root, &server);

    let (_, doc) = run_verb(root, "rollback", &["--no-vlt-install-cleanup"]);

    assert_eq!(
        advisory_details(&doc),
        [
            "restored registry pins for 1 packages, but node_modules still holds 1 patched copies \
          and `vlt install` will not refresh them; run `vlt ci` (or re-run without \
          --no-vlt-install-cleanup)"
        ],
        "{doc:#}"
    );
    assert!(store_dir(root, TILDE_ID).join("index.js").exists());
}

#[tokio::test]
async fn vlt_rollback_of_a_pristine_tree_keeps_it() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let _server = hosted_vlt_project(root).await;
    install_store(root, TILDE_ID, PRISTINE);
    write_hidden_lock(root, &[registry_node(TILDE_ID)]);

    let (_, doc) = run_verb(root, "rollback", &[]);

    assert!(advisory_details(&doc).is_empty(), "{doc:#}");
    assert!(store_dir(root, TILDE_ID).join("index.js").exists());
    assert!(root.join("node_modules/.vlt-lock.json").exists());
}
