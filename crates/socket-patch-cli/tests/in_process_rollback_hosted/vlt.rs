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

/// A hosted scan of a project whose left-pad node is optional (`flags`),
/// followed by vlt's warm install of the pin.
async fn hosted_optional_project(root: &Path, flags: u8) -> MockServer {
    hosted_flagged_project(root, &[(TILDE_ID, flags)]).await
}

/// A hosted scan of a project with left-pad instances `nodes` (each
/// `(DepID, flags)`), followed by vlt's warm install of the pins.
async fn hosted_flagged_project(root: &Path, nodes: &[(&str, u8)]) -> MockServer {
    let server = MockServer::start().await;
    mock_all(&server).await;
    write_vlt_project(root, Era::V1);
    let registry: Vec<String> = nodes
        .iter()
        .map(|(id, flags)| with_flags(&registry_node(id), *flags))
        .collect();
    std::fs::write(root.join("vlt-lock.json"), vlt_lock(Era::V1, &registry)).unwrap();
    let (_, doc) = scan_hosted(root, &server, &[], &[]);
    assert_eq!(redirected(&doc), 1, "{doc:#}");
    let pinned: Vec<String> = nodes
        .iter()
        .map(|(id, flags)| with_flags(&pinned_node(id, &server), *flags))
        .collect();
    assert_eq!(read(root, "vlt-lock.json"), vlt_lock(Era::V1, &pinned));
    for (id, _) in nodes {
        install_store(root, id, PATCHED);
    }
    write_hidden_lock(root, &pinned);
    server
}

fn optional_kept(restored: usize, kept: usize) -> String {
    format!(
        "restored registry pins for {restored} packages, but node_modules still holds {kept} \
         patched copies of optional dependencies; {OPTIONAL_KEPT}"
    )
}

#[tokio::test]
async fn vlt_rollback_keeps_a_patched_optional_copy() {
    for (verb, flags) in [("rollback", 1), ("rollback", 3), ("remove", 1)] {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let _server = hosted_optional_project(root, flags).await;
        let targets: &[&str] = if verb == "remove" { &[PURL] } else { &[] };

        let (_, doc) = run_verb(root, verb, targets);

        assert_eq!(
            read(root, "vlt-lock.json"),
            vlt_lock(Era::V1, &[with_flags(&registry_node(TILDE_ID), flags)]),
            "{verb} flags={flags}"
        );
        assert_eq!(
            advisory_details(&doc),
            [optional_kept(1, 1)],
            "{verb} flags={flags}: {doc:#}"
        );
        assert_eq!(
            std::fs::read(store_dir(root, TILDE_ID).join("index.js")).unwrap(),
            PATCHED,
            "{verb} flags={flags}"
        );
        assert!(root.join("node_modules/.vlt-lock.json").exists());
    }
}

#[tokio::test]
async fn vlt_rollback_removes_the_prod_copy_keeps_the_optional_one() {
    let optional = "~npm~left-pad@1.3.0~peer.2";
    let nodes = [(TILDE_ID, 0), (optional, 1)];
    let also = also_optional_kept(1, "patched copies of optional dependencies");
    let removed = format!(
        "restored registry pins for 1 packages; removed 1 patched installed copies, so \
         node_modules is incomplete until you run `vlt install` (or `vlt ci`). {also}"
    );
    let skipped = format!(
        "restored registry pins for 1 packages, but node_modules still holds 1 patched copies \
         and `vlt install` will not refresh them; run `vlt ci` (or re-run without \
         --no-vlt-install-cleanup). {also}"
    );
    for (verb, extra, cleaned) in [
        ("rollback", &[][..], true),
        ("rollback", &["--no-vlt-install-cleanup"][..], false),
        ("remove", &[PURL][..], true),
        ("remove", &[PURL, "--no-vlt-install-cleanup"][..], false),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let _server = hosted_flagged_project(root, &nodes).await;
        let expected = if cleaned { &removed } else { &skipped };

        let (_, doc) = run_verb(root, verb, extra);

        assert_eq!(
            read(root, "vlt-lock.json"),
            vlt_lock(
                Era::V1,
                &[
                    registry_node(TILDE_ID),
                    with_flags(&registry_node(optional), 1)
                ]
            ),
            "{verb} {extra:?}"
        );
        assert_eq!(
            advisory_details(&doc),
            [expected.clone()],
            "{verb} {extra:?}: {doc:#}"
        );
        assert_eq!(
            store_dir(root, TILDE_ID).exists(),
            !cleaned,
            "{verb} {extra:?}"
        );
        assert_eq!(
            root.join("node_modules/.vlt-lock.json").exists(),
            !cleaned,
            "{verb} {extra:?}"
        );
        assert_eq!(
            std::fs::read(store_dir(root, optional).join("index.js")).unwrap(),
            PATCHED,
            "the optional copy is kept: {verb} {extra:?}"
        );
    }
}

/// Once vlt re-locked the package, the healed DepID is gone from the lock,
/// so the heal goes by the flags the ledger recorded for it.
#[tokio::test]
async fn vlt_rollback_after_relock_goes_by_the_recorded_flags() {
    for flags in [0, 1] {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let _server = hosted_optional_project(root, flags).await;
        let relocked = vlt_lock(
            Era::V1,
            &[with_flags(&registry_node(TILDE_ID), flags).replace("1.3.0", "1.3.1")],
        );
        std::fs::write(root.join("vlt-lock.json"), &relocked).unwrap();
        write_hidden_lock(root, &[]);

        let (_, doc) = run_verb(root, "rollback", &[]);

        assert_eq!(read(root, "vlt-lock.json"), relocked);
        let (advisory, kept) = if flags == 0 {
            (RESTORED.to_string(), false)
        } else {
            (optional_kept(1, 1), true)
        };
        assert_eq!(advisory_details(&doc), [advisory], "flags={flags}: {doc:#}");
        assert_eq!(
            store_dir(root, TILDE_ID).join("index.js").exists(),
            kept,
            "flags={flags}"
        );
    }
}

const OTHER: &str = "right-pad";
const OTHER_UUID: &str = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";

fn as_other(text: &str) -> String {
    text.replace(NAME, OTHER).replace(UUID, OTHER_UUID)
}

/// Add a second hosted vlt package to the ledger and the lock by renaming
/// left-pad's recorded edit, record and pinned node.
fn add_second_hosted_package(root: &Path, server: &MockServer) -> String {
    let path = ledger_path(root);
    let mut ledger: Value = serde_json::from_str(&read(root, ".socket/vendor/redirect-state.json"))
        .expect("the hosted run wrote a ledger");
    let edits: Vec<Value> = ledger["edits"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["kind"] == "redirect_vlt_lock_node")
        .map(|e| serde_json::from_str(&as_other(&e.to_string())).unwrap())
        .collect();
    assert_eq!(edits.len(), 1);
    ledger["edits"].as_array_mut().unwrap().extend(edits);
    let record: Value =
        serde_json::from_str(&as_other(&ledger["records"][PURL].to_string())).unwrap();
    ledger["records"][as_other(PURL)] = record;
    std::fs::write(&path, serde_json::to_vec_pretty(&ledger).unwrap()).unwrap();
    let other_pinned = as_other(&pinned_node(TILDE_ID, server));
    std::fs::write(
        root.join("vlt-lock.json"),
        vlt_lock(
            Era::V1,
            &[pinned_node(TILDE_ID, server), other_pinned.clone()],
        ),
    )
    .unwrap();
    other_pinned
}

fn other_store_dir(root: &Path) -> std::path::PathBuf {
    root.join("node_modules/.vlt")
        .join(as_other(TILDE_ID))
        .join("node_modules")
        .join(OTHER)
}

/// A scoped rollback of one of two hosted vlt packages takes the per-purl
/// path (not a whole-ledger replay): only that package's pin is restored
/// and only its patched store entry (plus the hidden lock) is removed.
#[tokio::test]
async fn vlt_scoped_rollback_of_one_of_two_heals_only_that_package() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let server = hosted_vlt_project(root).await;
    let other_pinned = add_second_hosted_package(root, &server);
    install_store(root, TILDE_ID, PATCHED);
    let other = other_store_dir(root);
    std::fs::create_dir_all(&other).unwrap();
    std::fs::write(
        other.join("package.json"),
        as_other(&String::from_utf8_lossy(PACKAGE_JSON)),
    )
    .unwrap();
    std::fs::write(other.join("index.js"), PATCHED).unwrap();
    write_hidden_lock(
        root,
        &[pinned_node(TILDE_ID, &server), other_pinned.clone()],
    );

    let (_, doc) = run_verb(root, "rollback", &[PURL]);

    assert_eq!(
        read(root, "vlt-lock.json"),
        vlt_lock(Era::V1, &[registry_node(TILDE_ID), other_pinned])
    );
    assert_eq!(advisory_details(&doc), [RESTORED], "{doc:#}");
    assert!(!store_dir(root, TILDE_ID).exists());
    assert!(!root.join("node_modules/.vlt-lock.json").exists());
    assert!(
        other.join("index.js").exists(),
        "the other package's copy stays"
    );
    let ledger = read(root, ".socket/vendor/redirect-state.json");
    assert!(ledger.contains(OTHER_UUID), "{ledger}");
}
