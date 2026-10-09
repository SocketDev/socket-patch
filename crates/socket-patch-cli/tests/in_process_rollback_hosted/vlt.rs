//! Hosted vlt round trips: a real `scan --mode hosted` over a vlt project,
//! then `rollback` / `remove` restoring the registry pins slot by slot
//! (after vlt re-laid the line) and invalidating the patched installed
//! copies so the next install extracts the registry bytes.
//!
//! v5 hosted mode keeps no ledger: the pins are read from `vlt-lock.json`
//! (on the mock server's origin, recognized through `--patch-server-url`)
//! and each is restored to the upstream registry entry re-resolved from the
//! mock npm registry (`SOCKET_NPM_REGISTRY`).

use std::path::Path;

use serde_json::Value;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::vlt_hosted_common::*;

const RESTORED: &str = "restored registry pins for 1 packages; removed the patched installed \
     copies, so node_modules is incomplete until you run `vlt install` (or `vlt ci`)";

/// Serve the npm registry's version document for left-pad@1.3.0 (the
/// registry entry `registry_node` pins) under `/npm-registry`.
async fn mock_registry(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path(format!("/npm-registry/{NAME}/{VERSION}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": NAME,
            "version": VERSION,
            "dist": { "tarball": REGISTRY_URL, "integrity": UPSTREAM_SHA512 }
        })))
        .mount(server)
        .await;
}

/// The node line the upstream restore writes back for `id`: slot [2] is the
/// registry's `dist.integrity`, and — this lock recording no
/// `options.registries` and no other default-registry node to read the
/// convention from — a tilde-era node gets no resolved URL (slot [3]), per
/// the restore's documented convention. (The URL `registry_node` carries is
/// what the rewrite discarded; it is not derivable from the lock.)
fn restored_node(id: &str) -> String {
    format!("\"{id}\": [0,\"{NAME}\",\"{UPSTREAM_SHA512}\"]")
}

async fn hosted_vlt_project(root: &Path) -> MockServer {
    let server = MockServer::start().await;
    mock_all(&server).await;
    mock_registry(&server).await;
    write_vlt_project(root, Era::V1);
    let (_, doc) = scan_hosted(root, &server, &[], &[]);
    assert_eq!(redirected(&doc), 1, "{doc:#}");
    assert_eq!(
        read(root, "vlt-lock.json"),
        vlt_lock(Era::V1, &[pinned_node(TILDE_ID, &server)])
    );
    assert!(!ledger_path(root).exists(), "hosted mode keeps no ledger");
    server
}

/// What `vlt install` leaves after the redirect: the patched store entry
/// and a hidden lock recording the pinned node.
fn vlt_install_patched(root: &Path, server: &MockServer) {
    install_store(root, TILDE_ID, PATCHED);
    write_hidden_lock(root, &[pinned_node(TILDE_ID, server)]);
}

/// `<verb> [extra] --yes --json` online against `server` (registry +
/// patch host); `(exit code, envelope, stderr)`.
fn run_verb_raw(
    root: &Path,
    server: &MockServer,
    verb: &str,
    extra: &[&str],
) -> (i32, Value, String) {
    let cwd = root.to_str().unwrap().to_string();
    let uri = server.uri();
    let registry = format!("{uri}/npm-registry");
    let mut args = vec![verb];
    args.extend_from_slice(extra);
    args.extend_from_slice(&["--yes", "--patch-server-url", &uri, "--cwd", &cwd]);
    run_json(root, &args, &[("SOCKET_NPM_REGISTRY", registry.as_str())])
}

fn run_verb(root: &Path, server: &MockServer, verb: &str, extra: &[&str]) -> (i32, Value) {
    let (code, doc, stderr) = run_verb_raw(root, server, verb, extra);
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
        let pristine = vlt_lock(Era::V1, &[restored_node(TILDE_ID)]);
        let server = hosted_vlt_project(root).await;
        vlt_install_patched(root, &server);

        let targets: &[&str] = if scoped { &[PURL] } else { &[] };
        let (_, doc) = run_verb(root, &server, "rollback", targets);

        assert_eq!(read(root, "vlt-lock.json"), pristine, "scoped={scoped}");
        assert_eq!(
            doc["hosted"]["reverted"],
            serde_json::json!([PURL]),
            "{doc:#}"
        );
        assert_eq!(advisory_details(&doc), [RESTORED], "{doc:#}");
        assert!(!store_dir(root, TILDE_ID).exists());
        assert!(!root.join("node_modules/.vlt-lock.json").exists());
        assert!(!ledger_path(root).exists());
    }
}

#[tokio::test]
async fn vlt_hosted_remove_restores_and_emits_the_advisory() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let server = hosted_vlt_project(root).await;
    vlt_install_patched(root, &server);

    let (_, doc) = run_verb(root, &server, "remove", &[PURL]);

    assert_eq!(
        read(root, "vlt-lock.json"),
        vlt_lock(Era::V1, &[restored_node(TILDE_ID)])
    );
    assert!(doc.to_string().contains(ADVISORY), "{doc:#}");
    assert!(!store_dir(root, TILDE_ID).exists());
}

/// Once vlt itself re-locked the package back onto the registry (a `vlt
/// update`, or a relock to another version, optional or not), no lockfile
/// pins a hosted patch any more — and v5 hosted mode keeps no ledger that
/// could remember the patched store copy. Rollback therefore has no hosted
/// state to act on: the plain "Manifest not found" exit 1, the lock and the
/// installed copies untouched (`vlt install` / `vlt ci` owns the store).
#[tokio::test]
async fn vlt_rollback_after_a_relock_has_no_hosted_state_left() {
    for (flags, version) in [(0, "1.3.0"), (0, "1.3.1"), (1, "1.3.1")] {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let server = hosted_vlt_project(root).await;
        let relocked = vlt_lock(
            Era::V1,
            &[with_flags(&registry_node(TILDE_ID), flags).replace("1.3.0", version)],
        );
        std::fs::write(root.join("vlt-lock.json"), &relocked).unwrap();
        install_store(root, TILDE_ID, PATCHED);
        write_hidden_lock(root, &[registry_node(TILDE_ID)]);

        let (code, doc, stderr) = run_verb_raw(root, &server, "rollback", &[]);

        let what = format!("flags={flags} version={version}");
        assert_eq!(code, 1, "{what}: {doc:#}\n{stderr}");
        assert_eq!(
            doc["error"]["message"], "Manifest not found",
            "{what}: {doc:#}"
        );
        assert_eq!(read(root, "vlt-lock.json"), relocked, "{what}");
        assert!(
            store_dir(root, TILDE_ID).join("index.js").exists(),
            "{what}"
        );
        assert!(root.join("node_modules/.vlt-lock.json").exists(), "{what}");
        assert!(!root.join(".socket").exists(), "{what}");
    }
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

    let (_, doc) = run_verb(root, &server, "rollback", &[PURL]);

    assert_eq!(
        read(root, "vlt-lock.json"),
        vlt_lock(Era::V1, &[restored_node(TILDE_ID), sibling])
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

    run_verb(root, &server, "rollback", &[]);

    assert_eq!(
        read(root, "vlt-lock.json"),
        vlt_lock(
            Era::V1,
            &[restored_node(TILDE_ID).replacen("[0,", "[1,", 1)]
        )
    );
}

#[tokio::test]
async fn vlt_rollback_honors_no_vlt_install_cleanup() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let server = hosted_vlt_project(root).await;
    vlt_install_patched(root, &server);

    let (_, doc) = run_verb(root, &server, "rollback", &["--no-vlt-install-cleanup"]);

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
    let server = hosted_vlt_project(root).await;
    install_store(root, TILDE_ID, PRISTINE);
    write_hidden_lock(root, &[registry_node(TILDE_ID)]);

    let (_, doc) = run_verb(root, &server, "rollback", &[]);

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
    mock_registry(&server).await;
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
        let server = hosted_optional_project(root, flags).await;
        let targets: &[&str] = if verb == "remove" { &[PURL] } else { &[] };

        let (_, doc) = run_verb(root, &server, verb, targets);

        assert_eq!(
            read(root, "vlt-lock.json"),
            vlt_lock(Era::V1, &[with_flags(&restored_node(TILDE_ID), flags)]),
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
        let server = hosted_flagged_project(root, &nodes).await;
        let expected = if cleaned { &removed } else { &skipped };

        let (_, doc) = run_verb(root, &server, verb, extra);

        assert_eq!(
            read(root, "vlt-lock.json"),
            vlt_lock(
                Era::V1,
                &[
                    restored_node(TILDE_ID),
                    with_flags(&restored_node(optional), 1)
                ]
            ),
            "{verb} {extra:?}"
        );
        assert_eq!(
            advisory_details(&doc),
            std::slice::from_ref(expected),
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

const OTHER: &str = "right-pad";
const OTHER_UUID: &str = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const OTHER_PURL: &str = "pkg:npm/right-pad@1.3.0";

fn as_other(text: &str) -> String {
    text.replace(NAME, OTHER).replace(UUID, OTHER_UUID)
}

/// Add a second hosted vlt package (right-pad, its own patch uuid) to the
/// lock by renaming left-pad's pinned node. The lock pin is the whole
/// hosted state; the mock registry does NOT serve right-pad.
fn add_second_hosted_package(root: &Path, server: &MockServer) -> String {
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

/// Both packages installed patched, with the hidden lock recording both
/// pins.
fn install_both_patched(
    root: &Path,
    server: &MockServer,
    other_pinned: &str,
) -> std::path::PathBuf {
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
        &[pinned_node(TILDE_ID, server), other_pinned.to_string()],
    );
    other
}

/// A scoped rollback of one of two hosted vlt packages restores only that
/// package's pin and removes only its patched store entry (plus the hidden
/// lock); the other package stays pinned and installed.
#[tokio::test]
async fn vlt_scoped_rollback_of_one_of_two_heals_only_that_package() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let server = hosted_vlt_project(root).await;
    let other_pinned = add_second_hosted_package(root, &server);
    let other = install_both_patched(root, &server, &other_pinned);

    let (_, doc) = run_verb(root, &server, "rollback", &[PURL]);

    assert_eq!(
        read(root, "vlt-lock.json"),
        vlt_lock(Era::V1, &[restored_node(TILDE_ID), other_pinned])
    );
    assert_eq!(
        doc["hosted"]["reverted"],
        serde_json::json!([PURL]),
        "{doc:#}"
    );
    assert_eq!(advisory_details(&doc), [RESTORED], "{doc:#}");
    assert!(!store_dir(root, TILDE_ID).exists());
    assert!(!root.join("node_modules/.vlt-lock.json").exists());
    assert!(
        other.join("index.js").exists(),
        "the other package's copy stays"
    );
}

/// Hosted rollback reads `vlt-lock.json` (to find the pins and the store
/// copies to heal). A FIFO planted at that path must fail the read at once
/// through the FIFO-safe opener, never block the process in open(2)
/// waiting for a writer; the run then fails closed and the FIFO is left as
/// it was.
#[cfg(unix)]
#[tokio::test]
async fn vlt_hosted_rollback_fails_fast_on_a_fifo_lock() {
    use std::os::unix::fs::FileTypeExt as _;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let server = hosted_vlt_project(root).await;
    let lock = root.join("vlt-lock.json");
    std::fs::remove_file(&lock).unwrap();
    let status = std::process::Command::new("mkfifo")
        .arg(&lock)
        .status()
        .unwrap();
    assert!(status.success());

    let cwd = root.to_str().unwrap().to_string();
    let uri = server.uri();
    let mut child = scrubbed_cli()
        .env("SOCKET_NPM_REGISTRY", format!("{uri}/npm-registry"))
        .args([
            "rollback",
            "--json",
            "--yes",
            "--patch-server-url",
            &uri,
            "--cwd",
            &cwd,
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    let exit = loop {
        if let Some(exit) = child.try_wait().unwrap() {
            break exit;
        }
        if std::time::Instant::now() > deadline {
            // Release a wedged open before failing, so the suite never hangs.
            use std::os::unix::fs::OpenOptionsExt as _;
            let _ = std::fs::OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&lock);
            let _ = child.kill();
            panic!("rollback must fail fast on a FIFO vlt-lock.json, not block in open(2)");
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    };

    assert!(!exit.success(), "a lock that cannot be read fails closed");
    assert!(std::fs::symlink_metadata(&lock)
        .unwrap()
        .file_type()
        .is_fifo());
    assert!(!ledger_path(root).exists(), "nothing is written");
}

/// Each pin restores or refuses on its own: when an unscoped rollback's
/// right-pad pin is refused (the registry does not answer for it) while
/// the left-pad pin is restored, left-pad's patched store copy — which the
/// restored vlt-lock.json no longer names — is still removed. The heal
/// follows the restored pins, not the run's overall outcome.
#[tokio::test]
async fn vlt_heal_follows_the_restored_pin_when_another_pin_refuses() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let server = hosted_vlt_project(root).await;
    let other_pinned = add_second_hosted_package(root, &server);
    let other = install_both_patched(root, &server, &other_pinned);

    let (code, doc, _) = run_verb_raw(root, &server, "rollback", &[]);

    assert_ne!(code, 0, "the refused right-pad pin fails the run");
    assert_eq!(doc["status"], "partial_failure", "{doc:#}");
    assert_eq!(
        doc["hosted"]["reverted"],
        serde_json::json!([PURL]),
        "{doc:#}"
    );
    assert_eq!(doc["hosted"]["failed"][0]["purl"], OTHER_PURL, "{doc:#}");
    assert_eq!(
        read(root, "vlt-lock.json"),
        vlt_lock(Era::V1, &[restored_node(TILDE_ID), other_pinned]),
        "left-pad restored, the refused right-pad pin untouched"
    );
    assert!(
        !store_dir(root, TILDE_ID).exists(),
        "the patched store copy is removed for the restored pin"
    );
    assert!(
        other.join("index.js").exists(),
        "the refused package's copy stays"
    );
    assert_eq!(
        advisory_details(&doc),
        [RESTORED],
        "the heal advisory is reported"
    );
}
