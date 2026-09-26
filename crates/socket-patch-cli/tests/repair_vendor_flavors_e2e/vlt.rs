//! `repair` over vlt DIRECTORY artifacts (DESIGN §4.8), for both lock
//! grammars (`lockfileVersion` 1 tilde ids, 0 legacy `·npm·` ids): the
//! artifact is `.socket/vendor/npm/<uuid>/left-pad-1.3.0/node_modules/
//! left-pad/`, its ledger `fileInventory` leaves out the package's own
//! `node_modules/` (vlt's links), and `<uuid>/.gitignore` /
//! `.gitattributes` are not part of it.
//!
//! (a) deleted dir → rebuilt to the recorded inventory, lock untouched;
//! (b) vlt's links inside the package dir are healthy; a modified member
//!     → corrupt, rebuilt;
//! (c) a planted regular file under the package's `node_modules/` →
//!     corrupt (`vendor_inventory_mismatch`), rebuilt without it;
//! (d) ledger deleted → reconstructed from `vlt-lock.json` (flavor `vlt`),
//!     rebuilt member-verified, and its revert blocked by the unwired guard;
//! (e) the orphan sweep keeps a lock-wired dir leaf and removes an
//!     unreferenced one;
//! (f) a deleted `<uuid>/.gitignore` is rewritten, no rebuild;
//! (g) a package.json-touching patch of a package with devDependencies is
//!     healthy (the vlt manifest exemption; no Corrupt → rebuild loop).

use std::path::{Path, PathBuf};

use super::{
    common, events_of, mount_patch_api, parse_env, run_cli, AFTER, BEFORE, DEP, DEP_VERSION, PURL,
    UUID,
};

#[derive(Clone, Copy, Debug)]
enum VltLock {
    V0,
    V1,
}

const LOCKS: [VltLock; 2] = [VltLock::V0, VltLock::V1];

impl VltLock {
    fn lock(self) -> String {
        let (version, id, importer) = match self {
            VltLock::V0 => (0, "·npm·left-pad@1.3.0", "file·."),
            VltLock::V1 => (1, "~npm~left-pad@1.3.0", "file~_d"),
        };
        format!(
            "{{\n  \"lockfileVersion\": {version},\n  \"options\": {{}},\n  \"nodes\": {{\n    \
             \"{id}\": [0,\"{DEP}\",\"sha512-orig==\",\"https://registry.npmjs.org/left-pad/-/\
             left-pad-1.3.0.tgz\"]\n  }},\n  \"edges\": {{\n    \"{importer} {DEP}\": \"prod \
             {DEP_VERSION} {id}\"\n  }}\n}}\n"
        )
    }
}

fn rel() -> String {
    format!(".socket/vendor/npm/{UUID}/{DEP}-{DEP_VERSION}/node_modules/{DEP}")
}

fn write_fixture(root: &Path, lock: VltLock, package_json: Option<&str>) {
    std::fs::write(
        root.join("package.json"),
        format!(
            "{{\n  \"name\": \"repair-vlt\",\n  \"dependencies\": {{\n    \"{DEP}\": \"{DEP_VERSION}\"\n  }}\n}}\n"
        ),
    )
    .unwrap();
    std::fs::write(root.join("vlt-lock.json"), lock.lock()).unwrap();
    let pkg = root.join("node_modules").join(DEP);
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        pkg.join("package.json"),
        package_json
            .map(str::to_string)
            .unwrap_or_else(|| format!(r#"{{"name":"{DEP}","version":"{DEP_VERSION}"}}"#)),
    )
    .unwrap();
    std::fs::write(pkg.join("index.js"), BEFORE).unwrap();
}

/// `scan --vendor --yes` over the fixture; returns the artifact dir.
fn vendor_project(root: &Path, uri: &str, lock: VltLock) -> PathBuf {
    let (code, stdout, stderr) = run_cli(root, uri, &["scan", "--vendor", "--yes"]);
    assert_eq!(code, 0, "{lock:?}: vendor setup: {stdout}\n{stderr}");
    let dir = root.join(rel());
    assert!(dir.join("index.js").is_file(), "{lock:?}: {stdout}");
    assert!(
        std::fs::read_to_string(root.join("vlt-lock.json"))
            .unwrap()
            .contains(&rel()),
        "{lock:?}"
    );
    dir
}

fn state(root: &Path) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(root.join(".socket/vendor/state.json")).unwrap()).unwrap()
}

fn repair(root: &Path, uri: &str) -> serde_json::Value {
    let (code, stdout, stderr) = run_cli(root, uri, &["repair"]);
    assert_eq!(code, 0, "repair: {stdout}\n{stderr}");
    parse_env(&stdout)
}

fn rebuilt(v: &serde_json::Value) -> bool {
    events_of(v)
        .iter()
        .any(|e| e["action"] == "rebuilt" && e["purl"] == PURL)
}

fn inventory(root: &Path) -> serde_json::Value {
    state(root)["entries"][PURL]["artifact"]["fileInventory"].clone()
}

/// vlt's links inside the vendored package dir: a dependency link (a real
/// dir here, so the suite runs everywhere) and a `.bin` script.
fn add_vlt_links(dir: &Path) {
    std::fs::create_dir_all(dir.join("node_modules/dep")).unwrap();
    std::fs::create_dir_all(dir.join("node_modules/.bin")).unwrap();
    std::fs::write(dir.join("node_modules/.bin/tool"), "#!/bin/sh\n").unwrap();
}

#[tokio::test]
async fn vlt_repair_rebuilds_a_deleted_dir() {
    for lock in LOCKS {
        let mock = wiremock::MockServer::start().await;
        mount_patch_api(&mock).await;
        let tmp = tempfile::tempdir().unwrap();
        write_fixture(tmp.path(), lock, None);
        let dir = vendor_project(tmp.path(), &mock.uri(), lock);
        let inv = inventory(tmp.path());
        assert!(inv["index.js"].is_string(), "{lock:?}: {inv}");
        let wired = std::fs::read(tmp.path().join("vlt-lock.json")).unwrap();
        std::fs::remove_dir_all(tmp.path().join(format!(".socket/vendor/npm/{UUID}"))).unwrap();
        let v = repair(tmp.path(), &mock.uri());
        assert!(rebuilt(&v), "{lock:?}: {v}");
        assert_eq!(std::fs::read(dir.join("index.js")).unwrap(), AFTER);
        assert_eq!(inventory(tmp.path()), inv, "{lock:?}");
        assert_eq!(
            std::fs::read(tmp.path().join("vlt-lock.json")).unwrap(),
            wired,
            "{lock:?}: repair never touches the lock"
        );
        assert!(tmp
            .path()
            .join(format!(".socket/vendor/npm/{UUID}/.gitignore"))
            .is_file());
    }
}

#[tokio::test]
async fn vlt_repair_rebuilds_a_corrupt_member() {
    for lock in LOCKS {
        let mock = wiremock::MockServer::start().await;
        mount_patch_api(&mock).await;
        let tmp = tempfile::tempdir().unwrap();
        write_fixture(tmp.path(), lock, None);
        let dir = vendor_project(tmp.path(), &mock.uri(), lock);
        add_vlt_links(&dir);
        let v = repair(tmp.path(), &mock.uri());
        assert!(
            !rebuilt(&v),
            "{lock:?}: vlt's links are not a mismatch: {v}"
        );
        std::fs::write(dir.join("index.js"), b"tampered\n").unwrap();
        let v = repair(tmp.path(), &mock.uri());
        assert!(rebuilt(&v), "{lock:?}: {v}");
        assert_eq!(std::fs::read(dir.join("index.js")).unwrap(), AFTER);
        assert_eq!(inventory(tmp.path())["index.js"], common::sha256_hex(AFTER));
    }
}

#[tokio::test]
async fn vlt_repair_rebuilds_over_a_planted_file() {
    for lock in LOCKS {
        let mock = wiremock::MockServer::start().await;
        mount_patch_api(&mock).await;
        let tmp = tempfile::tempdir().unwrap();
        write_fixture(tmp.path(), lock, None);
        let dir = vendor_project(tmp.path(), &mock.uri(), lock);
        std::fs::create_dir_all(dir.join("node_modules")).unwrap();
        std::fs::write(dir.join("node_modules/evil.js"), b"planted\n").unwrap();
        let (_, stdout, _) = run_cli(tmp.path(), &mock.uri(), &["repair", "--dry-run"]);
        let dry = parse_env(&stdout);
        assert!(
            dry.to_string().contains("vendor_artifact_corrupt"),
            "{lock:?}: {dry}"
        );
        let v = repair(tmp.path(), &mock.uri());
        assert!(rebuilt(&v), "{lock:?}: {v}");
        assert!(!dir.join("node_modules/evil.js").exists(), "{lock:?}");
        assert_eq!(std::fs::read(dir.join("index.js")).unwrap(), AFTER);
    }
}

#[tokio::test]
async fn vlt_repair_reconstructs_the_ledger_from_the_lock() {
    for lock in LOCKS {
        let mock = wiremock::MockServer::start().await;
        mount_patch_api(&mock).await;
        super::mount_blob(&mock).await;
        let tmp = tempfile::tempdir().unwrap();
        write_fixture(tmp.path(), lock, None);
        vendor_project(tmp.path(), &mock.uri(), lock);
        let inv = inventory(tmp.path());
        std::fs::remove_file(tmp.path().join(".socket/vendor/state.json")).unwrap();
        let v = repair(tmp.path(), &mock.uri());
        let entry = state(tmp.path())["entries"][PURL].clone();
        assert_eq!(entry["flavor"], "vlt", "{lock:?}: {entry:#}\n{v}");
        assert_eq!(entry["artifact"]["path"], rel(), "{lock:?}");
        assert_eq!(
            entry["artifact"]["fileInventory"], inv,
            "{lock:?}: the fingerprint comes from a member-verified rebuild: {v}"
        );
        assert!(
            v["warnings"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|w| w["code"] == "vendor_wiring_unknown"),
            "{lock:?}: {v}"
        );
        let (code, stdout, _) = common::run_with_env(
            tmp.path(),
            &["vendor", "--revert", "--json"],
            &[("SOCKET_TELEMETRY_DISABLED", "1")],
        );
        let r = parse_env(&stdout);
        assert_ne!(code, 0, "{lock:?}: {r}");
        assert!(
            events_of(&r)
                .iter()
                .any(|e| e["errorCode"] == "vendor_wiring_unknown_revert_blocked"),
            "{lock:?}: the unwired guard: {r}"
        );
        assert!(tmp.path().join(rel()).join("index.js").is_file());
    }
}

#[tokio::test]
async fn vlt_orphan_sweep_keeps_a_wired_dir_leaf() {
    for lock in LOCKS {
        let mock = wiremock::MockServer::start().await;
        mount_patch_api(&mock).await;
        let tmp = tempfile::tempdir().unwrap();
        write_fixture(tmp.path(), lock, None);
        let dir = vendor_project(tmp.path(), &mock.uri(), lock);
        let other = "33333333-3333-4333-8333-333333333333";
        let orphan = tmp.path().join(format!(
            ".socket/vendor/npm/{other}/{DEP}-{DEP_VERSION}/node_modules/{DEP}"
        ));
        std::fs::create_dir_all(&orphan).unwrap();
        std::fs::write(orphan.join("index.js"), AFTER).unwrap();
        std::fs::write(
            tmp.path().join(".socket/vendor/state.json"),
            "{\"version\":1,\"entries\":{}}",
        )
        .unwrap();
        let (code, stdout, stderr) = common::run_with_env(
            tmp.path(),
            &["vendor", "--revert", "--json"],
            &[("SOCKET_TELEMETRY_DISABLED", "1")],
        );
        assert_eq!(code, 0, "{lock:?}: {stdout}\n{stderr}");
        assert!(
            dir.join("index.js").is_file(),
            "{lock:?}: the lock still installs it"
        );
        assert!(
            !tmp.path()
                .join(format!(".socket/vendor/npm/{other}"))
                .exists(),
            "{lock:?}: the unreferenced dir leaf is swept: {stdout}"
        );
    }
}

#[tokio::test]
async fn vlt_repair_restores_the_uuid_gitignore() {
    for lock in LOCKS {
        let mock = wiremock::MockServer::start().await;
        mount_patch_api(&mock).await;
        let tmp = tempfile::tempdir().unwrap();
        write_fixture(tmp.path(), lock, None);
        vendor_project(tmp.path(), &mock.uri(), lock);
        let uuid = tmp.path().join(format!(".socket/vendor/npm/{UUID}"));
        let ignore = std::fs::read(uuid.join(".gitignore")).unwrap();
        std::fs::remove_file(uuid.join(".gitignore")).unwrap();
        std::fs::write(uuid.join(".gitattributes"), "* text=auto\n").unwrap();
        let v = repair(tmp.path(), &mock.uri());
        assert!(!rebuilt(&v), "{lock:?}: no rebuild: {v}");
        assert_eq!(std::fs::read(uuid.join(".gitignore")).unwrap(), ignore);
        assert_eq!(
            std::fs::read_to_string(uuid.join(".gitattributes")).unwrap(),
            "* -text\n"
        );
    }
}

#[tokio::test]
async fn vlt_repair_keeps_a_devdependency_stripped_manifest_healthy() {
    let before_pkg =
        format!("{{\"name\":\"{DEP}\",\"version\":\"{DEP_VERSION}\",\"devDependencies\":{{\"tap\":\"1\"}}}}");
    let after_pkg = format!(
        "{{\"name\":\"{DEP}\",\"version\":\"{DEP_VERSION}\",\"main\":\"index.js\",\"devDependencies\":{{\"tap\":\"1\"}}}}"
    );
    let mock = wiremock::MockServer::start().await;
    super::mount_patch_api_with(
        &mock,
        &[(
            "package/package.json",
            before_pkg.as_bytes(),
            after_pkg.as_bytes(),
        )],
    )
    .await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(tmp.path(), VltLock::V1, Some(&before_pkg));
    let dir = vendor_project(tmp.path(), &mock.uri(), VltLock::V1);
    let committed = std::fs::read_to_string(dir.join("package.json")).unwrap();
    assert!(!committed.contains("devDependencies"), "{committed}");
    assert_eq!(
        inventory(tmp.path())["package.json"],
        common::sha256_hex(committed.as_bytes()),
    );
    for run in 0..2 {
        let v = repair(tmp.path(), &mock.uri());
        assert!(!rebuilt(&v), "[{run}] no Corrupt → rebuild loop: {v}");
        assert!(
            !v.to_string().contains("vendor_artifact_corrupt"),
            "[{run}] {v}"
        );
    }
    assert_eq!(
        std::fs::read_to_string(dir.join("package.json")).unwrap(),
        committed
    );
}
