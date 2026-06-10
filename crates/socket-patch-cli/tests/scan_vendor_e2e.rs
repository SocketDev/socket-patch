//! End-to-end tests for `scan --vendor` (and `--detached`) — the bot
//! workflow that discovers patches, downloads them, and vendors each
//! patched package into the committable `.socket/vendor/` tree instead
//! of applying in place. Mock API + a real npm lockfile fixture, driven
//! through the built binary.

use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

const ORG_SLUG: &str = "test-org";
const UUID: &str = "11111111-1111-4111-8111-111111111111";
const NEW_UUID: &str = "22222222-2222-4222-8222-222222222222";
const PURL: &str = "pkg:npm/left-pad@1.3.0";
const ENCODED: &str = "pkg%3Anpm%2Fleft-pad%401.3.0";
const BEFORE: &[u8] = b"before\n";
const AFTER: &[u8] = b"after\n";
/// base64 of AFTER, inlined as the view response's blobContent.
const AFTER_B64: &str = "YWZ0ZXIK";

fn git_sha256(content: &[u8]) -> String {
    let header = format!("blob {}\0", content.len());
    let mut hasher = Sha256::new();
    hasher.update(header.as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

/// A vendorable npm project: root package.json, a v3 package-lock with a
/// registry-resolved left-pad entry, and the installed package.
fn write_fixture(root: &Path) {
    std::fs::write(
        root.join("package.json"),
        r#"{ "name": "scan-vendor-test", "version": "0.0.0" }"#,
    )
    .unwrap();
    let lock = serde_json::json!({
        "name": "scan-vendor-test",
        "version": "0.0.0",
        "lockfileVersion": 3,
        "requires": true,
        "packages": {
            "": {
                "name": "scan-vendor-test",
                "version": "0.0.0",
                "dependencies": { "left-pad": "^1.3.0" }
            },
            "node_modules/left-pad": {
                "version": "1.3.0",
                "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
                "integrity": "sha512-orig==",
                "license": "WTFPL"
            }
        }
    });
    let mut lock_bytes = serde_json::to_vec_pretty(&lock).unwrap();
    lock_bytes.push(b'\n');
    std::fs::write(root.join("package-lock.json"), lock_bytes).unwrap();

    let pkg = root.join("node_modules/left-pad");
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        pkg.join("package.json"),
        br#"{"name":"left-pad","version":"1.3.0"}"#,
    )
    .unwrap();
    std::fs::write(pkg.join("index.js"), BEFORE).unwrap();
}

/// Mount discovery (batch), per-package search, and the full view for
/// `uuid` on the mock server.
async fn mount_patch_api(mock: &MockServer, uuid: &str) {
    let before_hash = git_sha256(BEFORE);
    let after_hash = git_sha256(AFTER);
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": PURL,
                "patches": [{
                    "uuid": uuid,
                    "purl": PURL,
                    "tier": "free",
                    "cveIds": ["CVE-2026-0001"],
                    "ghsaIds": [],
                    "severity": "high",
                    "title": "vendor target"
                }]
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(mock)
        .await;
    Mock::given(method("GET"))
        .and(path(format!(
            "/v0/orgs/{ORG_SLUG}/patches/by-package/{ENCODED}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [{
                "uuid": uuid,
                "purl": PURL,
                "publishedAt": "2026-01-01T00:00:00Z",
                "description": "Vendor patch",
                "license": "MIT",
                "tier": "free",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(mock)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/view/{uuid}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": uuid,
            "purl": PURL,
            "publishedAt": "2026-01-01T00:00:00Z",
            "files": {
                "package/index.js": {
                    "beforeHash": before_hash,
                    "afterHash":  after_hash,
                    "blobContent": AFTER_B64,
                }
            },
            "vulnerabilities": {
                "GHSA-aaaa-bbbb-cccc": {
                    "cves": ["CVE-2026-0001"],
                    "summary": "test vuln",
                    "severity": "high",
                    "description": "details"
                }
            },
            "description": "Vendor patch",
            "license": "MIT",
            "tier": "free",
        })))
        .mount(mock)
        .await;
}

fn run_scan_vendor(root: &Path, mock_uri: &str, extra: &[&str]) -> (i32, String, String) {
    let mut argv = vec![
        "scan",
        "--json",
        "--vendor",
        "--yes",
        "--api-url",
        mock_uri,
        "--api-token",
        "fake-token",
        "--org",
        ORG_SLUG,
    ];
    argv.extend_from_slice(extra);
    let out = Command::new(binary())
        .args(&argv)
        .current_dir(root)
        .output()
        .expect("run");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[tokio::test]
async fn scan_vendor_manifest_mode_end_to_end() {
    // scan --vendor: discover → download (manifest written) → vendor.
    let mock = MockServer::start().await;
    mount_patch_api(&mock, UUID).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(tmp.path());

    let (code, stdout, stderr) = run_scan_vendor(tmp.path(), &mock.uri(), &[]);
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(v["status"], "success", "envelope={v}");

    // Download phase: manifest written with the patch, blob staged.
    let dl = v["download"].as_object().expect("download sub-object");
    assert_eq!(dl["downloaded"], 1, "download={dl:?}");
    assert_eq!(dl["failed"], 0, "download={dl:?}");
    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(tmp.path().join(".socket/manifest.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        manifest["patches"][PURL]["uuid"], UUID,
        "manifest={manifest}"
    );

    // Vendor phase: a full vendor Envelope with one applied event.
    let venv = v["vendor"].as_object().expect("vendor sub-object");
    assert_eq!(venv["command"], "vendor", "vendor={venv:?}");
    assert_eq!(venv["status"], "success", "vendor={venv:?}");
    assert_eq!(venv["summary"]["applied"], 1, "vendor={venv:?}");

    // Disk: tarball at the contract path, ledger entry NOT detached,
    // lock rewired to consume the vendored artifact.
    let tgz = tmp
        .path()
        .join(format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz"));
    assert!(tgz.is_file(), "vendored tarball must exist");
    let state: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(tmp.path().join(".socket/vendor/state.json")).unwrap(),
    )
    .unwrap();
    let entry = &state["entries"][PURL];
    assert_eq!(entry["uuid"], UUID, "state={state}");
    assert!(
        entry["detached"].is_null(),
        "manifest-mode entries are not detached: {state}"
    );
    assert!(entry["record"].is_null(), "no embedded record: {state}");
    let lock = std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap();
    assert!(
        lock.contains(&format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz")),
        "lock must consume the vendored tarball; lock={lock}"
    );
    // The installed tree is untouched — vendoring is not an in-place apply.
    assert_eq!(
        std::fs::read(tmp.path().join("node_modules/left-pad/index.js")).unwrap(),
        BEFORE,
        "installed tree stays pristine"
    );

    // Idempotent re-run: already_vendored skip, zero new applies.
    let (code, stdout, stderr) = run_scan_vendor(tmp.path(), &mock.uri(), &[]);
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    let v2: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(v2["status"], "success", "envelope={v2}");
    assert_eq!(v2["vendor"]["summary"]["applied"], 0, "envelope={v2}");
    let events = v2["vendor"]["events"].as_array().expect("events");
    assert!(
        events
            .iter()
            .any(|e| e["action"] == "skipped" && e["errorCode"] == "already_vendored"),
        "re-run must be an already_vendored skip: {v2}"
    );
}

#[tokio::test]
async fn scan_vendor_detached_mode_writes_no_manifest() {
    // scan --vendor --detached: the ledger (with embedded records) is the
    // only state — .socket/manifest.json is never created.
    let mock = MockServer::start().await;
    mount_patch_api(&mock, UUID).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(tmp.path());

    let (code, stdout, stderr) = run_scan_vendor(
        tmp.path(),
        &mock.uri(),
        &["--detached", "--vex", "out.vex.json"],
    );
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(v["status"], "success", "envelope={v}");
    assert_eq!(v["download"]["detached"], true, "envelope={v}");
    assert_eq!(v["vendor"]["summary"]["applied"], 1, "envelope={v}");

    // Embedded VEX works manifest-less: the detached entry's embedded
    // record is the attestation source.
    assert_eq!(v["vex"]["statements"], 1, "envelope={v}");
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(tmp.path().join("out.vex.json")).unwrap())
            .unwrap();
    let stmts = doc["statements"].as_array().expect("statements");
    assert_eq!(stmts.len(), 1, "doc={doc}");
    assert!(
        stmts[0]["impact_statement"]
            .as_str()
            .unwrap()
            .contains("(vendored)"),
        "doc={doc}"
    );

    assert!(
        !tmp.path().join(".socket/manifest.json").exists(),
        "detached mode must not create a manifest"
    );
    let state: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(tmp.path().join(".socket/vendor/state.json")).unwrap(),
    )
    .unwrap();
    let entry = &state["entries"][PURL];
    assert_eq!(entry["detached"], true, "state={state}");
    assert_eq!(entry["uuid"], UUID, "state={state}");
    let record = entry["record"]
        .as_object()
        .unwrap_or_else(|| panic!("detached entry must embed its record: {state}"));
    assert_eq!(record["uuid"], UUID, "record={record:?}");
    assert_eq!(
        record["files"]["package/index.js"]["afterHash"],
        git_sha256(AFTER),
        "record={record:?}"
    );
    assert!(
        record["vulnerabilities"]["GHSA-aaaa-bbbb-cccc"].is_object(),
        "vulnerabilities embedded for VEX: {record:?}"
    );
    assert!(tmp
        .path()
        .join(format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz"))
        .is_file());
    let lock = std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap();
    assert!(lock.contains(&format!(".socket/vendor/npm/{UUID}/")));

    // Idempotent re-run: the ledger's embedded record short-circuits the
    // view fetch entirely (request-log proof) and the backend skips.
    let before_reqs = mock.received_requests().await.unwrap().len();
    let (code, stdout, _) = run_scan_vendor(tmp.path(), &mock.uri(), &["--detached"]);
    assert_eq!(code, 0, "stdout={stdout}");
    let v2: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(v2["download"]["skipped"], 1, "envelope={v2}");
    assert_eq!(v2["download"]["downloaded"], 0, "envelope={v2}");
    let after_reqs = mock.received_requests().await.unwrap();
    assert!(
        !after_reqs[before_reqs..]
            .iter()
            .any(|r| r.url.path().contains("/patches/view/")),
        "idempotent detached re-run must not re-fetch the patch view"
    );
}

#[tokio::test]
async fn scan_vendor_dry_run_previews_without_touching_disk() {
    // Pre-vendored at UUID; discovery now offers NEW_UUID. The dry run
    // must classify it as would_revendor (oldUuid = UUID) and write
    // nothing — no view fetch, no lock edit, no vendor tree change.
    let mock = MockServer::start().await;
    mount_patch_api(&mock, NEW_UUID).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(tmp.path());
    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(socket.join("vendor")).unwrap();
    std::fs::write(
        socket.join("vendor/state.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "version": 1,
            "entries": { PURL: {
                "ecosystem": "npm",
                "basePurl": PURL,
                "uuid": UUID,
                "artifact": {
                    "path": format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz"),
                },
                "wiring": []
            }}
        }))
        .unwrap(),
    )
    .unwrap();
    let lock_before = std::fs::read(tmp.path().join("package-lock.json")).unwrap();

    let (code, stdout, stderr) = run_scan_vendor(tmp.path(), &mock.uri(), &["--dry-run"]);
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    let patches = v["vendor"]["patches"].as_array().expect("vendor preview");
    assert_eq!(patches.len(), 1, "envelope={v}");
    assert_eq!(patches[0]["purl"], PURL);
    assert_eq!(patches[0]["action"], "would_revendor", "envelope={v}");
    assert_eq!(patches[0]["oldUuid"], UUID, "envelope={v}");
    assert_eq!(patches[0]["uuid"], NEW_UUID, "envelope={v}");

    assert!(
        !tmp.path().join(".socket/manifest.json").exists(),
        "dry run must not write a manifest"
    );
    assert_eq!(
        std::fs::read(tmp.path().join("package-lock.json")).unwrap(),
        lock_before,
        "dry run must not edit the lock"
    );
    let reqs = mock.received_requests().await.unwrap();
    assert!(
        !reqs.iter().any(|r| r.url.path().contains("/patches/view/")),
        "dry run must not download patch views"
    );
}

#[tokio::test]
async fn scan_vendor_flag_conflicts_are_clap_errors() {
    // --vendor conflicts with --apply/--sync; --detached requires --vendor.
    for argv in [
        &["scan", "--vendor", "--apply"][..],
        &["scan", "--vendor", "--sync"][..],
        &["scan", "--detached"][..],
    ] {
        let out = Command::new(binary())
            .args(argv)
            .env("SOCKET_TELEMETRY_DISABLED", "1")
            .output()
            .expect("run");
        let code = out.status.code().unwrap_or(-1);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(
            code, 2,
            "argv={argv:?} must be a clap usage error: {stderr}"
        );
        assert!(
            stderr.contains("cannot be used with") || stderr.contains("required"),
            "argv={argv:?}: {stderr}"
        );
    }
}
