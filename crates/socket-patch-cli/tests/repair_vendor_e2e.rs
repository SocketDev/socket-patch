//! End-to-end tests for `repair`'s vendored-artifact phase: artifacts
//! referenced by the ledger and/or rewired lockfiles but missing/corrupt on
//! disk are rebuilt fail-closed (and the ledger itself is reconstructed from
//! lockfile references when it was deleted wholesale). Mock API + real npm
//! lockfile fixtures, driven through the built binary.

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
const PURL: &str = "pkg:npm/left-pad@1.3.0";
const ENCODED: &str = "pkg%3Anpm%2Fleft-pad%401.3.0";
const BEFORE: &[u8] = b"before\n";
const AFTER: &[u8] = b"after\n";
const AFTER_B64: &str = "YWZ0ZXIK";

fn git_sha256(content: &[u8]) -> String {
    let header = format!("blob {}\0", content.len());
    let mut hasher = Sha256::new();
    hasher.update(header.as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn sri_of(bytes: &[u8]) -> String {
    use base64::Engine as _;
    use sha2::Sha512;
    format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode(Sha512::digest(bytes))
    )
}

/// A pristine registry tarball for left-pad@1.3.0 (BEFORE bytes).
fn pristine_tgz() -> Vec<u8> {
    let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
        Vec::new(),
        flate2::Compression::default(),
    ));
    for (path, bytes) in [
        (
            "package/package.json",
            br#"{"name":"left-pad","version":"1.3.0"}"#.as_slice(),
        ),
        ("package/index.js", BEFORE),
    ] {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, path, bytes).unwrap();
    }
    builder.into_inner().unwrap().finish().unwrap()
}

/// Vendorable npm project: package.json, a v3 lock whose left-pad entry
/// resolves to `resolved_url`/`integrity`, and the installed package.
fn write_fixture(root: &Path, resolved_url: &str, integrity: &str) {
    std::fs::write(
        root.join("package.json"),
        r#"{ "name": "repair-vendor-test", "version": "0.0.0" }"#,
    )
    .unwrap();
    let lock = serde_json::json!({
        "name": "repair-vendor-test",
        "version": "0.0.0",
        "lockfileVersion": 3,
        "requires": true,
        "packages": {
            "": {
                "name": "repair-vendor-test",
                "version": "0.0.0",
                "dependencies": { "left-pad": "^1.3.0" }
            },
            "node_modules/left-pad": {
                "version": "1.3.0",
                "resolved": resolved_url,
                "integrity": integrity,
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

/// Mount discovery + view for `UUID` (same shapes as scan_vendor_e2e).
async fn mount_patch_api(mock: &MockServer) {
    let before_hash = git_sha256(BEFORE);
    let after_hash = git_sha256(AFTER);
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": PURL,
                "patches": [{
                    "uuid": UUID,
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
                "uuid": UUID,
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
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": UUID,
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

/// Serve the after-blob for `--download-mode file` repairs (test 7's step 1
/// runs before the ledger is reconstructed, so its vendored entry is not
/// yet excluded from the download phase).
async fn mount_blob(mock: &MockServer) {
    Mock::given(method("GET"))
        .and(path(format!(
            "/v0/orgs/{ORG_SLUG}/patches/blob/{}",
            git_sha256(AFTER)
        )))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(AFTER))
        .mount(mock)
        .await;
}

fn run_cli(root: &Path, mock_uri: &str, argv: &[&str]) -> (i32, String, String) {
    let mut full = argv.to_vec();
    full.extend_from_slice(&[
        "--json",
        "--api-url",
        mock_uri,
        "--api-token",
        "fake-token",
        "--org",
        ORG_SLUG,
    ]);
    let out = Command::new(binary())
        .args(&full)
        .current_dir(root)
        .env("SOCKET_TELEMETRY_DISABLED", "1")
        .output()
        .expect("run");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// `scan --vendor --yes` to establish a vendored project; returns the
/// vendored tarball path.
fn vendor_project(root: &Path, mock_uri: &str, extra: &[&str]) -> PathBuf {
    let mut argv = vec!["scan", "--vendor", "--yes"];
    argv.extend_from_slice(extra);
    let (code, stdout, stderr) = run_cli(root, mock_uri, &argv);
    assert_eq!(code, 0, "vendor setup failed: {stdout} {stderr}");
    let tgz = root.join(format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz"));
    assert!(tgz.is_file(), "setup must vendor the tarball");
    tgz
}

fn parse_env(stdout: &str) -> serde_json::Value {
    serde_json::from_str(stdout.trim()).unwrap_or_else(|e| panic!("bad JSON ({e}): {stdout}"))
}

fn events_of(v: &serde_json::Value) -> Vec<serde_json::Value> {
    v["events"].as_array().cloned().unwrap_or_default()
}

/// 1. Deleted tarball → `repair` rebuilds it byte-identically (installed
///    copy + view-fetched patch content), lockfile and ledger untouched.
#[tokio::test]
async fn repair_rebuilds_deleted_vendored_tarball() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(
        tmp.path(),
        "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        "sha512-orig==",
    );
    let tgz = vendor_project(tmp.path(), &mock.uri(), &[]);
    let tgz_bytes = std::fs::read(&tgz).unwrap();
    let lock1 = std::fs::read(tmp.path().join("package-lock.json")).unwrap();
    let state1 = std::fs::read(tmp.path().join(".socket/vendor/state.json")).unwrap();

    std::fs::remove_file(&tgz).unwrap();

    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair"]);
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    let v = parse_env(&stdout);
    assert_eq!(v["summary"]["rebuilt"], 1, "envelope={v}");
    assert!(
        events_of(&v)
            .iter()
            .any(|e| e["action"] == "rebuilt" && e["purl"] == PURL),
        "envelope={v}"
    );
    assert_eq!(
        std::fs::read(&tgz).unwrap(),
        tgz_bytes,
        "deterministic rebuild must reproduce the recorded bytes"
    );
    assert_eq!(
        std::fs::read(tmp.path().join("package-lock.json")).unwrap(),
        lock1,
        "lockfile untouched"
    );
    assert_eq!(
        std::fs::read(tmp.path().join(".socket/vendor/state.json")).unwrap(),
        state1,
        "ledger untouched"
    );

    // Healthy re-run: nothing to rebuild.
    let (code, stdout, _) = run_cli(tmp.path(), &mock.uri(), &["repair"]);
    assert_eq!(code, 0);
    let v = parse_env(&stdout);
    assert!(
        v["summary"]["rebuilt"].is_null() || v["summary"]["rebuilt"] == 0,
        "healthy ledger rebuilds nothing: {v}"
    );
}

/// 2. `repair --offline` rebuilds from purely local sources (installed copy
///    + seeded blob) with zero network.
#[tokio::test]
async fn repair_offline_rebuilds_from_local_sources() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(
        tmp.path(),
        "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        "sha512-orig==",
    );
    let tgz = vendor_project(tmp.path(), &mock.uri(), &[]);
    std::fs::remove_file(&tgz).unwrap();

    // Patch content available locally: the after-blob on disk.
    let blobs = tmp.path().join(".socket/blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::write(blobs.join(git_sha256(AFTER)), AFTER).unwrap();

    let before_reqs = mock.received_requests().await.unwrap().len();
    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair", "--offline"]);
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    let v = parse_env(&stdout);
    assert_eq!(v["summary"]["rebuilt"], 1, "envelope={v}");
    assert!(tgz.is_file(), "tarball rebuilt offline");
    let after_reqs = mock.received_requests().await.unwrap().len();
    assert_eq!(
        before_reqs, after_reqs,
        "--offline must make no network requests"
    );
}

/// 3. Truncated/corrupt tarball → detected (whole-file sha vs ledger) and
///    rebuilt.
#[tokio::test]
async fn repair_rebuilds_corrupt_vendored_tarball() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(
        tmp.path(),
        "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        "sha512-orig==",
    );
    let tgz = vendor_project(tmp.path(), &mock.uri(), &[]);
    let tgz_bytes = std::fs::read(&tgz).unwrap();

    std::fs::write(&tgz, b"\x1f\x8bgarbage").unwrap();

    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair"]);
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    let v = parse_env(&stdout);
    assert_eq!(v["summary"]["rebuilt"], 1, "envelope={v}");
    assert_eq!(
        std::fs::read(&tgz).unwrap(),
        tgz_bytes,
        "rebuild restores the recorded bytes"
    );
}

/// 4. A tampered ledger sha can never be satisfied: the rebuild is removed
///    and the run fails loudly rather than leaving unverifiable bytes.
#[tokio::test]
async fn repair_fails_closed_on_tampered_ledger_sha() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(
        tmp.path(),
        "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        "sha512-orig==",
    );
    let tgz = vendor_project(tmp.path(), &mock.uri(), &[]);

    let state_path = tmp.path().join(".socket/vendor/state.json");
    let state = std::fs::read_to_string(&state_path).unwrap();
    let mut v: serde_json::Value = serde_json::from_str(&state).unwrap();
    v["entries"][PURL]["artifact"]["sha256"] = serde_json::json!("0".repeat(64));
    std::fs::write(&state_path, serde_json::to_vec_pretty(&v).unwrap()).unwrap();

    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair"]);
    assert_eq!(code, 1, "stdout={stdout} stderr={stderr}");
    let env = parse_env(&stdout);
    assert!(
        events_of(&env)
            .iter()
            .any(|e| e["action"] == "failed" && e["errorCode"] == "vendor_artifact_rebuild_failed"),
        "envelope={env}"
    );
    assert!(
        !tgz.exists(),
        "an unverifiable rebuild must not be left on disk"
    );
}

/// 5. Fresh-clone `vendor` re-run with the committed artifact AND
///    node_modules gone: the ledger's wiring original recovers the registry
///    resolution, the pristine tarball is fetched + verified, and the
///    artifact is rebuilt — exit 0 (previously a hard vendor_fetch_failed).
#[tokio::test]
async fn vendor_rerun_recovers_registry_resolution_from_ledger() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    let tgz_bytes = pristine_tgz();
    let integrity = sri_of(&tgz_bytes);
    Mock::given(method("GET"))
        .and(path("/left-pad/-/left-pad-1.3.0.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(tgz_bytes))
        .mount(&mock)
        .await;
    let tmp = tempfile::tempdir().unwrap();
    // The PRE-VENDOR lock resolves to the mock registry with the real
    // integrity — that's what the ledger preserves as the wiring original.
    write_fixture(
        tmp.path(),
        &format!("{}/left-pad/-/left-pad-1.3.0.tgz", mock.uri()),
        &integrity,
    );
    let tgz = vendor_project(tmp.path(), &mock.uri(), &[]);
    let lock1 = std::fs::read(tmp.path().join("package-lock.json")).unwrap();

    std::fs::remove_file(&tgz).unwrap();
    std::fs::remove_dir_all(tmp.path().join("node_modules")).unwrap();

    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["vendor"]);
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    let v = parse_env(&stdout);
    assert!(
        events_of(&v)
            .iter()
            .any(|e| e["errorCode"] == "vendor_artifact_missing"),
        "the missing artifact is surfaced as a warning skip: {v}"
    );
    assert!(tgz.is_file(), "artifact rebuilt from the recovered fetch");
    assert_eq!(
        std::fs::read(tmp.path().join("package-lock.json")).unwrap(),
        lock1,
        "lockfile byte-stable"
    );
}

/// 6. Detached vendoring (no manifest ever): repair rebuilds via the
///    ledger-embedded record.
#[tokio::test]
async fn repair_rebuilds_detached_entry_without_manifest() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(
        tmp.path(),
        "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        "sha512-orig==",
    );
    let tgz = vendor_project(tmp.path(), &mock.uri(), &["--detached"]);
    assert!(
        !tmp.path().join(".socket/manifest.json").exists(),
        "detached mode writes no manifest"
    );
    std::fs::remove_file(&tgz).unwrap();

    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair"]);
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    let v = parse_env(&stdout);
    assert_eq!(v["summary"]["rebuilt"], 1, "envelope={v}");
    assert!(tgz.is_file());
}

/// 7. The whole `.socket/vendor` tree (state.json included) deleted while
///    the manifest survives: repair reconstructs the ledger entry from the
///    lockfile's vendor-path reference and rebuilds the artifact.
#[tokio::test]
async fn repair_reconstructs_ledger_from_lockfile_references() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(
        tmp.path(),
        "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        "sha512-orig==",
    );
    let tgz = vendor_project(tmp.path(), &mock.uri(), &[]);
    let lock1 = std::fs::read(tmp.path().join("package-lock.json")).unwrap();

    std::fs::remove_dir_all(tmp.path().join(".socket/vendor")).unwrap();

    // With the ledger gone, step 1 sees the manifest entry as un-vendored
    // and downloads its source; serve the blob and use file mode.
    mount_blob(&mock).await;
    let (code, stdout, stderr) = run_cli(
        tmp.path(),
        &mock.uri(),
        &["repair", "--download-mode", "file"],
    );
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    let v = parse_env(&stdout);
    assert_eq!(v["summary"]["rebuilt"], 1, "envelope={v}");
    assert!(tgz.is_file(), "artifact rebuilt");
    assert_eq!(
        std::fs::read(tmp.path().join("package-lock.json")).unwrap(),
        lock1,
        "lockfile untouched"
    );

    // The re-synthesized ledger entry: same uuid, fingerprint of the
    // rebuilt bytes, NOT detached (the manifest still has the record).
    let state: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(tmp.path().join(".socket/vendor/state.json")).unwrap(),
    )
    .unwrap();
    let entry = &state["entries"][PURL];
    assert_eq!(entry["uuid"], UUID, "state={state}");
    assert!(entry["detached"].is_null(), "state={state}");
    assert_eq!(
        entry["artifact"]["sha256"],
        sha256_hex(&std::fs::read(&tgz).unwrap()),
        "recomputed fingerprint matches the rebuilt artifact: {state}"
    );

    // Revert degrades gracefully (no recorded originals): exit 0, artifact
    // removed, the drifted-entry guidance surfaced.
    let (code, stdout, _) = run_cli(tmp.path(), &mock.uri(), &["vendor", "--revert"]);
    assert_eq!(code, 0, "revert of a reconstructed entry: {stdout}");
    assert!(!tgz.exists(), "revert removed the artifact");
}

/// 7b. Only `state.json` was lost; the committed artifact survived INTACT.
///     Repair restores the ledger entry from the lockfile reference without
///     rebuilding — the artifact bytes stay untouched and the re-synthesized
///     entry fingerprints them.
#[tokio::test]
async fn repair_restores_ledger_for_intact_surviving_artifact() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(
        tmp.path(),
        "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        "sha512-orig==",
    );
    let tgz = vendor_project(tmp.path(), &mock.uri(), &[]);
    let vendored_bytes = std::fs::read(&tgz).unwrap();

    std::fs::remove_file(tmp.path().join(".socket/vendor/state.json")).unwrap();

    mount_blob(&mock).await;
    let (code, stdout, stderr) = run_cli(
        tmp.path(),
        &mock.uri(),
        &["repair", "--download-mode", "file"],
    );
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    let v = parse_env(&stdout);
    assert!(
        events_of(&v)
            .iter()
            .any(|e| e["action"] == "rebuilt" && e["details"]["ledgerRestored"] == true),
        "envelope={v}"
    );
    assert_eq!(
        std::fs::read(&tgz).unwrap(),
        vendored_bytes,
        "an intact artifact is restored, not rebuilt"
    );
    let state: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(tmp.path().join(".socket/vendor/state.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        state["entries"][PURL]["artifact"]["sha256"],
        sha256_hex(&vendored_bytes),
        "state={state}"
    );
}

/// 7c. `state.json` lost AND the surviving artifact DRIFTED from the wired
///     lock integrity while its patched members still verify (an unpatched
///     member was altered — exactly the drift the whole-file ledger sha
///     would have caught, but the re-synthesized entry has no sha yet).
///     Reconstruction must not bless the drifted bytes into the new ledger:
///     the artifact is rebuilt and reproduces the wired integrity.
#[tokio::test]
async fn repair_ledger_reconstruction_rejects_drifted_surviving_artifact() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(
        tmp.path(),
        "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        "sha512-orig==",
    );
    let tgz = vendor_project(tmp.path(), &mock.uri(), &[]);
    let lock: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap(),
    )
    .unwrap();
    let wired_sri = lock["packages"]["node_modules/left-pad"]["integrity"]
        .as_str()
        .expect("vendor wired the lock integrity")
        .to_string();

    std::fs::remove_file(tmp.path().join(".socket/vendor/state.json")).unwrap();
    // Drift: an UNPATCHED member changes; the patched member keeps its
    // AFTER bytes, so per-file afterHashes still verify.
    let mut drifted = tar::Builder::new(flate2::write::GzEncoder::new(
        Vec::new(),
        flate2::Compression::default(),
    ));
    for (p, bytes) in [
        (
            "package/package.json",
            br#"{"name":"left-pad","version":"1.3.0","scripts":{"postinstall":"evil"}}"#.as_slice(),
        ),
        ("package/index.js", AFTER),
    ] {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        drifted.append_data(&mut header, p, bytes).unwrap();
    }
    let drifted = drifted.into_inner().unwrap().finish().unwrap();
    assert_ne!(sri_of(&drifted), wired_sri, "fixture must actually drift");
    std::fs::write(&tgz, &drifted).unwrap();

    mount_blob(&mock).await;
    let (code, stdout, stderr) = run_cli(
        tmp.path(),
        &mock.uri(),
        &["repair", "--download-mode", "file"],
    );
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    let v = parse_env(&stdout);
    // THE regression: after a successful repair the committed artifact must
    // be the bytes the rewired lock records — not the drifted ones blessed
    // into the reconstructed ledger.
    assert_eq!(
        sri_of(&std::fs::read(&tgz).unwrap()),
        wired_sri,
        "envelope={v}"
    );
    let state: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(tmp.path().join(".socket/vendor/state.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        state["entries"][PURL]["artifact"]["sha256"],
        sha256_hex(&std::fs::read(&tgz).unwrap()),
        "state={state}"
    );
}

/// 8. No ledger AND no manifest — only the rewired lockfile: the uuid in
///    the lock path drives an API view fetch and the entry is re-created
///    DETACHED (manifest-invisible), with the artifact rebuilt.
#[tokio::test]
async fn repair_reconstructs_detached_from_lockfile_only() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(
        tmp.path(),
        "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        "sha512-orig==",
    );
    let tgz = vendor_project(tmp.path(), &mock.uri(), &[]);

    std::fs::remove_dir_all(tmp.path().join(".socket")).unwrap();

    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair"]);
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    let v = parse_env(&stdout);
    assert_eq!(v["summary"]["rebuilt"], 1, "envelope={v}");
    assert!(tgz.is_file(), "artifact rebuilt");

    let state: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(tmp.path().join(".socket/vendor/state.json")).unwrap(),
    )
    .unwrap();
    let entry = &state["entries"][PURL];
    assert_eq!(entry["uuid"], UUID, "state={state}");
    assert_eq!(
        entry["detached"], true,
        "manifest-less reconstruction is detached: {state}"
    );
    assert_eq!(
        entry["record"]["uuid"], UUID,
        "the record is embedded for future repairs/VEX: {state}"
    );
}

/// 9. The hardest reconstruction: no ledger, no manifest help needed beyond
///    the record, and NO installed copy. The rewired lockfile's recorded
///    integrity is the trust anchor: the pristine tarball is fetched
///    unverified from the conventional registry URL and the REBUILT
///    artifact must reproduce the wired integrity.
#[tokio::test]
async fn repair_reconstructs_without_installed_copy_via_wired_integrity() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    Mock::given(method("GET"))
        .and(path("/left-pad/-/left-pad-1.3.0.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(pristine_tgz()))
        .mount(&mock)
        .await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(
        tmp.path(),
        "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        "sha512-orig==",
    );
    let tgz = vendor_project(tmp.path(), &mock.uri(), &[]);

    // Fresh-clone hole: vendor tree gone AND nothing installed.
    std::fs::remove_dir_all(tmp.path().join(".socket/vendor")).unwrap();
    std::fs::remove_dir_all(tmp.path().join("node_modules")).unwrap();

    mount_blob(&mock).await;
    let out = Command::new(binary())
        .args([
            "repair",
            "--download-mode",
            "file",
            "--json",
            "--api-url",
            &mock.uri(),
            "--api-token",
            "fake-token",
            "--org",
            ORG_SLUG,
        ])
        .current_dir(tmp.path())
        .env("SOCKET_TELEMETRY_DISABLED", "1")
        .env("SOCKET_NPM_REGISTRY", mock.uri())
        .output()
        .expect("run");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stdout={stdout} stderr={stderr}"
    );
    let v = parse_env(&stdout);
    assert_eq!(v["summary"]["rebuilt"], 1, "envelope={v}");
    assert!(tgz.is_file(), "artifact rebuilt from the unverified fetch");

    // The rebuilt tarball's integrity is exactly what the lock records.
    let lock = std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap();
    let rebuilt_sri = sri_of(&std::fs::read(&tgz).unwrap());
    assert!(
        lock.contains(&rebuilt_sri),
        "rebuilt sri {rebuilt_sri} must be the wired one; lock={lock}"
    );
}

/// 10. A tampered pristine source changes the deterministic rebuild, which
///     then fails the wired-integrity check: nothing is kept, exit 1.
#[tokio::test]
async fn repair_reconstruction_rejects_tampered_pristine_source() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    // The "registry" serves a tarball whose non-patched member differs.
    let mut tampered = tar::Builder::new(flate2::write::GzEncoder::new(
        Vec::new(),
        flate2::Compression::default(),
    ));
    for (p, bytes) in [
        (
            "package/package.json",
            br#"{"name":"left-pad","version":"1.3.0","scripts":{"postinstall":"evil"}}"#.as_slice(),
        ),
        ("package/index.js", BEFORE),
    ] {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tampered.append_data(&mut header, p, bytes).unwrap();
    }
    let tampered = tampered.into_inner().unwrap().finish().unwrap();
    Mock::given(method("GET"))
        .and(path("/left-pad/-/left-pad-1.3.0.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(tampered))
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    write_fixture(
        tmp.path(),
        "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        "sha512-orig==",
    );
    let tgz = vendor_project(tmp.path(), &mock.uri(), &[]);
    std::fs::remove_dir_all(tmp.path().join(".socket/vendor")).unwrap();
    std::fs::remove_dir_all(tmp.path().join("node_modules")).unwrap();

    mount_blob(&mock).await;
    let out = Command::new(binary())
        .args([
            "repair",
            "--download-mode",
            "file",
            "--json",
            "--api-url",
            &mock.uri(),
            "--api-token",
            "fake-token",
            "--org",
            ORG_SLUG,
        ])
        .current_dir(tmp.path())
        .env("SOCKET_TELEMETRY_DISABLED", "1")
        .env("SOCKET_NPM_REGISTRY", mock.uri())
        .output()
        .expect("run");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(1), "stdout={stdout}");
    let v = parse_env(&stdout);
    assert!(
        events_of(&v).iter().any(|e| e["action"] == "failed"
            && e["errorCode"] == "vendor_artifact_rebuild_failed"
            && e["error"]
                .as_str()
                .unwrap_or("")
                .contains("integrity the lockfile records")),
        "envelope={v}"
    );
    assert!(!tgz.exists(), "a tampered rebuild must not be kept");
}

/// Dry run previews the rebuild without touching disk.
#[tokio::test]
async fn repair_dry_run_previews_rebuild() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(
        tmp.path(),
        "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        "sha512-orig==",
    );
    let tgz = vendor_project(tmp.path(), &mock.uri(), &[]);
    std::fs::remove_file(&tgz).unwrap();

    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair", "--dry-run"]);
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    let v = parse_env(&stdout);
    assert!(
        events_of(&v).iter().any(|e| e["action"] == "verified"
            && e["details"]["wouldRebuild"] == true
            && e["purl"] == PURL),
        "envelope={v}"
    );
    assert!(!tgz.exists(), "dry run writes nothing");
}

/// Offline with a broken artifact and NO local sources: a calm, loud,
/// per-entry failure naming the purl and the path; exit 1.
#[tokio::test]
async fn repair_offline_without_sources_fails_loudly() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(
        tmp.path(),
        "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        "sha512-orig==",
    );
    let tgz = vendor_project(tmp.path(), &mock.uri(), &[]);
    std::fs::remove_file(&tgz).unwrap();
    // No installed copy either — and no local patch sources.
    std::fs::remove_dir_all(tmp.path().join("node_modules")).unwrap();

    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair", "--offline"]);
    assert_eq!(code, 1, "stdout={stdout} stderr={stderr}");
    let v = parse_env(&stdout);
    let failed: Vec<_> = events_of(&v)
        .into_iter()
        .filter(|e| e["action"] == "failed")
        .collect();
    assert!(
        failed
            .iter()
            .any(|e| e["purl"] == PURL && e["error"].as_str().unwrap_or("").contains("--offline")),
        "the failure names the purl and the offline cause: {v}"
    );
    assert!(!tgz.exists());
}
