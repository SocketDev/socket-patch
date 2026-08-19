//! End-to-end tests for `repair`'s vendored-artifact phase: artifacts
//! referenced by the ledger and/or rewired lockfiles but missing/corrupt on
//! disk are rebuilt fail-closed (and the ledger itself is reconstructed from
//! lockfile references when it was deleted wholesale). Mock API + real npm
//! lockfile fixtures, driven through the built binary.
//!
//! The gem rows exercise the dir-shaped counterparts: whole-tree
//! fileInventory tamper detection, full wiring reconstruction from the live
//! Gemfile/lock pair (revert then byte-restores), and the loud empty-wiring
//! revert refusal. Their fixture pair is hand-written, modeled byte-for-byte
//! on real `bundle lock` output (bundler 4.0.15).

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

/// Run-level `warnings[]` (`{code, detail}`); empty when omitted.
fn warnings_of(v: &serde_json::Value) -> Vec<serde_json::Value> {
    v["warnings"].as_array().cloned().unwrap_or_default()
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

/// 3b. Corrupt tarball with NO rebuild source: the per-entry failure must
///     PRESERVE the corrupt-but-diagnosable bytes. Deleting them (as the
///     old delete-corrupt-first pass did) converts an integrity-mismatch
///     state into a bare ENOENT on the next install — the lock still
///     points at the tarball — and destroys the forensic evidence of the
///     tamper. Both no-source rungs are pinned: patch content missing
///     (staging unavailable) and patch content present but the pristine
///     package unreachable (--offline, node_modules gone). RED before the
///     rebuild-source-first ordering: the uuid dir was emptied up front
///     and both arms left it bare.
#[tokio::test]
async fn repair_keeps_corrupt_artifact_when_no_rebuild_source_exists() {
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

    const GARBAGE: &[u8] = b"\x1f\x8bgarbage";
    std::fs::write(&tgz, GARBAGE).unwrap();
    std::fs::remove_dir_all(tmp.path().join("node_modules")).unwrap();

    // Arm 1: no local patch sources either — the staging step itself has
    // nothing to rebuild from.
    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair", "--offline"]);
    assert_eq!(code, 1, "stdout={stdout} stderr={stderr}");
    let v = parse_env(&stdout);
    assert!(
        events_of(&v).iter().any(|e| e["action"] == "failed"
            && e["purl"] == PURL
            && e["error"].as_str().unwrap_or("").contains("--offline")),
        "the failure names the purl and the offline cause: {v}"
    );
    assert_eq!(
        std::fs::read(&tgz).unwrap(),
        GARBAGE,
        "arm 1: an unrebuildable corrupt artifact must not be destroyed"
    );

    // Arm 2: patch content IS local (seeded after-blob), but the pristine
    // package ladder still has no source — the corrupt copy must survive
    // the deeper rung too.
    let blobs = tmp.path().join(".socket/blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::write(blobs.join(git_sha256(AFTER)), AFTER).unwrap();
    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair", "--offline"]);
    assert_eq!(code, 1, "stdout={stdout} stderr={stderr}");
    let v = parse_env(&stdout);
    assert!(
        events_of(&v).iter().any(|e| e["action"] == "failed"
            && e["purl"] == PURL
            && e["error"].as_str().unwrap_or("").contains("--offline")),
        "the failure names the purl and the offline cause: {v}"
    );
    assert_eq!(
        std::fs::read(&tgz).unwrap(),
        GARBAGE,
        "arm 2: an unrebuildable corrupt artifact must not be destroyed"
    );

    // Heal: with the installed copy restored, the same repair rebuilds the
    // recorded bytes — retention never wedges the corrupt→rebuild path.
    let pkg = tmp.path().join("node_modules/left-pad");
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        pkg.join("package.json"),
        br#"{"name":"left-pad","version":"1.3.0"}"#,
    )
    .unwrap();
    std::fs::write(pkg.join("index.js"), BEFORE).unwrap();
    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair", "--offline"]);
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    let v = parse_env(&stdout);
    assert_eq!(v["summary"]["rebuilt"], 1, "envelope={v}");
    assert_eq!(
        std::fs::read(&tgz).unwrap(),
        tgz_bytes,
        "rebuild restores the recorded bytes once a source exists"
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
    // npm wiring originals are registry integrity material repair cannot
    // reconstruct offline: the gap is a run-level ADVISORY (the entry
    // itself repaired fine), so it rides `warnings[]` naming the purl —
    // never `events[]` as a `skipped` a consumer would count as work not
    // done.
    assert!(
        warnings_of(&v)
            .iter()
            .any(|w| w["code"] == "vendor_wiring_unknown"
                && w["detail"].as_str().unwrap_or("").contains(PURL)),
        "the wiring gap rides run-level warnings[] with the purl: {v}"
    );
    assert!(
        !events_of(&v)
            .iter()
            .any(|e| e["errorCode"] == "vendor_wiring_unknown"),
        "no skipped event for the run-level advisory: {v}"
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

    // Revert fails CLOSED: there are no recorded originals to replay and
    // the rewired lock still resolves through the artifact — removing it
    // would brick every later `npm ci` (see test 12 for the full recovery
    // arc).
    let (code, stdout, _) = run_cli(tmp.path(), &mock.uri(), &["vendor", "--revert"]);
    assert_ne!(
        code, 0,
        "revert of a still-wired reconstructed entry must refuse: {stdout}"
    );
    let v = parse_env(&stdout);
    assert!(
        events_of(&v)
            .iter()
            .any(|e| e["errorCode"] == "vendor_wiring_unknown_revert_blocked"),
        "envelope={v}"
    );
    assert!(tgz.exists(), "the artifact the lock references survives");
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

/// 7d. `.socket/vendor` deleted wholesale AND the installed copy's UNPATCHED
///     member tampered (the patched file keeps its pristine bytes, so the
///     backend's per-file checks all pass). The reconstruction rebuilds from
///     the installed copy, so the rebuilt artifact cannot reproduce the wired
///     lock integrity — the same trust anchor tests 9/10 enforce for the
///     unverified-fetch rung. It must be rejected fail-closed (nothing kept,
///     exit 1), never blessed into the reconstructed ledger while `npm ci`
///     stays broken.
#[tokio::test]
async fn repair_reconstruction_rejects_tampered_installed_copy() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(
        tmp.path(),
        "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        "sha512-orig==",
    );
    let tgz = vendor_project(tmp.path(), &mock.uri(), &[]);

    std::fs::remove_dir_all(tmp.path().join(".socket/vendor")).unwrap();
    // Tamper the installed copy's UNPATCHED member; name/version stay intact
    // so the crawler still finds the package, and the patched index.js keeps
    // its BEFORE bytes so per-file hash checks pass.
    std::fs::write(
        tmp.path().join("node_modules/left-pad/package.json"),
        br#"{"name":"left-pad","version":"1.3.0","scripts":{"postinstall":"evil"}}"#,
    )
    .unwrap();

    mount_blob(&mock).await;
    let (code, stdout, stderr) = run_cli(
        tmp.path(),
        &mock.uri(),
        &["repair", "--download-mode", "file"],
    );
    assert_eq!(code, 1, "stdout={stdout} stderr={stderr}");
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
    assert!(
        !tgz.exists(),
        "a rebuild that cannot reproduce the wired integrity must not be kept"
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

/// 12. The flavor-None brick, exactly as observed empirically (real project,
///     2026-08-18): only `state.json` is lost, the artifact and the rewired
///     `package-lock.json` survive. `repair` reconstructs the entry with
///     EMPTY wiring (npm pre-vendor lock fragments are not
///     offline-recoverable) — and `vendor --revert` of that entry used to
///     exit 0 while DELETING the tarball the lock still resolves through,
///     silently bricking every later `npm ci` (ENOENT on the file: spec).
///     Now: the revert fails closed (`vendor_wiring_unknown_revert_blocked`),
///     the artifact and lock survive, `repair` stays idempotent, and once
///     the pre-vendor lock is restored a normal revert removes the orphaned
///     artifact cleanly. The reconstruction also stamps the flavor it found
///     the reference in (`package-lock`), so revert routes to the backend
///     whose guard probes the RIGHT lockfile.
#[tokio::test]
async fn revert_of_reconstructed_package_lock_entry_fails_closed_then_recovers() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(
        tmp.path(),
        "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        "sha512-orig==",
    );
    let lock_pre = std::fs::read(tmp.path().join("package-lock.json")).unwrap();
    let tgz = vendor_project(tmp.path(), &mock.uri(), &[]);
    let lock_vendored = std::fs::read(tmp.path().join("package-lock.json")).unwrap();

    // Ledger gone; artifact + rewired lock intact (the empirical shape).
    // The anchored reconstruction restores the entry with wiring: [].
    std::fs::remove_file(tmp.path().join(".socket/vendor/state.json")).unwrap();
    mount_blob(&mock).await;
    let (code, stdout, stderr) = run_cli(
        tmp.path(),
        &mock.uri(),
        &["repair", "--download-mode", "file"],
    );
    assert_eq!(code, 0, "reconstruction: stdout={stdout} stderr={stderr}");
    let state_path = tmp.path().join(".socket/vendor/state.json");
    let state: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&state_path).unwrap()).unwrap();
    assert_eq!(
        state["entries"][PURL]["wiring"].as_array().map(Vec::len),
        Some(0),
        "npm wiring is not offline-recoverable: {state}"
    );
    let stamped_flavor = state["entries"][PURL]["flavor"].clone();

    // Nothing to replay + the lock still resolves through the artifact:
    // revert must refuse loudly instead of silently removing the tarball.
    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["vendor", "--revert"]);
    assert_ne!(
        code, 0,
        "revert of an empty-wiring entry the lock still references must fail closed: \
         stdout={stdout} stderr={stderr}"
    );
    let v = parse_env(&stdout);
    assert!(
        events_of(&v)
            .iter()
            .any(|e| e["errorCode"] == "vendor_wiring_unknown_revert_blocked"),
        "envelope={v}"
    );
    assert!(
        tgz.is_file(),
        "the artifact the lock still references must survive the refusal"
    );
    assert_eq!(
        std::fs::read(tmp.path().join("package-lock.json")).unwrap(),
        lock_vendored,
        "the lock stays untouched by the refusal"
    );

    // The reconstruction identified the referencing lockfile, so the entry
    // carries the detected flavor — not None (which would depend on the
    // flavor-None fallback route for its guard).
    assert_eq!(
        stamped_flavor,
        serde_json::json!("package-lock"),
        "reconstruction stamps the detected flavor"
    );

    // Recovery, exactly as the refusal advises: `repair` keeps the vendored
    // artifact healthy (idempotent — the entry and tarball survive)...
    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair"]);
    assert_eq!(
        code, 0,
        "repair after refusal: stdout={stdout} stderr={stderr}"
    );
    assert!(tgz.is_file(), "repair keeps the artifact");

    // ...and once the pre-vendor lock is restored (the manual-restore arm —
    // the wiring originals are unrecoverable by design), a normal revert
    // removes the now-orphaned artifact cleanly.
    std::fs::write(tmp.path().join("package-lock.json"), &lock_pre).unwrap();
    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["vendor", "--revert"]);
    assert_eq!(code, 0, "final revert: stdout={stdout} stderr={stderr}");
    let v = parse_env(&stdout);
    assert!(
        events_of(&v)
            .iter()
            .any(|e| e["action"] == "removed" && e["purl"] == PURL),
        "envelope={v}"
    );
    assert!(
        !tmp.path()
            .join(format!(".socket/vendor/npm/{UUID}"))
            .exists(),
        "the orphaned artifact dir is removed"
    );
    assert_eq!(
        std::fs::read(tmp.path().join("package-lock.json")).unwrap(),
        lock_pre,
        "clean end state: the restored pre-vendor lock is untouched"
    );
}

// ────────────────────────────── gem rows ──────────────────────────────

const GEM_UUID: &str = "22222222-2222-4222-8222-222222222222";
const GEM_NAME: &str = "padlock";
const GEM_VERSION: &str = "1.2.0";
const GEM_PURL: &str = "pkg:gem/padlock@1.2.0";
const GEM_ENCODED: &str = "pkg%3Agem%2Fpadlock%401.2.0";
// Assigns the rubygems-required `summary` + `authors` (as every healthy
// rubygems-written stub does): the vendor/rebuild write choke point validates
// them since the D4 invalid-stub hardening.
const GEMSPEC_STUB: &[u8] = b"Gem::Specification.new do |s|\n  s.name = \"padlock\"\n  s.version = \"1.2.0\"\n  s.summary = \"repair fixture\"\n  s.authors = [\"socket-patch e2e\"]\n  s.require_paths = [\"lib\"]\nend\n";

fn gem_copy_rel() -> String {
    format!(".socket/vendor/gem/{GEM_UUID}/{GEM_NAME}-{GEM_VERSION}")
}

/// Hermetic bundler project: exact-pin Gemfile, a lock modeled on real
/// bundler 4.0.15 output (`with_checksums` adds the ≥ 2.6 CHECKSUMS
/// section), and the installed gem + stub gemspec under the project-local
/// `vendor/bundle` layout the ruby crawler discovers.
fn write_gem_fixture(root: &Path, with_checksums: bool) {
    std::fs::write(
        root.join("Gemfile"),
        format!("source \"https://rubygems.org\"\n\ngem \"{GEM_NAME}\", \"{GEM_VERSION}\"\n"),
    )
    .unwrap();
    let checksums = if with_checksums {
        format!(
            "CHECKSUMS\n  {GEM_NAME} ({GEM_VERSION}) sha256={}\n\n",
            "e".repeat(64)
        )
    } else {
        String::new()
    };
    std::fs::write(
        root.join("Gemfile.lock"),
        format!(
            "GEM\n  remote: https://rubygems.org/\n  specs:\n    {GEM_NAME} ({GEM_VERSION})\n\n\
             PLATFORMS\n  ruby\n\nDEPENDENCIES\n  {GEM_NAME} (= {GEM_VERSION})\n\n\
             {checksums}BUNDLED WITH\n   4.0.15\n"
        ),
    )
    .unwrap();

    let home = root.join("vendor/bundle/ruby/3.4.0");
    let gem_dir = home.join(format!("gems/{GEM_NAME}-{GEM_VERSION}"));
    std::fs::create_dir_all(gem_dir.join("lib")).unwrap();
    std::fs::write(gem_dir.join("lib/padlock.rb"), BEFORE).unwrap();
    std::fs::create_dir_all(home.join("specifications")).unwrap();
    std::fs::write(
        home.join(format!("specifications/{GEM_NAME}-{GEM_VERSION}.gemspec")),
        GEMSPEC_STUB,
    )
    .unwrap();
}

/// Mount discovery + view for `GEM_UUID` (the gem twin of
/// [`mount_patch_api`]; file key is package-relative, no `package/`).
async fn mount_gem_patch_api(mock: &MockServer) {
    let before_hash = git_sha256(BEFORE);
    let after_hash = git_sha256(AFTER);
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": GEM_PURL,
                "patches": [{
                    "uuid": GEM_UUID,
                    "purl": GEM_PURL,
                    "tier": "free",
                    "cveIds": ["CVE-2026-0002"],
                    "ghsaIds": [],
                    "severity": "high",
                    "title": "gem vendor target"
                }]
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(mock)
        .await;
    Mock::given(method("GET"))
        .and(path(format!(
            "/v0/orgs/{ORG_SLUG}/patches/by-package/{GEM_ENCODED}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [{
                "uuid": GEM_UUID,
                "purl": GEM_PURL,
                "publishedAt": "2026-01-01T00:00:00Z",
                "description": "Gem vendor patch",
                "license": "MIT",
                "tier": "free",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(mock)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/view/{GEM_UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": GEM_UUID,
            "purl": GEM_PURL,
            "publishedAt": "2026-01-01T00:00:00Z",
            "files": {
                "lib/padlock.rb": {
                    "beforeHash": before_hash,
                    "afterHash":  after_hash,
                    "blobContent": AFTER_B64,
                }
            },
            "vulnerabilities": {
                "GHSA-dddd-eeee-ffff": {
                    "cves": ["CVE-2026-0002"],
                    "summary": "gem test vuln",
                    "severity": "high",
                    "description": "details"
                }
            },
            "description": "Gem vendor patch",
            "license": "MIT",
            "tier": "free",
        })))
        .mount(mock)
        .await;
}

const CARGO_UUID: &str = "33333333-3333-4333-8333-333333333333";
const CARGO_PURL: &str = "pkg:cargo/padcrate@1.0.0";

/// Synthesize a healthy, detached, DIR-shaped cargo ledger entry with no
/// fileInventory into an existing project: artifact dir + embedded record
/// whose afterHash matches the tree. The cargo backend records no
/// inventories (yet), so this is exactly the population the
/// vendor_inventory_missing warning must NOT nag about.
fn add_healthy_cargo_dir_entry(root: &Path) -> PathBuf {
    let rel = format!(".socket/vendor/cargo/{CARGO_UUID}/padcrate-1.0.0");
    let dir = root.join(&rel);
    std::fs::create_dir_all(dir.join("src")).unwrap();
    std::fs::write(dir.join("src/lib.rs"), AFTER).unwrap();
    let state_path = root.join(".socket/vendor/state.json");
    let mut state: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&state_path).unwrap()).unwrap();
    state["entries"][CARGO_PURL] = serde_json::json!({
        "ecosystem": "cargo",
        "basePurl": CARGO_PURL,
        "uuid": CARGO_UUID,
        "artifact": { "path": rel },
        "wiring": [],
        "detached": true,
        "record": {
            "uuid": CARGO_UUID,
            "exportedAt": "2026-01-01T00:00:00Z",
            "files": {
                "src/lib.rs": {
                    "beforeHash": git_sha256(BEFORE),
                    "afterHash": git_sha256(AFTER),
                }
            },
            "vulnerabilities": {},
            "description": "cargo dir fixture",
            "license": "MIT",
            "tier": "free",
        }
    });
    std::fs::write(&state_path, serde_json::to_vec_pretty(&state).unwrap()).unwrap();
    dir
}

/// `scan --vendor --yes` the gem fixture; returns the vendored copy dir.
fn vendor_gem_project(root: &Path, mock_uri: &str) -> PathBuf {
    let (code, stdout, stderr) = run_cli(root, mock_uri, &["scan", "--vendor", "--yes"]);
    assert_eq!(code, 0, "gem vendor setup failed: {stdout} {stderr}");
    let copy = root.join(gem_copy_rel());
    assert_eq!(
        std::fs::read(copy.join("lib/padlock.rb")).expect("vendored lib"),
        AFTER,
        "setup must vendor the patched copy"
    );
    assert_eq!(
        std::fs::read(copy.join("padlock.gemspec")).expect("stub gemspec"),
        GEMSPEC_STUB
    );
    copy
}

/// G1. Ledger deleted, wired pair + artifact survive: repair reconstructs
///     the ENTRY — wiring included — byte-identically to the original
///     ledger, and a subsequent `vendor --revert` byte-restores Gemfile and
///     Gemfile.lock and removes the artifact. RED without wiring
///     reconstruction: the revert "succeeds" silently while both files keep
///     pointing at the deleted dir.
#[tokio::test]
async fn repair_reconstructs_gem_wiring_and_revert_byte_restores() {
    let mock = MockServer::start().await;
    mount_gem_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_gem_fixture(tmp.path(), false);
    let gemfile_before = std::fs::read(tmp.path().join("Gemfile")).unwrap();
    let lock_before = std::fs::read(tmp.path().join("Gemfile.lock")).unwrap();
    let copy = vendor_gem_project(tmp.path(), &mock.uri());
    let state_path = tmp.path().join(".socket/vendor/state.json");
    let state_before = std::fs::read(&state_path).unwrap();
    // Anti-vacuity: the pair is actually wired before the ledger loss.
    let wired_gemfile = std::fs::read(tmp.path().join("Gemfile")).unwrap();
    assert_ne!(wired_gemfile, gemfile_before, "Gemfile must be wired");

    std::fs::remove_file(&state_path).unwrap();

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
    assert!(
        !events_of(&v)
            .iter()
            .any(|e| e["errorCode"] == "vendor_wiring_unknown")
            && !warnings_of(&v)
                .iter()
                .any(|w| w["code"] == "vendor_wiring_unknown"),
        "gem wiring IS reconstructable — no unknown-wiring warning: {v}"
    );
    // THE oracle: the reconstructed ledger equals the original, wiring,
    // fileInventory and all (deterministic sorted serialization).
    assert_eq!(
        std::fs::read(&state_path).unwrap(),
        state_before,
        "reconstructed state.json must be byte-identical to the original"
    );

    let (code, stdout, _) = run_cli(tmp.path(), &mock.uri(), &["vendor", "--revert"]);
    assert_eq!(code, 0, "revert after reconstruction: {stdout}");
    assert_eq!(
        std::fs::read(tmp.path().join("Gemfile")).unwrap(),
        gemfile_before,
        "Gemfile byte-restored"
    );
    assert_eq!(
        std::fs::read(tmp.path().join("Gemfile.lock")).unwrap(),
        lock_before,
        "Gemfile.lock byte-restored"
    );
    assert!(!copy.exists(), "artifact dir removed");
    assert!(
        !tmp.path().join(".socket/vendor").exists(),
        "fully-reverted project carries no vendor residue"
    );
}

/// G1b. Same reconstruction on a bundler ≥ 2.6 CHECKSUMS lock: the
///      pre-vendor `sha256=` token is not offline-recoverable, so repair
///      surfaces `vendor_checksum_unrecoverable` and the revert restores
///      everything EXCEPT that one line, which stays in bundler's bare form
///      (a plain `bundle install` refills it — verified on 4.0.15).
#[tokio::test]
async fn repair_reconstruction_flags_unrecoverable_gem_checksum() {
    let mock = MockServer::start().await;
    mount_gem_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_gem_fixture(tmp.path(), true);
    let lock_before = std::fs::read_to_string(tmp.path().join("Gemfile.lock")).unwrap();
    let gemfile_before = std::fs::read(tmp.path().join("Gemfile")).unwrap();
    vendor_gem_project(tmp.path(), &mock.uri());

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
            .any(|e| e["action"] == "skipped" && e["errorCode"] == "vendor_checksum_unrecoverable"),
        "the unrecoverable sha256 must be surfaced: {v}"
    );

    let (code, stdout, _) = run_cli(tmp.path(), &mock.uri(), &["vendor", "--revert"]);
    assert_eq!(code, 0, "revert: {stdout}");
    assert_eq!(
        std::fs::read(tmp.path().join("Gemfile")).unwrap(),
        gemfile_before
    );
    let lock_after = std::fs::read_to_string(tmp.path().join("Gemfile.lock")).unwrap();
    let expected = lock_before.replace(
        &format!("  {GEM_NAME} ({GEM_VERSION}) sha256={}\n", "e".repeat(64)),
        &format!("  {GEM_NAME} ({GEM_VERSION})\n"),
    );
    assert_ne!(expected, lock_before, "fixture must carry the sha256 line");
    assert_eq!(
        lock_after, expected,
        "everything byte-restored except the bare CHECKSUMS entry"
    );
}

/// G1c. No-ledger restore must NEVER canonize a tampered tree
///      (trust-on-first-use): an UNPATCHED file in the vendored gem dir is
///      tampered and the ledger deleted. The re-synthesized entry has no
///      fileInventory, so the health check sees only the patched members
///      (Healthy) — and no npm-family lock records an integrity for a gem
///      dir. Repair must derive the canonical fingerprint from a
///      member-verified LOCAL REBUILD (installed copy + recorded patch),
///      healing the tamper; the restored ledger is byte-identical to the
///      pre-tamper original. RED without the fix: the LIVE dir was
///      fingerprinted into the restored ledger — the tampered gemspec
///      survives as the canonical tree later repairs enforce and VEX
///      attests.
#[tokio::test]
async fn repair_no_ledger_restore_never_canonizes_tampered_gem_tree() {
    let mock = MockServer::start().await;
    mount_gem_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_gem_fixture(tmp.path(), false);
    let copy = vendor_gem_project(tmp.path(), &mock.uri());
    let state_path = tmp.path().join(".socket/vendor/state.json");
    let state_before = std::fs::read(&state_path).unwrap();

    // Tamper an UNPATCHED member (the stub gemspec); the patched member
    // keeps its AFTER bytes so member-only verification still passes.
    let tampered = b"Gem::Specification.new do |s|\n  s.name = \"padlock\"\n  s.version = \"1.2.0\"\n  s.require_paths = [\"lib\", \"exfil\"]\nend\n";
    std::fs::write(copy.join("padlock.gemspec"), tampered).unwrap();
    std::fs::remove_file(&state_path).unwrap();

    mount_blob(&mock).await;
    let (code, stdout, stderr) = run_cli(
        tmp.path(),
        &mock.uri(),
        &["repair", "--download-mode", "file"],
    );
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    let v = parse_env(&stdout);
    // The tamper is healed: the rebuild reproduced the pristine stub...
    assert_eq!(
        std::fs::read(copy.join("padlock.gemspec")).unwrap(),
        GEMSPEC_STUB,
        "the tampered unpatched file must be rebuilt, not kept: {v}"
    );
    assert_eq!(std::fs::read(copy.join("lib/padlock.rb")).unwrap(), AFTER);
    // ...and the restored ledger equals the pre-tamper original — the
    // tampered tree was never fingerprinted in.
    assert_eq!(
        std::fs::read(&state_path).unwrap(),
        state_before,
        "reconstructed state.json must equal the pre-tamper original"
    );
    // A later repair finds the canonical tree healthy — nothing to rebuild.
    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair"]);
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    let v2 = parse_env(&stdout);
    assert!(
        !events_of(&v2).iter().any(|e| e["action"] == "rebuilt"),
        "second repair must find nothing to rebuild: {v2}"
    );
}

/// G1d. Same no-ledger tamper, but NO trustworthy rebuild source exists
///      (the installed copy is gone, and a reconstructed gem entry records
///      no pre-vendor registry checksum to fetch by): repair must restore
///      the ledger entry WITHOUT a fileInventory — surfacing
///      `vendor_inventory_unverified` — so later runs stay in the legacy
///      member-only-warn state (`vendor_inventory_missing`) instead of
///      enforcing the tampered live tree as canonical. RED without the
///      fix: the entry carries an inventory hashing the tampered bytes,
///      no warning fires, and later repairs report fully Healthy.
#[tokio::test]
async fn repair_no_ledger_restore_without_pristine_source_stays_unverified() {
    let mock = MockServer::start().await;
    mount_gem_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_gem_fixture(tmp.path(), false);
    let copy = vendor_gem_project(tmp.path(), &mock.uri());

    let tampered = b"tampered unpatched member\n";
    std::fs::write(copy.join("padlock.gemspec"), tampered).unwrap();
    std::fs::remove_file(tmp.path().join(".socket/vendor/state.json")).unwrap();
    // No pristine source: the installed copy is gone, and the reconstructed
    // wiring carries no CHECKSUMS sha256 (offline-unrecoverable, see G1b).
    std::fs::remove_dir_all(tmp.path().join("vendor/bundle")).unwrap();

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
            .any(|e| e["errorCode"] == "vendor_inventory_unverified"),
        "the unverifiable fingerprint must be surfaced: {v}"
    );
    assert!(
        events_of(&v)
            .iter()
            .any(|e| e["action"] == "rebuilt" && e["details"]["ledgerRestored"] == true),
        "the ledger entry is still restored: {v}"
    );
    let state: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(tmp.path().join(".socket/vendor/state.json")).unwrap(),
    )
    .unwrap();
    assert!(
        state["entries"][GEM_PURL]["artifact"]["fileInventory"].is_null(),
        "the tampered live tree must NOT be fingerprinted into the ledger: {state}"
    );
    assert!(
        !state["entries"][GEM_PURL]["wiring"]
            .as_array()
            .unwrap_or(&Vec::new())
            .is_empty(),
        "the reconstructed wiring is still persisted: {state}"
    );
    // No pristine source: repair must not have invented bytes either.
    assert_eq!(
        std::fs::read(copy.join("padlock.gemspec")).unwrap(),
        tampered.as_slice(),
        "the artifact is left as-is in the legacy member-only state"
    );
    // Later repairs keep naming the gap instead of enforcing the tampered
    // tree as canonical.
    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair"]);
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    let v2 = parse_env(&stdout);
    assert!(
        events_of(&v2)
            .iter()
            .any(|e| e["errorCode"] == "vendor_inventory_missing"),
        "later repairs stay in the legacy-warn state: {v2}"
    );
}

/// G2. Empty-wiring gem entry (a reconstructed ledger without recoverable
///     originals, synthesized here): `vendor --revert` must FAIL loudly —
///     naming vendor_wiring_unknown — and keep the artifact and both files
///     untouched. RED without the guard: exit 0, artifact deleted, pair
///     stranded on a dead dir.
#[tokio::test]
async fn revert_of_empty_wiring_gem_entry_fails_loudly() {
    let mock = MockServer::start().await;
    mount_gem_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_gem_fixture(tmp.path(), false);
    let copy = vendor_gem_project(tmp.path(), &mock.uri());

    let state_path = tmp.path().join(".socket/vendor/state.json");
    let mut state: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&state_path).unwrap()).unwrap();
    state["entries"][GEM_PURL]["wiring"] = serde_json::json!([]);
    std::fs::write(&state_path, serde_json::to_vec_pretty(&state).unwrap()).unwrap();

    let gemfile_wired = std::fs::read(tmp.path().join("Gemfile")).unwrap();
    let lock_wired = std::fs::read(tmp.path().join("Gemfile.lock")).unwrap();

    let (code, stdout, _) = run_cli(tmp.path(), &mock.uri(), &["vendor", "--revert"]);
    assert_eq!(code, 1, "empty-wiring revert must fail: {stdout}");
    let v = parse_env(&stdout);
    let failed = events_of(&v)
        .into_iter()
        .find(|e| e["action"] == "failed" && e["purl"] == GEM_PURL)
        .unwrap_or_else(|| panic!("expected a failed event: {v}"));
    assert_eq!(failed["errorCode"], "revert_failed", "{failed}");
    assert!(
        failed["error"]
            .as_str()
            .unwrap_or("")
            .contains("vendor_wiring_unknown"),
        "the machine tag must be named: {failed}"
    );
    assert!(
        copy.join("lib/padlock.rb").is_file(),
        "the artifact must NOT be deleted"
    );
    assert_eq!(
        std::fs::read(tmp.path().join("Gemfile")).unwrap(),
        gemfile_wired,
        "Gemfile untouched"
    );
    assert_eq!(
        std::fs::read(tmp.path().join("Gemfile.lock")).unwrap(),
        lock_wired,
        "Gemfile.lock untouched"
    );
}

/// G2b. The same empty-wiring population, healed at the repair seam: a
///     LEDGERED gem entry whose wiring is empty (pre-reconstruction repairs
///     persisted exactly these) gets full revert-capable wiring backfilled
///     from the live pair while the artifact is healthy — byte-identical to
///     the original ledger for the exact-pin fixture — and the revert that
///     used to refuse (G2) byte-restores both files. RED without the pass-1
///     backfill: repair exits 0 leaving `"wiring": []`, no wiringRestored
///     event, and the revert fails.
#[tokio::test]
async fn repair_backfills_wiring_for_empty_wiring_gem_entry() {
    let mock = MockServer::start().await;
    mount_gem_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_gem_fixture(tmp.path(), false);
    let gemfile_before = std::fs::read(tmp.path().join("Gemfile")).unwrap();
    let lock_before = std::fs::read(tmp.path().join("Gemfile.lock")).unwrap();
    let copy = vendor_gem_project(tmp.path(), &mock.uri());
    let state_path = tmp.path().join(".socket/vendor/state.json");
    let state_before = std::fs::read(&state_path).unwrap();

    let mut state: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&state_path).unwrap()).unwrap();
    state["entries"][GEM_PURL]["wiring"] = serde_json::json!([]);
    std::fs::write(&state_path, serde_json::to_vec_pretty(&state).unwrap()).unwrap();

    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair"]);
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    let v = parse_env(&stdout);
    assert!(
        events_of(&v).iter().any(|e| e["action"] == "rebuilt"
            && e["purl"] == GEM_PURL
            && e["details"]["wiringRestored"] == true
            && e["details"]["artifactRebuilt"] == false),
        "envelope={v}"
    );
    // THE oracle: the backfilled ledger equals the original byte-for-byte
    // (the exact-pin fixture reconstructs losslessly).
    assert_eq!(
        std::fs::read(&state_path).unwrap(),
        state_before,
        "backfilled state.json must be byte-identical to the original"
    );

    let (code, stdout, _) = run_cli(tmp.path(), &mock.uri(), &["vendor", "--revert"]);
    assert_eq!(code, 0, "revert after backfill: {stdout}");
    assert_eq!(
        std::fs::read(tmp.path().join("Gemfile")).unwrap(),
        gemfile_before,
        "Gemfile byte-restored"
    );
    assert_eq!(
        std::fs::read(tmp.path().join("Gemfile.lock")).unwrap(),
        lock_before,
        "Gemfile.lock byte-restored"
    );
    assert!(!copy.exists(), "artifact dir removed");
}

/// G3. Dir-shaped tamper matrix: an altered UNPATCHED file (the stub
///     gemspec), a deleted file, and a planted extra file must each flip
///     the health check to Corrupt — repair rebuilds the exact recorded
///     tree — and VEX refuses to attest while tampered. RED without the
///     fileInventory: every arm was blessed Healthy and attested.
#[tokio::test]
async fn repair_gem_dir_tamper_matrix_and_vex_refusal() {
    let mock = MockServer::start().await;
    mount_gem_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_gem_fixture(tmp.path(), false);
    let copy = vendor_gem_project(tmp.path(), &mock.uri());

    // Anti-vacuity: the ledger records the whole-tree inventory.
    let state: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(tmp.path().join(".socket/vendor/state.json")).unwrap(),
    )
    .unwrap();
    let inventory = &state["entries"][GEM_PURL]["artifact"]["fileInventory"];
    assert_eq!(
        inventory["padlock.gemspec"],
        sha256_hex(GEMSPEC_STUB),
        "state={state}"
    );
    assert_eq!(inventory["lib/padlock.rb"], sha256_hex(AFTER));

    let tamper: [&dyn Fn(); 3] = [
        &|| std::fs::write(copy.join("padlock.gemspec"), b"tampered stub\n").unwrap(),
        &|| std::fs::remove_file(copy.join("padlock.gemspec")).unwrap(),
        &|| std::fs::write(copy.join("lib/evil.rb"), b"payload\n").unwrap(),
    ];
    for (i, arm) in tamper.iter().enumerate() {
        arm();

        // VEX refuses while tampered (the patched member still verifies —
        // only the inventory knows).
        let vex_path = tmp.path().join("out.vex.json");
        let (code, stdout, _) = run_cli(
            tmp.path(),
            &mock.uri(),
            &[
                "vex",
                "--output",
                vex_path.to_str().unwrap(),
                "--product",
                "pkg:gem/app@1.0.0",
            ],
        );
        assert_eq!(code, 1, "arm {i}: tampered dir must not attest: {stdout}");
        let venv = parse_env(&stdout);
        assert!(
            events_of(&venv)
                .iter()
                .any(|e| e["action"] == "skipped" && e["errorCode"] == "vendor_inventory_mismatch"),
            "arm {i}: envelope={venv}"
        );
        assert!(!vex_path.exists(), "arm {i}: no VEX doc while tampered");

        // Repair heals: Corrupt → deterministic rebuild of the recorded tree.
        let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair"]);
        assert_eq!(code, 0, "arm {i}: stdout={stdout} stderr={stderr}");
        let v = parse_env(&stdout);
        assert!(
            events_of(&v).iter().any(|e| e["action"] == "rebuilt"
                && e["purl"] == GEM_PURL
                && e["details"]["reason"] == "vendor_artifact_corrupt"),
            "arm {i}: envelope={v}"
        );
        assert_eq!(
            std::fs::read(copy.join("padlock.gemspec")).unwrap(),
            GEMSPEC_STUB,
            "arm {i}: stub byte-restored"
        );
        assert_eq!(
            std::fs::read(copy.join("lib/padlock.rb")).unwrap(),
            AFTER,
            "arm {i}: patched member intact"
        );
        assert!(
            !copy.join("lib/evil.rb").exists(),
            "arm {i}: planted file removed"
        );

        // And VEX attests again after the heal.
        let (code, _, _) = run_cli(
            tmp.path(),
            &mock.uri(),
            &[
                "vex",
                "--output",
                vex_path.to_str().unwrap(),
                "--product",
                "pkg:gem/app@1.0.0",
            ],
        );
        assert_eq!(code, 0, "arm {i}: healed artifact attests");
        let doc: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&vex_path).unwrap()).unwrap();
        assert_eq!(doc["statements"].as_array().unwrap().len(), 1);
        std::fs::remove_file(&vex_path).unwrap();
    }
}

/// G3c. A service-vendored entry records the SERVICE tree's inventory (its
///     converter-generated stub gemspec differs byte-wise from the local
///     stub), but repair always rebuilds LOCALLY. The member-verified local
///     rebuild must refresh the stale inventory — loudly, with the
///     provenance named — instead of deleting the rebuild and stranding the
///     wired pair on a dead dir. RED without the refresh: exit 1
///     vendor_artifact_rebuild_failed, artifact gone, and every subsequent
///     repair loops the same failure.
#[tokio::test]
async fn repair_refreshes_stale_inventory_from_service_provenance() {
    const SERVICE_STUB: &[u8] = b"# converter-generated stub\nGem::Specification.new do |s|\n  s.name = \"padlock\"\n  s.version = \"1.2.0\"\n  s.summary = \"repair fixture\"\n  s.authors = [\"socket-patch e2e\"]\n  s.require_paths = [\"lib\"]\nend\n";
    let mock = MockServer::start().await;
    mount_gem_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_gem_fixture(tmp.path(), false);
    let copy = vendor_gem_project(tmp.path(), &mock.uri());

    // Simulate service provenance: the on-disk stub and the recorded
    // inventory BOTH carry the converter-generated form (they agree), which
    // a LOCAL rebuild cannot reproduce.
    std::fs::write(copy.join("padlock.gemspec"), SERVICE_STUB).unwrap();
    let state_path = tmp.path().join(".socket/vendor/state.json");
    let mut state: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&state_path).unwrap()).unwrap();
    state["entries"][GEM_PURL]["artifact"]["fileInventory"]["padlock.gemspec"] =
        serde_json::json!(sha256_hex(SERVICE_STUB));
    std::fs::write(&state_path, serde_json::to_vec_pretty(&state).unwrap()).unwrap();

    // Anti-vacuity: the simulated service state is self-consistent.
    let (code, stdout, _) = run_cli(tmp.path(), &mock.uri(), &["repair"]);
    assert_eq!(code, 0, "{stdout}");
    let v = parse_env(&stdout);
    assert!(
        v["summary"]["rebuilt"].is_null() || v["summary"]["rebuilt"] == 0,
        "the simulated service tree must be healthy: {v}"
    );

    std::fs::remove_dir_all(&copy).unwrap();

    // THE pin: the local rebuild's stub differs from the recorded
    // inventory; repair keeps the member-verified rebuild and refreshes
    // the inventory rather than deleting it and failing forever.
    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair"]);
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    let v = parse_env(&stdout);
    assert!(
        events_of(&v)
            .iter()
            .any(|e| e["action"] == "rebuilt" && e["purl"] == GEM_PURL),
        "envelope={v}"
    );
    assert!(
        events_of(&v).iter().any(|e| e["action"] == "skipped"
            && e["errorCode"] == "vendor_inventory_refreshed"
            && e["purl"] == GEM_PURL),
        "the provenance switch must be surfaced: {v}"
    );
    assert_eq!(
        std::fs::read(copy.join("padlock.gemspec")).unwrap(),
        GEMSPEC_STUB,
        "the local rebuild's stub is kept"
    );
    assert_eq!(
        std::fs::read(copy.join("lib/padlock.rb")).unwrap(),
        AFTER,
        "patched member intact"
    );
    let state: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&state_path).unwrap()).unwrap();
    assert_eq!(
        state["entries"][GEM_PURL]["artifact"]["fileInventory"]["padlock.gemspec"],
        serde_json::json!(sha256_hex(GEMSPEC_STUB)),
        "inventory refreshed from the verified rebuild: {state}"
    );

    // The loop is dead: the next repair is clean.
    let (code, stdout, _) = run_cli(tmp.path(), &mock.uri(), &["repair"]);
    assert_eq!(code, 0, "{stdout}");
    let v = parse_env(&stdout);
    assert!(
        v["summary"]["rebuilt"].is_null() || v["summary"]["rebuilt"] == 0,
        "no repair loop: {v}"
    );
    assert!(
        !events_of(&v).iter().any(|e| e["action"] == "failed"),
        "no repair loop: {v}"
    );
}

/// G3b. Backward tolerance: a pre-inventory ledger entry (fileInventory
///      stripped) keeps today's member-only verdict on the same tamper —
///      no rebuild, exit 0 — but repair names the gap
///      (vendor_inventory_missing) instead of staying silent. The warning
///      is GEM-only: a healthy inventory-less cargo dir entry (that backend
///      records no inventories, so "re-vendor" could never silence it) must
///      produce no events at all.
#[tokio::test]
async fn repair_warns_on_legacy_gem_entry_without_inventory() {
    let mock = MockServer::start().await;
    mount_gem_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_gem_fixture(tmp.path(), false);
    let copy = vendor_gem_project(tmp.path(), &mock.uri());

    let state_path = tmp.path().join(".socket/vendor/state.json");
    let mut state: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&state_path).unwrap()).unwrap();
    state["entries"][GEM_PURL]["artifact"]
        .as_object_mut()
        .unwrap()
        .remove("fileInventory")
        .expect("the fixture entry must have recorded an inventory");
    std::fs::write(&state_path, serde_json::to_vec_pretty(&state).unwrap()).unwrap();
    let cargo_dir = add_healthy_cargo_dir_entry(tmp.path());

    std::fs::write(copy.join("padlock.gemspec"), b"tampered stub\n").unwrap();

    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair"]);
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    let v = parse_env(&stdout);
    assert!(
        v["summary"]["rebuilt"].is_null() || v["summary"]["rebuilt"] == 0,
        "legacy entries keep member-only behavior (no rebuild): {v}"
    );
    let missing: Vec<_> = events_of(&v)
        .into_iter()
        .filter(|e| e["errorCode"] == "vendor_inventory_missing")
        .collect();
    assert_eq!(
        missing.len(),
        1,
        "only the gem entry warns about the inventory gap: {v}"
    );
    assert_eq!(missing[0]["purl"], GEM_PURL, "envelope={v}");
    assert!(
        !events_of(&v).iter().any(|e| e["purl"] == CARGO_PURL),
        "the healthy inventory-less cargo entry stays silent: {v}"
    );
    assert_eq!(
        std::fs::read(copy.join("padlock.gemspec")).unwrap(),
        b"tampered stub\n",
        "member-only verification cannot see the tamper (documented legacy gap)"
    );

    // Anti-vacuity for the silence above: the cargo entry IS health-checked
    // — break its artifact and the same repair pipeline must surface it.
    std::fs::remove_dir_all(&cargo_dir).unwrap();
    let (code, stdout, _) = run_cli(tmp.path(), &mock.uri(), &["repair"]);
    assert_eq!(code, 1, "a missing cargo artifact must fail: {stdout}");
    let v = parse_env(&stdout);
    assert!(
        events_of(&v)
            .iter()
            .any(|e| e["action"] == "failed" && e["purl"] == CARGO_PURL),
        "the cargo entry is live in pass 1: {v}"
    );
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
