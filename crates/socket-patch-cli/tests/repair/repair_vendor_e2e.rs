//! End-to-end tests for `repair`'s vendored-artifact phase: artifacts the
//! ledger records but that are missing/corrupt on disk are re-vendored
//! fail-closed; lockfile references with no ledger entry are reported
//! (`vendor_ledger_missing`), never reconstructed. Mock API + real npm
//! lockfile fixtures, driven through the built binary.
//!
//! The gem rows exercise the dir-shaped counterparts: whole-tree
//! fileInventory tamper detection, inventory refresh, and the loud
//! empty-wiring revert refusal. Their fixture pair is hand-written, modeled
//! byte-for-byte on real `bundle lock` output (bundler 4.0.15).

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::npm_e2e_common;
use crate::vex_e2e_common;

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
    let archive_view = serde_json::json!({
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
    });
    crate::prebuilt_common::mount_view(mock, &archive_view, None).await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(archive_view))
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
    let out = crate::common::hermetic_command(&binary())
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

/// `scan --mode vendored --yes` to establish a vendored project; returns the
/// vendored tarball path.
fn vendor_project(root: &Path, mock_uri: &str, extra: &[&str]) -> PathBuf {
    let mut argv = vec!["scan", "--mode", "vendored", "--yes"];
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
async fn repair_offline_refuses_even_with_installed_tree_and_blobs() {
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
    assert_eq!(code, 1, "stdout={stdout} stderr={stderr}");
    let v = parse_env(&stdout);
    assert_eq!(v["summary"]["failed"], 1, "envelope={v}");
    assert!(!tgz.exists(), "no local rebuild");
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

    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair"]);
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    assert_eq!(std::fs::read(&tgz).unwrap(), tgz_bytes);
    assert!(!tmp.path().join("node_modules").exists());
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
            .any(|e| e["action"] == "failed"
                && e["errorCode"] == "vendor_artifact_redownload_failed"),
        "envelope={env}"
    );
    assert!(
        tgz.is_file(),
        "a failed redownload must preserve the original artifact"
    );
}

/// 5. Fresh clone with the committed artifact AND node_modules gone. A
///    vendored project has no manifest, so a standalone `vendor` re-run is
///    a clean `noManifest` no-op (it never re-vendors from the ledger);
///    `repair` is the rebuild path: the ledger's wiring original recovers
///    the registry resolution, the pristine tarball is fetched + verified,
///    and the artifact is rebuilt — exit 0.
#[tokio::test]
async fn vendor_rerun_is_a_noop_and_repair_recovers_registry_resolution_from_ledger() {
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
    assert_eq!(v["status"], "noManifest", "envelope={v}");
    assert!(events_of(&v).is_empty(), "envelope={v}");
    assert!(!tgz.exists(), "`vendor` never re-vendors from the ledger");

    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair"]);
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    let v = parse_env(&stdout);
    assert!(
        events_of(&v)
            .iter()
            .any(|e| e["action"] == "rebuilt" && e["purl"] == PURL),
        "the missing artifact is rebuilt from the recovered fetch: {v}"
    );
    assert!(tgz.is_file(), "artifact rebuilt from the recovered fetch");
    assert_eq!(
        std::fs::read(tmp.path().join("package-lock.json")).unwrap(),
        lock1,
        "lockfile byte-stable"
    );
}

/// 6. Vendored entries are detached (no manifest ever): repair rebuilds via
///    the ledger-embedded record.
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
    let tgz = vendor_project(tmp.path(), &mock.uri(), &[]);
    assert!(
        !tmp.path().join(".socket/manifest.json").exists(),
        "vendored runs write no manifest"
    );
    std::fs::remove_file(&tgz).unwrap();

    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair"]);
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    let v = parse_env(&stdout);
    assert_eq!(v["summary"]["rebuilt"], 1, "envelope={v}");
    assert!(tgz.is_file());
    assert_socket_dir_lean(tmp.path());
}

/// G6 for a manifest-free vendored project: after the run, `.socket/` holds
/// exactly `vendor/` — no `apply.lock` outlives it, no blobs/diffs/packages
/// are conjured by a repair that rebuilds from the ledger's embedded record.
fn assert_socket_dir_lean(root: &Path) {
    let mut names: Vec<String> = std::fs::read_dir(root.join(".socket"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(
        names,
        vec!["vendor".to_string()],
        "a vendored project's .socket/ holds only vendor/"
    );
}

/// 7. The ledger is gone (only `state.json`, or the whole `.socket/vendor`
///    tree) while the lockfile still points into `.socket/vendor/`: repair
///    does NOT re-synthesize the entry (the rewired lock cannot supply the
///    pre-vendor originals a revert needs). It fails with
///    `vendor_ledger_missing` naming the uuid and path, writes no ledger,
///    leaves the lockfile and any surviving artifact alone — and once
///    `state.json` is restored, the next repair is clean.
#[tokio::test]
async fn repair_reports_missing_ledger_instead_of_reconstructing() {
    for wholesale in [false, true] {
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
        let state_path = tmp.path().join(".socket/vendor/state.json");
        let state1 = std::fs::read(&state_path).unwrap();

        if wholesale {
            std::fs::remove_dir_all(tmp.path().join(".socket/vendor")).unwrap();
        } else {
            std::fs::remove_file(&state_path).unwrap();
        }

        let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair"]);
        assert_eq!(
            code, 1,
            "wholesale={wholesale} stdout={stdout} stderr={stderr}"
        );
        let v = parse_env(&stdout);
        let missing: Vec<_> = events_of(&v)
            .into_iter()
            .filter(|e| e["errorCode"] == "vendor_ledger_missing")
            .collect();
        assert_eq!(missing.len(), 1, "wholesale={wholesale} envelope={v}");
        let ev = &missing[0];
        assert_eq!(ev["action"], "failed", "{ev}");
        assert_eq!(ev["uuid"], UUID, "{ev}");
        assert!(ev.get("purl").is_none(), "no fabricated purl: {ev}");
        assert_eq!(ev["details"]["ecosystem"], "npm", "{ev}");
        assert!(
            ev["details"]["path"]
                .as_str()
                .unwrap_or("")
                .starts_with(&format!(".socket/vendor/npm/{UUID}/")),
            "{ev}"
        );
        assert!(
            ev["error"].as_str().unwrap_or("").contains("state.json"),
            "the remedy names state.json: {ev}"
        );
        assert!(
            v["summary"]["rebuilt"].is_null() || v["summary"]["rebuilt"] == 0,
            "nothing is rebuilt without a ledger: {v}"
        );
        assert!(!state_path.exists(), "no ledger is synthesized");
        assert_eq!(
            std::fs::read(tmp.path().join("package-lock.json")).unwrap(),
            lock1,
            "lockfile untouched"
        );
        if wholesale {
            assert!(!tgz.exists(), "nothing is rebuilt without a ledger");
            continue;
        }
        assert_eq!(
            std::fs::read(&tgz).unwrap(),
            tgz_bytes,
            "artifact untouched"
        );

        // Restoring the ledger from version control is the recovery.
        std::fs::write(&state_path, &state1).unwrap();
        let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair"]);
        assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
        let v = parse_env(&stdout);
        assert!(
            !events_of(&v).iter().any(|e| e["action"] == "failed"),
            "restored ledger repairs clean: {v}"
        );
    }
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
            && e["details"]["wouldRedownload"] == true
            && e["purl"] == PURL),
        "envelope={v}"
    );
    assert!(!tgz.exists(), "dry run writes nothing");
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
    let archive_view = serde_json::json!({
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
    });
    crate::prebuilt_common::mount_view(mock, &archive_view, Some(GEMSPEC_STUB)).await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/view/{GEM_UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(archive_view))
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

/// `scan --mode vendored --yes` the gem fixture; returns the vendored copy dir.
fn vendor_gem_project(root: &Path, mock_uri: &str) -> PathBuf {
    let (code, stdout, stderr) = run_cli(root, mock_uri, &["scan", "--mode", "vendored", "--yes"]);
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
///     vendor_artifact_redownload_failed, artifact gone, and every subsequent
///     repair loops the same failure.
#[tokio::test]
async fn repair_refuses_changed_service_inventory() {
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

    let ledger_before = std::fs::read(&state_path).unwrap();
    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair"]);
    assert_eq!(code, 1, "{stdout} {stderr}");
    assert!(stdout.contains("vendor_inventory_mismatch"));
    assert!(!copy.exists());
    assert_eq!(std::fs::read(&state_path).unwrap(), ledger_before);
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

/// Manifest-less VEX over what `repair` restores for npm: a deleted
/// tarball rebuilt byte-identically. The checkout attests `(vendored)` with
/// the manifest deleted, with the ledgers deleted (lockfile discovery +
/// patch API), never `--offline` (`record_unavailable`, zero requests), and
/// not once the lock is reverted (`vendor_unwired`, `--no-verify` too).
#[tokio::test]
async fn repaired_vendored_state_attests_manifest_less() {
    {
        let mock = MockServer::start().await;
        mount_patch_api(&mock).await;
        let tmp = tempfile::tempdir().unwrap();
        write_fixture(
            tmp.path(),
            "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
            "sha512-orig==",
        );
        let pristine = std::fs::read(tmp.path().join("package-lock.json")).unwrap();
        let tgz = vendor_project(tmp.path(), &mock.uri(), &[]);
        std::fs::remove_file(&tgz).unwrap();
        let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair"]);
        assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
        assert!(tgz.is_file(), "repair rebuilt the artifact");

        let checkout = tmp.path().join("checkout");
        npm_e2e_common::fresh_checkout(tmp.path(), &checkout, &["package-lock.json"]);
        std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let api = vex_e2e_common::PatchApi::start(vec![(
                        UUID.to_string(),
                        vex_e2e_common::patch_view(
                            UUID,
                            PURL,
                            &[("package/index.js", &git_sha256(AFTER))],
                            &[("GHSA-aaaa-bbbb-cccc", &["CVE-2026-0001"])],
                        ),
                    )]);
                    npm_e2e_common::manifestless_vex_matrix(&npm_e2e_common::ManifestlessCase {
                        label: "repair".to_string(),
                        project: &checkout,
                        purl: PURL,
                        uuid: UUID,
                        marker: vex_e2e_common::Marker::Vendored,
                        vulns: &[("GHSA-aaaa-bbbb-cccc", &["CVE-2026-0001"])],
                        api: &api,
                        patch_server_url: None,
                        registry_locks: vec![("package-lock.json", pristine.clone())],
                        embedded: &[vex_e2e_common::VexVia::Apply],
                    });
                })
                .join()
                .expect("manifest-less VEX tail panicked");
        });
    }
}

use crate::vlt_hosted_common;
use crate::vlt_vendored;

/// `repair --dry-run` over a deleted vlt directory artifact previews the
/// rebuild (`wouldRedownload`, the dir path) and writes nothing; the wet run
/// rebuilds it offline from the installed copy.
#[test]
fn repair_previews_then_rebuilds_a_deleted_vlt_dir() {
    use vlt_hosted_common as hosted;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    vlt_vendored::vendored_project(root, true);
    let uuid_dir = root.join(format!(".socket/vendor/npm/{}", hosted::UUID));
    std::fs::remove_dir_all(&uuid_dir).unwrap();
    let cwd = root.to_str().unwrap().to_string();
    let (code, v, stderr) = hosted::run_json(
        root,
        &["repair", "--dry-run", "--offline", "--cwd", &cwd],
        &[],
    );
    assert_eq!(code, 0, "{v:#}\n{stderr}");
    let text = v.to_string();
    assert!(
        text.contains("wouldRedownload") && text.contains(&vlt_vendored::rel()),
        "{v:#}"
    );
    assert!(!uuid_dir.exists());
    let fixture = crate::prebuilt_common::Server::project(root);
    let (code, v, stderr) = hosted::run_json(
        root,
        &["repair", "--cwd", &cwd],
        &[("SOCKET_VENDOR_URL", &fixture.uri)],
    );
    assert_eq!(code, 0, "{v:#}\n{stderr}");
    assert_eq!(
        std::fs::read(root.join(vlt_vendored::rel()).join("index.js")).unwrap(),
        hosted::PATCHED
    );
    assert!(uuid_dir.join(".gitignore").is_file());
}

/// Rewrite a `.tgz` through `edit` over its (path, bytes) members, then
/// re-gzip with `mtime` in the gzip header.
fn retar(tgz: &[u8], mtime: u32, edit: impl FnOnce(&mut Vec<(String, Vec<u8>)>)) -> Vec<u8> {
    use std::io::Read as _;
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(tgz));
    let mut members: Vec<(String, Vec<u8>)> = Vec::new();
    for entry in archive.entries().unwrap() {
        let mut entry = entry.unwrap();
        let path = entry.path().unwrap().to_string_lossy().into_owned();
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes).unwrap();
        members.push((path, bytes));
    }
    edit(&mut members);
    let gz = flate2::GzBuilder::new()
        .mtime(mtime)
        .write(Vec::new(), flate2::Compression::default());
    let mut builder = tar::Builder::new(gz);
    for (path, bytes) in &members {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, path, bytes.as_slice())
            .unwrap();
    }
    builder.into_inner().unwrap().finish().unwrap()
}

/// A corrupt artifact that still carries the valid patched member (an
/// unrelated member was added): `repair --offline` harvests the verified
/// patched bytes BEFORE setting the artifact aside, rebuilds from the
/// pristine installed copy, and restores the byte-exact recorded archive.
#[tokio::test]
async fn repair_offline_never_repacks_verified_members() {
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
    assert!(!tmp.path().join(".socket/blobs").exists(), "no local blobs");

    let corrupt = retar(&tgz_bytes, 0, |m| {
        m.push(("package/extra.txt".into(), b"planted\n".to_vec()))
    });
    std::fs::write(&tgz, &corrupt).unwrap();

    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair", "--offline"]);
    assert_eq!(code, 1, "stdout={stdout} stderr={stderr}");
    let v = parse_env(&stdout);
    assert_eq!(v["summary"]["failed"], 1, "envelope={v}");
    assert_eq!(
        std::fs::read(&tgz).unwrap(),
        corrupt,
        "preserves the corrupt archive"
    );
    assert_eq!(
        std::fs::read(tmp.path().join("package-lock.json")).unwrap(),
        lock1
    );
    assert_eq!(
        std::fs::read(tmp.path().join(".socket/vendor/state.json")).unwrap(),
        state1
    );
}

/// Repair keeps the ORIGINAL artifact identity: a service archive with the
/// same members but different bytes (only the gzip mtime changed) is not
/// committed. Repair falls back to the deterministic local build, restores
/// the recorded bytes, and leaves the lockfile and ledger byte-identical.
#[tokio::test]
async fn repair_never_rewires_to_different_service_bytes() {
    identity_kept_over_different_service_bytes(false).await;
}

/// Same, with the wired `package-lock.json` a symlink to the real lock: the
/// put-back rewrites the link's target and leaves the link in place.
#[cfg(unix)]
#[tokio::test]
async fn repair_identity_undo_follows_a_symlinked_lockfile() {
    identity_kept_over_different_service_bytes(true).await;
}

async fn identity_kept_over_different_service_bytes(symlinked_lock: bool) {
    let mock = MockServer::start().await;
    mount_patch_api(&mock).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(
        tmp.path(),
        "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        "sha512-orig==",
    );
    let tgz = vendor_project(tmp.path(), &mock.uri(), &[]);
    // The wired lock moved behind a symlink after vendoring.
    #[cfg(unix)]
    if symlinked_lock {
        let lock = tmp.path().join("package-lock.json");
        std::fs::rename(&lock, tmp.path().join("real-lock.json")).unwrap();
        std::os::unix::fs::symlink("real-lock.json", &lock).unwrap();
    }
    let tgz_bytes = std::fs::read(&tgz).unwrap();
    let lock1 = std::fs::read(tmp.path().join("package-lock.json")).unwrap();
    let state1 = std::fs::read(tmp.path().join(".socket/vendor/state.json")).unwrap();

    let service_bytes = retar(&tgz_bytes, 1_234_567, |_| {});
    assert_ne!(service_bytes, tgz_bytes, "fixture: the bytes must differ");
    let serve = "/serve/left-pad-1.3.0.tgz";
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/package")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "results": { UUID: {
                "status": "granted",
                "url": format!("{}{serve}", mock.uri()),
                "artifacts": [{ "kind": "tarball", "url": format!("{}{serve}", mock.uri()),
                                "integrity": { "sha512": sri_of(&service_bytes) } }]
            }}
        })))
        .with_priority(1)
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path(serve))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(service_bytes.clone()))
        .mount(&mock)
        .await;

    std::fs::remove_file(&tgz).unwrap();
    let (code, stdout, stderr) = run_cli(tmp.path(), &mock.uri(), &["repair"]);
    assert_eq!(code, 0, "stdout={stdout} stderr={stderr}");
    let v = parse_env(&stdout);
    assert_eq!(v["summary"]["rebuilt"], 1, "envelope={v}");
    assert_eq!(
        std::fs::read(&tgz).unwrap(),
        tgz_bytes,
        "the recorded bytes"
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
    if symlinked_lock {
        let meta = std::fs::symlink_metadata(tmp.path().join("package-lock.json")).unwrap();
        assert!(meta.file_type().is_symlink(), "the lockfile link is kept");
    }
}
