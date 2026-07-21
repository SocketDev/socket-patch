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

/// Spawn the built binary in `root` with `extra_env` injected into the
/// child environment.
fn run_cli_env(root: &Path, argv: &[&str], extra_env: &[(&str, &str)]) -> (i32, String, String) {
    let mut cmd = Command::new(binary());
    cmd.args(argv).current_dir(root);
    // Scrub the ambient `SOCKET_*` surface (prefix scrub — fixed lists rot)
    // so a developer's shell can't steer the child, then force the telemetry
    // kill-switch: telemetry resolves its endpoint from `SOCKET_API_URL` /
    // `SOCKET_PROXY_URL` env ONLY (`--api-url` is invisible to it), so an
    // ambient value would send every run's events to the LIVE API with the
    // fake bearer token. Caller-supplied env lands last so explicit
    // injections survive the scrub —
    // `scan_vendor_emits_no_telemetry_even_with_endpoint_env` seeds those
    // endpoint vars deliberately and proves the kill-switch still holds.
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("SOCKET_")
            && key.to_string_lossy() != "SOCKET_NO_CONFIG"
        {
            cmd.env_remove(&key);
        }
    }
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1");
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("run");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
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
    run_cli_env(root, &argv, &[])
}

/// Vendor flows hold patch content in MEMORY: `.socket/` must end up with
/// nothing beyond the manifest and the committed vendor artifacts — no
/// `blobs/`, `diffs/`, `packages/`, or stray temp files.
fn assert_socket_dir_lean(root: &Path) {
    let entries: Vec<String> = std::fs::read_dir(root.join(".socket"))
        .expect(".socket exists")
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n != "apply.lock")
        .collect();
    assert!(
        entries
            .iter()
            .all(|n| n == "manifest.json" || n == "vendor"),
        "vendoring must not write blobs or temp files into .socket; found: {entries:?}"
    );
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
    assert_socket_dir_lean(tmp.path());

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
    assert!(
        !tmp.path().join(".socket/blobs").exists(),
        "detached vendoring must never persist blobs"
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

/// Interactive (non-JSON) `scan --vendor --detached` with a failing patch
/// view fetch must SAY what failed: exit 1 with a `[fail]` line naming the
/// purl on stderr. Regression guard: `download_patch_records`' failure arms
/// recorded the error only in their JSON report, so the human path exited
/// non-zero with no error output at all (the JSON report is discarded and
/// the vendor engine just says "No vendorable patches in scope").
#[tokio::test]
async fn scan_vendor_detached_fetch_failure_reports_error() {
    let mock = MockServer::start().await;
    // Discovery succeeds (batch + per-package search, same shapes as
    // `mount_patch_api`), but the view fetch fails.
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
        .mount(&mock)
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
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(500))
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    write_fixture(tmp.path());

    let out = Command::new(binary())
        .args([
            "scan",
            "--vendor",
            "--detached",
            "--yes",
            "--api-url",
            &mock.uri(),
            "--api-token",
            "fake-token",
            "--org",
            ORG_SLUG,
        ])
        .current_dir(tmp.path())
        .env("SOCKET_TELEMETRY_DISABLED", "1")
        .output()
        .expect("run");
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert_eq!(
        code, 1,
        "a failed download must exit non-zero; stdout={stdout}; stderr={stderr}"
    );
    assert!(
        stderr.contains("[fail]") && stderr.contains("left-pad"),
        "the failed fetch must be reported on stderr, not swallowed; \
         stdout={stdout}; stderr={stderr}"
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

/// No invocation in this suite may emit telemetry. Telemetry resolves its
/// endpoint from `SOCKET_API_URL` / `SOCKET_PROXY_URL` env ONLY (the
/// `--api-url` flag is invisible to it — utils::telemetry), so the
/// unhardened harness sent every successful run's `patch_vendored` event to
/// the LIVE `/v0/orgs/test-org/telemetry` with the fake bearer token. Seed
/// the child env with a reachable endpoint (worst case for the kill-switch)
/// and prove not a single telemetry request escapes.
#[tokio::test]
async fn scan_vendor_emits_no_telemetry_even_with_endpoint_env() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock, UUID).await;
    // Accept both telemetry arms: authenticated (`/v0/orgs/<slug>/telemetry`)
    // and public-proxy (`/patch/telemetry`). Unmatched requests are recorded
    // by wiremock anyway; mounting keeps the child's send path realistic.
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/telemetry")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
        .mount(&mock)
        .await;
    Mock::given(method("POST"))
        .and(path("/patch/telemetry"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
        .mount(&mock)
        .await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(tmp.path());

    let mock_uri = mock.uri();
    let (code, stdout, stderr) = run_cli_env(
        tmp.path(),
        &[
            "scan",
            "--json",
            "--vendor",
            "--yes",
            "--api-url",
            &mock_uri,
            "--api-token",
            "fake-token",
            "--org",
            ORG_SLUG,
        ],
        &[
            ("SOCKET_API_URL", mock_uri.as_str()),
            ("SOCKET_PROXY_URL", mock_uri.as_str()),
        ],
    );
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");

    let telemetry: Vec<String> = mock
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|r| r.url.path().to_string())
        .filter(|p| p.contains("telemetry"))
        .collect();
    assert!(
        telemetry.is_empty(),
        "test runs must never phone telemetry home (live-API leak when \
         SOCKET_API_URL is unset); observed: {telemetry:?}"
    );
}

// ───────────── percent-encoded scoped purls (API canonical form) ─────────────

const SCOPED_CRAWLER_PURL: &str = "pkg:npm/@scope/left-pad@1.3.0";
const SCOPED_API_PURL: &str = "pkg:npm/%40scope/left-pad@1.3.0";

/// Like `write_fixture`, but the installed package is the SCOPED
/// `@scope/left-pad` (the crawler reports the literal `@scope` form).
fn write_scoped_fixture(root: &Path) {
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
                "dependencies": { "@scope/left-pad": "^1.3.0" }
            },
            "node_modules/@scope/left-pad": {
                "version": "1.3.0",
                "resolved": "https://registry.npmjs.org/@scope/left-pad/-/left-pad-1.3.0.tgz",
                "integrity": "sha512-orig==",
                "license": "WTFPL"
            }
        }
    });
    let mut lock_bytes = serde_json::to_vec_pretty(&lock).unwrap();
    lock_bytes.push(b'\n');
    std::fs::write(root.join("package-lock.json"), lock_bytes).unwrap();

    let pkg = root.join("node_modules/@scope/left-pad");
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        pkg.join("package.json"),
        br#"{"name":"@scope/left-pad","version":"1.3.0"}"#,
    )
    .unwrap();
    std::fs::write(pkg.join("index.js"), BEFORE).unwrap();
}

/// Mock API that serves the patch under the percent-ENCODED purl (the
/// canonical form the production patches API returns for scoped packages),
/// while the batch request/response is keyed by the crawler's literal form.
async fn mount_scoped_patch_api(mock: &MockServer, uuid: &str) {
    let before_hash = git_sha256(BEFORE);
    let after_hash = git_sha256(AFTER);
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": SCOPED_CRAWLER_PURL,
                "patches": [{
                    "uuid": uuid,
                    "purl": SCOPED_API_PURL,
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
    // Per-package search: the crawler purl, urlencoded.
    Mock::given(method("GET"))
        .and(path(format!(
            "/v0/orgs/{ORG_SLUG}/patches/by-package/pkg%3Anpm%2F%40scope%2Fleft-pad%401.3.0"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [{
                "uuid": uuid,
                "purl": SCOPED_API_PURL,
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
            "purl": SCOPED_API_PURL,
            "publishedAt": "2026-01-01T00:00:00Z",
            "files": {
                "package/index.js": {
                    "beforeHash": before_hash,
                    "afterHash":  after_hash,
                    "blobContent": AFTER_B64,
                }
            },
            "vulnerabilities": {},
            "description": "Vendor patch",
            "license": "MIT",
            "tier": "free",
        })))
        .mount(mock)
        .await;
}

/// The production patches API serves scoped purls percent-encoded
/// (`pkg:npm/%40scope/...`) and scan stores them verbatim as manifest keys.
/// The whole pipeline — download, vendor lookup against the literal
/// `node_modules/@scope/...` install, lock rewiring, prune exemption — must
/// bridge the two spellings. (Flowise regression: `%40modelcontextprotocol`
/// failed with `package not installed`.)
#[tokio::test]
async fn scan_vendor_resolves_percent_encoded_scoped_purl() {
    let mock = MockServer::start().await;
    mount_scoped_patch_api(&mock, UUID).await;
    let tmp = tempfile::tempdir().unwrap();
    write_scoped_fixture(tmp.path());

    // --prune in the same run: the freshly-downloaded ENCODED manifest
    // entry must not be GC'd against the literal crawler purl.
    let (code, stdout, stderr) = run_scan_vendor(tmp.path(), &mock.uri(), &["--prune"]);
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(v["status"], "success", "envelope={v}");

    // Manifest keyed by the verbatim encoded purl — and NOT pruned.
    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(tmp.path().join(".socket/manifest.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        manifest["patches"][SCOPED_API_PURL]["uuid"], UUID,
        "manifest={manifest}"
    );
    assert_eq!(
        v["gc"]["prunedManifestEntries"],
        serde_json::json!([]),
        "the encoded entry must not look prunable: {v}"
    );

    // Vendored: artifact under the DECODED scope dir, lock rewired.
    assert_eq!(v["vendor"]["summary"]["applied"], 1, "envelope={v}");
    let tgz = tmp.path().join(format!(
        ".socket/vendor/npm/{UUID}/@scope/left-pad-1.3.0.tgz"
    ));
    assert!(tgz.is_file(), "tarball at the decoded scoped path");
    let lock = std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap();
    assert!(
        lock.contains(&format!(
            ".socket/vendor/npm/{UUID}/@scope/left-pad-1.3.0.tgz"
        )),
        "lock consumes the vendored tarball; lock={lock}"
    );
    // Ledger keyed by the verbatim encoded purl.
    let state: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(tmp.path().join(".socket/vendor/state.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(state["entries"][SCOPED_API_PURL]["uuid"], UUID, "{state}");
}

// ───────────────────── prune reconciles vendored state ─────────────────────

/// After a dependency is removed and re-locked, `scan --prune` (without
/// `--vendor`) reverts the now-unused vendored entry: lock restored, ledger
/// entry + manifest entry dropped, artifact dir removed.
#[tokio::test]
async fn scan_prune_reverts_unused_vendored_entry() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock, UUID).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(tmp.path());

    // A second installed package so the later prune run's crawl is
    // non-empty (left-pad itself gets removed below).
    let other = tmp.path().join("node_modules/keeper");
    std::fs::create_dir_all(&other).unwrap();
    std::fs::write(
        other.join("package.json"),
        br#"{"name":"keeper","version":"1.0.0"}"#,
    )
    .unwrap();

    let (code, stdout, stderr) = run_scan_vendor(tmp.path(), &mock.uri(), &[]);
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");

    // Simulate `npm uninstall left-pad` + re-lock: drop the dep from the
    // lock graph and remove the installed copy. The override-free npm
    // wiring leaves nothing else behind.
    let lock = serde_json::json!({
        "name": "scan-vendor-test",
        "version": "0.0.0",
        "lockfileVersion": 3,
        "requires": true,
        "packages": {
            "": { "name": "scan-vendor-test", "version": "0.0.0" }
        }
    });
    let mut lock_bytes = serde_json::to_vec_pretty(&lock).unwrap();
    lock_bytes.push(b'\n');
    std::fs::write(tmp.path().join("package-lock.json"), &lock_bytes).unwrap();
    std::fs::remove_dir_all(tmp.path().join("node_modules/left-pad")).unwrap();

    // Plain prune scan (read-only discovery + GC; no --vendor, no --apply).
    let out = Command::new(binary())
        .args([
            "scan",
            "--json",
            "--prune",
            "--yes",
            "--api-url",
            &mock.uri(),
            "--api-token",
            "fake-token",
            "--org",
            ORG_SLUG,
        ])
        .current_dir(tmp.path())
        .output()
        .expect("run");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let code = out.status.code().unwrap_or(-1);
    assert_eq!(code, 0, "stdout={stdout}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");

    assert_eq!(
        v["gc"]["revertedVendoredEntries"],
        serde_json::json!([PURL]),
        "gc must report the reverted entry: {v}"
    );

    // Ledger empty (an emptied state file may be removed outright),
    // manifest entry dropped, artifact gone.
    match std::fs::read_to_string(tmp.path().join(".socket/vendor/state.json")) {
        Ok(text) => {
            let state: serde_json::Value = serde_json::from_str(&text).unwrap();
            assert!(
                state["entries"].as_object().is_none_or(|m| m.is_empty()),
                "ledger entry removed: {state}"
            );
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => panic!("unexpected state.json read error: {e}"),
    }
    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(tmp.path().join(".socket/manifest.json")).unwrap(),
    )
    .unwrap();
    assert!(
        manifest["patches"]
            .as_object()
            .is_none_or(|m| !m.contains_key(PURL)),
        "manifest entry dropped: {manifest}"
    );
    assert!(
        !tmp.path()
            .join(format!(".socket/vendor/npm/{UUID}"))
            .exists(),
        "artifact dir removed"
    );
    // The (already left-pad-free) lock stays exactly as the user re-locked
    // it — the revert had nothing to restore there.
    assert_eq!(
        std::fs::read(tmp.path().join("package-lock.json")).unwrap(),
        lock_bytes
    );
}

/// Interactive (non-JSON) `scan --vendor` pre-verifies patch baselines:
/// installed content matching NEITHER hash is annotated BEFORE the
/// confirm prompt, and the run still vendors (auto-force) with the
/// `vendor_content_mismatch_overwritten` warning on stderr.
#[tokio::test]
async fn scan_vendor_annotates_mismatched_baseline_and_vendors_anyway() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock, UUID).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(tmp.path());
    // Divergent installed bytes: neither BEFORE nor AFTER.
    std::fs::write(
        tmp.path().join("node_modules/left-pad/index.js"),
        b"divergent\n",
    )
    .unwrap();

    let out = Command::new(binary())
        .args([
            "scan",
            "--vendor",
            "--yes",
            "--api-url",
            &mock.uri(),
            "--api-token",
            "fake-token",
            "--org",
            ORG_SLUG,
        ])
        .current_dir(tmp.path())
        .output()
        .expect("run");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code().unwrap_or(-1),
        0,
        "stdout={stdout}; stderr={stderr}"
    );
    assert!(
        stdout.contains("installed content differs from patch baseline"),
        "pre-prompt annotation present; stdout={stdout}"
    );
    assert!(
        stderr.contains("vendor_content_mismatch_overwritten"),
        "overwrite warning surfaced; stderr={stderr}"
    );
    // Vendored despite the mismatch.
    assert!(tmp
        .path()
        .join(format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz"))
        .is_file());
}

// ───────────── lockfile auto-fetch + scan lockfile supplement ─────────────

/// sha512 SRI of the given bytes (what an npm-family lock records).
fn sri_of(bytes: &[u8]) -> String {
    use base64::Engine as _;
    use sha2::Sha512;
    format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode(Sha512::digest(bytes))
    )
}

/// A pristine registry tarball for left-pad@1.3.0 whose index.js carries
/// the patch's BEFORE bytes.
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

/// Project fixture with a lockfile but NO node_modules: package.json +
/// package-lock.json whose left-pad entry resolves to `resolved_url` with
/// `integrity`.
fn write_lockfile_only_fixture(root: &Path, resolved_url: &str, integrity: &str) {
    std::fs::write(
        root.join("package.json"),
        r#"{ "name": "scan-vendor-test", "version": "0.0.0", "dependencies": { "left-pad": "^1.3.0" } }"#,
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
                "resolved": resolved_url,
                "integrity": integrity,
                "license": "WTFPL"
            }
        }
    });
    let mut lock_bytes = serde_json::to_vec_pretty(&lock).unwrap();
    lock_bytes.push(b'\n');
    std::fs::write(root.join("package-lock.json"), lock_bytes).unwrap();
}

/// Pre-seed `.socket/manifest.json` + the after-blob so a standalone
/// `vendor` run has local patch sources (no patch-API traffic).
fn seed_manifest_and_blob(root: &Path) {
    let socket = root.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    let manifest = serde_json::json!({
        "patches": {
            PURL: {
                "uuid": UUID,
                "exportedAt": "2026-01-01T00:00:00Z",
                "files": {
                    "package/index.js": {
                        "beforeHash": git_sha256(BEFORE),
                        "afterHash": git_sha256(AFTER),
                    }
                },
                "vulnerabilities": {},
                "description": "synthetic",
                "license": "MIT",
                "tier": "free"
            }
        }
    });
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    std::fs::write(socket.join("blobs").join(git_sha256(AFTER)), AFTER).unwrap();
}

async fn mount_registry_tarball(mock: &MockServer, tgz: Vec<u8>) {
    Mock::given(method("GET"))
        .and(path("/left-pad/-/left-pad-1.3.0.tgz"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(tgz))
        .mount(mock)
        .await;
}

fn run_vendor(root: &Path, extra: &[&str]) -> (i32, serde_json::Value, String) {
    let mut argv = vec!["vendor", "--json"];
    argv.extend_from_slice(extra);
    let out = Command::new(binary())
        .args(&argv)
        .current_dir(root)
        .env("SOCKET_TELEMETRY_DISABLED", "1")
        .output()
        .expect("run vendor");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let v: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("vendor --json must emit JSON: {e}\n{stdout}\n{stderr}"));
    (out.status.code().unwrap_or(-1), v, stderr)
}

/// A manifest patch whose package is NOT installed but IS lockfile-resolved
/// is fetched pristine from the registry (integrity-verified against the
/// lock) and vendored — node_modules never appears.
#[tokio::test]
async fn vendor_auto_fetches_missing_package_from_lockfile() {
    let mock = MockServer::start().await;
    let tgz = pristine_tgz();
    let integrity = sri_of(&tgz);
    mount_registry_tarball(&mock, tgz).await;

    let tmp = tempfile::tempdir().unwrap();
    write_lockfile_only_fixture(
        tmp.path(),
        &format!("{}/left-pad/-/left-pad-1.3.0.tgz", mock.uri()),
        &integrity,
    );
    seed_manifest_and_blob(tmp.path());

    let (code, v, _) = run_vendor(tmp.path(), &[]);
    assert_eq!(code, 0, "{v:#}");
    let events = v["events"].as_array().unwrap();
    assert!(
        events
            .iter()
            .any(|e| e["action"] == "applied" && e["purl"] == PURL),
        "{v:#}"
    );
    assert!(
        events
            .iter()
            .any(|e| e["errorCode"] == "vendor_fetched_missing"),
        "fetch surfaced as a warning event: {v:#}"
    );
    assert!(tmp
        .path()
        .join(format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz"))
        .is_file());
    let lock = std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap();
    assert!(lock.contains(&format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz")));
    assert!(
        !tmp.path().join("node_modules").exists(),
        "the project tree is never touched"
    );
}

/// Integrity mismatch between the lock and the served bytes is a distinct
/// vendor_fetch_failed failure — and nothing is written.
#[tokio::test]
async fn vendor_fetch_integrity_mismatch_is_vendor_fetch_failed() {
    let mock = MockServer::start().await;
    mount_registry_tarball(&mock, pristine_tgz()).await;

    let tmp = tempfile::tempdir().unwrap();
    write_lockfile_only_fixture(
        tmp.path(),
        &format!("{}/left-pad/-/left-pad-1.3.0.tgz", mock.uri()),
        &sri_of(b"the lock expects different bytes"),
    );
    seed_manifest_and_blob(tmp.path());

    let (code, v, _) = run_vendor(tmp.path(), &[]);
    assert_ne!(code, 0, "{v:#}");
    let events = v["events"].as_array().unwrap();
    assert!(
        events
            .iter()
            .any(|e| e["action"] == "failed" && e["errorCode"] == "vendor_fetch_failed"),
        "{v:#}"
    );
    assert!(
        !events
            .iter()
            .any(|e| e["errorCode"] == "package_not_installed"),
        "no duplicate not-installed skip: {v:#}"
    );
    assert!(!tmp.path().join(".socket/vendor").exists());
}

/// --offline refuses the fetch with a calm package_not_installed skip that
/// names the lockfile as the would-be source. No HTTP traffic happens (no
/// registry route is mounted — a request would 404 and fail differently).
#[tokio::test]
async fn vendor_offline_refuses_fetch_with_calm_skip() {
    let tmp = tempfile::tempdir().unwrap();
    write_lockfile_only_fixture(
        tmp.path(),
        "http://127.0.0.1:1/left-pad/-/left-pad-1.3.0.tgz",
        &sri_of(b"irrelevant"),
    );
    seed_manifest_and_blob(tmp.path());

    let (code, v, _) = run_vendor(tmp.path(), &["--offline"]);
    assert_ne!(code, 0, "not-installed stays a non-benign skip: {v:#}");
    let events = v["events"].as_array().unwrap();
    let skip = events
        .iter()
        .find(|e| e["errorCode"] == "package_not_installed")
        .unwrap_or_else(|| panic!("{v:#}"));
    assert!(
        skip["reason"]
            .as_str()
            .unwrap_or("")
            .contains("--offline prevents fetching"),
        "offline detail names the lockfile resolution: {v:#}"
    );
}

/// An entry whose lock records no integrity is never fetched (fail-closed)
/// and keeps the plain not-installed outcome plus an explanatory warning.
#[tokio::test]
async fn vendor_fetch_unverifiable_lock_entry_stays_not_installed() {
    let tmp = tempfile::tempdir().unwrap();
    // Hand-write a lock whose entry has no integrity field.
    std::fs::write(
        tmp.path().join("package.json"),
        r#"{ "name": "x", "version": "0.0.0" }"#,
    )
    .unwrap();
    std::fs::write(
        tmp.path().join("package-lock.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "name": "x", "version": "0.0.0", "lockfileVersion": 3,
            "packages": {
                "": { "name": "x", "version": "0.0.0" },
                "node_modules/left-pad": {
                    "version": "1.3.0",
                    "resolved": "http://127.0.0.1:1/left-pad/-/left-pad-1.3.0.tgz"
                }
            }
        }))
        .unwrap(),
    )
    .unwrap();
    seed_manifest_and_blob(tmp.path());

    let (code, v, _) = run_vendor(tmp.path(), &[]);
    assert_ne!(code, 0, "{v:#}");
    let events = v["events"].as_array().unwrap();
    assert!(
        events
            .iter()
            .any(|e| e["errorCode"] == "vendor_fetch_unverifiable"),
        "{v:#}"
    );
    assert!(
        events
            .iter()
            .any(|e| e["errorCode"] == "package_not_installed"),
        "{v:#}"
    );
}

/// The headline flow: a COMPLETELY fresh clone (lockfile, no node_modules,
/// no .socket) discovers from the lockfile and `scan --vendor` vendors
/// end-to-end via the registry fetch.
#[tokio::test]
async fn scan_vendor_works_on_a_completely_fresh_clone() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock, UUID).await;
    let tgz = pristine_tgz();
    let integrity = sri_of(&tgz);
    mount_registry_tarball(&mock, tgz).await;

    let tmp = tempfile::tempdir().unwrap();
    write_lockfile_only_fixture(
        tmp.path(),
        &format!("{}/left-pad/-/left-pad-1.3.0.tgz", mock.uri()),
        &integrity,
    );

    let (code, stdout, stderr) = run_scan_vendor(tmp.path(), &mock.uri(), &[]);
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(v["lockfileOnlyPackages"], 1, "{v}");
    assert_eq!(v["vendor"]["summary"]["applied"], 1, "{v}");
    assert!(tmp
        .path()
        .join(format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz"))
        .is_file());
    assert!(!tmp.path().join("node_modules").exists());
    assert_socket_dir_lean(tmp.path());

    // Second run: in sync.
    let (code, stdout, stderr) = run_scan_vendor(tmp.path(), &mock.uri(), &[]);
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    let events = v["vendor"]["events"].as_array().unwrap();
    assert!(
        events.iter().any(|e| e["errorCode"] == "already_vendored"),
        "{v}"
    );
    assert_socket_dir_lean(tmp.path());
}

/// Read-only discovery flags lockfile-only packages in JSON and the human
/// table.
#[tokio::test]
async fn scan_discovers_lockfile_only_packages_with_warning() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock, UUID).await;
    let tmp = tempfile::tempdir().unwrap();
    write_lockfile_only_fixture(
        tmp.path(),
        "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        &sri_of(b"unused for discovery"),
    );

    // JSON shape.
    let out = Command::new(binary())
        .args([
            "scan",
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
        .output()
        .expect("run");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(v["scannedPackages"], 1, "{v}");
    assert_eq!(v["lockfileOnlyPackages"], 1, "{v}");
    assert_eq!(v["packages"][0]["notInstalled"], true, "{v}");

    // Human output: the table marker + the note.
    let out = Command::new(binary())
        .args([
            "scan",
            "--api-url",
            &mock.uri(),
            "--api-token",
            "fake-token",
            "--org",
            ORG_SLUG,
            "--dry-run",
            "--yes",
        ])
        .current_dir(tmp.path())
        .env("SOCKET_TELEMETRY_DISABLED", "1")
        .output()
        .expect("run");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stdout.contains("[NOT INSTALLED]"),
        "stdout={stdout}; stderr={stderr}"
    );
    assert!(
        stderr.contains("not yet installed (lockfile-only)"),
        "stderr={stderr}"
    );
}

/// The not-installed flag must survive the API's purl spelling: the
/// patches API serves purls in canonical percent-encoded form
/// (`pkg:npm/%40scope/...` — see `utils::purl`), while the lockfile
/// supplement records the literal on-disk form (`pkg:npm/@scope/...`).
/// The apply-path skip partitions already bridge the encodings via
/// `normalize_purl`; the JSON `notInstalled` flag and the table's
/// `[NOT INSTALLED]` marker must agree with them.
#[tokio::test]
async fn scan_flags_scoped_lockfile_only_package_despite_api_purl_encoding() {
    const SCOPED_ENCODED: &str = "pkg:npm/%40scope/left-pad@1.3.0";
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": SCOPED_ENCODED,
                "patches": [{
                    "uuid": UUID,
                    "purl": SCOPED_ENCODED,
                    "tier": "free",
                    "cveIds": ["CVE-2026-0001"],
                    "ghsaIds": [],
                    "severity": "high",
                    "title": "scoped fixture"
                }]
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(&mock)
        .await;
    // Detail route for the human run's fetch phase (the purl is
    // URL-encoded into the path — match any by-package request).
    Mock::given(method("GET"))
        .and(wiremock::matchers::path_regex(format!(
            "^/v0/orgs/{ORG_SLUG}/patches/by-package/.+$"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [{
                "uuid": UUID,
                "purl": SCOPED_ENCODED,
                "publishedAt": "2026-01-01T00:00:00Z",
                "description": "Scoped patch",
                "license": "MIT",
                "tier": "free",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(&mock)
        .await;

    // Lockfile-only fixture for @scope/left-pad (literal on-disk spelling,
    // no node_modules).
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("package.json"),
        r#"{ "name": "scoped-test", "version": "0.0.0", "dependencies": { "@scope/left-pad": "^1.3.0" } }"#,
    )
    .unwrap();
    let lock = serde_json::json!({
        "name": "scoped-test",
        "version": "0.0.0",
        "lockfileVersion": 3,
        "requires": true,
        "packages": {
            "": {
                "name": "scoped-test",
                "version": "0.0.0",
                "dependencies": { "@scope/left-pad": "^1.3.0" }
            },
            "node_modules/@scope/left-pad": {
                "version": "1.3.0",
                "resolved": "https://registry.npmjs.org/@scope/left-pad/-/left-pad-1.3.0.tgz",
                "integrity": "sha512-unused==",
                "license": "WTFPL"
            }
        }
    });
    std::fs::write(
        tmp.path().join("package-lock.json"),
        serde_json::to_vec_pretty(&lock).unwrap(),
    )
    .unwrap();

    // JSON: the additive notInstalled flag must be set even though the
    // API spelled the purl percent-encoded.
    let out = Command::new(binary())
        .args([
            "scan",
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
        .output()
        .expect("run");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(v["lockfileOnlyPackages"], 1, "{v}");
    assert_eq!(v["packages"][0]["purl"], SCOPED_ENCODED, "{v}");
    assert_eq!(
        v["packages"][0]["notInstalled"], true,
        "notInstalled must bridge the API's percent-encoded purl: {v}"
    );

    // Human table: the [NOT INSTALLED] marker must match through the
    // encoding difference too.
    let out = Command::new(binary())
        .args([
            "scan",
            "--api-url",
            &mock.uri(),
            "--api-token",
            "fake-token",
            "--org",
            ORG_SLUG,
            "--dry-run",
            "--yes",
        ])
        .current_dir(tmp.path())
        .env("SOCKET_TELEMETRY_DISABLED", "1")
        .output()
        .expect("run");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stdout.contains("[NOT INSTALLED]"),
        "stdout={stdout}; stderr={stderr}"
    );
}

/// `scan --apply` skips lockfile-only patches calmly: exit 0, a skipped
/// record with package_not_installed, and NO manifest entry written.
#[tokio::test]
async fn scan_apply_skips_lockfile_only_without_error() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock, UUID).await;
    let tmp = tempfile::tempdir().unwrap();
    write_lockfile_only_fixture(
        tmp.path(),
        "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
        &sri_of(b"unused"),
    );

    let out = Command::new(binary())
        .args([
            "scan",
            "--json",
            "--apply",
            "--yes",
            "--api-url",
            &mock.uri(),
            "--api-token",
            "fake-token",
            "--org",
            ORG_SLUG,
        ])
        .current_dir(tmp.path())
        .env("SOCKET_TELEMETRY_DISABLED", "1")
        .output()
        .expect("run");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let code = out.status.code().unwrap_or(-1);
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(code, 0, "lockfile-only must not flip the exit code: {v}");
    assert_eq!(v["status"], "success", "{v}");
    let patches = v["apply"]["patches"].as_array().unwrap();
    assert!(
        patches
            .iter()
            .any(|p| p["action"] == "skipped" && p["errorCode"] == "package_not_installed"),
        "{v}"
    );
    assert!(
        !tmp.path().join(".socket/manifest.json").exists(),
        "no manifest entry is written for a not-installed package"
    );
}
