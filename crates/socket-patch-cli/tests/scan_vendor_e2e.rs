//! End-to-end tests for `scan --vendor` — the bot workflow that discovers
//! patches, fetches their records in memory, and vendors each patched
//! package into the committable `.socket/vendor/` tree instead of
//! applying in place. Vendored mode is manifest-free: the ledger's
//! embedded records are the only state written. Mock API + a real npm lockfile fixture, driven
//! through the built binary.

#[path = "prebuilt_common/mod.rs"]
mod prebuilt_common;

use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[path = "npm_e2e_common/manifestless.rs"]
mod npm_e2e_common;
#[path = "vex_e2e_common/mod.rs"]
mod vex_e2e_common;

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
    let archive_view = serde_json::json!({
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
    });
    prebuilt_common::mount_view(mock, &archive_view, None).await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/view/{uuid}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(archive_view))
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

/// How many `/patches/view/…` requests the mock has served.
async fn view_fetches(mock: &MockServer) -> usize {
    mock.received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path().contains("/patches/view/"))
        .count()
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

/// Vendored mode writes ONLY `.socket/vendor/**`: no manifest, no
/// `blobs/`, `diffs/`, `packages/`, no stray temp files — and no
/// `apply.lock`, which every run removes on exit.
fn assert_socket_dir_lean(root: &Path) {
    let entries: Vec<String> = std::fs::read_dir(root.join(".socket"))
        .expect(".socket exists")
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        entries,
        vec!["vendor".to_string()],
        "vendored mode must write only .socket/vendor; found: {entries:?}"
    );
}

#[tokio::test]
async fn scan_vendor_end_to_end_is_manifest_free() {
    // scan --vendor: discover → fetch records in memory → vendor. The
    // ledger (with embedded records) is the only state written.
    let mock = MockServer::start().await;
    mount_patch_api(&mock, UUID).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(tmp.path());

    let (code, stdout, stderr) = run_scan_vendor(tmp.path(), &mock.uri(), &[]);
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(v["status"], "success", "envelope={v}");

    // Download phase: the record fetched in memory, nothing written.
    let dl = v["download"].as_object().expect("download sub-object");
    assert_eq!(dl["downloaded"], 1, "download={dl:?}");
    assert_eq!(dl["failed"], 0, "download={dl:?}");
    assert_eq!(dl["detached"], true, "download={dl:?}");
    assert_eq!(dl["patches"][0]["action"], "downloaded", "download={dl:?}");
    assert!(
        !tmp.path().join(".socket/manifest.json").exists(),
        "vendored mode never writes a manifest"
    );
    // One view fetch per patch for the whole run: the download phase's
    // blob content seeds the vendor stager, which never re-fetches it.
    assert_eq!(
        view_fetches(&mock).await,
        1,
        "the view is fetched exactly once"
    );

    // Vendor phase: a full vendor Envelope with one applied event.
    let venv = v["vendor"].as_object().expect("vendor sub-object");
    assert_eq!(venv["command"], "vendor", "vendor={venv:?}");
    assert_eq!(venv["status"], "success", "vendor={venv:?}");
    assert_eq!(venv["summary"]["applied"], 1, "vendor={venv:?}");

    // Disk: tarball at the contract path, ledger entry DETACHED with the
    // embedded record (the verification source), lock rewired to consume
    // the vendored artifact.
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
    assert_eq!(
        entry["detached"], true,
        "every vendored entry is ledger-owned: {state}"
    );
    assert_eq!(
        entry["record"]["uuid"], UUID,
        "the embedded record is the verification source: {state}"
    );
    assert!(
        entry["record"]["files"]
            .as_object()
            .is_some_and(|f| !f.is_empty()),
        "the embedded record carries the afterHashes vex verifies against: {state}"
    );
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

    // Idempotent re-run: the embedded record is reused (no view fetch),
    // already_vendored skip, zero new applies.
    let (code, stdout, stderr) = run_scan_vendor(tmp.path(), &mock.uri(), &[]);
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    let v2: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(v2["status"], "success", "envelope={v2}");
    assert_eq!(v2["download"]["skipped"], 1, "envelope={v2}");
    assert_eq!(v2["vendor"]["summary"]["applied"], 0, "envelope={v2}");
    let events = v2["vendor"]["events"].as_array().expect("events");
    assert!(
        events
            .iter()
            .any(|e| e["action"] == "skipped" && e["errorCode"] == "already_vendored"),
        "re-run must be an already_vendored skip: {v2}"
    );
}

/// A batch endpoint that reports NO available patches for the installed
/// set — the shape a withdrawn patch (or a free account against a
/// paid-only catalog) produces. The by-package / view endpoints are
/// deliberately unmounted: nothing may reach them.
async fn mount_empty_discovery(mock: &MockServer) {
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [],
            "canAccessPaidPatches": false,
        })))
        .mount(mock)
        .await;
}

/// Seed a committed `.socket/manifest.json` plus its afterHash blob — the
/// state a repo has after `scan --vendor` was run and `.socket/vendor/`
/// was later wiped (or never committed). The blob lets the vendor engine
/// stage sources with no download phase and no network.
fn seed_committed_manifest(root: &Path) {
    let socket = root.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    std::fs::write(socket.join("blobs").join(git_sha256(AFTER)), AFTER).unwrap();
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
                "description": "Vendor patch",
                "license": "MIT",
                "tier": "free",
            }
        }
    });
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();
}

/// Vendored mode takes its work from DISCOVERY, never from a committed
/// manifest: with nothing discovered there is nothing to vendor, so
/// `scan --vendor` is a clean no-op that creates nothing — no
/// `.socket/vendor/`, no `apply.lock` — and a legacy manifest is left
/// byte-identical. Both arms agree (the interactive arm exits before the
/// vendor dispatch; the JSON arm's vendor step skips itself before taking
/// the lock). Rebuilding committed vendored state is `repair`'s job;
/// migrating a legacy manifest-mode project is a NON-empty vendored run's
/// (see `scan_vendor_migrates_legacy_manifest_mode_project`).
#[tokio::test]
async fn scan_vendor_with_empty_discovery_is_a_no_op() {
    let mock = MockServer::start().await;
    mount_empty_discovery(&mock).await;
    let uri = mock.uri();

    for json in [true, false] {
        let tmp = tempfile::tempdir().unwrap();
        write_fixture(tmp.path());
        seed_committed_manifest(tmp.path());
        let manifest_before = std::fs::read(tmp.path().join(".socket/manifest.json")).unwrap();
        let mut argv = vec![
            "scan",
            "--vendor",
            "--yes",
            "--api-url",
            &uri,
            "--api-token",
            "fake-token",
            "--org",
            ORG_SLUG,
        ];
        if json {
            argv.push("--json");
        }
        let (code, stdout, stderr) = run_cli_env(tmp.path(), &argv, &[]);
        assert_eq!(code, 0, "json={json}; stdout={stdout}; stderr={stderr}");
        if json {
            let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
            assert_eq!(v["download"]["found"], 0, "{v}");
            assert_eq!(v["download"]["detached"], true, "{v}");
            assert_eq!(v["vendor"]["summary"]["applied"], 0, "{v}");
        }
        assert!(
            !tmp.path().join(".socket/vendor").exists(),
            "json={json}: nothing discovered ⇒ nothing vendored; stdout={stdout}; stderr={stderr}"
        );
        assert!(
            !tmp.path().join(".socket/apply.lock").exists(),
            "json={json}: a run with nothing to vendor takes no lock"
        );
        assert_eq!(
            std::fs::read(tmp.path().join(".socket/manifest.json")).unwrap(),
            manifest_before,
            "json={json}: a committed manifest is not vendored mode's record source"
        );
    }
}

/// A project vendored by an older, manifest-mode CLI (manifest record +
/// NON-detached ledger entry at the same uuid): the next vendored run
/// migrates it — the ledger entry gains `detached: true` plus the embedded
/// record, the manifest record moves out (an emptied manifest stays as
/// `{"patches":{}}`), the run says so in `vendor.warnings[]` — and the run
/// after that is a fetch-free `skipped` re-run with nothing left to
/// migrate.
#[tokio::test]
async fn scan_vendor_migrates_legacy_manifest_mode_project() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock, UUID).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(tmp.path());
    // The legacy state, produced by the (still manifest-driven) standalone
    // `vendor` command from a committed manifest + blob.
    seed_committed_manifest(tmp.path());
    let (code, venv, stderr) = run_vendor(tmp.path(), &["--vendor-source", "service"]);
    assert_eq!(code, 0, "legacy setup: {venv:#} {stderr}");
    let state_path = tmp.path().join(".socket/vendor/state.json");
    let state: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&state_path).unwrap()).unwrap();
    assert_eq!(state["entries"][PURL]["uuid"], UUID, "{state}");
    assert!(
        state["entries"][PURL]["detached"].is_null(),
        "legacy setup must be manifest-tracked: {state}"
    );

    let (code, stdout, stderr) = run_scan_vendor(tmp.path(), &mock.uri(), &[]);
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(v["status"], "success", "{v}");
    // A legacy entry carries no record, so the view is fetched once more…
    assert_eq!(v["download"]["downloaded"], 1, "{v}");
    // …and the engine finds artifact + wiring already in sync.
    let events = v["vendor"]["events"].as_array().expect("events");
    assert!(
        events
            .iter()
            .any(|e| e["action"] == "skipped" && e["errorCode"] == "already_vendored"),
        "{v}"
    );
    assert!(
        v["vendor"]["warnings"]
            .as_array()
            .is_some_and(|ws| ws.iter().any(|w| {
                w["code"] == "vendor_manifest_record_migrated"
                    && w["detail"].as_str().unwrap_or("").contains(PURL)
            })),
        "the migration must be announced: {v}"
    );
    let state: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&state_path).unwrap()).unwrap();
    let entry = &state["entries"][PURL];
    assert_eq!(entry["detached"], true, "upgraded in place: {state}");
    assert_eq!(entry["record"]["uuid"], UUID, "record embedded: {state}");
    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(tmp.path().join(".socket/manifest.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        manifest,
        serde_json::json!({ "patches": {} }),
        "the record moved to the ledger; an emptied manifest is kept, not deleted"
    );
    assert!(tmp
        .path()
        .join(format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz"))
        .is_file());

    // Migrated: the re-run reuses the embedded record (no view fetch) and
    // has nothing left to warn about.
    let before_reqs = mock.received_requests().await.unwrap().len();
    let (code, stdout, stderr) = run_scan_vendor(tmp.path(), &mock.uri(), &[]);
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    let v2: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(v2["download"]["skipped"], 1, "{v2}");
    assert!(
        v2["vendor"].get("warnings").is_none(),
        "nothing left to migrate: {v2}"
    );
    let after_reqs = mock.received_requests().await.unwrap();
    assert!(
        !after_reqs[before_reqs..]
            .iter()
            .any(|r| r.url.path().contains("/patches/view/")),
        "a migrated project re-runs without re-fetching the view"
    );
}

#[tokio::test]
async fn scan_vendor_writes_no_manifest() {
    // scan --vendor: the manifest-free flow, embedded-record ledger and all.
    let mock = MockServer::start().await;
    mount_patch_api(&mock, UUID).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(tmp.path());

    let (code, stdout, stderr) =
        run_scan_vendor(tmp.path(), &mock.uri(), &["--vex", "out.vex.json"]);
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
    let (code, stdout, _) = run_scan_vendor(tmp.path(), &mock.uri(), &[]);
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

/// Interactive (non-JSON) `scan --vendor` with a failing patch
/// view fetch must SAY what failed: exit 1 with a `[fail]` line naming the
/// purl on stderr. Regression guard: `download_patch_records`' failure arms
/// recorded the error only in their JSON report, so the human path exited
/// non-zero with no error output at all (the JSON report is discarded and
/// the vendor engine just says "No vendorable patches in scope").
#[tokio::test]
async fn scan_vendor_fetch_failure_reports_error() {
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
    // With --yes no prompt was answered, so the header gets no blank line
    // of its own (the listing's trailing blank line separates the sections).
    assert!(
        stderr.contains("Downloading 1 patch...")
            && !stderr.starts_with('\n')
            && !stderr.contains("\n\nDownloading"),
        "no extra blank line before the header under --yes; stderr={stderr}"
    );
    assert!(
        stdout.contains("Nothing was vendored: 1 patch failed (see above)."),
        "the run ends with the empty-run line; stdout={stdout}"
    );
}

#[tokio::test]
async fn scan_vendor_flag_conflicts_are_clap_errors() {
    // --vendor conflicts with --apply/--sync.
    for argv in [
        &["scan", "--vendor", "--apply"][..],
        &["scan", "--vendor", "--sync"][..],
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
            stderr.contains("cannot be used with"),
            "argv={argv:?}: {stderr}"
        );
    }
}

/// No invocation in this suite may emit telemetry. Telemetry resolves its
/// endpoint from `SOCKET_API_URL` / `SOCKET_PROXY_URL` env ONLY (the
/// `--api-url` flag is invisible to it — telemetry), so the
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
    let archive_view = serde_json::json!({
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
    });
    prebuilt_common::mount_view(mock, &archive_view, None).await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/view/{uuid}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(archive_view))
        .mount(mock)
        .await;
}

/// The production patches API serves scoped purls percent-encoded
/// (`pkg:npm/%40scope/...`) and scan stores them verbatim as ledger keys.
/// The whole pipeline — download, vendor lookup against the literal
/// `node_modules/@scope/...` install, lock rewiring, GC exemption — must
/// bridge the two spellings. (Flowise regression: `%40modelcontextprotocol`
/// failed with `package not installed`.)
#[tokio::test]
async fn scan_vendor_resolves_percent_encoded_scoped_purl() {
    let mock = MockServer::start().await;
    mount_scoped_patch_api(&mock, UUID).await;
    let tmp = tempfile::tempdir().unwrap();
    write_scoped_fixture(tmp.path());

    // --prune in the same run: the freshly-vendored ENCODED entry must not
    // be GC'd against the literal crawler purl (nor by the lockfile-usage
    // probe — the lock consumes its artifact).
    let (code, stdout, stderr) = run_scan_vendor(tmp.path(), &mock.uri(), &["--prune"]);
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(v["status"], "success", "envelope={v}");

    assert!(
        !tmp.path().join(".socket/manifest.json").exists(),
        "vendored mode never writes a manifest"
    );
    assert_eq!(
        v["gc"]["prunedManifestEntries"],
        serde_json::json!([]),
        "nothing looks prunable: {v}"
    );
    assert_eq!(
        v["gc"]["revertedVendoredEntries"],
        serde_json::json!([]),
        "the just-vendored entry is lock-visible and must not be reverted: {v}"
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
/// `--vendor`) honors the drift-keep contract, then completes the reclaim
/// once the drift is undone:
///
/// 1. The wired lock entry VANISHED (an uninstall is one drift flavor —
///    the live lock no longer matches anything the wiring recorded), so
///    the backend revert keeps the artifacts (`RevertOutcome::
///    kept_artifact`) and the GC must keep the ledger entry too — pruning
///    it would let the orphan sweep destroy the kept artifacts (with the
///    recorded pre-vendor originals, the state a later `git checkout` of
///    the vendored lock still points at).
/// 2. Undoing the drift (restoring the pre-vendor registry lock — the
///    keep warning's documented remediation) converges every recorded
///    fragment, and the same prune then reverts fully: ledger entry
///    dropped, artifact dir removed, lock untouched.
///
/// Every vendored entry is ledger-owned (`detached`), and the lockfile-
/// usage leg of the GC judges entries by the LIVE lock, so being detached
/// exempts nothing here.
#[tokio::test]
async fn scan_prune_reverts_unused_vendored_entry() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock, UUID).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(tmp.path());
    let original_lock = std::fs::read(tmp.path().join("package-lock.json")).unwrap();

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
    assert!(
        !tmp.path().join(".socket/manifest.json").exists(),
        "vendored mode never writes a manifest"
    );

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
    let run_prune = || {
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
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let code = out.status.code().unwrap_or(-1);
        assert_eq!(code, 0, "stdout={stdout}");
        serde_json::from_str::<serde_json::Value>(stdout.trim()).expect("valid JSON")
    };

    // 1. Drifted (vanished) lock entry: everything is KEPT — nothing may
    //    be reported reverted, and the artifacts must survive the sweep.
    let v = run_prune();
    assert_eq!(
        v["gc"]["revertedVendoredEntries"],
        serde_json::json!([]),
        "a drift-kept entry must not be reported reverted: {v}"
    );
    let state: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(tmp.path().join(".socket/vendor/state.json")).unwrap(),
    )
    .unwrap();
    assert!(
        state["entries"][PURL].is_object(),
        "ledger entry must be kept: {state}"
    );
    assert!(
        tmp.path()
            .join(format!(".socket/vendor/npm/{UUID}"))
            .exists(),
        "kept artifacts must survive the orphan sweep"
    );
    // The (already left-pad-free) lock stays exactly as the user re-locked
    // it — the keep never edits a lock it refused to own.
    assert_eq!(
        std::fs::read(tmp.path().join("package-lock.json")).unwrap(),
        lock_bytes
    );

    // 2. Undo the drift: restore the pre-vendor registry lock, so every
    //    recorded fragment is converged. The same prune now reclaims fully.
    std::fs::write(tmp.path().join("package-lock.json"), &original_lock).unwrap();
    let v = run_prune();
    assert_eq!(
        v["gc"]["revertedVendoredEntries"],
        serde_json::json!([PURL]),
        "gc must report the reverted entry: {v}"
    );

    // Ledger empty (an emptied state file is removed outright), artifact
    // gone.
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
    assert!(
        !tmp.path()
            .join(format!(".socket/vendor/npm/{UUID}"))
            .exists(),
        "artifact dir removed"
    );
    // The converged revert restores nothing (the lock already equals every
    // recorded original), so the restored lock survives byte-for-byte.
    assert_eq!(
        std::fs::read(tmp.path().join("package-lock.json")).unwrap(),
        original_lock
    );
}

/// #541, npm package-lock flavor: after `npm uninstall left-pad` re-locks
/// the project without the vendored dependency, a vendored rescan skips
/// the stale ledger entry with a `vendor_ledger_entry_unwired` warning
/// and exits 0. Before, the ledger supplement re-added the entry and the
/// vendor step failed to re-vendor a package the lock no longer has.
#[tokio::test]
async fn scan_vendor_skips_ledger_entry_the_lock_no_longer_wires() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock, UUID).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(tmp.path());
    let other = tmp.path().join("node_modules/keeper");
    std::fs::create_dir_all(&other).unwrap();
    std::fs::write(
        other.join("package.json"),
        br#"{"name":"keeper","version":"1.0.0"}"#,
    )
    .unwrap();
    let (code, stdout, stderr) = run_scan_vendor(tmp.path(), &mock.uri(), &[]);
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");

    // `npm uninstall left-pad`: the lock and the installed copy are gone.
    let lock = serde_json::json!({
        "name": "scan-vendor-test",
        "version": "0.0.0",
        "lockfileVersion": 3,
        "requires": true,
        "packages": {
            "": { "name": "scan-vendor-test", "version": "0.0.0" }
        }
    });
    std::fs::write(
        tmp.path().join("package-lock.json"),
        serde_json::to_vec_pretty(&lock).unwrap(),
    )
    .unwrap();
    std::fs::remove_dir_all(tmp.path().join("node_modules/left-pad")).unwrap();
    // The patch API answers by requested purl: it has nothing for keeper.
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [],
            "canAccessPaidPatches": false,
        })))
        .with_priority(1)
        .mount(&mock)
        .await;

    let (code, stdout, stderr) = run_scan_vendor(tmp.path(), &mock.uri(), &[]);
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    let warned: Vec<&serde_json::Value> = v["warnings"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|w| w["code"] == "vendor_ledger_entry_unwired")
        .collect();
    assert_eq!(warned.len(), 1, "envelope={v}");
    assert!(
        warned[0]["detail"].as_str().unwrap().contains(PURL),
        "envelope={v}"
    );
    // A plain rescan reverts nothing: the entry waits for `--prune`.
    let state: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(tmp.path().join(".socket/vendor/state.json")).unwrap(),
    )
    .unwrap();
    assert!(state["entries"][PURL].is_object(), "{state}");
}

/// #541 with no dependency left: the crawl is empty, so the manifest half
/// of the GC is skipped, but a vendored `--prune` still runs the vendored
/// half (it asks the lockfile, not the crawl) instead of skipping the
/// reconcile forever. A plain rescan of the same project warns.
#[tokio::test]
async fn scan_vendor_prune_reconciles_unwired_entry_on_an_empty_crawl() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock, UUID).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(tmp.path());
    let (code, stdout, stderr) = run_scan_vendor(tmp.path(), &mock.uri(), &[]);
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");

    // `npm uninstall left-pad` of the only dependency.
    let lock = serde_json::json!({
        "name": "scan-vendor-test",
        "version": "0.0.0",
        "lockfileVersion": 3,
        "requires": true,
        "packages": {
            "": { "name": "scan-vendor-test", "version": "0.0.0" }
        }
    });
    std::fs::write(
        tmp.path().join("package-lock.json"),
        serde_json::to_vec_pretty(&lock).unwrap(),
    )
    .unwrap();
    std::fs::remove_dir_all(tmp.path().join("node_modules/left-pad")).unwrap();
    let unwired = |v: &serde_json::Value| {
        v["warnings"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|w| w["code"] == "vendor_ledger_entry_unwired")
            .count()
    };

    let (code, stdout, stderr) = run_scan_vendor(tmp.path(), &mock.uri(), &[]);
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(v["scannedPackages"], 0, "envelope={v}");
    assert_eq!(unwired(&v), 1, "envelope={v}");
    assert!(v.get("gc").is_none(), "no --prune, no GC: {v}");

    let (code, stdout, stderr) = run_scan_vendor(tmp.path(), &mock.uri(), &["--prune"]);
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(unwired(&v), 0, "the pruning run reconciles instead: {v}");
    // npm re-locked the entry away, so the wet revert drift-keeps it (see
    // `scan_prune_reverts_unused_vendored_entry`): the point here is that
    // the vendored GC ran at all on an empty crawl.
    assert_eq!(
        v["gc"]["keptVendoredEntries"],
        serde_json::json!([PURL]),
        "envelope={v}"
    );
}

/// Interactive (non-JSON) `scan --vendor` pre-verifies patch baselines:
/// installed content matching NEITHER hash is annotated before vendoring
/// starts, and the run still vendors (auto-force) with the
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
        stdout.contains(&format!("  {PURL}: installed content differs")),
        "the annotation names the purl; stdout={stdout}"
    );
    assert!(
        !stderr.contains("vendored the patched content anyway"),
        "the server archive does not overwrite installed content; stderr={stderr}"
    );
    // Vendored despite the mismatch.
    assert!(tmp
        .path()
        .join(format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz"))
        .is_file());
    // The pre-verify fetched the view; the download phase served the
    // record from that view and the stager from its blob content — one
    // fetch for the whole interactive run, not three.
    assert_eq!(
        view_fetches(&mock).await,
        1,
        "the view is fetched exactly once"
    );
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
    let fixture = prebuilt_common::Server::project(root);
    let out = Command::new(binary())
        .env("SOCKET_VENDOR_URL", &fixture.uri)
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
async fn vendor_downloads_missing_package_without_fetching_pristine_sources() {
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
            .any(|e| e["errorCode"] == "vendor_prebuilt_downloaded"),
        "service download reported: {v:#}"
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

/// A lockfile-only npm package the patch service serves prebuilt: the
/// backend reads the pristine tarball only if the service falls back to a
/// local build, so the registry download is deferred until then — here,
/// never — and no `vendor_fetched_missing` is reported for it.
#[tokio::test]
async fn vendor_auto_takes_a_missing_package_from_the_service_without_the_registry() {
    let registry = MockServer::start().await;
    let tgz = pristine_tgz();
    let integrity = sri_of(&tgz);
    mount_registry_tarball(&registry, tgz).await;

    let prebuilt = {
        let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::default(),
        ));
        for (path, bytes) in [
            (
                "package/package.json",
                br#"{"name":"left-pad","version":"1.3.0"}"#.as_slice(),
            ),
            ("package/index.js", AFTER),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, path, bytes).unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap()
    };
    let api = MockServer::start().await;
    let serve_path = format!("/patch/npm/left-pad/1.3.0/tok/{UUID}/left-pad-1.3.0.tgz");
    let serve_url = format!("{}{serve_path}", api.uri());
    Mock::given(method("POST"))
        .and(path("/v0/orgs/acme/patches/package"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "results": { UUID: {
                "status": "granted", "url": serve_url, "purl": PURL,
                "artifacts": [{ "kind": "tarball", "url": serve_url,
                                "integrity": { "sha512": sri_of(&prebuilt) } }]
            }}
        })))
        .mount(&api)
        .await;
    Mock::given(method("GET"))
        .and(path(serve_path))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(prebuilt))
        .mount(&api)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    write_lockfile_only_fixture(
        tmp.path(),
        &format!("{}/left-pad/-/left-pad-1.3.0.tgz", registry.uri()),
        &integrity,
    );
    seed_manifest_and_blob(tmp.path());
    let vendor = |extra: &[&str]| {
        let mut cmd = Command::new(binary());
        cmd.args([
            "vendor",
            "--json",
            "--vendor-source",
            "auto",
            "--api-url",
            &api.uri(),
            "--api-token",
            "sktsec_placeholder_value_for_tests_api",
            "--org",
            "acme",
        ])
        .args(extra)
        .current_dir(tmp.path());
        for (key, _) in std::env::vars() {
            if key.starts_with("SOCKET_") && key != "SOCKET_NO_CONFIG" {
                cmd.env_remove(key);
            }
        }
        let out = cmd.env("SOCKET_TELEMETRY_DISABLED", "1").output().unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        let v: serde_json::Value = serde_json::from_str(stdout.trim())
            .unwrap_or_else(|e| panic!("{e}: {stdout}\n{}", String::from_utf8_lossy(&out.stderr)));
        (out.status.code(), v)
    };

    // Offline, nothing is deferred to a service it cannot reach: the
    // not-installed skip (exit 1, as before), and no request to either
    // server.
    let (code, v) = vendor(&["--offline"]);
    assert_eq!(code, Some(1), "{v:#}");
    assert!(
        v["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["purl"] == PURL
                && e["action"] == "failed"
                && e["errorCode"] == "vendor_service_offline_conflict"),
        "{v:#}"
    );
    assert!(registry
        .received_requests()
        .await
        .unwrap_or_default()
        .is_empty());
    assert!(api.received_requests().await.unwrap_or_default().is_empty());

    let (code, v) = vendor(&[]);
    assert_eq!(code, Some(0), "{v:#}");
    let events = v["events"].as_array().unwrap();
    assert!(
        events
            .iter()
            .any(|e| e["action"] == "applied" && e["purl"] == PURL),
        "{v:#}"
    );
    assert!(
        !events
            .iter()
            .any(|e| e["errorCode"] == "vendor_fetched_missing"),
        "no pristine fetch happened, so none is reported: {v:#}"
    );
    assert!(
        registry
            .received_requests()
            .await
            .unwrap_or_default()
            .is_empty(),
        "the pristine tarball is never downloaded"
    );
    assert!(tmp
        .path()
        .join(format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz"))
        .is_file());
}

/// Integrity mismatch between the lock and the served bytes is a distinct
/// vendor_fetch_failed failure — and nothing is written.
#[tokio::test]
async fn vendor_uses_service_integrity_without_fetching_old_registry_bytes() {
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
    assert_eq!(code, 0, "{v:#}");
    assert!(mock.received_requests().await.unwrap().is_empty());
    assert!(tmp
        .path()
        .join(format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0.tgz"))
        .is_file());
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
    assert!(v["events"].as_array().unwrap().iter().any(|e| e["action"] == "failed" && e["errorCode"] == "vendor_service_offline_conflict"), "{v:#}");
}

/// An entry whose lock records no integrity is never fetched (fail-closed)
/// and keeps the plain not-installed outcome plus an explanatory warning.
#[tokio::test]
async fn vendor_verifies_server_artifact_without_old_lock_integrity() {
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
    assert_eq!(code, 0, "{v:#}");
    assert_eq!(v["summary"]["applied"], 1, "{v:#}");
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

/// A bare (hosted-mode) scan flags lockfile-only packages in JSON and the
/// human table.
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

// ---------------------------------------------------------------------------
// Bun vendored-mode preflight through `scan`: download phase, --silent
// ---------------------------------------------------------------------------

const BUN_WS_CODE: &str = "vendor_bun_workspace_unsupported";

/// `write_fixture` re-locked by bun 1.3.14 as a workspace: the real
/// lockfileVersion-1 grammar (1-tuple `workspace:` entry, blank line
/// between entries, trailing commas; registry integrity from the BN3 spike
/// fixture), left-pad declared by the member — the shape the vendored gate
/// refuses (bun < 1.4 resolves member tarball paths relative to the member).
fn write_bun_v1_workspace_fixture(root: &Path) {
    write_fixture(root);
    std::fs::remove_file(root.join("package-lock.json")).unwrap();
    std::fs::write(
        root.join("package.json"),
        r#"{ "name": "scan-vendor-test", "version": "0.0.0", "private": true, "workspaces": ["packages/*"], "dependencies": { "consumer": "workspace:*" } }"#,
    )
    .unwrap();
    let consumer = root.join("packages/consumer");
    std::fs::create_dir_all(&consumer).unwrap();
    std::fs::write(
        consumer.join("package.json"),
        r#"{ "name": "consumer", "version": "1.0.0", "dependencies": { "left-pad": "1.3.0" } }"#,
    )
    .unwrap();
    std::fs::write(
        root.join("bun.lock"),
        "{\n  \"lockfileVersion\": 1,\n  \"configVersion\": 1,\n  \"workspaces\": {\n    \"\": {\n      \"name\": \"scan-vendor-test\",\n      \"dependencies\": {\n        \"consumer\": \"workspace:*\",\n      },\n    },\n    \"packages/consumer\": {\n      \"name\": \"consumer\",\n      \"version\": \"1.0.0\",\n      \"dependencies\": {\n        \"left-pad\": \"1.3.0\",\n      },\n    },\n  },\n  \"packages\": {\n    \"consumer\": [\"consumer@workspace:packages/consumer\"],\n\n    \"left-pad\": [\"left-pad@1.3.0\", \"\", {}, \"sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA==\"],\n  }\n}\n",
    )
    .unwrap();
}

/// The vendored scan refuses a v1 workspace lock IN THE DOWNLOAD PHASE:
/// the record is `failed` with the vendor code + detail, nothing is
/// fetched (request-log oracle), the lock is byte-identical, nothing is
/// vendored — and a run with nothing left to vendor creates nothing under
/// `.socket/` at all.
#[tokio::test]
async fn scan_vendored_bun_v1_workspace_refuses_in_download_phase() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock, UUID).await;
    let tmp = tempfile::tempdir().unwrap();
    write_bun_v1_workspace_fixture(tmp.path());
    let lock_before = std::fs::read(tmp.path().join("bun.lock")).unwrap();

    let (code, stdout, stderr) = run_scan_vendor(tmp.path(), &mock.uri(), &["--mode", "vendored"]);
    assert_eq!(code, 1, "stdout={stdout}; stderr={stderr}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(v["status"], "partial_failure", "envelope={v}");
    let dl = &v["download"];
    assert_eq!(dl["found"], 1, "envelope={v}");
    assert_eq!(dl["downloaded"], 0, "envelope={v}");
    assert_eq!(dl["failed"], 1, "envelope={v}");
    assert_eq!(dl["patches"][0]["purl"], PURL, "envelope={v}");
    assert_eq!(dl["patches"][0]["action"], "failed", "envelope={v}");
    assert_eq!(dl["patches"][0]["errorCode"], BUN_WS_CODE, "envelope={v}");
    assert!(
        dl["patches"][0]["error"]
            .as_str()
            .is_some_and(|d| !d.is_empty()),
        "the refused record carries the engine's detail: {v}"
    );
    assert_eq!(v["vendor"]["summary"]["applied"], 0, "envelope={v}");

    let reqs = mock.received_requests().await.unwrap();
    assert!(
        !reqs.iter().any(|r| r.url.path().contains("/patches/view/")),
        "a refused patch must never be fetched"
    );
    assert_eq!(
        std::fs::read(tmp.path().join("bun.lock")).unwrap(),
        lock_before,
        "bun.lock must be byte-identical"
    );
    assert!(
        !tmp.path().join(".socket").exists(),
        "a fully refused run vendors nothing and creates nothing under .socket/"
    );
}

/// The interactive (`--silent`, non-JSON) arm: "errors only" means the
/// refusal line — code-tagged, naming the purl — stays on stderr while
/// stdout is empty, exit 1. Regression guard: the line was gated on
/// `!silent`, so a `--silent` scan exited 1 with no text at all.
#[tokio::test]
async fn scan_vendored_bun_silent_human_names_code_on_stderr() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock, UUID).await;
    let tmp = tempfile::tempdir().unwrap();
    write_bun_v1_workspace_fixture(tmp.path());

    let uri = mock.uri();
    let (code, stdout, stderr) = run_cli_env(
        tmp.path(),
        &[
            "scan",
            "--mode",
            "vendored",
            "--vendor-source",
            "service",
            "--silent",
            "--yes",
            "--api-url",
            &uri,
            "--api-token",
            "fake-token",
            "--org",
            ORG_SLUG,
        ],
        &[],
    );
    assert_eq!(code, 1, "stdout={stdout}; stderr={stderr}");
    assert!(
        stdout.trim().is_empty(),
        "--silent must print nothing on stdout:\n{stdout}"
    );
    assert!(
        stderr.contains(&format!("[error] {PURL} ({BUN_WS_CODE}):")),
        "--silent must keep the code-tagged refusal on stderr:\n{stderr}"
    );
    assert!(!tmp.path().join(".socket/vendor").exists());
}

// ---------------------------------------------------------------------------
// vlt vendored mode through `scan` (DESIGN §4.6): the preflight in the
// download phase and the dry-run preview, and a direct dependency vendored
// ---------------------------------------------------------------------------

const VLT_TRANSITIVE_CODE: &str = "vendor_vlt_transitive_unsupported";

/// `left-pad` in vlt's store, reached from the root through `has` (a
/// transitive target) or directly.
fn write_vlt_fixture(root: &Path, transitive: bool) {
    write_fixture(root);
    std::fs::remove_file(root.join("package-lock.json")).unwrap();
    std::fs::remove_dir_all(root.join("node_modules")).unwrap();
    let store = root.join("node_modules/.vlt/~npm~left-pad@1.3.0/node_modules/left-pad");
    std::fs::create_dir_all(&store).unwrap();
    std::fs::write(
        store.join("package.json"),
        br#"{"name":"left-pad","version":"1.3.0"}"#,
    )
    .unwrap();
    std::fs::write(store.join("index.js"), BEFORE).unwrap();
    let (dep, nodes, edges) = if transitive {
        (
            "has",
            "    \"~npm~has@1.0.0\": [0,\"has\",\"sha512-H==\"],\n    \"~npm~left-pad@1.3.0\": [0,\"left-pad\",\"sha512-orig==\"]",
            "    \"file~_d has\": \"prod 1.0.0 ~npm~has@1.0.0\",\n    \"~npm~has@1.0.0 left-pad\": \"prod ^1.3.0 ~npm~left-pad@1.3.0\"",
        )
    } else {
        (
            "left-pad",
            "    \"~npm~left-pad@1.3.0\": [0,\"left-pad\",\"sha512-orig==\"]",
            "    \"file~_d left-pad\": \"prod 1.3.0 ~npm~left-pad@1.3.0\"",
        )
    };
    let spec = if transitive { "1.0.0" } else { "1.3.0" };
    std::fs::write(
        root.join("package.json"),
        format!("{{\n  \"name\": \"scan-vendor-test\",\n  \"dependencies\": {{\n    \"{dep}\": \"{spec}\"\n  }}\n}}\n"),
    )
    .unwrap();
    std::fs::write(
        root.join("vlt-lock.json"),
        format!(
            "{{\n  \"lockfileVersion\": 1,\n  \"options\": {{}},\n  \"nodes\": {{\n{nodes}\n  }},\n  \"edges\": {{\n{edges}\n  }}\n}}\n"
        ),
    )
    .unwrap();
}

#[tokio::test]
async fn scan_vendored_vlt_transitive_refuses_in_download_phase() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock, UUID).await;
    let tmp = tempfile::tempdir().unwrap();
    write_vlt_fixture(tmp.path(), true);
    let lock_before = std::fs::read(tmp.path().join("vlt-lock.json")).unwrap();
    let (code, stdout, stderr) = run_scan_vendor(tmp.path(), &mock.uri(), &["--mode", "vendored"]);
    assert_eq!(code, 1, "stdout={stdout}; stderr={stderr}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    let dl = &v["download"];
    assert_eq!(dl["failed"], 1, "envelope={v}");
    assert_eq!(
        dl["patches"][0]["errorCode"], VLT_TRANSITIVE_CODE,
        "envelope={v}"
    );
    assert_eq!(
        view_fetches(&mock).await,
        0,
        "a refused patch is never fetched"
    );
    assert_eq!(
        std::fs::read(tmp.path().join("vlt-lock.json")).unwrap(),
        lock_before
    );
    assert!(!tmp.path().join(".socket").exists());

    let (code, stdout, stderr) = run_scan_vendor(
        tmp.path(),
        &mock.uri(),
        &["--mode", "vendored", "--dry-run"],
    );
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    let text = v.to_string();
    assert!(
        text.contains("would_refuse") && text.contains(VLT_TRANSITIVE_CODE),
        "envelope={v}"
    );
    assert!(!tmp.path().join(".socket").exists());
}

#[tokio::test]
async fn scan_vendored_vlt_direct_dependency_vendors() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock, UUID).await;
    let tmp = tempfile::tempdir().unwrap();
    write_vlt_fixture(tmp.path(), false);
    let (code, stdout, stderr) = run_scan_vendor(tmp.path(), &mock.uri(), &["--mode", "vendored"]);
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    let rel = format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0/node_modules/left-pad");
    assert_eq!(
        std::fs::read(tmp.path().join(&rel).join("index.js")).unwrap(),
        AFTER
    );
    let lock = std::fs::read_to_string(tmp.path().join("vlt-lock.json")).unwrap();
    assert!(lock.contains(&format!("prod file:./{rel} ")), "{lock}");
    let state: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(tmp.path().join(".socket/vendor/state.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(state["entries"][PURL]["flavor"], "vlt", "{state}");
    assert_socket_dir_lean(tmp.path());
}

/// Manifest-less VEX over the committed state `scan --vendor` leaves
/// (manifest-free since 5.0 — the ledger's `detached` entries embed the
/// records, so there is one shape to cover): the checkout attests `(vendored)` from the ledger's
/// embedded record, then from lockfile discovery + the patch API once the
/// ledgers are gone too, never `--offline` (`record_unavailable`, zero
/// requests), and not once the lock is reverted (`vendor_unwired`,
/// `--no-verify` too). The embedded `scan --vendor --vex` of the producing
/// run attests as well. The manifest-driven standalone `vendor` shape (a
/// NON-detached entry with a fallback record) is
/// `standalone_vendor_state_attests_from_the_embedded_record`.
#[tokio::test]
async fn scan_vendor_state_attests_manifest_less() {
    let mock = MockServer::start().await;
    mount_patch_api(&mock, UUID).await;
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(tmp.path());
    let pristine = std::fs::read(tmp.path().join("package-lock.json")).unwrap();
    let (code, stdout, stderr) =
        run_scan_vendor(tmp.path(), &mock.uri(), &["--vex", "out.vex.json"]);
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(
        v["vex"]["statements"], 1,
        "embedded scan --vendor --vex: {v}"
    );
    assert!(
        !tmp.path().join(".socket/manifest.json").exists(),
        "vendored mode writes no manifest"
    );

    let checkout = tmp.path().join("checkout");
    npm_e2e_common::fresh_checkout(tmp.path(), &checkout, &["package-lock.json"]);
    run_manifestless_tail("scan --vendor", &checkout, pristine);
}

/// The committed state of the manifest-driven standalone `vendor` — the
/// one writer of NON-detached ledger entries, which embed the patch record
/// as a fallback copy — once `.socket/manifest.json` (and its blobs) are
/// gone, like a checkout that never committed them. The real writer must
/// embed the record in that non-detached entry; offline `vex` must then
/// attest from it with no manifest, and `list` must show the same patch
/// (labeled `vendored`) instead of `manifest_not_found` — one tree never
/// reads "no patches" while its VEX document attests one. The shared
/// manifest-less tail then runs over a fresh checkout.
#[tokio::test]
async fn standalone_vendor_state_attests_from_the_embedded_record() {
    let tmp = tempfile::tempdir().unwrap();
    write_fixture(tmp.path());
    let pristine = std::fs::read(tmp.path().join("package-lock.json")).unwrap();
    seed_manifest_and_blob_with_vuln(tmp.path());

    let (code, v, stderr) = run_vendor(tmp.path(), &[]);
    assert_eq!(code, 0, "{v:#}\n{stderr}");
    assert_eq!(v["summary"]["applied"], 1, "{v:#}");
    let state: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(tmp.path().join(".socket/vendor/state.json")).unwrap(),
    )
    .unwrap();
    let entry = &state["entries"][PURL];
    assert_eq!(entry["uuid"], UUID, "{state:#}");
    assert!(
        entry["detached"].as_bool() != Some(true),
        "standalone vendor entries are manifest-owned, never detached: {state:#}"
    );
    assert_eq!(
        entry["record"]["uuid"], UUID,
        "the real writer embeds the fallback record: {state:#}"
    );
    assert_eq!(
        entry["record"]["files"]["package/index.js"]["afterHash"],
        git_sha256(AFTER),
        "the embedded record carries the afterHashes vex verifies against: {state:#}"
    );

    // Drop the manifest and its blobs: the ledger's copy is all that is left.
    std::fs::remove_file(tmp.path().join(".socket/manifest.json")).unwrap();
    std::fs::remove_dir_all(tmp.path().join(".socket/blobs")).unwrap();

    let out = vex_e2e_common::run_vex(
        &vex_e2e_common::binary(),
        tmp.path(),
        &vex_e2e_common::VexRun::offline(),
    );
    assert_eq!(
        out.code,
        Some(0),
        "offline vex from the embedded record:\n{out}"
    );
    vex_e2e_common::assert_attested(
        out.doc(),
        PURL,
        UUID,
        vex_e2e_common::Marker::Vendored,
        &[("GHSA-aaaa-bbbb-cccc", &["CVE-2026-0001"])],
    );

    let (code, stdout, stderr) = run_cli_env(tmp.path(), &["list", "--json"], &[]);
    assert_eq!(code, 0, "list sees what vex attests: {stdout}\n{stderr}");
    let listed: serde_json::Value = serde_json::from_str(stdout.trim()).expect("list JSON");
    let events = listed["events"].as_array().expect("events");
    assert_eq!(events.len(), 1, "{listed:#}");
    assert_eq!(events[0]["purl"], PURL, "{listed:#}");
    assert_eq!(events[0]["uuid"], UUID, "{listed:#}");
    assert_eq!(events[0]["details"]["mode"], "vendored", "{listed:#}");
    assert_eq!(
        events[0]["details"]["ledger"], ".socket/vendor/state.json",
        "{listed:#}"
    );
    std::fs::remove_file(tmp.path().join("out.vex.json")).unwrap();

    let checkout = tmp.path().join("checkout");
    npm_e2e_common::fresh_checkout(tmp.path(), &checkout, &["package-lock.json"]);
    run_manifestless_tail("standalone vendor", &checkout, pristine);
}

/// `seed_manifest_and_blob` with the advisory the patch API mock serves,
/// so the record the standalone `vendor` embeds names what vex attests.
fn seed_manifest_and_blob_with_vuln(root: &Path) {
    seed_manifest_and_blob(root);
    let path = root.join(".socket/manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    manifest["patches"][PURL]["vulnerabilities"] = serde_json::json!({
        "GHSA-aaaa-bbbb-cccc": {
            "cves": ["CVE-2026-0001"],
            "summary": "test vuln",
            "severity": "high",
            "description": "details"
        }
    });
    std::fs::write(&path, serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();
}

/// The shared manifest-less VEX tail over a vendored npm `checkout`
/// (`manifestless_vex_matrix`, with the embedded `apply` / `vendor --vex`
/// runs), against a patch API serving `UUID`'s view.
fn run_manifestless_tail(label: &str, checkout: &Path, pristine: Vec<u8>) {
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
                    label: label.to_string(),
                    project: checkout,
                    purl: PURL,
                    uuid: UUID,
                    marker: vex_e2e_common::Marker::Vendored,
                    vulns: &[("GHSA-aaaa-bbbb-cccc", &["CVE-2026-0001"])],
                    api: &api,
                    patch_server_url: None,
                    registry_locks: vec![("package-lock.json", pristine)],
                    embedded: &[
                        vex_e2e_common::VexVia::Apply,
                        vex_e2e_common::VexVia::Vendor,
                    ],
                });
            })
            .join()
            .expect("manifest-less VEX tail panicked");
    });
}

// ───────────────────── the download plan is exact ─────────────────────

mod exact_download_plan {
    //! A vendored run fetches prebuilt archives ahead of its serial wiring
    //! loop, from a plan of the packages the loop will ask the service
    //! for. A download grant (`POST /patches/package`) can start a
    //! server-side build and counts against quota, so the plan must be
    //! EXACT: a package the loop refuses before it would ask the service
    //! — here a pnpm entry the backend cannot rewire — costs no grant at
    //! all, while every package the loop does reach costs exactly one.
    use super::*;
    use wiremock::matchers::path_regex;

    const UUID_A: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const UUID_B: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    const UUID_C: &str = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
    const PACKAGES: [(&str, &str); 3] = [("pkg-a", UUID_A), ("pkg-b", UUID_B), ("pkg-c", UUID_C)];

    fn purl(name: &str) -> String {
        format!("pkg:npm/{name}@1.0.0")
    }

    /// A pnpm 9 project with three installed, patched packages. `pkg-b`'s
    /// snapshot key carries a peer suffix (`1.0.0(peer-x@1.0.0)`), which
    /// the pnpm backend refuses as `vendor_lock_entry_unsupported` before
    /// staging anything, so the plan must not issue it a speculative grant.
    fn write_pnpm_fixture(root: &Path) {
        std::fs::write(
            root.join("package.json"),
            r#"{ "name": "plan-test", "version": "0.0.0", "dependencies": { "pkg-a": "1.0.0", "pkg-b": "1.0.0", "pkg-c": "1.0.0" } }"#,
        )
        .unwrap();
        std::fs::write(
            root.join("pnpm-lock.yaml"),
            "lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

importers:

  .:
    dependencies:
      pkg-a:
        specifier: 1.0.0
        version: 1.0.0
      pkg-b:
        specifier: 1.0.0
        version: 1.0.0(peer-x@1.0.0)
      pkg-c:
        specifier: 1.0.0
        version: 1.0.0

packages:

  pkg-a@1.0.0:
    resolution: {integrity: sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==}

  pkg-b@1.0.0:
    resolution: {integrity: sha512-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB==}
    peerDependencies:
      peer-x: '*'

  pkg-c@1.0.0:
    resolution: {integrity: sha512-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC==}

snapshots:

  pkg-a@1.0.0: {}

  pkg-b@1.0.0(peer-x@1.0.0): {}

  pkg-c@1.0.0: {}
",
        )
        .unwrap();
        for (name, _) in PACKAGES {
            let pkg = root.join("node_modules").join(name);
            std::fs::create_dir_all(&pkg).unwrap();
            std::fs::write(
                pkg.join("package.json"),
                format!(r#"{{"name":"{name}","version":"1.0.0"}}"#),
            )
            .unwrap();
            std::fs::write(pkg.join("index.js"), BEFORE).unwrap();
        }
    }

    /// Discovery, per-package search and views for the three patches, and a
    /// grant endpoint that answers `not_found` for every uuid (the loop then
    /// builds locally — the grant is what this test counts).
    async fn mount_three_patch_api(mock: &MockServer) {
        let before_hash = git_sha256(BEFORE);
        let after_hash = git_sha256(AFTER);
        let packages: Vec<serde_json::Value> = PACKAGES
            .iter()
            .map(|(name, uuid)| {
                serde_json::json!({
                    "purl": purl(name),
                    "patches": [{
                        "uuid": uuid, "purl": purl(name), "tier": "free",
                        "cveIds": ["CVE-2026-0001"], "ghsaIds": [], "severity": "high",
                        "title": "plan target"
                    }]
                })
            })
            .collect();
        Mock::given(method("POST"))
            .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/batch")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "packages": packages,
                "canAccessPaidPatches": false,
            })))
            .mount(mock)
            .await;
        for (name, uuid) in PACKAGES {
            let encoded = format!("pkg%3Anpm%2F{name}%401.0.0");
            Mock::given(method("GET"))
                .and(path(format!(
                    "/v0/orgs/{ORG_SLUG}/patches/by-package/{encoded}"
                )))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "patches": [{
                        "uuid": uuid, "purl": purl(name),
                        "publishedAt": "2026-01-01T00:00:00Z",
                        "description": "plan target", "license": "MIT", "tier": "free",
                        "vulnerabilities": {}
                    }],
                    "canAccessPaidPatches": false,
                })))
                .mount(mock)
                .await;
            let archive_view = serde_json::json!({
                "uuid": uuid,
                "purl": purl(name),
                "publishedAt": "2026-01-01T00:00:00Z",
                "files": {
                    "package/index.js": {
                        "beforeHash": before_hash,
                        "afterHash": after_hash,
                        "blobContent": AFTER_B64,
                    }
                },
                "vulnerabilities": {
                    "GHSA-aaaa-bbbb-cccc": {
                        "cves": ["CVE-2026-0001"], "summary": "test vuln",
                        "severity": "high", "description": "details"
                    }
                },
                "description": "plan target", "license": "MIT", "tier": "free",
            });
            crate::prebuilt_common::mount_view(mock, &archive_view, None).await;
            Mock::given(method("GET"))
                .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/view/{uuid}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(archive_view))
                .mount(mock)
                .await;
        }
        let results: serde_json::Map<String, serde_json::Value> = PACKAGES
            .iter()
            .map(|(_, uuid)| {
                (
                    uuid.to_string(),
                    serde_json::json!({ "status": "not_found", "url": null, "artifacts": [] }),
                )
            })
            .collect();
        Mock::given(method("POST"))
            .and(path_regex(format!("^/v0/orgs/{ORG_SLUG}/patches/package$")))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "results": results })),
            )
            .mount(mock)
            .await;
    }

    /// Every uuid the run asked a download grant for, in request order
    /// (one request may name several).
    async fn granted_uuids(mock: &MockServer) -> Vec<String> {
        mock.received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| {
                r.method == wiremock::http::Method::POST
                    && r.url.path().ends_with("/patches/package")
            })
            .flat_map(|r| {
                let body: serde_json::Value = serde_json::from_slice(&r.body).expect("grant body");
                body["uuids"]
                    .as_array()
                    .expect("uuids array")
                    .iter()
                    .map(|u| u.as_str().unwrap().to_string())
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    /// Composer twins of the three npm packages: `psr/cache` and `psr/log`
    /// are installed AND locked; `psr/http-message` is installed but absent
    /// from composer.lock, which the composer backend refuses as
    /// `vendor_lock_entry_not_found` before it asks the service. It sorts
    /// BETWEEN the two, in the middle of the loop (and plan) order: the
    /// prefetch only ever requests positions at or past the loop's, so a
    /// refused package the loop meets FIRST would be passed over before
    /// any request whether the plan named it or not — only one behind a
    /// granted position shows whether the gate kept it out of the plan.
    const COMPOSER: [(&str, &str, &str); 3] = [
        ("pkg:composer/psr/cache@1.0.0", "psr/cache", UUID_A),
        (
            "pkg:composer/psr/http-message@1.1.0",
            "psr/http-message",
            UUID_B,
        ),
        ("pkg:composer/psr/log@3.0.2", "psr/log", UUID_C),
    ];
    const COMPOSER_REFUSED: &str = "psr/http-message";

    fn write_composer_fixture(root: &Path) {
        std::fs::write(root.join("composer.json"), r#"{"require":{}}"#).unwrap();
        let locked: Vec<serde_json::Value> = COMPOSER
            .iter()
            .filter(|(_, name, _)| *name != COMPOSER_REFUSED)
            .map(|(purl, name, _)| {
                let version = purl.rsplit('@').next().unwrap();
                serde_json::json!({
                    "name": name, "version": version,
                    "dist": {"type": "zip", "url": format!("https://example.invalid/{name}.zip"),
                             "reference": "abc", "shasum": ""},
                    "type": "library"
                })
            })
            .collect();
        std::fs::write(
            root.join("composer.lock"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "content-hash": "x", "packages": locked, "packages-dev": []
            }))
            .unwrap(),
        )
        .unwrap();
        let installed: Vec<serde_json::Value> = COMPOSER
            .iter()
            .map(|(purl, name, _)| {
                serde_json::json!({
                    "name": name, "version": purl.rsplit('@').next().unwrap(),
                    "install-path": format!("../{name}")
                })
            })
            .collect();
        std::fs::create_dir_all(root.join("vendor/composer")).unwrap();
        std::fs::write(
            root.join("vendor/composer/installed.json"),
            serde_json::to_vec(&serde_json::json!({ "packages": installed })).unwrap(),
        )
        .unwrap();
        for (_, name, _) in COMPOSER {
            let pkg = root.join("vendor").join(name);
            std::fs::create_dir_all(&pkg).unwrap();
            std::fs::write(pkg.join("index.js"), BEFORE).unwrap();
        }
    }

    /// [`mount_three_patch_api`] for arbitrary `(purl, uuid)` pairs whose
    /// patch rewrites `file`.
    async fn mount_patch_api(mock: &MockServer, patches: &[(&str, &str)], file: &str) {
        let before_hash = git_sha256(BEFORE);
        let after_hash = git_sha256(AFTER);
        let packages: Vec<serde_json::Value> = patches
            .iter()
            .map(|(purl, uuid)| {
                serde_json::json!({
                    "purl": purl,
                    "patches": [{
                        "uuid": uuid, "purl": purl, "tier": "free",
                        "cveIds": ["CVE-2026-0001"], "ghsaIds": [], "severity": "high",
                        "title": "plan target"
                    }]
                })
            })
            .collect();
        Mock::given(method("POST"))
            .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/batch")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "packages": packages,
                "canAccessPaidPatches": false,
            })))
            .mount(mock)
            .await;
        for (purl, uuid) in patches {
            let encoded = purl
                .replace(':', "%3A")
                .replace('/', "%2F")
                .replace('@', "%40");
            Mock::given(method("GET"))
                .and(path(format!(
                    "/v0/orgs/{ORG_SLUG}/patches/by-package/{encoded}"
                )))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "patches": [{
                        "uuid": uuid, "purl": purl,
                        "publishedAt": "2026-01-01T00:00:00Z",
                        "description": "plan target", "license": "MIT", "tier": "free",
                        "vulnerabilities": {}
                    }],
                    "canAccessPaidPatches": false,
                })))
                .mount(mock)
                .await;
            let archive_view = serde_json::json!({
                "uuid": uuid,
                "purl": purl,
                "publishedAt": "2026-01-01T00:00:00Z",
                "files": {
                    file: {
                        "beforeHash": before_hash,
                        "afterHash": after_hash,
                        "blobContent": AFTER_B64,
                    }
                },
                "vulnerabilities": {
                    "GHSA-aaaa-bbbb-cccc": {
                        "cves": ["CVE-2026-0001"], "summary": "test vuln",
                        "severity": "high", "description": "details"
                    }
                },
                "description": "plan target", "license": "MIT", "tier": "free",
            });
            crate::prebuilt_common::mount_view(mock, &archive_view, None).await;
            Mock::given(method("GET"))
                .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/view/{uuid}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(archive_view))
                .mount(mock)
                .await;
        }
        let results: serde_json::Map<String, serde_json::Value> = patches
            .iter()
            .map(|(_, uuid)| {
                (
                    uuid.to_string(),
                    serde_json::json!({ "status": "not_found", "url": null, "artifacts": [] }),
                )
            })
            .collect();
        Mock::given(method("POST"))
            .and(path_regex(format!("^/v0/orgs/{ORG_SLUG}/patches/package$")))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "results": results })),
            )
            .mount(mock)
            .await;
    }

    /// The plan is exact beyond npm: every ecosystem's backend gate keeps
    /// the packages it refuses before its first service call out of the
    /// plan. Here the composer backend refuses `psr/http-message` (not in
    /// composer.lock, and in the middle of the loop order, behind a
    /// package the service answers) — zero grants — while the two locked
    /// packages it does ask the service for cost exactly one grant each.
    /// (`plan_gate_tests` in `commands/vendor.rs` pins the plan itself.)
    #[tokio::test]
    async fn a_composer_package_the_loop_refuses_costs_zero_grants() {
        assert!(
            !socket_patch_core::crawlers::walk_pool::fd_limit_is_tight(),
            "the descriptor limit is too tight for the download plan to be built, so this \
             test cannot exercise the pre-flight it pins; raise `ulimit -n` and re-run"
        );
        let mock = MockServer::start().await;
        let patches: Vec<(&str, &str)> = COMPOSER.iter().map(|(p, _, u)| (*p, *u)).collect();
        mount_patch_api(&mock, &patches, "index.js").await;
        let tmp = tempfile::tempdir().unwrap();
        write_composer_fixture(tmp.path());

        let (_code, stdout, stderr) = run_scan_vendor(tmp.path(), &mock.uri(), &[]);
        let v: serde_json::Value = serde_json::from_str(stdout.trim())
            .unwrap_or_else(|e| panic!("valid JSON: {e}\nstdout={stdout}\nstderr={stderr}"));
        let events = v["vendor"]["events"].as_array().expect("vendor events");
        let event_for = |purl: &str| {
            events
                .iter()
                .find(|e| e["purl"] == purl && e["action"] != "skipped")
                .unwrap_or_else(|| panic!("no vendor event for {purl}: {v}"))
        };
        assert_eq!(event_for(COMPOSER[0].0)["action"], "applied", "{v}");
        assert_eq!(event_for(COMPOSER[2].0)["action"], "applied", "{v}");
        let refused = event_for(COMPOSER[1].0);
        assert_eq!(refused["action"], "failed", "{v}");
        assert_eq!(refused["errorCode"], "vendor_lock_entry_not_found", "{v}");

        let mut granted = granted_uuids(&mock).await;
        granted.sort();
        assert_eq!(
            granted,
            vec![UUID_A.to_string(), UUID_C.to_string()],
            "exactly one grant per package the loop reaches the service for, and none \
             for the package it refuses first"
        );
    }

    /// A package the loop refuses before its first service call costs ZERO
    /// download grants: the plan is built from the backend's own pre-flight,
    /// so `pkg-b` is never asked for, while `pkg-a` and `pkg-c` — which the
    /// loop does ask for — cost exactly one grant each. `pkg-b`'s refusal
    /// reads only pnpm-lock.yaml, so the download phase raises it before
    /// fetching its view — the backend's code and words on a failed download
    /// record — and it costs no request at all.
    #[tokio::test]
    async fn a_package_the_loop_refuses_costs_zero_grants() {
        // The plan is only built when the run may keep more than one
        // request in flight, and a tight descriptor limit pins the API
        // concurrency at one whatever the environment says (the helper
        // already scrubs `SOCKET_API_CONCURRENCY`). The strictly serial
        // loop then trivially grants nothing for the refused package, and
        // this test would pass without the pre-flight it pins ever
        // running — so fail loudly rather than vacuously.
        assert!(
            !socket_patch_core::crawlers::walk_pool::fd_limit_is_tight(),
            "the descriptor limit is too tight for the download plan to be built, so this \
             test cannot exercise the pre-flight it pins; raise `ulimit -n` and re-run"
        );
        let mock = MockServer::start().await;
        mount_three_patch_api(&mock).await;
        let tmp = tempfile::tempdir().unwrap();
        write_pnpm_fixture(tmp.path());

        let (_code, stdout, stderr) = run_scan_vendor(tmp.path(), &mock.uri(), &[]);
        let v: serde_json::Value = serde_json::from_str(stdout.trim())
            .unwrap_or_else(|e| panic!("valid JSON: {e}\nstdout={stdout}\nstderr={stderr}"));
        let events = v["vendor"]["events"].as_array().expect("vendor events");
        let event_for = |name: &str| events.iter().find(|e| e["purl"] == purl(name));
        assert_eq!(
            event_for("pkg-a").expect("pkg-a event")["action"],
            "applied",
            "{v}"
        );
        assert_eq!(
            event_for("pkg-c").expect("pkg-c event")["action"],
            "applied",
            "{v}"
        );
        assert!(
            event_for("pkg-b").is_none(),
            "refused before the vendor step: {v}"
        );
        let refused = v["download"]["patches"]
            .as_array()
            .and_then(|p| p.iter().find(|r| r["purl"] == purl("pkg-b")))
            .unwrap_or_else(|| panic!("no download record for pkg-b: {v}"));
        assert_eq!(refused["action"], "failed", "{v}");
        assert_eq!(refused["errorCode"], "vendor_lock_entry_unsupported", "{v}");
        assert_eq!(v["download"]["failed"], 1, "{v}");

        let mut granted = granted_uuids(&mock).await;
        granted.sort();
        assert_eq!(
            granted,
            vec![UUID_A.to_string(), UUID_C.to_string()],
            "exactly one grant per package the loop reaches the service for, and none \
             for the package it refuses first"
        );
        let viewed: Vec<String> = mock
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.url.path().contains("/patches/view/"))
            .map(|r| r.url.path().rsplit('/').next().unwrap().to_string())
            .collect();
        assert!(
            !viewed.contains(&UUID_B.to_string()),
            "a package refused on lock text alone costs no view: {viewed:?}"
        );
    }

    // ── Which packages the lock-text refusal reaches ────────────────────
    //
    // The download phase refuses, before the view, only a package the
    // vendor loop would hand to its backend: one installed on disk, or one
    // the lockfile resolves to a verifiable registry source. A package with
    // neither never reached its backend — the loop skips it
    // `package_not_installed` — and keeps that outcome.

    const UUID_Y: &str = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
    const UUID_Z: &str = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";

    /// A pnpm 9 project: `pkg-a` installed and locked (wireable); `pkg-b`
    /// locked behind a peer-suffixed snapshot key (refused), NOT installed;
    /// `pkg-y` installed but absent from the lock (refused); `pkg-z`
    /// neither installed nor locked.
    fn write_pnpm_scope_fixture(root: &Path) {
        std::fs::write(
            root.join("package.json"),
            r#"{ "name": "scope-test", "version": "0.0.0", "dependencies": { "pkg-a": "1.0.0", "pkg-b": "1.0.0" } }"#,
        )
        .unwrap();
        std::fs::write(
            root.join("pnpm-lock.yaml"),
            "lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

importers:

  .:
    dependencies:
      pkg-a:
        specifier: 1.0.0
        version: 1.0.0
      pkg-b:
        specifier: 1.0.0
        version: 1.0.0(peer-x@1.0.0)

packages:

  pkg-a@1.0.0:
    resolution: {integrity: sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==}

  pkg-b@1.0.0:
    resolution: {integrity: sha512-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB==}
    peerDependencies:
      peer-x: '*'

snapshots:

  pkg-a@1.0.0: {}

  pkg-b@1.0.0(peer-x@1.0.0): {}
",
        )
        .unwrap();
        for name in ["pkg-a", "pkg-y"] {
            let pkg = root.join("node_modules").join(name);
            std::fs::create_dir_all(&pkg).unwrap();
            std::fs::write(
                pkg.join("package.json"),
                format!(r#"{{"name":"{name}","version":"1.0.0"}}"#),
            )
            .unwrap();
            std::fs::write(pkg.join("index.js"), BEFORE).unwrap();
        }
    }

    const PNPM_SCOPE: [(&str, &str); 4] = [
        ("pkg:npm/pkg-a@1.0.0", UUID_A),
        ("pkg:npm/pkg-b@1.0.0", UUID_B),
        ("pkg:npm/pkg-y@1.0.0", UUID_Y),
        ("pkg:npm/pkg-z@1.0.0", UUID_Z),
    ];

    /// Every uuid whose view the run fetched.
    async fn viewed_uuids(mock: &MockServer) -> Vec<String> {
        let mut viewed: Vec<String> = mock
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.url.path().contains("/patches/view/"))
            .map(|r| r.url.path().rsplit('/').next().unwrap().to_string())
            .collect();
        viewed.sort();
        viewed
    }

    /// No request reached the (mock) registry.
    async fn assert_no_registry_request(mock: &MockServer) {
        let registry: Vec<String> = mock
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|r| r.url.path().to_string())
            .filter(|p| p.starts_with("/registry/"))
            .collect();
        assert!(registry.is_empty(), "no pristine fetch: {registry:?}");
    }

    fn record_for<'a>(records: &'a serde_json::Value, purl: &str) -> &'a serde_json::Value {
        records
            .as_array()
            .and_then(|p| p.iter().find(|r| r["purl"] == purl))
            .unwrap_or_else(|| panic!("no record for {purl}: {records}"))
    }

    fn events_for<'a>(v: &'a serde_json::Value, purl: &str) -> Vec<(&'a str, &'a str)> {
        v["vendor"]["events"]
            .as_array()
            .expect("vendor events")
            .iter()
            .filter(|e| e["purl"] == purl)
            .map(|e| {
                (
                    e["action"].as_str().unwrap_or_default(),
                    e["errorCode"].as_str().unwrap_or_default(),
                )
            })
            .collect()
    }

    fn run_json(root: &Path, argv: &[&str], env: &[(&str, &str)]) -> serde_json::Value {
        let (_code, stdout, stderr) = run_cli_env(root, argv, env);
        serde_json::from_str(stdout.trim())
            .unwrap_or_else(|e| panic!("valid JSON: {e}\nstdout={stdout}\nstderr={stderr}"))
    }

    fn api_argv<'a>(mock_uri: &'a str, head: &[&'a str]) -> Vec<&'a str> {
        let mut argv = head.to_vec();
        argv.extend_from_slice(&[
            "--json",
            "--yes",
            "--api-url",
            mock_uri,
            "--api-token",
            "fake-token",
            "--org",
            ORG_SLUG,
        ]);
        argv
    }

    /// `scan --mode vendored` over the pnpm scope fixture: the installed
    /// (`pkg-y`) and the lock-resolved (`pkg-b`) refused packages fail in
    /// the download phase with no view and no pristine fetch; `pkg-z`,
    /// which the lock does not resolve and nothing installed, is fetched
    /// and skipped `package_not_installed` by the loop exactly as before.
    #[tokio::test]
    async fn scan_refuses_early_only_what_reaches_the_pnpm_backend() {
        let mock = MockServer::start().await;
        mount_patch_api(&mock, &PNPM_SCOPE, "package/index.js").await;
        let tmp = tempfile::tempdir().unwrap();
        write_pnpm_scope_fixture(tmp.path());
        let registry = format!("{}/registry", mock.uri());
        let uri = mock.uri();
        let v = run_json(
            tmp.path(),
            &api_argv(&uri, &["scan", "--mode", "vendored"]),
            &[("SOCKET_NPM_REGISTRY", registry.as_str())],
        );
        let dl = &v["download"]["patches"];
        let b = record_for(dl, "pkg:npm/pkg-b@1.0.0");
        assert_eq!(
            (&b["action"], &b["errorCode"]),
            (
                &serde_json::json!("failed"),
                &serde_json::json!("vendor_lock_entry_unsupported")
            ),
            "{v}"
        );
        let y = record_for(dl, "pkg:npm/pkg-y@1.0.0");
        assert_eq!(
            (&y["action"], &y["errorCode"]),
            (
                &serde_json::json!("failed"),
                &serde_json::json!("vendor_lock_entry_not_found")
            ),
            "{v}"
        );
        assert_eq!(
            record_for(dl, "pkg:npm/pkg-z@1.0.0")["action"],
            "downloaded",
            "not refused early: {v}"
        );
        assert_eq!(
            (&v["download"]["downloaded"], &v["download"]["failed"]),
            (&serde_json::json!(2), &serde_json::json!(2)),
            "{v}"
        );
        assert_eq!(
            events_for(&v, "pkg:npm/pkg-z@1.0.0"),
            vec![("failed", "vendor_lock_entry_not_found")],
            "{v}"
        );
        assert!(events_for(&v, "pkg:npm/pkg-b@1.0.0").is_empty(), "{v}");
        assert!(events_for(&v, "pkg:npm/pkg-y@1.0.0").is_empty(), "{v}");
        assert_eq!(
            events_for(&v, "pkg:npm/pkg-a@1.0.0"),
            vec![("applied", ""), ("skipped", "vendor_prebuilt_downloaded")],
            "{v}"
        );
        assert_eq!(
            viewed_uuids(&mock).await,
            vec![UUID_A.to_string(), UUID_Z.to_string()]
        );
        assert_no_registry_request(&mock).await;
    }

    /// `get <exact purl> --mode vendored` (exact-versioned purls skip the
    /// installed-version narrowing): a package neither installed nor locked
    /// keeps the loop's `package_not_installed` skip; a lock-resolved one
    /// the backend refuses fails before its view.
    #[tokio::test]
    async fn exact_purl_get_refuses_early_only_what_reaches_the_pnpm_backend() {
        let mock = MockServer::start().await;
        mount_patch_api(&mock, &PNPM_SCOPE, "package/index.js").await;
        let registry = format!("{}/registry", mock.uri());
        let uri = mock.uri();

        let tmp = tempfile::tempdir().unwrap();
        write_pnpm_scope_fixture(tmp.path());
        let v = run_json(
            tmp.path(),
            &api_argv(&uri, &["get", "pkg:npm/pkg-z@1.0.0", "--mode", "vendored"]),
            &[("SOCKET_NPM_REGISTRY", registry.as_str())],
        );
        assert_eq!(
            record_for(&v["patches"], "pkg:npm/pkg-z@1.0.0")["action"],
            "downloaded",
            "{v}"
        );
        assert_eq!(v["failed"], 0, "{v}");
        assert_eq!(
            events_for(&v, "pkg:npm/pkg-z@1.0.0"),
            vec![("failed", "vendor_lock_entry_not_found")],
            "{v}"
        );

        let tmp = tempfile::tempdir().unwrap();
        write_pnpm_scope_fixture(tmp.path());
        let v = run_json(
            tmp.path(),
            &api_argv(&uri, &["get", "pkg:npm/pkg-b@1.0.0", "--mode", "vendored"]),
            &[("SOCKET_NPM_REGISTRY", registry.as_str())],
        );
        let b = record_for(&v["patches"], "pkg:npm/pkg-b@1.0.0");
        assert_eq!(
            (&b["action"], &b["errorCode"]),
            (
                &serde_json::json!("failed"),
                &serde_json::json!("vendor_lock_entry_unsupported")
            ),
            "{v}"
        );
        assert!(events_for(&v, "pkg:npm/pkg-b@1.0.0").is_empty(), "{v}");
        assert_eq!(viewed_uuids(&mock).await, vec![UUID_Z.to_string()]);
        assert_no_registry_request(&mock).await;
    }

    const CARGO_SCOPE: [(&str, &str); 2] = [
        ("pkg:cargo/cfg-if@9.9.9", UUID_Y),
        ("pkg:cargo/absent-crate@1.0.0", UUID_Z),
    ];

    /// A cargo project locking `cfg-if 1.0.4`, with `cfg-if 9.9.9` in the
    /// (private) registry cache — installed at a version the lock does not
    /// resolve — and `absent-crate` nowhere. Returns the `CARGO_HOME`.
    fn write_cargo_scope_fixture(tmp: &Path) -> (PathBuf, String) {
        let root = tmp.join("proj");
        let cargo_home = tmp.join("cargo-home");
        let krate = cargo_home.join("registry/src/index.crates.io-6f17d22bba15001f/cfg-if-9.9.9");
        std::fs::create_dir_all(krate.join("src")).unwrap();
        std::fs::write(krate.join("src/lib.rs"), BEFORE).unwrap();
        std::fs::write(
            krate.join("Cargo.toml"),
            "[package]\nname = \"cfg-if\"\nversion = \"9.9.9\"\n",
        )
        .unwrap();
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\ncfg-if = \"1\"\n",
        )
        .unwrap();
        std::fs::write(
            root.join("Cargo.lock"),
            format!(
                "version = 4\n\n\
                 [[package]]\nname = \"app\"\nversion = \"0.1.0\"\n\
                 dependencies = [\n \"cfg-if\",\n]\n\n\
                 [[package]]\nname = \"cfg-if\"\nversion = \"1.0.4\"\n\
                 source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
                 checksum = \"{}\"\n",
                "9".repeat(64)
            ),
        )
        .unwrap();
        (root, cargo_home.to_string_lossy().into_owned())
    }

    /// cargo's `locked_version_mismatch` is refused before the view only
    /// for a crate installed at the unlocked version (the loop hands it to
    /// the backend); a crate the lock does not resolve and nothing
    /// installed keeps the loop's `package_not_installed` skip — on
    /// `scan --mode vendored` and on exact-purl `get --mode vendored`.
    #[tokio::test]
    async fn cargo_refuses_early_only_an_installed_crate() {
        let mock = MockServer::start().await;
        mount_patch_api(&mock, &CARGO_SCOPE, "package/src/lib.rs").await;
        let registry = format!("{}/registry", mock.uri());
        let uri = mock.uri();
        let env_for = |home: &str| {
            vec![
                ("CARGO_HOME".to_string(), home.to_string()),
                ("SOCKET_CRATES_REGISTRY".to_string(), registry.clone()),
            ]
        };

        let tmp = tempfile::tempdir().unwrap();
        let (root, home) = write_cargo_scope_fixture(tmp.path());
        let env = env_for(&home);
        let env: Vec<(&str, &str)> = env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let v = run_json(
            &root,
            &api_argv(&uri, &["scan", "--mode", "vendored"]),
            &env,
        );
        let dl = &v["download"]["patches"];
        let installed = record_for(dl, CARGO_SCOPE[0].0);
        assert_eq!(
            (&installed["action"], &installed["errorCode"]),
            (
                &serde_json::json!("failed"),
                &serde_json::json!("locked_version_mismatch")
            ),
            "{v}"
        );
        assert!(events_for(&v, CARGO_SCOPE[0].0).is_empty(), "{v}");
        assert_eq!(
            record_for(dl, CARGO_SCOPE[1].0)["action"],
            "downloaded",
            "{v}"
        );
        assert_eq!(
            events_for(&v, CARGO_SCOPE[1].0),
            vec![("failed", "locked_version_mismatch")],
            "{v}"
        );
        assert_eq!(viewed_uuids(&mock).await, vec![UUID_Z.to_string()]);

        let tmp = tempfile::tempdir().unwrap();
        let (root, home) = write_cargo_scope_fixture(tmp.path());
        let env = env_for(&home);
        let env: Vec<(&str, &str)> = env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let v = run_json(
            &root,
            &api_argv(&uri, &["get", CARGO_SCOPE[1].0, "--mode", "vendored"]),
            &env,
        );
        assert_eq!(
            record_for(&v["patches"], CARGO_SCOPE[1].0)["action"],
            "downloaded",
            "{v}"
        );
        assert_eq!(
            events_for(&v, CARGO_SCOPE[1].0),
            vec![("failed", "locked_version_mismatch")],
            "{v}"
        );
        let v = run_json(
            &root,
            &api_argv(&uri, &["get", CARGO_SCOPE[0].0, "--mode", "vendored"]),
            &env,
        );
        let installed = record_for(&v["patches"], CARGO_SCOPE[0].0);
        assert_eq!(installed["errorCode"], "locked_version_mismatch", "{v}");
        assert_eq!(
            viewed_uuids(&mock).await,
            vec![UUID_Z.to_string(), UUID_Z.to_string()],
            "the installed crate's view is never fetched"
        );
        assert_no_registry_request(&mock).await;
    }
}
