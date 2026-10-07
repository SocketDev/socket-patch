//! Agent-mode `scan` / `get` must reconcile a patch that is already
//! recorded in `.socket/manifest.json` against the installed tree (#454).
//!
//! The first run records and applies the patch. Then the package is
//! "reinstalled" (the pristine file comes back, as after `hatch env
//! create`, `pip install --force-reinstall` or a CI cache miss). The
//! re-run finds the same uuid already in the manifest (`skipped`) and must
//! still run the nested apply. Before the fix it exited 0 with the package
//! unpatched.

use std::path::Path;

use serial_test::serial;
use sha2::{Digest, Sha256};
use socket_patch_cli::commands::get::{run as get_run, GetArgs};
use socket_patch_cli::commands::scan::{run as scan_run, ScanArgs, ScanMode};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";
const NAME: &str = "agent-reapply";
const VERSION: &str = "1.0.0";
const PURL: &str = "pkg:npm/agent-reapply@1.0.0";
const UUID: &str = "45445445-4544-4544-8544-454454454454";
const ORIGINAL: &[u8] = b"module.exports = 'original';\n";
const PATCHED: &[u8] = b"module.exports = 'patched';\n";

fn git_sha256(content: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("blob {}\0", content.len()).as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

fn common(cwd: &Path, server: &MockServer) -> socket_patch_cli::args::GlobalArgs {
    socket_patch_cli::args::GlobalArgs {
        cwd: cwd.to_path_buf(),
        org: Some(ORG.to_string()),
        json: true,
        yes: true,
        api_token: Some("fake".to_string()),
        api_url: Some(server.uri()),
        ..socket_patch_cli::args::GlobalArgs::default()
    }
}

fn scan_args(cwd: &Path, server: &MockServer) -> ScanArgs {
    ScanArgs {
        socket_yml: Default::default(),
        paths: Vec::new(),
        packages: Vec::new(),
        common: common(cwd, server),
        batch_size: Some(100),
        apply: false,
        prune: false,
        sync: false,
        vendor: false,
        mode: None,
        all_releases: false,
        vex: Default::default(),
        rollout: Default::default(),
    }
}

fn agent_get_args(cwd: &Path, server: &MockServer) -> GetArgs {
    GetArgs {
        common: common(cwd, server),
        identifier: UUID.to_string(),
        id: true,
        cve: false,
        ghsa: false,
        package: false,
        save_only: false,
        all_releases: false,
        mode: Some(ScanMode::Agent),
    }
}

fn index_js(root: &Path) -> std::path::PathBuf {
    root.join("node_modules").join(NAME).join("index.js")
}

/// Lay down (or re-lay, simulating a reinstall) the pristine package.
fn install(root: &Path) {
    std::fs::write(
        root.join("package.json"),
        r#"{ "name": "agent-reapply-test", "version": "0.0.0" }"#,
    )
    .unwrap();
    let pkg = root.join("node_modules").join(NAME);
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        pkg.join("package.json"),
        format!(r#"{{ "name": "{NAME}", "version": "{VERSION}" }}"#),
    )
    .unwrap();
    std::fs::write(index_js(root), ORIGINAL).unwrap();
}

async fn mock_api(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": PURL,
                "patches": [{
                    "uuid": UUID, "purl": PURL,
                    "tier": "free", "cveIds": [], "ghsaIds": [],
                    "severity": "high", "title": "agent re-apply fixture"
                }]
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(format!(
            "^/v0/orgs/{ORG}/patches/by-package/.+$"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [{
                "uuid": UUID, "purl": PURL,
                "publishedAt": "2024-01-01T00:00:00Z",
                "description": "x", "license": "MIT", "tier": "free",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;
    use base64::Engine;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": UUID,
            "purl": PURL,
            "publishedAt": "2024-01-01T00:00:00Z",
            "files": {
                "package/index.js": {
                    "beforeHash": git_sha256(ORIGINAL),
                    "afterHash": git_sha256(PATCHED),
                    "blobContent": base64::engine::general_purpose::STANDARD.encode(PATCHED),
                }
            },
            "vulnerabilities": {},
            "description": "x", "license": "MIT", "tier": "free",
        })))
        .mount(server)
        .await;
}

fn recorded_patch_id(root: &Path) -> Option<String> {
    let text = std::fs::read_to_string(root.join(".socket/manifest.json")).ok()?;
    let manifest: serde_json::Value = serde_json::from_str(&text).ok()?;
    manifest["patches"][PURL]["uuid"]
        .as_str()
        .map(str::to_owned)
}

async fn scan(args: ScanArgs) -> i32 {
    // Same scrub as in_process_scan.rs: an ambient venv would add purls.
    std::env::remove_var("VIRTUAL_ENV");
    scan_run(args).await
}

/// Record + apply once, then reinstall the pristine package.
async fn first_run_then_reinstall(root: &Path, server: &MockServer) {
    install(root);
    let mut args = scan_args(root, server);
    args.mode = Some(ScanMode::Agent);
    assert_eq!(scan(args).await, 0, "first agent scan must apply cleanly");
    assert_eq!(std::fs::read(index_js(root)).unwrap(), PATCHED);
    assert_eq!(recorded_patch_id(root).as_deref(), Some(UUID));
    install(root);
    assert_eq!(std::fs::read(index_js(root)).unwrap(), ORIGINAL);
}

#[tokio::test]
#[serial]
async fn agent_scan_reapplies_already_recorded_patch_after_reinstall() {
    let server = MockServer::start().await;
    mock_api(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    first_run_then_reinstall(tmp.path(), &server).await;

    let mut args = scan_args(tmp.path(), &server);
    args.mode = Some(ScanMode::Agent);
    assert_eq!(scan(args).await, 0);
    assert_eq!(
        std::fs::read(index_js(tmp.path())).unwrap(),
        PATCHED,
        "a re-scan must re-apply the recorded patch to the reinstalled package"
    );
    assert_eq!(recorded_patch_id(tmp.path()).as_deref(), Some(UUID));
}

#[tokio::test]
#[serial]
async fn scan_sync_reapplies_already_recorded_patch_after_reinstall() {
    let server = MockServer::start().await;
    mock_api(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    first_run_then_reinstall(tmp.path(), &server).await;

    let mut args = scan_args(tmp.path(), &server);
    args.sync = true;
    assert_eq!(scan(args).await, 0);
    assert_eq!(
        std::fs::read(index_js(tmp.path())).unwrap(),
        PATCHED,
        "scan --sync must end fully reconciled"
    );
}

#[tokio::test]
#[serial]
async fn agent_scan_in_sync_rerun_is_a_clean_noop() {
    let server = MockServer::start().await;
    mock_api(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    install(tmp.path());
    let mut args = scan_args(tmp.path(), &server);
    args.mode = Some(ScanMode::Agent);
    assert_eq!(scan(args).await, 0);
    let manifest_before = std::fs::read(tmp.path().join(".socket/manifest.json")).unwrap();

    // Nothing reinstalled: the re-run still succeeds and changes nothing.
    let mut args = scan_args(tmp.path(), &server);
    args.mode = Some(ScanMode::Agent);
    assert_eq!(scan(args).await, 0);
    assert_eq!(std::fs::read(index_js(tmp.path())).unwrap(), PATCHED);
    assert_eq!(
        std::fs::read(tmp.path().join(".socket/manifest.json")).unwrap(),
        manifest_before,
        "an all-skipped run must not rewrite the manifest"
    );
}

#[tokio::test]
#[serial]
async fn agent_scan_rerun_fails_when_recorded_patch_cannot_be_applied() {
    let server = MockServer::start().await;
    mock_api(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    first_run_then_reinstall(tmp.path(), &server).await;
    // A different upstream build: neither the before nor the after hash,
    // which `--strict` refuses to overwrite.
    let other = b"module.exports = 'other';\n";
    std::fs::write(index_js(tmp.path()), other).unwrap();

    let mut args = scan_args(tmp.path(), &server);
    args.mode = Some(ScanMode::Agent);
    args.common.strict = true;
    assert_eq!(
        scan(args).await,
        1,
        "an all-skipped run whose apply fails must not report success"
    );
    assert_eq!(std::fs::read(index_js(tmp.path())).unwrap(), other);
}

#[tokio::test]
#[serial]
async fn get_uuid_agent_reapplies_already_recorded_patch_after_reinstall() {
    let server = MockServer::start().await;
    mock_api(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    install(tmp.path());
    assert_eq!(get_run(agent_get_args(tmp.path(), &server)).await, 0);
    assert_eq!(std::fs::read(index_js(tmp.path())).unwrap(), PATCHED);

    install(tmp.path());
    assert_eq!(get_run(agent_get_args(tmp.path(), &server)).await, 0);
    assert_eq!(
        std::fs::read(index_js(tmp.path())).unwrap(),
        PATCHED,
        "get <uuid> of an already-recorded patch must re-apply it"
    );
}

#[tokio::test]
#[serial]
async fn get_purl_agent_reapplies_already_recorded_patch_after_reinstall() {
    let server = MockServer::start().await;
    mock_api(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    first_run_then_reinstall(tmp.path(), &server).await;

    let mut args = agent_get_args(tmp.path(), &server);
    args.identifier = PURL.to_string();
    args.id = false;
    assert_eq!(get_run(args).await, 0);
    assert_eq!(
        std::fs::read(index_js(tmp.path())).unwrap(),
        PATCHED,
        "get <purl> of an already-recorded patch must re-apply it"
    );
}

#[tokio::test]
#[serial]
async fn get_save_only_of_recorded_patch_still_does_not_apply() {
    let server = MockServer::start().await;
    mock_api(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    first_run_then_reinstall(tmp.path(), &server).await;

    let mut args = agent_get_args(tmp.path(), &server);
    args.save_only = true;
    assert_eq!(get_run(args).await, 0);
    assert_eq!(
        std::fs::read(index_js(tmp.path())).unwrap(),
        ORIGINAL,
        "--save-only keeps its record-only intent"
    );
}
