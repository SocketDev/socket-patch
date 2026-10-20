//! `scan --mode hosted` over a lockfile pin whose patch was withdrawn.
//!
//! Each test wires an npm package-lock project through the REAL hosted flow
//! (in-process `scan --mode hosted` against a wiremock API, the
//! `in_process_rollback_hosted.rs` fixture), then re-scans against a second
//! mock whose reference endpoint reports the pinned uuid's new state:
//!
//! - `withdrawn` / `not_found`: the pin is restored to its upstream registry
//!   entry (byte-identical to the pristine lock), or, when a replacement
//!   patch is offered, re-pinned to the replacement.
//! - `granted`, or a failed reference lookup: the pin is kept, even when the
//!   search results no longer list the patch.
//!
//! `#[serial]`: every command's `run` mirrors env toggles into
//! process-global env vars (`apply_env_toggles`), and the upstream restore
//! reads `SOCKET_NPM_REGISTRY`.

#[path = "common/hermetic.rs"]
mod hermetic;

use std::path::Path;

use serde_json::Value;
use serial_test::serial;
use socket_patch_cli::commands::scan::{run as scan_run, ScanArgs, ScanMode};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";
const NAME: &str = "in-proc-redirect";
const VERSION: &str = "1.0.0";
const PURL: &str = "pkg:npm/in-proc-redirect@1.0.0";
const UUID: &str = "11111111-1111-4111-8111-111111111111";
const HOSTED_URL: &str = "http://patch.test/patch/npm/in-proc-redirect/1.0.0/22222222-2222-4222-8222-222222222222/11111111-1111-4111-8111-111111111111/in-proc-redirect-1.0.0.tgz";
const PATCHED_SHA512: &str = "sha512-PATCHEDpatchedPATCHEDpatched0123456789==";
/// The replacement patch a superseding offer pins.
const UUID2: &str = "33333333-3333-4333-8333-333333333333";
const HOSTED_URL2: &str = "http://patch.test/patch/npm/in-proc-redirect/1.0.0/22222222-2222-4222-8222-222222222222/33333333-3333-4333-8333-333333333333/in-proc-redirect-1.0.0.tgz";
const PATCHED_SHA512_2: &str = "sha512-REPLACEMENTreplacementREPLACEMENT0123456==";

fn scan_args(cwd: &Path, api_url: String, dry_run: bool) -> ScanArgs {
    ScanArgs {
        socket_yml: Default::default(),
        paths: Vec::new(),
        packages: Vec::new(),
        common: socket_patch_cli::args::GlobalArgs {
            cwd: cwd.to_path_buf(),
            org: Some(ORG.to_string()),
            api_token: Some("fake".to_string()),
            api_url: Some(api_url),
            // The mock patch host's pins count as hosted.
            patch_server_url: Some("http://patch.test".to_string()),
            json: true,
            yes: true,
            dry_run,
            ..socket_patch_cli::args::GlobalArgs::default()
        },
        batch_size: Some(100),
        prune: false,
        sync: false,
        mode: Some(ScanMode::Hosted),
        all_releases: false,
        vex: Default::default(),
        rollout: Default::default(),
    }
}

/// Run an in-process hosted scan with the npm registry pointed at
/// `server`, scrubbing the env toggles `run` mirrors into the process.
async fn scan(cwd: &Path, server: &MockServer, dry_run: bool) -> i32 {
    std::env::set_var(
        "SOCKET_NPM_REGISTRY",
        format!("{}/npm-registry", server.uri()),
    );
    let code = scan_run(scan_args(cwd, server.uri(), dry_run)).await;
    for var in ["SOCKET_NPM_REGISTRY", "SOCKET_DRY_RUN"] {
        std::env::remove_var(var);
    }
    code
}

fn offer(uuid: &str) -> Value {
    serde_json::json!({
        "uuid": uuid, "purl": PURL, "tier": "free",
        "cveIds": [], "ghsaIds": [], "severity": "high",
        "title": "withdrawn fixture"
    })
}

/// The batch search (offering `offers`) and by-package endpoints.
async fn mock_search(server: &MockServer, offers: &[&str]) {
    let packages = if offers.is_empty() {
        serde_json::json!([])
    } else {
        serde_json::json!([{
            "purl": PURL,
            "patches": offers.iter().map(|u| offer(u)).collect::<Vec<_>>(),
        }])
    };
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": packages,
            "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;
    let records: Vec<Value> = offers
        .iter()
        .map(|u| {
            serde_json::json!({
                "uuid": u, "purl": PURL,
                "publishedAt": "2024-01-01T00:00:00Z",
                "description": "x", "license": "MIT", "tier": "free",
                "vulnerabilities": {}
            })
        })
        .collect();
    Mock::given(method("GET"))
        .and(path_regex(format!(
            "^/v0/orgs/{ORG}/patches/by-package/.+$"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": records,
            "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;
}

fn granted(url: &str, sha512: &str) -> Value {
    serde_json::json!({
        "status": "granted",
        "url": url,
        "purl": PURL,
        "artifacts": [{
            "kind": "tarball",
            "url": url,
            "integrity": { "sha512": sha512 }
        }],
        "registryOverride": null
    })
}

/// The reference endpoint answering `results`.
async fn mock_references(server: &MockServer, results: Value) {
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({ "results": results })),
        )
        .mount(server)
        .await;
}

async fn mock_view(server: &MockServer, uuid: &str) {
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{uuid}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": uuid,
            "purl": PURL,
            "publishedAt": "2024-01-01T00:00:00Z",
            "files": {
                "package/index.js": {
                    "beforeHash": "a".repeat(64),
                    "afterHash": "b".repeat(64),
                }
            },
            "vulnerabilities": {},
            "description": "x", "license": "MIT", "tier": "free"
        })))
        .mount(server)
        .await;
}

/// The npm registry's version document, for the upstream restore.
async fn mock_npm_registry(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path(format!("/npm-registry/{NAME}/{VERSION}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": NAME,
            "version": VERSION,
            "dist": {
                "tarball": format!("https://registry.npmjs.org/{NAME}/-/{NAME}-{VERSION}.tgz"),
                "integrity": "sha512-UPSTREAMupstream==",
            }
        })))
        .mount(server)
        .await;
}

/// Write the npm project and return the pristine lock bytes (normalized
/// the way the redirect writer serializes, so a restore can be compared
/// byte for byte).
fn write_npm_project(root: &Path) -> String {
    std::fs::write(
        root.join("package.json"),
        format!(
            r#"{{ "name": "consumer", "version": "0.0.0", "dependencies": {{ "{NAME}": "{VERSION}" }} }}"#
        ),
    )
    .unwrap();
    let pkg = root.join("node_modules").join(NAME);
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        pkg.join("package.json"),
        format!(r#"{{ "name": "{NAME}", "version": "{VERSION}" }}"#),
    )
    .unwrap();
    let raw = format!(
        r#"{{
  "name": "consumer",
  "version": "0.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {{
    "": {{ "name": "consumer", "version": "0.0.0", "dependencies": {{ "{NAME}": "{VERSION}" }} }},
    "node_modules/{NAME}": {{
      "version": "{VERSION}",
      "resolved": "https://registry.npmjs.org/{NAME}/-/{NAME}-{VERSION}.tgz",
      "integrity": "sha512-UPSTREAMupstream=="
    }}
  }}
}}
"#
    );
    let normalized = format!(
        "{}\n",
        serde_json::to_string_pretty(&serde_json::from_str::<Value>(&raw).unwrap()).unwrap()
    );
    std::fs::write(root.join("package-lock.json"), &normalized).unwrap();
    normalized
}

fn lock(root: &Path) -> String {
    std::fs::read_to_string(root.join("package-lock.json")).unwrap()
}

/// Wire the project to [`UUID`] through a real hosted scan; returns the
/// pristine and the wired lock.
async fn wired_project(root: &Path) -> (String, String) {
    let pristine = write_npm_project(root);
    let server = MockServer::start().await;
    mock_search(&server, &[UUID]).await;
    mock_references(
        &server,
        serde_json::json!({ UUID: granted(HOSTED_URL, PATCHED_SHA512) }),
    )
    .await;
    mock_view(&server, UUID).await;
    assert_eq!(scan(root, &server, false).await, 0, "wiring scan");
    let wired = lock(root);
    assert!(
        wired.contains(HOSTED_URL) && wired.contains(PATCHED_SHA512),
        "the lock must be wired before the re-scan means anything:\n{wired}"
    );
    (pristine, wired)
}

/// Requests `server` received on the reference endpoint.
async fn reference_posts(server: &MockServer) -> usize {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .filter(|r| r.url.path().ends_with("/patches/package"))
        .count()
}

#[tokio::test]
#[serial]
async fn a_withdrawn_pin_is_restored_upstream() {
    let tmp = tempfile::tempdir().unwrap();
    let (pristine, _) = wired_project(tmp.path()).await;

    // The patch was unpublished: search no longer lists it.
    let server = MockServer::start().await;
    mock_search(&server, &[]).await;
    mock_references(
        &server,
        serde_json::json!({ UUID: { "status": "withdrawn" } }),
    )
    .await;
    mock_npm_registry(&server).await;
    assert_eq!(scan(tmp.path(), &server, false).await, 0);

    assert_eq!(
        lock(tmp.path()),
        pristine,
        "the withdrawn pin must be restored to the upstream registry entry"
    );
    assert!(
        !tmp.path().join(".socket").exists(),
        "the sweep's apply lock leaves no .socket/ residue"
    );
}

#[tokio::test]
#[serial]
async fn a_not_found_pin_is_restored_upstream() {
    let tmp = tempfile::tempdir().unwrap();
    let (pristine, _) = wired_project(tmp.path()).await;

    let server = MockServer::start().await;
    mock_search(&server, &[]).await;
    mock_references(
        &server,
        serde_json::json!({ UUID: { "status": "not_found" } }),
    )
    .await;
    mock_npm_registry(&server).await;
    assert_eq!(scan(tmp.path(), &server, false).await, 0);

    assert_eq!(lock(tmp.path()), pristine);
}

#[tokio::test]
#[serial]
async fn a_withdrawn_pin_with_a_replacement_is_repinned() {
    let tmp = tempfile::tempdir().unwrap();
    wired_project(tmp.path()).await;

    // The old patch was unpublished and a new one published for the same
    // package version.
    let server = MockServer::start().await;
    mock_search(&server, &[UUID2]).await;
    mock_references(
        &server,
        serde_json::json!({
            UUID: { "status": "withdrawn" },
            UUID2: granted(HOSTED_URL2, PATCHED_SHA512_2),
        }),
    )
    .await;
    mock_view(&server, UUID2).await;
    mock_npm_registry(&server).await;
    assert_eq!(scan(tmp.path(), &server, false).await, 0);

    let after = lock(tmp.path());
    assert!(
        after.contains(HOSTED_URL2) && after.contains(PATCHED_SHA512_2),
        "the replacement patch must be pinned:\n{after}"
    );
    assert!(
        !after.contains(UUID),
        "nothing may still name the withdrawn patch:\n{after}"
    );
}

#[tokio::test]
#[serial]
async fn a_pin_missing_from_search_but_still_granted_is_kept() {
    let tmp = tempfile::tempdir().unwrap();
    let (_, wired) = wired_project(tmp.path()).await;

    // Absent from search (a failed batch, the free-only proxy and a lapsed
    // entitlement all look like this), but the server still serves it.
    let server = MockServer::start().await;
    mock_search(&server, &[]).await;
    mock_references(
        &server,
        serde_json::json!({ UUID: granted(HOSTED_URL, PATCHED_SHA512) }),
    )
    .await;
    mock_npm_registry(&server).await;
    assert_eq!(scan(tmp.path(), &server, false).await, 0);

    assert_eq!(lock(tmp.path()), wired, "a served pin is never unpinned");
    assert_eq!(
        reference_posts(&server).await,
        1,
        "the pin was checked against the reference endpoint"
    );
}

#[tokio::test]
#[serial]
async fn a_forbidden_pin_is_kept() {
    let tmp = tempfile::tempdir().unwrap();
    let (_, wired) = wired_project(tmp.path()).await;

    let server = MockServer::start().await;
    mock_search(&server, &[]).await;
    mock_references(
        &server,
        serde_json::json!({ UUID: { "status": "forbidden" } }),
    )
    .await;
    mock_npm_registry(&server).await;
    assert_eq!(scan(tmp.path(), &server, false).await, 0);

    assert_eq!(lock(tmp.path()), wired);
}

#[tokio::test]
#[serial]
async fn a_failed_reference_lookup_keeps_every_pin() {
    let tmp = tempfile::tempdir().unwrap();
    let (_, wired) = wired_project(tmp.path()).await;

    // The patch API answers search but its reference endpoint is down.
    let server = MockServer::start().await;
    mock_search(&server, &[]).await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    mock_npm_registry(&server).await;
    assert_eq!(scan(tmp.path(), &server, false).await, 0);

    assert_eq!(lock(tmp.path()), wired, "an outage must never unpin");
}

#[tokio::test]
#[serial]
async fn a_search_outage_never_reaches_the_sweep() {
    let tmp = tempfile::tempdir().unwrap();
    let (_, wired) = wired_project(tmp.path()).await;

    // Every search batch fails: the scan fails before the sweep runs.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    mock_references(
        &server,
        serde_json::json!({ UUID: { "status": "withdrawn" } }),
    )
    .await;
    mock_npm_registry(&server).await;
    assert_eq!(scan(tmp.path(), &server, false).await, 1);

    assert_eq!(lock(tmp.path()), wired);
    assert_eq!(reference_posts(&server).await, 0);
}

#[tokio::test]
#[serial]
async fn a_dry_run_previews_the_restore_without_writing() {
    let tmp = tempfile::tempdir().unwrap();
    let (_, wired) = wired_project(tmp.path()).await;

    let server = MockServer::start().await;
    mock_search(&server, &[]).await;
    mock_references(
        &server,
        serde_json::json!({ UUID: { "status": "withdrawn" } }),
    )
    .await;
    mock_npm_registry(&server).await;
    assert_eq!(scan(tmp.path(), &server, true).await, 0);

    assert_eq!(lock(tmp.path()), wired, "a dry run writes nothing");
    assert!(!tmp.path().join(".socket").exists());
}

/// The `--json` envelope (through the binary: an in-process run prints to
/// the real stdout): one `rolledBack` event with `reason: patch_withdrawn`.
#[tokio::test]
#[serial]
async fn the_envelope_reports_the_restored_pin() {
    let tmp = tempfile::tempdir().unwrap();
    let (pristine, _) = wired_project(tmp.path()).await;

    let server = MockServer::start().await;
    mock_search(&server, &[]).await;
    mock_references(
        &server,
        serde_json::json!({ UUID: { "status": "withdrawn" } }),
    )
    .await;
    mock_npm_registry(&server).await;

    let mut cmd = hermetic::binary_command();
    for key in ["NPM_CONFIG_REGISTRY", "npm_config_registry"] {
        cmd.env_remove(key);
    }
    let out = cmd
        .env(
            "SOCKET_NPM_REGISTRY",
            format!("{}/npm-registry", server.uri()),
        )
        .args([
            "scan",
            "--json",
            "--yes",
            "--mode",
            "hosted",
            "--org",
            ORG,
            "--api-token",
            "fake",
            "--api-url",
            &server.uri(),
            "--patch-server-url",
            "http://patch.test",
            "--cwd",
            tmp.path().to_str().unwrap(),
        ])
        .output()
        .expect("run socket-patch");
    let envelope: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "scan --json stdout must be a JSON envelope: {e}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    });
    assert_eq!(out.status.code(), Some(0), "{envelope:#}");
    assert_eq!(envelope["status"], "success", "{envelope:#}");
    let restored: Vec<&Value> = envelope["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["action"] == "rolledBack")
        .collect();
    assert_eq!(restored.len(), 1, "{envelope:#}");
    assert_eq!(restored[0]["purl"], PURL);
    assert_eq!(restored[0]["uuid"], UUID);
    assert_eq!(restored[0]["errorCode"], "patch_withdrawn", "{envelope:#}");
    assert_eq!(restored[0]["details"]["mode"], "hosted");
    assert_eq!(lock(tmp.path()), pristine);
}
