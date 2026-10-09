//! The shared target grammar on the verbs that act on one package per
//! name: `get`, `remove` and `rollback` refuse a bare name whose
//! last-segment rule reaches several packages (`core` → `@angular/core`
//! and `@babel/core`), a Go major-version suffix (`v2`) is never a name,
//! and `rollback` treats a slash-containing package name (composer
//! `vendor/pkg`) as a target before it treats it as a path glob.
//!
//! In-process, against manifest-only fixtures: nothing is installed, so
//! every assertion is about which records a token selects.

use std::path::Path;

use serial_test::serial;
use socket_patch_cli::commands::get::{run as get_run, GetArgs};
use socket_patch_cli::commands::remove::{run as remove_run, RemoveArgs};
use socket_patch_cli::commands::rollback::{run as rollback_run, RollbackArgs};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";

fn record(uuid: &str) -> String {
    format!(
        r#"{{
            "uuid": "{uuid}",
            "exportedAt": "2024-01-01T00:00:00Z",
            "files": {{ "package/index.js": {{
                "beforeHash": "0000000000000000000000000000000000000000000000000000000000000000",
                "afterHash": "1111111111111111111111111111111111111111111111111111111111111111"
            }}}},
            "vulnerabilities": {{}}, "description": "x",
            "license": "MIT", "tier": "free"
        }}"#
    )
}

/// Write `.socket/manifest.json` holding one record per `(purl, uuid)`;
/// returns the manifest text.
fn write_manifest(cwd: &Path, records: &[(&str, &str)]) -> String {
    let body: Vec<String> = records
        .iter()
        .map(|(purl, uuid)| format!("\"{purl}\": {}", record(uuid)))
        .collect();
    let text = format!("{{ \"patches\": {{ {} }} }}", body.join(", "));
    let socket = cwd.join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    std::fs::write(socket.join("manifest.json"), &text).unwrap();
    std::fs::write(
        cwd.join("package.json"),
        r#"{"name":"r","version":"0.0.0"}"#,
    )
    .unwrap();
    text
}

fn read_manifest(cwd: &Path) -> String {
    std::fs::read_to_string(cwd.join(".socket/manifest.json")).unwrap()
}

fn common(cwd: &Path) -> socket_patch_cli::args::GlobalArgs {
    socket_patch_cli::args::GlobalArgs {
        cwd: cwd.to_path_buf(),
        manifest_path: ".socket/manifest.json".to_string(),
        yes: true,
        json: true,
        offline: true,
        ..socket_patch_cli::args::GlobalArgs::default()
    }
}

fn remove_args(cwd: &Path, identifier: &str) -> RemoveArgs {
    RemoveArgs {
        common: common(cwd),
        identifier: identifier.to_string(),
        skip_rollback: true,
        preserve_state: false,
    }
}

fn rollback_args(cwd: &Path, targets: &[&str]) -> RollbackArgs {
    let mut common = common(cwd);
    common.dry_run = true;
    RollbackArgs {
        targets: targets.iter().map(|t| t.to_string()).collect(),
        common,
        preserve_state: false,
    }
}

const ANGULAR: (&str, &str) = (
    "pkg:npm/%40angular/core@17.0.0",
    "a1a1a1a1-0000-4000-8000-000000000001",
);
const BABEL: (&str, &str) = (
    "pkg:npm/@babel/core@7.0.0",
    "b2b2b2b2-0000-4000-8000-000000000002",
);
const GO_V2: (&str, &str) = (
    "pkg:golang/github.com/x/y/v2@v2.0.0",
    "c3c3c3c3-0000-4000-8000-000000000003",
);
const GO_Z_V2: (&str, &str) = (
    "pkg:golang/github.com/x/z/v2@v2.1.0",
    "d4d4d4d4-0000-4000-8000-000000000004",
);
const MONOLOG: (&str, &str) = (
    "pkg:composer/monolog/monolog@2.9.0",
    "e5e5e5e5-0000-4000-8000-000000000005",
);

#[tokio::test]
#[serial]
async fn remove_refuses_a_name_that_reaches_two_packages() {
    let tmp = tempfile::tempdir().unwrap();
    let before = write_manifest(tmp.path(), &[ANGULAR, BABEL]);
    assert_eq!(remove_run(remove_args(tmp.path(), "core")).await, 1);
    assert_eq!(read_manifest(tmp.path()), before, "nothing may be removed");

    // The full name selects one package and removes only it.
    assert_eq!(remove_run(remove_args(tmp.path(), "@babel/core")).await, 0);
    let after = read_manifest(tmp.path());
    assert!(after.contains("angular"), "{after}");
    assert!(!after.contains("@babel/core"), "{after}");
}

#[tokio::test]
#[serial]
async fn remove_never_treats_a_go_major_suffix_as_a_name() {
    let tmp = tempfile::tempdir().unwrap();
    let before = write_manifest(tmp.path(), &[GO_V2, GO_Z_V2]);
    // `v2` names no package: not_found (exit 1), nothing removed.
    assert_eq!(remove_run(remove_args(tmp.path(), "v2")).await, 1);
    assert_eq!(read_manifest(tmp.path()), before);
    // The module path still works.
    assert_eq!(
        remove_run(remove_args(tmp.path(), "github.com/x/y/v2")).await,
        0
    );
    let after = read_manifest(tmp.path());
    assert!(!after.contains("github.com/x/y/v2"), "{after}");
    assert!(after.contains("github.com/x/z/v2"), "{after}");
}

#[tokio::test]
#[serial]
async fn rollback_refuses_a_name_that_reaches_two_packages() {
    let tmp = tempfile::tempdir().unwrap();
    write_manifest(tmp.path(), &[ANGULAR, BABEL]);
    assert_eq!(rollback_run(rollback_args(tmp.path(), &["core"])).await, 1);
    // One package by full name is fine (dry run: nothing installed).
    assert_eq!(
        rollback_run(rollback_args(tmp.path(), &["@angular/core"])).await,
        0
    );
}

#[tokio::test]
#[serial]
async fn rollback_never_treats_a_go_major_suffix_as_a_name() {
    let tmp = tempfile::tempdir().unwrap();
    write_manifest(tmp.path(), &[GO_V2, GO_Z_V2]);
    std::fs::write(
        tmp.path().join("go.mod"),
        "module example.com/app\n\ngo 1.21\n",
    )
    .unwrap();
    assert_eq!(rollback_run(rollback_args(tmp.path(), &["v2"])).await, 1);
    // The versionless module purl selects it (dry run: nothing installed).
    assert_eq!(
        rollback_run(rollback_args(tmp.path(), &["pkg:golang/github.com/x/y/v2"])).await,
        0
    );
}

#[tokio::test]
#[serial]
async fn rollback_takes_a_slash_package_name_as_a_target() {
    // `remove monolog/monolog` selects the composer record; rollback used
    // to read the same token as a path glob that matched no installed
    // copy (exit 1).
    let tmp = tempfile::tempdir().unwrap();
    write_manifest(tmp.path(), &[MONOLOG, BABEL]);
    assert_eq!(
        rollback_run(rollback_args(tmp.path(), &["monolog/monolog"])).await,
        0
    );
    assert_eq!(
        rollback_run(rollback_args(tmp.path(), &["github.com/x/y/v2"])).await,
        1,
        "a slash token selecting no record stays a path glob (matches nothing)"
    );
}

fn install_npm(cwd: &Path, name: &str, version: &str) {
    let dir = cwd.join("node_modules").join(name);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("package.json"),
        serde_json::json!({ "name": name, "version": version }).to_string(),
    )
    .unwrap();
}

fn get_args(identifier: &str, cwd: &Path, api_url: String) -> GetArgs {
    GetArgs {
        common: socket_patch_cli::args::GlobalArgs {
            org: Some(ORG.to_string()),
            cwd: cwd.to_path_buf(),
            yes: true,
            api_token: Some("fake-token-for-tests".to_string()),
            api_url: Some(api_url),
            json: true,
            ..socket_patch_cli::args::GlobalArgs::default()
        },
        identifier: identifier.to_string(),
        id: false,
        cve: false,
        ghsa: false,
        package: false,
        save_only: true,
        all_releases: false,
        mode: None,
    }
}

#[tokio::test]
#[serial]
async fn get_refuses_a_name_that_reaches_two_installed_packages() {
    let server = MockServer::start().await;
    let tmp = tempfile::tempdir().unwrap();
    install_npm(tmp.path(), "@angular/core", "17.0.0");
    install_npm(tmp.path(), "@babel/core", "7.0.0");
    assert_eq!(get_run(get_args("core", tmp.path(), server.uri())).await, 1);
    assert!(!tmp.path().join(".socket").exists(), "nothing recorded");
    let searched: Vec<String> = server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|r| r.url.path().to_string())
        .filter(|p| p.contains("/patches/"))
        .collect();
    assert!(
        searched.is_empty(),
        "no search for an ambiguous name: {searched:?}"
    );
}

/// A UUID outside `--ecosystems` is refused before the "Found patch" line
/// and before the `patch_fetched` telemetry event: it is not this run's
/// patch.
#[tokio::test]
#[serial]
async fn get_uuid_outside_the_ecosystems_sends_no_fetched_event() {
    const UUID: &str = "11111111-1111-4111-8111-111111111111";
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": UUID,
            "purl": "pkg:npm/in-process-test@1.0.0",
            "publishedAt": "2024-01-01T00:00:00Z",
            "files": {},
            "vulnerabilities": {},
            "description": "x",
            "license": "MIT",
            "tier": "free",
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    let tmp = tempfile::tempdir().unwrap();
    let mut args = get_args(UUID, tmp.path(), server.uri());
    args.common.ecosystems = Some(vec!["pypi".to_string()]);

    // Telemetry resolves its endpoint from the environment.
    std::env::set_var("SOCKET_API_URL", server.uri());
    std::env::set_var("SOCKET_API_TOKEN", "fake");
    std::env::set_var("SOCKET_ORG_SLUG", ORG);
    std::env::remove_var("SOCKET_TELEMETRY_DISABLED");
    std::env::remove_var("SOCKET_OFFLINE");
    std::env::remove_var("VITEST");
    let code = get_run(args).await;
    std::env::remove_var("SOCKET_API_URL");
    std::env::remove_var("SOCKET_API_TOKEN");
    std::env::remove_var("SOCKET_ORG_SLUG");
    assert_eq!(code, 0);
    assert!(!tmp.path().join(".socket").exists());
    let bodies: Vec<String> = server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path().ends_with("/telemetry"))
        .map(|r| String::from_utf8_lossy(&r.body).into_owned())
        .collect();
    assert!(
        !bodies.iter().any(|b| b.contains("patch_fetched")),
        "a refused UUID must not record a fetch: {bodies:?}"
    );
}
