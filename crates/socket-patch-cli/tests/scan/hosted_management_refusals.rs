//! Management commands over hosted state they cannot act on safely:
//!
//! * contested hosted wiring (a hosted `npm-shrinkwrap.json` beside an
//!   upstream `package-lock.json`) is hosted state, so `rollback`, `list`
//!   and `vendor` refuse and name it instead of reporting a bare project;
//! * `vendor` ejecting a hosted project needs every patch record from the
//!   API, so an offline run (flag or env, wet or dry) refuses before it
//!   sends a single request.

use std::path::Path;
use std::process::Command;

use serde_json::Value;
use wiremock::MockServer;

const PATCH: &str = "11111111-1111-4111-8111-111111111111";
const GRANT: &str = "22222222-2222-4222-8222-222222222222";

fn cli() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_socket-patch"));
    for (key, _) in std::env::vars() {
        if key.starts_with("SOCKET_") && key != "SOCKET_NO_CONFIG" {
            cmd.env_remove(key);
        }
    }
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1");
    cmd
}

fn lock(resolved: &str, integrity: &str) -> String {
    format!(
        r#"{{"name":"app","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{{"":{{"name":"app","version":"1.0.0","dependencies":{{"left-pad":"1.3.0"}}}},"node_modules/left-pad":{{"version":"1.3.0","resolved":"{resolved}","integrity":"{integrity}"}}}}}}"#
    )
}

fn hosted_lock() -> String {
    lock(
        &format!(
            "https://patch.socket.dev/patch/npm/left-pad/1.3.0/{GRANT}/{PATCH}/left-pad-1.3.0.tgz"
        ),
        "sha512-patched==",
    )
}

fn write_package_json(root: &Path) {
    std::fs::write(
        root.join("package.json"),
        r#"{"name":"app","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}}"#,
    )
    .unwrap();
}

/// Hosted shrinkwrap, upstream package-lock: the locks disagree.
fn write_contested(root: &Path) {
    write_package_json(root);
    std::fs::write(
        root.join("package-lock.json"),
        lock(
            "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
            "sha512-upstream==",
        ),
    )
    .unwrap();
    std::fs::write(root.join("npm-shrinkwrap.json"), hosted_lock()).unwrap();
}

fn run_json(args: &[&str], cwd: &Path) -> (Option<i32>, Value) {
    let out = cli()
        .args(args)
        .arg("--cwd")
        .arg(cwd)
        .output()
        .expect("run socket-patch");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "{args:?}: stdout is not JSON ({e}): {stdout}\nstderr: {}",
            String::from_utf8_lossy(&out.stderr)
        )
    });
    (out.status.code(), v)
}

fn snapshot(root: &Path) -> Vec<(String, String)> {
    ["package-lock.json", "npm-shrinkwrap.json"]
        .iter()
        .map(|f| {
            (
                f.to_string(),
                std::fs::read_to_string(root.join(f)).unwrap_or_default(),
            )
        })
        .collect()
}

#[test]
fn rollback_refuses_contested_hosted_wiring_and_names_it() {
    let tmp = tempfile::tempdir().unwrap();
    write_contested(tmp.path());
    let before = snapshot(tmp.path());
    let (code, v) = run_json(&["rollback", "--json", "--yes"], tmp.path());
    assert_eq!(code, Some(1), "{v}");
    let err = v["error"].as_str().unwrap_or_default();
    assert!(
        err.contains("npm-shrinkwrap.json") && err.contains("git checkout --"),
        "the refusal names the contested file and the remedy: {v}"
    );
    assert!(!err.contains("Manifest not found"), "{v}");
    assert_eq!(snapshot(tmp.path()), before, "nothing was rewritten");
}

#[test]
fn list_reports_contested_hosted_wiring_instead_of_no_manifest() {
    let tmp = tempfile::tempdir().unwrap();
    write_contested(tmp.path());
    let (code, v) = run_json(&["list", "--json"], tmp.path());
    assert_eq!(code, Some(1), "{v}");
    assert_eq!(v["error"]["code"], "hosted_wiring_contested", "{v}");
}

#[test]
fn vendor_refuses_to_eject_contested_hosted_wiring() {
    let tmp = tempfile::tempdir().unwrap();
    write_contested(tmp.path());
    let before = snapshot(tmp.path());
    let (code, v) = run_json(&["vendor", "--offline", "--dry-run", "--json"], tmp.path());
    assert_eq!(code, Some(1), "{v}");
    assert_eq!(v["error"]["code"], "hosted_wiring_contested", "{v}");
    assert_eq!(snapshot(tmp.path()), before);
    assert!(!tmp.path().join(".socket").exists());
}

/// An offline eject refuses with ZERO requests to the API, whether offline
/// comes from the flag or the env, and on a dry run too.
#[tokio::test]
async fn offline_eject_refuses_before_any_request() {
    let server = MockServer::start().await;
    for (flag, env, dry) in [
        (true, false, false),
        (true, false, true),
        (false, true, false),
        (false, true, true),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        write_package_json(tmp.path());
        std::fs::write(tmp.path().join("package-lock.json"), hosted_lock()).unwrap();
        let before = snapshot(tmp.path());
        let mut cmd = cli();
        cmd.args(["vendor", "--json", "--org", "test-org", "--api-token", "fake"])
            .arg("--api-url")
            .arg(server.uri())
            .arg("--cwd")
            .arg(tmp.path());
        if flag {
            cmd.arg("--offline");
        }
        if env {
            cmd.env("SOCKET_OFFLINE", "1");
        }
        if dry {
            cmd.arg("--dry-run");
        }
        let out = cmd.output().unwrap();
        let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
            panic!(
                "flag={flag} env={env} dry={dry}: {e}: {}",
                String::from_utf8_lossy(&out.stdout)
            )
        });
        assert_eq!(out.status.code(), Some(1), "flag={flag} env={env} dry={dry}: {v}");
        assert_eq!(v["error"]["code"], "offline_eject_unavailable", "{v}");
        assert_eq!(snapshot(tmp.path()), before);
    }
    let received = server.received_requests().await.unwrap_or_default();
    assert!(
        received.is_empty(),
        "an offline eject must not touch the network: {:?}",
        received.iter().map(|r| r.url.to_string()).collect::<Vec<_>>()
    );
}

// ── eject is one transaction ────────────────────────────────────────────────

const ORG: &str = "test-org";
const MOCK_PATCH: &str = "33333333-3333-4333-8333-333333333333";

/// A fresh hosted checkout: package.json + a package-lock.json pinning
/// left-pad to the mock patch server, and NOTHING installed.
fn write_fresh_hosted_checkout(root: &Path, patch_origin: &str) -> String {
    write_package_json(root);
    let lock = lock(
        &format!(
            "{patch_origin}/patch/npm/left-pad/1.3.0/{GRANT}/{MOCK_PATCH}/left-pad-1.3.0.tgz"
        ),
        "sha512-patched==",
    );
    std::fs::write(root.join("package-lock.json"), &lock).unwrap();
    lock
}

async fn mount_view_and_registry(server: &MockServer, tarball_status: u16) {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{MOCK_PATCH}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": MOCK_PATCH,
            "purl": "pkg:npm/left-pad@1.3.0",
            "publishedAt": "2024-01-01T00:00:00Z",
            "files": { "package/index.js": { "beforeHash": "a".repeat(64), "afterHash": "b".repeat(64) } },
            "vulnerabilities": {},
            "description": "x", "license": "MIT", "tier": "free"
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/npm-registry/left-pad/1.3.0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": "left-pad",
            "version": "1.3.0",
            "dist": {
                "tarball": format!("{}/npm-registry/left-pad/-/left-pad-1.3.0.tgz", server.uri()),
                "integrity": "sha512-upstream==",
            }
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/npm-registry/left-pad/-/left-pad-1.3.0.tgz"))
        .respond_with(ResponseTemplate::new(tarball_status))
        .mount(server)
        .await;
}

fn eject_cmd(server: &MockServer, cwd: &Path, dry: bool) -> Command {
    let mut cmd = cli();
    cmd.args(["vendor", "--json", "--org", ORG, "--api-token", "fake"])
        .args(["--vendor-source", "build"])
        .arg("--api-url")
        .arg(server.uri())
        .arg("--patch-server-url")
        .arg(server.uri())
        .arg("--cwd")
        .arg(cwd)
        .env("SOCKET_NPM_REGISTRY", format!("{}/npm-registry", server.uri()));
    if dry {
        cmd.arg("--dry-run");
    }
    cmd
}

/// Failure injection: the pristine tarball cannot be fetched, so vendoring
/// fails AFTER the upstream restore landed — the eject rolls everything
/// back and the project stays hosted, byte for byte.
#[tokio::test]
async fn failed_eject_rolls_back_and_keeps_the_project_hosted() {
    let server = MockServer::start().await;
    mount_view_and_registry(&server, 404).await;
    let tmp = tempfile::tempdir().unwrap();
    let hosted = write_fresh_hosted_checkout(tmp.path(), &server.uri());
    let out = eject_cmd(&server, tmp.path(), false).output().unwrap();
    let v: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "{e}: {}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    });
    assert_eq!(out.status.code(), Some(1), "{v}");
    assert!(
        v["warnings"]
            .as_array()
            .is_some_and(|w| w.iter().any(|w| w["code"] == "eject_rolled_back")),
        "the rollback is announced: {v}"
    );
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap(),
        hosted,
        "the hosted pin survives a failed eject"
    );
    assert!(
        !tmp.path().join(".socket/vendor").exists()
            || std::fs::read_dir(tmp.path().join(".socket/vendor"))
                .unwrap()
                .next()
                .is_none(),
        "no vendored residue"
    );
    assert!(
        !tmp.path().join(".npmrc").exists(),
        "the restore's side-config cleanup is rolled back with the rest"
    );
}

/// A dry-run eject verifies the plan (records, upstream restore) and writes
/// nothing.
#[tokio::test]
async fn dry_run_eject_verifies_the_plan_and_writes_nothing() {
    let server = MockServer::start().await;
    mount_view_and_registry(&server, 200).await;
    let tmp = tempfile::tempdir().unwrap();
    let hosted = write_fresh_hosted_checkout(tmp.path(), &server.uri());
    let out = eject_cmd(&server, tmp.path(), true).output().unwrap();
    let v: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(out.status.code(), Some(0), "{v}");
    assert_eq!(v["dryRun"], true, "{v}");
    assert!(
        v["events"]
            .as_array()
            .is_some_and(|e| e.iter().any(|e| e["purl"] == "pkg:npm/left-pad@1.3.0")),
        "{v}"
    );
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap(),
        hosted
    );
    assert!(!tmp.path().join(".socket").exists(), "a dry run creates no .socket/");
}
