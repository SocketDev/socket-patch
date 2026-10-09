//! Vendored composer against a CRLF `composer.lock` (a Windows checkout,
//! `core.autocrlf=true`, or a lock committed with CRLF).
//!
//! Every vendored front door — `vendor` over a staged manifest, `scan
//! --mode vendored`, and `get <uuid> --mode vendored` — must write the wired lock
//! back in CRLF (so the diff is the one entry, not every line), an in-sync
//! re-run must leave it byte-identical, and `vendor --revert` must restore
//! the pre-vendor bytes exactly. Each test runs the built binary; the
//! discovery/view routes are a wiremock API, so no composer and no network.

#[path = "prebuilt_common/mod.rs"]
mod prebuilt_common;

use std::path::Path;
use std::process::Command;

use base64::Engine as _;
use serde_json::{json, Value};
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";
const UUID: &str = "5e6f7a8b-9c0d-4e1f-8a2b-3c4d5e6f7a8b";
const PURL: &str = "pkg:composer/psr/log@3.0.2";
const GHSA: &str = "GHSA-crlf-aaaa-bbbb";
const FILE: &str = "src/LoggerInterface.php";
const ORIGINAL: &[u8] = b"<?php\nnamespace Psr\\Log;\ninterface LoggerInterface {}\n";
const PATCHED: &[u8] =
    b"<?php\nnamespace Psr\\Log;\ninterface LoggerInterface {}\n// SOCKET-PATCH-CRLF-MARKER\n";

/// A composer-formatted lock (4-space `JSON_PRETTY_PRINT`, trailing
/// newline) with every line break a CRLF.
fn crlf_lock() -> String {
    r#"{
    "_readme": [
        "This file locks the dependencies of your project to a known state"
    ],
    "content-hash": "abc123def456abc123def456abc1",
    "packages": [
        {
            "name": "psr/log",
            "version": "3.0.2",
            "source": {
                "type": "git",
                "url": "https://github.com/php-fig/log.git",
                "reference": "f16e1d5863e37f8d8c2a01719f5b34baa2b714d3"
            },
            "dist": {
                "type": "zip",
                "url": "https://api.github.com/repos/php-fig/log/zipball/f16e1d5863e37f8d8c2a01719f5b34baa2b714d3",
                "reference": "f16e1d5863e37f8d8c2a01719f5b34baa2b714d3",
                "shasum": ""
            },
            "type": "library"
        }
    ],
    "packages-dev": [],
    "plugin-api-version": "2.6.0"
}
"#
    .replace('\n', "\r\n")
}

fn write_project(root: &Path) {
    std::fs::write(
        root.join("composer.json"),
        "{\r\n    \"require\": {\r\n        \"psr/log\": \"^3.0\"\r\n    }\r\n}\r\n",
    )
    .unwrap();
    let installed = root.join("vendor/composer");
    std::fs::create_dir_all(&installed).unwrap();
    std::fs::write(
        installed.join("installed.json"),
        r#"{ "packages": [ { "name": "psr/log", "version": "3.0.2", "version_normalized": "3.0.2.0" } ] }
"#,
    )
    .unwrap();
    let pkg = root.join("vendor/psr/log");
    std::fs::create_dir_all(pkg.join("src")).unwrap();
    std::fs::write(pkg.join(FILE), ORIGINAL).unwrap();
    std::fs::write(root.join("composer.lock"), crlf_lock()).unwrap();
}

fn vulnerabilities() -> Value {
    json!({ GHSA: {
        "cves": ["CVE-2026-0005"],
        "summary": "composer crlf fixture",
        "severity": "high",
        "description": "d"
    }})
}

/// `.socket/manifest.json` + the after-hash blob, so `vendor` runs offline.
fn stage_manifest(root: &Path) {
    let after = compute_git_sha256_from_bytes(PATCHED);
    let socket = root.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    let manifest = json!({ "patches": { PURL: {
        "uuid": UUID,
        "exportedAt": "2026-01-01T00:00:00Z",
        "files": { FILE: {
            "beforeHash": compute_git_sha256_from_bytes(ORIGINAL),
            "afterHash": after,
        }},
        "vulnerabilities": vulnerabilities(),
        "description": "x", "license": "MIT", "tier": "free",
    }}});
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();
    std::fs::write(socket.join("blobs").join(after), PATCHED).unwrap();
}

async fn mount_api(server: &MockServer) {
    let blob = base64::engine::general_purpose::STANDARD.encode(PATCHED);
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "packages": [{
                "purl": PURL,
                "patches": [{
                    "uuid": UUID, "purl": PURL, "tier": "free",
                    "cveIds": ["CVE-2026-0005"], "ghsaIds": [GHSA], "severity": "high",
                    "title": "composer crlf fixture"
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
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "patches": [{
                "uuid": UUID, "purl": PURL,
                "publishedAt": "2026-01-01T00:00:00Z",
                "description": "x", "license": "MIT", "tier": "free",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;
    let view = json!({
        "uuid": UUID,
        "purl": PURL,
        "publishedAt": "2026-01-01T00:00:00Z",
        "files": {
            format!("package/{FILE}"): {
                "beforeHash": compute_git_sha256_from_bytes(ORIGINAL),
                "afterHash": compute_git_sha256_from_bytes(PATCHED),
                "blobContent": blob,
            }
        },
        "vulnerabilities": vulnerabilities(),
        "description": "x", "license": "MIT", "tier": "free"
    });
    prebuilt_common::mount_view(server, &view, None).await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(view.clone()))
        .mount(server)
        .await;
}

fn cli() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_socket-patch"));
    for (key, _) in std::env::vars_os() {
        let name = key.to_string_lossy();
        if name.starts_with("SOCKET_") && name != "SOCKET_NO_CONFIG" {
            cmd.env_remove(&key);
        }
    }
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1");
    cmd
}

fn run_json(root: &Path, args: &[&str]) -> (i32, Value) {
    let mut command = cli();
    let _fixture = prebuilt_common::prepare_command(&mut command, root, args, &[]);
    let out = command
        .args(["--json", "--cwd", root.to_str().unwrap()])
        .output()
        .expect("run socket-patch");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let env: Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!(
            "{args:?} --json must emit JSON: {e}\nstdout:\n{stdout}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stderr)
        )
    });
    (out.status.code().unwrap_or(-1), env)
}

fn api_args(api_url: &str) -> [&str; 7] {
    [
        "--yes",
        "--api-url",
        api_url,
        "--org",
        ORG,
        "--api-token",
        "fake",
    ]
}

/// No bare `\n` and no stray `\r`: every line break is a CRLF.
fn assert_all_crlf(text: &str, what: &str) {
    let crlf = text.matches("\r\n").count();
    assert!(crlf > 0, "{what} has no line breaks:\n{text}");
    assert_eq!(
        crlf,
        text.matches('\n').count(),
        "{what} must keep CRLF line endings:\n{text:?}"
    );
    assert_eq!(crlf, text.matches('\r').count(), "{what}: {text:?}");
}

/// The lock after vendoring: CRLF, wired to the copy, and nothing but the
/// psr/log entry changed.
fn assert_wired_crlf(root: &Path) -> String {
    let text = std::fs::read_to_string(root.join("composer.lock")).unwrap();
    assert_all_crlf(&text, "vendored composer.lock");
    let lock: Value = serde_json::from_str(&text).unwrap();
    let entry = &lock["packages"][0];
    assert_eq!(entry["dist"]["type"], "path", "{lock:#}");
    assert_eq!(
        entry["dist"]["url"],
        format!(".socket/vendor/composer/{UUID}/psr/log@3.0.2").as_str()
    );
    assert_eq!(entry["dist"]["reference"], UUID);
    assert!(entry.get("source").is_none(), "{lock:#}");
    let before: Value = serde_json::from_str(&crlf_lock()).unwrap();
    for key in [
        "_readme",
        "content-hash",
        "packages-dev",
        "plugin-api-version",
    ] {
        assert_eq!(lock[key], before[key], "{key} untouched");
    }
    text
}

/// A re-run leaves the lock byte-identical, then `vendor --revert` restores
/// the original CRLF bytes and composer.json stays untouched throughout.
fn assert_rerun_and_revert(root: &Path, rerun: &[&str], vendored: &str) {
    let (code, env) = run_json(root, rerun);
    assert_eq!(code, 0, "re-vendor must succeed: {env:#}");
    assert_eq!(
        std::fs::read_to_string(root.join("composer.lock")).unwrap(),
        vendored,
        "an in-sync re-vendor leaves composer.lock byte-identical"
    );

    let (code, env) = run_json(root, &["vendor", "--revert", "--offline"]);
    assert_eq!(code, 0, "vendor --revert must succeed: {env:#}");
    assert_eq!(
        std::fs::read_to_string(root.join("composer.lock")).unwrap(),
        crlf_lock(),
        "vendor --revert must restore the CRLF composer.lock byte-for-byte"
    );
    assert_eq!(
        std::fs::read(root.join("composer.json")).unwrap(),
        b"{\r\n    \"require\": {\r\n        \"psr/log\": \"^3.0\"\r\n    }\r\n}\r\n",
        "composer.json is never touched"
    );
    assert!(
        !root.join(".socket/vendor/composer").exists(),
        "revert removes the vendored copy"
    );
}

#[test]
fn vendor_offline_keeps_a_crlf_lock_and_reverts_it_byte_identically() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_project(root);
    stage_manifest(root);

    let (code, env) = run_json(root, &["vendor", "--offline"]);
    assert_eq!(code, 0, "vendor must succeed: {env:#}");
    let vendored = assert_wired_crlf(root);
    assert_eq!(
        std::fs::read(
            root.join(format!(".socket/vendor/composer/{UUID}/psr/log@3.0.2"))
                .join(FILE)
        )
        .unwrap(),
        PATCHED
    );
    assert_rerun_and_revert(root, &["vendor", "--offline"], &vendored);
}

#[tokio::test]
async fn scan_vendor_keeps_a_crlf_lock_and_reverts_it_byte_identically() {
    let server = MockServer::start().await;
    mount_api(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_project(root);
    let uri = server.uri();
    let mut args = vec!["scan", "--mode", "vendored", "--vendor-source", "service"];
    args.extend(api_args(&uri));

    let (code, env) = run_json(root, &args);
    assert_eq!(code, 0, "scan --mode vendored must succeed: {env:#}");
    assert_eq!(env["vendor"]["summary"]["applied"], 1, "{env:#}");
    let vendored = assert_wired_crlf(root);
    assert_rerun_and_revert(root, &args, &vendored);
}

#[tokio::test]
async fn get_vendored_keeps_a_crlf_lock_and_reverts_it_byte_identically() {
    let server = MockServer::start().await;
    mount_api(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_project(root);
    let uri = server.uri();
    let mut args = vec![
        "get",
        UUID,
        "--mode",
        "vendored",
        "--vendor-source",
        "service",
    ];
    args.extend(api_args(&uri));

    let (code, env) = run_json(root, &args);
    assert_eq!(code, 0, "get --mode vendored must succeed: {env:#}");
    let vendored = assert_wired_crlf(root);
    assert_rerun_and_revert(root, &args, &vendored);
}
