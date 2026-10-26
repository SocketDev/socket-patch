//! Composer vendored → hosted mode takeover (#536): `scan --mode hosted`
//! and `get <uuid> --mode hosted` over a project socket-patch itself
//! vendored must revert its own vendored `composer.lock` entry (the per-purl
//! `vendor --revert` machinery) and then redirect, leaving the project
//! FULLY hosted: the same lock a direct hosted scan writes, which `rollback`
//! can restore from packagist. Before the fix the takeover gate omitted
//! `pkg:composer/`, so the hosted rewriter edited the vendored entry in
//! place and kept the patch-uuid `dist.reference`; `rollback` then refused
//! ("packagist now serves …") and the vendored copy and ledger entry were
//! orphaned.
//!
//! Hermetic: the vendored copy is built from the staged manifest, and the
//! patch API and packagist are wiremocks.

#[path = "common/hermetic.rs"]
mod hermetic;
#[path = "prebuilt_common/mod.rs"]
mod prebuilt_common;

use std::path::Path;

use base64::Engine as _;
use serde_json::{json, Value};
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";
const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
const PURL: &str = "pkg:composer/psr/log@3.0.2";
const FILE: &str = "src/LoggerInterface.php";
const ORIGINAL: &[u8] = b"<?php\nnamespace Psr\\Log;\ninterface LoggerInterface {}\n";
const PATCHED: &[u8] =
    b"<?php\nnamespace Psr\\Log;\ninterface LoggerInterface {}\n// SOCKET-PATCH-TAKEOVER\n";
const REFERENCE: &str = "f16e1d5863e37f8d8c2a01719f5b34baa2b714d3";
const SHA1: &str = "40b75d18c1b1ba0bd9fc0e8b51b1b44b1d5e8d7f";

/// A packagist-origin lock, as `composer update` writes it.
fn original_lock() -> String {
    format!(
        r#"{{
    "_readme": [
        "This file locks the dependencies of your project to a known state"
    ],
    "content-hash": "abc123def456abc123def456abc1",
    "packages": [
        {{
            "name": "psr/log",
            "version": "3.0.2",
            "source": {{
                "type": "git",
                "url": "https://github.com/php-fig/log.git",
                "reference": "{REFERENCE}"
            }},
            "dist": {{
                "type": "zip",
                "url": "https://api.github.com/repos/php-fig/log/zipball/{REFERENCE}",
                "reference": "{REFERENCE}",
                "shasum": ""
            }},
            "type": "library",
            "notification-url": "https://packagist.org/downloads/"
        }}
    ],
    "packages-dev": [],
    "plugin-api-version": "2.6.0"
}}
"#
    )
}

fn write_project(root: &Path) {
    std::fs::create_dir_all(root).unwrap();
    std::fs::write(
        root.join("composer.json"),
        "{\n    \"require\": {\n        \"psr/log\": \"3.0.2\"\n    }\n}\n",
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
    std::fs::write(root.join("composer.lock"), original_lock()).unwrap();
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
        "vulnerabilities": {},
        "description": "x", "license": "MIT", "tier": "free",
    }}});
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();
    std::fs::write(socket.join("blobs").join(after), PATCHED).unwrap();
}

/// The hosted archive URL the grant names.
fn hosted_url(server: &MockServer) -> String {
    format!(
        "{}/patch/composer/psr/log/3.0.2/33333333-3333-4333-8333-333333333333/{UUID}/log-3.0.2.zip",
        server.uri()
    )
}

/// The patch API (discovery, view, the hosted grant) and packagist's p2
/// metadata for psr/log, which hosted `rollback` restores the entry from.
async fn mount_api(server: &MockServer) {
    let url = hosted_url(server);
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "packages": [{ "purl": PURL, "patches": [{
                "uuid": UUID, "purl": PURL, "tier": "free", "cveIds": [], "ghsaIds": [],
                "severity": "high", "title": "composer takeover fixture"
            }]}],
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
                "uuid": UUID, "purl": PURL, "publishedAt": "2026-01-01T00:00:00Z",
                "description": "x", "license": "MIT", "tier": "free", "vulnerabilities": {}
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
                "blobContent": base64::engine::general_purpose::STANDARD.encode(PATCHED),
            }
        },
        "vulnerabilities": {},
        "description": "x", "license": "MIT", "tier": "free"
    });
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(view))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": { UUID: {
                "status": "granted", "url": url, "purl": PURL,
                "artifacts": [{ "kind": "tarball", "url": url,
                                "integrity": { "sha1": SHA1 } }],
                "registryOverride": null
            }}
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/p2/psr/log.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "packages": { "psr/log": [{
                "name": "psr/log",
                "version": "3.0.2",
                "version_normalized": "3.0.2.0",
                "source": {
                    "type": "git",
                    "url": "https://github.com/php-fig/log.git",
                    "reference": REFERENCE
                },
                "dist": {
                    "type": "zip",
                    "url": format!("https://api.github.com/repos/php-fig/log/zipball/{REFERENCE}"),
                    "reference": REFERENCE,
                    "shasum": ""
                },
                "type": "library"
            }]}
        })))
        .mount(server)
        .await;
}

fn run_json(root: &Path, args: &[&str], server: &MockServer) -> (i32, Value) {
    let mut command = hermetic::binary_command();
    let _fixture = prebuilt_common::prepare_command(&mut command, root, args, &[]);
    let out = command
        .args(["--json", "--cwd", root.to_str().unwrap()])
        .env("SOCKET_PACKAGIST_URL", server.uri())
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

fn api_args(uri: &str) -> Vec<&str> {
    vec![
        "--yes",
        "--api-url",
        uri,
        "--org",
        ORG,
        "--api-token",
        "fake",
        "--patch-server-url",
        uri,
    ]
}

fn scan_hosted_args(uri: &str) -> Vec<&str> {
    let mut args = vec!["scan", "--mode", "hosted"];
    args.extend(api_args(uri));
    args
}

fn get_hosted_args(uri: &str) -> Vec<&str> {
    let mut args = vec!["get", UUID, "--mode", "hosted"];
    args.extend(api_args(uri));
    args
}

/// The lock a direct hosted scan of the untouched project writes: what the
/// takeover must converge on.
async fn direct_hosted_lock(server: &MockServer, base: &Path) -> String {
    let root = base.join("direct");
    write_project(&root);
    let (code, env) = run_json(&root, &scan_hosted_args(&server.uri()), server);
    assert_eq!(code, 0, "direct hosted scan: {env:#}");
    std::fs::read_to_string(root.join("composer.lock")).unwrap()
}

/// Vendor `root`, run `hosted` (a `scan` or `get` invocation) over it, and
/// check the takeover: the vendored wiring is reverted first, the lock is
/// the direct hosted scan's, the vendored copy and ledger entry are gone,
/// and `rollback` restores the original packagist entry.
async fn assert_vendored_to_hosted(hosted: fn(&str) -> Vec<&str>) {
    let server = MockServer::start().await;
    mount_api(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    let expected = direct_hosted_lock(&server, tmp.path()).await;
    assert!(expected.contains(&hosted_url(&server)), "{expected}");

    let root = tmp.path().join("proj");
    write_project(&root);
    stage_manifest(&root);
    let (code, env) = run_json(&root, &["vendor", "--offline"], &server);
    assert_eq!(code, 0, "vendor: {env:#}");
    let vendored = std::fs::read_to_string(root.join("composer.lock")).unwrap();
    assert!(
        vendored.contains(&format!(".socket/vendor/composer/{UUID}/")),
        "vendored first:\n{vendored}"
    );

    let uri = server.uri();
    let (code, env) = run_json(&root, &hosted(&uri), &server);
    assert_eq!(code, 0, "hosted over the vendored project: {env:#}");
    assert!(
        env.to_string()
            .contains("redirect_takeover_reverted_vendored"),
        "the takeover is surfaced: {env:#}"
    );
    let lock = std::fs::read_to_string(root.join("composer.lock")).unwrap();
    assert_eq!(
        lock, expected,
        "the takeover writes the same lock as a direct hosted scan \
         (upstream dist.reference, no vendored transport-options)"
    );
    assert!(
        !root
            .join(format!(".socket/vendor/composer/{UUID}"))
            .exists(),
        "the vendored copy is reclaimed"
    );
    let state = std::fs::read_to_string(root.join(".socket/vendor/state.json")).unwrap_or_default();
    assert!(
        !state.contains(PURL) && !state.contains("psr/log"),
        "the vendored ledger entry is removed: {state}"
    );

    let (code, env) = run_json(
        &root,
        &["rollback", "--yes", "--patch-server-url", &uri],
        &server,
    );
    assert_eq!(code, 0, "rollback of the hosted pin: {env:#}");
    assert_eq!(
        std::fs::read_to_string(root.join("composer.lock")).unwrap(),
        original_lock(),
        "rollback restores the packagist entry"
    );
}

#[tokio::test]
async fn scan_hosted_takes_over_a_vendored_composer_package() {
    assert_vendored_to_hosted(scan_hosted_args).await;
}

#[tokio::test]
async fn get_hosted_takes_over_a_vendored_composer_package() {
    assert_vendored_to_hosted(get_hosted_args).await;
}

/// With the vendored ledger lost, the takeover cannot revert the entry, so
/// the composer.lock rewriter must leave socket-patch's vendored entry
/// alone rather than repoint it in place with the patch-uuid
/// `dist.reference` (#536).
#[tokio::test]
async fn scan_hosted_leaves_a_vendored_entry_without_a_ledger_alone() {
    let server = MockServer::start().await;
    mount_api(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("proj");
    write_project(&root);
    stage_manifest(&root);
    let (code, env) = run_json(&root, &["vendor", "--offline"], &server);
    assert_eq!(code, 0, "vendor: {env:#}");
    std::fs::remove_file(root.join(".socket/vendor/state.json")).unwrap();
    let vendored = std::fs::read_to_string(root.join("composer.lock")).unwrap();

    let (code, env) = run_json(&root, &scan_hosted_args(&server.uri()), &server);
    assert_eq!(code, 0, "{env:#}");
    assert!(
        env.to_string().contains("redirect_composer_vendored_entry"),
        "{env:#}"
    );
    assert_eq!(
        std::fs::read_to_string(root.join("composer.lock")).unwrap(),
        vendored,
        "the vendored entry is left byte-identical"
    );
}
