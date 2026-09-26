//! Composer patch purls in the padded `version_normalized` spelling.
//!
//! Socket's SBOM ingestion stores composer versions padded (`3.0.2.0`), so a
//! patch's base purl can say `pkg:composer/psr/log@3.0.2.0` while the
//! project's `installed.json` and `composer.lock` say `3.0.2` or `v3.0.2`.
//! Every mode must treat those as the same release: agent-mode `scan --sync`
//! patches the installed copy and its prune keeps the patch, `scan --vendor`
//! vendors and wires the lock entry (and `vex` attests it), and hosted
//! `scan --redirect` repoints the lock entry. Each test runs the built binary
//! against a wiremock API that serves only the padded spelling.

use std::path::Path;
use std::process::Command;

use base64::Engine as _;
use serde_json::{json, Value};
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";
const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
/// The patch purl the API serves: the padded composer spelling.
const API_PURL: &str = "pkg:composer/psr/log@3.0.2.0";
/// What the crawler reports for the installed `3.0.2` / `v3.0.2`.
const CRAWLED_PURL: &str = "pkg:composer/psr/log@3.0.2";
const GHSA: &str = "GHSA-cmpv-aaaa-bbbb";
const SHA1: &str = "abcdef0123456789abcdef0123456789abcdef01";
const FILE: &str = "src/LoggerInterface.php";
const ORIGINAL: &[u8] = b"<?php\nnamespace Psr\\Log;\ninterface LoggerInterface {}\n";
const PATCHED: &[u8] =
    b"<?php\nnamespace Psr\\Log;\ninterface LoggerInterface {}\n// SOCKET-PATCH-E2E-MARKER\n";

fn hosted_url() -> String {
    format!(
        "http://patch.test/patch/composer/psr/log/3.0.2.0/\
         77777777-7777-4777-8777-777777777777/{UUID}/log-3.0.2.0.zip"
    )
}

fn lock_text(version: &str) -> String {
    format!(
        r#"{{
    "content-hash": "abc123def456abc123def456abc1",
    "packages": [
        {{
            "name": "psr/log",
            "version": "{version}",
            "source": {{
                "type": "git",
                "url": "https://github.com/php-fig/log.git",
                "reference": "f16e1d5863e37f8d8c2a01719f5b34baa2b714d3"
            }},
            "dist": {{
                "type": "zip",
                "url": "https://api.github.com/repos/php-fig/log/zipball/f16e1d5863e37f8d8c2a01719f5b34baa2b714d3",
                "reference": "f16e1d5863e37f8d8c2a01719f5b34baa2b714d3",
                "shasum": ""
            }},
            "type": "library"
        }}
    ],
    "packages-dev": []
}}
"#
    )
}

/// A composer project with `psr/log` installed (and locked) as `version`.
fn write_project(root: &Path, version: &str) {
    std::fs::write(
        root.join("composer.json"),
        "{ \"require\": { \"psr/log\": \"^3.0\" } }\n",
    )
    .unwrap();
    let installed = root.join("vendor/composer");
    std::fs::create_dir_all(&installed).unwrap();
    std::fs::write(
        installed.join("installed.json"),
        format!(
            r#"{{ "packages": [ {{ "name": "psr/log", "version": "{version}", "version_normalized": "3.0.2.0" }} ] }}
"#
        ),
    )
    .unwrap();
    let pkg = root.join("vendor/psr/log");
    std::fs::create_dir_all(pkg.join("src")).unwrap();
    std::fs::write(pkg.join(FILE), ORIGINAL).unwrap();
    std::fs::write(root.join("composer.lock"), lock_text(version)).unwrap();
}

/// Discovery, per-package search, the full view (inline blob), and the
/// hosted package reference — every patch record in the padded spelling.
/// The batch response's outer package purl echoes the crawler's query, as
/// production does.
async fn mount_api(server: &MockServer) {
    let before_hash = compute_git_sha256_from_bytes(ORIGINAL);
    let after_hash = compute_git_sha256_from_bytes(PATCHED);
    let blob = base64::engine::general_purpose::STANDARD.encode(PATCHED);
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "packages": [{
                "purl": CRAWLED_PURL,
                "patches": [{
                    "uuid": UUID, "purl": API_PURL, "tier": "free",
                    "cveIds": ["CVE-2026-0003"], "ghsaIds": [GHSA], "severity": "high",
                    "title": "composer padded version fixture"
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
                "uuid": UUID, "purl": API_PURL,
                "publishedAt": "2026-01-01T00:00:00Z",
                "description": "x", "license": "MIT", "tier": "free",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "uuid": UUID,
            "purl": API_PURL,
            "publishedAt": "2026-01-01T00:00:00Z",
            "files": {
                format!("package/{FILE}"): {
                    "beforeHash": before_hash,
                    "afterHash": after_hash,
                    "blobContent": blob,
                }
            },
            "vulnerabilities": {
                GHSA: {
                    "cves": ["CVE-2026-0003"],
                    "summary": "composer padded version fixture",
                    "severity": "high",
                    "description": "d"
                }
            },
            "description": "x", "license": "MIT", "tier": "free"
        })))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": {
                UUID: {
                    "status": "granted",
                    "url": hosted_url(),
                    "purl": API_PURL,
                    "artifacts": [{
                        "kind": "tarball",
                        "url": hosted_url(),
                        "integrity": { "sha1": SHA1 }
                    }],
                    "registryOverride": null
                }
            }
        })))
        .mount(server)
        .await;
}

/// The built binary with every ambient `SOCKET_*` variable scrubbed and
/// telemetry off, so the assertions reflect only the argv.
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

/// `socket-patch <args> --json` against `api_url`, returning `(exit, stdout
/// JSON)`; panics with both streams when stdout is not JSON.
fn run_json(cwd: &Path, api_url: &str, args: &[&str]) -> (i32, Value) {
    let out = cli()
        .args(args)
        .args([
            "--json",
            "--yes",
            "--cwd",
            cwd.to_str().unwrap(),
            "--api-url",
            api_url,
            "--org",
            ORG,
            "--api-token",
            "fake",
        ])
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

fn read_json(file: &Path) -> Value {
    serde_json::from_slice(
        &std::fs::read(file).unwrap_or_else(|e| panic!("read {}: {e}", file.display())),
    )
    .unwrap_or_else(|e| panic!("{} is not JSON: {e}", file.display()))
}

/// Agent mode: `scan --sync` downloads the `@3.0.2.0` patch, applies it to
/// the installed `v3.0.2` copy, and its prune step keeps the manifest entry
/// (the crawler reports `@3.0.2`, the same release).
#[tokio::test]
async fn agent_sync_applies_and_keeps_a_padded_composer_patch() {
    let server = MockServer::start().await;
    mount_api(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path(), "v3.0.2");

    let (code, env) = run_json(tmp.path(), &server.uri(), &["scan", "--sync"]);
    assert_eq!(code, 0, "scan --sync must succeed: {env:#}");
    assert_eq!(
        std::fs::read(tmp.path().join("vendor/psr/log").join(FILE)).unwrap(),
        PATCHED,
        "the installed v3.0.2 copy must carry the patched bytes: {env:#}"
    );
    let manifest = read_json(&tmp.path().join(".socket/manifest.json"));
    assert_eq!(
        manifest["patches"][API_PURL]["uuid"], UUID,
        "the manifest keeps the patch under the API spelling (not pruned): {manifest:#}"
    );

    // A second sync is a no-op that still keeps the patch.
    let (code, env) = run_json(tmp.path(), &server.uri(), &["scan", "--sync"]);
    assert_eq!(code, 0, "re-sync must succeed: {env:#}");
    let manifest = read_json(&tmp.path().join(".socket/manifest.json"));
    assert_eq!(manifest["patches"][API_PURL]["uuid"], UUID, "{manifest:#}");
}

/// Vendored mode: `scan --vendor` finds the installed `3.0.2`, finds the
/// lock's `3.0.2` entry for the `@3.0.2.0` patch, vendors the copy under the
/// patch spelling and wires the entry; `vex` attests the vendored patch
/// (lock `3.0.2` vs leaf `@3.0.2.0`); `vendor --revert` byte-restores the lock.
#[tokio::test]
async fn vendor_wires_and_attests_a_padded_composer_patch() {
    let server = MockServer::start().await;
    mount_api(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_project(root, "3.0.2");

    let (code, env) = run_json(
        root,
        &server.uri(),
        &["scan", "--vendor", "--vendor-source", "build"],
    );
    assert_eq!(code, 0, "scan --vendor must succeed: {env:#}");
    assert_eq!(env["vendor"]["summary"]["applied"], 1, "{env:#}");
    assert_eq!(env["vendor"]["summary"]["failed"], 0, "{env:#}");

    let copy_rel = format!(".socket/vendor/composer/{UUID}/psr/log@3.0.2.0");
    assert_eq!(
        std::fs::read(root.join(&copy_rel).join(FILE)).unwrap(),
        PATCHED,
        "the vendored copy must carry the patched bytes"
    );
    let lock = read_json(&root.join("composer.lock"));
    let entry = &lock["packages"][0];
    assert_eq!(
        entry["version"], "3.0.2",
        "the lock's version is never rewritten"
    );
    assert_eq!(entry["dist"]["type"], "path");
    assert_eq!(entry["dist"]["url"], copy_rel.as_str());
    assert_eq!(entry["dist"]["reference"], UUID);
    let state = read_json(&root.join(".socket/vendor/state.json"));
    assert_eq!(state["entries"][API_PURL]["uuid"], UUID, "{state:#}");

    let out = cli()
        .args([
            "vex",
            "--cwd",
            root.to_str().unwrap(),
            "--product",
            "pkg:github/acme/app@1.0.0",
            "--offline",
        ])
        .output()
        .expect("invoke vex");
    assert!(
        out.status.success(),
        "vex must attest the vendored patch. stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let doc: Value = serde_json::from_slice(&out.stdout).expect("VEX JSON on stdout");
    let stmts = doc["statements"].as_array().unwrap();
    assert_eq!(stmts.len(), 1, "one attested vulnerability: {doc:#}");
    assert_eq!(stmts[0]["vulnerability"]["name"], GHSA);
    assert_eq!(stmts[0]["status"], "not_affected", "{doc:#}");
    assert_eq!(
        stmts[0]["impact_statement"].as_str().unwrap(),
        format!("Patched via Socket patch {UUID} (vendored)")
    );

    let out = cli()
        .args([
            "vendor",
            "--revert",
            "--json",
            "--offline",
            "--cwd",
            root.to_str().unwrap(),
        ])
        .output()
        .expect("invoke vendor --revert");
    assert!(
        out.status.success(),
        "vendor --revert must succeed. stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(root.join("composer.lock")).unwrap(),
        lock_text("3.0.2"),
        "revert must byte-restore composer.lock"
    );
}

/// Hosted mode: the package reference names `@3.0.2.0`, the lock `3.0.2`;
/// the redirect repoints the entry, is confirmed, and is recorded.
#[tokio::test]
async fn hosted_redirect_repoints_a_padded_composer_patch() {
    let server = MockServer::start().await;
    mount_api(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path(), "3.0.2");

    let (code, env) = run_json(tmp.path(), &server.uri(), &["scan", "--redirect"]);
    assert_eq!(code, 0, "scan --redirect must succeed: {env:#}");
    assert_eq!(env["redirect"]["redirected"], 1, "{env:#}");
    let codes: Vec<&str> = env["redirect"]["warnings"]
        .as_array()
        .map(|w| w.iter().filter_map(|w| w["code"].as_str()).collect())
        .unwrap_or_default();
    assert!(
        !codes.contains(&"redirect_composer_version_mismatch"),
        "3.0.2 and 3.0.2.0 are one release: {env:#}"
    );

    let lock = read_json(&tmp.path().join("composer.lock"));
    let entry = &lock["packages"][0];
    assert_eq!(
        entry["version"], "3.0.2",
        "the lock's version is never rewritten"
    );
    assert_eq!(entry["dist"]["url"], hosted_url().as_str(), "{lock:#}");
    assert_eq!(entry["dist"]["shasum"], SHA1, "{lock:#}");
    let ledger = std::fs::read_to_string(tmp.path().join(".socket/vendor/redirect-state.json"))
        .expect("redirect ledger written");
    assert!(
        ledger.contains(API_PURL) && ledger.contains("redirect_composer_dist"),
        "the ledger records the redirected patch and its revert edit: {ledger}"
    );
}
