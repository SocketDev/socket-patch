//! In-process rollback tests for HOSTED-mode state.
//!
//! v5 hosted mode keeps no ledger: the hosted pins ARE the lockfile entries
//! (discovered on `--patch-server-url`'s origin for these mock-host URLs),
//! and rollback restores each in-scope pin to its DEFAULT UPSTREAM registry
//! entry, re-resolved from the (wiremocked) registry through the
//! `SOCKET_NPM_REGISTRY` base override. A refused pin (offline, registry
//! failure) is left untouched and reported. A pre-v5 ledger is never
//! replayed; it is retired once no hosted pin remains.
//!
//! The genuine-wiring fixtures run the REAL hosted flow first — in-process
//! `scan --mode hosted` over an npm package-lock project (the
//! `in_process_redirect.rs` fixture, wiremock API) and in-process
//! `get <uuid> --mode hosted` over a pip requirements.txt project (the
//! `in_process_get_hosted_ecosystems.rs` fixture) — then roll back and
//! byte-compare the lockfiles against their pristine snapshots. The other
//! fixtures hand-write hosted yarn.lock entries (and, for the migration
//! tests, a pre-v5 ledger through the exported
//! `socket_patch_core::patch::redirect` types).
//!
//! Convention split (the same one `in_process_redirect.rs` documents):
//! in-process `rollback::run(RollbackArgs)` for exit codes + on-disk
//! post-state, and the `SOCKET_*`-scrubbed subprocess binary wherever the
//! `--json` envelope must be parsed back — an in-process `run` prints its
//! JSON to the real stdout, which the hosting test cannot read.
//!
//! `#[serial]`: every command's `run` mirrors env toggles into
//! process-global env vars (`apply_env_toggles`).

use std::collections::HashMap;
use std::path::Path;

#[path = "vex_e2e_common/mod.rs"]
mod vex_e2e_common;
#[path = "vex_pipenv_pip_steps/mod.rs"]
mod vex_pipenv_pip_steps;
#[path = "in_process_rollback_hosted/vlt.rs"]
mod vlt;
#[path = "vlt_hosted_common/mod.rs"]
mod vlt_hosted_common;

use serde_json::Value;
use serial_test::serial;
use socket_patch_cli::commands::rollback::{run as rollback_run, RollbackArgs};
use socket_patch_cli::commands::scan::{run as scan_run, ScanArgs, ScanMode};
use socket_patch_core::manifest::schema::{PatchFileInfo, PatchRecord, VulnerabilityInfo};
use socket_patch_core::patch::redirect::{save_redirect_state, FileEdit, RedirectState};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";

// ── the real-flow npm fixture (in_process_redirect.rs shapes) ───────────────
const NAME: &str = "in-proc-redirect";
const VERSION: &str = "1.0.0";
const PURL: &str = "pkg:npm/in-proc-redirect@1.0.0";
const UUID: &str = "11111111-1111-4111-8111-111111111111";
const HOSTED_URL: &str = "http://patch.test/patch/npm/in-proc-redirect/1.0.0/22222222-2222-4222-8222-222222222222/11111111-1111-4111-8111-111111111111/in-proc-redirect-1.0.0.tgz";
const PATCHED_SHA512: &str = "sha512-PATCHEDpatchedPATCHEDpatched0123456789==";
const GHSA: &str = "GHSA-rbhr-aaaa-bbbb";

// ── the hand-written hosted yarn.lock pins ──────────────────────────────────
const LP_PURL: &str = "pkg:npm/left-pad@1.2.3";
const LP_UUID: &str = "55555555-5555-4555-8555-555555555555";
const LP_HOSTED_URL: &str = "http://patch.test/patch/npm/left-pad/1.2.3/66666666-6666-4666-8666-666666666666/55555555-5555-4555-8555-555555555555/left-pad-1.2.3.tgz";
const IO_PURL: &str = "pkg:npm/is-odd@3.0.1";
const IO_HOSTED_URL: &str = "http://patch.test/patch/npm/is-odd/3.0.1/66666666-6666-4666-8666-666666666666/99999999-9999-4999-8999-999999999999/is-odd-3.0.1.tgz";
const GEM_UPSTREAM_REMOTE: &str = "https://rubygems.org/";
const GEM_PATCH_REMOTE: &str = "http://patch.test/gems/t0k3nt0k3n/";

fn hosted_scan_args(cwd: &Path, api_url: String) -> ScanArgs {
    ScanArgs {
        socket_yml: Default::default(),
        paths: Vec::new(),
        packages: Vec::new(),
        common: socket_patch_cli::args::GlobalArgs {
            cwd: cwd.to_path_buf(),
            org: Some(ORG.to_string()),
            api_token: Some("fake".to_string()),
            api_url: Some(api_url),
            json: true,
            yes: true,
            ..socket_patch_cli::args::GlobalArgs::default()
        },
        batch_size: Some(100),
        apply: false,
        prune: false,
        sync: false,
        vendor: false,
        mode: Some(ScanMode::Hosted),
        all_releases: false,
        vex: Default::default(),
        rollout: Default::default(),
    }
}

/// Bare (or targeted) in-process rollback with the sibling suites' arg
/// defaults: `--json --yes --offline`, manifest at the default path.
async fn rollback_in_process(cwd: &Path, targets: Vec<String>, preserve_state: bool) -> i32 {
    let args = RollbackArgs {
        targets,
        common: socket_patch_cli::args::GlobalArgs {
            cwd: cwd.to_path_buf(),
            manifest_path: ".socket/manifest.json".to_string(),
            offline: true,
            json: true,
            yes: true,
            silent: true,
            patch_server_url: Some("http://patch.test".to_string()),
            ..socket_patch_cli::args::GlobalArgs::default()
        },
        preserve_state,
    };
    let code = rollback_run(args).await;
    // `apply_env_toggles` mirrored `--offline` into the PROCESS env and
    // nothing unsets it; scrub so a later in-process `scan`/`get` in this
    // `#[serial]` process isn't silently forced offline.
    std::env::remove_var("SOCKET_OFFLINE");
    code
}

/// Serve the npm registry's version document for the real-flow fixture's
/// package, so the upstream restore can re-resolve its pristine entry.
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

/// Bare in-process rollback that may reach the (mocked) npm registry: the
/// upstream restore re-resolves each hosted pin's registry entry.
async fn rollback_online(cwd: &Path, server: &MockServer) -> i32 {
    std::env::set_var(
        "SOCKET_NPM_REGISTRY",
        format!("{}/npm-registry", server.uri()),
    );
    let args = RollbackArgs {
        targets: Vec::new(),
        common: socket_patch_cli::args::GlobalArgs {
            cwd: cwd.to_path_buf(),
            manifest_path: ".socket/manifest.json".to_string(),
            json: true,
            yes: true,
            silent: true,
            patch_server_url: Some("http://patch.test".to_string()),
            ..socket_patch_cli::args::GlobalArgs::default()
        },
        preserve_state: false,
    };
    let code = rollback_run(args).await;
    std::env::remove_var("SOCKET_NPM_REGISTRY");
    code
}

/// A `socket-patch` Command with the ambient `SOCKET_*` env surface scrubbed
/// (the `in_process_redirect.rs` seed-then-scrub pattern): hostile seeds
/// never reach the child because `env_remove` clears them too, but if a
/// scrub line is ever dropped the seed turns the suite red immediately.
/// Telemetry opt-outs are deliberately kept so an opted-out dev stays
/// opted out.
fn scrubbed_cli() -> std::process::Command {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_socket-patch"));
    cmd.env("SOCKET_DRY_RUN", "true")
        .env("SOCKET_OFFLINE", "true")
        .env("SOCKET_ECOSYSTEMS", "cargo")
        .env("SOCKET_MANIFEST_PATH", "/nonexistent/manifest.json")
        .env("SOCKET_PRESERVE_STATE", "true")
        .env_remove("SOCKET_DRY_RUN")
        .env_remove("SOCKET_OFFLINE")
        .env_remove("SOCKET_ECOSYSTEMS")
        .env_remove("SOCKET_MANIFEST_PATH")
        .env_remove("SOCKET_PRESERVE_STATE");
    for (key, _) in std::env::vars_os() {
        let name = key.to_string_lossy();
        if name.starts_with("SOCKET_") && !name.contains("TELEMETRY") && name != "SOCKET_NO_CONFIG"
        {
            cmd.env_remove(&key);
        }
    }
    // In-process tests in this binary `std::env::set_var` these via
    // `apply_env_toggles`; one set by a parallel test between the scan
    // above and the spawn would be inherited, so remove them
    // unconditionally (see in_process_vendor.rs `run_cli`).
    for key in [
        "SOCKET_OFFLINE",
        "SOCKET_DEBUG",
        "SOCKET_API_URL",
        "SOCKET_PROXY_URL",
    ] {
        cmd.env_remove(key);
    }
    cmd
}

/// Run `rollback --json --yes --offline [extra]` (the mock patch host
/// recognized as hosted) as a scrubbed subprocess
/// and parse the envelope back (in-process runs print to the real stdout,
/// which a hosting test can't read). Returns (exit code, envelope).
fn run_rollback_subprocess(cwd: &Path, extra: &[&str]) -> (i32, Value) {
    let out = scrubbed_cli()
        .args([
            "rollback",
            "--json",
            "--yes",
            "--offline",
            "--patch-server-url",
            "http://patch.test",
            "--cwd",
            cwd.to_str().unwrap(),
        ])
        .args(extra)
        .output()
        .expect("run socket-patch");
    let envelope: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "rollback --json stdout must be a pure JSON envelope: {e}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    });
    (out.status.code().unwrap_or(-1), envelope)
}

/// [`run_rollback_subprocess`] ONLINE: no `--offline`, the npm registry
/// pointed at `server`'s `/npm-registry` (see [`mock_yarn_registry`] /
/// [`mock_npm_registry`]), and the mock patch host recognized as hosted.
fn run_rollback_subprocess_online(cwd: &Path, server: &MockServer, extra: &[&str]) -> (i32, Value) {
    let out = scrubbed_cli()
        .env(
            "SOCKET_NPM_REGISTRY",
            format!("{}/npm-registry", server.uri()),
        )
        .args([
            "rollback",
            "--json",
            "--yes",
            "--patch-server-url",
            "http://patch.test",
            "--cwd",
            cwd.to_str().unwrap(),
        ])
        .args(extra)
        .output()
        .expect("run socket-patch");
    let envelope: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "rollback --json stdout must be a pure JSON envelope: {e}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    });
    (out.status.code().unwrap_or(-1), envelope)
}

/// The `code` field of every run-level warning in a rollback envelope.
fn warning_codes(envelope: &Value) -> Vec<String> {
    envelope["warnings"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|w| w["code"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

async fn mock_discovery(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": PURL,
                "patches": [{
                    "uuid": UUID, "purl": PURL, "tier": "free",
                    "cveIds": [], "ghsaIds": [], "severity": "high",
                    "title": "rollback hosted fixture"
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
}

async fn mock_reference(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "results": {
                UUID: {
                    "status": "granted",
                    "url": HOSTED_URL,
                    "purl": PURL,
                    "artifacts": [{
                        "kind": "tarball",
                        "url": HOSTED_URL,
                        "integrity": { "sha512": PATCHED_SHA512 }
                    }],
                    "registryOverride": null
                }
            }
        })))
        .mount(server)
        .await;
}

/// The `view/{uuid}` endpoint the hosted flow calls to build the patch
/// record it persists into the ledger — WITHOUT it the ledger is a degraded
/// records-empty ledger and the per-purl revert has nothing to claim.
async fn mock_view(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": UUID,
            "purl": PURL,
            "publishedAt": "2024-01-01T00:00:00Z",
            "files": {
                "package/index.js": {
                    "beforeHash": "a".repeat(64),
                    "afterHash": "b".repeat(64),
                }
            },
            "vulnerabilities": {
                GHSA: {
                    "cves": ["CVE-2024-9"],
                    "summary": "rollback hosted fixture",
                    "severity": "high",
                    "description": "d"
                }
            },
            "description": "x", "license": "MIT", "tier": "free"
        })))
        .mount(server)
        .await;
}

/// Write the npm project (package.json + installed tree + package-lock.json)
/// and return the PRISTINE lock bytes. The lock is normalized through the
/// same `to_string_pretty + "\n"` form the redirect writer emits
/// (`serialize_json`), so the pristine snapshot is a meaningful byte-identity
/// oracle for the wire→unwind round trip.
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

fn ledger_path(root: &Path) -> std::path::PathBuf {
    root.join(".socket/vendor/redirect-state.json")
}

/// A full camelCase patch record for the hand-written pre-v5 ledgers.
fn patch_record(uuid: &str, ghsa: &str) -> PatchRecord {
    let mut files = HashMap::new();
    files.insert(
        "package/index.js".to_string(),
        PatchFileInfo {
            before_hash: "a".repeat(64),
            after_hash: "b".repeat(64),
        },
    );
    let mut vulns = HashMap::new();
    vulns.insert(
        ghsa.to_string(),
        VulnerabilityInfo {
            cves: vec!["CVE-2024-1".to_string()],
            summary: "s".to_string(),
            severity: "high".to_string(),
            description: "d".to_string(),
        },
    );
    PatchRecord {
        uuid: uuid.to_string(),
        exported_at: "2024-01-01T00:00:00Z".to_string(),
        files,
        vulnerabilities: vulns,
        description: "x".to_string(),
        license: "MIT".to_string(),
        tier: "free".to_string(),
    }
}

/// Serialize a PRE-V5 hosted ledger (v5 never writes one) through the real
/// core writer (real schema: version, mode "hosted", edits[FileEdit],
/// records{purl: record}) — what an older release left on disk.
async fn write_legacy_ledger(root: &Path, edits: Vec<FileEdit>) {
    let mut state = RedirectState::new();
    state.edits = edits;
    state.records.insert(
        LP_PURL.to_string(),
        patch_record(LP_UUID, "GHSA-lpad-aaaa-bbbb"),
    );
    save_redirect_state(root, &state)
        .await
        .expect("write redirect ledger");
}

/// Serve the npm registry's version document for `name@version` under
/// `/npm-registry` (the `SOCKET_NPM_REGISTRY` base `rollback_online` and
/// `run_rollback_subprocess_online` set) in the shape a yarn-classic
/// restore turns back into [`yarn_upstream_block`].
async fn mock_yarn_registry(server: &MockServer, name: &str, version: &str) {
    Mock::given(method("GET"))
        .and(path(format!("/npm-registry/{name}/{version}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": name,
            "version": version,
            "dist": {
                "tarball": format!("https://registry.yarnpkg.com/{name}/-/{name}-{version}.tgz"),
                "shasum": "aaaa",
                "integrity": "sha512-UPSTREAMupstream==",
            }
        })))
        .mount(server)
        .await;
}

// ── yarn-classic fragments ──────────────────────────────────────────────────
// The hosted wiring is the lock entry itself; the upstream block is exactly
// what the restore re-derives from `mock_yarn_registry`'s document.

fn yarn_block_for(name: &str, version: &str, resolved: &str, integrity: &str) -> String {
    format!(
        "{name}@{version}:\n  version \"{version}\"\n  resolved \"{resolved}\"\n  integrity {integrity}"
    )
}

fn yarn_block(resolved: &str, integrity: &str) -> String {
    yarn_block_for("left-pad", "1.2.3", resolved, integrity)
}

fn yarn_upstream_block(name: &str, version: &str) -> String {
    yarn_block_for(
        name,
        version,
        &format!("https://registry.yarnpkg.com/{name}/-/{name}-{version}.tgz#aaaa"),
        "sha512-UPSTREAMupstream==",
    )
}

fn yarn_original_block() -> String {
    yarn_upstream_block("left-pad", "1.2.3")
}

fn yarn_redirected_block() -> String {
    yarn_block(LP_HOSTED_URL, "sha512-PATCHEDpatched==")
}

fn io_redirected_block() -> String {
    yarn_block_for("is-odd", "3.0.1", IO_HOSTED_URL, "sha512-PATCHEDio==")
}

fn yarn_lock_content(block: &str) -> String {
    format!(
        "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n\
         # yarn lockfile v1\n\n\n{block}\n"
    )
}

/// The yarn-classic edit a pre-v5 ledger recorded for the left-pad pin.
fn yarn_classic_edit() -> FileEdit {
    FileEdit {
        path: "yarn.lock".to_string(),
        kind: "redirect_yarn_classic_entry".to_string(),
        action: "rewritten".to_string(),
        key: Some("left-pad@1.2.3".to_string()),
        original: Some(Value::String(yarn_original_block())),
        new: Some(Value::String(yarn_redirected_block())),
    }
}

// ── other pre-v5 ledger edits (never replayed) ──────────────────────────────

fn gemfile_lock_content(remote: &str) -> String {
    format!(
        "GEM\n  remote: {remote}\n  specs:\n    rex (1.0.0)\n\n\
         PLATFORMS\n  ruby\n\nDEPENDENCIES\n  rex\n\nBUNDLED WITH\n   2.5.9\n"
    )
}

fn gem_source_edit() -> FileEdit {
    FileEdit {
        path: "Gemfile.lock".to_string(),
        kind: "redirect_gemfile_lock_source_url".to_string(),
        action: "rewritten".to_string(),
        key: Some("rex".to_string()),
        original: Some(Value::String(GEM_UPSTREAM_REMOTE.to_string())),
        new: Some(Value::String(GEM_PATCH_REMOTE.to_string())),
    }
}

/// An edit kind no release understands (a ledger from a newer build).
fn future_lock_edit() -> FileEdit {
    FileEdit {
        path: "future.lock".to_string(),
        kind: "redirect_future_lock_entry".to_string(),
        action: "rewritten".to_string(),
        key: Some("left-pad@1.2.3".to_string()),
        original: Some(Value::String(
            "left-pad@1.2.3 sha512-UPSTREAMupstream==".to_string(),
        )),
        new: Some(Value::String(format!("left-pad@1.2.3 {LP_HOSTED_URL}"))),
    }
}

/// Single-pin npm fixture: a yarn.lock hosted-wired to the mock patch host.
fn write_single_npm_fixture(root: &Path) {
    std::fs::write(
        root.join("yarn.lock"),
        yarn_lock_content(&yarn_redirected_block()),
    )
    .unwrap();
}

/// Two-pin fixture: left-pad then is-odd, both hosted in one yarn.lock.
fn write_two_pin_fixture(root: &Path) {
    std::fs::write(
        root.join("yarn.lock"),
        yarn_lock_content(&format!(
            "{}\n\n{}",
            yarn_redirected_block(),
            io_redirected_block()
        )),
    )
    .unwrap();
}

// ---------------------------------------------------------------------------
// 1. npm round trip: real scan --mode hosted wiring, then bare rollback
// ---------------------------------------------------------------------------

/// Snapshot the pristine lock → `scan --mode hosted` wires it (resolved URL
/// rewritten, NO ledger written) → bare in-process rollback restoring the
/// upstream entry from the mocked registry → exit 0, lock byte-identical to
/// pristine, and nothing materialized under `.socket/` as a side effect.
#[tokio::test]
#[serial]
async fn npm_hosted_round_trip() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    mock_view(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    let pristine = write_npm_project(tmp.path());

    let code = scan_run(hosted_scan_args(tmp.path(), server.uri())).await;
    assert_eq!(code, 0, "scan --mode hosted should succeed");
    let wired = std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap();
    assert!(
        wired.contains(HOSTED_URL) && wired.contains(PATCHED_SHA512),
        "the lock must be wired to the hosted patch before the rollback \
         means anything; got:\n{wired}"
    );
    assert_ne!(wired, pristine, "wiring must actually change the lock");
    assert!(
        !ledger_path(tmp.path()).exists(),
        "scan --mode hosted keeps no redirect ledger: the lockfile is the record"
    );

    mock_npm_registry(&server).await;
    let code = rollback_online(tmp.path(), &server).await;
    assert_eq!(code, 0, "bare rollback over hosted wiring should exit 0");

    let restored = std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap();
    assert_eq!(
        restored, pristine,
        "rollback must restore the lock byte-identical to the pristine snapshot"
    );
    assert!(
        !tmp.path().join(".socket").exists(),
        "a fully restored hosted project keeps no .socket/ residue: no manifest \
         or ledger is materialized, and the lock guard removes apply.lock and \
         the emptied directory"
    );
}

/// Dry-run twin of the round trip: a hosted npm dry run resolves the
/// upstream entry exactly like a wet run (the registry IS asked), exits 0,
/// and mutates NOTHING (no ledger is ever written either).
#[tokio::test]
#[serial]
async fn npm_hosted_dry_run_previews_cleanly() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    mock_view(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_npm_project(tmp.path());
    let code = scan_run(hosted_scan_args(tmp.path(), server.uri())).await;
    assert_eq!(code, 0, "scan --mode hosted should succeed");
    let wired = std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap();
    mock_npm_registry(&server).await;

    std::env::set_var(
        "SOCKET_NPM_REGISTRY",
        format!("{}/npm-registry", server.uri()),
    );
    let args = RollbackArgs {
        targets: Vec::new(),
        common: socket_patch_cli::args::GlobalArgs {
            cwd: tmp.path().to_path_buf(),
            manifest_path: ".socket/manifest.json".to_string(),
            json: true,
            yes: true,
            silent: true,
            dry_run: true,
            patch_server_url: Some("http://patch.test".to_string()),
            ..socket_patch_cli::args::GlobalArgs::default()
        },
        preserve_state: false,
    };
    let code = rollback_run(args).await;
    std::env::remove_var("SOCKET_NPM_REGISTRY");
    std::env::remove_var("SOCKET_DRY_RUN");
    assert_eq!(code, 0, "a hosted npm dry run must preview cleanly");
    let registry_hits = server
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .filter(|r| r.url.path().starts_with("/npm-registry/"))
        .count();
    assert!(
        registry_hits >= 1,
        "a dry run resolves the upstream entry like a wet run"
    );
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap(),
        wired,
        "dry run must not touch the lock"
    );
    assert!(
        !tmp.path().join(".socket").exists(),
        "dry run must write no ledger (or any .socket/ state)"
    );
}

/// The same round trip through the binary so the `--json` envelope can be
/// parsed back: `hosted.reverted == [purl]`, `hosted.editedFiles >= 1`,
/// nothing failed/unsupported, status success.
#[tokio::test]
#[serial]
async fn npm_hosted_round_trip_envelope() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    mock_view(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    let pristine = write_npm_project(tmp.path());
    let code = scan_run(hosted_scan_args(tmp.path(), server.uri())).await;
    assert_eq!(code, 0, "scan --mode hosted should succeed");

    mock_npm_registry(&server).await;
    let (code, envelope) = run_rollback_subprocess_online(tmp.path(), &server, &[]);
    assert_eq!(code, 0, "bare rollback should exit 0: {envelope}");
    assert_eq!(envelope["status"], "success", "{envelope}");
    assert_eq!(
        envelope["hosted"]["reverted"],
        serde_json::json!([PURL]),
        "the unwound purl must be reported: {envelope}"
    );
    assert!(
        envelope["hosted"]["editedFiles"].as_u64().unwrap_or(0) >= 1,
        "at least the lockfile was rewritten: {envelope}"
    );
    assert_eq!(envelope["hosted"]["failed"], serde_json::json!([]));
    assert_eq!(envelope["hosted"]["unsupported"], serde_json::json!([]));
    assert_eq!(
        envelope["manifest"]["removedEntries"],
        serde_json::json!([]),
        "hosted state lives in the lockfile, not the manifest: {envelope}"
    );
    assert!(
        warning_codes(&envelope).contains(&"reinstall_required".to_string()),
        "unwiring must carry the stale-install warning: {envelope}"
    );

    let restored = std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap();
    assert_eq!(restored, pristine, "lock must be byte-restored");
    assert!(
        !ledger_path(tmp.path()).exists(),
        "no ledger is ever written"
    );
}

// ---------------------------------------------------------------------------
// 2. pypi requirements.txt round trip (real hosted flow via get --mode hosted)
// ---------------------------------------------------------------------------

/// A pip project wired by the REAL hosted flow (`get <uuid> --mode hosted`,
/// the `in_process_get_hosted_ecosystems.rs` fixture — the UUID path needs
/// no installed tree), then a bare rollback: requirements.txt restored
/// byte-for-byte to the upstream `name==version` line (the file is
/// unhashed, so no registry lookup is needed and the run may stay offline),
/// no ledger ever written, exit 0.
#[tokio::test]
#[serial]
async fn pypi_requirements_hosted_round_trip() {
    const PY_UUID: &str = "a1a1a1a1-a1a1-4a1a-8a1a-a1a1a1a1a1a1";
    const PY_PURL: &str = "pkg:pypi/requests@2.31.0";
    const SHA256: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let url = format!(
        "http://patch.test/patch/pypi/requests/2.31.0/22222222-2222-4222-8222-222222222222/{PY_UUID}/requests-2.31.0-py3-none-any.whl"
    );

    let py_view = serde_json::json!({
        "uuid": PY_UUID,
        "purl": PY_PURL,
        "publishedAt": "2024-01-01T00:00:00Z",
        "files": {
            "requests/api.py": {
                "beforeHash": "a".repeat(64),
                "afterHash": "b".repeat(64),
            }
        },
        "vulnerabilities": {
            "GHSA-pypi-eeee-ffff": {
                "cves": ["CVE-2024-2"],
                "summary": "pypi hosted rollback fixture",
                "severity": "high",
                "description": "d"
            }
        },
        "description": "x", "license": "MIT", "tier": "free"
    });
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{PY_UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(py_view.clone()))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "results": {
                PY_UUID: {
                    "status": "granted",
                    "url": url,
                    "purl": PY_PURL,
                    "artifacts": [{
                        "kind": "tarball",
                        "url": url,
                        "integrity": { "sha256": SHA256 }
                    }],
                    "registryOverride": null
                }
            }
        })))
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let pristine = "flask==2.0.1\nrequests==2.31.0\n";
    std::fs::write(tmp.path().join("requirements.txt"), pristine).unwrap();

    let get_args = socket_patch_cli::commands::get::GetArgs {
        common: socket_patch_cli::args::GlobalArgs {
            org: Some(ORG.to_string()),
            cwd: tmp.path().to_path_buf(),
            yes: true,
            api_token: Some("fake".to_string()),
            api_url: Some(server.uri()),
            json: true,
            ..socket_patch_cli::args::GlobalArgs::default()
        },
        identifier: PY_UUID.to_string(),
        id: false,
        cve: false,
        ghsa: false,
        package: false,
        save_only: false,
        all_releases: false,
        mode: Some(ScanMode::Hosted),
    };
    let code = socket_patch_cli::commands::get::run(get_args).await;
    assert_eq!(code, 0, "get <uuid> --mode hosted (pypi) should succeed");

    let wired = std::fs::read_to_string(tmp.path().join("requirements.txt")).unwrap();
    assert!(
        wired.contains(&url),
        "requirements.txt must be wired to the hosted wheel; got:\n{wired}"
    );
    assert!(
        !ledger_path(tmp.path()).exists(),
        "get --mode hosted keeps no ledger: requirements.txt is the record"
    );

    // Manifest-less VEX over the committed hosted state (an EMPTY in-project
    // venv keeps the crawl hermetic; the `--hash` pin is the evidence).
    let site = if cfg!(windows) {
        tmp.path().join(".venv/Lib/site-packages")
    } else {
        tmp.path().join(".venv/lib/python3.12/site-packages")
    };
    std::fs::create_dir_all(site).unwrap();
    vex_pipenv_pip_steps::run_manifestless_steps(&vex_pipenv_pip_steps::Steps {
        what: "get --mode hosted requirements.txt (rollback round trip)".into(),
        project: tmp.path(),
        purl: PY_PURL,
        uuid: PY_UUID,
        marker: vex_e2e_common::Marker::Redirected,
        vulns: Some(&[("GHSA-pypi-eeee-ffff", &["CVE-2024-2"])]),
        records: vex_pipenv_pip_steps::Records::Mock(vec![(PY_UUID.into(), py_view.clone())]),
        patch_server_url: Some("http://patch.test".into()),
        product: "pkg:pypi/app@1.0.0",
        revert: &|p: &Path| std::fs::write(p.join("requirements.txt"), pristine).unwrap(),
        envs: Vec::new(),
        on_step: None,
        expect_verified: true,
    });

    let code = rollback_in_process(tmp.path(), Vec::new(), false).await;
    assert_eq!(
        code, 0,
        "bare rollback over the pypi redirect should exit 0"
    );

    let restored = std::fs::read_to_string(tmp.path().join("requirements.txt")).unwrap();
    assert_eq!(
        restored, pristine,
        "requirements.txt must be restored byte-for-byte"
    );
    assert!(
        !tmp.path().join(".socket/manifest.json").exists(),
        "hosted mode never touches the manifest"
    );
    assert!(
        !tmp.path().join(".socket").exists(),
        "a fully unwound hosted project keeps no .socket/ residue"
    );

    // After the rollback nothing references the patch any more: VEX finds
    // nothing to attest (online, the API would still vouch for the uuid).
    let dir = tmp.path().to_path_buf();
    let view = py_view.clone();
    std::thread::spawn(move || {
        let api = vex_e2e_common::PatchApi::start(vec![(PY_UUID.into(), view)]);
        let out = vex_e2e_common::run_vex(
            &vex_e2e_common::binary(),
            &dir,
            &vex_e2e_common::VexRun {
                patch_server_url: Some("http://patch.test".into()),
                ..vex_e2e_common::VexRun::online(&api)
            },
        );
        assert_eq!(out.code, Some(2), "{out}");
        assert_eq!(out.envelope["error"]["code"], "manifest_not_found", "{out}");
        api.assert_no_requests();
    })
    .join()
    .unwrap_or_else(|e| std::panic::resume_unwind(e));
    assert!(
        !tmp.path().join(".socket").exists(),
        "vex is read-only: it never recreates .socket/"
    );
}

// ---------------------------------------------------------------------------
// 3. scoped rollback restores only the named pins
// ---------------------------------------------------------------------------

/// Two hosted pins in one yarn.lock, scoped to ONE: only the named pin is
/// restored to its upstream registry entry (each pin restores on its own;
/// there is no whole-state replay), the other stays hosted byte-for-byte,
/// and a pre-v5 ledger beside them is kept while a pin remains. The
/// unscoped follow-up restores the other pin and then retires the ledger.
#[tokio::test]
#[serial]
async fn scoped_rollback_restores_only_the_named_pin() {
    let server = MockServer::start().await;
    mock_yarn_registry(&server, "left-pad", "1.2.3").await;
    mock_yarn_registry(&server, "is-odd", "3.0.1").await;
    let tmp = tempfile::tempdir().unwrap();
    write_two_pin_fixture(tmp.path());
    write_legacy_ledger(tmp.path(), vec![yarn_classic_edit()]).await;
    let ledger_before = std::fs::read(ledger_path(tmp.path())).unwrap();

    let (code, envelope) = run_rollback_subprocess_online(tmp.path(), &server, &[LP_PURL]);
    assert_eq!(code, 0, "{envelope}");
    assert_eq!(envelope["status"], "success", "{envelope}");
    assert_eq!(
        envelope["hosted"]["reverted"],
        serde_json::json!([LP_PURL]),
        "only the named pin is restored: {envelope}"
    );
    assert_eq!(envelope["hosted"]["failed"], serde_json::json!([]));
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("yarn.lock")).unwrap(),
        yarn_lock_content(&format!(
            "{}\n\n{}",
            yarn_original_block(),
            io_redirected_block()
        )),
        "the out-of-scope pin must stay hosted"
    );
    assert_eq!(
        std::fs::read(ledger_path(tmp.path())).unwrap(),
        ledger_before,
        "a pre-v5 ledger is kept while a hosted pin remains"
    );

    let code = rollback_online(tmp.path(), &server).await;
    assert_eq!(code, 0, "the unscoped follow-up restores the rest");
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("yarn.lock")).unwrap(),
        yarn_lock_content(&format!(
            "{}\n\n{}",
            yarn_original_block(),
            yarn_upstream_block("is-odd", "3.0.1")
        ))
    );
    assert!(
        !ledger_path(tmp.path()).exists(),
        "with no hosted pin left the pre-v5 ledger is retired"
    );
}

/// A ledger written by an OLDER (or newer) socket-patch may carry edits of
/// kinds this release never replays — an unknown kind, a gem source edit.
/// v5 never replays a ledger at all: the yarn pin is restored from the
/// registry (not from the ledger's recorded original), the files the
/// ledger's other edits name are left byte-identical, and the ledger is
/// retired once no hosted pin remains. Scoped and unscoped alike.
#[tokio::test]
#[serial]
async fn legacy_ledger_edits_of_any_kind_are_never_replayed() {
    for scoped in [true, false] {
        let server = MockServer::start().await;
        mock_yarn_registry(&server, "left-pad", "1.2.3").await;
        let tmp = tempfile::tempdir().unwrap();
        write_single_npm_fixture(tmp.path());
        let future_lock = format!("left-pad@1.2.3 {LP_HOSTED_URL}\n");
        std::fs::write(tmp.path().join("future.lock"), &future_lock).unwrap();
        let gem_lock = gemfile_lock_content(GEM_PATCH_REMOTE);
        std::fs::write(tmp.path().join("Gemfile.lock"), &gem_lock).unwrap();
        write_legacy_ledger(
            tmp.path(),
            vec![
                // Its recorded original disagrees with the registry: a
                // replay would write it, the restore must not.
                FileEdit {
                    original: Some(Value::String(yarn_block(
                        "https://registry.yarnpkg.com/left-pad/-/left-pad-1.2.3.tgz#bbbb",
                        "sha512-LEDGERledger==",
                    ))),
                    ..yarn_classic_edit()
                },
                gem_source_edit(),
                future_lock_edit(),
            ],
        )
        .await;

        let targets: &[&str] = if scoped { &[LP_PURL] } else { &[] };
        let (code, envelope) = run_rollback_subprocess_online(tmp.path(), &server, targets);
        assert_eq!(code, 0, "scoped={scoped}: {envelope}");
        assert_eq!(
            envelope["hosted"]["reverted"],
            serde_json::json!([LP_PURL]),
            "scoped={scoped}: {envelope}"
        );
        assert_eq!(
            std::fs::read_to_string(tmp.path().join("yarn.lock")).unwrap(),
            yarn_lock_content(&yarn_original_block()),
            "scoped={scoped}: the entry comes back from the registry, not the ledger"
        );
        assert_eq!(
            std::fs::read_to_string(tmp.path().join("future.lock")).unwrap(),
            future_lock,
            "scoped={scoped}: an unknown-kind ledger edit is never replayed"
        );
        assert_eq!(
            std::fs::read_to_string(tmp.path().join("Gemfile.lock")).unwrap(),
            gem_lock,
            "scoped={scoped}: a ledger-only gem edit is never replayed"
        );
        assert!(
            !ledger_path(tmp.path()).exists(),
            "scoped={scoped}: the pre-v5 ledger is retired once no hosted pin remains"
        );
    }
}

// ---------------------------------------------------------------------------
// 4. a refused pin fails closed on its own
// ---------------------------------------------------------------------------

/// The registry answers for one pin and not the other: the answered pin is
/// restored, the other is REFUSED with the `git checkout` remedy
/// (`hosted.failed`, `partial_failure`, exit 1) and its block stays hosted
/// byte-for-byte. An `--offline` run refuses every pin and writes nothing.
#[tokio::test]
#[serial]
async fn a_refused_pin_fails_closed_beside_a_restored_one() {
    let server = MockServer::start().await;
    mock_yarn_registry(&server, "is-odd", "3.0.1").await;

    // Offline: both refused, nothing written.
    let tmp = tempfile::tempdir().unwrap();
    write_two_pin_fixture(tmp.path());
    let wired = std::fs::read_to_string(tmp.path().join("yarn.lock")).unwrap();
    let (code, envelope) = run_rollback_subprocess(tmp.path(), &[]);
    assert_eq!(code, 1, "{envelope}");
    assert_eq!(envelope["status"], "partial_failure", "{envelope}");
    assert_eq!(envelope["hosted"]["reverted"], serde_json::json!([]));
    let failed: Vec<&str> = envelope["hosted"]["failed"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["purl"].as_str().unwrap())
        .collect();
    assert_eq!(failed, [IO_PURL, LP_PURL], "{envelope}");
    assert!(
        envelope["hosted"]["failed"][0]["error"]
            .as_str()
            .is_some_and(|e| e.contains("this run is offline")
                && e.contains(
                    "restore it from version control instead (`git checkout -- yarn.lock`)"
                )),
        "{envelope}"
    );
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("yarn.lock")).unwrap(),
        wired,
        "an offline run writes nothing"
    );

    // Online, left-pad unanswered (404): is-odd restores on its own.
    let (code, envelope) = run_rollback_subprocess_online(tmp.path(), &server, &[]);
    assert_eq!(code, 1, "{envelope}");
    assert_eq!(envelope["status"], "partial_failure", "{envelope}");
    assert_eq!(envelope["hosted"]["reverted"], serde_json::json!([IO_PURL]));
    assert_eq!(
        envelope["hosted"]["failed"][0]["purl"], LP_PURL,
        "{envelope}"
    );
    assert_eq!(envelope["hosted"]["unsupported"], serde_json::json!([]));
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("yarn.lock")).unwrap(),
        yarn_lock_content(&format!(
            "{}\n\n{}",
            yarn_redirected_block(),
            yarn_upstream_block("is-odd", "3.0.1")
        )),
        "the refused pin stays hosted, the other is restored"
    );
}

/// #363: an older release rewired a git-pattern yarn-classic block to the
/// hosted tarball. yarn 1 fetches that pattern with git, from `resolved`, so
/// restoring a registry tarball there still fails every install. The pin is
/// refused with the `git checkout` remedy and the lock left untouched,
/// instead of a "success" that installs nothing; a registry pin beside it
/// still restores.
#[tokio::test]
#[serial]
async fn a_git_pattern_hosted_pin_is_refused_not_restored_to_the_registry() {
    let server = MockServer::start().await;
    mock_yarn_registry(&server, "left-pad", "1.2.3").await;
    mock_yarn_registry(&server, "is-odd", "3.0.1").await;
    let tmp = tempfile::tempdir().unwrap();
    let git_wired = format!(
        "\"left-pad@git+https://github.com/stevemao/left-pad.git#v1.2.3\":\n  \
         version \"1.2.3\"\n  resolved \"{LP_HOSTED_URL}\"\n  integrity sha512-PATCHEDpatched=="
    );
    std::fs::write(
        tmp.path().join("yarn.lock"),
        yarn_lock_content(&format!("{git_wired}\n\n{}", io_redirected_block())),
    )
    .unwrap();

    let (code, envelope) = run_rollback_subprocess_online(tmp.path(), &server, &[]);
    assert_eq!(code, 1, "{envelope}");
    assert_eq!(envelope["status"], "partial_failure", "{envelope}");
    assert_eq!(envelope["hosted"]["reverted"], serde_json::json!([IO_PURL]));
    // Discovery already refuses to attribute the git-wired entry, so the
    // pin fails closed as contested wiring before any restore is planned.
    assert_eq!(
        envelope["hosted"]["failed"].as_array().map(Vec::len),
        Some(1),
        "{envelope}"
    );
    assert!(
        envelope["hosted"]["failed"][0]["error"]
            .as_str()
            .is_some_and(|e| e.contains("installs from git")
                && e.contains("`git checkout -- yarn.lock`")),
        "{envelope}"
    );
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("yarn.lock")).unwrap(),
        yarn_lock_content(&format!(
            "{git_wired}\n\n{}",
            yarn_upstream_block("is-odd", "3.0.1")
        )),
        "the git block is left as it was; the registry pin is restored"
    );
}

// ---------------------------------------------------------------------------
// 5. manifest-less hosted-only project vs. the truly-empty project
// ---------------------------------------------------------------------------

/// A hosted-only project (a wired lock, NO manifest, NO ledger) rolls back
/// fine — a missing manifest is not fatal when the lockfiles pin hosted
/// patches. A project whose only state is a stale pre-v5 ledger retires it
/// and exits 0. A TRULY empty directory keeps the legacy "Manifest not
/// found" exit-1 error.
#[tokio::test]
#[serial]
async fn hosted_only_project_without_manifest() {
    // Hosted-only: restores and exits 0.
    let server = MockServer::start().await;
    mock_yarn_registry(&server, "left-pad", "1.2.3").await;
    let tmp = tempfile::tempdir().unwrap();
    write_single_npm_fixture(tmp.path());
    assert!(!tmp.path().join(".socket").exists());

    let code = rollback_online(tmp.path(), &server).await;
    assert_eq!(
        code, 0,
        "a manifest-less hosted-only project must roll back fine"
    );
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("yarn.lock")).unwrap(),
        yarn_lock_content(&yarn_original_block()),
        "the hosted pin must be restored to its upstream entry"
    );
    assert!(
        !tmp.path().join(".socket").exists(),
        "no manifest or ledger may be materialized, and apply.lock is removed"
    );

    // Only a stale pre-v5 ledger: retired, exit 0.
    let stale = tempfile::tempdir().unwrap();
    write_legacy_ledger(stale.path(), vec![yarn_classic_edit()]).await;
    let (code, envelope) = run_rollback_subprocess(stale.path(), &[]);
    assert_eq!(code, 0, "{envelope}");
    assert_eq!(envelope["status"], "success", "{envelope}");
    assert_eq!(envelope["legacyRedirectLedgerRemoved"], true, "{envelope}");
    assert!(!ledger_path(stale.path()).exists());

    // Truly empty: all three stores absent keeps the legacy error.
    let empty = tempfile::tempdir().unwrap();
    let (code, envelope) = run_rollback_subprocess(empty.path(), &[]);
    assert_eq!(
        code, 1,
        "a truly-empty project must keep exit 1: {envelope}"
    );
    assert_eq!(envelope["status"], "error", "{envelope}");
    assert!(
        envelope["error"]
            .as_str()
            .unwrap_or_default()
            .contains("Manifest not found"),
        "the legacy error message must be preserved: {envelope}"
    );
}

// ---------------------------------------------------------------------------
// 6. --preserve-state still restores hosted pins
// ---------------------------------------------------------------------------

/// Hosted pins have no preservable local state: a `--preserve-state` run
/// still restores the upstream entry, surfacing the
/// `hosted_state_not_preservable` warning; manifest cleanup and GC stay
/// skipped (`manifest.preserved`, `gc.skipped`).
#[tokio::test]
#[serial]
async fn preserve_state_still_unwinds_hosted() {
    let server = MockServer::start().await;
    mock_yarn_registry(&server, "left-pad", "1.2.3").await;
    let tmp = tempfile::tempdir().unwrap();
    write_single_npm_fixture(tmp.path());

    let (code, envelope) =
        run_rollback_subprocess_online(tmp.path(), &server, &["--preserve-state"]);
    assert_eq!(
        code, 0,
        "preserve-state hosted rollback exits 0: {envelope}"
    );
    assert_eq!(envelope["status"], "success", "{envelope}");
    assert_eq!(
        envelope["hosted"]["reverted"],
        serde_json::json!([LP_PURL]),
        "the pin must still be restored under --preserve-state: {envelope}"
    );
    assert!(
        warning_codes(&envelope).contains(&"hosted_state_not_preservable".to_string()),
        "restoring hosted pins under --preserve-state must be surfaced: {envelope}"
    );
    assert_eq!(
        envelope["manifest"]["preserved"], true,
        "manifest cleanup must be skipped: {envelope}"
    );
    assert_eq!(
        envelope["gc"]["skipped"], true,
        "GC must be skipped under --preserve-state: {envelope}"
    );

    assert_eq!(
        std::fs::read_to_string(tmp.path().join("yarn.lock")).unwrap(),
        yarn_lock_content(&yarn_original_block()),
        "the hosted pin must be restored on disk"
    );
    assert!(
        !tmp.path().join(".socket").exists(),
        "with nothing preservable, no .socket/ is left behind"
    );
}

/// Manifest-less VEX across the hosted npm round trip. Before the rollback
/// a checkout of the committed state (package.json, the redirected lock;
/// nothing installable — the host is fictional — so the lock pin is the
/// basis; no ledger exists) attests `(redirected)` from lockfile discovery +
/// the patch API. After the bare rollback the restored lock names no patch:
/// nothing attests, online or `--no-verify`, and the patch API is never
/// asked.
#[tokio::test]
#[serial]
async fn npm_hosted_round_trip_manifest_less_vex() {
    use vex_e2e_common::{
        assert_absent, assert_attested, patch_view, run_vex, Marker, PatchApi, VexRun,
    };
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    mock_view(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    write_npm_project(tmp.path());
    assert_eq!(
        scan_run(hosted_scan_args(tmp.path(), server.uri())).await,
        0,
        "scan --mode hosted"
    );

    let checkout = |name: &str| {
        let dir = tmp.path().join(name);
        std::fs::create_dir_all(&dir).unwrap();
        for f in ["package.json", "package-lock.json"] {
            std::fs::copy(tmp.path().join(f), dir.join(f)).unwrap();
        }
        if tmp.path().join(".socket/vendor").is_dir() {
            std::fs::create_dir_all(dir.join(".socket/vendor")).unwrap();
            for entry in std::fs::read_dir(tmp.path().join(".socket/vendor")).unwrap() {
                let entry = entry.unwrap();
                if entry.file_type().unwrap().is_file() {
                    std::fs::copy(
                        entry.path(),
                        dir.join(".socket/vendor").join(entry.file_name()),
                    )
                    .unwrap();
                }
            }
        }
        dir
    };
    let wired = checkout("wired");
    assert!(
        !wired.join(".socket").exists(),
        "hosted mode commits no .socket/ state"
    );

    mock_npm_registry(&server).await;
    let code = rollback_online(tmp.path(), &server).await;
    assert_eq!(code, 0, "bare rollback");
    let reverted = checkout("reverted");

    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let api = PatchApi::start(vec![(
                    UUID.to_string(),
                    patch_view(
                        UUID,
                        PURL,
                        &[("package/index.js", &"b".repeat(64))],
                        &[(GHSA, &["CVE-2024-9"])],
                    ),
                )]);
                let online = || VexRun {
                    patch_server_url: Some("http://patch.test".to_string()),
                    ..VexRun::online(&api)
                };
                let out = run_vex(&vex_e2e_common::binary(), &wired, &online());
                assert_eq!(out.code, Some(0), "wired:\n{out}");
                assert_attested(
                    out.doc(),
                    PURL,
                    UUID,
                    Marker::Redirected,
                    &[(GHSA, &["CVE-2024-9"])],
                );

                let before = api.request_count();
                for no_verify in [false, true] {
                    let out = run_vex(
                        &vex_e2e_common::binary(),
                        &reverted,
                        &VexRun {
                            no_verify,
                            ..online()
                        },
                    );
                    assert_ne!(out.code, Some(0), "rolled back:\n{out}");
                    assert_absent(out.doc.as_ref(), PURL);
                }
                assert_eq!(api.request_count(), before, "{:?}", api.requests());
            })
            .join()
            .expect("manifest-less VEX cells panicked");
    });
}

// ---------------------------------------------------------------------------
// Agent record superseded by a hosted pin (#933)
// ---------------------------------------------------------------------------
//
// An agent-mode apply recorded patch A in `.socket/manifest.json`; a later
// hosted scan pinned the same `name@version` to a SUPERSEDING patch (the
// fixture's UUID, B) and left record A in place. After a reinstall the tree
// holds B's bytes, which are neither of A's sides, so restoring A in place
// would fail "modified after patching". The hosted leg owns that package
// now: rollback and remove restore the lock, drop the superseded record
// with a warning, and exit 0.

const SUPERSEDED_UUID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const ORIGINAL_INDEX: &[u8] = b"module.exports = 'original';\n";
const A_PATCHED_INDEX: &[u8] = b"module.exports = 'patched by A';\n";
const B_PATCHED_INDEX: &[u8] = b"module.exports = 'patched by B';\n";

/// The npm project wired by a real hosted scan to patch B, with agent
/// record A left in the manifest (its before-blob cached, as agent apply
/// leaves it) and `installed` as the installed `index.js`. Returns the
/// pristine lock bytes.
async fn write_superseded_agent_fixture(
    root: &Path,
    server: &MockServer,
    installed: &[u8],
) -> String {
    let pristine = write_npm_project(root);
    let pkg = root.join("node_modules").join(NAME);
    std::fs::write(pkg.join("index.js"), A_PATCHED_INDEX).unwrap();

    let before = socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes(ORIGINAL_INDEX);
    let after = socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes(A_PATCHED_INDEX);
    let mut record = patch_record(SUPERSEDED_UUID, GHSA);
    record.files.clear();
    record.files.insert(
        "package/index.js".to_string(),
        PatchFileInfo {
            before_hash: before.clone(),
            after_hash: after,
        },
    );
    let mut manifest = socket_patch_core::manifest::schema::PatchManifest::new();
    manifest.patches.insert(PURL.to_string(), record);
    std::fs::create_dir_all(root.join(".socket/blobs")).unwrap();
    std::fs::write(root.join(".socket/blobs").join(&before), ORIGINAL_INDEX).unwrap();
    std::fs::write(
        root.join(".socket/manifest.json"),
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();

    mock_discovery(server).await;
    mock_reference(server).await;
    mock_view(server).await;
    let code = scan_run(hosted_scan_args(root, server.uri())).await;
    assert_eq!(code, 0, "the superseding hosted scan should succeed");
    let wired = std::fs::read_to_string(root.join("package-lock.json")).unwrap();
    assert!(
        wired.contains(HOSTED_URL),
        "the lock must pin the superseding hosted patch; got:\n{wired}"
    );
    let manifest = std::fs::read_to_string(root.join(".socket/manifest.json")).unwrap();
    assert!(
        manifest.contains(SUPERSEDED_UUID),
        "the hosted scan leaves the superseded agent record A in place; got:\n{manifest}"
    );

    // What the next `npm ci` (or no reinstall at all) leaves installed.
    std::fs::write(pkg.join("index.js"), installed).unwrap();
    mock_npm_registry(server).await;
    pristine
}

fn manifest_patch_keys(root: &Path) -> Vec<String> {
    let raw = std::fs::read_to_string(root.join(".socket/manifest.json")).unwrap();
    let v: Value = serde_json::from_str(&raw).unwrap();
    v["patches"]
        .as_object()
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default()
}

/// Run `remove <identifier> --json --yes` online as a scrubbed subprocess.
fn run_remove_subprocess_online(cwd: &Path, server: &MockServer, identifier: &str) -> (i32, Value) {
    let out = scrubbed_cli()
        .env(
            "SOCKET_NPM_REGISTRY",
            format!("{}/npm-registry", server.uri()),
        )
        .args([
            "remove",
            identifier,
            "--json",
            "--yes",
            "--patch-server-url",
            "http://patch.test",
            "--cwd",
            cwd.to_str().unwrap(),
        ])
        .output()
        .expect("run socket-patch");
    let envelope: Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "remove --json stdout must be a pure JSON envelope: {e}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    });
    (out.status.code().unwrap_or(-1), envelope)
}

/// #933: after the reinstall the tree holds B's bytes. Rollback restores
/// the lock, drops record A with `rollback_record_superseded`, leaves the
/// installed bytes for the reinstall to replace, and exits 0 — twice.
#[tokio::test]
#[serial]
async fn rollback_drops_an_agent_record_superseded_by_a_hosted_pin() {
    let server = MockServer::start().await;
    let tmp = tempfile::tempdir().unwrap();
    let pristine = write_superseded_agent_fixture(tmp.path(), &server, B_PATCHED_INDEX).await;

    let (code, envelope) = run_rollback_subprocess_online(tmp.path(), &server, &[]);
    assert_eq!(
        code, 0,
        "rollback must not fail on the superseded record:\n{envelope:#}"
    );
    assert!(
        warning_codes(&envelope).contains(&"rollback_record_superseded".to_string()),
        "the superseded record is named in warnings[]:\n{envelope:#}"
    );
    let restored = std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap();
    assert_eq!(restored, pristine, "the hosted leg restores the lock");
    assert!(
        manifest_patch_keys(tmp.path()).is_empty(),
        "the superseded record leaves the manifest"
    );
    let installed =
        std::fs::read(tmp.path().join("node_modules").join(NAME).join("index.js")).unwrap();
    assert_eq!(
        installed, B_PATCHED_INDEX,
        "B's installed bytes are the reinstall's to replace, never overwritten with A's original"
    );

    let (code, envelope) = run_rollback_subprocess_online(tmp.path(), &server, &[]);
    assert_eq!(code, 0, "a re-run is a clean no-op:\n{envelope:#}");
}

/// #933 without a reinstall: the tree still holds A's patched bytes, so
/// the agent leg restores them in place as before.
#[tokio::test]
#[serial]
async fn rollback_restores_a_superseded_agent_record_still_installed() {
    let server = MockServer::start().await;
    let tmp = tempfile::tempdir().unwrap();
    let pristine = write_superseded_agent_fixture(tmp.path(), &server, A_PATCHED_INDEX).await;

    let (code, envelope) = run_rollback_subprocess_online(tmp.path(), &server, &[]);
    assert_eq!(code, 0, "{envelope:#}");
    assert!(
        !warning_codes(&envelope).contains(&"rollback_record_superseded".to_string()),
        "A's bytes were restored in place, nothing was left to the reinstall:\n{envelope:#}"
    );
    let restored = std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap();
    assert_eq!(restored, pristine);
    assert!(manifest_patch_keys(tmp.path()).is_empty());
    let installed =
        std::fs::read(tmp.path().join("node_modules").join(NAME).join("index.js")).unwrap();
    assert_eq!(installed, ORIGINAL_INDEX);
}

/// #933: `remove <purl>` un-hosts the package instead of aborting on the
/// superseded agent record before the hosted leg runs.
#[tokio::test]
#[serial]
async fn remove_unhosts_a_package_whose_agent_record_is_superseded() {
    let server = MockServer::start().await;
    let tmp = tempfile::tempdir().unwrap();
    let pristine = write_superseded_agent_fixture(tmp.path(), &server, B_PATCHED_INDEX).await;

    let (code, envelope) = run_remove_subprocess_online(tmp.path(), &server, PURL);
    assert_eq!(
        code, 0,
        "remove must not refuse the superseded record:\n{envelope:#}"
    );
    let restored = std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap();
    assert_eq!(
        restored, pristine,
        "remove must not leave the hosted pin live"
    );
    assert!(manifest_patch_keys(tmp.path()).is_empty());
    assert!(
        envelope.to_string().contains("rollback_record_superseded"),
        "the superseded record is reported:\n{envelope:#}"
    );
}
