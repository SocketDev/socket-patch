//! In-process rollback tests for HOSTED-mode state (the redirect ledger).
//!
//! The genuine-wiring fixtures run the REAL hosted flow first — in-process
//! `scan --mode hosted` over an npm package-lock project (the
//! `in_process_redirect.rs` fixture, wiremock API) and in-process
//! `get <uuid> --mode hosted` over a pip requirements.txt project (the
//! `in_process_get_hosted_ecosystems.rs` fixture) — then roll back and
//! byte-compare the lockfiles against their pristine snapshots. The
//! fail-closed / replay fixtures hand-write the redirect ledger through the
//! exported `socket_patch_core::patch::redirect` types (real schema, real
//! edit kinds) with matching file fragments on disk.
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

// ── the hand-written two-record ledger fixture ──────────────────────────────
const LP_PURL: &str = "pkg:npm/left-pad@1.2.3";
const LP_UUID: &str = "55555555-5555-4555-8555-555555555555";
const LP_HOSTED_URL: &str = "http://patch.test/patch/npm/left-pad/1.2.3/66666666-6666-4666-8666-666666666666/55555555-5555-4555-8555-555555555555/left-pad-1.2.3.tgz";
const GEM_PURL: &str = "pkg:gem/rex@1.0.0";
const GEM_UUID: &str = "77777777-7777-4777-8777-777777777777";
const GEM_UPSTREAM_REMOTE: &str = "https://rubygems.org/";
const GEM_PATCH_REMOTE: &str = "http://patch.test/gems/t0k3nt0k3n/";

fn hosted_scan_args(cwd: &Path, api_url: String) -> ScanArgs {
    ScanArgs {
        paths: Vec::new(),
        common: socket_patch_cli::args::GlobalArgs {
            cwd: cwd.to_path_buf(),
            org: Some(ORG.to_string()),
            api_token: Some("fake".to_string()),
            api_url: Some(api_url),
            json: true,
            yes: true,
            ..socket_patch_cli::args::GlobalArgs::default()
        },
        batch_size: 100,
        apply: false,
        prune: false,
        sync: false,
        vendor: false,
        detached: false,
        redirect: false,
        mode: Some(ScanMode::Hosted),
        all_releases: false,
        vex: Default::default(),
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
            ..socket_patch_cli::args::GlobalArgs::default()
        },
        one_off: false,
        preserve_state,
    };
    let code = rollback_run(args).await;
    // `apply_env_toggles` mirrored `--offline` into the PROCESS env and
    // nothing unsets it; scrub so a later in-process `scan`/`get` in this
    // `#[serial]` process isn't silently forced offline.
    std::env::remove_var("SOCKET_OFFLINE");
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
    cmd
}

/// Run `rollback --json --yes --offline [extra]` as a scrubbed subprocess
/// and parse the envelope back (in-process runs print to the real stdout,
/// which a hosting test can't read). Returns (exit code, envelope).
fn run_rollback_subprocess(cwd: &Path, extra: &[&str]) -> (i32, Value) {
    let out = scrubbed_cli()
        .args([
            "rollback",
            "--json",
            "--yes",
            "--offline",
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

/// A full camelCase patch record for hand-written ledgers (the same shape
/// the hosted flow persists from `view/{uuid}`).
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

/// Serialize a hand-written ledger through the real core writer (real
/// schema: version, mode "hosted", edits[FileEdit], records{purl: record}).
async fn write_hosted_ledger(root: &Path, records: Vec<(&str, PatchRecord)>, edits: Vec<FileEdit>) {
    let mut state = RedirectState::new();
    state.edits = edits;
    for (purl, record) in records {
        state.records.insert(purl.to_string(), record);
    }
    save_redirect_state(root, &state)
        .await
        .expect("write redirect ledger");
}

// ── yarn-classic fragments for the hand-written npm record ─────────────────
// `redirect_yarn_classic_entry` is one of the text kinds the per-purl npm
// revert claims by `<name>@<version>` key; original/new record whole blocks,
// exactly as the real writer does.

fn yarn_block(resolved: &str, integrity: &str) -> String {
    format!(
        "left-pad@1.2.3:\n  version \"1.2.3\"\n  resolved \"{resolved}\"\n  integrity {integrity}"
    )
}

fn yarn_original_block() -> String {
    yarn_block(
        "https://registry.yarnpkg.com/left-pad/-/left-pad-1.2.3.tgz#aaaa",
        "sha512-UPSTREAMupstream==",
    )
}

fn yarn_redirected_block() -> String {
    yarn_block(LP_HOSTED_URL, "sha512-PATCHEDpatched==")
}

fn yarn_lock_content(block: &str) -> String {
    format!(
        "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n\
         # yarn lockfile v1\n\n\n{block}\n"
    )
}

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

// ── gem fragments for the hand-written gem record ───────────────────────────
// `redirect_gemfile_lock_source_url` has NO per-purl revert (gem is not in
// `redirect_revert_supported`); its unwind is the whole-ledger replay's
// ReplaceFragment arm.

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

/// The two-record fixture: an npm purl with a yarn-classic text edit (owned
/// by the per-purl npm revert) and a gem purl with a Gemfile.lock edit
/// (replay-only), both with REAL redirected fragments on disk.
async fn write_two_record_fixture(root: &Path) {
    std::fs::write(
        root.join("yarn.lock"),
        yarn_lock_content(&yarn_redirected_block()),
    )
    .unwrap();
    std::fs::write(
        root.join("Gemfile.lock"),
        gemfile_lock_content(GEM_PATCH_REMOTE),
    )
    .unwrap();
    write_hosted_ledger(
        root,
        vec![
            (LP_PURL, patch_record(LP_UUID, "GHSA-lpad-aaaa-bbbb")),
            (GEM_PURL, patch_record(GEM_UUID, "GHSA-gems-cccc-dddd")),
        ],
        vec![yarn_classic_edit(), gem_source_edit()],
    )
    .await;
}

/// Single-record npm fixture (yarn-classic wiring) for the manifest-less and
/// preserve-state tests.
async fn write_single_npm_fixture(root: &Path) {
    std::fs::write(
        root.join("yarn.lock"),
        yarn_lock_content(&yarn_redirected_block()),
    )
    .unwrap();
    write_hosted_ledger(
        root,
        vec![(LP_PURL, patch_record(LP_UUID, "GHSA-lpad-aaaa-bbbb"))],
        vec![yarn_classic_edit()],
    )
    .await;
}

// ---------------------------------------------------------------------------
// 1. npm round trip: real scan --mode hosted wiring, then bare rollback
// ---------------------------------------------------------------------------

/// Snapshot the pristine lock → `scan --mode hosted` wires it (resolved URL
/// rewritten + ledger written) → bare in-process rollback → exit 0, lock
/// byte-identical to pristine, redirect-state.json DELETED, and no manifest
/// materialized as a side effect.
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
        ledger_path(tmp.path()).is_file(),
        "scan --mode hosted must write the redirect ledger"
    );

    let code = rollback_in_process(tmp.path(), Vec::new(), false).await;
    assert_eq!(code, 0, "bare rollback over hosted wiring should exit 0");

    let restored = std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap();
    assert_eq!(
        restored, pristine,
        "rollback must restore the lock byte-identical to the pristine snapshot"
    );
    assert!(
        !ledger_path(tmp.path()).exists(),
        "an emptied redirect ledger must be DELETED, not left as an empty file"
    );
    assert!(
        !tmp.path().join(".socket/manifest.json").exists(),
        "a hosted-only rollback must not materialize a manifest"
    );
}

/// Dry-run twin of the round trip — the review-caught regression: the
/// per-purl dry revert must claim its npm JSON edits IN MEMORY so the
/// whole-ledger replay does not refuse them as unclaimed (`group:npm`)
/// and flip a would-succeed run to partial_failure. A hosted npm dry run
/// exits 0, reports the purl as would-be-reverted, and mutates NOTHING.
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
    let ledger_before = std::fs::read(ledger_path(tmp.path())).unwrap();

    let args = RollbackArgs {
        targets: Vec::new(),
        common: socket_patch_cli::args::GlobalArgs {
            cwd: tmp.path().to_path_buf(),
            manifest_path: ".socket/manifest.json".to_string(),
            offline: true,
            json: true,
            yes: true,
            silent: true,
            dry_run: true,
            ..socket_patch_cli::args::GlobalArgs::default()
        },
        one_off: false,
        preserve_state: false,
    };
    let code = rollback_run(args).await;
    std::env::remove_var("SOCKET_OFFLINE");
    std::env::remove_var("SOCKET_DRY_RUN");
    assert_eq!(
        code, 0,
        "a hosted npm dry run must preview cleanly, never refuse its own \
         per-purl-claimed edits"
    );
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap(),
        wired,
        "dry run must not touch the lock"
    );
    assert_eq!(
        std::fs::read(ledger_path(tmp.path())).unwrap(),
        ledger_before,
        "dry run must not touch the on-disk ledger"
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

    let (code, envelope) = run_rollback_subprocess(tmp.path(), &[]);
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
        "hosted state lives in the ledger, not the manifest: {envelope}"
    );
    assert!(
        warning_codes(&envelope).contains(&"reinstall_required".to_string()),
        "unwiring must carry the stale-install warning: {envelope}"
    );

    let restored = std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap();
    assert_eq!(restored, pristine, "lock must be byte-restored");
    assert!(!ledger_path(tmp.path()).exists(), "ledger must be deleted");
}

// ---------------------------------------------------------------------------
// 2. pypi requirements.txt round trip (real hosted flow via get --mode hosted)
// ---------------------------------------------------------------------------

/// A pip project wired by the REAL hosted flow (`get <uuid> --mode hosted`,
/// the `in_process_get_hosted_ecosystems.rs` fixture — the UUID path needs
/// no installed tree), then a bare rollback: requirements.txt restored
/// byte-for-byte via the whole-ledger replay (pypi has no per-purl revert),
/// ledger deleted, exit 0.
#[tokio::test]
#[serial]
async fn pypi_requirements_hosted_round_trip() {
    const PY_UUID: &str = "a1a1a1a1-a1a1-4a1a-8a1a-a1a1a1a1a1a1";
    const PY_PURL: &str = "pkg:pypi/requests@2.31.0";
    const SHA256: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let url = format!(
        "http://patch.test/patch/pypi/requests/2.31.0/22222222-2222-4222-8222-222222222222/{PY_UUID}/requests-2.31.0-py3-none-any.whl"
    );

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{PY_UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
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
        })))
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
        one_off: false,
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
    let ledger = std::fs::read_to_string(ledger_path(tmp.path())).unwrap();
    assert!(
        ledger.contains(PY_PURL) && ledger.contains("redirect_requirements_line"),
        "the ledger must record the pypi redirect; got:\n{ledger}"
    );

    let code = rollback_in_process(tmp.path(), Vec::new(), false).await;
    assert_eq!(code, 0, "bare rollback over the pypi redirect should exit 0");

    let restored = std::fs::read_to_string(tmp.path().join("requirements.txt")).unwrap();
    assert_eq!(
        restored, pristine,
        "requirements.txt must be restored byte-for-byte"
    );
    assert!(
        !ledger_path(tmp.path()).exists(),
        "the emptied ledger must be deleted"
    );
    assert!(
        !tmp.path().join(".socket/manifest.json").exists(),
        "hosted mode never touches the manifest"
    );
}

// ---------------------------------------------------------------------------
// 3. scoped rollback of an unsupported ecosystem fails closed
// ---------------------------------------------------------------------------

/// A two-record ledger (npm + gem) scoped to ONLY the gem purl: gem has no
/// per-purl revert and the scope does not cover the full record set, so the
/// replay may not run — the run fails closed with the purl in
/// `hosted.unsupported`, exit 1, and both the ledger and every wired file
/// stay byte-identical on disk.
#[tokio::test]
#[serial]
async fn scoped_unsupported_ecosystem_fails_closed() {
    let tmp = tempfile::tempdir().unwrap();
    write_two_record_fixture(tmp.path()).await;
    let ledger_before = std::fs::read(ledger_path(tmp.path())).unwrap();
    let yarn_before = std::fs::read_to_string(tmp.path().join("yarn.lock")).unwrap();
    let gem_before = std::fs::read_to_string(tmp.path().join("Gemfile.lock")).unwrap();

    let (code, envelope) = run_rollback_subprocess(tmp.path(), &[GEM_PURL]);
    assert_eq!(
        code, 1,
        "a scoped hosted purl with no per-purl revert must fail closed: {envelope}"
    );
    assert_eq!(envelope["status"], "partial_failure", "{envelope}");
    assert_eq!(
        envelope["hosted"]["unsupported"],
        serde_json::json!([GEM_PURL]),
        "the refused purl must be reported unsupported: {envelope}"
    );
    assert_eq!(
        envelope["hosted"]["reverted"],
        serde_json::json!([]),
        "nothing may be unwound on a refused scoped run: {envelope}"
    );

    assert_eq!(
        std::fs::read(ledger_path(tmp.path())).unwrap(),
        ledger_before,
        "the ledger must stay byte-identical on a fail-closed run"
    );
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("yarn.lock")).unwrap(),
        yarn_before,
        "the out-of-scope npm wiring must be untouched"
    );
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("Gemfile.lock")).unwrap(),
        gem_before,
        "the refused gem wiring must be untouched"
    );
}

// ---------------------------------------------------------------------------
// 4. unscoped rollback replays the unsupported ecosystems
// ---------------------------------------------------------------------------

/// The same two-record ledger, unscoped: the npm purl unwinds through the
/// per-purl revert and the gem purl through the whole-ledger reverse replay
/// (its scope covers every record). Both files are byte-restored, the
/// ledger is deleted, exit 0.
#[tokio::test]
#[serial]
async fn unscoped_replays_unsupported_ecosystems() {
    let tmp = tempfile::tempdir().unwrap();
    write_two_record_fixture(tmp.path()).await;

    let code = rollback_in_process(tmp.path(), Vec::new(), false).await;
    assert_eq!(code, 0, "unscoped rollback must unwind BOTH records");

    assert_eq!(
        std::fs::read_to_string(tmp.path().join("yarn.lock")).unwrap(),
        yarn_lock_content(&yarn_original_block()),
        "the npm wiring must be unwound (per-purl revert)"
    );
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("Gemfile.lock")).unwrap(),
        gemfile_lock_content(GEM_UPSTREAM_REMOTE),
        "the gem wiring must be unwound (whole-ledger replay)"
    );
    assert!(
        !ledger_path(tmp.path()).exists(),
        "all records and edits unwound: the ledger must be deleted"
    );
}

// ---------------------------------------------------------------------------
// 5. manifest-less hosted-only project vs. the truly-empty project
// ---------------------------------------------------------------------------

/// A hosted-only project (redirect ledger + wired lock, NO manifest) rolls
/// back fine — a missing manifest is no longer fatal when a ledger holds
/// work. A TRULY empty directory keeps the legacy "Manifest not found"
/// exit-1 error.
#[tokio::test]
#[serial]
async fn hosted_only_project_without_manifest() {
    // Hosted-only: unwinds and exits 0.
    let tmp = tempfile::tempdir().unwrap();
    write_single_npm_fixture(tmp.path()).await;
    assert!(!tmp.path().join(".socket/manifest.json").exists());

    let code = rollback_in_process(tmp.path(), Vec::new(), false).await;
    assert_eq!(
        code, 0,
        "a manifest-less hosted-only project must roll back fine"
    );
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("yarn.lock")).unwrap(),
        yarn_lock_content(&yarn_original_block()),
        "the hosted wiring must be unwound"
    );
    assert!(!ledger_path(tmp.path()).exists(), "ledger must be deleted");
    assert!(
        !tmp.path().join(".socket/manifest.json").exists(),
        "no manifest may be materialized"
    );

    // Truly empty: all three stores absent keeps the legacy error.
    let empty = tempfile::tempdir().unwrap();
    let (code, envelope) = run_rollback_subprocess(empty.path(), &[]);
    assert_eq!(code, 1, "a truly-empty project must keep exit 1: {envelope}");
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
// 6. --preserve-state still unwinds hosted state
// ---------------------------------------------------------------------------

/// Hosted redirects have no preservable local state: a `--preserve-state`
/// run still unwinds the wiring and drops the ledger records, surfacing the
/// `hosted_state_not_preservable` warning; manifest cleanup and GC stay
/// skipped (`manifest.preserved`, `gc.skipped`).
#[tokio::test]
#[serial]
async fn preserve_state_still_unwinds_hosted() {
    let tmp = tempfile::tempdir().unwrap();
    write_single_npm_fixture(tmp.path()).await;

    let (code, envelope) = run_rollback_subprocess(tmp.path(), &["--preserve-state"]);
    assert_eq!(code, 0, "preserve-state hosted rollback exits 0: {envelope}");
    assert_eq!(envelope["status"], "success", "{envelope}");
    assert_eq!(
        envelope["hosted"]["reverted"],
        serde_json::json!([LP_PURL]),
        "the wiring must still be unwound under --preserve-state: {envelope}"
    );
    assert!(
        warning_codes(&envelope).contains(&"hosted_state_not_preservable".to_string()),
        "dropping hosted records under --preserve-state must be surfaced: {envelope}"
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
        "the hosted wiring must be unwound on disk"
    );
    assert!(
        !ledger_path(tmp.path()).exists(),
        "hosted ledger records are dropped with the wiring — no preservable state"
    );
}
