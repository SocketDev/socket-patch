//! In-process CLI test for `scan --mode hosted` on a Poetry project: mocks the
//! API (discovery + reference + view) via wiremock, lays down a native
//! `poetry.lock` (the committed Poetry 2.4.3 fixture) with NO installed
//! package — the lock-only fresh-checkout / CI shape — and asserts the lock is
//! repointed at the hosted wheel, the redirect ledger is written, the same-run
//! `--vex` attests the redirect, a re-scan is idempotent, and `rollback`
//! restores every byte. The rewriter bytes themselves are pinned by the core
//! `poetry_hosted` tests; this covers the CLI wiring around them.

use std::path::Path;

use serial_test::serial;
use socket_patch_cli::args::GlobalArgs;
use socket_patch_cli::commands::rollback::{self, RollbackArgs};
use socket_patch_cli::commands::scan::{run, ScanArgs};
use socket_patch_cli::commands::vex::VexEmbedArgs;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";
/// Discovery names the base purl (the lockfile supplement's spelling)…
const PURL: &str = "pkg:pypi/urllib3@1.26.18";
/// …while the patch record carries the API's artifact-qualified purl, which
/// is what the redirect ledger is keyed by.
const RECORD_PURL: &str = "pkg:pypi/urllib3@1.26.18?artifact_id=py2-py3-none-any-whl";
const UUID: &str = "e828efa5-5c6d-43f3-9909-03f5ac232b98";
const HOSTED_URL: &str = "http://patch.test/patch/pypi/urllib3/1.26.18/22222222-2222-4222-8222-222222222222/e828efa5-5c6d-43f3-9909-03f5ac232b98/urllib3-1.26.18-py2.py3-none-any.whl";
const GHSA: &str = "GHSA-gm62-xv2j-4w53";

const LOCK: &str = include_str!("../../socket-patch-core/tests/fixtures/poetry/2.4.3/poetry.lock");
/// Poetry 1.2.2's native lock (lock-version 1.1, populated `[metadata.files]`).
const LOCK_1_1: &str =
    include_str!("../../socket-patch-core/tests/fixtures/poetry/1.2.2/poetry.lock");
const PYPROJECT: &str =
    include_str!("../../socket-patch-core/tests/fixtures/poetry/2.4.3/pyproject.toml");

fn sha256() -> String {
    "c".repeat(64)
}

fn global(cwd: &Path, api_url: String) -> GlobalArgs {
    GlobalArgs {
        cwd: cwd.to_path_buf(),
        org: Some(ORG.to_string()),
        api_token: Some("fake".to_string()),
        api_url: Some(api_url),
        json: true,
        yes: true,
        ..GlobalArgs::default()
    }
}

fn hosted_args(cwd: &Path, api_url: String, vex: Option<&Path>) -> ScanArgs {
    ScanArgs {
        paths: Vec::new(),
        common: global(cwd, api_url),
        batch_size: 100,
        apply: false,
        prune: false,
        sync: false,
        vendor: false,
        detached: false,
        redirect: true,
        mode: None,
        all_releases: false,
        vex: VexEmbedArgs {
            vex: vex.map(Path::to_path_buf),
            ..Default::default()
        },
    }
}

async fn mock_api(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": PURL,
                "patches": [{
                    "uuid": UUID, "purl": RECORD_PURL, "tier": "free",
                    "cveIds": ["CVE-2025-66418"], "ghsaIds": [GHSA], "severity": "HIGH",
                    "title": "poetry redirect fixture"
                }]
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(format!("^/v0/orgs/{ORG}/patches/by-package/.+$")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [{
                "uuid": UUID, "purl": RECORD_PURL,
                "publishedAt": "2026-07-29T20:20:47Z",
                "description": "x", "license": "MIT", "tier": "free",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;
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
                        "integrity": { "sha256": sha256() }
                    }],
                    "registryOverride": null
                }
            }
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": UUID,
            "purl": RECORD_PURL,
            "publishedAt": "2026-07-29T20:20:47Z",
            "files": {
                "urllib3/response.py": {
                    "beforeHash": "a".repeat(64),
                    "afterHash": "b".repeat(64),
                }
            },
            "vulnerabilities": {
                GHSA: {
                    "cves": ["CVE-2025-66418"],
                    "summary": "poetry redirect vex fixture",
                    "severity": "HIGH",
                    "description": "d"
                }
            },
            "description": "x", "license": "MIT", "tier": "free"
        })))
        .mount(server)
        .await;
}

/// A Poetry project with nothing installed: the lock is the only source of
/// the dependency. An EMPTY in-project venv keeps the crawl hermetic (without
/// it the project-marker fallback would walk this machine's global
/// interpreters).
fn write_project(root: &Path) {
    std::fs::write(root.join("pyproject.toml"), PYPROJECT).unwrap();
    std::fs::write(root.join("poetry.lock"), LOCK).unwrap();
    let site = if cfg!(windows) {
        root.join(".venv").join("Lib").join("site-packages")
    } else {
        root.join(".venv").join("lib").join("python3.12").join("site-packages")
    };
    std::fs::create_dir_all(site).unwrap();
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap()
}

#[tokio::test]
#[serial]
async fn lock_only_poetry_project_redirects_attests_rescans_and_rolls_back() {
    let server = MockServer::start().await;
    mock_api(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    let lock_path = tmp.path().join("poetry.lock");
    let vex_path = tmp.path().join("out.vex.json");

    // 1. Hosted redirect with same-run --vex on the lock-only checkout.
    let code = run(hosted_args(tmp.path(), server.uri(), Some(&vex_path))).await;
    assert_eq!(code, 0, "hosted redirect + same-run vex must succeed");
    let redirected = read(&lock_path);
    assert!(redirected.contains(HOSTED_URL), "{redirected}");
    assert!(
        redirected.contains(&format!("hash = \"sha256:{}\"", sha256())),
        "{redirected}"
    );
    assert!(redirected.contains("type = \"url\""), "{redirected}");
    assert_eq!(read(&tmp.path().join("pyproject.toml")), PYPROJECT, "pyproject untouched");
    let ledger: serde_json::Value =
        serde_json::from_str(&read(&tmp.path().join(".socket/vendor/redirect-state.json")))
            .unwrap();
    assert!(
        ledger["records"][RECORD_PURL].is_object(),
        "ledger keyed by the artifact-qualified purl: {ledger}"
    );
    assert_eq!(
        ledger["edits"][0]["kind"].as_str(),
        Some("redirect_poetry_lock_package"),
        "{ledger}"
    );
    // The redirect is attested from the ledger (assume_applied) even though
    // the base purl the run confirmed differs from the record's qualified
    // purl only by its `?artifact_id=` qualifier.
    let vex: serde_json::Value = serde_json::from_str(&read(&vex_path)).unwrap();
    let statements = vex["statements"].as_array().expect("statements");
    assert_eq!(statements.len(), 1, "{vex}");
    assert_eq!(
        statements[0]["vulnerability"]["name"].as_str(),
        Some(GHSA),
        "{vex}"
    );

    // 2. Idempotent re-scan: no further edits, lock byte-identical.
    let code = run(hosted_args(tmp.path(), server.uri(), None)).await;
    assert_eq!(code, 0);
    assert_eq!(read(&lock_path), redirected, "re-scan must not touch the lock");

    // 3. rollback unwinds the redirect and drops the record.
    let code = rollback::run(RollbackArgs {
        targets: Vec::new(),
        common: global(tmp.path(), server.uri()),
        one_off: false,
        preserve_state: false,
    })
    .await;
    assert_eq!(code, 0, "rollback must succeed");
    assert_eq!(read(&lock_path), LOCK, "rollback must restore the pristine lock byte for byte");
    let ledger_path = tmp.path().join(".socket/vendor/redirect-state.json");
    if ledger_path.exists() {
        let ledger: serde_json::Value = serde_json::from_str(&read(&ledger_path)).unwrap();
        assert!(
            ledger["records"]
                .as_object()
                .is_none_or(|records| records.is_empty()),
            "no redirect record may survive rollback: {ledger}"
        );
    }
}

/// What `poetry lock --no-update` on Poetry 1.1 / 1.2 does to a redirected
/// lock-1.1 unit: keeps `[package.source]`, drops the inserted package-level
/// `files` line, and re-lays the `[metadata.files]` entry from the CLI's
/// inline table into Poetry's multi-line array.
fn simulate_poetry_1x_relock(lock: &str) -> String {
    let mut out = String::new();
    for line in lock.lines() {
        if line.starts_with("files = [{ file = ") {
            continue;
        }
        if let Some(rest) = line.strip_prefix("urllib3 = [{ ") {
            let inner = rest.trim_end_matches(" }]");
            out.push_str("urllib3 = [\n    {");
            out.push_str(inner);
            out.push_str("},\n]\n");
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// Relock → re-scan → rollback must still land on the pristine lock. The
/// re-scan REBASES the ledger's edits (pristine → freshly written) instead of
/// appending edits recorded against the relocked text, whose older links
/// would match nothing and make rollback (and remove) refuse forever.
#[tokio::test]
#[serial]
async fn relock_then_rescan_keeps_rollback_invertible() {
    let server = MockServer::start().await;
    mock_api(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    let lock_path = tmp.path().join("poetry.lock");
    std::fs::write(&lock_path, LOCK_1_1).unwrap();

    assert_eq!(run(hosted_args(tmp.path(), server.uri(), None)).await, 0);
    let redirected = read(&lock_path);
    let ledger_path = tmp.path().join(".socket/vendor/redirect-state.json");
    let ledger: serde_json::Value = serde_json::from_str(&read(&ledger_path)).unwrap();
    assert_eq!(ledger["edits"].as_array().unwrap().len(), 2, "package + metadata fragments");

    let relocked = simulate_poetry_1x_relock(&redirected);
    assert_ne!(relocked, redirected);
    assert!(relocked.contains(HOSTED_URL), "relock keeps the source");
    std::fs::write(&lock_path, &relocked).unwrap();

    // Re-scan: the unit lost its `files` line, so the rewriter writes again.
    assert_eq!(run(hosted_args(tmp.path(), server.uri(), None)).await, 0);
    let rescanned = read(&lock_path);
    assert_ne!(rescanned, relocked, "the re-scan must restore the package files entry");
    let ledger: serde_json::Value = serde_json::from_str(&read(&ledger_path)).unwrap();
    let edits = ledger["edits"].as_array().unwrap();
    assert_eq!(edits.len(), 2, "rebased, not appended: {ledger}");
    for edit in edits {
        let original = edit["original"].as_str().unwrap();
        assert!(!original.contains(HOSTED_URL), "originals stay pristine: {original}");
        let new = edit["new"].as_str().unwrap();
        assert!(rescanned.contains(new), "new fragments describe the current lock");
    }

    let code = rollback::run(RollbackArgs {
        targets: Vec::new(),
        common: global(tmp.path(), server.uri()),
        one_off: false,
        preserve_state: false,
    })
    .await;
    assert_eq!(code, 0, "rollback after relock + re-scan must succeed");
    assert_eq!(read(&lock_path), LOCK_1_1, "pristine lock restored byte for byte");
}
