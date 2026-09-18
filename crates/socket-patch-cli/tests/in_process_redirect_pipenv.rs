//! In-process CLI tests for `scan --mode hosted` on Pipenv projects: mocks
//! the API (discovery + reference + view) via wiremock, lays down a native
//! `Pipfile.lock` (the committed Pipenv 2026.8.0 fixture) and drives the
//! real command wiring. Covered here (the rewriter bytes themselves are
//! pinned by the core `patch::redirect::pipenv` tests):
//!
//! * the lock-only fresh-checkout shape (nothing installed) is discovered
//!   from `Pipfile.lock` alone, repointed with a `file` reference carrying
//!   the `#sha256=` fragment and a matching `hashes` entry, attested by the
//!   same-run `--vex`, re-scanned idempotently and rolled back byte for byte;
//! * `SOCKET_PIPENV_MAJOR=11` selects the legacy `path` reference shape the
//!   installer probe would otherwise need a real Pipenv 7–11 on PATH for;
//! * a stale `Pipfile.lock` that does not pin the package no longer vetoes
//!   the sibling `requirements.txt` redirect (Bugbot HIGH on #242);
//! * a venv still holding the UPSTREAM release is reported stale and kept
//!   out of the same-run attestation.

use std::path::Path;

use serial_test::serial;
use socket_patch_cli::args::GlobalArgs;
use socket_patch_cli::commands::rollback::{self, RollbackArgs};
use socket_patch_cli::commands::scan::{run, ScanArgs};
use socket_patch_cli::commands::vex::VexEmbedArgs;
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";
/// Discovery names the base purl (the lockfile supplement's spelling)…
const PURL: &str = "pkg:pypi/urllib3@1.26.18";
/// …while the patch record carries the API's artifact-qualified purl, which
/// is what the redirect ledger is keyed by.
const RECORD_PURL: &str = "pkg:pypi/urllib3@1.26.18?artifact_id=py2-py3-none-any-whl";
const UUID: &str = "e828efa5-5c6d-43f3-9909-03f5ac232b98";
const HOSTED_URL: &str = "https://patch.socket.dev/patch/pypi/urllib3/1.26.18/22222222-2222-4222-8222-222222222222/e828efa5-5c6d-43f3-9909-03f5ac232b98/urllib3-1.26.18-py2.py3-none-any.whl";
const GHSA: &str = "GHSA-gm62-xv2j-4w53";
const MAJOR_ENV: &str = socket_patch_core::utils::pipenv::MAJOR_OVERRIDE_ENV;

const LOCK: &str =
    include_str!("../../socket-patch-core/tests/fixtures/pipenv/2026.8.0/Pipfile.lock");
const PIPFILE: &str = include_str!("../../socket-patch-core/tests/fixtures/pipenv/2026.8.0/Pipfile");

/// The upstream and patched bytes of the record's one file, so the venv
/// tests can materialize a real `Ready` (upstream) install.
const UPSTREAM: &[u8] = b"def upstream():\n    return 'vulnerable'\n";
const PATCHED: &[u8] = b"def patched():\n    return 'fixed'\n";

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
            // A Pipfile names no project, so the embedded VEX cannot detect a
            // product purl on its own (nor without a git remote): callers pass
            // `--vex-product`, as documented for Pipenv projects.
            vex_product: vex.map(|_| "pkg:pypi/pipenv-fixture@0.1.0".to_string()),
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
                    "title": "pipenv redirect fixture"
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
                    "beforeHash": compute_git_sha256_from_bytes(UPSTREAM),
                    "afterHash": compute_git_sha256_from_bytes(PATCHED),
                }
            },
            "vulnerabilities": {
                GHSA: {
                    "cves": ["CVE-2025-66418"],
                    "summary": "pipenv redirect vex fixture",
                    "severity": "HIGH",
                    "description": "d"
                }
            },
            "description": "x", "license": "MIT", "tier": "free"
        })))
        .mount(server)
        .await;
}

fn site_packages(root: &Path) -> std::path::PathBuf {
    if cfg!(windows) {
        root.join(".venv").join("Lib").join("site-packages")
    } else {
        root.join(".venv")
            .join("lib")
            .join("python3.12")
            .join("site-packages")
    }
}

/// A Pipenv project with nothing installed: the lock is the only source of
/// the dependency. An EMPTY in-project venv keeps the crawl hermetic (without
/// it the project-marker fallback would walk this machine's global
/// interpreters).
fn write_project(root: &Path) {
    std::fs::write(root.join("Pipfile"), PIPFILE).unwrap();
    std::fs::write(root.join("Pipfile.lock"), LOCK).unwrap();
    std::fs::create_dir_all(site_packages(root)).unwrap();
}

/// The same project with the UPSTREAM release installed in its venv (the
/// warm-venv shape Pipenv never reinstalls over).
fn write_project_with_upstream_install(root: &Path) {
    write_project(root);
    let site = site_packages(root);
    let dist_info = site.join("urllib3-1.26.18.dist-info");
    std::fs::create_dir_all(&dist_info).unwrap();
    std::fs::write(
        dist_info.join("METADATA"),
        "Metadata-Version: 2.1\nName: urllib3\nVersion: 1.26.18\n",
    )
    .unwrap();
    std::fs::create_dir_all(site.join("urllib3")).unwrap();
    std::fs::write(site.join("urllib3").join("response.py"), UPSTREAM).unwrap();
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap()
}

/// Pins the installer major for the duration of a test (restored on drop) so
/// the reference shape does not depend on whatever `pipenv` the machine has.
struct MajorGuard(Option<String>);

impl MajorGuard {
    fn set(major: &str) -> Self {
        let saved = std::env::var(MAJOR_ENV).ok();
        std::env::set_var(MAJOR_ENV, major);
        MajorGuard(saved)
    }
}

impl Drop for MajorGuard {
    fn drop(&mut self) {
        match &self.0 {
            Some(v) => std::env::set_var(MAJOR_ENV, v),
            None => std::env::remove_var(MAJOR_ENV),
        }
    }
}

fn urllib3_entry(lock: &str) -> serde_json::Value {
    let value: serde_json::Value = serde_json::from_str(lock).expect("lock stays JSON");
    value["default"]["urllib3"].clone()
}

async fn roll_back(cwd: &Path, api_url: String) {
    let code = rollback::run(RollbackArgs {
        targets: Vec::new(),
        common: global(cwd, api_url),
        one_off: false,
        preserve_state: false,
    })
    .await;
    assert_eq!(code, 0, "rollback must succeed");
}

#[tokio::test]
#[serial]
async fn lock_only_pipenv_project_redirects_attests_rescans_and_rolls_back() {
    let _major = MajorGuard::set("2026");
    let server = MockServer::start().await;
    mock_api(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    let lock_path = tmp.path().join("Pipfile.lock");
    let vex_path = tmp.path().join("out.vex.json");

    // 1. Hosted redirect with same-run --vex on the lock-only checkout.
    let code = run(hosted_args(tmp.path(), server.uri(), Some(&vex_path))).await;
    assert_eq!(code, 0, "hosted redirect + same-run vex must succeed");
    let redirected = read(&lock_path);
    let entry = urllib3_entry(&redirected);
    assert_eq!(
        entry["file"].as_str(),
        Some(format!("{HOSTED_URL}#sha256={}", sha256()).as_str()),
        "{redirected}"
    );
    assert_eq!(
        entry["hashes"],
        serde_json::json!([format!("sha256:{}", sha256())]),
        "{redirected}"
    );
    assert!(entry.get("version").is_none() && entry.get("index").is_none(), "{entry}");
    assert_eq!(
        entry["markers"],
        urllib3_entry(LOCK)["markers"],
        "markers are preserved"
    );
    let before: serde_json::Value = serde_json::from_str(LOCK).unwrap();
    let after: serde_json::Value = serde_json::from_str(&redirected).unwrap();
    assert_eq!(after["_meta"], before["_meta"], "the Pipfile content hash stays");
    assert_eq!(read(&tmp.path().join("Pipfile")), PIPFILE, "Pipfile untouched");
    let ledger: serde_json::Value =
        serde_json::from_str(&read(&tmp.path().join(".socket/vendor/redirect-state.json")))
            .unwrap();
    assert!(
        ledger["records"][RECORD_PURL].is_object(),
        "ledger keyed by the artifact-qualified purl: {ledger}"
    );
    assert_eq!(
        ledger["edits"][0]["kind"].as_str(),
        Some("redirect_pipenv_entry"),
        "{ledger}"
    );
    assert_eq!(
        ledger["edits"][0]["key"].as_str(),
        Some(r#"["default","urllib3"]"#),
        "{ledger}"
    );
    // Attested from the ledger (assume_applied) although the base purl the
    // run confirmed differs from the record's qualified purl.
    let vex: serde_json::Value = serde_json::from_str(&read(&vex_path)).unwrap();
    let statements = vex["statements"].as_array().expect("statements");
    assert_eq!(statements.len(), 1, "{vex}");
    assert_eq!(statements[0]["vulnerability"]["name"].as_str(), Some(GHSA), "{vex}");
    assert_eq!(statements[0]["status"].as_str(), Some("not_affected"), "{vex}");

    // 2. Idempotent re-scan: no further edits, lock byte-identical.
    let code = run(hosted_args(tmp.path(), server.uri(), None)).await;
    assert_eq!(code, 0);
    assert_eq!(read(&lock_path), redirected, "re-scan must not touch the lock");
    let ledger: serde_json::Value =
        serde_json::from_str(&read(&tmp.path().join(".socket/vendor/redirect-state.json")))
            .unwrap();
    assert_eq!(ledger["edits"].as_array().map(Vec::len), Some(1), "one edit, not two");

    // 3. rollback unwinds the redirect and drops the record.
    roll_back(tmp.path(), server.uri()).await;
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

#[tokio::test]
#[serial]
async fn legacy_installer_major_selects_path_references() {
    let _major = MajorGuard::set("11");
    let server = MockServer::start().await;
    mock_api(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    let lock_path = tmp.path().join("Pipfile.lock");

    let code = run(hosted_args(tmp.path(), server.uri(), None)).await;
    assert_eq!(code, 0);
    let redirected = read(&lock_path);
    let entry = urllib3_entry(&redirected);
    assert_eq!(
        entry["path"].as_str(),
        Some(format!("{HOSTED_URL}#sha256={}", sha256()).as_str()),
        "Pipenv 7–11 install `path` references: {redirected}"
    );
    assert!(entry.get("file").is_none(), "{entry}");
    assert_eq!(entry["hashes"], serde_json::json!([format!("sha256:{}", sha256())]));

    roll_back(tmp.path(), server.uri()).await;
    assert_eq!(read(&lock_path), LOCK);
}

#[tokio::test]
#[serial]
async fn stale_pipfile_lock_does_not_veto_the_requirements_redirect() {
    let _major = MajorGuard::set("2026");
    let server = MockServer::start().await;
    mock_api(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    // The Pipfile.lock left behind pins a DIFFERENT package; the project
    // installs from requirements.txt.
    let stale = LOCK.replace("\"urllib3\"", "\"six\"").replace("==1.26.18", "==1.16.0");
    std::fs::write(tmp.path().join("Pipfile.lock"), &stale).unwrap();
    std::fs::write(tmp.path().join("requirements.txt"), "urllib3==1.26.18\n").unwrap();

    let code = run(hosted_args(tmp.path(), server.uri(), None)).await;
    assert_eq!(code, 0);
    let requirements = read(&tmp.path().join("requirements.txt"));
    assert!(
        requirements.contains(HOSTED_URL),
        "requirements.txt must be redirected past a stale Pipfile.lock: {requirements}"
    );
    assert_eq!(read(&tmp.path().join("Pipfile.lock")), stale, "the stale lock is left alone");

    roll_back(tmp.path(), server.uri()).await;
    assert_eq!(read(&tmp.path().join("requirements.txt")), "urllib3==1.26.18\n");
    assert_eq!(read(&tmp.path().join("Pipfile.lock")), stale);
}

#[tokio::test]
#[serial]
async fn warm_venv_with_the_upstream_release_is_not_attested() {
    let _major = MajorGuard::set("2026");
    let server = MockServer::start().await;
    mock_api(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    write_project_with_upstream_install(tmp.path());
    let lock_path = tmp.path().join("Pipfile.lock");
    let vex_path = tmp.path().join("out.vex.json");

    // The lock is rewritten, but the installed release is the UPSTREAM one
    // Pipenv will not reinstall: the stale purl is kept out of the same-run
    // attestation (`redirect_pypi_stale_install`), so nothing can be
    // attested and the embedded-VEX contract fails the command.
    let code = run(hosted_args(tmp.path(), server.uri(), Some(&vex_path))).await;
    let redirected = read(&lock_path);
    assert!(redirected.contains(HOSTED_URL), "the lock is still repointed: {redirected}");
    let attested = vex_path
        .exists()
        .then(|| serde_json::from_str::<serde_json::Value>(&read(&vex_path)).unwrap())
        .and_then(|v| v["statements"].as_array().map(Vec::len))
        .unwrap_or(0);
    assert_eq!(attested, 0, "a stale install must not be attested from the ledger");
    assert_ne!(code, 0, "nothing to attest fails the embedded-VEX run");
    assert_eq!(
        std::fs::read(site_packages(tmp.path()).join("urllib3").join("response.py")).unwrap(),
        UPSTREAM,
        "the probe is read-only"
    );

    roll_back(tmp.path(), server.uri()).await;
    assert_eq!(read(&lock_path), LOCK);
}
