//! In-process CLI tests for `scan --mode hosted` on Pipenv projects: mocks
//! the API (discovery + reference + view) via wiremock, lays down a native
//! `Pipfile.lock` (the committed Pipenv 2026.8.0 fixture) and drives the
//! real command wiring. Covered here (the rewriter bytes themselves are
//! pinned by the core `patch::redirect::pipenv` tests):
//!
//! * the lock-only fresh-checkout shape (nothing installed) is discovered
//!   from `Pipfile.lock` alone, repointed with a `file` reference carrying
//!   the `#sha256=` fragment and a matching `hashes` entry, attested by the
//!   same-run `--vex`, re-scanned idempotently and rolled back byte for byte
//!   (v5: no redirect ledger is written; `rollback` re-resolves the upstream
//!   entry from a mocked PyPI JSON API, `SOCKET_PYPI_JSON_API`);
//! * `SOCKET_PIPENV_MAJOR=11` selects the legacy `path` reference shape the
//!   installer probe would otherwise need a real Pipenv 7–11 on PATH for;
//! * a stale `Pipfile.lock` that does not pin the package does not veto
//!   the sibling `requirements.txt` redirect;
//! * a conflicting entry in a live `Pipfile.lock` (a `Pipfile` beside it)
//!   vetoes the sibling `requirements.txt` redirect, while the same
//!   conflict in an abandoned lock (no `Pipfile`) does not (#333);
//! * a venv still holding the UPSTREAM release is reported stale and kept
//!   out of the same-run attestation.
//!
//! Every flow ends with the manifest-less VEX steps (`vex_pipenv_pip_steps`)
//! over a copy of the committed state it produced: no manifest and no ledger,
//! `--offline` (`record_unavailable`, zero requests),
//! the lock reverted to the registry (`redirect_unwired`, `--no-verify`
//! too) and `apply --vex` — and, for the warm venv, `not_applied` whatever
//! the lock says.

use std::path::Path;

#[path = "common/hermetic.rs"]
mod hermetic;
#[path = "vex_e2e_common/mod.rs"]
mod vex_e2e_common;
#[path = "vex_pipenv_pip_steps/mod.rs"]
mod vex_pipenv_pip_steps;

use serial_test::serial;
use socket_patch_cli::args::GlobalArgs;
use socket_patch_cli::commands::rollback::{self, RollbackArgs};
use socket_patch_cli::commands::scan::{run, ScanArgs};
use socket_patch_cli::commands::vex::VexEmbedArgs;
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

use vex_e2e_common::Marker;
use vex_pipenv_pip_steps::{run_manifestless_steps, Records, Steps};

const ORG: &str = "test-org";
/// Discovery names the base purl (the lockfile supplement's spelling)…
const PURL: &str = "pkg:pypi/urllib3@1.26.18";
/// …while the patch record carries the API's artifact-qualified purl.
const RECORD_PURL: &str = "pkg:pypi/urllib3@1.26.18?artifact_id=py2-py3-none-any-whl";
const UUID: &str = "e828efa5-5c6d-43f3-9909-03f5ac232b98";
const HOSTED_URL: &str = "https://patch.socket.dev/patch/pypi/urllib3/1.26.18/22222222-2222-4222-8222-222222222222/e828efa5-5c6d-43f3-9909-03f5ac232b98/urllib3-1.26.18-py2.py3-none-any.whl";
const GHSA: &str = "GHSA-gm62-xv2j-4w53";
const MAJOR_ENV: &str = socket_patch_core::utils::pipenv::MAJOR_OVERRIDE_ENV;

const LOCK: &str =
    include_str!("../../socket-patch-core/tests/fixtures/pipenv/2026.8.0/Pipfile.lock");
const PIPFILE: &str =
    include_str!("../../socket-patch-core/tests/fixtures/pipenv/2026.8.0/Pipfile");

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
        socket_yml: Default::default(),
        paths: Vec::new(),
        packages: Vec::new(),
        common: global(cwd, api_url),
        batch_size: Some(100),
        apply: false,
        prune: false,
        sync: false,
        vendor: false,
        mode: Some(socket_patch_cli::commands::scan::ScanMode::Hosted),
        all_releases: false,
        vex: VexEmbedArgs {
            vex: vex.map(Path::to_path_buf),
            // A Pipfile names no project, so the embedded VEX cannot detect a
            // product purl on its own (nor without a git remote): callers pass
            // `--vex-product`, as documented for Pipenv projects.
            vex_product: vex.map(|_| "pkg:pypi/pipenv-fixture@0.1.0".to_string()),
            ..Default::default()
        },
        rollout: Default::default(),
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
        .and(path_regex(format!(
            "^/v0/orgs/{ORG}/patches/by-package/.+$"
        )))
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
        .respond_with(ResponseTemplate::new(200).set_body_json(view_body()))
        .mount(server)
        .await;
}

/// The patch view (`GET …/view/<uuid>`) — also what the manifest-less VEX
/// steps' patch API serves on the public-proxy route.
fn view_body() -> serde_json::Value {
    serde_json::json!({
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
    })
}

const VEX_PRODUCT: &str = "pkg:pypi/pipenv-fixture@0.1.0";

/// The manifest-less VEX steps over the committed state `project` holds
/// (nothing installed: the lock's integrity pin is the evidence), with
/// `revert` putting the wiring back on the registry.
fn manifestless_vex(project: &Path, what: &str, revert: &(dyn Fn(&Path) + Sync)) {
    run_manifestless_steps(&Steps {
        what: what.to_string(),
        project,
        purl: PURL,
        uuid: UUID,
        marker: Marker::Redirected,
        vulns: Some(&[(GHSA, &["CVE-2025-66418"])]),
        records: Records::Mock(vec![(UUID.to_string(), view_body())]),
        patch_server_url: None,
        product: VEX_PRODUCT,
        revert,
        envs: Vec::new(),
        on_step: None,
        expect_verified: true,
    });
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

/// The urllib3 1.26.18 release files the Pipenv fixture pins, as the PyPI
/// JSON API serves them (`GET /pypi/urllib3/1.26.18/json`).
async fn mock_pypi(server: &MockServer) {
    let file = |filename: &str, sha: &str, size: u64, uploaded: &str| {
        serde_json::json!({
            "filename": filename,
            "url": format!("https://files.pythonhosted.org/packages/ab/cd/{filename}"),
            "digests": { "sha256": sha },
            "size": size,
            "upload_time_iso_8601": uploaded,
        })
    };
    Mock::given(method("GET"))
        .and(path("/pypi/urllib3/1.26.18/json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "urls": [
                file(
                    "urllib3-1.26.18-py2.py3-none-any.whl",
                    "34b97092d7e0a3a8cf7cd10e386f401b3737364026c45e622aa02903dffe0f07",
                    143835,
                    "2023-10-17T17:46:21.184066Z",
                ),
                file(
                    "urllib3-1.26.18.tar.gz",
                    "f8ecc1bba5667413457c529ab955bf8c67b45db799d159066261719e328580a0",
                    305687,
                    "2023-10-17T17:46:24.000000Z",
                ),
            ]
        })))
        .mount(server)
        .await;
}

/// In-process `rollback`: the hosted pin (on patch.socket.dev) is restored
/// to its upstream entry, re-resolved from the mocked PyPI JSON API.
async fn roll_back(cwd: &Path, server: &MockServer) {
    mock_pypi(server).await;
    std::env::set_var("SOCKET_PYPI_JSON_API", format!("{}/pypi", server.uri()));
    let code = rollback::run(RollbackArgs {
        targets: Vec::new(),
        common: global(cwd, server.uri()),
        preserve_state: false,
    })
    .await;
    std::env::remove_var("SOCKET_PYPI_JSON_API");
    assert_eq!(code, 0, "rollback must succeed");
    assert_no_ledger(cwd);
}

fn assert_no_ledger(root: &Path) {
    assert!(
        !root.join(".socket/vendor/redirect-state.json").exists(),
        "v5 hosted mode writes no redirect ledger"
    );
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
    assert!(entry.get("version").is_none(), "{entry}");
    assert_eq!(
        entry.get("index"),
        urllib3_entry(LOCK).get("index"),
        "Pipenv's own index is kept for rollback"
    );
    assert_eq!(
        entry["markers"],
        urllib3_entry(LOCK)["markers"],
        "markers are preserved"
    );
    let before: serde_json::Value = serde_json::from_str(LOCK).unwrap();
    let after: serde_json::Value = serde_json::from_str(&redirected).unwrap();
    assert_eq!(
        after["_meta"], before["_meta"],
        "the Pipfile content hash stays"
    );
    assert_eq!(
        read(&tmp.path().join("Pipfile")),
        PIPFILE,
        "Pipfile untouched"
    );
    assert_no_ledger(tmp.path());
    // Attested from this run's fetched record (keyed by RECORD_PURL, assume
    // applied) although the base purl the run confirmed differs from the
    // record's qualified purl.
    let vex: serde_json::Value = serde_json::from_str(&read(&vex_path)).unwrap();
    let statements = vex["statements"].as_array().expect("statements");
    assert_eq!(statements.len(), 1, "{vex}");
    assert_eq!(
        statements[0]["vulnerability"]["name"].as_str(),
        Some(GHSA),
        "{vex}"
    );
    assert_eq!(
        statements[0]["status"].as_str(),
        Some("not_affected"),
        "{vex}"
    );

    // 2. Idempotent re-scan: no further edits, lock byte-identical.
    let code = run(hosted_args(tmp.path(), server.uri(), None)).await;
    assert_eq!(code, 0);
    assert_eq!(
        read(&lock_path),
        redirected,
        "re-scan must not touch the lock"
    );
    assert_no_ledger(tmp.path());

    // Manifest-less VEX over the committed state (the depscan / CI shape).
    manifestless_vex(tmp.path(), "pipenv lock-only", &|p: &Path| {
        std::fs::write(p.join("Pipfile.lock"), LOCK).unwrap();
    });

    // 3. rollback restores the upstream registry entry.
    roll_back(tmp.path(), &server).await;
    assert_eq!(
        read(&lock_path),
        LOCK,
        "rollback must restore the pristine lock byte for byte"
    );
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
    assert_eq!(
        entry["hashes"],
        serde_json::json!([format!("sha256:{}", sha256())])
    );

    // The legacy `path` reference is discovered just like `file`.
    manifestless_vex(tmp.path(), "pipenv legacy path", &|p: &Path| {
        std::fs::write(p.join("Pipfile.lock"), LOCK).unwrap();
    });

    roll_back(tmp.path(), &server).await;
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
    let stale = LOCK
        .replace("\"urllib3\"", "\"six\"")
        .replace("==1.26.18", "==1.16.0");
    std::fs::write(tmp.path().join("Pipfile.lock"), &stale).unwrap();
    // An unpatched, unhashed sibling makes the file's hash mode derivable,
    // so rollback can restore the hosted line (a file whose every line is a
    // hosted pin is refused with the `git checkout` remedy instead).
    const REQS: &str = "urllib3==1.26.18\nrequests==2.31.0\n";
    std::fs::write(tmp.path().join("requirements.txt"), REQS).unwrap();

    let code = run(hosted_args(tmp.path(), server.uri(), None)).await;
    assert_eq!(code, 0);
    let requirements = read(&tmp.path().join("requirements.txt"));
    assert!(
        requirements.contains(HOSTED_URL),
        "requirements.txt must be redirected past a stale Pipfile.lock: {requirements}"
    );
    assert_eq!(
        read(&tmp.path().join("Pipfile.lock")),
        stale,
        "the stale lock is left alone"
    );

    // The requirements wiring attests manifest-less; the stale lock beside
    // it neither vetoes nor contributes.
    manifestless_vex(tmp.path(), "requirements past a stale lock", &|p: &Path| {
        std::fs::write(p.join("requirements.txt"), REQS).unwrap();
    });

    roll_back(tmp.path(), &server).await;
    assert_eq!(read(&tmp.path().join("requirements.txt")), REQS);
    assert_eq!(read(&tmp.path().join("Pipfile.lock")), stale);
}

/// The lock entry repointed at the user's own wheel: a `file` source that
/// is not Socket's, which the Pipenv planner refuses as a conflict.
fn lock_with_user_file_source() -> String {
    LOCK.replace(
        "\"version\": \"==1.26.18\"",
        "\"file\": \"wheels/urllib3-1.26.18-py2.py3-none-any.whl\"",
    )
}

/// #333: a conflicting entry in a LIVE Pipfile.lock (a Pipfile beside it)
/// means Pipenv never installs the patch, so the patch is refused for the
/// whole project. The hosted scan must therefore see the Pipfile: the
/// sibling requirements.txt stays untouched instead of being
/// half-redirected.
#[tokio::test]
#[serial]
async fn live_pipfile_lock_conflict_vetoes_the_requirements_redirect() {
    let _major = MajorGuard::set("2026");
    let server = MockServer::start().await;
    mock_api(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    let lock = lock_with_user_file_source();
    std::fs::write(tmp.path().join("Pipfile.lock"), &lock).unwrap();
    const REQS: &str = "urllib3==1.26.18\nrequests==2.31.0\n";
    std::fs::write(tmp.path().join("requirements.txt"), REQS).unwrap();

    run(hosted_args(tmp.path(), server.uri(), None)).await;
    assert_eq!(
        read(&tmp.path().join("requirements.txt")),
        REQS,
        "a live Pipfile.lock conflict must veto the sibling requirements.txt"
    );
    assert_eq!(read(&tmp.path().join("Pipfile.lock")), lock);
    assert_eq!(read(&tmp.path().join("Pipfile")), PIPFILE);
}

/// The same conflict in an ABANDONED lock (no Pipfile beside it) says
/// nothing about the project's install files: the sibling requirements.txt
/// is still redirected.
#[tokio::test]
#[serial]
async fn abandoned_pipfile_lock_conflict_does_not_veto_the_requirements_redirect() {
    let _major = MajorGuard::set("2026");
    let server = MockServer::start().await;
    mock_api(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    std::fs::remove_file(tmp.path().join("Pipfile")).unwrap();
    let lock = lock_with_user_file_source();
    std::fs::write(tmp.path().join("Pipfile.lock"), &lock).unwrap();
    const REQS: &str = "urllib3==1.26.18\nrequests==2.31.0\n";
    std::fs::write(tmp.path().join("requirements.txt"), REQS).unwrap();

    let code = run(hosted_args(tmp.path(), server.uri(), None)).await;
    assert_eq!(code, 0);
    let requirements = read(&tmp.path().join("requirements.txt"));
    assert!(
        requirements.contains(HOSTED_URL),
        "an abandoned lock must not veto requirements.txt: {requirements}"
    );
    assert_eq!(read(&tmp.path().join("Pipfile.lock")), lock);
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
    assert!(
        redirected.contains(HOSTED_URL),
        "the lock is still repointed: {redirected}"
    );
    let attested = vex_path
        .exists()
        .then(|| serde_json::from_str::<serde_json::Value>(&read(&vex_path)).unwrap())
        .and_then(|v| v["statements"].as_array().map(Vec::len))
        .unwrap_or(0);
    assert_eq!(
        attested, 0,
        "a stale install must not be attested from the fetched record"
    );
    assert_ne!(code, 0, "nothing to attest fails the embedded-VEX run");
    assert_eq!(
        std::fs::read(
            site_packages(tmp.path())
                .join("urllib3")
                .join("response.py")
        )
        .unwrap(),
        UPSTREAM,
        "the probe is read-only"
    );

    assert_no_ledger(tmp.path());

    // Manifest-less: the installed UPSTREAM copy is the evidence, whatever
    // the lock says — `not_applied`, online (the record from the API).
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let api = vex_e2e_common::PatchApi::start(vec![(UUID.to_string(), view_body())]);
                let scratch = tempfile::tempdir().unwrap();
                let p = scratch.path().join("proj");
                vex_pipenv_pip_steps::copy_tree(tmp.path(), &p);
                vex_e2e_common::strip_manifest(&p);
                let out = vex_e2e_common::run_vex(
                    &vex_e2e_common::binary(),
                    &p,
                    &vex_e2e_common::VexRun {
                        product: Some(VEX_PRODUCT.into()),
                        ..vex_e2e_common::VexRun::online(&api)
                    },
                );
                assert_eq!(out.code, Some(1), "{out}");
                vex_e2e_common::assert_absent(out.doc.as_ref(), PURL);
                vex_e2e_common::assert_not_attested(&out.envelope, PURL, "not_applied");
            })
            .join()
            .unwrap_or_else(|e| std::panic::resume_unwind(e));
    });

    roll_back(tmp.path(), &server).await;
    assert_eq!(read(&lock_path), LOCK);
}

/// Native Pipenv resolves these .env settings before choosing its env.
/// A healthy ambient interpreter or empty local env must not hide the
/// selected stale installation from the hosted-byte/VEX check.
#[tokio::test]
#[serial]
async fn dotenv_selected_pipenv_install_is_checked_before_vex() {
    for case in [
        "single-quoted",
        "multiline",
        "ignore-active",
        "override-active",
        "relative-active",
    ] {
        let server = MockServer::start().await;
        mock_api(&server).await;
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path().join("project");
        std::fs::create_dir_all(&project).unwrap();
        write_project_with_upstream_install(&project);
        let workon = tmp.path().join("workon");
        std::fs::create_dir_all(&workon).unwrap();
        let actual = workon.join("actual");
        std::fs::rename(project.join(".venv"), &actual).unwrap();
        std::fs::create_dir_all(site_packages(&project)).unwrap();
        let ambient_project = tmp.path().join("ambient-project");
        std::fs::create_dir_all(&ambient_project).unwrap();
        write_project_with_upstream_install(&ambient_project);
        let ambient_file = site_packages(&ambient_project).join("urllib3/response.py");
        std::fs::write(&ambient_file, PATCHED).unwrap();
        let actual_file = if cfg!(windows) {
            actual.join("Lib/site-packages/urllib3/response.py")
        } else {
            actual.join("lib/python3.12/site-packages/urllib3/response.py")
        };
        let dotenv = match case {
            "single-quoted" => "NAME=actual\nPIPENV_CUSTOM_VENV_NAME='${NAME}'\n".to_string(),
            "multiline" => "PIPENV_CUSTOM_VENV_NAME=actual\nAPP_SETTINGS=\"first\nPIPENV_CUSTOM_VENV_NAME=decoy\nlast\"\n".to_string(),
            "ignore-active" => "PIPENV_IGNORE_VIRTUALENVS=1\nPIPENV_CUSTOM_VENV_NAME=actual\n".to_string(),
            "relative-active" => "VIRTUAL_ENV=../workon/actual\n".to_string(),
            _ => format!("VIRTUAL_ENV='{}'\n", actual.to_string_lossy().replace('\\', "/")),
        };
        std::fs::write(project.join(".env"), &dotenv).unwrap();
        let vex = project.join("out.vex.json");
        let mut cmd = tokio::process::Command::from(hermetic::command(Path::new(env!(
            "CARGO_BIN_EXE_socket-patch"
        ))));
        for (key, _) in std::env::vars_os() {
            let key_text = key.to_string_lossy();
            if key_text.starts_with("SOCKET_")
                || key_text.starts_with("PIPENV_")
                || matches!(key_text.as_ref(), "VIRTUAL_ENV" | "WORKON_HOME")
            {
                cmd.env_remove(key);
            }
        }
        for key in [
            "SOCKET_OFFLINE",
            "SOCKET_DEBUG",
            "SOCKET_API_URL",
            "SOCKET_PROXY_URL",
        ] {
            cmd.env_remove(key);
        }
        cmd.env("SOCKET_TELEMETRY_DISABLED", "1")
            .env(MAJOR_ENV, "2026")
            .env("WORKON_HOME", &workon)
            .args(["scan", "--mode", "hosted", "--yes", "--json", "--cwd"])
            .arg(&project)
            .args([
                "--api-url",
                &server.uri(),
                "--org",
                ORG,
                "--api-token",
                "fake",
                "--vex",
            ])
            .arg(&vex)
            .args(["--vex-product", VEX_PRODUCT]);
        if case.ends_with("active") {
            cmd.env("VIRTUAL_ENV", ambient_project.join(".venv"));
        }
        let out = cmd.output().await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|error| {
            panic!(
                "{case}: {error}: stdout={} stderr={}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            )
        });
        assert_eq!(out.status.code(), Some(1), "{case}: {json}");
        assert!(
            json["redirect"]["warnings"]
                .as_array()
                .unwrap()
                .iter()
                .any(|warning| warning["code"] == "redirect_pypi_stale_install"),
            "{case}: {json}"
        );
        assert!(!vex.exists(), "{case}: stale bytes must not produce VEX");
        assert_eq!(
            std::fs::read(&actual_file).unwrap(),
            UPSTREAM,
            "the probe is read-only"
        );
        assert_eq!(
            std::fs::read(&ambient_file).unwrap(),
            PATCHED,
            "the ambient env is unchanged"
        );
        assert_eq!(read(&project.join("Pipfile")), PIPFILE);
        assert!(read(&project.join("Pipfile.lock")).contains(HOSTED_URL));
    }
}

/// Pipenv 2018 shell can select a third dotenv WORKON_HOME while current
/// Pipenv and pre-dotenv commands use a healthy cached environment.
#[tokio::test]
#[serial]
async fn legacy_dotenv_workon_install_is_checked_before_vex() {
    for forward_reference in [true, false] {
        let server = MockServer::start().await;
        mock_api(&server).await;
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path().join("project");
        let legacy = tmp.path().join("legacy-workon");
        let cached = tmp.path().join("cached-workon");
        let make_install = |seed: &Path, root: &Path, bytes: &[u8]| {
            std::fs::create_dir_all(seed).unwrap();
            std::fs::create_dir_all(root.parent().unwrap()).unwrap();
            write_project_with_upstream_install(seed);
            let relative = site_packages(seed)
                .strip_prefix(seed.join(".venv"))
                .unwrap()
                .to_path_buf();
            std::fs::rename(seed.join(".venv"), root).unwrap();
            let file = root.join(relative).join("urllib3/response.py");
            std::fs::write(&file, bytes).unwrap();
            file
        };
        let stale_file = make_install(&project, &legacy.join("env"), UPSTREAM);
        let healthy_file = make_install(&tmp.path().join("seed"), &cached.join("env"), PATCHED);
        // The .venv file names a project-specific venv within WORKON_HOME
        // in both native generations, avoiding unrelated directory scans.
        std::fs::write(project.join(".venv"), "env\n").unwrap();
        let legacy_text = legacy.to_string_lossy().replace('\\', "/");
        let cached_text = cached.to_string_lossy().replace('\\', "/");
        let dotenv = if forward_reference {
            format!("WORKON_HOME=${{BASE}}\nBASE={legacy_text}\n")
        } else {
            format!("BASE={cached_text}\nWORKON_HOME=${{BASE}}\n")
        };
        std::fs::write(project.join(".env"), dotenv).unwrap();
        let vex = project.join("out.vex.json");
        let mut cmd = tokio::process::Command::from(hermetic::command(Path::new(env!(
            "CARGO_BIN_EXE_socket-patch"
        ))));
        for (key, _) in std::env::vars_os() {
            let text = key.to_string_lossy();
            if text.starts_with("SOCKET_")
                || text.starts_with("PIPENV_")
                || matches!(text.as_ref(), "VIRTUAL_ENV" | "WORKON_HOME" | "BASE")
            {
                cmd.env_remove(key);
            }
        }
        cmd.env("SOCKET_TELEMETRY_DISABLED", "1")
            .env(MAJOR_ENV, "2026")
            .env("HOME", tmp.path().join("home"))
            .env("USERPROFILE", tmp.path().join("home"))
            .env("WORKON_HOME", &cached)
            .args(["scan", "--mode", "hosted", "--yes", "--json", "--cwd"])
            .arg(&project)
            .args([
                "--api-url",
                &server.uri(),
                "--org",
                ORG,
                "--api-token",
                "fake",
                "--vex",
            ])
            .arg(&vex)
            .args(["--vex-product", VEX_PRODUCT]);
        if !forward_reference {
            cmd.env("BASE", &legacy);
        }
        let out = cmd.output().await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|error| {
            panic!(
                "{error}: stdout={} stderr={}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            )
        });
        assert_eq!(
            out.status.code(),
            Some(1),
            "forward={forward_reference}: {json}"
        );
        assert!(
            json["redirect"]["warnings"]
                .as_array()
                .unwrap()
                .iter()
                .any(|warning| warning["code"] == "redirect_pypi_stale_install"),
            "{json}"
        );
        assert!(
            !vex.exists(),
            "a healthy cached copy cannot attest the stale shell copy"
        );
        assert_eq!(std::fs::read(stale_file).unwrap(), UPSTREAM);
        assert_eq!(std::fs::read(healthy_file).unwrap(), PATCHED);
        assert_eq!(read(&project.join(".venv")), "env\n");
        assert_eq!(read(&project.join("Pipfile")), PIPFILE);
    }
}
