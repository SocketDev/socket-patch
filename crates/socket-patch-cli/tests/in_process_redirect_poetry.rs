//! In-process CLI test for `scan --mode hosted` on a Poetry project: mocks the
//! API (discovery + reference + view) via wiremock, lays down a native
//! `poetry.lock` (the committed Poetry 2.4.3 fixture) with NO installed
//! package — the lock-only fresh-checkout / CI shape — and asserts the lock is
//! repointed at the hosted wheel, NO redirect ledger is written (v5), the
//! same-run `--vex` attests the redirect, a re-scan is idempotent, and
//! `rollback` restores every byte by re-resolving the upstream entry from a
//! mocked PyPI JSON API (`SOCKET_PYPI_JSON_API`). The rewriter bytes
//! themselves are pinned by the core `poetry_hosted` tests; this covers the
//! CLI wiring around them.

use std::path::Path;

#[path = "vex_e2e_common/mod.rs"]
mod vex_e2e_common;

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
/// …while the patch record carries the API's artifact-qualified purl (what a
/// pre-v5 redirect ledger was keyed by).
const RECORD_PURL: &str = "pkg:pypi/urllib3@1.26.18?artifact_id=py2-py3-none-any-whl";
const UUID: &str = "e828efa5-5c6d-43f3-9909-03f5ac232b98";
const HOSTED_URL: &str = "http://patch.test/patch/pypi/urllib3/1.26.18/22222222-2222-4222-8222-222222222222/e828efa5-5c6d-43f3-9909-03f5ac232b98/urllib3-1.26.18-py2.py3-none-any.whl";
const GHSA: &str = "GHSA-gm62-xv2j-4w53";
const UPSTREAM: &[u8] = b"upstream response implementation\n";
const PATCHED: &[u8] = b"patched response implementation\n";

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

/// The urllib3 1.26.18 release files the Poetry fixtures pin, as the PyPI
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

/// In-process `rollback` of the hosted pin: the mock patch host is named by
/// `--patch-server-url` (so discovery finds the pin) and the upstream restore
/// re-resolves the release from the mocked PyPI JSON API.
async fn rollback_hosted(cwd: &Path, server: &MockServer) -> i32 {
    mock_pypi(server).await;
    std::env::set_var("SOCKET_PYPI_JSON_API", format!("{}/pypi", server.uri()));
    let code = rollback::run(RollbackArgs {
        targets: Vec::new(),
        common: GlobalArgs {
            patch_server_url: Some("http://patch.test".to_string()),
            ..global(cwd, server.uri())
        },
        one_off: false,
        preserve_state: false,
    })
    .await;
    std::env::remove_var("SOCKET_PYPI_JSON_API");
    code
}

fn assert_no_ledger(root: &Path) {
    assert!(
        !root.join(".socket/vendor/redirect-state.json").exists(),
        "v5 hosted mode writes no redirect ledger"
    );
}

fn hosted_args(cwd: &Path, api_url: String, vex: Option<&Path>) -> ScanArgs {
    ScanArgs {
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
        root.join(".venv")
            .join("lib")
            .join("python3.12")
            .join("site-packages")
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
    assert_eq!(
        read(&tmp.path().join("pyproject.toml")),
        PYPROJECT,
        "pyproject untouched"
    );
    assert_no_ledger(tmp.path());
    // The redirect is attested from this run's fetched record (assume
    // applied) even though the base purl the run confirmed differs from the
    // record's qualified purl only by its `?artifact_id=` qualifier.
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
    assert_eq!(
        read(&lock_path),
        redirected,
        "re-scan must not touch the lock"
    );

    // 3. rollback restores the upstream registry entry.
    let code = rollback_hosted(tmp.path(), &server).await;
    assert_eq!(code, 0, "rollback must succeed");
    assert_eq!(
        read(&lock_path),
        LOCK,
        "rollback must restore the pristine lock byte for byte"
    );
    assert_no_ledger(tmp.path());
}

/// What `poetry lock --no-update` on Poetry 1.1 / 1.2 does to a redirected
/// lock-1.1 unit: keeps `[package.source]`, drops the inserted package-level
/// `files` line, and re-lays the `[metadata.files]` entry from the CLI's
/// inline table into Poetry's multi-line array.
fn simulate_poetry_1x_relock(lock: &str) -> String {
    let newline = if lock.contains("\r\n") { "\r\n" } else { "\n" };
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
    out.replace("\n", newline)
}

/// Relock → re-scan → rollback must still land on the pristine lock. The
/// re-scan plans from the relocked text (v5 keeps no ledger chain to rebase)
/// and rollback re-resolves the upstream entry from the registry, so the
/// relock never strands the unwind.
#[tokio::test]
#[serial]
async fn relock_then_rescan_keeps_rollback_invertible() {
    // Checkout settings must not decide which newline shape this test covers.
    for newline in ["\n", "\r\n"] {
        let lock = LOCK_1_1.replace("\r\n", "\n").replace("\n", newline);
        assert_relock_roundtrip(&lock).await;
    }
}

async fn assert_relock_roundtrip(lock: &str) {
    let server = MockServer::start().await;
    mock_api(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    let lock_path = tmp.path().join("poetry.lock");
    std::fs::write(&lock_path, lock).unwrap();

    assert_eq!(run(hosted_args(tmp.path(), server.uri(), None)).await, 0);
    let redirected = read(&lock_path);
    assert!(redirected.contains(HOSTED_URL), "{redirected}");
    assert_no_ledger(tmp.path());

    let relocked = simulate_poetry_1x_relock(&redirected);
    assert_ne!(relocked, redirected);
    assert!(relocked.contains(HOSTED_URL), "relock keeps the source");
    std::fs::write(&lock_path, &relocked).unwrap();

    // Re-scan: the unit lost its `files` line, so the rewriter writes again.
    assert_eq!(run(hosted_args(tmp.path(), server.uri(), None)).await, 0);
    let rescanned = read(&lock_path);
    assert_ne!(
        rescanned, relocked,
        "the re-scan must restore the package files entry"
    );
    assert_no_ledger(tmp.path());

    let code = rollback_hosted(tmp.path(), &server).await;
    assert_eq!(code, 0, "rollback after relock + re-scan must succeed");
    assert_eq!(
        read(&lock_path),
        lock,
        "pristine lock restored byte for byte"
    );
}

fn install_package(root: &Path, venv: &str, bytes: &[u8]) -> std::path::PathBuf {
    let site = if cfg!(windows) {
        root.join(venv).join("Lib").join("site-packages")
    } else {
        root.join(venv)
            .join("lib")
            .join("python3.12")
            .join("site-packages")
    };
    std::fs::create_dir_all(site.join("urllib3-1.26.18.dist-info")).unwrap();
    std::fs::create_dir_all(site.join("urllib3")).unwrap();
    let file = site.join("urllib3").join("response.py");
    std::fs::write(&file, bytes).unwrap();
    file
}

async fn scan_output(root: &Path, server: &MockServer, extra: &[&str]) -> std::process::Output {
    let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_socket-patch"));
    for (key, _) in std::env::vars_os() {
        let name = key.to_string_lossy();
        if name.starts_with("SOCKET_") || name.starts_with("POETRY_") || name == "VIRTUAL_ENV" {
            cmd.env_remove(key);
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
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1")
        .args(["scan", "--mode", "hosted", "--yes", "--cwd"])
        .arg(root)
        .args([
            "--api-url",
            &server.uri(),
            "--org",
            ORG,
            "--api-token",
            "fake",
        ])
        .args(extra);
    cmd.output().await.unwrap()
}

fn envelope(out: &std::process::Output) -> serde_json::Value {
    serde_json::from_slice(&out.stdout).unwrap_or_else(|error| {
        panic!(
            "{error}: stdout={} stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    })
}

fn stale_warning(value: &serde_json::Value) -> bool {
    value["redirect"]["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|warning| warning["code"] == "redirect_pypi_stale_install")
}

/// Both upstream and locally modified warm installs must be diagnosed on
/// every scan. Merely rewriting the lock must never attest their live bytes.
#[tokio::test]
async fn stale_python_install_warns_and_cannot_attest_even_on_rescan() {
    for bytes in [UPSTREAM, b"local modification\n".as_slice()] {
        let server = MockServer::start().await;
        mock_api(&server).await;
        let tmp = tempfile::tempdir().unwrap();
        write_project(tmp.path());
        let installed = install_package(tmp.path(), ".venv", bytes);
        let out = scan_output(tmp.path(), &server, &["--json"]).await;
        let json = envelope(&out);
        assert!(out.status.success(), "{json}");
        assert_eq!(json["redirect"]["redirected"], 1, "{json}");
        assert!(stale_warning(&json), "{json}");
        let redirected = read(&tmp.path().join("poetry.lock"));
        let vex = tmp.path().join("out.vex.json");
        for extra in [
            vec!["--json", "--vex", vex.to_str().unwrap()],
            vec!["--json", "--vex", vex.to_str().unwrap(), "--vex-no-verify"],
        ] {
            let out = scan_output(tmp.path(), &server, &extra).await;
            let json = envelope(&out);
            assert_eq!(out.status.code(), Some(1), "{json}");
            assert!(stale_warning(&json), "{json}");
            assert_eq!(json["error"]["code"], "no_applicable_patches", "{json}");
            assert!(!vex.exists(), "stale bytes cannot produce a VEX file");
        }
        // A failed fresh record fetch leaves the probe no evidence (v5 keeps
        // no persisted record): the run still succeeds, says the record
        // could not be fetched, and never attests.
        Mock::given(method("GET"))
            .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
            .respond_with(ResponseTemplate::new(404))
            .with_priority(1)
            .mount(&server)
            .await;
        let out = scan_output(tmp.path(), &server, &[]).await;
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "{stderr}");
        assert!(
            stderr.contains("was switched to hosted, but its patch record could not be fetched"),
            "{stderr}"
        );
        assert_eq!(
            std::fs::read(installed).unwrap(),
            bytes,
            "probe is read-only"
        );
        assert_eq!(read(&tmp.path().join("poetry.lock")), redirected);
    }
}

#[tokio::test]
async fn patched_python_install_attests_without_a_stale_warning() {
    let server = MockServer::start().await;
    mock_api(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    let installed = install_package(tmp.path(), ".venv", PATCHED);
    let vex = tmp.path().join("out.vex.json");
    let out = scan_output(
        tmp.path(),
        &server,
        &["--json", "--vex", vex.to_str().unwrap()],
    )
    .await;
    let json = envelope(&out);
    assert!(out.status.success(), "{json}");
    assert!(!stale_warning(&json), "{json}");
    assert_eq!(json["vex"]["statements"], 1, "{json}");
    assert_eq!(std::fs::read(installed).unwrap(), PATCHED);
}

#[tokio::test]
async fn healthy_interpreter_cannot_mask_a_stale_python_install() {
    let server = MockServer::start().await;
    mock_api(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    install_package(tmp.path(), ".venv", PATCHED);
    install_package(tmp.path(), "venv", UPSTREAM);
    let vex = tmp.path().join("out.vex.json");
    let out = scan_output(
        tmp.path(),
        &server,
        &["--json", "--vex", vex.to_str().unwrap()],
    )
    .await;
    let json = envelope(&out);
    assert_eq!(out.status.code(), Some(1), "{json}");
    assert!(stale_warning(&json), "{json}");
    assert!(!vex.exists());
}

#[tokio::test]
async fn python_probe_does_not_guess_staleness_or_run_on_dry_run() {
    let server = MockServer::start().await;
    mock_api(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    let installed = install_package(tmp.path(), ".venv", UPSTREAM);
    let out = scan_output(tmp.path(), &server, &["--json", "--dry-run"]).await;
    let json = envelope(&out);
    assert!(out.status.success(), "{json}");
    assert!(!stale_warning(&json), "{json}");
    assert_eq!(read(&tmp.path().join("poetry.lock")), LOCK);
    assert!(!tmp
        .path()
        .join(".socket/vendor/redirect-state.json")
        .exists());
    std::fs::remove_file(&installed).unwrap();
    for unreadable in [false, true] {
        if unreadable {
            std::fs::create_dir(&installed).unwrap();
        }
        let out = scan_output(tmp.path(), &server, &["--json"]).await;
        let json = envelope(&out);
        assert!(out.status.success(), "{json}");
        assert!(!stale_warning(&json), "{json}");
    }
}

// ── manifest-less VEX over the hosted wiring ──────────────────────────────

/// Standalone `vex` on the redirected checkout `root` (hosted urls live on
/// the mock's `http://patch.test` origin, which `vex` must be told is the
/// patch server).
fn manifestless_vex(
    root: &Path,
    api: &vex_e2e_common::PatchApi,
    offline: bool,
    extra: &[&str],
) -> vex_e2e_common::VexOutcome {
    let _ = std::fs::remove_file(root.join(vex_e2e_common::DEFAULT_OUTPUT));
    let mut run = vex_e2e_common::VexRun {
        offline,
        proxy_url: Some(api.uri()),
        patch_server_url: Some("http://patch.test".to_string()),
        product: Some("pkg:pypi/app@0.1.0".to_string()),
        ..vex_e2e_common::VexRun::default()
    };
    for arg in extra {
        run = run.arg(*arg);
    }
    vex_e2e_common::run_vex(&vex_e2e_common::binary(), root, &run)
}

/// After `scan --mode hosted` wired the lock-only checkout, VEX needs no
/// manifest and no ledger (v5 hosted writes neither):
///   1. attests from the lock's sha256 pin + the API record, and after an
///      install only when the installed tree hashes to the patch
///      (`not_applied` for the upstream bytes); `apply --vex` agrees;
///   2. `--offline` with no local record → `record_unavailable`, no request;
///   3. a pre-v5 ledger carrying the record is an extra local record
///      source: the same offline run attests with no request;
///   4. the lock reverted with that ledger kept → `redirect_unwired`, also
///      under `--no-verify`; and the self-hosted origin only counts when
///      `--patch-server-url` names it.
#[test]
#[serial]
fn manifestless_vex_after_hosted_redirect() {
    use vex_e2e_common::{assert_attested, assert_not_attested, Marker, PatchApi, VexVia};
    let rt = tokio::runtime::Runtime::new().unwrap();
    let server = rt.block_on(MockServer::start());
    rt.block_on(mock_api(&server));
    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    let root = tmp.path();
    assert_eq!(rt.block_on(run(hosted_args(root, server.uri(), None))), 0);
    assert!(!root.join(".socket/manifest.json").exists());
    assert_no_ledger(root);
    let ledger_path = root.join(".socket/vendor/redirect-state.json");
    let redirected = read(&root.join("poetry.lock"));

    let mut view = vex_e2e_common::patch_view(
        UUID,
        RECORD_PURL,
        &[(
            "urllib3/response.py",
            &compute_git_sha256_from_bytes(PATCHED),
        )],
        &[(GHSA, &["CVE-2025-66418"])],
    );
    view["files"]["urllib3/response.py"]["beforeHash"] =
        compute_git_sha256_from_bytes(UPSTREAM).into();
    let api = PatchApi::start(vec![(UUID.into(), view.clone())]);
    let vulns: &[(&str, &[&str])] = &[(GHSA, &["CVE-2025-66418"])];

    // 1. lock pin + API record.
    let out = manifestless_vex(root, &api, false, &[]);
    assert_eq!(out.code, Some(0), "{out}");
    assert_attested(out.doc(), PURL, UUID, Marker::Redirected, vulns);
    assert!(api.view_requests(UUID) >= 1);
    let _ = std::fs::remove_file(root.join(vex_e2e_common::DEFAULT_OUTPUT));
    let apply = vex_e2e_common::VexRun {
        proxy_url: Some(api.uri()),
        patch_server_url: Some("http://patch.test".to_string()),
        product: Some("pkg:pypi/app@0.1.0".to_string()),
        ..vex_e2e_common::VexRun::default()
    }
    .via(VexVia::Apply);
    let out = vex_e2e_common::run_vex(&vex_e2e_common::binary(), root, &apply);
    assert_eq!(out.code, Some(0), "{out}");
    assert_eq!(out.envelope["status"], "noManifest", "{out}");
    assert_attested(out.doc(), PURL, UUID, Marker::Redirected, vulns);
    // Without the origin configured, `http://patch.test` is nobody's patch
    // server: nothing is referenced at all.
    let mut run = vex_e2e_common::VexRun::online(&api);
    run.product = Some("pkg:pypi/app@0.1.0".to_string());
    let out = vex_e2e_common::run_vex(&vex_e2e_common::binary(), root, &run);
    assert_eq!(out.code, Some(2), "{out}");
    assert_eq!(out.envelope["error"]["code"], "manifest_not_found", "{out}");
    // Installed: the installed tree decides.
    let installed = install_package(root, ".venv", PATCHED);
    let out = manifestless_vex(root, &api, false, &[]);
    assert_eq!(out.code, Some(0), "{out}");
    assert_attested(out.doc(), PURL, UUID, Marker::Redirected, vulns);
    std::fs::write(&installed, UPSTREAM).unwrap();
    let out = manifestless_vex(root, &api, false, &[]);
    assert_eq!(out.code, Some(1), "{out}");
    assert_not_attested(&out.envelope, PURL, "not_applied");
    std::fs::write(&installed, PATCHED).unwrap();

    // 2. offline with no local record.
    let seen = api.request_count();
    let out = manifestless_vex(root, &api, true, &[]);
    assert_eq!(out.code, Some(1), "{out}");
    assert_not_attested(&out.envelope, PURL, "record_unavailable");
    assert!(out.doc.is_none());
    assert_eq!(api.request_count(), seen, "--offline made a request");

    // 3. a pre-v5 ledger's record serves the offline run.
    let mut record = view;
    let obj = record.as_object_mut().unwrap();
    obj.remove("purl");
    let exported = obj.remove("publishedAt").unwrap();
    obj.insert("exportedAt".to_string(), exported);
    std::fs::create_dir_all(ledger_path.parent().unwrap()).unwrap();
    std::fs::write(
        &ledger_path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "version": 1,
            "mode": "hosted",
            "records": { RECORD_PURL: record },
        }))
        .unwrap(),
    )
    .unwrap();
    let out = manifestless_vex(root, &api, true, &[]);
    assert_eq!(out.code, Some(0), "{out}");
    assert_attested(out.doc(), PURL, UUID, Marker::Redirected, vulns);
    assert_eq!(api.request_count(), seen, "--offline made a request");

    // 4. reverted lock, that ledger kept.
    std::fs::write(root.join("poetry.lock"), LOCK).unwrap();
    for extra in [&[][..], &["--no-verify"][..]] {
        for offline in [true, false] {
            let out = manifestless_vex(root, &api, offline, extra);
            assert_eq!(out.code, Some(1), "{extra:?} offline={offline}: {out}");
            assert_not_attested(&out.envelope, PURL, "redirect_unwired");
            assert!(out.doc.is_none());
        }
    }
    // Re-wired: live again.
    std::fs::write(root.join("poetry.lock"), &redirected).unwrap();
    let out = manifestless_vex(root, &api, true, &[]);
    assert_eq!(out.code, Some(0), "{out}");
    drop(server);
}
