//! In-process CLI test for `scan --mode hosted` on a PDM project: mocks the API
//! (discovery + reference + view) via wiremock, lays down a native `pdm.lock`
//! (the committed backtest fixtures) with NO installed package — the lock-only
//! fresh-checkout / CI shape — and asserts the lock is repointed at the hosted
//! wheel, NO redirect ledger is written (v5), the same-run `--vex` attests the
//! redirect, a re-scan is idempotent, and `rollback` restores every byte by
//! re-resolving the upstream entry from a mocked PyPI JSON API
//! (`SOCKET_PYPI_JSON_API`). It also covers the PDM-specific relock
//! convergence: `pdm lock` un-patches the lock AND can reflow its line
//! endings (CRLF → LF); a re-scan plans from the relocked bytes and
//! `rollback` lands on the relocked lock. The rewriter bytes themselves are
//! pinned by the core `utils::pdm_lock` tests; this covers the CLI wiring.
//!
//! Every flow ends with the MANIFEST-LESS VEX step ([`assert_manifestless_vex`],
//! the shared `vex_e2e_common` helper): a fresh copy of the committed state
//! (pyproject + lock, never a manifest or ledger in v5 hosted mode) attests
//! the redirect from the lock + patch API (`--patch-server-url` admits the
//! fixture's non-Socket host), omits it `record_unavailable` offline (zero
//! requests), attests offline from a pre-v5 ledger's record, and omits it
//! `redirect_unwired` once the lock is reverted — `--no-verify` included.

use std::path::Path;

use serial_test::serial;
use socket_patch_cli::args::GlobalArgs;
use socket_patch_cli::commands::rollback::{self, RollbackArgs};
use socket_patch_cli::commands::scan::{run, ScanArgs};
use socket_patch_cli::commands::vex::VexEmbedArgs;
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[path = "vex_e2e_common/mod.rs"]
mod vex_e2e_common;
use vex_e2e_common::{
    assert_attested, assert_not_attested, binary, git_sha256, patch_view, run_vex, strip_manifest,
    Marker, PatchApi, VexRun,
};

const ORG: &str = "test-org";
/// Discovery names the base purl (the lock inventory's spelling)…
const PURL: &str = "pkg:pypi/urllib3@1.26.18";
/// …while the patch record carries the API's artifact-qualified purl (what a
/// pre-v5 redirect ledger was keyed by).
const RECORD_PURL: &str = "pkg:pypi/urllib3@1.26.18?artifact_id=py2-py3-none-any-whl";
const UUID: &str = "e828efa5-5c6d-43f3-9909-03f5ac232b98";
const HOSTED_URL: &str = "http://patch.test/patch/pypi/urllib3/1.26.18/22222222-2222-4222-8222-222222222222/e828efa5-5c6d-43f3-9909-03f5ac232b98/urllib3-1.26.18-py2.py3-none-any.whl";
const GHSA: &str = "GHSA-gm62-xv2j-4w53";
const UPSTREAM: &[u8] = b"upstream response implementation\n";
const PATCHED: &[u8] = b"patched response implementation\n";

/// PDM 2.29.2 native lock (lock_version 4.5.1, inline `files`).
const LOCK: &str = include_str!("../../socket-patch-core/tests/fixtures/pdm-native/2.29.2.lock");
/// PDM 0.12.3 native lock (lock_version 2, legacy `[metadata.files]`).
const LOCK_LEGACY: &str =
    include_str!("../../socket-patch-core/tests/fixtures/pdm-native/0.12.3.lock");

const PYPROJECT: &str = "[project]\nname = \"x\"\nversion = \"0.0.0\"\nrequires-python = \">=3.8\"\ndependencies = [\"urllib3==1.26.18\"]\n\n[tool.pdm]\ndistribution = false\n";

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

/// The urllib3 1.26.18 release files the PDM fixtures pin, as the PyPI JSON
/// API serves them (`GET /pypi/urllib3/1.26.18/json`).
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
            patch_server_url: Some(PATCH_SERVER.to_string()),
            ..global(cwd, server.uri())
        },
        preserve_state: false,
    })
    .await;
    std::env::remove_var("SOCKET_PYPI_JSON_API");
    code
}

/// A pre-v5 redirect ledger holding `record` under `purl` (no edits).
fn write_legacy_ledger(root: &Path, purl: &str, record: serde_json::Value) {
    let dir = root.join(".socket/vendor");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("redirect-state.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "version": 1,
            "mode": "hosted",
            "records": { purl: record },
        }))
        .unwrap(),
    )
    .unwrap();
}

fn assert_no_ledger(root: &Path) {
    assert!(
        !root.join(".socket/vendor/redirect-state.json").exists(),
        "v5 hosted mode writes no redirect ledger"
    );
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
                    "title": "pdm redirect fixture"
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
                    "summary": "pdm redirect vex fixture",
                    "severity": "HIGH",
                    "description": "d"
                }
            },
            "description": "x", "license": "MIT", "tier": "free"
        })))
        .mount(server)
        .await;
}

/// A PDM project with nothing installed: the lock is the only source of the
/// dependency. An EMPTY in-project venv keeps the crawl hermetic (without it
/// the project-marker fallback would walk this machine's global interpreters).
fn write_project(root: &Path, lock: &str) {
    std::fs::write(root.join("pyproject.toml"), PYPROJECT).unwrap();
    std::fs::write(root.join("pdm.lock"), lock).unwrap();
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

/// Origin of [`HOSTED_URL`]: not on the Socket host allowlist, so discovery
/// only counts it as a hosted reference when named by `--patch-server-url`.
const PATCH_SERVER: &str = "http://patch.test";

/// The manifest-less VEX step every flow ends with. `root` holds the
/// committed state the flow produced (pyproject + lock + `.socket/`);
/// `pristine_lock` is the registry lock a revert restores. Runs on its own
/// thread: the patch-API stand-in owns a runtime, which cannot be driven
/// from inside this test's.
fn assert_manifestless_vex(root: &Path, pristine_lock: &str) {
    let root = root.to_path_buf();
    let pristine_lock = pristine_lock.to_string();
    std::thread::spawn(move || manifestless_vex_steps(&root, &pristine_lock))
        .join()
        .unwrap_or_else(|e| std::panic::resume_unwind(e));
}

fn manifestless_vex_steps(root: &Path, pristine_lock: &str) {
    let vulns: &[(&str, &[&str])] = &[(GHSA, &["CVE-2025-66418"])];
    let view = patch_view(
        UUID,
        RECORD_PURL,
        &[("urllib3/response.py", &git_sha256(PATCHED))],
        vulns,
    );
    let api = PatchApi::start(vec![(UUID.to_string(), view.clone())]);
    let online = || VexRun {
        patch_server_url: Some(PATCH_SERVER.to_string()),
        ..VexRun::online(&api)
    };
    // A fresh checkout of the committed state: the files, no installed
    // package (an EMPTY in-project venv keeps the crawl hermetic).
    let tmp = tempfile::tempdir().unwrap();
    let copy = tmp.path();
    write_project(copy, &read(&root.join("pdm.lock")));
    std::fs::copy(root.join("pyproject.toml"), copy.join("pyproject.toml")).unwrap();
    copy_dir(&root.join(".socket"), &copy.join(".socket"));
    strip_manifest(copy);
    assert_no_ledger(copy);

    // (1) The lock alone, the record from the patch API. Nothing is
    // installed, so the basis is the lock's sha256 pin — which counts only
    // once `--patch-server-url` makes the lock's url a discovered hosted
    // reference.
    let out = run_vex(&binary(), copy, &online());
    assert_eq!(out.code, Some(0), "{out}");
    assert_attested(out.doc(), PURL, UUID, Marker::Redirected, vulns);
    assert!(api.view_requests(UUID) >= 1, "{:?}", api.requests());
    // …and without `--patch-server-url` the non-Socket host is no reference.
    let out = run_vex(&binary(), copy, &VexRun::online(&api));
    assert_eq!(out.code, Some(2), "{out}");
    assert_eq!(out.envelope["error"]["code"], "manifest_not_found", "{out}");

    // (2) offline with no local record: nothing to attest from, no network.
    let quiet = PatchApi::empty();
    let offline = VexRun {
        offline: true,
        patch_server_url: Some(PATCH_SERVER.to_string()),
        ..VexRun::online(&quiet)
    };
    let out = run_vex(&binary(), copy, &offline);
    assert_eq!(out.code, Some(1), "{out}");
    assert_not_attested(&out.envelope, PURL, "record_unavailable");
    quiet.assert_no_requests();

    // (3) a pre-v5 ledger's record is an extra local record source: the
    // same offline run now attests, still with zero requests.
    write_legacy_ledger(copy, RECORD_PURL, legacy_record(&view));
    let out = run_vex(&binary(), copy, &offline);
    assert_eq!(out.code, Some(0), "{out}");
    assert_attested(out.doc(), PURL, UUID, Marker::Redirected, vulns);
    quiet.assert_no_requests();

    // (4) lock reverted to the registry, that ledger kept: dead claim.
    let tmp2 = tempfile::tempdir().unwrap();
    let reverted = tmp2.path();
    write_project(reverted, pristine_lock);
    std::fs::copy(root.join("pyproject.toml"), reverted.join("pyproject.toml")).unwrap();
    copy_dir(&copy.join(".socket"), &reverted.join(".socket"));
    strip_manifest(reverted);
    for no_verify in [false, true] {
        let out = run_vex(
            &binary(),
            reverted,
            &VexRun {
                no_verify,
                ..online()
            },
        );
        assert_eq!(out.code, Some(1), "no_verify={no_verify}: {out}");
        assert_not_attested(&out.envelope, PURL, "redirect_unwired");
    }
}

/// A pre-v5 ledger record (the `PatchRecord` shape) from a view body.
fn legacy_record(view: &serde_json::Value) -> serde_json::Value {
    let mut record = view.clone();
    let obj = record.as_object_mut().unwrap();
    obj.remove("purl");
    let exported = obj
        .remove("publishedAt")
        .unwrap_or_else(|| serde_json::json!("2024-01-01T00:00:00Z"));
    obj.insert("exportedAt".to_string(), exported);
    obj.entry("description").or_insert_with(|| serde_json::json!("x"));
    obj.entry("license").or_insert_with(|| serde_json::json!("MIT"));
    obj.entry("tier").or_insert_with(|| serde_json::json!("free"));
    record
}

fn copy_dir(from: &Path, to: &Path) {
    if !from.is_dir() {
        return;
    }
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap().flatten() {
        let target = to.join(entry.file_name());
        if entry.path().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

/// Lock-only hosted redirect regression: before the `pdm.lock` inventory
/// reader, a fresh checkout with nothing installed surfaced no package to the
/// batch API, so `redirected` was 0 and nothing was attested.
#[tokio::test]
#[serial]
async fn lock_only_pdm_project_redirects_attests_rescans_and_rolls_back() {
    let server = MockServer::start().await;
    mock_api(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path(), LOCK);
    let lock_path = tmp.path().join("pdm.lock");
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
    assert!(
        redirected.contains(&format!("url = \"{HOSTED_URL}\"")),
        "the package unit gains the hosted url: {redirected}"
    );
    assert!(
        !redirected.contains("urllib3-1.26.18.tar.gz"),
        "the stale registry sdist hash is dropped: {redirected}"
    );
    assert_eq!(
        read(&tmp.path().join("pyproject.toml")),
        PYPROJECT,
        "pyproject untouched"
    );
    assert_no_ledger(tmp.path());
    // The redirect is attested from this run's fetched record even though
    // the base purl the run confirmed differs from the record's qualified
    // purl only by its `?artifact_id=` qualifier (the shared qualifier-strip
    // in vex).
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

    // 3. The committed state, manifest-less, attests (and only while wired).
    assert_manifestless_vex(tmp.path(), LOCK);

    // 4. rollback restores the upstream registry entry.
    let code = rollback_hosted(tmp.path(), &server).await;
    assert_eq!(code, 0, "rollback must succeed");
    assert_eq!(
        read(&lock_path),
        LOCK,
        "rollback must restore the pristine lock byte for byte"
    );
    assert_no_ledger(tmp.path());
}

/// A PDM project whose `pyproject.toml` names `hatchling` as its build
/// backend is still a PDM project. The hatch rewriter claims every pypi uuid
/// for such a project and then yields to the lock without confirming any, so
/// hosted confirmation must key off the pdm rewriter's own report BEFORE the
/// hatch gate can veto it — otherwise the lock is rewritten but nothing is
/// confirmed or attested.
#[tokio::test]
#[serial]
async fn hatchling_build_backend_does_not_veto_the_pdm_lock_redirect() {
    let server = MockServer::start().await;
    mock_api(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path(), LOCK);
    let pyproject = format!(
        "{PYPROJECT}\n[build-system]\nrequires = [\"hatchling\"]\nbuild-backend = \"hatchling.build\"\n"
    );
    std::fs::write(tmp.path().join("pyproject.toml"), &pyproject).unwrap();
    let lock_path = tmp.path().join("pdm.lock");

    let code = run(hosted_args(tmp.path(), server.uri(), None)).await;
    assert_eq!(code, 0, "hosted redirect must succeed");
    let redirected = read(&lock_path);
    assert!(redirected.contains(HOSTED_URL), "{redirected}");
    assert_eq!(
        read(&tmp.path().join("pyproject.toml")),
        pyproject,
        "pyproject untouched"
    );
    assert_no_ledger(tmp.path());
    // Confirmed despite the hatch backend: the record was fetched.
    let views = server
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .filter(|r| r.url.path().ends_with(&format!("/patches/view/{UUID}")))
        .count();
    assert_eq!(views, 1, "the pdm redirect must be confirmed despite the hatch backend");
    assert_manifestless_vex(tmp.path(), LOCK);

    let code = rollback_hosted(tmp.path(), &server).await;
    assert_eq!(code, 0, "rollback must succeed");
    assert_eq!(read(&lock_path), LOCK, "rollback must restore the pristine lock");
}

/// The legacy `[metadata.files]` lock (lock_version 2) redirects the package
/// unit AND the integrity-table entry, and warns about the freshness bug.
#[tokio::test]
#[serial]
async fn legacy_metadata_files_lock_redirects_both_fragments_and_warns() {
    let server = MockServer::start().await;
    mock_api(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path(), LOCK_LEGACY);
    let lock_path = tmp.path().join("pdm.lock");

    let code = run(hosted_args(tmp.path(), server.uri(), None)).await;
    assert_eq!(code, 0);
    let redirected = read(&lock_path);
    assert!(redirected.contains(HOSTED_URL), "{redirected}");
    assert!(
        redirected.contains(&format!("url = \"{HOSTED_URL}\"")),
        "the package unit gains the hosted url: {redirected}"
    );
    assert!(
        redirected.contains(&format!(
            "\"urllib3 1.26.18\" = [{{ file = \"urllib3-1.26.18-py2.py3-none-any.whl\", \
             hash = \"sha256:{}\" }}]",
            sha256()
        )),
        "the [metadata.files] entry pins the patched wheel: {redirected}"
    );
    assert_no_ledger(tmp.path());
    assert_manifestless_vex(tmp.path(), LOCK_LEGACY);

    // rollback restores both fragments byte for byte.
    let code = rollback_hosted(tmp.path(), &server).await;
    assert_eq!(code, 0);
    assert_eq!(read(&lock_path), LOCK_LEGACY, "byte-identical revert");
}

/// `pdm lock` un-patches the lock (registry source restored) and — this is the
/// PDM-specific hazard — can reflow its line endings (CRLF → LF). The re-scan
/// plans from the relocked bytes (v5 keeps no ledger to rebase), and
/// `rollback` lands on the RELOCKED lock: the upstream entry re-resolved in
/// the file's current (LF) line endings, never a stale CRLF fragment.
#[tokio::test]
#[serial]
async fn relock_reflow_then_rescan_keeps_rollback_invertible() {
    // A CRLF checkout that `pdm lock` normalizes to LF, and a pure-LF one.
    for start in ["\r\n", "\n"] {
        let lock = LOCK.replace("\r\n", "\n").replace('\n', start);
        // `pdm lock` output: registry lock, always LF, patch dropped.
        let relocked = LOCK.replace("\r\n", "\n");
        assert_relock_roundtrip(&lock, &relocked).await;
    }
}

async fn assert_relock_roundtrip(lock: &str, relocked: &str) {
    let server = MockServer::start().await;
    mock_api(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path(), lock);
    let lock_path = tmp.path().join("pdm.lock");

    assert_eq!(run(hosted_args(tmp.path(), server.uri(), None)).await, 0);
    let redirected = read(&lock_path);
    assert!(redirected.contains(HOSTED_URL));
    assert_no_ledger(tmp.path());

    // The user runs `pdm lock`: the patch is gone and the file is LF now.
    assert!(!relocked.contains(HOSTED_URL), "relock un-patches the lock");
    std::fs::write(&lock_path, relocked).unwrap();

    // Re-scan re-applies from the relocked bytes.
    assert_eq!(run(hosted_args(tmp.path(), server.uri(), None)).await, 0);
    let rescanned = read(&lock_path);
    assert!(rescanned.contains(HOSTED_URL), "the re-scan re-redirects");
    assert!(
        !rescanned.contains('\r'),
        "the re-scan keeps the relocked LF line endings"
    );
    assert_no_ledger(tmp.path());
    // The re-redirected (relocked) lock attests; reverting to the relocked
    // registry lock unwires it.
    assert_manifestless_vex(tmp.path(), relocked);

    // rollback lands on the relocked (LF, registry) lock — the user's `pdm
    // lock` is preserved, only the Socket patch is unwound.
    let code = rollback_hosted(tmp.path(), &server).await;
    assert_eq!(code, 0, "rollback after relock + re-scan must succeed");
    assert_eq!(
        read(&lock_path),
        relocked,
        "rollback restores the relocked lock byte for byte"
    );
}
