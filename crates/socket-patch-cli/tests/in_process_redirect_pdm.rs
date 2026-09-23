//! In-process CLI test for `scan --mode hosted` on a PDM project: mocks the API
//! (discovery + reference + view) via wiremock, lays down a native `pdm.lock`
//! (the committed backtest fixtures) with NO installed package — the lock-only
//! fresh-checkout / CI shape — and asserts the lock is repointed at the hosted
//! wheel, the redirect ledger is written, the same-run `--vex` attests the
//! redirect, a re-scan is idempotent, and `rollback` restores every byte. It
//! also covers the PDM-specific relock convergence: `pdm lock` un-patches the
//! lock AND can reflow its line endings (CRLF → LF), so a re-scan must rebase
//! the ledger onto the relocked bytes — adopting the fresh `original` — for
//! `rollback` to still land on the relocked lock. The rewriter bytes themselves
//! are pinned by the core `utils::pdm_lock` tests; this covers the CLI wiring.
//!
//! Every flow ends with the MANIFEST-LESS VEX step ([`assert_manifestless_vex`],
//! the shared `vex_e2e_common` helper): a fresh copy of the committed state
//! (pyproject + lock + `.socket/`, never a manifest in hosted mode) attests the
//! redirect from the ledger offline, from the lock + patch API with the ledger
//! gone (`--patch-server-url` admits the fixture's non-Socket host), omits it
//! `record_unavailable` offline with no ledger (zero requests), and omits it
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
    assert_attested, assert_not_attested, binary, git_sha256, patch_view, run_vex, strip_ledgers,
    strip_manifest, Marker, PatchApi, VexRun,
};

const ORG: &str = "test-org";
/// Discovery names the base purl (the lock inventory's spelling)…
const PURL: &str = "pkg:pypi/urllib3@1.26.18";
/// …while the patch record carries the API's artifact-qualified purl, which is
/// what the redirect ledger is keyed by.
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
    let api = PatchApi::start(vec![(
        UUID.to_string(),
        patch_view(
            UUID,
            RECORD_PURL,
            &[("urllib3/response.py", &git_sha256(PATCHED))],
            vulns,
        ),
    )]);
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

    // (1) ledger kept: attested offline from the ledger record (zero
    // network), and online. Nothing is installed, so the basis is the
    // lock's sha256 pin — which counts only once `--patch-server-url` makes
    // the lock's url a discovered hosted reference.
    let offline_ledger = VexRun {
        offline: true,
        patch_server_url: Some(PATCH_SERVER.to_string()),
        ..VexRun::default()
    };
    for (i, run) in [offline_ledger, online()].into_iter().enumerate() {
        let out = run_vex(&binary(), copy, &run);
        assert_eq!(out.code, Some(0), "{out}");
        assert_attested(out.doc(), PURL, UUID, Marker::Redirected, vulns);
        if i == 0 {
            api.assert_no_requests();
        }
    }

    // (2) ledgers gone: the lock alone, the record from the patch API.
    strip_ledgers(copy);
    let out = run_vex(&binary(), copy, &online());
    assert_eq!(out.code, Some(0), "{out}");
    assert_attested(out.doc(), PURL, UUID, Marker::Redirected, vulns);
    assert!(api.view_requests(UUID) >= 1, "{:?}", api.requests());
    // …and without `--patch-server-url` the non-Socket host is no reference.
    let out = run_vex(&binary(), copy, &VexRun::online(&api));
    assert_eq!(out.code, Some(2), "{out}");
    assert_eq!(out.envelope["error"]["code"], "manifest_not_found", "{out}");

    // (3) offline with no ledger: nothing local to attest from, no network.
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

    // (4) lock reverted to the registry, ledger kept: dead claim.
    let tmp2 = tempfile::tempdir().unwrap();
    let reverted = tmp2.path();
    write_project(reverted, pristine_lock);
    std::fs::copy(root.join("pyproject.toml"), reverted.join("pyproject.toml")).unwrap();
    copy_dir(&root.join(".socket"), &reverted.join(".socket"));
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

fn copy_dir(from: &Path, to: &Path) {
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
    let ledger: serde_json::Value =
        serde_json::from_str(&read(&tmp.path().join(".socket/vendor/redirect-state.json"))).unwrap();
    assert!(
        ledger["records"][RECORD_PURL].is_object(),
        "ledger keyed by the artifact-qualified purl: {ledger}"
    );
    assert_eq!(
        ledger["edits"][0]["kind"].as_str(),
        Some("redirect_pdm_lock_package"),
        "{ledger}"
    );
    // The redirect is attested from the ledger even though the base purl the
    // run confirmed differs from the record's qualified purl only by its
    // `?artifact_id=` qualifier (the shared qualifier-strip in vex).
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

    // 4. rollback unwinds the redirect and drops the record.
    let code = rollback::run(RollbackArgs {
        targets: Vec::new(),
        common: global(tmp.path(), server.uri()),
        one_off: false,
        preserve_state: false,
    })
    .await;
    assert_eq!(code, 0, "rollback must succeed");
    assert_eq!(
        read(&lock_path),
        LOCK,
        "rollback must restore the pristine lock byte for byte"
    );
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

/// A PDM project whose `pyproject.toml` names `hatchling` as its build
/// backend is still a PDM project. The hatch rewriter claims every pypi uuid
/// for such a project and then yields to the lock without confirming any, so
/// hosted confirmation must key off the pdm rewriter's own report BEFORE the
/// hatch gate can veto it — otherwise the lock is rewritten but nothing is
/// recorded or attested.
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
    let ledger: serde_json::Value =
        serde_json::from_str(&read(&tmp.path().join(".socket/vendor/redirect-state.json"))).unwrap();
    assert!(
        ledger["records"][RECORD_PURL].is_object(),
        "the pdm redirect must be confirmed and recorded despite the hatch backend: {ledger}"
    );
    assert_eq!(
        ledger["edits"][0]["kind"].as_str(),
        Some("redirect_pdm_lock_package"),
        "{ledger}"
    );
    assert_manifestless_vex(tmp.path(), LOCK);

    let code = rollback::run(RollbackArgs {
        targets: Vec::new(),
        common: global(tmp.path(), server.uri()),
        one_off: false,
        preserve_state: false,
    })
    .await;
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
    let ledger: serde_json::Value =
        serde_json::from_str(&read(&tmp.path().join(".socket/vendor/redirect-state.json"))).unwrap();
    assert_eq!(
        ledger["edits"].as_array().unwrap().len(),
        2,
        "package unit + [metadata.files] entry: {ledger}"
    );
    assert_manifestless_vex(tmp.path(), LOCK_LEGACY);

    // rollback restores both fragments byte for byte.
    let code = rollback::run(RollbackArgs {
        targets: Vec::new(),
        common: global(tmp.path(), server.uri()),
        one_off: false,
        preserve_state: false,
    })
    .await;
    assert_eq!(code, 0);
    assert_eq!(read(&lock_path), LOCK_LEGACY, "byte-identical revert");
}

/// `pdm lock` un-patches the lock (registry source restored) and — this is the
/// PDM-specific hazard — can reflow its line endings (CRLF → LF). The re-scan
/// must rebase the ledger onto the relocked bytes, adopting the fresh
/// `original`, so `rollback` lands on the RELOCKED lock rather than restoring a
/// stale CRLF fragment into an LF file. Appending instead would leave a chain
/// whose older link matches nothing and make rollback refuse.
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
    let ledger_path = tmp.path().join(".socket/vendor/redirect-state.json");
    let before: serde_json::Value = serde_json::from_str(&read(&ledger_path)).unwrap();
    let n_edits = before["edits"].as_array().unwrap().len();

    // The user runs `pdm lock`: the patch is gone and the file is LF now.
    assert!(!relocked.contains(HOSTED_URL), "relock un-patches the lock");
    std::fs::write(&lock_path, relocked).unwrap();

    // Re-scan re-applies and rebases the ledger (no appended chain).
    assert_eq!(run(hosted_args(tmp.path(), server.uri(), None)).await, 0);
    let rescanned = read(&lock_path);
    assert!(rescanned.contains(HOSTED_URL), "the re-scan re-redirects");
    let after: serde_json::Value = serde_json::from_str(&read(&ledger_path)).unwrap();
    let edits = after["edits"].as_array().unwrap();
    assert_eq!(edits.len(), n_edits, "rebased, not appended: {after}");
    for edit in edits {
        let original = edit["original"].as_str().unwrap();
        assert!(
            !original.contains(HOSTED_URL),
            "originals describe the relocked registry lock: {original}"
        );
        assert!(
            rescanned.contains(edit["new"].as_str().unwrap()),
            "new fragments describe the current lock: {after}"
        );
    }
    // The rebased ledger + re-redirected (relocked) lock attest; reverting
    // to the relocked registry lock unwires it.
    assert_manifestless_vex(tmp.path(), relocked);

    // rollback lands on the relocked (LF, registry) lock — the user's `pdm
    // lock` is preserved, only the Socket patch is unwound.
    let code = rollback::run(RollbackArgs {
        targets: Vec::new(),
        common: global(tmp.path(), server.uri()),
        one_off: false,
        preserve_state: false,
    })
    .await;
    assert_eq!(code, 0, "rollback after relock + re-scan must succeed");
    assert_eq!(
        read(&lock_path),
        relocked,
        "rollback restores the relocked lock byte for byte"
    );
}
