//! In-process tests for `socket-patch scan --mode hosted` against a pnpm
//! (lockfileVersion 9.0) ROOT lock — the pnpm counterpart of the npm legs in
//! `tests/in_process_redirect.rs`. Mocks the API (discovery + reference +
//! view) via wiremock, lays down a pnpm project whose only lockfile is a root
//! `pnpm-lock.yaml`, runs the redirect, and asserts the patched package's
//! `resolution:` was spliced to `{integrity: sha512-<patched>, tarball:
//! <hosted url>}` (the shape the shared golden `npm/pnpm` fixture pins) — and,
//! v5, that no redirect ledger is written: `rollback` restores the upstream
//! entry from the (mocked) npm registry instead.
//!
//! `in_process_redirect.rs` covers pnpm ONLY through the Rush nested-lock
//! path; these tests pin the plain single-project pnpm root-lock rewrite plus
//! its idempotency and the `--vex` `(redirected)` attestation.

use serial_test::serial;
use socket_patch_cli::commands::rollback::{self, RollbackArgs};
use socket_patch_cli::commands::scan::{run, ScanArgs, ScanMode};
use std::path::Path;

#[path = "vex_e2e_common/mod.rs"]
mod vex_e2e_common;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";
const NAME: &str = "in-proc-redirect-pnpm";
const VERSION: &str = "1.0.0";
const PURL: &str = "pkg:npm/in-proc-redirect-pnpm@1.0.0";
const UUID: &str = "11111111-1111-4111-8111-111111111111";
const HOSTED_URL: &str = "http://patch.test/patch/npm/in-proc-redirect-pnpm/1.0.0/22222222-2222-4222-8222-222222222222/11111111-1111-4111-8111-111111111111/in-proc-redirect-pnpm-1.0.0.tgz";
const PATCHED_SHA512: &str = "sha512-PATCHEDpatchedPATCHEDpatched0123456789==";
const UPSTREAM_SHA512: &str = "sha512-UPSTREAMupstream==";
const GHSA: &str = "GHSA-rdir-pnpm-bbbb";

fn assert_no_ledger(root: &Path) {
    assert!(
        !root.join(".socket/vendor/redirect-state.json").exists(),
        "v5 hosted mode writes no redirect ledger"
    );
}

/// In-process `rollback` of the hosted pin: the mock patch host is named by
/// `--patch-server-url` (so discovery finds the pin) and the upstream restore
/// re-resolves `NAME@VERSION` from a mocked npm registry serving
/// `UPSTREAM_SHA512`.
async fn rollback_hosted(cwd: &Path, server: &MockServer) -> i32 {
    Mock::given(method("GET"))
        .and(path(format!("/npm-registry/{NAME}/{VERSION}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": NAME,
            "version": VERSION,
            "dist": {
                "tarball": format!("{}/npm-registry/{NAME}/-/{NAME}-{VERSION}.tgz", server.uri()),
                "integrity": UPSTREAM_SHA512,
            }
        })))
        .mount(server)
        .await;
    std::env::set_var("SOCKET_NPM_REGISTRY", format!("{}/npm-registry", server.uri()));
    let code = rollback::run(RollbackArgs {
        targets: Vec::new(),
        common: socket_patch_cli::args::GlobalArgs {
            cwd: cwd.to_path_buf(),
            json: true,
            yes: true,
            silent: true,
            patch_server_url: Some("http://patch.test".to_string()),
            ..socket_patch_cli::args::GlobalArgs::default()
        },
        preserve_state: false,
    })
    .await;
    std::env::remove_var("SOCKET_NPM_REGISTRY");
    code
}

/// `--mode hosted`.
fn hosted_args(cwd: &Path, api_url: String) -> ScanArgs {
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
        prune: false,
        sync: false,
        mode: Some(ScanMode::Hosted),
        all_releases: false,
        vex: Default::default(),
        rollout: Default::default(),
    }
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
                    "title": "pnpm redirect fixture"
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

/// `view/{uuid}` — the patch record the in-run VEX attests from (in memory).
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
                    "summary": "pnpm redirect vex fixture",
                    "severity": "high",
                    "description": "d"
                }
            },
            "description": "x", "license": "MIT", "tier": "free"
        })))
        .mount(server)
        .await;
}

/// A pnpm project whose only lockfile is a lockfileVersion 9.0 root
/// `pnpm-lock.yaml` resolving the patched package under `packages:` (the
/// shape the shared `npm/pnpm` golden fixture uses). An installed
/// `node_modules/<NAME>` copy makes the crawler discover it directly (a real
/// pnpm project always has one).
fn write_pnpm_project(root: &Path) {
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
    std::fs::write(
        root.join("pnpm-lock.yaml"),
        format!(
            "lockfileVersion: '9.0'

importers:
  .:
    dependencies:
      {NAME}:
        specifier: {VERSION}
        version: {VERSION}

packages:
  {NAME}@{VERSION}:
    resolution: {{integrity: {UPSTREAM_SHA512}}}

snapshots:
  {NAME}@{VERSION}: {{}}
"
        ),
    )
    .unwrap();
}

/// (a) The pnpm root-lock rewrite: the `resolution:` for the patched package
/// gains the `tarball:` key pointing at the hosted patch and its integrity
/// becomes the patched sha512, the upstream integrity is gone, no ledger is
/// written, a second run is a byte-stable no-op, and `rollback` restores the
/// pristine lock AND removes the auto-created pnpm-workspace.yaml.
#[tokio::test]
#[serial]
async fn hosted_rewrites_pnpm_root_lock_resolution() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_pnpm_project(tmp.path());
    let pristine_lock = std::fs::read_to_string(tmp.path().join("pnpm-lock.yaml")).unwrap();

    let code = run(hosted_args(tmp.path(), server.uri())).await;
    assert_eq!(code, 0, "scan --mode hosted should succeed for pnpm");

    let lock = std::fs::read_to_string(tmp.path().join("pnpm-lock.yaml")).unwrap();
    // The resolution is spliced to `{integrity: <patched>, tarball: <hosted>}`
    // (golden `npm/pnpm` shape): assert the tarball key, the hosted URL, and
    // the patched integrity all landed on the resolution line.
    assert!(
        lock.contains(&format!("tarball: {HOSTED_URL}")),
        "resolution must carry the hosted tarball; got:\n{lock}"
    );
    assert!(
        lock.contains(PATCHED_SHA512),
        "resolution integrity must be the patched sha512; got:\n{lock}"
    );
    assert!(
        !lock.contains("UPSTREAMupstream"),
        "the upstream integrity must be replaced; got:\n{lock}"
    );
    // The importer specifier/version and snapshot key are untouched — only the
    // `resolution:` line is spliced (pnpm keys off `name@version`).
    assert!(
        lock.contains(&format!("{NAME}@{VERSION}:"))
            && lock.contains(&format!("specifier: {VERSION}")),
        "the importer/snapshot keys must be preserved; got:\n{lock}"
    );

    assert_no_ledger(tmp.path());

    // Zero-touch trust config: a rewritten root v9 lock auto-creates
    // pnpm-workspace.yaml with the root-only scaffold + `trustLockfile: true`
    // (pnpm >=11 rejects the redirected lock without it; 9/10 ignore the
    // key).
    let ws_path = tmp.path().join("pnpm-workspace.yaml");
    let ws = std::fs::read_to_string(&ws_path)
        .expect("the redirect must auto-create pnpm-workspace.yaml");
    assert_eq!(
        ws, "packages:\n  - '.'\ntrustLockfile: true\n",
        "created workspace file must be the scaffold + trust key"
    );

    // Idempotency: a second run rewrites nothing — the lock and the
    // auto-created workspace file stay byte-stable.
    let pristine = pristine_lock;
    let code = run(hosted_args(tmp.path(), server.uri())).await;
    assert_eq!(code, 0, "second scan --mode hosted should succeed");
    let lock_after_rerun = std::fs::read_to_string(tmp.path().join("pnpm-lock.yaml")).unwrap();
    assert_eq!(
        lock, lock_after_rerun,
        "the re-run must leave the lock byte-stable"
    );
    assert_eq!(
        std::fs::read_to_string(&ws_path).unwrap(),
        ws,
        "the re-run must leave pnpm-workspace.yaml byte-stable"
    );
    assert_no_ledger(tmp.path());

    // rollback: the upstream entry comes back from the registry, and the
    // trust key the run added (here: the whole scaffold file) goes with it.
    let code = rollback_hosted(tmp.path(), &server).await;
    assert_eq!(code, 0, "rollback must restore the pnpm pin");
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("pnpm-lock.yaml")).unwrap(),
        pristine,
        "rollback restores the pristine lock byte for byte"
    );
    assert!(
        !ws_path.exists(),
        "the auto-created pnpm-workspace.yaml is removed with the pin"
    );
    assert_no_ledger(tmp.path());
}

/// MERGE case: a pre-existing pnpm-workspace.yaml (comments, multi-glob
/// packages, catalog — none of it ours) gains EXACTLY one appended
/// `trustLockfile: true` line after its last non-empty line; every other
/// byte survives verbatim. v5 keeps no ledger record of that edit, so
/// `rollback` cannot prove the line is ours: it restores the lock entry and
/// leaves the user's file (trust line included) alone, warning
/// `pnpm_trust_lockfile_left` instead of guessing.
#[tokio::test]
#[serial]
async fn hosted_merges_trust_key_into_existing_workspace_yaml_byte_exactly() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_pnpm_project(tmp.path());
    let user_ws =
        "# team workspace\npackages:\n  - '.'\n  - 'tools/*'\n\ncatalog:\n  react: ^18.0.0\n";
    std::fs::write(tmp.path().join("pnpm-workspace.yaml"), user_ws).unwrap();

    let code = run(hosted_args(tmp.path(), server.uri())).await;
    assert_eq!(code, 0, "scan --mode hosted should succeed");

    let ws = std::fs::read_to_string(tmp.path().join("pnpm-workspace.yaml")).unwrap();
    assert_eq!(
        ws,
        "# team workspace\npackages:\n  - '.'\n  - 'tools/*'\n\ncatalog:\n  react: ^18.0.0\ntrustLockfile: true\n",
        "the merge must preserve every user byte and append exactly one line"
    );
    assert_no_ledger(tmp.path());

    let code = rollback_hosted(tmp.path(), &server).await;
    assert_eq!(code, 0, "rollback must restore the pnpm pin");
    assert!(
        !std::fs::read_to_string(tmp.path().join("pnpm-lock.yaml"))
            .unwrap()
            .contains(HOSTED_URL),
        "the pin is restored upstream"
    );
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("pnpm-workspace.yaml")).unwrap(),
        ws,
        "a user-authored workspace file is never edited by the restore"
    );
}

/// #400 / #402: a workspace file the trust edit must not append to — an
/// explicit opt-out spelled with a quoted key, a `trustLockfile : false`
/// key, or a flow-style document — is left byte-identical (no duplicate key,
/// no block line after a flow mapping), while the lock is still redirected.
/// A `...`-terminated file gains the key inside the document.
#[tokio::test]
#[serial]
async fn hosted_trust_edit_reads_the_workspace_yaml_shape() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;

    for (user_ws, want) in [
        ("packages:\n  - '.'\n\"trustLockfile\": false\n", None),
        ("packages:\n  - '.'\ntrustLockfile : false\n", None),
        ("{packages: [.]}\n", None),
        (
            "packages:\n  - '.'\n...\n",
            Some("packages:\n  - '.'\ntrustLockfile: true\n...\n"),
        ),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        write_pnpm_project(tmp.path());
        std::fs::write(tmp.path().join("pnpm-workspace.yaml"), user_ws).unwrap();

        let code = run(hosted_args(tmp.path(), server.uri())).await;
        assert_eq!(code, 0, "scan --mode hosted should succeed for {user_ws:?}");
        assert!(
            std::fs::read_to_string(tmp.path().join("pnpm-lock.yaml"))
                .unwrap()
                .contains(HOSTED_URL),
            "the lock is still redirected for {user_ws:?}"
        );
        assert_eq!(
            std::fs::read_to_string(tmp.path().join("pnpm-workspace.yaml")).unwrap(),
            want.unwrap_or(user_ws),
            "workspace file for {user_ws:?}"
        );
    }
}

/// #903 / #904: a `pnpm-lock.yaml` and `pnpm-workspace.yaml` saved with a
/// UTF-8 BOM read like their plain twins. The BOM lock gets the
/// `trustLockfile: true` auto-config (it used to read as unversioned and
/// skip it), `rollback` unwinds the pin it just wrote (it used to refuse the
/// lock as "not a pnpm lockfile") byte-exact, BOM included, and a BOM first
/// `trustLockfile: false` key is the user's explicit opt-out, not a missing
/// key a duplicate is appended after.
#[tokio::test]
#[serial]
async fn hosted_bom_lock_and_workspace_read_like_their_plain_twins() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;

    // A BOM lock, no workspace file: the trust scaffold is created and the
    // rollback restores the lock byte for byte.
    let tmp = tempfile::tempdir().unwrap();
    write_pnpm_project(tmp.path());
    let lock_path = tmp.path().join("pnpm-lock.yaml");
    let pristine = format!("\u{feff}{}", std::fs::read_to_string(&lock_path).unwrap());
    std::fs::write(&lock_path, &pristine).unwrap();

    let code = run(hosted_args(tmp.path(), server.uri())).await;
    assert_eq!(code, 0, "scan --mode hosted should succeed on a BOM lock");
    let lock = std::fs::read_to_string(&lock_path).unwrap();
    assert!(lock.starts_with("\u{feff}lockfileVersion:"), "{lock}");
    assert!(lock.contains(HOSTED_URL), "the BOM lock is redirected: {lock}");
    let ws_path = tmp.path().join("pnpm-workspace.yaml");
    assert_eq!(
        std::fs::read_to_string(&ws_path).ok().as_deref(),
        Some("packages:\n  - '.'\ntrustLockfile: true\n"),
        "a BOM v9 lock gets the trustLockfile auto-config"
    );

    let code = rollback_hosted(tmp.path(), &server).await;
    assert_eq!(code, 0, "rollback must unwind the pin on a BOM lock");
    assert_eq!(
        std::fs::read_to_string(&lock_path).unwrap(),
        pristine,
        "rollback restores the BOM lock byte for byte"
    );
    assert!(!ws_path.exists(), "the auto-created workspace file goes too");

    // A BOM workspace file whose first key is the user's opt-out: left
    // byte-identical (no duplicate `trustLockfile`), lock still redirected.
    // One whose first key is something else gains the key once, BOM kept.
    for (user_ws, want) in [
        ("\u{feff}trustLockfile: false\npackages:\n  - '.'\n", None),
        ("\u{feff}trustLockfile: true\npackages:\n  - '.'\n", None),
        (
            "\u{feff}packages:\n  - '.'\n",
            Some("\u{feff}packages:\n  - '.'\ntrustLockfile: true\n"),
        ),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        write_pnpm_project(tmp.path());
        std::fs::write(tmp.path().join("pnpm-workspace.yaml"), user_ws).unwrap();

        let code = run(hosted_args(tmp.path(), server.uri())).await;
        assert_eq!(code, 0, "scan --mode hosted should succeed for {user_ws:?}");
        assert!(
            std::fs::read_to_string(tmp.path().join("pnpm-lock.yaml"))
                .unwrap()
                .contains(HOSTED_URL),
            "the lock is still redirected for {user_ws:?}"
        );
        let ws = std::fs::read_to_string(tmp.path().join("pnpm-workspace.yaml")).unwrap();
        assert_eq!(ws, want.unwrap_or(user_ws), "workspace file for {user_ws:?}");
        assert_eq!(ws.matches("trustLockfile").count(), 1, "{ws:?}");
    }
}

/// `--dry-run` previews: NOTHING lands on disk — no lock rewrite, no
/// pnpm-workspace.yaml, no ledger — while the envelope still reports both
/// files as would-be-rewritten (`dryRun: true`).
#[tokio::test]
#[serial]
async fn hosted_dry_run_writes_neither_lock_nor_workspace_trust() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_pnpm_project(tmp.path());
    let lock_before = std::fs::read(tmp.path().join("pnpm-lock.yaml")).unwrap();

    let mut args = hosted_args(tmp.path(), server.uri());
    args.common.dry_run = true;
    let code = run(args).await;
    assert_eq!(code, 0, "dry-run scan --mode hosted should succeed");

    assert_eq!(
        std::fs::read(tmp.path().join("pnpm-lock.yaml")).unwrap(),
        lock_before,
        "dry-run must leave the lock byte-identical"
    );
    assert!(
        !tmp.path().join("pnpm-workspace.yaml").exists(),
        "dry-run must not create pnpm-workspace.yaml"
    );
    assert!(
        !tmp.path()
            .join(".socket/vendor/redirect-state.json")
            .exists(),
        "dry-run must not write the redirect ledger"
    );
}

/// LEGACY lock (pnpm 8's lockfileVersion '6.0', byte-real matrix shape): the
/// plain `/name@version:` key stays redirectable, but the trustLockfile
/// auto-config must NOT fire — pnpm 7/8 have neither the >=11 policy nor the
/// flag, so writing trust config for them would be pure noise. No
/// pnpm-workspace.yaml appears (and no ledger is written) — no workspace-trust
/// edit.
#[tokio::test]
#[serial]
async fn hosted_legacy_v6_lock_gets_no_workspace_trust_config() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
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
    // The v6 shape pnpm 8 emits (matrix hosted-pnpm8): quoted '6.0',
    // `/name@version:` package key.
    std::fs::write(
        root.join("pnpm-lock.yaml"),
        format!(
            "lockfileVersion: '6.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

dependencies:
  {NAME}:
    specifier: {VERSION}
    version: {VERSION}

packages:

  /{NAME}@{VERSION}:
    resolution: {{integrity: {UPSTREAM_SHA512}}}
    dev: false
"
        ),
    )
    .unwrap();

    let code = run(hosted_args(root, server.uri())).await;
    assert_eq!(code, 0, "scan --mode hosted should succeed on a v6 lock");

    let lock = std::fs::read_to_string(root.join("pnpm-lock.yaml")).unwrap();
    assert!(
        lock.contains(&format!("tarball: {HOSTED_URL}")),
        "anchor: the v6 lock must still be redirected; got:\n{lock}"
    );
    assert!(
        !root.join("pnpm-workspace.yaml").exists(),
        "a legacy v6 lock must not trigger the trustLockfile auto-config"
    );
    assert_no_ledger(root);
}

/// (a2) SCOPED package: pnpm lockfileVersion 9 single-quotes `packages:` keys
/// that begin with `@` (`'@scope/name@1.0.0':` — YAML forbids a plain scalar
/// starting with `@`; verified against pnpm 10 output), and the API serves
/// scoped purls percent-encoded (`pkg:npm/%40scope/name@version`). The
/// rewriter must splice the resolution under the QUOTED key, and the run must
/// count the dep as redirected (ledger edit present) — a silent
/// entry-not-found here would leave every scoped npm package unredirected.
#[tokio::test]
#[serial]
async fn hosted_rewrites_pnpm_quoted_scoped_key() {
    const SCOPED_NAME: &str = "@socktest/in-proc-redirect-pnpm";
    const SCOPED_PURL: &str = "pkg:npm/%40socktest/in-proc-redirect-pnpm@1.0.0";
    const SCOPED_HOSTED_URL: &str = "http://patch.test/patch/npm/%40socktest/in-proc-redirect-pnpm/1.0.0/22222222-2222-4222-8222-222222222222/11111111-1111-4111-8111-111111111111/in-proc-redirect-pnpm-1.0.0.tgz";

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": SCOPED_PURL,
                "patches": [{
                    "uuid": UUID, "purl": SCOPED_PURL, "tier": "free",
                    "cveIds": [], "ghsaIds": [], "severity": "high",
                    "title": "pnpm scoped redirect fixture"
                }]
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(format!(
            "^/v0/orgs/{ORG}/patches/by-package/.+$"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [{
                "uuid": UUID, "purl": SCOPED_PURL,
                "publishedAt": "2024-01-01T00:00:00Z",
                "description": "x", "license": "MIT", "tier": "free",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "results": {
                UUID: {
                    "status": "granted",
                    "url": SCOPED_HOSTED_URL,
                    "purl": SCOPED_PURL,
                    "artifacts": [{
                        "kind": "tarball",
                        "url": SCOPED_HOSTED_URL,
                        "integrity": { "sha512": PATCHED_SHA512 }
                    }],
                    "registryOverride": null
                }
            }
        })))
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    std::fs::write(
        root.join("package.json"),
        format!(
            r#"{{ "name": "consumer", "version": "0.0.0", "dependencies": {{ "{SCOPED_NAME}": "{VERSION}" }} }}"#
        ),
    )
    .unwrap();
    let pkg = root.join("node_modules").join(SCOPED_NAME);
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        pkg.join("package.json"),
        format!(r#"{{ "name": "{SCOPED_NAME}", "version": "{VERSION}" }}"#),
    )
    .unwrap();
    // The quoted-key shape below is byte-for-byte what pnpm 10 (lockfile 9.0)
    // emits for a scoped dependency.
    std::fs::write(
        root.join("pnpm-lock.yaml"),
        format!(
            "lockfileVersion: '9.0'

importers:
  .:
    dependencies:
      '{SCOPED_NAME}':
        specifier: {VERSION}
        version: {VERSION}

packages:

  '{SCOPED_NAME}@{VERSION}':
    resolution: {{integrity: {UPSTREAM_SHA512}}}

snapshots:

  '{SCOPED_NAME}@{VERSION}': {{}}
"
        ),
    )
    .unwrap();

    let code = run(hosted_args(root, server.uri())).await;
    assert_eq!(code, 0, "scan --mode hosted should succeed for scoped pnpm");

    let lock = std::fs::read_to_string(root.join("pnpm-lock.yaml")).unwrap();
    assert!(
        lock.contains(&format!(
            "  '{SCOPED_NAME}@{VERSION}':\n    resolution: {{integrity: {PATCHED_SHA512}, tarball: {SCOPED_HOSTED_URL}}}"
        )),
        "the QUOTED scoped key's resolution must be spliced (quotes preserved); got:\n{lock}"
    );
    assert!(
        !lock.contains("UPSTREAMupstream"),
        "the upstream integrity must be replaced; got:\n{lock}"
    );

    assert_no_ledger(root);
}

/// (b) `scan --mode hosted --vex`: the redirected pnpm patch is attested with
/// the `(redirected)` provenance marker (bytes are remote until install, so
/// this is the NO-VERIFY attestation built from this run's fetched record — the same
/// contract `scan_redirect_vex_emits_redirected_attestation` pins for npm).
#[tokio::test]
#[serial]
async fn hosted_pnpm_vex_emits_redirected_attestation() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    mock_view(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_pnpm_project(tmp.path());

    let vex_path = tmp.path().join("out.vex.json");
    let mut args = hosted_args(tmp.path(), server.uri());
    args.vex = socket_patch_cli::commands::vex::VexEmbedArgs {
        vex: Some(vex_path.clone()),
        vex_product: Some("pkg:npm/consumer@0.0.0".to_string()),
        ..Default::default()
    };

    let code = run(args).await;
    assert_eq!(code, 0, "scan --mode hosted --vex should succeed for pnpm");

    // The record reached the attestation in memory: nothing persisted.
    assert_no_ledger(tmp.path());

    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&vex_path).unwrap()).unwrap();
    let stmts = doc["statements"].as_array().unwrap();
    assert_eq!(
        stmts.len(),
        1,
        "the redirected pnpm patch must be attested: {doc}"
    );
    assert_eq!(stmts[0]["vulnerability"]["name"], GHSA);
    assert_eq!(stmts[0]["status"], "not_affected");
    assert_eq!(stmts[0]["products"][0]["subcomponents"][0]["@id"], PURL);
    let impact = stmts[0]["impact_statement"].as_str().unwrap();
    assert!(
        impact.contains("(redirected)"),
        "the attestation must carry the (redirected) marker: {impact}"
    );
}

/// Manifest-less VEX after the in-process hosted rewrite of a v9 root lock
/// AND a legacy shrinkwrap-3 lock (pnpm 1/2): the project carries no
/// manifest (hosted mode never writes one), the hosted URL sits on the
/// operator's patch server (`--patch-server-url http://patch.test`).
///
/// * not installed, no ledger (v5): the lockfile reference + the patch API
///   record attest `(redirected)` from the integrity pin, then
///   hash-verified against an installed copy;
/// * `--offline`, no local record: `record_unavailable`, zero requests;
/// * a pre-v5 ledger carrying the record serves the offline run;
/// * lock reverted, that ledger kept: `redirect_unwired`, `--no-verify` too.
#[tokio::test]
#[serial]
async fn hosted_pnpm_manifestless_vex_from_lockfile_legacy_ledger_and_api() {
    use vex_e2e_common::{
        assert_absent, assert_attested, assert_not_attested, git_sha256, patch_view, run_vex,
        strip_manifest, Marker, PatchApi, VexRun,
    };
    const PATCHED: &[u8] = b"/* patched */\nmodule.exports = 1;\n";
    let vulns: &[(&str, &[&str])] = &[(GHSA, &["CVE-2024-9"])];

    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    mock_view(&server).await;

    for legacy in [false, true] {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        write_pnpm_project(root);
        let lock_name = if legacy {
            std::fs::remove_file(root.join("pnpm-lock.yaml")).unwrap();
            std::fs::write(
                root.join("shrinkwrap.yaml"),
                format!(
                    "dependencies:\n  {NAME}: {VERSION}\npackages:\n  /{NAME}/{VERSION}:\n    dev: false\n    resolution:\n      integrity: {UPSTREAM_SHA512}\nregistry: 'https://registry.npmjs.org/'\nshrinkwrapMinorVersion: 9\nshrinkwrapVersion: 3\nspecifiers:\n  {NAME}: {VERSION}\n"
                ),
            )
            .unwrap();
            "shrinkwrap.yaml"
        } else {
            "pnpm-lock.yaml"
        };
        let pristine = std::fs::read(root.join(lock_name)).unwrap();
        let code = run(hosted_args(root, server.uri())).await;
        assert_eq!(code, 0, "scan --mode hosted ({lock_name})");
        let wired = std::fs::read_to_string(root.join(lock_name)).unwrap();
        assert!(wired.contains(HOSTED_URL), "{wired}");
        assert!(!root.join(".socket/manifest.json").exists());

        std::thread::scope(|s| {
            s.spawn(|| {
                let bin = vex_e2e_common::binary();
                let view = patch_view(
                    UUID,
                    PURL,
                    &[("package/index.js", &git_sha256(PATCHED))],
                    vulns,
                );
                let api = PatchApi::start(vec![(UUID.to_string(), view.clone())]);
                let online = |no_verify| VexRun {
                    patch_server_url: Some("http://patch.test".to_string()),
                    no_verify,
                    ..VexRun::online(&api)
                };
                strip_manifest(root);
                assert_no_ledger(root);
                std::fs::remove_dir_all(root.join("node_modules")).unwrap();
                let out = run_vex(&bin, root, &online(false));
                assert_eq!(out.code, Some(0), "[{lock_name}] ledger-less: {out}");
                assert_attested(out.doc(), PURL, UUID, Marker::Redirected, vulns);
                assert!(api.view_requests(UUID) >= 1);
                let pkg = root.join("node_modules").join(NAME);
                std::fs::create_dir_all(&pkg).unwrap();
                std::fs::write(
                    pkg.join("package.json"),
                    format!(r#"{{ "name": "{NAME}", "version": "{VERSION}" }}"#),
                )
                .unwrap();
                std::fs::write(pkg.join("index.js"), PATCHED).unwrap();
                let out = run_vex(&bin, root, &online(false));
                assert_eq!(out.code, Some(0), "[{lock_name}] installed: {out}");
                assert_attested(out.doc(), PURL, UUID, Marker::Redirected, vulns);

                let seen = api.request_count();
                let out = run_vex(
                    &bin,
                    root,
                    &VexRun {
                        patch_server_url: Some("http://patch.test".to_string()),
                        ..VexRun::offline()
                    },
                );
                assert_eq!(out.code, Some(1), "[{lock_name}] offline: {out}");
                assert_not_attested(&out.envelope, PURL, "record_unavailable");
                assert_eq!(api.request_count(), seen);

                // A pre-v5 ledger's record is an extra local record source.
                let mut record = view.clone();
                let obj = record.as_object_mut().unwrap();
                obj.remove("purl");
                let exported = obj.remove("publishedAt").unwrap();
                obj.insert("exportedAt".to_string(), exported);
                let ledger = root.join(".socket/vendor/redirect-state.json");
                std::fs::create_dir_all(ledger.parent().unwrap()).unwrap();
                std::fs::write(
                    &ledger,
                    serde_json::to_vec_pretty(&serde_json::json!({
                        "version": 1, "mode": "hosted", "records": { PURL: record },
                    }))
                    .unwrap(),
                )
                .unwrap();
                let out = run_vex(
                    &bin,
                    root,
                    &VexRun {
                        patch_server_url: Some("http://patch.test".to_string()),
                        ..VexRun::offline()
                    },
                );
                assert_eq!(out.code, Some(0), "[{lock_name}] legacy ledger, offline: {out}");
                assert_attested(out.doc(), PURL, UUID, Marker::Redirected, vulns);
                assert_eq!(api.request_count(), seen);

                std::fs::write(root.join(lock_name), &pristine).unwrap();
                for no_verify in [false, true] {
                    let out = run_vex(&bin, root, &online(no_verify));
                    assert_eq!(out.code, Some(1), "[{lock_name}] reverted: {out}");
                    assert_not_attested(&out.envelope, PURL, "redirect_unwired");
                    assert_absent(out.doc.as_ref(), PURL);
                }
            })
            .join()
            .unwrap_or_else(|p| std::panic::resume_unwind(p))
        });
    }
}

/// The CLI binary with ambient SOCKET_* env scrubbed (same hermeticity rule
/// as `in_process_redirect.rs`'s `scrubbed_cli`; duplicated because test
/// binaries cannot share helpers). Subprocess (not in-process `run`) so the
/// `--json` stdout envelope can be read back — the diagnostics under test
/// ARE the envelope's `redirect.warnings`.
fn scrubbed_cli() -> std::process::Command {
    let cmd = std::process::Command::new(env!("CARGO_BIN_EXE_socket-patch"));
    let mut cmd = cmd;
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

/// Run `scan --mode hosted --json` as a subprocess against `cwd` and parse
/// the stdout envelope (exit code, parsed JSON).
fn run_hosted_json(cwd: &Path, api_url: &str) -> (Option<i32>, serde_json::Value) {
    let out = scrubbed_cli()
        .args([
            "scan",
            "--mode",
            "hosted",
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
    let stderr = String::from_utf8_lossy(&out.stderr);
    let doc = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("stdout must be the JSON envelope ({e});\nstdout=\n{stdout}\nstderr=\n{stderr}")
    });
    (out.status.code(), doc)
}

/// Legacy shrinkwrap projects support both installed discovery and the
/// lock-only supplement. Hosted mode edits their block resolutions without
/// changing unrelated packages or introducing npm-specific diagnostics.
#[tokio::test]
#[serial]
async fn hosted_legacy_shrinkwrap_project_redirects_and_discovers_uninstalled_packages() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
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
    // pnpm layout marker (pnpm 1/2 writes it, modern pnpm still does).
    std::fs::write(
        root.join("node_modules/.modules.yaml"),
        "packageManager: pnpm@2.17.0\n",
    )
    .unwrap();
    // shrinkwrapVersion-3 grammar (real shape from the legacy matrix):
    // v5-style `/name/version` keys, BLOCK-mapped resolution. One entry is
    // installed (NAME), one is lock-only — the supplement must see it.
    let shrinkwrap = format!(
        "dependencies:
  {NAME}: {VERSION}
packages:
  /{NAME}/{VERSION}:
    dev: false
    resolution:
      integrity: {UPSTREAM_SHA512}
  /legacy-only-dep/2.0.0:
    dev: false
    resolution:
      integrity: sha512-LEGACYONLYlegacyonly==
registry: 'https://registry.npmjs.org/'
shrinkwrapMinorVersion: 9
shrinkwrapVersion: 3
specifiers:
  {NAME}: {VERSION}
"
    );
    std::fs::write(root.join("shrinkwrap.yaml"), &shrinkwrap).unwrap();

    let (code, doc) = run_hosted_json(root, &server.uri());
    assert_eq!(code, Some(0), "fail-closed diagnostics still exit 0: {doc}");

    assert_eq!(
        doc["redirect"]["redirected"], 1,
        "legacy package must redirect: {doc}"
    );
    assert!(!doc.to_string().contains("redirect_npm_no_lockfile"));
    assert!(!doc.to_string().contains("redirect_pnpm_legacy_lockfile"));

    // The lockfile-only supplement reads shrinkwrap.yaml: the uninstalled
    // `/legacy-only-dep/2.0.0` entry surfaces.
    assert_eq!(
        doc["lockfileOnlyPackages"], 1,
        "shrinkwrap.yaml must feed the lockfile-only supplement: {doc}"
    );

    let rewritten = std::fs::read_to_string(root.join("shrinkwrap.yaml")).unwrap();
    assert!(
        rewritten.contains(&format!("tarball: {HOSTED_URL}")),
        "{rewritten}"
    );
    assert!(rewritten.contains("integrity: sha512-LEGACYONLYlegacyonly=="));
}

/// (d) hosted over a VENDORED pnpm lock (the mode-conversion matrix's projB
/// shape: overrides + `<name>@file:.socket/vendor/…` packages/snapshots
/// keys): the per-dep warning must be `redirect_pnpm_entry_vendored`
/// pointing at `vendor --revert` — not the `redirect_pnpm_entry_not_found`
/// wording that reads as "not locked" and invites a `pnpm install`
/// wild-goose chase. Fail-closed unchanged: zero redirects, lock untouched,
/// no redirect ledger.
#[tokio::test]
#[serial]
async fn hosted_over_vendored_pnpm_lock_diagnoses_vendored_not_missing() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
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
    // Byte-real vendored v9 shape (mode-conversion snap-B, renamed to the
    // fixture package).
    let vendored_spec = format!(
        "file:.socket/vendor/npm/1a2b3c4d-5e6f-4a1b-8c2d-0123456789ab/{NAME}-{VERSION}.tgz"
    );
    let lock = format!(
        "lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

overrides:
  {NAME}@{VERSION}: {vendored_spec}

importers:

  .:
    dependencies:
      {NAME}:
        specifier: {vendored_spec}
        version: {vendored_spec}

packages:

  {NAME}@{vendored_spec}:
    resolution: {{integrity: {UPSTREAM_SHA512}, tarball: {vendored_spec}}}
    version: {VERSION}

snapshots:

  {NAME}@{vendored_spec}: {{}}
"
    );
    std::fs::write(root.join("pnpm-lock.yaml"), &lock).unwrap();

    let (code, doc) = run_hosted_json(root, &server.uri());
    assert_eq!(code, Some(0), "fail-closed diagnostics still exit 0: {doc}");

    let warnings = doc["redirect"]["warnings"].as_array().unwrap();
    assert!(
        warnings
            .iter()
            .any(|w| w["code"] == "redirect_pnpm_entry_vendored"),
        "the vendored state must be named: {doc}"
    );
    let detail = warnings
        .iter()
        .find(|w| w["code"] == "redirect_pnpm_entry_vendored")
        .and_then(|w| w["detail"].as_str())
        .unwrap();
    assert!(
        detail.contains("vendor --revert"),
        "detail must give the mode-switch path: {detail}"
    );
    assert!(
        !doc.to_string().contains("redirect_pnpm_entry_not_found"),
        "the not-locked wording must be gone for a vendored dep: {doc}"
    );
    assert_eq!(doc["redirect"]["redirected"], 0, "nothing redirects: {doc}");
    assert_eq!(
        std::fs::read_to_string(root.join("pnpm-lock.yaml")).unwrap(),
        lock,
        "the vendored lock must be byte-untouched (fail-closed)"
    );
    assert!(
        !root.join(".socket/vendor/redirect-state.json").exists(),
        "a zero-redirect run must not write a redirect ledger"
    );
}

/// A URL in one instance must not confirm the whole package while another
/// peer instance remains upstream. This also prevents an unverified --vex
/// attestation from being created for an incomplete rewrite.
#[tokio::test]
#[serial]
async fn hosted_partial_pnpm_redirect_is_not_confirmed_by_url_presence() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    write_pnpm_project(tmp.path());
    let lock = format!("lockfileVersion: '6.0'\npackages:\n  /{NAME}@{VERSION}:\n    resolution: {{integrity: {PATCHED_SHA512}, tarball: {HOSTED_URL}}}\n  /{NAME}@{VERSION}(unbalanced:\n    resolution: {{integrity: {UPSTREAM_SHA512}}}\n");
    std::fs::write(tmp.path().join("pnpm-lock.yaml"), &lock).unwrap();
    let (code, doc) = run_hosted_json(tmp.path(), &server.uri());
    assert_eq!(code, Some(0), "{doc}");
    assert_eq!(
        doc["redirect"]["redirected"], 0,
        "incomplete package must not be confirmed: {doc}"
    );
    assert!(doc["redirect"]["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|w| w["code"] == "redirect_pnpm_unsupported_lock_key"));
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("pnpm-lock.yaml")).unwrap(),
        lock
    );
    assert!(!tmp
        .path()
        .join(".socket/vendor/redirect-state.json")
        .exists());
}

/// A pnpm workspace: the root holds `pnpm-workspace.yaml` and the only
/// `pnpm-lock.yaml` (importer `packages/a`); the member `packages/a` holds
/// its manifest and the installed copy, as pnpm lays it out.
fn write_pnpm_workspace(root: &Path) -> std::path::PathBuf {
    std::fs::write(
        root.join("package.json"),
        r#"{ "name": "root", "private": true }"#,
    )
    .unwrap();
    std::fs::write(
        root.join("pnpm-workspace.yaml"),
        "packages:\n  - packages/*\n",
    )
    .unwrap();
    std::fs::write(
        root.join("pnpm-lock.yaml"),
        format!(
            "lockfileVersion: '9.0'

importers:
  .: {{}}
  packages/a:
    dependencies:
      {NAME}:
        specifier: {VERSION}
        version: {VERSION}

packages:
  {NAME}@{VERSION}:
    resolution: {{integrity: {UPSTREAM_SHA512}}}

snapshots:
  {NAME}@{VERSION}: {{}}
"
        ),
    )
    .unwrap();
    let member = root.join("packages/a");
    let pkg = member.join("node_modules").join(NAME);
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        member.join("package.json"),
        format!(
            r#"{{ "name": "a", "version": "1.0.0", "dependencies": {{ "{NAME}": "{VERSION}" }} }}"#
        ),
    )
    .unwrap();
    std::fs::write(
        pkg.join("package.json"),
        format!(r#"{{ "name": "{NAME}", "version": "{VERSION}" }}"#),
    )
    .unwrap();
    member
}

/// Assert the run refused with `redirect_pnpm_lockfile_elsewhere`, naming
/// the governing lock, and wrote nothing anywhere.
fn assert_refused_lock_elsewhere(
    code: Option<i32>,
    doc: &serde_json::Value,
    lock: &Path,
    lock_before: &str,
    cwd: &Path,
) {
    assert_eq!(
        code,
        Some(1),
        "a found-but-unpinnable patch is not success: {doc}"
    );
    assert_eq!(doc["status"], "error", "{doc}");
    assert_eq!(
        doc["errorCode"], "redirect_pnpm_lockfile_elsewhere",
        "{doc}"
    );
    let message = doc["error"].as_str().unwrap_or_default();
    assert!(
        message.contains("pnpm-lock.yaml") && message.contains("nothing was written"),
        "the error names the governing lock: {message}"
    );
    assert_eq!(std::fs::read_to_string(lock).unwrap(), lock_before);
    assert!(
        !cwd.join(".socket").exists(),
        "nothing written in the member"
    );
    assert!(!cwd.join("pnpm-workspace.yaml").exists());
}

/// #590: `scan --mode hosted` from a pnpm workspace member saw no lock in
/// the member, pinned nothing, and exited 0 with `success` and an npm
/// "no package-lock.json" warning while pnpm installs the unpatched copy
/// from the root lock. It now refuses and names the root.
#[tokio::test]
#[serial]
async fn hosted_scan_from_pnpm_workspace_member_refuses() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    mock_view(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    let member = write_pnpm_workspace(tmp.path());
    let lock = tmp.path().join("pnpm-lock.yaml");
    let before = std::fs::read_to_string(&lock).unwrap();

    let (code, doc) = run_hosted_json(&member, &server.uri());
    assert_refused_lock_elsewhere(code, &doc, &lock, &before, &member);

    // `get <uuid> --mode hosted` takes the same path.
    let out = scrubbed_cli()
        .args([
            "get",
            UUID,
            "--mode",
            "hosted",
            "--json",
            "--yes",
            "--cwd",
            member.to_str().unwrap(),
            "--api-url",
            &server.uri(),
            "--org",
            ORG,
            "--api-token",
            "fake",
        ])
        .output()
        .expect("run socket-patch");
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "get --json output is not JSON ({e}):\n{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    });
    assert_refused_lock_elsewhere(out.status.code(), &doc, &lock, &before, &member);

    // From the workspace root the same patch is pinned.
    let (code, doc) = run_hosted_json(tmp.path(), &server.uri());
    assert_eq!(code, Some(0), "{doc}");
    assert_eq!(doc["redirect"]["redirected"], 1, "{doc}");
    assert!(std::fs::read_to_string(&lock).unwrap().contains(HOSTED_URL));
}

/// #590, `lockfile-dir=..` variant: pnpm writes the project's lock to the
/// parent directory, so the project directory has none.
#[tokio::test]
#[serial]
async fn hosted_scan_with_pnpm_lockfile_dir_elsewhere_refuses() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    write_pnpm_project(&proj);
    std::fs::rename(
        proj.join("pnpm-lock.yaml"),
        tmp.path().join("pnpm-lock.yaml"),
    )
    .unwrap();
    std::fs::write(proj.join(".npmrc"), "lockfile-dir=..\n").unwrap();
    let lock = tmp.path().join("pnpm-lock.yaml");
    let before = std::fs::read_to_string(&lock).unwrap();

    let (code, doc) = run_hosted_json(&proj, &server.uri());
    assert_refused_lock_elsewhere(code, &doc, &lock, &before, &proj);
}

/// pnpm inherits workspace-root config even when
/// invoked from a member. Absolute npmrc paths isolate inheritance; relative
/// YAML paths are resolved from the member cwd by pnpm 10.34.5 itself.
async fn assert_workspace_configured_lock_refused(case: &str) {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("workspace");
    std::fs::create_dir_all(&root).unwrap();
    let member = write_pnpm_workspace(&root);
    let lock_dir = if case == "root-npmrc-absolute" {
        let dir = tmp.path().join("locks");
        std::fs::write(
            root.join(".npmrc"),
            format!("lockfile-dir={}\n", dir.display()),
        )
        .unwrap();
        dir
    } else if case == "root-yaml-relative" {
        std::fs::write(
            root.join("pnpm-workspace.yaml"),
            "packages:\n  - packages/*\nlockfileDir: ../locks\n",
        )
        .unwrap();
        root.join("packages/locks")
    } else {
        let dir = tmp.path().join("yaml-locks");
        std::fs::write(
            root.join("pnpm-workspace.yaml"),
            format!(
                "packages:\n  - packages/*\nlockfileDir: {}\n",
                dir.display()
            ),
        )
        .unwrap();
        std::fs::write(member.join(".npmrc"), "lockfile-dir=../unused-locks\n").unwrap();
        dir
    };
    std::fs::create_dir_all(&lock_dir).unwrap();
    let lock = lock_dir.join("pnpm-lock.yaml");
    std::fs::rename(root.join("pnpm-lock.yaml"), &lock).unwrap();
    let before = std::fs::read_to_string(&lock).unwrap();
    let (code, doc) = run_hosted_json(&member, &server.uri());
    assert_refused_lock_elsewhere(code, &doc, &lock, &before, &member);
}

#[tokio::test]
#[serial]
async fn hosted_scan_inherits_workspace_npmrc_lockfile_dir() {
    assert_workspace_configured_lock_refused("root-npmrc-absolute").await;
}

#[tokio::test]
#[serial]
async fn hosted_scan_resolves_inherited_lockfile_dir_from_cwd() {
    assert_workspace_configured_lock_refused("root-yaml-relative").await;
}

#[tokio::test]
#[serial]
async fn hosted_scan_workspace_yaml_overrides_member_npmrc() {
    assert_workspace_configured_lock_refused("root-yaml-precedence").await;
}

/// The workspace root as refusals and warnings name it: canonical (Windows
/// expands 8.3 names) without the verbatim `\\?\` prefix.
fn member_root(tmp: &tempfile::TempDir) -> std::path::PathBuf {
    socket_patch_core::utils::pnpm_workspace::without_verbatim_prefix(
        std::fs::canonicalize(tmp.path()).unwrap(),
    )
}

/// Every redirect warning's text, unescaped: a JSON dump doubles each
/// Windows `\`, so a path would never match.
fn warning_texts(doc: &serde_json::Value) -> String {
    let mut out = String::new();
    for warning in doc["redirect"]["warnings"].as_array().into_iter().flatten() {
        for value in warning.as_object().into_iter().flat_map(|o| o.values()) {
            if let Some(text) = value.as_str() {
                out.push_str(text);
                out.push('\n');
            }
        }
        if let Some(text) = warning.as_str() {
            out.push_str(text);
            out.push('\n');
        }
    }
    out
}

/// #880: a workspace member with its own lock (`sharedWorkspaceLockfile:
/// false`) is pinned through its own lock, but pnpm reads `trustLockfile`
/// only from the workspace root's `pnpm-workspace.yaml`. Hosted mode used
/// to create a nested `packages: ['.']` + `trustLockfile: true` file in the
/// member, which pnpm ignores, so every root install failed on pnpm 11/12
/// while the scan reported success. It now refuses before any write and
/// names the root file; once that file trusts the lock, the member pins
/// with no nested file.
#[tokio::test]
#[serial]
async fn hosted_scan_from_pnpm_member_with_own_lock_never_nests_trust_config() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    mock_view(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    let root = member_root(&tmp);
    std::fs::write(
        root.join("package.json"),
        r#"{ "name": "root", "private": true }"#,
    )
    .unwrap();
    let root_ws = root.join("pnpm-workspace.yaml");
    let ws_before = "packages:\n  - 'packages/*'\nsharedWorkspaceLockfile: false\n";
    std::fs::write(&root_ws, ws_before).unwrap();
    let member = root.join("packages/a");
    std::fs::create_dir_all(&member).unwrap();
    write_pnpm_project(&member);
    let lock = member.join("pnpm-lock.yaml");
    let lock_before = std::fs::read_to_string(&lock).unwrap();

    let (code, doc) = run_hosted_json(&member, &server.uri());
    assert_eq!(code, Some(1), "{doc}");
    assert_eq!(doc["status"], "error", "{doc}");
    assert_eq!(
        doc["errorCode"], "redirect_pnpm_settings_elsewhere",
        "{doc}"
    );
    let message = doc["error"].as_str().unwrap_or_default();
    assert!(
        message.contains(&root_ws.display().to_string())
            && message.contains("trustLockfile: true")
            && message.contains("nothing was written"),
        "the error names the root file and the key to add: {message}"
    );
    assert_eq!(std::fs::read_to_string(&lock).unwrap(), lock_before);
    assert_eq!(std::fs::read_to_string(&root_ws).unwrap(), ws_before);
    assert!(!member.join("pnpm-workspace.yaml").exists());

    // With the key in the root file (what pnpm reads), the member pins and
    // no nested settings file is created.
    let ws_trusted = format!("{ws_before}trustLockfile: true\n");
    std::fs::write(&root_ws, &ws_trusted).unwrap();
    let (code, doc) = run_hosted_json(&member, &server.uri());
    assert_eq!(code, Some(0), "{doc}");
    assert_eq!(doc["redirect"]["redirected"], 1, "{doc}");
    assert!(std::fs::read_to_string(&lock).unwrap().contains(HOSTED_URL));
    assert!(
        !member.join("pnpm-workspace.yaml").exists(),
        "pnpm ignores a member's settings file; none is created"
    );
    assert_eq!(std::fs::read_to_string(&root_ws).unwrap(), ws_trusted);
    let warnings = warning_texts(&doc);
    assert!(
        warnings.contains(&root_ws.display().to_string()) && warnings.contains("already carries"),
        "the trust warning names the root file: {warnings}"
    );
}

/// #880: an explicit `trustLockfile: false` in the root file is the user's
/// call, respected as in a single project: the member pins, nothing is
/// nested, and the warning names the root file.
#[tokio::test]
#[serial]
async fn hosted_scan_from_pnpm_member_respects_root_trust_opt_out() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    mock_view(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    let root = member_root(&tmp);
    let root_ws = root.join("pnpm-workspace.yaml");
    let ws = "packages:\n  - 'packages/*'\ntrustLockfile: false\n";
    std::fs::write(&root_ws, ws).unwrap();
    let member = root.join("packages/a");
    std::fs::create_dir_all(&member).unwrap();
    write_pnpm_project(&member);

    let (code, doc) = run_hosted_json(&member, &server.uri());
    assert_eq!(code, Some(0), "{doc}");
    assert_eq!(doc["redirect"]["redirected"], 1, "{doc}");
    assert!(!member.join("pnpm-workspace.yaml").exists());
    assert_eq!(std::fs::read_to_string(&root_ws).unwrap(), ws);
    let warnings = warning_texts(&doc);
    assert!(
        warnings.contains(&root_ws.display().to_string())
            && warnings.contains("trustLockfile: false"),
        "{warnings}"
    );
}

/// An npm / yarn / Bun workspace: the root `package.json` lists
/// `packages/*` under `workspaces` (array form, or yarn classic's
/// `{packages, nohoist}` object form) and holds the only lock, `lock_name`;
/// the member `packages/a` holds its manifest and its own unhoisted copy.
fn write_package_json_workspace(
    root: &Path,
    lock_name: &str,
    object_form: bool,
) -> std::path::PathBuf {
    let workspaces = if object_form {
        r#"{ "packages": ["packages/*"], "nohoist": ["**/in-proc-redirect-pnpm"] }"#
    } else {
        r#"["packages/*"]"#
    };
    std::fs::write(
        root.join("package.json"),
        format!(r#"{{ "name": "root", "private": true, "workspaces": {workspaces} }}"#),
    )
    .unwrap();
    std::fs::write(root.join(lock_name), format!("# root lock {lock_name}\n")).unwrap();
    let member = root.join("packages/a");
    let pkg = member.join("node_modules").join(NAME);
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        member.join("package.json"),
        format!(
            r#"{{ "name": "a", "version": "1.0.0", "dependencies": {{ "{NAME}": "{VERSION}" }} }}"#
        ),
    )
    .unwrap();
    std::fs::write(
        pkg.join("package.json"),
        format!(r#"{{ "name": "{NAME}", "version": "{VERSION}" }}"#),
    )
    .unwrap();
    member
}

/// #884: `scan --mode hosted` and `get <uuid> --mode hosted` from an npm,
/// yarn classic, yarn berry or Bun workspace member found the member's
/// copy, read no lock in the member, pinned nothing, and exited 0 with
/// `success` and an npm "no package-lock.json" warning, while the package
/// manager installs the unpatched copy from the root lock. They now refuse
/// and name the workspace root.
#[tokio::test]
#[serial]
async fn hosted_scan_from_package_json_workspace_member_refuses() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;
    mock_view(&server).await;
    for (lock_name, object_form) in [
        ("package-lock.json", false),
        ("npm-shrinkwrap.json", false),
        ("yarn.lock", false),
        ("yarn.lock", true),
        ("bun.lock", false),
        ("bun.lockb", false),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let member = write_package_json_workspace(tmp.path(), lock_name, object_form);
        let lock = tmp.path().join(lock_name);
        let before = std::fs::read_to_string(&lock).unwrap();
        let case = format!("{lock_name} (object form: {object_form})");

        let (code, doc) = run_hosted_json(&member, &server.uri());
        assert_refused_workspace_lock_elsewhere(&case, code, &doc, &lock, &before, &member);

        let out = scrubbed_cli()
            .args([
                "get",
                UUID,
                "--mode",
                "hosted",
                "--json",
                "--yes",
                "--cwd",
                member.to_str().unwrap(),
                "--api-url",
                &server.uri(),
                "--org",
                ORG,
                "--api-token",
                "fake",
            ])
            .output()
            .expect("run socket-patch");
        let doc: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
            panic!(
                "{case}: get --json output is not JSON ({e}):\n{}\n{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            )
        });
        assert_refused_workspace_lock_elsewhere(
            &case,
            out.status.code(),
            &doc,
            &lock,
            &before,
            &member,
        );
    }
}

fn assert_refused_workspace_lock_elsewhere(
    case: &str,
    code: Option<i32>,
    doc: &serde_json::Value,
    lock: &Path,
    lock_before: &str,
    cwd: &Path,
) {
    assert_eq!(
        code,
        Some(1),
        "{case}: a found-but-unpinnable patch is not success: {doc}"
    );
    assert_eq!(doc["status"], "error", "{case}: {doc}");
    assert_eq!(
        doc["errorCode"], "redirect_workspace_lockfile_elsewhere",
        "{case}: {doc}"
    );
    let message = doc["error"].as_str().unwrap_or_default();
    let lock_name = lock.file_name().unwrap().to_str().unwrap();
    assert!(
        message.contains(lock_name) && message.contains("nothing was written"),
        "{case}: the error names the governing lock: {message}"
    );
    assert_eq!(
        std::fs::read_to_string(lock).unwrap(),
        lock_before,
        "{case}"
    );
    assert!(
        !cwd.join(".socket").exists(),
        "{case}: nothing written in the member"
    );
}
