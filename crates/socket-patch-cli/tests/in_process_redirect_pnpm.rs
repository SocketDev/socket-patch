//! In-process tests for `socket-patch scan --mode hosted` against a pnpm
//! (lockfileVersion 9.0) ROOT lock — the pnpm counterpart of the npm legs in
//! `tests/in_process_redirect.rs`. Mocks the API (discovery + reference +
//! view) via wiremock, lays down a pnpm project whose only lockfile is a root
//! `pnpm-lock.yaml`, runs the redirect, and asserts the patched package's
//! `resolution:` was spliced to `{integrity: sha512-<patched>, tarball:
//! <hosted url>}` (the shape the shared golden `npm/pnpm` fixture pins) with a
//! `redirect_pnpm_resolution` edit recorded in the revert ledger.
//!
//! `in_process_redirect.rs` covers pnpm ONLY through the Rush nested-lock
//! path; these tests pin the plain single-project pnpm root-lock rewrite plus
//! its idempotency and the `--vex` `(redirected)` attestation.

use serial_test::serial;
use socket_patch_cli::commands::scan::{run, ScanArgs, ScanMode};
use std::path::Path;
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

/// `--mode hosted` (the released spelling that folds to `redirect: true`).
fn hosted_args(cwd: &Path, api_url: String) -> ScanArgs {
    ScanArgs {
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

/// `view/{uuid}` — the patch record persisted into the redirect ledger for VEX.
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
/// becomes the patched sha512, the upstream integrity is gone, a
/// `redirect_pnpm_resolution` edit lands in the ledger, and a second run adds
/// zero edits (idempotent).
#[tokio::test]
#[serial]
async fn hosted_rewrites_pnpm_root_lock_resolution() {
    let server = MockServer::start().await;
    mock_discovery(&server).await;
    mock_reference(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_pnpm_project(tmp.path());

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

    let ledger_path = tmp.path().join(".socket/vendor/redirect-state.json");
    let first: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&ledger_path).unwrap()).unwrap();
    let edits = first["edits"].as_array().unwrap();
    assert!(
        edits
            .iter()
            .any(|e| e["kind"] == "redirect_pnpm_resolution"
                && e["key"] == format!("{NAME}@{VERSION}")),
        "the ledger must record a redirect_pnpm_resolution edit: {first}"
    );
    // The ORIGINAL upstream integrity is preserved for revert.
    assert!(
        first.to_string().contains("UPSTREAMupstream"),
        "the ledger must preserve the original upstream integrity for revert: {first}"
    );

    // Zero-touch trust config: a rewritten root v9 lock auto-creates
    // pnpm-workspace.yaml with the root-only scaffold + `trustLockfile: true`
    // (pnpm >=11 rejects the redirected lock without it; 9/10 ignore the
    // key), and the ledger records the created-file edit for revert.
    let ws_path = tmp.path().join("pnpm-workspace.yaml");
    let ws = std::fs::read_to_string(&ws_path)
        .expect("the redirect must auto-create pnpm-workspace.yaml");
    assert_eq!(
        ws, "packages:\n  - '.'\ntrustLockfile: true\n",
        "created workspace file must be the scaffold + trust key"
    );
    assert!(
        edits.iter().any(|e| {
            e["kind"] == "redirect_pnpm_workspace_trust"
                && e["action"] == "created"
                && e["path"] == "pnpm-workspace.yaml"
                && e["key"] == "trustLockfile"
        }),
        "the ledger must record the workspace-trust creation: {first}"
    );

    // Idempotency: a second run rewrites nothing new — an already-redirected
    // resolution must not append duplicate edits (which would poison a revert),
    // and the auto-created workspace file must stay byte-stable.
    let code = run(hosted_args(tmp.path(), server.uri())).await;
    assert_eq!(code, 0, "second scan --mode hosted should succeed");
    let second: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&ledger_path).unwrap()).unwrap();
    assert_eq!(
        edits.len(),
        second["edits"].as_array().unwrap().len(),
        "a pnpm re-run must not append duplicate edits: {second}"
    );
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
}

/// MERGE case: a pre-existing pnpm-workspace.yaml (comments, multi-glob
/// packages, catalog — none of it ours) gains EXACTLY one appended
/// `trustLockfile: true` line after its last non-empty line; every other
/// byte survives verbatim, and the ledger records the `added` (not
/// `created`) action so a revert removes just that line.
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
    let ledger: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(tmp.path().join(".socket/vendor/redirect-state.json")).unwrap(),
    )
    .unwrap();
    assert!(
        ledger["edits"].as_array().unwrap().iter().any(|e| {
            e["kind"] == "redirect_pnpm_workspace_trust"
                && e["action"] == "added"
                && e["path"] == "pnpm-workspace.yaml"
        }),
        "the ledger must record the merged (added) trust edit: {ledger}"
    );
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
/// pnpm-workspace.yaml appears and the ledger carries no workspace-trust
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
    let ledger = std::fs::read_to_string(root.join(".socket/vendor/redirect-state.json")).unwrap();
    assert!(
        !ledger.contains("redirect_pnpm_workspace_trust"),
        "no workspace-trust edit may be recorded for a legacy lock: {ledger}"
    );
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

    let ledger: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(root.join(".socket/vendor/redirect-state.json")).unwrap(),
    )
    .unwrap();
    assert!(
        ledger["edits"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["kind"] == "redirect_pnpm_resolution"
                && e["key"] == format!("{SCOPED_NAME}@{VERSION}")),
        "the ledger must record the scoped redirect edit: {ledger}"
    );
}

/// (b) `scan --mode hosted --vex`: the redirected pnpm patch is attested with
/// the `(redirected)` provenance marker (bytes are remote until install, so
/// this is the NO-VERIFY attestation built from the ledger record — the same
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

    // The ledger embeds the patch record (so a post-install `vex` can verify).
    let ledger =
        std::fs::read_to_string(tmp.path().join(".socket/vendor/redirect-state.json")).unwrap();
    assert!(
        ledger.contains("\"records\"") && ledger.contains(GHSA) && ledger.contains(PURL),
        "ledger must embed the patch record + vulnerability: {ledger}"
    );

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

/// (c) pnpm 1/2 legacy project (the 2026-08-18 legacy-matrix layout:
/// `shrinkwrap.yaml` + `node_modules/.modules.yaml`, no pnpm-lock.yaml and
/// no package-lock.json): the no-lockfile diagnostic must be PNPM-flavored
/// — `redirect_pnpm_legacy_lockfile` naming shrinkwrap.yaml and the pnpm
/// upgrade path — never the npm `redirect_npm_no_lockfile` wording that
/// dead-ends on a pnpm project. The legacy lock also feeds the
/// lockfile-only supplement (shrinkwrap.yaml IS the v5 grammar under the
/// pre-rename filename), and the run stays fail-closed: shrinkwrap.yaml is
/// byte-untouched with zero redirects.
#[tokio::test]
#[serial]
async fn hosted_legacy_shrinkwrap_project_diagnoses_pnpm_not_npm() {
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

    let warnings = doc["redirect"]["warnings"].as_array().unwrap();
    assert_eq!(
        warnings.len(),
        1,
        "exactly the pnpm-legacy diagnostic, no npm noise: {doc}"
    );
    assert_eq!(
        warnings[0]["code"], "redirect_pnpm_legacy_lockfile",
        "the family selection must be marker-aware: {doc}"
    );
    let detail = warnings[0]["detail"].as_str().unwrap();
    assert!(
        detail.contains("shrinkwrap.yaml") && detail.contains("pnpm"),
        "detail must name the legacy lock and pnpm: {detail}"
    );
    assert!(
        !doc.to_string().contains("redirect_npm_no_lockfile"),
        "the npm wording must be gone: {doc}"
    );
    assert_eq!(doc["redirect"]["redirected"], 0, "nothing redirects: {doc}");

    // The lockfile-only supplement reads shrinkwrap.yaml: the uninstalled
    // `/legacy-only-dep/2.0.0` entry surfaces (it was 0 before the fix).
    assert_eq!(
        doc["lockfileOnlyPackages"], 1,
        "shrinkwrap.yaml must feed the lockfile-only supplement: {doc}"
    );

    assert_eq!(
        std::fs::read_to_string(root.join("shrinkwrap.yaml")).unwrap(),
        shrinkwrap,
        "shrinkwrap.yaml must be byte-untouched (fail-closed)"
    );
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
