//! In-process tests for `get --mode hosted|vendored` and the coarse
//! installed-VERSION narrowing of advisory fan-outs (v3.6).
//!
//! Disk-state assertions only — in-process `run()` prints its JSON envelope
//! to the real stdout, which these tests cannot capture; envelope shapes are
//! pinned by the subprocess suite (`get_modes_e2e.rs`). The API is mocked
//! with wiremock: `by-ghsa` search (a two-version fan-out), `view/{uuid}`,
//! and the hosted `patches/package` reference endpoint.
//!
//! `#[serial]`: `get::run` mirrors env toggles into process-global env vars.

use std::path::Path;

use serial_test::serial;
use socket_patch_cli::commands::get::GetArgs;
use socket_patch_cli::commands::scan::ScanMode;
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";
const NAME: &str = "getmodes-pkg";
const GHSA: &str = "GHSA-aaaa-bbbb-cccc";

/// The INSTALLED version's patch.
const UUID1: &str = "11111111-1111-4111-8111-111111111111";
const PURL1: &str = "pkg:npm/getmodes-pkg@1.0.0";
/// A patch for a version this project does NOT have.
const UUID2: &str = "22222222-2222-4222-8222-222222222222";
const PURL2: &str = "pkg:npm/getmodes-pkg@2.0.0";

const HOSTED_URL1: &str = "http://patch.test/patch/npm/getmodes-pkg/1.0.0/33333333-3333-4333-8333-333333333333/11111111-1111-4111-8111-111111111111/getmodes-pkg-1.0.0.tgz";
const PATCHED_SHA512: &str = "sha512-PATCHEDpatchedPATCHEDpatched0123456789==";

const BEFORE_BYTES: &[u8] = b"vulnerable\n";
const AFTER_BYTES: &[u8] = b"patched\n";

fn before_hash() -> String {
    compute_git_sha256_from_bytes(BEFORE_BYTES)
}
fn after_hash() -> String {
    compute_git_sha256_from_bytes(AFTER_BYTES)
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn get_args(identifier: &str, cwd: &Path, api_url: String) -> GetArgs {
    GetArgs {
        common: socket_patch_cli::args::GlobalArgs {
            org: Some(ORG.to_string()),
            cwd: cwd.to_path_buf(),
            yes: true,
            api_token: Some("fake-token-for-tests".to_string()),
            api_url: Some(api_url),
            json: true,
            download_mode: "diff".to_string(),
            // Local build so the vendored tests never reach the vendoring
            // service (no grant/tarball mocks needed).
            vendor_source: "build".to_string(),
            ..socket_patch_cli::args::GlobalArgs::default()
        },
        identifier: identifier.to_string(),
        id: false,
        cve: false,
        ghsa: false,
        package: false,
        save_only: false,
        one_off: false,
        all_releases: false,
        mode: None,
    }
}

/// `view/{uuid}` with REAL git-blob hashes and inline blob content, so the
/// vendored flow's staging hash-gates pass and the agent flow can apply.
async fn mock_view(server: &MockServer, uuid: &str, purl: &str) {
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{uuid}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": uuid,
            "purl": purl,
            "publishedAt": "2024-01-01T00:00:00Z",
            "files": {
                "package/index.js": {
                    "beforeHash": before_hash(),
                    "afterHash": after_hash(),
                    "blobContent": b64(AFTER_BYTES),
                }
            },
            "vulnerabilities": {
                GHSA: {
                    "cves": ["CVE-2024-1234"],
                    "summary": "get-modes fixture",
                    "severity": "high",
                    "description": "d"
                }
            },
            "description": "get-modes fixture",
            "license": "MIT",
            "tier": "free",
        })))
        .mount(server)
        .await;
}

/// `by-ghsa/{GHSA}`: the two-version fan-out — the installed 1.0.0 and the
/// absent 2.0.0, both free.
async fn mock_ghsa_fanout(server: &MockServer) {
    let patch = |uuid: &str, purl: &str, published: &str| {
        serde_json::json!({
            "uuid": uuid, "purl": purl,
            "publishedAt": published,
            "description": "x", "license": "MIT", "tier": "free",
            "vulnerabilities": {}
        })
    };
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/by-ghsa/{GHSA}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [
                patch(UUID2, PURL2, "2024-02-01T00:00:00Z"),
                patch(UUID1, PURL1, "2024-01-01T00:00:00Z"),
            ],
            "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;
}

/// The hosted reference grant for the INSTALLED version's patch only. A
/// narrowing regression that requests UUID2 gets no grant for it (skipped
/// `not_found`), and the request-body assertion below catches it loudly.
async fn mock_reference(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "results": {
                UUID1: {
                    "status": "granted",
                    "url": HOSTED_URL1,
                    "purl": PURL1,
                    "artifacts": [{
                        "kind": "tarball",
                        "url": HOSTED_URL1,
                        "integrity": { "sha512": PATCHED_SHA512 }
                    }],
                    "registryOverride": null
                }
            }
        })))
        .mount(server)
        .await;
}

/// An npm project with `getmodes-pkg@1.0.0` INSTALLED (crawler-visible) and
/// lockfile-resolved; version 2.0.0 exists nowhere in the project.
fn write_project(root: &Path) {
    std::fs::write(
        root.join("package.json"),
        format!(
            r#"{{ "name": "consumer", "version": "0.0.0", "dependencies": {{ "{NAME}": "1.0.0" }} }}"#
        ),
    )
    .unwrap();
    let pkg = root.join("node_modules").join(NAME);
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        pkg.join("package.json"),
        format!(r#"{{ "name": "{NAME}", "version": "1.0.0", "main": "index.js" }}"#),
    )
    .unwrap();
    std::fs::write(pkg.join("index.js"), BEFORE_BYTES).unwrap();
    std::fs::write(
        root.join("package-lock.json"),
        format!(
            r#"{{
  "name": "consumer",
  "version": "0.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {{
    "": {{ "name": "consumer", "version": "0.0.0", "dependencies": {{ "{NAME}": "1.0.0" }} }},
    "node_modules/{NAME}": {{
      "version": "1.0.0",
      "resolved": "https://registry.npmjs.org/{NAME}/-/{NAME}-1.0.0.tgz",
      "integrity": "sha512-UPSTREAMupstream=="
    }}
  }}
}}
"#
        ),
    )
    .unwrap();
}

fn read_manifest_purls(cwd: &Path) -> Vec<String> {
    let manifest_path = cwd.join(".socket/manifest.json");
    if !manifest_path.is_file() {
        return Vec::new();
    }
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(manifest_path).unwrap()).unwrap();
    let mut purls: Vec<String> = manifest["patches"]
        .as_object()
        .map(|o| o.keys().cloned().collect())
        .unwrap_or_default();
    purls.sort();
    purls
}

/// Requests the mock server saw for a given path fragment.
async fn requests_containing(server: &MockServer, fragment: &str) -> usize {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .filter(|r| r.url.path().contains(fragment))
        .count()
}

// ---------------------------------------------------------------------------
// Hosted mode
// ---------------------------------------------------------------------------

/// `get <uuid> --mode hosted` must produce scan's hosted result: lockfile
/// repointed at the hosted artifact with the patched integrity, a redirect
/// ledger with the patch record — and NO manifest, NO blobs (the ledger IS
/// the persistence; parity with `scan --mode hosted`).
#[tokio::test]
#[serial]
async fn get_uuid_hosted_rewrites_lockfile_and_writes_ledger_not_manifest() {
    let server = MockServer::start().await;
    mock_view(&server, UUID1, PURL1).await;
    mock_reference(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());

    let mut args = get_args(UUID1, tmp.path(), server.uri());
    args.mode = Some(ScanMode::Hosted);
    let code = socket_patch_cli::commands::get::run(args).await;
    assert_eq!(code, 0, "get --mode hosted should succeed");

    let lock = std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap();
    assert!(
        lock.contains(HOSTED_URL1),
        "lockfile must point at the hosted patch; got:\n{lock}"
    );
    assert!(
        lock.contains(PATCHED_SHA512),
        "lockfile integrity must be the patched sha512; got:\n{lock}"
    );
    assert!(
        !lock.contains("UPSTREAMupstream"),
        "upstream resolved/integrity must be replaced; got:\n{lock}"
    );

    let ledger_path = tmp.path().join(".socket/vendor/redirect-state.json");
    assert!(ledger_path.is_file(), "redirect ledger must be written");
    let ledger: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&ledger_path).unwrap()).unwrap();
    assert_eq!(ledger["mode"], "hosted");
    assert_eq!(
        ledger["records"][PURL1]["uuid"], UUID1,
        "the ledger must record the redirected patch for VEX; got:\n{ledger}"
    );

    assert!(
        !tmp.path().join(".socket/manifest.json").exists(),
        "hosted mode must NOT write the manifest (parity with scan --mode hosted)"
    );
    assert!(
        !tmp.path().join(".socket/blobs").exists(),
        "hosted mode must NOT persist blobs"
    );
}

/// A GHSA fan-out across two versions must be narrowed to the INSTALLED
/// version before the hosted engine runs: only its uuid is sent to the
/// reference endpoint, only its lock entry is rewritten, and only its purl
/// lands in the ledger.
#[tokio::test]
#[serial]
async fn get_ghsa_hosted_narrows_to_installed_version() {
    let server = MockServer::start().await;
    mock_ghsa_fanout(&server).await;
    mock_view(&server, UUID1, PURL1).await;
    mock_reference(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());

    let mut args = get_args(GHSA, tmp.path(), server.uri());
    args.mode = Some(ScanMode::Hosted);
    let code = socket_patch_cli::commands::get::run(args).await;
    assert_eq!(code, 0, "get GHSA --mode hosted should succeed");

    let lock = std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap();
    assert!(lock.contains(HOSTED_URL1), "installed version redirected");

    // The reference request must carry ONLY the installed version's uuid —
    // requesting UUID2's grant means the fan-out was not narrowed.
    let reference_bodies: Vec<String> = server
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .filter(|r| r.url.path().ends_with("/patches/package"))
        .map(|r| String::from_utf8_lossy(&r.body).into_owned())
        .collect();
    assert_eq!(reference_bodies.len(), 1, "exactly one reference request");
    assert!(reference_bodies[0].contains(UUID1));
    assert!(
        !reference_bodies[0].contains(UUID2),
        "the uninstalled version's uuid must be narrowed out BEFORE the grant \
         request; body: {}",
        reference_bodies[0]
    );

    let ledger: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(tmp.path().join(".socket/vendor/redirect-state.json")).unwrap(),
    )
    .unwrap();
    assert!(ledger["records"][PURL1].is_object());
    assert!(
        ledger["records"][PURL2].is_null(),
        "no record for the uninstalled version"
    );
    assert!(!tmp.path().join(".socket/manifest.json").exists());
}

/// `--dry-run` on hosted mode flows through the engine's dry-run contract:
/// exit 0, no lockfile write, no ledger.
#[tokio::test]
#[serial]
async fn get_uuid_hosted_dry_run_writes_nothing() {
    let server = MockServer::start().await;
    mock_view(&server, UUID1, PURL1).await;
    mock_reference(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    let lock_before = std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap();

    let mut args = get_args(UUID1, tmp.path(), server.uri());
    args.mode = Some(ScanMode::Hosted);
    args.common.dry_run = true;
    let code = socket_patch_cli::commands::get::run(args).await;
    assert_eq!(code, 0);

    let lock_after = std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap();
    assert_eq!(lock_before, lock_after, "dry-run must not touch the lock");
    assert!(
        !tmp.path().join(".socket/vendor/redirect-state.json").exists(),
        "dry-run must not write the ledger"
    );
    assert!(!tmp.path().join(".socket/manifest.json").exists());
}

// ---------------------------------------------------------------------------
// Vendored mode
// ---------------------------------------------------------------------------

/// `get <uuid> --mode vendored` must produce scan's vendored result: the
/// manifest record, the committed artifact under `.socket/vendor/npm/<uuid>/`,
/// the vendor ledger, the lock rewired to the `file:` artifact — and NO
/// `.socket/blobs` (the download phase holds content in memory).
#[tokio::test]
#[serial]
async fn get_uuid_vendored_commits_artifact_and_wires_lock() {
    let server = MockServer::start().await;
    mock_view(&server, UUID1, PURL1).await;

    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());

    let mut args = get_args(UUID1, tmp.path(), server.uri());
    args.mode = Some(ScanMode::Vendored);
    let code = socket_patch_cli::commands::get::run(args).await;
    assert_eq!(code, 0, "get --mode vendored should succeed");

    assert_eq!(
        read_manifest_purls(tmp.path()),
        vec![PURL1.to_string()],
        "the manifest must record the vendored patch"
    );
    let artifact = tmp
        .path()
        .join(".socket/vendor/npm")
        .join(UUID1)
        .join(format!("{NAME}-1.0.0.tgz"));
    assert!(
        artifact.is_file(),
        "the patched artifact must be committed at {}",
        artifact.display()
    );
    assert!(
        tmp.path().join(".socket/vendor/state.json").is_file(),
        "the vendor ledger must be written"
    );
    let lock = std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap();
    assert!(
        lock.contains(".socket/vendor/npm/"),
        "the lock must be rewired to the vendored artifact; got:\n{lock}"
    );
    assert!(
        !tmp.path().join(".socket/blobs").exists(),
        "vendored mode must NOT persist blobs (scan parity: content stays in memory)"
    );
}

/// Re-running the same vendored get is an idempotent no-op: the manifest
/// insert is gated on `changed` and the vendor engine lands on its benign
/// `already_vendored` skip. The artifact survives.
#[tokio::test]
#[serial]
async fn get_uuid_vendored_rerun_is_idempotent() {
    let server = MockServer::start().await;
    mock_view(&server, UUID1, PURL1).await;

    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());

    let mut args = get_args(UUID1, tmp.path(), server.uri());
    args.mode = Some(ScanMode::Vendored);
    assert_eq!(socket_patch_cli::commands::get::run(args).await, 0);

    let artifact = tmp
        .path()
        .join(".socket/vendor/npm")
        .join(UUID1)
        .join(format!("{NAME}-1.0.0.tgz"));
    let lock_after_first =
        std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap();

    let mut args = get_args(UUID1, tmp.path(), server.uri());
    args.mode = Some(ScanMode::Vendored);
    assert_eq!(
        socket_patch_cli::commands::get::run(args).await,
        0,
        "re-run must be a benign no-op"
    );
    assert!(artifact.is_file(), "artifact must survive the re-run");
    let lock_after_second =
        std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap();
    assert_eq!(
        lock_after_first, lock_after_second,
        "the re-run must leave the lock byte-identical"
    );
}

/// `--dry-run` on vendored mode is a classification preview: no download, no
/// manifest write, no artifact, no lock change.
#[tokio::test]
#[serial]
async fn get_uuid_vendored_dry_run_writes_nothing() {
    let server = MockServer::start().await;
    mock_view(&server, UUID1, PURL1).await;

    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    let lock_before = std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap();

    let mut args = get_args(UUID1, tmp.path(), server.uri());
    args.mode = Some(ScanMode::Vendored);
    args.common.dry_run = true;
    let code = socket_patch_cli::commands::get::run(args).await;
    assert_eq!(code, 0);

    assert!(!tmp.path().join(".socket").exists(), "no .socket writes");
    assert_eq!(
        lock_before,
        std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap()
    );
}

// ---------------------------------------------------------------------------
// Installed narrowing (agent mode) + exemptions + terminal states
// ---------------------------------------------------------------------------

/// Agent mode narrows the GHSA fan-out too: only the installed version's
/// patch is fetched, recorded, and applied; the absent version's view is
/// never even requested.
#[tokio::test]
#[serial]
async fn get_ghsa_agent_narrows_to_installed_version() {
    let server = MockServer::start().await;
    mock_ghsa_fanout(&server).await;
    mock_view(&server, UUID1, PURL1).await;

    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());

    let args = get_args(GHSA, tmp.path(), server.uri());
    let code = socket_patch_cli::commands::get::run(args).await;
    assert_eq!(code, 0, "narrowed agent get should succeed");

    assert_eq!(
        read_manifest_purls(tmp.path()),
        vec![PURL1.to_string()],
        "only the installed version may be recorded"
    );
    assert_eq!(
        std::fs::read(tmp.path().join("node_modules").join(NAME).join("index.js")).unwrap(),
        AFTER_BYTES,
        "the installed copy must be patched in place"
    );
    assert_eq!(
        requests_containing(&server, &format!("/patches/view/{UUID2}")).await,
        0,
        "the uninstalled version's view must never be fetched"
    );
}

/// When NO found version is installed, get exits 0 with the additive
/// `not_installed` status and touches nothing — and performs zero view
/// fetches.
#[tokio::test]
#[serial]
async fn get_ghsa_all_versions_uninstalled_exits_zero_untouched() {
    let server = MockServer::start().await;
    mock_ghsa_fanout(&server).await;

    let tmp = tempfile::tempdir().unwrap();

    let args = get_args(GHSA, tmp.path(), server.uri());
    let code = socket_patch_cli::commands::get::run(args).await;
    assert_eq!(code, 0, "not-installed narrowing is a calm exit-0 state");

    assert!(
        !tmp.path().join(".socket").exists(),
        "nothing may be written when every version was narrowed out"
    );
    assert_eq!(
        requests_containing(&server, "/patches/view/").await,
        0,
        "no view fetches for narrowed-out patches"
    );
}

/// `--save-only` is EXEMPT from the coarse narrowing: record-only has no
/// installation precondition (the fresh-clone `get --save-only` → `vendor`
/// flow), so both versions' records land in the manifest even in an empty
/// project.
#[tokio::test]
#[serial]
async fn get_ghsa_save_only_is_exempt_from_narrowing() {
    let server = MockServer::start().await;
    mock_ghsa_fanout(&server).await;
    mock_view(&server, UUID1, PURL1).await;
    mock_view(&server, UUID2, PURL2).await;

    let tmp = tempfile::tempdir().unwrap();

    let mut args = get_args(GHSA, tmp.path(), server.uri());
    args.save_only = true;
    let code = socket_patch_cli::commands::get::run(args).await;
    assert_eq!(code, 0);

    assert_eq!(
        read_manifest_purls(tmp.path()),
        vec![PURL1.to_string(), PURL2.to_string()],
        "--save-only must keep recording uninstalled versions"
    );
}

/// A purl already tracked in the manifest counts as PRESENT: updating its
/// record keeps working on hosts without the installed copy (manifest
/// maintenance), while untracked uninstalled versions still narrow away.
#[tokio::test]
#[serial]
async fn get_ghsa_manifest_membership_counts_as_presence() {
    let server = MockServer::start().await;
    mock_ghsa_fanout(&server).await;
    mock_view(&server, UUID1, PURL1).await;

    let tmp = tempfile::tempdir().unwrap();
    // Seed a manifest that already tracks PURL1 at an OLDER uuid; nothing
    // is installed. save_only=false, so narrowing applies — the tracked
    // purl survives it and gets updated; PURL2 narrows away.
    let socket_dir = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket_dir).unwrap();
    std::fs::write(
        socket_dir.join("manifest.json"),
        serde_json::json!({
            "patches": {
                PURL1: {
                    "uuid": "99999999-9999-4999-8999-999999999999",
                    "exportedAt": "2023-01-01T00:00:00Z",
                    "files": {},
                    "vulnerabilities": {},
                    "description": "old", "license": "MIT", "tier": "free"
                }
            }
        })
        .to_string(),
    )
    .unwrap();

    let args = get_args(GHSA, tmp.path(), server.uri());
    let code = socket_patch_cli::commands::get::run(args).await;
    // The apply step may fail (nothing installed) — the record update is
    // what this test pins; accept either exit but require the manifest
    // state below.
    let _ = code;

    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(socket_dir.join("manifest.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        manifest["patches"][PURL1]["uuid"], UUID1,
        "the tracked purl must be updated to the new uuid"
    );
    assert!(
        manifest["patches"][PURL2].is_null(),
        "the untracked uninstalled version must be narrowed out"
    );
}

/// `--mode hosted|vendored` + `--save-only` is a usage conflict: exit 1
/// (get's self-enforced-conflict style), before any network contact.
#[tokio::test]
#[serial]
async fn mode_with_save_only_conflicts_exit_one_before_network() {
    let server = MockServer::start().await;

    let tmp = tempfile::tempdir().unwrap();
    for mode in [ScanMode::Hosted, ScanMode::Vendored] {
        let mut args = get_args(UUID1, tmp.path(), server.uri());
        args.mode = Some(mode);
        args.save_only = true;
        let code = socket_patch_cli::commands::get::run(args).await;
        assert_eq!(code, 1, "--save-only + --mode {mode:?} must be rejected");
    }
    assert!(
        server.received_requests().await.unwrap_or_default().is_empty(),
        "the conflict must be rejected before any network contact"
    );
    assert!(!tmp.path().join(".socket").exists());
}

/// `--all-releases` disables the coarse narrowing: both versions are
/// recorded even though only 1.0.0 is installed (agent mode, save+apply —
/// apply tolerates the uninstalled entry as a skip).
#[tokio::test]
#[serial]
async fn get_ghsa_all_releases_disables_narrowing() {
    let server = MockServer::start().await;
    mock_ghsa_fanout(&server).await;
    mock_view(&server, UUID1, PURL1).await;
    mock_view(&server, UUID2, PURL2).await;

    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());

    let mut args = get_args(GHSA, tmp.path(), server.uri());
    args.all_releases = true;
    let code = socket_patch_cli::commands::get::run(args).await;
    assert_eq!(code, 0, "--all-releases run should succeed");

    assert_eq!(
        read_manifest_purls(tmp.path()),
        vec![PURL1.to_string(), PURL2.to_string()],
        "--all-releases must record every found version"
    );
}
