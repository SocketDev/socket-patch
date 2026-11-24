//! Agent-mode `scan` / `get` replacing a recorded patch with another one
//! for the same package (#2096).
//!
//! Patch A changes `index.js` and `lib/extra.js`; patch B changes
//! `index.js` only. Replacing A's manifest record with B's must roll
//! patch A back first: once the record is B's, nothing lists
//! `lib/extra.js`, so `apply --check` and `vex` would pass on a tree
//! holding edits from two patches and `rollback` could never restore it.
//!
//! When patch A cannot be rolled back (a file holds bytes that are
//! neither side of it), the replacement is refused, patch A stays
//! recorded and nothing in the package changes.

use std::path::{Path, PathBuf};

use base64::Engine;
use serial_test::serial;
use socket_patch_cli::commands::get::{run as get_run, GetArgs};
use socket_patch_cli::commands::rollback::{run as rollback_run, RollbackArgs};
use socket_patch_cli::commands::scan::{run as scan_run, ScanArgs, ScanMode};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";
const NAME: &str = "agent-replace";
const VERSION: &str = "1.0.0";
const PURL: &str = "pkg:npm/agent-replace@1.0.0";
const UUID_A: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const UUID_B: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

const INDEX: &str = "index.js";
const EXTRA: &str = "lib/extra.js";
const INDEX_ORIGINAL: &[u8] = b"module.exports = 'index original';\n";
const INDEX_A: &[u8] = b"module.exports = 'index patch A';\n";
const INDEX_B: &[u8] = b"module.exports = 'index patch B';\n";
const EXTRA_ORIGINAL: &[u8] = b"module.exports = 'extra original';\n";
const EXTRA_A: &[u8] = b"module.exports = 'extra patch A';\n";

/// One file of a patch: `(path in the package, original bytes, patched bytes)`.
type PatchFile = (&'static str, &'static [u8], &'static [u8]);

const PATCH_A: &[PatchFile] = &[
    (INDEX, INDEX_ORIGINAL, INDEX_A),
    (EXTRA, EXTRA_ORIGINAL, EXTRA_A),
];
const PATCH_B: &[PatchFile] = &[(INDEX, INDEX_ORIGINAL, INDEX_B)];

#[path = "common/mod.rs"]
mod common;
use common::git_sha256;

fn common(cwd: &Path, server: &MockServer) -> socket_patch_cli::args::GlobalArgs {
    socket_patch_cli::args::GlobalArgs {
        cwd: cwd.to_path_buf(),
        org: Some(ORG.to_string()),
        json: true,
        yes: true,
        api_token: Some("fake".to_string()),
        api_url: Some(server.uri()),
        ..socket_patch_cli::args::GlobalArgs::default()
    }
}

fn installed(root: &Path, file: &str) -> PathBuf {
    root.join("node_modules").join(NAME).join(file)
}

fn read(root: &Path, file: &str) -> Vec<u8> {
    std::fs::read(installed(root, file)).unwrap()
}

/// Lay down (or re-lay, simulating a reinstall) the pristine package.
fn install(root: &Path) {
    std::fs::write(
        root.join("package.json"),
        r#"{ "name": "agent-replace-test", "version": "0.0.0" }"#,
    )
    .unwrap();
    let pkg = root.join("node_modules").join(NAME);
    std::fs::create_dir_all(pkg.join("lib")).unwrap();
    std::fs::write(
        pkg.join("package.json"),
        format!(r#"{{ "name": "{NAME}", "version": "{VERSION}" }}"#),
    )
    .unwrap();
    std::fs::write(installed(root, INDEX), INDEX_ORIGINAL).unwrap();
    std::fs::write(installed(root, EXTRA), EXTRA_ORIGINAL).unwrap();
}

/// Make the patch API serve exactly one patch for the package: `uuid`,
/// changing `files`. Replaces whatever it served before, the way the API
/// starts serving a newer patch for a purl.
async fn serve(server: &MockServer, uuid: &str, files: &[PatchFile]) {
    server.reset().await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": PURL,
                "patches": [{
                    "uuid": uuid, "purl": PURL,
                    "tier": "free", "cveIds": [], "ghsaIds": [],
                    "severity": "high", "title": "patch replacement fixture"
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
                "uuid": uuid, "purl": PURL,
                "publishedAt": "2024-01-01T00:00:00Z",
                "description": "x", "license": "MIT", "tier": "free",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;
    mount_view(server, PURL, uuid, files).await;
}

/// Serve the view of patch `uuid` for `purl`, changing `files`.
async fn mount_view(server: &MockServer, purl: &str, uuid: &str, files: &[PatchFile]) {
    let b64 = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
    let files: serde_json::Map<String, serde_json::Value> = files
        .iter()
        .map(|(file, before, after)| {
            (
                format!("package/{file}"),
                serde_json::json!({
                    "beforeHash": git_sha256(before),
                    "afterHash": git_sha256(after),
                    "blobContent": b64(after),
                    "beforeBlobContent": b64(before),
                }),
            )
        })
        .collect();
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{uuid}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": uuid,
            "purl": purl,
            "publishedAt": "2024-01-01T00:00:00Z",
            "files": files,
            "vulnerabilities": {},
            "description": "x", "license": "MIT", "tier": "free",
        })))
        .mount(server)
        .await;
}

fn manifest(root: &Path) -> serde_json::Value {
    let text = std::fs::read_to_string(root.join(".socket/manifest.json")).unwrap();
    serde_json::from_str(&text).unwrap()
}

fn recorded_uuid(root: &Path) -> String {
    manifest(root)["patches"][PURL]["uuid"]
        .as_str()
        .expect("the package has a manifest record")
        .to_owned()
}

/// The files the manifest record of the package lists, sorted.
fn recorded_files(root: &Path) -> Vec<String> {
    let mut files: Vec<String> = manifest(root)["patches"][PURL]["files"]
        .as_object()
        .expect("the record lists files")
        .keys()
        .cloned()
        .collect();
    files.sort();
    files
}

async fn agent_scan(root: &Path, server: &MockServer) -> i32 {
    // Same scrub as in_process_scan.rs: an ambient venv would add purls.
    std::env::remove_var("VIRTUAL_ENV");
    scan_run(ScanArgs {
        socket_yml: Default::default(),
        paths: Vec::new(),
        packages: Vec::new(),
        common: common(root, server),
        batch_size: Some(100),
        prune: false,
        sync: false,
        mode: Some(ScanMode::Agent),
        all_releases: false,
        vex: Default::default(),
        rollout: Default::default(),
    })
    .await
}

async fn agent_get(root: &Path, server: &MockServer, uuid: &str, save_only: bool) -> i32 {
    get_run(GetArgs {
        common: common(root, server),
        identifier: uuid.to_string(),
        id: true,
        cve: false,
        ghsa: false,
        package: false,
        save_only,
        all_releases: false,
        mode: Some(ScanMode::Agent),
    })
    .await
}

async fn rollback_all(root: &Path, server: &MockServer) -> i32 {
    rollback_run(RollbackArgs {
        targets: Vec::new(),
        common: common(root, server),
        preserve_state: false,
    })
    .await
}

/// Install the package and apply patch A with an agent scan.
async fn project_with_patch_a(root: &Path, server: &MockServer) {
    install(root);
    serve(server, UUID_A, PATCH_A).await;
    assert_eq!(agent_scan(root, server).await, 0, "patch A must apply");
    assert_eq!(read(root, INDEX), INDEX_A);
    assert_eq!(read(root, EXTRA), EXTRA_A);
    assert_eq!(recorded_uuid(root), UUID_A);
}

/// The issue's repro: a re-scan that replaces patch A with patch B.
#[tokio::test]
#[serial]
async fn scan_replacing_a_patch_restores_the_files_only_the_old_patch_changed() {
    let server = MockServer::start().await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    project_with_patch_a(root, &server).await;

    serve(&server, UUID_B, PATCH_B).await;
    assert_eq!(agent_scan(root, &server).await, 0);

    assert_eq!(recorded_uuid(root), UUID_B);
    assert_eq!(recorded_files(root), ["package/index.js"]);
    assert_eq!(read(root, INDEX), INDEX_B, "patch B's file is patched");
    assert_eq!(
        read(root, EXTRA),
        EXTRA_ORIGINAL,
        "a file only the replaced patch changed must be put back"
    );

    // With nothing left behind, a rollback gives the whole package back.
    assert_eq!(rollback_all(root, &server).await, 0);
    assert_eq!(read(root, INDEX), INDEX_ORIGINAL);
    assert_eq!(read(root, EXTRA), EXTRA_ORIGINAL);
}

/// The single-uuid `get` path records through its own function.
#[tokio::test]
#[serial]
async fn get_by_uuid_replacing_a_patch_restores_the_files_only_the_old_patch_changed() {
    let server = MockServer::start().await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    project_with_patch_a(root, &server).await;

    serve(&server, UUID_B, PATCH_B).await;
    assert_eq!(agent_get(root, &server, UUID_B, false).await, 0);

    assert_eq!(recorded_uuid(root), UUID_B);
    assert_eq!(read(root, INDEX), INDEX_B);
    assert_eq!(
        read(root, EXTRA),
        EXTRA_ORIGINAL,
        "a file only the replaced patch changed must be put back"
    );
}

/// `--save-only` records patch B without applying it. Patch A is still
/// rolled back, because after this run no record could: the package is
/// left as a `--save-only` of a new patch leaves it, original and
/// recorded, for the later `apply`.
#[tokio::test]
#[serial]
async fn save_only_replacement_still_rolls_the_old_patch_back() {
    let server = MockServer::start().await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    project_with_patch_a(root, &server).await;

    serve(&server, UUID_B, PATCH_B).await;
    assert_eq!(agent_get(root, &server, UUID_B, true).await, 0);

    assert_eq!(recorded_uuid(root), UUID_B);
    assert_eq!(read(root, EXTRA), EXTRA_ORIGINAL);
    assert_eq!(
        read(root, INDEX),
        INDEX_ORIGINAL,
        "--save-only does not apply the new patch"
    );
}

/// `--strict` refuses to patch a file that holds neither side of the
/// patch. The file both patches change must reach the nested apply at its
/// original bytes, not at patch A's.
#[tokio::test]
#[serial]
async fn strict_replacement_applies_the_new_patch_to_the_shared_file() {
    let server = MockServer::start().await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    project_with_patch_a(root, &server).await;

    serve(&server, UUID_B, PATCH_B).await;
    std::env::remove_var("VIRTUAL_ENV");
    let mut flags = common(root, &server);
    flags.strict = true;
    let code = scan_run(ScanArgs {
        socket_yml: Default::default(),
        paths: Vec::new(),
        packages: Vec::new(),
        common: flags,
        batch_size: Some(100),
        prune: false,
        sync: false,
        mode: Some(ScanMode::Agent),
        all_releases: false,
        vex: Default::default(),
        rollout: Default::default(),
    })
    .await;

    assert_eq!(code, 0);
    assert_eq!(recorded_uuid(root), UUID_B);
    assert_eq!(read(root, INDEX), INDEX_B);
    assert_eq!(read(root, EXTRA), EXTRA_ORIGINAL);
}

/// Two installed copies, one of which cannot be rolled back: the refusal
/// is decided before anything is written, so the other copy keeps patch
/// A whole.
#[tokio::test]
#[serial]
async fn refused_replacement_leaves_every_copy_as_it_was() {
    let server = MockServer::start().await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    install(root);
    // A nested duplicate of the same version under another package.
    let host = root.join("node_modules/host");
    let nested = host.join("node_modules").join(NAME);
    std::fs::create_dir_all(nested.join("lib")).unwrap();
    std::fs::write(
        host.join("package.json"),
        r#"{ "name": "host", "version": "1.0.0" }"#,
    )
    .unwrap();
    std::fs::write(
        nested.join("package.json"),
        format!(r#"{{ "name": "{NAME}", "version": "{VERSION}" }}"#),
    )
    .unwrap();
    std::fs::write(nested.join(INDEX), INDEX_ORIGINAL).unwrap();
    std::fs::write(nested.join(EXTRA), EXTRA_ORIGINAL).unwrap();

    serve(&server, UUID_A, PATCH_A).await;
    assert_eq!(agent_scan(root, &server).await, 0);
    assert_eq!(read(root, EXTRA), EXTRA_A);
    assert_eq!(
        std::fs::read(nested.join(EXTRA)).unwrap(),
        EXTRA_A,
        "the nested copy is patched too"
    );
    let drifted: &[u8] = b"module.exports = 'edited by hand';\n";
    std::fs::write(nested.join(EXTRA), drifted).unwrap();

    serve(&server, UUID_B, PATCH_B).await;
    assert_eq!(agent_scan(root, &server).await, 1);

    assert_eq!(recorded_uuid(root), UUID_A);
    for (file, bytes) in [(INDEX, INDEX_A), (EXTRA, EXTRA_A)] {
        assert_eq!(read(root, file), bytes, "{file} of the root copy");
    }
    assert_eq!(std::fs::read(nested.join(INDEX)).unwrap(), INDEX_A);
    assert_eq!(std::fs::read(nested.join(EXTRA)).unwrap(), drifted);
}

/// A reinstall already put the original files back: nothing to restore,
/// and the replacement goes through.
#[tokio::test]
#[serial]
async fn replacement_after_a_reinstall_goes_through() {
    let server = MockServer::start().await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    project_with_patch_a(root, &server).await;
    install(root);

    serve(&server, UUID_B, PATCH_B).await;
    assert_eq!(agent_scan(root, &server).await, 0);

    assert_eq!(recorded_uuid(root), UUID_B);
    assert_eq!(read(root, INDEX), INDEX_B);
    assert_eq!(read(root, EXTRA), EXTRA_ORIGINAL);
}

/// The package is not installed (a checkout before its install): the
/// record is replaced, as before.
#[tokio::test]
#[serial]
async fn replacement_of_a_package_that_is_not_installed_goes_through() {
    let server = MockServer::start().await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    project_with_patch_a(root, &server).await;
    std::fs::remove_dir_all(root.join("node_modules")).unwrap();

    serve(&server, UUID_B, PATCH_B).await;
    assert_eq!(agent_get(root, &server, UUID_B, true).await, 0);
    assert_eq!(recorded_uuid(root), UUID_B);
}

/// A file of patch A that holds neither A's original nor A's patched
/// bytes cannot be put back. Both entry points then keep patch A's record
/// and change nothing in the package.
#[tokio::test]
#[serial]
async fn replacement_is_refused_when_a_dropped_file_cannot_be_restored() {
    let drifted: &[u8] = b"module.exports = 'edited by hand';\n";
    for by_uuid in [false, true] {
        let server = MockServer::start().await;
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        project_with_patch_a(root, &server).await;
        std::fs::write(installed(root, EXTRA), drifted).unwrap();
        let manifest_before = std::fs::read(root.join(".socket/manifest.json")).unwrap();

        serve(&server, UUID_B, PATCH_B).await;
        let code = if by_uuid {
            agent_get(root, &server, UUID_B, false).await
        } else {
            agent_scan(root, &server).await
        };

        assert_eq!(code, 1, "by_uuid={by_uuid}: the replacement must fail");
        assert_eq!(
            std::fs::read(root.join(".socket/manifest.json")).unwrap(),
            manifest_before,
            "by_uuid={by_uuid}: patch A's record must be kept"
        );
        assert_eq!(read(root, EXTRA), drifted, "by_uuid={by_uuid}");
        assert_eq!(
            read(root, INDEX),
            INDEX_A,
            "by_uuid={by_uuid}: patch B must not be applied over patch A"
        );
        // Patch B's blob has no record pointing at it.
        assert!(
            !root
                .join(".socket/blobs")
                .join(git_sha256(INDEX_B))
                .exists(),
            "by_uuid={by_uuid}: the refused patch's blob must not be left behind"
        );
    }
}

/// A recorded patch that is not on the installed copy at all: its hashes
/// match no file there (it was recorded with `--save-only` for another
/// build of the version). There is nothing of it to roll back, so the
/// corrected patch replaces it and applies.
#[tokio::test]
#[serial]
async fn replacement_of_a_patch_that_was_never_applied_goes_through() {
    const OTHER_BUILD: &[u8] = b"module.exports = 'another build';\n";
    const OTHER_PATCHED: &[u8] = b"module.exports = 'another build, patched';\n";
    let server = MockServer::start().await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    install(root);
    serve(&server, UUID_A, &[(INDEX, OTHER_BUILD, OTHER_PATCHED)]).await;
    assert_eq!(agent_get(root, &server, UUID_A, true).await, 0);
    assert_eq!(recorded_uuid(root), UUID_A);
    assert_eq!(read(root, INDEX), INDEX_ORIGINAL);

    serve(&server, UUID_B, PATCH_B).await;
    assert_eq!(agent_scan(root, &server).await, 0);

    assert_eq!(recorded_uuid(root), UUID_B);
    assert_eq!(read(root, INDEX), INDEX_B);
    assert_eq!(read(root, EXTRA), EXTRA_ORIGINAL);
}

/// The original bytes of patch A's files are gone from `.socket/blobs`
/// and the API does not serve them: patch A cannot be rolled back, so it
/// stays recorded and applied.
#[tokio::test]
#[serial]
async fn replacement_is_refused_when_an_original_blob_cannot_be_had() {
    let server = MockServer::start().await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    project_with_patch_a(root, &server).await;
    // Patch B carries `index.js`'s original; only `lib/extra.js`'s is lost.
    std::fs::remove_file(root.join(".socket/blobs").join(git_sha256(EXTRA_ORIGINAL))).unwrap();

    serve(&server, UUID_B, PATCH_B).await;
    assert_eq!(agent_scan(root, &server).await, 1);

    assert_eq!(recorded_uuid(root), UUID_A);
    assert_eq!(read(root, INDEX), INDEX_A);
    assert_eq!(read(root, EXTRA), EXTRA_A);
}

/// Replace the recorded patch with patch B through the engine `scan` and
/// `get` share, for its envelope: `(exit code, envelope)`.
async fn engine_replace_with_b(root: &Path, server: &MockServer) -> (i32, serde_json::Value) {
    serve(server, UUID_B, PATCH_B).await;
    engine_get(root, server, &[(PURL, UUID_B)]).await
}

/// Run the engine `scan` and `get` share over `selected` (`(purl, uuid)`
/// of patches whose views the mock serves): `(exit code, envelope)`.
async fn engine_get(
    root: &Path,
    server: &MockServer,
    selected: &[(&str, &str)],
) -> (i32, serde_json::Value) {
    use socket_patch_cli::commands::get::{
        download_and_apply_patches_with, DownloadParams, DownloadRun,
    };
    use socket_patch_core::api::client::{get_api_client_with_overrides, ApiClientEnvOverrides};
    use socket_patch_core::api::types::PatchSearchResult;

    let (api_client, _) = get_api_client_with_overrides(ApiClientEnvOverrides {
        api_url: Some(server.uri()),
        api_token: Some("fake".to_string()),
        org_slug: Some(ORG.to_string()),
        proxy_url: None,
    })
    .await;
    let flags = common(root, server);
    let params = DownloadParams {
        cwd: root.to_path_buf(),
        manifest_path: root.join(".socket/manifest.json"),
        save_only: false,
        global: false,
        global_prefix: None,
        json: true,
        silent: true,
        strict: false,
        allow_patch_conflicts: false,
        user_patch_skips_reported: false,
        ecosystems: None,
        persist_blobs: true,
        patch_server_url: None,
        patch_mirror_url: None,
        all_releases: true,
    };
    let selected: Vec<PatchSearchResult> = selected
        .iter()
        .map(|(purl, uuid)| PatchSearchResult {
            uuid: (*uuid).into(),
            purl: (*purl).into(),
            published_at: "2024-06-01T00:00:00Z".into(),
            description: "x".into(),
            license: "MIT".into(),
            tier: "free".into(),
            vulnerabilities: Default::default(),
        })
        .collect();
    let run = DownloadRun {
        api_client: &api_client,
        common: &flags,
    };
    let (code, env) = download_and_apply_patches_with(&selected, &params, &run).await;
    (code, env.to_value())
}

/// Two packages are replaced in one run and the original blob of one is
/// gone. That one is refused. The other does not depend on the blob: its
/// old patch is rolled back and its replacement applied.
#[tokio::test]
#[serial]
async fn a_missing_blob_refuses_only_the_package_that_needs_it() {
    const OTHER: &str = "agent-replace-two";
    const OTHER_PURL: &str = "pkg:npm/agent-replace-two@1.0.0";
    const OTHER_A: &str = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
    const OTHER_B: &str = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
    const TWO_ORIGINAL: &[u8] = b"module.exports = 'two original';\n";
    const TWO_A: &[u8] = b"module.exports = 'two patch A';\n";
    const TWO_EXTRA_ORIGINAL: &[u8] = b"module.exports = 'two extra original';\n";
    const TWO_EXTRA_A: &[u8] = b"module.exports = 'two extra patch A';\n";
    const TWO_B: &[u8] = b"module.exports = 'two patch B';\n";

    let server = MockServer::start().await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    install(root);
    let other = root.join("node_modules").join(OTHER);
    std::fs::create_dir_all(other.join("lib")).unwrap();
    std::fs::write(
        other.join("package.json"),
        format!(r#"{{ "name": "{OTHER}", "version": "{VERSION}" }}"#),
    )
    .unwrap();
    std::fs::write(other.join(INDEX), TWO_ORIGINAL).unwrap();
    std::fs::write(other.join(EXTRA), TWO_EXTRA_ORIGINAL).unwrap();

    mount_view(&server, PURL, UUID_A, PATCH_A).await;
    mount_view(
        &server,
        OTHER_PURL,
        OTHER_A,
        &[
            (INDEX, TWO_ORIGINAL, TWO_A),
            (EXTRA, TWO_EXTRA_ORIGINAL, TWO_EXTRA_A),
        ],
    )
    .await;
    let (code, json) = engine_get(root, &server, &[(PURL, UUID_A), (OTHER_PURL, OTHER_A)]).await;
    assert_eq!(code, 0, "json={json}");
    assert_eq!(read(root, EXTRA), EXTRA_A);
    assert_eq!(std::fs::read(other.join(EXTRA)).unwrap(), TWO_EXTRA_A);

    // The first package's dropped file loses its original blob.
    std::fs::remove_file(root.join(".socket/blobs").join(git_sha256(EXTRA_ORIGINAL))).unwrap();
    server.reset().await;
    mount_view(&server, PURL, UUID_B, PATCH_B).await;
    mount_view(
        &server,
        OTHER_PURL,
        OTHER_B,
        &[(INDEX, TWO_ORIGINAL, TWO_B)],
    )
    .await;
    let (code, json) = engine_get(root, &server, &[(PURL, UUID_B), (OTHER_PURL, OTHER_B)]).await;

    assert_eq!(code, 1, "json={json}");
    assert_eq!(
        recorded_uuid(root),
        UUID_A,
        "the first package keeps patch A"
    );
    assert_eq!(read(root, INDEX), INDEX_A);
    assert_eq!(read(root, EXTRA), EXTRA_A);
    assert_eq!(
        manifest(root)["patches"][OTHER_PURL]["uuid"],
        OTHER_B,
        "the second package is replaced; json={json}"
    );
    assert_eq!(std::fs::read(other.join(INDEX)).unwrap(), TWO_B);
    assert_eq!(
        std::fs::read(other.join(EXTRA)).unwrap(),
        TWO_EXTRA_ORIGINAL
    );
    let refused: Vec<&serde_json::Value> = json["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|event| event["errorCode"] == "replaced_patch_not_restored")
        .collect();
    assert_eq!(refused.len(), 1, "json={json}");
    assert_eq!(refused[0]["purl"], PURL, "json={json}");
    let error = refused[0]["error"].as_str().unwrap();
    assert!(
        error.contains("stays recorded and applied"),
        "nothing of the refused package was written: {error}"
    );
}

/// The recorded patch changed one file, and that file was edited by hand
/// afterwards: no file of the copy holds the patch's bytes, so there is
/// nothing the rollback could restore. The replacement goes through, the
/// edited file is left alone, and a run warning names the copy.
#[tokio::test]
#[serial]
async fn replacement_warns_about_a_copy_the_old_patch_is_not_on() {
    let drifted: &[u8] = b"module.exports = 'edited by hand';\n";
    let server = MockServer::start().await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    install(root);
    serve(&server, UUID_A, &[(EXTRA, EXTRA_ORIGINAL, EXTRA_A)]).await;
    assert_eq!(agent_scan(root, &server).await, 0);
    assert_eq!(read(root, EXTRA), EXTRA_A);
    std::fs::write(installed(root, EXTRA), drifted).unwrap();

    let (code, json) = engine_replace_with_b(root, &server).await;

    assert_eq!(code, 0, "json={json}");
    assert_eq!(json["summary"]["updated"], 1, "json={json}");
    assert_eq!(recorded_uuid(root), UUID_B);
    assert_eq!(read(root, INDEX), INDEX_B);
    assert_eq!(read(root, EXTRA), drifted, "the edited file is left alone");
    let warnings: Vec<&serde_json::Value> = json["warnings"]
        .as_array()
        .map(|warnings| {
            warnings
                .iter()
                .filter(|warning| warning["code"] == "replaced_patch_not_on_copy")
                .collect()
        })
        .unwrap_or_default();
    assert_eq!(warnings.len(), 1, "json={json}");
    let detail = warnings[0]["detail"].as_str().unwrap();
    assert!(
        detail.contains(PURL) && detail.contains("aaaaaaaa"),
        "the warning names the package and the replaced patch: {detail}"
    );
}

/// The refusal in the engine's envelope: one `failed` event with its own
/// code, and no `updated` one.
#[tokio::test]
#[serial]
async fn refused_replacement_is_a_failed_event_with_its_own_code() {
    let server = MockServer::start().await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    project_with_patch_a(root, &server).await;
    std::fs::write(installed(root, EXTRA), b"edited by hand\n").unwrap();

    let (code, json) = engine_replace_with_b(root, &server).await;

    assert_eq!(code, 1, "json={json}");
    assert_eq!(json["status"], "partialFailure", "json={json}");
    assert_eq!(json["summary"]["updated"], 0, "json={json}");
    assert_eq!(json["summary"]["failed"], 1, "json={json}");
    let failed: Vec<&serde_json::Value> = json["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|event| event["purl"] == PURL)
        .collect();
    assert_eq!(failed.len(), 1, "json={json}");
    assert_eq!(failed[0]["action"], "failed", "json={json}");
    assert_eq!(failed[0]["uuid"], UUID_B, "json={json}");
    assert_eq!(
        failed[0]["errorCode"], "replaced_patch_not_restored",
        "json={json}"
    );
    assert_eq!(recorded_uuid(root), UUID_A);
    assert_eq!(read(root, INDEX), INDEX_A);
}

/// A replacement that lists every file of the old patch ends on the new
/// patch's bytes, and a rollback gives the originals back.
#[tokio::test]
#[serial]
async fn replacement_with_the_same_files_ends_on_the_new_patch() {
    const INDEX_A2: &[u8] = b"module.exports = 'index patch A2';\n";
    const EXTRA_A2: &[u8] = b"module.exports = 'extra patch A2';\n";
    let server = MockServer::start().await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    project_with_patch_a(root, &server).await;

    serve(
        &server,
        UUID_B,
        &[
            (INDEX, INDEX_ORIGINAL, INDEX_A2),
            (EXTRA, EXTRA_ORIGINAL, EXTRA_A2),
        ],
    )
    .await;
    assert_eq!(agent_scan(root, &server).await, 0);

    assert_eq!(recorded_uuid(root), UUID_B);
    assert_eq!(read(root, INDEX), INDEX_A2);
    assert_eq!(read(root, EXTRA), EXTRA_A2);
    assert_eq!(rollback_all(root, &server).await, 0);
    assert_eq!(read(root, INDEX), INDEX_ORIGINAL);
    assert_eq!(read(root, EXTRA), EXTRA_ORIGINAL);
}
