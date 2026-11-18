//! Multi-platform (per-`platform`) RubyGems patching coverage.
//!
//! RubyGems ships platform-specific gems — `nokogiri-1.16.5-x86_64-linux`,
//! `nokogiri-1.16.5-arm64-darwin`, … — alongside the generic ruby gem.
//! Each is a distinct release with its own compiled files, distinguished
//! by a `?platform=` PURL qualifier. An environment installs exactly one,
//! so this mirrors PyPI's one-installed-variant model.
//!
//! Unlike the pypi test, this needs no `gem` binary: a platform gem on
//! disk is just `gems/<name>-<version>-<platform>/lib/<name>.rb`, so we
//! synthesize it under a `vendor/bundle/ruby/*/gems` tree (what the
//! crawler scans in local mode) and serve matching hashes via wiremock.
//!
//! Behaviors pinned:
//!   * `scan` (narrow, default) stores only the installed platform's patch.
//!   * `scan --all-releases` (broad) stores every platform variant; apply
//!     still patches with the installed platform only.
//!   * `remove <base PURL>` over a broad manifest removes ALL platform
//!     variants and rolls back the file without spurious failure.
//!   * `rollback` (no id) over a broad manifest exits 0.
//!   * `rollback`/`remove` over a broad manifest succeed even when the
//!     UNINSTALLED sibling variant's before-blob is missing and
//!     unfetchable — the gate covers only the narrowed (installed)
//!     variant, online and `--offline`.

use std::path::{Path, PathBuf};

use base64::Engine;
use serial_test::serial;
use socket_patch_cli::commands::remove::{run as remove_run, RemoveArgs};
use socket_patch_cli::commands::rollback::{run as rollback_run, RollbackArgs};
use socket_patch_cli::commands::scan::{run as scan_run, ScanArgs};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";
const GEM_NAME: &str = "nokogiri";
const GEM_VERSION: &str = "1.16.5";

const UUID_INSTALLED: &str = "11111111-1111-4111-8111-aaaaaaaaaaaa";
const UUID_OTHER: &str = "22222222-2222-4222-8222-bbbbbbbbbbbb";

const PLATFORM_INSTALLED: &str = "x86_64-linux";
const PLATFORM_OTHER: &str = "arm64-darwin";

const MARKER_INSTALLED: &[u8] = b"\n# SOCKET-GEM-INSTALLED-X86_64\n";

/// The pristine on-disk bytes of the installed gem's `lib/nokogiri.rb`.
const ORIGINAL_BYTES: &[u8] = b"module Nokogiri\n  VERSION = '1.16.5'\nend\n";

/// The exact bytes a correct apply must produce (original + marker).
fn patched_bytes() -> Vec<u8> {
    let mut p = ORIGINAL_BYTES.to_vec();
    p.extend_from_slice(MARKER_INSTALLED);
    p
}

/// The "other" (darwin) distribution's bytes. A distinct distribution, so
/// its `beforeHash` never matches the on-disk linux gem. Hoisted to the top
/// level so tests can recompute its hashes independently of `setup_mock` and
/// assert the manifest actually stored *this* variant's patch data.
const DARWIN_BEFORE_BYTES: &[u8] = b"# nokogiri.rb from the arm64-darwin gem\n";
const DARWIN_MARKER: &[u8] = b"\n# DARWIN-MARKER\n";

fn darwin_after_bytes() -> Vec<u8> {
    let mut p = DARWIN_BEFORE_BYTES.to_vec();
    p.extend_from_slice(DARWIN_MARKER);
    p
}

#[path = "common/mod.rs"]
mod common;
use common::git_sha256;

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn base_purl() -> String {
    format!("pkg:gem/{GEM_NAME}@{GEM_VERSION}")
}

fn qualified(platform: &str) -> String {
    format!("{}?platform={platform}", base_purl())
}

/// Create an installed platform gem under the cwd's vendor/bundle tree.
/// Returns the path to the patchable file (`lib/<name>.rb`).
fn install_platform_gem(cwd: &Path, platform: &str, contents: &[u8]) -> PathBuf {
    let gems = cwd
        .join("vendor")
        .join("bundle")
        .join("ruby")
        .join("3.0.0")
        .join("gems");
    let gem_dir = gems.join(format!("{GEM_NAME}-{GEM_VERSION}-{platform}"));
    let lib = gem_dir.join("lib");
    std::fs::create_dir_all(&lib).expect("create gem lib dir");
    let file = lib.join(format!("{GEM_NAME}.rb"));
    std::fs::write(&file, contents).expect("write gem file");
    file
}

/// Stand up a wiremock advertising two platform variants for the base
/// PURL. Only the installed platform's `beforeHash` matches the on-disk
/// `lib/nokogiri.rb`.
async fn setup_mock(
    server: &MockServer,
    installed_before_hash: &str,
    installed_after_hash: &str,
    installed_before_bytes: &[u8],
    installed_after_bytes: &[u8],
) {
    setup_mock_with_other(
        server,
        installed_before_hash,
        installed_after_hash,
        installed_before_bytes,
        installed_after_bytes,
        UUID_OTHER,
        &darwin_after_bytes(),
    )
    .await;
}

/// [`setup_mock`] with the darwin variant's patch chosen by the caller:
/// its uuid (`other_uuid`) and patched bytes (`other_after`).
#[allow(clippy::too_many_arguments)]
async fn setup_mock_with_other(
    server: &MockServer,
    installed_before_hash: &str,
    installed_after_hash: &str,
    installed_before_bytes: &[u8],
    installed_after_bytes: &[u8],
    other_uuid: &str,
    other_after: &[u8],
) {
    let base = base_purl();

    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": base,
                "patches": [
                    { "uuid": UUID_INSTALLED, "purl": qualified(PLATFORM_INSTALLED),
                      "tier": "free", "cveIds": [], "ghsaIds": [],
                      "severity": "high", "title": "linux gem" },
                    { "uuid": other_uuid, "purl": qualified(PLATFORM_OTHER),
                      "tier": "free", "cveIds": [], "ghsaIds": [],
                      "severity": "high", "title": "darwin gem" },
                ]
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
            "patches": [
                { "uuid": UUID_INSTALLED, "purl": qualified(PLATFORM_INSTALLED),
                  "publishedAt": "2024-01-01T00:00:00Z", "description": "linux gem",
                  "license": "MIT", "tier": "free", "vulnerabilities": {} },
                { "uuid": other_uuid, "purl": qualified(PLATFORM_OTHER),
                  "publishedAt": "2024-01-01T00:00:00Z", "description": "darwin gem",
                  "license": "MIT", "tier": "free", "vulnerabilities": {} },
            ],
            "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;

    // Installed (linux) variant: hashes match the on-disk file.
    mount_view(
        server,
        UUID_INSTALLED,
        &qualified(PLATFORM_INSTALLED),
        installed_before_hash,
        installed_after_hash,
        installed_before_bytes,
        installed_after_bytes,
    )
    .await;

    // Other (darwin) variant: a different distribution's bytes, so its
    // beforeHash never matches the installed linux gem.
    mount_view(
        server,
        other_uuid,
        &qualified(PLATFORM_OTHER),
        &git_sha256(DARWIN_BEFORE_BYTES),
        &git_sha256(other_after),
        DARWIN_BEFORE_BYTES,
        other_after,
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
async fn mount_view(
    server: &MockServer,
    uuid: &str,
    purl: &str,
    before_hash: &str,
    after_hash: &str,
    before_bytes: &[u8],
    after_bytes: &[u8],
) {
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{uuid}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": uuid,
            "purl": purl,
            "publishedAt": "2024-01-01T00:00:00Z",
            "files": {
                "lib/nokogiri.rb": {
                    "beforeHash": before_hash,
                    "afterHash": after_hash,
                    "blobContent": b64(after_bytes),
                    "beforeBlobContent": b64(before_bytes),
                }
            },
            "vulnerabilities": {},
            "description": "gem multi-platform fixture",
            "license": "MIT",
            "tier": "free",
        })))
        .mount(server)
        .await;
}

fn scan_args(cwd: &Path, api_url: String, all_releases: bool) -> ScanArgs {
    ScanArgs {
        socket_yml: Default::default(),
        paths: Vec::new(),
        packages: Vec::new(),
        common: socket_patch_cli::args::GlobalArgs {
            cwd: cwd.to_path_buf(),
            org: Some(ORG.to_string()),
            json: true,
            yes: true,
            global: false,
            global_prefix: None,
            api_url: Some(api_url),
            api_token: Some("fake".to_string()),
            ecosystems: Some(vec!["gem".to_string()]),
            dry_run: false,
            ..socket_patch_cli::args::GlobalArgs::default()
        },
        batch_size: Some(100),
        // apply (not sync) so the post-sync GC doesn't sweep beforeHash
        // blobs the later rollback/remove needs offline.
        prune: false,
        sync: false,
        mode: Some(socket_patch_cli::commands::scan::ScanMode::Agent),
        all_releases,
        vex: Default::default(),
        rollout: Default::default(),
    }
}

fn manifest_keys(cwd: &Path) -> Vec<String> {
    let path = cwd.join(".socket").join("manifest.json");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("manifest not found at {}", path.display()));
    let v: serde_json::Value = serde_json::from_str(&raw).expect("manifest json");
    v["patches"]
        .as_object()
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default()
}

fn read_file(file: &Path) -> Vec<u8> {
    std::fs::read(file).expect("read file")
}

/// Return the full patch record stored under `purl` in the manifest, or panic
/// if absent. Lets a test assert that a stored variant carries the *correct*
/// uuid and per-file before/after hashes — not merely that its key exists.
fn manifest_record(cwd: &Path, purl: &str) -> serde_json::Value {
    let path = cwd.join(".socket").join("manifest.json");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("manifest not found at {}", path.display()));
    let v: serde_json::Value = serde_json::from_str(&raw).expect("manifest json");
    let rec = v["patches"].get(purl).unwrap_or_else(|| {
        panic!(
            "no manifest record for {purl}; have {:?}",
            manifest_keys(cwd)
        )
    });
    rec.clone()
}

/// Assert the manifest record for `purl` stores `uuid` plus the exact
/// git-sha256 before/after hashes for `lib/nokogiri.rb`. The expected hashes
/// are derived independently in the test from the raw distribution bytes, so
/// this cannot agree with a broken impl that stored the key but dropped or
/// garbled the patch payload (e.g. copied the installed variant's hashes onto
/// the darwin key).
fn assert_variant_record(cwd: &Path, purl: &str, uuid: &str, before: &[u8], after: &[u8]) {
    let rec = manifest_record(cwd, purl);
    assert_eq!(
        rec["uuid"].as_str(),
        Some(uuid),
        "manifest record for {purl} must store uuid {uuid}; got {:?}",
        rec["uuid"]
    );
    let file = &rec["files"]["lib/nokogiri.rb"];
    assert_eq!(
        file["beforeHash"].as_str(),
        Some(git_sha256(before).as_str()),
        "beforeHash for {purl} must match this variant's distribution bytes"
    );
    assert_eq!(
        file["afterHash"].as_str(),
        Some(git_sha256(after).as_str()),
        "afterHash for {purl} must match this variant's patched bytes"
    );
}

// --- Request introspection -------------------------------------------------
// Asserting only the exit code / final file bytes lets a scan that filtered
// the wrong variant, short-circuited the API, or never fetched the broad
// variants stay green. These confirm the *real* network path: which view
// endpoints scan actually hit, and that the batch carried the gem PURL.

async fn recorded(server: &MockServer) -> Vec<wiremock::Request> {
    server.received_requests().await.unwrap_or_default()
}

fn batch_bodies(reqs: &[wiremock::Request]) -> Vec<String> {
    reqs.iter()
        .filter(|r| format!("{}", r.method) == "POST" && r.url.path().ends_with("/patches/batch"))
        .map(|r| String::from_utf8_lossy(&r.body).into_owned())
        .collect()
}

fn view_gets(reqs: &[wiremock::Request], uuid: &str) -> usize {
    reqs.iter()
        .filter(|r| {
            format!("{}", r.method) == "GET"
                && r.url.path().ends_with(&format!("/patches/view/{uuid}"))
        })
        .count()
}

/// Install the linux gem, compute its hashes, stand up the mock.
async fn fixture(cwd: &Path) -> (PathBuf, MockServer) {
    let original = ORIGINAL_BYTES.to_vec();
    let file = install_platform_gem(cwd, PLATFORM_INSTALLED, &original);
    let before_hash = git_sha256(&original);
    let patched = patched_bytes();
    let after_hash = git_sha256(&patched);

    let server = MockServer::start().await;
    setup_mock(&server, &before_hash, &after_hash, &original, &patched).await;
    (file, server)
}

#[tokio::test]
#[serial]
async fn narrow_scan_keeps_only_installed_platform() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (gem_file, server) = fixture(tmp.path()).await;

    let code = scan_run(scan_args(tmp.path(), server.uri(), false)).await;
    assert_eq!(code, 0, "narrow scan+apply over a matching gem must exit 0");

    let keys = manifest_keys(tmp.path());
    assert_eq!(
        keys,
        vec![qualified(PLATFORM_INSTALLED)],
        "narrow scan must store only the installed platform variant; got {keys:?}"
    );
    // The single stored record must carry the installed variant's real
    // payload, not just an empty key.
    assert_variant_record(
        tmp.path(),
        &qualified(PLATFORM_INSTALLED),
        UUID_INSTALLED,
        ORIGINAL_BYTES,
        &patched_bytes(),
    );
    assert_eq!(
        read_file(&gem_file),
        patched_bytes(),
        "installed platform gem must be patched to exactly original+marker bytes"
    );

    // Real-path proof: the batch must have carried the gem's base PURL and
    // the installed variant's view must have been fetched (so the patched
    // bytes came from the server, not a short-circuit). NOTE: narrow scan
    // still *fetches* the other platform's view; it just discards it at
    // storage time — the narrow/broad difference is the manifest, asserted
    // above, not the set of endpoints hit.
    let reqs = recorded(&server).await;
    let bodies = batch_bodies(&reqs);
    assert!(
        bodies.iter().any(|b| b.contains(&base_purl())),
        "batch request must carry {}; bodies={bodies:?}",
        base_purl()
    );
    assert!(
        view_gets(&reqs, UUID_INSTALLED) >= 1,
        "narrow scan must fetch the installed variant's view"
    );
}

#[tokio::test]
#[serial]
async fn broad_scan_keeps_all_platforms() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (gem_file, server) = fixture(tmp.path()).await;

    let code = scan_run(scan_args(tmp.path(), server.uri(), true)).await;
    assert_eq!(code, 0, "broad scan+apply over a matching gem must exit 0");

    let mut keys = manifest_keys(tmp.path());
    keys.sort();
    let mut expected = vec![qualified(PLATFORM_INSTALLED), qualified(PLATFORM_OTHER)];
    expected.sort();
    assert_eq!(
        keys, expected,
        "broad scan must store every platform variant"
    );

    // Each stored variant must carry its OWN distribution's patch data —
    // proving broad scan genuinely fetched and stored both variants, not just
    // mirrored the installed variant's payload onto a second key.
    assert_variant_record(
        tmp.path(),
        &qualified(PLATFORM_INSTALLED),
        UUID_INSTALLED,
        ORIGINAL_BYTES,
        &patched_bytes(),
    );
    assert_variant_record(
        tmp.path(),
        &qualified(PLATFORM_OTHER),
        UUID_OTHER,
        DARWIN_BEFORE_BYTES,
        &darwin_after_bytes(),
    );

    // Apply still patches only with the installed platform's variant, and
    // must not splice in the darwin variant's bytes ("DARWIN-MARKER").
    assert_eq!(
        read_file(&gem_file),
        patched_bytes(),
        "broad apply must patch with exactly the installed platform's bytes"
    );
    assert!(
        !read_file(&gem_file)
            .windows(DARWIN_MARKER.len())
            .any(|w| w == DARWIN_MARKER),
        "broad apply must not write the other platform's distribution bytes"
    );

    // Real-path proof: broad scan must fetch BOTH variants' views.
    let reqs = recorded(&server).await;
    let bodies = batch_bodies(&reqs);
    assert!(
        bodies.iter().any(|b| b.contains(&base_purl())),
        "batch request must carry {}; bodies={bodies:?}",
        base_purl()
    );
    assert!(
        view_gets(&reqs, UUID_INSTALLED) >= 1,
        "broad scan must fetch the installed variant's view"
    );
    assert!(
        view_gets(&reqs, UUID_OTHER) >= 1,
        "broad scan must also fetch the other platform's view"
    );
}

#[tokio::test]
#[serial]
async fn remove_base_purl_clears_all_platforms_and_rolls_back() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (gem_file, server) = fixture(tmp.path()).await;

    let scan_code = scan_run(scan_args(tmp.path(), server.uri(), true)).await;
    assert_eq!(scan_code, 0, "broad scan+apply must exit 0 before remove");
    assert_eq!(manifest_keys(tmp.path()).len(), 2);
    assert_eq!(
        read_file(&gem_file),
        patched_bytes(),
        "gem must be patched before remove"
    );

    let remove_args = RemoveArgs {
        identifier: base_purl(),
        common: socket_patch_cli::args::GlobalArgs {
            cwd: tmp.path().to_path_buf(),
            org: Some(ORG.to_string()),
            api_url: Some(server.uri()),
            api_token: Some("fake".to_string()),
            json: true,
            yes: true,
            ecosystems: Some(vec!["gem".to_string()]),
            ..socket_patch_cli::args::GlobalArgs::default()
        },
        skip_rollback: false,
        preserve_state: false,
    };
    let code = remove_run(remove_args).await;
    assert_eq!(code, 0, "remove base PURL should succeed (exit 0)");

    assert!(
        manifest_keys(tmp.path()).is_empty(),
        "all platform variants should be removed from the manifest"
    );
    assert_eq!(
        read_file(&gem_file),
        ORIGINAL_BYTES,
        "remove must roll the gem file back to exactly its original bytes"
    );
}

/// Delete the uninstalled (darwin) sibling's cached before-blob,
/// returning its hash. Asserts the blob was actually cached by the broad
/// scan first — without that, the "unfetchable sibling blob" scenario
/// below would pass vacuously (nothing missing, nothing gated).
fn delete_darwin_before_blob(cwd: &Path) -> String {
    let hash = git_sha256(DARWIN_BEFORE_BYTES);
    let blob = cwd.join(".socket").join("blobs").join(&hash);
    assert!(
        blob.exists(),
        "broad scan must have cached the darwin before-blob at {}",
        blob.display()
    );
    std::fs::remove_file(&blob).expect("delete darwin before-blob");
    hash
}

fn rollback_args(cwd: &Path, api_url: String, offline: bool) -> RollbackArgs {
    RollbackArgs {
        targets: Vec::new(),
        preserve_state: false,
        common: socket_patch_cli::args::GlobalArgs {
            cwd: cwd.to_path_buf(),
            org: Some(ORG.to_string()),
            api_url: Some(api_url),
            api_token: Some("fake".to_string()),
            json: true,
            offline,
            ecosystems: Some(vec!["gem".to_string()]),
            ..socket_patch_cli::args::GlobalArgs::default()
        },
    }
}

/// A broad manifest's UNINSTALLED sibling variant resolves to the same
/// installed dir but is narrowed away by `select_installed_variants`, so
/// its before-blob is never read. With that blob missing and unfetchable
/// (the mock serves no blob endpoint — every fetch 404s), rollback must
/// still restore the installed variant. Before the fix the before-blob
/// gate ran over the whole ecosystem-scoped manifest BEFORE narrowing, so
/// the sibling's 404 aborted the entire rollback ("1 blob(s) could not be
/// downloaded. Cannot rollback.") with the installed file left patched.
#[tokio::test]
#[serial]
async fn rollback_succeeds_when_uninstalled_sibling_before_blob_unfetchable() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (gem_file, server) = fixture(tmp.path()).await;

    assert_eq!(
        scan_run(scan_args(tmp.path(), server.uri(), true)).await,
        0,
        "broad scan+apply must exit 0 before rollback"
    );
    assert_eq!(
        read_file(&gem_file),
        patched_bytes(),
        "gem must be patched before rollback"
    );
    let darwin_hash = delete_darwin_before_blob(tmp.path());

    let code = rollback_run(rollback_args(tmp.path(), server.uri(), false)).await;
    assert_eq!(
        code, 0,
        "an unfetchable before-blob for the narrowed-away sibling variant must not abort rollback"
    );
    assert_eq!(
        read_file(&gem_file),
        ORIGINAL_BYTES,
        "the installed variant must be restored to exactly its original bytes"
    );
    // The sibling never gates, so its blob must not even be requested.
    let reqs = recorded(&server).await;
    assert!(
        !reqs
            .iter()
            .any(|r| r.url.path().contains(darwin_hash.as_str())),
        "rollback must not fetch the narrowed-away sibling's before-blob; paths={:?}",
        reqs.iter()
            .map(|r| r.url.path().to_string())
            .collect::<Vec<_>>()
    );
    // v4 default: rollback removes the rolled-back group from the
    // manifest — the attempted variant AND its narrowed-away sibling
    // (half a variant group must never linger). --preserve-state keeps
    // them; the default cleans up.
    assert!(
        manifest_keys(tmp.path()).is_empty(),
        "the rolled-back variant group must leave the manifest"
    );
}

/// The `--offline` twin: with only the INSTALLED variant's blobs cached,
/// an offline rollback of the broad manifest must succeed without any
/// blob fetch. Before the fix the pre-narrowing gate counted the missing
/// sibling blob and bailed ("blob(s) are missing and --offline mode is
/// enabled") before restoring anything.
#[tokio::test]
#[serial]
async fn rollback_offline_succeeds_with_only_installed_variant_blobs_cached() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (gem_file, server) = fixture(tmp.path()).await;

    assert_eq!(
        scan_run(scan_args(tmp.path(), server.uri(), true)).await,
        0,
        "broad scan+apply must exit 0 before rollback"
    );
    assert_eq!(
        read_file(&gem_file),
        patched_bytes(),
        "gem must be patched before rollback"
    );
    delete_darwin_before_blob(tmp.path());

    // `rollback --offline` mirrors the flag into SOCKET_OFFLINE for the
    // process (apply_env_toggles); save/restore it so this #[serial]
    // binary's later tests don't inherit an offline environment.
    let prev_offline = std::env::var("SOCKET_OFFLINE").ok();
    let code = rollback_run(rollback_args(tmp.path(), server.uri(), true)).await;
    match prev_offline {
        Some(v) => std::env::set_var("SOCKET_OFFLINE", v),
        None => std::env::remove_var("SOCKET_OFFLINE"),
    }

    assert_eq!(
        code, 0,
        "--offline rollback needs only the installed variant's cached blobs"
    );
    assert_eq!(
        read_file(&gem_file),
        ORIGINAL_BYTES,
        "the installed variant must be restored to exactly its original bytes"
    );
    // No blob endpoint may be hit at all: everything needed was cached.
    let reqs = recorded(&server).await;
    assert!(
        !reqs.iter().any(|r| r.url.path().contains("/patches/blob/")),
        "--offline rollback must not fetch any blob; paths={:?}",
        reqs.iter()
            .map(|r| r.url.path().to_string())
            .collect::<Vec<_>>()
    );
}

/// `remove <base PURL>` delegates to the same rollback path: with the
/// uninstalled sibling's before-blob missing and unfetchable (404), the
/// remove must still roll back the installed variant and clear BOTH
/// manifest records. Before the fix it aborted with `rollback_failed`,
/// leaving the file patched and the manifest intact.
#[tokio::test]
#[serial]
async fn remove_succeeds_when_uninstalled_sibling_before_blob_unfetchable() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (gem_file, server) = fixture(tmp.path()).await;

    assert_eq!(
        scan_run(scan_args(tmp.path(), server.uri(), true)).await,
        0,
        "broad scan+apply must exit 0 before remove"
    );
    assert_eq!(
        read_file(&gem_file),
        patched_bytes(),
        "gem must be patched before remove"
    );
    let darwin_hash = delete_darwin_before_blob(tmp.path());

    let code = remove_run(RemoveArgs {
        identifier: base_purl(),
        common: socket_patch_cli::args::GlobalArgs {
            cwd: tmp.path().to_path_buf(),
            org: Some(ORG.to_string()),
            api_url: Some(server.uri()),
            api_token: Some("fake".to_string()),
            json: true,
            yes: true,
            ecosystems: Some(vec!["gem".to_string()]),
            ..socket_patch_cli::args::GlobalArgs::default()
        },
        skip_rollback: false,
        preserve_state: false,
    })
    .await;
    assert_eq!(
        code, 0,
        "an unfetchable before-blob for the narrowed-away sibling variant must not abort remove"
    );
    assert!(
        manifest_keys(tmp.path()).is_empty(),
        "remove must clear every platform variant from the manifest"
    );
    assert_eq!(
        read_file(&gem_file),
        ORIGINAL_BYTES,
        "remove must roll the gem file back to exactly its original bytes"
    );
    let reqs = recorded(&server).await;
    assert!(
        !reqs
            .iter()
            .any(|r| r.url.path().contains(darwin_hash.as_str())),
        "remove must not fetch the narrowed-away sibling's before-blob; paths={:?}",
        reqs.iter()
            .map(|r| r.url.path().to_string())
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
#[serial]
async fn rollback_all_over_broad_manifest_succeeds() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (gem_file, server) = fixture(tmp.path()).await;

    let scan_code = scan_run(scan_args(tmp.path(), server.uri(), true)).await;
    assert_eq!(scan_code, 0, "broad scan+apply must exit 0 before rollback");
    assert_eq!(manifest_keys(tmp.path()).len(), 2);
    assert_eq!(
        read_file(&gem_file),
        patched_bytes(),
        "gem must be patched before rollback"
    );

    let rollback_args = RollbackArgs {
        targets: Vec::new(),
        preserve_state: false,
        common: socket_patch_cli::args::GlobalArgs {
            cwd: tmp.path().to_path_buf(),
            org: Some(ORG.to_string()),
            api_url: Some(server.uri()),
            api_token: Some("fake".to_string()),
            json: true,
            ecosystems: Some(vec!["gem".to_string()]),
            ..socket_patch_cli::args::GlobalArgs::default()
        },
    };
    let code = rollback_run(rollback_args).await;
    assert_eq!(code, 0, "rollback-all over broad manifest should exit 0");
    assert_eq!(
        read_file(&gem_file),
        ORIGINAL_BYTES,
        "rollback must restore exactly the original gem file bytes"
    );
    // v4 default: rollback removes the rolled-back group from the manifest
    // — the attempted variant AND its narrowed-away sibling. (Keeping the
    // records for a later re-apply is now `--preserve-state`'s job.)
    assert!(
        manifest_keys(tmp.path()).is_empty(),
        "the rolled-back variant group must leave the manifest"
    );
}

/// A broad manifest whose UNINSTALLED variant's patch is replaced by a
/// newer one (#2096). Replacing a record rolls the recorded patch back
/// first, but nothing of the darwin record was ever applied to the linux
/// gem on disk: the re-scan must replace the record without trying to
/// roll it back on that copy (a hash mismatch that would refuse the
/// replacement on every scan), and must leave the linux gem patched.
#[tokio::test]
#[serial]
async fn broad_rescan_replaces_the_uninstalled_variants_patch() {
    const UUID_OTHER_NEW: &str = "33333333-3333-4333-8333-cccccccccccc";
    let tmp = tempfile::tempdir().expect("tempdir");
    let (gem_file, server) = fixture(tmp.path()).await;
    assert_eq!(scan_run(scan_args(tmp.path(), server.uri(), true)).await, 0);
    assert_eq!(read_file(&gem_file), patched_bytes());

    // The API now serves a newer patch for the darwin variant only.
    let mut darwin_new = DARWIN_BEFORE_BYTES.to_vec();
    darwin_new.extend_from_slice(b"\n# DARWIN-MARKER-2\n");
    server.reset().await;
    setup_mock_with_other(
        &server,
        &git_sha256(ORIGINAL_BYTES),
        &git_sha256(&patched_bytes()),
        ORIGINAL_BYTES,
        &patched_bytes(),
        UUID_OTHER_NEW,
        &darwin_new,
    )
    .await;
    assert_eq!(
        scan_run(scan_args(tmp.path(), server.uri(), true)).await,
        0,
        "replacing the uninstalled variant's record must not fail"
    );

    assert_variant_record(
        tmp.path(),
        &qualified(PLATFORM_OTHER),
        UUID_OTHER_NEW,
        DARWIN_BEFORE_BYTES,
        &darwin_new,
    );
    assert_variant_record(
        tmp.path(),
        &qualified(PLATFORM_INSTALLED),
        UUID_INSTALLED,
        ORIGINAL_BYTES,
        &patched_bytes(),
    );
    assert_eq!(
        read_file(&gem_file),
        patched_bytes(),
        "the installed variant stays patched"
    );
}

/// Make the mock serve the installed (linux) variant's patch with
/// `linux_files` and the darwin variant's patch `darwin_uuid` with
/// `darwin_files` (each a patch view's `files` object), replacing whatever
/// it served before.
async fn serve_variants(
    server: &MockServer,
    linux_files: &serde_json::Value,
    darwin_uuid: &str,
    darwin_files: serde_json::Value,
) {
    server.reset().await;
    let listing = |uuid: &str, platform: &str| {
        serde_json::json!({
            "uuid": uuid, "purl": qualified(platform),
            "tier": "free", "cveIds": [], "ghsaIds": [],
            "severity": "high", "title": platform,
            "publishedAt": "2024-01-01T00:00:00Z", "description": platform,
            "license": "MIT", "vulnerabilities": {}
        })
    };
    let patches = serde_json::json!([
        listing(UUID_INSTALLED, PLATFORM_INSTALLED),
        listing(darwin_uuid, PLATFORM_OTHER),
    ]);
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{ "purl": base_purl(), "patches": patches }],
            "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path_regex(format!(
            "^/v0/orgs/{ORG}/patches/by-package/.+$"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": patches,
            "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;
    for (uuid, platform, files) in [
        (UUID_INSTALLED, PLATFORM_INSTALLED, linux_files.clone()),
        (darwin_uuid, PLATFORM_OTHER, darwin_files),
    ] {
        Mock::given(method("GET"))
            .and(path(format!("/v0/orgs/{ORG}/patches/view/{uuid}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "uuid": uuid,
                "purl": qualified(platform),
                "publishedAt": "2024-01-01T00:00:00Z",
                "files": files,
                "vulnerabilities": {},
                "description": "gem sibling fixture",
                "license": "MIT",
                "tier": "free",
            })))
            .mount(server)
            .await;
    }
}

/// The uninstalled variant's record shares a file with the installed
/// variant's (a pure-Ruby file both distributions ship and both patches
/// change the same way), and a newer patch for it drops that file
/// (#2096). The linux copy holds that file's patched bytes, but they are
/// the linux record's: replacing the darwin record must neither be
/// refused over the copy's other file nor take the shared file back.
#[tokio::test]
#[serial]
async fn broad_rescan_leaves_a_file_the_installed_sibling_variant_shares() {
    const UUID_OTHER_NEW: &str = "44444444-4444-4444-8444-dddddddddddd";
    const SHARED: &str = "lib/nokogiri/shared.rb";
    const SHARED_ORIGINAL: &[u8] = b"# shared by every platform\n";
    const SHARED_PATCHED: &[u8] = b"# shared by every platform\n# SHARED-FIX\n";

    let tmp = tempfile::tempdir().expect("tempdir");
    let gem_file = install_platform_gem(tmp.path(), PLATFORM_INSTALLED, ORIGINAL_BYTES);
    let shared_file = gem_file.parent().unwrap().join("nokogiri/shared.rb");
    std::fs::create_dir_all(shared_file.parent().unwrap()).unwrap();
    std::fs::write(&shared_file, SHARED_ORIGINAL).unwrap();

    let entry = |before: &[u8], after: &[u8]| {
        serde_json::json!({
            "beforeHash": git_sha256(before),
            "afterHash": git_sha256(after),
            "blobContent": b64(after),
            "beforeBlobContent": b64(before),
        })
    };
    let shared = entry(SHARED_ORIGINAL, SHARED_PATCHED);
    let linux_files = serde_json::json!({
        "lib/nokogiri.rb": entry(ORIGINAL_BYTES, &patched_bytes()),
        SHARED: shared.clone(),
    });
    let darwin_main = entry(DARWIN_BEFORE_BYTES, &darwin_after_bytes());
    let server = MockServer::start().await;
    serve_variants(
        &server,
        &linux_files,
        UUID_OTHER,
        serde_json::json!({ "lib/nokogiri.rb": darwin_main.clone(), SHARED: shared }),
    )
    .await;
    assert_eq!(scan_run(scan_args(tmp.path(), server.uri(), true)).await, 0);
    assert_eq!(read_file(&gem_file), patched_bytes());
    assert_eq!(read_file(&shared_file), SHARED_PATCHED);

    // The darwin variant's newer patch no longer lists the shared file.
    serve_variants(
        &server,
        &linux_files,
        UUID_OTHER_NEW,
        serde_json::json!({ "lib/nokogiri.rb": darwin_main }),
    )
    .await;
    assert_eq!(
        scan_run(scan_args(tmp.path(), server.uri(), true)).await,
        0,
        "the replacement must not be refused over the sibling's copy"
    );

    assert_eq!(
        manifest_record(tmp.path(), &qualified(PLATFORM_OTHER))["uuid"],
        UUID_OTHER_NEW
    );
    assert_eq!(read_file(&gem_file), patched_bytes());
    assert_eq!(
        read_file(&shared_file),
        SHARED_PATCHED,
        "the shared file is the installed variant's to keep"
    );
}
