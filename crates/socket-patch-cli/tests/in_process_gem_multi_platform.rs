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

use std::path::{Path, PathBuf};

use base64::Engine;
use serial_test::serial;
use sha2::{Digest, Sha256};
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

fn git_sha256(content: &[u8]) -> String {
    let header = format!("blob {}\0", content.len());
    let mut hasher = Sha256::new();
    hasher.update(header.as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

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
                    { "uuid": UUID_OTHER, "purl": qualified(PLATFORM_OTHER),
                      "tier": "free", "cveIds": [], "ghsaIds": [],
                      "severity": "high", "title": "darwin gem" },
                ]
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path_regex(format!("^/v0/orgs/{ORG}/patches/by-package/.+$")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [
                { "uuid": UUID_INSTALLED, "purl": qualified(PLATFORM_INSTALLED),
                  "publishedAt": "2024-01-01T00:00:00Z", "description": "linux gem",
                  "license": "MIT", "tier": "free", "vulnerabilities": {} },
                { "uuid": UUID_OTHER, "purl": qualified(PLATFORM_OTHER),
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
    let other_after = darwin_after_bytes();
    mount_view(
        server,
        UUID_OTHER,
        &qualified(PLATFORM_OTHER),
        &git_sha256(DARWIN_BEFORE_BYTES),
        &git_sha256(&other_after),
        DARWIN_BEFORE_BYTES,
        &other_after,
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
        common: socket_patch_cli::args::GlobalArgs {
            cwd: cwd.to_path_buf(),
            org: Some(ORG.to_string()),
            json: true,
            yes: true,
            global: false,
            global_prefix: None,
            api_url,
            api_token: Some("fake".to_string()),
            ecosystems: Some(vec!["gem".to_string()]),
            download_mode: "diff".to_string(),
            dry_run: false,
            ..socket_patch_cli::args::GlobalArgs::default()
        },
        batch_size: 100,
        // apply (not sync) so the post-sync GC doesn't sweep beforeHash
        // blobs the later rollback/remove needs offline.
        apply: true,
        prune: false,
        sync: false,
        all_releases,
        vex: Default::default(),
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
    let rec = v["patches"]
        .get(purl)
        .unwrap_or_else(|| panic!("no manifest record for {purl}; have {:?}", manifest_keys(cwd)));
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
    assert_eq!(keys, expected, "broad scan must store every platform variant");

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
            api_url: server.uri(),
            api_token: Some("fake".to_string()),
            json: true,
            yes: true,
            ecosystems: Some(vec!["gem".to_string()]),
            ..socket_patch_cli::args::GlobalArgs::default()
        },
        skip_rollback: false,
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
        identifier: None,
        common: socket_patch_cli::args::GlobalArgs {
            cwd: tmp.path().to_path_buf(),
            org: Some(ORG.to_string()),
            api_url: server.uri(),
            api_token: Some("fake".to_string()),
            json: true,
            ecosystems: Some(vec!["gem".to_string()]),
            ..socket_patch_cli::args::GlobalArgs::default()
        },
        one_off: false,
    };
    let code = rollback_run(rollback_args).await;
    assert_eq!(code, 0, "rollback-all over broad manifest should exit 0");
    assert_eq!(
        read_file(&gem_file),
        ORIGINAL_BYTES,
        "rollback must restore exactly the original gem file bytes"
    );
    // Rollback restores files but, unlike `remove`, must NOT prune the
    // manifest — both platform variants stay recorded so they can be
    // re-applied. (If this ever flips to empty, rollback has silently become
    // a destructive remove.)
    let mut keys = manifest_keys(tmp.path());
    keys.sort();
    let mut expected = vec![qualified(PLATFORM_INSTALLED), qualified(PLATFORM_OTHER)];
    expected.sort();
    assert_eq!(
        keys, expected,
        "rollback must leave both variants in the manifest (it is not a remove)"
    );
}
