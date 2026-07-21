//! In-process regression tests: `get` must honor the global
//! `--manifest-path` flag and a relative `--cwd`.
//!
//! Regression guards:
//!
//! 1. `--manifest-path` / `SOCKET_MANIFEST_PATH` is a documented global
//!    flag ("Manifest location, resolved relative to `--cwd`") honored by
//!    apply/list/remove/rollback/repair/vendor/unlock — and by scan's own
//!    discovery and GC — but `get`'s save paths hardcoded
//!    `<cwd>/.socket/manifest.json` (and `<cwd>/.socket/blobs`). A `get`
//!    under a custom manifest path saved the patch to a location every
//!    other command then ignores: `list`/`apply` with the same
//!    `SOCKET_MANIFEST_PATH` reported no patches at all.
//!
//! 2. The nested apply step was handed `<cwd>/.socket/manifest.json` as a
//!    STRING that apply re-resolves against `--cwd`
//!    (`resolved_manifest_path`), double-joining any relative cwd:
//!    `get --cwd proj <uuid>` made the nested apply look for
//!    `proj/proj/.socket/manifest.json`, hit the no-manifest clean no-op,
//!    and report success (`applied: 1`, exit 0) without patching anything.

use std::path::Path;

use serial_test::serial;
use sha2::{Digest, Sha256};
use socket_patch_cli::args::GlobalArgs;
use socket_patch_cli::commands::get::{run, GetArgs};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";
const UUID: &str = "33333333-3333-4333-8333-333333333333";
const PURL: &str = "pkg:npm/manifest-path-test@1.0.0";

const ORIGINAL: &[u8] = b"original\n";
const PATCHED: &[u8] = b"patched\n";
/// base64 of `PATCHED` / `ORIGINAL`.
const PATCHED_B64: &str = "cGF0Y2hlZAo=";
const ORIGINAL_B64: &str = "b3JpZ2luYWwK";

/// Git-blob-style sha256 — the hash shape apply verifies against.
fn git_sha256(content: &[u8]) -> String {
    let header = format!("blob {}\0", content.len());
    let mut hasher = Sha256::new();
    hasher.update(header.as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

/// Mount the patch-view endpoint for `UUID`/`PURL` with real (git-blob)
/// hashes so the nested apply can verify and patch. Returns `after_hash`.
async fn mount_view_mock(server: &MockServer) -> String {
    let before_hash = git_sha256(ORIGINAL);
    let after_hash = git_sha256(PATCHED);
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": UUID,
            "purl": PURL,
            "publishedAt": "2024-01-01T00:00:00Z",
            "files": {
                "package/index.js": {
                    "beforeHash": before_hash,
                    "afterHash": after_hash,
                    "blobContent": PATCHED_B64,
                    "beforeBlobContent": ORIGINAL_B64,
                }
            },
            "vulnerabilities": {},
            "description": "manifest-path test fixture",
            "license": "MIT",
            "tier": "free",
        })))
        .mount(server)
        .await;
    after_hash
}

fn get_args(identifier: &str, cwd: &Path, api_url: String) -> GetArgs {
    GetArgs {
        common: GlobalArgs {
            org: Some(ORG.to_string()),
            cwd: cwd.to_path_buf(),
            yes: true,
            api_token: Some("fake-token-for-tests".to_string()),
            api_url: Some(api_url),
            json: true,
            no_telemetry: true,
            download_mode: "diff".to_string(),
            ..GlobalArgs::default()
        },
        identifier: identifier.to_string(),
        id: false,
        cve: false,
        ghsa: false,
        package: false,
        save_only: true,
        one_off: false,
        all_releases: false,
    }
}

/// Assert the patch record + blob landed under the CUSTOM manifest
/// location and nothing was written to the default `.socket/`.
fn assert_saved_at(manifest_path: &Path, after_hash: &str, default_socket: &Path) {
    let body = std::fs::read_to_string(manifest_path)
        .unwrap_or_else(|e| panic!("manifest must be at {}: {e}", manifest_path.display()));
    let m: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        m["patches"][PURL]["uuid"], UUID,
        "custom-path manifest must record the patch; manifest={m}"
    );
    // The blob must live NEXT TO the manifest — apply/rollback resolve
    // blobs from the manifest's parent dir, not from `<cwd>/.socket`.
    let blob = manifest_path
        .parent()
        .unwrap()
        .join("blobs")
        .join(after_hash);
    assert!(
        blob.exists(),
        "blob must be written next to the manifest at {}",
        blob.display()
    );
    assert!(
        !default_socket.join("manifest.json").exists(),
        "nothing must be written to the default .socket/ when --manifest-path points elsewhere"
    );
}

/// Restore the process cwd when a test that changes it exits (pass or
/// panic) so later `#[serial]` tests in this binary aren't poisoned.
struct CwdGuard(std::path::PathBuf);
impl CwdGuard {
    fn change_to(dir: &Path) -> Self {
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir).unwrap();
        Self(prev)
    }
}
impl Drop for CwdGuard {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.0);
    }
}

// ---------------------------------------------------------------------------
// 1. --manifest-path honored on the UUID flow (save_and_apply_patch)
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn get_by_uuid_honors_custom_manifest_path() {
    let server = MockServer::start().await;
    let after_hash = mount_view_mock(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    let mut args = get_args(UUID, tmp.path(), server.uri());
    args.common.manifest_path = "custom/mp.json".to_string();

    let code = run(args).await;
    assert_eq!(code, 0, "save-only get must succeed");

    assert_saved_at(
        &tmp.path().join("custom/mp.json"),
        &after_hash,
        &tmp.path().join(".socket"),
    );
}

// ---------------------------------------------------------------------------
// 2. --manifest-path honored on the search flow (download_and_apply_patches)
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn get_by_purl_honors_custom_manifest_path() {
    let server = MockServer::start().await;
    let after_hash = mount_view_mock(&server).await;
    // PURL identifier → package search → one free patch auto-selected.
    Mock::given(method("GET"))
        .and(path_regex(format!(
            r"^/v0/orgs/{ORG}/patches/by-package/.+$"
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
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let mut args = get_args(PURL, tmp.path(), server.uri());
    args.common.manifest_path = "custom/mp.json".to_string();

    let code = run(args).await;
    assert_eq!(code, 0, "save-only get by PURL must succeed");

    assert_saved_at(
        &tmp.path().join("custom/mp.json"),
        &after_hash,
        &tmp.path().join(".socket"),
    );
}

// ---------------------------------------------------------------------------
// 3. Relative --cwd: the nested apply must find the manifest it just wrote
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn get_with_relative_cwd_actually_applies() {
    let server = MockServer::start().await;
    mount_view_mock(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    // A project in `proj/` with the target package installed.
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    std::fs::write(
        proj.join("package.json"),
        r#"{"name":"r","version":"0.0.0"}"#,
    )
    .unwrap();
    let pkg = proj.join("node_modules/manifest-path-test");
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        pkg.join("package.json"),
        r#"{"name":"manifest-path-test","version":"1.0.0"}"#,
    )
    .unwrap();
    std::fs::write(pkg.join("index.js"), ORIGINAL).unwrap();

    // `--cwd proj`, exactly as a user types it: RELATIVE to the process cwd.
    let _cwd = CwdGuard::change_to(tmp.path());
    let mut args = get_args(UUID, Path::new("proj"), server.uri());
    args.save_only = false; // exercise the nested apply step

    let code = run(args).await;
    assert_eq!(code, 0, "get + apply under a relative --cwd must succeed");
    assert_eq!(
        std::fs::read(pkg.join("index.js")).unwrap(),
        PATCHED,
        "the nested apply must actually patch the file — reporting success \
         while leaving it untouched means the manifest path was resolved \
         against --cwd twice and apply no-op'd on a missing manifest"
    );
}
