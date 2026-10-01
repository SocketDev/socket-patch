//! Vendoring consumes immutable service artifacts without downloading patch blobs.
#[path = "prebuilt_common/mod.rs"]
mod prebuilt_common;
use std::path::Path;
use std::process::Command;

use serde_json::{json, Value};
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use wiremock::matchers::{method, path as wm_path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";

const GOOD_PURL: &str = "pkg:npm/left-pad@1.3.0";
const GOOD_UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
const GOOD_ORIG: &[u8] = b"module.exports = () => 'orig';\n";
const GOOD_PATCHED: &[u8] = b"module.exports = () => 'patched';\n";

/// The JS-7 package shape: one changed file plus one zero-delta file the
/// view always serves with no `blobContent`. Whether the CHANGED file is
/// served with content is what each test varies.
const BAD_PURL: &str = "pkg:npm/tar-fs@2.1.1";
const BAD_UUID: &str = "8ff3e0c7-6855-4224-924b-3e1151744ed4";
const BAD_ORIG: &[u8] = b"module.exports = require('./lib');\n";
const BAD_PATCHED: &[u8] = b"module.exports = require('./lib'); // patched\n";
/// Zero-delta: identical `beforeHash`/`afterHash`, never served as content.
const BAD_FIXTURE: &[u8] = b"";

fn git_hash(bytes: &[u8]) -> String {
    compute_git_sha256_from_bytes(bytes)
}

fn patch_record(uuid: &str, files: Value) -> Value {
    json!({
        "uuid": uuid,
        "exportedAt": "2026-01-01T00:00:00Z",
        "files": files,
        "vulnerabilities": {},
        "description": "synthetic vendor staging test patch",
        "license": "MIT",
        "tier": "free"
    })
}

fn good_files() -> Value {
    json!({
        "package/index.js": {
            "beforeHash": git_hash(GOOD_ORIG),
            "afterHash": git_hash(GOOD_PATCHED),
        }
    })
}

fn bad_files() -> Value {
    json!({
        "package/index.js": {
            "beforeHash": git_hash(BAD_ORIG),
            "afterHash": git_hash(BAD_PATCHED),
        },
        "package/test/fixtures/d/file1": {
            "beforeHash": git_hash(BAD_FIXTURE),
            "afterHash": git_hash(BAD_FIXTURE),
        }
    })
}

fn fixture(root: &Path) {
    for (name, version, index, extra) in [
        ("left-pad", "1.3.0", GOOD_ORIG, None),
        (
            "tar-fs",
            "2.1.1",
            BAD_ORIG,
            Some(("test/fixtures/d/file1", BAD_FIXTURE)),
        ),
    ] {
        let pkg = root.join("node_modules").join(name);
        std::fs::create_dir_all(&pkg).unwrap();
        std::fs::write(
            pkg.join("package.json"),
            format!(r#"{{"name":"{name}","version":"{version}"}}"#),
        )
        .unwrap();
        std::fs::write(pkg.join("index.js"), index).unwrap();
        if let Some((rel, bytes)) = extra {
            let p = pkg.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, bytes).unwrap();
        }
    }

    std::fs::write(
        root.join("package.json"),
        br#"{"name":"fixture","version":"1.0.0","private":true}"#,
    )
    .unwrap();
    let lock = json!({
        "name": "fixture",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "requires": true,
        "packages": {
            "": {
                "name": "fixture",
                "version": "1.0.0",
                "dependencies": { "left-pad": "^1.3.0", "tar-fs": "^2.1.1" }
            },
            "node_modules/left-pad": {
                "version": "1.3.0",
                "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
                "integrity": "sha512-orig=="
            },
            "node_modules/tar-fs": {
                "version": "2.1.1",
                "resolved": "https://registry.npmjs.org/tar-fs/-/tar-fs-2.1.1.tgz",
                "integrity": "sha512-orig2=="
            }
        }
    });
    let mut lock_bytes = serde_json::to_vec_pretty(&lock).unwrap();
    lock_bytes.push(b'\n');
    std::fs::write(root.join("package-lock.json"), &lock_bytes).unwrap();

    let manifest = json!({ "patches": {
        GOOD_PURL: patch_record(GOOD_UUID, good_files()),
        BAD_PURL: patch_record(BAD_UUID, bad_files()),
    }});
    let socket = root.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    let mut manifest_bytes = serde_json::to_vec_pretty(&manifest).unwrap();
    manifest_bytes.push(b'\n');
    std::fs::write(socket.join("manifest.json"), &manifest_bytes).unwrap();
    // Only the good package is locally satisfied.
    std::fs::write(
        socket.join("blobs").join(git_hash(GOOD_PATCHED)),
        GOOD_PATCHED,
    )
    .unwrap();
}

fn tgz_members(tgz: &Path) -> std::collections::BTreeMap<String, Vec<u8>> {
    let file = std::fs::File::open(tgz).unwrap_or_else(|e| panic!("open {}: {e}", tgz.display()));
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(file));
    let mut out = std::collections::BTreeMap::new();
    for entry in archive.entries().expect("tar entries") {
        let mut entry = entry.expect("tar entry");
        let path = entry
            .path()
            .expect("tar path")
            .to_string_lossy()
            .into_owned();
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut entry, &mut bytes).expect("tar member bytes");
        out.insert(path, bytes);
    }
    out
}

fn vendor_cli_with_source(root: &Path, api_url: &str, source: &str) -> (i32, Value, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_socket-patch"));
    cmd.args([
        "vendor",
        "--json",
        "--vendor-source",
        source,
        "--api-url",
        api_url,
        "--api-token",
        "fake-token",
        "--org",
        ORG,
    ])
    .current_dir(root);
    for (key, _) in std::env::vars() {
        if key.starts_with("SOCKET_") && key != "SOCKET_NO_CONFIG" {
            cmd.env_remove(key);
        }
    }
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1");
    let out = cmd.output().expect("spawn socket-patch");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let env: Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("vendor --json must emit an envelope: {e}\nstdout:\n{stdout}\nstderr:\n{stderr}")
    });
    (out.status.code().unwrap_or(-1), env, stderr)
}

fn events(env: &Value) -> &Vec<Value> {
    env["events"].as_array().expect("events array")
}

fn event_for<'a>(env: &'a Value, purl: &str) -> &'a Value {
    events(env)
        .iter()
        .find(|e| e["purl"] == purl)
        .unwrap_or_else(|| panic!("expected an event for {purl} in:\n{env:#}"))
}

async fn mount_discovery(server: &MockServer) {
    Mock::given(method("POST"))
        .and(wm_path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "packages": [
                { "purl": GOOD_PURL, "patches": [{
                    "uuid": GOOD_UUID, "purl": GOOD_PURL, "tier": "free",
                    "cveIds": ["CVE-2026-0001"], "ghsaIds": [], "severity": "high",
                    "title": "good" }] },
                { "purl": BAD_PURL, "patches": [{
                    "uuid": BAD_UUID, "purl": BAD_PURL, "tier": "free",
                    "cveIds": ["CVE-2026-0002"], "ghsaIds": [], "severity": "high",
                    "title": "bad" }] },
            ],
            "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;
    for (encoded, uuid, purl) in [
        ("pkg%3Anpm%2Fleft-pad%401.3.0", GOOD_UUID, GOOD_PURL),
        ("pkg%3Anpm%2Ftar-fs%402.1.1", BAD_UUID, BAD_PURL),
    ] {
        Mock::given(method("GET"))
            .and(wm_path(format!(
                "/v0/orgs/{ORG}/patches/by-package/{encoded}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "patches": [{
                    "uuid": uuid,
                    "purl": purl,
                    "publishedAt": "2026-01-01T00:00:00Z",
                    "description": "d",
                    "license": "MIT",
                    "tier": "free",
                    "vulnerabilities": {},
                }],
                "canAccessPaidPatches": false,
            })))
            .mount(server)
            .await;
    }
}

fn scan_vendored_cli(root: &Path, api_url: &str) -> (i32, Value, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_socket-patch"));
    cmd.args([
        "scan",
        "--json",
        "--mode",
        "vendored",
        "--yes",
        "--vendor-source",
        "service",
        "--api-url",
        api_url,
        "--api-token",
        "fake-token",
        "--org",
        ORG,
    ])
    .current_dir(root);
    for (key, _) in std::env::vars() {
        if key.starts_with("SOCKET_") && key != "SOCKET_NO_CONFIG" {
            cmd.env_remove(key);
        }
    }
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1");
    let out = cmd.output().expect("spawn socket-patch");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let env: Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("scan --json must emit an envelope: {e}\nstdout:\n{stdout}\nstderr:\n{stderr}")
    });
    (out.status.code().unwrap_or(-1), env, stderr)
}

async fn publish(server: &MockServer, root: &Path, bad: Option<&[u8]>) {
    if let Some(bytes) = bad {
        std::fs::write(
            root.join(".socket/blobs").join(git_hash(BAD_PATCHED)),
            bytes,
        )
        .unwrap();
        std::fs::write(
            root.join(".socket/blobs").join(git_hash(BAD_FIXTURE)),
            BAD_FIXTURE,
        )
        .unwrap();
    }
    prebuilt_common::mount_project(server, root).await;
    std::fs::remove_dir_all(root.join(".socket/blobs")).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn vendor_downloads_without_local_blobs_or_installed_packages() {
    let server = MockServer::start().await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fixture(root);
    publish(&server, root, Some(BAD_PATCHED)).await;
    std::fs::remove_dir_all(root.join("node_modules")).unwrap();
    let (code, env, stderr) = vendor_cli_with_source(root, &server.uri(), "service");
    assert_eq!(code, 0, "{env:#}\n{stderr}");
    assert_eq!(env["summary"]["applied"], 2);
    assert!(!root.join(".socket/blobs").exists());
    let members =
        tgz_members(&root.join(format!(".socket/vendor/npm/{BAD_UUID}/tar-fs-2.1.1.tgz")));
    assert_eq!(members["package/index.js"], BAD_PATCHED);
    assert_eq!(members["package/test/fixtures/d/file1"], BAD_FIXTURE);
    let requests = server.received_requests().await.unwrap();
    assert!(!requests.iter().any(|r| r.url.path().contains("/view/")));
    let requested: Vec<_> = requests
        .iter()
        .filter(|r| r.method == "POST")
        .flat_map(|r| {
            serde_json::from_slice::<Value>(&r.body).unwrap()["uuids"]
                .as_array()
                .unwrap()
                .clone()
        })
        .collect();
    assert!(requested.contains(&json!(GOOD_UUID)) && requested.contains(&json!(BAD_UUID)));
}

#[tokio::test(flavor = "multi_thread")]
async fn unavailable_artifact_fails_only_its_package_without_local_fallback() {
    let server = MockServer::start().await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fixture(root);
    publish(&server, root, None).await;
    // Even valid after-blobs cannot supply an unavailable server artifact.
    std::fs::create_dir_all(root.join(".socket/blobs")).unwrap();
    std::fs::write(
        root.join(".socket/blobs").join(git_hash(BAD_PATCHED)),
        BAD_PATCHED,
    )
    .unwrap();
    let (code, env, stderr) = vendor_cli_with_source(root, &server.uri(), "auto");
    assert_eq!(code, 1, "{env:#}\n{stderr}");
    assert_eq!(event_for(&env, GOOD_PURL)["action"], "applied");
    assert_eq!(event_for(&env, BAD_PURL)["action"], "failed");
    assert!(!root.join(format!(".socket/vendor/npm/{BAD_UUID}")).exists());
    assert_eq!(
        std::fs::read(root.join("node_modules/tar-fs/index.js")).unwrap(),
        BAD_ORIG
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn valid_archive_integrity_does_not_hide_incorrect_patched_members() {
    let server = MockServer::start().await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fixture(root);
    publish(&server, root, Some(BAD_ORIG)).await;
    let (code, env, stderr) = vendor_cli_with_source(root, &server.uri(), "service");
    assert_eq!(code, 1, "{env:#}\n{stderr}");
    assert_eq!(event_for(&env, GOOD_PURL)["action"], "applied");
    assert_eq!(event_for(&env, BAD_PURL)["action"], "failed");
    assert!(!root.join(format!(".socket/vendor/npm/{BAD_UUID}")).exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn scan_vendor_uses_contentless_views_and_downloaded_archives() {
    let server = MockServer::start().await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fixture(root);
    publish(&server, root, Some(BAD_PATCHED)).await;
    mount_discovery(&server).await;
    for (purl, uuid, files) in [
        (GOOD_PURL, GOOD_UUID, good_files()),
        (BAD_PURL, BAD_UUID, bad_files()),
    ] {
        let mut view = patch_record(uuid, files);
        view["purl"] = json!(purl);
        view["publishedAt"] = json!("2026-01-01T00:00:00Z");
        Mock::given(method("GET"))
            .and(wm_path(format!("/v0/orgs/{ORG}/patches/view/{uuid}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(view))
            .mount(&server)
            .await;
    }
    std::fs::remove_file(root.join(".socket/manifest.json")).unwrap();
    let (code, env, stderr) = scan_vendored_cli(root, &server.uri());
    assert_eq!(code, 0, "{env:#}\n{stderr}");
    assert_eq!(env["vendor"]["summary"]["applied"], 2);
    assert!(!root.join(".socket/manifest.json").exists());
    assert!(!root.join(".socket/blobs").exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn local_build_source_is_rejected() {
    let server = MockServer::start().await;
    let tmp = tempfile::tempdir().unwrap();
    fixture(tmp.path());
    let before = std::fs::read(tmp.path().join("package-lock.json")).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_socket-patch"))
        .current_dir(tmp.path())
        .args([
            "vendor",
            "--json",
            "--vendor-source",
            "build",
            "--api-url",
            &server.uri(),
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("local artifact construction was removed")
    );
    assert_eq!(
        std::fs::read(tmp.path().join("package-lock.json")).unwrap(),
        before
    );
    assert!(server.received_requests().await.unwrap().is_empty());
}
