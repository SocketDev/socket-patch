//! One unstageable patch must not abort a whole vendored run.
//!
//! The patch view serves `blobContent` only for files the patch actually
//! CHANGES: a file whose `beforeHash` equals its `afterHash` comes back with
//! hashes and no content (live example: `pkg:npm/tar-fs@2.1.1`, patch
//! `8ff3e0c7-6855-4224-924b-3e1151744ed4`, seven zero-delta fixture files
//! plus one changed `package/index.js`). The in-memory vendor stager treats
//! any such view as a failed fetch, and a single failed fetch made the WHOLE
//! run bail `no_local_source` — exit 1, `status: error`, zero events, and
//! every OTHER package in the manifest left unvendored without a word.
//!
//! A package whose patch content cannot be obtained is an unsatisfiable
//! package like any other (`vendor_fetch_failed`, `redirect_revert_failed`,
//! the Bun refusals …): it gets its own `failed` event and the run carries
//! on. The pre-event `no_local_source` bail stays for the case it was
//! written for — NOTHING in the manifest can be staged, so there are no
//! events to report.
//!
//! Hermetic: the API is a `wiremock` mock, `--vendor-source build` keeps the
//! vendoring service out of the run, and every package is installed on disk
//! so no registry fetch happens.

use std::path::Path;
use std::process::Command;

use serde_json::{json, Value};
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use wiremock::matchers::{method, path as wm_path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";

/// The satisfiable package: its after-blob is staged under `.socket/blobs`,
/// so staging never fetches its view.
const GOOD_PURL: &str = "pkg:npm/left-pad@1.3.0";
const GOOD_UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
const GOOD_ORIG: &[u8] = b"module.exports = () => 'orig';\n";
const GOOD_PATCHED: &[u8] = b"module.exports = () => 'patched';\n";

/// The JS-7 package: one changed file plus one zero-delta file the view
/// serves with no `blobContent`.
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

/// A two-package npm project: both installed, both in the v3 lock, both in
/// the manifest. Only the good package's after-blob is staged on disk.
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

/// The JS-7 view: the changed file carries `blobContent`, the zero-delta
/// file carries hashes only.
async fn mount_contentless_view(server: &MockServer) {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(BAD_PATCHED);
    Mock::given(method("GET"))
        .and(wm_path(format!("/v0/orgs/{ORG}/patches/view/{BAD_UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "uuid": BAD_UUID,
            "purl": BAD_PURL,
            "publishedAt": "2026-01-01T00:00:00Z",
            "files": {
                "package/index.js": {
                    "beforeHash": git_hash(BAD_ORIG),
                    "afterHash": git_hash(BAD_PATCHED),
                    "blobContent": b64,
                },
                "package/test/fixtures/d/file1": {
                    "beforeHash": git_hash(BAD_FIXTURE),
                    "afterHash": git_hash(BAD_FIXTURE),
                }
            },
            "vulnerabilities": {},
            "description": "d",
            "license": "MIT",
            "tier": "free",
        })))
        .mount(server)
        .await;
}

/// `vendor --json --vendor-source build` against the mock API, with every
/// ambient `SOCKET_*` var scrubbed from the child.
fn vendor_cli(root: &Path, api_url: &str) -> (i32, Value, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_socket-patch"));
    cmd.args([
        "vendor",
        "--json",
        "--vendor-source",
        "build",
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

#[tokio::test]
async fn contentless_patch_view_fails_only_its_own_package() {
    let server = MockServer::start().await;
    mount_contentless_view(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fixture(root);

    let (code, env, stderr) = vendor_cli(root, &server.uri());

    assert_eq!(
        code, 1,
        "an unstageable package still fails the run: {env:#}\nstderr:\n{stderr}"
    );
    assert_eq!(
        env["status"], "partialFailure",
        "one bad package is a partial failure, not a pre-event abort: {env:#}"
    );
    assert!(
        env["error"].is_null(),
        "no run-level error payload: the failure is per-package: {env:#}"
    );

    let bad = event_for(&env, BAD_PURL);
    assert_eq!(bad["action"], "failed", "{env:#}");
    assert_eq!(
        bad["errorCode"], "no_local_source",
        "the per-package failure keeps the staging code: {env:#}"
    );

    let good = event_for(&env, GOOD_PURL);
    assert_eq!(
        good["action"], "applied",
        "the rest of the run must continue: {env:#}"
    );
    assert!(
        root.join(format!(".socket/vendor/npm/{GOOD_UUID}/left-pad-1.3.0.tgz"))
            .is_file(),
        "the satisfiable package must still be vendored: {env:#}"
    );
    // The unstageable package is left completely alone.
    assert!(
        !root.join(format!(".socket/vendor/npm/{BAD_UUID}")).exists(),
        "nothing is written for the unstageable package: {env:#}"
    );
    let lock: Value =
        serde_json::from_slice(&std::fs::read(root.join("package-lock.json")).unwrap()).unwrap();
    assert_eq!(
        lock["packages"]["node_modules/tar-fs"]["resolved"],
        "https://registry.npmjs.org/tar-fs/-/tar-fs-2.1.1.tgz",
        "the unstageable package's lock entry stays registry-resolved: {env:#}"
    );
}

/// The pre-event bail survives for the case it was written for: when NO
/// patch in the manifest can be staged there are no per-package events to
/// report, so the run keeps its top-level `no_local_source` error.
#[tokio::test]
async fn every_patch_unstageable_keeps_the_run_level_error() {
    let server = MockServer::start().await;
    mount_contentless_view(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fixture(root);
    // Drop the good package's staged blob: now both patches need a view,
    // and neither view is complete (left-pad's 404s).
    std::fs::remove_file(root.join(".socket/blobs").join(git_hash(GOOD_PATCHED))).unwrap();

    let (code, env, stderr) = vendor_cli(root, &server.uri());

    assert_eq!(code, 1, "{env:#}\nstderr:\n{stderr}");
    assert_eq!(env["status"], "error", "{env:#}");
    assert_eq!(env["error"]["code"], "no_local_source", "{env:#}");
    assert!(
        events(&env).is_empty(),
        "a pre-event abort reports no events: {env:#}"
    );
    assert!(
        !root.join(".socket/vendor").exists(),
        "an aborted run vendors nothing: {env:#}"
    );
}
