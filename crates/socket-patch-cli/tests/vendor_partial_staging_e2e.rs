//! Two rules about a patch view that does not serve every file's bytes.
//!
//! The view serves `blobContent` only for files the patch actually CHANGES:
//! a file whose `beforeHash` equals its `afterHash` comes back with hashes
//! and no content (live example: `pkg:npm/tar-fs@2.1.1`, patch
//! `8ff3e0c7-6855-4224-924b-3e1151744ed4`, seven zero-delta fixture files
//! plus one changed `package/index.js`).
//!
//! 1. A zero-delta file needs NO content — the pristine copy already holds
//!    the patched bytes — so such a view stages and the package vendors
//!    (`a_view_whose_only_contentless_files_are_zero_delta_vendors`).
//! 2. A file the patch CHANGES that is served without content is genuinely
//!    unsatisfiable. That is a broken PACKAGE, not a broken run: it gets
//!    its own `failed` event and the rest of the run carries on. A single
//!    such patch used to make the WHOLE run bail `no_local_source` — exit
//!    1, `status: error`, zero events, and every OTHER package in the
//!    manifest left unvendored without a word.
//!
//! A package whose patch content cannot be obtained is an unsatisfiable
//! package like any other (`vendor_fetch_failed`, `redirect_revert_failed`,
//! the Bun refusals …). The pre-event `no_local_source` bail stays for the
//! case it was written for — NOTHING in the manifest can be staged, so
//! there are no events to report.
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

/// Mount the bad package's view. `changed_content` is the `blobContent`
/// the CHANGED file is served with; `None` makes the view genuinely
/// unsatisfiable (the patch needs those bytes and nothing can supply
/// them). The zero-delta file always comes back with hashes and no
/// content — that is how the API serves a file a patch does not change.
async fn mount_view(server: &MockServer, changed_content: Option<&[u8]>) {
    use base64::Engine;
    let mut changed = json!({
        "beforeHash": git_hash(BAD_ORIG),
        "afterHash": git_hash(BAD_PATCHED),
    });
    if let Some(bytes) = changed_content {
        changed["blobContent"] = json!(base64::engine::general_purpose::STANDARD.encode(bytes));
    }
    Mock::given(method("GET"))
        .and(wm_path(format!("/v0/orgs/{ORG}/patches/view/{BAD_UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "uuid": BAD_UUID,
            "purl": BAD_PURL,
            "publishedAt": "2026-01-01T00:00:00Z",
            "files": {
                "package/index.js": changed,
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

/// A view the run genuinely cannot satisfy: the file the patch CHANGES is
/// served with no `blobContent`, so the patched bytes exist nowhere.
async fn mount_contentless_view(server: &MockServer) {
    mount_view(server, None).await;
}

/// The live JS-7 view: the changed file carries `blobContent`, and only
/// the zero-delta file comes back contentless — which needs no content.
async fn mount_zero_delta_view(server: &MockServer) {
    mount_view(server, Some(BAD_PATCHED)).await;
}

/// The `path -> bytes` map of a gzipped tarball's regular members.
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
    // The per-package slot is the ONE machine-readable explanation a
    // `--json` consumer gets (every human channel in the stager is gated
    // on `!--json`), so it must carry the REAL reason. This run is neither
    // offline nor a download failure: the view was served, 200, with a
    // file it had no content for.
    assert_eq!(
        bad["error"].as_str(),
        Some("the patch view served no blob content for package/index.js"),
        "the failure names the file that was served without content: {env:#}"
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

/// The JS-7 package itself must VENDOR, not merely fail politely.
///
/// `pkg:npm/tar-fs@2.1.1` patch `8ff3e0c7-…` changes one file and carries
/// seven zero-delta fixture files (`beforeHash == afterHash`). The view
/// serves `blobContent` only for the file it CHANGES, so those seven come
/// back contentless — and a zero-delta file needs no content: the pristine
/// copy already holds the patched bytes, which is exactly what
/// `verify_file_patch` answers `AlreadyPatched` for. Requiring the
/// after-blob for every file made this patch permanently unvendorable.
#[tokio::test]
async fn a_view_whose_only_contentless_files_are_zero_delta_vendors() {
    let server = MockServer::start().await;
    mount_zero_delta_view(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    fixture(root);

    let (code, env, stderr) = vendor_cli(root, &server.uri());

    assert_eq!(
        code, 0,
        "nothing in this patch needs the unserved bytes: {env:#}\nstderr:\n{stderr}"
    );
    assert_eq!(env["status"], "success", "{env:#}");
    assert_eq!(event_for(&env, BAD_PURL)["action"], "applied", "{env:#}");
    assert_eq!(event_for(&env, GOOD_PURL)["action"], "applied", "{env:#}");

    // The vendored tarball carries BOTH files — the changed one at its
    // patched bytes, the zero-delta one at the bytes it always had.
    let tgz = root.join(format!(".socket/vendor/npm/{BAD_UUID}/tar-fs-2.1.1.tgz"));
    let members = tgz_members(&tgz);
    assert_eq!(
        members.get("package/index.js").map(Vec::as_slice),
        Some(BAD_PATCHED),
        "the changed file is the patched content: {members:?}"
    );
    assert_eq!(
        members
            .get("package/test/fixtures/d/file1")
            .map(Vec::as_slice),
        Some(BAD_FIXTURE),
        "the zero-delta file is vendored from the pristine copy: {members:?}"
    );
}
