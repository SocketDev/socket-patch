//! Hermetic hosted → vendored takeover tests through the built binary for
//! an npm project whose lock the vendored backend refuses: a
//! lockfileVersion-1 `package-lock.json` / `npm-shrinkwrap.json` (npm 6).
//!
//! Hosted mode accepts a v1 lock, the npm vendored backend does not
//! (`vendor_lockfile_version_unsupported`). `scan`/`get --mode vendored`
//! over such a hosted pin used to restore the upstream registry entry
//! FIRST and only then reach the backend's version gate, so the run
//! failed with the hosted pin already gone and the project went back to
//! unpatched (#659). The gate must run before the restore, so the
//! refused purl stays hosted; a v2 lock still takes over.
//!
//! The API and the npm registry are wiremock; no npm binary is needed.
//! Every child process gets the ambient `SOCKET_*` vars scrubbed and
//! telemetry hard-disabled; each test runs in its own tempdir.

#[path = "prebuilt_common/mod.rs"]
mod prebuilt_common;

use std::path::Path;
use std::process::Command;

use base64::Engine as _;
use serde_json::{json, Value};
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";
const NAME: &str = "left-pad";
const VERSION: &str = "1.3.0";
const PURL: &str = "pkg:npm/left-pad@1.3.0";
const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
const HOSTED_URL: &str = "https://patch.socket.dev/patch/npm/left-pad/1.3.0/55555555-5555-4555-8555-555555555555/9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f/left-pad-1.3.0.tgz";
const PATCHED_SHA512: &str = "sha512-PATCHEDpatchedPATCHEDpatched0123456789==";
const UPSTREAM_TARBALL: &str = "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz";
const UPSTREAM_SHA512: &str = "sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA==";
const ORIG_INDEX: &[u8] = b"module.exports = () => 'orig';\n";
const PATCHED_INDEX: &[u8] = b"module.exports = () => 'patched';\n";
const V1_CODE: &str = "vendor_lockfile_version_unsupported";

// ───────────────────────────── fixture ─────────────────────────────

/// The pristine lock npm `lock_version` writes for a root project
/// depending on `left-pad@1.3.0`.
fn pristine_lock(lock_version: u64) -> Value {
    let dep = json!({
        "version": VERSION,
        "resolved": UPSTREAM_TARBALL,
        "integrity": UPSTREAM_SHA512,
    });
    if lock_version == 1 {
        json!({
            "name": "v6",
            "version": "1.0.0",
            "lockfileVersion": 1,
            "requires": true,
            "dependencies": { NAME: dep },
        })
    } else {
        json!({
            "name": "v6",
            "version": "1.0.0",
            "lockfileVersion": lock_version,
            "requires": true,
            "packages": {
                "": { "name": "v6", "version": "1.0.0", "dependencies": { NAME: VERSION } },
                "node_modules/left-pad": dep,
            },
        })
    }
}

/// package.json, the installed (unpatched) copy and the pristine lock
/// named `lock_name`.
fn write_npm_project(root: &Path, lock_name: &str, lock_version: u64) {
    std::fs::write(
        root.join("package.json"),
        format!(
            r#"{{"name":"v6","version":"1.0.0","private":true,"dependencies":{{"{NAME}":"{VERSION}"}}}}"#
        ),
    )
    .unwrap();
    let pkg = root.join("node_modules").join(NAME);
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        pkg.join("package.json"),
        format!(r#"{{"name":"{NAME}","version":"{VERSION}"}}"#),
    )
    .unwrap();
    std::fs::write(pkg.join("index.js"), ORIG_INDEX).unwrap();
    let mut lock = serde_json::to_string_pretty(&pristine_lock(lock_version)).unwrap();
    lock.push('\n');
    std::fs::write(root.join(lock_name), lock).unwrap();
}

fn patch_record() -> Value {
    json!({
        "uuid": UUID,
        "exportedAt": "2026-01-01T00:00:00Z",
        "files": {
            "package/index.js": {
                "beforeHash": compute_git_sha256_from_bytes(ORIG_INDEX),
                "afterHash": compute_git_sha256_from_bytes(PATCHED_INDEX),
            }
        },
        "vulnerabilities": {},
        "description": "npm v1 takeover fixture",
        "license": "MIT",
        "tier": "free"
    })
}

fn patch_view() -> Value {
    let mut view = patch_record();
    view["purl"] = json!(PURL);
    view["publishedAt"] = json!("2024-01-01T00:00:00Z");
    view["files"]["package/index.js"]["blobContent"] =
        json!(base64::engine::general_purpose::STANDARD.encode(PATCHED_INDEX));
    view
}

/// The hosted-mode API (discovery + by-package + grant + view) for the one
/// patch over `PURL`, plus the npm registry's version document the
/// upstream restore re-resolves the pristine entry from.
async fn mock_api(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "packages": [{
                "purl": PURL,
                "patches": [{
                    "uuid": UUID, "purl": PURL, "tier": "free",
                    "cveIds": [], "ghsaIds": [], "severity": "high",
                    "title": "npm v1 takeover fixture"
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
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
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
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
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
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(patch_view()))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/{NAME}/{VERSION}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": NAME,
            "version": VERSION,
            "dist": { "tarball": UPSTREAM_TARBALL, "integrity": UPSTREAM_SHA512 }
        })))
        .mount(server)
        .await;
}

// ───────────────────────── subprocess runner ─────────────────────────

/// Run the built binary with every ambient `SOCKET_*` var scrubbed and the
/// npm registry pointed at the mock. Returns `(exit_code, envelope)`.
fn run_json(cwd: &Path, registry: &str, args: &[&str]) -> (i32, Value) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_socket-patch"));
    cmd.current_dir(cwd);
    for (key, _) in std::env::vars() {
        if key.starts_with("SOCKET_") && key != "SOCKET_NO_CONFIG" {
            cmd.env_remove(key);
        }
    }
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1")
        .env("SOCKET_NPM_REGISTRY", registry);
    let _fixture = prebuilt_common::prepare_command(&mut cmd, cwd, args, &[]);
    let out = cmd.output().expect("spawn socket-patch binary");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    if !stderr.trim().is_empty() {
        println!("[{}] stderr:\n{stderr}", args.first().unwrap_or(&"?"));
    }
    let env: Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("{args:?} must emit a JSON envelope: {e}\nstdout:\n{stdout}\nstderr:\n{stderr}")
    });
    (out.status.code().unwrap_or(-1), env)
}

/// `scan --mode <mode>` (or, with `get`, `get <purl> --mode <mode>`)
/// against the mock API.
fn run_mode(cwd: &Path, api: &str, command: &str, mode: &str, extra: &[&str]) -> (i32, Value) {
    let mut args = vec![command];
    if command == "get" {
        args.push(PURL);
    }
    args.extend([
        "--mode",
        mode,
        "--json",
        "--yes",
        "--api-url",
        api,
        "--api-token",
        "fake",
        "--org",
        ORG,
        "--cwd",
        cwd.to_str().unwrap(),
    ]);
    let fixture = (mode == "vendored").then(|| prebuilt_common::Server::view(patch_view()));
    if let Some(fixture) = &fixture {
        args.extend(["--vendor-url", &fixture.uri]);
    }
    args.extend_from_slice(extra);
    run_json(cwd, api, &args)
}

fn events(envelope: &Value) -> Vec<Value> {
    envelope["events"].as_array().cloned().unwrap_or_default()
}

fn has_event_code(envelope: &Value, code: &str) -> bool {
    events(envelope).iter().any(|e| e["errorCode"] == code)
        || envelope.to_string().contains(&format!("\"{code}\""))
}

/// The hosted project: pristine lock, then a real `scan --mode hosted`.
/// Returns `(lock text, .npmrc text)` as hosted mode left them.
fn host_project(root: &Path, api: &str, lock_name: &str, lock_version: u64) -> (String, String) {
    write_npm_project(root, lock_name, lock_version);
    let (code, env) = run_mode(root, api, "scan", "hosted", &[]);
    assert_eq!(code, 0, "hosted scan must succeed: {env:#}");
    let lock = std::fs::read_to_string(root.join(lock_name)).unwrap();
    assert!(
        lock.contains(HOSTED_URL),
        "hosted mode must pin the {lock_name} v{lock_version} entry:\n{lock}\n{env:#}"
    );
    let npmrc = std::fs::read_to_string(root.join(".npmrc")).unwrap_or_default();
    (lock, npmrc)
}

/// A refused takeover leaves every byte of the hosted wiring in place and
/// writes no vendored state.
fn assert_still_hosted(root: &Path, lock_name: &str, lock: &str, npmrc: &str) {
    assert_eq!(
        std::fs::read_to_string(root.join(lock_name)).unwrap(),
        lock,
        "{lock_name} must keep the hosted pin byte-for-byte"
    );
    assert_eq!(
        std::fs::read_to_string(root.join(".npmrc")).unwrap_or_default(),
        npmrc,
        ".npmrc must stay as hosted mode wrote it"
    );
    assert!(
        !root.join(".socket/vendor/npm").exists(),
        "a refused run must not stage or pack an artifact"
    );
}

/// The wet vendored run over a hosted v1 pin: refused with the backend's
/// own code BEFORE the takeover restores anything.
fn assert_refused_before_unhosting(env: &Value, code: i32) {
    assert_eq!(code, 1, "the refusal fails the run: {env:#}");
    let failed = events(env)
        .into_iter()
        .find(|e| e["action"] == "failed" && e["errorCode"] == V1_CODE)
        .unwrap_or_else(|| panic!("expected a failed `{V1_CODE}` event: {env:#}"));
    assert_eq!(failed["purl"], PURL, "{env:#}");
    assert!(
        failed["error"]
            .as_str()
            .is_some_and(|d| d.contains("lockfileVersion Some(1)")),
        "the detail is the backend's own words: {env:#}"
    );
    assert!(
        !has_event_code(env, "vendor_takeover_reverted_redirect"),
        "the hosted pin must not be restored before the refusal: {env:#}"
    );
    assert!(!has_event_code(env, "redirect_revert_failed"), "{env:#}");
}

// ───────────────────────────── scenarios ─────────────────────────────

/// #659: `scan --mode vendored` over a hosted v1 `package-lock.json`.
#[tokio::test(flavor = "multi_thread")]
async fn scan_vendored_over_hosted_v1_package_lock_keeps_the_hosted_pin() {
    let server = MockServer::start().await;
    mock_api(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (lock, npmrc) = host_project(root, &server.uri(), "package-lock.json", 1);

    // The dry run previews the refusal instead of "would vendor".
    let (code, env) = run_mode(root, &server.uri(), "scan", "vendored", &["--dry-run"]);
    assert!(
        has_event_code(&env, V1_CODE),
        "the dry run must preview the refusal (exit {code}): {env:#}"
    );
    assert_still_hosted(root, "package-lock.json", &lock, &npmrc);

    let (code, env) = run_mode(root, &server.uri(), "scan", "vendored", &[]);
    assert_refused_before_unhosting(&env, code);
    assert_still_hosted(root, "package-lock.json", &lock, &npmrc);
}

/// #659: `get <purl> --mode vendored`, same project shape.
#[tokio::test(flavor = "multi_thread")]
async fn get_vendored_over_hosted_v1_package_lock_keeps_the_hosted_pin() {
    let server = MockServer::start().await;
    mock_api(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (lock, npmrc) = host_project(root, &server.uri(), "package-lock.json", 1);

    let (code, env) = run_mode(root, &server.uri(), "get", "vendored", &[]);
    assert_refused_before_unhosting(&env, code);
    assert_still_hosted(root, "package-lock.json", &lock, &npmrc);
}

/// #659: the `npm-shrinkwrap.json` v1 variant.
#[tokio::test(flavor = "multi_thread")]
async fn scan_vendored_over_hosted_v1_shrinkwrap_keeps_the_hosted_pin() {
    let server = MockServer::start().await;
    mock_api(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (lock, npmrc) = host_project(root, &server.uri(), "npm-shrinkwrap.json", 1);

    let (code, env) = run_mode(root, &server.uri(), "scan", "vendored", &[]);
    assert_refused_before_unhosting(&env, code);
    assert_still_hosted(root, "npm-shrinkwrap.json", &lock, &npmrc);
}

/// Control: a v2 lock is supported by both modes, so the takeover still
/// restores the registry entry and vendors it.
#[tokio::test(flavor = "multi_thread")]
async fn scan_vendored_over_hosted_v2_package_lock_still_takes_over() {
    let server = MockServer::start().await;
    mock_api(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    host_project(root, &server.uri(), "package-lock.json", 2);

    let (code, env) = run_mode(root, &server.uri(), "scan", "vendored", &["--dry-run"]);
    assert_eq!(code, 0, "{env:#}");
    assert!(!has_event_code(&env, V1_CODE), "{env:#}");

    let (code, env) = run_mode(root, &server.uri(), "scan", "vendored", &[]);
    assert_eq!(code, 0, "the v2 takeover must succeed: {env:#}");
    assert!(
        has_event_code(&env, "vendor_takeover_reverted_redirect"),
        "{env:#}"
    );
    assert!(!has_event_code(&env, V1_CODE), "{env:#}");
    let lock = std::fs::read_to_string(root.join("package-lock.json")).unwrap();
    assert!(!lock.contains(HOSTED_URL), "{lock}");
    assert!(
        lock.contains(&format!(".socket/vendor/npm/{UUID}/")),
        "the lock must point at the vendored artifact:\n{lock}"
    );
}
