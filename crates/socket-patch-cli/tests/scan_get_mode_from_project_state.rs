//! A `scan`/`get` with no `--mode` keeps the mode the project's patch
//! state already records (#1088): a bare run on a vendored project stays
//! vendored, one on an agent-mode project stays agent, and only an
//! explicit `--mode hosted` runs the vendored→hosted takeover. A project
//! holding both agent and vendored state is a usage error that asks for
//! `--mode`.
//!
//! The API and the npm registry are wiremock; no npm binary is needed.
//! Every child process gets the ambient `SOCKET_*` vars scrubbed and
//! telemetry hard-disabled; each test runs in its own tempdir.

#[path = "common/hermetic.rs"]
mod hermetic;
#[path = "prebuilt_common/mod.rs"]
mod prebuilt_common;

use std::path::Path;

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
        "description": "mode-from-state fixture",
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
                    "title": "mode-from-state fixture"
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
    let mut cmd = hermetic::binary_command();
    cmd.current_dir(cwd);
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

/// `scan` (or `get <purl>`) against the mock API, with `--mode <mode>`
/// only when `mode` is `Some`. The vendored fixture server is passed on
/// every run, so a bare run that resolves to vendored mode can fetch.
fn run_cmd(
    cwd: &Path,
    api: &str,
    command: &str,
    mode: Option<&str>,
    extra: &[&str],
) -> (i32, Value) {
    let fixture = prebuilt_common::Server::view(patch_view());
    let mut args = vec![command];
    if command == "get" {
        args.push(PURL);
    }
    if let Some(mode) = mode {
        args.extend(["--mode", mode]);
    }
    args.extend([
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
        "--vendor-url",
        &fixture.uri,
    ]);
    args.extend_from_slice(extra);
    run_json(cwd, api, &args)
}

/// Every file a mode change would touch, by relative path.
const WATCHED: &[&str] = &[
    "package-lock.json",
    ".npmrc",
    ".socket/vendor/state.json",
    ".socket/manifest.json",
];

fn snapshot(root: &Path) -> Vec<(String, Option<Vec<u8>>)> {
    WATCHED
        .iter()
        .map(|rel| (rel.to_string(), std::fs::read(root.join(rel)).ok()))
        .collect()
}

/// A project vendored by `scan --mode vendored` over a pristine v2 lock.
fn vendor_project(root: &Path, api: &str) {
    write_npm_project(root, "package-lock.json", 2);
    let (code, env) = run_cmd(root, api, "scan", Some("vendored"), &[]);
    assert_eq!(code, 0, "the vendored scan must succeed: {env:#}");
    let lock = std::fs::read_to_string(root.join("package-lock.json")).unwrap();
    assert!(
        lock.contains(&format!(".socket/vendor/npm/{UUID}/")),
        "the lock must point at the vendored artifact:\n{lock}"
    );
    assert!(root.join(".socket/vendor/state.json").exists());
}

fn assert_unchanged(root: &Path, before: &[(String, Option<Vec<u8>>)], env: &Value) {
    for ((rel, was), (_, now)) in before.iter().zip(snapshot(root)) {
        assert!(
            *was == now,
            "{rel} must stay byte-identical on a run with no --mode: {env:#}"
        );
    }
    let lock = std::fs::read_to_string(root.join("package-lock.json")).unwrap();
    assert!(
        !lock.contains(HOSTED_URL),
        "no hosted pin may appear:\n{lock}"
    );
}

// ───────────────────────────── scenarios ─────────────────────────────

/// A bare `scan` on a vendored project stays vendored: the vendor ledger
/// and the lockfile are byte-identical afterwards.
#[tokio::test(flavor = "multi_thread")]
async fn bare_scan_keeps_a_vendored_project_vendored() {
    let server = MockServer::start().await;
    mock_api(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    vendor_project(root, &server.uri());
    let before = snapshot(root);

    let (code, env) = run_cmd(root, &server.uri(), "scan", None, &["--dry-run"]);
    assert_eq!(code, 0, "{env:#}");
    assert_unchanged(root, &before, &env);

    let (code, env) = run_cmd(root, &server.uri(), "scan", None, &[]);
    assert_eq!(code, 0, "{env:#}");
    assert_unchanged(root, &before, &env);
}

/// A bare `get <purl>` on a vendored project stays vendored too.
#[tokio::test(flavor = "multi_thread")]
async fn bare_get_keeps_a_vendored_project_vendored() {
    let server = MockServer::start().await;
    mock_api(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    vendor_project(root, &server.uri());
    let before = snapshot(root);

    let (code, env) = run_cmd(root, &server.uri(), "get", None, &[]);
    assert_eq!(code, 0, "{env:#}");
    assert_unchanged(root, &before, &env);
}

/// An explicit `--mode hosted` is the takeover: the vendored project
/// becomes hosted in place.
#[tokio::test(flavor = "multi_thread")]
async fn explicit_mode_hosted_still_takes_over_a_vendored_project() {
    let server = MockServer::start().await;
    mock_api(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    vendor_project(root, &server.uri());

    let (code, env) = run_cmd(root, &server.uri(), "scan", Some("hosted"), &[]);
    assert_eq!(code, 0, "the explicit takeover must succeed: {env:#}");
    let lock = std::fs::read_to_string(root.join("package-lock.json")).unwrap();
    assert!(
        lock.contains(HOSTED_URL),
        "--mode hosted must pin the hosted artifact:\n{lock}\n{env:#}"
    );
    assert!(
        !lock.contains(&format!(".socket/vendor/npm/{UUID}/")),
        "the vendored wiring must be gone:\n{lock}"
    );
}

/// The manifest holding patches (agent mode) keeps a bare `scan` in agent
/// mode: no hosted pin is written.
#[tokio::test(flavor = "multi_thread")]
async fn bare_scan_keeps_an_agent_project_out_of_hosted_mode() {
    let server = MockServer::start().await;
    mock_api(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_npm_project(root, "package-lock.json", 2);
    write_manifest(root);
    let lock_before = std::fs::read(root.join("package-lock.json")).unwrap();

    // The mock serves no patch artifacts, so the agent apply step itself
    // fails (exit 1); what matters is which mode ran.
    let (code, env) = run_cmd(root, &server.uri(), "scan", None, &[]);
    assert_ne!(code, 2, "the mode is not ambiguous: {env:#}");
    assert!(
        env.get("apply").is_some(),
        "the agent apply step ran: {env:#}"
    );
    assert!(
        env.get("redirect").is_none(),
        "no hosted step may run: {env:#}"
    );
    assert_eq!(
        std::fs::read(root.join("package-lock.json")).unwrap(),
        lock_before,
        "an agent-mode scan never rewrites the lockfile: {env:#}"
    );
    assert!(!root.join(".npmrc").exists(), "{env:#}");
    let manifest: Value =
        serde_json::from_slice(&std::fs::read(root.join(".socket/manifest.json")).unwrap())
            .unwrap();
    assert!(manifest["patches"].get(PURL).is_some(), "{manifest:#}");
}

/// Agent and vendored state together: the run cannot tell which mode to
/// keep, so it is a usage error naming `--mode`, and nothing is written.
#[tokio::test(flavor = "multi_thread")]
async fn bare_scan_and_get_refuse_a_project_with_agent_and_vendored_state() {
    let server = MockServer::start().await;
    mock_api(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    vendor_project(root, &server.uri());
    write_manifest(root);
    let before = snapshot(root);

    for command in ["scan", "get"] {
        let (code, env) = run_cmd(root, &server.uri(), command, None, &[]);
        assert_eq!(code, 2, "{command}: {env:#}");
        assert_eq!(env["status"], "error", "{command}: {env:#}");
        assert!(
            env.to_string().contains("mode_ambiguous"),
            "{command}: the error carries its code: {env:#}"
        );
        assert!(
            env.to_string().contains("--mode"),
            "{command}: the error names the remedy: {env:#}"
        );
        assert_unchanged(root, &before, &env);
    }
}

/// An agent-mode manifest holding the fixture patch.
fn write_manifest(root: &Path) {
    std::fs::create_dir_all(root.join(".socket")).unwrap();
    let record = patch_record();
    let manifest = json!({ "patches": { PURL: record } });
    std::fs::write(
        root.join(".socket/manifest.json"),
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();
}
