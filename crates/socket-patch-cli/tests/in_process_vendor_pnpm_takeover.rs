//! Hermetic hosted → vendored takeover tests through the built binary for
//! pnpm projects whose shape the pnpm vendored backend refuses although
//! hosted mode accepts it (#853): a `catalog:` dependency
//! (`vendor_lock_entry_unsupported`), a CRLF `pnpm-lock.yaml`
//! (`vendor_lockfile_crlf_unsupported`) and a conflicting user override
//! (a range) in `pnpm-workspace.yaml` (`vendor_override_conflict`).
//!
//! `scan`/`get --mode vendored` over such a hosted pin used to commit the
//! upstream restore FIRST and only then reach the backend's refusal, so
//! the run failed with the hosted pin already gone and the project went
//! back to installing the unpatched registry release. A refused takeover
//! must leave the hosted wiring byte-for-byte in place; a plain dependency
//! and a workspace exact pin equal to the vendored version (#854) still
//! take over.
//!
//! The API and the npm registry are wiremock; no pnpm binary is needed.
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

/// The project shapes under test.
#[derive(Clone, Copy, Debug)]
enum Shape {
    /// `"left-pad": "catalog:"` resolved through the default catalog.
    Catalog,
    /// A plain dependency whose lock is converted to CRLF after hosting.
    Crlf,
    /// A plain dependency plus a conflicting user
    /// `overrides: { left-pad: ^1.3.0 }` in pnpm-workspace.yaml.
    Override,
    /// A plain dependency plus a user exact pin
    /// `overrides: { left-pad: 1.3.0 }` in pnpm-workspace.yaml, which
    /// vendoring takes over (#854).
    ExactPin,
    /// A plain dependency: the control both modes accept.
    Plain,
}

/// package.json, pnpm-workspace.yaml, the installed (unpatched) copy and
/// the pristine lockfileVersion 9.0 lock pnpm writes for `shape`.
fn write_pnpm_project(root: &Path, shape: Shape) {
    let spec = match shape {
        Shape::Catalog => "catalog:",
        _ => VERSION,
    };
    std::fs::write(
        root.join("package.json"),
        format!(
            r#"{{"name":"c","version":"1.0.0","private":true,"dependencies":{{"{NAME}":"{spec}"}}}}"#
        ),
    )
    .unwrap();
    let workspace = match shape {
        Shape::Catalog => format!("packages:\n  - .\ncatalog:\n  {NAME}: {VERSION}\n"),
        Shape::Override => format!("overrides:\n  {NAME}: ^{VERSION}\n"),
        Shape::ExactPin => format!("overrides:\n  {NAME}: {VERSION}\n"),
        Shape::Crlf | Shape::Plain => String::new(),
    };
    if !workspace.is_empty() {
        std::fs::write(root.join("pnpm-workspace.yaml"), workspace).unwrap();
    }
    let pkg = root.join("node_modules").join(NAME);
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        pkg.join("package.json"),
        format!(r#"{{"name":"{NAME}","version":"{VERSION}"}}"#),
    )
    .unwrap();
    std::fs::write(pkg.join("index.js"), ORIG_INDEX).unwrap();

    let mut lock = String::from(
        "lockfileVersion: '9.0'\n\nsettings:\n  autoInstallPeers: true\n  excludeLinksFromLockfile: false\n\n",
    );
    match shape {
        Shape::Catalog => lock.push_str(&format!(
            "catalogs:\n  default:\n    {NAME}:\n      specifier: {VERSION}\n      version: {VERSION}\n\n"
        )),
        Shape::Override => lock.push_str(&format!("overrides:\n  {NAME}: ^{VERSION}\n\n")),
        Shape::ExactPin => lock.push_str(&format!("overrides:\n  {NAME}: {VERSION}\n\n")),
        Shape::Crlf | Shape::Plain => {}
    }
    let specifier = match shape {
        Shape::Catalog => "'catalog:'".to_string(),
        _ => VERSION.to_string(),
    };
    lock.push_str(&format!(
        "importers:\n\n  .:\n    dependencies:\n      {NAME}:\n        specifier: {specifier}\n        version: {VERSION}\n\n\
         packages:\n\n  {NAME}@{VERSION}:\n    resolution: {{integrity: {UPSTREAM_SHA512}}}\n\n\
         snapshots:\n\n  {NAME}@{VERSION}: {{}}\n"
    ));
    std::fs::write(root.join("pnpm-lock.yaml"), lock).unwrap();
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
        "description": "pnpm takeover fixture",
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
                    "title": "pnpm takeover fixture"
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

/// The vendor events: top-level for `vendor`, under `vendor` for the
/// `scan`/`get` envelopes that embed the vendor step.
fn events(envelope: &Value) -> Vec<Value> {
    envelope["events"]
        .as_array()
        .or_else(|| envelope["vendor"]["events"].as_array())
        .cloned()
        .unwrap_or_default()
}

fn has_event_code(envelope: &Value, code: &str) -> bool {
    events(envelope).iter().any(|e| e["errorCode"] == code)
        || envelope.to_string().contains(&format!("\"{code}\""))
}

/// Every file hosted mode or the takeover may write.
const WIRING: &[&str] = &[
    "pnpm-lock.yaml",
    "pnpm-workspace.yaml",
    "package.json",
    ".npmrc",
];

fn snapshot(root: &Path) -> Vec<(&'static str, Option<Vec<u8>>)> {
    WIRING
        .iter()
        .map(|f| (*f, std::fs::read(root.join(f)).ok()))
        .collect()
}

/// The hosted project: pristine lock, then a real `scan --mode hosted`
/// (and, for [`Shape::Crlf`], the lock converted to CRLF as a
/// `core.autocrlf` checkout would leave it). Returns the hosted wiring.
fn host_project(root: &Path, api: &str, shape: Shape) -> Vec<(&'static str, Option<Vec<u8>>)> {
    write_pnpm_project(root, shape);
    let (code, env) = run_mode(root, api, "scan", "hosted", &[]);
    assert_eq!(code, 0, "hosted scan must succeed for {shape:?}: {env:#}");
    let lock_path = root.join("pnpm-lock.yaml");
    let lock = std::fs::read_to_string(&lock_path).unwrap();
    assert!(
        lock.contains(HOSTED_URL),
        "hosted mode must pin the {shape:?} lock entry:\n{lock}\n{env:#}"
    );
    if matches!(shape, Shape::Crlf) {
        std::fs::write(&lock_path, lock.replace('\n', "\r\n")).unwrap();
    }
    snapshot(root)
}

/// A refused takeover leaves every byte of the hosted wiring in place and
/// writes no vendored state.
fn assert_still_hosted(root: &Path, hosted: &[(&'static str, Option<Vec<u8>>)], env: &Value) {
    for ((file, before), (_, now)) in hosted.iter().zip(snapshot(root)) {
        assert_eq!(
            before.as_deref().map(String::from_utf8_lossy),
            now.as_deref().map(String::from_utf8_lossy),
            "{file} must keep the hosted wiring byte-for-byte: {env:#}"
        );
    }
    assert!(
        !root.join(".socket/vendor/npm").exists(),
        "a refused run must not leave a vendored artifact: {env:#}"
    );
}

/// The vendored run over a hosted pin the backend refuses: failed with the
/// backend's own `code`, and never reported as un-hosted.
fn assert_refused(env: &Value, exit: i32, code: &str) {
    assert_eq!(exit, 1, "the refusal fails the run: {env:#}");
    let failed = events(env)
        .into_iter()
        .find(|e| e["action"] == "failed" && e["errorCode"] == code)
        .unwrap_or_else(|| panic!("expected a failed `{code}` event: {env:#}"));
    assert_eq!(failed["purl"], PURL, "{env:#}");
    assert!(
        !has_event_code(env, "vendor_takeover_reverted_redirect"),
        "a refused purl must not be reported as restored: {env:#}"
    );
}

async fn refused_takeover_keeps_hosted_pin(shape: Shape, command: &str, code: &str) {
    let server = MockServer::start().await;
    mock_api(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let hosted = host_project(root, &server.uri(), shape);

    // The dry run writes nothing.
    let (_, env) = run_mode(root, &server.uri(), command, "vendored", &["--dry-run"]);
    assert_still_hosted(root, &hosted, &env);

    let (exit, env) = run_mode(root, &server.uri(), command, "vendored", &[]);
    assert_refused(&env, exit, code);
    assert_still_hosted(root, &hosted, &env);
}

// ───────────────────────────── scenarios ─────────────────────────────

/// #853: a `catalog:` dependency.
#[tokio::test(flavor = "multi_thread")]
async fn scan_vendored_over_hosted_pnpm_catalog_dep_keeps_the_hosted_pin() {
    refused_takeover_keeps_hosted_pin(Shape::Catalog, "scan", "vendor_lock_entry_unsupported")
        .await;
}

/// #853: `get --mode vendored`, same catalog shape.
#[tokio::test(flavor = "multi_thread")]
async fn get_vendored_over_hosted_pnpm_catalog_dep_keeps_the_hosted_pin() {
    refused_takeover_keeps_hosted_pin(Shape::Catalog, "get", "vendor_lock_entry_unsupported").await;
}

/// #853: a CRLF `pnpm-lock.yaml` (a `core.autocrlf` checkout).
#[tokio::test(flavor = "multi_thread")]
async fn scan_vendored_over_hosted_pnpm_crlf_lock_keeps_the_hosted_pin() {
    refused_takeover_keeps_hosted_pin(Shape::Crlf, "scan", "vendor_lockfile_crlf_unsupported")
        .await;
}

/// #853: a conflicting user override (a range) in `pnpm-workspace.yaml`.
#[tokio::test(flavor = "multi_thread")]
async fn scan_vendored_over_hosted_pnpm_workspace_override_keeps_the_hosted_pin() {
    refused_takeover_keeps_hosted_pin(Shape::Override, "scan", "vendor_override_conflict").await;
}

/// Control: a plain dependency is supported by both modes, so the takeover
/// still restores the registry entry and vendors it.
#[tokio::test(flavor = "multi_thread")]
async fn scan_vendored_over_hosted_pnpm_plain_dep_still_takes_over() {
    let server = MockServer::start().await;
    mock_api(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    host_project(root, &server.uri(), Shape::Plain);

    let (exit, env) = run_mode(root, &server.uri(), "scan", "vendored", &["--dry-run"]);
    assert_eq!(exit, 0, "{env:#}");

    let (exit, env) = run_mode(root, &server.uri(), "scan", "vendored", &[]);
    assert_eq!(exit, 0, "the plain takeover must succeed: {env:#}");
    assert!(
        has_event_code(&env, "vendor_takeover_reverted_redirect"),
        "{env:#}"
    );
    let lock = std::fs::read_to_string(root.join("pnpm-lock.yaml")).unwrap();
    assert!(!lock.contains(HOSTED_URL), "{lock}");
    assert!(
        lock.contains(&format!(".socket/vendor/npm/{UUID}/")),
        "the lock must point at the vendored artifact:\n{lock}"
    );
}

/// #854: a user exact pin equal to the vendored version in
/// `pnpm-workspace.yaml` (the pnpm 10.5+/11/12 override map) is taken over
/// like the same pin in package.json: the workspace value becomes the
/// vendored `file:` spec under the user's own key, and package.json is
/// left alone. It used to be refused as `vendor_override_conflict`.
#[tokio::test(flavor = "multi_thread")]
async fn scan_vendored_over_hosted_pnpm_workspace_exact_pin_takes_over() {
    let server = MockServer::start().await;
    mock_api(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let hosted = host_project(root, &server.uri(), Shape::ExactPin);

    let (exit, env) = run_mode(root, &server.uri(), "scan", "vendored", &["--dry-run"]);
    assert_eq!(exit, 0, "{env:#}");
    assert_still_hosted(root, &hosted, &env);

    let (exit, env) = run_mode(root, &server.uri(), "scan", "vendored", &[]);
    assert_eq!(exit, 0, "the exact-pin takeover must succeed: {env:#}");
    let spec = format!("file:.socket/vendor/npm/{UUID}/{NAME}-{VERSION}.tgz");
    let ws = std::fs::read_to_string(root.join("pnpm-workspace.yaml")).unwrap();
    // Hosted mode's `trustLockfile: true` line may follow; the override
    // entry itself is rewritten in place under the user's key.
    assert!(
        ws.starts_with(&format!("overrides:\n  {NAME}: {spec}\n")),
        "{ws}\n{env:#}"
    );
    let lock = std::fs::read_to_string(root.join("pnpm-lock.yaml")).unwrap();
    assert!(!lock.contains(HOSTED_URL), "{lock}");
    assert!(
        lock.contains(&format!("overrides:\n  {NAME}: {spec}\n")),
        "the lock override map must equal the workspace file's:\n{lock}"
    );
    let pkg = std::fs::read_to_string(root.join("package.json")).unwrap();
    assert!(!pkg.contains("overrides"), "{pkg}");
}

/// `vendor --dry-run` over the hosted pin previews the backend's refusal of
/// the RESTORED project (staged in memory, never written) with the wet
/// run's code, instead of promising the takeover; the wet `vendor` then
/// keeps the hosted pin.
#[tokio::test(flavor = "multi_thread")]
async fn vendor_dry_run_over_hosted_pnpm_catalog_dep_previews_the_refusal() {
    let server = MockServer::start().await;
    mock_api(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    host_project(root, &server.uri(), Shape::Catalog);
    let manifest = json!({ "patches": { PURL: patch_record() } });
    std::fs::create_dir_all(root.join(".socket/blobs")).unwrap();
    std::fs::write(
        root.join(".socket/manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    std::fs::write(
        root.join(".socket/blobs")
            .join(compute_git_sha256_from_bytes(PATCHED_INDEX)),
        PATCHED_INDEX,
    )
    .unwrap();
    let hosted = snapshot(root);
    let vendor = |extra: &[&str]| {
        let mut args = vec!["vendor", "--json", "--cwd", root.to_str().unwrap()];
        args.extend_from_slice(extra);
        run_json(root, &server.uri(), &args)
    };

    let (exit, env) = vendor(&["--dry-run"]);
    assert_still_hosted(root, &hosted, &env);
    assert_refused(&env, exit, "vendor_lock_entry_unsupported");
    assert!(
        !has_event_code(&env, "vendor_would_revert_redirect"),
        "the refused takeover is not promised: {env:#}"
    );

    let (exit, env) = vendor(&[]);
    assert_refused(&env, exit, "vendor_lock_entry_unsupported");
    assert_still_hosted(root, &hosted, &env);
}
