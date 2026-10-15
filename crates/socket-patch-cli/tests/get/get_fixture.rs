//! Fixtures and runners shared by `get_failure_paths.rs` (the `--json`
//! contracts) and `get_render.rs` (the human output) (#1089).
//!
//! In-process tests drive `get::run` / the agent download engine and are
//! `#[serial]`: `get::run` mirrors flags into process-global env vars.
//! Subprocess tests use [`run_get_bin`] (`common::run_with_env`), which
//! scrubs the ambient `SOCKET_*` surface and spawns a hermetic child, so
//! they need no serialization.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use socket_patch_cli::commands::get::{
    download_and_apply_patches_with, DownloadParams, DownloadRun, GetArgs,
};
use socket_patch_cli::commands::scan::ScanMode;
use socket_patch_core::api::client::{get_api_client_with_overrides, ApiClientEnvOverrides};
use socket_patch_core::api::types::PatchSearchResult;
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::{common, prebuilt_common};

/// The agent engine driven from `params` plus the mock server's URI: builds
/// the run's client against it (what scan/get do once per run) with the
/// default try-once lock, then runs [`download_and_apply_patches_with`].
pub async fn download_and_apply_patches(
    selected: &[PatchSearchResult],
    params: &DownloadParams,
    server_uri: &str,
) -> (i32, serde_json::Value) {
    let (api_client, _) = get_api_client_with_overrides(ApiClientEnvOverrides {
        api_url: Some(server_uri.to_string()),
        api_token: Some("fake".to_string()),
        org_slug: Some(ORG.to_string()),
        proxy_url: None,
    })
    .await;
    let run = DownloadRun {
        api_client: &api_client,
        lock_timeout: None,
        verbose: false,
    };
    let (code, env) = download_and_apply_patches_with(selected, params, &run).await;
    (code, env.to_value())
}

pub const ORG: &str = "test-org";

pub const UUID: &str = "11111111-1111-4111-8111-111111111111";

pub const UUID_B: &str = "22222222-2222-4222-8222-222222222222";

pub const PURL: &str = "pkg:npm/covgap-pkg@1.0.0";

pub const NAME: &str = "covgap-pkg";

pub const GHSA: &str = "GHSA-aaaa-bbbb-cccc";

/// A patch for a version the fixture project never has.
pub const UUID_V2: &str = "33333333-3333-4333-8333-333333333333";

pub const PURL_V2: &str = "pkg:npm/covgap-pkg@2.0.0";

pub const BEFORE_BYTES: &[u8] = b"vulnerable\n";

pub const AFTER_BYTES: &[u8] = b"patched\n";

pub fn b64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

pub fn git_hash(bytes: &[u8]) -> String {
    compute_git_sha256_from_bytes(bytes)
}

/// In-process `GetArgs` — same defaults as `in_process_get.rs`.
pub fn default_args(identifier: &str, cwd: &Path) -> GetArgs {
    GetArgs {
        common: socket_patch_cli::args::GlobalArgs {
            org: Some(ORG.to_string()),
            cwd: cwd.to_path_buf(),
            yes: true,
            api_token: Some("fake-token-for-tests".to_string()),
            global: false,
            global_prefix: None,
            json: true,
            ..socket_patch_cli::args::GlobalArgs::default()
        },
        identifier: identifier.to_string(),
        id: false,
        cve: false,
        ghsa: false,
        package: false,
        save_only: true,
        all_releases: false,
        mode: Some(socket_patch_cli::commands::scan::ScanMode::Agent),
    }
}

/// A `view/{uuid}` body with an arbitrary `files` map.
pub fn view_json(uuid: &str, purl: &str, files: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "uuid": uuid,
        "purl": purl,
        "publishedAt": "2024-01-01T00:00:00Z",
        "files": files,
        "vulnerabilities": {},
        "description": "covgap fixture",
        "license": "MIT",
        "tier": "free",
    })
}

/// `view/{uuid}` with an arbitrary `files` map.
pub async fn mount_view_files(
    server: &MockServer,
    uuid: &str,
    purl: &str,
    files: serde_json::Value,
) {
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{uuid}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(view_json(uuid, purl, files)))
        .mount(server)
        .await;
}

/// A view whose files carry hashes but NO `blobContent`: the download
/// phase records it fine (hashes only), but the vendor step has nothing to
/// stage from — not in the download phase's blob seed, not on disk, and not
/// from the view it re-fetches — so it dies `no_local_source`.
pub async fn mount_contentless_view(server: &MockServer, uuid: &str, purl: &str) {
    let mut files = good_files();
    files["package/index.js"]
        .as_object_mut()
        .unwrap()
        .remove("blobContent");
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{uuid}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(view_json(uuid, purl, files)))
        .mount(server)
        .await;
}

/// A single-file view map with well-formed 64-hex hashes and blob content.
pub fn good_files() -> serde_json::Value {
    serde_json::json!({
        "package/index.js": {
            "beforeHash": "0".repeat(64),
            // The real git-sha256 of the content: inline blobs are
            // verified against their name before they are stored (#726).
            "afterHash": git_hash(b"patched\n"),
            "blobContent": "cGF0Y2hlZAo=", // base64("patched\n")
        }
    })
}

pub fn assert_no_manifest(cwd: &Path) {
    assert!(
        !cwd.join(".socket/manifest.json").exists(),
        "no manifest may be written"
    );
}

pub fn manifest_json(cwd: &Path) -> serde_json::Value {
    let body = std::fs::read_to_string(cwd.join(".socket/manifest.json")).unwrap();
    serde_json::from_str(&body).unwrap()
}

/// The vendor ledger — the ONLY record a `--mode vendored` run writes.
pub fn vendor_state(cwd: &Path) -> serde_json::Value {
    let body = std::fs::read_to_string(cwd.join(".socket/vendor/state.json"))
        .expect("the vendor ledger must be written");
    serde_json::from_str(&body).unwrap()
}

/// A vendored get records `purl` as a DETACHED ledger entry at `uuid` with
/// the patch record embedded (vendored mode is manifest-free), and never
/// writes `.socket/manifest.json` or `.socket/blobs`.
pub fn assert_vendored_detached(cwd: &Path, purl: &str, uuid: &str) {
    let state = vendor_state(cwd);
    let entry = &state["entries"][purl];
    assert_eq!(entry["uuid"], uuid, "ledger entry for {purl}: {state}");
    assert_eq!(
        entry["detached"], true,
        "every get --mode vendored entry is detached: {state}"
    );
    assert_eq!(
        entry["record"]["uuid"], uuid,
        "the embedded record is the verification source: {state}"
    );
    assert_no_manifest(cwd);
    assert!(
        !cwd.join(".socket/blobs").exists(),
        "the vendored download phase must not persist blobs"
    );
    // G6: vendored writes ONLY `.socket/vendor/**` — no `apply.lock` outlives
    // the run, no `diffs/`/`packages/`, nothing else.
    let mut names: Vec<String> = std::fs::read_dir(cwd.join(".socket"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(
        names,
        vec!["vendor".to_string()],
        "a vendored get's footprint is .socket/vendor/** only"
    );
}

/// Pre-stage an `apply.lock` so the lock can be acquired inside a directory
/// the test is about to make read-only: `acquire` opens an EXISTING file
/// without needing to create one, so the run gets past the lock and fails
/// at the write under test (the manifest) instead.
#[cfg(unix)]
pub fn prestage_lock_file(socket: &Path) {
    std::fs::write(socket.join("apply.lock"), b"").unwrap();
}

/// The path of every request the mock received: which code path the binary
/// really took. Panics when recording is off, so an empty list never passes
/// a "no request" check vacuously.
pub async fn received_paths(server: &MockServer) -> Vec<String> {
    server
        .received_requests()
        .await
        .expect("wiremock must record received requests")
        .iter()
        .map(|r| r.url.path().to_string())
        .collect()
}

pub async fn requests_containing(server: &MockServer, fragment: &str) -> usize {
    received_paths(server)
        .await
        .iter()
        .filter(|p| p.contains(fragment))
        .count()
}

/// Seed a valid manifest with one record (same shape as
/// `in_process_get_update_count::seed_manifest_with`).
pub fn seed_manifest_with(root: &Path, purl: &str, uuid: &str) {
    seed_manifest_with_files(root, purl, uuid, serde_json::json!({}));
}

pub fn seed_manifest_with_files(root: &Path, purl: &str, uuid: &str, files: serde_json::Value) {
    let socket = root.join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "patches": {
                purl: {
                    "uuid": uuid,
                    "exportedAt": "2024-01-01T00:00:00Z",
                    "files": files,
                    "vulnerabilities": {},
                    "description": "seeded",
                    "license": "MIT",
                    "tier": "free",
                }
            }
        }))
        .unwrap(),
    )
    .unwrap();
}

pub fn search_result(uuid: &str, purl: &str) -> PatchSearchResult {
    PatchSearchResult {
        uuid: uuid.into(),
        purl: purl.into(),
        published_at: "2024-06-01T00:00:00Z".into(),
        description: "covgap".into(),
        license: "MIT".into(),
        tier: "free".into(),
        vulnerabilities: HashMap::new(),
    }
}

/// Engine params (mirrors `in_process_get_update_count::params`).
pub fn engine_params(root: &Path) -> DownloadParams {
    DownloadParams {
        cwd: root.to_path_buf(),
        manifest_path: root.join(".socket/manifest.json"),
        save_only: true,
        global: false,
        global_prefix: None,
        json: true,
        silent: true,
        strict: false,
        ecosystems: None,
        persist_blobs: true,
        patch_server_url: None,
        all_releases: true,
    }
}

/// Save/remove/restore guard for env vars an in-process test must not see.
pub struct EnvVarGuard {
    saved: Vec<(&'static str, Option<String>)>,
}

impl EnvVarGuard {
    pub fn scrub(keys: &[&'static str]) -> Self {
        let saved = keys
            .iter()
            .map(|k| {
                let old = std::env::var(k).ok();
                std::env::remove_var(k);
                (*k, old)
            })
            .collect();
        Self { saved }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        for (k, v) in &self.saved {
            match v {
                Some(v) => std::env::set_var(k, v),
                None => std::env::remove_var(k),
            }
        }
    }
}

/// Probe whether permission bits are enforced for this process; root (or
/// CAP_DAC_OVERRIDE containers) bypasses them, making read-only-dir tests
/// vacuously green-or-red. Returns false (and logs) when they are not.
#[cfg(unix)]
pub fn readonly_dir_enforced(dir: &Path) -> bool {
    let probe = dir.join(".covgap-probe");
    if std::fs::write(&probe, b"x").is_ok() {
        let _ = std::fs::remove_file(&probe);
        eprintln!("skipping: permission bits not enforced (running as root?)");
        return false;
    }
    true
}

/// Write a minimal installed npm package under `<cwd>/node_modules/<name>`.
pub fn install_npm_fixture(cwd: &Path, name: &str, version: &str) {
    let pkg_dir = cwd.join("node_modules").join(name);
    std::fs::create_dir_all(&pkg_dir).unwrap();
    std::fs::write(
        pkg_dir.join("package.json"),
        serde_json::json!({ "name": name, "version": version }).to_string(),
    )
    .unwrap();
}

/// The npm project fixture from `in_process_get_modes.rs`: `covgap-pkg@1.0.0`
/// installed (crawler-visible) and lockfile-resolved; 2.0.0 exists nowhere.
pub fn write_project(root: &Path) {
    std::fs::write(
        root.join("package.json"),
        format!(
            r#"{{ "name": "consumer", "version": "0.0.0", "dependencies": {{ "{NAME}": "1.0.0" }} }}"#
        ),
    )
    .unwrap();
    let pkg = root.join("node_modules").join(NAME);
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        pkg.join("package.json"),
        format!(r#"{{ "name": "{NAME}", "version": "1.0.0", "main": "index.js" }}"#),
    )
    .unwrap();
    std::fs::write(pkg.join("index.js"), BEFORE_BYTES).unwrap();
    std::fs::write(
        root.join("package-lock.json"),
        format!(
            r#"{{
  "name": "consumer",
  "version": "0.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {{
    "": {{ "name": "consumer", "version": "0.0.0", "dependencies": {{ "{NAME}": "1.0.0" }} }},
    "node_modules/{NAME}": {{
      "version": "1.0.0",
      "resolved": "https://registry.npmjs.org/{NAME}/-/{NAME}-1.0.0.tgz",
      "integrity": "sha512-UPSTREAMupstream=="
    }}
  }}
}}
"#
        ),
    )
    .unwrap();
}

/// `view/{uuid}` with REAL git-blob hashes over the project fixture's bytes,
/// so the vendored staging hash-gates pass.
pub async fn mount_real_view(server: &MockServer, uuid: &str, purl: &str) {
    let files = serde_json::json!({"package/index.js":{"beforeHash":git_hash(BEFORE_BYTES),"afterHash":git_hash(AFTER_BYTES),"blobContent":b64(AFTER_BYTES)}});
    prebuilt_common::mount_view(server, &view_json(uuid, purl, files), None).await;
    mount_view_files(
        server,
        uuid,
        purl,
        serde_json::json!({
            "package/index.js": {
                "beforeHash": git_hash(BEFORE_BYTES),
                "afterHash": git_hash(AFTER_BYTES),
                "blobContent": b64(AFTER_BYTES),
            }
        }),
    )
    .await;
}

/// `by-ghsa/{GHSA}`: the two-version fan-out over the project fixture.
pub async fn mount_ghsa_fanout(server: &MockServer) {
    let patch = |uuid: &str, purl: &str, published: &str| {
        serde_json::json!({
            "uuid": uuid, "purl": purl,
            "publishedAt": published,
            "description": "x", "license": "MIT", "tier": "free",
            "vulnerabilities": {}
        })
    };
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/by-ghsa/{GHSA}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [
                patch(UUID_V2, PURL_V2, "2024-02-01T00:00:00Z"),
                patch(UUID, PURL, "2024-01-01T00:00:00Z"),
            ],
            "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;
}

/// Subprocess `get` against the mock (telemetry disabled in the child).
pub fn run_get_bin(cwd: &Path, api_url: &str, extra: &[&str]) -> (i32, String, String) {
    let mut args = vec!["get"];
    args.extend_from_slice(extra);
    // v5 `get` defaults to hosted; these fixtures drive agent mode.
    if !extra.contains(&"--mode") {
        args.extend_from_slice(&["--mode", "agent"]);
    }
    args.extend_from_slice(&[
        "--api-url",
        api_url,
        "--api-token",
        "fake-token-for-tests",
        "--org",
        ORG,
        "--yes",
    ]);
    common::run_with_env(cwd, &args, &[("SOCKET_TELEMETRY_DISABLED", "1")])
}

/// Fabricate a crawler-visible PyPI install without python: a `.venv`
/// site-packages with a `<name>-<version>.dist-info/METADATA` and the
/// package's single module file. Returns the module file path.
///
/// The crawler probes a platform-specific venv layout
/// (`find_site_packages_under`): `.venv/Lib/site-packages` on Windows,
/// `.venv/lib/python3.*/site-packages` elsewhere — stage whichever this
/// runner will actually look in, or the package is "not installed" and the
/// variant narrowing under test never runs.
pub fn fake_pypi_venv(root: &Path, name: &str, version: &str, file_bytes: &[u8]) -> PathBuf {
    let sp = if cfg!(windows) {
        root.join(".venv").join("Lib").join("site-packages")
    } else {
        root.join(".venv")
            .join("lib")
            .join("python3.11")
            .join("site-packages")
    };
    let dist = sp.join(format!("{name}-{version}.dist-info"));
    std::fs::create_dir_all(&dist).unwrap();
    std::fs::write(
        dist.join("METADATA"),
        format!("Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n"),
    )
    .unwrap();
    let module = sp.join(format!("{name}.py"));
    std::fs::write(&module, file_bytes).unwrap();
    module
}

pub fn vendored_args(identifier: &str, cwd: &Path, api_url: String) -> GetArgs {
    let mut args = default_args(identifier, cwd);
    args.common.api_url = Some(api_url);
    args.common.vendor_source = "service".to_string();
    args.save_only = false;
    args.mode = Some(ScanMode::Vendored);
    args
}

/// `get <uuid> --mode vendored --json` flags for `uuid`.
pub fn vendored_json_args(uuid: &str) -> [&str; 6] {
    [
        uuid,
        "--mode",
        "vendored",
        "--vendor-source",
        "service",
        "--json",
    ]
}

/// Legacy on-disk state a vendored get must leave ALONE: an agent-mode
/// manifest record and a non-detached ledger entry the selection never
/// names. Vendored mode is manifest-free — its vendor step verifies exactly
/// the records the download phase fetched and never reconciles the ledger
/// against a manifest — so neither may change, even when the run fails.
pub const OTHER_UUID: &str = "44444444-4444-4444-8444-444444444444";

pub const OTHER_PURL: &str = "pkg:npm/left-pad@1.3.0";

pub const UNSELECTED_UUID: &str = "55555555-5555-4555-8555-555555555555";

pub const UNSELECTED_PURL: &str = "pkg:npm/gone@9.9.9";

/// Seed the legacy state; returns the exact manifest and ledger bytes for
/// the byte-identical checks after the run.
pub fn seed_legacy_state(root: &Path) -> (String, String) {
    seed_manifest_with_files(
        root,
        OTHER_PURL,
        OTHER_UUID,
        serde_json::json!({
            "package/index.js": {
                "beforeHash": git_hash(b"lp before\n"),
                "afterHash": git_hash(b"lp after\n"),
            }
        }),
    );
    let vendor = root.join(".socket/vendor");
    std::fs::create_dir_all(&vendor).unwrap();
    std::fs::write(
        vendor.join("state.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "version": 1,
            "entries": { UNSELECTED_PURL: {
                "ecosystem": "npm",
                "basePurl": UNSELECTED_PURL,
                "uuid": UNSELECTED_UUID,
                "artifact": {
                    "path": format!(".socket/vendor/npm/{UNSELECTED_UUID}/gone-9.9.9.tgz"),
                },
                "wiring": []
            }}
        }))
        .unwrap(),
    )
    .unwrap();
    (
        std::fs::read_to_string(root.join(".socket/manifest.json")).unwrap(),
        std::fs::read_to_string(vendor.join("state.json")).unwrap(),
    )
}

pub fn assert_legacy_state_untouched(root: &Path, manifest_before: &str, state_before: &str) {
    assert_eq!(
        std::fs::read_to_string(root.join(".socket/manifest.json")).unwrap(),
        manifest_before,
        "vendored mode never reads or writes the manifest"
    );
    assert_eq!(
        std::fs::read_to_string(root.join(".socket/vendor/state.json")).unwrap(),
        state_before,
        "the detached vendor step never reconciles unselected ledger entries"
    );
}

pub fn assert_vendor_error_envelope(v: &serde_json::Value) {
    assert_eq!(v["status"], "partialFailure", "envelope={v}");
    let events = v["events"]
        .as_array()
        .unwrap_or_else(|| panic!("the envelope must have events[]; envelope={v}"));
    // The download half reports the record it fetched first; the vendor
    // engine's events follow in the same envelope.
    assert_eq!(events[0]["action"], "downloaded", "envelope={v}");
    assert!(
        events
            .iter()
            .any(|e| e["errorCode"] == "vendor_lockfile_missing"
                && e["details"]["mode"] == "vendored"),
        "{v}"
    );
    assert!(
        !events.iter().any(|e| e["purl"] == UNSELECTED_PURL),
        "the detached vendor step must not reconcile (revert) unselected ledger entries; envelope={v}"
    );
    assert!(v.get("vendor").is_none(), "no nested vendor envelope: {v}");
}

/// `by-ghsa/{GHSA}` returning exactly the one project-fixture patch.
pub async fn mount_ghsa_single(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/by-ghsa/{GHSA}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
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
}

/// The hosted reference endpoint granting `uuid` for `purl` at `url` (the
/// `covgap_commands_scan_hosted` fixture shape).
pub async fn mount_granted_reference(server: &MockServer, uuid: &str, purl: &str, url: &str) {
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/package")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "results": {
                uuid: {
                    "status": "granted",
                    "url": url,
                    "purl": purl,
                    "artifacts": [{
                        "kind": "tarball",
                        "url": url,
                        "integrity": { "sha512": "sha512-PATCHEDpatchedPATCHEDpatched0123456789==" }
                    }],
                    "registryOverride": null
                }
            }
        })))
        .mount(server)
        .await;
}

/// The npm project fixture, except `node_modules/covgap-pkg` is a symlink
/// to a first-party `packages/covgap-pkg` (a workspace member that shares
/// the patched name@version). Apply refuses to patch it (it lies outside
/// every `node_modules` tree), a deterministic apply failure that needs no
/// read-only filesystem.
#[cfg(unix)]
pub fn write_first_party_link_project(root: &Path) {
    write_project(root);
    let installed = root.join("node_modules").join(NAME);
    let member = root.join("packages").join(NAME);
    std::fs::create_dir_all(member.parent().unwrap()).unwrap();
    std::fs::rename(&installed, &member).unwrap();
    std::os::unix::fs::symlink(Path::new("../packages").join(NAME), &installed).unwrap();
}

/// Locally edited bytes: neither the patch's beforeHash nor its afterHash.
pub const LOCAL_EDIT_BYTES: &[u8] = b"vulnerable\n// local edit\n";

/// Whether `json["warnings"]` carries a `content_mismatch_overwritten`
/// entry naming `purl` and the overwritten file.
pub fn has_mismatch_warning(json: &serde_json::Value, purl: &str) -> bool {
    json["warnings"].as_array().is_some_and(|ws| {
        ws.iter().any(|w| {
            let detail = w["detail"].as_str().unwrap_or_default();
            w["code"] == "content_mismatch_overwritten"
                && detail.contains(purl)
                && detail.contains("package/index.js")
        })
    })
}

/// A one-file view whose `afterHash` is a path traversal: the blob write
/// must refuse it.
pub fn traversal_files() -> serde_json::Value {
    serde_json::json!({
        "package/index.js": {
            "beforeHash": "0".repeat(64),
            "afterHash": "../covgap-escape",
            "blobContent": "cGF0Y2hlZAo=",
        }
    })
}

/// Subprocess `get` with no `--api-token` / `--org`: the scrubbed child
/// falls back to the public proxy, seeded at `uri` through
/// `SOCKET_PROXY_URL`.
pub fn run_get_via_proxy(cwd: &Path, uri: &str, extra: &[&str]) -> (i32, String, String) {
    let mut args = vec!["get"];
    args.extend_from_slice(extra);
    args.extend_from_slice(&["--yes", "--api-url", uri]);
    common::run_with_env(
        cwd,
        &args,
        &[
            ("SOCKET_PROXY_URL", uri),
            ("SOCKET_TELEMETRY_DISABLED", "1"),
        ],
    )
}

/// The patched tarball URL [`hosted_project_with_held_lock`] grants.
pub const HOSTED_URL: &str = "http://patch.test/patch/npm/covgap-pkg/1.0.0/22222222-2222-4222-8222-222222222222/11111111-1111-4111-8111-111111111111/covgap-pkg-1.0.0.tgz";

/// The project fixture with [`UUID`] granted for hosted mode at
/// [`HOSTED_URL`], while another holder keeps `.socket/apply.lock` (until
/// the returned guard drops).
pub async fn hosted_project_with_held_lock() -> (
    MockServer,
    tempfile::TempDir,
    socket_patch_core::patch::apply_lock::LockGuard,
) {
    let server = MockServer::start().await;
    mount_view_files(&server, UUID, PURL, good_files()).await;
    mount_granted_reference(&server, UUID, PURL, HOSTED_URL).await;
    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    let lock =
        socket_patch_core::patch::apply_lock::acquire(&socket, std::time::Duration::ZERO).unwrap();
    (server, tmp, lock)
}
