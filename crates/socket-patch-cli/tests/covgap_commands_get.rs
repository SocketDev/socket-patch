//! Coverage-gap tests for `commands/get.rs` (coverage audit 2026-09).
//!
//! Targets the audited never-executed branches: `run()`'s flag/package-path
//! edges, the `save_patch_record` failure ladder on the uuid path, the
//! `download_and_apply_patches` engine failure branches, the release-variant
//! narrowing fallbacks (fabricated PyPI venv — no real python needed), the
//! search-path `--mode vendored` flow, the vendor-step error arms, and every
//! human-mode (non `--json`) output path the existing suites left to
//! `--json`/`--silent` runs.
//!
//! In-process tests are `#[serial]` (like `in_process_get*.rs`: `get::run`
//! mirrors flags into process-global env vars). Subprocess tests use
//! `common::run_with_env`, which scrubs the ambient `SOCKET_*` surface and
//! spawns a hermetic child, so they need no serialization.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serial_test::serial;
use socket_patch_cli::commands::get::{
    download_and_apply_patches_with, run, DownloadParams, DownloadRun, GetArgs,
};
use socket_patch_cli::commands::scan::ScanMode;
use socket_patch_core::api::client::{get_api_client_with_overrides, ApiClientEnvOverrides};
use socket_patch_core::api::types::PatchSearchResult;
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// The agent engine driven from `params` plus the mock server's URI: builds
/// the run's client against it (what scan/get do once per run) with the
/// default try-once lock, then runs [`download_and_apply_patches_with`].
async fn download_and_apply_patches(
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
    download_and_apply_patches_with(selected, params, &run).await
}

#[path = "common/mod.rs"]
mod common;

const ORG: &str = "test-org";
const UUID: &str = "11111111-1111-4111-8111-111111111111";
const UUID_B: &str = "22222222-2222-4222-8222-222222222222";
const PURL: &str = "pkg:npm/covgap-pkg@1.0.0";
const NAME: &str = "covgap-pkg";
const GHSA: &str = "GHSA-aaaa-bbbb-cccc";
/// A patch for a version the fixture project never has.
const UUID_V2: &str = "33333333-3333-4333-8333-333333333333";
const PURL_V2: &str = "pkg:npm/covgap-pkg@2.0.0";

const BEFORE_BYTES: &[u8] = b"vulnerable\n";
const AFTER_BYTES: &[u8] = b"patched\n";

fn b64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn git_hash(bytes: &[u8]) -> String {
    compute_git_sha256_from_bytes(bytes)
}

// ---------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------

/// In-process `GetArgs` — same defaults as `in_process_get.rs`.
fn default_args(identifier: &str, cwd: &Path) -> GetArgs {
    GetArgs {
        common: socket_patch_cli::args::GlobalArgs {
            org: Some(ORG.to_string()),
            cwd: cwd.to_path_buf(),
            yes: true,
            api_token: Some("fake-token-for-tests".to_string()),
            global: false,
            global_prefix: None,
            json: true,
            download_mode: "diff".to_string(),
            ..socket_patch_cli::args::GlobalArgs::default()
        },
        identifier: identifier.to_string(),
        id: false,
        cve: false,
        ghsa: false,
        package: false,
        save_only: true,
        one_off: false,
        all_releases: false,
        mode: None,
    }
}

/// A `view/{uuid}` body with an arbitrary `files` map.
fn view_json(uuid: &str, purl: &str, files: serde_json::Value) -> serde_json::Value {
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
async fn mount_view_files(server: &MockServer, uuid: &str, purl: &str, files: serde_json::Value) {
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{uuid}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(view_json(uuid, purl, files)))
        .mount(server)
        .await;
}

/// `view/{uuid}` served exactly ONCE: the get's own fetch succeeds, and the
/// vendor step's in-memory staging — which fetches the view again — then
/// 404s, tripping the `no_local_source` staging refusal.
/// A view whose files carry hashes but NO `blobContent`: the download
/// phase records it fine (hashes only), but the vendor step has nothing to
/// stage from — not in the download phase's blob seed, not on disk, and not
/// from the view it re-fetches — so it dies `no_local_source`. (Serving a
/// good view exactly once no longer produces that: the step stages from
/// the seed and never fetches the view a second time.)
async fn mount_contentless_view(server: &MockServer, uuid: &str, purl: &str) {
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
fn good_files() -> serde_json::Value {
    serde_json::json!({
        "package/index.js": {
            "beforeHash": "0".repeat(64),
            "afterHash": "1".repeat(64),
            "blobContent": "cGF0Y2hlZAo=", // base64("patched\n")
        }
    })
}

fn assert_no_manifest(cwd: &Path) {
    assert!(
        !cwd.join(".socket/manifest.json").exists(),
        "no manifest may be written"
    );
}

fn manifest_json(cwd: &Path) -> serde_json::Value {
    let body = std::fs::read_to_string(cwd.join(".socket/manifest.json")).unwrap();
    serde_json::from_str(&body).unwrap()
}

/// The vendor ledger — the ONLY record a `--mode vendored` run writes.
fn vendor_state(cwd: &Path) -> serde_json::Value {
    let body = std::fs::read_to_string(cwd.join(".socket/vendor/state.json"))
        .expect("the vendor ledger must be written");
    serde_json::from_str(&body).unwrap()
}

/// A vendored get records `purl` as a DETACHED ledger entry at `uuid` with
/// the patch record embedded (vendored mode is manifest-free), and never
/// writes `.socket/manifest.json` or `.socket/blobs`.
fn assert_vendored_detached(cwd: &Path, purl: &str, uuid: &str) {
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
fn prestage_lock_file(socket: &Path) {
    std::fs::write(socket.join("apply.lock"), b"").unwrap();
}

async fn received_paths(server: &MockServer) -> Vec<String> {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .map(|r| r.url.path().to_string())
        .collect()
}

async fn requests_containing(server: &MockServer, fragment: &str) -> usize {
    received_paths(server)
        .await
        .iter()
        .filter(|p| p.contains(fragment))
        .count()
}

/// Seed a valid manifest with one record (same shape as
/// `in_process_get_update_count::seed_manifest_with`).
fn seed_manifest_with(root: &Path, purl: &str, uuid: &str) {
    seed_manifest_with_files(root, purl, uuid, serde_json::json!({}));
}

fn seed_manifest_with_files(root: &Path, purl: &str, uuid: &str, files: serde_json::Value) {
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

fn search_result(uuid: &str, purl: &str) -> PatchSearchResult {
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
fn engine_params(root: &Path) -> DownloadParams {
    DownloadParams {
        cwd: root.to_path_buf(),
        manifest_path: root.join(".socket/manifest.json"),
        save_only: true,
        global: false,
        global_prefix: None,
        json: true,
        silent: true,
        download_mode: "diff".to_string(),
        strict: false,
        ecosystems: None,
        persist_blobs: true,
        all_releases: true,
    }
}

/// Save/remove/restore guard for env vars an in-process test must not see.
struct EnvVarGuard {
    saved: Vec<(&'static str, Option<String>)>,
}

impl EnvVarGuard {
    fn scrub(keys: &[&'static str]) -> Self {
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
fn readonly_dir_enforced(dir: &Path) -> bool {
    let probe = dir.join(".covgap-probe");
    if std::fs::write(&probe, b"x").is_ok() {
        let _ = std::fs::remove_file(&probe);
        eprintln!("skipping: permission bits not enforced (running as root?)");
        return false;
    }
    true
}

/// Write a minimal installed npm package under `<cwd>/node_modules/<name>`.
fn install_npm_fixture(cwd: &Path, name: &str, version: &str) {
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
fn write_project(root: &Path) {
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
async fn mount_real_view(server: &MockServer, uuid: &str, purl: &str) {
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
async fn mount_ghsa_fanout(server: &MockServer) {
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
fn run_get_bin(cwd: &Path, api_url: &str, extra: &[&str]) -> (i32, String, String) {
    let mut args = vec!["get"];
    args.extend_from_slice(extra);
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

/// Parse stdout as exactly ONE JSON document (get's `--json` contract).
fn parse_single_json_doc(stdout: &str) -> serde_json::Value {
    let trimmed = stdout.trim();
    assert!(
        !trimmed.is_empty(),
        "expected a JSON envelope on stdout, got nothing"
    );
    serde_json::from_str(trimmed).unwrap_or_else(|e| {
        panic!("stdout must be exactly one JSON document: {e}\nstdout:\n{stdout}")
    })
}

// ===========================================================================
// (1) run() flag validation and package-path edges
// ===========================================================================

/// Two identifier type flags together must be rejected up front: exit 1,
/// nothing fetched, nothing written. This branch (line-level: the
/// `type_flags > 1` guard) had never executed — every caller passes at most
/// one flag.
#[tokio::test]
#[serial]
async fn get_conflicting_type_flags_rejected_before_any_network() {
    // Live trap mock so "rejected before any fetch" is provable.
    let server = MockServer::start().await;
    mount_view_files(&server, UUID, PURL, good_files()).await;

    let tmp = tempfile::tempdir().unwrap();
    let mut args = default_args(UUID, tmp.path());
    args.common.api_url = Some(server.uri());
    args.id = true;
    args.cve = true;

    let code = run(args).await;
    assert_eq!(code, 1, "conflicting --id/--cve must exit 1");
    assert_no_manifest(tmp.path());
    assert!(
        received_paths(&server).await.is_empty(),
        "the conflict must be rejected before any API call"
    );
}

/// The uuid save path's no-applicable-files guardrail: a view whose files
/// all lack an `afterHash` must exit 1 with the guardrail error and write
/// NO manifest — never `applied: 1` over an empty record.
#[tokio::test]
async fn get_uuid_view_without_after_hashes_fails_no_applicable_files() {
    let server = MockServer::start().await;
    mount_view_files(
        &server,
        UUID,
        PURL,
        serde_json::json!({
            "package/index.js": { "beforeHash": "e".repeat(64), "afterHash": null }
        }),
    )
    .await;

    let tmp = tempfile::tempdir().unwrap();
    let (code, stdout, _stderr) =
        run_get_bin(tmp.path(), &server.uri(), &[UUID, "--save-only", "--json"]);
    assert_eq!(code, 1, "guardrail must exit 1; stdout={stdout}");
    let v = parse_single_json_doc(&stdout);
    assert_eq!(v["status"], "error", "stdout={stdout}");
    assert!(
        v["error"]
            .as_str()
            .unwrap_or_default()
            .contains("no applicable files"),
        "error must name the guardrail; stdout={stdout}"
    );
    assert_no_manifest(tmp.path());
}

/// The uuid save path's blob-failure ladder: a traversal `afterHash` must
/// fail the blob write, emit the error envelope (json) / stderr line
/// (human), exit 1, and leave no manifest and no escaped file.
#[tokio::test]
async fn get_uuid_traversal_after_hash_fails_blob_write_both_modes() {
    let traversal_files = serde_json::json!({
        "package/index.js": {
            "beforeHash": "0".repeat(64),
            "afterHash": "../covgap-escape",
            "blobContent": "cGF0Y2hlZAo=",
        }
    });

    // --json flavor: the envelope carries the error.
    {
        let server = MockServer::start().await;
        mount_view_files(&server, UUID, PURL, traversal_files.clone()).await;
        let tmp = tempfile::tempdir().unwrap();
        let (code, stdout, _stderr) =
            run_get_bin(tmp.path(), &server.uri(), &[UUID, "--save-only", "--json"]);
        assert_eq!(code, 1, "blob failure must exit 1; stdout={stdout}");
        let v = parse_single_json_doc(&stdout);
        assert_eq!(v["status"], "error", "stdout={stdout}");
        assert_eq!(v["error"], "Blob decode or write failed", "stdout={stdout}");
        assert_eq!(v["patches"][0]["action"], "failed", "stdout={stdout}");
        assert_no_manifest(tmp.path());
        assert!(
            !tmp.path().join("covgap-escape").exists()
                && !tmp.path().join(".socket/covgap-escape").exists(),
            "the traversal hash must never produce a file outside blobs/"
        );
    }

    // Human flavor: the error goes to stderr, naming the purl.
    {
        let server = MockServer::start().await;
        mount_view_files(&server, UUID, PURL, traversal_files).await;
        let tmp = tempfile::tempdir().unwrap();
        let (code, _stdout, stderr) =
            run_get_bin(tmp.path(), &server.uri(), &[UUID, "--save-only"]);
        assert_eq!(code, 1, "blob failure must exit 1; stderr={stderr}");
        assert!(
            stderr.contains("Blob decode or write failed for patch") && stderr.contains(PURL),
            "human mode must report the blob failure on stderr; stderr={stderr}"
        );
        assert_no_manifest(tmp.path());
    }
}

/// A regular FILE squatting on the `.socket` path must fail the run
/// fail-closed in BOTH uuid modes without destroying the file: the agent
/// save's apply-lock acquire refuses (`.socket` cannot be created), and the
/// vendored run's vendor step refuses the same way (its download phase
/// writes nothing).
#[tokio::test]
#[serial]
async fn get_uuid_socket_path_occupied_by_file_fails_closed() {
    let server = MockServer::start().await;
    mount_view_files(&server, UUID, PURL, good_files()).await;
    let uri = server.uri();

    // Agent mode: the lock acquire inside the save refuses.
    {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join(".socket"), b"not a dir").unwrap();
        let mut args = default_args(UUID, tmp.path());
        args.common.api_url = Some(uri.clone());
        let code = run(args).await;
        assert_eq!(code, 1, "agent save must fail when .socket is a file");
        assert_eq!(
            std::fs::read(tmp.path().join(".socket")).unwrap(),
            b"not a dir",
            "the squatting file must be left untouched"
        );
    }

    // Vendored mode: the vendor step's `.socket` create / lock refuses.
    {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join(".socket"), b"not a dir").unwrap();
        let mut args = default_args(UUID, tmp.path());
        args.common.api_url = Some(uri.clone());
        args.save_only = false;
        args.mode = Some(ScanMode::Vendored);
        args.common.vendor_source = "build".to_string();
        let code = run(args).await;
        assert_eq!(code, 1, "vendored run must fail when .socket is a file");
        assert_eq!(
            std::fs::read(tmp.path().join(".socket")).unwrap(),
            b"not a dir",
            "the squatting file must be left untouched"
        );
    }
}

/// Manifest-write failure on the uuid save path: a read-only `.socket` dir
/// (blobs dir kept writable, lock file pre-staged so the acquire succeeds)
/// must fail the run with exit 1 and leave the pre-existing manifest
/// byte-identical.
#[cfg(unix)]
#[tokio::test]
#[serial]
async fn get_uuid_readonly_socket_dir_fails_manifest_write_preserving_manifest() {
    use std::os::unix::fs::PermissionsExt;

    let server = MockServer::start().await;
    mount_view_files(&server, UUID, PURL, good_files()).await;

    let tmp = tempfile::tempdir().unwrap();
    // A DIFFERENT uuid is recorded, so the save classifies as `updated`
    // and must attempt the manifest write.
    seed_manifest_with(tmp.path(), PURL, UUID_B);
    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    prestage_lock_file(&socket);
    let before = std::fs::read_to_string(socket.join("manifest.json")).unwrap();

    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o555)).unwrap();
    if !readonly_dir_enforced(&socket) {
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o755)).unwrap();
        return;
    }

    let mut args = default_args(UUID, tmp.path());
    args.common.api_url = Some(server.uri());
    let code = run(args).await;

    // Restore before asserting so the tempdir can always be cleaned up.
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o755)).unwrap();

    assert_eq!(code, 1, "a failed manifest write must exit 1");
    let after = std::fs::read_to_string(socket.join("manifest.json")).unwrap();
    assert_eq!(
        before, after,
        "the original manifest must survive the failed write"
    );
    let m: serde_json::Value = serde_json::from_str(&after).unwrap();
    assert_eq!(m["patches"][PURL]["uuid"], UUID_B, "old uuid must remain");
}

/// Human-mode uuid path: an update prints `Updated: 1 (replacing …)`, and
/// a same-uuid re-get lands on the `already has this patch recorded` note —
/// both exiting 0 with the manifest converged on the fetched uuid.
#[tokio::test]
#[serial]
async fn get_uuid_human_update_then_rerun_skips_preserving_manifest() {
    let server = MockServer::start().await;
    mount_view_files(&server, UUID, PURL, good_files()).await;
    let uri = server.uri();

    let tmp = tempfile::tempdir().unwrap();
    seed_manifest_with(tmp.path(), PURL, UUID_B);

    // First run: replaces UUID_B with UUID (the human `[update]` print).
    let mut args = default_args(UUID, tmp.path());
    args.common.api_url = Some(uri.clone());
    args.common.json = false;
    assert_eq!(run(args).await, 0, "the update run must succeed");
    assert_eq!(manifest_json(tmp.path())["patches"][PURL]["uuid"], UUID);

    // Second run: same uuid → the human "already recorded" note; still exit 0
    // and the manifest still records the same uuid.
    let mut args = default_args(UUID, tmp.path());
    args.common.api_url = Some(uri);
    args.common.json = false;
    assert_eq!(run(args).await, 0, "a same-uuid re-get is a benign skip");
    assert_eq!(manifest_json(tmp.path())["patches"][PURL]["uuid"], UUID);
}

/// Human-mode uuid path WITHOUT --save-only over an empty project: the
/// nested apply runs, finds nothing to patch, and fails — the run must
/// print the failure note and exit 1 (`partial_failure`), with the record
/// still saved (download succeeded; only the apply degraded).
#[tokio::test]
#[serial]
async fn get_uuid_human_nested_apply_failure_is_partial_failure() {
    let server = MockServer::start().await;
    mount_view_files(&server, UUID, PURL, good_files()).await;

    let tmp = tempfile::tempdir().unwrap();
    let mut args = default_args(UUID, tmp.path());
    args.common.api_url = Some(server.uri());
    args.common.json = false;
    args.save_only = false;

    let code = run(args).await;
    assert_eq!(
        code, 1,
        "a failed nested apply must degrade the run to exit 1"
    );
    // The record itself was saved before apply ran.
    assert_eq!(manifest_json(tmp.path())["patches"][PURL]["uuid"], UUID);
}

// ===========================================================================
// (2) package-name path edges (subprocess: the prints ARE the contract)
// ===========================================================================

/// `--package --global` with an EMPTY `--global-prefix`: exits 0 before any
/// network with the dedicated "No global packages found." message.
#[tokio::test]
async fn human_global_package_search_empty_prefix_prints_no_global_packages() {
    let server = MockServer::start().await;
    let tmp = tempfile::tempdir().unwrap();
    let prefix = tempfile::tempdir().unwrap();

    let (code, stdout, stderr) = run_get_bin(
        tmp.path(),
        &server.uri(),
        &[
            "some-package",
            "--package",
            "--global",
            "--global-prefix",
            prefix.path().to_str().unwrap(),
            "--save-only",
        ],
    );
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    assert!(
        stdout.contains("No global packages found."),
        "global no-packages must use its dedicated message; stdout={stdout}"
    );
    assert_no_manifest(tmp.path());
    assert!(
        received_paths(&server).await.is_empty(),
        "no API call may happen for an empty global prefix"
    );
}

/// Installed packages that fuzzy-match NOTHING: the `no_match` terminal —
/// json envelope + human message — exits 0 with zero API calls.
#[tokio::test]
async fn package_search_without_fuzzy_match_is_no_match_in_both_modes() {
    // json flavor.
    {
        let server = MockServer::start().await;
        let tmp = tempfile::tempdir().unwrap();
        install_npm_fixture(tmp.path(), "leftpad", "1.0.0");
        let (code, stdout, _stderr) = run_get_bin(
            tmp.path(),
            &server.uri(),
            &["zzqxjvwq", "--package", "--save-only", "--json"],
        );
        assert_eq!(code, 0, "no_match is a clean exit; stdout={stdout}");
        let v = parse_single_json_doc(&stdout);
        assert_eq!(v["status"], "no_match", "stdout={stdout}");
        assert_eq!(v["patches"].as_array().unwrap().len(), 0);
        assert!(
            received_paths(&server).await.is_empty(),
            "no_match must be decided before any API call"
        );
    }
    // human flavor: the message + the crawl progress prints.
    {
        let server = MockServer::start().await;
        let tmp = tempfile::tempdir().unwrap();
        install_npm_fixture(tmp.path(), "leftpad", "1.0.0");
        let (code, stdout, stderr) = run_get_bin(
            tmp.path(),
            &server.uri(),
            &["zzqxjvwq", "--package", "--save-only"],
        );
        assert_eq!(code, 0, "stdout={stdout}");
        assert!(
            stdout.contains("No packages matching \"zzqxjvwq\" found."),
            "human no_match message; stdout={stdout}"
        );
        // Crawl progress is stderr narration: the transient
        // "Enumerating packages..." line never reaches a pipe, the result
        // line does (singular for one package).
        assert!(
            !stdout.contains("Enumerating packages") && stderr.contains("Found 1 package\n"),
            "the crawl progress prints must appear; stdout={stdout}"
        );
        assert!(received_paths(&server).await.is_empty());
    }
}

/// The package path's search-API error arm: a fuzzy-matched package whose
/// by-package search 500s must exit 1 via `report_fetch_failure`, after
/// printing the "checking for available patches" progress line.
#[tokio::test]
async fn human_package_search_api_error_reports_fetch_failure() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(format!(
            "^/v0/orgs/{ORG}/patches/by-package/.+$"
        )))
        .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    install_npm_fixture(tmp.path(), NAME, "1.0.0");
    let (code, stdout, stderr) = run_get_bin(
        tmp.path(),
        &server.uri(),
        &[NAME, "--package", "--save-only"],
    );
    assert_eq!(
        code, 1,
        "a 500 from the package search must exit 1; stdout={stdout}\nstderr={stderr}"
    );
    assert!(
        stderr.contains(&format!("Best match: pkg:npm/{NAME}@1.0.0\n")),
        "the best-match line must print first; stderr={stderr}"
    );
    assert!(
        stderr.contains("Error:"),
        "human mode reports the fetch failure on stderr; stderr={stderr}"
    );
    assert_no_manifest(tmp.path());
    assert_eq!(
        requests_containing(&server, "/patches/by-package/").await,
        1,
        "the search endpoint must actually have been consulted"
    );
}

// ===========================================================================
// (3) download_and_apply_patches engine failure branches
// ===========================================================================

/// The agent download loop's no-applicable-files guardrail: a fetched view
/// with NO recordable files is a per-patch failure — exit 1,
/// `partial_failure` — and, since nothing was recorded, no manifest is
/// written and the `.socket/` the lock created is pruned again.
#[tokio::test]
#[serial]
async fn engine_no_applicable_files_is_failed_and_unrecorded() {
    let server = MockServer::start().await;
    mount_view_files(
        &server,
        UUID,
        PURL,
        serde_json::json!({
            "package/index.js": { "beforeHash": "e".repeat(64), "afterHash": null }
        }),
    )
    .await;

    let tmp = tempfile::tempdir().unwrap();
    let selected = vec![search_result(UUID, PURL)];
    let (code, json) =
        download_and_apply_patches(&selected, &engine_params(tmp.path()), &server.uri()).await;

    assert_eq!(code, 1, "json={json}");
    assert_eq!(json["status"], "partial_failure", "json={json}");
    assert_eq!(json["failed"], 1, "json={json}");
    assert_eq!(json["downloaded"], 0, "json={json}");
    assert_eq!(json["patches"][0]["action"], "failed", "json={json}");
    assert_eq!(
        json["patches"][0]["error"], "patch has no applicable files",
        "json={json}"
    );
    assert_no_manifest(tmp.path());
    assert!(
        !tmp.path().join(".socket").exists(),
        "a run that records nothing leaves no .socket/ behind"
    );
}

/// The agent download loop's blob-failure branch: an invalid (traversal)
/// afterHash fails the blob write — `Blob decode or write failed`, purl
/// unrecorded (no manifest), and nothing written outside `.socket/blobs`.
#[tokio::test]
#[serial]
async fn engine_invalid_blob_hash_is_failed_and_unrecorded() {
    let server = MockServer::start().await;
    mount_view_files(
        &server,
        UUID,
        PURL,
        serde_json::json!({
            "package/index.js": {
                "beforeHash": "0".repeat(64),
                "afterHash": "../covgap-escaped",
                "blobContent": "cGF0Y2hlZAo=",
            }
        }),
    )
    .await;

    let tmp = tempfile::tempdir().unwrap();
    let selected = vec![search_result(UUID, PURL)];
    let (code, json) =
        download_and_apply_patches(&selected, &engine_params(tmp.path()), &server.uri()).await;

    assert_eq!(code, 1, "json={json}");
    assert_eq!(json["failed"], 1, "json={json}");
    assert_eq!(
        json["patches"][0]["error"], "Blob decode or write failed",
        "json={json}"
    );
    assert_no_manifest(tmp.path());
    assert!(
        !tmp.path().join("covgap-escaped").exists()
            && !tmp.path().join(".socket/covgap-escaped").exists(),
        "the traversal hash must never escape the blobs dir"
    );
}

/// The agent download loop's fetch-miss branch: a 404 view is `Ok(None)` —
/// recorded as `could not fetch details`, never a panic or a silent skip.
#[tokio::test]
#[serial]
async fn engine_view_404_is_could_not_fetch_details() {
    let server = MockServer::start().await; // no view mounted -> 404
    let tmp = tempfile::tempdir().unwrap();
    let selected = vec![search_result(UUID, PURL)];
    let (code, json) =
        download_and_apply_patches(&selected, &engine_params(tmp.path()), &server.uri()).await;

    assert_eq!(code, 1, "json={json}");
    assert_eq!(json["failed"], 1, "json={json}");
    assert_eq!(
        json["patches"][0]["error"], "could not fetch details",
        "json={json}"
    );
    assert_no_manifest(tmp.path());
}

/// `.socket` occupied by a regular file: the engine's apply-lock acquire
/// (the first thing it does — the manifest RMW runs under the lock) must
/// fail before ANY fetch with an `error`-status envelope carrying the
/// stable `lock_io` code.
#[tokio::test]
#[serial]
async fn engine_socket_path_occupied_fails_before_any_fetch() {
    let server = MockServer::start().await;
    mount_view_files(&server, UUID, PURL, good_files()).await;

    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(tmp.path().join(".socket"), b"not a dir").unwrap();

    let selected = vec![search_result(UUID, PURL)];
    let (code, json) =
        download_and_apply_patches(&selected, &engine_params(tmp.path()), &server.uri()).await;

    assert_eq!(code, 1, "json={json}");
    assert_eq!(json["status"], "error", "json={json}");
    assert_eq!(json["errorCode"], "lock_io", "json={json}");
    assert!(
        json["error"]
            .as_str()
            .unwrap_or_default()
            .contains(".socket"),
        "the error must name the directory; json={json}"
    );
    assert_eq!(
        requests_containing(&server, "/patches/view/").await,
        0,
        "the engine must fail before any fetch"
    );
    assert_eq!(
        std::fs::read(tmp.path().join(".socket")).unwrap(),
        b"not a dir",
        "the squatting file must be left untouched"
    );
}

/// Read-only `.socket`: the engine cannot create its lock file, so it fails
/// closed with the `lock_io` error envelope before any fetch — nothing is
/// downloaded into a directory it could not record in.
#[cfg(unix)]
#[tokio::test]
#[serial]
async fn engine_readonly_socket_fails_closed_before_any_fetch() {
    use std::os::unix::fs::PermissionsExt;

    let server = MockServer::start().await;
    mount_view_files(&server, UUID, PURL, good_files()).await;

    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o555)).unwrap();
    if !readonly_dir_enforced(&socket) {
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o755)).unwrap();
        return;
    }

    let selected = vec![search_result(UUID, PURL)];
    let (code, json) =
        download_and_apply_patches(&selected, &engine_params(tmp.path()), &server.uri()).await;

    // A refused acquire prunes the EMPTY `.socket/` it could not lock (no
    // residue), so there is normally nothing left to restore.
    if socket.exists() {
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    assert_eq!(code, 1, "json={json}");
    assert_eq!(json["status"], "error", "json={json}");
    assert_eq!(json["errorCode"], "lock_io", "json={json}");
    assert!(
        json["error"]
            .as_str()
            .unwrap_or_default()
            .contains(".socket"),
        "the error must name the lock path; json={json}"
    );
    assert_eq!(requests_containing(&server, "/patches/view/").await, 0);
    assert!(
        !socket.exists(),
        "a refused lock leaves no empty .socket/ behind (D1: the failed acquire prunes it)"
    );
}

/// Read-only `.socket` with the lock file pre-staged (so the acquire
/// succeeds) and no blobs to write (`persist_blobs: false`): the fetched
/// record's manifest write is the first write — its failure must surface as
/// the `Failed to write manifest` envelope, with no manifest materializing.
#[cfg(unix)]
#[tokio::test]
#[serial]
async fn engine_readonly_socket_fails_manifest_write() {
    use std::os::unix::fs::PermissionsExt;

    let server = MockServer::start().await;
    mount_view_files(&server, UUID, PURL, good_files()).await;
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    prestage_lock_file(&socket);
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o555)).unwrap();
    if !readonly_dir_enforced(&socket) {
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o755)).unwrap();
        return;
    }

    let selected = vec![search_result(UUID, PURL)];
    let mut params = engine_params(tmp.path());
    params.persist_blobs = false;
    let (code, json) = download_and_apply_patches(&selected, &params, &server.uri()).await;

    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o755)).unwrap();

    assert_eq!(code, 1, "json={json}");
    assert_eq!(json["status"], "error", "json={json}");
    assert!(
        json["error"]
            .as_str()
            .unwrap_or_default()
            .contains("Failed to write manifest"),
        "the error must name the manifest write; json={json}"
    );
    assert!(
        !socket.join("manifest.json").exists(),
        "no manifest may materialize through a read-only dir"
    );
}

/// The blobs an agent-mode run wrote before its manifest write failed have
/// no record pointing at them: the engine unwinds exactly those (a
/// pre-existing blob — some other record's revert data — survives) and
/// prunes what it can. The read-only `.socket/` keeps `blobs/` itself from
/// being removed (rmdir needs write on the parent), but it must be EMPTY of
/// this run's blobs.
#[cfg(unix)]
#[tokio::test]
#[serial]
async fn engine_manifest_write_failure_unwinds_the_blobs_it_wrote() {
    use std::os::unix::fs::PermissionsExt;

    let server = MockServer::start().await;
    mount_view_files(&server, UUID, PURL, good_files()).await;
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join(".socket");
    let blobs = socket.join("blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    // A blob some other record owns: never this run's to remove.
    let foreign = blobs.join("f".repeat(64));
    std::fs::write(&foreign, b"someone else's revert data").unwrap();
    prestage_lock_file(&socket);
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o555)).unwrap();
    if !readonly_dir_enforced(&socket) {
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o755)).unwrap();
        return;
    }

    let selected = vec![search_result(UUID, PURL)];
    let params = engine_params(tmp.path());
    let (code, json) = download_and_apply_patches(&selected, &params, &server.uri()).await;

    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o755)).unwrap();

    assert_eq!(code, 1, "json={json}");
    assert!(
        json["error"]
            .as_str()
            .unwrap_or_default()
            .contains("Failed to write manifest"),
        "json={json}"
    );
    let mut left: Vec<String> = std::fs::read_dir(&blobs)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    left.sort();
    assert_eq!(
        left,
        vec!["f".repeat(64)],
        "only the pre-existing blob survives; this run's blobs are unwound"
    );
    assert_eq!(
        std::fs::read(&foreign).unwrap(),
        b"someone else's revert data",
        "a blob this run did not create is never touched"
    );
}

/// Release-narrowing warnings must ride the agent envelope: two qualified
/// PyPI variants of an UNINSTALLED base are both kept (the keep-all
/// fallback) and the `warnings` key explains why.
#[tokio::test]
#[serial]
async fn engine_uninstalled_variant_base_keeps_all_with_warning() {
    let server = MockServer::start().await; // views 404 -> both fail
    let tmp = tempfile::tempdir().unwrap();
    let base = "pkg:pypi/covgap-sixish@1.0.0";
    let selected = vec![
        search_result(UUID, &format!("{base}?artifact_id=wheel")),
        search_result(UUID_B, &format!("{base}?artifact_id=sdist")),
    ];
    let mut params = engine_params(tmp.path());
    params.all_releases = false;
    let (code, json) = download_and_apply_patches(&selected, &params, &server.uri()).await;

    assert_eq!(code, 1, "json={json}");
    assert_eq!(json["found"], 2, "both variants must be kept; json={json}");
    assert_eq!(json["failed"], 2, "json={json}");
    let warnings = json["warnings"]
        .as_array()
        .unwrap_or_else(|| panic!("keep-all fallback must surface warnings; json={json}"));
    assert!(
        warnings.iter().any(|w| w
            .as_str()
            .unwrap_or_default()
            .contains("not installed locally")),
        "json={json}"
    );
}

/// Human-mode engine run: a same-uuid `[skip]` plus a failed fetch must
/// print the skip line and the `Failed:` summary while the envelope keeps
/// the exact counts (`skipped:1, failed:1, partial_failure`).
#[tokio::test]
#[serial]
async fn engine_human_mode_skip_and_failed_summary() {
    let server = MockServer::start().await;
    mount_view_files(&server, UUID, PURL, good_files()).await;
    // UUID_V2's view stays unmounted -> 404 -> failed.

    let tmp = tempfile::tempdir().unwrap();
    seed_manifest_with(tmp.path(), PURL, UUID);

    let selected = vec![search_result(UUID, PURL), search_result(UUID_V2, PURL_V2)];
    let mut params = engine_params(tmp.path());
    params.json = false;
    params.silent = false;
    let (code, json) = download_and_apply_patches(&selected, &params, &server.uri()).await;

    assert_eq!(code, 1, "json={json}");
    assert_eq!(json["status"], "partial_failure", "json={json}");
    assert_eq!(
        json["skipped"], 1,
        "same-uuid entry is skipped; json={json}"
    );
    assert_eq!(json["failed"], 1, "json={json}");
    assert_eq!(json["downloaded"], 0, "json={json}");
    // The skipped purl's record is untouched.
    assert_eq!(manifest_json(tmp.path())["patches"][PURL]["uuid"], UUID);
    assert!(manifest_json(tmp.path())["patches"][PURL_V2].is_null());
}

// ===========================================================================
// (4) release-variant narrowing fallbacks (fabricated PyPI venv)
// ===========================================================================

/// Fabricate a crawler-visible PyPI install without python: a `.venv`
/// site-packages with a `<name>-<version>.dist-info/METADATA` and the
/// package's single module file. Returns the module file path.
///
/// The crawler probes a platform-specific venv layout
/// (`find_site_packages_under`): `.venv/Lib/site-packages` on Windows,
/// `.venv/lib/python3.*/site-packages` elsewhere — stage whichever this
/// runner will actually look in, or the package is "not installed" and the
/// variant narrowing under test never runs.
fn fake_pypi_venv(root: &Path, name: &str, version: &str, file_bytes: &[u8]) -> PathBuf {
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

/// Installed base, but NO variant's beforeHash matches the on-disk file:
/// the narrowing must fall back to keeping ALL variants (with the
/// "No release variant" warning) rather than silently dropping the package.
/// Human mode (json:false, silent:false) so the `[note]` loop executes.
#[tokio::test]
#[serial]
async fn engine_variant_no_hash_match_keeps_all_variants_with_note() {
    let _env = EnvVarGuard::scrub(&["VIRTUAL_ENV"]);
    let server = MockServer::start().await;
    let tmp = tempfile::tempdir().unwrap();
    fake_pypi_venv(tmp.path(), "covgapsix", "1.0.0", b"real on-disk content\n");

    let base = "pkg:pypi/covgapsix@1.0.0";
    let purl_wheel = format!("{base}?artifact_id=wheel");
    let purl_sdist = format!("{base}?artifact_id=sdist");

    // Both variants describe a DIFFERENT distribution's bytes.
    let other_before = b"some other distribution\n".as_slice();
    let other_after = b"some other distribution patched\n".as_slice();
    let mismatch_files = serde_json::json!({
        "covgapsix.py": {
            "beforeHash": git_hash(other_before),
            "afterHash": git_hash(other_after),
            "blobContent": b64(other_after),
        }
    });
    mount_view_files(&server, UUID, &purl_wheel, mismatch_files.clone()).await;
    mount_view_files(&server, UUID_B, &purl_sdist, mismatch_files).await;

    let selected = vec![
        search_result(UUID, &purl_wheel),
        search_result(UUID_B, &purl_sdist),
    ];
    let mut params = engine_params(tmp.path());
    params.all_releases = false;
    params.json = false;
    params.silent = false;
    let (code, json) = download_and_apply_patches(&selected, &params, &server.uri()).await;

    assert_eq!(
        code, 0,
        "keep-all downloads must still succeed; json={json}"
    );
    assert_eq!(json["found"], 2, "json={json}");
    assert_eq!(json["downloaded"], 2, "json={json}");
    let warnings = json["warnings"]
        .as_array()
        .unwrap_or_else(|| panic!("no-match fallback must warn; json={json}"));
    assert!(
        warnings.iter().any(|w| w
            .as_str()
            .unwrap_or_default()
            .contains("No release variant")),
        "json={json}"
    );
    // Keep-all is observable in the manifest: BOTH qualified purls recorded.
    let manifest = manifest_json(tmp.path());
    assert!(manifest["patches"][&purl_wheel].is_object(), "{manifest}");
    assert!(manifest["patches"][&purl_sdist].is_object(), "{manifest}");
}

/// A variant whose view FETCH fails during narrowing gets an empty candidate
/// map — a vacuous match — so it is KEPT for the main loop to record the
/// failure (the documented keep-the-variant contract), while a hash-mismatch
/// sibling is dropped.
#[tokio::test]
#[serial]
async fn engine_variant_view_fetch_error_keeps_errored_variant() {
    let _env = EnvVarGuard::scrub(&["VIRTUAL_ENV"]);
    let server = MockServer::start().await;
    let tmp = tempfile::tempdir().unwrap();
    fake_pypi_venv(tmp.path(), "covgapsix", "1.0.0", b"real on-disk content\n");

    let base = "pkg:pypi/covgapsix@1.0.0";
    let purl_erroring = format!("{base}?artifact_id=wheel");
    let purl_mismatch = format!("{base}?artifact_id=sdist");

    // The erroring variant's view 500s (both in narrowing and in the loop).
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
        .mount(&server)
        .await;
    // The sibling fetches fine but mismatches the installed file.
    let other = b"different distribution\n".as_slice();
    mount_view_files(
        &server,
        UUID_B,
        &purl_mismatch,
        serde_json::json!({
            "covgapsix.py": {
                "beforeHash": git_hash(other),
                "afterHash": git_hash(b"different distribution patched\n"),
                "blobContent": b64(b"different distribution patched\n"),
            }
        }),
    )
    .await;

    let selected = vec![
        search_result(UUID, &purl_erroring),
        search_result(UUID_B, &purl_mismatch),
    ];
    let mut params = engine_params(tmp.path());
    params.all_releases = false;
    let (code, json) = download_and_apply_patches(&selected, &params, &server.uri()).await;

    assert_eq!(
        code, 1,
        "the kept variant's failure must surface; json={json}"
    );
    assert_eq!(
        json["found"], 1,
        "only the fetch-error variant may be kept (vacuous match); json={json}"
    );
    assert_eq!(json["failed"], 1, "json={json}");
    assert_eq!(
        json["patches"][0]["purl"], purl_erroring,
        "the KEPT variant must be the one whose view errored; json={json}"
    );
    // The mismatching sibling was narrowed out entirely.
    assert!(
        !json["patches"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["purl"] == purl_mismatch.as_str()),
        "json={json}"
    );
    // Neither variant was recorded: the only kept one failed, so no
    // manifest is written at all.
    assert_no_manifest(tmp.path());
}

// ===========================================================================
// (5) search-path --mode vendored flow (in-process disk-state parity)
// ===========================================================================

fn vendored_args(identifier: &str, cwd: &Path, api_url: String) -> GetArgs {
    let mut args = default_args(identifier, cwd);
    args.common.api_url = Some(api_url);
    args.common.vendor_source = "build".to_string();
    args.save_only = false;
    args.mode = Some(ScanMode::Vendored);
    args
}

/// `get <GHSA> --mode vendored` (search path): scan's vendored posture end
/// to end. The narrowed fan-out's installed version is recorded as a
/// detached ledger entry (vendored mode is manifest-free), the artifact
/// committed, the lock rewired — and NO manifest, NO blobs (content stays in
/// memory).
#[tokio::test]
#[serial]
async fn get_ghsa_vendored_search_commits_artifact_and_wires_lock() {
    let server = MockServer::start().await;
    mount_ghsa_fanout(&server).await;
    mount_real_view(&server, UUID, PURL).await;

    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());

    let code = run(vendored_args(GHSA, tmp.path(), server.uri())).await;
    assert_eq!(code, 0, "search-path vendored get should succeed");

    assert_vendored_detached(tmp.path(), PURL, UUID);
    let state = vendor_state(tmp.path());
    assert!(
        state["entries"][PURL_V2].is_null(),
        "the uninstalled version must be narrowed out; state={state}"
    );
    let artifact = tmp
        .path()
        .join(".socket/vendor/npm")
        .join(UUID)
        .join(format!("{NAME}-1.0.0.tgz"));
    assert!(
        artifact.is_file(),
        "the patched artifact must be committed at {}",
        artifact.display()
    );
    let lock = std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap();
    assert!(
        lock.contains(".socket/vendor/npm/"),
        "the lock must be rewired to the vendored artifact; got:\n{lock}"
    );
}

/// The search-path vendored dry-run: classification preview only — exit 0,
/// no download, no `.socket`, lock untouched.
#[tokio::test]
#[serial]
async fn get_ghsa_vendored_search_dry_run_writes_nothing() {
    let server = MockServer::start().await;
    mount_ghsa_fanout(&server).await;
    mount_real_view(&server, UUID, PURL).await;

    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    let lock_before = std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap();

    let mut args = vendored_args(GHSA, tmp.path(), server.uri());
    args.common.dry_run = true;
    let code = run(args).await;
    assert_eq!(code, 0);

    assert!(!tmp.path().join(".socket").exists(), "no .socket writes");
    assert_eq!(
        lock_before,
        std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap(),
        "dry-run must not touch the lock"
    );
    assert_eq!(
        requests_containing(&server, "/patches/view/").await,
        0,
        "a dry-run must not download patch views"
    );
}

/// `get <uuid> --mode vendored --json` flags for `uuid`.
fn vendored_json_args(uuid: &str) -> [&str; 6] {
    [
        uuid,
        "--mode",
        "vendored",
        "--vendor-source",
        "build",
        "--json",
    ]
}

/// `get <uuid> --mode vendored --json` over a purl the ledger already
/// vendors at a DIFFERENT uuid (an earlier vendored get): the envelope's
/// record is `downloaded` with `oldUuid` naming the superseded entry —
/// derived from the ledger, vendored mode having no manifest — and the
/// ledger converges on the new uuid (subprocess: the envelope is the
/// contract).
#[tokio::test]
async fn get_uuid_vendored_superseding_action_carries_old_uuid() {
    let server = MockServer::start().await;
    mount_real_view(&server, UUID_B, PURL).await;
    mount_real_view(&server, UUID, PURL).await;

    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());

    let (code, stdout, stderr) =
        run_get_bin(tmp.path(), &server.uri(), &vendored_json_args(UUID_B));
    assert_eq!(code, 0, "first vendoring: stdout={stdout}\nstderr={stderr}");
    assert_vendored_detached(tmp.path(), PURL, UUID_B);

    let (code, stdout, stderr) = run_get_bin(tmp.path(), &server.uri(), &vendored_json_args(UUID));
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    let v = parse_single_json_doc(&stdout);
    assert_eq!(v["status"], "success", "stdout={stdout}");
    assert_eq!(v["downloaded"], 1, "stdout={stdout}");
    assert_eq!(v["skipped"], 0, "stdout={stdout}");
    assert_eq!(v["detached"], true, "stdout={stdout}");
    assert_eq!(v["patches"][0]["action"], "downloaded", "stdout={stdout}");
    assert_eq!(v["patches"][0]["oldUuid"], UUID_B, "stdout={stdout}");
    assert!(v["vendor"].is_object(), "stdout={stdout}");
    assert_vendored_detached(tmp.path(), PURL, UUID);
}

/// Human vendored-uuid dry-run line (the same count flavor as the search
/// path — both identifier kinds share one preview).
#[tokio::test]
async fn human_vendored_uuid_dry_run_prints_line() {
    let server = MockServer::start().await;
    mount_real_view(&server, UUID, PURL).await;

    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());

    let (code, stdout, stderr) = run_get_bin(
        tmp.path(),
        &server.uri(),
        &[UUID, "--mode", "vendored", "--dry-run"],
    );
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    assert!(
        stdout.contains("[dry-run] Would download and vendor 1 patch. No changes made."),
        "stdout={stdout}"
    );
    assert!(!tmp.path().join(".socket").exists());
}

/// Human search-path vendored dry-run line (the pluralized count flavor).
#[tokio::test]
async fn human_vendored_search_dry_run_prints_count() {
    let server = MockServer::start().await;
    mount_ghsa_fanout(&server).await;
    mount_real_view(&server, UUID, PURL).await;

    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());

    let (code, stdout, stderr) = run_get_bin(
        tmp.path(),
        &server.uri(),
        &[GHSA, "--mode", "vendored", "--dry-run"],
    );
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    assert!(
        stdout.contains("[dry-run] Would download and vendor 1 patch. No changes made."),
        "the narrowed selection is exactly one patch; stdout={stdout}"
    );
    assert!(!tmp.path().join(".socket").exists());
}

// ===========================================================================
// (6) vendor-step error arms (uuid + search paths)
// ===========================================================================

/// Legacy on-disk state a vendored get must leave ALONE: an agent-mode
/// manifest record and a non-detached ledger entry the selection never
/// names. Vendored mode is manifest-free — its vendor step verifies exactly
/// the records the download phase fetched and never reconciles the ledger
/// against a manifest — so neither may change, even when the run fails.
const OTHER_UUID: &str = "44444444-4444-4444-8444-444444444444";
const OTHER_PURL: &str = "pkg:npm/left-pad@1.3.0";
const UNSELECTED_UUID: &str = "55555555-5555-4555-8555-555555555555";
const UNSELECTED_PURL: &str = "pkg:npm/gone@9.9.9";

/// Seed the legacy state; returns the exact manifest and ledger bytes for
/// the byte-identical checks after the run.
fn seed_legacy_state(root: &Path) -> (String, String) {
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

fn assert_legacy_state_untouched(root: &Path, manifest_before: &str, state_before: &str) {
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

fn assert_vendor_error_envelope(v: &serde_json::Value) {
    assert_eq!(v["status"], "error", "envelope={v}");
    assert_eq!(
        v["error"]["code"], "no_local_source",
        "the staging refusal must be the error code; envelope={v}"
    );
    assert_eq!(
        v["vendor"]["status"], "partialFailure",
        "the carried envelope's status must be demoted; envelope={v}"
    );
    let events = v["vendor"]["events"]
        .as_array()
        .unwrap_or_else(|| panic!("the carried envelope must have events[]; envelope={v}"));
    assert!(
        !events.iter().any(|e| e["purl"] == UNSELECTED_PURL),
        "the detached vendor step must not reconcile (revert) unselected ledger entries; envelope={v}"
    );
    // The download half reports the record it fetched before the abort.
    assert_eq!(v["patches"][0]["action"], "downloaded", "envelope={v}");
    assert_eq!(v["detached"], true, "envelope={v}");
}

/// `get <uuid> --mode vendored --json` whose vendor step dies at staging:
/// exit 1, ONE JSON document with `status: error`, `error.code`, the
/// demoted vendor envelope carried in `result.vendor` — and the legacy
/// manifest record + unselected ledger entry byte-identical.
#[tokio::test]
async fn get_uuid_vendored_vendor_step_error_leaves_legacy_state_alone() {
    let server = MockServer::start().await;
    mount_contentless_view(&server, UUID, PURL).await;

    let tmp = tempfile::tempdir().unwrap();
    let (manifest_before, state_before) = seed_legacy_state(tmp.path());

    let (code, stdout, stderr) = run_get_bin(tmp.path(), &server.uri(), &vendored_json_args(UUID));
    assert_eq!(code, 1, "stdout={stdout}\nstderr={stderr}");
    let v = parse_single_json_doc(&stdout);
    assert_vendor_error_envelope(&v);
    assert_legacy_state_untouched(tmp.path(), &manifest_before, &state_before);
}

/// The SEARCH-path flavor of the same error arm: a GHSA-selected vendored
/// run must emit the identical single-document error envelope and leave the
/// legacy state alone. `--all-releases` keeps the uninstalled fixture
/// package out of the narrowing's way.
#[tokio::test]
async fn get_search_vendored_vendor_step_error_leaves_legacy_state_alone() {
    let server = MockServer::start().await;
    mount_ghsa_single(&server).await;
    mount_contentless_view(&server, UUID, PURL).await;

    let tmp = tempfile::tempdir().unwrap();
    let (manifest_before, state_before) = seed_legacy_state(tmp.path());

    let (code, stdout, stderr) = run_get_bin(
        tmp.path(),
        &server.uri(),
        &[
            GHSA,
            "--mode",
            "vendored",
            "--vendor-source",
            "build",
            "--all-releases",
            "--json",
        ],
    );
    assert_eq!(code, 1, "stdout={stdout}\nstderr={stderr}");
    let v = parse_single_json_doc(&stdout);
    assert_vendor_error_envelope(&v);
    assert_legacy_state_untouched(tmp.path(), &manifest_before, &state_before);
}

/// Human flavor of the vendored-uuid run over legacy state: stderr carries
/// the engine's `[fetch]` line and — the vendor step failing at staging —
/// the `Error (no_local_source)` line; nothing claims a manifest save and no
/// whole-manifest note prints (vendored mode has no manifest scope).
#[tokio::test]
async fn human_vendored_uuid_prints_fetch_and_vendor_error_without_manifest_note() {
    let server = MockServer::start().await;
    mount_contentless_view(&server, UUID, PURL).await;

    let tmp = tempfile::tempdir().unwrap();
    let (manifest_before, state_before) = seed_legacy_state(tmp.path());

    let (code, stdout, stderr) = run_get_bin(
        tmp.path(),
        &server.uri(),
        &[UUID, "--mode", "vendored", "--vendor-source", "build"],
    );
    assert_eq!(code, 1, "stdout={stdout}\nstderr={stderr}");
    assert!(
        stderr.contains(&format!("[fetch] {PURL}")),
        "the detached download phase reports the fetched record; stderr={stderr}"
    );
    assert!(
        !stdout.contains("Patch record saved to") && !stdout.contains("Added: 1"),
        "nothing is saved to a manifest in vendored mode; stdout={stdout}"
    );
    assert!(
        !stderr.contains("whole manifest"),
        "there is no whole-manifest scope to warn about; stderr={stderr}"
    );
    assert!(
        stderr.contains("Error (no_local_source):"),
        "the vendor-step error must print with its code; stderr={stderr}"
    );
    assert_legacy_state_untouched(tmp.path(), &manifest_before, &state_before);
}

// ===========================================================================
// (7) human-mode search/uuid output paths (subprocess stdout/stderr pins)
// ===========================================================================

/// Human twin of the paid-via-proxy uuid envelope test: the upgrade message.
#[tokio::test]
async fn human_uuid_paid_via_proxy_prints_upgrade_message() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/patch/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": UUID,
            "purl": "pkg:npm/paid-by-uuid@1.0.0",
            "publishedAt": "2024-01-01T00:00:00Z",
            "files": {},
            "vulnerabilities": {},
            "description": "Paid patch fetched by UUID",
            "license": "MIT",
            "tier": "paid",
        })))
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let uri = mock.uri();
    // No --api-token / --org: the scrubbed child env falls back to the
    // public proxy seeded via the legacy env var (get_invariants' recipe).
    let (code, stdout, stderr) = common::run_with_env(
        tmp.path(),
        &["get", UUID, "--save-only", "--yes", "--api-url", &uri],
        &[
            ("SOCKET_PATCH_PROXY_URL", uri.as_str()),
            ("SOCKET_TELEMETRY_DISABLED", "1"),
        ],
    );
    assert_eq!(
        code, 0,
        "paid_required is exit 0; stdout={stdout}\nstderr={stderr}"
    );
    assert!(
        stdout.contains("requires a paid subscription"),
        "stdout={stdout}"
    );
    assert!(
        stdout.contains("https://socket.dev/pricing"),
        "the upgrade pointer must print; stdout={stdout}"
    );
    assert_no_manifest(tmp.path());
}

/// Human twin of the uuid-404 test: the not-found message, exit 0.
#[tokio::test]
async fn human_uuid_not_found_prints_message() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let (code, stdout, stderr) = run_get_bin(tmp.path(), &server.uri(), &[UUID, "--save-only"]);
    assert_eq!(
        code, 0,
        "not-found is exit 0; stdout={stdout}\nstderr={stderr}"
    );
    assert!(
        stdout.contains(&format!("No patch found with UUID: {UUID}")),
        "stdout={stdout}"
    );
    assert_no_manifest(tmp.path());
}

/// Human CVE search with no results: both the search label and the
/// per-type not-found message (the `IdentifierType` Display impl's only
/// consumer) must print.
#[tokio::test]
async fn human_cve_search_empty_prints_search_label_and_not_found() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(format!(r"^/v0/orgs/{ORG}/patches/by-cve/.+$")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [],
            "canAccessPaidPatches": false,
        })))
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let (code, stdout, stderr) = run_get_bin(
        tmp.path(),
        &server.uri(),
        &["CVE-2099-40990", "--save-only"],
    );
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    // The search progress is a transient stderr status line: it never
    // lands on stdout (or in a pipe at all).
    assert!(
        !stdout.contains("Searching patches for") && !stderr.contains("Searching patches for"),
        "stdout={stdout}\nstderr={stderr}"
    );
    assert!(
        stdout.contains("No patches found for CVE: CVE-2099-40990"),
        "stdout={stdout}"
    );
}

/// Human search listing: a paid patch a free user cannot access shows
/// `[PAID] (no access)`; the accessible free patch shows `[FREE]` and its
/// vulnerability summary on the `Fixes:` line.
#[tokio::test]
async fn human_search_results_show_paid_access_and_fixes_lines() {
    let server = MockServer::start().await;
    let cve = "CVE-2024-4242";
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/by-cve/{cve}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [
                {
                    "uuid": UUID, "purl": PURL,
                    "publishedAt": "2024-01-01T00:00:00Z",
                    "description": "free patch", "license": "MIT", "tier": "free",
                    "vulnerabilities": {
                        "GHSA-free-fix": {
                            "cves": [cve], "summary": "s",
                            "severity": "high", "description": "d"
                        }
                    }
                },
                {
                    "uuid": UUID_B, "purl": "pkg:npm/other-pkg@1.0.0",
                    "publishedAt": "2024-01-01T00:00:00Z",
                    "description": "paid patch", "license": "MIT", "tier": "paid",
                    "vulnerabilities": {}
                }
            ],
            "canAccessPaidPatches": false,
        })))
        .mount(&server)
        .await;
    mount_view_files(&server, UUID, PURL, good_files()).await;

    let tmp = tempfile::tempdir().unwrap();
    let (code, stdout, stderr) = run_get_bin(tmp.path(), &server.uri(), &[cve, "--save-only"]);
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    assert!(stdout.contains("[FREE]"), "stdout={stdout}");
    assert!(
        stdout.contains("[PAID] (no access)"),
        "an inaccessible paid patch must be labeled; stdout={stdout}"
    );
    assert!(
        stdout.contains(&format!("Fixes: {cve} (high)")),
        "the vulnerability summary must print; stdout={stdout}"
    );
    // The free patch was still fetched and saved.
    assert_eq!(manifest_json(tmp.path())["patches"][PURL]["uuid"], UUID);
}

/// Human paid-only search: the subscription message, exit 0, no download.
#[tokio::test]
async fn human_paid_only_search_prints_subscription_message() {
    let server = MockServer::start().await;
    let cve = "CVE-2024-9999";
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/by-cve/{cve}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [{
                "uuid": UUID_B, "purl": "pkg:npm/paid-only@1.0.0",
                "publishedAt": "2024-01-01T00:00:00Z",
                "description": "paid", "license": "MIT", "tier": "paid",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    let (code, stdout, stderr) = run_get_bin(tmp.path(), &server.uri(), &[cve, "--save-only"]);
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    assert!(
        stdout.contains("All available patches require a paid subscription."),
        "stdout={stdout}"
    );
    assert!(
        stdout.contains("https://socket.dev/pricing"),
        "stdout={stdout}"
    );
    assert_no_manifest(tmp.path());
    assert_eq!(
        requests_containing(&server, "/patches/view/").await,
        0,
        "a paywalled patch must never be downloaded"
    );
}

/// Human twin of the vendored-uuid-drift warning (the json flavor is pinned
/// by get_edge_cases_e2e): the `[note]` goes to stderr.
#[tokio::test]
async fn human_vendored_drift_note_prints_on_stderr() {
    let server = MockServer::start().await;
    let purl = "pkg:npm/vendored-drift@1.0.0";
    mount_view_files(&server, UUID_B, purl, good_files()).await;

    let tmp = tempfile::tempdir().unwrap();
    // The vendor ledger wires the purl at UUID (an older patch).
    let vendor_dir = tmp.path().join(".socket/vendor");
    std::fs::create_dir_all(&vendor_dir).unwrap();
    std::fs::write(
        vendor_dir.join("state.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "version": 1,
            "entries": { purl: {
                "ecosystem": "npm",
                "basePurl": purl,
                "uuid": UUID,
                "artifact": {
                    "path": format!(".socket/vendor/npm/{UUID}/vendored-drift-1.0.0.tgz"),
                },
                "wiring": []
            }}
        }))
        .unwrap(),
    )
    .unwrap();

    let (code, stdout, stderr) =
        run_get_bin(tmp.path(), &server.uri(), &[UUID_B, "--id", "--save-only"]);
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    assert!(
        stderr.contains("[note]") && stderr.contains("is vendored at patch"),
        "the drift note must print on stderr in human mode; stderr={stderr}"
    );
    assert!(
        stderr.contains("socket-patch vendor"),
        "the note must point at the remedy; stderr={stderr}"
    );
}

/// Human twin of the all-uninstalled narrowing envelope: the plain
/// (non-PnP) message with the --all-releases advice.
#[tokio::test]
async fn human_ghsa_all_uninstalled_advises_all_releases() {
    let server = MockServer::start().await;
    mount_ghsa_fanout(&server).await;

    // Empty project: neither found version installed.
    let tmp = tempfile::tempdir().unwrap();
    let (code, stdout, stderr) = run_get_bin(tmp.path(), &server.uri(), &[GHSA]);
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    assert!(
        stdout.contains("none of them are installed here")
            && stdout.contains("Use --all-releases to fetch them anyway."),
        "stdout={stdout}"
    );
    // The terminal message already says it: no per-version [skip] flood
    // unless --verbose asks for the detail.
    assert!(
        !stderr.contains("[skip]"),
        "per-version [skip] lines are verbose-only; stderr={stderr}"
    );
    let (code, _stdout, stderr) = run_get_bin(tmp.path(), &server.uri(), &[GHSA, "--verbose"]);
    assert_eq!(code, 0, "stderr={stderr}");
    assert!(
        stderr.contains("(version not installed)"),
        "--verbose prints the per-version [skip] lines; stderr={stderr}"
    );
    assert!(!tmp.path().join(".socket").exists());
}

// ===========================================================================
// (8) final coverage mop-up (2026-09): human/silent twins, the vendored
//     search path's manifest independence and partial-failure arm,
//     lock-held vendor-step errors, and the detached vendor step's
//     hands-off posture toward unselected ledger entries.
// ===========================================================================

/// `by-ghsa/{GHSA}` returning exactly the one project-fixture patch.
async fn mount_ghsa_single(server: &MockServer) {
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

/// Human-mode (json=false) engine run with `--silent`: the
/// no-applicable-files failure is an ERROR, exempt from --silent — the
/// envelope still degrades to partial_failure and the purl stays
/// unrecorded, exactly like the --json flavor.
#[tokio::test]
#[serial]
async fn engine_human_silent_no_applicable_files_still_fails() {
    let server = MockServer::start().await;
    mount_view_files(
        &server,
        UUID,
        PURL,
        serde_json::json!({
            "package/index.js": { "beforeHash": "e".repeat(64), "afterHash": null }
        }),
    )
    .await;

    let tmp = tempfile::tempdir().unwrap();
    let selected = vec![search_result(UUID, PURL)];
    let mut params = engine_params(tmp.path());
    params.json = false;
    params.silent = true;
    let (code, json) = download_and_apply_patches(&selected, &params, &server.uri()).await;

    assert_eq!(code, 1, "json={json}");
    assert_eq!(json["status"], "partial_failure", "json={json}");
    assert_eq!(json["failed"], 1, "json={json}");
    assert_no_manifest(tmp.path());
}

/// Human-mode (json=false) twin of the manifest-write-failure envelope: the
/// error goes to stderr instead of stdout, and the returned envelope still
/// carries `status: error` for the caller's early-return guard.
#[cfg(unix)]
#[tokio::test]
#[serial]
async fn engine_human_readonly_socket_manifest_write_failure_still_errors() {
    use std::os::unix::fs::PermissionsExt;

    let server = MockServer::start().await;
    mount_view_files(&server, UUID, PURL, good_files()).await;
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    prestage_lock_file(&socket);
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o555)).unwrap();
    if !readonly_dir_enforced(&socket) {
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o755)).unwrap();
        return;
    }

    let selected = vec![search_result(UUID, PURL)];
    let mut params = engine_params(tmp.path());
    params.persist_blobs = false;
    params.json = false;
    params.silent = true;
    let (code, json) = download_and_apply_patches(&selected, &params, &server.uri()).await;

    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o755)).unwrap();

    assert_eq!(code, 1, "json={json}");
    assert_eq!(json["status"], "error", "json={json}");
    assert!(
        json["error"]
            .as_str()
            .unwrap_or_default()
            .contains("Failed to write manifest"),
        "json={json}"
    );
    assert!(!socket.join("manifest.json").exists());
}

/// `--silent` twin of the all-uninstalled narrowing terminal: a clean
/// no-op run must print NOTHING — no advise message on stdout, no per-
/// version `[skip]` lines on stderr — while still exiting 0.
#[tokio::test]
async fn silent_ghsa_all_uninstalled_prints_nothing() {
    let server = MockServer::start().await;
    mount_ghsa_fanout(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    let (code, stdout, stderr) = run_get_bin(tmp.path(), &server.uri(), &[GHSA, "--silent"]);
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    assert!(
        stdout.trim().is_empty(),
        "--silent must mute the advise message; stdout={stdout}"
    );
    assert!(
        !stderr.contains("[skip]") && !stderr.contains("installed here"),
        "--silent must mute the per-version skip lines; stderr={stderr}"
    );
    assert!(!tmp.path().join(".socket").exists());
}

/// The human search listing's `Fixes:` line falls back to the advisory id
/// when the vulnerability has no CVE assigned yet.
#[tokio::test]
async fn human_search_fixes_line_falls_back_to_advisory_id_without_cves() {
    let server = MockServer::start().await;
    let cve = "CVE-2024-31337";
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/by-cve/{cve}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [{
                "uuid": UUID, "purl": PURL,
                "publishedAt": "2024-01-01T00:00:00Z",
                "description": "no cve assigned yet", "license": "MIT", "tier": "free",
                "vulnerabilities": {
                    "GHSA-nocv-1111-2222": {
                        "cves": [], "summary": "s",
                        "severity": "high", "description": "d"
                    }
                }
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(&server)
        .await;

    // Empty project + --all-releases (no installed-version narrowing, so
    // the listing — the surface under test — prints) + --dry-run (stop
    // at the preview: no view fetch, no writes).
    let tmp = tempfile::tempdir().unwrap();
    let (code, stdout, stderr) = run_get_bin(
        tmp.path(),
        &server.uri(),
        &[cve, "--all-releases", "--dry-run"],
    );
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    assert!(
        stdout.contains("Fixes: GHSA-nocv-1111-2222 (high)"),
        "a CVE-less advisory must be summarized by its id; stdout={stdout}"
    );
    assert!(!tmp.path().join(".socket").exists());
}

/// Human search-path vendored SUCCESS: the vendored flow commits the
/// artifact and rewires the lock in human mode too — and no whole-manifest
/// blast-radius note prints (the detached vendor step touches exactly the
/// selected records; there is no manifest scope).
#[tokio::test]
async fn human_vendored_search_success_commits_artifact_without_blast_radius_note() {
    let server = MockServer::start().await;
    mount_ghsa_fanout(&server).await;
    mount_real_view(&server, UUID, PURL).await;

    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());

    let (code, stdout, stderr) = run_get_bin(
        tmp.path(),
        &server.uri(),
        &[GHSA, "--mode", "vendored", "--vendor-source", "build"],
    );
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    let artifact = tmp
        .path()
        .join(".socket/vendor/npm")
        .join(UUID)
        .join(format!("{NAME}-1.0.0.tgz"));
    assert!(
        artifact.is_file(),
        "the artifact must be committed; stdout={stdout}\nstderr={stderr}"
    );
    let lock = std::fs::read_to_string(tmp.path().join("package-lock.json")).unwrap();
    assert!(
        lock.contains(".socket/vendor/npm/"),
        "lock must be rewired:\n{lock}"
    );
    assert!(
        !stderr.contains("whole manifest"),
        "no blast-radius note without a pre-existing manifest; stderr={stderr}"
    );
}

/// A corrupt committed `.socket/manifest.json` does not block a vendored
/// get: vendored mode never reads the manifest (the download phase records
/// in memory, the vendor step verifies from the ledger), so the run
/// succeeds — ONE JSON document — and the corrupt bytes are preserved,
/// never clobbered.
#[tokio::test]
async fn vendored_search_ignores_corrupt_manifest_and_vendors() {
    let server = MockServer::start().await;
    mount_ghsa_single(&server).await;
    mount_real_view(&server, UUID, PURL).await;

    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    std::fs::create_dir_all(tmp.path().join(".socket")).unwrap();
    std::fs::write(tmp.path().join(".socket/manifest.json"), b"{ corrupt").unwrap();

    let (code, stdout, stderr) = run_get_bin(
        tmp.path(),
        &server.uri(),
        &[
            GHSA,
            "--mode",
            "vendored",
            "--vendor-source",
            "build",
            "--all-releases",
            "--json",
        ],
    );
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    let v = parse_single_json_doc(&stdout);
    assert_eq!(v["status"], "success", "stdout={stdout}");
    assert_eq!(v["patches"][0]["action"], "downloaded", "stdout={stdout}");
    assert_eq!(v["vendor"]["summary"]["applied"], 1, "stdout={stdout}");
    assert_eq!(
        std::fs::read(tmp.path().join(".socket/manifest.json")).unwrap(),
        b"{ corrupt",
        "the corrupt manifest must be preserved, never clobbered"
    );
    let state = vendor_state(tmp.path());
    assert_eq!(state["entries"][PURL]["uuid"], UUID, "state={state}");
    assert_eq!(state["entries"][PURL]["detached"], true, "state={state}");
}

/// Search-path vendored run where one patch's download FAILS but the vendor
/// step itself succeeds: the run demotes to `partial_failure` (exit 1)
/// while the nested vendor envelope stays `success` — the download failure
/// alone must degrade the run.
#[tokio::test]
async fn vendored_search_json_download_failure_with_clean_vendor_is_partial_failure() {
    let server = MockServer::start().await;
    mount_ghsa_fanout(&server).await;
    mount_real_view(&server, UUID, PURL).await;
    // UUID_V2's view stays unmounted -> 404 -> per-patch download failure.

    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());

    let (code, stdout, stderr) = run_get_bin(
        tmp.path(),
        &server.uri(),
        &[
            GHSA,
            "--mode",
            "vendored",
            "--vendor-source",
            "build",
            "--all-releases",
            "--json",
        ],
    );
    assert_eq!(code, 1, "stdout={stdout}\nstderr={stderr}");
    let v = parse_single_json_doc(&stdout);
    assert_eq!(v["status"], "partial_failure", "stdout={stdout}");
    assert_eq!(v["failed"], 1, "stdout={stdout}");
    assert_eq!(
        v["vendor"]["status"], "success",
        "the vendor step itself was clean; stdout={stdout}"
    );
    // The successfully-downloaded patch was still vendored.
    let artifact = tmp
        .path()
        .join(".socket/vendor/npm")
        .join(UUID)
        .join(format!("{NAME}-1.0.0.tgz"));
    assert!(artifact.is_file(), "stdout={stdout}");
}

/// Vendor step dying BEFORE any reconcile (the apply lock is held by
/// another process): the error envelope carries `lock_held` and — with no
/// pre-failure vendor envelope to hand over — NO `vendor` key at all, in
/// both the uuid and search flavors; human mode prints the
/// `Error (lock_held):` line.
#[tokio::test]
async fn vendored_lock_held_vendor_step_errors_without_vendor_envelope() {
    use std::time::Duration;

    // (a) uuid path, --json: the record is fetched into memory (the
    // lock-free download phase), then the vendor step refuses on the held
    // lock.
    {
        let server = MockServer::start().await;
        mount_view_files(&server, UUID, PURL, good_files()).await;
        let tmp = tempfile::tempdir().unwrap();
        let socket = tmp.path().join(".socket");
        std::fs::create_dir_all(&socket).unwrap();
        let _lock = socket_patch_core::patch::apply_lock::acquire(&socket, Duration::ZERO).unwrap();

        let (code, stdout, stderr) =
            run_get_bin(tmp.path(), &server.uri(), &vendored_json_args(UUID));
        assert_eq!(code, 1, "stdout={stdout}\nstderr={stderr}");
        let v = parse_single_json_doc(&stdout);
        assert_eq!(v["status"], "error", "stdout={stdout}");
        assert_eq!(v["error"]["code"], "lock_held", "stdout={stdout}");
        assert!(
            v.get("vendor").is_none(),
            "no pre-failure vendor envelope exists to carry; stdout={stdout}"
        );
        assert_eq!(
            v["patches"][0]["action"], "downloaded",
            "the download phase preceded the refusal; stdout={stdout}"
        );
        assert_no_manifest(tmp.path());
    }

    // (b) search path, --json: same refusal after the download phase.
    {
        let server = MockServer::start().await;
        mount_ghsa_single(&server).await;
        mount_view_files(&server, UUID, PURL, good_files()).await;
        let tmp = tempfile::tempdir().unwrap();
        let socket = tmp.path().join(".socket");
        std::fs::create_dir_all(&socket).unwrap();
        let _lock = socket_patch_core::patch::apply_lock::acquire(&socket, Duration::ZERO).unwrap();

        let (code, stdout, stderr) = run_get_bin(
            tmp.path(),
            &server.uri(),
            &[
                GHSA,
                "--mode",
                "vendored",
                "--vendor-source",
                "build",
                "--all-releases",
                "--json",
            ],
        );
        assert_eq!(code, 1, "stdout={stdout}\nstderr={stderr}");
        let v = parse_single_json_doc(&stdout);
        assert_eq!(v["status"], "error", "stdout={stdout}");
        assert_eq!(v["error"]["code"], "lock_held", "stdout={stdout}");
        assert!(v.get("vendor").is_none(), "stdout={stdout}");
    }

    // (c) search path, human: the `Error (lock_held):` stderr line.
    {
        let server = MockServer::start().await;
        mount_ghsa_single(&server).await;
        mount_view_files(&server, UUID, PURL, good_files()).await;
        let tmp = tempfile::tempdir().unwrap();
        let socket = tmp.path().join(".socket");
        std::fs::create_dir_all(&socket).unwrap();
        let _lock = socket_patch_core::patch::apply_lock::acquire(&socket, Duration::ZERO).unwrap();

        let (code, stdout, stderr) = run_get_bin(
            tmp.path(),
            &server.uri(),
            &[
                GHSA,
                "--mode",
                "vendored",
                "--vendor-source",
                "build",
                "--all-releases",
            ],
        );
        assert_eq!(code, 1, "stdout={stdout}\nstderr={stderr}");
        // The shared vendor-step formatter: capitalized, period-terminated,
        // plus the same wait hint every other lock error carries.
        let line = stderr
            .lines()
            .position(|l| l.starts_with("Error (lock_held): "))
            .unwrap_or_else(|| panic!("no coded vendor-step error; stderr={stderr}"));
        let lines: Vec<&str> = stderr.lines().collect();
        assert_eq!(
            lines[line],
            "Error (lock_held): Another socket-patch process is operating in this directory.",
            "stderr={stderr}"
        );
        assert_eq!(
            lines.get(line + 1).copied(),
            Some("  Wait for it to finish, or retry with --lock-timeout <secs> to wait for the lock."),
            "stderr={stderr}"
        );
    }
}

/// The hosted reference endpoint granting `uuid` for `purl` at `url` (the
/// `covgap_commands_scan_hosted` fixture shape).
async fn mount_granted_reference(server: &MockServer, uuid: &str, purl: &str, url: &str) {
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

/// Hosted twin of `vendored_lock_held_vendor_step_errors_without_vendor_envelope`
/// (and of `covgap_commands_scan_hosted::hosted_lock_held_refuses_before_any_write`):
/// `get <uuid> --mode hosted` folds its result into the HOSTED error
/// envelope, so a held apply lock surfaces as the top-level `errorCode`
/// with a string `error` — NOT the vendored `error: {code, message}`
/// object — exit 1, `redirect.mode` retained, nothing written; the human
/// arm prints the shared `Error: Another socket-patch process …` line plus
/// the `--lock-timeout` hint. A
/// `--dry-run` never contends: it previews the redirect under the held
/// lock and exits 0.
#[tokio::test]
async fn hosted_lock_held_get_errors_with_top_level_error_code() {
    use std::time::Duration;

    const HOSTED_URL: &str = "http://patch.test/patch/npm/covgap-pkg/1.0.0/22222222-2222-4222-8222-222222222222/11111111-1111-4111-8111-111111111111/covgap-pkg-1.0.0.tgz";
    const HELD: &str = "another socket-patch process is operating in this directory";

    let server = MockServer::start().await;
    mount_view_files(&server, UUID, PURL, good_files()).await;
    mount_granted_reference(&server, UUID, PURL, HOSTED_URL).await;
    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    let lock_before = std::fs::read(tmp.path().join("package-lock.json")).unwrap();
    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    let _lock = socket_patch_core::patch::apply_lock::acquire(&socket, Duration::ZERO).unwrap();

    // Wet --json: get's envelope fold keeps the hosted shape.
    let (code, stdout, stderr) = run_get_bin(
        tmp.path(),
        &server.uri(),
        &[UUID, "--mode", "hosted", "--json"],
    );
    assert_eq!(code, 1, "stdout={stdout}\nstderr={stderr}");
    let v = parse_single_json_doc(&stdout);
    assert_eq!(v["status"], "error", "stdout={stdout}");
    assert_eq!(v["errorCode"], "lock_held", "stdout={stdout}");
    assert_eq!(
        v["error"], HELD,
        "the hosted envelope carries a string `error`, not the vendored object; stdout={stdout}"
    );
    assert!(
        v["error"].get("code").is_none(),
        "no nested `error.code` on the hosted shape; stdout={stdout}"
    );
    assert_eq!(
        v["redirect"]["mode"], "hosted",
        "the hosted error envelope keeps its redirect block; stdout={stdout}"
    );

    // Wet human: the shared lock error line and the wait hint.
    let (code, stdout, stderr) =
        run_get_bin(tmp.path(), &server.uri(), &[UUID, "--mode", "hosted"]);
    assert_eq!(code, 1, "stdout={stdout}\nstderr={stderr}");
    assert!(
        stderr.contains("Error: Another socket-patch process is operating in this directory\n"),
        "stderr={stderr}"
    );
    assert!(
        stderr.contains("--lock-timeout"),
        "the wait hint must accompany a live holder; stderr={stderr}"
    );

    // --dry-run under the held lock: a preview never locks, so it previews
    // the redirect instead of contending.
    let (code, stdout, stderr) = run_get_bin(
        tmp.path(),
        &server.uri(),
        &[UUID, "--mode", "hosted", "--json", "--dry-run"],
    );
    assert_eq!(
        code, 0,
        "a dry run never contends; stdout={stdout}\nstderr={stderr}"
    );
    let v = parse_single_json_doc(&stdout);
    assert_eq!(v["status"], "success", "stdout={stdout}");
    assert_eq!(v["redirect"]["dryRun"], true, "stdout={stdout}");
    assert_eq!(v["redirect"]["redirected"], 1, "stdout={stdout}");

    assert_eq!(
        std::fs::read(tmp.path().join("package-lock.json")).unwrap(),
        lock_before,
        "none of the runs may touch the lockfile"
    );
    assert!(!tmp
        .path()
        .join(".socket/vendor/redirect-state.json")
        .exists());
    assert_no_manifest(tmp.path());
}

/// Human vendored-uuid over a purl the ledger already vendors at a
/// DIFFERENT uuid: the engine's `[fetch] … (replacing …)` line names the
/// superseded short uuid (ledger-derived — there is no manifest), then a
/// clean vendor step — exit 0 with the artifact committed at the new uuid.
#[tokio::test]
async fn human_vendored_uuid_supersede_prints_replacing_and_vendors() {
    let server = MockServer::start().await;
    mount_real_view(&server, UUID_B, PURL).await;
    mount_real_view(&server, UUID, PURL).await;

    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    let (code, stdout, stderr) =
        run_get_bin(tmp.path(), &server.uri(), &vendored_json_args(UUID_B));
    assert_eq!(code, 0, "first vendoring: stdout={stdout}\nstderr={stderr}");

    let (code, stdout, stderr) = run_get_bin(
        tmp.path(),
        &server.uri(),
        &[UUID, "--mode", "vendored", "--vendor-source", "build"],
    );
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    assert!(
        stderr.contains(&format!("[fetch] {PURL} (replacing 22222222)")),
        "the fetch line must carry the short superseded uuid; stderr={stderr}"
    );
    assert!(
        !stdout.contains("Patch record saved to"),
        "nothing is saved to a manifest in vendored mode; stdout={stdout}"
    );
    assert_vendored_detached(tmp.path(), PURL, UUID);
    let artifact = tmp
        .path()
        .join(".socket/vendor/npm")
        .join(UUID)
        .join(format!("{NAME}-1.0.0.tgz"));
    assert!(artifact.is_file(), "stdout={stdout}\nstderr={stderr}");
}

/// Human vendored-uuid re-get of an ALREADY-VENDORED uuid: the download
/// phase reuses the ledger's detached record (`[skip] … (already vendored)`,
/// no manifest anywhere) and the vendor step still runs (and succeeds) over
/// it — the artifact survives.
#[tokio::test]
async fn human_vendored_uuid_rerun_prints_already_vendored_skip() {
    let server = MockServer::start().await;
    mount_real_view(&server, UUID, PURL).await;

    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    let (code, stdout, stderr) = run_get_bin(tmp.path(), &server.uri(), &vendored_json_args(UUID));
    assert_eq!(code, 0, "first vendoring: stdout={stdout}\nstderr={stderr}");

    let (code, stdout, stderr) = run_get_bin(
        tmp.path(),
        &server.uri(),
        &[UUID, "--mode", "vendored", "--vendor-source", "build"],
    );
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    assert!(
        stderr.contains(&format!("[skip] {PURL} (already vendored)")),
        "stderr={stderr}"
    );
    assert!(
        !stdout.contains("Skipped: 1 (already exists)"),
        "the manifest-vocabulary summary is gone with the manifest; stdout={stdout}"
    );
    assert_vendored_detached(tmp.path(), PURL, UUID);
    let artifact = tmp
        .path()
        .join(".socket/vendor/npm")
        .join(UUID)
        .join(format!("{NAME}-1.0.0.tgz"));
    assert!(artifact.is_file(), "stdout={stdout}\nstderr={stderr}");
}

/// A ledger entry the vendored get did not select — here one from an
/// ecosystem this build cannot even revert — is left alone: the detached
/// vendor step vendors exactly the selected records and never reconciles
/// the ledger against a manifest, so the run is a clean `success` and the
/// foreign entry survives untouched beside the new one.
#[tokio::test]
async fn vendored_uuid_json_leaves_unselected_ledger_entries_alone() {
    let server = MockServer::start().await;
    mount_real_view(&server, UUID, PURL).await;

    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    let foreign_purl = "pkg:covgapeco/gone@1.0.0";
    let vendor = tmp.path().join(".socket/vendor");
    std::fs::create_dir_all(&vendor).unwrap();
    std::fs::write(
        vendor.join("state.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "version": 1,
            "entries": { foreign_purl: {
                "ecosystem": "covgapeco",
                "basePurl": foreign_purl,
                "uuid": UNSELECTED_UUID,
                "artifact": {
                    "path": format!(".socket/vendor/covgapeco/{UNSELECTED_UUID}/gone-1.0.0.tgz"),
                },
                "wiring": []
            }}
        }))
        .unwrap(),
    )
    .unwrap();

    let (code, stdout, stderr) = run_get_bin(tmp.path(), &server.uri(), &vendored_json_args(UUID));
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    let v = parse_single_json_doc(&stdout);
    assert_eq!(v["status"], "success", "stdout={stdout}");
    assert_eq!(v["vendor"]["status"], "success", "stdout={stdout}");
    let events = v["vendor"]["events"]
        .as_array()
        .unwrap_or_else(|| panic!("vendor events must be carried; stdout={stdout}"));
    assert!(
        !events.iter().any(|e| e["purl"] == foreign_purl),
        "an unselected ledger entry must not be touched or reported; stdout={stdout}"
    );
    let state = vendor_state(tmp.path());
    assert_eq!(
        state["entries"][foreign_purl]["uuid"], UNSELECTED_UUID,
        "the foreign entry must survive: {state}"
    );
    assert_vendored_detached(tmp.path(), PURL, UUID);
    let artifact = tmp
        .path()
        .join(".socket/vendor/npm")
        .join(UUID)
        .join(format!("{NAME}-1.0.0.tgz"));
    assert!(artifact.is_file(), "stdout={stdout}\nstderr={stderr}");
}

// ===========================================================================
// (9) terminal-UI polish: agent dry-run, --silent failures, forced-type
//     validation, proxy 403 → paid_required, narrowed listing.
// ===========================================================================

/// Agent-mode `--dry-run` (search path) previews and writes NOTHING: no
/// `.socket/`, no view fetch, no prompt, exit 0.
#[tokio::test]
async fn agent_search_dry_run_writes_nothing() {
    let server = MockServer::start().await;
    mount_ghsa_fanout(&server).await;
    mount_real_view(&server, UUID, PURL).await;

    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    let index_before = std::fs::read(tmp.path().join("node_modules/covgap-pkg/index.js")).unwrap();

    let (code, stdout, stderr) = run_get_bin(tmp.path(), &server.uri(), &[GHSA, "--dry-run"]);
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    assert!(
        stdout.contains(&format!("  [would-add] {PURL}\n"))
            && stdout.contains("[dry-run] Would download and apply 1 patch. No changes made."),
        "stdout={stdout}"
    );
    // The listing shows only the installed version; the other one is
    // summarized once on stderr.
    assert!(
        stdout.contains("Found 1 patch:") && !stdout.contains(PURL_V2),
        "stdout={stdout}"
    );
    assert!(
        stderr.contains(
            "Skipped 1 patch for 1 package version not installed here \
             (use --all-releases to include it)."
        ),
        "stderr={stderr}"
    );
    assert!(
        !stderr.contains("[Y/n]"),
        "a dry run never prompts; stderr={stderr}"
    );
    assert!(!tmp.path().join(".socket").exists());
    assert_eq!(
        std::fs::read(tmp.path().join("node_modules/covgap-pkg/index.js")).unwrap(),
        index_before
    );
    assert!(
        !received_paths(&server)
            .await
            .iter()
            .any(|p| p.contains("/patches/view/")),
        "a dry run must not fetch patch views"
    );
}

/// Agent-mode `--dry-run --json` (uuid path): one envelope with
/// `dryRun: true` and a `would_update` record carrying `oldUuid`; the
/// manifest bytes stay untouched.
#[tokio::test]
async fn agent_uuid_dry_run_json_classifies_against_the_manifest() {
    let server = MockServer::start().await;
    mount_real_view(&server, UUID, PURL).await;

    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    seed_manifest_with(tmp.path(), PURL, UUID_B);
    let before = std::fs::read_to_string(tmp.path().join(".socket/manifest.json")).unwrap();

    let (code, stdout, stderr) =
        run_get_bin(tmp.path(), &server.uri(), &[UUID, "--dry-run", "--json"]);
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    let v = parse_single_json_doc(&stdout);
    assert_eq!(v["status"], "success", "{v}");
    assert_eq!(v["dryRun"], true, "{v}");
    assert_eq!(v["applied"], 0, "{v}");
    assert_eq!(v["patches"][0]["action"], "would_update", "{v}");
    assert_eq!(v["patches"][0]["oldUuid"], UUID_B, "{v}");
    assert_eq!(
        before,
        std::fs::read_to_string(tmp.path().join(".socket/manifest.json")).unwrap()
    );
}

/// `--silent` is "errors only", never "nothing": a failed nested apply
/// still says why the run exits 1.
#[tokio::test]
async fn silent_apply_failure_still_prints_an_error() {
    let server = MockServer::start().await;
    // A view whose beforeHash matches nothing on disk and whose file is
    // missing: the nested apply fails.
    mount_view_files(
        &server,
        UUID,
        PURL,
        serde_json::json!({
            "package/missing.js": {
                "beforeHash": "0".repeat(64),
                "afterHash": git_hash(AFTER_BYTES),
                "blobContent": b64(AFTER_BYTES),
            }
        }),
    )
    .await;

    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    let (code, stdout, stderr) = run_get_bin(tmp.path(), &server.uri(), &[UUID, "--silent"]);
    assert_eq!(code, 1, "stdout={stdout}\nstderr={stderr}");
    assert!(stdout.is_empty(), "stdout={stdout}");
    // The per-package reason prints even under --silent, so the closing
    // line needs no "re-run without --silent" hint.
    assert!(
        stderr.contains(&format!("Error: Failed to patch {PURL}: ")),
        "stderr={stderr}"
    );
    assert!(
        stderr.ends_with("Error: Some patches could not be applied.\n"),
        "stderr={stderr}"
    );

    // --json: the envelope is the only channel; the nested apply's
    // per-package error lines stay off stderr too.
    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    let (code, stdout, stderr) = run_get_bin(tmp.path(), &server.uri(), &[UUID, "--json"]);
    assert_eq!(code, 1, "stdout={stdout}\nstderr={stderr}");
    assert!(!stderr.contains("Error"), "stderr={stderr}");
    serde_json::from_str::<serde_json::Value>(&stdout).expect("one JSON envelope");

    // Loud twin: the same closing line.
    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    let (code, _stdout, stderr) = run_get_bin(tmp.path(), &server.uri(), &[UUID]);
    assert_eq!(code, 1, "stderr={stderr}");
    assert!(
        stderr.contains("Error: Some patches could not be applied.\n"),
        "stderr={stderr}"
    );
}

/// The nested apply's `Patched packages:` block puts its leading blank
/// line on stderr: stdout gets no blank line of its own before it, and
/// never two in a row.
#[tokio::test]
async fn nested_apply_block_starts_stdout_without_a_blank_line() {
    let server = MockServer::start().await;
    mount_view_files(
        &server,
        UUID,
        PURL,
        serde_json::json!({
            "package/index.js": {
                "beforeHash": git_hash(BEFORE_BYTES),
                "afterHash": git_hash(AFTER_BYTES),
                "blobContent": b64(AFTER_BYTES),
            }
        }),
    )
    .await;
    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    let (code, stdout, stderr) = run_get_bin(tmp.path(), &server.uri(), &[UUID]);
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    assert!(
        stdout.starts_with(&format!("Patched packages:\n  {PURL}")),
        "stdout={stdout:?}"
    );
    assert!(!stdout.contains("\n\n\n"), "stdout={stdout:?}");
}

/// A forced `--id` / `--cve` / `--ghsa` identifier is shape-checked before
/// any network call: a readable error, exit 1, zero requests.
#[tokio::test]
async fn forced_identifier_type_is_validated_locally() {
    let server = MockServer::start().await;
    let tmp = tempfile::tempdir().unwrap();
    for (flag, what) in [
        ("--id", "is not a valid patch UUID"),
        ("--cve", "is not a valid CVE ID"),
        ("--ghsa", "is not a valid GHSA ID"),
    ] {
        let (code, stdout, stderr) = run_get_bin(tmp.path(), &server.uri(), &["lodash", flag]);
        assert_eq!(code, 1, "{flag}: stdout={stdout}\nstderr={stderr}");
        assert!(
            stderr.contains(&format!("Error: \"lodash\" {what} (expected ")),
            "{flag}: stderr={stderr}"
        );
        let (code, stdout, _) = run_get_bin(tmp.path(), &server.uri(), &["lodash", flag, "--json"]);
        assert_eq!(code, 1);
        let v = parse_single_json_doc(&stdout);
        assert_eq!(v["status"], "error", "{v}");
        assert!(v["error"].as_str().unwrap().contains(what), "{v}");
    }
    assert!(
        received_paths(&server).await.is_empty(),
        "no request may be sent"
    );
}

/// The public proxy answers a paid patch with 403: that is the same clean
/// `paid_required` outcome (exit 0) as a tier=paid view, not a raw
/// "Forbidden" error.
#[tokio::test]
async fn proxy_403_on_uuid_is_paid_required() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/patch/view/{UUID}")))
        .respond_with(ResponseTemplate::new(403))
        .mount(&server)
        .await;
    let uri = server.uri();
    let tmp = tempfile::tempdir().unwrap();
    let run = |extra: &[&str]| {
        let mut args = vec!["get", UUID, "--yes", "--api-url", uri.as_str()];
        args.extend_from_slice(extra);
        common::run_with_env(
            tmp.path(),
            &args,
            &[
                ("SOCKET_PATCH_PROXY_URL", uri.as_str()),
                ("SOCKET_TELEMETRY_DISABLED", "1"),
            ],
        )
    };

    let (code, stdout, stderr) = run(&["--json"]);
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    let v = parse_single_json_doc(&stdout);
    assert_eq!(v["status"], "paid_required", "{v}");
    assert_eq!(v["patches"][0]["uuid"], UUID, "{v}");
    assert_eq!(v["patches"][0]["tier"], "paid", "{v}");

    let (code, stdout, stderr) = run(&[]);
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    assert!(
        stdout.contains(&format!(
            "This patch requires a paid subscription to download.\n  Patch: {UUID}\n  \
             Upgrade at: https://socket.dev/pricing"
        )),
        "stdout={stdout}"
    );
    assert!(!stderr.contains("Forbidden"), "stderr={stderr}");
    assert!(!tmp.path().join(".socket").exists());
}

/// A free user's CVE search: a free patch for one installed package and a
/// paid patch for ANOTHER installed package. The narrowed listing must
/// still show the paid fix as `[PAID] (no access)` (an installed package's
/// fix is never silently hidden), while a paid patch for a version that is
/// not installed stays out of it. No `Selected:` block (the one free patch
/// was the only candidate), and stdout starts with the result itself.
#[tokio::test]
async fn narrowed_listing_keeps_installed_paid_no_access_patch() {
    let server = MockServer::start().await;
    let cve = "CVE-2024-5151";
    let paid = |uuid: &str, purl: &str| {
        serde_json::json!({
            "uuid": uuid, "purl": purl,
            "publishedAt": "2024-01-01T00:00:00Z",
            "description": "paid", "license": "MIT", "tier": "paid",
            "vulnerabilities": {}
        })
    };
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/by-cve/{cve}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [
                {
                    "uuid": UUID, "purl": PURL,
                    "publishedAt": "2024-01-01T00:00:00Z",
                    "description": "free", "license": "MIT", "tier": "free",
                    "vulnerabilities": {}
                },
                paid(UUID_B, "pkg:npm/covgap-paid-other@2.0.0"),
                paid(UUID_V2, "pkg:npm/covgap-paid-other@9.0.0"),
            ],
            "canAccessPaidPatches": false,
        })))
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());
    install_npm_fixture(tmp.path(), "covgap-paid-other", "2.0.0");
    let (code, stdout, stderr) = run_get_bin(tmp.path(), &server.uri(), &[cve, "--dry-run"]);
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    assert!(
        stdout.starts_with("Found 2 patches:\n"),
        "stdout must start with the listing; stdout={stdout:?}"
    );
    assert!(
        stdout.contains("pkg:npm/covgap-paid-other@2.0.0 [PAID] (no access)"),
        "stdout={stdout}"
    );
    assert!(
        !stdout.contains("covgap-paid-other@9.0.0"),
        "a paid patch for an uninstalled version must not be listed; stdout={stdout}"
    );
    assert!(!stdout.contains("Selected:"), "stdout={stdout}");
    assert!(
        stdout.contains(&format!("  [would-add] {PURL}\n")),
        "stdout={stdout}"
    );
    // The paid skip is not the user's to act on: no skip summary counts it.
    assert!(!stderr.contains("Skipped "), "stderr={stderr}");
    assert!(!tmp.path().join(".socket").exists());
}

/// Agent `--dry-run` runs the same per-release variant narrowing as the
/// wet run: of two PyPI variants of one installed version, only the one
/// matching the installed distribution is previewed.
#[tokio::test]
async fn agent_dry_run_previews_only_the_installed_release_variant() {
    let server = MockServer::start().await;
    let tmp = tempfile::tempdir().unwrap();
    let installed = b"installed wheel bytes\n".as_slice();
    fake_pypi_venv(tmp.path(), "covgapsix", "1.0.0", installed);
    let venv = tmp.path().join(".venv");

    let base = "pkg:pypi/covgapsix@1.0.0";
    let purl_wheel = format!("{base}?artifact_id=wheel");
    let purl_sdist = format!("{base}?artifact_id=sdist");
    let files_for = |before: &[u8]| {
        serde_json::json!({
            "covgapsix.py": {
                "beforeHash": git_hash(before),
                "afterHash": git_hash(b"patched\n"),
                "blobContent": b64(b"patched\n"),
            }
        })
    };
    mount_view_files(&server, UUID, &purl_wheel, files_for(installed)).await;
    mount_view_files(&server, UUID_B, &purl_sdist, files_for(b"other dist\n")).await;
    let patch = |uuid: &str, purl: &str| {
        serde_json::json!({
            "uuid": uuid, "purl": purl,
            "publishedAt": "2024-01-01T00:00:00Z",
            "description": "x", "license": "MIT", "tier": "free",
            "vulnerabilities": {}
        })
    };
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/by-ghsa/{GHSA}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "patches": [patch(UUID, &purl_wheel), patch(UUID_B, &purl_sdist)],
            "canAccessPaidPatches": false,
        })))
        .mount(&server)
        .await;

    let venv_str = venv.to_string_lossy().into_owned();
    let (code, stdout, stderr) = common::run_with_env(
        tmp.path(),
        &[
            "get",
            GHSA,
            "--dry-run",
            "--json",
            "--api-url",
            &server.uri(),
            "--api-token",
            "fake-token-for-tests",
            "--org",
            ORG,
            "--yes",
        ],
        &[
            ("SOCKET_TELEMETRY_DISABLED", "1"),
            ("VIRTUAL_ENV", venv_str.as_str()),
        ],
    );
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    let v = parse_single_json_doc(&stdout);
    assert_eq!(v["dryRun"], true, "{v}");
    let adds: Vec<&serde_json::Value> = v["patches"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|p| p["action"] == "would_add")
        .collect();
    assert_eq!(adds.len(), 1, "only the installed variant; {v}");
    assert_eq!(adds[0]["purl"], purl_wheel.as_str(), "{v}");
    assert!(!tmp.path().join(".socket").exists());
}

/// Human `get --mode vendored` whose every download fails: no record
/// reaches the vendor step, the vendor engine is quiet about an empty record
/// set, and the scan vendor step (in its `get` flavor) closes the run with
/// "No vendorable patches in scope." instead of ending with no summary.
#[tokio::test]
async fn human_vendored_search_all_downloads_failed_prints_empty_run_line() {
    let server = MockServer::start().await;
    mount_ghsa_fanout(&server).await;
    // No views mounted -> every view fetch 404s.

    let tmp = tempfile::tempdir().unwrap();
    write_project(tmp.path());

    let (code, stdout, stderr) = run_get_bin(
        tmp.path(),
        &server.uri(),
        &[
            GHSA,
            "--mode",
            "vendored",
            "--vendor-source",
            "build",
            "--all-releases",
        ],
    );
    assert_eq!(code, 1, "stdout={stdout}\nstderr={stderr}");
    assert!(
        stdout.contains("No vendorable patches in scope."),
        "stdout={stdout}\nstderr={stderr}"
    );
}
