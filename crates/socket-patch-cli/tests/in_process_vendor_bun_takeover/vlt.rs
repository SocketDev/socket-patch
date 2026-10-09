//! vlt mode takeovers (DESIGN §4.10) through the built binary:
//!
//! 1. hosted → vendored by `scan --mode vendored` and by `vendor`: the
//!    takeover restores the pristine registry node (v5: re-resolved from
//!    the registry — a wiremock mirror here — with no ledger), the vendor
//!    ledger records REGISTRY originals (never the
//!    hosted URL), the store copy vlt installed from the hosted pin is
//!    invalidated, and `vendor --revert` lands on the registry lock;
//! 2. vendored → hosted by `scan --mode hosted` and `get <uuid> --mode
//!    hosted`: the vlt revert restores node, edges and package.json before
//!    the hosted rewrite, and `rollback` (the upstream restore) lands on
//!    the registry lock;
//! 3. refusals fire BEFORE the other mode is reverted: the complete vlt
//!    vendored preflight in front of a hosted revert, and the hosted
//!    artifact preflight in front of a vendored revert.

#[path = "../prebuilt_common/mod.rs"]
mod prebuilt_common;

use std::path::Path;

use base64::Engine as _;
use serde_json::{json, Value};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::vlt_hosted_common as hosted;
use hosted::{ORG, PATCHED, PRISTINE, PURL, TILDE_ID, UUID};

/// The registry lock as vlt rc.33+ writes it: `options.registries` recorded
/// and the registry node carrying its tarball URL in slot [3]. The v5
/// upstream restore re-derives slot [3] from the lock's own convention
/// (see core `patch::redirect::upstream::vlt`), which the recorded
/// `registries` pins — so the unwinds below land on these exact bytes.
fn registry_lock() -> String {
    format!(
        "{{\n  \"lockfileVersion\": 1,\n  \"options\": {{\n    \"registries\": {{\n      \
         \"npm\": \"https://registry.npmjs.org/\"\n    }}\n  }},\n  \"nodes\": {{\n    {}\n  }},\n  \
         \"edges\": {{\n    \"file~_d left-pad\": \"prod 1.3.0 {TILDE_ID}\"\n  }}\n}}\n",
        hosted::registry_node(TILDE_ID)
    )
}

const PACKAGE_JSON: &str =
    "{\n  \"name\": \"consumer\",\n  \"dependencies\": {\n    \"left-pad\": \"1.3.0\"\n  }\n}\n";

fn write_project(root: &Path) {
    std::fs::write(root.join("vlt-lock.json"), registry_lock()).unwrap();
    std::fs::write(root.join("package.json"), PACKAGE_JSON).unwrap();
    hosted::install_importer(root, PRISTINE);
}

/// The manifest record + after-hash blob `vendor --offline` reads.
fn seed_manifest(root: &Path) {
    let socket = root.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    let mut record = hosted::view_body();
    record.as_object_mut().unwrap().remove("purl");
    record["exportedAt"] = json!("2026-01-01T00:00:00Z");
    std::fs::write(
        socket.join("manifest.json"),
        serde_json::to_vec_pretty(&json!({ "patches": { PURL: record } })).unwrap(),
    )
    .unwrap();
    std::fs::write(
        socket.join("blobs").join(hosted::git_sha256(PATCHED)),
        PATCHED,
    )
    .unwrap();
}

/// Discovery, grant, the artifact, and a view carrying the blob (the
/// vendored download phase stages it from `blobContent`).
async fn mock_api(server: &MockServer) {
    let mut view = hosted::view_body();
    view["files"]["package/index.js"]["blobContent"] =
        json!(base64::engine::general_purpose::STANDARD.encode(PATCHED));
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(view))
        .mount(server)
        .await;
    hosted::mock_discovery(server).await;
    hosted::mock_reference(server).await;
    hosted::mock_artifact(server).await;
    mock_registry(server).await;
}

/// The npm registry's version document the v5 upstream restore reads for
/// the hosted node (`SOCKET_NPM_REGISTRY` = `<server>/registry`): the
/// pristine node's integrity and tarball.
async fn mock_registry(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path(format!(
            "/registry/{}/{}",
            hosted::NAME,
            hosted::VERSION
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": hosted::NAME,
            "version": hosted::VERSION,
            "dist": { "tarball": hosted::REGISTRY_URL, "integrity": hosted::UPSTREAM_SHA512 }
        })))
        .mount(server)
        .await;
}

/// The env naming `server` the patch server (its artifact URLs are hosted
/// pins — v5 keeps no ledger to vouch for them) and its `/registry` the npm
/// registry the upstream restore reads.
fn online_env(server: &MockServer) -> [(&'static str, String); 2] {
    [
        ("SOCKET_PATCH_SERVER_URL", server.uri()),
        ("SOCKET_NPM_REGISTRY", format!("{}/registry", server.uri())),
    ]
}

fn run_online(root: &Path, argv: &[&str], server: &MockServer) -> (i32, Value, String) {
    let env = online_env(server);
    let env: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();
    hosted::run_json(root, argv, &env)
}

fn args<'a>(root: &'a str, uri: &'a str, head: &[&'a str]) -> Vec<&'a str> {
    let mut out = head.to_vec();
    out.extend([
        "--yes",
        "--cwd",
        root,
        "--api-url",
        uri,
        "--org",
        ORG,
        "--api-token",
        "fake",
    ]);
    out
}

fn scan(root: &Path, server: &MockServer, mode: &str, extra: &[&str]) -> (i32, Value, String) {
    let cwd = root.to_str().unwrap().to_string();
    let uri = server.uri();
    let mut argv = args(&cwd, &uri, &["scan", "--mode", mode]);
    argv.extend_from_slice(extra);
    run_online(root, &argv, server)
}

/// `vendor --offline`: nothing hosted to restore.
fn vendor(root: &Path, extra: &[&str]) -> (i32, Value, String) {
    let cwd = root.to_str().unwrap().to_string();
    let fixture = prebuilt_common::Server::project(root);
    let mut argv = vec!["vendor", "--cwd", &cwd];
    argv.extend_from_slice(extra);
    hosted::run_json(root, &argv, &[("SOCKET_VENDOR_URL", &fixture.uri)])
}

/// `vendor` over a hosted pin on `server`: online, the takeover's upstream
/// restore reads the registry mirror.
fn vendor_online(root: &Path, server: &MockServer, extra: &[&str]) -> (i32, Value, String) {
    let cwd = root.to_str().unwrap().to_string();
    let uri = server.uri();
    let mut argv = args(&cwd, &uri, &["vendor"]);
    argv.extend_from_slice(extra);
    run_online(root, &argv, server)
}

fn all_codes(env: &Value) -> Vec<String> {
    let mut out = Vec::new();
    fn walk(v: &Value, out: &mut Vec<String>) {
        match v {
            Value::Object(map) => {
                for (k, v) in map {
                    if (k == "errorCode" || k == "code") && v.is_string() {
                        out.push(v.as_str().unwrap().to_string());
                    }
                    walk(v, out);
                }
            }
            Value::Array(items) => items.iter().for_each(|i| walk(i, out)),
            _ => {}
        }
    }
    walk(env, &mut out);
    out
}

fn detail_of(env: &Value, code: &str) -> String {
    fn walk(v: &Value, code: &str) -> Option<String> {
        match v {
            Value::Object(map) => {
                if map
                    .get("errorCode")
                    .or(map.get("code"))
                    .and_then(Value::as_str)
                    == Some(code)
                {
                    for key in ["reason", "detail", "error", "message"] {
                        if let Some(s) = map.get(key).and_then(Value::as_str) {
                            return Some(s.to_string());
                        }
                    }
                }
                map.values().find_map(|v| walk(v, code))
            }
            Value::Array(items) => items.iter().find_map(|i| walk(i, code)),
            _ => None,
        }
    }
    walk(env, code).unwrap_or_else(|| panic!("no `{code}` in {env:#}"))
}

fn rel() -> String {
    format!(".socket/vendor/npm/{UUID}/left-pad-1.3.0/node_modules/left-pad")
}

/// v5 hosted mode keeps no ledger: none may ever appear.
fn assert_no_redirect_ledger(root: &Path) {
    assert!(
        !hosted::ledger_path(root).exists(),
        "no hosted ledger may exist"
    );
}

fn vendor_entry(root: &Path) -> Option<Value> {
    let bytes = std::fs::read(root.join(".socket/vendor/state.json")).ok()?;
    let state: Value = serde_json::from_slice(&bytes).unwrap();
    let entry = state["entries"][PURL].clone();
    (!entry.is_null()).then_some(entry)
}

/// The hosted pin, plus vlt's warm install of it: the store entry holding
/// the patched bytes and a hidden lock recording the hosted integrity.
async fn hosted_project(root: &Path, server: &MockServer) -> String {
    write_project(root);
    let (code, env, stderr) = scan(root, server, "hosted", &[]);
    assert_eq!(code, 0, "{env:#}\n{stderr}");
    assert_eq!(hosted::redirected(&env), 1, "{env:#}");
    let lock = hosted::read(root, "vlt-lock.json");
    assert!(lock.contains(&hosted::artifact_url(server)), "{lock}");
    hosted::install_store(root, TILDE_ID, PATCHED);
    hosted::write_hidden_lock(root, &[hosted::pinned_node(TILDE_ID, server)]);
    lock
}

fn assert_vendored_from_registry(root: &Path) {
    let lock = hosted::read(root, "vlt-lock.json");
    assert!(lock.contains(&rel()), "{lock}");
    assert!(
        !lock.contains("/patch/npm/"),
        "the hosted pin is gone: {lock}"
    );
    let entry = vendor_entry(root).expect("a vendor ledger entry");
    assert_eq!(entry["flavor"], "vlt", "{entry:#}");
    let node = entry["wiring"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["kind"] == "vlt_lock_node")
        .unwrap()
        .clone();
    assert_eq!(
        node["original"],
        hosted::registry_node(TILDE_ID),
        "the vendor ledger records the REGISTRY node: {node:#}"
    );
    assert_no_redirect_ledger(root);
    assert!(
        !hosted::store_dir(root, TILDE_ID).exists(),
        "the hosted store copy is invalidated"
    );
    assert!(!root.join("node_modules/.vlt-lock.json").exists());
}

fn revert_lands_on_registry(root: &Path) {
    let (code, env, stderr) = vendor(root, &["--revert"]);
    assert_eq!(code, 0, "{env:#}\n{stderr}");
    assert_eq!(hosted::read(root, "vlt-lock.json"), registry_lock());
    assert_eq!(hosted::read(root, "package.json"), PACKAGE_JSON);
    assert!(!root.join(format!(".socket/vendor/npm/{UUID}")).exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn vlt_hosted_then_scan_vendored_takeover_round_trips_to_registry() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let server = MockServer::start().await;
    mock_api(&server).await;
    hosted_project(root, &server).await;

    let (code, env, stderr) = scan(root, &server, "vendored", &[]);
    assert_eq!(code, 0, "{env:#}\n{stderr}");
    let codes = all_codes(&env);
    assert!(
        codes.contains(&"vendor_takeover_reverted_redirect".to_string()),
        "{env:#}"
    );
    assert_eq!(
        detail_of(&env, "redirect_vlt_reinstall_required"),
        "vendored 1 hosted-pinned packages; removed their hosted installed copies, so \
         node_modules is incomplete until you run `vlt install`"
    );
    assert_vendored_from_registry(root);
    assert!(!root.join(".socket/manifest.json").exists());
    revert_lands_on_registry(root);
}

#[tokio::test(flavor = "multi_thread")]
async fn vlt_vendor_dry_run_previews_the_takeover_then_wet_vendor_completes_it() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let server = MockServer::start().await;
    mock_api(&server).await;
    let hosted_lock = hosted_project(root, &server).await;
    seed_manifest(root);
    assert_no_redirect_ledger(root);

    let (code, env, stderr) = vendor_online(root, &server, &["--dry-run"]);
    assert_eq!(code, 0, "{env:#}\n{stderr}");
    let codes = all_codes(&env);
    assert!(
        codes.contains(&"vendor_would_revert_redirect".to_string()),
        "{env:#}"
    );
    assert!(
        !codes.contains(&"vendor_lock_entry_not_found".to_string()),
        "the hosted node is registry-shaped: {env:#}"
    );
    assert_eq!(hosted::read(root, "vlt-lock.json"), hosted_lock);
    assert_no_redirect_ledger(root);
    assert!(
        hosted::store_dir(root, TILDE_ID).exists(),
        "a dry run heals nothing"
    );

    let (code, env, stderr) = vendor_online(root, &server, &[]);
    assert_eq!(code, 0, "{env:#}\n{stderr}");
    assert!(
        all_codes(&env).contains(&"vendor_takeover_reverted_redirect".to_string()),
        "{env:#}"
    );
    assert_vendored_from_registry(root);
    revert_lands_on_registry(root);
}

/// A vendored project, then the hosted takeover by `driver`.
async fn vendored_then_hosted(driver: &str) {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_project(root);
    seed_manifest(root);
    let (code, env, stderr) = vendor(root, &[]);
    assert_eq!(code, 0, "{env:#}\n{stderr}");
    assert!(hosted::read(root, "vlt-lock.json").contains(&rel()));
    std::fs::remove_file(root.join(".socket/manifest.json")).unwrap();

    let server = MockServer::start().await;
    mock_api(&server).await;
    let (code, env, stderr) = if driver == "scan" {
        scan(root, &server, "hosted", &[])
    } else {
        let cwd = root.to_str().unwrap().to_string();
        let uri = server.uri();
        let argv = args(&cwd, &uri, &["get", UUID, "--mode", "hosted"]);
        run_online(root, &argv, &server)
    };
    assert_eq!(code, 0, "[{driver}] {env:#}\n{stderr}");
    let lock = hosted::read(root, "vlt-lock.json");
    assert!(
        lock.contains(&hosted::artifact_url(&server)) && !lock.contains(&rel()),
        "[{driver}] the registry node is back and pinned to the hosted artifact: {lock}"
    );
    assert!(
        lock.contains(&format!("\"file~_d left-pad\": \"prod 1.3.0 {TILDE_ID}\"")),
        "[{driver}] the importer edge is restored: {lock}"
    );
    assert_eq!(
        hosted::read(root, "package.json"),
        PACKAGE_JSON,
        "[{driver}]"
    );
    assert!(
        vendor_entry(root).is_none(),
        "[{driver}] the vendor entry is dropped"
    );
    assert!(
        !root.join(format!(".socket/vendor/npm/{UUID}")).exists(),
        "[{driver}] the vendored artifact is removed"
    );
    assert_no_redirect_ledger(root);
    // The upstream restore: online against the registry mirror, with the
    // mock origin named hosted so the pin is found.
    let cwd = root.to_str().unwrap().to_string();
    let (code, env, stderr) = run_online(root, &["rollback", "--cwd", &cwd], &server);
    assert_eq!(code, 0, "[{driver}] rollback: {env:#}\n{stderr}");
    assert_eq!(
        hosted::read(root, "vlt-lock.json"),
        registry_lock(),
        "[{driver}]"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn vlt_vendored_then_scan_hosted_takeover_round_trips_to_registry() {
    vendored_then_hosted("scan").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn vlt_vendored_then_get_hosted_takeover_round_trips_to_registry() {
    vendored_then_hosted("get").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn vlt_vendored_preflight_refuses_before_the_hosted_revert() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let server = MockServer::start().await;
    mock_api(&server).await;
    let hosted_lock = hosted_project(root, &server).await;
    seed_manifest(root);
    // Declared in two dependency fields: the vlt backend would refuse it,
    // so no driver may strip the live hosted pin on its behalf.
    let pkg = "{\n  \"dependencies\": {\n    \"left-pad\": \"1.3.0\"\n  },\n  \"devDependencies\": {\n    \"left-pad\": \"1.3.0\"\n  }\n}\n";
    std::fs::write(root.join("package.json"), pkg).unwrap();
    let assert_intact = |what: &str| {
        assert_eq!(hosted::read(root, "vlt-lock.json"), hosted_lock, "[{what}]");
        assert_eq!(hosted::read(root, "package.json"), pkg, "[{what}]");
        assert_no_redirect_ledger(root);
        assert!(vendor_entry(root).is_none(), "[{what}]");
        assert!(hosted::store_dir(root, TILDE_ID).exists(), "[{what}]");
    };
    for (what, dry) in [("vendor --dry-run", true), ("vendor", false)] {
        let extra: &[&str] = if dry { &["--dry-run"] } else { &[] };
        let (code, env, stderr) = vendor_online(root, &server, extra);
        assert_eq!(code, 1, "[{what}] {env:#}\n{stderr}");
        assert!(
            detail_of(&env, "vendor_lock_entry_unsupported").contains("multiple dependency fields"),
            "[{what}] {env:#}"
        );
        assert!(
            !all_codes(&env).contains(&"vendor_takeover_reverted_redirect".to_string()),
            "[{what}] {env:#}"
        );
        assert_intact(what);
    }
    std::fs::remove_file(root.join(".socket/manifest.json")).unwrap();
    let (code, env, stderr) = scan(root, &server, "vendored", &[]);
    assert_ne!(code, 0, "[scan] {env:#}\n{stderr}");
    assert!(
        all_codes(&env).contains(&"vendor_lock_entry_unsupported".to_string()),
        "[scan] {env:#}"
    );
    assert_intact("scan --mode vendored");
    let (code, env, _) = scan(root, &server, "vendored", &["--dry-run"]);
    assert_eq!(code, 0, "[scan --dry-run] {env:#}");
    assert!(
        env["events"].as_array().is_some_and(|evs| {
            evs.iter().any(|e| {
                e["action"] == "skipped" && e["errorCode"] == "vendor_lock_entry_unsupported"
            })
        }),
        "[scan --dry-run] the preview names the refusal: {env:#}"
    );
    assert_intact("scan --mode vendored --dry-run");
}

#[tokio::test(flavor = "multi_thread")]
async fn vlt_hosted_artifact_preflight_refuses_before_the_vendored_revert() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    write_project(root);
    seed_manifest(root);
    let (code, env, _) = vendor(root, &[]);
    assert_eq!(code, 0, "{env:#}");
    std::fs::remove_file(root.join(".socket/manifest.json")).unwrap();
    let lock = hosted::read(root, "vlt-lock.json");
    let pkg = hosted::read(root, "package.json");
    let state = std::fs::read(root.join(".socket/vendor/state.json")).unwrap();

    let server = MockServer::start().await;
    hosted::mock_discovery(&server).await;
    hosted::mock_reference(&server).await;
    hosted::mock_view(&server).await;
    hosted::mock_artifact_with(&server, ResponseTemplate::new(404)).await;
    let (_, env, stderr) = scan(root, &server, "hosted", &[]);
    assert!(
        hosted::warning_codes(&env).contains(&hosted::UNVERIFIABLE.to_string()),
        "{env:#}\n{stderr}"
    );
    assert_eq!(
        hosted::read(root, "vlt-lock.json"),
        lock,
        "the vendored wiring stays"
    );
    assert_eq!(hosted::read(root, "package.json"), pkg);
    assert_eq!(
        std::fs::read(root.join(".socket/vendor/state.json")).unwrap(),
        state
    );
    assert!(root.join(rel()).join("index.js").is_file());
}

/// A vendor that fails after the takeover's upstream restore (here a
/// patch-service artifact failing its integrity check) rolls the restore
/// back (#853, #944): the purl stays hosted-patched, the lock and the
/// hosted store copy are left as hosted mode wrote them, and nothing asks
/// for a reinstall.
#[tokio::test(flavor = "multi_thread")]
async fn vlt_failed_vendor_after_the_takeover_revert_keeps_the_hosted_pin() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let server = MockServer::start().await;
    mock_api(&server).await;
    hosted_project(root, &server).await;
    seed_manifest(root);
    let lock = hosted::read(root, "vlt-lock.json");
    let pkg = hosted::read(root, "package.json");
    let store = hosted::store_dir(root, TILDE_ID).exists();

    let service = MockServer::start().await;
    hosted::mock_reference_at(
        &service,
        &hosted::artifact_url(&service),
        "sha512-bm90IHRoZSBieXRlcw==",
    )
    .await;
    hosted::mock_artifact(&service).await;
    let cwd = root.to_str().unwrap().to_string();
    let uri = service.uri();
    let argv = [
        "vendor",
        "--cwd",
        &cwd,
        "--api-url",
        &uri,
        "--vendor-url",
        &uri,
        "--org",
        ORG,
        "--api-token",
        "fake",
    ];
    let (code, env, stderr) = run_online(root, &argv, &server);
    assert_eq!(code, 1, "{env:#}\n{stderr}");
    let codes = all_codes(&env);
    assert!(
        !codes.contains(&"vendor_takeover_reverted_redirect".to_string()),
        "the restore is rolled back, never reported: {env:#}"
    );
    assert!(
        detail_of(&env, "apply_failed").contains("integrity"),
        "{env:#}"
    );
    assert!(
        !codes.contains(&"redirect_vlt_reinstall_required".to_string()),
        "{env:#}"
    );
    assert_eq!(
        hosted::read(root, "vlt-lock.json"),
        lock,
        "the hosted pin stays"
    );
    assert_eq!(hosted::read(root, "package.json"), pkg);
    assert!(vendor_entry(root).is_none());
    assert_no_redirect_ledger(root);
    assert_eq!(
        hosted::store_dir(root, TILDE_ID).exists(),
        store,
        "the hosted store copy is left alone"
    );
}

/// An optional hosted pin taken over by `scan --mode vendored`: the
/// hosted store copy stays (vlt would not reinstall a removed optional
/// node), and the advisory says how to refresh it.
#[tokio::test(flavor = "multi_thread")]
async fn vlt_hosted_then_vendored_takeover_keeps_an_optional_hosted_copy() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let server = MockServer::start().await;
    mock_api(&server).await;
    let lock = format!(
        "{{\n  \"lockfileVersion\": 1,\n  \"options\": {{}},\n  \"nodes\": {{\n    {}\n  }},\n  \
         \"edges\": {{\n    \"file~_d left-pad\": \"optional 1.3.0 {TILDE_ID}\"\n  }}\n}}\n",
        hosted::with_flags(&hosted::registry_node(TILDE_ID), 1)
    );
    std::fs::write(root.join("vlt-lock.json"), &lock).unwrap();
    std::fs::write(
        root.join("package.json"),
        "{\n  \"name\": \"consumer\",\n  \"optionalDependencies\": {\n    \"left-pad\": \
         \"1.3.0\"\n  }\n}\n",
    )
    .unwrap();
    hosted::install_importer(root, PRISTINE);
    let (code, env, stderr) = scan(root, &server, "hosted", &[]);
    assert_eq!(code, 0, "{env:#}\n{stderr}");
    assert_eq!(hosted::redirected(&env), 1, "{env:#}");
    hosted::install_store(root, TILDE_ID, PATCHED);
    hosted::write_hidden_lock(
        root,
        &[hosted::with_flags(
            &hosted::pinned_node(TILDE_ID, &server),
            1,
        )],
    );

    let (code, env, stderr) = scan(root, &server, "vendored", &[]);

    assert_eq!(code, 0, "{env:#}\n{stderr}");
    assert!(
        hosted::read(root, "vlt-lock.json").contains(&rel()),
        "{env:#}"
    );
    assert_eq!(
        detail_of(&env, "redirect_vlt_reinstall_required"),
        format!(
            "vendored 1 hosted-pinned packages, but node_modules still holds 1 installed copies \
             of the vendored optional dependencies; {}",
            hosted::OPTIONAL_KEPT
        )
    );
    assert!(
        detail_of(&env, "vendor_vlt_reinstall_required")
            .starts_with("left-pad@1.3.0 is an optional dependency"),
        "{env:#}"
    );
    assert_eq!(
        std::fs::read(hosted::store_dir(root, TILDE_ID).join("index.js")).unwrap(),
        PATCHED
    );
    assert!(root.join("node_modules/.vlt-lock.json").exists());
}

/// A vendored optional dependency taken over by `scan --mode hosted`: the
/// revert's `vlt ci` advisory reaches the takeover's warnings.
#[tokio::test(flavor = "multi_thread")]
async fn vlt_vendored_then_hosted_takeover_of_an_optional_dep_asks_for_vlt_ci() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let lock = registry_lock().replace("\"prod 1.3.0", "\"optional 1.3.0");
    let pkg = PACKAGE_JSON.replace("\"dependencies\"", "\"optionalDependencies\"");
    std::fs::write(root.join("vlt-lock.json"), &lock).unwrap();
    std::fs::write(root.join("package.json"), &pkg).unwrap();
    hosted::install_importer(root, PRISTINE);
    seed_manifest(root);
    let (code, env, stderr) = vendor(root, &[]);
    assert_eq!(code, 0, "{env:#}\n{stderr}");
    assert!(hosted::read(root, "vlt-lock.json").contains(&rel()));
    std::fs::remove_file(root.join(".socket/manifest.json")).unwrap();
    let server = MockServer::start().await;
    mock_api(&server).await;

    let (code, env, stderr) = scan(root, &server, "hosted", &[]);

    assert_eq!(code, 0, "{env:#}\n{stderr}");
    assert!(
        all_codes(&env).contains(&"redirect_takeover_reverted_vendored".to_string()),
        "{env:#}"
    );
    let detail = detail_of(&env, "vendor_vlt_reinstall_required");
    assert!(
        detail.starts_with(
            "left-pad@1.3.0 is an optional dependency: `vlt install` (vlt 0.0.0-30 and later) \
             keeps node_modules linked to the vendored `file:` directory"
        ) && detail.contains("run `vlt ci`"),
        "{detail}"
    );
    assert_eq!(hosted::read(root, "package.json"), pkg);
    assert!(!root.join(format!(".socket/vendor/npm/{UUID}")).exists());
}
