//! Behavior of the in-memory hosted engine beyond disk parity: lookup
//! dedup across roots, isolation from the process environment, hostile
//! and malformed input, limits, cancellation and timeouts, dry runs, and
//! the per-project refusals.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use serial_test::serial;
use socket_patch_cli::hosted_memory::{
    run_in_memory, select_paths, EngineError, HostedScanLimits, HostedScanOptions,
    HostedScanOutput, SelectOptions, SessionBuilder, TreeEntryInput,
};
use socket_patch_core::api::client::{ApiError, ApiFuture, PatchApi};
use socket_patch_core::api::types::{
    BatchSearchResponse, PackageVendorResult, PatchResponse, SearchResponse,
};
use tokio_util::sync::CancellationToken;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[path = "hosted_memory_common/mod.rs"]
mod common;

use common::*;

const NPM_FIXTURE: &str = "redirect/npm/package-lock-v3/basic";

fn npm_files() -> BTreeMap<String, Vec<u8>> {
    fixture_files(&fixtures_root().join(NPM_FIXTURE).join("input"))
}

async fn npm_server() -> MockServer {
    let server = MockServer::start().await;
    let patches = patches_from_overrides(
        &fixtures_root().join(NPM_FIXTURE).join("overrides.json"),
        None,
    );
    mount_api(&server, &patches).await;
    server
}

async fn count(server: &MockServer, method_name: &str, fragment: &str) -> usize {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .filter(|r| r.method.as_str() == method_name && r.url.path().contains(fragment))
        .count()
}

fn prefixed(prefix: &str, files: &BTreeMap<String, Vec<u8>>) -> BTreeMap<String, Vec<u8>> {
    files
        .iter()
        .map(|(k, v)| (format!("{prefix}/{k}"), v.clone()))
        .collect()
}

fn comparable(output: &HostedScanOutput) -> Value {
    let mut value = serde_json::to_value(output).unwrap();
    value["stats"]["phaseMs"] = Value::Null;
    value
}

#[tokio::test]
async fn roots_sharing_a_purl_share_every_lookup() {
    let server = npm_server().await;
    let mut repo = prefixed("a", &npm_files());
    repo.extend(prefixed("b", &npm_files()));
    let output = run_engine(&server, build_input(&repo, &[], options(false))).await;
    assert_eq!(output.projects.len(), 2);
    for project in &output.projects {
        assert!(project.error.is_none(), "{:?}", project.error);
        assert_eq!(project.redirected.len(), 1, "{}", project.root);
    }
    assert_eq!(count(&server, "POST", "/patches/batch").await, 1);
    assert_eq!(count(&server, "GET", "/patches/by-package/").await, 1);
    assert_eq!(count(&server, "POST", "/patches/package").await, 1);
    assert_eq!(count(&server, "GET", "/patches/view/").await, 1);
    let paths: Vec<&str> = output
        .changed_files
        .iter()
        .map(|f| f.path.as_str())
        .collect();
    assert_eq!(
        paths,
        vec![
            "a/.npmrc",
            "a/package-lock.json",
            "b/.npmrc",
            "b/package-lock.json"
        ]
    );
    assert_eq!(output.stats.projects, 2);
    assert_eq!(output.stats.patches_redirected, 2);
    assert_eq!(
        output.stats.provider_calls.get("searchPatchesBatch"),
        Some(&1)
    );
}

#[tokio::test]
async fn output_is_deterministic() {
    let server = npm_server().await;
    let mut repo = prefixed("x", &npm_files());
    repo.extend(prefixed("y/z", &npm_files()));
    let first = run_engine(&server, build_input(&repo, &[], options(false))).await;
    let second = run_engine(&server, build_input(&repo, &[], options(false))).await;
    assert_eq!(comparable(&first), comparable(&second));
}

const HOSTILE_ENV: &[(&str, &str)] = &[
    ("SOCKET_API_URL", "http://127.0.0.1:9"),
    ("SOCKET_API_TOKEN", "sktsec_hostile_api"),
    ("SOCKET_ORG_SLUG", "hostile-org"),
    ("SOCKET_PROXY_URL", "http://127.0.0.1:9"),
    ("SOCKET_OFFLINE", "1"),
    ("SOCKET_DRY_RUN", "1"),
    ("SOCKET_ECOSYSTEMS", "cargo"),
    ("SOCKET_BATCH_SIZE", "1"),
    ("SOCKET_PIPENV_MAJOR", "7"),
    ("SOCKET_NO_TRUST_LOCKFILE_CONFIG", "1"),
    ("SOCKET_NO_NPM_ALLOW_REMOTE_CONFIG", "1"),
    ("SOCKET_TELEMETRY_DISABLED", "0"),
    ("SOCKET_NPM_REGISTRY", "http://127.0.0.1:9"),
    ("SOCKET_PYPI_JSON_API", "http://127.0.0.1:9"),
    ("npm_config_allow_remote", "none"),
    ("NPM_CONFIG_USERCONFIG", "/nonexistent/.npmrc"),
];

#[tokio::test]
#[serial]
async fn hostile_process_environment_changes_nothing() {
    let server = npm_server().await;
    let mut repo = npm_files();
    repo.insert(
        "pnpm-lock.yaml".into(),
        std::fs::read(fixtures_root().join("redirect/npm/pnpm/basic/input/pnpm-lock.yaml"))
            .unwrap(),
    );
    let baseline = run_engine(&server, build_input(&repo, &[], options(false))).await;
    let saved: Vec<(&str, Option<std::ffi::OsString>)> = HOSTILE_ENV
        .iter()
        .map(|(k, _)| (*k, std::env::var_os(k)))
        .collect();
    for (k, v) in HOSTILE_ENV {
        std::env::set_var(k, v);
    }
    let hostile = run_engine(&server, build_input(&repo, &[], options(false))).await;
    for (k, v) in saved {
        match v {
            Some(v) => std::env::set_var(k, v),
            None => std::env::remove_var(k),
        }
    }
    assert_eq!(comparable(&baseline), comparable(&hostile));
    assert!(!baseline.projects[0].redirected.is_empty());
}

fn deep(open: &str, close: &str, depth: usize) -> Vec<u8> {
    let mut s = String::with_capacity(depth * (open.len() + close.len()));
    for _ in 0..depth {
        s.push_str(open);
    }
    for _ in 0..depth {
        s.push_str(close);
    }
    s.into_bytes()
}

async fn run_on_small_stack(
    server: &MockServer,
    input: socket_patch_cli::hosted_memory::HostedScanInput,
) -> Result<HostedScanOutput, EngineError> {
    let api = client(server);
    let handle = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        std::thread::Builder::new()
            .stack_size(2 * 1024 * 1024)
            .spawn(move || handle.block_on(run_in_memory(input, api, CancellationToken::new())))
            .unwrap()
            .join()
            .expect("the engine must not panic or overflow on hostile input")
    })
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_and_deeply_nested_inputs_never_panic() {
    let server = MockServer::start().await;
    let mut patches = patches_from_overrides(
        &fixtures_root().join(NPM_FIXTURE).join("overrides.json"),
        None,
    );
    patches.extend(patches_from_overrides(
        &fixtures_root().join("redirect/cargo/cargo/basic/overrides.json"),
        None,
    ));
    patches.extend(patches_from_overrides(
        &fixtures_root().join("redirect/pypi/requirements/basic/overrides.json"),
        None,
    ));
    mount_api(&server, &patches).await;
    let depth = 200_000;
    let mut repo: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    repo.extend(prefixed("npm", &npm_files()));
    repo.insert("npm/.yarnrc.yml".into(), deep("- ", "", depth));
    repo.insert("npm/pnpm-workspace.yaml".into(), deep("[", "]", depth));
    repo.insert("npm/.npmrc".into(), deep("[", "]", depth));
    repo.extend(prefixed(
        "rs",
        &fixture_files(&fixtures_root().join("redirect/cargo/cargo/basic/input")),
    ));
    repo.insert("rs/.cargo/config.toml".into(), deep("a = [", "]", depth));
    repo.extend(prefixed(
        "py",
        &fixture_files(&fixtures_root().join("redirect/pypi/requirements/basic/input")),
    ));
    repo.insert("py/pyproject.toml".into(), deep("x = [", "]", depth));
    repo.insert("py/hatch.toml".into(), deep("{a=", "}", depth));
    repo.insert("deepjson/package-lock.json".into(), deep("[", "]", depth));
    repo.insert("deepjson/composer.lock".into(), deep("{\"a\":", "}", depth));
    repo.insert("deepjson/Pipfile.lock".into(), deep("[", "]", depth));
    repo.insert(
        "deepjson/.socket/vendor/redirect-state.json".into(),
        deep("[", "]", depth),
    );
    repo.insert("deeptoml/uv.lock".into(), deep("a = [", "]", depth));
    repo.insert("deeptoml/Cargo.lock".into(), deep("a = {b=", "}", depth));
    repo.insert("deeptoml/Cargo.toml".into(), deep("[", "]", depth));
    repo.insert("deeptoml/poetry.lock".into(), deep("a = [", "]", depth));
    repo.insert(
        "garbage/yarn.lock".into(),
        b"\x00\x01 not a lock \"\"\"\n  ::".to_vec(),
    );
    repo.insert(
        "garbage/go.mod".into(),
        b"module \nrequire (\n(((\n".to_vec(),
    );
    repo.insert("garbage/go.sum".into(), b"x y z\n\n h1:\n".to_vec());
    repo.insert(
        "garbage/Gemfile.lock".into(),
        b"GEM\n  specs:\n    (((\n".to_vec(),
    );
    repo.insert(
        "garbage/bun.lock".into(),
        b"{\"lockfileVersion\": 99,".to_vec(),
    );
    repo.insert("garbage2/bun.lockb".into(), vec![0xa5; 4096]);
    repo.insert("garbage3/pnpm-lock.yaml".into(), deep("- ", "", depth));
    let mut opts = options(false);
    opts.limits = Some(HostedScanLimits {
        max_total_bytes: Some(64 * 1024 * 1024),
        ..HostedScanLimits::default()
    });
    let output = run_on_small_stack(&server, build_input(&repo, &[], opts))
        .await
        .expect("engine result");
    let roots: Vec<&str> = output.projects.iter().map(|p| p.root.as_str()).collect();
    for expected in [
        "npm", "rs", "py", "deepjson", "deeptoml", "garbage", "garbage2",
    ] {
        assert!(
            roots.contains(&expected),
            "{expected} missing from {roots:?}"
        );
    }
    let deepjson = output
        .projects
        .iter()
        .find(|p| p.root == "deepjson")
        .unwrap();
    // The deep pre-v5 ledger is never parsed: whatever the project reports,
    // it is not a ledger fault.
    assert!(
        deepjson
            .error
            .as_ref()
            .is_none_or(|e| e.code != "corrupt_ledger"),
        "{:?}",
        deepjson.error
    );
}

#[test]
fn session_limits_reject_oversized_input() {
    let mut opts = options(false);
    opts.limits = Some(HostedScanLimits {
        max_files: Some(1),
        ..HostedScanLimits::default()
    });
    let mut builder = SessionBuilder::new(opts).unwrap();
    builder.add_text("a/package-lock.json", "{}").unwrap();
    let err = builder.add_text("b/package-lock.json", "{}").unwrap_err();
    assert_eq!(err.code(), "max_files");
    assert_eq!(err.kind(), "limit");
}

#[tokio::test]
async fn project_and_purl_limits_reject_the_run() {
    let server = npm_server().await;
    let mut repo = prefixed("a", &npm_files());
    repo.extend(prefixed("b", &npm_files()));
    let mut opts = options(false);
    opts.limits = Some(HostedScanLimits {
        max_projects: Some(1),
        ..HostedScanLimits::default()
    });
    let err = run_in_memory(
        build_input(&repo, &[], opts),
        client(&server),
        CancellationToken::new(),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(
            err,
            EngineError::Limit {
                code: "max_projects",
                ..
            }
        ),
        "{err}"
    );

    let mut opts = options(false);
    opts.limits = Some(HostedScanLimits {
        max_purls: Some(0),
        ..HostedScanLimits::default()
    });
    let err = run_in_memory(
        build_input(&npm_files(), &[], opts),
        client(&server),
        CancellationToken::new(),
    )
    .await
    .unwrap_err();
    assert_eq!(err.code(), "max_purls");
    assert_eq!(count(&server, "POST", "/patches/batch").await, 0);
}

/// A provider whose every call pends forever.
struct Stalled;

impl PatchApi for Stalled {
    fn uses_public_proxy(&self) -> bool {
        false
    }
    fn search_patches_batch<'a>(&'a self, _: &'a [String]) -> ApiFuture<'a, BatchSearchResponse> {
        Box::pin(std::future::pending())
    }
    fn search_patches_by_package<'a>(&'a self, _: &'a str) -> ApiFuture<'a, SearchResponse> {
        Box::pin(std::future::pending())
    }
    fn fetch_registry_references<'a>(
        &'a self,
        _: &'a [String],
    ) -> ApiFuture<'a, std::collections::HashMap<String, PackageVendorResult>> {
        Box::pin(std::future::pending())
    }
    fn fetch_patch<'a>(&'a self, _: &'a str) -> ApiFuture<'a, Option<PatchResponse>> {
        Box::pin(std::future::pending())
    }
    fn download_artifact<'a>(&'a self, _: &'a str, _: u64) -> ApiFuture<'a, Vec<u8>> {
        Box::pin(async { Err(ApiError::Other("unused".into())) })
    }
}

#[tokio::test]
async fn cancellation_rejects_with_cancelled() {
    let cancel = CancellationToken::new();
    let trigger = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        trigger.cancel();
    });
    let err = run_in_memory(
        build_input(&npm_files(), &[], options(false)),
        Arc::new(Stalled),
        cancel,
    )
    .await
    .unwrap_err();
    assert_eq!(err, EngineError::Cancelled);
    assert_eq!(err.code(), "cancelled");

    let cancelled = CancellationToken::new();
    cancelled.cancel();
    let err = run_in_memory(
        build_input(&npm_files(), &[], options(false)),
        Arc::new(Stalled),
        cancelled,
    )
    .await
    .unwrap_err();
    assert_eq!(err, EngineError::Cancelled);
}

/// A provider that counts batch searches, each of which pends forever.
#[derive(Default)]
struct CountingStalled(std::sync::atomic::AtomicUsize);

impl PatchApi for CountingStalled {
    fn uses_public_proxy(&self) -> bool {
        false
    }
    fn search_patches_batch<'a>(&'a self, _: &'a [String]) -> ApiFuture<'a, BatchSearchResponse> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Box::pin(std::future::pending())
    }
    fn search_patches_by_package<'a>(&'a self, _: &'a str) -> ApiFuture<'a, SearchResponse> {
        Box::pin(std::future::pending())
    }
    fn fetch_registry_references<'a>(
        &'a self,
        _: &'a [String],
    ) -> ApiFuture<'a, std::collections::HashMap<String, PackageVendorResult>> {
        Box::pin(std::future::pending())
    }
    fn fetch_patch<'a>(&'a self, _: &'a str) -> ApiFuture<'a, Option<PatchResponse>> {
        Box::pin(std::future::pending())
    }
    fn download_artifact<'a>(&'a self, _: &'a str, _: u64) -> ApiFuture<'a, Vec<u8>> {
        Box::pin(async { Err(ApiError::Other("unused".into())) })
    }
}

/// The inventory phase never pends on memory reads; it must still yield
/// between roots so a cancel (and every other task on this single-threaded
/// runtime) runs before the whole phase — and the first provider call —
/// completes.
#[tokio::test(flavor = "current_thread")]
async fn cancellation_is_honored_between_roots_of_the_inventory() {
    let mut repo: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for i in 0..20 {
        repo.extend(prefixed(&format!("r{i:02}"), &npm_files()));
    }
    let cancel = CancellationToken::new();
    let trigger = cancel.clone();
    tokio::spawn(async move { trigger.cancel() });
    let provider = Arc::new(CountingStalled::default());
    let err = run_in_memory(
        build_input(&repo, &[], options(false)),
        provider.clone(),
        cancel,
    )
    .await
    .unwrap_err();
    assert_eq!(err, EngineError::Cancelled);
    assert_eq!(provider.0.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[tokio::test]
async fn provider_timeouts_become_project_errors() {
    let mut opts = options(false);
    opts.request_timeout_ms = Some(30);
    let output = run_in_memory(
        build_input(&npm_files(), &[], opts),
        Arc::new(Stalled),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    let error = output.projects[0].error.as_ref().unwrap();
    assert_eq!(error.code, "patch_lookup_failed");
    assert!(error.message.contains("timed out"), "{}", error.message);
    assert!(output.changed_files.is_empty());
}

#[tokio::test]
async fn unauthorized_is_a_project_error_without_proxy_fallback() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(401).set_body_string("bad token"))
        .mount(&server)
        .await;
    let output = run_engine(&server, build_input(&npm_files(), &[], options(false))).await;
    let error = output.projects[0].error.as_ref().unwrap();
    assert_eq!(error.code, "patch_lookup_failed");
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert!(requests
        .iter()
        .all(|r| !r.url.path().starts_with("/patch/")));
}

#[tokio::test]
async fn dry_run_previews_without_records() {
    let server = npm_server().await;
    let output = run_engine(&server, build_input(&npm_files(), &[], options(true))).await;
    let paths: Vec<&str> = output
        .changed_files
        .iter()
        .map(|f| f.path.as_str())
        .collect();
    assert_eq!(paths, vec![".npmrc", "package-lock.json"]);
    assert_eq!(output.projects[0].redirect["dryRun"], true);
    assert_eq!(count(&server, "GET", "/patches/view/").await, 0);
    assert_eq!(count(&server, "POST", "/patches/package").await, 1);
}

#[tokio::test]
async fn symlinked_workspace_config_refuses_the_project() {
    let dir = fixtures_root().join("redirect/npm/pnpm/basic");
    let server = MockServer::start().await;
    mount_api(
        &server,
        &patches_from_overrides(&dir.join("overrides.json"), None),
    )
    .await;
    let files = fixture_files(&dir.join("input"));
    let mut builder = SessionBuilder::new(options(false)).unwrap();
    for (path, bytes) in &files {
        builder
            .add_text(path, std::str::from_utf8(bytes).unwrap())
            .unwrap();
    }
    builder
        .mark_present(
            "pnpm-workspace.yaml",
            socket_patch_cli::hosted_memory::MarkKind::Symlink,
        )
        .unwrap();
    let output = run_engine(&server, builder.finish().unwrap()).await;
    let error = output.projects[0].error.as_ref().unwrap();
    assert_eq!(error.code, "redirect_symlinked_file_unsupported");
    assert!(output.changed_files.is_empty());
}

#[tokio::test]
async fn symlinked_npmrc_is_left_alone_with_a_warning() {
    let server = npm_server().await;
    let mut builder = SessionBuilder::new(options(false)).unwrap();
    for (path, bytes) in &npm_files() {
        builder
            .add_text(path, std::str::from_utf8(bytes).unwrap())
            .unwrap();
    }
    builder
        .mark_present(".npmrc", socket_patch_cli::hosted_memory::MarkKind::Symlink)
        .unwrap();
    let output = run_engine(&server, builder.finish().unwrap()).await;
    let project = &output.projects[0];
    assert!(project.error.is_none());
    let warnings = project.redirect["warnings"].as_array().unwrap();
    let npm = warnings
        .iter()
        .find(|w| w["code"] == "redirect_npm_allow_remote")
        .unwrap();
    assert!(npm["detail"].as_str().unwrap().contains("symbolic link"));
    assert!(output.changed_files.iter().all(|f| f.path != ".npmrc"));
}

#[tokio::test]
async fn vendored_takeover_is_refused() {
    let server = npm_server().await;
    let mut files = npm_files();
    files.insert(
        ".socket/vendor/state.json".into(),
        serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "entries": {
                "pkg:npm/left-pad@1.3.0": {
                    "ecosystem": "npm",
                    "basePurl": "pkg:npm/left-pad@1.3.0",
                    "uuid": "22222222-2222-2222-2222-222222222222",
                    "artifact": {"path": ".socket/vendor/npm/22222222-2222-2222-2222-222222222222/left-pad-1.3.0.tgz"},
                    "wiring": []
                }
            }
        }))
        .unwrap(),
    );
    let output = run_engine(&server, build_input(&files, &[], options(false))).await;
    let project = &output.projects[0];
    assert!(project
        .skipped
        .iter()
        .any(|s| s.reason == "vendored_takeover_unsupported_in_memory"));
    assert!(project.redirected.is_empty());
    let warnings = project.redirect["warnings"].as_array().unwrap();
    assert!(warnings
        .iter()
        .any(|w| w["code"] == "vendored_takeover_unsupported_in_memory"));
    assert!(output.changed_files.is_empty());
}

/// A pre-v5 redirect ledger (`.socket/vendor/redirect-state.json`) is
/// never read by the v5 engine: a torn one neither fails its project nor
/// changes its plan, and the engine never emits (or rewrites) the file.
#[tokio::test]
async fn corrupt_pre_v5_ledger_is_ignored() {
    let server = npm_server().await;
    let mut repo = prefixed("good", &npm_files());
    repo.extend(prefixed("bad", &npm_files()));
    repo.insert(
        "bad/.socket/vendor/redirect-state.json".into(),
        b"{ torn".to_vec(),
    );
    let output = run_engine(&server, build_input(&repo, &[], options(false))).await;
    let bad = output.projects.iter().find(|p| p.root == "bad").unwrap();
    let good = output.projects.iter().find(|p| p.root == "good").unwrap();
    assert!(bad.error.is_none(), "{:?}", bad.error);
    assert!(good.error.is_none(), "{:?}", good.error);
    assert_eq!(bad.redirected.len(), 1);
    assert_eq!(good.redirected.len(), 1);
    let paths: Vec<&str> = output
        .changed_files
        .iter()
        .map(|f| f.path.as_str())
        .collect();
    assert_eq!(
        paths,
        vec![
            "bad/.npmrc",
            "bad/package-lock.json",
            "good/.npmrc",
            "good/package-lock.json"
        ],
        "the ledger is neither consumed nor emitted"
    );
}

#[tokio::test]
async fn maven_files_warn_that_the_ecosystem_is_unsupported() {
    let server = npm_server().await;
    let mut files = npm_files();
    files.insert("pom.xml".into(), b"<project/>".to_vec());
    let output = run_engine(&server, build_input(&files, &[], options(false))).await;
    assert!(output
        .warnings
        .iter()
        .any(|w| w.code == "ecosystem_unsupported_in_memory"
            && w.project_root.as_deref() == Some("")));
}

#[tokio::test]
async fn a_maven_only_repo_warns_through_selection() {
    let server = npm_server().await;
    let entries: Vec<TreeEntryInput> = ["java/app/pom.xml", "java/app/src/Main.java"]
        .iter()
        .map(|p| TreeEntryInput {
            path: (*p).to_string(),
            mode: "100644".into(),
            kind: "blob".into(),
            size: Some(1),
        })
        .collect();
    let selection = select_paths(&entries, &SelectOptions::default());
    assert!(selection.roots.is_empty());
    let present: Vec<&str> = selection.present_only.iter().map(String::as_str).collect();
    assert_eq!(present, vec!["java/app/pom.xml"]);
    let output = run_engine(
        &server,
        build_input(&BTreeMap::new(), &present, options(false)),
    )
    .await;
    assert!(output.projects.is_empty());
    let warning = output
        .warnings
        .iter()
        .find(|w| w.code == "ecosystem_unsupported_in_memory")
        .expect("the unsupported ecosystem is reported");
    assert!(warning.project_root.is_none());
    assert!(
        warning.detail.contains("java/app/pom.xml"),
        "{}",
        warning.detail
    );
}

#[tokio::test]
async fn an_unreadable_higher_precedence_lock_refuses_the_project() {
    let server = npm_server().await;
    let output = run_engine(
        &server,
        build_input(&npm_files(), &["npm-shrinkwrap.json"], options(false)),
    )
    .await;
    let project = &output.projects[0];
    assert_eq!(
        project.error.as_ref().map(|e| e.code.as_str()),
        Some("candidate_file_unreadable"),
        "{:#}",
        project.redirect
    );
    assert!(project.redirected.is_empty());
    assert!(output.changed_files.is_empty());
}

#[tokio::test]
async fn selection_drives_the_engine_roots() {
    let server = npm_server().await;
    let mut repo = prefixed("apps/web", &npm_files());
    repo.extend(prefixed("apps/web/test/fixture", &npm_files()));
    repo.insert("apps/web/src/index.js".into(), b"x".to_vec());
    let entries: Vec<TreeEntryInput> = repo
        .keys()
        .map(|p| TreeEntryInput {
            path: p.clone(),
            mode: "100644".into(),
            kind: "blob".into(),
            size: Some(1),
        })
        .collect();
    let selection = select_paths(&entries, &SelectOptions::default());
    assert_eq!(selection.roots, vec!["apps/web"]);
    let fetched: BTreeMap<String, Vec<u8>> = selection
        .fetch_text
        .iter()
        .map(|p| (p.clone(), repo[p].clone()))
        .collect();
    let mut opts = options(false);
    opts.project_roots = Some(selection.roots.clone());
    let output = run_engine(&server, build_input(&fetched, &[], opts)).await;
    assert_eq!(output.projects.len(), 1);
    assert_eq!(output.projects[0].root, "apps/web");
    assert_eq!(output.projects[0].redirected.len(), 1);
}

#[tokio::test]
async fn ecosystem_filter_skips_other_ecosystems() {
    let server = npm_server().await;
    let mut opts = options(false);
    opts.ecosystems = Some(vec!["cargo".to_string()]);
    let output = run_engine(&server, build_input(&npm_files(), &[], opts)).await;
    assert!(output.projects.is_empty() || output.projects[0].summary.scanned_packages == 0);
    assert_eq!(count(&server, "POST", "/patches/batch").await, 0);
}

#[tokio::test]
async fn invalid_options_reject() {
    let server = npm_server().await;
    let err = run_in_memory(
        build_input(&npm_files(), &[], options(false)),
        client(&server),
        CancellationToken::new(),
    )
    .await
    .map(|_| ())
    .err();
    assert!(err.is_none());
    let err = SessionBuilder::new(HostedScanOptions {
        org_slug: String::new(),
        ..HostedScanOptions::default()
    })
    .unwrap_err();
    assert_eq!(err.code(), "invalid_org_slug");
}

#[tokio::test]
async fn hosted_bundle_command_prints_the_engine_result() {
    let server = npm_server().await;
    let files: BTreeMap<String, String> = npm_files()
        .into_iter()
        .map(|(k, v)| (k, String::from_utf8(v).unwrap()))
        .collect();
    let bundle = serde_json::json!({ "files": files, "presentOnly": [".pnp.loader.mjs"] });
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_socket-patch"))
        .args([
            "hosted-bundle",
            "--org",
            ORG,
            "--api-token",
            "fake-token",
            "--api-url",
            &server.uri(),
        ])
        .env("SOCKET_NO_CONFIG", "1")
        .env("SOCKET_TELEMETRY_DISABLED", "1")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    {
        use std::io::Write;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(bundle.to_string().as_bytes())
            .unwrap();
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["projects"][0]["root"], "");
    let warnings = result["warnings"].as_array().unwrap();
    assert!(
        warnings.iter().any(|w| w["code"] == "yarn_pnp_unsupported"),
        "{warnings:?}"
    );
    assert!(result["engineVersion"]
        .as_str()
        .unwrap()
        .starts_with(env!("CARGO_PKG_VERSION")));

    let missing = std::process::Command::new(env!("CARGO_BIN_EXE_socket-patch"))
        .args(["hosted-bundle"])
        .env_remove("SOCKET_API_TOKEN")
        .env_remove("SOCKET_ORG_SLUG")
        .env("SOCKET_NO_CONFIG", "1")
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    assert_eq!(missing.status.code(), Some(2));
}

#[tokio::test]
async fn warnings_are_scoped_to_their_project() {
    let server = npm_server().await;
    let output = run_engine(
        &server,
        build_input(
            &prefixed("pkg", &npm_files()),
            &["pkg/.pnp.cjs"],
            options(false),
        ),
    )
    .await;
    let pnp = output
        .warnings
        .iter()
        .find(|w| w.code == "yarn_pnp_unsupported")
        .expect("pnp refusal");
    assert_eq!(pnp.project_root.as_deref(), Some("pkg"));
}

#[tokio::test]
async fn stats_count_inputs_and_calls() {
    let server = npm_server().await;
    let files = npm_files();
    let bytes: usize = files.values().map(Vec::len).sum();
    let output = run_engine(&server, build_input(&files, &[], options(false))).await;
    assert_eq!(output.stats.files_input, files.len() as u64);
    assert_eq!(output.stats.bytes_input, bytes as u64);
    assert_eq!(output.stats.patches_selected, 1);
    assert_eq!(
        output.stats.files_changed,
        output.changed_files.len() as u64
    );
    for method_name in [
        "searchPatchesBatch",
        "searchPatchesByPackage",
        "fetchRegistryReferences",
        "fetchPatch",
    ] {
        assert_eq!(
            output.stats.provider_calls.get(method_name),
            Some(&1),
            "{method_name}"
        );
    }
}

#[test]
fn engine_future_is_send_and_static() {
    fn assert_send_static<T: Send + 'static>(_: &T) {}
    let input = build_input(&npm_files(), &[], options(false));
    let future = run_in_memory(input, Arc::new(Stalled), CancellationToken::new());
    assert_send_static(&future);
}

#[test]
fn contract_shapes_are_camel_case() {
    let options: HostedScanOptions = serde_json::from_value(serde_json::json!({
        "orgSlug": "org", "ecosystems": ["npm"], "batchSize": 50, "dryRun": true,
        "pipenvMajor": 11, "trustLockfileConfig": false, "npmAllowRemoteConfig": false,
        "projectRoots": ["a"], "providerConcurrency": 4, "requestTimeoutMs": 1000,
        "limits": {"maxFileBytes": 1, "maxTotalBytes": 2, "maxFiles": 3, "maxPurls": 4,
                   "maxProjects": 5, "maxArtifactBytes": 6}
    }))
    .unwrap();
    assert_eq!(options.batch_size, Some(50));
    assert_eq!(options.limits.unwrap().max_artifact_bytes, Some(6));
    let entry: TreeEntryInput = serde_json::from_value(serde_json::json!({
        "path": "a/package-lock.json", "mode": "100644", "type": "blob", "size": 10
    }))
    .unwrap();
    let selection =
        serde_json::to_value(select_paths(&[entry], &SelectOptions::default())).unwrap();
    for key in [
        "roots",
        "fetchText",
        "fetchBinary",
        "presentOnly",
        "symlinks",
        "ignoredCount",
        "ignoredSample",
    ] {
        assert!(
            selection.get(key).is_some(),
            "{key} missing from {selection}"
        );
    }
}

#[tokio::test]
async fn result_serializes_with_the_contract_keys() {
    let server = npm_server().await;
    let output = run_engine(&server, build_input(&npm_files(), &[], options(false))).await;
    let value = serde_json::to_value(&output).unwrap();
    for key in [
        "projects",
        "changedFiles",
        "changedBinaryFiles",
        "deletedFiles",
        "warnings",
        "stats",
        "engineVersion",
    ] {
        assert!(value.get(key).is_some(), "{key}");
    }
    let project = &value["projects"][0];
    for key in ["root", "redirect", "summary", "redirected", "skipped"] {
        assert!(project.get(key).is_some(), "{key}");
    }
    for key in [
        "scannedPackages",
        "packagesWithPatches",
        "totalPatches",
        "freePatches",
        "paidPatches",
        "canAccessPaidPatches",
    ] {
        assert!(project["summary"].get(key).is_some(), "{key}");
    }
    for key in [
        "projects",
        "filesInput",
        "bytesInput",
        "packagesScanned",
        "packagesWithPatches",
        "patchesSelected",
        "patchesRedirected",
        "filesChanged",
        "providerCalls",
        "phaseMs",
    ] {
        assert!(value["stats"].get(key).is_some(), "{key}");
    }
}

/// A vlt project: the engine has no network for the artifact preflight the
/// disk flow runs, so every in-scope dep is judged as `--offline` judges
/// it. vlt drives here, so the dep is withheld from every rewriter
/// (`redirect_vlt_artifact_unverifiable`) and nothing is written. The
/// warning quotes the artifact URL with its grant-token level redacted.
#[tokio::test]
async fn a_vlt_project_is_withheld_as_offline() {
    const VLT_FIXTURE: &str = "redirect/npm/vlt/basic";
    let server = MockServer::start().await;
    let patches = patches_from_overrides(
        &fixtures_root().join(VLT_FIXTURE).join("overrides.json"),
        None,
    );
    mount_api(&server, &patches).await;
    let files = fixture_files(&fixtures_root().join(VLT_FIXTURE).join("input"));

    let output = run_engine(&server, build_input(&files, &[], options(false))).await;

    let project = &output.projects[0];
    assert!(project.error.is_none(), "the vlt root is scanned");
    assert!(project.redirected.is_empty(), "nothing is pinned");
    assert!(project
        .skipped
        .iter()
        .any(|s| s.reason == "redirect_vlt_artifact_unverifiable"));
    let warnings = project.redirect["warnings"].as_array().unwrap();
    let detail = warnings
        .iter()
        .find(|w| w["code"] == "redirect_vlt_artifact_unverifiable")
        .and_then(|w| w["detail"].as_str())
        .expect("the preflight warning is reported");
    assert!(
        detail.contains("/patch/npm/<redacted>/") && detail.contains(": offline; nothing was written"),
        "the offline refusal quotes the redacted URL"
    );
    assert!(output.changed_files.is_empty());
}

const GEM_BASIC_FIXTURE: &str = "redirect/gem/bundler/basic";

/// The gem fixture's API mocks and input files.
async fn gem_server_and_input() -> (MockServer, BTreeMap<String, Vec<u8>>) {
    let server = MockServer::start().await;
    let patches = patches_from_overrides(
        &fixtures_root()
            .join(GEM_BASIC_FIXTURE)
            .join("overrides.json"),
        None,
    );
    mount_api(&server, &patches).await;
    let input = fixture_files(&fixtures_root().join(GEM_BASIC_FIXTURE).join("input"));
    (server, input)
}

fn warning_codes(redirect: &Value) -> Vec<String> {
    redirect["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| w["code"].as_str().unwrap().to_string())
        .collect()
}

fn changed_paths(output: &HostedScanOutput) -> Vec<&str> {
    output
        .changed_files
        .iter()
        .map(|f| f.path.as_str())
        .collect()
}

/// #749: bundler 4 reads the lock `bundle config set lockfile custom.lock`
/// names, which the rewriter never pins. With a leftover `Gemfile.lock`
/// beside it, the run used to rewrite that ignored lock, report success,
/// and break every frozen install; the project is refused with nothing
/// written instead. (A memory tree only finds gem candidates through a
/// default lock; the no-leftover shape is covered on disk by
/// `ruby_crawler`'s `loaded_manifest_reads_the_lockfile_setting`.)
#[tokio::test]
async fn a_bundler4_custom_lockfile_is_refused() {
    let (server, input) = gem_server_and_input().await;
    let mut files = input.clone();
    files.insert("custom.lock".to_string(), input["Gemfile.lock"].clone());
    files.insert(
        ".bundle/config".to_string(),
        b"---\nBUNDLE_LOCKFILE: \"custom.lock\"\n".to_vec(),
    );
    let output = run_engine(&server, build_input(&files, &[], options(false))).await;
    let project = &output.projects[0];
    assert!(project.error.is_none(), "{:?}", project.error);
    assert!(project.redirected.is_empty(), "{:?}", project.redirected);
    assert!(
        warning_codes(&project.redirect)
            .contains(&"redirect_gem_bundle_lockfile_unsupported".into()),
        "{:?}",
        warning_codes(&project.redirect)
    );
    assert!(
        changed_paths(&output).is_empty(),
        "{:?}",
        changed_paths(&output)
    );
}

/// #749: a configured lockfile naming the pair's own default lock is the
/// lock the rewriter pins anyway, so the project is wired as usual.
#[tokio::test]
async fn a_lockfile_setting_naming_the_default_lock_is_wired() {
    let (server, input) = gem_server_and_input().await;
    let mut files = input.clone();
    files.insert(
        ".bundle/config".to_string(),
        b"---\nBUNDLE_LOCKFILE: \"Gemfile.lock\"\n".to_vec(),
    );
    let output = run_engine(&server, build_input(&files, &[], options(false))).await;
    let project = &output.projects[0];
    assert_eq!(
        project.redirected.len(),
        1,
        "{:?}",
        warning_codes(&project.redirect)
    );
    assert_eq!(changed_paths(&output), vec!["Gemfile", "Gemfile.lock"]);
}

/// The fixture lock re-stamped `BUNDLED WITH <version>`.
fn bundled_with(lock: &[u8], version: &str) -> Vec<u8> {
    let text = String::from_utf8(lock.to_vec()).unwrap();
    let (head, _) = text.split_once("BUNDLED WITH").unwrap();
    format!("{head}BUNDLED WITH\n   {version}\n").into_bytes()
}

/// A `Gemfile` + `gems.rb` twin with each lock bundled by `versions`.
fn gem_twin(
    input: &BTreeMap<String, Vec<u8>>,
    versions: (&str, &str),
) -> BTreeMap<String, Vec<u8>> {
    let mut files = BTreeMap::new();
    files.insert("Gemfile".to_string(), input["Gemfile"].clone());
    files.insert("gems.rb".to_string(), input["Gemfile"].clone());
    files.insert(
        "Gemfile.lock".to_string(),
        bundled_with(&input["Gemfile.lock"], versions.0),
    );
    files.insert(
        "gems.locked".to_string(),
        bundled_with(&input["Gemfile.lock"], versions.1),
    );
    files
}

/// #751: bundler 1.x loads `Gemfile` before `gems.rb`. A twin whose locks
/// say bundler 1.17 wrote them is wired through the `Gemfile` pair (the
/// one that installs), never `gems.rb`.
#[tokio::test]
async fn a_bundler1_twin_wires_the_gemfile_pair() {
    let (server, input) = gem_server_and_input().await;
    let files = gem_twin(&input, ("1.17.3", "1.17.3"));
    let output = run_engine(&server, build_input(&files, &[], options(false))).await;
    let project = &output.projects[0];
    assert!(project.error.is_none(), "{:?}", project.error);
    assert_eq!(
        project.redirected.len(),
        1,
        "{:?}",
        warning_codes(&project.redirect)
    );
    assert_eq!(changed_paths(&output), vec!["Gemfile", "Gemfile.lock"]);
}

/// #751 control: a bundler >= 2 twin still wires `gems.rb`, as bundler
/// >= 2 loads it.
#[tokio::test]
async fn a_bundler2_twin_still_wires_gems_rb() {
    let (server, input) = gem_server_and_input().await;
    let files = gem_twin(&input, ("2.6.2", "2.6.2"));
    let output = run_engine(&server, build_input(&files, &[], options(false))).await;
    let project = &output.projects[0];
    assert_eq!(
        project.redirected.len(),
        1,
        "{:?}",
        warning_codes(&project.redirect)
    );
    assert_eq!(changed_paths(&output), vec!["gems.locked", "gems.rb"]);
}

/// #751: twin locks written by different bundler majors leave no safe
/// spelling to wire: refused, nothing written.
#[tokio::test]
async fn a_twin_with_diverging_bundler_majors_is_refused() {
    let (server, input) = gem_server_and_input().await;
    for versions in [("1.17.3", "2.6.2"), ("2.6.2", "1.17.3")] {
        let files = gem_twin(&input, versions);
        let output = run_engine(&server, build_input(&files, &[], options(false))).await;
        let project = &output.projects[0];
        assert!(project.redirected.is_empty(), "{versions:?}");
        assert!(
            warning_codes(&project.redirect)
                .contains(&"redirect_gem_twin_bundler_versions_diverge".into()),
            "{versions:?}: {:?}",
            warning_codes(&project.redirect)
        );
        assert!(changed_paths(&output).is_empty());
    }
}
