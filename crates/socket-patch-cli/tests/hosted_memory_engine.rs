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

/// The in-memory engine refuses exactly the takeovers the disk flow
/// performs (one shared predicate): a vendored PyPI package is one, so it
/// is refused as a takeover rather than handed to the Python rewriters,
/// which would refuse socket-patch's own vendored source as user-authored.
#[tokio::test]
async fn vendored_pypi_takeover_is_refused_like_the_disk_flow() {
    const PYPI_FIXTURE: &str = "redirect/pypi/requirements/basic";
    let server = MockServer::start().await;
    let patches = patches_from_overrides(
        &fixtures_root().join(PYPI_FIXTURE).join("overrides.json"),
        None,
    );
    mount_api(&server, &patches).await;
    let mut files = fixture_files(&fixtures_root().join(PYPI_FIXTURE).join("input"));
    let uuid = "33333333-3333-3333-3333-333333333333";
    files.insert(
        ".socket/vendor/state.json".into(),
        serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "entries": {
                "pkg:pypi/requests@2.28.1": {
                    "ecosystem": "pypi",
                    "basePurl": "pkg:pypi/requests@2.28.1",
                    "uuid": uuid,
                    "flavor": "requirements",
                    "artifact": {"path": format!(".socket/vendor/pypi/{uuid}/requests-2.28.1-py3-none-any.whl")},
                    "wiring": []
                }
            }
        }))
        .unwrap(),
    );
    let output = run_engine(&server, build_input(&files, &[], options(false))).await;
    let project = &output.projects[0];
    assert!(
        project
            .skipped
            .iter()
            .any(|s| s.reason == "vendored_takeover_unsupported_in_memory"),
        "{:?}",
        project.skipped
    );
    assert!(project.redirected.is_empty());
    assert!(output.changed_files.is_empty());
}

/// #536: a vendored composer package is refused as a takeover too, rather
/// than handed to the composer.lock rewriter, which would edit the vendored
/// entry in place and keep its patch-uuid `dist.reference`.
#[tokio::test]
async fn vendored_composer_takeover_is_refused_like_the_disk_flow() {
    const COMPOSER_FIXTURE: &str = "redirect/composer/composer-lock/basic";
    let server = MockServer::start().await;
    let patches = patches_from_overrides(
        &fixtures_root().join(COMPOSER_FIXTURE).join("overrides.json"),
        None,
    );
    mount_api(&server, &patches).await;
    let mut files = fixture_files(&fixtures_root().join(COMPOSER_FIXTURE).join("input"));
    let uuid = "44444444-4444-4444-4444-444444444444";
    files.insert(
        ".socket/vendor/state.json".into(),
        serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "entries": {
                "pkg:composer/monolog/monolog@2.0.0": {
                    "ecosystem": "composer",
                    "basePurl": "pkg:composer/monolog/monolog@2.0.0",
                    "uuid": uuid,
                    "artifact": {"path": format!(".socket/vendor/composer/{uuid}/monolog/monolog@2.0.0")},
                    "wiring": []
                }
            }
        }))
        .unwrap(),
    );
    let output = run_engine(&server, build_input(&files, &[], options(false))).await;
    let project = &output.projects[0];
    assert!(
        project
            .skipped
            .iter()
            .any(|s| s.reason == "vendored_takeover_unsupported_in_memory"),
        "{:?}",
        project.skipped
    );
    assert!(project.redirected.is_empty());
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
    let mut child = hermetic::binary_command()
        .args([
            "hosted-bundle",
            "--org",
            ORG,
            "--api-token",
            "fake-token",
            "--api-url",
            &server.uri(),
        ])
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

    let missing = hermetic::binary_command()
        .args(["hosted-bundle"])
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
        detail.contains("/patch/npm/<redacted>/")
            && detail.contains(": offline; nothing was written"),
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
/// written instead. A memory tree only finds gem candidates through the
/// lock bundler loads (#736), and that lock is none of the default ones
/// here, so the project yields no gem candidate; the run reports
/// `gem_lock_unsupported` instead (the per-candidate
/// `redirect_gem_bundle_lockfile_unsupported` refusal is covered by the
/// engine unit tests).
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
        changed_paths(&output).is_empty(),
        "{:?}",
        changed_paths(&output)
    );
    assert_gem_lock_unsupported(&output);
}

/// #1477: bundler 4's Gemfile `lockfile "custom.lock"` call names the
/// lock bundler reads just like the setting, so the project is refused the
/// same way, with nothing written.
#[tokio::test]
async fn a_bundler4_gemfile_lockfile_call_is_refused() {
    let (server, input) = gem_server_and_input().await;
    let mut files = input.clone();
    files.insert("custom.lock".to_string(), input["Gemfile.lock"].clone());
    let mut gemfile = b"lockfile \"custom.lock\"\n".to_vec();
    gemfile.extend_from_slice(&input["Gemfile"]);
    files.insert("Gemfile".to_string(), gemfile);
    let output = run_engine(&server, build_input(&files, &[], options(false))).await;
    let project = &output.projects[0];
    assert!(project.error.is_none(), "{:?}", project.error);
    assert!(project.redirected.is_empty(), "{:?}", project.redirected);
    assert!(
        changed_paths(&output).is_empty(),
        "{:?}",
        changed_paths(&output)
    );
    assert_gem_lock_unsupported(&output);
}

/// The run says the project's gems were not scanned, rather than finding
/// none: the lock inventory's `gem_lock_unsupported` diagnosis.
fn assert_gem_lock_unsupported(output: &HostedScanOutput) {
    let codes: Vec<&str> = output.warnings.iter().map(|w| w.code.as_str()).collect();
    assert!(codes.contains(&"gem_lock_unsupported"), "{codes:?}");
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

/// #751: bundler 1.x loads a twin's `Gemfile` and bundler >= 2 its
/// `gems.rb`, and a lock's `BUNDLED WITH` records who wrote it, not who
/// installs it, so no twin is wired whatever its locks say: refused,
/// nothing written. No lock is the one bundler loads (#736), so the
/// memory tree yields no gem candidate and the run reports
/// `gem_lock_unsupported`; the per-candidate
/// `redirect_gem_twin_manifest_ambiguous` refusal is covered by the engine
/// unit tests.
#[tokio::test]
async fn a_gemfile_gems_rb_twin_is_refused() {
    let (server, input) = gem_server_and_input().await;
    for versions in [
        ("1.17.3", "1.17.3"),
        ("2.6.2", "2.6.2"),
        ("1.17.3", "2.6.2"),
        ("2.6.2", "1.17.3"),
    ] {
        let files = gem_twin(&input, versions);
        let output = run_engine(&server, build_input(&files, &[], options(false))).await;
        let project = &output.projects[0];
        assert!(project.redirected.is_empty(), "{versions:?}");
        assert!(changed_paths(&output).is_empty(), "{versions:?}");
        assert_gem_lock_unsupported(&output);
    }
}

/// #736: the engine's purl set comes from the lock bundler loads. A
/// `gems.rb` project's gems live in `gems.locked`; reading only
/// `Gemfile.lock` found nothing to redirect, and a leftover `Gemfile.lock`
/// beside it must not change that.
#[tokio::test]
async fn gems_rb_project_yields_its_gem_candidates() {
    const GEM_FIXTURE: &str = "redirect/gem/bundler/basic";
    let server = MockServer::start().await;
    let patches = patches_from_overrides(
        &fixtures_root().join(GEM_FIXTURE).join("overrides.json"),
        None,
    );
    mount_api(&server, &patches).await;
    let input = fixture_files(&fixtures_root().join(GEM_FIXTURE).join("input"));
    let renamed = |stale_twin: bool| {
        let mut files = BTreeMap::new();
        files.insert("gems.rb".to_string(), input["Gemfile"].clone());
        files.insert("gems.locked".to_string(), input["Gemfile.lock"].clone());
        if stale_twin {
            // Locks nothing the patch API knows about.
            files.insert(
                "Gemfile.lock".to_string(),
                b"GEM\n  remote: https://rubygems.org/\n  specs:\n    rake (13.0.0)\n\n\
                  PLATFORMS\n  ruby\n\nDEPENDENCIES\n  rake\n"
                    .to_vec(),
            );
        }
        files
    };
    for stale_twin in [false, true] {
        let output = run_engine(
            &server,
            build_input(&renamed(stale_twin), &[], options(true)),
        )
        .await;
        assert_eq!(output.projects.len(), 1);
        let project = &output.projects[0];
        assert!(project.error.is_none(), "{:?}", project.error);
        assert_eq!(
            project.redirected.len(),
            1,
            "stale twin {stale_twin}: {}",
            serde_json::to_string_pretty(&comparable(&output)).unwrap()
        );
    }
}

/// #718 in the in-memory engine: a yarn berry pin of a package with a `bin`
/// takes the map from the served tarball's own package.json (fetched
/// through the provider, like wheel metadata), and a tarball it cannot
/// fetch drops the patch instead of pinning an entry yarn rewrites.
#[tokio::test]
async fn yarn_berry_pin_takes_bin_from_the_served_tarball() {
    use base64::Engine as _;
    use sha2::Digest as _;

    const UUID: &str = "71717171-7171-4171-8171-717171717171";
    let tarball = {
        let manifest = br#"{"name":"uuid","version":"9.0.1","bin":{"uuid":"./dist/bin/uuid"}}"#;
        let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::default(),
        ));
        let mut header = tar::Header::new_gnu();
        header.set_size(manifest.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "package/package.json", &manifest[..])
            .unwrap();
        builder.into_inner().unwrap().finish().unwrap()
    };
    let sha512 = format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode(sha2::Sha512::digest(&tarball))
    );
    let mut files = BTreeMap::new();
    files.insert(
        "package.json".to_string(),
        b"{\n  \"name\": \"app\",\n  \"version\": \"1.0.0\",\n  \"dependencies\": {\n    \"uuid\": \"^9.0.0\"\n  }\n}\n".to_vec(),
    );
    files.insert(
        "yarn.lock".to_string(),
        format!(
            "__metadata:\n  version: 8\n  cacheKey: 10c0\n\n\
             \"app@workspace:.\":\n  version: 0.0.0-use.local\n  resolution: \"app@workspace:.\"\n  \
             dependencies:\n    uuid: \"npm:^9.0.0\"\n  languageName: unknown\n  linkType: soft\n\n\
             \"uuid@npm:^9.0.0\":\n  version: 9.0.1\n  resolution: \"uuid@npm:9.0.1\"\n  \
             bin:\n    uuid: dist/bin/uuid\n  checksum: 10c0/{}\n  languageName: node\n  \
             linkType: hard\n",
            "1".repeat(128)
        )
        .into_bytes(),
    );

    for served in [true, false] {
        let server = MockServer::start().await;
        let artifact = format!("/patch/npm/uuid/9.0.1/tok/{UUID}/uuid-9.0.1.tgz");
        let url = format!("{}{artifact}", server.uri());
        let patch = common::Patch {
            purl: "pkg:npm/uuid@9.0.1".into(),
            uuid: UUID.into(),
            reference: serde_json::json!({
                "status": "granted",
                "url": url,
                "purl": null,
                "artifacts": [
                    { "kind": "tarball", "url": url, "integrity": { "sha512": sha512 } },
                    { "kind": "yarn-berry-zip", "url": url,
                      "integrity": { "yarnBerry10c0": format!("10c0/{}", "7".repeat(128)) } }
                ],
                "registryOverride": null,
            }),
        };
        mount_api(&server, &[patch]).await;
        Mock::given(method("GET"))
            .and(path(artifact))
            .respond_with(if served {
                ResponseTemplate::new(200).set_body_bytes(tarball.clone())
            } else {
                ResponseTemplate::new(404)
            })
            .mount(&server)
            .await;

        let output = run_engine(&server, build_input(&files, &[], options(false))).await;
        let project = &output.projects[0];
        assert!(project.error.is_none(), "{:?}", project.error);
        let changed = engine_changed(&output);
        if served {
            assert_eq!(project.redirected.len(), 1, "{:?}", project.skipped);
            let lock = String::from_utf8(changed["yarn.lock"].clone()).unwrap();
            assert!(
                lock.contains(&format!(
                    "\"uuid@{url}\":\n  version: 9.0.1\n  resolution: \"uuid@{url}\"\n  \
                     bin:\n    uuid: ./dist/bin/uuid\n  checksum: 10c0/{}\n",
                    "7".repeat(128)
                )),
                "{lock}"
            );
        } else {
            assert!(project.redirected.is_empty(), "{:?}", project.redirected);
            assert!(
                project
                    .skipped
                    .iter()
                    .any(|s| s.reason == "npm_manifest_unavailable"),
                "{:?}",
                project.skipped
            );
            assert!(!changed.contains_key("yarn.lock"), "{changed:?}");
        }
    }
}

/// #558 in the in-memory engine: a yarn classic pin whose grant carries
/// only a sha512 takes its `#<sha1>` fragment from the served tarball
/// (fetched through the provider and checked against that sha512); a
/// tarball it cannot fetch drops the patch instead of pinning a
/// fragmentless URL yarn 1 would serve stale cached bytes for.
#[tokio::test]
async fn issue_558_yarn_classic_pin_takes_sha1_from_the_served_tarball() {
    use base64::Engine as _;
    use sha1::Digest as _;

    const UUID: &str = "55858558-5585-4558-8558-558558558558";
    let tarball = {
        let manifest = br#"{"name":"left-pad","version":"1.3.0"}"#;
        let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::default(),
        ));
        let mut header = tar::Header::new_gnu();
        header.set_size(manifest.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "package/package.json", &manifest[..])
            .unwrap();
        builder.into_inner().unwrap().finish().unwrap()
    };
    let sha512 = format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode(sha2::Sha512::digest(&tarball))
    );
    let sha1 = hex::encode(sha1::Sha1::digest(&tarball));
    let mut files = BTreeMap::new();
    files.insert(
        "package.json".to_string(),
        b"{\n  \"name\": \"app\",\n  \"version\": \"1.0.0\",\n  \"packageManager\": \"yarn@1.22.22\",\n  \"dependencies\": {\n    \"left-pad\": \"1.3.0\"\n  }\n}\n".to_vec(),
    );
    files.insert(
        "yarn.lock".to_string(),
        b"# yarn lockfile v1\n\n\nleft-pad@1.3.0:\n  version \"1.3.0\"\n  \
          resolved \"https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz\"\n  \
          integrity sha512-UP==\n"
            .to_vec(),
    );

    for served in [true, false] {
        let server = MockServer::start().await;
        let artifact = format!("/patch/npm/left-pad/1.3.0/tok/{UUID}/left-pad-1.3.0.tgz");
        let url = format!("{}{artifact}", server.uri());
        let patch = common::Patch {
            purl: "pkg:npm/left-pad@1.3.0".into(),
            uuid: UUID.into(),
            reference: serde_json::json!({
                "status": "granted",
                "url": url,
                "purl": null,
                "artifacts": [
                    { "kind": "tarball", "url": url, "integrity": { "sha512": sha512 } }
                ],
                "registryOverride": null,
            }),
        };
        mount_api(&server, &[patch]).await;
        Mock::given(method("GET"))
            .and(path(artifact))
            .respond_with(if served {
                ResponseTemplate::new(200).set_body_bytes(tarball.clone())
            } else {
                ResponseTemplate::new(404)
            })
            .mount(&server)
            .await;

        let output = run_engine(&server, build_input(&files, &[], options(false))).await;
        let project = &output.projects[0];
        assert!(project.error.is_none(), "{:?}", project.error);
        let changed = engine_changed(&output);
        if served {
            assert_eq!(project.redirected.len(), 1, "{:?}", project.skipped);
            let lock = String::from_utf8(changed["yarn.lock"].clone()).unwrap();
            assert!(
                lock.contains(&format!(
                    "  resolved \"{url}#{sha1}\"\n  integrity {sha512}\n"
                )),
                "{lock}"
            );
        } else {
            assert!(project.redirected.is_empty(), "{:?}", project.redirected);
            assert!(
                project
                    .skipped
                    .iter()
                    .any(|s| s.reason == "npm_tarball_unavailable"),
                "{:?}",
                project.skipped
            );
            assert!(!changed.contains_key("yarn.lock"), "{changed:?}");
        }
    }
}

/// #734 in memory: with no node_modules in the view, package.json's
/// `packageManager` is the only pin. pnpm 9.15.9 gets its lock pinned and
/// no root-only pnpm-workspace.yaml; pnpm 11 still gets the trust scaffold.
#[tokio::test]
async fn pnpm_9_pin_gets_no_root_only_workspace_in_memory() {
    let dir = fixtures_root().join("redirect/npm/pnpm/basic");
    let server = MockServer::start().await;
    mount_api(
        &server,
        &patches_from_overrides(&dir.join("overrides.json"), None),
    )
    .await;
    for (pin, scaffold) in [("9.15.9", false), ("11.0.0", true)] {
        let mut files = fixture_files(&dir.join("input"));
        files.insert(
            "package.json".into(),
            format!(r#"{{"name":"app","packageManager":"pnpm@{pin}"}}"#).into_bytes(),
        );
        let output = run_engine(&server, build_input(&files, &[], options(false))).await;
        let project = &output.projects[0];
        assert!(project.error.is_none(), "{:?}", project.error);
        let paths: Vec<&str> = output
            .changed_files
            .iter()
            .map(|f| f.path.as_str())
            .collect();
        assert!(paths.contains(&"pnpm-lock.yaml"), "{paths:?}");
        assert_eq!(
            paths.contains(&"pnpm-workspace.yaml"),
            scaffold,
            "{pin}: {paths:?}"
        );
        let warnings = project.redirect["warnings"].to_string();
        assert_eq!(
            warnings.contains("ERR_PNPM_ADDING_TO_ROOT"),
            !scaffold,
            "{warnings}"
        );
    }
}

/// #492 in memory: the lock of a `sharedWorkspaceLockfile: false` pnpm
/// workspace member is demoted into the workspace root, which pins it and
/// trusts it in its own pnpm-workspace.yaml (the only one pnpm reads),
/// never in a nested scaffold. A project the root file does not list
/// stays a standalone root. A member named alone as a project root is not
/// pinned on its own; a warning names the workspace root to scan.
#[tokio::test]
async fn a_pnpm_workspace_member_lock_is_demoted_into_the_workspace_root_in_memory() {
    let dir = fixtures_root().join("redirect/npm/pnpm/basic");
    let server = MockServer::start().await;
    mount_api(
        &server,
        &patches_from_overrides(&dir.join("overrides.json"), None),
    )
    .await;
    let mut member = prefixed("packages/a", &fixture_files(&dir.join("input")));
    member.insert("packages/a/package.json".into(), b"{}".to_vec());
    for (globs, listed) in [("packages/*", true), ("tools/*", false)] {
        let mut files = member.clone();
        files.insert(
            "pnpm-workspace.yaml".into(),
            format!("packages:\n  - {globs}\nsharedWorkspaceLockfile: false\n").into_bytes(),
        );
        files.insert(
            "pnpm-lock.yaml".into(),
            b"lockfileVersion: '9.0'\n\nimporters:\n\n  .: {}\n".to_vec(),
        );
        let output = run_engine(&server, build_input(&files, &[], options(false))).await;
        let roots: Vec<&str> = output.projects.iter().map(|p| p.root.as_str()).collect();
        let paths: Vec<&str> = output
            .changed_files
            .iter()
            .map(|f| f.path.as_str())
            .collect();
        assert!(
            output.projects.iter().all(|p| p.error.is_none()),
            "{:?}",
            output.projects
        );
        assert!(paths.contains(&"packages/a/pnpm-lock.yaml"), "{paths:?}");
        if listed {
            assert_eq!(roots, [""]);
            assert!(paths.contains(&"pnpm-workspace.yaml"), "{paths:?}");
            assert!(
                !paths.contains(&"packages/a/pnpm-workspace.yaml"),
                "{paths:?}"
            );
        } else {
            assert_eq!(roots, ["", "packages/a"]);
            assert!(
                paths.contains(&"packages/a/pnpm-workspace.yaml"),
                "a standalone project gets its own file: {paths:?}"
            );
        }
        // The trust auto-config off pins the lock without any scaffold.
        let mut opts = options(false);
        opts.trust_lockfile_config = Some(false);
        let output = run_engine(&server, build_input(&files, &[], opts)).await;
        let paths: Vec<&str> = output
            .changed_files
            .iter()
            .map(|f| f.path.as_str())
            .collect();
        assert_eq!(paths, ["packages/a/pnpm-lock.yaml"]);

        // The member named alone: its lock is the workspace root's.
        let mut opts = options(false);
        opts.project_roots = Some(vec!["packages/a".into()]);
        let output = run_engine(&server, build_input(&files, &[], opts)).await;
        let ignored = output
            .warnings
            .iter()
            .any(|w| w.code == "pnpm_member_lock_ignored");
        assert_eq!(ignored, listed, "{:?}", output.warnings);
        assert_eq!(output.changed_files.is_empty(), listed);
    }
}

/// Path selection fetches the nearest ancestor pnpm-workspace.yaml of a
/// pnpm root that has none of its own, so the session can tell a member
/// from a standalone project.
#[test]
fn selection_fetches_the_governing_pnpm_workspace_file() {
    let blob = |path: &str| TreeEntryInput {
        path: path.into(),
        mode: "100644".into(),
        kind: "blob".into(),
        size: Some(10),
    };
    let entries = vec![
        blob("pnpm-workspace.yaml"),
        blob("packages/pnpm-workspace.yaml"),
        blob("packages/a/pnpm-lock.yaml"),
        blob("packages/a/package.json"),
        blob("tools/b/pnpm-lock.yaml"),
    ];
    let s = select_paths(&entries, &SelectOptions::default());
    assert!(
        s.fetch_text
            .iter()
            .any(|p| p == "packages/pnpm-workspace.yaml"),
        "{:?}",
        s.fetch_text
    );
    assert!(
        s.fetch_text.iter().any(|p| p == "pnpm-workspace.yaml"),
        "{:?}",
        s.fetch_text
    );
}

/// #734 re-scan: a project pinned to pnpm 9.0–10.4 that still carries the
/// root-only scaffold an earlier run created is told to delete it; a
/// workspace file the user wrote (or one in a pnpm 11 project) is not.
#[tokio::test]
async fn a_leftover_root_only_scaffold_on_pnpm_9_is_flagged() {
    let dir = fixtures_root().join("redirect/npm/pnpm/basic");
    let server = MockServer::start().await;
    mount_api(
        &server,
        &patches_from_overrides(&dir.join("overrides.json"), None),
    )
    .await;
    let scaffold = "packages:\n  - '.'\ntrustLockfile: true\n";
    let user = "packages:\n  - '.'\ncatalog: {}\ntrustLockfile: true\n";
    for (pin, workspace, flagged) in [
        ("9.15.9", scaffold, true),
        ("9.15.9", user, false),
        ("11.0.0", scaffold, false),
    ] {
        let mut files = fixture_files(&dir.join("input"));
        files.insert(
            "package.json".into(),
            format!(r#"{{"name":"app","packageManager":"pnpm@{pin}"}}"#).into_bytes(),
        );
        files.insert("pnpm-workspace.yaml".into(), workspace.as_bytes().to_vec());
        let output = run_engine(&server, build_input(&files, &[], options(false))).await;
        let project = &output.projects[0];
        assert!(project.error.is_none(), "{:?}", project.error);
        let warnings = project.redirect["warnings"].to_string();
        assert_eq!(
            warnings.contains("ERR_PNPM_ADDING_TO_ROOT"),
            flagged,
            "{pin} {workspace:?}: {warnings}"
        );
        assert!(
            !output
                .changed_files
                .iter()
                .any(|f| f.path == "pnpm-workspace.yaml"),
            "the file is never rewritten or removed"
        );
    }
}

/// An npm tarball holding only `package/package.json` for `name@version`.
fn npm_manifest_tgz(name: &str, version: &str) -> Vec<u8> {
    let manifest = format!(r#"{{"name":"{name}","version":"{version}"}}"#);
    let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
        Vec::new(),
        flate2::Compression::default(),
    ));
    let mut header = tar::Header::new_gnu();
    header.set_size(manifest.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder
        .append_data(&mut header, "package/package.json", manifest.as_bytes())
        .unwrap();
    builder.into_inner().unwrap().finish().unwrap()
}

/// A granted hosted left-pad@1.3.0 patch on `server` (tarball and yarn
/// berry zip artifacts), its served tarball mounted.
async fn mount_left_pad_grant(server: &MockServer, uuid: &str) {
    use base64::Engine as _;
    use sha2::Digest as _;
    let tarball = npm_manifest_tgz("left-pad", "1.3.0");
    let sha512 = format!(
        "sha512-{}",
        base64::engine::general_purpose::STANDARD.encode(sha2::Sha512::digest(&tarball))
    );
    let artifact = format!("/patch/npm/left-pad/1.3.0/tok/{uuid}/left-pad-1.3.0.tgz");
    let url = format!("{}{artifact}", server.uri());
    let patch = common::Patch {
        purl: "pkg:npm/left-pad@1.3.0".into(),
        uuid: uuid.into(),
        reference: serde_json::json!({
            "status": "granted",
            "url": url,
            "purl": null,
            "artifacts": [
                { "kind": "tarball", "url": url, "integrity": { "sha512": sha512 } },
                { "kind": "yarn-berry-zip", "url": url,
                  "integrity": { "yarnBerry10c0": format!("10c0/{}", "7".repeat(128)) } }
            ],
            "registryOverride": null,
        }),
    };
    mount_api(server, &[patch]).await;
    Mock::given(method("GET"))
        .and(path(artifact))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(tarball))
        .mount(server)
        .await;
}

/// The `redirect_copy_unpatched` warnings a project's redirect reports.
fn copy_unpatched_details(project: &socket_patch_cli::hosted_memory::ProjectResult) -> Vec<String> {
    project.redirect["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|w| w["code"] == "redirect_copy_unpatched")
        .map(|w| w["detail"].as_str().unwrap().to_string())
        .collect()
}

/// #1236 follow-up: yarn 1 locks a `file:` TARBALL declared under another
/// dependency name (`"lp2": "file:./forks/left-pad-1.3.0.tgz"`) as
/// `lp2@file:…` and installs it as `node_modules/lp2`, which is
/// left-pad@1.3.0 and stays unpatched whatever the pin does. The hosted
/// scan still pins the registry block, and now names that copy (the
/// tarball's own `package.json` says which package it is). Control: a
/// tarball holding another package is not named.
#[tokio::test]
async fn issue_1236_classic_renamed_file_tarball_copy_is_named() {
    const UUID: &str = "12361236-1236-4236-8236-123612361236";
    let key = "\"lp2@file:./forks/left-pad-1.3.0.tgz\"";
    for (fork, named) in [("left-pad", true), ("other-pkg", false)] {
        let server = MockServer::start().await;
        mount_left_pad_grant(&server, UUID).await;
        let mut files = BTreeMap::new();
        files.insert(
            "package.json".to_string(),
            br#"{"name":"app","version":"1.0.0","packageManager":"yarn@1.22.22","dependencies":{"left-pad":"1.3.0","lp2":"file:./forks/left-pad-1.3.0.tgz"}}"#.to_vec(),
        );
        files.insert(
            "yarn.lock".to_string(),
            format!(
                "# yarn lockfile v1\n\n\nleft-pad@1.3.0:\n  version \"1.3.0\"\n  \
                 resolved \"https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz#{}\"\n  \
                 integrity sha512-UP==\n\n{key}:\n  version \"1.3.0\"\n  \
                 resolved \"file:./forks/left-pad-1.3.0.tgz#{}\"\n",
                "a".repeat(40),
                "b".repeat(40),
            )
            .into_bytes(),
        );
        files.insert(
            "forks/left-pad-1.3.0.tgz".to_string(),
            npm_manifest_tgz(fork, "1.3.0"),
        );
        let output = run_engine(&server, build_input(&files, &[], options(false))).await;
        let project = &output.projects[0];
        assert!(project.error.is_none(), "{:?}", project.error);
        assert_eq!(project.redirected.len(), 1, "{fork}: {:?}", project.skipped);
        let details = copy_unpatched_details(project);
        if named {
            assert_eq!(details.len(), 1, "{:#}", project.redirect);
            assert!(
                details[0].contains(&format!("`{key}`")) && details[0].contains("UNPATCHED"),
                "{}",
                details[0]
            );
        } else {
            assert!(details.is_empty(), "{details:?}");
        }
    }
}

/// #939: yarn berry keys a `file:` tarball / directory, a url tarball and
/// a `portal:` / `link:` dependency by the DEPENDENCY name (`lp2@…`), so a
/// copy of left-pad@1.3.0 under another name escapes the `resolutions` pin
/// and installs unpatched. The hosted scan still pins the registry entry,
/// and now names that copy instead of reporting a clean success. Control:
/// a `file:` / `portal:` copy holding another package is not named.
#[tokio::test]
async fn issue_939_berry_renamed_copy_is_named() {
    const UUID: &str = "93939393-9393-4393-8393-939393939393";
    let ws = "app%40workspace%3A.";
    let url = "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz";
    // (case, manifest spec, lock key, lock version, resolution)
    let cases = [
        (
            "file: tarball",
            "file:./forks/left-pad-1.3.0.tgz".to_string(),
            format!("lp2@file:./forks/left-pad-1.3.0.tgz::locator={ws}"),
            "1.3.0",
            format!(
                "lp2@file:./forks/left-pad-1.3.0.tgz#./forks/left-pad-1.3.0.tgz::hash=5c8e4c&locator={ws}"
            ),
        ),
        (
            "file: directory",
            "file:./forks/left-pad".to_string(),
            format!("lp2@file:./forks/left-pad::locator={ws}"),
            "1.3.0",
            format!("lp2@file:./forks/left-pad#./forks/left-pad::hash=1a2b3c&locator={ws}"),
        ),
        (
            "registry tarball url",
            url.to_string(),
            format!("lp2@{url}"),
            "1.3.0",
            format!("lp2@{url}"),
        ),
        (
            "portal:",
            "portal:./forks/left-pad".to_string(),
            format!("lp2@portal:./forks/left-pad::locator={ws}"),
            "0.0.0-use.local",
            format!("lp2@portal:./forks/left-pad::locator={ws}"),
        ),
        (
            "link:",
            "link:./forks/left-pad".to_string(),
            format!("lp2@link:./forks/left-pad::locator={ws}"),
            "0.0.0-use.local",
            format!("lp2@link:./forks/left-pad::locator={ws}"),
        ),
    ];
    for (case, spec, key, version, resolution) in &cases {
        for fork in ["left-pad", "other-pkg"] {
            let named = fork == "left-pad" || case.contains("url");
            let server = MockServer::start().await;
            mount_left_pad_grant(&server, UUID).await;
            let mut files = BTreeMap::new();
            files.insert(
                "package.json".to_string(),
                format!(
                    r#"{{"name":"app","version":"1.0.0","dependencies":{{"left-pad":"^1.3.0","lp2":"{spec}"}}}}"#
                )
                .into_bytes(),
            );
            files.insert(
                "yarn.lock".to_string(),
                format!(
                    "__metadata:\n  version: 8\n  cacheKey: 10c0\n\n\
                     \"app@workspace:.\":\n  version: 0.0.0-use.local\n  \
                     resolution: \"app@workspace:.\"\n  dependencies:\n    \
                     left-pad: \"npm:^1.3.0\"\n    lp2: \"{spec}\"\n  \
                     languageName: unknown\n  linkType: soft\n\n\
                     \"left-pad@npm:^1.3.0\":\n  version: 1.3.0\n  \
                     resolution: \"left-pad@npm:1.3.0\"\n  checksum: 10c0/{}\n  \
                     languageName: node\n  linkType: hard\n\n\
                     \"{key}\":\n  version: {version}\n  resolution: \"{resolution}\"\n  \
                     languageName: node\n  linkType: hard\n",
                    "1".repeat(128)
                )
                .into_bytes(),
            );
            files.insert(
                "forks/left-pad-1.3.0.tgz".to_string(),
                npm_manifest_tgz(fork, "1.3.0"),
            );
            files.insert(
                "forks/left-pad/package.json".to_string(),
                format!(r#"{{"name":"{fork}","version":"1.3.0"}}"#).into_bytes(),
            );
            let output = run_engine(&server, build_input(&files, &[], options(false))).await;
            let project = &output.projects[0];
            assert!(project.error.is_none(), "{case}: {:?}", project.error);
            assert_eq!(
                project.redirected.len(),
                1,
                "{case}/{fork}: {:?} {:#}",
                project.skipped,
                project.redirect
            );
            let details = copy_unpatched_details(project);
            if named {
                assert_eq!(details.len(), 1, "{case}/{fork}: {:#}", project.redirect);
                assert!(
                    details[0].contains(key.as_str()) && details[0].contains("UNPATCHED"),
                    "{case}: {}",
                    details[0]
                );
            } else {
                assert!(details.is_empty(), "{case}/{fork}: {details:?}");
            }
        }
    }
}

/// Run the hosted engine over a berry project that depends on left-pad
/// from the registry and on `lp2` through the `portal:` / `link:` `spec`,
/// plus `extra` files, and return its `redirect_copy_unpatched` details
/// (after checking the registry entry is still pinned).
async fn berry_linked_copy_details(uuid: &str, spec: &str, extra: &[(&str, &str)]) -> Vec<String> {
    let server = MockServer::start().await;
    mount_left_pad_grant(&server, uuid).await;
    let mut files = berry_linked_copy_files(spec);
    for (rel, text) in extra {
        files.insert(rel.to_string(), text.as_bytes().to_vec());
    }
    let output = run_engine(&server, build_input(&files, &[], options(false))).await;
    let project = &output.projects[0];
    assert!(project.error.is_none(), "{spec}: {:?}", project.error);
    assert_eq!(
        project.redirected.len(),
        1,
        "{spec}: {:?} {:#}",
        project.skipped,
        project.redirect
    );
    copy_unpatched_details(project)
}

/// A berry project depending on registry left-pad and on `lp2` at `spec`.
fn berry_linked_copy_files(spec: &str) -> BTreeMap<String, Vec<u8>> {
    let ws = "app%40workspace%3A.";
    let key = format!("lp2@{spec}::locator={ws}");
    let mut files = BTreeMap::new();
    files.insert(
        "package.json".to_string(),
        format!(
            r#"{{"name":"app","version":"1.0.0","dependencies":{{"left-pad":"^1.3.0","lp2":"{spec}"}}}}"#
        )
        .into_bytes(),
    );
    files.insert(
        "yarn.lock".to_string(),
        format!(
            "__metadata:\n  version: 8\n  cacheKey: 10c0\n\n\
             \"app@workspace:.\":\n  version: 0.0.0-use.local\n  \
             resolution: \"app@workspace:.\"\n  dependencies:\n    \
             left-pad: \"npm:^1.3.0\"\n    lp2: \"{spec}\"\n  \
             languageName: unknown\n  linkType: soft\n\n\
             \"left-pad@npm:^1.3.0\":\n  version: 1.3.0\n  \
             resolution: \"left-pad@npm:1.3.0\"\n  checksum: 10c0/{}\n  \
             languageName: node\n  linkType: hard\n\n\
             \"{key}\":\n  version: 0.0.0-use.local\n  resolution: \"{key}\"\n  \
             languageName: node\n  linkType: soft\n",
            "1".repeat(128)
        )
        .into_bytes(),
    );
    files
}

/// #1540: a berry `portal:` / `link:` copy with an ABSOLUTE path is never
/// read (#1516), and its lock version is the placeholder
/// `0.0.0-use.local`, so it may be any version of any package. The hosted
/// scan still pins the registry entry, and names that copy as possibly
/// unpatched (`redirect_copy_unpatched`) whatever it links to; it used to
/// report a clean success while `node_modules/lp2` held unpatched bytes.
#[tokio::test]
async fn issue_1540_berry_absolute_portal_and_link_copies_are_named() {
    for protocol in ["portal", "link"] {
        let spec = format!("{protocol}:/home/me/shared/left-pad");
        let details =
            berry_linked_copy_details("15401540-1540-4540-8540-154015401540", &spec, &[]).await;
        assert_eq!(details.len(), 1, "{protocol}: {details:?}");
        assert!(
            details[0].contains(&format!("lp2@{spec}::"))
                && details[0].contains("can't be read")
                && details[0].contains("UNPATCHED"),
            "{protocol}: {}",
            details[0]
        );
    }
}

/// #1561: a berry `portal:` / `link:` copy with a RELATIVE path whose
/// target is not in the snapshot (a git submodule CI never checked out)
/// can't be read, so like an absolute one (#1540) it may be any version of
/// any package. The hosted scan still pins the registry entry, and names
/// that copy as possibly unpatched (`redirect_copy_unpatched`); it used to
/// report a clean success while the install with the submodule linked
/// unpatched bytes as `node_modules/lp2`. Control: a target whose
/// `package.json` the snapshot holds is read, so one naming another
/// package is no copy of left-pad.
#[tokio::test]
async fn issue_1561_berry_missing_relative_portal_and_link_copies_are_named() {
    const UUID: &str = "15611561-1561-4561-8561-156115611561";
    for protocol in ["portal", "link"] {
        let spec = format!("{protocol}:./vend/lp");
        let details = berry_linked_copy_details(UUID, &spec, &[]).await;
        assert_eq!(details.len(), 1, "{protocol}: {details:?}");
        assert!(
            details[0].contains(&format!("lp2@{spec}::"))
                && details[0].contains("can't be read")
                && details[0].contains("UNPATCHED"),
            "{protocol}: {}",
            details[0]
        );
        let other = [(
            "vend/lp/package.json",
            r#"{"name":"other-pkg","version":"1.3.0"}"#,
        )];
        let details = berry_linked_copy_details(UUID, &spec, &other).await;
        assert!(details.is_empty(), "{protocol}: {details:?}");
    }
}

/// #1579: a `portal:` target holding only a `.gitkeep` placeholder (yarn
/// refuses a manifest-less portal, so it is not what gets installed), and a
/// linked manifest with no `name`, may be any package; one naming left-pad
/// with no version may be left-pad. The hosted scan pins the registry entry
/// and names each as possibly unpatched; it reported a clean success.
/// Controls: a `link:` to the placeholder (plain assets) and a versionless
/// manifest naming another package are no copy of left-pad.
#[tokio::test]
async fn issue_1579_berry_portal_placeholder_and_versionless_copies_are_named() {
    const UUID: &str = "15791579-1579-4579-8579-157915791579";
    for protocol in ["portal", "link"] {
        let spec = format!("{protocol}:./vend/lp");
        for (file, text, named) in [
            ("vend/lp/.gitkeep", "", protocol == "portal"),
            ("vend/lp/package.json", r#"{"version":"1.3.0"}"#, true),
            ("vend/lp/package.json", r#"{"name":"left-pad"}"#, true),
            ("vend/lp/package.json", r#"{"name":"other-pkg"}"#, false),
        ] {
            let details = berry_linked_copy_details(UUID, &spec, &[(file, text)]).await;
            if !named {
                assert!(details.is_empty(), "{protocol} {text:?}: {details:?}");
                continue;
            }
            assert_eq!(details.len(), 1, "{protocol} {text:?}: {details:?}");
            assert!(
                details[0].contains(&format!("lp2@{spec}::")) && details[0].contains("UNPATCHED"),
                "{protocol} {text:?}: {}",
                details[0]
            );
        }
    }
}

/// #1598: a linked manifest whose `name` is empty or no valid npm name
/// names no package, and one whose `version` is empty or no semver names
/// no version, exactly like a missing key (#1579). The hosted scan read
/// them literally ("a package called `""`", "another version"), reported a
/// clean success, and its in-run VEX attested `not_affected` while yarn
/// linked unpatched left-pad as `node_modules/lp2`. Now each is named.
#[tokio::test]
async fn issue_1598_berry_invalid_manifest_name_or_version_is_named() {
    const UUID: &str = "15981598-1598-4598-8598-159815981598";
    for protocol in ["portal", "link"] {
        let spec = format!("{protocol}:./vend/lp");
        for text in [
            r#"{"name":"","version":"1.3.0"}"#,
            r#"{"name":"../x","version":"1.3.0"}"#,
            r#"{"name":" left-pad","version":"1.3.0"}"#,
            r#"{"name":"left-pad","version":""}"#,
            r#"{"name":"left-pad","version":"v1.3.0"}"#,
        ] {
            let details =
                berry_linked_copy_details(UUID, &spec, &[("vend/lp/package.json", text)]).await;
            assert_eq!(details.len(), 1, "{protocol} {text}: {details:?}");
            assert!(
                details[0].contains(&format!("lp2@{spec}::")) && details[0].contains("UNPATCHED"),
                "{protocol} {text}: {}",
                details[0]
            );
        }
    }
}

/// #1598 on disk: the real binary's `scan --mode hosted` over the same
/// project names the copy too, not only the in-memory engine.
#[tokio::test]
async fn issue_1598_berry_invalid_manifest_name_or_version_is_named_on_disk() {
    const UUID: &str = "15981598-1598-4598-8598-159815981598";
    for text in [
        r#"{"name":"","version":"1.3.0"}"#,
        r#"{"name":"../x","version":"1.3.0"}"#,
        r#"{"name":"left-pad","version":""}"#,
    ] {
        let server = MockServer::start().await;
        mount_left_pad_grant(&server, UUID).await;
        let mut files = berry_linked_copy_files("portal:./vend/lp");
        files.insert("vend/lp/package.json".to_string(), text.as_bytes().to_vec());
        let disk = run_disk(&server, &files, false);
        let warnings = disk.redirect["warnings"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert!(
            warnings
                .iter()
                .any(|w| w["code"] == "redirect_copy_unpatched"
                    && w["detail"]
                        .as_str()
                        .is_some_and(|d| d.contains("UNPATCHED"))),
            "{text}: {:#}",
            disk.envelope
        );
    }
}

/// #1630: a berry `exec:` script, or a git remote that isn't http(s),
/// under another dependency name installs `node_modules/lp2` from a
/// package the lock doesn't name, at its lock version. It may be the
/// pinned left-pad@1.3.0, so the hosted scan names it as possibly
/// unpatched (`redirect_copy_unpatched`); it used to report a clean
/// success while yarn installed unpatched left-pad as `node_modules/lp2`.
/// Control: the same copy at another version is no copy of 1.3.0.
#[tokio::test]
async fn issue_1630_berry_exec_and_git_copies_are_named() {
    const UUID: &str = "16301630-1630-4630-8630-163016301630";
    let ws = "app%40workspace%3A.";
    for (spec, key, resolution) in [
        (
            "exec:./gen.js",
            format!("lp2@exec:./gen.js::locator={ws}"),
            format!("lp2@exec:./gen.js#./gen.js::hash=db115a&locator={ws}"),
        ),
        (
            "git+ssh://git@github.com/stevemao/left-pad.git#v1.3.0",
            "lp2@git+ssh://git@github.com/stevemao/left-pad.git#v1.3.0".to_string(),
            "lp2@git+ssh://git@github.com/stevemao/left-pad.git#commit=5d3c4f2".to_string(),
        ),
    ] {
        for (version, named) in [("1.3.0", true), ("2.0.0", false)] {
            let server = MockServer::start().await;
            mount_left_pad_grant(&server, UUID).await;
            let mut files = berry_linked_copy_files(spec);
            let lock = String::from_utf8(files["yarn.lock"].clone()).unwrap();
            let linked = format!(
                "\"lp2@{spec}::locator={ws}\":\n  version: 0.0.0-use.local\n  \
                 resolution: \"lp2@{spec}::locator={ws}\"\n  \
                 languageName: node\n  linkType: soft\n"
            );
            assert!(lock.contains(&linked), "{lock}");
            let lock = lock.replace(
                &linked,
                &format!(
                    "\"{key}\":\n  version: {version}\n  resolution: \"{resolution}\"\n  \
                     languageName: node\n  linkType: hard\n"
                ),
            );
            files.insert("yarn.lock".to_string(), lock.into_bytes());
            let output = run_engine(&server, build_input(&files, &[], options(false))).await;
            let project = &output.projects[0];
            assert!(project.error.is_none(), "{spec}: {:?}", project.error);
            assert_eq!(
                project.redirected.len(),
                1,
                "{spec}: {:?} {:#}",
                project.skipped,
                project.redirect
            );
            let details = copy_unpatched_details(project);
            if !named {
                assert!(details.is_empty(), "{spec}@{version}: {details:?}");
                continue;
            }
            assert_eq!(details.len(), 1, "{spec}@{version}: {details:?}");
            assert!(
                details[0].contains(&key) && details[0].contains("UNPATCHED"),
                "{spec}: {}",
                details[0]
            );
        }
    }
}
