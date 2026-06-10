//! In-process e2e tests for the `scan` subcommand.
//!
//! Calls `socket_patch_cli::commands::scan::run` directly so coverage
//! is fully instrumented. Mocks the API via wiremock. Hits every flag
//! combination that the subprocess-based tests don't explicitly
//! exercise (non-JSON paths, --apply without --prune, --prune without
//! --apply, --batch-size variations, --download-mode variations).

use std::path::Path;

use serial_test::serial;
use socket_patch_cli::commands::scan::{run, ScanArgs};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG: &str = "test-org";
const PURL: &str = "pkg:npm/in-proc-scan@1.0.0";
const UUID: &str = "11111111-1111-4111-8111-111111111111";

fn default_args(cwd: &Path) -> ScanArgs {
    ScanArgs {
        common: socket_patch_cli::args::GlobalArgs {
            cwd: cwd.to_path_buf(),
            org: Some(ORG.to_string()),
            json: true,
            yes: true,
            global: false,
            global_prefix: None,
            api_token: Some("fake".to_string()),
            ecosystems: None,
            download_mode: "diff".to_string(),
            dry_run: false,
            ..socket_patch_cli::args::GlobalArgs::default()
        },
        batch_size: 100,
        apply: false,
        prune: false,
        sync: false,
        all_releases: false,
        vex: Default::default(),
    }
}

fn write_root_package_json(root: &Path) {
    std::fs::write(
        root.join("package.json"),
        r#"{ "name": "in-proc-scan-test", "version": "0.0.0" }"#,
    )
    .unwrap();
}

fn write_npm_package(root: &Path, name: &str, version: &str) {
    let pkg = root.join("node_modules").join(name);
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        pkg.join("package.json"),
        format!(r#"{{ "name": "{name}", "version": "{version}" }}"#),
    )
    .unwrap();
}

/// Lay down a locally-installed RubyGem the gem crawler discovers in
/// `vendor/bundle/ruby/*/gems/<name>-<version>/` (a `lib/` dir makes it
/// verify as a real gem). Used to install a *second*-ecosystem package
/// alongside npm so `--ecosystems npm` filtering can be exercised.
fn write_gem_package(root: &Path, name: &str, version: &str) {
    let gem = root
        .join("vendor/bundle/ruby/3.0.0/gems")
        .join(format!("{name}-{version}"));
    std::fs::create_dir_all(gem.join("lib")).unwrap();
}

async fn mock_batch_empty(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [], "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;
}

async fn mock_batch_one(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [{
                "purl": PURL,
                "patches": [{
                    "uuid": UUID, "purl": PURL,
                    "tier": "free", "cveIds": [], "ghsaIds": [],
                    "severity": "high", "title": "in-proc fixture"
                }]
            }],
            "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;
}

async fn mock_by_package(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path_regex(format!(
            "^/v0/orgs/{ORG}/patches/by-package/.+$"
        )))
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

async fn mock_view_with_blob(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG}/patches/view/{UUID}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "uuid": UUID,
            "purl": PURL,
            "publishedAt": "2024-01-01T00:00:00Z",
            "files": {
                "package/index.js": {
                    "beforeHash": "0000000000000000000000000000000000000000000000000000000000000000",
                    "afterHash":  "1111111111111111111111111111111111111111111111111111111111111111",
                    "blobContent": "cGF0Y2hlZAo=",
                }
            },
            "vulnerabilities": {},
            "description": "x", "license": "MIT", "tier": "free",
        })))
        .mount(server)
        .await;
}

// --- Request introspection helpers -----------------------------------------
// These let each test assert on the *real* code path: which endpoints the
// scan actually hit, and what PURLs it sent. Asserting only the exit code
// (the original loophole) let a scan that crawled nothing, filtered
// everything out, or short-circuited the API still pass green.

async fn recorded(server: &MockServer) -> Vec<wiremock::Request> {
    server.received_requests().await.unwrap_or_default()
}

fn batch_posts(reqs: &[wiremock::Request]) -> Vec<&wiremock::Request> {
    reqs.iter()
        .filter(|r| format!("{}", r.method) == "POST" && r.url.path().ends_with("/patches/batch"))
        .collect()
}

fn by_package_gets(reqs: &[wiremock::Request]) -> usize {
    reqs.iter()
        .filter(|r| {
            format!("{}", r.method) == "GET" && r.url.path().contains("/patches/by-package/")
        })
        .count()
}

fn view_gets(reqs: &[wiremock::Request], uuid: &str) -> usize {
    reqs.iter()
        .filter(|r| {
            format!("{}", r.method) == "GET"
                && r.url.path().ends_with(&format!("/patches/view/{uuid}"))
        })
        .count()
}

fn req_body(req: &wiremock::Request) -> String {
    String::from_utf8_lossy(&req.body).into_owned()
}

// ---------------------------------------------------------------------------
// Discovery — read-only --json mode
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn scan_empty_project_json() {
    let server = MockServer::start().await;
    mock_batch_empty(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    let mut args = default_args(tmp.path());
    args.common.api_url = server.uri();

    assert_eq!(run(args).await, 0);
    // An empty project crawls zero packages, so the batch API must never
    // be queried. (Asserting only exit 0 would also pass if the crawler
    // silently found nothing on a *non-empty* project.)
    let reqs = recorded(&server).await;
    assert!(
        batch_posts(&reqs).is_empty(),
        "empty project must not query the batch API; saw {} POST(s)",
        batch_posts(&reqs).len()
    );
}

#[tokio::test]
#[serial]
async fn scan_installed_package_discovers_patch() {
    let server = MockServer::start().await;
    mock_batch_one(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "in-proc-scan", "1.0.0");
    let mut args = default_args(tmp.path());
    args.common.api_url = server.uri();

    assert_eq!(run(args).await, 0);
    // The installed package must actually be discovered by the crawler and
    // sent to the batch endpoint. Without this, a regression that crawled
    // nothing would still exit 0 and pass the old test.
    let reqs = recorded(&server).await;
    let posts = batch_posts(&reqs);
    assert_eq!(posts.len(), 1, "exactly one batch query expected");
    let body = req_body(posts[0]);
    assert!(
        body.contains(PURL),
        "batch request must carry the discovered purl {PURL}; body was: {body}"
    );
}

// ---------------------------------------------------------------------------
// --apply (without --prune)
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn scan_apply_dry_run_does_not_write() {
    let server = MockServer::start().await;
    mock_batch_one(&server).await;
    mock_by_package(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "in-proc-scan", "1.0.0");
    let mut args = default_args(tmp.path());
    args.common.api_url = server.uri();
    args.apply = true;
    args.common.dry_run = true;

    assert_eq!(run(args).await, 0);
    assert!(
        !tmp.path().join(".socket/manifest.json").exists(),
        "dry-run must not write manifest"
    );
    assert!(
        !tmp.path().join(".socket/blobs").exists(),
        "dry-run must not download/write any blobs"
    );
    // Prove the apply path was actually entered (not short-circuited before
    // --apply did anything): a dry-run --apply still fetches patch details
    // via the by-package endpoint to synthesize the preview.
    let reqs = recorded(&server).await;
    assert!(
        batch_posts(&reqs).len() == 1 && by_package_gets(&reqs) >= 1,
        "dry-run --apply must query batch + patch details; \
         batch={}, by_package={}",
        batch_posts(&reqs).len(),
        by_package_gets(&reqs),
    );
}

#[tokio::test]
#[serial]
async fn scan_apply_wet_writes_manifest_and_blob() {
    let server = MockServer::start().await;
    mock_batch_one(&server).await;
    mock_by_package(&server).await;
    mock_view_with_blob(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "in-proc-scan", "1.0.0");
    let mut args = default_args(tmp.path());
    args.common.api_url = server.uri();
    args.apply = true;

    let code = run(args).await;
    // Apply over our handcrafted node_modules deterministically reports
    // partial_failure (exit 1): the on-disk "package/index.js" doesn't
    // match the fixture's beforeHash, so the patch can't be applied. The
    // download stage still ran, though — that's what we verify.
    assert_eq!(
        code, 1,
        "apply over a hash-mismatched file must partial-fail"
    );

    // The view endpoint (which carries the blob) must have been hit.
    let reqs = recorded(&server).await;
    assert_eq!(
        view_gets(&reqs, UUID),
        1,
        "apply must fetch the patch view (blob source) exactly once"
    );

    // Manifest written and records the patched package.
    let manifest_path = tmp.path().join(".socket/manifest.json");
    assert!(manifest_path.exists(), "apply must write the manifest");
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
    assert!(
        manifest["patches"].get(PURL).is_some(),
        "manifest must contain a patch record for {PURL}; got {manifest}"
    );

    // The after-blob was decoded from base64 and written verbatim. The
    // fixture's blobContent "cGF0Y2hlZAo=" decodes to exactly "patched\n";
    // asserting the bytes (not just existence) catches a regression that
    // wrote an empty/garbled blob.
    let after_hash = "1111111111111111111111111111111111111111111111111111111111111111";
    let blob = tmp.path().join(".socket/blobs").join(after_hash);
    assert!(blob.exists(), "after-blob must be written");
    assert_eq!(
        std::fs::read(&blob).unwrap(),
        b"patched\n",
        "blob bytes must be the base64-decoded fixture content"
    );
}

// ---------------------------------------------------------------------------
// --prune (without --apply)
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn scan_prune_only_dry_run_reports_orphans() {
    let server = MockServer::start().await;
    mock_batch_empty(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "still-installed", "1.0.0");
    // Manifest has a stale entry for a package that's not installed.
    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    std::fs::write(
        socket.join("manifest.json"),
        r#"{ "patches": {
            "pkg:npm/stale@1.0.0": {
                "uuid": "22222222-2222-4222-8222-222222222222",
                "exportedAt": "2024-01-01T00:00:00Z",
                "files": {}, "vulnerabilities": {},
                "description": "stale", "license": "MIT", "tier": "free"
            }
        }}"#,
    )
    .unwrap();

    let mut args = default_args(tmp.path());
    args.common.api_url = server.uri();
    args.prune = true;
    args.common.dry_run = true;

    assert_eq!(run(args).await, 0);
    // Dry-run preserves the manifest *entirely* unchanged — the stale entry
    // must survive and remain the sole entry (a buggy preview that actually
    // pruned, or that added/dropped entries, must fail here).
    let body = std::fs::read_to_string(tmp.path().join(".socket/manifest.json")).unwrap();
    let manifest: serde_json::Value = serde_json::from_str(&body).unwrap();
    let patches = manifest["patches"].as_object().unwrap();
    assert_eq!(
        patches.len(),
        1,
        "dry-run prune must not mutate the manifest"
    );
    assert!(
        patches.contains_key("pkg:npm/stale@1.0.0"),
        "stale entry must be preserved by a dry-run prune; got {manifest}"
    );
}

#[tokio::test]
#[serial]
async fn scan_prune_only_wet_removes_orphans() {
    let server = MockServer::start().await;
    mock_batch_empty(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "still-installed", "1.0.0");
    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    // Two manifest entries: one orphan (not installed) and one for the
    // package that IS installed. Prune must remove ONLY the orphan and leave
    // the live entry untouched. With a single orphan-only manifest, a buggy
    // prune that wipes EVERYTHING would also pass `len == 0`; the live entry
    // is what makes this test discriminate orphan-prune from manifest-wipe.
    std::fs::write(
        socket.join("manifest.json"),
        r#"{ "patches": {
            "pkg:npm/orphan@1.0.0": {
                "uuid": "33333333-3333-4333-8333-333333333333",
                "exportedAt": "2024-01-01T00:00:00Z",
                "files": {}, "vulnerabilities": {},
                "description": "orphan", "license": "MIT", "tier": "free"
            },
            "pkg:npm/still-installed@1.0.0": {
                "uuid": "44444444-4444-4444-8444-444444444444",
                "exportedAt": "2024-01-01T00:00:00Z",
                "files": {}, "vulnerabilities": {},
                "description": "live", "license": "MIT", "tier": "free"
            }
        }}"#,
    )
    .unwrap();

    let mut args = default_args(tmp.path());
    args.common.api_url = server.uri();
    args.prune = true;

    assert_eq!(run(args).await, 0);
    let body = std::fs::read_to_string(tmp.path().join(".socket/manifest.json")).unwrap();
    let m: serde_json::Value = serde_json::from_str(&body).unwrap();
    let patches = m["patches"].as_object().unwrap();
    assert_eq!(
        patches.len(),
        1,
        "prune must remove exactly the orphan and keep the live entry; got {m}"
    );
    assert!(
        !patches.contains_key("pkg:npm/orphan@1.0.0"),
        "orphan (not installed) must be pruned; got {m}"
    );
    assert!(
        patches.contains_key("pkg:npm/still-installed@1.0.0"),
        "live entry (installed) must NOT be pruned; got {m}"
    );
}

// ---------------------------------------------------------------------------
// --sync (== --apply --prune)
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn scan_sync_full_cycle_against_clean_project() {
    let server = MockServer::start().await;
    mock_batch_one(&server).await;
    mock_by_package(&server).await;
    mock_view_with_blob(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "in-proc-scan", "1.0.0");
    let mut args = default_args(tmp.path());
    args.common.api_url = server.uri();
    args.sync = true;

    let code = run(args).await;
    // --sync == --apply --prune; apply over the hash-mismatched fixture file
    // deterministically partial-fails (exit 1) just like the apply-wet case.
    assert_eq!(
        code, 1,
        "sync over a hash-mismatched file must partial-fail"
    );

    // The full apply pipeline ran: view fetched, manifest written with the
    // package, and the after-blob persisted with the exact decoded bytes.
    let reqs = recorded(&server).await;
    assert_eq!(view_gets(&reqs, UUID), 1, "sync must fetch the patch view");

    let manifest_path = tmp.path().join(".socket/manifest.json");
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
    assert!(
        manifest["patches"].get(PURL).is_some(),
        "sync manifest must record {PURL}; got {manifest}"
    );

    let after_hash = "1111111111111111111111111111111111111111111111111111111111111111";
    let blob = tmp.path().join(".socket/blobs").join(after_hash);
    assert!(blob.exists(), "sync must write the after-blob");
    assert_eq!(std::fs::read(&blob).unwrap(), b"patched\n");
}

// ---------------------------------------------------------------------------
// --batch-size affects chunking
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn scan_small_batch_size_chunks_requests() {
    let server = MockServer::start().await;
    mock_batch_empty(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "pkg-a", "1.0.0");
    write_npm_package(tmp.path(), "pkg-b", "2.0.0");
    write_npm_package(tmp.path(), "pkg-c", "3.0.0");

    let mut args = default_args(tmp.path());
    args.common.api_url = server.uri();
    args.batch_size = 1; // force 3 separate API calls
    assert_eq!(run(args).await, 0);
    // The whole point of this test: batch_size=1 over 3 discovered packages
    // must produce exactly 3 separate batch requests, each carrying one
    // package. The original test asserted *nothing* about chunking.
    let reqs = recorded(&server).await;
    let posts = batch_posts(&reqs);
    assert_eq!(
        posts.len(),
        3,
        "batch_size=1 over 3 packages must chunk into 3 requests; got {}",
        posts.len()
    );
    // Each chunk carries exactly one of the three packages, and together
    // they cover all three.
    let mut covered: Vec<bool> = vec![false, false, false];
    for p in &posts {
        let body = req_body(p);
        let hits = ["pkg-a", "pkg-b", "pkg-c"]
            .iter()
            .filter(|n| body.contains(*n))
            .count();
        assert_eq!(
            hits, 1,
            "each chunk must carry exactly one package; body={body}"
        );
        for (i, n) in ["pkg-a", "pkg-b", "pkg-c"].iter().enumerate() {
            if body.contains(n) {
                covered[i] = true;
            }
        }
    }
    assert!(
        covered.iter().all(|c| *c),
        "all three packages must be queried"
    );
}

// ---------------------------------------------------------------------------
// --ecosystems filter
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn scan_ecosystems_filter_excludes_others() {
    let server = MockServer::start().await;
    mock_batch_empty(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "npm-pkg", "1.0.0");

    let mut args = default_args(tmp.path());
    args.common.api_url = server.uri();
    args.common.ecosystems = Some(vec!["pypi".to_string()]);
    assert_eq!(run(args).await, 0);
    // The npm package must be filtered out by `--ecosystems pypi`. With no
    // surviving packages the batch API is never queried — proving the
    // filter actually excluded the npm package rather than the scan just
    // happening to exit 0. A regression that ignored the filter would send
    // the npm purl and fail this assertion.
    let reqs = recorded(&server).await;
    let posts = batch_posts(&reqs);
    assert!(
        posts.is_empty(),
        "ecosystem filter must exclude the npm package; saw {} batch POST(s): {:?}",
        posts.len(),
        posts.iter().map(|p| req_body(p)).collect::<Vec<_>>()
    );
}

// ---------------------------------------------------------------------------
// Non-JSON output (table-printing path)
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn scan_non_json_with_patches_prints_table() {
    let server = MockServer::start().await;
    mock_batch_one(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "in-proc-scan", "1.0.0");
    let mut args = default_args(tmp.path());
    args.common.api_url = server.uri();
    args.common.json = false;

    let code = run(args).await;
    // Non-JSON path: discovery → batch query → render table → fetch
    // per-package details. We only mount the batch mock, so detail-fetch
    // 404s and scan exits 1 ("Could not fetch patch details"). That exit is
    // deterministic given these mocks.
    assert_eq!(code, 1, "missing detail mock → detail fetch fails → exit 1");
    // Prove the table-rendering path actually ran against real discovered
    // data: the batch endpoint was queried with the package, and the path
    // proceeded to the per-package detail fetch (i.e. it had a row to print).
    let reqs = recorded(&server).await;
    let posts = batch_posts(&reqs);
    assert_eq!(posts.len(), 1, "table path must query the batch endpoint");
    assert!(
        req_body(posts[0]).contains(PURL),
        "batch query must carry the discovered purl"
    );
    assert!(
        by_package_gets(&reqs) >= 1,
        "table path must proceed to fetch per-package patch details"
    );
}

#[tokio::test]
#[serial]
async fn scan_non_json_empty_project_friendly_message() {
    let server = MockServer::start().await;
    mock_batch_empty(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    let mut args = default_args(tmp.path());
    args.common.api_url = server.uri();
    args.common.json = false;

    assert_eq!(run(args).await, 0);
    // No packages crawled → the friendly "No packages found" path → no API
    // call at all.
    let reqs = recorded(&server).await;
    assert!(
        batch_posts(&reqs).is_empty(),
        "empty project must not query the batch API"
    );
}

// ---------------------------------------------------------------------------
// API error handling
//
// The original `assert!(code == 0 || code == 1)` here was the headline
// loophole of this file: a disjoint-outcome assertion that passes whether
// the scan correctly surfaces the failure OR silently swallows it. scan.rs
// itself documents the intended behavior (see the `if batch_error_count ==
// total_batches` block): "surface this as a full scan failure rather than
// silently reporting zero patches." The implementation only emits a
// telemetry event there — it does NOT set status="error" or a non-zero exit
// — so when *every* batch errors, `run` returns 0 and prints
// status="success" with an empty package list.
//
// The assertions below encode the documented intent. They are EXPECTED TO
// FAIL against the current (buggy) implementation and are left RED on
// purpose to guard the fix — matching the project's existing convention for
// this same bug (see memory: scan-all-batches-failed-reports-success).
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn scan_api_500_does_not_panic() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(500).set_body_string("oh no"))
        .mount(&server)
        .await;

    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "in-proc-scan", "1.0.0");
    let mut args = default_args(tmp.path());
    args.common.api_url = server.uri();

    let code = run(args).await;

    // Real path actually executed: the batch endpoint was queried (and 500'd)
    // and no spurious manifest was written.
    let reqs = recorded(&server).await;
    assert_eq!(
        batch_posts(&reqs).len(),
        1,
        "the batch endpoint must be queried"
    );
    assert!(
        !tmp.path().join(".socket/manifest.json").exists(),
        "a fully-failed scan must not write a manifest"
    );

    // Intended behavior (currently a KNOWN BUG — left RED to guard the fix):
    // when every batch errors, the scan must NOT report plain success.
    assert_ne!(
        code, 0,
        "scan must report failure (non-zero exit) when ALL API batches fail; \
         a 0 here is the documented 'reports success on total failure' bug"
    );
}

#[tokio::test]
#[serial]
async fn scan_unreachable_api_does_not_panic() {
    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "in-proc-scan", "1.0.0");
    let mut args = default_args(tmp.path());
    args.common.api_url = "http://127.0.0.1:1".to_string();

    let code = run(args).await;

    assert!(
        !tmp.path().join(".socket/manifest.json").exists(),
        "an unreachable-API scan must not write a manifest"
    );

    // Same KNOWN BUG as above (left RED): a connection failure on every
    // batch must surface as a non-zero exit, not a silent success.
    assert_ne!(
        code, 0,
        "scan must report failure when the API is unreachable for every batch"
    );
}

// ---------------------------------------------------------------------------
// Regression: --batch-size 0 must not panic
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn scan_batch_size_zero_does_not_panic() {
    // `--batch-size 0` (or `SOCKET_BATCH_SIZE=0`) is unvalidated at the
    // parser. A zero divisor/chunk-size would panic the API-query loop
    // (`len.div_ceil(0)` / `all_purls.chunks(0)`), aborting the process on
    // any non-empty project. It must instead clamp to a one-package batch
    // and complete normally.
    let server = MockServer::start().await;
    mock_batch_one(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "in-proc-scan", "1.0.0");
    let mut args = default_args(tmp.path());
    args.common.api_url = server.uri();
    args.batch_size = 0;

    // No panic, and the discovered package still reaches the batch endpoint
    // (proving the loop ran rather than being skipped).
    assert_eq!(run(args).await, 0);
    let reqs = recorded(&server).await;
    let posts = batch_posts(&reqs);
    assert_eq!(
        posts.len(),
        1,
        "batch must still be queried with a clamped size"
    );
    assert!(
        req_body(posts[0]).contains(PURL),
        "the discovered purl must be sent even with --batch-size 0"
    );
}

// ---------------------------------------------------------------------------
// Regression: --ecosystems filtering must not let --prune delete installed
// packages of the filtered-out ecosystems.
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn scan_prune_with_ecosystem_filter_keeps_other_ecosystem() {
    // Two ecosystems are installed: an npm package and a RubyGem. The
    // manifest holds three entries: the installed npm pkg, an *uninstalled*
    // npm orphan, and the installed gem. We scan with `--ecosystems npm
    // --prune`.
    //
    // Prune must reference what is actually INSTALLED, not what this scan
    // chose to query. So: the npm orphan is pruned (genuinely gone), the
    // installed npm entry is kept, and the installed gem entry is kept —
    // even though `--ecosystems npm` excluded it from the query/display.
    //
    // The bug this guards: prune keyed off the `--ecosystems`-filtered crawl
    // set, so the gem (filtered out, but installed) looked "uninstalled" and
    // was silently pruned along with its blobs — cross-ecosystem data loss.
    let server = MockServer::start().await;
    mock_batch_empty(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "live-npm", "1.0.0");
    write_gem_package(tmp.path(), "live-gem", "2.0.0");

    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    std::fs::write(
        socket.join("manifest.json"),
        r#"{ "patches": {
            "pkg:npm/live-npm@1.0.0": {
                "uuid": "11111111-1111-4111-8111-111111111111",
                "exportedAt": "2024-01-01T00:00:00Z",
                "files": {}, "vulnerabilities": {},
                "description": "live npm", "license": "MIT", "tier": "free"
            },
            "pkg:npm/orphan-npm@9.9.9": {
                "uuid": "22222222-2222-4222-8222-222222222222",
                "exportedAt": "2024-01-01T00:00:00Z",
                "files": {}, "vulnerabilities": {},
                "description": "orphan npm", "license": "MIT", "tier": "free"
            },
            "pkg:gem/live-gem@2.0.0": {
                "uuid": "33333333-3333-4333-8333-333333333333",
                "exportedAt": "2024-01-01T00:00:00Z",
                "files": {}, "vulnerabilities": {},
                "description": "live gem", "license": "MIT", "tier": "free"
            }
        }}"#,
    )
    .unwrap();

    let mut args = default_args(tmp.path());
    args.common.api_url = server.uri();
    args.common.ecosystems = Some(vec!["npm".to_string()]);
    args.prune = true;

    assert_eq!(run(args).await, 0);

    let body = std::fs::read_to_string(socket.join("manifest.json")).unwrap();
    let m: serde_json::Value = serde_json::from_str(&body).unwrap();
    let patches = m["patches"].as_object().unwrap();

    assert!(
        !patches.contains_key("pkg:npm/orphan-npm@9.9.9"),
        "the genuinely-uninstalled npm orphan must be pruned; got {m}"
    );
    assert!(
        patches.contains_key("pkg:npm/live-npm@1.0.0"),
        "the installed npm entry must be kept; got {m}"
    );
    assert!(
        patches.contains_key("pkg:gem/live-gem@2.0.0"),
        "an installed package of a filtered-OUT ecosystem must NOT be pruned; got {m}"
    );
    assert_eq!(
        patches.len(),
        2,
        "exactly the orphan should be removed; got {m}"
    );
}

// ---------------------------------------------------------------------------
// Regression: non-JSON --dry-run must not mutate (apply or prune).
// ---------------------------------------------------------------------------

#[tokio::test]
#[serial]
async fn scan_non_json_dry_run_does_not_mutate() {
    // `--dry-run` is documented as a non-mutating preview. The JSON path
    // honored it; the interactive (non-JSON) path ignored it and ran the
    // real download/apply + a mutating prune GC. With a stale manifest entry
    // present and `--prune` set, an un-honored dry-run would prune it (and
    // download/write blobs). It must instead preview and leave disk intact.
    let server = MockServer::start().await;
    mock_batch_one(&server).await;
    mock_by_package(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "in-proc-scan", "1.0.0");

    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    let manifest = r#"{ "patches": {
        "pkg:npm/stale@1.0.0": {
            "uuid": "22222222-2222-4222-8222-222222222222",
            "exportedAt": "2024-01-01T00:00:00Z",
            "files": {}, "vulnerabilities": {},
            "description": "stale", "license": "MIT", "tier": "free"
        }
    }}"#;
    std::fs::write(socket.join("manifest.json"), manifest).unwrap();
    let before = std::fs::read_to_string(socket.join("manifest.json")).unwrap();

    let mut args = default_args(tmp.path());
    args.common.api_url = server.uri();
    args.common.json = false; // interactive path
    args.prune = true;
    args.common.dry_run = true;

    assert_eq!(run(args).await, 0);

    // Manifest is byte-for-byte unchanged: neither the apply nor the prune
    // GC touched it.
    let after = std::fs::read_to_string(socket.join("manifest.json")).unwrap();
    assert_eq!(
        after, before,
        "non-JSON dry-run must not mutate the manifest"
    );
    assert!(
        !socket.join("blobs").exists(),
        "non-JSON dry-run must not download/write blobs"
    );
    // Prove the path actually reached the patch-selection stage (and thus
    // the dry-run short-circuit), rather than bailing earlier: details for
    // the discovered package were fetched via the by-package endpoint.
    let reqs = recorded(&server).await;
    assert!(
        by_package_gets(&reqs) >= 1,
        "non-JSON scan must fetch patch details before the dry-run stop"
    );
}
