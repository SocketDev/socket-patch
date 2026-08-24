//! End-to-end tests for `scan [PATHS]...` path-glob scoping (v5.0) against
//! a local `wiremock` server.
//!
//! Spawns the real `socket-patch` binary (same recipe as
//! `scan_invariants.rs`, with `rollback_invariants.rs`'s SOCKET_* env
//! scrub) and pins the CONTRACT of path-scoped scans:
//!
//! * scoping narrows the API QUERY (batch-POST body oracle) and the
//!   envelope counters, echoing the patterns in an always-present `paths`
//!   key;
//! * scoping NEVER narrows the prune universe — `scan PATHS --prune`
//!   prunes exactly what an unscoped `scan --prune` would (the data-loss
//!   pin);
//! * an empty match is a normal empty scan (exit 0, no GC, no API calls);
//! * lockfile-only supplements are excluded from a scoped scan with the
//!   `path_scope_excluded_supplements` run-level warning;
//! * PATHS with `--mode hosted`/`--mode vendored`, and unparseable globs,
//!   are usage errors (exit 2).

use std::path::{Path, PathBuf};
use std::process::Command;

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

const ORG: &str = "test-org";
const ROOT_PURL: &str = "pkg:npm/root-dep@1.0.0";
const APP_PURL: &str = "pkg:npm/app-dep@1.0.0";

/// A `scan` command with the full `SOCKET_*` environment scrubbed (except
/// the workspace-pinned `SOCKET_NO_CONFIG`) and the working directory
/// pinned — the `rollback_invariants.rs` recipe, so no test can be
/// satisfied (or broken) by ambient environment instead of its flags.
/// `VIRTUAL_ENV` is scrubbed too: the python crawler honors it FIRST, so
/// an activated venv would inject its site-packages into every scan and
/// break the exact-batch-body oracles (see `in_process_scan.rs`).
/// Telemetry is disabled so the request log holds ONLY patch-API traffic.
fn scan_cmd(cwd: &Path) -> Command {
    let mut cmd = Command::new(binary());
    cmd.arg("scan").current_dir(cwd);
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("SOCKET_")
            && key.to_string_lossy() != "SOCKET_NO_CONFIG"
        {
            cmd.env_remove(&key);
        }
    }
    cmd.env_remove("VIRTUAL_ENV");
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1");
    cmd
}

/// Run `socket-patch scan --json <extra…>` against the given API URL.
fn run_scan(cwd: &Path, api_url: &str, extra: &[&str]) -> (i32, String, String) {
    let out = scan_cmd(cwd)
        .args([
            "--json",
            "--api-url",
            api_url,
            "--api-token",
            "fake-token-for-test",
            "--org",
            ORG,
        ])
        .args(extra)
        .output()
        .expect("run socket-patch");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

fn parse_envelope(stdout: &str) -> serde_json::Value {
    serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("stdout must be a JSON envelope ({e}); got: {stdout}"))
}

// --- Fixtures ---------------------------------------------------------------

fn write_root_package_json(root: &Path) {
    std::fs::write(
        root.join("package.json"),
        r#"{ "name": "scan-paths-root", "version": "0.0.0" }"#,
    )
    .unwrap();
}

/// Install a fake npm package under `<root>/<prefix>/node_modules/<name>/`
/// (`prefix = ""` for the root tree). The crawler walks the project tree
/// for `node_modules` dirs — including workspace subtrees — and derives
/// the PURL from each package.json.
fn write_npm_package_at(root: &Path, prefix: &str, name: &str, version: &str) {
    let base = if prefix.is_empty() {
        root.to_path_buf()
    } else {
        root.join(prefix)
    };
    let pkg = base.join("node_modules").join(name);
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        pkg.join("package.json"),
        format!(r#"{{ "name": "{name}", "version": "{version}" }}"#),
    )
    .unwrap();
}

/// The two-subtree fixture every scoping test uses: `root-dep` installed in
/// the root `node_modules/`, `app-dep` installed under
/// `packages/app/node_modules/` (with a workspace-member package.json so
/// the layout is a realistic monorepo).
fn write_two_subtree_project(root: &Path) {
    write_root_package_json(root);
    write_npm_package_at(root, "", "root-dep", "1.0.0");
    std::fs::create_dir_all(root.join("packages/app")).unwrap();
    std::fs::write(
        root.join("packages/app/package.json"),
        r#"{ "name": "app", "version": "0.0.0" }"#,
    )
    .unwrap();
    write_npm_package_at(root, "packages/app", "app-dep", "1.0.0");
}

/// One hand-written camelCase manifest entry (the TS-compat wire shape the
/// repo's suites hand-write everywhere).
fn manifest_entry(uuid: &str, after_hash: &str) -> serde_json::Value {
    serde_json::json!({
        "uuid": uuid,
        "exportedAt": "2024-01-01T00:00:00Z",
        "files": {
            "package/index.js": {
                "beforeHash": "0".repeat(64),
                "afterHash": after_hash,
            }
        },
        "vulnerabilities": {},
        "description": "scan-paths fixture",
        "license": "MIT",
        "tier": "free",
    })
}

/// Stage a blob file named `<hash>` under `.socket/blobs/`.
fn stage_blob(root: &Path, hash: &str) -> PathBuf {
    let blobs = root.join(".socket/blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    let p = blobs.join(hash);
    std::fs::write(&p, vec![0u8; 64]).unwrap();
    p
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

// --- Request-inspection helpers (the "what did scan actually send" oracle) --

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

fn req_body(req: &wiremock::Request) -> String {
    String::from_utf8_lossy(&req.body).into_owned()
}

/// The run-level `warnings[]` codes carried by the envelope (empty when the
/// additive key is absent).
fn warning_codes(v: &serde_json::Value) -> Vec<String> {
    v.get("warnings")
        .and_then(|w| w.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|w| w["code"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// 1. Path scoping narrows the API query to in-scope purls only.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn paths_scope_narrows_the_query() {
    let server = MockServer::start().await;
    mock_batch_empty(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_two_subtree_project(tmp.path());

    let (code, stdout, stderr) = run_scan(tmp.path(), &server.uri(), &["packages/app"]);
    assert_eq!(
        code, 0,
        "scoped scan must exit 0; stdout={stdout}; stderr={stderr}"
    );

    // Request oracle: exactly one batch POST carrying ONLY the in-scope
    // purl. A regression that ignored the scope would send root-dep too;
    // one that over-filtered would send nothing (zero POSTs).
    let reqs = recorded(&server).await;
    let posts = batch_posts(&reqs);
    assert_eq!(
        posts.len(),
        1,
        "scoped scan must query the batch API exactly once; saw {}",
        posts.len()
    );
    let body = req_body(posts[0]);
    assert!(
        body.contains(APP_PURL),
        "batch body must carry the in-scope purl {APP_PURL}; body: {body}"
    );
    assert!(
        !body.contains("root-dep"),
        "batch body must NOT carry the out-of-scope purl {ROOT_PURL}; body: {body}"
    );

    // Envelope: patterns echoed verbatim, counter reflects the scope.
    let v = parse_envelope(&stdout);
    assert_eq!(v["status"], "success");
    assert_eq!(
        v["paths"],
        serde_json::json!(["packages/app"]),
        "envelope must echo the path patterns verbatim; got {v}"
    );
    assert_eq!(
        v["scannedPackages"], 1,
        "only the in-scope package counts as scanned; got {v}"
    );
}

// ---------------------------------------------------------------------------
// 2. The prune universe is NEVER narrowed by path scoping (data-loss pin).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn paths_never_narrow_the_prune_universe() {
    // Manifest holds THREE entries: both installed packages (one in scope,
    // one out of scope) and one genuinely-uninstalled orphan. A scoped
    // `scan packages/app --prune` must prune exactly the orphan — the
    // out-of-scope-but-installed entry and its blob MUST survive. The
    // orphan is what makes this discriminate "prune keyed off the full
    // crawl" from "prune didn't run at all"; the out-of-scope entry is
    // what makes it discriminate full-crawl from scope-narrowed (the bug
    // this pins would silently delete root-dep's patch + blob).
    let server = MockServer::start().await;
    mock_batch_empty(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_two_subtree_project(tmp.path());

    let root_hash = "a".repeat(64);
    let app_hash = "b".repeat(64);
    let orphan_hash = "c".repeat(64);
    let root_blob = stage_blob(tmp.path(), &root_hash);
    let app_blob = stage_blob(tmp.path(), &app_hash);
    let orphan_blob = stage_blob(tmp.path(), &orphan_hash);

    let manifest = serde_json::json!({
        "patches": {
            ROOT_PURL: manifest_entry("11111111-1111-4111-8111-111111111111", &root_hash),
            APP_PURL: manifest_entry("22222222-2222-4222-8222-222222222222", &app_hash),
            "pkg:npm/gone@9.9.9":
                manifest_entry("33333333-3333-4333-8333-333333333333", &orphan_hash),
        }
    });
    std::fs::write(
        tmp.path().join(".socket/manifest.json"),
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();

    let (code, stdout, stderr) = run_scan(
        tmp.path(),
        &server.uri(),
        &["packages/app", "--prune", "--yes"],
    );
    assert_eq!(
        code, 0,
        "scoped prune scan must exit 0; stdout={stdout}; stderr={stderr}"
    );

    // On-disk post-state: the out-of-scope INSTALLED entry survives with
    // its blob; only the genuinely-uninstalled orphan was pruned.
    let m: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(tmp.path().join(".socket/manifest.json")).unwrap(),
    )
    .unwrap();
    let patches = m["patches"].as_object().unwrap();
    assert!(
        patches.contains_key(ROOT_PURL),
        "OUT-of-scope installed entry must survive a scoped --prune \
         (path scoping must never narrow the prune universe); got {m}"
    );
    assert!(
        patches.contains_key(APP_PURL),
        "in-scope installed entry must survive; got {m}"
    );
    assert!(
        !patches.contains_key("pkg:npm/gone@9.9.9"),
        "the genuinely-uninstalled orphan must still be pruned \
         (proves the prune pass actually ran); got {m}"
    );
    assert!(
        root_blob.exists(),
        "the out-of-scope entry's blob must survive the sweep"
    );
    assert!(app_blob.exists(), "the in-scope entry's blob must survive");
    assert!(
        !orphan_blob.exists(),
        "the orphan's blob must be swept with its entry"
    );

    // Envelope gc block agrees with the on-disk outcome.
    let v = parse_envelope(&stdout);
    assert_eq!(
        v["gc"]["prunedManifestEntries"],
        serde_json::json!(["pkg:npm/gone@9.9.9"]),
        "gc must report exactly the orphan as pruned; got {v}"
    );
    assert_eq!(
        v["gc"]["removedBlobs"], 1,
        "gc must report exactly the orphan's blob removed; got {v}"
    );
    assert_eq!(v["paths"], serde_json::json!(["packages/app"]));
}

// ---------------------------------------------------------------------------
// 3. A scope matching nothing is a normal empty scan.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn empty_match_is_empty_scan() {
    // A package IS installed and the manifest holds a prunable orphan —
    // but the scope matches nothing, so the run must hit the zero-package
    // early return: exit 0, scannedPackages 0, NO gc key even with
    // --prune, no API traffic, manifest + blob byte-untouched.
    let server = MockServer::start().await;
    mock_batch_empty(&server).await;

    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    write_npm_package_at(tmp.path(), "", "root-dep", "1.0.0");

    let orphan_hash = "d".repeat(64);
    let orphan_blob = stage_blob(tmp.path(), &orphan_hash);
    let manifest = serde_json::json!({
        "patches": {
            "pkg:npm/gone@9.9.9":
                manifest_entry("33333333-3333-4333-8333-333333333333", &orphan_hash),
        }
    });
    let manifest_bytes = serde_json::to_string_pretty(&manifest).unwrap();
    std::fs::write(tmp.path().join(".socket/manifest.json"), &manifest_bytes).unwrap();

    let (code, stdout, stderr) = run_scan(
        tmp.path(),
        &server.uri(),
        &["no/such/path", "--prune", "--yes"],
    );
    assert_eq!(
        code, 0,
        "empty-match scoped scan must exit 0; stdout={stdout}; stderr={stderr}"
    );

    let v = parse_envelope(&stdout);
    assert_eq!(v["status"], "success");
    assert_eq!(v["scannedPackages"], 0, "nothing is in scope; got {v}");
    assert_eq!(v["paths"], serde_json::json!(["no/such/path"]));
    assert!(
        v.get("gc").is_none(),
        "the zero-package early return fires before any GC — no gc key \
         even with --prune; got {v}"
    );

    // No patch-API traffic at all: the early return fires before the
    // batch loop.
    let reqs = recorded(&server).await;
    assert!(
        batch_posts(&reqs).is_empty() && by_package_gets(&reqs) == 0,
        "empty-match scan must not touch the API; saw {} batch POST(s), \
         {} by-package GET(s)",
        batch_posts(&reqs).len(),
        by_package_gets(&reqs),
    );

    // And no GC ran: the prunable orphan (entry + blob) is untouched.
    assert_eq!(
        std::fs::read_to_string(tmp.path().join(".socket/manifest.json")).unwrap(),
        manifest_bytes,
        "empty-match scan must leave the manifest byte-identical"
    );
    assert!(
        orphan_blob.exists(),
        "empty-match scan must not sweep any blobs"
    );
}

// ---------------------------------------------------------------------------
// 4. Lockfile-only supplements are excluded from a scoped scan (warned),
//    but still included in an unscoped one.
// ---------------------------------------------------------------------------

/// A v3 package-lock resolving `lock-only-dep` — which is never installed,
/// so it joins discovery only as a lockfile supplement (fabricated path).
fn write_npm_lock_with_lock_only_dep(root: &Path) {
    let lock = serde_json::json!({
        "name": "scan-paths-root",
        "version": "0.0.0",
        "lockfileVersion": 3,
        "requires": true,
        "packages": {
            "": {
                "name": "scan-paths-root",
                "version": "0.0.0",
                "dependencies": { "lock-only-dep": "^1.0.0" }
            },
            "node_modules/lock-only-dep": {
                "version": "1.0.0",
                "resolved":
                    "https://registry.npmjs.org/lock-only-dep/-/lock-only-dep-1.0.0.tgz",
                "integrity": "sha512-fake==",
                "license": "MIT"
            }
        }
    });
    let mut bytes = serde_json::to_vec_pretty(&lock).unwrap();
    bytes.push(b'\n');
    std::fs::write(root.join("package-lock.json"), bytes).unwrap();
}

#[tokio::test]
async fn supplements_excluded_with_warning() {
    const LOCK_ONLY_PURL: &str = "pkg:npm/lock-only-dep@1.0.0";

    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    write_npm_lock_with_lock_only_dep(tmp.path());
    std::fs::create_dir_all(tmp.path().join("packages/app")).unwrap();
    std::fs::write(
        tmp.path().join("packages/app/package.json"),
        r#"{ "name": "app", "version": "0.0.0" }"#,
    )
    .unwrap();
    write_npm_package_at(tmp.path(), "packages/app", "app-dep", "1.0.0");

    // --- Scoped run: the supplement has no installed path → excluded,
    // with the counted run-level warning; only the installed in-scope
    // purl reaches the API.
    let scoped_server = MockServer::start().await;
    mock_batch_empty(&scoped_server).await;
    let (code, stdout, stderr) = run_scan(tmp.path(), &scoped_server.uri(), &["packages/app"]);
    assert_eq!(
        code, 0,
        "scoped scan must exit 0; stdout={stdout}; stderr={stderr}"
    );
    let v = parse_envelope(&stdout);
    assert!(
        warning_codes(&v).contains(&"path_scope_excluded_supplements".to_string()),
        "scoped scan must warn that supplements were excluded; got {v}"
    );
    assert_eq!(
        v["scannedPackages"], 1,
        "only the installed in-scope package counts; got {v}"
    );
    // Pinning ACTUAL behavior: the `lockfileOnlyPackages` count reports the
    // supplement inventory and is NOT narrowed by the path scope (the
    // exclusion happens downstream, at the discovery filter).
    assert_eq!(v["lockfileOnlyPackages"], 1, "got {v}");
    let reqs = recorded(&scoped_server).await;
    let posts = batch_posts(&reqs);
    assert_eq!(posts.len(), 1, "scoped scan must query the batch API once");
    let body = req_body(posts[0]);
    assert!(
        body.contains(APP_PURL),
        "scoped batch body must carry the installed in-scope purl; body: {body}"
    );
    assert!(
        !body.contains("lock-only-dep"),
        "scoped batch body must NOT carry the excluded supplement purl; body: {body}"
    );

    // --- Control (unscoped): the supplement joins discovery and the
    // query; no path_scope warning fires.
    let unscoped_server = MockServer::start().await;
    mock_batch_empty(&unscoped_server).await;
    let (code, stdout, stderr) = run_scan(tmp.path(), &unscoped_server.uri(), &[]);
    assert_eq!(
        code, 0,
        "unscoped control scan must exit 0; stdout={stdout}; stderr={stderr}"
    );
    let v = parse_envelope(&stdout);
    assert!(
        !warning_codes(&v).contains(&"path_scope_excluded_supplements".to_string()),
        "unscoped scan must not emit the path-scope warning; got {v}"
    );
    assert_eq!(
        v["scannedPackages"], 2,
        "unscoped scan counts installed + supplement; got {v}"
    );
    assert_eq!(v["lockfileOnlyPackages"], 1, "got {v}");
    let reqs = recorded(&unscoped_server).await;
    let posts = batch_posts(&reqs);
    assert_eq!(posts.len(), 1);
    let body = req_body(posts[0]);
    assert!(
        body.contains(APP_PURL) && body.contains(LOCK_ONLY_PURL),
        "unscoped batch body must carry BOTH the installed purl and the \
         supplement purl; body: {body}"
    );
}

// ---------------------------------------------------------------------------
// 5. Usage errors: PATHS with hosted/vendored modes, and invalid globs.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn paths_with_hosted_or_vendored_mode_exit_2() {
    // All three refusals fire before any network I/O, so the unreachable
    // API URL doubles as the no-network oracle (a connect attempt would
    // surface as a different error, not the usage message).
    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());

    for mode in ["hosted", "vendored"] {
        let (code, stdout, stderr) = run_scan(
            tmp.path(),
            "http://127.0.0.1:1",
            &["packages/app", "--mode", mode],
        );
        assert_eq!(
            code, 2,
            "PATHS + --mode {mode} must be a usage error (exit 2); \
             stdout={stdout}; stderr={stderr}"
        );
        assert!(
            stderr.contains("path targeting"),
            "--mode {mode} refusal must name path targeting; stderr={stderr}"
        );
        assert!(
            stdout.trim().is_empty(),
            "a usage error must not print a JSON envelope; stdout={stdout}"
        );
    }

    // An unparseable glob is the same exit-2 usage-error shape.
    let (code, stdout, stderr) = run_scan(tmp.path(), "http://127.0.0.1:1", &["x["]);
    assert_eq!(
        code, 2,
        "an invalid glob must be a usage error (exit 2); stdout={stdout}; stderr={stderr}"
    );
    assert!(
        stderr.contains("invalid path pattern"),
        "the error must name the invalid pattern; stderr={stderr}"
    );
}

// ---------------------------------------------------------------------------
// 6. The `paths` echo key is always present (empty array when unscoped).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn paths_echo_always_present() {
    // ≥1-package envelope: unscoped scan of an installed package.
    let server = MockServer::start().await;
    mock_batch_empty(&server).await;
    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    write_npm_package_at(tmp.path(), "", "root-dep", "1.0.0");

    let (code, stdout, stderr) = run_scan(tmp.path(), &server.uri(), &[]);
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    let v = parse_envelope(&stdout);
    assert_eq!(
        v["scannedPackages"], 1,
        "fixture must exercise the >=1-package envelope; got {v}"
    );
    assert!(
        v.as_object().unwrap().contains_key("paths"),
        "the paths key must be present on every scan envelope; got {v}"
    );
    assert_eq!(
        v["paths"],
        serde_json::json!([]),
        "unscoped scan must echo an EMPTY paths array; got {v}"
    );

    // Zero-package envelope (empty project) carries the same empty echo.
    let empty_server = MockServer::start().await;
    mock_batch_empty(&empty_server).await;
    let empty = tempfile::tempdir().unwrap();
    write_root_package_json(empty.path());
    let (code, stdout, stderr) = run_scan(empty.path(), &empty_server.uri(), &[]);
    assert_eq!(code, 0, "stdout={stdout}; stderr={stderr}");
    let v = parse_envelope(&stdout);
    assert_eq!(v["scannedPackages"], 0);
    assert!(
        v.as_object().unwrap().contains_key("paths"),
        "the zero-package envelope must carry the paths key too; got {v}"
    );
    assert_eq!(v["paths"], serde_json::json!([]));
}
