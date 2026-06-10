#![cfg(feature = "golang")]
//! End-to-end tests for the Go module patching lifecycle.
//!
//! These tests exercise crawling against a temporary directory with a fake
//! Go module cache layout.  They do **not** require a real Go installation.
//!
//! The API is served by an in-test [`wiremock`] server: the binary is pinned
//! to it via `SOCKET_API_URL` so the scan's *batch* request is captured and
//! its body inspected. This is what lets the tests assert the **exact decoded
//! PURLs** the crawler discovered (not merely a count): a crawler that found
//! the wrong directories, or that failed to decode Go's `!`-case-escaping
//! (`!azure` → `Azure`), would send a different PURL and fail loudly.
//!
//! # Running
//! ```sh
//! cargo test -p socket-patch-cli --features golang --test e2e_golang
//! ```

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Output;

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Org slug pinned via `SOCKET_ORG_SLUG` so the authenticated batch endpoint
/// resolves to a fixed path and no `/v0/organizations` lookup is needed.
const ORG: &str = "testorg";

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

/// Mount a batch endpoint that returns "no patches" (200, empty `packages`).
///
/// The point is not the response — offline-equivalent emptiness is fine — but
/// that wiremock *records* the POST body so the test can read back exactly
/// which PURLs the crawler asked about.
async fn mount_batch(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path(format!("/v0/orgs/{ORG}/patches/batch")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [],
            "canAccessPaidPatches": false,
        })))
        .mount(server)
        .await;
}

/// Run the binary as a blocking subprocess (off the async runtime so the
/// wiremock server can service the request concurrently).
///
/// The environment is pinned hard: `GOMODCACHE` fixes the crawl root, the
/// token/url/org steer the API at the in-test server, and every variable that
/// could redirect the API elsewhere or disable it (`GOPATH`, `SOCKET_OFFLINE`,
/// the proxy URLs) is scrubbed so an ambient value in the test environment
/// can't quietly change what the crawler discovers or whether it calls home.
async fn run(args: &[&str], cwd: &Path, gomodcache: &Path, api_url: &str) -> Output {
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let cwd = cwd.to_path_buf();
    let gomodcache = gomodcache.to_path_buf();
    let api_url = api_url.to_string();
    tokio::task::spawn_blocking(move || {
        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        std::process::Command::new(binary())
            .args(&arg_refs)
            .current_dir(&cwd)
            .env("GOMODCACHE", &gomodcache)
            .env("SOCKET_API_URL", &api_url)
            .env("SOCKET_API_TOKEN", "sktsec_dummy_e2e_golang_token_api")
            .env("SOCKET_ORG_SLUG", ORG)
            .env_remove("GOPATH")
            .env_remove("SOCKET_OFFLINE")
            .env_remove("SOCKET_PROXY_URL")
            .env_remove("SOCKET_PATCH_PROXY_URL")
            .env_remove("SOCKET_BATCH_SIZE")
            .output()
            .expect("Failed to run socket-patch binary")
    })
    .await
    .expect("socket-patch subprocess task panicked")
}

/// Run `socket-patch scan --json ...`, assert the process succeeded, and
/// return the parsed JSON envelope from stdout.
///
/// Parsing (rather than substring matching) means a malformed or missing
/// envelope fails the test loudly instead of slipping past a `.contains()`
/// check.
async fn scan_json(cwd: &Path, gomodcache: &Path, api_url: &str) -> serde_json::Value {
    let output = run(
        &["scan", "--json", "--cwd", cwd.to_str().unwrap()],
        cwd,
        gomodcache,
        api_url,
    )
    .await;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "scan --json should exit 0, got {:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        output.status.code()
    );
    serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("scan --json must emit valid JSON ({e}), got:\n{stdout}"))
}

/// Collect the union of every PURL the binary sent to the batch endpoint
/// across all runs recorded by `server`.
///
/// This is the independent oracle: the set is built from the *request bodies
/// the production crawler produced*, decoded module path and all, not from any
/// value the test itself computed from the on-disk layout.
async fn batched_purls(server: &MockServer) -> BTreeSet<String> {
    let reqs = server.received_requests().await.unwrap_or_default();
    let batch_posts: Vec<_> = reqs
        .iter()
        .filter(|r| format!("{}", r.method) == "POST" && r.url.path().ends_with("/patches/batch"))
        .collect();
    assert!(
        !batch_posts.is_empty(),
        "scan never POSTed to the batch endpoint — the API path was \
         short-circuited and no PURL was ever exercised. Recorded requests: {:?}",
        reqs.iter()
            .map(|r| format!("{} {}", r.method, r.url.path()))
            .collect::<Vec<_>>()
    );

    let mut purls = BTreeSet::new();
    for req in batch_posts {
        let body: serde_json::Value = serde_json::from_slice(&req.body)
            .unwrap_or_else(|e| panic!("batch body was not valid JSON ({e})"));
        let components = body["components"]
            .as_array()
            .unwrap_or_else(|| panic!("batch body missing `components` array; got:\n{body:#}"));
        for c in components {
            purls.insert(
                c["purl"]
                    .as_str()
                    .unwrap_or_else(|| panic!("component missing string `purl`; got:\n{c:#}"))
                    .to_string(),
            );
        }
    }
    purls
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Verify `socket-patch scan` discovers Go modules in a fake module cache and
/// reports them — by exact count, by ecosystem, and by exact decoded PURL.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scan_discovers_go_modules() {
    let server = MockServer::start().await;
    mount_batch(&server).await;
    let api_url = server.uri();

    let dir = tempfile::tempdir().unwrap();
    let cache_dir = dir.path().join("gomodcache");

    // Create fake module: github.com/gin-gonic/gin@v1.9.1
    let gin_dir = cache_dir
        .join("github.com")
        .join("gin-gonic")
        .join("gin@v1.9.1");
    std::fs::create_dir_all(&gin_dir).unwrap();
    std::fs::write(
        gin_dir.join("go.mod"),
        "module github.com/gin-gonic/gin\n\ngo 1.21\n",
    )
    .unwrap();

    // Create fake module: golang.org/x/text@v0.14.0
    let text_dir = cache_dir.join("golang.org").join("x").join("text@v0.14.0");
    std::fs::create_dir_all(&text_dir).unwrap();
    std::fs::write(
        text_dir.join("go.mod"),
        "module golang.org/x/text\n\ngo 1.21\n",
    )
    .unwrap();

    // --- Decoys that MUST NOT be counted, proving the crawler parses the
    // versioned (`name@version`) layout rather than counting every directory:
    //   * the root `cache/` download dir is pruned at the cache root, so a
    //     versioned dir beneath it must be ignored;
    //   * a non-versioned directory (no `@`) is not a module.
    // If either leaked in, `scannedPackages` would be 3+ and the exact-count
    // assertion below would fail.
    let decoy_cache = cache_dir.join("cache").join("download").join("evil@v9.9.9");
    std::fs::create_dir_all(&decoy_cache).unwrap();
    std::fs::create_dir_all(cache_dir.join("github.com").join("plain").join("noversion")).unwrap();

    // Create a go.mod in the project directory so local mode activates
    std::fs::write(
        dir.path().join("go.mod"),
        "module example.com/myproject\n\ngo 1.21\n",
    )
    .unwrap();

    // --- JSON path: assert the EXACT discovered count, not just "non-zero".
    // The empty-scan envelope also emits `"scannedPackages": 0`, so a count
    // check is what distinguishes "found both modules" from "found nothing".
    let json = scan_json(dir.path(), &cache_dir, &api_url).await;
    assert_eq!(
        json["status"], "success",
        "scan envelope must report success; got:\n{json:#}"
    );
    assert_eq!(
        json["scannedPackages"], 2,
        "scan must discover exactly the two Go modules (gin + text) and skip \
         the cache/ and non-versioned decoys; got:\n{json:#}"
    );

    // --- Human path: the count must be attributed to the *go* ecosystem in a
    // single contiguous phrase. Two independent `contains` substrings would
    // accept a split-ecosystem regression (e.g. "Found 2 packages (1 go, 1
    // npm)") — require the exact "(2 go)" attribution.
    let output = run(
        &["scan", "--cwd", dir.path().to_str().unwrap()],
        dir.path(),
        &cache_dir,
        &api_url,
    )
    .await;
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{stdout}{stderr}");
    assert!(
        output.status.success(),
        "human scan should exit 0, got {:?}\n{combined}",
        output.status.code()
    );
    assert!(
        combined.contains("Found 2 packages (2 go)"),
        "Expected human scan to report 'Found 2 packages (2 go)', got:\n{combined}"
    );
    assert!(
        !combined.contains("No packages found"),
        "scan reported no packages despite a populated module cache:\n{combined}"
    );

    // --- Identity oracle: the crawler must have asked the API about exactly
    // these two modules, by their full Go module paths. A count of 2 alone
    // would survive a crawler that discovered the wrong directories; pinning
    // the PURL set closes that.
    let purls = batched_purls(&server).await;
    let expected: BTreeSet<String> = [
        "pkg:golang/github.com/gin-gonic/gin@v1.9.1".to_string(),
        "pkg:golang/golang.org/x/text@v0.14.0".to_string(),
    ]
    .into_iter()
    .collect();
    assert_eq!(
        purls, expected,
        "scan must query the API for exactly the two planted module PURLs"
    );
}

/// Verify `socket-patch scan` discovers AND case-decodes Go modules.
///
/// Go's module cache stores uppercase letters as `!`+lowercase, so
/// `github.com/Azure/...` lands on disk under `github.com/!azure/...`. The
/// crawler must descend into `!azure` AND decode it back to `Azure` in the
/// PURL it emits — a crawler that skipped `!`-prefixed dirs would report zero,
/// and one that descended but left the escaping in place would emit the wrong
/// PURL. The batch-body assertion below catches both.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scan_discovers_case_encoded_modules() {
    let server = MockServer::start().await;
    mount_batch(&server).await;
    let api_url = server.uri();

    let dir = tempfile::tempdir().unwrap();
    let cache_dir = dir.path().join("gomodcache");

    // Create case-encoded module: github.com/!azure/azure-sdk-for-go@v1.0.0
    // (represents github.com/Azure/azure-sdk-for-go)
    let azure_dir = cache_dir
        .join("github.com")
        .join("!azure")
        .join("azure-sdk-for-go@v1.0.0");
    std::fs::create_dir_all(&azure_dir).unwrap();

    // Decoy: a root-level cache/ download dir whose versioned entry must be
    // pruned, so the count stays at exactly one.
    std::fs::create_dir_all(cache_dir.join("cache").join("download").join("evil@v9.9.9")).unwrap();

    // Create a go.mod in the project directory so local mode activates.
    std::fs::write(
        dir.path().join("go.mod"),
        "module example.com/myproject\n\ngo 1.21\n",
    )
    .unwrap();

    // --- JSON path: exactly one case-encoded module must be discovered.
    let json = scan_json(dir.path(), &cache_dir, &api_url).await;
    assert_eq!(
        json["status"], "success",
        "scan envelope must report success; got:\n{json:#}"
    );
    assert_eq!(
        json["scannedPackages"], 1,
        "scan must discover exactly the one case-encoded module under !azure; got:\n{json:#}"
    );

    // --- Human path: discovery attributed to the go ecosystem, contiguous.
    let output = run(
        &["scan", "--cwd", dir.path().to_str().unwrap()],
        dir.path(),
        &cache_dir,
        &api_url,
    )
    .await;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");
    assert!(
        output.status.success(),
        "human scan should exit 0, got {:?}\n{combined}",
        output.status.code()
    );
    assert!(
        combined.contains("Found 1 packages (1 go)"),
        "Expected human scan to report 'Found 1 packages (1 go)', got:\n{combined}"
    );
    assert!(
        !combined.contains("No packages found"),
        "scan reported no packages despite a populated module cache:\n{combined}"
    );

    // --- Decode oracle: the PURL the crawler emitted must carry the DECODED
    // module path `github.com/Azure/...`, not the on-disk `!azure` form. This
    // is the assertion the test name actually promises and that a count alone
    // could never make.
    let purls = batched_purls(&server).await;
    let expected: BTreeSet<String> =
        ["pkg:golang/github.com/Azure/azure-sdk-for-go@v1.0.0".to_string()]
            .into_iter()
            .collect();
    assert_eq!(
        purls, expected,
        "scan must query the API with the case-DECODED module PURL (Azure, not !azure)"
    );
}
