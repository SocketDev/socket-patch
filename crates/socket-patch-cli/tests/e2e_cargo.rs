//! End-to-end tests for the Cargo/Rust crate patching lifecycle.
//!
//! These tests exercise crawling against a temporary directory with a fake
//! Cargo registry layout.  They do **not** require network access or a real
//! Cargo installation: the scan's patch lookup is pinned to an in-test
//! [`wiremock`] public-proxy stand-in via `--proxy-url`. That pinning is
//! load-bearing, not cosmetic — since the all-batches-failed fix, an
//! unreachable API is a hard scan failure (exit 1, `status: "error"`), so an
//! unpinned scan would phone home to the live proxy on every test run and go
//! red whenever the network (or an ambient `SOCKET_*` variable) misbehaved.
//!
//! # Running
//! ```sh
//! cargo test -p socket-patch-cli --test e2e_cargo
//! ```

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

/// Start a mock Socket public proxy answering the scan's `POST /patch/batch`
/// with an empty (no-patch) result, so no scan in this file ever leaves
/// localhost.
async fn start_proxy() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/patch/batch"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "packages": [],
            "canAccessPaidPatches": false,
        })))
        .mount(&server)
        .await;
    server
}

/// Run the binary as a blocking subprocess (off the async runtime so the
/// in-test proxy can service its requests concurrently), pinned to `proxy_url`.
///
/// `SOCKET_API_TOKEN` is stripped so the binary deterministically takes the
/// public-proxy path (an ambient token would flip it onto the authenticated
/// API, bypassing `--proxy-url`), and every other variable that could
/// redirect the API elsewhere or disable it is scrubbed so an ambient value
/// can't quietly change what the scan reports.
async fn run(args: &[&str], cwd: &Path, proxy_url: &str) -> Output {
    let mut args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    args.extend(["--proxy-url".to_string(), proxy_url.to_string()]);
    let cwd = cwd.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        Command::new(binary())
            .args(&arg_refs)
            .current_dir(&cwd)
            .env("CARGO_HOME", cwd.join(".cargo"))
            .env_remove("SOCKET_API_TOKEN")
            .env_remove("SOCKET_CLI_API_TOKEN")
            .env_remove("SOCKET_API_URL")
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
/// check. The package *count* is derived from the local crawl; the patch
/// lookup is served by the in-test proxy, so the exit-0 / status=success
/// assertions hold without live network access.
async fn scan_json(cwd: &Path, proxy_url: &str) -> serde_json::Value {
    let output = run(
        &["scan", "--json", "--cwd", cwd.to_str().unwrap()],
        cwd,
        proxy_url,
    )
    .await;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "scan --json should exit 0, got {:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
        output.status.code()
    );
    let value: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("scan --json must emit valid JSON ({e}), got:\n{stdout}"));
    // The discovery contract is "success" — guard the envelope shape so a
    // regression that swaps the status (or drops the field, yielding Null)
    // is caught here rather than slipping past the count assertion below.
    assert_eq!(
        value["status"], "success",
        "scan --json envelope must report status=success; got:\n{value:#}"
    );
    value
}

/// Regression guard for the hermeticity fix: every scan in a test must have
/// routed its patch lookup through the in-test proxy. Fewer recorded requests
/// than scans means at least one binary invocation talked to the live API (or
/// skipped the lookup outright) despite the pinning — exactly the bug this
/// file used to have.
async fn assert_proxy_served_scans(server: &MockServer, scans: usize) {
    let requests = server.received_requests().await.unwrap_or_default();
    assert!(
        requests.len() >= scans,
        "expected all {scans} scan invocations to hit the in-test proxy; \
         recorded only {} request(s)",
        requests.len()
    );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Verify that `socket-patch scan` discovers crates in a registry-cache layout
/// (`$CARGO_HOME/registry/src/index.crates.io-*/<name>-<version>/`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scan_discovers_fake_registry_crates() {
    let server = start_proxy().await;
    let proxy_url = server.uri();
    let dir = tempfile::tempdir().unwrap();

    // The crawler only falls back to scanning the global `$CARGO_HOME`
    // registry when the cwd actually looks like a Rust project (has a
    // `Cargo.toml` / `Cargo.lock`). Without this manifest the registry path
    // is never exercised and discovery silently returns zero — which the old
    // `contains("packages")` assertion happily accepted via the
    // "No packages found" message. Provide the manifest so the registry
    // branch is genuinely taken.
    std::fs::write(
        dir.path().join("Cargo.toml"),
        "[package]\nname = \"myapp\"\nversion = \"0.1.0\"\n",
    )
    .unwrap();

    // Set up a fake CARGO_HOME/registry/src/index.crates.io-xxx/ structure
    let index_dir = dir
        .path()
        .join(".cargo")
        .join("registry")
        .join("src")
        .join("index.crates.io-test");

    // Create serde-1.0.200
    let serde_dir = index_dir.join("serde-1.0.200");
    std::fs::create_dir_all(&serde_dir).unwrap();
    std::fs::write(
        serde_dir.join("Cargo.toml"),
        "[package]\nname = \"serde\"\nversion = \"1.0.200\"\n",
    )
    .unwrap();

    // Create tokio-1.38.0
    let tokio_dir = index_dir.join("tokio-1.38.0");
    std::fs::create_dir_all(&tokio_dir).unwrap();
    std::fs::write(
        tokio_dir.join("Cargo.toml"),
        "[package]\nname = \"tokio\"\nversion = \"1.38.0\"\n",
    )
    .unwrap();

    // --- JSON path: assert the exact discovered count, not just "non-zero".
    let json = scan_json(dir.path(), &proxy_url).await;
    assert_eq!(
        json["scannedPackages"], 2,
        "scan must discover exactly the two registry crates (serde + tokio); got:\n{json:#}"
    );

    // --- Human path: the count must be attributed to the *cargo* ecosystem,
    // proving the registry crawler (not some accidental npm/pypi pickup) is
    // what found them. This also guards against the old loophole where the
    // failure message "No packages found" satisfied a `contains("packages")`
    // check.
    let output = run(
        &["scan", "--cwd", dir.path().to_str().unwrap()],
        dir.path(),
        &proxy_url,
    )
    .await;
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{stdout}{stderr}");
    // Match the exact ecosystem summary, not two loose substrings. The old
    // `contains("Found 2 packages") && contains("cargo")` was satisfied by an
    // incidental "cargo" anywhere (the proxy banner, the
    // "npm/yarn/pnpm/pip/cargo" install hint, a PURL) and would NOT have
    // caught a stray non-cargo pickup, e.g. `Found 2 packages (1 cargo, 1
    // npm)`. Requiring `(2 cargo)` proves all of the count is attributed to
    // the registry crawler.
    assert!(
        combined.contains("Found 2 packages (2 cargo)"),
        "Expected human scan to report exactly 'Found 2 packages (2 cargo)', got:\n{combined}"
    );
    assert!(
        !combined.contains("No packages found"),
        "scan reported no packages despite a populated registry:\n{combined}"
    );

    assert_proxy_served_scans(&server, 2).await;
}

/// Verify that `socket-patch scan` discovers crates in a vendor layout
/// (`<cwd>/vendor/<name>/`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scan_discovers_vendor_crates() {
    let server = start_proxy().await;
    let proxy_url = server.uri();
    let dir = tempfile::tempdir().unwrap();

    // A bare `vendor/` dir is not cargo-specific; the crawler only treats it as
    // a crate source once the root is identified as a Cargo project. A vendored
    // project always carries a lockfile, so stage one as the project marker.
    std::fs::write(dir.path().join("Cargo.lock"), "version = 3\n").unwrap();

    // Set up vendor directory
    let vendor_dir = dir.path().join("vendor");

    let serde_dir = vendor_dir.join("serde");
    std::fs::create_dir_all(&serde_dir).unwrap();
    std::fs::write(
        serde_dir.join("Cargo.toml"),
        "[package]\nname = \"serde\"\nversion = \"1.0.200\"\n",
    )
    .unwrap();

    // --- JSON path: exactly one vendored crate must be discovered.
    let json = scan_json(dir.path(), &proxy_url).await;
    assert_eq!(
        json["scannedPackages"], 1,
        "scan must discover exactly the one vendored crate (serde); got:\n{json:#}"
    );

    // --- Human path: the discovery must be attributed to the cargo ecosystem,
    // and must NOT report "No packages found" (the old loophole).
    let output = run(
        &["scan", "--cwd", dir.path().to_str().unwrap()],
        dir.path(),
        &proxy_url,
    )
    .await;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");
    // Exact ecosystem summary — see the registry test for why the two-loose-
    // substring form was a loophole. `(1 cargo)` proves the single discovered
    // package is the vendored crate and not an accidental npm/pypi pickup.
    assert!(
        combined.contains("Found 1 packages (1 cargo)"),
        "Expected human scan to report exactly 'Found 1 packages (1 cargo)', got:\n{combined}"
    );
    assert!(
        !combined.contains("No packages found"),
        "scan reported no packages despite a populated vendor dir:\n{combined}"
    );

    assert_proxy_served_scans(&server, 2).await;
}
