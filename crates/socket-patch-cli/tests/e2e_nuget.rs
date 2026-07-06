//! End-to-end tests for the NuGet/.NET package patching lifecycle.
//!
//! These tests exercise crawling against a temporary directory with fake
//! NuGet package layouts.  They do **not** require network access or a real
//! .NET installation: the scan's patch lookup is pinned to an in-test
//! [`wiremock`] public-proxy stand-in via `--proxy-url`. That pinning is
//! load-bearing, not cosmetic — since the all-batches-failed fix, an
//! unreachable API is a hard scan failure (exit 1, `status: "error"`), so an
//! unpinned scan would phone home to the live proxy on every test run and go
//! red whenever the network (or an ambient `SOCKET_*` variable) misbehaved.
//!
//! # Running
//! ```sh
//! cargo test -p socket-patch-cli --test e2e_nuget -- --ignored
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
async fn run(args: &[&str], cwd: &Path, nuget_packages: &Path, proxy_url: &str) -> Output {
    let mut args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    args.extend(["--proxy-url".to_string(), proxy_url.to_string()]);
    let cwd = cwd.to_path_buf();
    let nuget_packages = nuget_packages.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        Command::new(binary())
            .args(&arg_refs)
            .current_dir(&cwd)
            .env("NUGET_PACKAGES", &nuget_packages)
            // The NuGet crawler is gated behind a runtime opt-in
            // (`nuget_runtime_enabled()` → `SOCKET_EXPERIMENTAL_NUGET`). Without
            // this, `scan` skips NuGet entirely and reports "No packages found.",
            // which would silently defeat any discovery assertion. Enabling it here
            // is what makes these tests actually exercise the NuGet code path.
            .env("SOCKET_EXPERIMENTAL_NUGET", "1")
            .env_remove("SOCKET_API_TOKEN")
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

/// Extract the integer N from a `Found N packages` line in scan's stderr.
/// Panics if the line is absent — a missing "Found" line means scan reported
/// "No packages found." (zero discovery), which is exactly the regression
/// these tests must catch.
fn parse_found_count(combined: &str) -> usize {
    let line = combined
        .lines()
        .find(|l| l.contains("Found") && l.contains("packages"))
        .unwrap_or_else(|| {
            panic!("scan did not print a `Found N packages` line; output was:\n{combined}")
        });
    // Last "Found" segment, in case a progress carriage-return prefixes it.
    let after = line.rsplit("Found").next().unwrap();
    after
        .split_whitespace()
        .next()
        .and_then(|tok| tok.parse::<usize>().ok())
        .unwrap_or_else(|| panic!("could not parse package count from line: {line:?}"))
}

/// Assert scan reported EXACTLY `n` packages and that ALL of them were
/// attributed to the NuGet ecosystem, via the contiguous breakdown line
/// `Found <n> packages (<n> nuget)`.
///
/// This is deliberately stricter than checking the count and the substring
/// "nuget" independently: a split-ecosystem regression that mis-attributed a
/// planted package (e.g. `Found 2 packages (1 nuget, 1 npm)`) would satisfy
/// both a `count == n` check and a loose `contains("nuget")` check, yet is
/// exactly the kind of breakage we must catch. Requiring the whole
/// `(<n> nuget)` breakdown segment to match the total proves every counted
/// package is NuGet and nothing leaked in from another crawler.
fn assert_all_nuget(combined: &str, n: usize) {
    // Cross-check the bare count first for a clear error on mismatch.
    let found = parse_found_count(combined);
    assert_eq!(
        found, n,
        "expected exactly {n} discovered packages, got {found}:\n{combined}"
    );
    let needle = format!("Found {n} packages ({n} nuget)");
    assert!(
        combined.contains(&needle),
        "expected the contiguous breakdown line {needle:?} \
         (all {n} packages attributed to NuGet); output was:\n{combined}"
    );
}

/// Run `scan --json` and assert the machine-readable envelope independently
/// agrees that exactly `n` packages were scanned with overall success. This is
/// a separate output formatter from the human-readable `Found N packages` line,
/// so it guards against the human line and the JSON envelope drifting apart.
async fn assert_json_scanned(
    cwd: &Path,
    nuget_packages: &Path,
    project_dir: &Path,
    proxy_url: &str,
    n: usize,
) {
    let output = run(
        &["scan", "--cwd", project_dir.to_str().unwrap(), "--json"],
        cwd,
        nuget_packages,
        proxy_url,
    )
    .await;
    assert!(
        output.status.success(),
        "scan --json should exit 0 on clean discovery, got {:?}",
        output.status.code()
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(&format!("\"scannedPackages\": {n}")),
        "scan --json envelope should report scannedPackages={n}:\n{stdout}"
    );
    assert!(
        stdout.contains("\"status\": \"success\""),
        "scan --json envelope should report status=success:\n{stdout}"
    );
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

/// Verify that `socket-patch scan` discovers packages in a fake global cache layout.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "experimental ecosystem (nuget): not gating CI until the nuget backend is implemented; run with --ignored"]
async fn scan_discovers_global_cache_packages() {
    let server = start_proxy().await;
    let proxy_url = server.uri();
    let dir = tempfile::tempdir().unwrap();

    // Set up a fake global NuGet cache: <name>/<version>/ with .nuspec
    let nuget_cache = dir.path().join("nuget-cache");

    let nj_dir = nuget_cache.join("newtonsoft.json").join("13.0.3");
    std::fs::create_dir_all(nj_dir.join("lib")).unwrap();
    std::fs::write(
        nj_dir.join("newtonsoft.json.nuspec"),
        r#"<package><metadata><id>Newtonsoft.Json</id><version>13.0.3</version></metadata></package>"#,
    )
    .unwrap();

    let stj_dir = nuget_cache.join("system.text.json").join("8.0.0");
    std::fs::create_dir_all(&stj_dir).unwrap();
    std::fs::write(
        stj_dir.join("system.text.json.nuspec"),
        r#"<package><metadata><id>System.Text.Json</id><version>8.0.0</version></metadata></package>"#,
    )
    .unwrap();

    // Create a .csproj so it's recognized as a .NET project
    let project_dir = dir.path().join("project");
    std::fs::create_dir_all(&project_dir).unwrap();
    std::fs::write(project_dir.join("MyApp.csproj"), "<Project/>").unwrap();

    let output = run(
        &["scan", "--cwd", project_dir.to_str().unwrap()],
        &project_dir,
        &nuget_cache,
        &proxy_url,
    )
    .await;
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{stdout}{stderr}");

    assert!(
        output.status.success(),
        "scan should exit 0 on a clean discovery, got {:?}:\n{combined}",
        output.status.code()
    );
    // The crawler must NOT fall through to the empty-result message — that is
    // the bug the old substring check ("packages" ⊂ "No packages found.")
    // masked.
    assert!(
        !combined.contains("No packages found") && !combined.contains("No global packages found"),
        "scan failed to discover the fake global cache:\n{combined}"
    );
    // Exactly the two packages we planted (Newtonsoft.Json, System.Text.Json),
    // ALL attributed to NuGet and nothing else — the temp project has no
    // node_modules/site-packages, so every counted package must come from the
    // fake NuGet cache. The contiguous `(2 nuget)` breakdown also rejects a
    // split-ecosystem regression that a separate count + loose substring check
    // would let through.
    assert_all_nuget(&combined, 2);
    // Independently confirm via the JSON envelope (a different output path).
    assert_json_scanned(&project_dir, &nuget_cache, &project_dir, &proxy_url, 2).await;

    assert_proxy_served_scans(&server, 2).await;
}

/// Verify that `socket-patch scan` discovers packages in a fake legacy packages/ layout.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "experimental ecosystem (nuget): not gating CI until the nuget backend is implemented; run with --ignored"]
async fn scan_discovers_legacy_packages() {
    let server = start_proxy().await;
    let proxy_url = server.uri();
    let dir = tempfile::tempdir().unwrap();
    let project_dir = dir.path().join("project");
    std::fs::create_dir_all(&project_dir).unwrap();

    // Create a .csproj
    std::fs::write(project_dir.join("MyApp.csproj"), "<Project/>").unwrap();

    // Set up legacy packages/ directory
    let packages_dir = project_dir.join("packages");

    let nj_dir = packages_dir.join("Newtonsoft.Json.13.0.3");
    std::fs::create_dir_all(nj_dir.join("lib")).unwrap();
    std::fs::write(
        nj_dir.join("Newtonsoft.Json.nuspec"),
        r#"<package><metadata><id>Newtonsoft.Json</id><version>13.0.3</version></metadata></package>"#,
    )
    .unwrap();

    // Use the packages dir itself as NUGET_PACKAGES (though legacy is found via cwd)
    let output = run(
        &["scan", "--cwd", project_dir.to_str().unwrap()],
        &project_dir,
        &packages_dir,
        &proxy_url,
    )
    .await;
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{stdout}{stderr}");

    assert!(
        output.status.success(),
        "scan should exit 0 on a clean discovery, got {:?}:\n{combined}",
        output.status.code()
    );
    assert!(
        !combined.contains("No packages found") && !combined.contains("No global packages found"),
        "scan failed to discover the legacy packages/ layout:\n{combined}"
    );
    // Exactly the single legacy package we planted (Newtonsoft.Json.13.0.3),
    // attributed to NuGet via the contiguous `(1 nuget)` breakdown.
    assert_all_nuget(&combined, 1);
    // Independently confirm via the JSON envelope (a different output path).
    assert_json_scanned(&project_dir, &packages_dir, &project_dir, &proxy_url, 1).await;

    assert_proxy_served_scans(&server, 2).await;
}
