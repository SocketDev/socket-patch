#![cfg(feature = "golang")]
//! End-to-end tests for the Go module patching lifecycle.
//!
//! These tests exercise crawling against a temporary directory with a fake
//! Go module cache layout.  They do **not** require network access or a real
//! Go installation.
//!
//! # Running
//! ```sh
//! cargo test -p socket-patch-cli --features golang --test e2e_golang
//! ```

use std::path::PathBuf;
use std::process::{Command, Output};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

fn run(args: &[&str], cwd: &std::path::Path, gomodcache: &std::path::Path) -> Output {
    Command::new(binary())
        .args(args)
        .current_dir(cwd)
        .env("GOMODCACHE", gomodcache)
        // Pin the cache lookup to GOMODCACHE only: a stray GOPATH/HOME in the
        // test environment must not let the crawler wander into a real module
        // cache and inflate the discovered count.
        .env_remove("GOPATH")
        .output()
        .expect("Failed to run socket-patch binary")
}

/// Run `socket-patch scan --json ...`, assert the process succeeded, and
/// return the parsed JSON envelope from stdout.
///
/// Parsing (rather than substring matching) means a malformed or missing
/// envelope fails the test loudly instead of slipping past a `.contains()`
/// check. Doing this offline is safe: the package *count* is derived from the
/// local crawl and is emitted regardless of whether the API query succeeds.
fn scan_json(cwd: &std::path::Path, gomodcache: &std::path::Path) -> serde_json::Value {
    let output = run(
        &["scan", "--json", "--cwd", cwd.to_str().unwrap()],
        cwd,
        gomodcache,
    );
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Verify that `socket-patch scan` discovers Go modules in a fake module cache.
#[test]
fn scan_discovers_go_modules() {
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

    // Create a go.mod in the project directory so local mode activates
    std::fs::write(
        dir.path().join("go.mod"),
        "module example.com/myproject\n\ngo 1.21\n",
    )
    .unwrap();

    // --- JSON path: assert the EXACT discovered count, not just "non-zero".
    // The old test accepted `contains("Found") || contains("packages")`, which
    // is satisfied even by the empty-scan envelope (`"scannedPackages": 0`) or
    // the "No packages found" message — so a crawler that discovered nothing
    // still passed. Pin the count to exactly the two modules planted above.
    let json = scan_json(dir.path(), &cache_dir);
    assert_eq!(
        json["status"], "success",
        "scan envelope must report success; got:\n{json:#}"
    );
    assert_eq!(
        json["scannedPackages"], 2,
        "scan must discover exactly the two Go modules (gin + text); got:\n{json:#}"
    );

    // --- Human path: the count must be attributed to the *go* ecosystem,
    // proving the Go crawler (not an accidental npm/pypi pickup) found them.
    // Also guards against the old loophole where "No packages found" still
    // satisfied a `contains("packages")` check.
    let output = run(
        &["scan", "--cwd", dir.path().to_str().unwrap()],
        dir.path(),
        &cache_dir,
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{stdout}{stderr}");
    assert!(
        output.status.success(),
        "human scan should exit 0, got {:?}\n{combined}",
        output.status.code()
    );
    assert!(
        combined.contains("Found 2 packages") && combined.contains("2 go"),
        "Expected human scan to report 'Found 2 packages (2 go)', got:\n{combined}"
    );
    assert!(
        !combined.contains("No packages found"),
        "scan reported no packages despite a populated module cache:\n{combined}"
    );
}

/// Verify that `socket-patch scan` discovers case-encoded Go modules.
///
/// Go's module cache stores uppercase letters as `!`+lowercase, so
/// `github.com/Azure/...` lands on disk under `github.com/!azure/...`. The
/// crawler must descend into the `!azure` directory and count the module; a
/// crawler that skipped `!`-prefixed dirs (or failed the layout) would report
/// zero.
#[test]
fn scan_discovers_case_encoded_modules() {
    let dir = tempfile::tempdir().unwrap();
    let cache_dir = dir.path().join("gomodcache");

    // Create case-encoded module: github.com/!azure/azure-sdk-for-go@v1.0.0
    // (represents github.com/Azure/azure-sdk-for-go)
    let azure_dir = cache_dir
        .join("github.com")
        .join("!azure")
        .join("azure-sdk-for-go@v1.0.0");
    std::fs::create_dir_all(&azure_dir).unwrap();

    // Create a go.mod in the project directory so local mode activates.
    std::fs::write(
        dir.path().join("go.mod"),
        "module example.com/myproject\n\ngo 1.21\n",
    )
    .unwrap();

    // --- JSON path: exactly one case-encoded module must be discovered.
    // The old assertion `contains("scannedPackages") || contains("Found")`
    // was vacuous: the empty-scan envelope ALSO emits `"scannedPackages": 0`,
    // so the test passed even when the `!azure` directory was never found.
    // Pin the count to exactly 1.
    let json = scan_json(dir.path(), &cache_dir);
    assert_eq!(
        json["status"], "success",
        "scan envelope must report success; got:\n{json:#}"
    );
    assert_eq!(
        json["scannedPackages"], 1,
        "scan must discover exactly the one case-encoded module under !azure; got:\n{json:#}"
    );

    // --- Human path: the discovery must be attributed to the go ecosystem and
    // must not fall through to "No packages found" (the old loophole).
    let output = run(
        &["scan", "--cwd", dir.path().to_str().unwrap()],
        dir.path(),
        &cache_dir,
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");
    assert!(
        output.status.success(),
        "human scan should exit 0, got {:?}\n{combined}",
        output.status.code()
    );
    assert!(
        combined.contains("Found 1 packages") && combined.contains("1 go"),
        "Expected human scan to report 'Found 1 packages (1 go)', got:\n{combined}"
    );
    assert!(
        !combined.contains("No packages found"),
        "scan reported no packages despite a populated module cache:\n{combined}"
    );
}
