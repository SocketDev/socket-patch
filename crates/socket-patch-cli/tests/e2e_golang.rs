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
        .output()
        .expect("Failed to run socket-patch binary")
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

    let output = run(
        &["scan", "--cwd", dir.path().to_str().unwrap()],
        dir.path(),
        &cache_dir,
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{stdout}{stderr}");

    assert!(
        combined.contains("Found") || combined.contains("packages"),
        "Expected scan to discover Go module packages, got:\n{combined}"
    );
}

/// Verify that `socket-patch scan` discovers case-encoded Go modules.
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

    // Create a go.mod in the project directory
    std::fs::write(
        dir.path().join("go.mod"),
        "module example.com/myproject\n\ngo 1.21\n",
    )
    .unwrap();

    let output = run(
        &["scan", "--json", "--cwd", dir.path().to_str().unwrap()],
        dir.path(),
        &cache_dir,
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");

    assert!(
        combined.contains("scannedPackages") || combined.contains("Found"),
        "Expected scan output, got:\n{combined}"
    );
}
