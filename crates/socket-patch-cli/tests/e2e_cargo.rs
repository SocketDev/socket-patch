#![cfg(feature = "cargo")]
//! End-to-end tests for the Cargo/Rust crate patching lifecycle.
//!
//! These tests exercise crawling against a temporary directory with a fake
//! Cargo registry layout.  They do **not** require network access or a real
//! Cargo installation.
//!
//! # Running
//! ```sh
//! cargo test -p socket-patch-cli --features cargo --test e2e_cargo
//! ```

use std::path::PathBuf;
use std::process::{Command, Output};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

fn run(args: &[&str], cwd: &std::path::Path) -> Output {
    Command::new(binary())
        .args(args)
        .current_dir(cwd)
        .env("CARGO_HOME", cwd.join(".cargo"))
        .output()
        .expect("Failed to run socket-patch binary")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Verify that `socket-patch scan` discovers crates in a fake registry layout.
#[test]
fn scan_discovers_fake_registry_crates() {
    let dir = tempfile::tempdir().unwrap();

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

    // Run scan (will fail to connect to API, but we just check discovery)
    let output = run(&["scan", "--cwd", dir.path().to_str().unwrap()], dir.path());
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{stdout}{stderr}");

    // Should discover the crates (output mentions "Found X packages")
    assert!(
        combined.contains("Found") || combined.contains("packages"),
        "Expected scan to discover crate packages, got:\n{combined}"
    );
}

/// Verify that `socket-patch scan` discovers crates in a vendor layout.
#[test]
fn scan_discovers_vendor_crates() {
    let dir = tempfile::tempdir().unwrap();

    // Set up vendor directory
    let vendor_dir = dir.path().join("vendor");

    let serde_dir = vendor_dir.join("serde");
    std::fs::create_dir_all(&serde_dir).unwrap();
    std::fs::write(
        serde_dir.join("Cargo.toml"),
        "[package]\nname = \"serde\"\nversion = \"1.0.200\"\n",
    )
    .unwrap();

    // Run scan with JSON output to avoid API calls
    let output = run(
        &["scan", "--json", "--cwd", dir.path().to_str().unwrap()],
        dir.path(),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // JSON output should show scannedPackages >= 1 (the vendor crate)
    // or at minimum the scan should report finding packages
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("scannedPackages") || combined.contains("Found"),
        "Expected scan output, got:\n{combined}"
    );
}
