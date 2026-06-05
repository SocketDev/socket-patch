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

/// Run `socket-patch scan --json ...`, assert the process succeeded, and
/// return the parsed JSON envelope from stdout.
///
/// Parsing (rather than substring matching) means a malformed or missing
/// envelope fails the test loudly instead of slipping past a `.contains()`
/// check. Doing this offline is safe: the package *count* is derived from the
/// local crawl and is emitted regardless of whether the API query succeeds.
fn scan_json(cwd: &std::path::Path) -> serde_json::Value {
    let output = run(&["scan", "--json", "--cwd", cwd.to_str().unwrap()], cwd);
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

/// Verify that `socket-patch scan` discovers crates in a registry-cache layout
/// (`$CARGO_HOME/registry/src/index.crates.io-*/<name>-<version>/`).
#[test]
fn scan_discovers_fake_registry_crates() {
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
    let json = scan_json(dir.path());
    assert_eq!(
        json["scannedPackages"], 2,
        "scan must discover exactly the two registry crates (serde + tokio); got:\n{json:#}"
    );

    // --- Human path: the count must be attributed to the *cargo* ecosystem,
    // proving the registry crawler (not some accidental npm/pypi pickup) is
    // what found them. This also guards against the old loophole where the
    // failure message "No packages found" satisfied a `contains("packages")`
    // check.
    let output = run(&["scan", "--cwd", dir.path().to_str().unwrap()], dir.path());
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("Found 2 packages") && combined.contains("cargo"),
        "Expected human scan to report 'Found 2 packages (2 cargo)', got:\n{combined}"
    );
    assert!(
        !combined.contains("No packages found"),
        "scan reported no packages despite a populated registry:\n{combined}"
    );
}

/// Verify that `socket-patch scan` discovers crates in a vendor layout
/// (`<cwd>/vendor/<name>/`).
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

    // --- JSON path: exactly one vendored crate must be discovered.
    let json = scan_json(dir.path());
    assert_eq!(
        json["scannedPackages"], 1,
        "scan must discover exactly the one vendored crate (serde); got:\n{json:#}"
    );

    // --- Human path: the discovery must be attributed to the cargo ecosystem,
    // and must NOT report "No packages found" (the old loophole).
    let output = run(&["scan", "--cwd", dir.path().to_str().unwrap()], dir.path());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("Found 1 packages") && combined.contains("cargo"),
        "Expected human scan to report 'Found 1 packages (1 cargo)', got:\n{combined}"
    );
    assert!(
        !combined.contains("No packages found"),
        "scan reported no packages despite a populated vendor dir:\n{combined}"
    );
}
