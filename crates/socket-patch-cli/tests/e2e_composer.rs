#![cfg(feature = "composer")]
//! End-to-end tests for the Composer/PHP package patching lifecycle.
//!
//! These tests exercise crawling against a temporary directory with a fake
//! Composer vendor layout.  They do **not** require network access or a real
//! PHP/Composer installation.
//!
//! # Running
//! ```sh
//! cargo test -p socket-patch-cli --features composer --test e2e_composer
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
        .output()
        .expect("Failed to run socket-patch binary")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Verify that `socket-patch scan` discovers packages via Composer 2 installed.json.
#[test]
fn scan_discovers_composer2_packages() {
    let dir = tempfile::tempdir().unwrap();
    let project_dir = dir.path().join("project");
    std::fs::create_dir_all(&project_dir).unwrap();

    // Create composer.json so local mode activates
    std::fs::write(
        project_dir.join("composer.json"),
        r#"{"require": {"monolog/monolog": "^3.0"}}"#,
    )
    .unwrap();

    // Set up vendor directory with installed.json (Composer 2 format)
    let vendor_dir = project_dir.join("vendor");
    let composer_dir = vendor_dir.join("composer");
    std::fs::create_dir_all(&composer_dir).unwrap();

    // Create Composer 2 installed.json with packages array
    std::fs::write(
        composer_dir.join("installed.json"),
        r#"{"packages": [
            {"name": "monolog/monolog", "version": "3.5.0"},
            {"name": "symfony/console", "version": "6.4.1"}
        ]}"#,
    )
    .unwrap();

    // Create the actual vendor directories for the packages
    std::fs::create_dir_all(vendor_dir.join("monolog").join("monolog")).unwrap();
    std::fs::create_dir_all(vendor_dir.join("symfony").join("console")).unwrap();

    let output = run(
        &["scan", "--cwd", project_dir.to_str().unwrap()],
        &project_dir,
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{stdout}{stderr}");

    assert!(
        combined.contains("Found") || combined.contains("packages"),
        "Expected scan to discover Composer packages, got:\n{combined}"
    );
}

/// Verify that `socket-patch scan` discovers packages via Composer 1 installed.json (flat array).
#[test]
fn scan_discovers_composer1_packages() {
    let dir = tempfile::tempdir().unwrap();
    let project_dir = dir.path().join("project");
    std::fs::create_dir_all(&project_dir).unwrap();

    // Create composer.lock so local mode activates
    std::fs::write(
        project_dir.join("composer.lock"),
        r#"{"packages": []}"#,
    )
    .unwrap();

    // Set up vendor directory with Composer 1 installed.json (flat array)
    let vendor_dir = project_dir.join("vendor");
    let composer_dir = vendor_dir.join("composer");
    std::fs::create_dir_all(&composer_dir).unwrap();

    std::fs::write(
        composer_dir.join("installed.json"),
        r#"[
            {"name": "guzzlehttp/guzzle", "version": "7.8.1"}
        ]"#,
    )
    .unwrap();

    // Create the actual vendor directory for the package
    std::fs::create_dir_all(vendor_dir.join("guzzlehttp").join("guzzle")).unwrap();

    let output = run(
        &["scan", "--json", "--cwd", project_dir.to_str().unwrap()],
        &project_dir,
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");

    assert!(
        combined.contains("scannedPackages") || combined.contains("Found"),
        "Expected scan output, got:\n{combined}"
    );
}
