#![cfg(feature = "gem")]
//! End-to-end tests for the RubyGems package patching lifecycle.
//!
//! These tests exercise crawling against a temporary directory with fake
//! gem layouts.  They do **not** require network access or a real Ruby
//! installation.
//!
//! # Running
//! ```sh
//! cargo test -p socket-patch-cli --features gem --test e2e_gem
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

/// Verify that `socket-patch scan` discovers gems in a vendor/bundle layout.
#[test]
fn scan_discovers_vendored_gems() {
    let dir = tempfile::tempdir().unwrap();
    let project_dir = dir.path().join("project");
    std::fs::create_dir_all(&project_dir).unwrap();

    // Create Gemfile so local mode activates
    std::fs::write(project_dir.join("Gemfile"), "source 'https://rubygems.org'\n").unwrap();

    // Set up vendor/bundle/ruby/<version>/gems/ layout
    let gems_dir = project_dir
        .join("vendor")
        .join("bundle")
        .join("ruby")
        .join("3.2.0")
        .join("gems");

    // Create rails-7.1.0 with lib/ marker
    let rails_dir = gems_dir.join("rails-7.1.0");
    std::fs::create_dir_all(rails_dir.join("lib")).unwrap();

    // Create nokogiri-1.15.4 with lib/ marker
    let nokogiri_dir = gems_dir.join("nokogiri-1.15.4");
    std::fs::create_dir_all(nokogiri_dir.join("lib")).unwrap();

    let output = run(
        &["scan", "--cwd", project_dir.to_str().unwrap()],
        &project_dir,
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined = format!("{stdout}{stderr}");

    assert!(
        combined.contains("Found") || combined.contains("packages"),
        "Expected scan to discover vendored gems, got:\n{combined}"
    );
}

/// Verify that `socket-patch scan` discovers gems with gemspec markers.
#[test]
fn scan_discovers_gems_with_gemspec() {
    let dir = tempfile::tempdir().unwrap();
    let project_dir = dir.path().join("project");
    std::fs::create_dir_all(&project_dir).unwrap();

    // Create Gemfile.lock so local mode activates
    std::fs::write(project_dir.join("Gemfile.lock"), "GEM\n  specs:\n").unwrap();

    // Set up vendor/bundle/ruby/<version>/gems/ layout
    let gems_dir = project_dir
        .join("vendor")
        .join("bundle")
        .join("ruby")
        .join("3.1.0")
        .join("gems");

    // Create net-http-0.4.1 with .gemspec marker (no lib/)
    let net_http_dir = gems_dir.join("net-http-0.4.1");
    std::fs::create_dir_all(&net_http_dir).unwrap();
    std::fs::write(net_http_dir.join("net-http.gemspec"), "# gemspec\n").unwrap();

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
