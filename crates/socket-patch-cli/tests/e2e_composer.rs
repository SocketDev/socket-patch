//! End-to-end tests for the Composer/PHP package patching lifecycle.
//!
//! These tests exercise crawling against a temporary directory with a fake
//! Composer vendor layout.  They do **not** require network access or a real
//! PHP/Composer installation.
//!
//! # Running
//! ```sh
//! cargo test -p socket-patch-cli --test e2e_composer
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

/// Run the human-readable `socket-patch scan` and return combined stdout+stderr.
fn scan_human(cwd: &std::path::Path) -> String {
    let output = run(&["scan", "--cwd", cwd.to_str().unwrap()], cwd);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "human scan should exit 0, got {:?}\n{stdout}{stderr}",
        output.status.code()
    );
    format!("{stdout}{stderr}")
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

    // Decoy: a populated vendor directory that is NOT listed in
    // installed.json. Discovery is installed.json-driven (the crawler
    // iterates the manifest entries and confirms each one on disk), so this
    // package must NOT be counted. If it ever is, the crawler has regressed
    // to blindly walking vendor/ subdirectories — which the exact-count
    // assertions below would then catch (3 != 2).
    std::fs::create_dir_all(vendor_dir.join("decoy").join("unlisted")).unwrap();

    // --- JSON path: assert the EXACT discovered count, not just "non-zero" and
    // not merely the presence of a `scannedPackages` key (which the envelope
    // always carries, even when zero packages are found). The Composer 2
    // `{"packages": [...]}` parser must surface both packages.
    let json = scan_json(&project_dir);
    assert_eq!(
        json["status"], "success",
        "scan envelope must report success; got:\n{json:#}"
    );
    assert_eq!(
        json["scannedPackages"], 2,
        "scan must discover exactly the two Composer 2 packages \
         (monolog/monolog + symfony/console); got:\n{json:#}"
    );

    // --- Human path: the count must be attributed *entirely* to the php
    // ecosystem. Assert the contiguous `Found 2 packages (2 php)` string
    // rather than two independent substrings (`"Found 2 packages"` AND
    // `"php"`): the latter would also accept a regression that splits the
    // count across ecosystems (e.g. `Found 2 packages (1 php, 1 npm)`) or
    // attributes it to the wrong crawler entirely while "php" leaks in from
    // an unrelated line. The closing paren after `php` pins the breakdown to
    // php-only.
    let combined = scan_human(&project_dir);
    assert!(
        combined.contains("Found 2 packages (2 php)"),
        "Expected human scan to report exactly 'Found 2 packages (2 php)', got:\n{combined}"
    );
    assert!(
        !combined.contains("No packages found"),
        "scan reported no packages despite a populated Composer vendor dir:\n{combined}"
    );
}

/// Verify that `socket-patch scan` discovers packages via Composer 1 installed.json (flat array).
#[test]
fn scan_discovers_composer1_packages() {
    let dir = tempfile::tempdir().unwrap();
    let project_dir = dir.path().join("project");
    std::fs::create_dir_all(&project_dir).unwrap();

    // Create composer.lock so local mode activates
    std::fs::write(project_dir.join("composer.lock"), r#"{"packages": []}"#).unwrap();

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

    // --- JSON path: exactly one package must be discovered via the Composer 1
    // flat-array (top-level `[...]`) form. Asserting the exact count guards
    // against a regression where only the Composer 2 object form is parsed
    // (which would silently yield 0 here while the envelope still validates).
    let json = scan_json(&project_dir);
    assert_eq!(
        json["status"], "success",
        "scan envelope must report success; got:\n{json:#}"
    );
    assert_eq!(
        json["scannedPackages"], 1,
        "scan must discover exactly the one Composer 1 package \
         (guzzlehttp/guzzle) from the flat-array installed.json; got:\n{json:#}"
    );

    // --- Human path: the single package must be attributed *entirely* to the
    // php ecosystem. Assert the contiguous `Found 1 packages (1 php)` string
    // (see the Composer 2 test for why two independent substrings are too
    // weak).
    let combined = scan_human(&project_dir);
    assert!(
        combined.contains("Found 1 packages (1 php)"),
        "Expected human scan to report exactly 'Found 1 packages (1 php)', got:\n{combined}"
    );
    assert!(
        !combined.contains("No packages found"),
        "scan reported no packages despite a populated Composer vendor dir:\n{combined}"
    );
}
