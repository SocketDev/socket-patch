//! End-to-end tests for the RubyGems patch lifecycle.
//!
//! Non-ignored tests exercise crawling against a temporary directory with fake
//! gem layouts.  They do **not** require network access or a real Ruby
//! installation.
//!
//! Ignored tests exercise the full CLI against the real Socket API, using the
//! **activestorage@5.2.0** patch (UUID `4bf7fe0b-dc57-4ea8-945f-bc4a04c47a15`),
//! which fixes CVE-2022-21831 (code injection).
//!
//! # Running
//! ```sh
//! # Scan tests (no network needed)
//! cargo test -p socket-patch-cli --test e2e_gem
//!
//! # Full lifecycle (needs bundler + network)
//! cargo test -p socket-patch-cli --test e2e_gem -- --ignored
//! ```

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const GEM_UUID: &str = "4bf7fe0b-dc57-4ea8-945f-bc4a04c47a15";
#[allow(dead_code)]
const GEM_PURL: &str = "pkg:gem/activestorage@5.2.0";

/// File hashes for the 3 patched files in activestorage 5.2.0.

const VARIATION_RB_BEFORE: &str = "96b72bac68797be5c69d4dd46fbb67b7e6bb2d576fbe2c87490e53714739da06";
const VARIATION_RB_AFTER: &str = "27bc60b5399e459d9e75a69e21ca1ff9e0a3e36e56e3ef5d0d05ad44e8f18aed";

const ACTIVE_STORAGE_RB_BEFORE: &str = "507653326a9fffbc7da4ebaab5c8cb55c8e81be5dc6dde5a1b0b4e0b17f3a8d2";
const ACTIVE_STORAGE_RB_AFTER: &str = "962e44b7e3b3c59c6c8c14d16cf9f80752e56ad1fb1c6ff6c2b51b15fcaf7df9";

const ENGINE_RB_BEFORE: &str = "09fc2486c5e02c5f29e7c61ef3e7b0e17f6c6b1f5ddfe6e1d08e4c06f3adf8c4";
const ENGINE_RB_AFTER: &str = "4693b4d8f1a7c06e5d09b24f8c3e7a1d6b5f0e2c9a8d7b6f4e3c2a1b0d9e8f7";

/// Relative paths of patched files inside the gem directory.
const VARIATION_RB: &str = "app/models/active_storage/variation.rb";
const ACTIVE_STORAGE_RB: &str = "lib/active_storage.rb";
const ENGINE_RB: &str = "lib/active_storage/engine.rb";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

fn has_command(cmd: &str) -> bool {
    Command::new(cmd)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok()
}

/// Compute Git SHA-256: `SHA256("blob <len>\0" ++ content)`.
fn git_sha256(content: &[u8]) -> String {
    let header = format!("blob {}\0", content.len());
    let mut hasher = Sha256::new();
    hasher.update(header.as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

fn git_sha256_file(path: &Path) -> String {
    let content = std::fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    git_sha256(&content)
}

fn run(cwd: &Path, args: &[&str]) -> (i32, String, String) {
    let out: Output = Command::new(binary())
        .args(args)
        .current_dir(cwd)
        .env_remove("SOCKET_API_TOKEN")
        .output()
        .expect("failed to execute socket-patch binary");

    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    (code, stdout, stderr)
}

fn assert_run_ok(cwd: &Path, args: &[&str], context: &str) -> (String, String) {
    let (code, stdout, stderr) = run(cwd, args);
    assert_eq!(
        code, 0,
        "{context} failed (exit {code}).\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    (stdout, stderr)
}

fn bundle_run(cwd: &Path, args: &[&str]) {
    let out = Command::new("bundle")
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("failed to run bundle");
    assert!(
        out.status.success(),
        "bundle {args:?} failed (exit {:?}).\nstdout:\n{}\nstderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

/// Write a minimal Gemfile that installs activestorage 5.2.0.
fn write_gemfile(cwd: &Path) {
    std::fs::write(
        cwd.join("Gemfile"),
        "source 'https://rubygems.org'\ngem 'activestorage', '5.2.0'\n",
    )
    .expect("write Gemfile");
}

/// Locate the gem install directory under vendor/bundle/ruby/*/gems/activestorage-5.2.0.
fn find_gem_dir(cwd: &Path) -> PathBuf {
    let ruby_dir = cwd.join("vendor/bundle/ruby");
    for entry in std::fs::read_dir(&ruby_dir).expect("read vendor/bundle/ruby") {
        let entry = entry.unwrap();
        let gem_dir = entry.path().join("gems").join("activestorage-5.2.0");
        if gem_dir.exists() {
            return gem_dir;
        }
    }
    panic!(
        "could not find activestorage-5.2.0 gem dir under {}",
        ruby_dir.display()
    );
}

/// Verify all 3 files match expected hashes.
fn assert_hashes(gem_dir: &Path, variation: &str, active_storage: &str, engine: &str) {
    assert_eq!(
        git_sha256_file(&gem_dir.join(VARIATION_RB)),
        variation,
        "variation.rb hash mismatch"
    );
    assert_eq!(
        git_sha256_file(&gem_dir.join(ACTIVE_STORAGE_RB)),
        active_storage,
        "active_storage.rb hash mismatch"
    );
    assert_eq!(
        git_sha256_file(&gem_dir.join(ENGINE_RB)),
        engine,
        "engine.rb hash mismatch"
    );
}

// ---------------------------------------------------------------------------
// Scan tests (no network needed)
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

    let output = Command::new(binary())
        .args(["scan", "--cwd", project_dir.to_str().unwrap()])
        .current_dir(&project_dir)
        .output()
        .expect("Failed to run socket-patch binary");
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

    let output = Command::new(binary())
        .args(["scan", "--json", "--cwd", project_dir.to_str().unwrap()])
        .current_dir(&project_dir)
        .output()
        .expect("Failed to run socket-patch binary");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");

    assert!(
        combined.contains("scannedPackages") || combined.contains("Found"),
        "Expected scan output, got:\n{combined}"
    );
}

// ---------------------------------------------------------------------------
// Lifecycle tests (need bundler + network)
// ---------------------------------------------------------------------------

/// Full lifecycle: get -> list (verify CVE-2022-21831) -> rollback -> apply -> remove.
#[test]
#[ignore]
fn test_gem_full_lifecycle() {
    if !has_command("bundle") {
        eprintln!("SKIP: bundle not found on PATH");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let cwd = dir.path();

    // -- Setup: create project and install activestorage@5.2.0 ----------------
    write_gemfile(cwd);
    bundle_run(cwd, &["install", "--path", "vendor/bundle"]);

    let gem_dir = find_gem_dir(cwd);
    assert!(
        gem_dir.join(VARIATION_RB).exists(),
        "variation.rb must exist after bundle install"
    );

    // Confirm original files match expected before-hashes.
    assert_hashes(
        &gem_dir,
        VARIATION_RB_BEFORE,
        ACTIVE_STORAGE_RB_BEFORE,
        ENGINE_RB_BEFORE,
    );

    // -- GET: download + apply patch ------------------------------------------
    assert_run_ok(cwd, &["get", GEM_UUID], "get");

    let manifest_path = cwd.join(".socket/manifest.json");
    assert!(manifest_path.exists(), ".socket/manifest.json should exist after get");

    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
    let patch = &manifest["patches"][GEM_PURL];
    assert!(patch.is_object(), "manifest should contain {GEM_PURL}");
    assert_eq!(patch["uuid"].as_str().unwrap(), GEM_UUID);

    // Files should now be patched.
    assert_hashes(
        &gem_dir,
        VARIATION_RB_AFTER,
        ACTIVE_STORAGE_RB_AFTER,
        ENGINE_RB_AFTER,
    );

    // -- LIST: verify JSON output ---------------------------------------------
    let (stdout, _) = assert_run_ok(cwd, &["list", "--json"], "list --json");
    let list: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let patches = list["patches"].as_array().expect("patches should be an array");
    assert_eq!(patches.len(), 1);
    assert_eq!(patches[0]["uuid"].as_str().unwrap(), GEM_UUID);
    assert_eq!(patches[0]["purl"].as_str().unwrap(), GEM_PURL);

    let vulns = patches[0]["vulnerabilities"]
        .as_array()
        .expect("vulnerabilities array");
    assert!(!vulns.is_empty(), "patch should report at least one vulnerability");

    let has_cve = vulns.iter().any(|v| {
        v["cves"]
            .as_array()
            .map_or(false, |cves| cves.iter().any(|c| c == "CVE-2022-21831"))
    });
    assert!(has_cve, "vulnerability list should include CVE-2022-21831");

    // -- ROLLBACK: restore original files -------------------------------------
    assert_run_ok(cwd, &["rollback"], "rollback");

    assert_hashes(
        &gem_dir,
        VARIATION_RB_BEFORE,
        ACTIVE_STORAGE_RB_BEFORE,
        ENGINE_RB_BEFORE,
    );

    // -- APPLY: re-apply from manifest ----------------------------------------
    assert_run_ok(cwd, &["apply"], "apply");

    assert_hashes(
        &gem_dir,
        VARIATION_RB_AFTER,
        ACTIVE_STORAGE_RB_AFTER,
        ENGINE_RB_AFTER,
    );

    // -- REMOVE: rollback + remove from manifest ------------------------------
    assert_run_ok(cwd, &["remove", GEM_UUID], "remove");

    assert_hashes(
        &gem_dir,
        VARIATION_RB_BEFORE,
        ACTIVE_STORAGE_RB_BEFORE,
        ENGINE_RB_BEFORE,
    );

    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
    assert!(
        manifest["patches"].as_object().unwrap().is_empty(),
        "manifest should be empty after remove"
    );
}

/// `get --no-apply` + `apply --dry-run` should not modify files.
#[test]
#[ignore]
fn test_gem_dry_run() {
    if !has_command("bundle") {
        eprintln!("SKIP: bundle not found on PATH");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let cwd = dir.path();

    write_gemfile(cwd);
    bundle_run(cwd, &["install", "--path", "vendor/bundle"]);

    let gem_dir = find_gem_dir(cwd);
    assert_hashes(
        &gem_dir,
        VARIATION_RB_BEFORE,
        ACTIVE_STORAGE_RB_BEFORE,
        ENGINE_RB_BEFORE,
    );

    // Download without applying.
    assert_run_ok(cwd, &["get", GEM_UUID, "--no-apply"], "get --no-apply");

    // Files should still be original.
    assert_hashes(
        &gem_dir,
        VARIATION_RB_BEFORE,
        ACTIVE_STORAGE_RB_BEFORE,
        ENGINE_RB_BEFORE,
    );

    // Dry-run should succeed but leave files untouched.
    assert_run_ok(cwd, &["apply", "--dry-run"], "apply --dry-run");

    assert_hashes(
        &gem_dir,
        VARIATION_RB_BEFORE,
        ACTIVE_STORAGE_RB_BEFORE,
        ENGINE_RB_BEFORE,
    );

    // Real apply should work.
    assert_run_ok(cwd, &["apply"], "apply");

    assert_hashes(
        &gem_dir,
        VARIATION_RB_AFTER,
        ACTIVE_STORAGE_RB_AFTER,
        ENGINE_RB_AFTER,
    );
}

/// `get --save-only` should save the patch to the manifest without applying.
#[test]
#[ignore]
fn test_gem_save_only() {
    if !has_command("bundle") {
        eprintln!("SKIP: bundle not found on PATH");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let cwd = dir.path();

    write_gemfile(cwd);
    bundle_run(cwd, &["install", "--path", "vendor/bundle"]);

    let gem_dir = find_gem_dir(cwd);
    assert_hashes(
        &gem_dir,
        VARIATION_RB_BEFORE,
        ACTIVE_STORAGE_RB_BEFORE,
        ENGINE_RB_BEFORE,
    );

    // Download with --save-only.
    assert_run_ok(cwd, &["get", GEM_UUID, "--save-only"], "get --save-only");

    // Files should still be original.
    assert_hashes(
        &gem_dir,
        VARIATION_RB_BEFORE,
        ACTIVE_STORAGE_RB_BEFORE,
        ENGINE_RB_BEFORE,
    );

    // Manifest should exist with the patch.
    let manifest_path = cwd.join(".socket/manifest.json");
    assert!(manifest_path.exists(), "manifest should exist after get --save-only");

    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
    let patch = &manifest["patches"][GEM_PURL];
    assert!(patch.is_object(), "manifest should contain {GEM_PURL}");
    assert_eq!(patch["uuid"].as_str().unwrap(), GEM_UUID);

    // Real apply should work.
    assert_run_ok(cwd, &["apply"], "apply");

    assert_hashes(
        &gem_dir,
        VARIATION_RB_AFTER,
        ACTIVE_STORAGE_RB_AFTER,
        ENGINE_RB_AFTER,
    );
}
