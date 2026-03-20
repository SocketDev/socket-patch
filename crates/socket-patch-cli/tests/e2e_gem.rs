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

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const GEM_UUID: &str = "4bf7fe0b-dc57-4ea8-945f-bc4a04c47a15";
const GEM_PURL: &str = "pkg:gem/activestorage@5.2.0";

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

/// Read the manifest and return the files map for the gem patch.
fn read_patch_files(manifest_path: &Path) -> serde_json::Value {
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(manifest_path).unwrap()).unwrap();
    let patch = &manifest["patches"][GEM_PURL];
    assert!(patch.is_object(), "manifest should contain {GEM_PURL}");
    patch["files"].clone()
}

/// Record hashes of all files in the gem dir that will be patched.
fn record_original_hashes(gem_dir: &Path, files: &serde_json::Value) -> HashMap<String, String> {
    let mut hashes = HashMap::new();
    for (rel_path, _) in files.as_object().expect("files object") {
        let full_path = gem_dir.join(rel_path);
        let hash = if full_path.exists() {
            git_sha256_file(&full_path)
        } else {
            String::new()
        };
        hashes.insert(rel_path.clone(), hash);
    }
    hashes
}

/// Verify all patched files match their afterHash from the manifest.
fn assert_after_hashes(gem_dir: &Path, files: &serde_json::Value) {
    for (rel_path, info) in files.as_object().expect("files object") {
        let after_hash = info["afterHash"]
            .as_str()
            .expect("afterHash should be a string");
        let full_path = gem_dir.join(rel_path);
        assert!(
            full_path.exists(),
            "patched file should exist: {}",
            full_path.display()
        );
        assert_eq!(
            git_sha256_file(&full_path),
            after_hash,
            "hash mismatch for {rel_path} after patching"
        );
    }
}

/// Verify all patched files match their beforeHash (or are removed if new).
fn assert_before_hashes(gem_dir: &Path, files: &serde_json::Value) {
    for (rel_path, info) in files.as_object().expect("files object") {
        let before_hash = info["beforeHash"].as_str().unwrap_or("");
        let full_path = gem_dir.join(rel_path);
        if before_hash.is_empty() {
            assert!(
                !full_path.exists(),
                "new file {rel_path} should be removed after rollback"
            );
        } else {
            assert_eq!(
                git_sha256_file(&full_path),
                before_hash,
                "{rel_path} should match beforeHash"
            );
        }
    }
}

/// Verify files match the originally recorded hashes.
fn assert_original_hashes(gem_dir: &Path, original_hashes: &HashMap<String, String>) {
    for (rel_path, orig_hash) in original_hashes {
        if orig_hash.is_empty() {
            continue;
        }
        let full_path = gem_dir.join(rel_path);
        if full_path.exists() {
            assert_eq!(
                git_sha256_file(&full_path),
                *orig_hash,
                "{rel_path} should match original hash"
            );
        }
    }
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

    // -- GET: download + apply patch ------------------------------------------
    assert_run_ok(cwd, &["get", GEM_UUID], "get");

    let manifest_path = cwd.join(".socket/manifest.json");
    assert!(manifest_path.exists(), ".socket/manifest.json should exist after get");

    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
    let patch = &manifest["patches"][GEM_PURL];
    assert!(patch.is_object(), "manifest should contain {GEM_PURL}");
    assert_eq!(patch["uuid"].as_str().unwrap(), GEM_UUID);

    let files = &patch["files"];
    assert!(
        files.as_object().map_or(false, |f| !f.is_empty()),
        "patch should modify at least one file"
    );

    // Files should now be patched — verify against afterHash from manifest.
    assert_after_hashes(&gem_dir, files);

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
    assert_before_hashes(&gem_dir, files);

    // -- APPLY: re-apply from manifest ----------------------------------------
    assert_run_ok(cwd, &["apply"], "apply");
    assert_after_hashes(&gem_dir, files);

    // -- REMOVE: rollback + remove from manifest ------------------------------
    assert_run_ok(cwd, &["remove", GEM_UUID], "remove");
    assert_before_hashes(&gem_dir, files);

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

    // Download without applying.
    assert_run_ok(cwd, &["get", GEM_UUID, "--no-apply"], "get --no-apply");

    // Read manifest to get file list and expected hashes.
    let manifest_path = cwd.join(".socket/manifest.json");
    let files = read_patch_files(&manifest_path);
    let original_hashes = record_original_hashes(&gem_dir, &files);

    // Files should still be original (not patched).
    assert_original_hashes(&gem_dir, &original_hashes);

    // Dry-run should succeed but leave files untouched.
    assert_run_ok(cwd, &["apply", "--dry-run"], "apply --dry-run");
    assert_original_hashes(&gem_dir, &original_hashes);

    // Real apply should work.
    assert_run_ok(cwd, &["apply"], "apply");
    assert_after_hashes(&gem_dir, &files);
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

    // Download with --save-only.
    assert_run_ok(cwd, &["get", GEM_UUID, "--save-only"], "get --save-only");

    // Read manifest to get file list and expected hashes.
    let manifest_path = cwd.join(".socket/manifest.json");
    let files = read_patch_files(&manifest_path);
    let original_hashes = record_original_hashes(&gem_dir, &files);

    // Files should still be original (not patched).
    assert_original_hashes(&gem_dir, &original_hashes);

    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
    let patch = &manifest["patches"][GEM_PURL];
    assert!(patch.is_object(), "manifest should contain {GEM_PURL}");
    assert_eq!(patch["uuid"].as_str().unwrap(), GEM_UUID);

    // Real apply should work.
    assert_run_ok(cwd, &["apply"], "apply");
    assert_after_hashes(&gem_dir, &files);
}
