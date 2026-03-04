//! End-to-end tests for the npm patch lifecycle.
//!
//! These tests exercise the full CLI against the real Socket API, using the
//! **minimist@1.2.2** patch (UUID `80630680-4da6-45f9-bba8-b888e0ffd58c`),
//! which fixes CVE-2021-44906 (Prototype Pollution).
//!
//! # Prerequisites
//! - `npm` on PATH
//! - Network access to `patches-api.socket.dev` and `registry.npmjs.org`
//!
//! # Running
//! ```sh
//! cargo test -p socket-patch-cli --test e2e_npm -- --ignored
//! ```

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const NPM_UUID: &str = "80630680-4da6-45f9-bba8-b888e0ffd58c";
#[allow(dead_code)]
const NPM_PURL: &str = "pkg:npm/minimist@1.2.2";

/// Git SHA-256 of the *unpatched* `index.js` shipped with minimist 1.2.2.
const BEFORE_HASH: &str = "311f1e893e6eac502693fad8617dcf5353a043ccc0f7b4ba9fe385e838b67a10";

/// Git SHA-256 of the *patched* `index.js` after the security fix.
const AFTER_HASH: &str = "043f04d19e884aa5f8371428718d2a3f27a0d231afe77a2620ac6312f80aaa28";

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

/// Run the CLI binary with the given args, setting `cwd` as the working dir.
/// Returns `(exit_code, stdout, stderr)`.
fn run(cwd: &Path, args: &[&str]) -> (i32, String, String) {
    let out: Output = Command::new(binary())
        .args(args)
        .current_dir(cwd)
        .env_remove("SOCKET_API_TOKEN") // force public proxy (free-tier)
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

fn npm_run(cwd: &Path, args: &[&str]) {
    let out = Command::new("npm")
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("failed to run npm");
    assert!(
        out.status.success(),
        "npm {args:?} failed (exit {:?}).\nstdout:\n{}\nstderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

/// Write a minimal package.json (avoids `npm init -y` which rejects temp dir
/// names that start with `.` or contain invalid characters).
fn write_package_json(cwd: &Path) {
    std::fs::write(
        cwd.join("package.json"),
        r#"{"name":"e2e-test","version":"0.0.0","private":true}"#,
    )
    .expect("write package.json");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Full lifecycle: get → verify → list → rollback → apply → remove.
#[test]
#[ignore]
fn test_npm_full_lifecycle() {
    if !has_command("npm") {
        eprintln!("SKIP: npm not found on PATH");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let cwd = dir.path();

    // -- Setup: create a project and install minimist@1.2.2 ----------------
    write_package_json(cwd);
    npm_run(cwd, &["install", "minimist@1.2.2"]);

    let index_js = cwd.join("node_modules/minimist/index.js");
    assert!(index_js.exists(), "minimist/index.js must exist after npm install");

    // Confirm the original file matches the expected before-hash.
    assert_eq!(
        git_sha256_file(&index_js),
        BEFORE_HASH,
        "freshly installed index.js should have the expected beforeHash"
    );

    // -- GET: download + apply patch ---------------------------------------
    assert_run_ok(cwd, &["get", NPM_UUID], "get");

    // Manifest should exist and contain the patch.
    let manifest_path = cwd.join(".socket/manifest.json");
    assert!(manifest_path.exists(), ".socket/manifest.json should exist after get");

    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
    let patch = &manifest["patches"][NPM_PURL];
    assert!(patch.is_object(), "manifest should contain {NPM_PURL}");
    assert_eq!(patch["uuid"].as_str().unwrap(), NPM_UUID);

    // The file should now be patched.
    assert_eq!(
        git_sha256_file(&index_js),
        AFTER_HASH,
        "index.js should match afterHash after get"
    );

    // -- LIST: verify JSON output ------------------------------------------
    let (stdout, _) = assert_run_ok(cwd, &["list", "--json"], "list --json");
    let list: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let patches = list["patches"].as_array().expect("patches should be an array");
    assert_eq!(patches.len(), 1);
    assert_eq!(patches[0]["uuid"].as_str().unwrap(), NPM_UUID);
    assert_eq!(patches[0]["purl"].as_str().unwrap(), NPM_PURL);

    let vulns = patches[0]["vulnerabilities"]
        .as_array()
        .expect("vulnerabilities array");
    assert!(!vulns.is_empty(), "patch should report at least one vulnerability");

    // Verify the vulnerability details match CVE-2021-44906
    let has_cve = vulns.iter().any(|v| {
        v["cves"]
            .as_array()
            .map_or(false, |cves| cves.iter().any(|c| c == "CVE-2021-44906"))
    });
    assert!(has_cve, "vulnerability list should include CVE-2021-44906");

    // -- ROLLBACK: restore original file -----------------------------------
    assert_run_ok(cwd, &["rollback"], "rollback");

    assert_eq!(
        git_sha256_file(&index_js),
        BEFORE_HASH,
        "index.js should match beforeHash after rollback"
    );

    // -- APPLY: re-apply from manifest ------------------------------------
    assert_run_ok(cwd, &["apply"], "apply");

    assert_eq!(
        git_sha256_file(&index_js),
        AFTER_HASH,
        "index.js should match afterHash after re-apply"
    );

    // -- REMOVE: rollback + remove from manifest ---------------------------
    assert_run_ok(cwd, &["remove", NPM_UUID], "remove");

    // File should be back to original.
    assert_eq!(
        git_sha256_file(&index_js),
        BEFORE_HASH,
        "index.js should match beforeHash after remove"
    );

    // Manifest should have no patches left.
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
    assert!(
        manifest["patches"].as_object().unwrap().is_empty(),
        "manifest should be empty after remove"
    );
}

/// `apply --dry-run` should not modify files on disk.
#[test]
#[ignore]
fn test_npm_dry_run() {
    if !has_command("npm") {
        eprintln!("SKIP: npm not found on PATH");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let cwd = dir.path();

    write_package_json(cwd);
    npm_run(cwd, &["install", "minimist@1.2.2"]);

    let index_js = cwd.join("node_modules/minimist/index.js");
    assert_eq!(git_sha256_file(&index_js), BEFORE_HASH);

    // Download the patch *without* applying.
    assert_run_ok(cwd, &["get", NPM_UUID, "--no-apply"], "get --no-apply");

    // File should still be original.
    assert_eq!(
        git_sha256_file(&index_js),
        BEFORE_HASH,
        "file should not change after get --no-apply"
    );

    // Dry-run should succeed but leave file untouched.
    assert_run_ok(cwd, &["apply", "--dry-run"], "apply --dry-run");

    assert_eq!(
        git_sha256_file(&index_js),
        BEFORE_HASH,
        "file should not change after apply --dry-run"
    );

    // Real apply should work.
    assert_run_ok(cwd, &["apply"], "apply");

    assert_eq!(
        git_sha256_file(&index_js),
        AFTER_HASH,
        "file should match afterHash after real apply"
    );
}

/// Global lifecycle: scan → get → list → rollback → apply → remove using `-g --global-prefix`.
#[test]
#[ignore]
fn test_npm_global_lifecycle() {
    if !has_command("npm") {
        eprintln!("SKIP: npm not found on PATH");
        return;
    }

    let global_dir = tempfile::tempdir().unwrap();
    let cwd_dir = tempfile::tempdir().unwrap();
    let cwd = cwd_dir.path();

    // -- Setup: install minimist@1.2.2 globally into a temp prefix ----------
    let out = Command::new("npm")
        .args(["install", "-g", "--prefix", global_dir.path().to_str().unwrap(), "minimist@1.2.2"])
        .output()
        .expect("failed to run npm install -g");
    assert!(
        out.status.success(),
        "npm install -g failed.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    // On Unix, npm -g --prefix puts packages under <prefix>/lib/node_modules/
    // On Windows, it's <prefix>/node_modules/
    let nm_path = if cfg!(windows) {
        global_dir.path().join("node_modules")
    } else {
        global_dir.path().join("lib/node_modules")
    };

    let index_js = nm_path.join("minimist/index.js");
    assert!(
        index_js.exists(),
        "minimist/index.js must exist after global install at {}",
        index_js.display()
    );
    assert_eq!(
        git_sha256_file(&index_js),
        BEFORE_HASH,
        "globally installed index.js should have the expected beforeHash"
    );

    let nm_str = nm_path.to_str().unwrap();

    // -- SCAN: verify scan -g finds the package ------------------------------
    let (stdout, _) = assert_run_ok(
        cwd,
        &["scan", "-g", "--global-prefix", nm_str, "--json"],
        "scan -g --json",
    );
    let scan: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let scanned = scan["scannedPackages"]
        .as_u64()
        .expect("scannedPackages should be a number");
    assert!(scanned >= 1, "scan should find at least 1 package, got {scanned}");

    // -- GET: download + apply patch globally --------------------------------
    assert_run_ok(
        cwd,
        &["get", NPM_UUID, "-g", "--global-prefix", nm_str],
        "get -g",
    );

    let manifest_path = cwd.join(".socket/manifest.json");
    assert!(manifest_path.exists(), "manifest should exist after get");
    assert_eq!(
        git_sha256_file(&index_js),
        AFTER_HASH,
        "index.js should match afterHash after global get"
    );

    // -- LIST: verify patch in output ----------------------------------------
    let (stdout, _) = assert_run_ok(cwd, &["list", "--json"], "list --json");
    let list: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let patches = list["patches"].as_array().expect("patches array");
    assert_eq!(patches.len(), 1);
    assert_eq!(patches[0]["uuid"].as_str().unwrap(), NPM_UUID);

    // -- ROLLBACK: restore original file globally ----------------------------
    assert_run_ok(
        cwd,
        &["rollback", "-g", "--global-prefix", nm_str],
        "rollback -g",
    );
    assert_eq!(
        git_sha256_file(&index_js),
        BEFORE_HASH,
        "index.js should match beforeHash after global rollback"
    );

    // -- APPLY: re-apply from manifest globally ------------------------------
    assert_run_ok(
        cwd,
        &["apply", "-g", "--global-prefix", nm_str],
        "apply -g",
    );
    assert_eq!(
        git_sha256_file(&index_js),
        AFTER_HASH,
        "index.js should match afterHash after global apply"
    );

    // -- REMOVE: rollback + remove from manifest globally --------------------
    assert_run_ok(
        cwd,
        &["remove", NPM_UUID, "-g", "--global-prefix", nm_str],
        "remove -g",
    );
    assert_eq!(
        git_sha256_file(&index_js),
        BEFORE_HASH,
        "index.js should match beforeHash after global remove"
    );

    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
    assert!(
        manifest["patches"].as_object().unwrap().is_empty(),
        "manifest should be empty after global remove"
    );
}

/// UUID shortcut: `socket-patch <UUID>` should behave like `socket-patch get <UUID>`.
#[test]
#[ignore]
fn test_npm_uuid_shortcut() {
    if !has_command("npm") {
        eprintln!("SKIP: npm not found on PATH");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let cwd = dir.path();

    write_package_json(cwd);
    npm_run(cwd, &["install", "minimist@1.2.2"]);

    let index_js = cwd.join("node_modules/minimist/index.js");
    assert_eq!(git_sha256_file(&index_js), BEFORE_HASH);

    // Run with bare UUID (no "get" subcommand).
    assert_run_ok(cwd, &[NPM_UUID], "uuid shortcut");

    assert_eq!(
        git_sha256_file(&index_js),
        AFTER_HASH,
        "index.js should match afterHash after UUID shortcut"
    );

    let manifest_path = cwd.join(".socket/manifest.json");
    assert!(manifest_path.exists(), "manifest should exist after UUID shortcut");
}
