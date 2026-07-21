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
    let mut cmd = Command::new(binary());
    cmd.args(args).current_dir(cwd);
    // The binary binds a wide `SOCKET_*` env surface (SOCKET_CWD,
    // SOCKET_DRY_RUN, SOCKET_STRICT, SOCKET_ECOSYSTEMS, SOCKET_GLOBAL_PREFIX,
    // ...). An ambient value silently changes what these tests exercise —
    // SOCKET_DRY_RUN=true turns every real apply into a no-op, and
    // SOCKET_GLOBAL_PREFIX flips commands into global mode, aiming mutations
    // at the host's *real* global node_modules. Scrub the whole prefix so
    // only the flags each test passes are in effect; removing
    // SOCKET_API_TOKEN also forces the public proxy (free-tier). Telemetry
    // opt-outs are deliberately kept so an opted-out dev stays opted out.
    for (key, _) in std::env::vars_os() {
        let name = key.to_string_lossy();
        if name.starts_with("SOCKET_") && !name.contains("TELEMETRY") && name != "SOCKET_NO_CONFIG"
        {
            cmd.env_remove(&key);
        }
    }
    let out: Output = cmd.output().expect("failed to execute socket-patch binary");

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
    assert!(
        index_js.exists(),
        "minimist/index.js must exist after npm install"
    );

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
    assert!(
        manifest_path.exists(),
        ".socket/manifest.json should exist after get"
    );

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
    // v3.0 envelope: `list --json` emits {command,status,events,summary}
    // with one `discovered` event per manifest entry. Patch metadata
    // (vulnerabilities, tier, license, etc.) lives under `details`.
    let (stdout, _) = assert_run_ok(cwd, &["list", "--json"], "list --json");
    let list: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let events = list["events"].as_array().expect("envelope events array");
    let patches: Vec<&serde_json::Value> = events
        .iter()
        .filter(|e| e["action"] == "discovered")
        .collect();
    assert_eq!(patches.len(), 1);
    assert_eq!(patches[0]["uuid"].as_str().unwrap(), NPM_UUID);
    assert_eq!(patches[0]["purl"].as_str().unwrap(), NPM_PURL);

    let vulns = patches[0]["details"]["vulnerabilities"]
        .as_array()
        .expect("vulnerabilities array");
    assert!(
        !vulns.is_empty(),
        "patch should report at least one vulnerability"
    );

    // Verify the vulnerability details match CVE-2021-44906
    let has_cve = vulns.iter().any(|v| {
        v["cves"]
            .as_array()
            .is_some_and(|cves| cves.iter().any(|c| c == "CVE-2021-44906"))
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

    // Dry-run should report that the patch *would* apply, but leave the
    // file untouched. Asserting only "file unchanged" is a loophole: a
    // dry-run that silently does nothing (never even detecting the saved
    // patch) would pass it. Use the JSON envelope to require a `verified`
    // event for our exact PURL so a no-op dry-run regresses loudly.
    let (stdout, _) = assert_run_ok(
        cwd,
        &["apply", "--dry-run", "--json"],
        "apply --dry-run --json",
    );
    let env: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("apply --dry-run --json should emit JSON: {e}\nstdout:\n{stdout}")
    });
    assert_eq!(
        env["dryRun"],
        serde_json::Value::Bool(true),
        "envelope should be flagged dryRun"
    );
    let events = env["events"].as_array().expect("envelope events array");
    let verified: Vec<&serde_json::Value> = events
        .iter()
        .filter(|e| e["action"] == "verified")
        .collect();
    assert_eq!(
        verified.len(),
        1,
        "dry-run should report exactly one verifiable patch, got: {events:#?}"
    );
    assert_eq!(verified[0]["purl"].as_str().unwrap(), NPM_PURL);

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
        .args([
            "install",
            "-g",
            "--prefix",
            global_dir.path().to_str().unwrap(),
            "minimist@1.2.2",
        ])
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
    assert_eq!(
        scan["status"], "success",
        "scan envelope should report success, got: {scan:#?}"
    );
    let scanned = scan["scannedPackages"]
        .as_u64()
        .expect("scannedPackages should be a number");
    assert!(
        scanned >= 1,
        "scan should find at least 1 package, got {scanned}"
    );

    // A bare count is a loophole: scan could enumerate *some* package while
    // failing to discover minimist or match its patch, and `scanned >= 1`
    // would still pass. Require that the scan actually surfaced our exact
    // PURL *with* the expected patch UUID in `packages`.
    let packages = scan["packages"].as_array().expect("scan packages array");
    let minimist = packages
        .iter()
        .find(|p| p["purl"].as_str() == Some(NPM_PURL))
        .unwrap_or_else(|| panic!("scan should discover {NPM_PURL}, got packages: {packages:#?}"));
    let patches = minimist["patches"]
        .as_array()
        .expect("discovered package should carry a patches array");
    assert!(
        patches.iter().any(|p| p["uuid"].as_str() == Some(NPM_UUID)),
        "scan should match patch {NPM_UUID} for minimist, got patches: {patches:#?}"
    );
    assert!(
        scan["packagesWithPatches"].as_u64().unwrap_or(0) >= 1,
        "packagesWithPatches should be >= 1, got: {}",
        scan["packagesWithPatches"]
    );

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
    // v3.0 envelope shape — see the main lifecycle test for details.
    let (stdout, _) = assert_run_ok(cwd, &["list", "--json"], "list --json");
    let list: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let events = list["events"].as_array().expect("envelope events array");
    let patches: Vec<&serde_json::Value> = events
        .iter()
        .filter(|e| e["action"] == "discovered")
        .collect();
    assert_eq!(patches.len(), 1);
    assert_eq!(patches[0]["uuid"].as_str().unwrap(), NPM_UUID);
    assert_eq!(patches[0]["purl"].as_str().unwrap(), NPM_PURL);

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
    assert_run_ok(cwd, &["apply", "-g", "--global-prefix", nm_str], "apply -g");
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

/// `get --save-only` should save the patch to the manifest without applying.
#[test]
#[ignore]
fn test_npm_save_only() {
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

    // Download with --save-only (new name for --no-apply).
    assert_run_ok(cwd, &["get", NPM_UUID, "--save-only"], "get --save-only");

    // File should still be original.
    assert_eq!(
        git_sha256_file(&index_js),
        BEFORE_HASH,
        "file should not change after get --save-only"
    );

    // Manifest should exist with the patch.
    let manifest_path = cwd.join(".socket/manifest.json");
    assert!(
        manifest_path.exists(),
        "manifest should exist after get --save-only"
    );

    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
    let patch = &manifest["patches"][NPM_PURL];
    assert!(patch.is_object(), "manifest should contain {NPM_PURL}");
    assert_eq!(patch["uuid"].as_str().unwrap(), NPM_UUID);

    // Real apply should work.
    assert_run_ok(cwd, &["apply"], "apply");
    assert_eq!(
        git_sha256_file(&index_js),
        AFTER_HASH,
        "file should match afterHash after apply"
    );
}

/// `apply --force` should apply patches even when file hashes don't match.
#[test]
#[ignore]
fn test_npm_apply_force() {
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

    // Save the patch without applying.
    assert_run_ok(cwd, &["get", NPM_UUID, "--save-only"], "get --save-only");

    // Corrupt the file to create a hash mismatch (keep same version so PURL matches).
    std::fs::write(&index_js, b"// corrupted content\n").unwrap();
    assert_ne!(
        git_sha256_file(&index_js),
        BEFORE_HASH,
        "corrupted file should have a different hash"
    );

    // The default policy on a hash mismatch is warn-and-overwrite (the full
    // patched blob is applied); `--strict` opts out and fails closed. The
    // mismatch must fail *specifically* because of the hash mismatch — not
    // for some unrelated reason (missing patch, crash, lock error) that
    // would also yield a non-zero exit and let a regression hide. Use the
    // JSON envelope to pin the failure to our PURL and its reason.
    let (code, stdout, stderr) = run(cwd, &["apply", "--strict", "--json"]);
    assert_ne!(
        code, 0,
        "apply --strict should fail on hash mismatch.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let env: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("apply --json should emit JSON: {e}\nstdout:\n{stdout}"));
    assert_eq!(
        env["status"], "partialFailure",
        "envelope should report partialFailure, got: {env:#?}"
    );
    let events = env["events"].as_array().expect("envelope events array");
    let failed: Vec<&serde_json::Value> =
        events.iter().filter(|e| e["action"] == "failed").collect();
    assert_eq!(
        failed.len(),
        1,
        "exactly one failed event expected, got: {events:#?}"
    );
    assert_eq!(failed[0]["purl"].as_str().unwrap(), NPM_PURL);
    let err_msg = failed[0]["error"].as_str().unwrap_or("").to_lowercase();
    assert!(
        err_msg.contains("hash") && err_msg.contains("match"),
        "failure should be a hash mismatch on the patched file, got error: {err_msg:?}"
    );

    // Strict must not have touched the file — the --force leg below is only
    // meaningful if the mismatch is still on disk (a strict that wrote the
    // patched content would leave --force a vacuous already-patched skip).
    assert_ne!(
        git_sha256_file(&index_js),
        AFTER_HASH,
        "apply --strict must leave the mismatched file unmodified"
    );

    // Apply with --force should succeed.
    assert_run_ok(cwd, &["apply", "--force"], "apply --force");

    assert_eq!(
        git_sha256_file(&index_js),
        AFTER_HASH,
        "index.js should match afterHash after apply --force"
    );
}

/// macOS auto-discovery: `scan -g --json` without `--global-prefix` uses real path probing.
#[cfg(target_os = "macos")]
#[test]
#[ignore]
fn test_npm_macos_global_auto_discovery() {
    if !has_command("npm") {
        eprintln!("SKIP: npm not found on PATH");
        return;
    }

    let cwd_dir = tempfile::tempdir().unwrap();
    let cwd = cwd_dir.path();

    // Run scan -g without --global-prefix to exercise macOS auto-discovery
    let (code, stdout, stderr) = run(cwd, &["scan", "-g", "--json"]);

    // Should complete without error (exit 0)
    assert_eq!(
        code, 0,
        "scan -g --json failed (exit {code}).\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );

    // Output should be a well-formed success envelope. We cannot assert a
    // package count (the host's global prefix is uncontrolled and may be
    // empty), but checking only `is_u64()` is a loophole: a regression that
    // emits a malformed/error envelope while still printing *some* number
    // would slip through. Pin the full envelope shape and its internal
    // invariant instead.
    let scan: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("invalid JSON from scan -g: {e}\nstdout:\n{stdout}"));
    assert_eq!(
        scan["status"], "success",
        "scan -g envelope should report success, got: {scan:#?}"
    );
    let scanned = scan["scannedPackages"].as_u64().unwrap_or_else(|| {
        panic!(
            "scannedPackages should be a number, got: {}",
            scan["scannedPackages"]
        )
    });
    let with_patches = scan["packagesWithPatches"].as_u64().unwrap_or_else(|| {
        panic!(
            "packagesWithPatches should be a number, got: {}",
            scan["packagesWithPatches"]
        )
    });
    let packages = scan["packages"]
        .as_array()
        .expect("scan -g should emit a packages array");
    // Discovery invariant: every package-with-a-patch was a scanned package,
    // and the `packages` list (packages carrying patches) cannot exceed the
    // total scanned count.
    assert!(
        with_patches <= scanned,
        "packagesWithPatches ({with_patches}) must not exceed scannedPackages ({scanned})"
    );
    assert_eq!(
        packages.len() as u64,
        with_patches,
        "packages array length should equal packagesWithPatches"
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

    // The shortcut must behave like `get`: the manifest must actually record
    // our patch, not merely exist as an empty stub.
    let manifest_path = cwd.join(".socket/manifest.json");
    assert!(
        manifest_path.exists(),
        "manifest should exist after UUID shortcut"
    );
    let manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
    let patch = &manifest["patches"][NPM_PURL];
    assert!(
        patch.is_object(),
        "manifest should contain {NPM_PURL} after UUID shortcut"
    );
    assert_eq!(patch["uuid"].as_str().unwrap(), NPM_UUID);
}
