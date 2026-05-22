//! Integration tests for `rollback` paths that don't require network or
//! installed packages — same shape as `apply_invariants.rs` for apply.
//!
//! The network-dependent paths (downloading missing `beforeHash` blobs)
//! and the actual disk-mutation paths (rolling back a real installed
//! package) stay in the `#[ignore]`'d e2e suite.

use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

/// Git-SHA256: SHA256("blob <len>\0" ++ content).
fn git_sha256(content: &[u8]) -> String {
    let header = format!("blob {}\0", content.len());
    let mut hasher = Sha256::new();
    hasher.update(header.as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

const MANIFEST_JSON: &str = r#"{
  "patches": {
    "pkg:npm/__rollback_test__@1.0.0": {
      "uuid": "33333333-3333-4333-8333-333333333333",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {
        "package/index.js": {
          "beforeHash": "0000000000000000000000000000000000000000000000000000000000000000",
          "afterHash":  "1111111111111111111111111111111111111111111111111111111111111111"
        }
      },
      "vulnerabilities": {},
      "description": "synthetic rollback test patch",
      "license": "MIT",
      "tier": "free"
    }
  }
}"#;

fn make_socket_dir(root: &Path) -> PathBuf {
    let socket = root.join(".socket");
    std::fs::create_dir_all(&socket).expect("create .socket");
    std::fs::write(socket.join("manifest.json"), MANIFEST_JSON).expect("write manifest");
    socket
}

fn run(cwd: &Path, args: &[&str]) -> (i32, String) {
    let mut full = vec!["rollback"];
    full.extend_from_slice(args);
    let out = Command::new(binary())
        .args(&full)
        .current_dir(cwd)
        .env_remove("SOCKET_API_TOKEN")
        .output()
        .expect("run socket-patch");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
    )
}

// ---------------------------------------------------------------------------
// Error paths
// ---------------------------------------------------------------------------

#[test]
fn rollback_with_no_manifest_emits_error() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (code, stdout) = run(tmp.path(), &["--json", "--offline"]);
    assert_eq!(code, 1, "no manifest must exit 1; stdout=\n{stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["status"], "error");
}

#[test]
fn rollback_one_off_without_identifier_errors() {
    // `--one-off` is documented as requiring a UUID/PURL positional.
    // Without one, rollback bails with an error envelope.
    let tmp = tempfile::tempdir().expect("tempdir");
    let (code, stdout) = run(tmp.path(), &["--json", "--one-off"]);
    assert_eq!(code, 1, "--one-off w/o identifier must exit 1; stdout=\n{stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["status"], "error");
    let err = v["error"].as_str().expect("error message string");
    assert!(
        err.contains("--one-off requires an identifier"),
        "unexpected error message: {err}"
    );
}

#[test]
fn rollback_one_off_with_identifier_reports_not_implemented() {
    // The one-off mode is a stub that always returns "not yet
    // implemented". We pin it here so a real implementation can't land
    // silently without updating the contract.
    let tmp = tempfile::tempdir().expect("tempdir");
    let (code, stdout) =
        run(tmp.path(), &["--json", "--one-off", "33333333-3333-4333-8333-333333333333"]);
    assert_eq!(code, 1, "one-off mode must exit 1 today; stdout=\n{stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["status"], "error");
    let err = v["error"].as_str().expect("error message string");
    assert!(
        err.contains("not yet implemented"),
        "unexpected error message: {err}"
    );
}

#[test]
fn rollback_unknown_identifier_emits_error() {
    let tmp = tempfile::tempdir().expect("tempdir");
    make_socket_dir(tmp.path());
    let (code, stdout) = run(
        tmp.path(),
        &["--json", "--offline", "pkg:npm/does-not-exist@9.9.9"],
    );
    assert_eq!(code, 1, "unknown identifier must exit 1; stdout=\n{stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["status"], "error");
    let err = v["error"].as_str().expect("error message string");
    assert!(
        err.contains("No patch found matching identifier"),
        "unexpected error: {err}"
    );
}

#[test]
fn rollback_offline_with_missing_before_blob_partial_failure() {
    // Manifest has a patch whose beforeHash is NOT on disk; --offline
    // means we won't fetch. Rollback should fail out before touching
    // anything.
    let tmp = tempfile::tempdir().expect("tempdir");
    make_socket_dir(tmp.path());
    let (code, stdout) = run(tmp.path(), &["--json", "--offline"]);
    assert_eq!(
        code, 1,
        "offline + missing blob must exit 1; stdout=\n{stdout}"
    );
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["status"], "partial_failure");
    assert_eq!(v["rolledBack"], 0);
    assert_eq!(v["alreadyOriginal"], 0);
}

// ---------------------------------------------------------------------------
// No-package-installed happy path
// ---------------------------------------------------------------------------

#[test]
fn rollback_with_no_installed_packages_succeeds_quietly() {
    // beforeHash blob is on disk, no installed packages match — rollback
    // succeeds with zero results.
    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = make_socket_dir(tmp.path());
    let before_hash = "0000000000000000000000000000000000000000000000000000000000000000";
    let blobs = socket.join("blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::write(blobs.join(before_hash), b"original content").unwrap();

    let (code, stdout) = run(tmp.path(), &["--json"]);
    assert_eq!(code, 0, "no installed packages must exit 0; stdout=\n{stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["status"], "success");
    assert_eq!(v["rolledBack"], 0);
    assert_eq!(v["alreadyOriginal"], 0);
    assert_eq!(v["failed"], 0);
}

// ---------------------------------------------------------------------------
// Top-level JSON shape — locks the keys for downstream consumers.
// ---------------------------------------------------------------------------

#[test]
fn rollback_json_shape_has_documented_keys() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = make_socket_dir(tmp.path());
    let before_hash = "0000000000000000000000000000000000000000000000000000000000000000";
    let blobs = socket.join("blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::write(blobs.join(before_hash), b"original content").unwrap();

    let (_, stdout) = run(tmp.path(), &["--json"]);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    let keys: std::collections::BTreeSet<&str> =
        v.as_object().unwrap().keys().map(|k| k.as_str()).collect();
    // These keys are documented in CLI_CONTRACT.md as the rollback shape
    // (not yet migrated to the unified envelope). Pin them so a future
    // migration trips this test instead of breaking wrappers silently.
    for key in [
        "status",
        "rolledBack",
        "alreadyOriginal",
        "failed",
        "dryRun",
        "results",
    ] {
        assert!(keys.contains(key), "rollback JSON missing key: {key}");
    }
}

// ---------------------------------------------------------------------------
// Manifest-path override
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Real rollback against an installed package
// ---------------------------------------------------------------------------

#[test]
fn rollback_restores_file_to_before_content() {
    // Simulate a patched-then-rollback workflow: node_modules has a
    // patched file (AFTER content), .socket/blobs/<beforeHash> holds
    // the original BEFORE bytes. rollback should restore the file to
    // the BEFORE content.
    let before = b"original-content\n";
    let after = b"patched-content\n";
    let before_hash = git_sha256(before);
    let after_hash = git_sha256(after);

    let tmp = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        tmp.path().join("package.json"),
        r#"{ "name": "rollback-test-root", "version": "0.0.0" }"#,
    )
    .unwrap();

    let pkg_dir = tmp.path().join("node_modules/rollback-target");
    std::fs::create_dir_all(&pkg_dir).unwrap();
    std::fs::write(
        pkg_dir.join("package.json"),
        r#"{ "name": "rollback-target", "version": "1.0.0" }"#,
    )
    .unwrap();
    // The installed file is currently in the patched (AFTER) state.
    std::fs::write(pkg_dir.join("index.js"), after).unwrap();

    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    let manifest = format!(
        r#"{{
  "patches": {{
    "pkg:npm/rollback-target@1.0.0": {{
      "uuid": "11111111-1111-4111-8111-111111111111",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {{
        "package/index.js": {{
          "beforeHash": "{before_hash}",
          "afterHash": "{after_hash}"
        }}
      }},
      "vulnerabilities": {{}},
      "description": "Synthetic rollback test",
      "license": "MIT",
      "tier": "free"
    }}
  }}
}}"#
    );
    std::fs::write(socket.join("manifest.json"), manifest).unwrap();
    // Stage the BEFORE blob — required to roll back.
    let blobs = socket.join("blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::write(blobs.join(&before_hash), before).unwrap();

    let out = Command::new(binary())
        .args(["rollback", "--json", "--offline"])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .output()
        .expect("run socket-patch");
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert_eq!(
        code, 0,
        "rollback must succeed; stdout={stdout}; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(v["status"], "success");
    assert_eq!(v["rolledBack"], 1);

    // The file in node_modules should now contain the BEFORE bytes.
    let restored = std::fs::read(pkg_dir.join("index.js")).unwrap();
    assert_eq!(restored, before, "rollback must restore BEFORE content");
}

#[test]
fn rollback_already_original_skips_work() {
    // The installed file already matches the BEFORE hash — rollback
    // should report "already original" and skip the file rewrite.
    let before = b"original-content\n";
    let after = b"patched-content\n";
    let before_hash = git_sha256(before);
    let after_hash = git_sha256(after);

    let tmp = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        tmp.path().join("package.json"),
        r#"{ "name": "rb", "version": "0.0.0" }"#,
    )
    .unwrap();

    let pkg_dir = tmp.path().join("node_modules/already-orig");
    std::fs::create_dir_all(&pkg_dir).unwrap();
    std::fs::write(
        pkg_dir.join("package.json"),
        r#"{ "name": "already-orig", "version": "1.0.0" }"#,
    )
    .unwrap();
    // File is ALREADY the BEFORE content (not patched).
    std::fs::write(pkg_dir.join("index.js"), before).unwrap();

    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    let manifest = format!(
        r#"{{
  "patches": {{
    "pkg:npm/already-orig@1.0.0": {{
      "uuid": "22222222-2222-4222-8222-222222222222",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {{
        "package/index.js": {{
          "beforeHash": "{before_hash}",
          "afterHash": "{after_hash}"
        }}
      }},
      "vulnerabilities": {{}},
      "description": "x",
      "license": "MIT",
      "tier": "free"
    }}
  }}
}}"#
    );
    std::fs::write(socket.join("manifest.json"), manifest).unwrap();
    let blobs = socket.join("blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::write(blobs.join(&before_hash), before).unwrap();

    let out = Command::new(binary())
        .args(["rollback", "--json", "--offline"])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .output()
        .expect("run socket-patch");
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert_eq!(code, 0, "rollback must succeed; stdout={stdout}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(v["alreadyOriginal"], 1);
    assert_eq!(v["rolledBack"], 0);

    // File unchanged.
    let content = std::fs::read(pkg_dir.join("index.js")).unwrap();
    assert_eq!(content, before);
}

#[test]
fn rollback_dry_run_does_not_modify_file() {
    let before = b"original-content\n";
    let after = b"patched-content\n";
    let before_hash = git_sha256(before);
    let after_hash = git_sha256(after);

    let tmp = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        tmp.path().join("package.json"),
        r#"{ "name": "rb", "version": "0.0.0" }"#,
    )
    .unwrap();
    let pkg_dir = tmp.path().join("node_modules/dry-target");
    std::fs::create_dir_all(&pkg_dir).unwrap();
    std::fs::write(
        pkg_dir.join("package.json"),
        r#"{ "name": "dry-target", "version": "1.0.0" }"#,
    )
    .unwrap();
    std::fs::write(pkg_dir.join("index.js"), after).unwrap();

    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    let manifest = format!(
        r#"{{
  "patches": {{
    "pkg:npm/dry-target@1.0.0": {{
      "uuid": "33333333-3333-4333-8333-333333333333",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {{
        "package/index.js": {{
          "beforeHash": "{before_hash}",
          "afterHash": "{after_hash}"
        }}
      }},
      "vulnerabilities": {{}},
      "description": "x",
      "license": "MIT",
      "tier": "free"
    }}
  }}
}}"#
    );
    std::fs::write(socket.join("manifest.json"), manifest).unwrap();
    let blobs = socket.join("blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::write(blobs.join(&before_hash), before).unwrap();

    let out = Command::new(binary())
        .args(["rollback", "--json", "--offline", "--dry-run"])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .output()
        .expect("run socket-patch");
    assert_eq!(out.status.code(), Some(0));

    // Dry-run must NOT modify the file.
    let content = std::fs::read(pkg_dir.join("index.js")).unwrap();
    assert_eq!(content, after, "dry-run must not modify the installed file");
}

#[test]
fn rollback_honors_manifest_path_override() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let custom_dir = tmp.path().join("custom");
    std::fs::create_dir_all(&custom_dir).unwrap();
    std::fs::write(custom_dir.join("patches.json"), MANIFEST_JSON).unwrap();
    // Stage the beforeHash blob next to the custom manifest.
    let blobs = custom_dir.join("blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    let before_hash = "0000000000000000000000000000000000000000000000000000000000000000";
    std::fs::write(blobs.join(before_hash), b"original content").unwrap();

    let out = Command::new(binary())
        .args([
            "rollback",
            "--json",
            "--offline",
            "--manifest-path",
            "custom/patches.json",
        ])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .output()
        .expect("run socket-patch");
    assert_eq!(out.status.code(), Some(0));
    let v: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert_eq!(v["status"], "success");
}
