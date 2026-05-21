//! Integration tests for `remove` against pre-populated manifests.
//!
//! `remove` runs rollback internally before deleting from the manifest.
//! These tests pass `--skip-rollback` so they don't try to walk
//! node_modules — every code path here is testable without network or
//! installed packages.

use std::path::{Path, PathBuf};
use std::process::Command;

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

const TWO_PATCH_MANIFEST: &str = r#"{
  "patches": {
    "pkg:npm/__remove_test_a__@1.0.0": {
      "uuid": "11111111-1111-4111-8111-111111111111",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {
        "package/a.js": {
          "beforeHash": "0000000000000000000000000000000000000000000000000000000000000000",
          "afterHash":  "1111111111111111111111111111111111111111111111111111111111111111"
        }
      },
      "vulnerabilities": {},
      "description": "synthetic remove test patch A",
      "license": "MIT",
      "tier": "free"
    },
    "pkg:npm/__remove_test_b__@2.0.0": {
      "uuid": "22222222-2222-4222-8222-222222222222",
      "exportedAt": "2024-01-02T00:00:00Z",
      "files": {
        "package/b.js": {
          "beforeHash": "0000000000000000000000000000000000000000000000000000000000000000",
          "afterHash":  "2222222222222222222222222222222222222222222222222222222222222222"
        }
      },
      "vulnerabilities": {},
      "description": "synthetic remove test patch B",
      "license": "MIT",
      "tier": "free"
    }
  }
}"#;

fn make_socket_dir(root: &Path) -> PathBuf {
    let socket = root.join(".socket");
    std::fs::create_dir_all(&socket).expect("create .socket");
    std::fs::write(socket.join("manifest.json"), TWO_PATCH_MANIFEST).expect("write manifest");
    socket
}

fn run_remove(cwd: &Path, identifier: &str, extra: &[&str]) -> (i32, String) {
    let mut args = vec!["remove", identifier, "--json", "--yes", "--skip-rollback"];
    args.extend_from_slice(extra);
    let out = Command::new(binary())
        .args(&args)
        .current_dir(cwd)
        .env_remove("SOCKET_API_TOKEN")
        .output()
        .expect("run socket-patch");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
    )
}

fn read_manifest(socket: &Path) -> serde_json::Value {
    let body = std::fs::read_to_string(socket.join("manifest.json")).expect("read manifest");
    serde_json::from_str(&body).expect("parse manifest")
}

// ---------------------------------------------------------------------------
// Error paths
// ---------------------------------------------------------------------------

#[test]
fn remove_with_no_manifest_emits_manifest_not_found() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (code, stdout) = run_remove(tmp.path(), "pkg:npm/foo@1.0.0", &[]);
    assert_eq!(code, 1, "no manifest must exit 1; stdout=\n{stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["command"], "remove");
    assert_eq!(v["status"], "error");
    assert_eq!(v["error"]["code"], "manifest_not_found");
}

#[test]
fn remove_with_unknown_identifier_emits_not_found() {
    let tmp = tempfile::tempdir().expect("tempdir");
    make_socket_dir(tmp.path());
    let (code, stdout) = run_remove(tmp.path(), "pkg:npm/does-not-exist@1.0.0", &[]);
    assert_eq!(code, 1, "unknown identifier must exit 1; stdout=\n{stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["command"], "remove");
    assert_eq!(v["status"], "notFound");
    assert_eq!(v["error"]["code"], "not_found");
}

#[test]
fn remove_with_invalid_manifest_emits_error() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    std::fs::write(socket.join("manifest.json"), "{not json").unwrap();

    let (code, stdout) = run_remove(tmp.path(), "pkg:npm/foo@1.0.0", &[]);
    assert_eq!(code, 1, "invalid manifest must exit 1; stdout=\n{stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["status"], "error");
}

// ---------------------------------------------------------------------------
// Happy paths
// ---------------------------------------------------------------------------

#[test]
fn remove_by_purl_drops_matching_entry() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = make_socket_dir(tmp.path());

    let (code, stdout) = run_remove(tmp.path(), "pkg:npm/__remove_test_a__@1.0.0", &[]);
    assert_eq!(code, 0, "remove must succeed; stdout=\n{stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["status"], "success");
    let events = v["events"].as_array().expect("events array");
    let removed_purls: Vec<&str> = events
        .iter()
        .filter(|e| e["action"] == "removed" && e["purl"].is_string())
        .map(|e| e["purl"].as_str().unwrap())
        .collect();
    assert_eq!(removed_purls, vec!["pkg:npm/__remove_test_a__@1.0.0"]);

    // Manifest should still contain the other entry.
    let manifest = read_manifest(&socket);
    let patches = manifest["patches"].as_object().expect("patches object");
    assert_eq!(patches.len(), 1);
    assert!(patches.contains_key("pkg:npm/__remove_test_b__@2.0.0"));
    assert!(!patches.contains_key("pkg:npm/__remove_test_a__@1.0.0"));
}

#[test]
fn remove_by_uuid_drops_matching_entry() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = make_socket_dir(tmp.path());

    let (code, stdout) = run_remove(tmp.path(), "22222222-2222-4222-8222-222222222222", &[]);
    assert_eq!(code, 0, "remove by uuid must succeed; stdout=\n{stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["status"], "success");

    let manifest = read_manifest(&socket);
    let patches = manifest["patches"].as_object().unwrap();
    assert_eq!(patches.len(), 1);
    assert!(patches.contains_key("pkg:npm/__remove_test_a__@1.0.0"));
    assert!(!patches.contains_key("pkg:npm/__remove_test_b__@2.0.0"));
}

#[test]
fn remove_event_has_required_envelope_fields() {
    let tmp = tempfile::tempdir().expect("tempdir");
    make_socket_dir(tmp.path());

    let (_, stdout) = run_remove(tmp.path(), "pkg:npm/__remove_test_a__@1.0.0", &[]);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["command"], "remove");
    assert_eq!(v["status"], "success");
    assert_eq!(v["summary"]["removed"], 1);
    // dryRun is part of the envelope contract — must always be present.
    assert!(v["dryRun"].is_boolean());
}

// ---------------------------------------------------------------------------
// Manifest-path override
// ---------------------------------------------------------------------------

#[test]
fn remove_honors_manifest_path_override() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let custom_dir = tmp.path().join("custom");
    std::fs::create_dir_all(&custom_dir).unwrap();
    std::fs::write(custom_dir.join("patches.json"), TWO_PATCH_MANIFEST).unwrap();

    let out = Command::new(binary())
        .args([
            "remove",
            "pkg:npm/__remove_test_a__@1.0.0",
            "--json",
            "--yes",
            "--skip-rollback",
            "--manifest-path",
            "custom/patches.json",
        ])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .output()
        .expect("run socket-patch");
    assert_eq!(out.status.code(), Some(0));

    let body = std::fs::read_to_string(custom_dir.join("patches.json")).unwrap();
    let manifest: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(manifest["patches"].as_object().unwrap().len(), 1);
}
