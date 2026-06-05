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
    // A "not found" error must not silently materialize a default manifest
    // directory as a side effect.
    assert!(
        !tmp.path().join(".socket").exists(),
        "a missing-manifest error must not create a .socket directory"
    );
}

#[test]
fn remove_with_unknown_identifier_emits_not_found() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = make_socket_dir(tmp.path());
    let before = std::fs::read(socket.join("manifest.json")).expect("read before");

    let (code, stdout) = run_remove(tmp.path(), "pkg:npm/does-not-exist@1.0.0", &[]);
    assert_eq!(code, 1, "unknown identifier must exit 1; stdout=\n{stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["command"], "remove");
    assert_eq!(v["status"], "notFound");
    assert_eq!(v["error"]["code"], "not_found");
    if let Some(summary) = v.get("summary") {
        assert_eq!(summary["removed"], 0, "a not-found remove must report 0 removed");
    }

    // A no-match remove must leave BOTH existing entries in place and must
    // not rewrite the file at all — otherwise a broken matcher that deletes
    // the wrong entry (or churns the manifest) could still report notFound.
    let manifest = read_manifest(&socket);
    let patches = manifest["patches"].as_object().expect("patches object");
    assert_eq!(patches.len(), 2, "no entries should be removed");
    assert!(patches.contains_key("pkg:npm/__remove_test_a__@1.0.0"));
    assert!(patches.contains_key("pkg:npm/__remove_test_b__@2.0.0"));
    let after = std::fs::read(socket.join("manifest.json")).expect("read after");
    assert_eq!(before, after, "a no-op remove must not rewrite the manifest file");
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
    assert_eq!(v["command"], "remove");
    assert_eq!(v["status"], "error");
    // A parse failure must be distinguished from a missing manifest, otherwise
    // a broken loader could silently treat corrupt JSON as "not found".
    assert_eq!(v["error"]["code"], "manifest_unreadable");
    let msg = v["error"]["message"].as_str().expect("error message string");
    assert!(
        msg.contains("parse") || msg.contains("JSON"),
        "error message should explain the parse failure; got: {msg}"
    );
    // Nothing was removed on the error path.
    assert_eq!(v["summary"]["removed"], 0);
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
    assert_eq!(v["summary"]["removed"], 1, "exactly one entry removed");
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
    assert_eq!(v["summary"]["removed"], 1, "exactly one entry removed");
    // Resolving a UUID must drop B's PURL (not just "some" entry): the event
    // stream must name B, proving the uuid→purl resolution is correct rather
    // than incidentally deleting the right count of entries.
    let events = v["events"].as_array().expect("events array");
    let removed_purls: Vec<&str> = events
        .iter()
        .filter(|e| e["action"] == "removed" && e["purl"].is_string())
        .map(|e| e["purl"].as_str().unwrap())
        .collect();
    assert_eq!(removed_purls, vec!["pkg:npm/__remove_test_b__@2.0.0"]);

    let manifest = read_manifest(&socket);
    let patches = manifest["patches"].as_object().unwrap();
    assert_eq!(patches.len(), 1);
    assert!(patches.contains_key("pkg:npm/__remove_test_a__@1.0.0"));
    assert!(!patches.contains_key("pkg:npm/__remove_test_b__@2.0.0"));
}

#[test]
fn remove_event_has_required_envelope_fields() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = make_socket_dir(tmp.path());

    let (code, stdout) = run_remove(tmp.path(), "pkg:npm/__remove_test_a__@1.0.0", &[]);
    assert_eq!(code, 0, "remove must succeed; stdout=\n{stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["command"], "remove");
    assert_eq!(v["status"], "success");
    assert_eq!(v["summary"]["removed"], 1);
    // This is a real removal (no --dry-run), so dryRun must be exactly false —
    // not merely "a boolean". A run that secretly short-circuits to dry-run
    // would report removed:1 while never touching the manifest.
    assert_eq!(v["dryRun"], serde_json::Value::Bool(false));

    // The event stream must name the actually-removed patch.
    let events = v["events"].as_array().expect("events array");
    let removed_purls: Vec<&str> = events
        .iter()
        .filter(|e| e["action"] == "removed" && e["purl"].is_string())
        .map(|e| e["purl"].as_str().unwrap())
        .collect();
    assert_eq!(removed_purls, vec!["pkg:npm/__remove_test_a__@1.0.0"]);

    // The reported removal must be durable: the manifest on disk must reflect it.
    let manifest = read_manifest(&socket);
    let patches = manifest["patches"].as_object().expect("patches object");
    assert_eq!(patches.len(), 1);
    assert!(!patches.contains_key("pkg:npm/__remove_test_a__@1.0.0"));
    assert!(patches.contains_key("pkg:npm/__remove_test_b__@2.0.0"));
}

// ---------------------------------------------------------------------------
// Real rollback path (no --skip-rollback)
// ---------------------------------------------------------------------------

/// Every other test passes `--skip-rollback`, which bypasses the
/// rollback-before-remove step that `remove` runs by default. That makes the
/// suite blind to the actual contract: if the internal rollback fails, the
/// manifest entry must NOT be deleted (fail-closed — never drop a patch from
/// the manifest while leaving patched files un-restored on disk).
///
/// Here we drive the real path. The synthetic patch references blobs/files
/// that don't exist on disk, so rollback cannot complete and `remove` must
/// abort with `rollback_failed`, leaving the manifest fully intact. A
/// regression that swallowed the rollback failure and deleted the entry
/// anyway would flip this test red.
#[test]
fn remove_without_skip_rollback_fails_closed_and_keeps_manifest() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = make_socket_dir(tmp.path());
    let before = std::fs::read(socket.join("manifest.json")).expect("read before");

    let out = Command::new(binary())
        .args([
            "remove",
            "pkg:npm/__remove_test_a__@1.0.0",
            "--json",
            "--yes",
        ])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .env_remove("SOCKET_SKIP_ROLLBACK")
        .output()
        .expect("run socket-patch");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert_eq!(
        out.status.code(),
        Some(1),
        "a failed rollback must abort remove; stdout=\n{stdout}"
    );
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["command"], "remove");
    assert_eq!(v["status"], "error");
    assert_eq!(
        v["error"]["code"], "rollback_failed",
        "remove must surface the rollback failure, not a generic error"
    );
    assert_eq!(v["summary"]["removed"], 0, "nothing removed when rollback fails");

    // The crucial invariant: the manifest is byte-for-byte unchanged. The
    // entry the user asked to remove is still present because its files could
    // not be restored.
    let after = std::fs::read(socket.join("manifest.json")).expect("read after");
    assert_eq!(
        before, after,
        "a failed rollback must leave the manifest entirely untouched"
    );
    let manifest = read_manifest(&socket);
    let patches = manifest["patches"].as_object().expect("patches object");
    assert_eq!(patches.len(), 2);
    assert!(patches.contains_key("pkg:npm/__remove_test_a__@1.0.0"));
    assert!(patches.contains_key("pkg:npm/__remove_test_b__@2.0.0"));
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
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert_eq!(out.status.code(), Some(0), "stdout=\n{stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["status"], "success");
    assert_eq!(v["summary"]["removed"], 1);

    // The override file — not the default location — must be the one mutated,
    // and it must drop exactly the requested entry (A), keeping B.
    let body = std::fs::read_to_string(custom_dir.join("patches.json")).unwrap();
    let manifest: serde_json::Value = serde_json::from_str(&body).unwrap();
    let patches = manifest["patches"].as_object().unwrap();
    assert_eq!(patches.len(), 1);
    assert!(!patches.contains_key("pkg:npm/__remove_test_a__@1.0.0"));
    assert!(patches.contains_key("pkg:npm/__remove_test_b__@2.0.0"));

    // The override must be honored, not silently ignored in favor of a
    // freshly-created default manifest.
    assert!(
        !tmp.path().join(".socket").exists(),
        "remove must not create a default .socket manifest when --manifest-path is given"
    );
}
