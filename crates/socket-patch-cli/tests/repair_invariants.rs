//! Integration tests for `repair` / `gc` against pre-populated `.socket/`
//! fixtures. These run fully offline (`--offline` flag), so they exercise
//! the cleanup paths — manifest read, orphan-blob detection, archive
//! cleanup, dry-run preview, JSON envelope output — without needing the
//! Socket API.
//!
//! Network-dependent paths (the fetch arm of `repair` when run without
//! `--offline`) stay in the `#[ignore]`'d e2e suite.

use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ORG_SLUG: &str = "test-org";

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

/// A manifest with one patch referencing one blob. Used as the baseline
/// `.socket/manifest.json` for every test below.
const MANIFEST_JSON: &str = r#"{
  "patches": {
    "pkg:npm/__repair_test__@1.0.0": {
      "uuid": "11111111-1111-4111-8111-111111111111",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {
        "package/index.js": {
          "beforeHash": "0000000000000000000000000000000000000000000000000000000000000000",
          "afterHash":  "1111111111111111111111111111111111111111111111111111111111111111"
        }
      },
      "vulnerabilities": {},
      "description": "synthetic repair test patch",
      "license": "MIT",
      "tier": "free"
    }
  }
}"#;

const REFERENCED_HASH: &str =
    "1111111111111111111111111111111111111111111111111111111111111111";

fn make_socket_dir(root: &Path) -> PathBuf {
    let socket = root.join(".socket");
    std::fs::create_dir_all(&socket).expect("create .socket");
    std::fs::write(socket.join("manifest.json"), MANIFEST_JSON).expect("write manifest");
    socket
}

fn write_blob(socket: &Path, hash: &str, content: &[u8]) {
    let blobs = socket.join("blobs");
    std::fs::create_dir_all(&blobs).expect("create blobs dir");
    std::fs::write(blobs.join(hash), content).expect("write blob");
}

fn run_repair(cwd: &Path, extra: &[&str]) -> (i32, String) {
    let mut args = vec!["repair", "--json", "--offline"];
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

// ---------------------------------------------------------------------------
// Error paths
// ---------------------------------------------------------------------------

#[test]
fn repair_with_no_manifest_emits_manifest_not_found_envelope() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (code, stdout) = run_repair(tmp.path(), &[]);
    assert_eq!(code, 1, "expected exit 1; stdout=\n{stdout}");
    let v: serde_json::Value =
        serde_json::from_str(&stdout).expect("envelope must be valid JSON");
    assert_eq!(v["command"], "repair");
    assert_eq!(v["status"], "error");
    assert_eq!(v["error"]["code"], "manifest_not_found");
}

#[test]
fn repair_with_invalid_manifest_emits_repair_failed_envelope() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    std::fs::write(socket.join("manifest.json"), "{ not valid json").unwrap();

    let (code, stdout) = run_repair(tmp.path(), &[]);
    assert_eq!(code, 1, "expected exit 1; stdout=\n{stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("envelope JSON");
    assert_eq!(v["status"], "error");
    // Failure can land either in the manifest-read path or in inner repair
    // depending on how the read surfaces the parse error — both are valid
    // envelope shapes documented in CLI_CONTRACT.md.
    let code_str = v["error"]["code"].as_str().expect("error.code");
    assert!(
        code_str == "manifest_invalid" || code_str == "repair_failed",
        "unexpected error.code: {code_str}"
    );
}

/// `--offline` (strict airgap, no network) and `--download-only`
/// (network-only, skip cleanup) are mutually exclusive — the
/// command rejects the combination up-front with exit code 2 and
/// an `invalid_args` error in JSON mode. Covers the early-exit
/// branch at the top of `commands::repair::run`.
#[test]
fn repair_offline_and_download_only_are_mutually_exclusive() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let out = Command::new(binary())
        .args(["repair", "--json", "--offline", "--download-only"])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .output()
        .expect("run socket-patch");
    assert_eq!(
        out.status.code(),
        Some(2),
        "expected exit 2 for invalid flag combo; stdout=\n{}",
        String::from_utf8_lossy(&out.stdout),
    );
    let v: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert_eq!(v["status"], "error");
    assert_eq!(v["error"]["code"], "invalid_args");
    assert!(
        v["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("mutually exclusive"),
        "error message should mention 'mutually exclusive'; got {v}"
    );
}

/// Same flag-combo rejection in the non-JSON (human text) path —
/// exit 2 with a stderr error message.
#[test]
fn repair_offline_and_download_only_human_mode_errors_to_stderr() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let out = Command::new(binary())
        .args(["repair", "--offline", "--download-only"])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .output()
        .expect("run socket-patch");
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("mutually exclusive"),
        "stderr should mention 'mutually exclusive'; got {stderr}"
    );
}

// ---------------------------------------------------------------------------
// Cleanup paths
// ---------------------------------------------------------------------------

#[test]
fn repair_offline_with_no_orphans_succeeds_quietly() {
    // Manifest references one hash; that exact blob is on disk. No
    // orphans, nothing to download (offline), nothing to clean up.
    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = make_socket_dir(tmp.path());
    write_blob(&socket, REFERENCED_HASH, b"patched content");

    let (code, stdout) = run_repair(tmp.path(), &[]);
    assert_eq!(code, 0, "expected exit 0; stdout=\n{stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("envelope JSON");
    assert_eq!(v["command"], "repair");
    assert_eq!(v["status"], "success");
    assert_eq!(v["summary"]["removed"], 0);
    assert_eq!(v["summary"]["downloaded"], 0);
}

#[test]
fn repair_offline_removes_orphan_blob() {
    // Manifest references one hash, but `.socket/blobs/` has BOTH that
    // hash AND an orphan. Cleanup should remove the orphan and keep the
    // referenced one.
    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = make_socket_dir(tmp.path());
    write_blob(&socket, REFERENCED_HASH, b"patched content");
    let orphan_hash = "deadbeef".repeat(8); // 64 chars
    write_blob(&socket, &orphan_hash, b"orphaned content");

    let (code, stdout) = run_repair(tmp.path(), &[]);
    assert_eq!(code, 0, "expected exit 0; stdout=\n{stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("envelope JSON");
    assert_eq!(v["status"], "success");
    assert_eq!(v["summary"]["removed"], 1, "one orphan should be removed");

    // The referenced blob must survive; the orphan must be gone.
    assert!(
        socket.join("blobs").join(REFERENCED_HASH).exists(),
        "referenced blob must not be deleted"
    );
    assert!(
        !socket.join("blobs").join(&orphan_hash).exists(),
        "orphan blob must be deleted"
    );
}

#[test]
fn repair_dry_run_does_not_remove_orphan_blob() {
    // With `--dry-run`, the orphan should be REPORTED but stay on disk.
    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = make_socket_dir(tmp.path());
    write_blob(&socket, REFERENCED_HASH, b"patched content");
    let orphan_hash = "cafebabe".repeat(8);
    write_blob(&socket, &orphan_hash, b"orphaned content");

    let (code, stdout) = run_repair(tmp.path(), &["--dry-run"]);
    assert_eq!(code, 0, "expected exit 0; stdout=\n{stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("envelope JSON");
    assert_eq!(v["dryRun"], true);
    // The cleanup event uses action=verified in dry-run mode.
    let actions: Vec<&str> = v["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["action"].as_str().unwrap())
        .collect();
    assert!(
        actions.contains(&"verified"),
        "dry-run must emit verified event; got actions={actions:?}"
    );
    // Orphan must still exist after dry-run.
    assert!(
        socket.join("blobs").join(&orphan_hash).exists(),
        "dry-run must not delete orphan blobs"
    );
}

#[test]
fn repair_download_only_skips_cleanup() {
    // `--download-only` skips the cleanup pass. An orphan that would
    // normally be removed should still be on disk afterward.
    //
    // We can't use `run_repair` here because it injects `--offline`,
    // and `--offline` is mutually exclusive with `--download-only`
    // (offline = strict airgap, download-only = network-only). Invoke
    // the binary directly. We pin `--download-mode file` so the
    // already-present `afterHash` blob fully satisfies the download
    // phase — there's nothing missing to fetch, so the test stays
    // hermetic (no network). The default `diff` mode would instead look
    // for `<uuid>.tar.gz`, which is absent, and try to hit the network.
    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = make_socket_dir(tmp.path());
    write_blob(&socket, REFERENCED_HASH, b"patched content");
    let orphan_hash = "feedface".repeat(8);
    write_blob(&socket, &orphan_hash, b"orphaned content");

    let out = Command::new(binary())
        .args(["repair", "--json", "--download-only", "--download-mode", "file"])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .output()
        .expect("run socket-patch");
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(code, 0, "expected exit 0; stdout=\n{stdout}");
    assert!(
        socket.join("blobs").join(&orphan_hash).exists(),
        "--download-only must skip cleanup; orphan should still exist"
    );
}

// ---------------------------------------------------------------------------
// gc alias parity
// ---------------------------------------------------------------------------

#[test]
fn gc_alias_behaves_identically_to_repair() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = make_socket_dir(tmp.path());
    write_blob(&socket, REFERENCED_HASH, b"patched content");
    let orphan_hash = "abadcafe".repeat(8);
    write_blob(&socket, &orphan_hash, b"orphaned content");

    // Run via `gc` instead of `repair`.
    let out = Command::new(binary())
        .args(["gc", "--json", "--offline"])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .output()
        .expect("run socket-patch");
    assert_eq!(out.status.code(), Some(0));
    let v: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    // The envelope's `command` field reports the canonical name, not the alias.
    assert_eq!(v["command"], "repair");
    assert_eq!(v["summary"]["removed"], 1);
    assert!(!socket.join("blobs").join(&orphan_hash).exists());
}

// ---------------------------------------------------------------------------
// Manifest-path override
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Online fetch path — exercises the network branch via mock server
// ---------------------------------------------------------------------------

#[tokio::test]
async fn repair_online_downloads_missing_blob() {
    // Manifest references a blob whose content we control. The blob is
    // NOT on disk, so repair (without --offline) must fetch it from the
    // mock API and write it under .socket/blobs/.
    let content = b"patched-content\n";
    let after_hash = git_sha256(content);

    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/blob/{after_hash}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(content.to_vec()))
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    let manifest = format!(
        r#"{{
  "patches": {{
    "pkg:npm/__repair_online__@1.0.0": {{
      "uuid": "11111111-1111-4111-8111-111111111111",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {{
        "package/index.js": {{
          "beforeHash": "0000000000000000000000000000000000000000000000000000000000000000",
          "afterHash": "{after_hash}"
        }}
      }},
      "vulnerabilities": {{}},
      "description": "synthetic",
      "license": "MIT",
      "tier": "free"
    }}
  }}
}}"#
    );
    std::fs::write(socket.join("manifest.json"), manifest).unwrap();

    let out = Command::new(binary())
        .args([
            "repair",
            "--json",
            "--download-mode",
            "file",
            "--download-only",
        ])
        .current_dir(tmp.path())
        .env("SOCKET_API_URL", &mock.uri())
        .env("SOCKET_API_TOKEN", "fake-token-for-test")
        .env("SOCKET_ORG_SLUG", ORG_SLUG)
        .output()
        .expect("run socket-patch");
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert_eq!(
        code, 0,
        "repair fetch must succeed; stdout={stdout}; stderr={stderr}"
    );
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(v["status"], "success");
    assert_eq!(v["summary"]["downloaded"], 1);

    // The fetched blob must be written to .socket/blobs/<hash>.
    let blob_path = socket.join("blobs").join(&after_hash);
    assert!(blob_path.exists(), "fetched blob must be persisted");
    let body = std::fs::read(&blob_path).unwrap();
    assert_eq!(body, content);
}

#[test]
fn repair_honors_manifest_path_override() {
    // Put the manifest somewhere other than `.socket/manifest.json` and
    // confirm `--manifest-path` finds it. This exercises the
    // `resolve_manifest_path` codepath.
    let tmp = tempfile::tempdir().expect("tempdir");
    let custom_dir = tmp.path().join("custom");
    std::fs::create_dir_all(&custom_dir).unwrap();
    std::fs::write(custom_dir.join("patches.json"), MANIFEST_JSON).unwrap();

    let out = Command::new(binary())
        .args([
            "repair",
            "--json",
            "--offline",
            "--manifest-path",
            "custom/patches.json",
        ])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .output()
        .expect("run socket-patch");
    assert_eq!(
        out.status.code(),
        Some(0),
        "expected exit 0; stdout=\n{}\nstderr=\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let v: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert_eq!(v["status"], "success");
}
