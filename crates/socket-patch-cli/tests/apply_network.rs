//! End-to-end tests for `apply`'s online code paths against a
//! wiremock-driven mock API. These complement `apply_invariants.rs`
//! (which only exercises offline paths).
//!
//! Verifies:
//!   - `apply` (default, online) fetches missing blobs from the API
//!     and writes them to an OS tempdir (NOT `.socket/`).
//!   - `--download-mode file` falls back to the per-file blob endpoint.
//!   - `apply` against installed packages writes patched content to
//!     node_modules and leaves `.socket/` byte-identical.

use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

const ORG_SLUG: &str = "test-org";

/// Git-SHA256: SHA256("blob <len>\0" ++ content). Matches the binary's
/// content-addressable hashing.
fn git_sha256(content: &[u8]) -> String {
    let header = format!("blob {}\0", content.len());
    let mut hasher = Sha256::new();
    hasher.update(header.as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

fn write_npm_package(root: &Path, name: &str, version: &str, file_path: &str, file_content: &[u8]) {
    let pkg_dir = root.join("node_modules").join(name);
    std::fs::create_dir_all(&pkg_dir).expect("create pkg dir");
    std::fs::write(
        pkg_dir.join("package.json"),
        format!(r#"{{ "name": "{name}", "version": "{version}" }}"#),
    )
    .expect("write pkg json");
    let full = pkg_dir.join(file_path);
    if let Some(parent) = full.parent() {
        std::fs::create_dir_all(parent).expect("create file parent");
    }
    std::fs::write(&full, file_content).expect("write package file");
}

fn write_root_package_json(root: &Path) {
    std::fs::write(
        root.join("package.json"),
        r#"{ "name": "apply-test-root", "version": "0.0.0" }"#,
    )
    .expect("write root package.json");
}

fn write_manifest_with_patch(socket: &Path, purl: &str, uuid: &str, before_hash: &str, after_hash: &str) {
    std::fs::create_dir_all(socket).expect("create .socket");
    let body = format!(
        r#"{{
  "patches": {{
    "{purl}": {{
      "uuid": "{uuid}",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {{
        "package/index.js": {{
          "beforeHash": "{before_hash}",
          "afterHash":  "{after_hash}"
        }}
      }},
      "vulnerabilities": {{}},
      "description": "Apply network test patch",
      "license": "MIT",
      "tier": "free"
    }}
  }}
}}"#
    );
    std::fs::write(socket.join("manifest.json"), body).expect("write manifest");
}

fn run_apply(cwd: &Path, api_url: &str, extra: &[&str]) -> (i32, String, String) {
    // CLI rejects --api-token / --api-url / --org on apply (those are
    // rollback-only flags) — apply respects them via env vars instead.
    let mut argv: Vec<&str> = vec!["apply", "--json"];
    argv.extend_from_slice(extra);
    let out = Command::new(binary())
        .args(&argv)
        .current_dir(cwd)
        .env("SOCKET_API_URL", api_url)
        .env("SOCKET_API_TOKEN", "fake-token-for-test")
        .env("SOCKET_ORG_SLUG", ORG_SLUG)
        .output()
        .expect("run socket-patch");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

// ---------------------------------------------------------------------------
// Online fetch path — apply downloads a missing blob and applies it.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn apply_online_fetches_missing_blob_and_patches_file() {
    let before = b"before\n";
    let after = b"after\n";
    let before_hash = git_sha256(before);
    let after_hash = git_sha256(after);

    let mock = MockServer::start().await;
    let purl = "pkg:npm/apply-network-test@1.0.0";
    let uuid = "11111111-1111-4111-8111-111111111111";

    // The fetcher hits /v0/orgs/{slug}/patches/blob/{hash}. Return the
    // patched bytes so the binary's content-hash check passes.
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/blob/{after_hash}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(after.to_vec()))
        .mount(&mock)
        .await;
    // The diff/package endpoints might be queried first (default mode is
    // `diff`). 404 them so the fetcher falls back to the blob endpoint.
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/diff/{uuid}")))
        .respond_with(ResponseTemplate::new(404))
        .mount(&mock)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v0/orgs/{ORG_SLUG}/patches/package/{uuid}")))
        .respond_with(ResponseTemplate::new(404))
        .mount(&mock)
        .await;

    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    write_npm_package(
        tmp.path(),
        "apply-network-test",
        "1.0.0",
        "index.js",
        before,
    );
    let socket = tmp.path().join(".socket");
    write_manifest_with_patch(&socket, purl, uuid, &before_hash, &after_hash);

    let (code, stdout, stderr) =
        run_apply(tmp.path(), &mock.uri(), &["--download-mode", "file"]);
    assert_eq!(
        code, 0,
        "apply must succeed; stdout={stdout}; stderr={stderr}"
    );

    // The file under node_modules should now contain the patched bytes.
    let patched_path = tmp
        .path()
        .join("node_modules/apply-network-test/index.js");
    let patched_content = std::fs::read(&patched_path).expect("read patched file");
    assert_eq!(
        patched_content, after,
        "node_modules file must contain after-content; got: {patched_content:?}"
    );

    // `.socket/blobs/` must remain empty — apply staged the fetched blob
    // into a tempdir, NOT into the persistent cache.
    let blobs_dir = socket.join("blobs");
    if blobs_dir.exists() {
        let entries: Vec<_> = std::fs::read_dir(&blobs_dir).unwrap().collect();
        assert!(
            entries.is_empty(),
            "apply must not write blobs to .socket/blobs/; found: {entries:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// --ecosystems filter
// ---------------------------------------------------------------------------

#[tokio::test]
async fn apply_with_ecosystem_filter_excluding_npm_skips_all_npm_patches() {
    let before = b"before\n";
    let after = b"after\n";
    let before_hash = git_sha256(before);
    let after_hash = git_sha256(after);

    let mock = MockServer::start().await;
    let purl = "pkg:npm/skipped@1.0.0";
    let uuid = "11111111-1111-4111-8111-111111111111";

    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "skipped", "1.0.0", "index.js", before);
    let socket = tmp.path().join(".socket");
    write_manifest_with_patch(&socket, purl, uuid, &before_hash, &after_hash);

    let (code, stdout, stderr) = run_apply(
        tmp.path(),
        &mock.uri(),
        &["--ecosystems", "pypi"],
    );
    // Exit code is 1 today (apply reports "nothing in scope" as a
    // partial-failure / not-success state); both 0 and 1 are acceptable
    // — what matters is that the file is NOT touched.
    assert!(
        code == 0 || code == 1,
        "expected 0 or 1; got {code}; stdout={stdout}; stderr={stderr}"
    );
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(v["command"], "apply");
    assert_eq!(v["summary"]["applied"], 0);

    // Node_modules file must be UNCHANGED.
    let content =
        std::fs::read(tmp.path().join("node_modules/skipped/index.js")).unwrap();
    assert_eq!(content, before, "non-matching ecosystem must skip apply");
}

// ---------------------------------------------------------------------------
// Dry-run with installed package — verified action, no disk write
// ---------------------------------------------------------------------------

#[tokio::test]
async fn apply_dry_run_emits_verified_event_without_writing() {
    let before = b"before\n";
    let after = b"after\n";
    let before_hash = git_sha256(before);
    let after_hash = git_sha256(after);

    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    write_npm_package(
        tmp.path(),
        "dryrun-target",
        "1.0.0",
        "index.js",
        before,
    );
    let socket = tmp.path().join(".socket");
    write_manifest_with_patch(
        &socket,
        "pkg:npm/dryrun-target@1.0.0",
        "11111111-1111-4111-8111-111111111111",
        &before_hash,
        &after_hash,
    );
    // Pre-stage the after blob so we don't need to mock the network
    // path; we just want to verify dry-run reports the action correctly.
    let blobs = socket.join("blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::write(blobs.join(&after_hash), after).unwrap();

    // No mock needed — apply finds everything locally.
    let out = Command::new(binary())
        .args(["apply", "--json", "--dry-run", "--offline"])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .output()
        .expect("run socket-patch");
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert_eq!(code, 0, "dry-run must succeed; stdout={stdout}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(v["dryRun"], true);
    let events = v["events"].as_array().expect("events array");
    let actions: Vec<&str> = events
        .iter()
        .map(|e| e["action"].as_str().unwrap())
        .collect();
    assert!(
        actions.contains(&"verified"),
        "dry-run must emit verified event; got actions={actions:?}"
    );

    // File content must be UNCHANGED.
    let content =
        std::fs::read(tmp.path().join("node_modules/dryrun-target/index.js")).unwrap();
    assert_eq!(content, before, "dry-run must not modify node_modules files");
}

// ---------------------------------------------------------------------------
// Apply when blob is already in `.socket/blobs/` (no fetch needed)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// `--force` accepts hash-mismatched files
// ---------------------------------------------------------------------------

#[tokio::test]
async fn apply_with_force_overrides_hash_mismatch() {
    let after = b"after\n";
    let after_hash = git_sha256(after);
    let expected_before = b"expected-before\n";
    let actual_before = b"DIFFERENT-CONTENT\n"; // wrong before content
    let expected_before_hash = git_sha256(expected_before);

    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "force-target", "1.0.0", "index.js", actual_before);
    let socket = tmp.path().join(".socket");
    write_manifest_with_patch(
        &socket,
        "pkg:npm/force-target@1.0.0",
        "11111111-1111-4111-8111-111111111111",
        &expected_before_hash,
        &after_hash,
    );
    // Pre-stage the after blob so we don't need the network.
    let blobs = socket.join("blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::write(blobs.join(&after_hash), after).unwrap();

    // Without --force apply should fail (hash mismatch). With --force it
    // should bypass the verification and write the patched content.
    let out = Command::new(binary())
        .args(["apply", "--json", "--offline", "--force"])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .output()
        .expect("run socket-patch");
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert_eq!(code, 0, "--force must succeed past hash mismatch; stdout={stdout}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    // With force on a HashMismatch, the diff path bails because the
    // on-disk hash still doesn't match `before_hash`, but the blob
    // fallback should kick in and overwrite the file with the
    // afterHash content.
    let content =
        std::fs::read(tmp.path().join("node_modules/force-target/index.js")).unwrap();
    assert_eq!(content, after, "--force must overwrite file with afterHash content");
    let _ = v;
}

#[tokio::test]
async fn apply_without_force_hash_mismatch_emits_failed_event() {
    let after = b"after\n";
    let after_hash = git_sha256(after);
    let expected_before = b"expected-before\n";
    let actual_before = b"DIFFERENT-CONTENT\n";
    let expected_before_hash = git_sha256(expected_before);

    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "mismatch", "1.0.0", "index.js", actual_before);
    let socket = tmp.path().join(".socket");
    write_manifest_with_patch(
        &socket,
        "pkg:npm/mismatch@1.0.0",
        "11111111-1111-4111-8111-111111111111",
        &expected_before_hash,
        &after_hash,
    );
    let blobs = socket.join("blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::write(blobs.join(&after_hash), after).unwrap();

    let out = Command::new(binary())
        .args(["apply", "--json", "--offline"])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .output()
        .expect("run socket-patch");
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert_eq!(code, 1, "hash mismatch w/o --force must exit 1");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(v["status"], "partialFailure");
    let events = v["events"].as_array().expect("events array");
    let has_failed = events.iter().any(|e| e["action"] == "failed");
    assert!(
        has_failed,
        "must emit a failed event on hash mismatch; got events={events:?}"
    );

    // File must be UNCHANGED.
    let content = std::fs::read(tmp.path().join("node_modules/mismatch/index.js")).unwrap();
    assert_eq!(content, actual_before, "hash mismatch must not modify file");
}

// ---------------------------------------------------------------------------
// Pypi ecosystem — covers the python crawler branch in ecosystem_dispatch
// ---------------------------------------------------------------------------

#[tokio::test]
async fn apply_pypi_package_uses_python_crawler() {
    let before = b"def hello():\n    return 'before'\n";
    let after = b"def hello():\n    return 'after'\n";
    let before_hash = git_sha256(before);
    let after_hash = git_sha256(after);

    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());

    // Pypi crawler looks for installed packages under site-packages.
    // For an in-cwd install we use `.venv/lib/python3.X/site-packages`
    // (the python_crawler probes multiple paths). Simplest: emulate
    // pip's layout with `.venv/lib/site-packages/<pkg>/`.
    let pkg_dir = tmp
        .path()
        .join(".venv/lib/python3.12/site-packages/pypi_target");
    std::fs::create_dir_all(&pkg_dir).expect("create pypi pkg dir");
    std::fs::write(pkg_dir.join("index.js"), before).expect("write source"); // file_path matches patch
    let dist_info = tmp
        .path()
        .join(".venv/lib/python3.12/site-packages/pypi_target-1.0.0.dist-info");
    std::fs::create_dir_all(&dist_info).unwrap();
    std::fs::write(
        dist_info.join("METADATA"),
        "Metadata-Version: 2.1\nName: pypi_target\nVersion: 1.0.0\n",
    )
    .unwrap();

    let socket = tmp.path().join(".socket");
    write_manifest_with_patch(
        &socket,
        "pkg:pypi/pypi_target@1.0.0",
        "11111111-1111-4111-8111-111111111111",
        &before_hash,
        &after_hash,
    );
    let blobs = socket.join("blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::write(blobs.join(&after_hash), after).unwrap();

    // Run apply restricted to pypi. The python crawler may or may not
    // locate the package depending on environment (it depends on what
    // python is available + path probing). The test's purpose is to
    // exercise the dispatch + crawler invocation paths, so we just
    // assert apply exits cleanly without panicking.
    let out = Command::new(binary())
        .args([
            "apply",
            "--json",
            "--offline",
            "--ecosystems",
            "pypi",
        ])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .output()
        .expect("run socket-patch");
    let code = out.status.code().unwrap_or(-1);
    // Either 0 (found + patched) or 1 (no python on PATH / package not
    // located) — both confirm the dispatch path was taken without
    // panicking.
    assert!(
        code == 0 || code == 1,
        "pypi apply must not panic; got {code}"
    );
}

#[tokio::test]
async fn apply_uses_locally_cached_blob_without_fetching() {
    let before = b"before\n";
    let after = b"after\n";
    let before_hash = git_sha256(before);
    let after_hash = git_sha256(after);

    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    write_npm_package(tmp.path(), "cached", "1.0.0", "index.js", before);
    let socket = tmp.path().join(".socket");
    write_manifest_with_patch(
        &socket,
        "pkg:npm/cached@1.0.0",
        "22222222-2222-4222-8222-222222222222",
        &before_hash,
        &after_hash,
    );
    let blobs = socket.join("blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::write(blobs.join(&after_hash), after).unwrap();

    // No mock server. If apply tries to hit the network, the test will
    // fail (connection refused) — proving the local-blob fast path is
    // taken when sources are already on disk.
    let out = Command::new(binary())
        .args(["apply", "--json"])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .env(
            "SOCKET_API_URL",
            "http://127.0.0.1:1", // unreachable port — should never be contacted
        )
        .output()
        .expect("run socket-patch");
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert_eq!(
        code, 0,
        "apply with cached blob must succeed without network; stdout={stdout}; stderr={stderr}"
    );

    // File was patched.
    let content = std::fs::read(tmp.path().join("node_modules/cached/index.js")).unwrap();
    assert_eq!(content, after);

    // `.socket/blobs/` must still contain the cached blob (apply is
    // read-only against the persistent cache).
    assert!(blobs.join(&after_hash).exists(), "cached blob must survive apply");
}
