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

fn write_manifest_with_patch(
    socket: &Path,
    purl: &str,
    uuid: &str,
    before_hash: &str,
    after_hash: &str,
) {
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
        .and(path(format!(
            "/v0/orgs/{ORG_SLUG}/patches/blob/{after_hash}"
        )))
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

    let (code, stdout, stderr) = run_apply(tmp.path(), &mock.uri(), &["--download-mode", "file"]);
    assert_eq!(
        code, 0,
        "apply must succeed; stdout={stdout}; stderr={stderr}"
    );

    // The whole point of this test is the ONLINE fetch path: the blob was
    // neither pre-staged in `.socket/blobs/` nor present anywhere on disk,
    // so the only way the file can end up with after-content is by the
    // binary actually GETting it from the blob endpoint. Assert the mock
    // recorded that request — otherwise a future regression that resolved
    // the content some other way (or short-circuited) would stay green.
    let requests = mock
        .received_requests()
        .await
        .expect("wiremock records requests");
    let blob_path = format!("/v0/orgs/{ORG_SLUG}/patches/blob/{after_hash}");
    assert!(
        requests.iter().any(|r| r.url.path() == blob_path),
        "apply must fetch the missing blob from the API; \
         got requests={:?}",
        requests
            .iter()
            .map(|r| r.url.path().to_string())
            .collect::<Vec<_>>()
    );
    // The fetch path must have actually applied the patch (not silently
    // no-op'd to a green exit). Assert the JSON summary, not just exit code.
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(v["command"], "apply");
    assert_eq!(
        v["summary"]["applied"], 1,
        "online fetch must apply exactly one patch; stdout={stdout}"
    );
    assert_eq!(
        v["summary"]["failed"], 0,
        "online fetch must not record any failures; stdout={stdout}"
    );
    let events = v["events"].as_array().expect("events array");
    assert!(
        events
            .iter()
            .any(|e| e["purl"] == purl && e["action"] != "failed"),
        "must emit a non-failed event for the patched purl; events={events:?}"
    );

    // The file under node_modules should now contain the patched bytes.
    let patched_path = tmp.path().join("node_modules/apply-network-test/index.js");
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

    let (code, stdout, stderr) = run_apply(tmp.path(), &mock.uri(), &["--ecosystems", "pypi"]);
    // Filtering out npm leaves nothing in scope: there is genuinely no
    // work this run can do, so apply is a clean no-op SUCCESS (exit 0) —
    // the same documented contract as an empty manifest (npm `postinstall`
    // runs `apply` on every install). This test previously pinned exit
    // 1/partialFailure, but that outcome was an artifact of a scoping bug:
    // the excluded npm patch's missing artifacts were fetched (and failed,
    // against this route-less mock) BEFORE the `--ecosystems` filter was
    // applied, so the run never reached the no-in-scope success path. The
    // filter now scopes the source probes and download planner up front.
    assert_eq!(
        code, 0,
        "ecosystem filter with nothing in scope is a clean no-op success; stdout={stdout}; stderr={stderr}"
    );
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(v["command"], "apply");
    assert_eq!(v["status"], "success");
    assert_eq!(v["summary"]["applied"], 0);
    // Nothing in the npm ecosystem may even be discovered/downloaded once
    // it's filtered out — guards against the filter being applied only at
    // the write step while still crawling/fetching the excluded packages.
    assert_eq!(
        v["summary"]["discovered"], 0,
        "filtered npm must not be discovered"
    );
    assert_eq!(
        v["summary"]["downloaded"], 0,
        "filtered npm must not be downloaded"
    );
    assert_eq!(
        v["summary"]["failed"], 0,
        "skipping out-of-scope is not a failure"
    );
    // The excluded patch's artifacts must not be fetched AT ALL — the
    // filter scopes the download planner itself, not just the write step.
    // (Only artifact endpoints are checked; telemetry may ping the API.)
    let requests = mock.received_requests().await.unwrap_or_default();
    let artifact_requests: Vec<_> = requests
        .iter()
        .filter(|r| r.url.path().contains("/patches/"))
        .collect();
    assert!(
        artifact_requests.is_empty(),
        "no patch artifacts may be fetched for a filtered-out ecosystem; got {artifact_requests:?}"
    );
    // The excluded npm patch must not appear as an applied/patched event —
    // an empty `events` array or one without our purl is fine, but a
    // "patched" event for the skipped purl would mean the filter leaked.
    if let Some(events) = v["events"].as_array() {
        assert!(
            !events
                .iter()
                .any(|e| e["purl"] == purl && e["action"] == "patched"),
            "ecosystem filter must not patch the excluded npm purl; events={events:?}"
        );
    }

    // Node_modules file must be UNCHANGED.
    let content = std::fs::read(tmp.path().join("node_modules/skipped/index.js")).unwrap();
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
    write_npm_package(tmp.path(), "dryrun-target", "1.0.0", "index.js", before);
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
    // Dry-run must report it would patch but never actually applies.
    assert_eq!(
        v["summary"]["applied"], 0,
        "dry-run must not count any applied patch; stdout={stdout}"
    );
    let events = v["events"].as_array().expect("events array");
    // The verified event must be for OUR purl, not some unrelated event;
    // and dry-run must NOT emit a real "patched"/"applied" action.
    assert!(
        events
            .iter()
            .any(|e| e["purl"] == "pkg:npm/dryrun-target@1.0.0" && e["action"] == "verified"),
        "dry-run must emit a verified event for the target purl; events={events:?}"
    );
    assert!(
        events
            .iter()
            .all(|e| e["action"] != "patched" && e["action"] != "applied"),
        "dry-run must not emit a patched/applied action; events={events:?}"
    );

    // File content must be UNCHANGED.
    let content = std::fs::read(tmp.path().join("node_modules/dryrun-target/index.js")).unwrap();
    assert_eq!(
        content, before,
        "dry-run must not modify node_modules files"
    );
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
    write_npm_package(
        tmp.path(),
        "force-target",
        "1.0.0",
        "index.js",
        actual_before,
    );
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
    assert_eq!(
        code, 0,
        "--force must succeed past hash mismatch; stdout={stdout}"
    );
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    // With force on a HashMismatch, the diff path bails because the
    // on-disk hash still doesn't match `before_hash`, but the blob
    // fallback should kick in and overwrite the file with the
    // afterHash content. Assert the run reports a real success — a
    // green exit with applied==0 would mean --force silently skipped.
    assert_eq!(v["command"], "apply");
    assert_eq!(
        v["summary"]["applied"], 1,
        "--force must apply the patch past the hash mismatch; stdout={stdout}"
    );
    let events = v["events"].as_array().expect("events array");
    assert!(
        events.iter().all(|e| e["action"] != "failed"),
        "--force run must not emit a failed event; events={events:?}"
    );
    let content = std::fs::read(tmp.path().join("node_modules/force-target/index.js")).unwrap();
    assert_eq!(
        content, after,
        "--force must overwrite file with afterHash content"
    );
}

#[tokio::test]
async fn apply_hash_mismatch_default_warns_and_applies_strict_fails() {
    let after = b"after\n";
    let after_hash = git_sha256(after);
    let expected_before = b"expected-before\n";
    let actual_before = b"DIFFERENT-CONTENT\n";
    let expected_before_hash = git_sha256(expected_before);

    let fixture = || {
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
        tmp
    };

    // DEFAULT: the mismatch is overwritten with the full verified patched
    // content (the diff strategy would self-skip; the blob is hash-gated to
    // afterHash) and surfaced as a warning event — exit 0.
    let tmp = fixture();
    let out = Command::new(binary())
        .args(["apply", "--json", "--offline"])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .output()
        .expect("run socket-patch");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(
        out.status.code().unwrap_or(-1),
        0,
        "default mismatch is a warning, not an error: {v:#}"
    );
    assert_eq!(v["status"], "success", "{v:#}");
    let events = v["events"].as_array().expect("events array");
    assert!(
        events.iter().any(|e| e["action"] == "applied"),
        "{events:?}"
    );
    assert!(
        events
            .iter()
            .any(|e| e["errorCode"] == "content_mismatch_overwritten"),
        "the overwrite is surfaced as a warning event: {events:?}"
    );
    let content = std::fs::read(tmp.path().join("node_modules/mismatch/index.js")).unwrap();
    assert_eq!(
        content, after,
        "the file carries the verified patched bytes"
    );

    // The human run logs the warning to stderr.
    let tmp = fixture();
    let out = Command::new(binary())
        .args(["apply", "--offline", "--yes"])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .output()
        .expect("run socket-patch");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code().unwrap_or(-1), 0, "stderr={stderr}");
    assert!(
        stderr.contains("content_mismatch_overwritten"),
        "stderr warning present: {stderr}"
    );

    // --strict: the old fail-closed contract — exit 1, failed event, file
    // untouched.
    let tmp = fixture();
    let out = Command::new(binary())
        .args(["apply", "--json", "--offline", "--strict"])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .output()
        .expect("run socket-patch");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(out.status.code().unwrap_or(-1), 1, "{v:#}");
    assert_eq!(v["status"], "partialFailure", "{v:#}");
    let events = v["events"].as_array().expect("events array");
    assert!(
        events.iter().any(|e| e["action"] == "failed"),
        "strict emits a failed event: {events:?}"
    );
    let content = std::fs::read(tmp.path().join("node_modules/mismatch/index.js")).unwrap();
    assert_eq!(content, actual_before, "strict must not modify the file");
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

    // Pypi crawler discovers a project-local venv via filesystem probing
    // (`find_local_venv_site_packages` → `find_site_packages_under`), so this is
    // fully deterministic and does NOT depend on a real Python on PATH. The
    // probed layout is platform-specific: `.venv/Lib/site-packages` on Windows,
    // `.venv/lib/python3.*/site-packages` on Unix — stage whichever this runner
    // will actually look in. The crawler returns the *site-packages* dir as the
    // package path, and apply joins it with the patch file key after stripping
    // the `package/` prefix — so the patch key `package/index.js` resolves to
    // `<site-packages>/index.js`. Write the source there so apply can patch it.
    let site_packages = if cfg!(windows) {
        tmp.path().join(".venv").join("Lib").join("site-packages")
    } else {
        tmp.path()
            .join(".venv")
            .join("lib")
            .join("python3.12")
            .join("site-packages")
    };
    std::fs::create_dir_all(&site_packages).expect("create site-packages");
    std::fs::write(site_packages.join("index.js"), before).expect("write source");
    let dist_info = site_packages.join("pypi_target-1.0.0.dist-info");
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

    // Run apply restricted to pypi. With the venv staged on disk and the
    // after-blob pre-cached, this must locate the package via the python
    // crawler and patch it — exercising the pypi dispatch branch end to
    // end, not just "without panicking". `VIRTUAL_ENV` is cleared so an
    // ambient venv in CI can't redirect discovery away from our `.venv`.
    let out = Command::new(binary())
        .args(["apply", "--json", "--offline", "--ecosystems", "pypi"])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .env_remove("VIRTUAL_ENV")
        .output()
        .expect("run socket-patch");
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert_eq!(
        code, 0,
        "pypi apply must find + patch the package; stdout={stdout}; stderr={stderr}"
    );
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(v["command"], "apply");
    assert_eq!(
        v["summary"]["applied"], 1,
        "exactly one pypi patch must be applied; stdout={stdout}"
    );
    // The pypi crawler must have been the one to resolve the package: the
    // patched event carries the pypi PURL.
    let events = v["events"].as_array().expect("events array");
    assert!(
        events
            .iter()
            .any(|e| e["purl"] == "pkg:pypi/pypi_target@1.0.0" && e["action"] != "failed"),
        "must emit a non-failed event for the pypi purl; got events={events:?}"
    );

    // The on-disk source file under site-packages must now hold after-content.
    let patched = std::fs::read(site_packages.join("index.js")).expect("read patched");
    assert_eq!(
        patched, after,
        "pypi apply must overwrite site-packages file with after-content"
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
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(
        v["summary"]["applied"], 1,
        "cached-blob apply must apply exactly one patch; stdout={stdout}"
    );

    // File was patched.
    let content = std::fs::read(tmp.path().join("node_modules/cached/index.js")).unwrap();
    assert_eq!(content, after);

    // `.socket/blobs/` must still contain the cached blob (apply is
    // read-only against the persistent cache).
    assert!(
        blobs.join(&after_hash).exists(),
        "cached blob must survive apply"
    );
}

// ---------------------------------------------------------------------------
// Mismatch + diff-mode sources: the full blob is redownloaded on demand.
// ---------------------------------------------------------------------------

/// A mismatched file cannot be patched from a partial source (the diff
/// strategy needs the exact before-bytes), so the default mismatch policy
/// redownloads the FULL afterHash blob and applies that — even when a
/// local source archive made the stage step skip downloading.
#[tokio::test]
async fn apply_mismatch_redownloads_full_blob_and_applies() {
    let after = b"after\n";
    let after_hash = git_sha256(after);
    let expected_before_hash = git_sha256(b"expected-before\n");

    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!(
            "/v0/orgs/{ORG_SLUG}/patches/blob/{after_hash}"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(after.to_vec()))
        .mount(&mock)
        .await;

    let uuid = "11111111-1111-4111-8111-111111111111";
    let tmp = tempfile::tempdir().expect("tempdir");
    write_root_package_json(tmp.path());
    write_npm_package(
        tmp.path(),
        "mismatch",
        "1.0.0",
        "index.js",
        b"DIFFERENT-CONTENT\n",
    );
    let socket = tmp.path().join(".socket");
    write_manifest_with_patch(
        &socket,
        "pkg:npm/mismatch@1.0.0",
        uuid,
        &expected_before_hash,
        &after_hash,
    );
    // A LOCAL package archive exists (so the stage step downloads nothing)
    // but carries no entry for index.js — only the blob can produce the
    // patched bytes, and no blob is staged.
    let packages = socket.join("packages");
    std::fs::create_dir_all(&packages).unwrap();
    {
        use std::io::Write as _;
        let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(
            std::fs::File::create(packages.join(format!("{uuid}.tar.gz"))).unwrap(),
            flate2::Compression::default(),
        ));
        let mut header = tar::Header::new_gnu();
        let bytes = b"unrelated";
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "other.js", &bytes[..])
            .unwrap();
        builder
            .into_inner()
            .unwrap()
            .finish()
            .unwrap()
            .flush()
            .unwrap();
    }

    let (code, stdout, stderr) = run_apply(tmp.path(), &mock.uri(), &[]);
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(code, 0, "stdout={v:#}\nstderr={stderr}");
    let events = v["events"].as_array().expect("events array");
    assert!(
        events
            .iter()
            .any(|e| e["errorCode"] == "content_mismatch_overwritten"),
        "{events:?}"
    );

    // The blob was fetched on demand…
    let requests = mock.received_requests().await.unwrap();
    let blob_path = format!("/v0/orgs/{ORG_SLUG}/patches/blob/{after_hash}");
    assert!(
        requests.iter().any(|r| r.url.path() == blob_path),
        "the full blob must be redownloaded for the mismatched file"
    );
    // …and the file carries the verified patched bytes.
    let content = std::fs::read(tmp.path().join("node_modules/mismatch/index.js")).unwrap();
    assert_eq!(content, after);
}
