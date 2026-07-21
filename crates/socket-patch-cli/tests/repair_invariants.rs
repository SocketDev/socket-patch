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

/// A `socket-patch` command rooted at `cwd` with every ambient `SOCKET_*`
/// env var scrubbed, so every assertion exercises the flag/argv path and
/// nothing the ambient environment happened to leak in:
///   * an ambient `SOCKET_OFFLINE` would make every `--offline` test pass even
///     if the `--offline` *flag* path regressed (the binary would be offline
///     for the wrong reason);
///   * `SOCKET_MANIFEST_PATH` / `SOCKET_CWD` could point the binary at a
///     different manifest than the fixture each test writes, so the
///     manifest-not-found / override assertions would be meaningless;
///   * `SOCKET_DOWNLOAD_ONLY` / `SOCKET_DOWNLOAD_MODE` / `SOCKET_DRY_RUN`
///     could flip the cleanup-vs-download branch out from under the test.
///
/// Scrubbing is by prefix, not an explicit list: an explicit list drifts
/// stale as `GlobalArgs` grows (it had already missed `SOCKET_STRICT` /
/// `SOCKET_VENDOR_SOURCE`, whose validating parsers abort every invocation
/// with exit 2 on ambient garbage), and `main` migrates legacy
/// `SOCKET_PATCH_*` names into `SOCKET_*` at startup, which the prefix also
/// covers. Tests re-seed (via `.env()`, after this scrub) only the handful
/// they deliberately control.
fn socket_cmd(cwd: &Path) -> Command {
    let mut cmd = Command::new(binary());
    cmd.current_dir(cwd);
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("SOCKET_")
            && name.to_string_lossy() != "SOCKET_NO_CONFIG"
        {
            cmd.env_remove(name);
        }
    }
    cmd
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

const REFERENCED_HASH: &str = "1111111111111111111111111111111111111111111111111111111111111111";

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
    let out = socket_cmd(cwd)
        .args(&args)
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
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("envelope must be valid JSON");
    assert_eq!(v["command"], "repair");
    assert_eq!(v["status"], "error");
    assert_eq!(v["error"]["code"], "manifest_not_found");
}

/// A project whose ONLY trace is the hosted-mode redirect ledger
/// (`.socket/vendor/redirect-state.json`) — no manifest, no vendor
/// `state.json`, no `.socket/vendor/...` lockfile references — is a no-op for
/// repair, not a `manifest_not_found` error. Hosted redirects point at
/// patch.socket.dev URLs and leave no local artifacts to rebuild or sweep, so
/// repair must exit success with an informational `redirect_only_project`
/// skip and route the user to `scan --mode hosted`.
#[test]
fn repair_redirect_only_project_is_informational_no_op() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let redirect_dir = tmp.path().join(".socket").join("vendor");
    std::fs::create_dir_all(&redirect_dir).unwrap();
    // Minimal valid ledger; repair must not validate its contents.
    std::fs::write(
        redirect_dir.join("redirect-state.json"),
        r#"{ "version": 1, "mode": "hosted" }"#,
    )
    .unwrap();

    let (code, stdout) = run_repair(tmp.path(), &[]);
    assert_eq!(
        code, 0,
        "redirect-only repair must succeed; stdout=\n{stdout}"
    );
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("envelope JSON");
    assert_eq!(v["command"], "repair");
    assert_eq!(v["status"], "success");
    // No error envelope — specifically NOT manifest_not_found.
    assert!(
        v.get("error").is_none() || v["error"].is_null(),
        "redirect-only repair must not carry an error; got {v}"
    );
    // One informational skip event routing to hosted mode.
    let events = v["events"].as_array().expect("events array");
    let skip = events
        .iter()
        .find(|e| e["action"] == "skipped")
        .expect("a skipped event");
    assert_eq!(skip["errorCode"], "redirect_only_project");
    assert!(
        skip["reason"]
            .as_str()
            .unwrap_or("")
            .contains("scan --mode hosted"),
        "skip reason must route to hosted mode; got {skip}"
    );
}

/// The human (non-JSON) path of the redirect-only no-op: exit 0 with the
/// informational message on stdout (not stderr, not an error).
#[test]
fn repair_redirect_only_project_human_mode_prints_note() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let redirect_dir = tmp.path().join(".socket").join("vendor");
    std::fs::create_dir_all(&redirect_dir).unwrap();
    std::fs::write(
        redirect_dir.join("redirect-state.json"),
        r#"{ "version": 1, "mode": "hosted" }"#,
    )
    .unwrap();

    let out = socket_cmd(tmp.path())
        .args(["repair", "--offline"])
        .output()
        .expect("run socket-patch");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("hosted redirects need no local repair"),
        "human mode must print the informational note; got stdout=\n{stdout}"
    );
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
    assert_eq!(v["command"], "repair");
    assert_eq!(v["status"], "error");
    // A malformed manifest must surface as a deterministic `repair_failed`
    // envelope whose message names the manifest-parse failure. (A bare
    // `manifest_not_found` here would mean the invalid file was silently
    // ignored — exactly the regression this test guards against.)
    let code_str = v["error"]["code"].as_str().expect("error.code");
    assert_eq!(
        code_str, "repair_failed",
        "invalid manifest must report repair_failed, got {code_str}"
    );
    let msg = v["error"]["message"].as_str().expect("error.message");
    assert!(
        msg.contains("manifest"),
        "error message should name the manifest parse failure; got {msg}"
    );
    // A parse failure must not be reported as a no-op success: nothing was
    // cleaned or downloaded.
    assert_eq!(v["summary"]["removed"], 0);
    assert_eq!(v["summary"]["downloaded"], 0);
    assert_eq!(v["events"].as_array().expect("events array").len(), 0);
}

/// `--offline` (strict airgap, no network) and `--download-only`
/// (network-only, skip cleanup) are mutually exclusive — the
/// command rejects the combination up-front with exit code 2 and
/// an `invalid_args` error in JSON mode. Covers the early-exit
/// branch at the top of `commands::repair::run`.
#[test]
fn repair_offline_and_download_only_are_mutually_exclusive() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let out = socket_cmd(tmp.path())
        .args(["repair", "--json", "--offline", "--download-only"])
        .output()
        .expect("run socket-patch");
    assert_eq!(
        out.status.code(),
        Some(2),
        "expected exit 2 for invalid flag combo; stdout=\n{}",
        String::from_utf8_lossy(&out.stdout),
    );
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
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
    let out = socket_cmd(tmp.path())
        .args(["repair", "--offline", "--download-only"])
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
    assert_eq!(v["summary"]["verified"], 0);
    // Nothing to do offline with the referenced blob present: no events at all.
    assert_eq!(
        v["events"].as_array().expect("events array").len(),
        0,
        "no-op repair must emit no events; got {}",
        v["events"]
    );
    // The referenced blob must remain untouched.
    assert!(
        socket.join("blobs").join(REFERENCED_HASH).exists(),
        "referenced blob must survive a no-op repair"
    );
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
    assert_eq!(v["status"], "success");
    assert_eq!(v["dryRun"], true);

    // Dry-run must actually DETECT the orphan, not merely emit a generic
    // "verified" event. The cleanup-preview event reports `count` (orphans
    // that would be removed) and `checked` (total blobs scanned). With one
    // referenced blob + one orphan on disk, that's count=1 / checked=2.
    let events = v["events"].as_array().expect("events array");
    let verified: Vec<&serde_json::Value> = events
        .iter()
        .filter(|e| e["action"] == "verified")
        .collect();
    assert_eq!(
        verified.len(),
        1,
        "dry-run must emit exactly one cleanup-preview event; got events={events:?}"
    );
    assert_eq!(
        verified[0]["details"]["count"], 1,
        "dry-run must report exactly one would-be-removed orphan; got {}",
        verified[0]
    );
    assert_eq!(
        verified[0]["details"]["checked"], 2,
        "dry-run must report both blobs as checked; got {}",
        verified[0]
    );
    // Summary must mirror the preview: one verified, zero actually removed.
    assert_eq!(v["summary"]["verified"], 1);
    assert_eq!(
        v["summary"]["removed"], 0,
        "dry-run must not record any actual removals"
    );

    // Neither blob may be touched on disk in dry-run mode.
    assert!(
        socket.join("blobs").join(&orphan_hash).exists(),
        "dry-run must not delete orphan blobs"
    );
    assert!(
        socket.join("blobs").join(REFERENCED_HASH).exists(),
        "dry-run must not delete the referenced blob"
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

    let out = socket_cmd(tmp.path())
        .args([
            "repair",
            "--json",
            "--download-only",
            "--download-mode",
            "file",
        ])
        .output()
        .expect("run socket-patch");
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(code, 0, "expected exit 0; stdout=\n{stdout}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("envelope JSON");
    assert_eq!(v["status"], "success");
    // The cleanup pass must be skipped entirely: zero removals AND no
    // cleanup event recorded. (Checking the orphan file alone would also
    // pass if the command silently no-op'd, so pin the summary/events too.)
    assert_eq!(
        v["summary"]["removed"], 0,
        "--download-only must not remove anything"
    );
    let events = v["events"].as_array().expect("events array");
    assert!(
        events
            .iter()
            .all(|e| e["action"] != "removed" && e["action"] != "verified"),
        "--download-only must emit no cleanup event; got events={events:?}"
    );
    // Both the referenced blob and the orphan must survive untouched.
    assert!(
        socket.join("blobs").join(REFERENCED_HASH).exists(),
        "referenced blob must survive --download-only"
    );
    assert!(
        socket.join("blobs").join(&orphan_hash).exists(),
        "--download-only must skip cleanup; orphan should still exist"
    );
}

/// Regression: a FAILED cleanup pass must not be silently swallowed by
/// `--json` / `--silent`. The human loud path warns on stderr
/// ("Warning: blob cleanup failed: ...") and continues with exit 0 — but
/// both warnings in `repair_inner`'s cleanup arms were gated on
/// `!(json || silent)`, so:
///   * `repair --json` emitted a clean `status: success` envelope with zero
///     events — a machine consumer could not distinguish "cleaned up fine"
///     from "cleanup failed with EACCES and the orphan is still there";
///   * `repair --silent` ("suppress non-error output") muted the failure
///     entirely, though an error is exactly what --silent must still print.
///
/// The fixture makes cleanup fail deterministically: the blobs dir is
/// read-only (r-x), so the orphan unlink fails EACCES while directory
/// listing and stat still work.
#[cfg(unix)]
#[test]
fn repair_cleanup_failure_is_reported_in_json_and_silent_modes() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = make_socket_dir(tmp.path());
    write_blob(&socket, REFERENCED_HASH, b"kept");
    let orphan = "0badf00d".repeat(8); // 64 chars, not referenced
    write_blob(&socket, &orphan, b"orphan bytes");
    let blobs_dir = socket.join("blobs");
    std::fs::set_permissions(&blobs_dir, std::fs::Permissions::from_mode(0o555))
        .expect("chmod blobs dir read-only");

    // Control (loud human mode): proves the fixture actually trips the
    // cleanup-failure path — the warning is on stderr and the run still
    // exits 0 (cleanup failure is warn-and-continue, not fatal). If this
    // fails, the environment can unlink from a r-x dir (e.g. running as
    // root) and the assertions below would be vacuous.
    let loud = socket_cmd(tmp.path())
        .args(["repair", "--offline"])
        .output()
        .expect("run socket-patch");
    assert_eq!(
        loud.status.code(),
        Some(0),
        "control: cleanup failure must stay non-fatal; stderr=\n{}",
        String::from_utf8_lossy(&loud.stderr)
    );
    assert!(
        String::from_utf8_lossy(&loud.stderr).contains("blob cleanup failed"),
        "control: loud human mode must warn about the failed cleanup; stderr=\n{}",
        String::from_utf8_lossy(&loud.stderr)
    );
    assert!(
        blobs_dir.join(&orphan).exists(),
        "control: the orphan must have survived the failed cleanup"
    );

    // JSON mode: the envelope must carry the cleanup failure as an
    // informational skip event (warn-and-continue semantics preserved:
    // status stays success, exit stays 0, nothing was removed).
    let (code, stdout) = run_repair(tmp.path(), &[]);
    assert_eq!(
        code, 0,
        "json: cleanup failure stays non-fatal; stdout=\n{stdout}"
    );
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("envelope JSON");
    assert_eq!(v["status"], "success");
    assert_eq!(v["summary"]["removed"], 0);
    let events = v["events"].as_array().expect("events array");
    let skip = events
        .iter()
        .find(|e| e["action"] == "skipped" && e["errorCode"] == "cleanup_failed")
        .unwrap_or_else(|| {
            panic!("json: envelope must record the failed cleanup; got events={events:?}")
        });
    assert!(
        skip["reason"].as_str().unwrap_or("").contains("blob"),
        "the skip reason must name the failing cleanup pass; got {skip}"
    );

    // Silent mode: stdout stays empty, but the failure warning must still
    // reach stderr — --silent suppresses non-ERROR output only.
    let silent = socket_cmd(tmp.path())
        .args(["repair", "--offline", "--silent"])
        .output()
        .expect("run socket-patch");
    assert_eq!(silent.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&silent.stdout).trim().is_empty(),
        "--silent must keep stdout empty; got:\n{}",
        String::from_utf8_lossy(&silent.stdout)
    );
    assert!(
        String::from_utf8_lossy(&silent.stderr).contains("blob cleanup failed"),
        "--silent must NOT mute the cleanup-failure warning; stderr=\n{}",
        String::from_utf8_lossy(&silent.stderr)
    );

    // Restore permissions so the tempdir can be cleaned up.
    std::fs::set_permissions(&blobs_dir, std::fs::Permissions::from_mode(0o755))
        .expect("restore blobs dir permissions");
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
    let out = socket_cmd(tmp.path())
        .args(["gc", "--json", "--offline"])
        .output()
        .expect("run socket-patch");
    assert_eq!(out.status.code(), Some(0));
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    // The envelope's `command` field reports the canonical name, not the alias.
    assert_eq!(v["command"], "repair");
    assert_eq!(v["status"], "success");
    // Full parity with `repair_offline_removes_orphan_blob`: the orphan is
    // swept, the referenced blob survives, and nothing is downloaded offline.
    assert_eq!(v["summary"]["removed"], 1);
    assert_eq!(v["summary"]["downloaded"], 0);
    assert!(
        !socket.join("blobs").join(&orphan_hash).exists(),
        "gc must remove the orphan just like repair"
    );
    assert!(
        socket.join("blobs").join(REFERENCED_HASH).exists(),
        "gc must keep the referenced blob just like repair"
    );
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
    let blob_endpoint = format!("/v0/orgs/{ORG_SLUG}/patches/blob/{after_hash}");
    Mock::given(method("GET"))
        .and(path(blob_endpoint.clone()))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(content.to_vec()))
        .expect(1)
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

    let out = socket_cmd(tmp.path())
        .args([
            "repair",
            "--json",
            "--download-mode",
            "file",
            "--download-only",
        ])
        .env("SOCKET_API_URL", mock.uri())
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

    // Prove the network path was actually exercised against the mock — that
    // the `downloaded: 1` count and the on-disk blob came from a real GET to
    // the blob endpoint, not from some cache/short-circuit that fabricated
    // the count. wiremock records every request it received.
    let requests = mock
        .received_requests()
        .await
        .expect("wiremock should be recording requests");
    let blob_hits: Vec<_> = requests
        .iter()
        .filter(|r| r.url.path() == blob_endpoint)
        .collect();
    assert_eq!(
        blob_hits.len(),
        1,
        "repair must issue exactly one GET to {blob_endpoint}; saw {} request(s): {:?}",
        requests.len(),
        requests
            .iter()
            .map(|r| r.url.path().to_string())
            .collect::<Vec<_>>(),
    );
    assert_eq!(format!("{}", blob_hits[0].method), "GET");
}

#[test]
fn repair_honors_manifest_path_override() {
    // Put the manifest somewhere other than `.socket/manifest.json` and
    // confirm `--manifest-path` finds it. This exercises the
    // `resolved_manifest_path` codepath.
    let tmp = tempfile::tempdir().expect("tempdir");
    let custom_dir = tmp.path().join("custom");
    std::fs::create_dir_all(&custom_dir).unwrap();
    std::fs::write(custom_dir.join("patches.json"), MANIFEST_JSON).unwrap();

    // Negative control: with NO `.socket/manifest.json` and no override,
    // repair must fail to find a manifest. This proves the success below is
    // attributable to `--manifest-path` and not to some incidental default
    // path resolution.
    let (ctrl_code, ctrl_stdout) = run_repair(tmp.path(), &[]);
    assert_eq!(
        ctrl_code, 1,
        "control: repair without override must fail; stdout=\n{ctrl_stdout}"
    );
    let cv: serde_json::Value = serde_json::from_str(&ctrl_stdout).expect("control envelope JSON");
    assert_eq!(cv["error"]["code"], "manifest_not_found");

    let out = socket_cmd(tmp.path())
        .args([
            "repair",
            "--json",
            "--offline",
            "--manifest-path",
            "custom/patches.json",
        ])
        .output()
        .expect("run socket-patch");
    assert_eq!(
        out.status.code(),
        Some(0),
        "expected exit 0; stdout=\n{}\nstderr=\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert_eq!(v["command"], "repair");
    assert_eq!(v["status"], "success");
    // The override manifest references one blob with no blob on disk, but
    // offline mode fetches nothing and there are no orphans to remove.
    assert_eq!(v["summary"]["removed"], 0);
    assert_eq!(v["summary"]["downloaded"], 0);
}

/// Regression: `--silent` ("Suppress non-error output") must mute the
/// human-readable progress that `repair` prints to stdout — "Found N
/// missing", "Downloading…", the cleanup summary and "Repair complete.".
///
/// Before the fix every informational print in `repair_inner` was gated on
/// `--json` ALONE, so `repair --silent` (no `--json`) still flooded stdout,
/// contradicting the flag's contract (and `get`/`apply`, which gate on
/// `!json && !silent`). We run an offline repair that has real work to
/// report — an orphan blob to sweep — once silent and once not, and prove
/// the silent run emits NOTHING on stdout while the loud control does.
#[test]
fn repair_silent_suppresses_human_stdout() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = make_socket_dir(tmp.path());
    // Keep the referenced blob (survives) plus an orphan (swept) so cleanup
    // has something to announce in the non-silent control.
    write_blob(&socket, REFERENCED_HASH, b"kept");
    let orphan = "deadbeef".repeat(8); // 64 hex chars, not referenced
    write_blob(&socket, &orphan, b"orphan bytes");

    // Loud control (offline, human mode): stdout must carry the summary.
    let loud = socket_cmd(tmp.path())
        .args(["repair", "--offline"])
        .output()
        .expect("run socket-patch");
    assert_eq!(loud.status.code(), Some(0));
    let loud_out = String::from_utf8_lossy(&loud.stdout);
    assert!(
        loud_out.contains("Repair complete."),
        "control: human repair must print progress; stdout=\n{loud_out}"
    );

    // Re-stage the orphan (the control swept it) so the silent run has the
    // identical workload — only the flag differs.
    write_blob(&socket, &orphan, b"orphan bytes");

    let silent = socket_cmd(tmp.path())
        .args(["repair", "--offline", "--silent"])
        .output()
        .expect("run socket-patch");
    assert_eq!(
        silent.status.code(),
        Some(0),
        "silent repair must still succeed; stderr=\n{}",
        String::from_utf8_lossy(&silent.stderr),
    );
    let silent_out = String::from_utf8_lossy(&silent.stdout);
    assert!(
        silent_out.trim().is_empty(),
        "--silent must suppress all human stdout; got:\n{silent_out}"
    );
    // And the work still happened: the orphan was actually swept.
    assert!(
        !socket.join("blobs").join(&orphan).exists(),
        "silent repair must still perform cleanup (orphan should be gone)"
    );
}
