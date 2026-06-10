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

/// Every `SOCKET_*` env var that `GlobalArgs` / `RollbackArgs` read as a flag
/// fallback. The child process inherits the parent's environment, so an
/// ambient value here would let a test pass via the environment instead of via
/// the flag (and the real code path) it is named after — e.g. an ambient
/// `SOCKET_OFFLINE=true` would satisfy the `--offline` tests even if `--offline`
/// were broken, and `SOCKET_MANIFEST_PATH` would silently redirect the manifest
/// out from under the no-manifest / override tests. Scrub the whole surface so
/// behavior is driven only by the explicit args we pass.
const SOCKET_ENV_VARS: &[&str] = &[
    "SOCKET_API_TOKEN",
    "SOCKET_CWD",
    "SOCKET_MANIFEST_PATH",
    "SOCKET_API_URL",
    "SOCKET_ORG_SLUG",
    "SOCKET_PROXY_URL",
    "SOCKET_ECOSYSTEMS",
    "SOCKET_DOWNLOAD_MODE",
    "SOCKET_OFFLINE",
    "SOCKET_GLOBAL",
    "SOCKET_GLOBAL_PREFIX",
    "SOCKET_JSON",
    "SOCKET_VERBOSE",
    "SOCKET_SILENT",
    "SOCKET_DRY_RUN",
    "SOCKET_YES",
    "SOCKET_LOCK_TIMEOUT",
    "SOCKET_BREAK_LOCK",
    "SOCKET_DEBUG",
    "SOCKET_TELEMETRY_DISABLED",
    "SOCKET_ONE_OFF",
];

/// A `rollback` command with the full `SOCKET_*` environment scrubbed and the
/// working directory pinned. All tests build their child process through here
/// so none can be satisfied by ambient environment instead of the code path.
fn rollback_cmd(cwd: &Path) -> Command {
    let mut cmd = Command::new(binary());
    cmd.arg("rollback").current_dir(cwd);
    for var in SOCKET_ENV_VARS {
        cmd.env_remove(var);
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
    let out = rollback_cmd(cwd)
        .args(args)
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
    // Pin the *specific* error so a regression that exits 1 for some other
    // reason (e.g. ambient env steering it into one-off mode) can't pass.
    let err = v["error"].as_str().expect("error message string");
    assert!(
        err.contains("Manifest not found"),
        "unexpected error message: {err}"
    );
}

#[test]
fn rollback_one_off_without_identifier_errors() {
    // `--one-off` is documented as requiring a UUID/PURL positional.
    // Without one, rollback bails with an error envelope.
    let tmp = tempfile::tempdir().expect("tempdir");
    let (code, stdout) = run(tmp.path(), &["--json", "--one-off"]);
    assert_eq!(
        code, 1,
        "--one-off w/o identifier must exit 1; stdout=\n{stdout}"
    );
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
    let (code, stdout) = run(
        tmp.path(),
        &[
            "--json",
            "--one-off",
            "33333333-3333-4333-8333-333333333333",
        ],
    );
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
    assert_eq!(v["dryRun"], false, "not a dry-run");
    // Known design gap (see memory `apply-invariants-test-hardened`): the
    // offline missing-blob bail returns a *contentless* partial_failure — it
    // aborts before crawling, so `failed` stays 0 and `results` is empty even
    // though the run did not succeed. Pin that exact shape so the bail can't
    // silently morph into either a real failure count or a spurious success.
    assert_eq!(
        v["failed"], 0,
        "contentless bail records no per-package failure"
    );
    assert_eq!(
        v["results"].as_array().expect("results array").len(),
        0,
        "offline bail must abort before producing any per-package results"
    );
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
    assert_eq!(
        code, 0,
        "no installed packages must exit 0; stdout=\n{stdout}"
    );
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
        "warnings",
        "results",
    ] {
        assert!(keys.contains(key), "rollback JSON missing key: {key}");
    }
    // `warnings` is documented as ALWAYS present (empty array when nothing
    // fired) so consumers can index `.warnings[]` without null-checking.
    assert!(
        v["warnings"].is_array(),
        "warnings must be an array (present even when empty)"
    );
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

    let out = rollback_cmd(tmp.path())
        .args(["--json", "--offline"])
        .output()
        .expect("run socket-patch");
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert_eq!(
        code,
        0,
        "rollback must succeed; stdout={stdout}; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(v["status"], "success");
    assert_eq!(v["rolledBack"], 1);
    assert_eq!(
        v["failed"], 0,
        "no file should fail to roll back; stdout={stdout}"
    );
    assert_eq!(v["alreadyOriginal"], 0, "file was patched, not original");
    assert_eq!(v["dryRun"], false, "live rollback, not dry-run");
    // The single result must name our package and actually list the restored file.
    let results = v["results"].as_array().expect("results array");
    let entry = results
        .iter()
        .find(|r| r["purl"] == "pkg:npm/rollback-target@1.0.0")
        .unwrap_or_else(|| panic!("missing result entry; stdout={stdout}"));
    assert_eq!(entry["success"], true);
    let rolled = entry["filesRolledBack"]
        .as_array()
        .expect("filesRolledBack array");
    assert!(
        rolled.iter().any(|f| f == "package/index.js"),
        "index.js must be listed as rolled back; stdout={stdout}"
    );

    // The file in node_modules should now contain the BEFORE bytes...
    let restored = std::fs::read(pkg_dir.join("index.js")).unwrap();
    assert_eq!(restored, before, "rollback must restore BEFORE content");
    // ...and its hash must match the manifest beforeHash (independent oracle,
    // not just byte-equality to the fixture constant).
    assert_eq!(
        git_sha256(&restored),
        before_hash,
        "restored content must hash to the manifest beforeHash"
    );
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

    let out = rollback_cmd(tmp.path())
        .args(["--json", "--offline"])
        .output()
        .expect("run socket-patch");
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert_eq!(code, 0, "rollback must succeed; stdout={stdout}");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(v["status"], "success", "stdout={stdout}");
    assert_eq!(v["alreadyOriginal"], 1);
    assert_eq!(v["rolledBack"], 0);
    assert_eq!(
        v["failed"], 0,
        "no-op must not record a failure; stdout={stdout}"
    );
    assert_eq!(v["dryRun"], false);

    // The package must actually be discovered and reported as already-original,
    // not merely produce a vacuous zero-work success (which would also satisfy
    // rolledBack==0 / alreadyOriginal would then be 0, but pin the entry too).
    let results = v["results"].as_array().expect("results array");
    let entry = results
        .iter()
        .find(|r| r["purl"] == "pkg:npm/already-orig@1.0.0")
        .unwrap_or_else(|| panic!("missing result entry; stdout={stdout}"));
    assert_eq!(entry["success"], true);
    // Nothing was rewritten, so filesRolledBack must be empty...
    assert_eq!(
        entry["filesRolledBack"]
            .as_array()
            .expect("filesRolledBack array")
            .len(),
        0,
        "already-original package must roll back zero files; stdout={stdout}"
    );
    // ...and the file must be verified as already at its original state.
    let verified = entry["filesVerified"]
        .as_array()
        .expect("filesVerified array");
    let file = verified
        .iter()
        .find(|f| f["file"] == "package/index.js")
        .expect("index.js must appear in filesVerified");
    assert_eq!(
        file["status"], "already_original",
        "file must verify as already_original; stdout={stdout}"
    );

    // File unchanged, and still hashes to the manifest beforeHash (independent
    // oracle, not just equality to the fixture constant).
    let content = std::fs::read(pkg_dir.join("index.js")).unwrap();
    assert_eq!(content, before);
    assert_eq!(git_sha256(&content), before_hash);
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

    let out = rollback_cmd(tmp.path())
        .args(["--json", "--offline", "--dry-run"])
        .output()
        .expect("run socket-patch");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert_eq!(
        out.status.code(),
        Some(0),
        "dry-run must exit 0; stdout={stdout}; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Exit-0 + unchanged-file alone would also be satisfied by a dry-run that
    // silently discovered nothing. Prove the rollback was actually *previewed*:
    // the package must be discovered, flagged dryRun, and reported as a file
    // that WOULD be rolled back (no actual rollback performed).
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(v["status"], "success", "dry-run status; stdout={stdout}");
    assert_eq!(v["dryRun"], true, "dry-run must set dryRun=true");
    // Nothing is actually written in a dry run.
    assert_eq!(v["rolledBack"], 0, "dry-run must not roll anything back");
    assert_eq!(v["failed"], 0, "dry-run must not record failures");
    let results = v["results"].as_array().expect("results array");
    let entry = results
        .iter()
        .find(|r| r["purl"] == "pkg:npm/dry-target@1.0.0")
        .unwrap_or_else(|| panic!("dry-run must discover the installed package; stdout={stdout}"));
    assert_eq!(
        entry["success"], true,
        "discovered package entry must be success"
    );
    let verified = entry["filesVerified"]
        .as_array()
        .expect("filesVerified array");
    let file = verified
        .iter()
        .find(|f| f["file"] == "package/index.js")
        .expect("index.js must appear in filesVerified");
    // "ready" means the engine confirmed it COULD restore this file (current
    // hash matches the patched AFTER state, before blob available) — i.e. it
    // genuinely walked the rollback path, just stopping short of writing.
    assert_eq!(
        file["status"], "ready",
        "dry-run must report the file as ready-to-roll-back; stdout={stdout}"
    );
    assert_eq!(
        file["targetHash"], before_hash,
        "dry-run must target the BEFORE hash"
    );

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

    let out = rollback_cmd(tmp.path())
        .args([
            "--json",
            "--offline",
            "--manifest-path",
            "custom/patches.json",
        ])
        .output()
        .expect("run socket-patch");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert_eq!(
        out.status.code(),
        Some(0),
        "manifest-path override must load + succeed; stdout={stdout}; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    // There is NO default `.socket/manifest.json` here, so a "success" status
    // can only mean the override path was honored — had it been ignored, the
    // command would have hit the no-manifest error path instead.
    assert_eq!(v["status"], "success", "stdout={stdout}");
    assert!(v["error"].is_null(), "no error expected; stdout={stdout}");
    // No installed packages match, so the run is a clean zero-work success.
    assert_eq!(v["rolledBack"], 0);
    assert_eq!(v["failed"], 0);
    assert_eq!(v["alreadyOriginal"], 0);
}
