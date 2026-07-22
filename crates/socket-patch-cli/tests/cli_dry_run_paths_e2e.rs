//! Coverage for the `--dry-run` paths across multiple commands.
//! Each test runs a command with `--dry-run` against a fixture and
//! asserts the JSON envelope's `dryRun: true` field — covering the
//! dry-run flag-propagation branches each command's `run` has.

use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

fn make_socket_with_empty_manifest(root: &std::path::Path) {
    let socket = root.join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    std::fs::write(socket.join("manifest.json"), r#"{"patches":{}}"#).unwrap();
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
}

/// Git SHA-256: `SHA256("blob <len>\0" ++ content)`. Computed
/// independently here so the manifest hashes are NOT derived from the
/// code under test (no circular oracle).
fn git_sha256(content: &[u8]) -> String {
    let header = format!("blob {}\0", content.len());
    let mut hasher = Sha256::new();
    hasher.update(header.as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

const DRYRUN_PURL: &str = "pkg:npm/dryrunpkg@1.0.0";
const DRYRUN_ORIGINAL: &[u8] = b"module.exports = function vulnerable() { return 'pwn'; };\n";
const DRYRUN_PATCHED: &[u8] = b"module.exports = function safe() { return 'ok'; };\n";

/// Lay down a project tree with ONE genuinely-applicable npm patch:
///   - `node_modules/dryrunpkg@1.0.0/index.js` holds the ORIGINAL bytes,
///   - `.socket/manifest.json` maps `package/index.js` before→after,
///   - the PATCHED bytes live as a blob keyed by their afterHash.
///
/// This is deliberately a *real* applicable patch (unlike the empty
/// manifest the other tests use), so `apply --dry-run` has actual work
/// it would do — which is the only way to tell a dry-run that honours
/// the flag apart from one that ignores it.
fn make_applicable_npm_patch(root: &Path) {
    let before = git_sha256(DRYRUN_ORIGINAL);
    let after = git_sha256(DRYRUN_PATCHED);

    // Project marker so the npm crawler treats `root` as a project root.
    std::fs::write(
        root.join("package.json"),
        r#"{"name":"dryrun-host","version":"0.0.0"}"#,
    )
    .unwrap();

    // The "installed" package the manifest patches.
    let pkg = root.join("node_modules").join("dryrunpkg");
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        pkg.join("package.json"),
        r#"{"name":"dryrunpkg","version":"1.0.0"}"#,
    )
    .unwrap();
    std::fs::write(pkg.join("index.js"), DRYRUN_ORIGINAL).unwrap();

    // .socket cache: manifest + the patched blob (named by afterHash).
    let socket = root.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    std::fs::write(socket.join("blobs").join(&after), DRYRUN_PATCHED).unwrap();
    let manifest = format!(
        r#"{{
  "patches": {{
    "{DRYRUN_PURL}": {{
      "uuid": "22222222-2222-4222-8222-222222222222",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {{
        "package/index.js": {{ "beforeHash": "{before}", "afterHash": "{after}" }}
      }},
      "vulnerabilities": {{}},
      "description": "dry-run distinguishing patch",
      "license": "MIT",
      "tier": "free"
    }}
  }}
}}"#
    );
    std::fs::write(socket.join("manifest.json"), manifest).unwrap();
}

/// `apply --dry-run --json` against an empty manifest reports
/// dryRun:true and success. Covers the dry-run flag propagation
/// in `commands::apply::run`.
#[test]
fn apply_dry_run_empty_manifest_emits_dry_run_envelope() {
    let tmp = tempfile::tempdir().expect("tempdir");
    make_socket_with_empty_manifest(tmp.path());
    let out = Command::new(binary())
        .args(["apply", "--json", "--dry-run"])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .env_remove("SOCKET_CLI_API_TOKEN")
        .output()
        .expect("run apply");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("invalid JSON: {e}\n{stdout}"));
    assert_eq!(v["command"], "apply");
    assert_eq!(v["dryRun"], true);
    // Pinned contract: `apply` against an empty manifest is a clean no-op
    // success — exit 0, status "success" — never a partialFailure/exit-1.
    // This is load-bearing for the install hooks (npm postinstall, the
    // Python .pth hook, the Bundler plugin), which run `apply` on every
    // install; a non-zero exit there would break user installs. The
    // non-dry-run flavor is pinned by
    // `in_process_edge_cases::apply_empty_manifest_is_noop`.
    assert_eq!(
        out.status.code(),
        Some(0),
        "empty-manifest dry-run should exit 0: {v}"
    );
    assert_eq!(v["status"], "success", "expected success status: {v}");
    // A dry-run must never mutate anything: every "did work" counter is 0.
    // NOTE: with an *empty* manifest this is vacuously true regardless of
    // whether `--dry-run` is honoured — the real dry-run/real-apply
    // distinction is locked down by
    // `apply_dry_run_with_real_patch_verifies_without_mutating` below.
    let summary = &v["summary"];
    assert!(summary.is_object(), "expected summary object; got {v}");
    assert_eq!(summary["applied"], 0, "dry-run applied a patch: {v}");
    assert_eq!(summary["updated"], 0, "dry-run updated a patch: {v}");
    assert_eq!(summary["removed"], 0, "dry-run removed a patch: {v}");
    assert_eq!(summary["downloaded"], 0, "dry-run downloaded a blob: {v}");
    assert_eq!(
        summary["verified"], 0,
        "empty manifest verified nothing: {v}"
    );
    // Empty manifest → nothing to do; events stay empty.
    assert_eq!(v["events"], serde_json::json!([]), "unexpected events: {v}");
}

/// The real dry-run contract: against a manifest with a patch that WOULD
/// apply, `apply --dry-run` must (a) report it would patch the package
/// (a `verified` event + `summary.verified >= 1`) yet (b) leave the
/// target file byte-for-byte unchanged on disk. A control `apply`
/// without `--dry-run` on the same fixture then proves the patch is
/// genuinely applicable — so an implementation that silently ignored the
/// `--dry-run` flag (and patched the file) would fail the on-disk check,
/// and one that did no work at all would fail the control.
#[test]
fn apply_dry_run_with_real_patch_verifies_without_mutating() {
    let tmp = tempfile::tempdir().expect("tempdir");
    make_applicable_npm_patch(tmp.path());
    let target = tmp
        .path()
        .join("node_modules")
        .join("dryrunpkg")
        .join("index.js");

    // Sanity: fixture starts at the unpatched bytes.
    assert_eq!(
        std::fs::read(&target).unwrap(),
        DRYRUN_ORIGINAL,
        "fixture should start unpatched"
    );

    // ---- DRY RUN ----
    let out = Command::new(binary())
        .args(["apply", "--json", "--dry-run", "--offline"])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .env_remove("SOCKET_CLI_API_TOKEN")
        .output()
        .expect("run apply --dry-run");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!(
            "invalid JSON: {e}\nstdout:\n{stdout}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stderr)
        )
    });
    assert_eq!(v["command"], "apply");
    assert_eq!(v["dryRun"], true);
    assert_eq!(
        out.status.code(),
        Some(0),
        "clean applicable dry-run must exit 0: {v}"
    );
    assert_eq!(
        v["status"], "success",
        "dry-run of an applicable patch should succeed: {v}"
    );

    // The dry-run must REPORT that it would patch this package...
    let summary = &v["summary"];
    assert_eq!(
        summary["verified"], 1,
        "dry-run must verify the applicable patch: {v}"
    );
    // ...while doing zero actual mutation work.
    assert_eq!(summary["applied"], 0, "dry-run must not apply: {v}");
    assert_eq!(summary["updated"], 0, "dry-run must not update: {v}");
    assert_eq!(summary["downloaded"], 0, "dry-run must not download: {v}");
    assert_eq!(
        summary["failed"], 0,
        "dry-run should not fail on a clean patch: {v}"
    );

    // The per-patch event must be a `verified` event for our exact PURL —
    // not a generic skip, and not an `applied` event.
    let events = v["events"]
        .as_array()
        .expect("envelope must carry an events array");
    let ev = events
        .iter()
        .find(|e| e["purl"] == DRYRUN_PURL)
        .unwrap_or_else(|| panic!("dry-run must emit an event for {DRYRUN_PURL}: {v}"));
    assert_eq!(
        ev["action"], "verified",
        "dry-run event must be `verified`: {v}"
    );
    // Dry-run events expose verified files but NEVER an appliedVia strategy.
    let files = ev["files"]
        .as_array()
        .expect("verified event must list files");
    assert!(
        !files.is_empty(),
        "verified event must name the file it checked: {v}"
    );
    for f in files {
        assert_eq!(
            f["verified"], true,
            "dry-run file must be marked verified: {v}"
        );
        assert!(
            f.get("appliedVia").map(|x| x.is_null()).unwrap_or(true),
            "dry-run must not record an appliedVia strategy: {v}"
        );
    }

    // The decisive check: the file on disk is untouched by the dry-run.
    assert_eq!(
        std::fs::read(&target).unwrap(),
        DRYRUN_ORIGINAL,
        "dry-run MUST NOT modify the target file on disk"
    );

    // ---- CONTROL: a real apply on the SAME fixture must actually patch ----
    // This guarantees the dry-run assertions above are non-vacuous: the
    // patch really is applicable, so "nothing changed" under --dry-run is a
    // meaningful result rather than an artifact of an inapplicable fixture.
    let out2 = Command::new(binary())
        .args(["apply", "--json", "--offline"])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .env_remove("SOCKET_CLI_API_TOKEN")
        .output()
        .expect("run apply (real)");
    let stdout2 = String::from_utf8_lossy(&out2.stdout);
    let v2: serde_json::Value = serde_json::from_str(stdout2.trim()).unwrap_or_else(|e| {
        panic!(
            "invalid JSON: {e}\nstdout:\n{stdout2}\nstderr:\n{}",
            String::from_utf8_lossy(&out2.stderr)
        )
    });
    assert_eq!(out2.status.code(), Some(0), "real apply must succeed: {v2}");
    assert_eq!(
        v2["dryRun"], false,
        "control run must not be a dry-run: {v2}"
    );
    assert_eq!(
        v2["summary"]["applied"], 1,
        "real apply must patch the package: {v2}"
    );
    assert_eq!(
        std::fs::read(&target).unwrap(),
        DRYRUN_PATCHED,
        "real apply must write the patched bytes to disk"
    );
}

const VENDORED_PURL: &str = "pkg:npm/vendored-pkg@1.0.0";

/// Extend [`make_applicable_npm_patch`] with a SECOND manifest entry that
/// is vendor-owned: recorded in `.socket/vendor/state.json`, with no
/// installed tree (the committed artifact is the source of truth). It
/// reuses the applicable patch's file hashes so the staged blob set stays
/// complete for `--offline`.
fn add_vendored_manifest_entry(root: &Path) {
    let socket = root.join(".socket");
    let manifest_path = socket.join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
    let template = manifest["patches"][DRYRUN_PURL].clone();
    manifest["patches"][VENDORED_PURL] = template;
    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();

    let vendor = socket.join("vendor");
    std::fs::create_dir_all(&vendor).unwrap();
    let state = format!(
        r#"{{
  "version": 1,
  "entries": {{
    "{VENDORED_PURL}": {{
      "ecosystem": "npm",
      "basePurl": "{VENDORED_PURL}",
      "uuid": "33333333-3333-4333-8333-333333333333",
      "artifact": {{
        "path": ".socket/vendor/npm/33333333-3333-4333-8333-333333333333/vendored-pkg-1.0.0.tgz"
      }},
      "wiring": []
    }}
  }}
}}"#
    );
    std::fs::write(vendor.join("state.json"), state).unwrap();
}

/// Regression: the human dry-run summary counted vendor-owned manifest
/// entries as "can be patched". The same run's JSON envelope classifies
/// them `skipped`/`vendored` (apply must never re-patch what
/// `socket-patch vendor` owns), so the human count must exclude them too:
/// one applicable patch + one vendored patch is "1 package(s) can be
/// patched", not 2.
#[test]
fn apply_dry_run_human_count_excludes_vendored() {
    let tmp = tempfile::tempdir().expect("tempdir");
    make_applicable_npm_patch(tmp.path());
    add_vendored_manifest_entry(tmp.path());

    // Prove the fixture is non-vacuous first: in JSON mode the vendored
    // entry must classify as skipped/vendored (if the vendor ledger were
    // unreadable it would fail open and this test would assert nothing).
    let out = Command::new(binary())
        .args(["apply", "--json", "--dry-run", "--offline"])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .env_remove("SOCKET_CLI_API_TOKEN")
        .output()
        .expect("run apply --json --dry-run");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!(
            "invalid JSON: {e}\nstdout:\n{stdout}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stderr)
        )
    });
    assert_eq!(out.status.code(), Some(0), "dry-run should exit 0: {v}");
    let events = v["events"].as_array().expect("events array");
    let vendored_ev = events
        .iter()
        .find(|e| e["purl"] == VENDORED_PURL)
        .unwrap_or_else(|| panic!("expected an event for {VENDORED_PURL}: {v}"));
    assert_eq!(
        vendored_ev["action"], "skipped",
        "vendored entry must be skipped: {v}"
    );
    assert_eq!(
        vendored_ev["errorCode"], "vendored",
        "vendored entry must carry the vendored reason: {v}"
    );

    // The human summary must agree with that classification: only the
    // genuinely applicable package counts as patchable.
    let out = Command::new(binary())
        .args(["apply", "--dry-run", "--offline"])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .env_remove("SOCKET_CLI_API_TOKEN")
        .output()
        .expect("run apply --dry-run");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("1 package(s) can be patched"),
        "human dry-run count must exclude the vendored entry; stdout:\n{stdout}"
    );
}

/// `repair --dry-run --offline --json`: dry-run with no patches
/// should succeed with `dryRun:true`.
#[test]
fn repair_dry_run_offline_emits_dry_run_envelope() {
    let tmp = tempfile::tempdir().expect("tempdir");
    make_socket_with_empty_manifest(tmp.path());
    let out = Command::new(binary())
        .args(["repair", "--json", "--dry-run", "--offline"])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .env_remove("SOCKET_CLI_API_TOKEN")
        .output()
        .expect("run repair");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("invalid JSON: {e}\n{stdout}"));
    assert_eq!(v["command"], "repair");
    assert_eq!(v["dryRun"], true);
    // No patches + offline + dry-run is a clean no-op success.
    assert_eq!(v["status"], "success", "expected success status: {v}");
    let summary = &v["summary"];
    assert!(summary.is_object(), "expected summary object; got {v}");
    assert_eq!(summary["applied"], 0, "dry-run applied a patch: {v}");
    assert_eq!(summary["updated"], 0, "dry-run updated a patch: {v}");
    assert_eq!(summary["removed"], 0, "dry-run removed a patch: {v}");
    assert_eq!(v["events"], serde_json::json!([]), "unexpected events: {v}");
}

/// Rollback with no patches in manifest + --json must not crash.
/// Locks in the manifest-empty-but-valid branch.
#[test]
fn rollback_with_empty_manifest_emits_envelope() {
    let tmp = tempfile::tempdir().expect("tempdir");
    make_socket_with_empty_manifest(tmp.path());
    let out = Command::new(binary())
        .args(["rollback", "--json", "--offline"])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .env_remove("SOCKET_CLI_API_TOKEN")
        .output()
        .expect("run rollback");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!(
            "invalid JSON: {e}\nstdout:\n{stdout}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stderr)
        )
    });
    // Empty-but-valid manifest: rollback is a clean success that touches nothing.
    assert_eq!(out.status.code(), Some(0), "rollback should exit 0: {v}");
    assert_eq!(v["status"], "success", "expected success status: {v}");
    assert_eq!(v["rolledBack"], 0, "nothing should roll back: {v}");
    assert_eq!(v["alreadyOriginal"], 0, "no files to inspect: {v}");
    assert_eq!(v["failed"], 0, "no rollback should fail: {v}");
    assert_eq!(
        v["results"],
        serde_json::json!([]),
        "unexpected results: {v}"
    );
}

/// `remove --json` with no manifest at all: the early-exit
/// envelope branch with `manifest_not_found` error code. Covered
/// elsewhere too but a redundant lock is cheap.
#[test]
fn remove_with_no_socket_dir_emits_manifest_not_found() {
    let tmp = tempfile::tempdir().expect("tempdir");
    // NO .socket/ directory at all.
    let out = Command::new(binary())
        .args([
            "remove",
            "11111111-1111-4111-8111-111111111111",
            "--json",
            "--yes",
            "--skip-rollback",
        ])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .env_remove("SOCKET_CLI_API_TOKEN")
        .output()
        .expect("run remove");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert_eq!(v["command"], "remove");
    assert_eq!(
        v["status"], "error",
        "missing manifest must be an error: {v}"
    );
    assert_eq!(out.status.code(), Some(1), "error must exit nonzero: {v}");
    // Must be the *specific* missing-manifest code, not a generic not_found.
    assert_eq!(
        v["error"]["code"], "manifest_not_found",
        "expected manifest_not_found error code; got {v}"
    );
}

/// `list --json` against an empty manifest emits status=success with
/// an all-zero summary and no events. Covers the list-empty path.
#[test]
fn list_with_empty_manifest_emits_empty_envelope() {
    let tmp = tempfile::tempdir().expect("tempdir");
    make_socket_with_empty_manifest(tmp.path());
    let out = Command::new(binary())
        .args(["list", "--json"])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .env_remove("SOCKET_CLI_API_TOKEN")
        .output()
        .expect("run list");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("invalid JSON: {e}\n{stdout}"));
    assert_eq!(v["command"], "list");
    assert_eq!(v["status"], "success");
    assert_eq!(out.status.code(), Some(0), "list should exit 0: {v}");
    // Empty manifest: nothing discovered, no events emitted.
    let summary = &v["summary"];
    assert!(summary.is_object(), "expected summary object; got {v}");
    assert_eq!(
        summary["discovered"], 0,
        "empty manifest discovered patches: {v}"
    );
    assert_eq!(v["events"], serde_json::json!([]), "unexpected events: {v}");
}

/// `--silent` flag suppresses the friendly "no manifest" message
/// in non-JSON mode for `apply`. Covers the silent-flag short-circuit.
#[test]
fn apply_silent_no_manifest_produces_no_output() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let out = Command::new(binary())
        .args(["apply", "--silent"])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .env_remove("SOCKET_CLI_API_TOKEN")
        .output()
        .expect("run apply");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.trim().is_empty(),
        "silent mode should produce no stdout"
    );
}
