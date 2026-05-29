//! End-to-end tests for embedded OpenVEX generation via `--vex` on the
//! `apply` and `scan` subcommands.
//!
//! These exercise the *integration* added on top of the core `vex`
//! pipeline (which `e2e_vex.rs` already covers): that a successful
//! `apply`/`scan` writes the VEX document, folds a `vex` summary into the
//! JSON envelope, and — per the fail-the-command contract — flips the
//! exit code (and surfaces an `error`) when VEX generation fails.
//!
//! All offline: `apply` runs against a pre-seeded `.socket/blobs/` cache,
//! and the `scan` cases find zero installed packages so no API call fires.

use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

use serde_json::Value;
use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes;
use socket_patch_core::manifest::schema::{
    PatchFileInfo, PatchManifest, PatchRecord, VulnerabilityInfo,
};

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_socket-patch")
}

fn write_manifest(cwd: &Path, manifest: &PatchManifest) {
    let dir = cwd.join(".socket");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("manifest.json"),
        serde_json::to_string_pretty(manifest).unwrap(),
    )
    .unwrap();
}

/// One-file, one-vuln patch record.
fn make_record(
    uuid: &str,
    file_name: &str,
    before_hash: &str,
    after_hash: &str,
    vuln_id: &str,
    cves: &[&str],
) -> PatchRecord {
    let mut files = HashMap::new();
    files.insert(
        file_name.to_string(),
        PatchFileInfo {
            before_hash: before_hash.to_string(),
            after_hash: after_hash.to_string(),
        },
    );
    let mut vulns = HashMap::new();
    vulns.insert(
        vuln_id.to_string(),
        VulnerabilityInfo {
            cves: cves.iter().map(|s| s.to_string()).collect(),
            summary: "test summary".to_string(),
            severity: "high".to_string(),
            description: "test description".to_string(),
        },
    );
    PatchRecord {
        uuid: uuid.to_string(),
        exported_at: "2024-01-01T00:00:00Z".to_string(),
        files,
        vulnerabilities: vulns,
        description: format!("Patch {uuid}"),
        license: "MIT".to_string(),
        tier: "free".to_string(),
    }
}

/// Lay down a synthetic npm package with a single file at `before`
/// content, plus the matching `after` blob in `.socket/blobs/`, and a
/// manifest entry so an offline `apply` can patch it in place.
///
/// Returns the `after_hash` (the on-disk hash once patched) so callers can
/// assert post-apply state.
fn seed_offline_apply(cwd: &Path) -> String {
    let before = b"before contents\n";
    let after = b"after contents\n";
    let before_hash = compute_git_sha256_from_bytes(before);
    let after_hash = compute_git_sha256_from_bytes(after);

    let pkg = cwd.join("node_modules").join("vuln-pkg");
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        pkg.join("package.json"),
        r#"{"name":"vuln-pkg","version":"1.0.0"}"#,
    )
    .unwrap();
    std::fs::write(pkg.join("index.js"), before).unwrap();

    let mut manifest = PatchManifest::new();
    manifest.patches.insert(
        "pkg:npm/vuln-pkg@1.0.0".to_string(),
        make_record(
            "11111111-1111-4111-8111-111111111111",
            "package/index.js",
            &before_hash,
            &after_hash,
            "GHSA-aaaa-bbbb-cccc",
            &["CVE-2024-0001"],
        ),
    );
    write_manifest(cwd, &manifest);

    let blobs = cwd.join(".socket").join("blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::write(blobs.join(&after_hash), after).unwrap();

    after_hash
}

// ──────────────────────────────────────────────────────────────────────
// apply --vex
// ──────────────────────────────────────────────────────────────────────

#[test]
fn apply_vex_writes_document_on_success() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    let after_hash = seed_offline_apply(cwd);
    let vex_path = cwd.join("apply.vex.json");

    let out = Command::new(binary())
        .args([
            "apply",
            "--cwd",
            cwd.to_str().unwrap(),
            "--offline",
            "--vex",
            vex_path.to_str().unwrap(),
            "--vex-product",
            "pkg:npm/my-app@1.0.0",
        ])
        .output()
        .expect("invoke apply");
    assert!(
        out.status.success(),
        "apply --vex should exit 0. stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // The patch was actually applied.
    let on_disk = std::fs::read(cwd.join("node_modules/vuln-pkg/index.js")).unwrap();
    assert_eq!(compute_git_sha256_from_bytes(&on_disk), after_hash);

    // The VEX doc landed at --vex with a statement for our GHSA.
    let doc: Value =
        serde_json::from_str(&std::fs::read_to_string(&vex_path).unwrap()).unwrap();
    assert_eq!(doc["@context"], "https://openvex.dev/ns/v0.2.0");
    let stmts = doc["statements"].as_array().unwrap();
    assert_eq!(stmts.len(), 1);
    assert_eq!(stmts[0]["vulnerability"]["name"], "GHSA-aaaa-bbbb-cccc");
    assert_eq!(
        stmts[0]["products"][0]["@id"], "pkg:npm/my-app@1.0.0",
        "product comes from --vex-product"
    );
}

#[test]
fn apply_json_envelope_carries_vex_summary() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    seed_offline_apply(cwd);
    let vex_path = cwd.join("apply.vex.json");

    let out = Command::new(binary())
        .args([
            "apply",
            "--cwd",
            cwd.to_str().unwrap(),
            "--offline",
            "--json",
            "--vex",
            vex_path.to_str().unwrap(),
            "--vex-product",
            "pkg:npm/my-app@1.0.0",
        ])
        .output()
        .expect("invoke apply");
    assert!(out.status.success());

    let env: Value = serde_json::from_slice(&out.stdout).expect("apply envelope JSON");
    assert_eq!(env["command"], "apply");
    assert_eq!(env["status"], "success");
    assert_eq!(env["vex"]["statements"], 1);
    assert_eq!(env["vex"]["format"], "openvex-0.2.0");
    assert_eq!(env["vex"]["path"], vex_path.to_str().unwrap());
    assert!(vex_path.exists());
}

#[test]
fn apply_vex_failure_flips_exit_code() {
    // Apply succeeds, but no product PURL can be detected (no root
    // package.json / git remote) and none was supplied → VEX generation
    // fails → the whole command exits non-zero and writes no file.
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    seed_offline_apply(cwd);
    let vex_path = cwd.join("apply.vex.json");

    let out = Command::new(binary())
        .args([
            "apply",
            "--cwd",
            cwd.to_str().unwrap(),
            "--offline",
            "--json",
            "--vex",
            vex_path.to_str().unwrap(),
        ])
        .output()
        .expect("invoke apply");
    assert!(
        !out.status.success(),
        "a requested-but-failed VEX must flip the exit code"
    );

    let env: Value = serde_json::from_slice(&out.stdout).expect("apply envelope JSON");
    assert_eq!(env["status"], "error");
    assert_eq!(env["error"]["code"], "product_undetected");
    assert!(!vex_path.exists(), "no VEX file on failure");

    // Patch still applied (apply itself succeeded before VEX failed).
    let on_disk = std::fs::read(cwd.join("node_modules/vuln-pkg/index.js")).unwrap();
    assert_eq!(&on_disk, b"after contents\n");
}

// ──────────────────────────────────────────────────────────────────────
// scan --vex (read-only; zero installed packages → no network)
// ──────────────────────────────────────────────────────────────────────

#[test]
fn scan_json_vex_no_verify_emits_summary() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();

    // Manifest with a vuln, but nothing installed on disk. With
    // `--vex-no-verify` the manifest is trusted, so the empty-scan path
    // still produces a document.
    let mut manifest = PatchManifest::new();
    manifest.patches.insert(
        "pkg:npm/vuln-pkg@1.0.0".to_string(),
        make_record(
            "11111111-1111-4111-8111-111111111111",
            "package/index.js",
            &"a".repeat(64),
            &"b".repeat(64),
            "GHSA-aaaa-bbbb-cccc",
            &["CVE-2024-0001"],
        ),
    );
    write_manifest(cwd, &manifest);
    let vex_path = cwd.join("scan.vex.json");

    let out = Command::new(binary())
        .args([
            "scan",
            "--cwd",
            cwd.to_str().unwrap(),
            "--json",
            "--vex",
            vex_path.to_str().unwrap(),
            "--vex-no-verify",
            "--vex-product",
            "pkg:npm/my-app@1.0.0",
        ])
        .output()
        .expect("invoke scan");
    assert!(
        out.status.success(),
        "scan --vex --vex-no-verify should exit 0. stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let result: Value = serde_json::from_slice(&out.stdout).expect("scan JSON");
    assert_eq!(result["scannedPackages"], 0);
    assert_eq!(result["vex"]["statements"], 1);
    assert_eq!(result["vex"]["path"], vex_path.to_str().unwrap());

    let doc: Value =
        serde_json::from_str(&std::fs::read_to_string(&vex_path).unwrap()).unwrap();
    assert_eq!(doc["statements"].as_array().unwrap().len(), 1);
}

#[test]
fn scan_json_vex_verify_failure_is_error() {
    // Verify mode (default), no installed packages → every manifest entry
    // fails verification → no statements → fail-the-command.
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();

    let mut manifest = PatchManifest::new();
    manifest.patches.insert(
        "pkg:npm/vuln-pkg@1.0.0".to_string(),
        make_record(
            "11111111-1111-4111-8111-111111111111",
            "package/index.js",
            &"a".repeat(64),
            &"b".repeat(64),
            "GHSA-aaaa-bbbb-cccc",
            &["CVE-2024-0001"],
        ),
    );
    write_manifest(cwd, &manifest);
    let vex_path = cwd.join("scan.vex.json");

    let out = Command::new(binary())
        .args([
            "scan",
            "--cwd",
            cwd.to_str().unwrap(),
            "--json",
            "--vex",
            vex_path.to_str().unwrap(),
            "--vex-product",
            "pkg:npm/my-app@1.0.0",
        ])
        .output()
        .expect("invoke scan");
    assert!(!out.status.success(), "VEX verify failure must be non-zero");

    let result: Value = serde_json::from_slice(&out.stdout).expect("scan JSON");
    assert_eq!(result["status"], "error");
    assert_eq!(result["error"]["code"], "no_applicable_patches");
    assert!(!vex_path.exists());
}
