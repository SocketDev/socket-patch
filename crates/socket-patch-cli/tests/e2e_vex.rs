//! End-to-end tests for the `socket-patch vex` subcommand.
//!
//! Validates the OpenVEX document shape produced by a real invocation
//! of the compiled binary. When `vexctl` is on `PATH` the test also
//! pipes the output through `vexctl validate` to confirm spec
//! conformance — the CI workflow installs vexctl before the test
//! step, so this branch is exercised in CI.
//!
//! Layered tests (no-network, no-disk-state required):
//!   1. `--no-verify` against a fixture manifest with multi-CVE vulns
//!   2. `--no-verify` with two patches sharing a GHSA (alias-merge path)
//!   3. error path: empty manifest exits non-zero with no doc
//!   4. verify-mode against patched files laid on disk
//!   5. verify-mode where one patch file is missing → omitted + warning

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

/// Write `manifest` to `<cwd>/.socket/manifest.json`.
fn write_manifest(cwd: &Path, manifest: &PatchManifest) {
    let dir = cwd.join(".socket");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("manifest.json"),
        serde_json::to_string_pretty(manifest).unwrap(),
    )
    .unwrap();
}

/// Patch record with one file (whose hashes you choose) and one
/// vulnerability.
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

// ──────────────────────────────────────────────────────────────────────
// no-verify path
// ──────────────────────────────────────────────────────────────────────

#[test]
fn no_verify_emits_valid_openvex() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();

    let mut manifest = PatchManifest::new();
    manifest.patches.insert(
        "pkg:npm/lodash@4.17.20".to_string(),
        make_record(
            "11111111-1111-4111-8111-111111111111",
            "package/index.js",
            "a".repeat(64).as_str(),
            "b".repeat(64).as_str(),
            "GHSA-aaaa-bbbb-cccc",
            &["CVE-2024-1111", "CVE-2024-1112"],
        ),
    );
    manifest.patches.insert(
        "pkg:npm/minimist@1.2.0".to_string(),
        make_record(
            "22222222-2222-4222-8222-222222222222",
            "package/index.js",
            "c".repeat(64).as_str(),
            "d".repeat(64).as_str(),
            "GHSA-dddd-eeee-ffff",
            &["CVE-2024-2222"],
        ),
    );
    write_manifest(cwd, &manifest);

    let out = Command::new(binary())
        .args([
            "vex",
            "--cwd",
            cwd.to_str().unwrap(),
            "--no-verify",
            "--product",
            "pkg:npm/test-app@1.0.0",
            "--doc-id",
            "urn:uuid:fixed-test-id",
        ])
        .output()
        .expect("invoke vex");
    assert!(
        out.status.success(),
        "vex exited non-zero. stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8(out.stdout).unwrap();
    let doc: Value = serde_json::from_str(&stdout)
        .expect("vex stdout must be valid JSON");

    assert_eq!(doc["@context"], "https://openvex.dev/ns/v0.2.0");
    assert_eq!(doc["@id"], "urn:uuid:fixed-test-id");
    assert_eq!(doc["author"], "Socket");
    assert_eq!(doc["version"], 1);
    assert!(doc["tooling"]
        .as_str()
        .unwrap()
        .starts_with("socket-patch "));

    let statements = doc["statements"].as_array().unwrap();
    assert_eq!(statements.len(), 2, "one statement per GHSA");

    // Statements are sorted by vuln id (BTreeMap order).
    let s0 = &statements[0];
    assert_eq!(s0["vulnerability"]["name"], "GHSA-aaaa-bbbb-cccc");
    let aliases = s0["vulnerability"]["aliases"].as_array().unwrap();
    assert_eq!(aliases.len(), 2);
    assert_eq!(aliases[0], "CVE-2024-1111");
    assert_eq!(aliases[1], "CVE-2024-1112");
    assert_eq!(s0["status"], "not_affected");
    assert_eq!(s0["justification"], "inline_mitigations_already_exist");

    let products = s0["products"].as_array().unwrap();
    assert_eq!(products.len(), 1);
    assert_eq!(products[0]["@id"], "pkg:npm/test-app@1.0.0");
    let subs = products[0]["subcomponents"].as_array().unwrap();
    assert_eq!(subs.len(), 1);
    assert_eq!(subs[0]["@id"], "pkg:npm/lodash@4.17.20");

    maybe_validate_with_vexctl(&stdout);
}

#[test]
fn two_patches_sharing_ghsa_merge_subcomponents() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();

    let mut manifest = PatchManifest::new();
    manifest.patches.insert(
        "pkg:npm/foo@1.0.0".to_string(),
        make_record(
            "11111111-1111-4111-8111-111111111111",
            "package/a.js",
            "a".repeat(64).as_str(),
            "b".repeat(64).as_str(),
            "GHSA-shared",
            &["CVE-SHARED"],
        ),
    );
    manifest.patches.insert(
        "pkg:npm/bar@2.0.0".to_string(),
        make_record(
            "22222222-2222-4222-8222-222222222222",
            "package/b.js",
            "c".repeat(64).as_str(),
            "d".repeat(64).as_str(),
            "GHSA-shared",
            &["CVE-SHARED"],
        ),
    );
    write_manifest(cwd, &manifest);

    let out = Command::new(binary())
        .args([
            "vex",
            "--cwd",
            cwd.to_str().unwrap(),
            "--no-verify",
            "--product",
            "pkg:npm/app@1.0.0",
        ])
        .output()
        .expect("invoke vex");
    assert!(out.status.success());

    let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
    let stmts = doc["statements"].as_array().unwrap();
    assert_eq!(stmts.len(), 1, "shared GHSA collapses into one statement");

    let subs = stmts[0]["products"][0]["subcomponents"].as_array().unwrap();
    assert_eq!(subs.len(), 2);
    let ids: Vec<&str> = subs.iter().map(|s| s["@id"].as_str().unwrap()).collect();
    assert!(ids.contains(&"pkg:npm/foo@1.0.0"));
    assert!(ids.contains(&"pkg:npm/bar@2.0.0"));
}

#[test]
fn empty_manifest_exits_non_zero_with_no_doc() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    write_manifest(cwd, &PatchManifest::new());

    let out = Command::new(binary())
        .args([
            "vex",
            "--cwd",
            cwd.to_str().unwrap(),
            "--no-verify",
            "--product",
            "pkg:npm/app@1.0.0",
        ])
        .output()
        .expect("invoke vex");
    assert!(!out.status.success(), "empty manifest must be non-zero exit");
    // Nothing on stdout — the VEX itself isn't written.
    assert!(
        out.stdout.is_empty(),
        "stdout should be empty when no doc is produced. got: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("Error"));
}

#[test]
fn missing_manifest_exits_non_zero() {
    let tmp = tempfile::tempdir().unwrap();
    let out = Command::new(binary())
        .args([
            "vex",
            "--cwd",
            tmp.path().to_str().unwrap(),
            "--no-verify",
            "--product",
            "pkg:npm/app@1.0.0",
        ])
        .output()
        .expect("invoke vex");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("Manifest not found"));
}

#[test]
fn json_envelope_requires_output() {
    let tmp = tempfile::tempdir().unwrap();
    write_manifest(tmp.path(), &PatchManifest::new());

    let out = Command::new(binary())
        .args([
            "vex",
            "--cwd",
            tmp.path().to_str().unwrap(),
            "--no-verify",
            "--json",
            "--product",
            "pkg:npm/app@1.0.0",
        ])
        .output()
        .expect("invoke vex");
    assert!(!out.status.success());
    // --json forces envelope-on-stdout, which we then assert lives in stdout.
    let stdout = String::from_utf8_lossy(&out.stdout);
    let env: Value = serde_json::from_str(&stdout).expect("envelope JSON");
    assert_eq!(env["status"], "error");
    assert_eq!(env["error"]["code"], "json_requires_output");
}

#[test]
fn json_envelope_with_output_emits_both() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();
    let mut manifest = PatchManifest::new();
    manifest.patches.insert(
        "pkg:npm/x@1.0.0".to_string(),
        make_record(
            "11111111-1111-4111-8111-111111111111",
            "package/index.js",
            "a".repeat(64).as_str(),
            "b".repeat(64).as_str(),
            "GHSA-zzzz",
            &["CVE-9999"],
        ),
    );
    write_manifest(cwd, &manifest);
    let vex_path = cwd.join("out.vex.json");

    let out = Command::new(binary())
        .args([
            "vex",
            "--cwd",
            cwd.to_str().unwrap(),
            "--no-verify",
            "--json",
            "--output",
            vex_path.to_str().unwrap(),
            "--product",
            "pkg:npm/app@1.0.0",
        ])
        .output()
        .expect("invoke vex");
    assert!(out.status.success());

    // Envelope on stdout.
    let env: Value = serde_json::from_slice(&out.stdout).expect("envelope JSON");
    assert_eq!(env["command"], "vex");
    assert_eq!(env["status"], "success");
    assert_eq!(env["summary"]["verified"], 1);

    // VEX doc at --output.
    let vex_text = std::fs::read_to_string(&vex_path).unwrap();
    let doc: Value = serde_json::from_str(&vex_text).unwrap();
    assert_eq!(doc["@context"], "https://openvex.dev/ns/v0.2.0");
    assert_eq!(doc["statements"].as_array().unwrap().len(), 1);

    maybe_validate_with_vexctl(&vex_text);
}

#[test]
fn auto_detect_uses_package_json() {
    // When --product is omitted the binary reads `package.json` for the
    // product PURL. We don't lay down node_modules so we pair this with
    // --no-verify.
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();

    std::fs::write(
        cwd.join("package.json"),
        r#"{"name":"my-app","version":"7.7.7"}"#,
    )
    .unwrap();

    let mut manifest = PatchManifest::new();
    manifest.patches.insert(
        "pkg:npm/x@1.0.0".to_string(),
        make_record(
            "11111111-1111-4111-8111-111111111111",
            "package/index.js",
            "a".repeat(64).as_str(),
            "b".repeat(64).as_str(),
            "GHSA-z",
            &["CVE-Z"],
        ),
    );
    write_manifest(cwd, &manifest);

    let out = Command::new(binary())
        .args([
            "vex",
            "--cwd",
            cwd.to_str().unwrap(),
            "--no-verify",
        ])
        .output()
        .expect("invoke vex");
    assert!(out.status.success());
    let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc["statements"][0]["products"][0]["@id"], "pkg:npm/my-app@7.7.7");
}

// ──────────────────────────────────────────────────────────────────────
// verify-mode tests — lay down patched files on disk and exercise the
// hash-check pipeline. We bypass ecosystem-crawler resolution by writing
// the manifest with PURLs whose npm package layout we control, then
// pointing --cwd at the synthetic node_modules.
// ──────────────────────────────────────────────────────────────────────

#[test]
fn verify_mode_includes_applied_omits_unapplied() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();

    // Two npm packages — one we'll lay down "patched", one we won't.
    let nm = cwd.join("node_modules");
    let applied_pkg = nm.join("applied-pkg");
    std::fs::create_dir_all(&applied_pkg).unwrap();
    std::fs::write(
        applied_pkg.join("package.json"),
        r#"{"name":"applied-pkg","version":"1.0.0"}"#,
    )
    .unwrap();
    let patched_content = b"patched index";
    let after_hash = compute_git_sha256_from_bytes(patched_content);
    std::fs::write(applied_pkg.join("index.js"), patched_content).unwrap();

    let unapplied_pkg = nm.join("unapplied-pkg");
    std::fs::create_dir_all(&unapplied_pkg).unwrap();
    std::fs::write(
        unapplied_pkg.join("package.json"),
        r#"{"name":"unapplied-pkg","version":"2.0.0"}"#,
    )
    .unwrap();
    // No matching file on disk → verify reports file_not_found.

    let mut manifest = PatchManifest::new();
    manifest.patches.insert(
        "pkg:npm/applied-pkg@1.0.0".to_string(),
        make_record(
            "11111111-1111-4111-8111-111111111111",
            "package/index.js",
            "a".repeat(64).as_str(),
            after_hash.as_str(),
            "GHSA-applied",
            &["CVE-APPLIED"],
        ),
    );
    manifest.patches.insert(
        "pkg:npm/unapplied-pkg@2.0.0".to_string(),
        make_record(
            "22222222-2222-4222-8222-222222222222",
            "package/missing.js",
            "c".repeat(64).as_str(),
            "d".repeat(64).as_str(),
            "GHSA-unapplied",
            &["CVE-UNAPPLIED"],
        ),
    );
    write_manifest(cwd, &manifest);

    let out = Command::new(binary())
        .args([
            "vex",
            "--cwd",
            cwd.to_str().unwrap(),
            "--product",
            "pkg:npm/test-app@1.0.0",
        ])
        .output()
        .expect("invoke vex");
    assert!(
        out.status.success(),
        "verify mode should succeed when at least one patch verifies. stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
    let stmts = doc["statements"].as_array().unwrap();
    assert_eq!(stmts.len(), 1, "only the verified patch should appear");
    assert_eq!(stmts[0]["vulnerability"]["name"], "GHSA-applied");

    // Warning surfaced on stderr.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("unapplied-pkg") && stderr.contains("omitting"),
        "stderr should warn about omitted patch. got: {stderr}"
    );

    maybe_validate_with_vexctl(&String::from_utf8_lossy(&out.stdout));
}

#[test]
fn verify_mode_all_failed_exits_non_zero() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path();

    let mut manifest = PatchManifest::new();
    manifest.patches.insert(
        "pkg:npm/ghost@1.0.0".to_string(),
        make_record(
            "11111111-1111-4111-8111-111111111111",
            "package/index.js",
            "a".repeat(64).as_str(),
            "b".repeat(64).as_str(),
            "GHSA-ghost",
            &["CVE-GHOST"],
        ),
    );
    write_manifest(cwd, &manifest);

    // No node_modules, no package directory — ecosystem dispatch returns
    // empty map, every patch lands in `failed` → no statements → exit 1.
    let out = Command::new(binary())
        .args([
            "vex",
            "--cwd",
            cwd.to_str().unwrap(),
            "--product",
            "pkg:npm/app@1.0.0",
        ])
        .output()
        .expect("invoke vex");
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("No applied patches"));
}

// ──────────────────────────────────────────────────────────────────────
// vexctl integration (run only when the binary is on PATH)
// ──────────────────────────────────────────────────────────────────────

/// Pipe the VEX text through `vexctl` if it's on `PATH`. CI installs
/// vexctl before the test step so the validation actually runs there;
/// local devs without Go see a skip message instead of a failure.
///
/// `vexctl inspect <file>` exits 0 when the JSON parses as an OpenVEX
/// document and 1 otherwise — that's the canonical schema gate.
fn maybe_validate_with_vexctl(vex_text: &str) {
    let Some(vexctl) = find_vexctl_on_path() else {
        eprintln!("(skipping vexctl validation — binary not on PATH)");
        return;
    };
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), vex_text).unwrap();

    let out = Command::new(&vexctl)
        .args(["inspect", tmp.path().to_str().unwrap()])
        .output()
        .expect("spawn vexctl");
    assert!(
        out.status.success(),
        "vexctl rejected the document.\nstderr:\n{}\nstdout:\n{}",
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
}

/// Stdlib-only `PATH` lookup for `vexctl`. Returns `None` if missing.
fn find_vexctl_on_path() -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    for entry in std::env::split_paths(&path) {
        let candidate = entry.join("vexctl");
        if candidate.is_file() {
            return Some(candidate);
        }
        let with_exe = entry.join("vexctl.exe");
        if with_exe.is_file() {
            return Some(with_exe);
        }
    }
    None
}
