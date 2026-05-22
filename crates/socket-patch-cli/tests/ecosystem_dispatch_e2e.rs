//! End-to-end tests that exercise every ecosystem dispatch branch in
//! `ecosystem_dispatch::find_packages_for_purls` and
//! `find_packages_for_rollback`. Each ecosystem has a separate code
//! branch in those functions; this file ensures every branch executes
//! at least once.
//!
//! The tests run `apply --offline --ecosystems <X>` against a manifest
//! containing a PURL for that ecosystem. Even when the crawler finds
//! no installed packages, the dispatch + crawler-init code runs — that
//! covers the branch.
//!
//! Feature-gated ecosystems (cargo/golang/maven/composer/nuget) are
//! `#[cfg(feature = "X")]`-gated so they only run with `--all-features`.

use std::path::{Path, PathBuf};
use std::process::Command;

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

fn write_root_package_json(root: &Path) {
    std::fs::write(
        root.join("package.json"),
        r#"{ "name": "ecosystem-dispatch-test", "version": "0.0.0" }"#,
    )
    .unwrap();
}

/// Write a minimal manifest with one patch for the given PURL.
fn write_manifest(root: &Path, purl: &str) {
    let socket = root.join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    let body = format!(
        r#"{{
  "patches": {{
    "{purl}": {{
      "uuid": "11111111-1111-4111-8111-111111111111",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {{}},
      "vulnerabilities": {{}},
      "description": "dispatch test",
      "license": "MIT",
      "tier": "free"
    }}
  }}
}}"#
    );
    std::fs::write(socket.join("manifest.json"), body).unwrap();
}

/// Run `socket-patch apply --offline --json --ecosystems <eco>` and
/// return the exit code + stdout. Either 0 or 1 is acceptable — both
/// mean the dispatch branch ran without panicking. We only fail the
/// test on a crash (exit code other than 0 or 1).
fn run_apply_for_ecosystem(cwd: &Path, ecosystem: &str) -> (i32, String) {
    let out = Command::new(binary())
        .args([
            "apply",
            "--offline",
            "--json",
            "--ecosystems",
            ecosystem,
            "--silent",
        ])
        .current_dir(cwd)
        .env_remove("SOCKET_API_TOKEN")
        .output()
        .expect("run socket-patch");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
    )
}

fn assert_dispatched(code: i32, stdout: &str, ecosystem: &str) {
    assert!(
        code == 0 || code == 1,
        "apply --ecosystems={ecosystem} must not crash; got code {code}; stdout={stdout}"
    );
    // The envelope must be parseable, confirming the binary completed
    // a normal control-flow path rather than crashing mid-output.
    let _: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("envelope JSON must parse");
}

// ---------------------------------------------------------------------------
// Default-feature ecosystems: npm, pypi, gem
// ---------------------------------------------------------------------------

#[test]
fn dispatch_branch_npm() {
    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    write_manifest(tmp.path(), "pkg:npm/__dispatch_test__@1.0.0");
    let (code, stdout) = run_apply_for_ecosystem(tmp.path(), "npm");
    assert_dispatched(code, &stdout, "npm");
}

#[test]
fn dispatch_branch_pypi() {
    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    write_manifest(tmp.path(), "pkg:pypi/__dispatch_test__@1.0.0");
    let (code, stdout) = run_apply_for_ecosystem(tmp.path(), "pypi");
    assert_dispatched(code, &stdout, "pypi");
}

#[test]
fn dispatch_branch_gem() {
    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    write_manifest(tmp.path(), "pkg:gem/__dispatch_test__@1.0.0");
    let (code, stdout) = run_apply_for_ecosystem(tmp.path(), "gem");
    assert_dispatched(code, &stdout, "gem");
}

// ---------------------------------------------------------------------------
// Feature-gated ecosystems
// ---------------------------------------------------------------------------

#[cfg(feature = "cargo")]
#[test]
fn dispatch_branch_cargo() {
    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    write_manifest(tmp.path(), "pkg:cargo/__dispatch_test__@1.0.0");
    let (code, stdout) = run_apply_for_ecosystem(tmp.path(), "cargo");
    assert_dispatched(code, &stdout, "cargo");
}

#[cfg(feature = "golang")]
#[test]
fn dispatch_branch_golang() {
    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    write_manifest(tmp.path(), "pkg:golang/example.com/foo@v1.0.0");
    let (code, stdout) = run_apply_for_ecosystem(tmp.path(), "golang");
    assert_dispatched(code, &stdout, "golang");
}

#[cfg(feature = "maven")]
#[test]
fn dispatch_branch_maven() {
    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    write_manifest(tmp.path(), "pkg:maven/org.example/foo@1.0.0");
    let (code, stdout) = run_apply_for_ecosystem(tmp.path(), "maven");
    assert_dispatched(code, &stdout, "maven");
}

#[cfg(feature = "composer")]
#[test]
fn dispatch_branch_composer() {
    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    write_manifest(tmp.path(), "pkg:composer/example/foo@1.0.0");
    let (code, stdout) = run_apply_for_ecosystem(tmp.path(), "composer");
    assert_dispatched(code, &stdout, "composer");
}

#[cfg(feature = "nuget")]
#[test]
fn dispatch_branch_nuget() {
    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    write_manifest(tmp.path(), "pkg:nuget/Foo@1.0.0");
    let (code, stdout) = run_apply_for_ecosystem(tmp.path(), "nuget");
    assert_dispatched(code, &stdout, "nuget");
}

// ---------------------------------------------------------------------------
// All ecosystems at once (with --offline so no actual fetch happens)
// ---------------------------------------------------------------------------

#[test]
fn dispatch_multi_ecosystem_csv() {
    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    std::fs::write(
        socket.join("manifest.json"),
        r#"{
  "patches": {
    "pkg:npm/__a__@1.0.0": {
      "uuid": "11111111-1111-4111-8111-111111111111",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {}, "vulnerabilities": {},
      "description": "a", "license": "MIT", "tier": "free"
    },
    "pkg:pypi/__b__@1.0.0": {
      "uuid": "22222222-2222-4222-8222-222222222222",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {}, "vulnerabilities": {},
      "description": "b", "license": "MIT", "tier": "free"
    },
    "pkg:gem/__c__@1.0.0": {
      "uuid": "33333333-3333-4333-8333-333333333333",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {}, "vulnerabilities": {},
      "description": "c", "license": "MIT", "tier": "free"
    }
  }
}"#,
    )
    .unwrap();

    let (code, stdout) = run_apply_for_ecosystem(tmp.path(), "npm,pypi,gem");
    assert_dispatched(code, &stdout, "npm,pypi,gem");
}

// ---------------------------------------------------------------------------
// Rollback dispatch branches — find_packages_for_rollback is a separate
// function and needs its own coverage.
// ---------------------------------------------------------------------------

fn write_manifest_with_blob(root: &Path, purl: &str) -> String {
    use sha2::{Digest, Sha256};
    let before = b"original\n";
    let header = format!("blob {}\0", before.len());
    let mut hasher = Sha256::new();
    hasher.update(header.as_bytes());
    hasher.update(before);
    let before_hash = hex::encode(hasher.finalize());

    let after_hash =
        "1111111111111111111111111111111111111111111111111111111111111111".to_string();
    let socket = root.join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    let body = format!(
        r#"{{
  "patches": {{
    "{purl}": {{
      "uuid": "44444444-4444-4444-8444-444444444444",
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
    std::fs::write(socket.join("manifest.json"), body).unwrap();
    // Stage the BEFORE blob so rollback's offline guard doesn't trip.
    let blobs = socket.join("blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::write(blobs.join(&before_hash), before).unwrap();
    before_hash
}

fn run_rollback_for_ecosystem(cwd: &Path, ecosystem: &str) -> (i32, String) {
    let out = Command::new(binary())
        .args([
            "rollback",
            "--offline",
            "--json",
            "--ecosystems",
            ecosystem,
            "--silent",
        ])
        .current_dir(cwd)
        .env_remove("SOCKET_API_TOKEN")
        .output()
        .expect("run socket-patch");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
    )
}

#[test]
fn rollback_dispatch_branch_npm() {
    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    write_manifest_with_blob(tmp.path(), "pkg:npm/__rollback_dispatch__@1.0.0");
    let (code, stdout) = run_rollback_for_ecosystem(tmp.path(), "npm");
    assert!(
        code == 0 || code == 1,
        "rollback npm dispatch must not crash; stdout={stdout}"
    );
}

#[test]
fn rollback_dispatch_branch_pypi() {
    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    write_manifest_with_blob(tmp.path(), "pkg:pypi/__rollback_dispatch__@1.0.0");
    let (code, stdout) = run_rollback_for_ecosystem(tmp.path(), "pypi");
    assert!(
        code == 0 || code == 1,
        "rollback pypi dispatch must not crash; stdout={stdout}"
    );
}

#[test]
fn rollback_dispatch_branch_gem() {
    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    write_manifest_with_blob(tmp.path(), "pkg:gem/__rollback_dispatch__@1.0.0");
    let (code, stdout) = run_rollback_for_ecosystem(tmp.path(), "gem");
    assert!(
        code == 0 || code == 1,
        "rollback gem dispatch must not crash; stdout={stdout}"
    );
}

#[cfg(feature = "cargo")]
#[test]
fn rollback_dispatch_branch_cargo() {
    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    write_manifest_with_blob(tmp.path(), "pkg:cargo/__rollback_dispatch__@1.0.0");
    let (code, stdout) = run_rollback_for_ecosystem(tmp.path(), "cargo");
    assert!(code == 0 || code == 1, "stdout={stdout}");
}

#[cfg(feature = "golang")]
#[test]
fn rollback_dispatch_branch_golang() {
    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    write_manifest_with_blob(tmp.path(), "pkg:golang/example.com/foo@v1.0.0");
    let (code, stdout) = run_rollback_for_ecosystem(tmp.path(), "golang");
    assert!(code == 0 || code == 1, "stdout={stdout}");
}

#[cfg(feature = "maven")]
#[test]
fn rollback_dispatch_branch_maven() {
    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    write_manifest_with_blob(tmp.path(), "pkg:maven/org.example/foo@1.0.0");
    let (code, stdout) = run_rollback_for_ecosystem(tmp.path(), "maven");
    assert!(code == 0 || code == 1, "stdout={stdout}");
}

#[cfg(feature = "composer")]
#[test]
fn rollback_dispatch_branch_composer() {
    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    write_manifest_with_blob(tmp.path(), "pkg:composer/example/foo@1.0.0");
    let (code, stdout) = run_rollback_for_ecosystem(tmp.path(), "composer");
    assert!(code == 0 || code == 1, "stdout={stdout}");
}

#[cfg(feature = "nuget")]
#[test]
fn rollback_dispatch_branch_nuget() {
    let tmp = tempfile::tempdir().unwrap();
    write_root_package_json(tmp.path());
    write_manifest_with_blob(tmp.path(), "pkg:nuget/Foo@1.0.0");
    let (code, stdout) = run_rollback_for_ecosystem(tmp.path(), "nuget");
    assert!(code == 0 || code == 1, "stdout={stdout}");
}
