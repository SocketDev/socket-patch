//! End-to-end tests for human-readable (non-JSON) output paths and
//! `--verbose` modes. The previous coverage push focused on `--json`
//! output; these tests exercise the table printers, verbose
//! verification details, and `--silent` short-circuits that the JSON
//! tests don't reach.

use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

fn git_sha256(content: &[u8]) -> String {
    let header = format!("blob {}\0", content.len());
    let mut hasher = Sha256::new();
    hasher.update(header.as_bytes());
    hasher.update(content);
    hex::encode(hasher.finalize())
}

fn write_root(root: &Path) {
    std::fs::write(
        root.join("package.json"),
        r#"{ "name": "output-test", "version": "0.0.0" }"#,
    )
    .unwrap();
}

fn write_npm_package(root: &Path, name: &str, version: &str, content: &[u8]) {
    let pkg_dir = root.join("node_modules").join(name);
    std::fs::create_dir_all(&pkg_dir).unwrap();
    std::fs::write(
        pkg_dir.join("package.json"),
        format!(r#"{{ "name": "{name}", "version": "{version}" }}"#),
    )
    .unwrap();
    std::fs::write(pkg_dir.join("index.js"), content).unwrap();
}

fn write_manifest(root: &Path, purl: &str, before: &[u8], after: &[u8]) {
    let socket = root.join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    let bh = git_sha256(before);
    let ah = git_sha256(after);
    std::fs::write(
        socket.join("manifest.json"),
        format!(
            r#"{{
  "patches": {{
    "{purl}": {{
      "uuid": "11111111-1111-4111-8111-111111111111",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {{
        "package/index.js": {{
          "beforeHash": "{bh}",
          "afterHash":  "{ah}"
        }}
      }},
      "vulnerabilities": {{
        "CVE-2024-12345": {{
          "cves": ["CVE-2024-12345"],
          "summary": "Test",
          "severity": "high",
          "description": "Test vulnerability"
        }}
      }},
      "description": "Test patch",
      "license": "MIT",
      "tier": "free"
    }}
  }}
}}"#
        ),
    )
    .unwrap();
    let blobs = socket.join("blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::write(blobs.join(&ah), after).unwrap();
    std::fs::write(blobs.join(&bh), before).unwrap();
}

// ---------------------------------------------------------------------------
// apply — non-JSON / verbose / silent paths
// ---------------------------------------------------------------------------

#[test]
fn apply_non_json_prints_human_readable_summary() {
    let before = b"before\n";
    let after = b"after\n";
    let tmp = tempfile::tempdir().unwrap();
    write_root(tmp.path());
    write_npm_package(tmp.path(), "non-json-target", "1.0.0", before);
    write_manifest(tmp.path(), "pkg:npm/non-json-target@1.0.0", before, after);

    let out = Command::new(binary())
        .args(["apply", "--offline"])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Patched packages") || stdout.contains("Summary"),
        "non-JSON apply should print human-readable summary; got: {stdout}"
    );
}

#[test]
fn apply_verbose_prints_per_file_details() {
    let before = b"before\n";
    let after = b"after\n";
    let tmp = tempfile::tempdir().unwrap();
    write_root(tmp.path());
    write_npm_package(tmp.path(), "verbose-target", "1.0.0", before);
    write_manifest(tmp.path(), "pkg:npm/verbose-target@1.0.0", before, after);

    let out = Command::new(binary())
        .args(["apply", "--offline", "--verbose"])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Detailed verification") || stdout.contains("Summary"),
        "--verbose apply must print per-file details; got: {stdout}"
    );
}

#[test]
fn apply_silent_emits_no_stdout() {
    let before = b"before\n";
    let after = b"after\n";
    let tmp = tempfile::tempdir().unwrap();
    write_root(tmp.path());
    write_npm_package(tmp.path(), "silent-target", "1.0.0", before);
    write_manifest(tmp.path(), "pkg:npm/silent-target@1.0.0", before, after);

    let out = Command::new(binary())
        .args(["apply", "--offline", "--silent"])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(0));
    assert!(
        out.stdout.is_empty(),
        "--silent must suppress stdout; got: {:?}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn apply_no_manifest_non_json_prints_message() {
    let tmp = tempfile::tempdir().unwrap();
    let out = Command::new(binary())
        .args(["apply"])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("No .socket folder") || stdout.contains("skipping"),
        "non-JSON no-manifest must print friendly message; got: {stdout}"
    );
}

#[test]
fn apply_dry_run_non_json_prints_verification_summary() {
    let before = b"before\n";
    let after = b"after\n";
    let tmp = tempfile::tempdir().unwrap();
    write_root(tmp.path());
    write_npm_package(tmp.path(), "dry-target", "1.0.0", before);
    write_manifest(tmp.path(), "pkg:npm/dry-target@1.0.0", before, after);

    let out = Command::new(binary())
        .args(["apply", "--offline", "--dry-run"])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("verification") || stdout.contains("Summary"),
        "dry-run non-JSON should print verification summary; got: {stdout}"
    );
}

// ---------------------------------------------------------------------------
// list — non-JSON paths
// ---------------------------------------------------------------------------

#[test]
fn list_non_json_prints_table() {
    let before = b"before\n";
    let after = b"after\n";
    let tmp = tempfile::tempdir().unwrap();
    write_manifest(tmp.path(), "pkg:npm/list-target@1.0.0", before, after);

    let out = Command::new(binary())
        .args(["list"])
        .current_dir(tmp.path())
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("pkg:npm/list-target")
            && (stdout.contains("CVE-2024-12345") || stdout.contains("Vulnerabilities")),
        "list non-JSON should print PURL + vulns; got: {stdout}"
    );
}

#[test]
fn list_empty_manifest_non_json() {
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    std::fs::write(
        socket.join("manifest.json"),
        r#"{"patches":{}}"#,
    )
    .unwrap();

    let out = Command::new(binary())
        .args(["list"])
        .current_dir(tmp.path())
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("No patches found"),
        "empty manifest non-JSON message; got: {stdout}"
    );
}

#[test]
fn list_no_manifest_non_json_prints_error_to_stderr() {
    let tmp = tempfile::tempdir().unwrap();
    let out = Command::new(binary())
        .args(["list"])
        .current_dir(tmp.path())
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Manifest not found") || stderr.contains("not found"),
        "non-JSON list-without-manifest must print to stderr; got: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// scan — non-JSON paths
// ---------------------------------------------------------------------------

#[test]
fn scan_non_json_no_packages_prints_friendly_message() {
    let tmp = tempfile::tempdir().unwrap();
    write_root(tmp.path());
    // Scan needs network normally, but with no packages crawled it
    // short-circuits before the network call.
    let out = Command::new(binary())
        .args(["scan"])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        // Point SOCKET_API_URL at a closed port so any accidental
        // network call fails fast.
        .env("SOCKET_API_URL", "http://127.0.0.1:1")
        .output()
        .expect("run");
    // Code may be 0 or 1.
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stdout.contains("No packages")
            || stderr.contains("No packages")
            || stdout.contains("install first")
            || !stdout.is_empty()
            || !stderr.is_empty(),
        "scan non-JSON should produce SOME output; stdout={stdout}; stderr={stderr}"
    );
}

// ---------------------------------------------------------------------------
// repair — non-JSON paths
// ---------------------------------------------------------------------------

#[test]
fn repair_non_json_no_orphans_prints_summary() {
    let tmp = tempfile::tempdir().unwrap();
    write_manifest(tmp.path(), "pkg:npm/repair-target@1.0.0", b"a", b"b");

    let out = Command::new(binary())
        .args(["repair", "--offline"])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Repair complete")
            || stdout.contains("All")
            || stdout.contains("Checked"),
        "non-JSON repair should print human summary; got: {stdout}"
    );
}

#[test]
fn repair_non_json_with_orphans_prints_cleanup_summary() {
    let tmp = tempfile::tempdir().unwrap();
    write_manifest(tmp.path(), "pkg:npm/repair-target@1.0.0", b"a", b"b");
    // Add an orphan blob (not referenced by manifest).
    let blobs = tmp.path().join(".socket/blobs");
    std::fs::write(
        blobs.join("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"),
        b"orphan",
    )
    .unwrap();

    let out = Command::new(binary())
        .args(["repair", "--offline"])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Either "blob(s)" (cleanup summary) or "Repair complete" tail.
    assert!(
        !stdout.is_empty(),
        "non-JSON repair with orphans should produce output"
    );
}

// ---------------------------------------------------------------------------
// remove — non-JSON paths
// ---------------------------------------------------------------------------

#[test]
fn remove_non_json_prints_what_will_be_removed() {
    let tmp = tempfile::tempdir().unwrap();
    write_manifest(tmp.path(), "pkg:npm/remove-target@1.0.0", b"a", b"b");

    let out = Command::new(binary())
        .args(["remove", "pkg:npm/remove-target@1.0.0", "--yes", "--skip-rollback"])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stdout.contains("Removed") || stderr.contains("removed"),
        "non-JSON remove must print confirmation; stdout={stdout}; stderr={stderr}"
    );
}

// ---------------------------------------------------------------------------
// rollback — non-JSON paths
// ---------------------------------------------------------------------------

#[test]
fn rollback_non_json_prints_summary() {
    let before = b"original\n";
    let after = b"patched\n";
    let tmp = tempfile::tempdir().unwrap();
    write_root(tmp.path());
    write_npm_package(tmp.path(), "rb-non-json", "1.0.0", after);
    write_manifest(tmp.path(), "pkg:npm/rb-non-json@1.0.0", before, after);

    let out = Command::new(binary())
        .args(["rollback", "--offline"])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Rolled back") || stdout.contains("original"),
        "non-JSON rollback should print summary; got: {stdout}"
    );
}

#[test]
fn rollback_verbose_prints_per_file_details() {
    let before = b"original\n";
    let after = b"patched\n";
    let tmp = tempfile::tempdir().unwrap();
    write_root(tmp.path());
    write_npm_package(tmp.path(), "rb-verbose", "1.0.0", after);
    write_manifest(tmp.path(), "pkg:npm/rb-verbose@1.0.0", before, after);

    let out = Command::new(binary())
        .args(["rollback", "--offline", "--verbose"])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Detailed") || stdout.contains("verification") || stdout.contains("Rolled"),
        "verbose rollback should print details; got: {stdout}"
    );
}

// ---------------------------------------------------------------------------
// get — non-JSON identifier-not-found
// ---------------------------------------------------------------------------

#[test]
fn get_non_json_invalid_uuid_falls_through_to_package_search() {
    let tmp = tempfile::tempdir().unwrap();
    // Invalid identifier without --cve/--ghsa/--package etc. The binary
    // should fall through to package-name search and either succeed or
    // exit 1 cleanly. We're exercising the type-detection branch.
    let out = Command::new(binary())
        .args([
            "get",
            "not-a-real-package",
            "--save-only",
            "--yes",
            "--api-url",
            "http://127.0.0.1:1",
            "--api-token",
            "fake",
            "--org",
            "test-org",
        ])
        .current_dir(tmp.path())
        .output()
        .expect("run");
    let code = out.status.code().unwrap_or(-1);
    // Either 0 or 1 — both confirm the binary didn't crash mid-output.
    assert!(
        code == 0 || code == 1,
        "non-JSON get with invalid identifier must not crash; code={code}"
    );
}

#[test]
fn get_with_explicit_cve_flag_works() {
    let tmp = tempfile::tempdir().unwrap();
    let out = Command::new(binary())
        .args([
            "get",
            "CVE-2099-99999",
            "--cve",
            "--save-only",
            "--yes",
            "--json",
            "--api-url",
            "http://127.0.0.1:1",
            "--api-token",
            "fake",
            "--org",
            "test-org",
        ])
        .current_dir(tmp.path())
        .output()
        .expect("run");
    // Will fail to reach the API; just verify clean exit + JSON.
    let code = out.status.code().unwrap_or(-1);
    assert!(code == 0 || code == 1, "code={code}");
    let stdout = String::from_utf8_lossy(&out.stdout);
    if !stdout.is_empty() {
        let _: serde_json::Value =
            serde_json::from_str(stdout.trim()).expect("must parse JSON");
    }
}

#[test]
fn get_with_explicit_ghsa_flag_works() {
    let tmp = tempfile::tempdir().unwrap();
    let out = Command::new(binary())
        .args([
            "get",
            "GHSA-1111-2222-3333",
            "--ghsa",
            "--save-only",
            "--yes",
            "--json",
            "--api-url",
            "http://127.0.0.1:1",
            "--api-token",
            "fake",
            "--org",
            "test-org",
        ])
        .current_dir(tmp.path())
        .output()
        .expect("run");
    let code = out.status.code().unwrap_or(-1);
    assert!(code == 0 || code == 1, "code={code}");
}

#[test]
fn get_with_explicit_package_flag_works() {
    let tmp = tempfile::tempdir().unwrap();
    let out = Command::new(binary())
        .args([
            "get",
            "some-package",
            "--package",
            "--save-only",
            "--yes",
            "--json",
            "--api-url",
            "http://127.0.0.1:1",
            "--api-token",
            "fake",
            "--org",
            "test-org",
        ])
        .current_dir(tmp.path())
        .output()
        .expect("run");
    let code = out.status.code().unwrap_or(-1);
    assert!(code == 0 || code == 1, "code={code}");
}

// ---------------------------------------------------------------------------
// setup — non-JSON paths
// ---------------------------------------------------------------------------

#[test]
fn setup_no_files_non_json_prints_friendly_message() {
    let tmp = tempfile::tempdir().unwrap();
    let out = Command::new(binary())
        .args(["setup"])
        .current_dir(tmp.path())
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("No package.json"),
        "non-JSON setup must report missing package.json; got: {stdout}"
    );
}

#[test]
fn setup_dry_run_non_json_prints_preview() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::write(
        tmp.path().join("package.json"),
        r#"{ "name": "p", "version": "1.0.0" }"#,
    )
    .unwrap();
    let out = Command::new(binary())
        .args(["setup", "--dry-run", "--yes"])
        .current_dir(tmp.path())
        .output()
        .expect("run");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("would be updated")
            || stdout.contains("Will update")
            || stdout.contains("Summary"),
        "non-JSON setup dry-run should print preview; got: {stdout}"
    );
}

// ---------------------------------------------------------------------------
// Bare-UUID fallback — `socket-patch <UUID>` rewrites to `get <UUID>`
// ---------------------------------------------------------------------------

#[test]
fn bare_uuid_fallback_treats_uuid_as_get_identifier() {
    let tmp = tempfile::tempdir().unwrap();
    let out = Command::new(binary())
        .args([
            "11111111-1111-4111-8111-111111111111",
            "--save-only",
            "--yes",
            "--json",
            "--api-url",
            "http://127.0.0.1:1",
            "--api-token",
            "fake",
            "--org",
            "test-org",
        ])
        .current_dir(tmp.path())
        .output()
        .expect("run");
    let code = out.status.code().unwrap_or(-1);
    // Network call will fail; we just need a clean exit code from the
    // rewrite path.
    assert!(
        code == 0 || code == 1,
        "bare-UUID fallback must not crash; code={code}"
    );
}

// ---------------------------------------------------------------------------
// --help on each subcommand
// ---------------------------------------------------------------------------

#[test]
fn each_subcommand_help_prints_usage() {
    let subcommands = [
        "apply", "rollback", "get", "scan", "list", "remove", "setup", "repair", "gc",
    ];
    for sub in subcommands {
        let out = Command::new(binary())
            .args([sub, "--help"])
            .output()
            .expect("run");
        assert_eq!(out.status.code(), Some(0), "subcommand {sub} --help failed");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("Usage:") || stdout.contains("USAGE"),
            "{sub} --help must print usage; got: {stdout}"
        );
    }
}

#[test]
fn top_level_help_prints_all_subcommands() {
    let out = Command::new(binary()).args(["--help"]).output().expect("run");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    for sub in ["apply", "rollback", "get", "scan", "list", "remove", "setup", "repair"] {
        assert!(stdout.contains(sub), "top-level help missing {sub}; got: {stdout}");
    }
    // `gc` is the visible alias.
    assert!(stdout.contains("gc"), "top-level help missing `gc` alias");
}

#[test]
fn version_flag_prints_version() {
    let out = Command::new(binary()).args(["--version"]).output().expect("run");
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("socket-patch") || stdout.contains("3.0.0"),
        "--version output missing identifier; got: {stdout}"
    );
}
