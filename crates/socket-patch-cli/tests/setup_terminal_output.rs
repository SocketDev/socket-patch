//! Terminal-output contract for `setup` / `setup --check` / `setup --remove`:
//! the advice a human gets, which stream it lands on, and the preview
//! layout. Host-only fixtures (no toolchains), hermetic runner.

#[path = "common/mod.rs"]
mod common;

use std::collections::HashMap;
use std::path::Path;

use socket_patch_core::manifest::schema::{
    PatchFileInfo, PatchManifest, PatchRecord, VulnerabilityInfo,
};

const WIRED_PACKAGE_JSON: &str = "{\"name\":\"root\",\"version\":\"1.0.0\",\"scripts\":{\"postinstall\":\"npx @socketsecurity/socket-patch apply --silent --ecosystems npm\",\"dependencies\":\"npx @socketsecurity/socket-patch apply --silent --ecosystems npm\"}}";

fn write(path: &Path, content: &str) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, content).unwrap();
}

fn run(cwd: &Path, args: &[&str]) -> (i32, String, String) {
    common::run_with_env(cwd, args, &[("SOCKET_TELEMETRY_DISABLED", "1")])
}

/// Hooks wired, but the installed minimist file matches neither hash.
fn drifted_patch_fixture(cwd: &Path) {
    write(&cwd.join("package.json"), WIRED_PACKAGE_JSON);
    let pkg = cwd.join("node_modules/minimist");
    write(
        &pkg.join("package.json"),
        r#"{"name":"minimist","version":"1.2.5"}"#,
    );
    write(&pkg.join("index.js"), "locally edited\n");
    let mut files = HashMap::new();
    files.insert(
        "package/index.js".to_string(),
        PatchFileInfo {
            before_hash: "a".repeat(64),
            after_hash: "b".repeat(64),
        },
    );
    let mut vulns = HashMap::new();
    vulns.insert(
        "GHSA-xvch-5gv4-984h".to_string(),
        VulnerabilityInfo {
            cves: vec!["CVE-2021-44906".to_string()],
            summary: "s".to_string(),
            severity: "critical".to_string(),
            description: "d".to_string(),
        },
    );
    let mut m = PatchManifest::new();
    m.patches.insert(
        "pkg:npm/minimist@1.2.5".to_string(),
        PatchRecord {
            uuid: "11111111-1111-4111-8111-111111111111".to_string(),
            exported_at: "2024-01-01T00:00:00Z".to_string(),
            files,
            vulnerabilities: vulns,
            description: "p".to_string(),
            license: "MIT".to_string(),
            tier: "free".to_string(),
        },
    );
    write(
        &cwd.join(".socket/manifest.json"),
        &serde_json::to_string_pretty(&m).unwrap(),
    );
}

#[test]
fn check_drifted_patch_points_at_apply_not_setup() {
    let tmp = tempfile::tempdir().unwrap();
    drifted_patch_fixture(tmp.path());

    let (code, stdout, stderr) = run(tmp.path(), &["setup", "--check"]);
    assert_eq!(code, 1, "stdout=\n{stdout}\nstderr=\n{stderr}");
    assert!(
        stdout.contains("  ✓ package.json (configured)"),
        "stdout=\n{stdout}"
    );
    assert!(
        stdout.contains("  ✗ pkg:npm/minimist@1.2.5: patch not applied on disk (hash_mismatch)"),
        "stdout=\n{stdout}"
    );
    assert!(
        stdout.trim_end().ends_with(
            "1 patch is not applied on disk. Run `socket-patch apply` to re-apply the patches."
        ),
        "stdout=\n{stdout}"
    );
    assert!(
        !stdout.contains("socket-patch setup` to"),
        "setup cannot fix drift; stdout=\n{stdout}"
    );
    assert!(!stdout.contains("(s)"), "stdout=\n{stdout}");
    // The progress line is stderr chrome.
    assert!(
        stderr.contains("Searching for package.json"),
        "stderr=\n{stderr}"
    );
    assert!(!stdout.contains("Searching for"), "stdout=\n{stdout}");
}

#[test]
fn check_invalid_json_keeps_parser_detail_and_advice() {
    let tmp = tempfile::tempdir().unwrap();
    write(&tmp.path().join("package.json"), "{");
    let (code, stdout, _) = run(tmp.path(), &["setup", "--check"]);
    assert_eq!(code, 1, "stdout=\n{stdout}");
    assert!(
        stdout.contains("  ! package.json: Invalid package.json: EOF while parsing"),
        "stdout=\n{stdout}"
    );
    assert!(
        stdout
            .trim_end()
            .ends_with("1 error. Fix the errors above, then re-run `socket-patch setup --check`."),
        "stdout=\n{stdout}"
    );
}

#[test]
fn setup_preview_errors_name_the_file() {
    let tmp = tempfile::tempdir().unwrap();
    write(
        &tmp.path().join("package.json"),
        r#"{ "name": "root", "workspaces": ["packages/*"] }"#,
    );
    write(&tmp.path().join("packages/bad/package.json"), "{");
    let (code, stdout, _) = run(tmp.path(), &["setup", "--dry-run"]);
    assert_eq!(code, 1, "stdout=\n{stdout}");
    let norm = stdout.replace('\\', "/");
    assert!(
        norm.contains("\nErrors:\n  ! packages/bad/package.json: Invalid package.json: "),
        "stdout=\n{stdout}"
    );
    assert!(
        !stdout.contains("\n\n\n"),
        "no double blank lines: {stdout:?}"
    );

    let (_, _, stderr) = run(tmp.path(), &["setup", "--dry-run", "--silent"]);
    let norm = stderr.replace('\\', "/");
    assert!(
        norm.contains("Error: packages/bad/package.json: Invalid package.json: "),
        "stderr=\n{stderr}"
    );
}

#[test]
fn unsupported_ecosystem_filter_says_so() {
    let tmp = tempfile::tempdir().unwrap();
    write(&tmp.path().join("package.json"), WIRED_PACKAGE_JSON);
    for args in [
        &["setup", "-e", "cargo"][..],
        &["setup", "--check", "-e", "cargo"],
    ] {
        let (code, stdout, _) = run(tmp.path(), args);
        assert_eq!(code, 0, "{args:?}: stdout=\n{stdout}");
        assert_eq!(
            stdout.trim_end(),
            "Setup has no install hook for: cargo (supported: npm, pypi, gem, composer)",
            "{args:?}"
        );
    }
    let empty = tempfile::tempdir().unwrap();
    let (_, stdout, _) = run(empty.path(), &["setup", "-e", "npm"]);
    assert_eq!(stdout.trim_end(), "No package.json project found");
}

#[test]
fn unmatched_exclude_warns() {
    let tmp = tempfile::tempdir().unwrap();
    write(
        &tmp.path().join("package.json"),
        r#"{ "name": "root", "version": "1.0.0", "workspaces": ["packages/*"] }"#,
    );
    write(
        &tmp.path().join("packages/b/package.json"),
        r#"{ "name": "b", "version": "1.0.0" }"#,
    );
    let (code, _, stderr) = run(
        tmp.path(),
        &["setup", "--dry-run", "--exclude", "packages/b, nope"],
    );
    assert_eq!(code, 0, "stderr=\n{stderr}");
    assert!(
        stderr.contains("Warning: --exclude \"nope\" matched no workspace member"),
        "stderr=\n{stderr}"
    );
    assert!(
        !stderr.contains("\"packages/b\" matched"),
        "stderr=\n{stderr}"
    );

    let (_, _, stderr) = run(
        tmp.path(),
        &["setup", "--dry-run", "--silent", "--exclude", "nope"],
    );
    assert!(stderr.is_empty(), "--silent mutes warnings: {stderr}");
}

#[test]
fn already_configured_run_prints_one_verdict() {
    let tmp = tempfile::tempdir().unwrap();
    write(&tmp.path().join("package.json"), WIRED_PACKAGE_JSON);
    let (code, stdout, stderr) = run(tmp.path(), &["setup", "--yes"]);
    assert_eq!(code, 0);
    assert_eq!(
        stdout.trim(),
        "All install hooks are already configured with socket-patch!"
    );
    assert_eq!(stderr.trim(), "Configuring socket-patch install hooks...");
}

#[test]
fn remove_dry_run_layout() {
    let tmp = tempfile::tempdir().unwrap();
    write(&tmp.path().join("package.json"), WIRED_PACKAGE_JSON);
    let (code, stdout, _) = run(tmp.path(), &["setup", "--remove", "--dry-run"]);
    assert_eq!(code, 0, "stdout=\n{stdout}");
    assert!(
        !stdout.contains("\n\n\n"),
        "no double blank lines: {stdout:?}"
    );
    assert!(
        stdout.ends_with(
            "    -> dependencies: (removed)\n\nSummary (dry run):\n  1 item would have \
             socket-patch removed\n"
        ),
        "{stdout:?}"
    );
}
