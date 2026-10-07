//! `apply --check` verifies every manifest patch, not only Go redirects.
//!
//! Before, `--check` audited the committed Go `replace`-redirects and
//! nothing else, so on an npm (or any non-Go) agent project whose installed
//! files were unpatched it printed "No Go patch redirects to check." and
//! exited 0 — a permanent false green for the obvious "are we patched?" CI
//! gate (audit B27). It now runs the `vex` verifier over every installed
//! copy of each in-scope, non-vendored manifest patch.

use std::path::Path;

use serde_json::{json, Value};

use crate::common;
use common::{git_sha256, parse_json_envelope, run_with_env};

const PURL: &str = "pkg:npm/check-target@1.0.0";
const ORIGINAL: &[u8] = b"module.exports = 'vulnerable';\n";
const PATCHED: &[u8] = b"module.exports = 'patched';\n";

fn run_check(cwd: &Path, extra: &[&str]) -> (i32, String, String) {
    let mut argv = vec!["apply", "--check", "--offline"];
    argv.extend_from_slice(extra);
    run_with_env(cwd, &argv, &[("SOCKET_TELEMETRY_DISABLED", "1")])
}

/// An npm agent project: `.socket/manifest.json` patching
/// `node_modules/check-target/index.js` from [`ORIGINAL`] to [`PATCHED`];
/// the installed copy holds `installed` (`None`: not installed).
fn project(installed: Option<&[u8]>) -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    std::fs::write(
        root.join("package.json"),
        r#"{ "name": "check-root", "version": "0.0.0" }"#,
    )
    .unwrap();
    std::fs::create_dir_all(root.join(".socket")).unwrap();
    let manifest = json!({ "patches": { PURL: {
        "uuid": "27272727-2727-4272-8272-272727272727",
        "exportedAt": "2024-01-01T00:00:00Z",
        "files": { "index.js": {
            "beforeHash": git_sha256(ORIGINAL),
            "afterHash": git_sha256(PATCHED),
        }},
        "vulnerabilities": {},
        "description": "apply --check fixture",
        "license": "MIT",
        "tier": "free",
    }}});
    std::fs::write(
        root.join(".socket/manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    if let Some(bytes) = installed {
        let pkg = root.join("node_modules/check-target");
        std::fs::create_dir_all(&pkg).unwrap();
        std::fs::write(
            pkg.join("package.json"),
            r#"{ "name": "check-target", "version": "1.0.0" }"#,
        )
        .unwrap();
        std::fs::write(pkg.join("index.js"), bytes).unwrap();
    }
    tmp
}

fn events(env: &Value) -> Vec<Value> {
    env["events"].as_array().cloned().unwrap_or_default()
}

/// The regression: an unpatched installed copy is drift (exit 1), in both
/// output modes, and `--check` writes nothing.
#[test]
fn check_fails_on_an_unpatched_npm_package() {
    let tmp = project(Some(ORIGINAL));
    let index = tmp.path().join("node_modules/check-target/index.js");

    let (code, stdout, stderr) = run_check(tmp.path(), &[]);
    assert_eq!(
        code, 1,
        "an unpatched tree is drift\nstdout={stdout}\nstderr={stderr}"
    );
    assert!(stderr.contains("OUT OF SYNC"), "{stderr}");
    assert!(
        stderr.contains(&format!("{PURL}: patch not applied")),
        "the drift names the package: {stderr}"
    );
    assert_eq!(
        std::fs::read(&index).unwrap(),
        ORIGINAL,
        "--check never writes"
    );

    let (code, stdout, stderr) = run_check(tmp.path(), &["--json"]);
    assert_eq!(code, 1, "stderr={stderr}");
    let env = parse_json_envelope(stdout.trim());
    assert_eq!(env["status"], "partialFailure", "{env}");
    let failed: Vec<Value> = events(&env)
        .into_iter()
        .filter(|e| e["action"] == "failed")
        .collect();
    assert_eq!(failed.len(), 1, "{env}");
    assert_eq!(failed[0]["purl"], PURL, "{env}");
    assert_eq!(failed[0]["errorCode"], "not_applied", "{env}");
}

/// Bytes that match neither hash are drift too (`apply` would overwrite
/// them), with their own code.
#[test]
fn check_fails_on_a_tampered_npm_package() {
    let tmp = project(Some(b"something else entirely\n"));
    let (code, stdout, stderr) = run_check(tmp.path(), &["--json"]);
    assert_eq!(code, 1, "stderr={stderr}");
    let env = parse_json_envelope(stdout.trim());
    assert!(
        events(&env)
            .iter()
            .any(|e| e["action"] == "failed" && e["errorCode"] == "hash_mismatch"),
        "{env}"
    );
}

/// A record with an empty `files` map offers nothing to hash, so an
/// installed copy of it is drift (`no_files`), never `already_patched`:
/// `apply` and `get` count such a record as failed, and `--check` exit 0
/// is the remediation attestation.
#[test]
fn check_fails_on_a_zero_file_record() {
    let tmp = project(Some(ORIGINAL));
    let path = tmp.path().join(".socket/manifest.json");
    let mut manifest: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    manifest["patches"][PURL]["files"] = json!({});
    std::fs::write(&path, serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();

    let (code, stdout, stderr) = run_check(tmp.path(), &["--json"]);
    assert_eq!(code, 1, "stdout={stdout}\nstderr={stderr}");
    let env = parse_json_envelope(stdout.trim());
    let evs = events(&env);
    assert!(
        evs.iter()
            .any(|e| e["action"] == "failed" && e["purl"] == PURL && e["errorCode"] == "no_files"),
        "{env}"
    );
    assert!(
        !evs.iter().any(|e| e["errorCode"] == "already_patched"),
        "{env}"
    );

    let (code, _stdout, stderr) = run_check(tmp.path(), &[]);
    assert_eq!(code, 1, "{stderr}");
    assert!(stderr.contains("OUT OF SYNC"), "{stderr}");
}

/// Anti-vacuous half: the same project with the patch in place is in sync,
/// and says how many patches it checked.
#[test]
fn check_passes_on_a_patched_npm_package() {
    let tmp = project(Some(PATCHED));
    let (code, stdout, stderr) = run_check(tmp.path(), &[]);
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    assert!(
        stdout.contains("Patches are in sync (1 patch checked)."),
        "{stdout}"
    );

    let (code, stdout, stderr) = run_check(tmp.path(), &["--json"]);
    assert_eq!(code, 0, "stderr={stderr}");
    let env = parse_json_envelope(stdout.trim());
    assert_eq!(env["status"], "success", "{env}");
    let events = events(&env);
    assert_eq!(events.len(), 1, "{env}");
    assert_eq!(events[0]["action"], "skipped", "{env}");
    assert_eq!(events[0]["errorCode"], "already_patched", "{env}");
}

/// A package with no installed copy is skipped — `apply` skips it too —
/// and the success line says so instead of a bare "in sync".
#[test]
fn check_skips_an_uninstalled_package_and_says_so() {
    let tmp = project(None);
    let (code, stdout, stderr) = run_check(tmp.path(), &[]);
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    assert!(
        stdout.contains("1 patch not installed, skipped"),
        "{stdout}"
    );

    let (code, stdout, _) = run_check(tmp.path(), &["--json"]);
    assert_eq!(code, 0);
    let env = parse_json_envelope(stdout.trim());
    assert!(
        events(&env)
            .iter()
            .any(|e| e["action"] == "skipped" && e["errorCode"] == "package_not_installed"),
        "{env}"
    );
}

/// `--ecosystems` scopes the check exactly as it scopes `apply`.
#[test]
fn check_honors_the_ecosystems_filter() {
    let tmp = project(Some(ORIGINAL));
    let (code, stdout, stderr) = run_check(tmp.path(), &["--ecosystems", "pypi"]);
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    assert!(stdout.contains("No patches to check."), "{stdout}");
}

const GEM_BASE: &str = "pkg:gem/nokogiri@1.16.5";
const GEM_LINUX: &str = "pkg:gem/nokogiri@1.16.5?platform=x86_64-linux";
const GEM_ORIGINAL: &[u8] = b"module Nokogiri\n  VERSION = '1.16.5'\nend\n";
const GEM_PATCHED: &[u8] = b"module Nokogiri\n  VERSION = '1.16.5'\nend\n# SOCKET-PATCH\n";

/// A gem project whose manifest keys the patch by a QUALIFIED purl (a
/// release variant, the normal form for gem and PyPI patches); the
/// installed `lib/nokogiri.rb` holds `installed`.
fn gem_project(installed: &[u8]) -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    std::fs::write(root.join("Gemfile"), b"source 'https://rubygems.org'\n").unwrap();
    let file = root.join("vendor/bundle/ruby/3.4.0/gems/nokogiri-1.16.5/lib/nokogiri.rb");
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(&file, installed).unwrap();
    std::fs::create_dir_all(root.join("vendor/bundle/ruby/3.4.0/specifications")).unwrap();
    std::fs::create_dir_all(root.join(".socket/blobs")).unwrap();
    let manifest = json!({ "patches": { GEM_LINUX: {
        "uuid": "41414141-4141-4141-8141-414141414141",
        "exportedAt": "2024-01-01T00:00:00Z",
        "files": { "lib/nokogiri.rb": {
            "beforeHash": git_sha256(GEM_ORIGINAL),
            "afterHash": git_sha256(GEM_PATCHED),
        }},
        "vulnerabilities": {},
        "description": "apply --check gem variant fixture",
        "license": "MIT",
        "tier": "free",
    }}});
    std::fs::write(
        root.join(".socket/manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    std::fs::write(
        root.join(".socket/blobs").join(git_sha256(GEM_PATCHED)),
        GEM_PATCHED,
    )
    .unwrap();
    tmp
}

/// The release-variant false green: an installed copy of a qualified
/// purl whose bytes match neither of the variant's hashes is drift
/// (`no_matching_variant`, exit 1) — `apply` fails the same copy with
/// "no matching variant found" — never "not installed, skipped".
#[test]
fn check_fails_on_a_qualified_gem_matching_no_variant() {
    let tmp = gem_project(b"# foreign bytes\n");
    let (code, stdout, stderr) = run_check(tmp.path(), &["--json", "--ecosystems", "gem"]);
    assert_eq!(code, 1, "stdout={stdout}\nstderr={stderr}");
    let env = parse_json_envelope(stdout.trim());
    assert!(
        events(&env).iter().any(|e| e["action"] == "failed"
            && e["purl"] == GEM_BASE
            && e["errorCode"] == "no_matching_variant"),
        "{env}"
    );
    // The installed mismatch is not also reported as not installed.
    assert!(
        !events(&env)
            .iter()
            .any(|e| e["errorCode"] == "package_not_installed"),
        "{env}"
    );

    // Parity: `apply` exits 1 on the same tree.
    let (code, stdout, stderr) = run_with_env(
        tmp.path(),
        &["apply", "--offline", "--ecosystems", "gem"],
        &[("SOCKET_TELEMETRY_DISABLED", "1")],
    );
    assert_eq!(code, 1, "stdout={stdout}\nstderr={stderr}");
}

/// The same qualified variant judged on its own copy: unpatched is
/// `not_applied` drift, patched is in sync.
#[test]
fn check_judges_a_qualified_gem_on_its_own_copy() {
    let tmp = gem_project(GEM_ORIGINAL);
    let (code, stdout, stderr) = run_check(tmp.path(), &["--json", "--ecosystems", "gem"]);
    assert_eq!(code, 1, "stdout={stdout}\nstderr={stderr}");
    let env = parse_json_envelope(stdout.trim());
    assert!(
        events(&env).iter().any(|e| e["action"] == "failed"
            && e["purl"] == GEM_LINUX
            && e["errorCode"] == "not_applied"),
        "{env}"
    );

    let tmp = gem_project(GEM_PATCHED);
    let (code, stdout, stderr) = run_check(tmp.path(), &["--ecosystems", "gem"]);
    assert_eq!(code, 0, "stdout={stdout}\nstderr={stderr}");
    assert!(
        stdout.contains("Patches are in sync (1 patch checked)."),
        "{stdout}"
    );
}
