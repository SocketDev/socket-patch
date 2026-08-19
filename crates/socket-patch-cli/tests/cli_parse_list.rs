//! Parser + `run()` contract tests for `socket-patch list`.
//!
//! These tests pin the public CLI surface of the `list` subcommand:
//! - clap parser tests assert flag long/short forms, defaults, and unknown-flag rejection
//! - async `run()` tests cover the no-network execution paths (missing manifest -> 1,
//!   empty manifest -> 0, populated manifest -> 0, absolute manifest path wins)
//! - one subprocess test against the compiled binary locks the JSON `status` shape for
//!   the missing-manifest error path, since `run()` writes directly to stdout/stderr
//!   and cannot be intercepted in-process.
//!
//! See `crates/socket-patch-cli/CLI_CONTRACT.md` for the surface these tests pin.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use clap::Parser;
use socket_patch_cli::commands::list::{run, ListArgs};

#[path = "common/mod.rs"]
mod common;
use socket_patch_cli::{Cli, Commands};
use socket_patch_core::manifest::schema::{
    PatchFileInfo, PatchManifest, PatchRecord, VulnerabilityInfo,
};

// ---------------------------------------------------------------------------
// Parser helpers
// ---------------------------------------------------------------------------

fn parse_list(extra: &[&str]) -> ListArgs {
    let mut argv = vec!["socket-patch", "list"];
    argv.extend_from_slice(extra);
    let cli = Cli::try_parse_from(&argv).expect("parse");
    match cli.command {
        Commands::List(a) => a,
        _ => panic!("expected List"),
    }
}

// ---------------------------------------------------------------------------
// Parser tests
// ---------------------------------------------------------------------------

#[test]
fn defaults_match_contract() {
    let args = parse_list(&[]);
    assert_eq!(args.common.cwd, PathBuf::from("."));
    assert_eq!(args.common.manifest_path, ".socket/manifest.json");
    assert!(!args.common.json);
}

#[test]
fn manifest_path_long_form() {
    let args = parse_list(&["--manifest-path", "custom.json"]);
    assert_eq!(args.common.manifest_path, "custom.json");
}

#[test]
fn cwd_long_form() {
    let args = parse_list(&["--cwd", "/tmp/x"]);
    assert_eq!(args.common.cwd, PathBuf::from("/tmp/x"));
}

#[test]
fn json_flag_sets_true() {
    let args = parse_list(&["--json"]);
    assert!(args.common.json);
}

#[test]
fn unknown_flag_is_rejected() {
    let err = match Cli::try_parse_from(["socket-patch", "list", "--nope"]) {
        Ok(_) => panic!("unknown flag must fail"),
        Err(e) => e,
    };
    assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
}

// ---------------------------------------------------------------------------
// run() integration tests — no-network paths
// ---------------------------------------------------------------------------

fn populated_manifest() -> PatchManifest {
    let mut files = HashMap::new();
    files.insert(
        "package/index.js".to_string(),
        PatchFileInfo {
            before_hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1111"
                .to_string(),
            after_hash: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb1111"
                .to_string(),
        },
    );

    let mut vulnerabilities = HashMap::new();
    vulnerabilities.insert(
        "GHSA-test-test-test".to_string(),
        VulnerabilityInfo {
            cves: vec!["CVE-2024-0001".to_string()],
            summary: "test vuln".to_string(),
            severity: "high".to_string(),
            description: "test description".to_string(),
        },
    );

    let mut patches = HashMap::new();
    patches.insert(
        "pkg:npm/test-pkg@1.0.0".to_string(),
        PatchRecord {
            uuid: "11111111-1111-4111-8111-111111111111".to_string(),
            exported_at: "2024-01-01T00:00:00Z".to_string(),
            files,
            vulnerabilities,
            description: "Test patch".to_string(),
            license: "MIT".to_string(),
            tier: "free".to_string(),
        },
    );

    PatchManifest {
        patches,
        setup: None,
    }
}

#[tokio::test]
async fn missing_manifest_returns_1_plain() {
    let tmp = tempfile::tempdir().unwrap();
    let args = ListArgs {
        common: socket_patch_cli::args::GlobalArgs {
            cwd: tmp.path().to_path_buf(),
            manifest_path: ".socket/manifest.json".into(),
            json: false,
            ..socket_patch_cli::args::GlobalArgs::default()
        },
    };
    assert_eq!(run(args).await, 1);
}

#[tokio::test]
async fn missing_manifest_returns_1_json() {
    let tmp = tempfile::tempdir().unwrap();
    let args = ListArgs {
        common: socket_patch_cli::args::GlobalArgs {
            cwd: tmp.path().to_path_buf(),
            manifest_path: ".socket/manifest.json".into(),
            json: true,
            ..socket_patch_cli::args::GlobalArgs::default()
        },
    };
    assert_eq!(run(args).await, 1);
}

#[tokio::test]
async fn empty_manifest_returns_0_plain() {
    let tmp = tempfile::tempdir().unwrap();
    let socket_dir = tmp.path().join(".socket");
    tokio::fs::create_dir_all(&socket_dir).await.unwrap();
    let manifest = PatchManifest::new();
    let path = socket_dir.join("manifest.json");
    tokio::fs::write(&path, serde_json::to_string_pretty(&manifest).unwrap())
        .await
        .unwrap();

    let args = ListArgs {
        common: socket_patch_cli::args::GlobalArgs {
            cwd: tmp.path().to_path_buf(),
            manifest_path: ".socket/manifest.json".into(),
            json: false,
            ..socket_patch_cli::args::GlobalArgs::default()
        },
    };
    assert_eq!(run(args).await, 0);
}

#[tokio::test]
async fn empty_manifest_returns_0_json() {
    let tmp = tempfile::tempdir().unwrap();
    let socket_dir = tmp.path().join(".socket");
    tokio::fs::create_dir_all(&socket_dir).await.unwrap();
    let manifest = PatchManifest::new();
    let path = socket_dir.join("manifest.json");
    tokio::fs::write(&path, serde_json::to_string_pretty(&manifest).unwrap())
        .await
        .unwrap();

    let args = ListArgs {
        common: socket_patch_cli::args::GlobalArgs {
            cwd: tmp.path().to_path_buf(),
            manifest_path: ".socket/manifest.json".into(),
            json: true,
            ..socket_patch_cli::args::GlobalArgs::default()
        },
    };
    assert_eq!(run(args).await, 0);
}

#[tokio::test]
async fn populated_manifest_returns_0_plain() {
    let tmp = tempfile::tempdir().unwrap();
    let socket_dir = tmp.path().join(".socket");
    tokio::fs::create_dir_all(&socket_dir).await.unwrap();
    let manifest = populated_manifest();
    let path = socket_dir.join("manifest.json");
    tokio::fs::write(&path, serde_json::to_string_pretty(&manifest).unwrap())
        .await
        .unwrap();

    let args = ListArgs {
        common: socket_patch_cli::args::GlobalArgs {
            cwd: tmp.path().to_path_buf(),
            manifest_path: ".socket/manifest.json".into(),
            json: false,
            ..socket_patch_cli::args::GlobalArgs::default()
        },
    };
    assert_eq!(run(args).await, 0);
}

#[tokio::test]
async fn populated_manifest_returns_0_json() {
    let tmp = tempfile::tempdir().unwrap();
    let socket_dir = tmp.path().join(".socket");
    tokio::fs::create_dir_all(&socket_dir).await.unwrap();
    let manifest = populated_manifest();
    let path = socket_dir.join("manifest.json");
    tokio::fs::write(&path, serde_json::to_string_pretty(&manifest).unwrap())
        .await
        .unwrap();

    let args = ListArgs {
        common: socket_patch_cli::args::GlobalArgs {
            cwd: tmp.path().to_path_buf(),
            manifest_path: ".socket/manifest.json".into(),
            json: true,
            ..socket_patch_cli::args::GlobalArgs::default()
        },
    };
    assert_eq!(run(args).await, 0);
}

#[tokio::test]
async fn absolute_manifest_path_wins_over_cwd() {
    // Manifest lives in tmp_manifest_dir, cwd points elsewhere.
    // resolved_manifest_path() must prefer the absolute path.
    let tmp_manifest_dir = tempfile::tempdir().unwrap();
    let tmp_cwd = tempfile::tempdir().unwrap();

    let manifest = PatchManifest::new();
    let abs_path = tmp_manifest_dir.path().join("abs.json");
    tokio::fs::write(&abs_path, serde_json::to_string_pretty(&manifest).unwrap())
        .await
        .unwrap();

    let args = ListArgs {
        common: socket_patch_cli::args::GlobalArgs {
            cwd: tmp_cwd.path().to_path_buf(),
            manifest_path: abs_path.to_string_lossy().into_owned(),
            json: false,
            ..socket_patch_cli::args::GlobalArgs::default()
        },
    };
    assert_eq!(run(args).await, 0);
}

// ---------------------------------------------------------------------------
// Subprocess test — locks the JSON `status` shape for missing-manifest error
// ---------------------------------------------------------------------------

#[test]
fn missing_manifest_json_status_is_error_via_binary() {
    // Pins the new unified envelope shape for `list --json` when the
    // manifest doesn't exist. Top-level keys: command, status, error
    // (object with code + message), plus the usual envelope fields.
    let tmp = tempfile::tempdir().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_socket-patch"))
        .args(["list", "--cwd", tmp.path().to_str().unwrap(), "--json"])
        .output()
        .expect("failed to execute socket-patch binary");

    assert_eq!(
        out.status.code(),
        Some(1),
        "missing manifest must exit 1, stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("stdout must be valid JSON");
    assert_eq!(parsed["command"], "list");
    assert_eq!(parsed["status"], "error");
    assert_eq!(parsed["error"]["code"], "manifest_not_found");
    let msg = parsed["error"]["message"].as_str().expect("error message");
    assert!(
        msg.contains("Manifest not found"),
        "error.message must include 'Manifest not found', got: {msg}"
    );
}

// ---------------------------------------------------------------------------
// Corrupt-manifest error-code tests — a manifest that EXISTS but cannot be
// parsed (or violates the schema) must report `manifest_invalid`, distinct
// from `manifest_not_found` (missing file) and `manifest_unreadable` (I/O
// error). The metadata pre-check in run() handles the missing case before
// read_manifest is ever called, so without this coverage a corrupt manifest
// could silently be mislabeled as an I/O error (or vice versa). See the
// error-code table in CLI_CONTRACT.md.
// ---------------------------------------------------------------------------

/// Run `list --json` against the compiled binary after writing `body` verbatim
/// to `<cwd>/.socket/manifest.json`. Returns (exit_code, parsed_json).
fn run_list_with_manifest_body(body: &str) -> (Option<i32>, serde_json::Value) {
    let tmp = tempfile::tempdir().unwrap();
    let socket_dir = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket_dir).unwrap();
    std::fs::write(socket_dir.join("manifest.json"), body).unwrap();

    let out = run_list_binary(tmp.path(), &["--json"]);
    let v: serde_json::Value = serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim())
        .expect("stdout must be valid JSON envelope");
    (out.status.code(), v)
}

#[test]
fn unparseable_manifest_reports_manifest_invalid_via_binary() {
    // Garbage that isn't JSON at all -> serde parse error -> InvalidData.
    let (code, v) = run_list_with_manifest_body("{not json");
    assert_eq!(code, Some(1), "corrupt manifest must exit 1");
    assert_eq!(v["command"], "list");
    assert_eq!(v["status"], "error");
    // The load-bearing assertion: a manifest that exists but can't be parsed
    // is `manifest_invalid`, NOT `manifest_unreadable` (an I/O error) and NOT
    // `manifest_not_found` (a missing file).
    assert_eq!(
        v["error"]["code"], "manifest_invalid",
        "unparseable manifest must be manifest_invalid, got envelope: {v}"
    );
}

#[test]
fn schema_invalid_manifest_reports_manifest_invalid_via_binary() {
    // Valid JSON, but not a valid manifest (missing the required `patches`
    // key). read_manifest's validation step rejects it with InvalidData, so
    // it must also surface as `manifest_invalid`, never `manifest_unreadable`.
    let (code, v) = run_list_with_manifest_body(r#"{"not_patches": {}}"#);
    assert_eq!(code, Some(1), "schema-invalid manifest must exit 1");
    assert_eq!(v["command"], "list");
    assert_eq!(v["status"], "error");
    assert_eq!(
        v["error"]["code"], "manifest_invalid",
        "schema-invalid manifest must be manifest_invalid, got envelope: {v}"
    );
}

#[test]
fn empty_file_manifest_reports_manifest_invalid_via_binary() {
    // An empty file is a present-but-unparseable manifest (serde rejects ""),
    // which is distinct from a missing file. It must NOT be misreported as
    // manifest_not_found or manifest_unreadable.
    let (code, v) = run_list_with_manifest_body("");
    assert_eq!(code, Some(1), "empty manifest file must exit 1");
    assert_eq!(v["error"]["code"], "manifest_invalid", "got envelope: {v}");
}

#[test]
fn missing_manifest_under_valid_cwd_reports_manifest_not_found_via_binary() {
    // The common missing-manifest case: cwd exists, but `.socket/manifest.json`
    // does not. `read_manifest` returns `Ok(None)` here, which must surface as
    // `manifest_not_found` — NOT `manifest_invalid`. (Regression: the `Ok(None)`
    // arm previously hard-coded `manifest_invalid`, telling consumers a missing
    // file was corrupt. It was masked by a now-removed metadata pre-check.)
    let tmp = tempfile::tempdir().unwrap();
    let out = run_list_binary(tmp.path(), &["--json"]);
    let v: serde_json::Value = serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim())
        .expect("stdout must be valid JSON envelope");
    assert_eq!(out.status.code(), Some(1), "missing manifest must exit 1");
    assert_eq!(v["status"], "error");
    assert_eq!(
        v["error"]["code"], "manifest_not_found",
        "missing manifest must be manifest_not_found, got envelope: {v}"
    );
    let msg = v["error"]["message"].as_str().expect("error message");
    assert!(
        msg.contains("Manifest not found"),
        "message must name the missing manifest, got: {msg}"
    );
}

#[test]
fn manifest_path_is_existing_directory_reports_unreadable_via_binary() {
    // A genuine I/O error reaching an *existing* path must be
    // `manifest_unreadable`, never `manifest_not_found`. Here the manifest path
    // points at a directory, so the read fails with a non-absence I/O error
    // (Unix `IsADirectory` / Windows `PermissionDenied`) — present, but
    // unreadable. (We use a directory rather than a `<regular-file>/manifest`
    // path because the latter is `ENOTDIR` on Unix but a NotFound-class error
    // on Windows, where traversing through a file is legitimately "path not
    // found"; a directory yields a non-NotFound error on every platform.)
    //
    // Regression: `run()` used to stat the path with `tokio::fs::metadata`
    // first and treat ANY stat failure as `manifest_not_found`, masking real
    // I/O errors. Removing that pre-check lets `read_manifest`'s I/O error
    // classify it correctly.
    let tmp = tempfile::tempdir().unwrap();
    let manifest_path = tmp.path().join("manifest-is-a-dir");
    std::fs::create_dir(&manifest_path).unwrap();

    let out = run_list_binary(
        tmp.path(),
        &["--json", "--manifest-path", manifest_path.to_str().unwrap()],
    );
    let v: serde_json::Value = serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim())
        .expect("stdout must be valid JSON envelope");
    assert_eq!(out.status.code(), Some(1), "I/O error must exit 1");
    assert_eq!(v["status"], "error");
    assert_eq!(
        v["error"]["code"], "manifest_unreadable",
        "a non-absence I/O error must be manifest_unreadable, not \
         manifest_not_found, got envelope: {v}"
    );
}

// ---------------------------------------------------------------------------
// Subprocess content tests — the in-process run() tests above only assert the
// exit code. run() prints the actual listing to stdout (which cannot be
// captured in-process), so exit-code-only checks would stay green even if the
// command printed nothing, or the wrong packages. These run the compiled
// binary and verify the real stdout payload so a regression in *what* is
// listed (not just the success/failure code) fails loudly.
// ---------------------------------------------------------------------------

/// Write a manifest to `<dir>/.socket/manifest.json`.
fn write_manifest_in(dir: &Path, manifest: &PatchManifest) {
    let socket_dir = dir.join(".socket");
    std::fs::create_dir_all(&socket_dir).unwrap();
    std::fs::write(
        socket_dir.join("manifest.json"),
        serde_json::to_string_pretty(manifest).unwrap(),
    )
    .unwrap();
}

/// Run `list` against the compiled binary with `--cwd <cwd>` plus extra args.
fn run_list_binary(cwd: &Path, extra: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_socket-patch"))
        .arg("list")
        .arg("--cwd")
        .arg(cwd)
        .args(extra)
        .output()
        .expect("failed to execute socket-patch binary")
}

#[test]
fn populated_manifest_plain_lists_full_record_via_binary() {
    let tmp = tempfile::tempdir().unwrap();
    write_manifest_in(tmp.path(), &populated_manifest());

    let out = run_list_binary(tmp.path(), &[]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(0),
        "populated list must exit 0, stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Every field of the single record must be rendered, not just an exit 0.
    assert!(
        stdout.contains("Found 1 patch(es):"),
        "missing count header: {stdout}"
    );
    assert!(
        stdout.contains("Package: pkg:npm/test-pkg@1.0.0"),
        "missing purl: {stdout}"
    );
    assert!(
        stdout.contains("UUID: 11111111-1111-4111-8111-111111111111"),
        "missing uuid: {stdout}"
    );
    assert!(stdout.contains("Tier: free"), "missing tier: {stdout}");
    assert!(stdout.contains("License: MIT"), "missing license: {stdout}");
    assert!(
        stdout.contains("Exported: 2024-01-01T00:00:00Z"),
        "missing exportedAt: {stdout}"
    );
    assert!(
        stdout.contains("Description: Test patch"),
        "missing description: {stdout}"
    );
    assert!(
        stdout.contains("GHSA-test-test-test"),
        "missing advisory id: {stdout}"
    );
    assert!(stdout.contains("CVE-2024-0001"), "missing cve: {stdout}");
    assert!(
        stdout.contains("Severity: high"),
        "missing severity: {stdout}"
    );
    assert!(
        stdout.contains("Summary: test vuln"),
        "missing summary: {stdout}"
    );
    assert!(
        stdout.contains("package/index.js"),
        "missing patched file path: {stdout}"
    );
}

#[test]
fn populated_manifest_json_envelope_via_binary() {
    let tmp = tempfile::tempdir().unwrap();
    write_manifest_in(tmp.path(), &populated_manifest());

    let out = run_list_binary(tmp.path(), &["--json"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "populated list --json must exit 0, stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    let v: serde_json::Value = serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim())
        .expect("stdout must be valid JSON");
    assert_eq!(v["command"], "list");
    assert_eq!(v["status"], "success");
    assert_eq!(v["summary"]["discovered"], 1);

    let events = v["events"].as_array().expect("events array");
    assert_eq!(events.len(), 1, "exactly one discovered event expected");
    let event = &events[0];
    assert_eq!(event["action"], "discovered");
    assert_eq!(event["purl"], "pkg:npm/test-pkg@1.0.0");
    assert_eq!(event["uuid"], "11111111-1111-4111-8111-111111111111");
    assert_eq!(event["details"]["tier"], "free");
    assert_eq!(event["details"]["license"], "MIT");
    assert_eq!(event["details"]["description"], "Test patch");

    let files: Vec<&str> = event["files"]
        .as_array()
        .expect("files array")
        .iter()
        .map(|f| f["path"].as_str().expect("file path"))
        .collect();
    assert_eq!(files, vec!["package/index.js"]);

    let vulns = event["details"]["vulnerabilities"]
        .as_array()
        .expect("vulnerabilities array");
    assert_eq!(vulns.len(), 1);
    assert_eq!(vulns[0]["id"], "GHSA-test-test-test");
    assert_eq!(vulns[0]["severity"], "high");
    assert_eq!(vulns[0]["summary"], "test vuln");
    assert_eq!(vulns[0]["cves"][0], "CVE-2024-0001");
}

#[test]
fn empty_manifest_plain_says_no_patches_via_binary() {
    let tmp = tempfile::tempdir().unwrap();
    write_manifest_in(tmp.path(), &PatchManifest::new());

    let out = run_list_binary(tmp.path(), &[]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "empty list must exit 0");
    assert!(
        stdout.contains("No patches found in manifest."),
        "empty manifest must report no patches, got: {stdout}"
    );
    // Guard against a regression that prints a record anyway.
    assert!(
        !stdout.contains("Package:"),
        "empty manifest must not list any package: {stdout}"
    );
}

#[test]
fn empty_manifest_json_has_no_events_via_binary() {
    let tmp = tempfile::tempdir().unwrap();
    write_manifest_in(tmp.path(), &PatchManifest::new());

    let out = run_list_binary(tmp.path(), &["--json"]);
    assert_eq!(out.status.code(), Some(0), "empty list --json must exit 0");
    let v: serde_json::Value = serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim())
        .expect("stdout must be valid JSON");
    assert_eq!(v["command"], "list");
    assert_eq!(v["status"], "success");
    assert_eq!(v["summary"]["discovered"], 0);
    assert_eq!(v["events"].as_array().expect("events array").len(), 0);
}

// ---------------------------------------------------------------------------
// Multi-record subprocess tests — the single-record fixtures above cannot tell
// "lists every patch, counts them, and sorts them" apart from "renders only the
// first entry / hardcodes the count / leaks HashMap order". These build a
// manifest with several patches (each with multiple out-of-order vulns/files)
// and assert the count header, full completeness, and the stable sort order on
// the *human-readable* path of run() — which is reachable only via the binary.
// ---------------------------------------------------------------------------

/// Three patches inserted in non-alphabetical PURL order, each carrying
/// multiple vulnerabilities and files (also out of order), so the test can pin
/// the count, completeness, and the by-PURL / by-id / by-path sort contract.
fn multi_manifest() -> PatchManifest {
    fn record(uuid: &str, vulns: &[(&str, &str)], files: &[&str]) -> PatchRecord {
        let mut file_map = HashMap::new();
        for fp in files {
            file_map.insert(
                fp.to_string(),
                PatchFileInfo {
                    before_hash: "a".repeat(64),
                    after_hash: "b".repeat(64),
                },
            );
        }
        let mut vuln_map = HashMap::new();
        for (id, cve) in vulns {
            vuln_map.insert(
                id.to_string(),
                VulnerabilityInfo {
                    cves: vec![cve.to_string()],
                    summary: format!("summary for {id}"),
                    severity: "high".to_string(),
                    description: "desc".to_string(),
                },
            );
        }
        PatchRecord {
            uuid: uuid.to_string(),
            exported_at: "2024-01-01T00:00:00Z".to_string(),
            files: file_map,
            vulnerabilities: vuln_map,
            description: format!("description for {uuid}"),
            license: "MIT".to_string(),
            tier: "free".to_string(),
        }
    }

    let mut patches = HashMap::new();
    // Insert deliberately out of sorted order: zzz, aaa, mmm.
    patches.insert(
        "pkg:npm/zzz-pkg@3.0.0".to_string(),
        record(
            "33333333-3333-4333-8333-333333333333",
            &[
                ("GHSA-zzzz-0000-0003", "CVE-2024-3003"),
                ("GHSA-aaaa-0000-0003", "CVE-2024-3001"),
            ],
            &["zzz/z.js", "zzz/a.js"],
        ),
    );
    patches.insert(
        "pkg:npm/aaa-pkg@1.0.0".to_string(),
        record(
            "11111111-1111-4111-8111-111111111111",
            &[("GHSA-mmmm-0000-0001", "CVE-2024-1001")],
            &["aaa/only.js"],
        ),
    );
    patches.insert(
        "pkg:npm/mmm-pkg@2.0.0".to_string(),
        record(
            "22222222-2222-4222-8222-222222222222",
            &[("GHSA-cccc-0000-0002", "CVE-2024-2002")],
            &["mmm/only.js"],
        ),
    );
    PatchManifest {
        patches,
        setup: None,
    }
}

/// Byte offset of `needle` in `haystack`; panics with context if absent.
fn pos_of(haystack: &str, needle: &str) -> usize {
    haystack
        .find(needle)
        .unwrap_or_else(|| panic!("expected to find {needle:?} in:\n{haystack}"))
}

#[test]
fn multi_manifest_plain_lists_all_records_sorted_via_binary() {
    let tmp = tempfile::tempdir().unwrap();
    write_manifest_in(tmp.path(), &multi_manifest());

    let out = run_list_binary(tmp.path(), &[]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(0),
        "multi list must exit 0, stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Count header must reflect the real number of patches, not a hardcode.
    assert!(
        stdout.contains("Found 3 patch(es):"),
        "count header must say 3, got: {stdout}"
    );

    // Every package must be listed (catches "only renders the first entry").
    let p_aaa = pos_of(&stdout, "Package: pkg:npm/aaa-pkg@1.0.0");
    let p_mmm = pos_of(&stdout, "Package: pkg:npm/mmm-pkg@2.0.0");
    let p_zzz = pos_of(&stdout, "Package: pkg:npm/zzz-pkg@3.0.0");
    // ...and in stable, PURL-sorted order despite reversed insertion order.
    assert!(
        p_aaa < p_mmm && p_mmm < p_zzz,
        "packages must be sorted by PURL (aaa<mmm<zzz), got offsets aaa={p_aaa} mmm={p_mmm} zzz={p_zzz}:\n{stdout}"
    );

    // Per-record completeness: every uuid, vuln id, cve and file must appear.
    for needle in [
        "UUID: 11111111-1111-4111-8111-111111111111",
        "UUID: 22222222-2222-4222-8222-222222222222",
        "UUID: 33333333-3333-4333-8333-333333333333",
        "GHSA-mmmm-0000-0001",
        "GHSA-cccc-0000-0002",
        "GHSA-zzzz-0000-0003",
        "GHSA-aaaa-0000-0003",
        "CVE-2024-1001",
        "CVE-2024-2002",
        "CVE-2024-3001",
        "CVE-2024-3003",
        "aaa/only.js",
        "mmm/only.js",
        "zzz/a.js",
        "zzz/z.js",
    ] {
        assert!(stdout.contains(needle), "missing {needle:?} in:\n{stdout}");
    }

    // The zzz record's vulns must be sorted by advisory id (aaaa before zzzz)
    // and its files by path (a.js before z.js) within that record's block.
    assert!(
        pos_of(&stdout, "GHSA-aaaa-0000-0003") < pos_of(&stdout, "GHSA-zzzz-0000-0003"),
        "vulnerabilities must be sorted by id within a record:\n{stdout}"
    );
    assert!(
        pos_of(&stdout, "zzz/a.js") < pos_of(&stdout, "zzz/z.js"),
        "patched files must be sorted by path within a record:\n{stdout}"
    );

    // The two-vuln record must announce its count.
    assert!(
        stdout.contains("Vulnerabilities (2):"),
        "zzz record must report 2 vulnerabilities, got: {stdout}"
    );
    assert!(
        stdout.contains("Files patched (2):"),
        "zzz record must report 2 patched files, got: {stdout}"
    );
}

#[test]
fn multi_manifest_json_lists_all_records_sorted_via_binary() {
    let tmp = tempfile::tempdir().unwrap();
    write_manifest_in(tmp.path(), &multi_manifest());

    let out = run_list_binary(tmp.path(), &["--json"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "multi list --json must exit 0, stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    let v: serde_json::Value = serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim())
        .expect("stdout must be valid JSON");
    assert_eq!(v["status"], "success");
    assert_eq!(v["summary"]["discovered"], 3, "discovered count must be 3");

    let events = v["events"].as_array().expect("events array");
    assert_eq!(events.len(), 3, "exactly three discovered events expected");

    // Events must be emitted in stable PURL-sorted order, not HashMap order.
    let purls: Vec<&str> = events
        .iter()
        .map(|e| e["purl"].as_str().expect("purl"))
        .collect();
    assert_eq!(
        purls,
        vec![
            "pkg:npm/aaa-pkg@1.0.0",
            "pkg:npm/mmm-pkg@2.0.0",
            "pkg:npm/zzz-pkg@3.0.0",
        ],
        "events must be sorted by PURL"
    );

    // The zzz event's two vulns must be sorted by id.
    let zeta = events
        .iter()
        .find(|e| e["purl"] == "pkg:npm/zzz-pkg@3.0.0")
        .expect("zzz event");
    let ids: Vec<&str> = zeta["details"]["vulnerabilities"]
        .as_array()
        .expect("vulnerabilities array")
        .iter()
        .map(|x| x["id"].as_str().expect("id"))
        .collect();
    assert_eq!(
        ids,
        vec!["GHSA-aaaa-0000-0003", "GHSA-zzzz-0000-0003"],
        "vulnerabilities must be sorted by id"
    );
    let paths: Vec<&str> = zeta["files"]
        .as_array()
        .expect("files array")
        .iter()
        .map(|f| f["path"].as_str().expect("path"))
        .collect();
    assert_eq!(
        paths,
        vec!["zzz/a.js", "zzz/z.js"],
        "files must be sorted by path"
    );
}

#[test]
fn absolute_manifest_path_content_wins_over_cwd_via_binary() {
    // Decoy manifest in cwd/.socket and a *different* manifest at an absolute
    // path. The absolute path must win, so the listed PURL must be the
    // absolute manifest's, never the decoy's. The in-process exit-code test
    // could not tell these apart (both resolve to a readable manifest -> 0).
    let tmp_cwd = tempfile::tempdir().unwrap();
    let tmp_manifest_dir = tempfile::tempdir().unwrap();

    // Decoy in cwd: a populated manifest with a distinct PURL.
    write_manifest_in(tmp_cwd.path(), &populated_manifest());

    // Absolute target: a manifest with an unmistakably different PURL.
    let mut abs_manifest = PatchManifest::new();
    let mut decoy = populated_manifest();
    let rec = decoy.patches.remove("pkg:npm/test-pkg@1.0.0").unwrap();
    abs_manifest
        .patches
        .insert("pkg:npm/abs-only-pkg@9.9.9".to_string(), rec);
    let abs_path = tmp_manifest_dir.path().join("abs.json");
    std::fs::write(
        &abs_path,
        serde_json::to_string_pretty(&abs_manifest).unwrap(),
    )
    .unwrap();

    let out = run_list_binary(
        tmp_cwd.path(),
        &["--manifest-path", abs_path.to_str().unwrap()],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(0),
        "must exit 0, stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("pkg:npm/abs-only-pkg@9.9.9"),
        "absolute manifest's package must be listed: {stdout}"
    );
    assert!(
        !stdout.contains("pkg:npm/test-pkg@1.0.0"),
        "cwd decoy manifest must NOT be listed when absolute path is given: {stdout}"
    );
}

// ---------------------------------------------------------------------------
// `--silent` contract — CLI_CONTRACT.md defines `--silent` as "Errors only".
// Regression guard: `run()` gated the human-readable listing on `!json`
// alone, so `list --silent` still printed the full patch table (and the
// "No patches found in manifest." line for an empty manifest). Mirrors the
// `get --silent` / `repair --silent` regressions fixed earlier.
// ---------------------------------------------------------------------------

/// Like [`run_list_binary`] but with every `GlobalArgs` env var scrubbed,
/// so ambient developer/CI configuration (SOCKET_SILENT, SOCKET_JSON,
/// tokens…) can't change the branch under test, and telemetry disabled so
/// the test stays offline.
fn run_list_binary_scrubbed(cwd: &Path, extra: &[&str]) -> std::process::Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_socket-patch"));
    cmd.arg("list").arg("--cwd").arg(cwd).args(extra);
    for var in socket_patch_cli::args::GLOBAL_ARG_ENV_VARS {
        cmd.env_remove(var);
    }
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1");
    cmd.output().expect("failed to execute socket-patch binary")
}

#[test]
fn silent_suppresses_human_listing_via_binary() {
    let tmp = tempfile::tempdir().unwrap();
    write_manifest_in(tmp.path(), &populated_manifest());

    let out = run_list_binary_scrubbed(tmp.path(), &["--silent"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(0),
        "list --silent must still exit 0"
    );
    assert!(
        stdout.trim().is_empty(),
        "--silent must produce no stdout for a populated manifest; got {stdout:?}"
    );

    // Control run: the same manifest WITHOUT --silent must print the table —
    // otherwise the assertion above passes vacuously.
    let loud = run_list_binary_scrubbed(tmp.path(), &[]);
    assert_eq!(loud.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&loud.stdout).contains("Package: pkg:npm/test-pkg@1.0.0"),
        "non-silent run must print the listing"
    );
}

#[test]
fn silent_suppresses_no_patches_message_via_binary() {
    let tmp = tempfile::tempdir().unwrap();
    write_manifest_in(tmp.path(), &PatchManifest::new());

    let out = run_list_binary_scrubbed(tmp.path(), &["--silent"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(0),
        "empty list --silent must exit 0"
    );
    assert!(
        stdout.trim().is_empty(),
        "--silent must suppress the no-patches message; got {stdout:?}"
    );
}

#[test]
fn silent_does_not_mute_json_envelope_via_binary() {
    // `--json` output is the machine-readable result, not human chatter:
    // `--silent --json` must still emit the envelope (matching `get`/`repair`).
    let tmp = tempfile::tempdir().unwrap();
    write_manifest_in(tmp.path(), &populated_manifest());

    let out = run_list_binary_scrubbed(tmp.path(), &["--silent", "--json"]);
    assert_eq!(out.status.code(), Some(0));
    let v: serde_json::Value = serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim())
        .expect("--silent --json must still print the JSON envelope");
    assert_eq!(v["command"], "list");
    assert_eq!(v["summary"]["discovered"], 1);
}

#[test]
fn silent_keeps_missing_manifest_error_on_stderr_via_binary() {
    // "Errors only": the missing-manifest diagnostic must survive --silent.
    let tmp = tempfile::tempdir().unwrap();

    let out = run_list_binary_scrubbed(tmp.path(), &["--silent"]);
    assert_eq!(out.status.code(), Some(1), "missing manifest must exit 1");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("Manifest not found"),
        "error output must NOT be muted by --silent"
    );
}

// ---------------------------------------------------------------------------
// Hosted redirect-ledger records — `scan --mode hosted` records its patches
// ONLY in `.socket/vendor/redirect-state.json` (it never writes
// `.socket/manifest.json`), so `list` on a purely hosted-wired project used
// to hard-fail `manifest_not_found` while patches were demonstrably live
// (verified against production on bundler 1.17/2.7/4.0 — the gem live-matrix
// D3 defect). `list` now folds the ledger's records in, labeled as hosted;
// when both stores exist, both are shown.
// ---------------------------------------------------------------------------

const HOSTED_PURL: &str = "pkg:npm/hosted-pkg@2.0.0";
const HOSTED_UUID: &str = "22222222-2222-4222-8222-222222222222";

/// A patch record for the redirect ledger, distinguishable from the
/// manifest fixture's record.
fn hosted_record(uuid: &str) -> PatchRecord {
    let mut files = HashMap::new();
    files.insert(
        "package/hosted.js".to_string(),
        PatchFileInfo {
            before_hash: "c".repeat(64),
            after_hash: "d".repeat(64),
        },
    );
    let mut vulnerabilities = HashMap::new();
    vulnerabilities.insert(
        "GHSA-host-host-host".to_string(),
        VulnerabilityInfo {
            cves: vec!["CVE-2024-0002".to_string()],
            summary: "hosted vuln".to_string(),
            severity: "critical".to_string(),
            description: "hosted description".to_string(),
        },
    );
    PatchRecord {
        uuid: uuid.to_string(),
        exported_at: "2024-02-02T00:00:00Z".to_string(),
        files,
        vulnerabilities,
        description: "Hosted patch".to_string(),
        license: "MIT".to_string(),
        tier: "free".to_string(),
    }
}

// The redirect-ledger writer lives in `tests/common/mod.rs`
// (`common::write_redirect_ledger`) — shared with the other suites that
// seed hosted state, so the fixture can never drift from the on-disk schema.

#[test]
fn hosted_only_project_list_json_lists_ledger_records_via_binary() {
    // No manifest at all — only the hosted redirect ledger. `list --json`
    // must exit 0 with the hosted records as labeled discovered events, not
    // `manifest_not_found`.
    let tmp = tempfile::tempdir().unwrap();
    common::write_redirect_ledger(tmp.path(), &[(HOSTED_PURL, hosted_record(HOSTED_UUID))]);

    let out = run_list_binary(tmp.path(), &["--json"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "hosted-only list --json must exit 0 (records found), stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim())
        .expect("stdout must be valid JSON");
    assert_eq!(v["command"], "list");
    assert_eq!(v["status"], "success", "envelope={v}");
    assert_eq!(v["summary"]["discovered"], 1, "envelope={v}");

    let events = v["events"].as_array().expect("events array");
    assert_eq!(events.len(), 1, "envelope={v}");
    let event = &events[0];
    assert_eq!(event["action"], "discovered");
    assert_eq!(event["purl"], HOSTED_PURL);
    assert_eq!(event["uuid"], HOSTED_UUID);
    // The hosted label: a consumer must be able to tell a redirect-ledger
    // record from a manifest entry.
    assert_eq!(event["details"]["mode"], "hosted", "envelope={v}");
    assert_eq!(
        event["details"]["ledger"], ".socket/vendor/redirect-state.json",
        "envelope={v}"
    );
    // The rich metadata rides along exactly like a manifest entry's.
    assert_eq!(event["details"]["tier"], "free");
    assert_eq!(event["details"]["exportedAt"], "2024-02-02T00:00:00Z");
    let vulns = event["details"]["vulnerabilities"]
        .as_array()
        .expect("vulnerabilities array");
    assert_eq!(vulns[0]["id"], "GHSA-host-host-host");
    assert_eq!(vulns[0]["severity"], "critical");
}

#[test]
fn hosted_only_project_list_plain_labels_hosted_via_binary() {
    let tmp = tempfile::tempdir().unwrap();
    common::write_redirect_ledger(tmp.path(), &[(HOSTED_PURL, hosted_record(HOSTED_UUID))]);

    let out = run_list_binary(tmp.path(), &[]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(0),
        "hosted-only list must exit 0, stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("Found 1 patch(es):"),
        "count header must include the hosted record: {stdout}"
    );
    assert!(
        stdout.contains(&format!("Package: {HOSTED_PURL}")),
        "missing hosted purl: {stdout}"
    );
    assert!(
        stdout.contains(&format!("UUID: {HOSTED_UUID}")),
        "missing hosted uuid: {stdout}"
    );
    // The human line must label the record as hosted and name the ledger.
    assert!(
        stdout.contains("Mode: hosted"),
        "hosted record must be labeled: {stdout}"
    );
    assert!(
        stdout.contains(".socket/vendor/redirect-state.json"),
        "the label must name the ledger the record came from: {stdout}"
    );
}

#[test]
fn manifest_and_hosted_ledger_coexist_via_binary() {
    // Manifest entry + hosted records, including one purl present in BOTH
    // stores: both are shown (labeled apart), globally purl-sorted with the
    // manifest entry first on a tie.
    let tmp = tempfile::tempdir().unwrap();
    write_manifest_in(tmp.path(), &populated_manifest());
    common::write_redirect_ledger(
        tmp.path(),
        &[
            (HOSTED_PURL, hosted_record(HOSTED_UUID)),
            // Same purl as the manifest fixture, different uuid.
            (
                "pkg:npm/test-pkg@1.0.0",
                hosted_record("33333333-3333-4333-8333-333333333333"),
            ),
        ],
    );

    let out = run_list_binary(tmp.path(), &["--json"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "list over both stores must exit 0, stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim())
        .expect("stdout must be valid JSON");
    assert_eq!(v["summary"]["discovered"], 3, "envelope={v}");
    let events = v["events"].as_array().expect("events array");
    let listed: Vec<(&str, &str, bool)> = events
        .iter()
        .map(|e| {
            (
                e["purl"].as_str().expect("purl"),
                e["uuid"].as_str().expect("uuid"),
                e["details"]["mode"] == "hosted",
            )
        })
        .collect();
    assert_eq!(
        listed,
        vec![
            (HOSTED_PURL, HOSTED_UUID, true),
            (
                "pkg:npm/test-pkg@1.0.0",
                "11111111-1111-4111-8111-111111111111",
                false
            ),
            (
                "pkg:npm/test-pkg@1.0.0",
                "33333333-3333-4333-8333-333333333333",
                true
            ),
        ],
        "both stores' records must be listed, purl-sorted, manifest entry \
         before the hosted record on a purl tie; envelope={v}"
    );
}

#[test]
fn edits_only_ledger_without_manifest_still_manifest_not_found_via_binary() {
    // A ledger with recorded edits but NO records (the post-takeover /
    // degraded shape) asserts no patches, so a manifest-less project stays
    // on the manifest_not_found path.
    let tmp = tempfile::tempdir().unwrap();
    let vendor_dir = tmp.path().join(".socket/vendor");
    std::fs::create_dir_all(&vendor_dir).unwrap();
    std::fs::write(
        vendor_dir.join("redirect-state.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "version": 1,
            "mode": "hosted",
            "edits": [{
                "path": "yarn.lock",
                "kind": "redirect_yarn_entry",
                "action": "rewritten",
                "key": "minimist@1.2.2",
                "original": "registry original"
            }]
        }))
        .unwrap(),
    )
    .unwrap();

    let out = run_list_binary(tmp.path(), &["--json"]);
    let v: serde_json::Value = serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim())
        .expect("stdout must be valid JSON");
    assert_eq!(
        out.status.code(),
        Some(1),
        "no records anywhere must exit 1"
    );
    assert_eq!(v["error"]["code"], "manifest_not_found", "envelope={v}");
}

#[test]
fn corrupt_manifest_with_hosted_ledger_still_manifest_invalid_via_binary() {
    // A corrupt manifest is an error state; hosted records must never mask
    // it as a healthy hosted-only listing.
    let tmp = tempfile::tempdir().unwrap();
    let socket_dir = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket_dir).unwrap();
    std::fs::write(socket_dir.join("manifest.json"), "{not json").unwrap();
    common::write_redirect_ledger(tmp.path(), &[(HOSTED_PURL, hosted_record(HOSTED_UUID))]);

    let out = run_list_binary(tmp.path(), &["--json"]);
    let v: serde_json::Value = serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim())
        .expect("stdout must be valid JSON");
    assert_eq!(out.status.code(), Some(1), "corrupt manifest must exit 1");
    assert_eq!(v["error"]["code"], "manifest_invalid", "envelope={v}");
}

#[test]
fn silent_suppresses_hosted_listing_via_binary() {
    // `--silent` is "errors only": the hosted listing is muted like the
    // manifest one, while the exit code still says records were found.
    let tmp = tempfile::tempdir().unwrap();
    common::write_redirect_ledger(tmp.path(), &[(HOSTED_PURL, hosted_record(HOSTED_UUID))]);

    let out = run_list_binary_scrubbed(tmp.path(), &["--silent"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "hosted-only --silent must exit 0"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.trim().is_empty(),
        "--silent must suppress the hosted listing; got {stdout:?}"
    );
}

#[test]
fn silent_gates_the_malformed_ledger_warning_via_binary() {
    // A malformed ledger degrades to "nothing to consult" with a stderr
    // warning — and that warning is advisory, so `--silent` ("errors only")
    // must mute it like every sibling warning. The listing itself proceeds
    // from the manifest either way.
    let tmp = tempfile::tempdir().unwrap();
    write_manifest_in(tmp.path(), &populated_manifest());
    let vendor_dir = tmp.path().join(".socket/vendor");
    std::fs::create_dir_all(&vendor_dir).unwrap();
    std::fs::write(vendor_dir.join("redirect-state.json"), "{ torn ledger").unwrap();

    // Control: without --silent the corruption is surfaced.
    let loud = run_list_binary_scrubbed(tmp.path(), &[]);
    assert_eq!(loud.status.code(), Some(0), "manifest still lists");
    assert!(
        String::from_utf8_lossy(&loud.stderr).contains("malformed"),
        "a malformed ledger must be surfaced on stderr when not silent; \
         stderr={}",
        String::from_utf8_lossy(&loud.stderr)
    );

    // --silent: the warning is muted, the exit code unchanged.
    let out = run_list_binary_scrubbed(tmp.path(), &["--silent"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&out.stderr).trim().is_empty(),
        "--silent must mute the malformed-ledger warning; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// ---------------------------------------------------------------------------
// `--manifest-path` store scoping — both stores must come from the SAME
// project. The redirect ledger used to be resolved against cwd
// unconditionally, so pointing `--manifest-path` at another project's
// manifest interleaved two projects' patch state (and a LOCAL ledger could
// suppress the flagged project's manifest_not_found).
// ---------------------------------------------------------------------------

#[test]
fn manifest_path_scopes_ledger_to_target_project_via_binary() {
    // cwd has its own (decoy) ledger; --manifest-path points at another
    // project that has BOTH a manifest and its own ledger. Only the target
    // project's stores may be listed.
    let cwd = tempfile::tempdir().unwrap();
    common::write_redirect_ledger(
        cwd.path(),
        &[("pkg:npm/local-decoy@0.0.1", hosted_record(HOSTED_UUID))],
    );

    let target = tempfile::tempdir().unwrap();
    write_manifest_in(target.path(), &populated_manifest());
    common::write_redirect_ledger(target.path(), &[(HOSTED_PURL, hosted_record(HOSTED_UUID))]);

    let manifest_path = target.path().join(".socket/manifest.json");
    let out = run_list_binary(
        cwd.path(),
        &["--json", "--manifest-path", manifest_path.to_str().unwrap()],
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim())
        .expect("stdout must be valid JSON");
    let purls: Vec<&str> = v["events"]
        .as_array()
        .expect("events array")
        .iter()
        .map(|e| e["purl"].as_str().expect("purl"))
        .collect();
    assert_eq!(
        purls,
        vec![HOSTED_PURL, "pkg:npm/test-pkg@1.0.0"],
        "only the target project's manifest + ledger may be listed — never \
         the cwd's local ledger; envelope={v}"
    );
}

#[test]
fn local_ledger_never_suppresses_flagged_manifest_not_found_via_binary() {
    // --manifest-path points at a project with NO manifest and NO ledger;
    // the cwd's local ledger records must not turn that into a success.
    let cwd = tempfile::tempdir().unwrap();
    common::write_redirect_ledger(cwd.path(), &[(HOSTED_PURL, hosted_record(HOSTED_UUID))]);
    let target = tempfile::tempdir().unwrap();

    let manifest_path = target.path().join(".socket/manifest.json");
    let out = run_list_binary(
        cwd.path(),
        &["--json", "--manifest-path", manifest_path.to_str().unwrap()],
    );
    let v: serde_json::Value = serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim())
        .expect("stdout must be valid JSON");
    assert_eq!(
        out.status.code(),
        Some(1),
        "the flagged project has no stores at all; envelope={v}"
    );
    assert_eq!(v["error"]["code"], "manifest_not_found", "envelope={v}");
}

// ---------------------------------------------------------------------------
// Telemetry — `patch_listed`'s `patches_count` predates the hosted folding
// and dashboards consume it as "manifest patches". Folding hosted records
// into the SAME field would silently redefine the metric (and double-count
// purls present in both stores), so the count stays manifest-only.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_telemetry_counts_manifest_patches_only_via_binary() {
    use wiremock::matchers::{method, path as url_path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(url_path("/v0/orgs/test-org/telemetry"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
        .mount(&server)
        .await;

    // 1 manifest patch + 2 hosted records (one sharing the manifest purl):
    // the listing shows 3 entries, the metric must still say 1.
    let tmp = tempfile::tempdir().unwrap();
    write_manifest_in(tmp.path(), &populated_manifest());
    common::write_redirect_ledger(
        tmp.path(),
        &[
            (HOSTED_PURL, hosted_record(HOSTED_UUID)),
            (
                "pkg:npm/test-pkg@1.0.0",
                hosted_record("33333333-3333-4333-8333-333333333333"),
            ),
        ],
    );

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_socket-patch"));
    cmd.arg("list")
        .arg("--cwd")
        .arg(tmp.path())
        .arg("--json")
        .arg("--api-token")
        .arg("sktsec_telemetry_test")
        .arg("--org")
        .arg("test-org");
    for var in socket_patch_cli::args::GLOBAL_ARG_ENV_VARS {
        cmd.env_remove(var);
    }
    cmd.env("SOCKET_TELEMETRY_DISABLED", "0");
    cmd.env("SOCKET_API_URL", server.uri());
    cmd.env("SOCKET_NO_UPDATE_CHECK", "1");
    let out = cmd.output().expect("run socket-patch binary");
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_str(String::from_utf8_lossy(&out.stdout).trim())
        .expect("stdout must be valid JSON");
    assert_eq!(
        v["summary"]["discovered"], 3,
        "the listing itself shows all three entries; envelope={v}"
    );

    let reqs = server.received_requests().await.unwrap_or_default();
    let telemetry = reqs
        .iter()
        .find(|r| r.url.path() == "/v0/orgs/test-org/telemetry")
        .expect("list must POST the patch_listed telemetry event");
    let body = String::from_utf8_lossy(&telemetry.body);
    assert!(
        body.contains("\"patches_count\":1"),
        "patches_count must keep its pre-hosted meaning (manifest patches \
         only — here 1, not the 3 listed entries); body={body}"
    );
}
