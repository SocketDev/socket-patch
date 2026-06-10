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
    // resolve_manifest_path() must prefer the absolute path.
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
