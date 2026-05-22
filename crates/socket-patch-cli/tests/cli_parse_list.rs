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
use std::path::PathBuf;
use std::process::Command;

use clap::Parser;
use socket_patch_cli::commands::list::{ListArgs, run};
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
fn manifest_path_short_form() {
    let args = parse_list(&["-m", "custom.json"]);
    assert_eq!(args.common.manifest_path, "custom.json");
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
            before_hash:
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1111"
                    .to_string(),
            after_hash:
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb1111"
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

    PatchManifest { patches }
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
        .args([
            "list",
            "--cwd",
            tmp.path().to_str().unwrap(),
            "--json",
        ])
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
