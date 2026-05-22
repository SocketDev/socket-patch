//! Parser-level contract tests for `socket-patch setup`.
//!
//! Locks in every flag in the `SetupArgs` table from
//! `crates/socket-patch-cli/CLI_CONTRACT.md` (long + short forms, defaults)
//! and exercises two no-network `run()` paths:
//!
//! 1. Calling `run()` directly against an empty tempdir → exit 0.
//! 2. Spawning the binary against the same empty tempdir with `--json` and
//!    asserting the documented `status: "no_files"` shape.
//!
//! These tests deliberately stay off the network so they run in the default
//! `cargo test` set (no `--ignored` required).

use clap::Parser;
use socket_patch_cli::commands::setup::{run, SetupArgs};
use socket_patch_cli::{Cli, Commands};
use std::path::PathBuf;
use std::process::Command;

fn parse_setup(extra: &[&str]) -> SetupArgs {
    let mut argv = vec!["socket-patch", "setup"];
    argv.extend_from_slice(extra);
    let cli = Cli::try_parse_from(&argv).expect("parse");
    match cli.command {
        Commands::Setup(a) => a,
        _ => panic!("expected Setup"),
    }
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

#[test]
fn defaults_with_no_flags() {
    let args = parse_setup(&[]);
    assert_eq!(args.common.cwd, PathBuf::from("."));
    assert!(!args.common.dry_run);
    assert!(!args.common.yes);
    assert!(!args.common.json);
}

// ---------------------------------------------------------------------------
// Flag forms — each one in the contract table must have a test
// ---------------------------------------------------------------------------

#[test]
fn dry_run_short_form() {
    let args = parse_setup(&["-d"]);
    assert!(args.common.dry_run);
}

#[test]
fn dry_run_long_form() {
    let args = parse_setup(&["--dry-run"]);
    assert!(args.common.dry_run);
}

#[test]
fn yes_short_form() {
    let args = parse_setup(&["-y"]);
    assert!(args.common.yes);
}

#[test]
fn yes_long_form() {
    let args = parse_setup(&["--yes"]);
    assert!(args.common.yes);
}

#[test]
fn cwd_long_form() {
    let args = parse_setup(&["--cwd", "/tmp/x"]);
    assert_eq!(args.common.cwd, PathBuf::from("/tmp/x"));
}

#[test]
fn json_long_form() {
    let args = parse_setup(&["--json"]);
    assert!(args.common.json);
}

#[test]
fn all_flags_combined() {
    let args = parse_setup(&["--cwd", "/tmp/x", "-d", "-y", "--json"]);
    assert_eq!(args.common.cwd, PathBuf::from("/tmp/x"));
    assert!(args.common.dry_run);
    assert!(args.common.yes);
    assert!(args.common.json);
}

// ---------------------------------------------------------------------------
// Failure paths
// ---------------------------------------------------------------------------

#[test]
fn unknown_flag_is_error() {
    let result = Cli::try_parse_from(["socket-patch", "setup", "--not-a-real-flag"]);
    let err = match result {
        Ok(_) => panic!("unknown flag must fail"),
        Err(e) => e,
    };
    assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
}

// ---------------------------------------------------------------------------
// Async run() — empty tempdir, no package.json files → exit 0
// ---------------------------------------------------------------------------

#[tokio::test]
async fn run_empty_tempdir_exits_zero() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let args = SetupArgs {
        common: socket_patch_cli::args::GlobalArgs {
            cwd: tempdir.path().to_path_buf(),
            dry_run: false,
            yes: true,
            json: true,
            ..socket_patch_cli::args::GlobalArgs::default()
        },
    };
    let exit = run(args).await;
    assert_eq!(
        exit, 0,
        "empty tempdir (no package.json) must exit 0 with status 'no_files'"
    );
}

// ---------------------------------------------------------------------------
// Subprocess: lock the JSON contract shape for `status: no_files`.
// ---------------------------------------------------------------------------

#[test]
fn subprocess_no_files_json_shape() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let exe = env!("CARGO_BIN_EXE_socket-patch");
    let output = Command::new(exe)
        .arg("setup")
        .arg("--cwd")
        .arg(tempdir.path())
        .arg("--json")
        .arg("--yes")
        .output()
        .expect("spawn socket-patch");
    assert!(
        output.status.success(),
        "setup against empty tempdir must succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("stdout must be JSON, got {stdout:?}: {e}");
    });
    assert_eq!(
        v["status"], "no_files",
        "status must be 'no_files' for empty tempdir; full payload: {v}"
    );
    assert_eq!(v["updated"], 0);
    assert_eq!(v["alreadyConfigured"], 0);
    assert_eq!(v["errors"], 0);
    assert!(v["files"].is_array(), "'files' must be an array");
    assert_eq!(
        v["files"].as_array().expect("array").len(),
        0,
        "'files' must be an empty array for status 'no_files'"
    );
}
