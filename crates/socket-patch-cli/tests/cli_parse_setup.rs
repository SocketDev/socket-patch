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
fn check_long_form() {
    let args = parse_setup(&["--check"]);
    assert!(args.check);
    assert!(!args.remove);
}

#[test]
fn remove_long_form() {
    let args = parse_setup(&["--remove"]);
    assert!(args.remove);
    assert!(!args.check);
}

#[test]
fn check_and_remove_conflict() {
    let result = Cli::try_parse_from(["socket-patch", "setup", "--check", "--remove"]);
    let err = match result {
        Ok(_) => panic!("--check + --remove must conflict"),
        Err(e) => e,
    };
    assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
}

#[test]
fn defaults_check_and_remove_false() {
    let args = parse_setup(&[]);
    assert!(!args.check);
    assert!(!args.remove);
}

#[test]
fn all_flags_combined() {
    let args = parse_setup(&["--cwd", "/tmp/x", "--dry-run", "-y", "--json"]);
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
        check: false,
        remove: false,
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

// ---------------------------------------------------------------------------
// Subprocess: the REAL setup path — a package.json present must actually be
// configured (status "success", count incremented) AND the file on disk must
// gain the postinstall hook. Without this, an impl that always short-circuits
// to `no_files` (or reports success without writing) would pass every other
// test in this file.
// ---------------------------------------------------------------------------

#[test]
fn subprocess_configures_real_package_json() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let pkg_path = tempdir.path().join("package.json");
    std::fs::write(&pkg_path, r#"{"name":"demo","version":"1.0.0"}"#).expect("write package.json");

    let exe = env!("CARGO_BIN_EXE_socket-patch");
    let output = Command::new(exe)
        .arg("setup")
        .arg("--cwd")
        .arg(tempdir.path())
        .arg("--json")
        .arg("--yes")
        // Keep this test off the network: a successful setup fires telemetry.
        .env("SOCKET_TELEMETRY_DISABLED", "1")
        .output()
        .expect("spawn socket-patch");

    assert!(
        output.status.success(),
        "setup on a real package.json must exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("utf8 stdout");
    let v: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout must be JSON, got {stdout:?}: {e}"));

    // The envelope must reflect a real change, not a no-op / no_files.
    assert_eq!(
        v["status"], "success",
        "a package.json that needed setup must report status 'success'; payload: {v}"
    );
    assert_eq!(
        v["updated"], 1,
        "exactly one manifest must be updated; payload: {v}"
    );
    assert_eq!(v["alreadyConfigured"], 0, "payload: {v}");
    assert_eq!(v["errors"], 0, "payload: {v}");
    assert_eq!(
        v["packageManager"], "npm",
        "default manager for a bare package.json is npm; payload: {v}"
    );

    let files = v["files"].as_array().expect("'files' must be an array");
    let pkg_entries: Vec<&serde_json::Value> = files
        .iter()
        .filter(|f| f["kind"] == "package_json")
        .collect();
    assert_eq!(
        pkg_entries.len(),
        1,
        "exactly one package_json file entry expected; payload: {v}"
    );
    let entry = pkg_entries[0];
    assert_eq!(
        entry["status"], "updated",
        "the package.json entry must report status 'updated'; entry: {entry}"
    );
    assert!(
        entry["error"].is_null(),
        "a successful update must carry no error; entry: {entry}"
    );
    assert!(
        entry["path"]
            .as_str()
            .map(|p| p.ends_with("package.json"))
            .unwrap_or(false),
        "the entry path must point at the package.json; entry: {entry}"
    );

    // The decisive check: the file on disk must actually carry the hook now.
    let after = std::fs::read_to_string(&pkg_path).expect("read package.json back");
    let parsed: serde_json::Value =
        serde_json::from_str(&after).expect("package.json must stay valid JSON after setup");
    let postinstall = parsed["scripts"]["postinstall"]
        .as_str()
        .unwrap_or_else(|| panic!("scripts.postinstall must be set after setup; file: {after}"));
    assert!(
        postinstall.contains("socket-patch apply"),
        "postinstall must invoke `socket-patch apply`, got {postinstall:?}"
    );
    // Original metadata must be preserved, not clobbered.
    assert_eq!(parsed["name"], "demo", "setup must preserve existing fields");
    assert_eq!(parsed["version"], "1.0.0", "setup must preserve existing fields");
}

// ---------------------------------------------------------------------------
// Subprocess: idempotency — running setup against an already-configured
// project must report `already_configured` (updated 0), not re-write or claim
// a fresh success. Guards against an impl that can't tell configured from not.
// ---------------------------------------------------------------------------

#[test]
fn subprocess_already_configured_is_idempotent() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let pkg_path = tempdir.path().join("package.json");
    std::fs::write(&pkg_path, r#"{"name":"demo","version":"1.0.0"}"#).expect("write package.json");

    let exe = env!("CARGO_BIN_EXE_socket-patch");
    let run = || {
        Command::new(exe)
            .arg("setup")
            .arg("--cwd")
            .arg(tempdir.path())
            .arg("--json")
            .arg("--yes")
            .env("SOCKET_TELEMETRY_DISABLED", "1")
            .output()
            .expect("spawn socket-patch")
    };

    // First run configures it.
    let first = run();
    assert!(first.status.success(), "first setup must succeed");
    let v1: serde_json::Value =
        serde_json::from_str(&String::from_utf8(first.stdout).expect("utf8")).expect("json");
    assert_eq!(v1["status"], "success", "first run must configure: {v1}");

    let before_second = std::fs::read_to_string(&pkg_path).expect("read");

    // Second run must be a no-op.
    let second = run();
    assert!(second.status.success(), "second setup must succeed");
    let v2: serde_json::Value =
        serde_json::from_str(&String::from_utf8(second.stdout).expect("utf8")).expect("json");
    assert_eq!(
        v2["status"], "already_configured",
        "re-running setup on a configured project must report 'already_configured'; payload: {v2}"
    );
    assert_eq!(v2["updated"], 0, "no further updates expected; payload: {v2}");

    let after_second = std::fs::read_to_string(&pkg_path).expect("read");
    assert_eq!(
        before_second, after_second,
        "an idempotent re-run must not rewrite package.json"
    );
}
