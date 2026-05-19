//! CLI contract tests for the `repair` subcommand (and its `gc` visible alias).
//!
//! These tests pin the public clap parser surface for `RepairArgs`. The most
//! important invariant guarded here is that `repair`'s `--download-mode`
//! defaults to `"file"` — diverging from every other command (which defaults
//! to `"diff"`). This is intentional: `repair` restores the legacy per-file
//! blobs needed to apply any patch. A silent flip to `"diff"` would be a
//! breaking behavior change with no parser-level signal, so we lock it down
//! here. The `gc` visible alias is also exercised so a refactor that drops
//! it is caught immediately.
//!
//! See `crates/socket-patch-cli/CLI_CONTRACT.md` for the full repair table.

use std::path::PathBuf;

use clap::Parser;
use socket_patch_cli::commands::repair::RepairArgs;
use socket_patch_cli::{Cli, Commands};

fn parse_repair(extra: &[&str]) -> RepairArgs {
    let mut argv = vec!["socket-patch", "repair"];
    argv.extend_from_slice(extra);
    let cli = Cli::try_parse_from(&argv).expect("parse");
    match cli.command {
        Commands::Repair(a) => a,
        _ => panic!("expected Repair"),
    }
}

fn parse_gc(extra: &[&str]) -> RepairArgs {
    let mut argv = vec!["socket-patch", "gc"];
    argv.extend_from_slice(extra);
    let cli = Cli::try_parse_from(&argv).expect("parse");
    match cli.command {
        Commands::Repair(a) => a,
        _ => panic!("expected Repair via gc alias"),
    }
}

#[test]
fn repair_defaults_match_contract() {
    let args = parse_repair(&[]);

    // CRITICAL: repair's --download-mode default is "file", not "diff".
    // This is the divergent default vs every other command.
    assert_eq!(
        args.download_mode, "file",
        "repair --download-mode default MUST be `file` (legacy per-file blobs); diverges from other commands"
    );

    // Remaining defaults from CLI_CONTRACT.md repair table.
    assert_eq!(args.cwd, PathBuf::from("."));
    assert_eq!(args.manifest_path, ".socket/manifest.json");
    assert!(!args.dry_run);
    assert!(!args.offline);
    assert!(!args.download_only);
    assert!(!args.json);
}

#[test]
fn repair_dry_run_short_flag() {
    let args = parse_repair(&["-d"]);
    assert!(args.dry_run);
}

#[test]
fn repair_dry_run_long_flag() {
    let args = parse_repair(&["--dry-run"]);
    assert!(args.dry_run);
}

#[test]
fn repair_manifest_path_short_flag() {
    let args = parse_repair(&["-m", "custom.json"]);
    assert_eq!(args.manifest_path, "custom.json");
}

#[test]
fn repair_manifest_path_long_flag() {
    let args = parse_repair(&["--manifest-path", "custom.json"]);
    assert_eq!(args.manifest_path, "custom.json");
}

#[test]
fn repair_cwd_flag() {
    let args = parse_repair(&["--cwd", "/tmp/x"]);
    assert_eq!(args.cwd, PathBuf::from("/tmp/x"));
}

#[test]
fn repair_offline_flag() {
    let args = parse_repair(&["--offline"]);
    assert!(args.offline);
}

#[test]
fn repair_download_only_flag() {
    let args = parse_repair(&["--download-only"]);
    assert!(args.download_only);
}

#[test]
fn repair_json_flag() {
    let args = parse_repair(&["--json"]);
    assert!(args.json);
}

#[test]
fn repair_download_mode_file() {
    let args = parse_repair(&["--download-mode", "file"]);
    assert_eq!(args.download_mode, "file");
}

#[test]
fn repair_download_mode_diff() {
    let args = parse_repair(&["--download-mode", "diff"]);
    assert_eq!(args.download_mode, "diff");
}

#[test]
fn repair_download_mode_package() {
    let args = parse_repair(&["--download-mode", "package"]);
    assert_eq!(args.download_mode, "package");
}

#[test]
fn repair_gc_alias_defaults_match_repair() {
    let via_gc = parse_gc(&[]);
    let via_repair = parse_repair(&[]);

    // The whole point of the alias: identical parsing.
    assert_eq!(via_gc.download_mode, "file");
    assert_eq!(via_gc.download_mode, via_repair.download_mode);
    assert_eq!(via_gc.cwd, via_repair.cwd);
    assert_eq!(via_gc.manifest_path, via_repair.manifest_path);
    assert_eq!(via_gc.dry_run, via_repair.dry_run);
    assert_eq!(via_gc.offline, via_repair.offline);
    assert_eq!(via_gc.download_only, via_repair.download_only);
    assert_eq!(via_gc.json, via_repair.json);
}

#[test]
fn repair_gc_alias_accepts_flags() {
    let args = parse_gc(&["--dry-run"]);
    assert!(args.dry_run);
}

#[test]
fn repair_unknown_flag_is_unknown_argument_error() {
    let err = match Cli::try_parse_from(["socket-patch", "repair", "--nope"]) {
        Ok(_) => panic!("unknown flag should fail to parse"),
        Err(e) => e,
    };
    assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
}
