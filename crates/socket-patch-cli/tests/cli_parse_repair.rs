//! CLI contract tests for the `repair` subcommand (and its `gc` visible alias).
//!
//! These tests pin the public clap parser surface for `RepairArgs`. In v3.0
//! `repair`'s `--download-mode` aligns with every other command (default
//! `"diff"`); the legacy `"file"` default was retired so the surface stays
//! uniform. Users that need legacy per-file blob downloads opt in with
//! `--download-mode file`. The `gc` visible alias is also exercised so a
//! refactor that drops it is caught immediately.
//!
//! See `crates/socket-patch-cli/CLI_CONTRACT.md` for the full repair table.

use std::path::PathBuf;

use clap::Parser;
use socket_patch_core::api::blob_fetcher::DownloadMode;
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

    // v3.0: repair's --download-mode default aligns with every other
    // command (was "file" in v2.x). Users that need the legacy per-file
    // blob behavior opt in with `--download-mode file`.
    assert_eq!(args.common.download_mode, "diff");
    // The clap layer stores a raw String with no value_parser, so the
    // assertion above only proves the literal echoes. Bind it to the real
    // runtime validator so a regression that changes what `"diff"` *means*
    // (or stops recognizing it) fails here too.
    assert_eq!(
        DownloadMode::parse(&args.common.download_mode),
        Ok(DownloadMode::Diff),
        "default download_mode must be the real Diff variant"
    );

    // Remaining defaults from CLI_CONTRACT.md repair table.
    assert_eq!(args.common.cwd, PathBuf::from("."));
    assert_eq!(args.common.manifest_path, ".socket/manifest.json");
    assert!(!args.common.dry_run);
    assert!(!args.common.offline);
    assert!(!args.download_only);
    assert!(!args.common.json);
}

#[test]
fn repair_dry_run_long_flag() {
    let args = parse_repair(&["--dry-run"]);
    assert!(args.common.dry_run);
}

#[test]
fn repair_manifest_path_long_flag() {
    let args = parse_repair(&["--manifest-path", "custom.json"]);
    assert_eq!(args.common.manifest_path, "custom.json");
}

#[test]
fn repair_cwd_flag() {
    let args = parse_repair(&["--cwd", "/tmp/x"]);
    assert_eq!(args.common.cwd, PathBuf::from("/tmp/x"));
}

#[test]
fn repair_offline_flag() {
    let args = parse_repair(&["--offline"]);
    assert!(args.common.offline);
}

#[test]
fn repair_download_only_flag() {
    let args = parse_repair(&["--download-only"]);
    assert!(args.download_only);
}

#[test]
fn repair_json_flag() {
    let args = parse_repair(&["--json"]);
    assert!(args.common.json);
}

#[test]
fn repair_download_mode_file() {
    let args = parse_repair(&["--download-mode", "file"]);
    assert_eq!(args.common.download_mode, "file");
    // The legacy per-file blob opt-in this test exists to protect: assert
    // `"file"` is a mode the engine actually recognizes, not just an echoed
    // string. If `File` support is dropped, this fails loudly.
    assert_eq!(
        DownloadMode::parse(&args.common.download_mode),
        Ok(DownloadMode::File)
    );
}

#[test]
fn repair_download_mode_diff() {
    let args = parse_repair(&["--download-mode", "diff"]);
    assert_eq!(args.common.download_mode, "diff");
    assert_eq!(
        DownloadMode::parse(&args.common.download_mode),
        Ok(DownloadMode::Diff)
    );
}

#[test]
fn repair_download_mode_package() {
    let args = parse_repair(&["--download-mode", "package"]);
    assert_eq!(args.common.download_mode, "package");
    assert_eq!(
        DownloadMode::parse(&args.common.download_mode),
        Ok(DownloadMode::Package)
    );
}

#[test]
fn repair_download_mode_rejects_unknown_at_runtime() {
    // The clap surface accepts ANY string for --download-mode (no
    // value_parser); validation is deferred to `DownloadMode::parse` in the
    // run path. Pin that two-layer contract: a bogus mode parses at the clap
    // layer but is rejected by the validator. Without this, a test asserting
    // only the clap echo would pass even if every mode were silently valid.
    let args = parse_repair(&["--download-mode", "bogus"]);
    assert_eq!(args.common.download_mode, "bogus");
    assert!(
        DownloadMode::parse(&args.common.download_mode).is_err(),
        "unknown download mode must be rejected by the runtime validator"
    );
}

#[test]
fn repair_gc_alias_defaults_match_repair() {
    let via_gc = parse_gc(&[]);
    let via_repair = parse_repair(&[]);

    // The whole point of the alias: identical parsing.
    assert_eq!(via_gc.common.download_mode, "diff");
    assert_eq!(
        DownloadMode::parse(&via_gc.common.download_mode),
        Ok(DownloadMode::Diff)
    );
    assert_eq!(via_gc.common.download_mode, via_repair.common.download_mode);
    assert_eq!(via_gc.common.cwd, via_repair.common.cwd);
    assert_eq!(via_gc.common.manifest_path, via_repair.common.manifest_path);
    assert_eq!(via_gc.common.dry_run, via_repair.common.dry_run);
    assert_eq!(via_gc.common.offline, via_repair.common.offline);
    assert_eq!(via_gc.download_only, via_repair.download_only);
    assert_eq!(via_gc.common.json, via_repair.common.json);
}

#[test]
fn repair_gc_alias_accepts_flags() {
    let args = parse_gc(&["--dry-run"]);
    assert!(args.common.dry_run);
}

#[test]
fn repair_unknown_flag_is_unknown_argument_error() {
    let err = match Cli::try_parse_from(["socket-patch", "repair", "--nope"]) {
        Ok(_) => panic!("unknown flag should fail to parse"),
        Err(e) => e,
    };
    assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
}

// --- `gc` is a first-class visible alias for `repair` ---------------------
//
// `scan --sync` is the recommended combined workflow, but `gc`/`repair`
// remain documented commands for users who want to clean up without an
// apply pass. These tests guard the `visible_alias = "gc"` attribute on
// `Commands::Repair` — if a future refactor demotes the alias (to
// `alias = "gc"` or removes it entirely), the help output check below
// will fail.

fn top_level_help() -> String {
    match Cli::try_parse_from(["socket-patch", "--help"]) {
        Ok(_) => panic!("--help should return a clap error (DisplayHelp)"),
        Err(e) => format!("{e}"),
    }
}

#[test]
fn repair_appears_in_top_level_help() {
    let help = top_level_help();
    assert!(
        help.lines().any(|l| l.trim_start().starts_with("repair ")
            || l.trim_start().starts_with("repair\t")),
        "`repair` must be listed in --help output:\n{help}"
    );
}

#[test]
fn gc_alias_is_visible_in_top_level_help() {
    let help = top_level_help();
    assert!(
        help.contains("[aliases: gc]") || help.contains("[alias: gc]"),
        "`gc` visible alias must be listed in --help output:\n{help}"
    );
}

#[test]
fn gc_alias_parses_as_repair() {
    match Cli::try_parse_from(["socket-patch", "gc"]) {
        Ok(cli) => assert!(
            matches!(cli.command, Commands::Repair(_)),
            "gc should resolve to Repair"
        ),
        Err(e) => panic!("gc alias should parse: {e}"),
    }
}
