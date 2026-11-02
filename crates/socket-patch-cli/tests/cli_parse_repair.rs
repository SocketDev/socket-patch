//! CLI contract tests for the `repair` subcommand.
//!
//! These tests pin the public clap parser surface for `RepairArgs`. v5.0
//! removed `--download-mode` (repair always fetches per-file blobs) and the
//! `gc` alias; both must stay parse errors.
//!
//! See `crates/socket-patch-cli/CLI_CONTRACT.md` for the full repair table.
//!
//! Two tests set `SOCKET_DOWNLOAD_ONLY`, and clap reads it during every parse,
//! so every test that parses is `#[serial]`.

use std::path::PathBuf;

use socket_patch_cli::commands::repair::RepairArgs;
use socket_patch_cli::Commands;

#[path = "common/clap_parse.rs"]
mod clap_parse;
#[path = "common/hermetic.rs"]
mod hermetic;

use clap_parse::{try_parse_with_env, Globals};
use hermetic::try_parse;

fn parse_repair(extra: &[&str]) -> RepairArgs {
    let mut argv = vec!["socket-patch", "repair"];
    argv.extend_from_slice(extra);
    let cli = try_parse(&argv).expect("parse");
    match cli.command {
        Commands::Repair(a) => a,
        _ => panic!("expected Repair"),
    }
}

/// Every parsed field of `RepairArgs`. The tests compare the whole snapshot,
/// so a flag wired to a second field fails too.
#[derive(Debug, Clone, PartialEq)]
struct Snap {
    common: Globals,
    download_only: bool,
}

fn snapshot(a: &RepairArgs) -> Snap {
    Snap {
        common: Globals(a.common.clone()),
        download_only: a.download_only,
    }
}

/// The snapshot of bare `repair`, written by hand.
fn expected_defaults() -> Snap {
    Snap {
        common: clap_parse::global_defaults(),
        download_only: false,
    }
}

#[test]
#[serial_test::serial]
fn repair_defaults_match_contract() {
    let args = parse_repair(&[]);
    assert_eq!(snapshot(&args), expected_defaults());
}

#[test]
#[serial_test::serial]
fn repair_dry_run_long_flag() {
    let args = parse_repair(&["--dry-run"]);
    // The flag flips dry_run and *nothing else* — anything but this exact
    // one-field delta from the defaults is a regression.
    let mut expected = expected_defaults();
    expected.common.dry_run = true;
    assert_eq!(snapshot(&args), expected);
}

#[test]
#[serial_test::serial]
fn repair_manifest_path_long_flag() {
    let args = parse_repair(&["--manifest-path", "custom.json"]);
    let mut expected = expected_defaults();
    expected.common.manifest_path = "custom.json".to_string();
    assert_eq!(snapshot(&args), expected);
}

#[test]
#[serial_test::serial]
fn repair_cwd_flag() {
    let args = parse_repair(&["--cwd", "/tmp/x"]);
    let mut expected = expected_defaults();
    expected.common.cwd = PathBuf::from("/tmp/x");
    assert_eq!(snapshot(&args), expected);
}

#[test]
#[serial_test::serial]
fn repair_offline_flag() {
    let args = parse_repair(&["--offline"]);
    let mut expected = expected_defaults();
    expected.common.offline = true;
    assert_eq!(snapshot(&args), expected);
}

#[test]
#[serial_test::serial]
fn repair_download_only_flag() {
    let args = parse_repair(&["--download-only"]);
    let mut expected = expected_defaults();
    expected.download_only = true;
    assert_eq!(snapshot(&args), expected);
}

#[test]
#[serial_test::serial]
fn repair_json_flag() {
    let args = parse_repair(&["--json"]);
    let mut expected = expected_defaults();
    expected.common.json = true;
    assert_eq!(snapshot(&args), expected);
}

/// v5.0 removed `--download-mode`: repair always fetches per-file blobs.
#[test]
#[serial_test::serial]
fn repair_download_mode_flag_is_removed() {
    match try_parse(&["socket-patch", "repair", "--download-mode", "file"]) {
        Ok(_) => panic!("--download-mode must be rejected"),
        Err(err) => assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument),
    }
}

/// Regression: an exported-but-empty `SOCKET_DOWNLOAD_ONLY=` — the shell/CI
/// idiom for blanking a variable without unsetting it — must mean "unset,
/// fall back to the default (false)", not abort every `repair` invocation
/// with a ValueValidation error. The flattened `GlobalArgs` bool flags
/// already have this semantic via `parse_bool_flag`; `repair`'s own
/// `--download-only` env binding must match. (`main`'s empty-var scrub also
/// removes a blank `SOCKET_DOWNLOAD_ONLY` via `LOCAL_ARG_ENV_VARS`, but the
/// parser itself must not depend on it — library callers of `Cli::parse`
/// never run the scrub, and neither does this test's parse.)
#[test]
#[serial_test::serial]
fn empty_download_only_env_var_parses_as_false_not_crash() {
    let parsed = try_parse_with_env(&[("SOCKET_DOWNLOAD_ONLY", "")], &["socket-patch", "repair"]);
    let cli = parsed.expect("empty SOCKET_DOWNLOAD_ONLY must not abort the parse");
    match cli.command {
        Commands::Repair(a) => assert!(
            !a.download_only,
            "empty SOCKET_DOWNLOAD_ONLY must resolve to false"
        ),
        _ => panic!("expected Repair"),
    }
}

/// The truthy env spellings keep working through the empty-string fix:
/// `SOCKET_DOWNLOAD_ONLY=1` must set the flag exactly like `--download-only`.
#[test]
#[serial_test::serial]
fn truthy_download_only_env_var_sets_flag() {
    let parsed = try_parse_with_env(
        &[("SOCKET_DOWNLOAD_ONLY", "1")],
        &["socket-patch", "repair"],
    );
    let cli = parsed.expect("SOCKET_DOWNLOAD_ONLY=1 must parse");
    match cli.command {
        Commands::Repair(a) => assert!(a.download_only),
        _ => panic!("expected Repair"),
    }
}

#[test]
#[serial_test::serial]
fn repair_unknown_flag_is_unknown_argument_error() {
    let err = match try_parse(&["socket-patch", "repair", "--nope"]) {
        Ok(_) => panic!("unknown flag should fail to parse"),
        Err(e) => e,
    };
    assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
}

// --- `repair` in help; the removed `gc` alias -------------------------------
//
// `scan --mode agent --prune` (or `--sync`) combines apply and GC in one
// pass, but `repair` remains a documented command for users who want to
// clean up without an apply pass. v5 removed its `gc` alias.

fn top_level_help() -> String {
    match try_parse(&["socket-patch", "--help"]) {
        Ok(_) => panic!("--help should return a clap error (DisplayHelp)"),
        Err(e) => format!("{e}"),
    }
}

#[test]
#[serial_test::serial]
fn repair_appears_in_top_level_help() {
    let help = top_level_help();
    assert!(
        help.lines().any(
            |l| l.trim_start().starts_with("repair ") || l.trim_start().starts_with("repair\t")
        ),
        "`repair` must be listed in --help output:\n{help}"
    );
}

#[test]
#[serial_test::serial]
fn removed_gc_alias_is_a_usage_error() {
    let help = top_level_help();
    assert!(!help.contains("[aliases: gc]"), "{help}");
    match try_parse(&["socket-patch", "gc"]) {
        Ok(_) => panic!("`gc` should no longer parse"),
        Err(e) => assert_eq!(e.kind(), clap::error::ErrorKind::InvalidSubcommand),
    }
}

#[test]
#[serial_test::serial]
fn no_vlt_install_cleanup_is_accepted_silently_by_repair() {
    let mut expected = expected_defaults();
    expected.common.no_vlt_install_cleanup = true;
    assert_eq!(
        snapshot(&parse_repair(&["--no-vlt-install-cleanup"])),
        expected
    );
}
