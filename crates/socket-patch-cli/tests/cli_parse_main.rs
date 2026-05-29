//! Top-level `Cli::try_parse_from` behavior tests.
//!
//! These tests cover the parser surface that doesn't fit in
//! `src/lib.rs::tests` — clap's auto-generated help/version handling, the
//! "no subcommand" error kind, every subcommand name, and the
//! visible_alias values (`download` for `get`, `gc` for `repair`).
//!
//! Each subcommand name and alias here is part of the CLI contract
//! defined in `crates/socket-patch-cli/CLI_CONTRACT.md`.

use clap::Parser;
use socket_patch_cli::{Cli, Commands};

fn parse(argv: &[&str]) -> Result<Cli, clap::Error> {
    Cli::try_parse_from(argv)
}

/// Pull the error out of a parse result. `Cli` doesn't derive `Debug`,
/// so `Result::unwrap_err` won't compile — this helper sidesteps that.
fn expect_err(result: Result<Cli, clap::Error>) -> clap::Error {
    match result {
        Ok(_) => panic!("expected parse to fail"),
        Err(e) => e,
    }
}

// ---------- top-level error kinds ----------

#[test]
fn no_subcommand_returns_display_help_on_missing() {
    // clap v4 returns `DisplayHelpOnMissingArgumentOrSubcommand` (not
    // `MissingSubcommand`) for `socket-patch` with no args when a
    // subcommand is required — this is the kind the binary's main.rs
    // handler branches on.
    let err = expect_err(parse(&["socket-patch"]));
    assert_eq!(
        err.kind(),
        clap::error::ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
    );
}

#[test]
fn version_flag_triggers_display_version() {
    let err = expect_err(parse(&["socket-patch", "--version"]));
    assert_eq!(err.kind(), clap::error::ErrorKind::DisplayVersion);
}

#[test]
fn help_flag_triggers_display_help() {
    let err = expect_err(parse(&["socket-patch", "--help"]));
    assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
}

#[test]
fn unknown_subcommand_returns_invalid_subcommand() {
    let err = expect_err(parse(&["socket-patch", "bogus"]));
    assert_eq!(err.kind(), clap::error::ErrorKind::InvalidSubcommand);
}

// ---------- every subcommand name parses ----------

#[test]
fn apply_subcommand_parses() {
    let cli = parse(&["socket-patch", "apply"]).expect("apply must parse with no positional");
    assert!(matches!(cli.command, Commands::Apply(_)));
}

#[test]
fn rollback_subcommand_parses_without_identifier() {
    // rollback's identifier is optional — bare `rollback` must succeed.
    let cli =
        parse(&["socket-patch", "rollback"]).expect("rollback must parse with no positional");
    assert!(matches!(cli.command, Commands::Rollback(_)));
}

#[test]
fn get_subcommand_parses_with_identifier() {
    let cli = parse(&["socket-patch", "get", "some-id"]).expect("get must parse with identifier");
    match cli.command {
        Commands::Get(args) => assert_eq!(args.identifier, "some-id"),
        _ => panic!("expected Commands::Get"),
    }
}

#[test]
fn scan_subcommand_parses() {
    let cli = parse(&["socket-patch", "scan"]).expect("scan must parse with no positional");
    assert!(matches!(cli.command, Commands::Scan(_)));
}

#[test]
fn list_subcommand_parses() {
    let cli = parse(&["socket-patch", "list"]).expect("list must parse with no positional");
    assert!(matches!(cli.command, Commands::List(_)));
}

#[test]
fn remove_subcommand_parses_with_identifier() {
    let cli =
        parse(&["socket-patch", "remove", "some-id"]).expect("remove must parse with identifier");
    match cli.command {
        Commands::Remove(args) => assert_eq!(args.identifier, "some-id"),
        _ => panic!("expected Commands::Remove"),
    }
}

#[test]
fn setup_subcommand_parses() {
    let cli = parse(&["socket-patch", "setup"]).expect("setup must parse with no positional");
    assert!(matches!(cli.command, Commands::Setup(_)));
}

#[test]
fn repair_subcommand_parses() {
    let cli = parse(&["socket-patch", "repair"]).expect("repair must parse with no positional");
    assert!(matches!(cli.command, Commands::Repair(_)));
}

#[test]
fn unlock_subcommand_parses() {
    // `unlock` is one of the two newest subcommands and the second-to-last
    // arm in main.rs's dispatch match — keep its name + dispatch wiring
    // covered alongside the older commands.
    let cli = parse(&["socket-patch", "unlock"]).expect("unlock must parse with no positional");
    assert!(matches!(cli.command, Commands::Unlock(_)));
}

#[test]
fn vex_subcommand_parses() {
    // `vex` is the last arm in main.rs's dispatch match; lock its name in.
    let cli = parse(&["socket-patch", "vex"]).expect("vex must parse with no positional");
    assert!(matches!(cli.command, Commands::Vex(_)));
}

// ---------- visible aliases ----------

#[test]
fn download_alias_parses_as_get() {
    // `download` is the visible_alias for `get` — wrappers in the wild
    // call this name directly, so it has to keep working.
    let cli = parse(&["socket-patch", "download", "some-id"])
        .expect("`download` alias must parse as Get");
    match cli.command {
        Commands::Get(args) => assert_eq!(args.identifier, "some-id"),
        _ => panic!("expected Commands::Get via `download` alias"),
    }
}

#[test]
fn gc_alias_parses_as_repair() {
    // `gc` is the visible_alias for `repair`.
    let cli = parse(&["socket-patch", "gc"]).expect("`gc` alias must parse as Repair");
    assert!(matches!(cli.command, Commands::Repair(_)));
}
