//! Top-level `Cli::try_parse_from` behavior tests.
//!
//! These tests cover the parser surface that doesn't fit in
//! `src/lib.rs::tests` — clap's auto-generated help/version handling, the
//! "no subcommand" error kind, every subcommand name, and the
//! visible_alias values (`download` for `get`, `gc` for `repair`).
//!
//! Each subcommand name and alias here is part of the CLI contract
//! defined in `crates/socket-patch-cli/CLI_CONTRACT.md`.

use socket_patch_cli::{parse_with_uuid_fallback, Cli, Commands};

/// Parse through the **production** entry point. `main.rs` does not call
/// `Cli::try_parse_from` directly — it calls `parse_with_uuid_fallback`, which
/// wraps clap with the bare-`<UUID>` → `get <UUID>` rewrite. Driving these
/// tests through the raw clap parser would leave that wrapper entirely
/// uncovered: a regression that swallows clap errors, mis-routes argv, or
/// drops the rewrite would keep every test in this file green while breaking
/// the real CLI. Routing through the wrapper means each name/alias/error-kind
/// assertion below also exercises the code path users actually hit.
fn parse(argv: &[&str]) -> Result<Cli, clap::Error> {
    parse_with_uuid_fallback(argv.iter().map(|s| s.to_string()).collect())
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

    // Kind alone would stay green even if the printed version were stale or
    // hardcoded. The rendered text must carry the *actual* crate version
    // (from Cargo.toml via CARGO_PKG_VERSION), not some frozen literal.
    let rendered = err.to_string();
    let version = env!("CARGO_PKG_VERSION");
    assert!(
        rendered.contains(version),
        "version output {rendered:?} must contain crate version {version:?}"
    );
    assert!(
        rendered.contains("socket-patch"),
        "version output {rendered:?} must name the binary"
    );
}

#[test]
fn help_flag_triggers_display_help() {
    let err = expect_err(parse(&["socket-patch", "--help"]));
    assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);

    // The kind alone is vacuous — a help screen that silently dropped whole
    // commands would still be `DisplayHelp`. Every contract subcommand must be
    // listed in the rendered help.
    let help = err.to_string();
    for name in [
        "apply", "rollback", "get", "scan", "list", "remove", "setup", "repair", "unlock", "vex",
    ] {
        assert!(
            help.contains(name),
            "--help must list the `{name}` subcommand; got:\n{help}"
        );
    }
}

#[test]
fn bare_uuid_is_rewritten_to_get_by_production_wrapper() {
    // Locks the production wrapper into this file's parse path: `parse()` only
    // exercises the real entry point if the bare-`<UUID>` → `get <UUID>`
    // rewrite actually runs. If the wrapper ever regressed to a plain
    // `Cli::try_parse_from` pass-through, a bare UUID would be rejected as an
    // unknown subcommand and this would fail — turning every other test here
    // back into a raw-clap test silently. (The shape predicate itself is
    // covered exhaustively in `src/lib.rs::tests`.)
    let uuid = "80630680-4da6-45f9-bba8-b888e0ffd58c";
    let cli = parse(&["socket-patch", uuid]).expect("bare UUID must rewrite to `get`");
    match cli.command {
        Commands::Get(args) => assert_eq!(args.identifier, uuid),
        _ => panic!("expected Commands::Get via bare-UUID fallback"),
    }
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

/// Render the top-level `--help` text. The aliases this file guards are
/// `visible_alias`es: the contract requires them to be discoverable in
/// `--help`, not merely parseable. A regression from `visible_alias` to a
/// hidden `alias` keeps the parse tests green but silently drops the name
/// from help — so the parse assertions alone are not enough.
fn top_level_help() -> String {
    let err = expect_err(parse(&["socket-patch", "--help"]));
    assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
    err.to_string()
}

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

    // It must be a *visible* alias: clap lists visible aliases on the `get`
    // row as `[aliases: download]`. A hidden alias would not appear here.
    let help = top_level_help();
    assert!(
        help.contains("[aliases: download]"),
        "`download` must be a visible alias of `get` in --help; got:\n{help}"
    );
}

#[test]
fn gc_alias_parses_as_repair() {
    // `gc` is the visible_alias for `repair`.
    let cli = parse(&["socket-patch", "gc"]).expect("`gc` alias must parse as Repair");
    assert!(matches!(cli.command, Commands::Repair(_)));

    // As above: `gc` must remain a visible alias of `repair`.
    let help = top_level_help();
    assert!(
        help.contains("[aliases: gc]"),
        "`gc` must be a visible alias of `repair` in --help; got:\n{help}"
    );
}
