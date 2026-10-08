//! Top-level `Cli::try_parse_from` behavior tests.
//!
//! These tests cover the parser surface that doesn't fit in
//! `src/lib.rs::tests` — clap's auto-generated help/version handling, the
//! "no subcommand" error kind, every subcommand name, and the v4
//! spellings v5 removed (`download`, `gc`, `scan --apply`/`--vendor`,
//! `get --no-apply`), which must stay usage errors.
//!
//! Each subcommand name and alias here is part of the CLI contract
//! defined in `crates/socket-patch-cli/CLI_CONTRACT.md`.

use socket_patch_cli::{parse_argv_with_shortcuts, Cli, Commands};

#[path = "common/hermetic.rs"]
mod hermetic;

/// Parse through the **production** entry point. `main.rs` does not call
/// `Cli::try_parse_from` directly — it calls `parse_argv_with_shortcuts`, which
/// wraps clap with the bare-`<UUID>` → `get <UUID>` rewrite. Driving these
/// tests through the raw clap parser would leave that wrapper entirely
/// uncovered: a regression that swallows clap errors, mis-routes argv, or
/// drops the rewrite would keep every test in this file green while breaking
/// the real CLI. Routing through the wrapper means each name/alias/error-kind
/// assertion below also exercises the code path users actually hit.
fn parse(argv: &[&str]) -> Result<Cli, clap::Error> {
    parse_argv_with_shortcuts(argv.iter().map(|s| s.to_string()).collect())
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
        "scan", "apply", "vex", "vendor", "rollback", "get", "list", "remove", "repair",
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
    let cli = parse(&["socket-patch", "rollback"]).expect("rollback must parse with no positional");
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
fn setup_subcommand_is_removed() {
    // BREAKING (5.0): `setup` (the npm/Python/Bundler/Composer install
    // hooks) was removed. Agent mode wires `socket-patch apply` into CI
    // instead. Pin the removal so the name can't quietly come back.
    let err = expect_err(parse(&["socket-patch", "setup"]));
    assert_eq!(err.kind(), clap::error::ErrorKind::InvalidSubcommand);
    // B76: clap's typo tip pointed at the hidden `self-update`; the error
    // names the removal and the replacement instead.
    let text = err.to_string();
    assert!(text.contains("removed in v5.0"), "{text}");
    assert!(text.contains("socket-patch apply"), "{text}");
    assert!(!text.contains("self-update"), "{text}");
}

#[test]
fn repair_subcommand_parses() {
    let cli = parse(&["socket-patch", "repair"]).expect("repair must parse with no positional");
    assert!(matches!(cli.command, Commands::Repair(_)));
}

#[test]
fn unlock_subcommand_is_removed() {
    // BREAKING (4.0): the `unlock` subcommand was removed. A leftover
    // lock never blocks acquisition (the OS releases a dead holder's
    // advisory lock) and every mutating command now unlinks its own
    // `apply.lock` on exit, so there is no stale-lock state to clear.
    // Pin the removal so the name can't quietly come back half-wired.
    let err = expect_err(parse(&["socket-patch", "unlock"]));
    assert_eq!(err.kind(), clap::error::ErrorKind::InvalidSubcommand);
    let text = err.to_string();
    assert!(text.contains("removed in v4.0"), "{text}");
    assert!(!text.contains("self-update"), "{text}");
}

#[test]
fn unknown_subcommand_never_suggests_a_hidden_one() {
    // B76: the hidden `self-update` / `hosted-bundle` carry no stability
    // guarantee, so clap must not offer them as typo fixes. `update`
    // points at the public `--update` flag instead.
    for typo in ["update", "self-updat", "hosted-bundl"] {
        let err = expect_err(parse(&["socket-patch", typo]));
        assert_eq!(
            err.kind(),
            clap::error::ErrorKind::InvalidSubcommand,
            "{typo}"
        );
        let text = err.to_string();
        assert!(!text.contains("'self-update'"), "{typo}: {text}");
        assert!(!text.contains("'hosted-bundle'"), "{typo}: {text}");
        assert!(text.contains(&format!("'{typo}'")), "{typo}: {text}");
    }
    let text = expect_err(parse(&["socket-patch", "update"])).to_string();
    assert!(text.contains("socket-patch --update"), "{text}");
    // A typo of a public subcommand keeps clap's own tip.
    let text = expect_err(parse(&["socket-patch", "scna"])).to_string();
    assert!(text.contains("'scan'"), "{text}");
}

#[test]
fn vex_subcommand_parses() {
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

/// Spellings v5 removed with no deprecation release (#966). Each must be an
/// ordinary clap usage error, and the two former subcommand aliases must be
/// gone from `--help`.
const REMOVED_SPELLINGS: &[&[&str]] = &[
    &["scan", "--apply"],
    &["scan", "--vendor"],
    &["get", "some-id", "--no-apply"],
    &["download", "some-id"],
    &["gc"],
];

#[test]
fn removed_spellings_are_usage_errors() {
    for argv in REMOVED_SPELLINGS {
        let mut full = vec!["socket-patch"];
        full.extend_from_slice(argv);
        let err = expect_err(parse(&full));
        assert!(
            matches!(
                err.kind(),
                clap::error::ErrorKind::UnknownArgument | clap::error::ErrorKind::InvalidSubcommand
            ),
            "{argv:?}: expected a usage error, got {:?}",
            err.kind()
        );
        assert_eq!(err.exit_code(), 2, "{argv:?}");
    }
    let help = top_level_help();
    assert!(
        !help.contains("aliases"),
        "no subcommand aliases remain; got:\n{help}"
    );
    for line in help.lines() {
        let first = line.split_whitespace().next();
        assert!(
            first != Some("download") && first != Some("gc"),
            "removed alias listed in --help: {line:?}"
        );
    }
}

#[test]
fn removed_spellings_exit_two_through_the_binary() {
    let tmp = tempfile::tempdir().unwrap();
    for argv in REMOVED_SPELLINGS {
        let out = hermetic::binary_command()
            .args(*argv)
            .current_dir(tmp.path())
            .env("SOCKET_TELEMETRY_DISABLED", "1")
            .output()
            .expect("run socket-patch");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{argv:?}: {stderr}");
        assert!(stderr.contains("error:"), "{argv:?}: {stderr}");
    }
}
