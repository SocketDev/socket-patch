//! CLI contract tests for the `report` subcommand.
//!
//! These tests pin the public clap parser surface for `ReportArgs`: the
//! required patch targets, `--reason` with its default, and `--message`.
//!
//! See `crates/socket-patch-cli/CLI_CONTRACT.md` ("`report`: report a
//! broken patch").
//!
//! clap reads the flag-bound environment during every parse, so every test
//! that parses is `#[serial]`.

use socket_patch_cli::commands::report::{Reason, ReportArgs};
use socket_patch_cli::Commands;

#[path = "common/clap_parse.rs"]
mod clap_parse;
#[path = "common/hermetic.rs"]
mod hermetic;

use clap_parse::Globals;
use hermetic::try_parse;

const UUID: &str = "8be53d06-7bd4-40cc-ab8f-36dc6248985a";

fn parse_report(extra: &[&str]) -> ReportArgs {
    let mut argv = vec!["socket-patch", "report"];
    argv.extend_from_slice(extra);
    let cli = try_parse(&argv).expect("parse");
    match cli.command {
        Commands::Report(a) => a,
        _ => panic!("expected Report"),
    }
}

/// Every parsed field of `ReportArgs`. The tests compare the whole
/// snapshot, so a flag wired to a second field fails too.
#[derive(Debug, Clone, PartialEq)]
struct Snap {
    targets: Vec<String>,
    reason: Reason,
    message: Option<String>,
    common: Globals,
}

fn snapshot(a: &ReportArgs) -> Snap {
    Snap {
        targets: a.targets.clone(),
        reason: a.reason,
        message: a.message.clone(),
        common: Globals(a.common.clone()),
    }
}

/// The snapshot of `report <UUID>`, written by hand.
fn expected_defaults() -> Snap {
    Snap {
        targets: vec![UUID.to_string()],
        reason: Reason::Other,
        message: None,
        common: clap_parse::global_defaults(),
    }
}

#[test]
#[serial_test::serial]
fn a_patch_alone_reports_it_as_other() {
    assert_eq!(snapshot(&parse_report(&[UUID])), expected_defaults());
}

#[test]
#[serial_test::serial]
fn several_patches_a_reason_and_a_message_parse() {
    let args = parse_report(&[
        UUID,
        "lodash",
        "--reason",
        "runtime",
        "--message",
        "it hangs",
    ]);
    assert_eq!(
        snapshot(&args),
        Snap {
            targets: vec![UUID.to_string(), "lodash".to_string()],
            reason: Reason::Runtime,
            message: Some("it hangs".to_string()),
            ..expected_defaults()
        }
    );
}

#[test]
#[serial_test::serial]
fn every_reason_parses_by_its_word() {
    for (word, reason) in [
        ("build", Reason::Build),
        ("tests", Reason::Tests),
        ("runtime", Reason::Runtime),
        ("other", Reason::Other),
    ] {
        assert_eq!(parse_report(&[UUID, "--reason", word]).reason, reason);
    }
}

/// A report about no patch, or with a reason that is not one of the four,
/// is a usage error.
#[test]
#[serial_test::serial]
fn no_patch_or_an_unknown_reason_is_a_usage_error() {
    let missing = try_parse(&["socket-patch", "report"])
        .err()
        .expect("no patch named");
    assert_eq!(
        missing.kind(),
        clap::error::ErrorKind::MissingRequiredArgument
    );
    let unknown = try_parse(&["socket-patch", "report", UUID, "--reason", "works"])
        .err()
        .expect("an unknown reason");
    assert_eq!(unknown.kind(), clap::error::ErrorKind::InvalidValue);
}
