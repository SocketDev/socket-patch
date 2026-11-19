//! CLI contract tests for the `show` subcommand.
//!
//! These tests pin the public clap parser surface for `ShowArgs`: the
//! required positional identifier and the three local flags.
//!
//! See `crates/socket-patch-cli/CLI_CONTRACT.md` ("`show`: inspect a patch").
//!
//! clap reads the flag-bound environment during every parse, so every test
//! that parses is `#[serial]`.

use socket_patch_cli::commands::show::ShowArgs;
use socket_patch_cli::Commands;

#[path = "common/clap_parse.rs"]
mod clap_parse;
#[path = "common/hermetic.rs"]
mod hermetic;

use clap_parse::Globals;
use hermetic::try_parse;

const UUID: &str = "8be53d06-7bd4-40cc-ab8f-36dc6248985a";

fn parse_show(extra: &[&str]) -> ShowArgs {
    let mut argv = vec!["socket-patch", "show"];
    argv.extend_from_slice(extra);
    let cli = try_parse(&argv).expect("parse");
    match cli.command {
        Commands::Show(a) => a,
        _ => panic!("expected Show"),
    }
}

/// Every parsed field of `ShowArgs`. The tests compare the whole snapshot,
/// so a flag wired to a second field fails too.
#[derive(Debug, Clone, PartialEq)]
struct Snap {
    identifier: String,
    common: Globals,
    files: Vec<String>,
    stat: bool,
    no_pager: bool,
}

fn snapshot(a: &ShowArgs) -> Snap {
    Snap {
        identifier: a.identifier.clone(),
        common: Globals(a.common.clone()),
        files: a.files.clone(),
        stat: a.stat,
        no_pager: a.no_pager,
    }
}

/// The snapshot of `show <UUID>`, written by hand.
fn expected_defaults() -> Snap {
    Snap {
        identifier: UUID.to_string(),
        common: clap_parse::global_defaults(),
        files: Vec::new(),
        stat: false,
        no_pager: false,
    }
}

#[test]
#[serial_test::serial]
fn show_defaults_match_contract() {
    assert_eq!(snapshot(&parse_show(&[UUID])), expected_defaults());
}

#[test]
#[serial_test::serial]
fn show_requires_an_identifier() {
    let err = match try_parse(&["socket-patch", "show"]) {
        Ok(_) => panic!("`show` without an identifier must not parse"),
        Err(e) => e,
    };
    assert_eq!(
        err.kind(),
        clap::error::ErrorKind::MissingRequiredArgument,
        "{err}"
    );
}

#[test]
#[serial_test::serial]
fn show_takes_any_target_token_verbatim() {
    for token in [
        "pkg:npm/lodash@4.17.20",
        "lodash",
        "CVE-2021-23337",
        "GHSA-35jh-r3h4-6jhm",
    ] {
        let mut expected = expected_defaults();
        expected.identifier = token.to_string();
        assert_eq!(snapshot(&parse_show(&[token])), expected, "{token}");
    }
}

#[test]
#[serial_test::serial]
fn show_file_flag_repeats() {
    let args = parse_show(&[UUID, "--file", "lib/a.js", "--file", "b.js"]);
    let mut expected = expected_defaults();
    expected.files = vec!["lib/a.js".to_string(), "b.js".to_string()];
    assert_eq!(snapshot(&args), expected);
}

#[test]
#[serial_test::serial]
fn show_stat_flag() {
    let args = parse_show(&[UUID, "--stat"]);
    let mut expected = expected_defaults();
    expected.stat = true;
    assert_eq!(snapshot(&args), expected);
}

#[test]
#[serial_test::serial]
fn show_no_pager_flag() {
    let args = parse_show(&[UUID, "--no-pager"]);
    let mut expected = expected_defaults();
    expected.no_pager = true;
    assert_eq!(snapshot(&args), expected);
}

#[test]
#[serial_test::serial]
fn show_json_flag_is_the_global_one() {
    let args = parse_show(&[UUID, "--json"]);
    let mut expected = expected_defaults();
    expected.common.json = true;
    assert_eq!(snapshot(&args), expected);
}
