//! CLI contract tests for the `vex` subcommand's env-bound bool flags, plus
//! the `VexEmbedArgs` twins flattened into `apply` and `scan`.
//!
//! Regression target: `--no-verify` / `--compact` (and `--vex-no-verify` /
//! `--vex-compact`) are env-bound bools (`SOCKET_VEX_NO_VERIFY` /
//! `SOCKET_VEX_COMPACT`). With clap's default bool value parser those env
//! bindings accept only the literal strings `true`/`false`, so the common
//! CI spellings (`SOCKET_VEX_NO_VERIFY=1`) — and the exported-but-empty
//! idiom (`SOCKET_VEX_NO_VERIFY=`) — aborted the parse with a
//! ValueValidation error. Because `VexEmbedArgs` is flattened into `apply`
//! and `scan`, the ambient env var broke those commands too (including
//! `apply` running from a postinstall hook). The fix wires
//! `value_parser = parse_bool_flag`, matching the `GlobalArgs` bool flags
//! and `repair --download-only`. `main`'s empty-var
//! scrub also removes exported-but-empty values (the vars are in
//! `LOCAL_ARG_ENV_VARS`), but these library-level parses bypass `main`, so
//! the value parser must accept the empty string itself.
//!
//! Most tests set a `SOCKET_*` var, and clap reads them during every parse,
//! so every test that parses is `#[serial]`.

use std::path::PathBuf;

use socket_patch_cli::commands::vex::VexArgs;
use socket_patch_cli::{Cli, Commands};

#[path = "common/clap_parse.rs"]
mod clap_parse;
#[path = "common/hermetic.rs"]
mod hermetic;

use clap_parse::{try_parse_with_env, Globals};
use hermetic::try_parse;

fn parse_vex(cli: Result<Cli, clap::Error>) -> VexArgs {
    match cli.expect("parse").command {
        Commands::Vex(a) => a,
        _ => panic!("expected Vex"),
    }
}

/// Every parsed field of `VexArgs`. The tests compare the whole snapshot, so
/// a value landing in a second field fails too.
#[derive(Debug, Clone, PartialEq)]
struct Snap {
    common: Globals,
    output: Option<PathBuf>,
    product: Option<String>,
    no_verify: bool,
    doc_id: Option<String>,
    compact: bool,
}

fn snapshot(a: &VexArgs) -> Snap {
    Snap {
        common: Globals(a.common.clone()),
        output: a.output.clone(),
        product: a.product.clone(),
        no_verify: a.no_verify,
        doc_id: a.doc_id.clone(),
        compact: a.compact,
    }
}

/// The snapshot of bare `vex`, written by hand.
fn expected_defaults() -> Snap {
    Snap {
        common: clap_parse::global_defaults(),
        output: None,
        product: None,
        no_verify: false,
        doc_id: None,
        compact: false,
    }
}

/// The truthy env spellings must work: `SOCKET_VEX_NO_VERIFY=1` must set
/// `vex --no-verify` exactly like the flag, not abort the parse.
#[test]
#[serial_test::serial]
fn truthy_vex_no_verify_env_sets_flag_on_vex() {
    let a = parse_vex(try_parse_with_env(
        &[("SOCKET_VEX_NO_VERIFY", "1")],
        &["socket-patch", "vex"],
    ));
    let mut want = expected_defaults();
    want.no_verify = true;
    assert_eq!(snapshot(&a), want);
}

/// An exported-but-empty `SOCKET_VEX_NO_VERIFY=` — the shell/CI idiom for
/// blanking a variable without unsetting it — must mean "unset, fall back
/// to the default (false)", not abort every `vex` invocation.
#[test]
#[serial_test::serial]
fn empty_vex_no_verify_env_parses_as_false_on_vex() {
    let a = parse_vex(try_parse_with_env(
        &[("SOCKET_VEX_NO_VERIFY", "")],
        &["socket-patch", "vex"],
    ));
    assert_eq!(snapshot(&a), expected_defaults());
}

/// `SOCKET_VEX_COMPACT=1` must set `vex --compact`.
#[test]
#[serial_test::serial]
fn truthy_vex_compact_env_sets_flag_on_vex() {
    let a = parse_vex(try_parse_with_env(
        &[("SOCKET_VEX_COMPACT", "1")],
        &["socket-patch", "vex"],
    ));
    let mut want = expected_defaults();
    want.compact = true;
    assert_eq!(snapshot(&a), want);
}

/// `VexEmbedArgs` shares the env var names with the standalone flags, so an
/// ambient `SOCKET_VEX_NO_VERIFY=1` must also parse (and set
/// `--vex-no-verify`) on `apply` — this is the postinstall-hook blast
/// radius: a parse failure here would abort every `apply` run.
#[test]
#[serial_test::serial]
fn truthy_vex_no_verify_env_sets_embedded_flag_on_apply() {
    let cli = try_parse_with_env(&[("SOCKET_VEX_NO_VERIFY", "1")], &["socket-patch", "apply"])
        .expect("SOCKET_VEX_NO_VERIFY=1 must not abort `apply`");
    match cli.command {
        Commands::Apply(a) => assert!(
            a.vex.vex_no_verify,
            "SOCKET_VEX_NO_VERIFY=1 must set apply's --vex-no-verify"
        ),
        _ => panic!("expected Apply"),
    }
}

/// The empty-var idiom must likewise not abort `scan` (the other
/// `VexEmbedArgs` host), and must leave the embedded flag at its default.
#[test]
#[serial_test::serial]
fn empty_vex_compact_env_parses_as_false_on_scan() {
    let cli = try_parse_with_env(&[("SOCKET_VEX_COMPACT", "")], &["socket-patch", "scan"])
        .expect("empty SOCKET_VEX_COMPACT must not abort `scan`");
    match cli.command {
        Commands::Scan(a) => assert!(!a.vex.vex_compact, "empty SOCKET_VEX_COMPACT must be false"),
        _ => panic!("expected Scan"),
    }
}

/// The explicit CLI flags keep working through the env fix (the custom
/// value parser must not change flag-only usage).
#[test]
#[serial_test::serial]
fn bare_flags_still_parse_without_env() {
    let a = parse_vex(try_parse(&[
        "socket-patch",
        "vex",
        "--no-verify",
        "--compact",
    ]));
    let mut want = expected_defaults();
    want.no_verify = true;
    want.compact = true;
    assert_eq!(snapshot(&a), want);
}

#[test]
#[serial_test::serial]
fn no_vlt_install_cleanup_env_is_accepted_silently_by_vex() {
    let a = parse_vex(try_parse_with_env(
        &[("SOCKET_NO_VLT_INSTALL_CLEANUP", "1")],
        &["socket-patch", "vex"],
    ));
    let mut want = expected_defaults();
    want.common.no_vlt_install_cleanup = true;
    assert_eq!(snapshot(&a), want);
}
