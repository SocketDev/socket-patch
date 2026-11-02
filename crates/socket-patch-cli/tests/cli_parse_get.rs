//! Clap parser snapshot tests for the `get` subcommand.
//!
//! These tests pin the public CLI contract for `socket-patch get`: every
//! flag and every default. The v4 spellings `--no-apply` and `download` were
//! removed in v5 and must stay parse errors. Changing any assertion here is a
//! breaking change to the CLI surface — see
//! `crates/socket-patch-cli/CLI_CONTRACT.md`.

use socket_patch_cli::commands::get::GetArgs;
use socket_patch_cli::Commands;
use std::path::PathBuf;

#[path = "common/clap_parse.rs"]
mod clap_parse;
#[path = "common/hermetic.rs"]
mod hermetic;

use clap_parse::Globals;
use hermetic::try_parse;

fn parse_get(extra: &[&str]) -> GetArgs {
    let mut argv = vec!["socket-patch", "get"];
    argv.extend_from_slice(extra);
    let cli = try_parse(&argv).expect("parse");
    match cli.command {
        Commands::Get(a) => a,
        _ => panic!("expected Get"),
    }
}

/// Every parsed field of `GetArgs`. The per-flag tests compare the whole
/// snapshot, so a flag wired to a second field fails too.
#[derive(Debug, Clone, PartialEq)]
struct Snap {
    identifier: String,
    common: Globals,
    id: bool,
    cve: bool,
    ghsa: bool,
    package: bool,
    save_only: bool,
    all_releases: bool,
    mode: Option<socket_patch_cli::commands::scan::ScanMode>,
}

fn snapshot(a: &GetArgs) -> Snap {
    Snap {
        identifier: a.identifier.clone(),
        common: Globals(a.common.clone()),
        id: a.id,
        cve: a.cve,
        ghsa: a.ghsa,
        package: a.package,
        save_only: a.save_only,
        all_releases: a.all_releases,
        mode: a.mode,
    }
}

/// The snapshot of `get <identifier>` with no other flag, written by hand.
fn expected_defaults(identifier: &str) -> Snap {
    Snap {
        identifier: identifier.to_string(),
        common: clap_parse::global_defaults(),
        id: false,
        cve: false,
        ghsa: false,
        package: false,
        save_only: false,
        all_releases: false,
        mode: None,
    }
}

// --- Defaults ----------------------------------------------------------------

#[test]
fn defaults_with_only_required_identifier() {
    let a = parse_get(&["some-id"]);
    assert_eq!(snapshot(&a), expected_defaults("some-id"));
}

#[test]
fn all_releases_flag_sets_all_releases() {
    let a = parse_get(&["some-id", "--all-releases"]);
    let mut want = expected_defaults("some-id");
    want.all_releases = true;
    assert_eq!(snapshot(&a), want);
}

// --- Positional --------------------------------------------------------------

#[test]
fn positional_identifier_stored() {
    let a = parse_get(&["pkg:npm/foo@1.0"]);
    // The positional lands in `identifier` and nothing else shifts.
    assert_eq!(snapshot(&a), expected_defaults("pkg:npm/foo@1.0"));
}

// --- Short flags -------------------------------------------------------------

#[test]
fn short_p_sets_package() {
    let a = parse_get(&["some-id", "-p"]);
    let mut want = expected_defaults("some-id");
    want.package = true;
    assert_eq!(snapshot(&a), want);
}

#[test]
fn long_package_sets_package() {
    let a = parse_get(&["some-id", "--package"]);
    let mut want = expected_defaults("some-id");
    want.package = true;
    assert_eq!(snapshot(&a), want);
}

#[test]
fn short_y_sets_yes() {
    let a = parse_get(&["some-id", "-y"]);
    let mut want = expected_defaults("some-id");
    want.common.yes = true;
    assert_eq!(snapshot(&a), want);
}

#[test]
fn long_yes_sets_yes() {
    let a = parse_get(&["some-id", "--yes"]);
    let mut want = expected_defaults("some-id");
    want.common.yes = true;
    assert_eq!(snapshot(&a), want);
}

#[test]
fn short_g_sets_global() {
    let a = parse_get(&["some-id", "-g"]);
    let mut want = expected_defaults("some-id");
    want.common.global = true;
    assert_eq!(snapshot(&a), want);
}

#[test]
fn long_global_sets_global() {
    let a = parse_get(&["some-id", "--global"]);
    let mut want = expected_defaults("some-id");
    want.common.global = true;
    assert_eq!(snapshot(&a), want);
}

// --- Long-only flags ---------------------------------------------------------

#[test]
fn cwd_flag_sets_cwd() {
    let a = parse_get(&["some-id", "--cwd", "/tmp/project"]);
    let mut want = expected_defaults("some-id");
    want.common.cwd = PathBuf::from("/tmp/project");
    assert_eq!(snapshot(&a), want);
}

#[test]
fn org_flag_sets_org() {
    let a = parse_get(&["some-id", "--org", "acme"]);
    let mut want = expected_defaults("some-id");
    want.common.org = Some("acme".to_string());
    assert_eq!(snapshot(&a), want);
}

#[test]
fn id_flag_sets_id() {
    let a = parse_get(&["some-id", "--id"]);
    let mut want = expected_defaults("some-id");
    want.id = true;
    assert_eq!(snapshot(&a), want);
}

#[test]
fn cve_flag_sets_cve() {
    let a = parse_get(&["some-id", "--cve"]);
    let mut want = expected_defaults("some-id");
    want.cve = true;
    assert_eq!(snapshot(&a), want);
}

#[test]
fn ghsa_flag_sets_ghsa() {
    let a = parse_get(&["some-id", "--ghsa"]);
    let mut want = expected_defaults("some-id");
    want.ghsa = true;
    assert_eq!(snapshot(&a), want);
}

#[test]
fn api_url_flag_sets_api_url() {
    let a = parse_get(&["some-id", "--api-url", "https://api.example.com"]);
    let mut want = expected_defaults("some-id");
    want.common.api_url = Some("https://api.example.com".to_string());
    assert_eq!(snapshot(&a), want);
}

#[test]
fn api_token_flag_sets_api_token() {
    let a = parse_get(&["some-id", "--api-token", "sktsec_abc"]);
    let mut want = expected_defaults("some-id");
    want.common.api_token = Some("sktsec_abc".to_string());
    assert_eq!(snapshot(&a), want);
}

#[test]
fn global_prefix_flag_sets_global_prefix() {
    let a = parse_get(&["some-id", "--global-prefix", "/usr/local/lib"]);
    let mut want = expected_defaults("some-id");
    want.common.global_prefix = Some(PathBuf::from("/usr/local/lib"));
    // `--global-prefix` must NOT imply `--global`; full-snapshot equality keeps
    // `global` pinned at its default.
    assert_eq!(snapshot(&a), want);
}

#[test]
fn json_flag_sets_json() {
    let a = parse_get(&["some-id", "--json"]);
    let mut want = expected_defaults("some-id");
    want.common.json = true;
    assert_eq!(snapshot(&a), want);
}

// --- save-only ------------------------------------------------------------------

#[test]
fn save_only_flag_sets_save_only() {
    let a = parse_get(&["some-id", "--save-only"]);
    let mut want = expected_defaults("some-id");
    want.save_only = true;
    assert_eq!(snapshot(&a), want);
}

#[test]
fn removed_no_apply_alias_is_a_usage_error() {
    // v5 removed the hidden `--no-apply` alias; `--save-only` (or
    // SOCKET_SAVE_ONLY) is the only spelling.
    let err = match try_parse(&["socket-patch", "get", "some-id", "--no-apply"]) {
        Ok(_) => panic!("--no-apply should no longer parse"),
        Err(e) => e,
    };
    assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
}

// --- `--mode` selector (v4.0) --------------------------------------------
//
// `get --mode <hosted|vendored|agent>` reuses scan's `ScanMode` value-enum
// (see cli_parse_scan.rs) so the two commands can never drift on mode
// names. Unlike scan, `get` has no `--sync` shorthand and no
// `resolve_mode_flags` fold — the parsed enum IS the source of truth
// (`None` = agent, today's behavior; the `--save-only` conflict is
// enforced inside `run()`, not by clap — pinned in get_modes_e2e.rs).
// The hidden VALUE aliases (`host`/`redirect` for hosted, `vendor` for
// vendored) ride along from the shared enum and are part of the contract.

#[test]
fn mode_defaults_to_none() {
    // No `--mode` → `None` (agent behavior). Whole-snapshot: the absent
    // flag must leave every field at its default, `mode` included.
    let a = parse_get(&["some-id"]);
    assert_eq!(snapshot(&a), expected_defaults("some-id"));
    assert!(a.mode.is_none(), "unset --mode must parse to None");
}

#[test]
fn mode_hosted_parses() {
    let a = parse_get(&["some-id", "--mode", "hosted"]);
    let mut want = expected_defaults("some-id");
    want.mode = Some(socket_patch_cli::commands::scan::ScanMode::Hosted);
    // Full-snapshot equality: `--mode hosted` sets `mode` and nothing else
    // (in particular it must NOT flip save_only or any GlobalArgs
    // field — the runtime conflicts are run()'s job, not the parser's).
    assert_eq!(snapshot(&a), want);
}

#[test]
fn mode_vendored_parses() {
    let a = parse_get(&["some-id", "--mode", "vendored"]);
    let mut want = expected_defaults("some-id");
    want.mode = Some(socket_patch_cli::commands::scan::ScanMode::Vendored);
    assert_eq!(snapshot(&a), want);
}

#[test]
fn mode_agent_parses() {
    let a = parse_get(&["some-id", "--mode", "agent"]);
    let mut want = expected_defaults("some-id");
    want.mode = Some(socket_patch_cli::commands::scan::ScanMode::Agent);
    assert_eq!(snapshot(&a), want);
}

#[test]
fn removed_mode_value_aliases_are_rejected() {
    // v5.0 dropped the hidden `host` / `redirect` / `vendor` value aliases
    // (shared with `scan --mode`); only the canonical names parse.
    for alias in ["host", "redirect", "vendor"] {
        let err = match try_parse(&["socket-patch", "get", "some-id", "--mode", alias]) {
            Ok(_) => panic!("--mode {alias} should fail to parse"),
            Err(e) => e,
        };
        assert!(
            matches!(
                err.kind(),
                clap::error::ErrorKind::ValueValidation | clap::error::ErrorKind::InvalidValue
            ),
            "--mode {alias}: expected ValueValidation or InvalidValue, got {:?}",
            err.kind()
        );
    }
}

#[test]
fn mode_rejects_unknown_value() {
    // The shared value_enum restricts `--mode` to the three known names.
    // `apply` is not a scan-mode name anywhere, so it must be rejected
    // exactly like a bogus value.
    for bad in ["bogus", "apply"] {
        let err = match try_parse(&["socket-patch", "get", "some-id", "--mode", bad]) {
            Ok(_) => panic!("--mode {bad} should fail to parse"),
            Err(e) => e,
        };
        assert!(
            matches!(
                err.kind(),
                clap::error::ErrorKind::ValueValidation | clap::error::ErrorKind::InvalidValue
            ),
            "--mode {bad}: expected ValueValidation or InvalidValue, got {:?}",
            err.kind()
        );
    }
}

// --- removed `download` alias -------------------------------------------------

#[test]
fn removed_download_alias_is_a_usage_error() {
    // v5 removed the `download` alias for `get`.
    let err = match try_parse(&["socket-patch", "download", "some-id"]) {
        Ok(_) => panic!("`download` should no longer parse"),
        Err(e) => e,
    };
    assert_eq!(err.kind(), clap::error::ErrorKind::InvalidSubcommand);
}

// --- Error paths -------------------------------------------------------------

#[test]
fn missing_required_identifier_errors() {
    let err = match try_parse(&["socket-patch", "get"]) {
        Err(e) => e,
        Ok(_) => panic!("expected parse error for missing required positional"),
    };
    assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
}

#[test]
fn unknown_flag_errors() {
    let err = match try_parse(&["socket-patch", "get", "some-id", "--bogus"]) {
        Err(e) => e,
        Ok(_) => panic!("expected parse error for unknown flag"),
    };
    assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
}

#[test]
fn removed_one_off_flag_is_unknown() {
    let err = match try_parse(&["socket-patch", "get", "some-id", "--one-off"]) {
        Err(e) => e,
        Ok(_) => panic!("expected parse error for the v5-removed --one-off"),
    };
    assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
}

#[test]
fn no_vlt_install_cleanup_flag_parses_for_hosted_get() {
    let a = parse_get(&["some-id", "--mode", "hosted", "--no-vlt-install-cleanup"]);
    let mut want = expected_defaults("some-id");
    want.mode = Some(socket_patch_cli::commands::scan::ScanMode::Hosted);
    want.common.no_vlt_install_cleanup = true;
    assert_eq!(snapshot(&a), want);
}
