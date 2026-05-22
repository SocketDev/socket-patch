//! Clap parser snapshot tests for the `get` subcommand.
//!
//! These tests pin the public CLI contract for `socket-patch get`: every
//! flag, every alias (including the hidden `--no-apply` and the visible
//! `download` alias), and every default. Changing any assertion here is a
//! breaking change to the CLI surface — see
//! `crates/socket-patch-cli/CLI_CONTRACT.md`.

use clap::Parser;
use socket_patch_cli::commands::get::GetArgs;
use socket_patch_cli::{Cli, Commands};
use std::path::PathBuf;

/// Parse `socket-patch get <extra...>` and return the `GetArgs`.
fn parse_get(extra: &[&str]) -> GetArgs {
    let mut argv = vec!["socket-patch", "get"];
    argv.extend_from_slice(extra);
    let cli = Cli::try_parse_from(&argv).expect("parse");
    match cli.command {
        Commands::Get(a) => a,
        _ => panic!("expected Get"),
    }
}

// --- Defaults ----------------------------------------------------------------

#[test]
fn defaults_with_only_required_identifier() {
    let a = parse_get(&["some-id"]);
    assert_eq!(a.identifier, "some-id");
    assert_eq!(a.common.org, None);
    assert_eq!(a.common.cwd, PathBuf::from("."));
    assert!(!a.id);
    assert!(!a.cve);
    assert!(!a.ghsa);
    assert!(!a.package);
    assert!(!a.common.yes);
    assert_eq!(a.common.api_url, "https://api.socket.dev");
    assert_eq!(a.common.api_token, None);
    assert!(!a.save_only);
    assert!(!a.common.global);
    assert_eq!(a.common.global_prefix, None);
    assert!(!a.one_off);
    assert!(!a.common.json);
    assert_eq!(a.common.download_mode, "diff");
}

#[test]
fn default_download_mode_is_diff() {
    let a = parse_get(&["some-id"]);
    assert_eq!(a.common.download_mode, "diff");
}

// --- Positional --------------------------------------------------------------

#[test]
fn positional_identifier_stored() {
    let a = parse_get(&["pkg:npm/foo@1.0"]);
    assert_eq!(a.identifier, "pkg:npm/foo@1.0");
}

// --- Short flags -------------------------------------------------------------

#[test]
fn short_p_sets_package() {
    let a = parse_get(&["some-id", "-p"]);
    assert!(a.package);
}

#[test]
fn long_package_sets_package() {
    let a = parse_get(&["some-id", "--package"]);
    assert!(a.package);
}

#[test]
fn short_y_sets_yes() {
    let a = parse_get(&["some-id", "-y"]);
    assert!(a.common.yes);
}

#[test]
fn long_yes_sets_yes() {
    let a = parse_get(&["some-id", "--yes"]);
    assert!(a.common.yes);
}

#[test]
fn short_g_sets_global() {
    let a = parse_get(&["some-id", "-g"]);
    assert!(a.common.global);
}

#[test]
fn long_global_sets_global() {
    let a = parse_get(&["some-id", "--global"]);
    assert!(a.common.global);
}

// --- Long-only flags ---------------------------------------------------------

#[test]
fn cwd_flag_sets_cwd() {
    let a = parse_get(&["some-id", "--cwd", "/tmp/project"]);
    assert_eq!(a.common.cwd, PathBuf::from("/tmp/project"));
}

#[test]
fn org_flag_sets_org() {
    let a = parse_get(&["some-id", "--org", "acme"]);
    assert_eq!(a.common.org.as_deref(), Some("acme"));
}

#[test]
fn id_flag_sets_id() {
    let a = parse_get(&["some-id", "--id"]);
    assert!(a.id);
}

#[test]
fn cve_flag_sets_cve() {
    let a = parse_get(&["some-id", "--cve"]);
    assert!(a.cve);
}

#[test]
fn ghsa_flag_sets_ghsa() {
    let a = parse_get(&["some-id", "--ghsa"]);
    assert!(a.ghsa);
}

#[test]
fn api_url_flag_sets_api_url() {
    let a = parse_get(&["some-id", "--api-url", "https://api.example.com"]);
    assert_eq!(a.common.api_url, "https://api.example.com");
}

#[test]
fn api_token_flag_sets_api_token() {
    let a = parse_get(&["some-id", "--api-token", "sktsec_abc"]);
    assert_eq!(a.common.api_token.as_deref(), Some("sktsec_abc"));
}

#[test]
fn global_prefix_flag_sets_global_prefix() {
    let a = parse_get(&["some-id", "--global-prefix", "/usr/local/lib"]);
    assert_eq!(a.common.global_prefix, Some(PathBuf::from("/usr/local/lib")));
}

#[test]
fn one_off_flag_sets_one_off() {
    let a = parse_get(&["some-id", "--one-off"]);
    assert!(a.one_off);
}

#[test]
fn json_flag_sets_json() {
    let a = parse_get(&["some-id", "--json"]);
    assert!(a.common.json);
}

// --- save-only / --no-apply alias -------------------------------------------

#[test]
fn save_only_flag_sets_save_only() {
    let a = parse_get(&["some-id", "--save-only"]);
    assert!(a.save_only);
}

#[test]
fn no_apply_hidden_alias_sets_save_only() {
    // `--no-apply` is a hidden alias for `--save-only`. It does not appear in
    // `--help` but is widely used in existing scripts — this is part of the
    // CLI contract.
    let a = parse_get(&["some-id", "--no-apply"]);
    assert!(a.save_only);
}

// --- download-mode -----------------------------------------------------------

#[test]
fn download_mode_package() {
    let a = parse_get(&["some-id", "--download-mode", "package"]);
    assert_eq!(a.common.download_mode, "package");
}

#[test]
fn download_mode_diff() {
    let a = parse_get(&["some-id", "--download-mode", "diff"]);
    assert_eq!(a.common.download_mode, "diff");
}

#[test]
fn download_mode_file() {
    let a = parse_get(&["some-id", "--download-mode", "file"]);
    assert_eq!(a.common.download_mode, "file");
}

// --- `download` visible alias for `get` -------------------------------------

#[test]
fn download_visible_alias_routes_to_get() {
    let cli =
        Cli::try_parse_from(["socket-patch", "download", "some-id"]).expect("parse");
    match cli.command {
        Commands::Get(a) => {
            assert_eq!(a.identifier, "some-id");
        }
        _ => panic!("expected Get from `download` alias"),
    }
}

// --- Error paths -------------------------------------------------------------

#[test]
fn missing_required_identifier_errors() {
    let err = match Cli::try_parse_from(["socket-patch", "get"]) {
        Err(e) => e,
        Ok(_) => panic!("expected parse error for missing required positional"),
    };
    assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
}

#[test]
fn unknown_flag_errors() {
    let err = match Cli::try_parse_from(["socket-patch", "get", "some-id", "--bogus"])
    {
        Err(e) => e,
        Ok(_) => panic!("expected parse error for unknown flag"),
    };
    assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
}
