//! Parser snapshot tests for `socket-patch rollback`.
//!
//! Pins the public clap surface of `RollbackArgs` — every flag, every short
//! form, and every default. These tests do not invoke the binary; they parse
//! argv directly through `socket_patch_cli::Cli::try_parse_from`. Any change
//! to a flag name, short form, default, or CSV delimiter that breaks one of
//! these tests is a breaking change and requires a MAJOR bump per
//! `crates/socket-patch-cli/CLI_CONTRACT.md`.

use clap::Parser;
use socket_patch_cli::commands::rollback::RollbackArgs;
use socket_patch_cli::{Cli, Commands};
use std::path::PathBuf;

fn parse_rollback(extra: &[&str]) -> RollbackArgs {
    let mut argv = vec!["socket-patch", "rollback"];
    argv.extend_from_slice(extra);
    let cli = Cli::try_parse_from(&argv).expect("parse");
    match cli.command {
        Commands::Rollback(a) => a,
        _ => panic!("expected Rollback"),
    }
}

#[test]
fn defaults_no_positional() {
    let args = parse_rollback(&[]);
    assert_eq!(args.identifier, None);
    assert_eq!(args.common.cwd, PathBuf::from("."));
    assert!(!args.common.dry_run);
    assert!(!args.common.silent);
    assert_eq!(args.common.manifest_path, ".socket/manifest.json");
    assert!(!args.common.offline);
    assert!(!args.common.global);
    assert_eq!(args.common.global_prefix, None);
    assert!(!args.one_off);
    assert_eq!(args.common.org, None);
    assert_eq!(args.common.api_url, "https://api.socket.dev");
    assert_eq!(args.common.api_token, None);
    assert_eq!(args.common.ecosystems, None);
    assert!(!args.common.json);
    assert!(!args.common.verbose);
}

#[test]
fn positional_identifier_uuid() {
    let args = parse_rollback(&["80630680-4da6-45f9-bba8-b888e0ffd58c"]);
    assert_eq!(
        args.identifier,
        Some("80630680-4da6-45f9-bba8-b888e0ffd58c".to_string())
    );
}

#[test]
fn positional_identifier_purl() {
    let args = parse_rollback(&["pkg:npm/foo@1"]);
    assert_eq!(args.identifier, Some("pkg:npm/foo@1".to_string()));
}

#[test]
fn dry_run_short() {
    let args = parse_rollback(&["-d"]);
    assert!(args.common.dry_run);
}

#[test]
fn dry_run_long() {
    let args = parse_rollback(&["--dry-run"]);
    assert!(args.common.dry_run);
}

#[test]
fn silent_short() {
    let args = parse_rollback(&["-s"]);
    assert!(args.common.silent);
}

#[test]
fn silent_long() {
    let args = parse_rollback(&["--silent"]);
    assert!(args.common.silent);
}

#[test]
fn manifest_path_short() {
    let args = parse_rollback(&["-m", "custom.json"]);
    assert_eq!(args.common.manifest_path, "custom.json");
}

#[test]
fn manifest_path_long() {
    let args = parse_rollback(&["--manifest-path", "custom.json"]);
    assert_eq!(args.common.manifest_path, "custom.json");
}

#[test]
fn global_short() {
    let args = parse_rollback(&["-g"]);
    assert!(args.common.global);
}

#[test]
fn global_long() {
    let args = parse_rollback(&["--global"]);
    assert!(args.common.global);
}

#[test]
fn verbose_short() {
    let args = parse_rollback(&["-v"]);
    assert!(args.common.verbose);
}

#[test]
fn verbose_long() {
    let args = parse_rollback(&["--verbose"]);
    assert!(args.common.verbose);
}

#[test]
fn cwd_long() {
    let args = parse_rollback(&["--cwd", "/tmp/x"]);
    assert_eq!(args.common.cwd, PathBuf::from("/tmp/x"));
}

#[test]
fn offline_long() {
    let args = parse_rollback(&["--offline"]);
    assert!(args.common.offline);
}

#[test]
fn json_long() {
    let args = parse_rollback(&["--json"]);
    assert!(args.common.json);
}

#[test]
fn global_prefix_long() {
    let args = parse_rollback(&["--global-prefix", "/foo"]);
    assert_eq!(args.common.global_prefix, Some(PathBuf::from("/foo")));
}

#[test]
fn one_off_long() {
    let args = parse_rollback(&["--one-off"]);
    assert!(args.one_off);
}

#[test]
fn org_long() {
    let args = parse_rollback(&["--org", "myorg"]);
    assert_eq!(args.common.org, Some("myorg".to_string()));
}

#[test]
fn api_url_long() {
    let args = parse_rollback(&["--api-url", "https://api"]);
    assert_eq!(args.common.api_url, "https://api");
}

#[test]
fn api_token_long() {
    let args = parse_rollback(&["--api-token", "tok"]);
    assert_eq!(args.common.api_token, Some("tok".to_string()));
}

#[test]
fn ecosystems_csv_split() {
    let args = parse_rollback(&["--ecosystems", "npm,pypi"]);
    assert_eq!(
        args.common.ecosystems,
        Some(vec!["npm".to_string(), "pypi".to_string()])
    );
}

#[test]
fn positional_plus_flags() {
    let args = parse_rollback(&["pkg:npm/foo@1", "--dry-run", "--json"]);
    assert_eq!(args.identifier, Some("pkg:npm/foo@1".to_string()));
    assert!(args.common.dry_run);
    assert!(args.common.json);
}

#[test]
fn unknown_flag_fails() {
    let err = match Cli::try_parse_from([
        "socket-patch",
        "rollback",
        "--unknown-flag",
    ]) {
        Ok(_) => panic!("expected parse failure"),
        Err(e) => e,
    };
    assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
}
