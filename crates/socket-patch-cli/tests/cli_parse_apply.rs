//! Parser snapshot tests for the `apply` subcommand.
//!
//! These tests pin **every flag name, short form, and default value**
//! listed in `crates/socket-patch-cli/CLI_CONTRACT.md` for `apply`. A
//! rename, dropped short form, or default-value drift fails here loudly
//! instead of silently breaking the npm/pypi/cargo wrappers and CI
//! scripts that depend on the surface.

use std::path::PathBuf;

use clap::Parser;
use socket_patch_cli::commands::apply::ApplyArgs;
use socket_patch_cli::{Cli, Commands};

/// Parse `socket-patch apply <extra...>` and return the inner `ApplyArgs`.
/// Panics if parsing fails or yields a non-`Apply` subcommand — tests for
/// the failure path call `Cli::try_parse_from` directly.
fn parse_apply(extra: &[&str]) -> ApplyArgs {
    let mut argv: Vec<&str> = vec!["socket-patch", "apply"];
    argv.extend_from_slice(extra);
    let cli = Cli::try_parse_from(&argv).expect("parse");
    match cli.command {
        Commands::Apply(a) => a,
        _ => panic!("expected Apply"),
    }
}

// ---------------------------------------------------------------------------
// Defaults — every default value from the contract table is pinned here.
// ---------------------------------------------------------------------------

#[test]
fn defaults_match_contract() {
    let a = parse_apply(&[]);
    assert_eq!(a.cwd, PathBuf::from("."));
    assert!(!a.dry_run);
    assert!(!a.silent);
    assert_eq!(a.manifest_path, ".socket/manifest.json");
    assert!(!a.offline);
    assert!(!a.global);
    assert_eq!(a.global_prefix, None);
    assert_eq!(a.ecosystems, None);
    assert!(!a.force);
    assert!(!a.json);
    assert!(!a.verbose);
    assert_eq!(a.download_mode, "diff");
}

/// The `download_mode` default is pinned separately — it's the one
/// field whose default value diverges across subcommands historically,
/// so we assert it explicitly to catch drift.
#[test]
fn default_download_mode_is_diff() {
    assert_eq!(parse_apply(&[]).download_mode, "diff");
}

/// The `manifest_path` default is contract — many scripts hard-code
/// `.socket/manifest.json` as the canonical location.
#[test]
fn default_manifest_path_is_dot_socket_manifest_json() {
    assert_eq!(parse_apply(&[]).manifest_path, ".socket/manifest.json");
}

// ---------------------------------------------------------------------------
// Boolean flags — long form, then short form (where applicable).
// ---------------------------------------------------------------------------

#[test]
fn dry_run_long() {
    assert!(parse_apply(&["--dry-run"]).dry_run);
}

#[test]
fn dry_run_short() {
    assert!(parse_apply(&["-d"]).dry_run);
}

#[test]
fn silent_long() {
    assert!(parse_apply(&["--silent"]).silent);
}

#[test]
fn silent_short() {
    assert!(parse_apply(&["-s"]).silent);
}

#[test]
fn global_long() {
    assert!(parse_apply(&["--global"]).global);
}

#[test]
fn global_short() {
    assert!(parse_apply(&["-g"]).global);
}

#[test]
fn force_long() {
    assert!(parse_apply(&["--force"]).force);
}

#[test]
fn force_short() {
    assert!(parse_apply(&["-f"]).force);
}

#[test]
fn verbose_long() {
    assert!(parse_apply(&["--verbose"]).verbose);
}

#[test]
fn verbose_short() {
    assert!(parse_apply(&["-v"]).verbose);
}

#[test]
fn offline_long() {
    assert!(parse_apply(&["--offline"]).offline);
}

#[test]
fn json_long() {
    assert!(parse_apply(&["--json"]).json);
}

// ---------------------------------------------------------------------------
// Value flags — long form, then short form (where applicable).
// ---------------------------------------------------------------------------

#[test]
fn cwd_long() {
    assert_eq!(parse_apply(&["--cwd", "/tmp/x"]).cwd, PathBuf::from("/tmp/x"));
}

#[test]
fn manifest_path_long() {
    assert_eq!(
        parse_apply(&["--manifest-path", "custom.json"]).manifest_path,
        "custom.json"
    );
}

#[test]
fn manifest_path_short() {
    assert_eq!(parse_apply(&["-m", "custom.json"]).manifest_path, "custom.json");
}

#[test]
fn global_prefix_long() {
    assert_eq!(
        parse_apply(&["--global-prefix", "/foo"]).global_prefix,
        Some(PathBuf::from("/foo"))
    );
}

// ---------------------------------------------------------------------------
// --ecosystems CSV split — the contract is that a comma-delimited value
// expands into a Vec<String>. Wrappers rely on this single-flag form.
// ---------------------------------------------------------------------------

#[test]
fn ecosystems_csv_splits_into_vec() {
    assert_eq!(
        parse_apply(&["--ecosystems", "npm,pypi,cargo"]).ecosystems,
        Some(vec!["npm".to_string(), "pypi".to_string(), "cargo".to_string()])
    );
}

#[test]
fn ecosystems_single_value() {
    assert_eq!(
        parse_apply(&["--ecosystems", "npm"]).ecosystems,
        Some(vec!["npm".to_string()])
    );
}

// ---------------------------------------------------------------------------
// --download-mode — accepted token values are documented contract.
// ---------------------------------------------------------------------------

#[test]
fn download_mode_diff() {
    assert_eq!(parse_apply(&["--download-mode", "diff"]).download_mode, "diff");
}

#[test]
fn download_mode_package() {
    assert_eq!(
        parse_apply(&["--download-mode", "package"]).download_mode,
        "package"
    );
}

#[test]
fn download_mode_file() {
    assert_eq!(parse_apply(&["--download-mode", "file"]).download_mode, "file");
}

// ---------------------------------------------------------------------------
// Failure path — unknown flags must produce a clap UnknownArgument error.
// This guards against accidentally accepting a typo via positional fallback.
// ---------------------------------------------------------------------------

#[test]
fn unknown_flag_fails_with_unknown_argument() {
    // `Cli` doesn't implement `Debug`, so we can't use `.expect_err()` —
    // match the Result by hand.
    match Cli::try_parse_from(["socket-patch", "apply", "--unknown-flag"]) {
        Ok(_) => panic!("--unknown-flag must be rejected"),
        Err(err) => {
            assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
        }
    }
}
