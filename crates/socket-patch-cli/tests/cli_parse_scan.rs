//! Clap parser snapshot tests for `ScanArgs`.
//!
//! These tests lock in the `scan` subcommand's CLI contract — every flag,
//! short form, and default. Changes that flip a default or rename a flag
//! must break these tests so the regression is caught before release.
//!
//! Two defaults are especially load-bearing and explicitly asserted:
//!
//! * `--batch-size` defaults to `100`. Downstream API batching assumes this.
//! * `--download-mode` defaults to `"diff"`. This diverges from `repair`'s
//!   default and is a silent-regression risk if flipped.

use clap::Parser;
use socket_patch_cli::commands::scan::ScanArgs;
use socket_patch_cli::{Cli, Commands};

fn parse_scan(extra: &[&str]) -> ScanArgs {
    let mut argv = vec!["socket-patch", "scan"];
    argv.extend_from_slice(extra);
    let cli = Cli::try_parse_from(&argv).expect("parse");
    match cli.command {
        Commands::Scan(a) => a,
        _ => panic!("expected Scan"),
    }
}

fn try_parse_scan(extra: &[&str]) -> Result<ScanArgs, clap::Error> {
    let mut argv = vec!["socket-patch", "scan"];
    argv.extend_from_slice(extra);
    let cli = Cli::try_parse_from(&argv)?;
    match cli.command {
        Commands::Scan(a) => Ok(a),
        _ => panic!("expected Scan"),
    }
}

#[test]
fn defaults_match_contract() {
    let args = parse_scan(&[]);

    // Critical load-bearing defaults.
    assert_eq!(args.batch_size, 100, "--batch-size default is 100");
    assert_eq!(
        args.download_mode, "diff",
        "--download-mode default is \"diff\""
    );

    // All other defaults from the scan table.
    assert_eq!(args.cwd, std::path::PathBuf::from("."));
    assert_eq!(args.org, None);
    assert!(!args.json);
    assert!(!args.yes);
    assert!(!args.global);
    assert_eq!(args.global_prefix, None);
    assert_eq!(args.api_url, None);
    assert_eq!(args.api_token, None);
    assert_eq!(args.ecosystems, None);
    assert!(!args.apply, "--apply default is false (scan --json stays read-only)");
    assert!(!args.prune, "--prune default is false (GC is opt-in in v3.0)");
    assert!(!args.sync, "--sync default is false");
    assert!(!args.dry_run, "--dry-run default is false");
}

#[test]
fn yes_short_flag() {
    let args = parse_scan(&["-y"]);
    assert!(args.yes);
}

#[test]
fn yes_long_flag() {
    let args = parse_scan(&["--yes"]);
    assert!(args.yes);
}

#[test]
fn global_short_flag() {
    let args = parse_scan(&["-g"]);
    assert!(args.global);
}

#[test]
fn global_long_flag() {
    let args = parse_scan(&["--global"]);
    assert!(args.global);
}

#[test]
fn cwd_flag() {
    let args = parse_scan(&["--cwd", "/tmp/x"]);
    assert_eq!(args.cwd, std::path::PathBuf::from("/tmp/x"));
}

#[test]
fn org_flag() {
    let args = parse_scan(&["--org", "myorg"]);
    assert_eq!(args.org.as_deref(), Some("myorg"));
}

#[test]
fn json_flag() {
    let args = parse_scan(&["--json"]);
    assert!(args.json);
}

#[test]
fn global_prefix_flag() {
    let args = parse_scan(&["--global-prefix", "/foo"]);
    assert_eq!(args.global_prefix, Some(std::path::PathBuf::from("/foo")));
}

#[test]
fn api_url_flag() {
    let args = parse_scan(&["--api-url", "https://api"]);
    assert_eq!(args.api_url.as_deref(), Some("https://api"));
}

#[test]
fn api_token_flag() {
    let args = parse_scan(&["--api-token", "tok"]);
    assert_eq!(args.api_token.as_deref(), Some("tok"));
}

#[test]
fn batch_size_500() {
    let args = parse_scan(&["--batch-size", "500"]);
    assert_eq!(args.batch_size, 500);
}

#[test]
fn batch_size_1() {
    let args = parse_scan(&["--batch-size", "1"]);
    assert_eq!(args.batch_size, 1);
}

#[test]
fn batch_size_0_parses() {
    // Clap accepts 0 as a valid usize. Whether 0 is a sensible batch size is
    // a command-level concern, not a parser concern. Lock in that the parser
    // itself does not reject it.
    let args = parse_scan(&["--batch-size", "0"]);
    assert_eq!(args.batch_size, 0);
}

#[test]
fn batch_size_negative_fails() {
    // Use `--batch-size=-1` (rather than two separate tokens) so clap parses
    // `-1` as the value, not a stray short flag. The value must then fail
    // the usize conversion.
    let err = match try_parse_scan(&["--batch-size=-1"]) {
        Ok(_) => panic!("negative batch-size should fail to parse"),
        Err(e) => e,
    };
    let kind = err.kind();
    assert!(
        matches!(
            kind,
            clap::error::ErrorKind::ValueValidation | clap::error::ErrorKind::InvalidValue
        ),
        "expected ValueValidation or InvalidValue, got {:?}",
        kind
    );
}

#[test]
fn ecosystems_csv_multi() {
    let args = parse_scan(&["--ecosystems", "npm,pypi,cargo,maven"]);
    assert_eq!(
        args.ecosystems,
        Some(vec![
            "npm".to_string(),
            "pypi".to_string(),
            "cargo".to_string(),
            "maven".to_string(),
        ])
    );
}

#[test]
fn ecosystems_csv_single() {
    let args = parse_scan(&["--ecosystems", "npm"]);
    assert_eq!(args.ecosystems, Some(vec!["npm".to_string()]));
}

#[test]
fn download_mode_diff() {
    let args = parse_scan(&["--download-mode", "diff"]);
    assert_eq!(args.download_mode, "diff");
}

#[test]
fn download_mode_package() {
    let args = parse_scan(&["--download-mode", "package"]);
    assert_eq!(args.download_mode, "package");
}

#[test]
fn download_mode_file() {
    let args = parse_scan(&["--download-mode", "file"]);
    assert_eq!(args.download_mode, "file");
}

#[test]
fn unknown_flag_fails() {
    let err = match try_parse_scan(&["--not-a-real-flag"]) {
        Ok(_) => panic!("unknown flag should fail to parse"),
        Err(e) => e,
    };
    assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
}

// --- `--apply` flag and JSON shape ----------------------------------------
//
// `--apply` opts JSON callers into the full discover → select → apply
// pipeline (read-only stays the default for backwards compatibility). The
// subprocess test below also locks in the new `updates` key that bots rely
// on to summarize what would change.

#[test]
fn apply_flag_long_form() {
    let args = parse_scan(&["--apply"]);
    assert!(args.apply);
}

#[test]
fn apply_flag_combines_with_json_and_yes() {
    let args = parse_scan(&["--apply", "--json", "--yes"]);
    assert!(args.apply);
    assert!(args.json);
    assert!(args.yes);
}

// --- `--prune` / `--sync` / `--dry-run` flags (v3.0 GC opt-in) ------------
//
// `--prune` opts into GC. `--sync` is sugar for `--apply --prune`.
// `--dry-run` (`-d`) previews what those flags would do without mutating.

#[test]
fn prune_flag_long_form() {
    let args = parse_scan(&["--prune"]);
    assert!(args.prune);
}

#[test]
fn prune_combines_with_apply_and_json() {
    let args = parse_scan(&["--apply", "--json", "--yes", "--prune"]);
    assert!(args.apply);
    assert!(args.json);
    assert!(args.yes);
    assert!(args.prune);
}

#[test]
fn sync_flag_long_form() {
    let args = parse_scan(&["--sync"]);
    assert!(args.sync);
    // --sync alone doesn't set --apply or --prune (the derivation
    // happens inside scan::run, not at parser time).
    assert!(!args.apply);
    assert!(!args.prune);
}

#[test]
fn sync_combines_with_json_and_yes() {
    let args = parse_scan(&["--json", "--sync", "--yes"]);
    assert!(args.json);
    assert!(args.sync);
    assert!(args.yes);
}

#[test]
fn dry_run_long_form() {
    let args = parse_scan(&["--dry-run"]);
    assert!(args.dry_run);
}

#[test]
fn dry_run_short_form() {
    let args = parse_scan(&["-d"]);
    assert!(args.dry_run);
}

#[test]
fn scan_json_empty_cwd_emits_updates_key() {
    // Spawn the compiled binary against an empty tempdir so no API call
    // happens (no packages found → early return with all-zero summary).
    // This locks in the new `updates: []` field in the JSON contract.
    let bin = env!("CARGO_BIN_EXE_socket-patch");
    let tmp = tempfile::tempdir().expect("tempdir");
    let out = std::process::Command::new(bin)
        .args(["scan", "--json", "--cwd"])
        .arg(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .env_remove("SOCKET_API_URL")
        .output()
        .expect("spawn socket-patch");

    assert_eq!(
        out.status.code(),
        Some(0),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    let v: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("scan emitted valid JSON");

    assert_eq!(v["status"], "success");
    assert_eq!(v["scannedPackages"], 0);
    assert_eq!(v["packagesWithPatches"], 0);
    assert_eq!(v["totalPatches"], 0);
    assert!(
        v["packages"].is_array(),
        "packages must be an array, got {}",
        v["packages"]
    );
    assert!(
        v["updates"].is_array(),
        "updates key must be present and an array — locks contract",
    );
    assert_eq!(
        v["updates"].as_array().unwrap().len(),
        0,
        "updates is empty when no packages were scanned"
    );
}
