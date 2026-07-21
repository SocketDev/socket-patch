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

/// Every boolean toggle on `rollback`, as `(contract name, current value)`.
/// Used to prove that a single flag flips *only* its own field — without this,
/// each positive test ignores all other fields, so a parser bug that
/// cross-wired e.g. `--one-off` into `--global`, `--silent` into `--break-lock`
/// (stealing a live lock), or any flag into another would still stay green.
/// Keep this in sync with the boolean flags in the contract.
fn bool_flags(a: &RollbackArgs) -> Vec<(&'static str, bool)> {
    vec![
        ("dry_run", a.common.dry_run),
        ("silent", a.common.silent),
        ("global", a.common.global),
        ("offline", a.common.offline),
        ("json", a.common.json),
        ("verbose", a.common.verbose),
        ("yes", a.common.yes),
        ("debug", a.common.debug),
        ("no_telemetry", a.common.no_telemetry),
        ("break_lock", a.common.break_lock),
        ("one_off", a.one_off),
    ]
}

/// Assert that exactly the flags named in `expected_true` are set, and every
/// other boolean toggle stayed at its `false` default. Closes the
/// cross-contamination loophole: a flag that silently flips an *extra* field
/// now fails loudly instead of passing because nobody looked.
fn assert_only_true(a: &RollbackArgs, expected_true: &[&str]) {
    for (name, value) in bool_flags(a) {
        let want = expected_true.contains(&name);
        assert_eq!(
            value, want,
            "flag `{name}` = {value}, expected {want} (set flags: {expected_true:?}) \
             — a single flag must not flip any other boolean"
        );
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
    assert_eq!(args.common.api_url, None); // default applied in core resolver
    assert_eq!(args.common.api_token, None);
    assert_eq!(args.common.ecosystems, None);
    assert!(!args.common.json);
    assert!(!args.common.verbose);
    // Remaining global defaults the contract pins but the original test omitted.
    assert_eq!(args.common.proxy_url, None); // default applied in core resolver
    assert_eq!(args.common.download_mode, "diff");
    assert!(!args.common.yes);
    assert_eq!(args.common.lock_timeout, None);
    assert!(!args.common.break_lock);
    assert!(!args.common.debug);
    assert!(!args.common.no_telemetry);
    // Belt-and-suspenders: with no args, NO boolean toggle may be on.
    assert_only_true(&args, &[]);
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
fn dry_run_long() {
    let args = parse_rollback(&["--dry-run"]);
    assert!(args.common.dry_run);
    assert_only_true(&args, &["dry_run"]);
}

#[test]
fn silent_short() {
    let args = parse_rollback(&["-s"]);
    assert!(args.common.silent);
    assert_only_true(&args, &["silent"]);
}

#[test]
fn silent_long() {
    let args = parse_rollback(&["--silent"]);
    assert!(args.common.silent);
    assert_only_true(&args, &["silent"]);
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
    assert_only_true(&args, &["global"]);
}

#[test]
fn global_long() {
    let args = parse_rollback(&["--global"]);
    assert!(args.common.global);
    assert_only_true(&args, &["global"]);
}

#[test]
fn verbose_short() {
    let args = parse_rollback(&["-v"]);
    assert!(args.common.verbose);
    assert_only_true(&args, &["verbose"]);
}

#[test]
fn verbose_long() {
    let args = parse_rollback(&["--verbose"]);
    assert!(args.common.verbose);
    assert_only_true(&args, &["verbose"]);
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
    assert_only_true(&args, &["offline"]);
}

#[test]
fn json_long() {
    let args = parse_rollback(&["--json"]);
    assert!(args.common.json);
    assert_only_true(&args, &["json"]);
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
    // `--one-off` is rollback-specific (fetch beforeHash blobs from API). It
    // must NOT silently imply `--offline`, `--global`, or any other toggle.
    assert_only_true(&args, &["one_off"]);
}

#[test]
fn org_long() {
    let args = parse_rollback(&["--org", "myorg"]);
    assert_eq!(args.common.org, Some("myorg".to_string()));
}

#[test]
fn api_url_long() {
    let args = parse_rollback(&["--api-url", "https://api"]);
    assert_eq!(args.common.api_url.as_deref(), Some("https://api"));
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
    // Exactly these two flags — nothing else rode along on the combination.
    assert_only_true(&args, &["dry_run", "json"]);
}

#[test]
fn org_short() {
    let args = parse_rollback(&["-o", "myorg"]);
    assert_eq!(args.common.org, Some("myorg".to_string()));
}

#[test]
fn ecosystems_short() {
    let args = parse_rollback(&["-e", "npm,pypi"]);
    assert_eq!(
        args.common.ecosystems,
        Some(vec!["npm".to_string(), "pypi".to_string()])
    );
}

#[test]
fn json_short() {
    let args = parse_rollback(&["-j"]);
    assert!(args.common.json);
    assert_only_true(&args, &["json"]);
}

#[test]
fn yes_short() {
    let args = parse_rollback(&["-y"]);
    assert!(args.common.yes);
    assert_only_true(&args, &["yes"]);
}

#[test]
fn yes_long() {
    let args = parse_rollback(&["--yes"]);
    assert!(args.common.yes);
    assert_only_true(&args, &["yes"]);
}

#[test]
fn proxy_url_long() {
    let args = parse_rollback(&["--proxy-url", "https://proxy.example"]);
    assert_eq!(
        args.common.proxy_url.as_deref(),
        Some("https://proxy.example")
    );
}

#[test]
fn download_mode_long() {
    let args = parse_rollback(&["--download-mode", "package"]);
    assert_eq!(args.common.download_mode, "package");
}

#[test]
fn lock_timeout_long() {
    let args = parse_rollback(&["--lock-timeout", "30"]);
    assert_eq!(args.common.lock_timeout, Some(30));
}

#[test]
fn break_lock_long() {
    let args = parse_rollback(&["--break-lock"]);
    assert!(args.common.break_lock);
    assert_only_true(&args, &["break_lock"]);
}

#[test]
fn debug_long() {
    let args = parse_rollback(&["--debug"]);
    assert!(args.common.debug);
    assert_only_true(&args, &["debug"]);
}

#[test]
fn no_telemetry_long() {
    let args = parse_rollback(&["--no-telemetry"]);
    assert!(args.common.no_telemetry);
    assert_only_true(&args, &["no_telemetry"]);
}

/// All boolean toggles set at once: each must independently be true. Catches a
/// regression where two flags share storage (only the last would win) or a
/// flag is dropped entirely.
#[test]
fn all_bools_settable_together() {
    let args = parse_rollback(&[
        "--dry-run",
        "--silent",
        "--global",
        "--offline",
        "--json",
        "--verbose",
        "--yes",
        "--debug",
        "--no-telemetry",
        "--break-lock",
        "--one-off",
    ]);
    assert_only_true(
        &args,
        &[
            "dry_run",
            "silent",
            "global",
            "offline",
            "json",
            "verbose",
            "yes",
            "debug",
            "no_telemetry",
            "break_lock",
            "one_off",
        ],
    );
}

/// All short flags bundled together must each map to their own distinct field.
/// Decisively catches short-flag cross-wiring (e.g. `-g` and `-j` writing the
/// same field) and proves the value-taking shorts (`-o`, `-e`) coexist with
/// the bundled boolean shorts without clobbering each other.
#[test]
fn all_short_flags_map_to_distinct_fields() {
    let args = parse_rollback(&["-sgjvy", "-o", "acme", "-e", "npm,cargo"]);
    assert!(args.common.silent, "-s");
    assert!(args.common.global, "-g");
    assert!(args.common.json, "-j");
    assert!(args.common.verbose, "-v");
    assert!(args.common.yes, "-y");
    assert_eq!(args.common.org.as_deref(), Some("acme"), "-o");
    assert_eq!(
        args.common.ecosystems,
        Some(vec!["npm".to_string(), "cargo".to_string()]),
        "-e"
    );
    assert_only_true(&args, &["silent", "global", "json", "verbose", "yes"]);
}

/// Bare boolean flags are `SetTrue` (num_args = 0): they must NOT swallow the
/// following token as a value. If `--one-off` silently became value-taking, a
/// wrapper invoking `rollback --one-off <purl>` would change meaning (the purl
/// would be consumed as the flag's value, not the `identifier` positional).
#[test]
fn bare_bool_does_not_consume_next_token() {
    let args = parse_rollback(&["--one-off", "pkg:npm/foo@1"]);
    assert!(args.one_off);
    // The trailing token landed in `identifier`, not as a value for `--one-off`.
    assert_eq!(args.identifier, Some("pkg:npm/foo@1".to_string()));
    assert_only_true(&args, &["one_off"]);
}

/// A second positional is rejected — `identifier` takes exactly one value, so
/// a stray extra arg must not be silently swallowed.
#[test]
fn second_positional_fails() {
    let err = match Cli::try_parse_from(["socket-patch", "rollback", "a", "b"]) {
        Ok(_) => panic!("expected parse failure for extra positional"),
        Err(e) => e,
    };
    assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
}

#[test]
fn unknown_flag_fails() {
    let err = match Cli::try_parse_from(["socket-patch", "rollback", "--unknown-flag"]) {
        Ok(_) => panic!("expected parse failure"),
        Err(e) => e,
    };
    assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
}
