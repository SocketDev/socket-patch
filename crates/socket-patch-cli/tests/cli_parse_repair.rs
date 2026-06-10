//! CLI contract tests for the `repair` subcommand (and its `gc` visible alias).
//!
//! These tests pin the public clap parser surface for `RepairArgs`. In v3.0
//! `repair`'s `--download-mode` aligns with every other command (default
//! `"diff"`); the legacy `"file"` default was retired so the surface stays
//! uniform. Users that need legacy per-file blob downloads opt in with
//! `--download-mode file`. The `gc` visible alias is also exercised so a
//! refactor that drops it is caught immediately.
//!
//! See `crates/socket-patch-cli/CLI_CONTRACT.md` for the full repair table.
//!
//! ## Hermeticity
//!
//! Every flag and default below is also wired to an `#[arg(env = "SOCKET_*")]`
//! source. clap reads those env vars during `try_parse_from`, so an ambient
//! `SOCKET_*` variable in the developer's shell or in CI would silently
//! satisfy these assertions even if the corresponding CLI default
//! (`default_value`/`default_value_t`) regressed or a flag's action broke —
//! the env value would mask the bug and the test would pass for the wrong
//! reason (e.g. an exported `SOCKET_DOWNLOAD_MODE=diff` keeps the default
//! assertion green even if the clap `default_value` were changed to `"file"`).
//! To make the assertions test *argv parsing* rather than the ambient
//! environment, every parse runs with the full set of `SOCKET_*` vars scrubbed
//! (see [`EnvScrub`]). Because the environment is process-global, every test is
//! `#[serial_test::serial]` so the scrub/restore dance can't race a concurrent
//! parse. This mirrors the hardening in `cli_parse_get.rs`.

use std::path::PathBuf;

use clap::Parser;
use socket_patch_cli::commands::repair::RepairArgs;
use socket_patch_cli::{Cli, Commands};
use socket_patch_core::api::blob_fetcher::DownloadMode;

/// Every `SOCKET_*` env var that clap consults while parsing `repair` (its own
/// `--download-only` flag plus the flattened `GlobalArgs`). If any leaks in
/// from the ambient environment it can mask a broken default or a regressed
/// flag, so the parse helpers below remove them for the duration of the parse.
const SOCKET_ENV_VARS: &[&str] = &[
    // GlobalArgs
    "SOCKET_CWD",
    "SOCKET_MANIFEST_PATH",
    "SOCKET_API_URL",
    "SOCKET_API_TOKEN",
    "SOCKET_ORG_SLUG",
    "SOCKET_PROXY_URL",
    "SOCKET_ECOSYSTEMS",
    "SOCKET_DOWNLOAD_MODE",
    "SOCKET_OFFLINE",
    "SOCKET_GLOBAL",
    "SOCKET_GLOBAL_PREFIX",
    "SOCKET_JSON",
    "SOCKET_VERBOSE",
    "SOCKET_SILENT",
    "SOCKET_DRY_RUN",
    "SOCKET_YES",
    "SOCKET_LOCK_TIMEOUT",
    "SOCKET_BREAK_LOCK",
    "SOCKET_DEBUG",
    "SOCKET_TELEMETRY_DISABLED",
    // RepairArgs-specific
    "SOCKET_DOWNLOAD_ONLY",
];

/// RAII guard that removes every [`SOCKET_ENV_VARS`] entry on construction and
/// restores the prior value on drop. Holding one of these around a clap parse
/// guarantees the parse sees only what's on the argv, not the developer's
/// shell. Pair with `#[serial_test::serial]` so the global env mutation never
/// races another test.
struct EnvScrub(Vec<(&'static str, Option<String>)>);

impl EnvScrub {
    fn new() -> Self {
        let saved = SOCKET_ENV_VARS
            .iter()
            .map(|&k| {
                let prev = std::env::var(k).ok();
                std::env::remove_var(k);
                (k, prev)
            })
            .collect();
        EnvScrub(saved)
    }
}

impl Drop for EnvScrub {
    fn drop(&mut self) {
        for (k, v) in &self.0 {
            match v {
                Some(val) => std::env::set_var(k, val),
                None => std::env::remove_var(k),
            }
        }
    }
}

fn parse_repair(extra: &[&str]) -> RepairArgs {
    let _scrub = EnvScrub::new();
    let mut argv = vec!["socket-patch", "repair"];
    argv.extend_from_slice(extra);
    let cli = Cli::try_parse_from(&argv).expect("parse");
    match cli.command {
        Commands::Repair(a) => a,
        _ => panic!("expected Repair"),
    }
}

fn parse_gc(extra: &[&str]) -> RepairArgs {
    let _scrub = EnvScrub::new();
    let mut argv = vec!["socket-patch", "gc"];
    argv.extend_from_slice(extra);
    let cli = Cli::try_parse_from(&argv).expect("parse");
    match cli.command {
        Commands::Repair(a) => a,
        _ => panic!("expected Repair via gc alias"),
    }
}

/// Owned, comparable snapshot of *every* parsed field in `RepairArgs` — its own
/// `download_only` flag plus every field of the flattened `GlobalArgs`.
/// `RepairArgs`/`GlobalArgs` are production types we may not touch and don't
/// derive `PartialEq`, so this mirror exists purely so a single `assert_eq!`
/// can police the entire parsed surface at once.
///
/// This is what makes the defaults/alias tests honest. A field-at-a-time
/// assertion only proves the one field it inspects; it says nothing about
/// whether some *other* default silently regressed to a non-default value, or
/// whether a flag flipped an unrelated field (a clap-derive copy/paste bug).
/// Comparing the whole snapshot against the independently-declared defaults
/// fails loudly the instant any field moves.
#[derive(Debug, Clone, PartialEq)]
struct Snap {
    cwd: PathBuf,
    manifest_path: String,
    api_url: String,
    api_token: Option<String>,
    org: Option<String>,
    proxy_url: String,
    ecosystems: Option<Vec<String>>,
    download_mode: String,
    offline: bool,
    global: bool,
    global_prefix: Option<PathBuf>,
    json: bool,
    verbose: bool,
    silent: bool,
    dry_run: bool,
    yes: bool,
    lock_timeout: Option<u64>,
    break_lock: bool,
    debug: bool,
    no_telemetry: bool,
    download_only: bool,
}

fn snapshot(a: &RepairArgs) -> Snap {
    Snap {
        cwd: a.common.cwd.clone(),
        manifest_path: a.common.manifest_path.clone(),
        api_url: a.common.api_url.clone(),
        api_token: a.common.api_token.clone(),
        org: a.common.org.clone(),
        proxy_url: a.common.proxy_url.clone(),
        ecosystems: a.common.ecosystems.clone(),
        download_mode: a.common.download_mode.clone(),
        offline: a.common.offline,
        global: a.common.global,
        global_prefix: a.common.global_prefix.clone(),
        json: a.common.json,
        verbose: a.common.verbose,
        silent: a.common.silent,
        dry_run: a.common.dry_run,
        yes: a.common.yes,
        lock_timeout: a.common.lock_timeout,
        break_lock: a.common.break_lock,
        debug: a.common.debug,
        no_telemetry: a.common.no_telemetry,
        download_only: a.download_only,
    }
}

/// Independent oracle: the snapshot a correct parse of bare `repair` (no flags)
/// must produce. The values are transcribed BY HAND from the
/// `default_value`/`default_value_t` declarations on `RepairArgs`/`GlobalArgs`
/// and the `DEFAULT_*` constants in `socket-patch-core` — NOT read back from a
/// live parse — so this can actually disagree with the implementation if a
/// default regresses.
fn expected_defaults() -> Snap {
    Snap {
        cwd: PathBuf::from("."),
        manifest_path: ".socket/manifest.json".to_string(),
        api_url: "https://api.socket.dev".to_string(),
        api_token: None,
        org: None,
        proxy_url: "https://patches-api.socket.dev".to_string(),
        ecosystems: None,
        download_mode: "diff".to_string(),
        offline: false,
        global: false,
        global_prefix: None,
        json: false,
        verbose: false,
        silent: false,
        dry_run: false,
        yes: false,
        lock_timeout: None,
        break_lock: false,
        debug: false,
        no_telemetry: false,
        download_only: false,
    }
}

#[test]
#[serial_test::serial]
fn repair_defaults_match_contract() {
    let args = parse_repair(&[]);

    // Pin the *entire* default surface in one shot against the independent
    // oracle. The previous version only checked download_mode, cwd,
    // manifest_path, dry_run, offline, download_only and json — leaving
    // api_url, proxy_url, verbose, silent, yes, lock_timeout, break_lock,
    // debug, no_telemetry, global, global_prefix, ecosystems, api_token and
    // org free to regress unnoticed.
    assert_eq!(snapshot(&args), expected_defaults());

    // v3.0: repair's --download-mode default aligns with every other
    // command (was "file" in v2.x). Users that need the legacy per-file
    // blob behavior opt in with `--download-mode file`.
    assert_eq!(args.common.download_mode, "diff");
    // The clap layer stores a raw String with no value_parser, so the
    // assertion above only proves the literal echoes. Bind it to the real
    // runtime validator so a regression that changes what `"diff"` *means*
    // (or stops recognizing it) fails here too.
    assert_eq!(
        DownloadMode::parse(&args.common.download_mode),
        Ok(DownloadMode::Diff),
        "default download_mode must be the real Diff variant"
    );
}

#[test]
#[serial_test::serial]
fn repair_dry_run_long_flag() {
    let args = parse_repair(&["--dry-run"]);
    // The flag flips dry_run and *nothing else* — anything but this exact
    // one-field delta from the defaults is a regression.
    let mut expected = expected_defaults();
    expected.dry_run = true;
    assert_eq!(snapshot(&args), expected);
}

#[test]
#[serial_test::serial]
fn repair_manifest_path_long_flag() {
    let args = parse_repair(&["--manifest-path", "custom.json"]);
    let mut expected = expected_defaults();
    expected.manifest_path = "custom.json".to_string();
    assert_eq!(snapshot(&args), expected);
}

#[test]
#[serial_test::serial]
fn repair_cwd_flag() {
    let args = parse_repair(&["--cwd", "/tmp/x"]);
    let mut expected = expected_defaults();
    expected.cwd = PathBuf::from("/tmp/x");
    assert_eq!(snapshot(&args), expected);
}

#[test]
#[serial_test::serial]
fn repair_offline_flag() {
    let args = parse_repair(&["--offline"]);
    let mut expected = expected_defaults();
    expected.offline = true;
    assert_eq!(snapshot(&args), expected);
}

#[test]
#[serial_test::serial]
fn repair_download_only_flag() {
    let args = parse_repair(&["--download-only"]);
    let mut expected = expected_defaults();
    expected.download_only = true;
    assert_eq!(snapshot(&args), expected);
}

#[test]
#[serial_test::serial]
fn repair_json_flag() {
    let args = parse_repair(&["--json"]);
    let mut expected = expected_defaults();
    expected.json = true;
    assert_eq!(snapshot(&args), expected);
}

#[test]
#[serial_test::serial]
fn repair_download_mode_file() {
    let args = parse_repair(&["--download-mode", "file"]);
    let mut expected = expected_defaults();
    expected.download_mode = "file".to_string();
    assert_eq!(snapshot(&args), expected);
    // The legacy per-file blob opt-in this test exists to protect: assert
    // `"file"` is a mode the engine actually recognizes, not just an echoed
    // string. If `File` support is dropped, this fails loudly.
    assert_eq!(
        DownloadMode::parse(&args.common.download_mode),
        Ok(DownloadMode::File)
    );
}

#[test]
#[serial_test::serial]
fn repair_download_mode_diff() {
    let args = parse_repair(&["--download-mode", "diff"]);
    let mut expected = expected_defaults();
    expected.download_mode = "diff".to_string();
    assert_eq!(snapshot(&args), expected);
    assert_eq!(
        DownloadMode::parse(&args.common.download_mode),
        Ok(DownloadMode::Diff)
    );
}

#[test]
#[serial_test::serial]
fn repair_download_mode_package() {
    let args = parse_repair(&["--download-mode", "package"]);
    let mut expected = expected_defaults();
    expected.download_mode = "package".to_string();
    assert_eq!(snapshot(&args), expected);
    assert_eq!(
        DownloadMode::parse(&args.common.download_mode),
        Ok(DownloadMode::Package)
    );
}

#[test]
#[serial_test::serial]
fn repair_download_mode_rejects_unknown_at_runtime() {
    // The clap surface accepts ANY string for --download-mode (no
    // value_parser); validation is deferred to `DownloadMode::parse` in the
    // run path. Pin that two-layer contract: a bogus mode parses at the clap
    // layer but is rejected by the validator. Without this, a test asserting
    // only the clap echo would pass even if every mode were silently valid.
    let args = parse_repair(&["--download-mode", "bogus"]);
    assert_eq!(args.common.download_mode, "bogus");
    assert!(
        DownloadMode::parse(&args.common.download_mode).is_err(),
        "unknown download mode must be rejected by the runtime validator"
    );
}

#[test]
#[serial_test::serial]
fn repair_gc_alias_defaults_match_repair() {
    let via_gc = parse_gc(&[]);
    let via_repair = parse_repair(&[]);

    // The whole point of the alias: identical parsing. Compare the *entire*
    // parsed surface, and independently anchor both to the contract defaults
    // so the test isn't merely "the parser agrees with itself".
    assert_eq!(snapshot(&via_gc), expected_defaults());
    assert_eq!(snapshot(&via_repair), expected_defaults());
    assert_eq!(snapshot(&via_gc), snapshot(&via_repair));
    assert_eq!(
        DownloadMode::parse(&via_gc.common.download_mode),
        Ok(DownloadMode::Diff)
    );
}

#[test]
#[serial_test::serial]
fn repair_gc_alias_accepts_flags() {
    let args = parse_gc(&["--dry-run"]);
    let mut expected = expected_defaults();
    expected.dry_run = true;
    assert_eq!(snapshot(&args), expected);
}

#[test]
#[serial_test::serial]
fn repair_unknown_flag_is_unknown_argument_error() {
    let _scrub = EnvScrub::new();
    let err = match Cli::try_parse_from(["socket-patch", "repair", "--nope"]) {
        Ok(_) => panic!("unknown flag should fail to parse"),
        Err(e) => e,
    };
    assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
}

// --- `gc` is a first-class visible alias for `repair` ---------------------
//
// `scan --sync` is the recommended combined workflow, but `gc`/`repair`
// remain documented commands for users who want to clean up without an
// apply pass. These tests guard the `visible_alias = "gc"` attribute on
// `Commands::Repair` — if a future refactor demotes the alias (to
// `alias = "gc"` or removes it entirely), the help output check below
// will fail.

fn top_level_help() -> String {
    let _scrub = EnvScrub::new();
    match Cli::try_parse_from(["socket-patch", "--help"]) {
        Ok(_) => panic!("--help should return a clap error (DisplayHelp)"),
        Err(e) => format!("{e}"),
    }
}

#[test]
#[serial_test::serial]
fn repair_appears_in_top_level_help() {
    let help = top_level_help();
    assert!(
        help.lines().any(
            |l| l.trim_start().starts_with("repair ") || l.trim_start().starts_with("repair\t")
        ),
        "`repair` must be listed in --help output:\n{help}"
    );
}

#[test]
#[serial_test::serial]
fn gc_alias_is_visible_in_top_level_help() {
    let help = top_level_help();
    // clap renders a *visible* alias inline on the subcommand's help row as
    // `[aliases: gc]`. A hidden `alias = "gc"` produces no such marker at all,
    // so this fails loudly if the alias is demoted or dropped. Require the
    // exact visible-alias marker — accepting a bare `gc` substring would match
    // unrelated help text (e.g. the prose explaining the alias).
    assert!(
        help.contains("[aliases: gc]"),
        "`gc` visible alias must be listed in --help output:\n{help}"
    );
}

#[test]
#[serial_test::serial]
fn gc_alias_parses_as_repair() {
    let _scrub = EnvScrub::new();
    match Cli::try_parse_from(["socket-patch", "gc"]) {
        Ok(cli) => assert!(
            matches!(cli.command, Commands::Repair(_)),
            "gc should resolve to Repair"
        ),
        Err(e) => panic!("gc alias should parse: {e}"),
    }
}
