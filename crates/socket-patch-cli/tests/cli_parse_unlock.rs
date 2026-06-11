//! CLI contract tests for the `unlock` subcommand's parse surface.
//!
//! Focus: the `--release` / `SOCKET_UNLOCK_RELEASE` env binding.
//! Regression guard: the flag shipped without `value_parser =
//! parse_bool_flag`, so clap's default bool parser accepted only the
//! literal strings `true`/`false` from the env — `SOCKET_UNLOCK_RELEASE=1`
//! (or an exported-but-empty `SOCKET_UNLOCK_RELEASE=`) aborted every
//! `unlock` invocation with a ValueValidation error. The flag is also
//! outside `GLOBAL_ARG_ENV_VARS`, so `main`'s empty-var scrub never
//! rescues it. Same bug class previously fixed on `repair
//! --download-only` and `rollback --one-off`.
//!
//! ## Hermeticity
//!
//! Mirrors `cli_parse_repair.rs`: every parse runs with the full
//! `SOCKET_*` surface scrubbed (see [`EnvScrub`]) and every test is
//! `#[serial_test::serial]` so the process-global env mutation can't
//! race a concurrent parse.

use clap::Parser;
use socket_patch_cli::{Cli, Commands};

/// Every `SOCKET_*` env var that clap consults while parsing `unlock`
/// (its own `--release` flag plus the flattened `GlobalArgs`).
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
    // UnlockArgs-specific
    "SOCKET_UNLOCK_RELEASE",
];

/// RAII guard that removes every [`SOCKET_ENV_VARS`] entry on
/// construction and restores the prior value on drop. Pair with
/// `#[serial_test::serial]` so the global env mutation never races
/// another test.
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

fn release_of(cli: Cli) -> bool {
    match cli.command {
        Commands::Unlock(a) => a.release,
        _ => panic!("expected Unlock"),
    }
}

#[test]
#[serial_test::serial]
fn unlock_release_defaults_to_false() {
    let _scrub = EnvScrub::new();
    let cli = Cli::try_parse_from(["socket-patch", "unlock"]).expect("parse");
    assert!(
        !release_of(cli),
        "bare `unlock` must default release to false"
    );
}

#[test]
#[serial_test::serial]
fn unlock_release_long_flag_sets_true() {
    let _scrub = EnvScrub::new();
    let cli = Cli::try_parse_from(["socket-patch", "unlock", "--release"]).expect("parse");
    assert!(release_of(cli), "`--release` must set the flag");
}

/// Regression: an exported-but-empty `SOCKET_UNLOCK_RELEASE=` — the
/// shell/CI idiom for blanking a variable without unsetting it — must
/// mean "unset, fall back to the default (false)", not abort every
/// `unlock` invocation with a ValueValidation error.
#[test]
#[serial_test::serial]
fn empty_unlock_release_env_var_parses_as_false_not_crash() {
    let _scrub = EnvScrub::new();
    std::env::set_var("SOCKET_UNLOCK_RELEASE", "");
    let parsed = Cli::try_parse_from(["socket-patch", "unlock"]);
    std::env::remove_var("SOCKET_UNLOCK_RELEASE");
    let cli = parsed.expect("empty SOCKET_UNLOCK_RELEASE must not abort the parse");
    assert!(
        !release_of(cli),
        "empty SOCKET_UNLOCK_RELEASE must resolve to false"
    );
}

/// Regression: the truthy env spellings must work —
/// `SOCKET_UNLOCK_RELEASE=1` must behave exactly like `--release`
/// instead of aborting the parse.
#[test]
#[serial_test::serial]
fn truthy_unlock_release_env_var_sets_flag() {
    let _scrub = EnvScrub::new();
    std::env::set_var("SOCKET_UNLOCK_RELEASE", "1");
    let parsed = Cli::try_parse_from(["socket-patch", "unlock"]);
    std::env::remove_var("SOCKET_UNLOCK_RELEASE");
    let cli = parsed.expect("SOCKET_UNLOCK_RELEASE=1 must parse");
    assert!(release_of(cli), "SOCKET_UNLOCK_RELEASE=1 must set release");
}
