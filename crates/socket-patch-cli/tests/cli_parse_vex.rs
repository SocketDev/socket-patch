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
//! and `repair --download-only` / `unlock --release`. These vars are also
//! outside `GLOBAL_ARG_ENV_VARS`, so `main`'s empty-var scrub never rescues
//! them.
//!
//! ## Hermeticity
//!
//! Every parse runs with the full set of `SOCKET_*` vars scrubbed (see
//! [`EnvScrub`]) and each test is `#[serial_test::serial]` because the
//! process environment is global. This mirrors `cli_parse_repair.rs`.

use clap::Parser;
use socket_patch_cli::{Cli, Commands};

/// Every `SOCKET_*` env var clap consults while parsing `vex`, `apply`, or
/// `scan` (their own flags plus the flattened `GlobalArgs` and
/// `VexEmbedArgs`). Scrubbed around each parse so ambient shell/CI values
/// can't mask or fabricate a result.
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
    // VexArgs / VexEmbedArgs
    "SOCKET_VEX",
    "SOCKET_VEX_OUTPUT",
    "SOCKET_VEX_PRODUCT",
    "SOCKET_VEX_NO_VERIFY",
    "SOCKET_VEX_DOC_ID",
    "SOCKET_VEX_COMPACT",
    // ApplyArgs-specific
    "SOCKET_FORCE",
    // ScanArgs-specific
    "SOCKET_BATCH_SIZE",
    "SOCKET_ALL_RELEASES",
];

/// RAII guard that removes every [`SOCKET_ENV_VARS`] entry on construction and
/// restores the prior value on drop. Holding one of these around a clap parse
/// guarantees the parse sees only what's on the argv (plus whatever the test
/// itself sets), not the developer's shell. Pair with `#[serial_test::serial]`
/// so the global env mutation never races another test.
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

/// Scrub the env, set `var=value`, parse `argv`, restore. Returns the parse
/// result so callers can assert on success or failure.
fn parse_with_env(var: &str, value: &str, argv: &[&str]) -> Result<Cli, clap::Error> {
    let _scrub = EnvScrub::new();
    std::env::set_var(var, value);
    let parsed = Cli::try_parse_from(argv);
    std::env::remove_var(var);
    parsed
}

/// The truthy env spellings must work: `SOCKET_VEX_NO_VERIFY=1` must set
/// `vex --no-verify` exactly like the flag, not abort the parse.
#[test]
#[serial_test::serial]
fn truthy_vex_no_verify_env_sets_flag_on_vex() {
    let cli = parse_with_env("SOCKET_VEX_NO_VERIFY", "1", &["socket-patch", "vex"])
        .expect("SOCKET_VEX_NO_VERIFY=1 must parse, not abort");
    match cli.command {
        Commands::Vex(a) => assert!(a.no_verify, "SOCKET_VEX_NO_VERIFY=1 must set --no-verify"),
        _ => panic!("expected Vex"),
    }
}

/// An exported-but-empty `SOCKET_VEX_NO_VERIFY=` — the shell/CI idiom for
/// blanking a variable without unsetting it — must mean "unset, fall back
/// to the default (false)", not abort every `vex` invocation.
#[test]
#[serial_test::serial]
fn empty_vex_no_verify_env_parses_as_false_on_vex() {
    let cli = parse_with_env("SOCKET_VEX_NO_VERIFY", "", &["socket-patch", "vex"])
        .expect("empty SOCKET_VEX_NO_VERIFY must not abort the parse");
    match cli.command {
        Commands::Vex(a) => assert!(!a.no_verify, "empty SOCKET_VEX_NO_VERIFY must be false"),
        _ => panic!("expected Vex"),
    }
}

/// `SOCKET_VEX_COMPACT=1` must set `vex --compact`.
#[test]
#[serial_test::serial]
fn truthy_vex_compact_env_sets_flag_on_vex() {
    let cli = parse_with_env("SOCKET_VEX_COMPACT", "1", &["socket-patch", "vex"])
        .expect("SOCKET_VEX_COMPACT=1 must parse, not abort");
    match cli.command {
        Commands::Vex(a) => assert!(a.compact, "SOCKET_VEX_COMPACT=1 must set --compact"),
        _ => panic!("expected Vex"),
    }
}

/// `VexEmbedArgs` shares the env var names with the standalone flags, so an
/// ambient `SOCKET_VEX_NO_VERIFY=1` must also parse (and set
/// `--vex-no-verify`) on `apply` — this is the postinstall-hook blast
/// radius: before the fix the env var aborted every `apply` run.
#[test]
#[serial_test::serial]
fn truthy_vex_no_verify_env_sets_embedded_flag_on_apply() {
    let cli = parse_with_env("SOCKET_VEX_NO_VERIFY", "1", &["socket-patch", "apply"])
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
    let cli = parse_with_env("SOCKET_VEX_COMPACT", "", &["socket-patch", "scan"])
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
    let _scrub = EnvScrub::new();
    let cli = Cli::try_parse_from(["socket-patch", "vex", "--no-verify", "--compact"])
        .expect("bare flags must parse");
    match cli.command {
        Commands::Vex(a) => {
            assert!(a.no_verify);
            assert!(a.compact);
        }
        _ => panic!("expected Vex"),
    }
}
