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
//! ## Hermeticity
//!
//! Every parse runs with the full set of `SOCKET_*` vars scrubbed (see
//! [`EnvScrub`]) and each test is `#[serial_test::serial]` because the
//! process environment is global. This mirrors `cli_parse_repair.rs`.

use std::path::PathBuf;

use clap::Parser;
use socket_patch_cli::commands::vex::VexArgs;
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
    "SOCKET_VENDOR_SOURCE",
    "SOCKET_VENDOR_URL",
    "SOCKET_PATCH_SERVER_URL",
    "SOCKET_OFFLINE",
    "SOCKET_STRICT",
    "SOCKET_GLOBAL",
    "SOCKET_GLOBAL_PREFIX",
    "SOCKET_JSON",
    "SOCKET_VERBOSE",
    "SOCKET_SILENT",
    "SOCKET_DRY_RUN",
    "SOCKET_YES",
    "SOCKET_LOCK_TIMEOUT",
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

/// Owned, comparable snapshot of *every* parsed field in `VexArgs` — its own
/// five flags plus every field of the flattened `GlobalArgs`. `VexArgs` /
/// `GlobalArgs` are production types that don't derive `PartialEq`, so this
/// mirror exists purely so a single `assert_eq!` can police the entire
/// parsed surface at once. Mirrors `cli_parse_repair.rs`.
#[derive(Debug, Clone, PartialEq)]
struct Snap {
    cwd: PathBuf,
    manifest_path: String,
    api_url: Option<String>,
    api_token: Option<String>,
    org: Option<String>,
    proxy_url: Option<String>,
    ecosystems: Option<Vec<String>>,
    download_mode: String,
    vendor_source: String,
    vendor_url: Option<String>,
    patch_server_url: Option<String>,
    offline: bool,
    strict: bool,
    global: bool,
    global_prefix: Option<PathBuf>,
    json: bool,
    verbose: bool,
    silent: bool,
    dry_run: bool,
    yes: bool,
    lock_timeout: Option<u64>,
    debug: bool,
    no_telemetry: bool,
    output: Option<PathBuf>,
    product: Option<String>,
    no_verify: bool,
    doc_id: Option<String>,
    compact: bool,
}

fn snapshot(a: &VexArgs) -> Snap {
    Snap {
        cwd: a.common.cwd.clone(),
        manifest_path: a.common.manifest_path.clone(),
        api_url: a.common.api_url.clone(),
        api_token: a.common.api_token.clone(),
        org: a.common.org.clone(),
        proxy_url: a.common.proxy_url.clone(),
        ecosystems: a.common.ecosystems.clone(),
        download_mode: a.common.download_mode.clone(),
        vendor_source: a.common.vendor_source.clone(),
        vendor_url: a.common.vendor_url.clone(),
        patch_server_url: a.common.patch_server_url.clone(),
        offline: a.common.offline,
        strict: a.common.strict,
        global: a.common.global,
        global_prefix: a.common.global_prefix.clone(),
        json: a.common.json,
        verbose: a.common.verbose,
        silent: a.common.silent,
        dry_run: a.common.dry_run,
        yes: a.common.yes,
        lock_timeout: a.common.lock_timeout,
        debug: a.common.debug,
        no_telemetry: a.common.no_telemetry,
        output: a.output.clone(),
        product: a.product.clone(),
        no_verify: a.no_verify,
        doc_id: a.doc_id.clone(),
        compact: a.compact,
    }
}

/// Independent oracle: the snapshot a correct parse of bare `vex` (no flags,
/// no env) must produce. The values are transcribed BY HAND from the
/// `default_value`/`default_value_t` declarations on `VexArgs`/`GlobalArgs`
/// and the `DEFAULT_*` constants in `socket-patch-core` — NOT read back from
/// a live parse — so this can actually disagree with the implementation if a
/// default regresses.
fn expected_defaults() -> Snap {
    Snap {
        cwd: PathBuf::from("."),
        manifest_path: ".socket/manifest.json".to_string(),
        api_url: None, // no clap default — resolved in core
        api_token: None,
        org: None,
        proxy_url: None, // no clap default — resolved in core
        ecosystems: None,
        download_mode: "diff".to_string(),
        vendor_source: "auto".to_string(),
        vendor_url: None,
        patch_server_url: None,
        offline: false,
        strict: false,
        global: false,
        global_prefix: None,
        json: false,
        verbose: false,
        silent: false,
        dry_run: false,
        yes: false,
        lock_timeout: None,
        debug: false,
        no_telemetry: false,
        output: None,
        product: None,
        no_verify: false,
        doc_id: None,
        compact: false,
    }
}

/// [`SOCKET_ENV_VARS`] claims to list "every `SOCKET_*` env var clap consults
/// while parsing `vex`, `apply`, or `scan`". `GlobalArgs` is flattened in
/// whole, so the production `GLOBAL_ARG_ENV_VARS` list is the oracle — a flag
/// added to `GlobalArgs` with an env binding is consulted here the moment it
/// lands, and if the scrub list lags behind, an ambient value either aborts
/// every parse in this file (validated flags: bools, ints, `--ecosystems`,
/// `--vendor-source`) or silently leaks into the parsed args (string flags),
/// voiding the hermeticity the module doc promises. `garbage` is rejected by
/// every validating parser and visibly non-default for every
/// string/path/option flag, so a missing scrub entry fails loudly either way.
/// Mirrors `cli_parse_repair.rs` / `cli_parse_get.rs`.
#[test]
#[serial_test::serial]
fn scrub_covers_every_global_env_var_clap_consults() {
    for &var in socket_patch_cli::args::GLOBAL_ARG_ENV_VARS {
        let prev = std::env::var(var).ok();
        std::env::set_var(var, "garbage");
        let parsed = {
            let _scrub = EnvScrub::new();
            Cli::try_parse_from(["socket-patch", "vex"])
        };
        match prev {
            Some(v) => std::env::set_var(var, v),
            None => std::env::remove_var(var),
        }
        let a = match parsed {
            Ok(cli) => match cli.command {
                Commands::Vex(a) => a,
                _ => panic!("expected Vex"),
            },
            Err(e) => panic!("ambient {var}=garbage aborted the scrubbed parse: {e}"),
        };
        assert_eq!(
            snapshot(&a),
            expected_defaults(),
            "ambient {var}=garbage leaked into the scrubbed parse",
        );
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
