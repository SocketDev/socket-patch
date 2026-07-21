//! Clap parser snapshot tests for the `vendor` subcommand.
//!
//! These tests pin the public CLI contract for `socket-patch vendor`: every
//! flag, every default, the embedded-VEX passthrough surface, env-var
//! wiring (`SOCKET_FORCE`, `SOCKET_VENDOR_REVERT`, `SOCKET_VEX*`), the
//! subcommand's presence in the top-level command list, and that the
//! bare-UUID convenience fallback still routes to `get` — never to
//! `vendor`. Changing any assertion here is a breaking change to the CLI
//! surface — see `crates/socket-patch-cli/CLI_CONTRACT.md`.
//!
//! ## Hermeticity
//!
//! Every flag and default below is also wired to an `#[arg(env = "SOCKET_*")]`
//! source. clap reads those env vars during `try_parse_from`, so an ambient
//! `SOCKET_*` variable in the developer's shell or in CI would silently
//! satisfy these assertions even if the corresponding CLI default
//! (`default_value`/`default_value_t`) regressed or a flag's action broke —
//! the env value would mask the bug and the test would pass for the wrong
//! reason. To make the assertions test *argv parsing* rather than the
//! ambient environment, every parse runs with the full set of `SOCKET_*`
//! vars scrubbed (see [`EnvScrub`]). Because the environment is process-
//! global, every test is `#[serial_test::serial]` so the scrub/restore
//! dance can't race a concurrent parse. This mirrors `cli_parse_get.rs` /
//! `cli_parse_repair.rs`.

use clap::Parser;
use socket_patch_cli::commands::vendor::VendorArgs;
use socket_patch_cli::{parse_with_uuid_fallback, Cli, Commands};
use std::path::PathBuf;

/// Every `SOCKET_*` env var that clap consults while parsing `vendor` (its
/// own flags, the flattened `GlobalArgs`, and the flattened `VexEmbedArgs`).
/// If any of these leaks in from the ambient environment it can mask a
/// broken default or a regressed flag, so the parse helpers below remove
/// them for the duration of the parse.
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
    "SOCKET_BREAK_LOCK",
    "SOCKET_DEBUG",
    "SOCKET_TELEMETRY_DISABLED",
    // VendorArgs-specific
    "SOCKET_FORCE",
    "SOCKET_VENDOR_REVERT",
    // VexEmbedArgs (flattened embedded-VEX passthrough)
    "SOCKET_VEX",
    "SOCKET_VEX_PRODUCT",
    "SOCKET_VEX_NO_VERIFY",
    "SOCKET_VEX_DOC_ID",
    "SOCKET_VEX_COMPACT",
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

/// Parse `socket-patch vendor <extra...>` and return the `VendorArgs`, with
/// the ambient `SOCKET_*` environment scrubbed so the result reflects only
/// the argv. The scrub guard is held across the parse and dropped before the
/// caller's assertions run (which only inspect the returned struct).
fn parse_vendor(extra: &[&str]) -> VendorArgs {
    let _scrub = EnvScrub::new();
    let mut argv = vec!["socket-patch", "vendor"];
    argv.extend_from_slice(extra);
    let cli = Cli::try_parse_from(&argv).expect("parse");
    match cli.command {
        Commands::Vendor(a) => a,
        _ => panic!("expected Vendor"),
    }
}

/// Parse `socket-patch vendor <extra...>` with `env` injected into an
/// otherwise fully-scrubbed `SOCKET_*` environment. Returns the raw clap
/// result so env-wiring tests can assert both the success and the failure
/// shapes. The injected vars are removed before the scrub guard restores
/// the ambient values.
fn parse_vendor_with_env(env: &[(&str, &str)], extra: &[&str]) -> Result<VendorArgs, clap::Error> {
    let _scrub = EnvScrub::new();
    for (k, v) in env {
        std::env::set_var(k, v);
    }
    let mut argv = vec!["socket-patch", "vendor"];
    argv.extend_from_slice(extra);
    let result = Cli::try_parse_from(&argv);
    for (k, _) in env {
        std::env::remove_var(k);
    }
    result.map(|cli| match cli.command {
        Commands::Vendor(a) => a,
        _ => panic!("expected Vendor"),
    })
}

/// Owned, comparable snapshot of *every* parsed field in `VendorArgs` — its
/// own flags (`force`, `revert`), every field of the flattened `GlobalArgs`,
/// and every field of the flattened `VexEmbedArgs`. `VendorArgs` is
/// production code that doesn't derive `PartialEq`, so this mirror exists
/// purely so a single `assert_eq!` can police the entire parsed surface at
/// once.
///
/// This is what makes the per-flag tests honest. A field-at-a-time assertion
/// (`assert!(a.force)`) only proves the flag set *its* field; it says nothing
/// about whether the same flag also flipped an unrelated one. A clap-derive
/// copy/paste regression (e.g. `--revert` accidentally wired to `force`)
/// would set both and still pass a single-field check. Comparing the whole
/// snapshot against the independently-declared defaults — with only the
/// field under test mutated — fails loudly the instant any other field moves.
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
    force: bool,
    revert: bool,
    vex: Option<PathBuf>,
    vex_product: Option<String>,
    vex_no_verify: bool,
    vex_doc_id: Option<String>,
    vex_compact: bool,
}

fn snapshot(a: &VendorArgs) -> Snap {
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
        force: a.force,
        revert: a.revert,
        vex: a.vex.vex.clone(),
        vex_product: a.vex.vex_product.clone(),
        vex_no_verify: a.vex.vex_no_verify,
        vex_doc_id: a.vex.vex_doc_id.clone(),
        vex_compact: a.vex.vex_compact,
    }
}

/// Independent oracle: the snapshot a correct parse of bare `vendor` (no
/// flags) must produce. The values are transcribed BY HAND from the
/// `default_value`/`default_value_t` declarations on `VendorArgs` /
/// `GlobalArgs` / `VexEmbedArgs` and the `DEFAULT_*` constants in
/// `socket-patch-core` — NOT read back from a live parse — so this can
/// actually disagree with the implementation if a default regresses. Every
/// per-flag test starts from this and mutates exactly the one field the flag
/// is supposed to touch.
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
        force: false,
        revert: false,
        vex: None,
        vex_product: None,
        vex_no_verify: false,
        vex_doc_id: None,
        vex_compact: false,
    }
}

// --- Defaults ----------------------------------------------------------------

#[test]
#[serial_test::serial]
fn defaults_with_no_flags() {
    let a = parse_vendor(&[]);
    // Pin the *entire* default surface in one shot against the independent
    // oracle: a plain `vendor` must default to a mutating (not dry-run),
    // human-output, non-force, non-revert run rooted at `.` with the
    // canonical manifest path, and the embedded VEX must be fully off.
    assert_eq!(snapshot(&a), expected_defaults());
}

// --- vendor's own flags --------------------------------------------------------

#[test]
#[serial_test::serial]
fn force_long_sets_force() {
    let a = parse_vendor(&["--force"]);
    let mut want = expected_defaults();
    want.force = true;
    // `--force` skips the pre-vendor beforeHash verification; it must NOT
    // also flip `revert` (or anything else) — full-snapshot equality.
    assert_eq!(snapshot(&a), want);
}

#[test]
#[serial_test::serial]
fn force_short_sets_force() {
    let a = parse_vendor(&["-f"]);
    let mut want = expected_defaults();
    want.force = true;
    assert_eq!(snapshot(&a), want);
}

#[test]
#[serial_test::serial]
fn revert_long_sets_revert() {
    let a = parse_vendor(&["--revert"]);
    let mut want = expected_defaults();
    want.revert = true;
    // `--revert` switches the command into undo mode; it must not imply
    // `--force` (revert never bypasses safety checks via force).
    assert_eq!(snapshot(&a), want);
}

#[test]
#[serial_test::serial]
fn force_and_revert_are_independent_fields() {
    let a = parse_vendor(&["--force", "--revert"]);
    let mut want = expected_defaults();
    want.force = true;
    want.revert = true;
    // Both settable together, each landing in its own field — catches a
    // shared-storage regression where only the last flag would win.
    assert_eq!(snapshot(&a), want);
}

// --- Embedded VEX passthrough --------------------------------------------------

#[test]
#[serial_test::serial]
fn vex_path_sets_only_the_vex_output() {
    let a = parse_vendor(&["--vex", "out.vex.json"]);
    let mut want = expected_defaults();
    want.vex = Some(PathBuf::from("out.vex.json"));
    // The trigger flag alone must not flip any other vex knob, nor `force`,
    // nor `revert`.
    assert_eq!(snapshot(&a), want);
}

#[test]
#[serial_test::serial]
fn vex_passthrough_knobs_each_set_their_field() {
    let a = parse_vendor(&[
        "--vex",
        "out.vex.json",
        "--vex-product",
        "pkg:npm/app@1.0.0",
        "--vex-no-verify",
        "--vex-doc-id",
        "urn:uuid:fixed",
        "--vex-compact",
    ]);
    let mut want = expected_defaults();
    want.vex = Some(PathBuf::from("out.vex.json"));
    want.vex_product = Some("pkg:npm/app@1.0.0".to_string());
    want.vex_no_verify = true;
    want.vex_doc_id = Some("urn:uuid:fixed".to_string());
    want.vex_compact = true;
    // Only the vex fields move; nothing (e.g. --force) rides along on the
    // vex passthrough.
    assert_eq!(snapshot(&a), want);
}

// --- Global flags on vendor ------------------------------------------------------

#[test]
#[serial_test::serial]
fn json_long_sets_json() {
    let a = parse_vendor(&["--json"]);
    let mut want = expected_defaults();
    want.json = true;
    assert_eq!(snapshot(&a), want);
}

#[test]
#[serial_test::serial]
fn json_short_sets_json() {
    let a = parse_vendor(&["-j"]);
    let mut want = expected_defaults();
    want.json = true;
    assert_eq!(snapshot(&a), want);
}

#[test]
#[serial_test::serial]
fn dry_run_sets_dry_run() {
    let a = parse_vendor(&["--dry-run"]);
    let mut want = expected_defaults();
    want.dry_run = true;
    // `--dry-run` is the preview contract ("verifies and writes nothing");
    // it must NOT be cross-wired into `--force` or `--revert`.
    assert_eq!(snapshot(&a), want);
}

#[test]
#[serial_test::serial]
fn cwd_flag_sets_cwd() {
    let a = parse_vendor(&["--cwd", "/tmp/project"]);
    let mut want = expected_defaults();
    want.cwd = PathBuf::from("/tmp/project");
    assert_eq!(snapshot(&a), want);
}

#[test]
#[serial_test::serial]
fn manifest_path_flag_sets_manifest_path() {
    let a = parse_vendor(&["--manifest-path", "custom.json"]);
    let mut want = expected_defaults();
    want.manifest_path = "custom.json".to_string();
    assert_eq!(snapshot(&a), want);
}

#[test]
#[serial_test::serial]
fn offline_flag_sets_offline() {
    let a = parse_vendor(&["--offline"]);
    let mut want = expected_defaults();
    want.offline = true;
    assert_eq!(snapshot(&a), want);
}

#[test]
#[serial_test::serial]
fn lock_timeout_flag_sets_lock_timeout() {
    let a = parse_vendor(&["--lock-timeout", "30"]);
    let mut want = expected_defaults();
    want.lock_timeout = Some(30);
    assert_eq!(snapshot(&a), want);
}

#[test]
#[serial_test::serial]
fn break_lock_flag_sets_break_lock() {
    let a = parse_vendor(&["--break-lock"]);
    let mut want = expected_defaults();
    want.break_lock = true;
    assert_eq!(snapshot(&a), want);
}

#[test]
#[serial_test::serial]
fn ecosystems_csv_splits_into_vec() {
    let a = parse_vendor(&["--ecosystems", "npm,cargo"]);
    let mut want = expected_defaults();
    want.ecosystems = Some(vec!["npm".to_string(), "cargo".to_string()]);
    assert_eq!(snapshot(&a), want);
}

// --- Env wiring ----------------------------------------------------------------
//
// Every assertion below runs against a scrubbed environment with exactly one
// injected variable, so the parsed value can only have come from that
// variable (not from the shell, and not from a flag).

#[test]
#[serial_test::serial]
fn env_socket_force_true_sets_force() {
    let a = parse_vendor_with_env(&[("SOCKET_FORCE", "true")], &[]).expect("parse");
    let mut want = expected_defaults();
    want.force = true;
    assert_eq!(snapshot(&a), want);
}

#[test]
#[serial_test::serial]
fn env_socket_force_false_keeps_force_off() {
    let a = parse_vendor_with_env(&[("SOCKET_FORCE", "false")], &[]).expect("parse");
    assert_eq!(snapshot(&a), expected_defaults());
}

/// The contract every other bool env var on this CLI follows (`SOCKET_JSON=1`,
/// `SOCKET_OFFLINE=yes`, `SOCKET_VENDOR_REVERT=1` all work): boolish tokens
/// must be accepted. `SOCKET_FORCE=1` should set `force = true`.
#[test]
#[serial_test::serial]
fn env_socket_force_numeric_one_should_set_force() {
    let a = parse_vendor_with_env(&[("SOCKET_FORCE", "1")], &[])
        .expect("boolish env tokens should be accepted like every other SOCKET_* bool");
    let mut want = expected_defaults();
    want.force = true;
    assert_eq!(snapshot(&a), want);
}

#[test]
#[serial_test::serial]
fn env_socket_force_empty_should_parse_as_false() {
    let a = parse_vendor_with_env(&[("SOCKET_FORCE", "")], &[])
        .expect("an exported-but-empty bool env var must not abort the parse");
    assert_eq!(snapshot(&a), expected_defaults());
}

#[test]
#[serial_test::serial]
fn env_socket_vendor_revert_truthy_tokens_set_revert() {
    // `--revert` declares clap's BoolishValueParser, so the documented token
    // vocabulary (1 / true / yes / on, case-insensitive) all enable it.
    for token in ["1", "true", "yes", "on", "TRUE"] {
        let a = parse_vendor_with_env(&[("SOCKET_VENDOR_REVERT", token)], &[])
            .unwrap_or_else(|e| panic!("SOCKET_VENDOR_REVERT={token} must parse: {e}"));
        let mut want = expected_defaults();
        want.revert = true;
        assert_eq!(snapshot(&a), want, "SOCKET_VENDOR_REVERT={token}");
    }
}

#[test]
#[serial_test::serial]
fn env_socket_vendor_revert_falsey_tokens_keep_revert_off() {
    for token in ["0", "false", "no", "off"] {
        let a = parse_vendor_with_env(&[("SOCKET_VENDOR_REVERT", token)], &[])
            .unwrap_or_else(|e| panic!("SOCKET_VENDOR_REVERT={token} must parse: {e}"));
        assert_eq!(
            snapshot(&a),
            expected_defaults(),
            "SOCKET_VENDOR_REVERT={token}"
        );
    }
}

#[test]
#[serial_test::serial]
fn env_socket_vendor_revert_empty_should_parse_as_false() {
    let a = parse_vendor_with_env(&[("SOCKET_VENDOR_REVERT", "")], &[])
        .expect("an exported-but-empty bool env var must not abort the parse");
    assert_eq!(snapshot(&a), expected_defaults());
}

#[test]
#[serial_test::serial]
fn env_socket_vendor_revert_garbage_is_rejected() {
    // The boolish vocabulary must not silently widen to "accept anything".
    let err = match parse_vendor_with_env(&[("SOCKET_VENDOR_REVERT", "garbage")], &[]) {
        Err(e) => e,
        Ok(_) => panic!("a non-boolean SOCKET_VENDOR_REVERT must fail the parse"),
    };
    assert_eq!(err.kind(), clap::error::ErrorKind::ValueValidation);
}

#[test]
#[serial_test::serial]
fn cli_revert_flag_wins_over_falsey_env() {
    // Precedence contract: CLI arg > env var. A falsey env value must not
    // override an explicit `--revert` on the argv.
    let a =
        parse_vendor_with_env(&[("SOCKET_VENDOR_REVERT", "false")], &["--revert"]).expect("parse");
    let mut want = expected_defaults();
    want.revert = true;
    assert_eq!(snapshot(&a), want);
}

#[test]
#[serial_test::serial]
fn env_socket_vex_sets_embedded_vex_path() {
    let a = parse_vendor_with_env(&[("SOCKET_VEX", "env.vex.json")], &[]).expect("parse");
    let mut want = expected_defaults();
    want.vex = Some(PathBuf::from("env.vex.json"));
    assert_eq!(snapshot(&a), want);
}

// --- Subcommand routing ----------------------------------------------------------

#[test]
#[serial_test::serial]
fn vendor_appears_in_subcommand_list() {
    let _scrub = EnvScrub::new();
    use clap::CommandFactory;
    let cmd = Cli::command();
    assert!(
        cmd.get_subcommands().any(|c| c.get_name() == "vendor"),
        "`vendor` must be a registered subcommand; found: {:?}",
        cmd.get_subcommands()
            .map(|c| c.get_name())
            .collect::<Vec<_>>()
    );
}

#[test]
#[serial_test::serial]
fn vendor_appears_in_top_level_help() {
    let _scrub = EnvScrub::new();
    let err = match Cli::try_parse_from(["socket-patch", "--help"]) {
        Ok(_) => panic!("--help should return a clap error (DisplayHelp)"),
        Err(e) => e,
    };
    let help = format!("{err}");
    assert!(
        help.lines()
            .any(|l| { l.trim_start().starts_with("vendor ") || l.trim_start() == "vendor" }),
        "`vendor` must be listed in --help output:\n{help}"
    );
}

/// The bare-UUID convenience form (`socket-patch <uuid>`) is rewritten to
/// `get <uuid>` — adding the `vendor` subcommand must not have hijacked that
/// fallback. Routing a bare UUID into `vendor` would silently turn a
/// read-mostly download shortcut into a lockfile-mutating command.
#[test]
#[serial_test::serial]
fn bare_uuid_fallback_still_routes_to_get_not_vendor() {
    let _scrub = EnvScrub::new();
    const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
    let cli = parse_with_uuid_fallback(vec!["socket-patch".to_string(), UUID.to_string()])
        .expect("bare uuid must parse via the get fallback");
    match cli.command {
        Commands::Get(a) => assert_eq!(a.identifier, UUID),
        Commands::Vendor(_) => panic!("bare uuid must NOT route to vendor"),
        _ => panic!("bare uuid must route to get"),
    }
}

// --- Harness invariants --------------------------------------------------------

/// Drift guard: [`EnvScrub`] must cover every env var `GlobalArgs` binds —
/// the production `GLOBAL_ARG_ENV_VARS` list is the source of truth. A
/// `GlobalArgs` flag whose env var is missing from [`SOCKET_ENV_VARS`]
/// escapes the scrub, so an ambient value in the developer's shell or CI
/// (e.g. `SOCKET_STRICT=garbage`) aborts every parse in this file —
/// exactly the wrong-reason failure mode the hermeticity contract at the
/// top of this file promises away.
#[test]
fn env_scrub_covers_every_global_arg_env_var() {
    for var in socket_patch_cli::args::GLOBAL_ARG_ENV_VARS {
        assert!(
            SOCKET_ENV_VARS.contains(var),
            "{var} is bound by GlobalArgs but missing from SOCKET_ENV_VARS — EnvScrub won't scrub it",
        );
    }
}

// --- Error paths -------------------------------------------------------------

#[test]
#[serial_test::serial]
fn unknown_flag_errors() {
    let _scrub = EnvScrub::new();
    let err = match Cli::try_parse_from(["socket-patch", "vendor", "--bogus"]) {
        Err(e) => e,
        Ok(_) => panic!("expected parse error for unknown flag"),
    };
    assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
}

/// Bare boolean flags are `SetTrue` (num_args = 0): they must NOT swallow the
/// following token as a value. If `--force` silently became value-taking, a
/// wrapper invoking `vendor --force <something>` would change meaning.
#[test]
#[serial_test::serial]
fn bare_force_does_not_consume_next_token() {
    let _scrub = EnvScrub::new();
    match Cli::try_parse_from(["socket-patch", "vendor", "--force", "stray"]) {
        Ok(_) => panic!("`vendor --force stray` must reject the stray positional"),
        Err(err) => assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument),
    }
}
