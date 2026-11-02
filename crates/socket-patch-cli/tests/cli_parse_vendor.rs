//! Clap parser snapshot tests for the `vendor` subcommand.
//!
//! These tests pin the public CLI contract for `socket-patch vendor`: every
//! flag, every default, the embedded-VEX passthrough surface, env-var
//! wiring (`SOCKET_VENDOR_REVERT`, `SOCKET_VEX*`; the retired `SOCKET_FORCE`
//! is pinned as ignored), the
//! subcommand's presence in the top-level command list, and that the
//! bare-UUID convenience fallback still routes to `get` — never to
//! `vendor`. Changing any assertion here is a breaking change to the CLI
//! surface — see `crates/socket-patch-cli/CLI_CONTRACT.md`.
//!
//! The env-wiring tests set `SOCKET_*` vars, and clap reads them during every
//! parse, so every test that parses is `#[serial]`.

use socket_patch_cli::commands::vendor::VendorArgs;
use socket_patch_cli::{parse_argv_with_shortcuts, Cli, Commands};
use std::path::PathBuf;

#[path = "common/clap_parse.rs"]
mod clap_parse;
#[path = "common/hermetic.rs"]
mod hermetic;

use clap_parse::Globals;
use hermetic::try_parse;

fn parse_vendor(extra: &[&str]) -> VendorArgs {
    let mut argv = vec!["socket-patch", "vendor"];
    argv.extend_from_slice(extra);
    let cli = try_parse(&argv).expect("parse");
    match cli.command {
        Commands::Vendor(a) => a,
        _ => panic!("expected Vendor"),
    }
}

fn parse_vendor_with_env(env: &[(&str, &str)], extra: &[&str]) -> Result<VendorArgs, clap::Error> {
    let mut argv = vec!["socket-patch", "vendor"];
    argv.extend_from_slice(extra);
    clap_parse::try_parse_with_env(env, &argv).map(|cli| match cli.command {
        Commands::Vendor(a) => a,
        _ => panic!("expected Vendor"),
    })
}

/// Every parsed field of `VendorArgs`, including the flattened `GlobalArgs`
/// and `VexEmbedArgs`. The per-flag tests compare the whole snapshot, so a
/// flag wired to a second field fails too.
#[derive(Debug, Clone, PartialEq)]
struct Snap {
    common: Globals,
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
        common: Globals(a.common.clone()),
        force: a.force,
        revert: a.revert,
        vex: a.vex.vex.clone(),
        vex_product: a.vex.vex_product.clone(),
        vex_no_verify: a.vex.vex_no_verify,
        vex_doc_id: a.vex.vex_doc_id.clone(),
        vex_compact: a.vex.vex_compact,
    }
}

/// The snapshot of bare `vendor`, written by hand.
fn expected_defaults() -> Snap {
    Snap {
        common: clap_parse::global_defaults(),
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
    want.common.json = true;
    assert_eq!(snapshot(&a), want);
}

#[test]
#[serial_test::serial]
fn json_short_sets_json() {
    let a = parse_vendor(&["-j"]);
    let mut want = expected_defaults();
    want.common.json = true;
    assert_eq!(snapshot(&a), want);
}

#[test]
#[serial_test::serial]
fn dry_run_sets_dry_run() {
    let a = parse_vendor(&["--dry-run"]);
    let mut want = expected_defaults();
    want.common.dry_run = true;
    // `--dry-run` is the preview contract ("verifies and writes nothing");
    // it must NOT be cross-wired into `--force` or `--revert`.
    assert_eq!(snapshot(&a), want);
}

#[test]
#[serial_test::serial]
fn cwd_flag_sets_cwd() {
    let a = parse_vendor(&["--cwd", "/tmp/project"]);
    let mut want = expected_defaults();
    want.common.cwd = PathBuf::from("/tmp/project");
    assert_eq!(snapshot(&a), want);
}

#[test]
#[serial_test::serial]
fn manifest_path_flag_sets_manifest_path() {
    let a = parse_vendor(&["--manifest-path", "custom.json"]);
    let mut want = expected_defaults();
    want.common.manifest_path = "custom.json".to_string();
    assert_eq!(snapshot(&a), want);
}

#[test]
#[serial_test::serial]
fn offline_flag_sets_offline() {
    let a = parse_vendor(&["--offline"]);
    let mut want = expected_defaults();
    want.common.offline = true;
    assert_eq!(snapshot(&a), want);
}

#[test]
#[serial_test::serial]
fn lock_timeout_flag_sets_lock_timeout() {
    let a = parse_vendor(&["--lock-timeout", "30"]);
    let mut want = expected_defaults();
    want.common.lock_timeout = Some(30);
    assert_eq!(snapshot(&a), want);
}

#[test]
#[serial_test::serial]
fn ecosystems_csv_splits_into_vec() {
    let a = parse_vendor(&["--ecosystems", "npm,cargo"]);
    let mut want = expected_defaults();
    want.common.ecosystems = Some(vec!["npm".to_string(), "cargo".to_string()]);
    assert_eq!(snapshot(&a), want);
}

// --- Env wiring ----------------------------------------------------------------
//
// Every assertion below runs against a scrubbed environment with exactly one
// injected variable, so the parsed value can only have come from that
// variable (not from the shell, and not from a flag).

/// v5 retired `SOCKET_FORCE` (#615): `--force` is flag-only, so a stale
/// export leaves `force` at its default instead of bypassing the variant
/// probe.
#[test]
#[serial_test::serial]
fn env_socket_force_is_ignored() {
    for val in ["1", "true", "yes", ""] {
        let a = parse_vendor_with_env(&[("SOCKET_FORCE", val)], &[]).expect("parse");
        assert_eq!(snapshot(&a), expected_defaults(), "SOCKET_FORCE={val:?}");
    }
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
fn vendor_appears_in_subcommand_list() {
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
    let err = match try_parse(&["socket-patch", "--help"]) {
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
    hermetic::scrub_process_socket_env();
    const UUID: &str = "9f6b2c4e-1d3a-4f6b-8c2d-7e5a9b1c3d5f";
    let cli = parse_argv_with_shortcuts(vec!["socket-patch".to_string(), UUID.to_string()])
        .expect("bare uuid must parse via the get fallback");
    match cli.command {
        Commands::Get(a) => assert_eq!(a.identifier, UUID),
        Commands::Vendor(_) => panic!("bare uuid must NOT route to vendor"),
        _ => panic!("bare uuid must route to get"),
    }
}

// --- Error paths -------------------------------------------------------------

#[test]
#[serial_test::serial]
fn unknown_flag_errors() {
    let err = match try_parse(&["socket-patch", "vendor", "--bogus"]) {
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
    match try_parse(&["socket-patch", "vendor", "--force", "stray"]) {
        Ok(_) => panic!("`vendor --force stray` must reject the stray positional"),
        Err(err) => assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument),
    }
}

#[test]
#[serial_test::serial]
fn no_vlt_install_cleanup_is_accepted_silently_by_vendor() {
    let mut want = expected_defaults();
    want.common.no_vlt_install_cleanup = true;
    assert_eq!(snapshot(&parse_vendor(&["--no-vlt-install-cleanup"])), want);
    let from_env =
        parse_vendor_with_env(&[("SOCKET_NO_VLT_INSTALL_CLEANUP", "true")], &[]).expect("parse");
    assert_eq!(snapshot(&from_env), want);
}
