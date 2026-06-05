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
    assert_eq!(a.common.cwd, PathBuf::from("."));
    assert!(!a.common.dry_run);
    assert!(!a.common.silent);
    assert_eq!(a.common.manifest_path, ".socket/manifest.json");
    assert!(!a.common.offline);
    assert!(!a.common.global);
    assert_eq!(a.common.global_prefix, None);
    assert_eq!(a.common.ecosystems, None);
    assert!(!a.force);
    assert!(!a.common.json);
    assert!(!a.common.verbose);
    assert_eq!(a.common.download_mode, "diff");

    // The remaining global defaults from the contract table. These were
    // previously unpinned, which let a dangerous default-value drift slip
    // through silently — e.g. `--break-lock` defaulting to `true` would make
    // `apply` steal a live lock, or the API/proxy URLs silently retargeting.
    assert_eq!(a.common.api_url, "https://api.socket.dev");
    assert_eq!(a.common.api_token, None);
    assert_eq!(a.common.org, None);
    assert_eq!(a.common.proxy_url, "https://patches-api.socket.dev");
    assert!(!a.common.yes);
    assert!(!a.common.debug);
    assert!(!a.common.no_telemetry);
    assert!(!a.common.break_lock);
    assert_eq!(a.common.lock_timeout, None);

    // `apply --check` is read-only audit mode. It MUST default off, otherwise
    // a plain `apply` would silently stop mutating anything. Pinning this is
    // the whole point of a "defaults" snapshot — leaving it out is exactly the
    // loophole that would let that default flip to `true` unnoticed.
    assert!(!a.check);

    // Embedded VEX is opt-in: off / unset by default.
    assert_eq!(a.vex.vex, None);
    assert_eq!(a.vex.vex_product, None);
    assert!(!a.vex.vex_no_verify);
    assert_eq!(a.vex.vex_doc_id, None);
    assert!(!a.vex.vex_compact);
}

/// `--check` (cargo redirect audit mode) must parse and flip the flag true.
/// It uses a `BoolishValueParser`, so the bare flag form is the canonical use.
#[test]
fn check_long() {
    assert!(parse_apply(&["--check"]).check);
}

// ---------------------------------------------------------------------------
// Embedded VEX flags (`--vex` + `--vex-*` passthrough). `--vex <path>` is
// the trigger; the rest mirror the standalone `vex` command's knobs.
// ---------------------------------------------------------------------------

#[test]
fn vex_path_sets_output() {
    assert_eq!(
        parse_apply(&["--vex", "out.vex.json"]).vex.vex,
        Some(PathBuf::from("out.vex.json"))
    );
}

#[test]
fn vex_passthrough_flags() {
    let a = parse_apply(&[
        "--vex",
        "out.vex.json",
        "--vex-product",
        "pkg:npm/app@1.0.0",
        "--vex-no-verify",
        "--vex-doc-id",
        "urn:uuid:fixed",
        "--vex-compact",
    ]);
    assert_eq!(a.vex.vex, Some(PathBuf::from("out.vex.json")));
    assert_eq!(a.vex.vex_product.as_deref(), Some("pkg:npm/app@1.0.0"));
    assert!(a.vex.vex_no_verify);
    assert_eq!(a.vex.vex_doc_id.as_deref(), Some("urn:uuid:fixed"));
    assert!(a.vex.vex_compact);
}

/// The `download_mode` default is pinned separately — it's the one
/// field whose default value diverges across subcommands historically,
/// so we assert it explicitly to catch drift.
#[test]
fn default_download_mode_is_diff() {
    assert_eq!(parse_apply(&[]).common.download_mode, "diff");
}

/// The `manifest_path` default is contract — many scripts hard-code
/// `.socket/manifest.json` as the canonical location.
#[test]
fn default_manifest_path_is_dot_socket_manifest_json() {
    assert_eq!(parse_apply(&[]).common.manifest_path, ".socket/manifest.json");
}

// ---------------------------------------------------------------------------
// Boolean flags — long form, then short form (where applicable).
// ---------------------------------------------------------------------------

#[test]
fn dry_run_long() {
    assert!(parse_apply(&["--dry-run"]).common.dry_run);
}

#[test]
fn silent_long() {
    assert!(parse_apply(&["--silent"]).common.silent);
}

#[test]
fn silent_short() {
    assert!(parse_apply(&["-s"]).common.silent);
}

#[test]
fn global_long() {
    assert!(parse_apply(&["--global"]).common.global);
}

#[test]
fn global_short() {
    assert!(parse_apply(&["-g"]).common.global);
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
    assert!(parse_apply(&["--verbose"]).common.verbose);
}

#[test]
fn verbose_short() {
    assert!(parse_apply(&["-v"]).common.verbose);
}

#[test]
fn offline_long() {
    assert!(parse_apply(&["--offline"]).common.offline);
}

#[test]
fn json_long() {
    assert!(parse_apply(&["--json"]).common.json);
}

#[test]
fn json_short() {
    assert!(parse_apply(&["-j"]).common.json);
}

#[test]
fn yes_long() {
    assert!(parse_apply(&["--yes"]).common.yes);
}

#[test]
fn yes_short() {
    assert!(parse_apply(&["-y"]).common.yes);
}

#[test]
fn debug_long() {
    assert!(parse_apply(&["--debug"]).common.debug);
}

#[test]
fn no_telemetry_long() {
    assert!(parse_apply(&["--no-telemetry"]).common.no_telemetry);
}

#[test]
fn break_lock_long() {
    assert!(parse_apply(&["--break-lock"]).common.break_lock);
}

// ---------------------------------------------------------------------------
// Value flags — long form, then short form (where applicable).
// ---------------------------------------------------------------------------

#[test]
fn cwd_long() {
    assert_eq!(parse_apply(&["--cwd", "/tmp/x"]).common.cwd, PathBuf::from("/tmp/x"));
}

#[test]
fn manifest_path_long() {
    assert_eq!(
        parse_apply(&["--manifest-path", "custom.json"]).common.manifest_path,
        "custom.json"
    );
}

#[test]
fn global_prefix_long() {
    assert_eq!(
        parse_apply(&["--global-prefix", "/foo"]).common.global_prefix,
        Some(PathBuf::from("/foo"))
    );
}

#[test]
fn api_url_long() {
    assert_eq!(
        parse_apply(&["--api-url", "https://api.example.test"]).common.api_url,
        "https://api.example.test"
    );
}

#[test]
fn api_token_long() {
    assert_eq!(
        parse_apply(&["--api-token", "tok-123"]).common.api_token.as_deref(),
        Some("tok-123")
    );
}

#[test]
fn proxy_url_long() {
    assert_eq!(
        parse_apply(&["--proxy-url", "https://proxy.example.test"]).common.proxy_url,
        "https://proxy.example.test"
    );
}

#[test]
fn org_long() {
    assert_eq!(parse_apply(&["--org", "acme"]).common.org.as_deref(), Some("acme"));
}

#[test]
fn org_short() {
    assert_eq!(parse_apply(&["-o", "acme"]).common.org.as_deref(), Some("acme"));
}

#[test]
fn lock_timeout_long() {
    assert_eq!(parse_apply(&["--lock-timeout", "30"]).common.lock_timeout, Some(30));
}

#[test]
fn ecosystems_short() {
    assert_eq!(
        parse_apply(&["-e", "npm,cargo"]).common.ecosystems,
        Some(vec!["npm".to_string(), "cargo".to_string()])
    );
}

// ---------------------------------------------------------------------------
// --ecosystems CSV split — the contract is that a comma-delimited value
// expands into a Vec<String>. Wrappers rely on this single-flag form.
// ---------------------------------------------------------------------------

#[test]
fn ecosystems_csv_splits_into_vec() {
    assert_eq!(
        parse_apply(&["--ecosystems", "npm,pypi,cargo"]).common.ecosystems,
        Some(vec!["npm".to_string(), "pypi".to_string(), "cargo".to_string()])
    );
}

#[test]
fn ecosystems_single_value() {
    assert_eq!(
        parse_apply(&["--ecosystems", "npm"]).common.ecosystems,
        Some(vec!["npm".to_string()])
    );
}

// ---------------------------------------------------------------------------
// --download-mode — accepted token values are documented contract.
// ---------------------------------------------------------------------------

#[test]
fn download_mode_diff() {
    assert_eq!(parse_apply(&["--download-mode", "diff"]).common.download_mode, "diff");
}

#[test]
fn download_mode_package() {
    assert_eq!(
        parse_apply(&["--download-mode", "package"]).common.download_mode,
        "package"
    );
}

#[test]
fn download_mode_file() {
    assert_eq!(parse_apply(&["--download-mode", "file"]).common.download_mode, "file");
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
