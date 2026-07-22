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

/// Every boolean toggle on `apply`, as `(contract name, current value)`.
/// Used to prove that a single flag flips *only* its own field — without
/// this, each positive test ignores all other fields, so a parser bug that
/// cross-wired `--yes` into `--force` (auto-approve → silently bypass the
/// beforeHash check) or any flag into `--global` would still
/// stay green. Keep this in sync with the boolean flags in the contract.
fn bool_flags(a: &ApplyArgs) -> Vec<(&'static str, bool)> {
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
        ("force", a.force),
        ("check", a.check),
        ("vex_no_verify", a.vex.vex_no_verify),
        ("vex_compact", a.vex.vex_compact),
    ]
}

/// Assert that exactly the flags named in `expected_true` are set, and every
/// other boolean toggle stayed at its `false` default. Closes the
/// cross-contamination loophole: a flag that silently flips an *extra* field
/// now fails loudly instead of passing because nobody looked.
fn assert_only_true(a: &ApplyArgs, expected_true: &[&str]) {
    for (name, value) in bool_flags(a) {
        let want = expected_true.contains(&name);
        assert_eq!(
            value, want,
            "flag `{name}` = {value}, expected {want} (set flags: {expected_true:?}) \
             — a single flag must not flip any other boolean"
        );
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
    // through silently — e.g. `--yes` defaulting to `true` would make
    // `apply` auto-approve every prompt. The API/proxy URLs parse to `None`
    // (no clap default) — the documented production URLs are applied by
    // `get_api_client_with_overrides` after env + socket-cli config fallback.
    assert_eq!(a.common.api_url, None);
    assert_eq!(a.common.api_token, None);
    assert_eq!(a.common.org, None);
    assert_eq!(a.common.proxy_url, None);
    assert!(!a.common.yes);
    assert!(!a.common.debug);
    assert!(!a.common.no_telemetry);
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

    // Belt-and-suspenders: with no args, NO boolean toggle may be on.
    assert_only_true(&a, &[]);
}

/// `--check` (cargo redirect audit mode) must parse and flip the flag true.
/// It uses a `BoolishValueParser`, so the bare flag form is the canonical use.
#[test]
fn check_long() {
    let a = parse_apply(&["--check"]);
    assert!(a.check);
    assert_only_true(&a, &["check"]);
}

// ---------------------------------------------------------------------------
// Embedded VEX flags (`--vex` + `--vex-*` passthrough). `--vex <path>` is
// the trigger; the rest mirror the standalone `vex` command's knobs.
// ---------------------------------------------------------------------------

#[test]
fn vex_path_sets_output() {
    let a = parse_apply(&["--vex", "out.vex.json"]);
    assert_eq!(a.vex.vex, Some(PathBuf::from("out.vex.json")));
    // The trigger flag alone must not flip any other vex knob or boolean.
    assert_eq!(a.vex.vex_product, None);
    assert_eq!(a.vex.vex_doc_id, None);
    assert_only_true(&a, &[]);
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
    // Only the two vex booleans should be set; nothing else (e.g. --force) may
    // ride along on the vex passthrough.
    assert_only_true(&a, &["vex_no_verify", "vex_compact"]);
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
    assert_eq!(
        parse_apply(&[]).common.manifest_path,
        ".socket/manifest.json"
    );
}

// ---------------------------------------------------------------------------
// Boolean flags — long form, then short form (where applicable).
// ---------------------------------------------------------------------------

#[test]
fn dry_run_long() {
    let a = parse_apply(&["--dry-run"]);
    assert!(a.common.dry_run);
    assert_only_true(&a, &["dry_run"]);
}

#[test]
fn silent_long() {
    let a = parse_apply(&["--silent"]);
    assert!(a.common.silent);
    assert_only_true(&a, &["silent"]);
}

#[test]
fn silent_short() {
    let a = parse_apply(&["-s"]);
    assert!(a.common.silent);
    assert_only_true(&a, &["silent"]);
}

#[test]
fn global_long() {
    let a = parse_apply(&["--global"]);
    assert!(a.common.global);
    assert_only_true(&a, &["global"]);
}

#[test]
fn global_short() {
    let a = parse_apply(&["-g"]);
    assert!(a.common.global);
    assert_only_true(&a, &["global"]);
}

#[test]
fn force_long() {
    let a = parse_apply(&["--force"]);
    assert!(a.force);
    assert_only_true(&a, &["force"]);
}

#[test]
fn force_short() {
    let a = parse_apply(&["-f"]);
    assert!(a.force);
    assert_only_true(&a, &["force"]);
}

#[test]
fn verbose_long() {
    let a = parse_apply(&["--verbose"]);
    assert!(a.common.verbose);
    assert_only_true(&a, &["verbose"]);
}

#[test]
fn verbose_short() {
    let a = parse_apply(&["-v"]);
    assert!(a.common.verbose);
    assert_only_true(&a, &["verbose"]);
}

#[test]
fn offline_long() {
    let a = parse_apply(&["--offline"]);
    assert!(a.common.offline);
    assert_only_true(&a, &["offline"]);
}

#[test]
fn json_long() {
    let a = parse_apply(&["--json"]);
    assert!(a.common.json);
    assert_only_true(&a, &["json"]);
}

#[test]
fn json_short() {
    let a = parse_apply(&["-j"]);
    assert!(a.common.json);
    assert_only_true(&a, &["json"]);
}

#[test]
fn yes_long() {
    let a = parse_apply(&["--yes"]);
    assert!(a.common.yes);
    // `--yes` must NOT imply `--force`: auto-approving prompts is not the same
    // as bypassing the beforeHash safety check.
    assert_only_true(&a, &["yes"]);
}

#[test]
fn yes_short() {
    let a = parse_apply(&["-y"]);
    assert!(a.common.yes);
    assert_only_true(&a, &["yes"]);
}

#[test]
fn debug_long() {
    let a = parse_apply(&["--debug"]);
    assert!(a.common.debug);
    assert_only_true(&a, &["debug"]);
}

#[test]
fn no_telemetry_long() {
    let a = parse_apply(&["--no-telemetry"]);
    assert!(a.common.no_telemetry);
    assert_only_true(&a, &["no_telemetry"]);
}

/// Bare boolean flags are `SetTrue` (num_args = 0): they must NOT swallow the
/// following token as a value. If `--force` silently became value-taking, a
/// wrapper invoking `apply --force <something>` would change meaning. Assert
/// the trailing token is rejected as an unknown argument.
#[test]
fn bare_bool_does_not_consume_next_token() {
    match Cli::try_parse_from(["socket-patch", "apply", "--force", "stray"]) {
        Ok(_) => panic!("`--force stray` must reject the stray positional"),
        Err(err) => assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument),
    }
}

/// All boolean toggles set at once: each must independently be true. Catches a
/// regression where two flags share storage (only the last would win) or a
/// flag is dropped entirely.
#[test]
fn all_bools_settable_together() {
    let a = parse_apply(&[
        "--dry-run",
        "--silent",
        "--global",
        "--offline",
        "--json",
        "--verbose",
        "--yes",
        "--debug",
        "--no-telemetry",
        "--force",
        "--check",
    ]);
    assert_only_true(
        &a,
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
            "force",
            "check",
        ],
    );
}

/// All short flags bundled together must each map to their own distinct field.
/// Decisively catches short-flag cross-wiring (e.g. `-g` and `-j` writing the
/// same field).
#[test]
fn all_short_flags_map_to_distinct_fields() {
    let a = parse_apply(&["-sgjvyf", "-o", "acme", "-e", "npm,cargo"]);
    assert!(a.common.silent, "-s");
    assert!(a.common.global, "-g");
    assert!(a.common.json, "-j");
    assert!(a.common.verbose, "-v");
    assert!(a.common.yes, "-y");
    assert!(a.force, "-f");
    assert_eq!(a.common.org.as_deref(), Some("acme"), "-o");
    assert_eq!(
        a.common.ecosystems,
        Some(vec!["npm".to_string(), "cargo".to_string()]),
        "-e"
    );
    assert_only_true(&a, &["silent", "global", "json", "verbose", "yes", "force"]);
}

// ---------------------------------------------------------------------------
// Value flags — long form, then short form (where applicable).
// ---------------------------------------------------------------------------

#[test]
fn cwd_long() {
    assert_eq!(
        parse_apply(&["--cwd", "/tmp/x"]).common.cwd,
        PathBuf::from("/tmp/x")
    );
}

#[test]
fn manifest_path_long() {
    assert_eq!(
        parse_apply(&["--manifest-path", "custom.json"])
            .common
            .manifest_path,
        "custom.json"
    );
}

#[test]
fn global_prefix_long() {
    assert_eq!(
        parse_apply(&["--global-prefix", "/foo"])
            .common
            .global_prefix,
        Some(PathBuf::from("/foo"))
    );
}

#[test]
fn api_url_long() {
    assert_eq!(
        parse_apply(&["--api-url", "https://api.example.test"])
            .common
            .api_url
            .as_deref(),
        Some("https://api.example.test")
    );
}

#[test]
fn api_token_long() {
    assert_eq!(
        parse_apply(&["--api-token", "tok-123"])
            .common
            .api_token
            .as_deref(),
        Some("tok-123")
    );
}

#[test]
fn proxy_url_long() {
    assert_eq!(
        parse_apply(&["--proxy-url", "https://proxy.example.test"])
            .common
            .proxy_url
            .as_deref(),
        Some("https://proxy.example.test")
    );
}

#[test]
fn org_long() {
    assert_eq!(
        parse_apply(&["--org", "acme"]).common.org.as_deref(),
        Some("acme")
    );
}

#[test]
fn org_short() {
    assert_eq!(
        parse_apply(&["-o", "acme"]).common.org.as_deref(),
        Some("acme")
    );
}

#[test]
fn lock_timeout_long() {
    assert_eq!(
        parse_apply(&["--lock-timeout", "30"]).common.lock_timeout,
        Some(30)
    );
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
        parse_apply(&["--ecosystems", "npm,pypi,cargo"])
            .common
            .ecosystems,
        Some(vec![
            "npm".to_string(),
            "pypi".to_string(),
            "cargo".to_string()
        ])
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
    assert_eq!(
        parse_apply(&["--download-mode", "diff"])
            .common
            .download_mode,
        "diff"
    );
}

#[test]
fn download_mode_package() {
    assert_eq!(
        parse_apply(&["--download-mode", "package"])
            .common
            .download_mode,
        "package"
    );
}

#[test]
fn download_mode_file() {
    assert_eq!(
        parse_apply(&["--download-mode", "file"])
            .common
            .download_mode,
        "file"
    );
}

/// Values pass through verbatim — no lowercasing, trimming, or aliasing at the
/// parse layer. `package` must not silently normalize to `diff`, etc. This
/// guards against a parser that quietly coerces input to a default.
#[test]
fn download_mode_values_are_not_normalized() {
    // Case is preserved verbatim (parse does not canonicalize).
    assert_eq!(
        parse_apply(&["--download-mode", "DIFF"])
            .common
            .download_mode,
        "DIFF"
    );
    // The three valid tokens are distinct and round-trip exactly.
    for token in ["diff", "package", "file"] {
        let got = parse_apply(&["--download-mode", token])
            .common
            .download_mode;
        assert_eq!(
            got, token,
            "download-mode `{token}` must round-trip exactly"
        );
    }
}

/// CONTRACT GAP (documented, not a hardening of a passing behavior): the
/// contract types `--download-mode` as `enum: diff | package | file`, but the
/// arg is a plain `String` with no `value_parser`, so clap accepts ANY value
/// at parse time. Invalid values are only rejected later by
/// `DownloadMode::parse` at runtime (see `commands/apply.rs`). This test pins
/// the *current* parse-layer behavior so a future move to a real
/// `value_parser`/enum (which WOULD reject here) is a deliberate, visible
/// change rather than a silent one. If the enum is enforced at parse, flip the
/// expectation to assert an `InvalidValue` error.
#[test]
fn download_mode_invalid_value_is_only_caught_at_runtime() {
    match Cli::try_parse_from(["socket-patch", "apply", "--download-mode", "totally-bogus"]) {
        Ok(cli) => match cli.command {
            Commands::Apply(a) => assert_eq!(
                a.common.download_mode, "totally-bogus",
                "parse layer currently passes unknown download modes through verbatim"
            ),
            _ => panic!("expected Apply"),
        },
        Err(err) => panic!(
            "parse layer unexpectedly rejected an unknown download-mode (kind={:?}); \
             if the enum is now enforced at parse, update this test to assert InvalidValue",
            err.kind()
        ),
    }
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
