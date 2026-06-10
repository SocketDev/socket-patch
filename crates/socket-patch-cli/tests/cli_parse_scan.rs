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

/// Every `ScanArgs`/`GlobalArgs`/`VexEmbedArgs` field that has an `env =
/// "SOCKET_*"` binding. clap reads these at parse time whenever the matching
/// flag is absent, so an ambient value silently overrides the code-level
/// `default_value`. That defeats the entire purpose of these snapshot tests:
/// a regression that flips a `default_value` (e.g. `--download-mode` →
/// `"package"`, or `--batch-size` → `50`) would stay GREEN on any machine
/// whose shell/CI happens to export the old value, and the "default" tests
/// would be asserting the environment, not the parser. We therefore clear
/// the whole set before every parse and restore it after, under `#[serial]`
/// so the process-global mutation can't race a concurrent test.
///
/// Keep this list in sync with `env = "SOCKET_*"` attrs in
/// `src/args.rs`, `src/commands/scan.rs`, and `src/commands/vex.rs`.
const SCAN_ENV_VARS: &[&str] = &[
    "SOCKET_ALL_RELEASES",
    "SOCKET_API_TOKEN",
    "SOCKET_API_URL",
    "SOCKET_BATCH_SIZE",
    "SOCKET_BREAK_LOCK",
    "SOCKET_CWD",
    "SOCKET_DEBUG",
    "SOCKET_DOWNLOAD_MODE",
    "SOCKET_DRY_RUN",
    "SOCKET_ECOSYSTEMS",
    "SOCKET_GLOBAL",
    "SOCKET_GLOBAL_PREFIX",
    "SOCKET_JSON",
    "SOCKET_LOCK_TIMEOUT",
    "SOCKET_MANIFEST_PATH",
    "SOCKET_OFFLINE",
    "SOCKET_ORG_SLUG",
    "SOCKET_PROXY_URL",
    "SOCKET_SILENT",
    "SOCKET_TELEMETRY_DISABLED",
    "SOCKET_VERBOSE",
    "SOCKET_VEX",
    "SOCKET_VEX_COMPACT",
    "SOCKET_VEX_DOC_ID",
    "SOCKET_VEX_NO_VERIFY",
    "SOCKET_VEX_OUTPUT",
    "SOCKET_VEX_PRODUCT",
    "SOCKET_YES",
];

/// Run `f` with every `SOCKET_*` var removed from the environment, then
/// restore the originals. Must be called only from `#[serial]` tests —
/// env state is process-global.
fn with_clean_env<T>(f: impl FnOnce() -> T) -> T {
    let saved: Vec<(&str, Option<String>)> = SCAN_ENV_VARS
        .iter()
        .map(|k| (*k, std::env::var(k).ok()))
        .collect();
    for k in SCAN_ENV_VARS {
        std::env::remove_var(k);
    }
    let result = f();
    for (k, orig) in saved {
        match orig {
            Some(v) => std::env::set_var(k, v),
            None => std::env::remove_var(k),
        }
    }
    result
}

fn parse_scan(extra: &[&str]) -> ScanArgs {
    let mut argv = vec!["socket-patch", "scan"];
    argv.extend_from_slice(extra);
    let cli = with_clean_env(|| Cli::try_parse_from(&argv)).expect("parse");
    match cli.command {
        Commands::Scan(a) => a,
        _ => panic!("expected Scan"),
    }
}

fn try_parse_scan(extra: &[&str]) -> Result<ScanArgs, clap::Error> {
    let mut argv = vec!["socket-patch", "scan"];
    argv.extend_from_slice(extra);
    let cli = with_clean_env(|| Cli::try_parse_from(&argv))?;
    match cli.command {
        Commands::Scan(a) => Ok(a),
        _ => panic!("expected Scan"),
    }
}

#[test]
#[serial_test::serial]
fn defaults_match_contract() {
    let args = parse_scan(&[]);

    // Critical load-bearing defaults.
    assert_eq!(args.batch_size, 100, "--batch-size default is 100");
    assert_eq!(
        args.common.download_mode, "diff",
        "--download-mode default is \"diff\""
    );

    // All other defaults from the scan table.
    assert_eq!(args.common.cwd, std::path::PathBuf::from("."));
    assert_eq!(args.common.org, None);
    assert!(!args.common.json);
    assert!(!args.common.yes);
    assert!(!args.common.global);
    assert_eq!(args.common.global_prefix, None);
    assert_eq!(args.common.api_url, "https://api.socket.dev");
    assert_eq!(args.common.api_token, None);
    assert_eq!(args.common.ecosystems, None);
    assert!(
        !args.apply,
        "--apply default is false (scan --json stays read-only)"
    );
    assert!(
        !args.prune,
        "--prune default is false (GC is opt-in in v3.0)"
    );
    assert!(!args.sync, "--sync default is false");
    assert!(!args.common.dry_run, "--dry-run default is false");
    assert!(
        !args.all_releases,
        "--all-releases default is false (narrow — installed-dist variant only)"
    );
    // Embedded VEX is opt-in: off / unset by default.
    assert_eq!(args.vex.vex, None);
    assert_eq!(args.vex.vex_product, None);
    assert!(!args.vex.vex_no_verify);
    assert_eq!(args.vex.vex_doc_id, None);
    assert!(!args.vex.vex_compact);
}

#[test]
#[serial_test::serial]
fn vex_path_sets_output() {
    assert_eq!(
        parse_scan(&["--vex", "out.vex.json"]).vex.vex,
        Some(std::path::PathBuf::from("out.vex.json"))
    );
}

#[test]
#[serial_test::serial]
fn vex_passthrough_flags() {
    let args = parse_scan(&[
        "--vex",
        "out.vex.json",
        "--vex-product",
        "pkg:npm/app@1.0.0",
        "--vex-no-verify",
        "--vex-doc-id",
        "urn:uuid:fixed",
        "--vex-compact",
    ]);
    assert_eq!(args.vex.vex, Some(std::path::PathBuf::from("out.vex.json")));
    assert_eq!(args.vex.vex_product.as_deref(), Some("pkg:npm/app@1.0.0"));
    assert!(args.vex.vex_no_verify);
    assert_eq!(args.vex.vex_doc_id.as_deref(), Some("urn:uuid:fixed"));
    assert!(args.vex.vex_compact);
}

#[test]
#[serial_test::serial]
fn all_releases_flag_long_form() {
    let args = parse_scan(&["--all-releases"]);
    assert!(args.all_releases);
}

#[test]
#[serial_test::serial]
fn yes_short_flag() {
    let args = parse_scan(&["-y"]);
    assert!(args.common.yes);
}

#[test]
#[serial_test::serial]
fn yes_long_flag() {
    let args = parse_scan(&["--yes"]);
    assert!(args.common.yes);
}

#[test]
#[serial_test::serial]
fn global_short_flag() {
    let args = parse_scan(&["-g"]);
    assert!(args.common.global);
}

#[test]
#[serial_test::serial]
fn global_long_flag() {
    let args = parse_scan(&["--global"]);
    assert!(args.common.global);
}

#[test]
#[serial_test::serial]
fn cwd_flag() {
    let args = parse_scan(&["--cwd", "/tmp/x"]);
    assert_eq!(args.common.cwd, std::path::PathBuf::from("/tmp/x"));
}

#[test]
#[serial_test::serial]
fn org_flag() {
    let args = parse_scan(&["--org", "myorg"]);
    assert_eq!(args.common.org.as_deref(), Some("myorg"));
}

#[test]
#[serial_test::serial]
fn json_flag() {
    let args = parse_scan(&["--json"]);
    assert!(args.common.json);
}

#[test]
#[serial_test::serial]
fn global_prefix_flag() {
    let args = parse_scan(&["--global-prefix", "/foo"]);
    assert_eq!(
        args.common.global_prefix,
        Some(std::path::PathBuf::from("/foo"))
    );
}

#[test]
#[serial_test::serial]
fn api_url_flag() {
    let args = parse_scan(&["--api-url", "https://api"]);
    assert_eq!(args.common.api_url, "https://api");
}

#[test]
#[serial_test::serial]
fn api_token_flag() {
    let args = parse_scan(&["--api-token", "tok"]);
    assert_eq!(args.common.api_token.as_deref(), Some("tok"));
}

#[test]
#[serial_test::serial]
fn batch_size_500() {
    let args = parse_scan(&["--batch-size", "500"]);
    assert_eq!(args.batch_size, 500);
}

#[test]
#[serial_test::serial]
fn batch_size_1() {
    let args = parse_scan(&["--batch-size", "1"]);
    assert_eq!(args.batch_size, 1);
}

#[test]
#[serial_test::serial]
fn batch_size_0_parses() {
    // Clap accepts 0 as a valid usize. Whether 0 is a sensible batch size is
    // a command-level concern, not a parser concern. Lock in that the parser
    // itself does not reject it.
    let args = parse_scan(&["--batch-size", "0"]);
    assert_eq!(args.batch_size, 0);
}

#[test]
#[serial_test::serial]
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
#[serial_test::serial]
fn ecosystems_csv_multi() {
    // Use only the unconditional ecosystems (npm/pypi/gem are always
    // compiled in) so this CSV-splitting assertion is independent of which
    // optional ecosystem features the test crate was built with.
    let args = parse_scan(&["--ecosystems", "npm,pypi,gem"]);
    assert_eq!(
        args.common.ecosystems,
        Some(vec![
            "npm".to_string(),
            "pypi".to_string(),
            "gem".to_string(),
        ])
    );
}

#[test]
#[serial_test::serial]
fn ecosystems_unsupported_name_rejected() {
    // The `--ecosystems` value-parser rejects names this build does not
    // support — both typos and ecosystems whose feature is not compiled
    // in. `definitely-not-an-ecosystem` is never a valid name in any
    // feature configuration, so this assertion holds regardless of the
    // build's feature set.
    let err = match try_parse_scan(&["--ecosystems", "definitely-not-an-ecosystem"]) {
        Ok(_) => panic!("unsupported ecosystem name should fail to parse"),
        Err(e) => e,
    };
    assert!(
        matches!(
            err.kind(),
            clap::error::ErrorKind::ValueValidation | clap::error::ErrorKind::InvalidValue
        ),
        "expected ValueValidation or InvalidValue, got {:?}",
        err.kind()
    );
}

/// maven is not in the default feature set, so a default build must reject
/// `--ecosystems maven` (the whole point of marking it unsupported). When
/// the `maven` feature *is* compiled in, the name is legitimately accepted,
/// so this assertion is itself feature-gated to match.
#[cfg(not(feature = "maven"))]
#[test]
#[serial_test::serial]
fn ecosystems_maven_rejected_without_feature() {
    let err = match try_parse_scan(&["--ecosystems", "maven"]) {
        Ok(_) => panic!("`maven` must be rejected when the maven feature is off"),
        Err(e) => e,
    };
    assert!(
        matches!(
            err.kind(),
            clap::error::ErrorKind::ValueValidation | clap::error::ErrorKind::InvalidValue
        ),
        "expected ValueValidation or InvalidValue, got {:?}",
        err.kind()
    );
}

#[test]
#[serial_test::serial]
fn ecosystems_csv_single() {
    let args = parse_scan(&["--ecosystems", "npm"]);
    assert_eq!(args.common.ecosystems, Some(vec!["npm".to_string()]));
}

#[test]
#[serial_test::serial]
fn download_mode_diff() {
    let args = parse_scan(&["--download-mode", "diff"]);
    assert_eq!(args.common.download_mode, "diff");
}

#[test]
#[serial_test::serial]
fn download_mode_package() {
    let args = parse_scan(&["--download-mode", "package"]);
    assert_eq!(args.common.download_mode, "package");
}

#[test]
#[serial_test::serial]
fn download_mode_file() {
    let args = parse_scan(&["--download-mode", "file"]);
    assert_eq!(args.common.download_mode, "file");
}

#[test]
#[serial_test::serial]
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
#[serial_test::serial]
fn apply_flag_long_form() {
    let args = parse_scan(&["--apply"]);
    assert!(args.apply);
}

#[test]
#[serial_test::serial]
fn apply_flag_combines_with_json_and_yes() {
    let args = parse_scan(&["--apply", "--json", "--yes"]);
    assert!(args.apply);
    assert!(args.common.json);
    assert!(args.common.yes);
}

// --- `--prune` / `--sync` / `--dry-run` flags (v3.0 GC opt-in) ------------
//
// `--prune` opts into GC. `--sync` is sugar for `--apply --prune`.
// `--dry-run` (`-d`) previews what those flags would do without mutating.

#[test]
#[serial_test::serial]
fn prune_flag_long_form() {
    let args = parse_scan(&["--prune"]);
    assert!(args.prune);
}

#[test]
#[serial_test::serial]
fn prune_combines_with_apply_and_json() {
    let args = parse_scan(&["--apply", "--json", "--yes", "--prune"]);
    assert!(args.apply);
    assert!(args.common.json);
    assert!(args.common.yes);
    assert!(args.prune);
}

#[test]
#[serial_test::serial]
fn sync_flag_long_form() {
    let args = parse_scan(&["--sync"]);
    assert!(args.sync);
    // --sync alone doesn't set --apply or --prune (the derivation
    // happens inside scan::run, not at parser time).
    assert!(!args.apply);
    assert!(!args.prune);
}

#[test]
#[serial_test::serial]
fn sync_combines_with_json_and_yes() {
    let args = parse_scan(&["--json", "--sync", "--yes"]);
    assert!(args.common.json);
    assert!(args.sync);
    assert!(args.common.yes);
}

#[test]
#[serial_test::serial]
fn dry_run_long_form() {
    let args = parse_scan(&["--dry-run"]);
    assert!(args.common.dry_run);
}

#[test]
#[serial_test::serial]
fn scan_json_empty_cwd_emits_updates_key() {
    // Spawn the compiled binary against an empty tempdir so no API call
    // happens (no packages found → early "no packages" JSON return).
    //
    // NOTE: this exercises the *short-circuit* empty-scan branch in
    // `scan::run`, where the whole result object — including `updates` — is
    // a hardcoded literal. It does NOT cover `detect_updates`, the real
    // function that populates `updates` once packages with patches are
    // discovered (that path needs live API results and cannot run
    // hermetically here, and `detect_updates` is `pub(crate)` so it can't
    // be unit-tested from this integration crate). What this test CAN do is
    // lock the empty-scan JSON contract *exactly*, so a regression that
    // drops/renames a key, flips a default count, or leaks an unexpected
    // `gc`/`apply`/`vex` sub-object onto the read-only default path fails
    // loudly. See the summary for the uncovered `detect_updates` gap.
    let bin = env!("CARGO_BIN_EXE_socket-patch");
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut cmd = std::process::Command::new(bin);
    cmd.args(["scan", "--json", "--cwd"]).arg(tmp.path());
    // Strip *every* SOCKET_* override the child would otherwise inherit.
    // It is not enough to drop the API creds: an ambient `SOCKET_VEX` would
    // fold a `vex` object into the output, `SOCKET_OFFLINE`/`SOCKET_GLOBAL`
    // would steer the crawl, and `SOCKET_JSON=false` would suppress JSON
    // entirely — any of which would either spuriously fail the exact-shape
    // lock or, worse, change the branch under test. Clear them all so the
    // subprocess sees only the CLI args we pass.
    for k in SCAN_ENV_VARS {
        cmd.env_remove(k);
    }
    let out = cmd.output().expect("spawn socket-patch");

    assert_eq!(
        out.status.code(),
        Some(0),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    let v: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("scan emitted valid JSON");

    // Exact-shape lock: the empty-scan JSON must be *precisely* this object.
    // Full-object equality (rather than per-key spot checks) is what makes
    // the regression net tight — it catches both missing keys (e.g. a
    // dropped `updates`) and unexpected extra keys (e.g. a `gc`/`apply`
    // object that must NOT appear when neither was requested, since both
    // default to false here).
    let expected = serde_json::json!({
        "status": "success",
        "scannedPackages": 0,
        "packagesWithPatches": 0,
        "totalPatches": 0,
        "freePatches": 0,
        "paidPatches": 0,
        "canAccessPaidPatches": false,
        "packages": [],
        "updates": [],
    });
    assert_eq!(
        v,
        expected,
        "empty-scan JSON contract drifted.\nexpected:\n{}\ngot:\n{}",
        serde_json::to_string_pretty(&expected).unwrap(),
        serde_json::to_string_pretty(&v).unwrap(),
    );

    // Belt-and-suspenders on the two type invariants the contract names,
    // in case the object above is ever loosened during maintenance.
    assert!(v["packages"].is_array(), "packages must be an array");
    assert!(
        v["updates"].is_array(),
        "updates must be present and an array"
    );
    assert!(
        v.get("gc").is_none(),
        "no `gc` sub-object may appear when --prune was not passed"
    );
    assert!(
        v.get("apply").is_none(),
        "no `apply` sub-object may appear when --apply was not passed"
    );
}
