//! Compose tests: every global flag must be accepted on every subcommand.
//!
//! `GlobalArgs` is `#[command(flatten)]`-ed into each subcommand's `Args`
//! struct, so each subcommand should accept the full set of global flags.
//! This file catches regressions if a new subcommand is added and someone
//! forgets the flatten, or if a flag is accidentally dropped from
//! `GlobalArgs`.
//!
//! For commands that have a required positional (e.g. `get` and `remove`
//! take an identifier), we supply a dummy value alongside the flag under
//! test so clap's parser can complete.

// The case tables below are tuples ending in `fn(&GlobalArgs)` pointers; a
// `type` alias per shape would add more noise than it removes in this test.
#![allow(clippy::type_complexity)]

use std::path::PathBuf;

use clap::Parser;
use socket_patch_cli::args::GlobalArgs;
use socket_patch_cli::Cli;

/// Subcommands under test. `rollback` is omitted because its only positional
/// is optional — covered by the no-positional variant. Setup is exercised
/// even though most globals are no-ops there; the point is to lock in that
/// every subcommand parses every global flag.
///
/// This must list **every** subcommand that flattens `GlobalArgs`. The
/// `all_subcommands_are_covered` test below introspects clap's own
/// subcommand table and fails loudly if a new subcommand is added without
/// being listed here — closing the "someone forgot the flatten on a new
/// command and nobody noticed" gap this file claims to guard.
const SUBCOMMANDS_NO_POSITIONAL: &[&str] = &[
    "apply", "list", "scan", "setup", "repair", "rollback", "unlock", "vendor", "vex",
];

/// Subcommands that require a positional identifier.
const SUBCOMMANDS_WITH_IDENTIFIER: &[&str] = &["get", "remove"];

const DUMMY_IDENTIFIER: &str = "80630680-4da6-45f9-bba8-b888e0ffd58c";

/// (flag, value-or-None, verifier) covering every flag on `GlobalArgs`.
///
/// The verifier asserts the flag actually lands in its corresponding
/// `GlobalArgs` field. Parsing-succeeds-only (`is_ok`) is not enough: it
/// would stay green if a flag were silently dropped, bound to the wrong
/// field, or mapped to a no-op. Each value is deliberately chosen to differ
/// from the field's default (e.g. `--download-mode package`, not `diff`) so
/// the assertion can distinguish "bound" from "left at default".
fn global_flag_cases() -> Vec<(&'static str, Option<&'static str>, fn(&GlobalArgs))> {
    vec![
        ("--cwd", Some("/tmp"), |c| {
            assert_eq!(c.cwd, PathBuf::from("/tmp"))
        }),
        ("--manifest-path", Some("custom.json"), |c| {
            assert_eq!(c.manifest_path, "custom.json")
        }),
        ("--api-url", Some("https://example.com"), |c| {
            assert_eq!(c.api_url, "https://example.com")
        }),
        ("--api-token", Some("tok123"), |c| {
            assert_eq!(c.api_token.as_deref(), Some("tok123"))
        }),
        ("--org", Some("acme"), |c| {
            assert_eq!(c.org.as_deref(), Some("acme"))
        }),
        ("--proxy-url", Some("https://proxy.example.com"), |c| {
            assert_eq!(c.proxy_url, "https://proxy.example.com")
        }),
        ("--ecosystems", Some("npm,pypi"), |c| {
            assert_eq!(
                c.ecosystems.as_deref(),
                Some(&["npm".to_string(), "pypi".to_string()][..])
            )
        }),
        ("--download-mode", Some("package"), |c| {
            assert_eq!(c.download_mode, "package")
        }),
        ("--vendor-source", Some("service"), |c| {
            assert_eq!(c.vendor_source, "service")
        }),
        ("--vendor-url", Some("https://vendor.example.com"), |c| {
            assert_eq!(c.vendor_url.as_deref(), Some("https://vendor.example.com"))
        }),
        ("--patch-server-url", Some("http://localhost:4026"), |c| {
            assert_eq!(c.patch_server_url.as_deref(), Some("http://localhost:4026"))
        }),
        ("--offline", None, |c| assert!(c.offline)),
        ("--global", None, |c| assert!(c.global)),
        ("--global-prefix", Some("/opt/global"), |c| {
            assert_eq!(c.global_prefix, Some(PathBuf::from("/opt/global")))
        }),
        ("--json", None, |c| assert!(c.json)),
        ("--verbose", None, |c| assert!(c.verbose)),
        ("--silent", None, |c| assert!(c.silent)),
        ("--dry-run", None, |c| assert!(c.dry_run)),
        ("--yes", None, |c| assert!(c.yes)),
        ("--debug", None, |c| assert!(c.debug)),
        ("--no-telemetry", None, |c| assert!(c.no_telemetry)),
        ("--break-lock", None, |c| assert!(c.break_lock)),
        ("--lock-timeout", Some("30"), |c| {
            assert_eq!(c.lock_timeout, Some(30))
        }),
    ]
}

/// Extract the flattened `GlobalArgs` from any parsed subcommand. The match
/// is exhaustive, so adding a `Commands` variant forces an update here —
/// another tripwire for new subcommands.
fn common_of(cli: &Cli) -> &GlobalArgs {
    use socket_patch_cli::Commands::*;
    match &cli.command {
        Apply(a) => &a.common,
        Rollback(a) => &a.common,
        Get(a) => &a.common,
        Scan(a) => &a.common,
        List(a) => &a.common,
        Remove(a) => &a.common,
        Setup(a) => &a.common,
        Repair(a) => &a.common,
        Unlock(a) => &a.common,
        Vendor(a) => &a.common,
        Vex(a) => &a.common,
    }
}

fn try_parse(subcommand: &str, extra: &[&str]) -> Result<Cli, clap::Error> {
    let mut argv: Vec<String> = vec!["socket-patch".into(), subcommand.into()];
    if SUBCOMMANDS_WITH_IDENTIFIER.contains(&subcommand) {
        argv.push(DUMMY_IDENTIFIER.into());
    }
    for &arg in extra {
        argv.push(arg.into());
    }
    Cli::try_parse_from(&argv)
}

#[test]
#[serial_test::serial]
fn every_global_flag_parses_on_every_subcommand() {
    // Serial + env-isolated: clap validates a field's `env` value during parse
    // even when the field is not on the CLI (an invalid `SOCKET_OFFLINE` will
    // abort a parse that never mentions `--offline`). So any ambient or
    // concurrently-set `SOCKET_*` value can break this matrix — the old
    // "CLI args win so it's deterministic" comment was wrong. Clear the slate.
    let saved = save_and_clear_global_env();
    let cases = global_flag_cases();
    let all_subcommands: Vec<&str> = SUBCOMMANDS_NO_POSITIONAL
        .iter()
        .chain(SUBCOMMANDS_WITH_IDENTIFIER.iter())
        .copied()
        .collect();

    for &subcommand in &all_subcommands {
        for &(flag, value, verify) in &cases {
            let extra: Vec<&str> = if let Some(v) = value {
                vec![flag, v]
            } else {
                vec![flag]
            };
            let cli = try_parse(subcommand, &extra).unwrap_or_else(|e| {
                panic!(
                    "subcommand `{}` failed to parse global flag `{}`: {}",
                    subcommand, flag, e
                )
            });
            // Not just "parsed" — the value must actually land in the
            // matching GlobalArgs field on this subcommand. With the env
            // cleared above, the only source for the field is the CLI flag.
            verify(common_of(&cli));
        }
    }

    restore_global_env(saved);
}

/// Tripwire: the long-flag matrix in `global_flag_cases()` must have exactly
/// one entry per `GlobalArgs` field. The exhaustive destructure below fails to
/// compile the moment a field is added or removed, forcing the matrix (and its
/// per-field verifier) to be updated. Without this, a newly-added global flag
/// could ship completely untested while every existing test stayed green —
/// precisely the "a flag was accidentally dropped/added" regression this file
/// claims to guard.
#[test]
#[serial_test::serial]
fn global_flag_cases_cover_every_global_field() {
    let saved = save_and_clear_global_env();
    let cli = Cli::try_parse_from(["socket-patch", "list"]).expect("parse");
    let common = common_of(&cli).clone();
    // Exhaustive: every field must be named here. `_`-binding keeps it honest
    // (we only care that the set of fields matches), and a `..` rest pattern is
    // deliberately NOT used so new fields break the build.
    let GlobalArgs {
        cwd: _,
        manifest_path: _,
        api_url: _,
        api_token: _,
        org: _,
        proxy_url: _,
        ecosystems: _,
        download_mode: _,
        offline: _,
        global: _,
        global_prefix: _,
        json: _,
        verbose: _,
        silent: _,
        dry_run: _,
        yes: _,
        lock_timeout: _,
        break_lock: _,
        debug: _,
        no_telemetry: _,
        strict: _,
        vendor_source: _,
        vendor_url: _,
        patch_server_url: _,
    } = common;

    // 23 fields ↔ 23 long-flag cases. Bump both this count and add a case when
    // the destructure above forces you to add a field.
    assert_eq!(
        global_flag_cases().len(),
        23,
        "every GlobalArgs field needs a long-flag case in global_flag_cases()",
    );

    restore_global_env(saved);
}

/// Tripwire: every subcommand clap knows about must appear in the
/// `SUBCOMMANDS_*` lists, so the global-flag matrix above genuinely covers
/// *every* command. If someone adds a subcommand (and forgets to flatten
/// `GlobalArgs`, or forgets to add it here), this fails loudly instead of
/// silently leaving the new command untested.
#[test]
fn all_subcommands_are_covered() {
    use clap::CommandFactory;

    let tested: std::collections::HashSet<&str> = SUBCOMMANDS_NO_POSITIONAL
        .iter()
        .chain(SUBCOMMANDS_WITH_IDENTIFIER.iter())
        .copied()
        .collect();

    let cmd = Cli::command();
    let real: Vec<String> = cmd
        .get_subcommands()
        .map(|s| s.get_name().to_string())
        // clap injects an implicit `help` subcommand that takes no globals.
        .filter(|n| n != "help")
        .collect();

    // Every real subcommand is exercised by the global-flag matrix.
    let missing: Vec<&String> = real
        .iter()
        .filter(|n| !tested.contains(n.as_str()))
        .collect();
    assert!(
        missing.is_empty(),
        "subcommands not covered by the global-flag tests: {:?}. \
         Add them to SUBCOMMANDS_NO_POSITIONAL / SUBCOMMANDS_WITH_IDENTIFIER \
         (with a dummy positional if the command requires one).",
        missing,
    );

    // And no stale/typo'd names that don't map to a real subcommand.
    let real_set: std::collections::HashSet<&str> = real.iter().map(|s| s.as_str()).collect();
    let stale: Vec<&&str> = tested.iter().filter(|n| !real_set.contains(*n)).collect();
    assert!(
        stale.is_empty(),
        "SUBCOMMANDS_* lists name commands clap doesn't have: {:?}",
        stale,
    );
}

/// Short forms (`-s`, `-y`, etc.) are part of the contract too. `-d`
/// and `-m` were dropped after v3.0 (they were reserved as aliases for
/// `--dry-run` and `--manifest-path` but we want those letters free
/// for future flags); the corresponding rejection check lives in
/// `reserved_short_forms_are_not_assigned` below.
#[test]
#[serial_test::serial]
fn every_global_short_form_parses_on_every_subcommand() {
    // Serial + env-isolated for the same reason as the long-flag matrix: an
    // ambient/concurrent invalid `SOCKET_*` bool would abort these parses.
    let saved = save_and_clear_global_env();
    // (short, value-or-None, verifier) — only flags that actually have a
    // short. The verifier proves the short maps to the *intended* GlobalArgs
    // field, not just that it parses (a short silently rebound to a different
    // field would otherwise stay green).
    let shorts: &[(&str, Option<&str>, fn(&GlobalArgs))] = &[
        ("-o", Some("acme"), |c| {
            assert_eq!(c.org.as_deref(), Some("acme"))
        }), // --org
        ("-e", Some("npm"), |c| {
            assert_eq!(c.ecosystems.as_deref(), Some(&["npm".to_string()][..]))
        }), // --ecosystems
        ("-g", None, |c| assert!(c.global)),  // --global
        ("-j", None, |c| assert!(c.json)),    // --json
        ("-v", None, |c| assert!(c.verbose)), // --verbose
        ("-s", None, |c| assert!(c.silent)),  // --silent
        ("-y", None, |c| assert!(c.yes)),     // --yes
    ];
    let all_subcommands: Vec<&str> = SUBCOMMANDS_NO_POSITIONAL
        .iter()
        .chain(SUBCOMMANDS_WITH_IDENTIFIER.iter())
        .copied()
        .collect();

    for &subcommand in &all_subcommands {
        for &(short, value, verify) in shorts {
            // `apply` has its own `-f` for --force; we don't test that here
            // because it's local. The shorts we test are all GlobalArgs shorts.
            // `get` has `-p` for --package (local); also not tested here.
            let extra: Vec<&str> = if let Some(v) = value {
                vec![short, v]
            } else {
                vec![short]
            };
            let cli = try_parse(subcommand, &extra).unwrap_or_else(|e| {
                panic!(
                    "subcommand `{}` failed to parse short flag `{}`: {}",
                    subcommand, short, e
                )
            });
            verify(common_of(&cli));
        }
    }

    restore_global_env(saved);
}

/// `-d` and `-m` were intentionally dropped (formerly aliases for
/// `--dry-run` and `--manifest-path`) so those letters stay free for
/// future flags. Lock that in: clap must reject the bare shorts on
/// every subcommand. The long forms still work and are exercised by
/// `every_global_flag_parses_on_every_subcommand` above.
#[test]
#[serial_test::serial]
fn reserved_short_forms_are_not_assigned() {
    // Env-isolated: an invalid ambient `SOCKET_*` bool would make clap fail
    // with ValueValidation *before* it ever reports UnknownArgument for the
    // reserved short, turning this assertion into a false positive/negative.
    let saved = save_and_clear_global_env();
    let all_subcommands: Vec<&str> = SUBCOMMANDS_NO_POSITIONAL
        .iter()
        .chain(SUBCOMMANDS_WITH_IDENTIFIER.iter())
        .copied()
        .collect();
    for &subcommand in &all_subcommands {
        for short in ["-d", "-m"] {
            let result = try_parse(subcommand, &[short]);
            assert!(
                result.is_err(),
                "`{}` should NOT accept the reserved short `{}` — \
                 if you bound it intentionally, update this test and \
                 the corresponding `--help` docs.",
                subcommand,
                short,
            );
            let err = result.err().unwrap();
            assert_eq!(
                err.kind(),
                clap::error::ErrorKind::UnknownArgument,
                "expected UnknownArgument when `{}` is passed to `{}`; got {:?}",
                short,
                subcommand,
                err.kind(),
            );
        }
    }

    restore_global_env(saved);
}

/// Locks the env-var bindings: setting a SOCKET_* env var must populate
/// the corresponding GlobalArgs field on parse.
///
/// Combined into one test to avoid env-var races between parallel tests.
#[test]
#[serial_test::serial]
fn env_vars_populate_global_args() {
    // Save then clear any env vars we set, then verify clap picks them up.
    let pairs = [
        ("SOCKET_CWD", "/env/cwd"),
        ("SOCKET_MANIFEST_PATH", "env-manifest.json"),
        ("SOCKET_API_URL", "https://env-api.example.com"),
        ("SOCKET_API_TOKEN", "env-token"),
        ("SOCKET_ORG_SLUG", "env-org"),
        ("SOCKET_PROXY_URL", "https://env-proxy.example.com"),
        ("SOCKET_ECOSYSTEMS", "npm,gem"),
        ("SOCKET_DOWNLOAD_MODE", "package"),
        ("SOCKET_OFFLINE", "true"),
        ("SOCKET_GLOBAL", "true"),
        ("SOCKET_GLOBAL_PREFIX", "/env/global"),
        ("SOCKET_JSON", "true"),
        ("SOCKET_VERBOSE", "true"),
        ("SOCKET_SILENT", "true"),
        ("SOCKET_DRY_RUN", "true"),
        ("SOCKET_YES", "true"),
        ("SOCKET_LOCK_TIMEOUT", "30"),
        ("SOCKET_BREAK_LOCK", "true"),
        ("SOCKET_DEBUG", "true"),
        ("SOCKET_TELEMETRY_DISABLED", "true"),
    ];

    // Save originals.
    let saved: Vec<(String, Option<String>)> = pairs
        .iter()
        .map(|(k, _)| (k.to_string(), std::env::var(k).ok()))
        .collect();

    // Set test values.
    for (k, v) in &pairs {
        std::env::set_var(k, v);
    }

    let cli = Cli::try_parse_from(["socket-patch", "list"]).expect("parse");
    if let socket_patch_cli::Commands::List(args) = cli.command {
        assert_eq!(args.common.cwd, std::path::PathBuf::from("/env/cwd"));
        assert_eq!(args.common.manifest_path, "env-manifest.json");
        assert_eq!(args.common.api_url, "https://env-api.example.com");
        assert_eq!(args.common.api_token.as_deref(), Some("env-token"));
        assert_eq!(args.common.org.as_deref(), Some("env-org"));
        assert_eq!(args.common.proxy_url, "https://env-proxy.example.com");
        assert_eq!(
            args.common.ecosystems.as_deref(),
            Some(&["npm".to_string(), "gem".to_string()][..])
        );
        assert_eq!(args.common.download_mode, "package");
        assert!(args.common.offline);
        assert!(args.common.global);
        assert_eq!(
            args.common.global_prefix,
            Some(std::path::PathBuf::from("/env/global"))
        );
        assert!(args.common.json);
        assert!(args.common.verbose);
        assert!(args.common.silent);
        assert!(args.common.dry_run);
        assert!(args.common.yes);
        assert_eq!(args.common.lock_timeout, Some(30));
        assert!(args.common.break_lock);
        assert!(args.common.debug);
        assert!(args.common.no_telemetry);
    } else {
        panic!("expected List");
    }

    // Restore originals.
    for (k, orig) in saved {
        match orig {
            Some(v) => std::env::set_var(&k, v),
            None => std::env::remove_var(&k),
        }
    }
}

/// Regression: bool env vars accept "1"/"yes" (the conventional truthy
/// strings), not just clap's strict "true"/"false". Before
/// BoolishValueParser was wired onto every bool with env, setting
/// SOCKET_OFFLINE=1 (or SOCKET_DEBUG=1) crashed clap with
/// `error: invalid value '1' for '--offline'`, taking down every
/// downstream CLI run that follows the conventional shell idiom.
///
/// `#[serial]` because env-var state is process-global; without it
/// these tests race each other (and the existing
/// `env_vars_populate_global_args`) when cargo runs them in
/// parallel.
#[test]
#[serial_test::serial]
fn bool_env_vars_accept_one_and_yes() {
    // (env var name, value to set)
    let cases: &[(&str, &str)] = &[
        ("SOCKET_OFFLINE", "1"),
        ("SOCKET_GLOBAL", "yes"),
        ("SOCKET_JSON", "on"),
        ("SOCKET_VERBOSE", "1"),
        ("SOCKET_SILENT", "y"),
        ("SOCKET_DRY_RUN", "1"),
        ("SOCKET_YES", "yes"),
        ("SOCKET_BREAK_LOCK", "1"),
        ("SOCKET_DEBUG", "1"),
        ("SOCKET_TELEMETRY_DISABLED", "1"),
    ];

    let saved: Vec<(String, Option<String>)> = cases
        .iter()
        .map(|(k, _)| (k.to_string(), std::env::var(k).ok()))
        .collect();
    for (k, v) in cases {
        std::env::set_var(k, v);
    }

    let cli = Cli::try_parse_from(["socket-patch", "list"]).expect("parse");
    if let socket_patch_cli::Commands::List(args) = cli.command {
        assert!(args.common.offline, "SOCKET_OFFLINE=1 must parse as true");
        assert!(args.common.global, "SOCKET_GLOBAL=yes must parse as true");
        assert!(args.common.json, "SOCKET_JSON=on must parse as true");
        assert!(args.common.verbose, "SOCKET_VERBOSE=1 must parse as true");
        assert!(args.common.silent, "SOCKET_SILENT=y must parse as true");
        assert!(args.common.dry_run, "SOCKET_DRY_RUN=1 must parse as true");
        assert!(args.common.yes, "SOCKET_YES=yes must parse as true");
        assert!(
            args.common.break_lock,
            "SOCKET_BREAK_LOCK=1 must parse as true"
        );
        assert!(args.common.debug, "SOCKET_DEBUG=1 must parse as true");
        assert!(
            args.common.no_telemetry,
            "SOCKET_TELEMETRY_DISABLED=1 must parse as true"
        );
    } else {
        panic!("expected List");
    }

    for (k, orig) in saved {
        match orig {
            Some(v) => std::env::set_var(&k, v),
            None => std::env::remove_var(&k),
        }
    }
}

/// Defensive: "0", "false", "no", "off" must NOT engage a bool. Otherwise
/// an operator unsetting via `SOCKET_OFFLINE=0` would still get airgap mode
/// (and various subtler shell idioms).
///
/// The original version of this test was vacuous: every assertion expected
/// `false`, which is *also* the field default. A regression that dropped the
/// `env = "SOCKET_*"` binding (or replaced `BoolishValueParser` with a parser
/// that silently ignored the var) would leave the fields at their default
/// `false` and the test would stay green — it never actually exercised the
/// env binding. We now first PROVE the binding is live by setting the var
/// truthy and asserting the field flips to `true`; only then is the
/// falsey-resolves-to-false assertion meaningful. Env is fully cleared and
/// isolated per iteration so no leaked `SOCKET_*` value can taint a parse.
#[test]
#[serial_test::serial]
fn bool_env_vars_reject_zero_and_falsey() {
    let fields: &[(&str, fn(&GlobalArgs) -> bool)] = &[
        ("SOCKET_OFFLINE", |c| c.offline),
        ("SOCKET_DEBUG", |c| c.debug),
        ("SOCKET_TELEMETRY_DISABLED", |c| c.no_telemetry),
        ("SOCKET_JSON", |c| c.json),
    ];

    let saved = save_and_clear_global_env();

    let parse_list = || {
        let cli = Cli::try_parse_from(["socket-patch", "list"]);
        cli.map(|cli| match cli.command {
            socket_patch_cli::Commands::List(args) => args.common,
            _ => panic!("expected List"),
        })
    };

    for &(var, get) in fields {
        // Liveness proof: a truthy value MUST flip the field to true. If this
        // fails, the env binding is dead and the falsey checks below would be
        // vacuous.
        std::env::set_var(var, "1");
        let common = parse_list().unwrap_or_else(|e| panic!("{var}=1 should parse: {e}"));
        assert!(
            get(&common),
            "{var}=1 must engage the bool (proves binding is live)"
        );
        std::env::remove_var(var);

        // Each falsey idiom must resolve to false — not true, not a parse error.
        for falsey in ["0", "false", "no", "off"] {
            std::env::set_var(var, falsey);
            let common =
                parse_list().unwrap_or_else(|e| panic!("{var}={falsey} should parse, got: {e}"));
            assert!(!get(&common), "{var}={falsey} must NOT engage the bool");
            std::env::remove_var(var);
        }
    }

    restore_global_env(saved);
}

/// An **empty** boolean env var resolves to `false` — it must NOT crash.
///
/// FIXED (2026-06-05): `SOCKET_OFFLINE=` (the conventional shell idiom for
/// blanking a variable without unsetting it) previously made clap fail with a
/// `ValueValidation` error via the stock `BoolishValueParser`, which rejects
/// `""`. That took down *every* CLI invocation, on *every* subcommand, for
/// *every* boolean global — an operator who blanked the var to disable airgap
/// mode got a hard crash instead. `args::parse_bool_flag` now maps an empty
/// (or whitespace-only) value to `false`. This test pins the fixed behavior:
/// every boolean global parses cleanly to `false` when its env var is empty.
#[test]
#[serial_test::serial]
fn empty_bool_env_var_resolves_to_false_not_crash() {
    // (env var, accessor) for every boolean global.
    let bool_vars: [(&str, fn(&GlobalArgs) -> bool); 10] = [
        ("SOCKET_OFFLINE", |c| c.offline),
        ("SOCKET_GLOBAL", |c| c.global),
        ("SOCKET_JSON", |c| c.json),
        ("SOCKET_VERBOSE", |c| c.verbose),
        ("SOCKET_SILENT", |c| c.silent),
        ("SOCKET_DRY_RUN", |c| c.dry_run),
        ("SOCKET_YES", |c| c.yes),
        ("SOCKET_BREAK_LOCK", |c| c.break_lock),
        ("SOCKET_DEBUG", |c| c.debug),
        ("SOCKET_TELEMETRY_DISABLED", |c| c.no_telemetry),
    ];

    let saved = save_and_clear_global_env();

    for (var, accessor) in bool_vars {
        std::env::set_var(var, "");
        let result = Cli::try_parse_from(["socket-patch", "list"]);
        std::env::remove_var(var);

        let cli =
            result.unwrap_or_else(|e| panic!("{var}= (empty) must parse cleanly, got error: {e}"));
        assert!(
            !accessor(common_of(&cli)),
            "{var}= (empty) must resolve to false",
        );
    }

    restore_global_env(saved);
}

/// Names of every `SOCKET_*` env var that `GlobalArgs` binds, so tests that
/// need a clean slate can save/clear/restore them in one place.
const GLOBAL_ENV_VARS: &[&str] = &[
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
];

/// An exported-but-**empty** non-bool env var must mean "unset", not crash.
///
/// `parse_bool_flag` gave the *bool* globals the empty-means-false semantic,
/// but `SOCKET_CWD=`, `SOCKET_GLOBAL_PREFIX=`, `SOCKET_LOCK_TIMEOUT=` and
/// `SOCKET_ECOSYSTEMS=` (the same blank-without-unsetting shell/CI idiom)
/// still aborted every subcommand at clap-parse time ("a value is required" /
/// "cannot parse integer from empty string"), and empty
/// `SOCKET_DOWNLOAD_MODE=` / `SOCKET_MANIFEST_PATH=` leaked `""` past the
/// documented defaults. The binary now scrubs empty `GlobalArgs` env vars
/// before clap parses (`args::scrub_empty_global_env_vars` in `main`),
/// restoring the documented CLI > env > default precedence for blank vars.
/// This spawns the real binary because the scrub is `main` wiring.
#[test]
#[serial_test::serial]
fn empty_nonbool_env_vars_do_not_crash_the_binary() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_socket-patch"));
    cmd.current_dir(tmp.path());
    // Start from a clean slate (no ambient SOCKET_* bleed into the child)…
    for var in GLOBAL_ENV_VARS {
        cmd.env_remove(var);
    }
    // …then export every non-bool global blank, the way `VAR=` does.
    for var in [
        "SOCKET_CWD",
        "SOCKET_MANIFEST_PATH",
        "SOCKET_GLOBAL_PREFIX",
        "SOCKET_LOCK_TIMEOUT",
        "SOCKET_ECOSYSTEMS",
        "SOCKET_DOWNLOAD_MODE",
    ] {
        cmd.env(var, "");
    }
    // Keep the spawned process from attempting telemetry network calls.
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1");

    let out = cmd
        .args(["list", "--json"])
        .output()
        .expect("spawn socket-patch");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert_ne!(
        out.status.code(),
        Some(2),
        "blank env vars must not abort the clap parse.\nstderr: {stderr}",
    );
    // The command must reach normal execution: with the blanks treated as
    // unset, `list --json` in an empty temp dir resolves the default manifest
    // path and emits the manifest_not_found envelope (exit 1).
    let envelope: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("expected a JSON envelope on stdout, got {e}.\nstdout: {stdout}\nstderr: {stderr}")
    });
    assert_eq!(
        envelope["error"]["code"], "manifest_not_found",
        "blank env vars must fall back to defaults: {envelope}",
    );
    assert_eq!(out.status.code(), Some(1), "manifest_not_found exits 1");
}

fn save_and_clear_global_env() -> Vec<(&'static str, Option<String>)> {
    let saved: Vec<(&'static str, Option<String>)> = GLOBAL_ENV_VARS
        .iter()
        .map(|&k| (k, std::env::var(k).ok()))
        .collect();
    for &k in GLOBAL_ENV_VARS {
        std::env::remove_var(k);
    }
    saved
}

fn restore_global_env(saved: Vec<(&'static str, Option<String>)>) {
    for (k, orig) in saved {
        match orig {
            Some(v) => std::env::set_var(k, v),
            None => std::env::remove_var(k),
        }
    }
}

/// Regression for the documented precedence (`CLI arg > env var > default`,
/// see the module header in `args.rs`): when both a CLI flag and its env var
/// are set, the CLI value must win. Covers a string field (`--api-url`) and a
/// bool field set on the CLI while the env says falsey. Env-only resolution is
/// asserted too so we know the env var really was live.
#[test]
#[serial_test::serial]
fn cli_arg_overrides_env_var() {
    let saved = save_and_clear_global_env();

    // String field: env set, CLI overrides.
    std::env::set_var("SOCKET_API_URL", "https://env-api.example.com");
    let cli = Cli::try_parse_from([
        "socket-patch",
        "list",
        "--api-url",
        "https://cli-api.example.com",
    ])
    .expect("parse");
    let socket_patch_cli::Commands::List(args) = cli.command else {
        panic!("expected List");
    };
    assert_eq!(
        args.common.api_url, "https://cli-api.example.com",
        "CLI --api-url must override SOCKET_API_URL"
    );

    // Sanity: with the CLI flag absent, the env value resolves through.
    let cli = Cli::try_parse_from(["socket-patch", "list"]).expect("parse");
    let socket_patch_cli::Commands::List(args) = cli.command else {
        panic!("expected List");
    };
    assert_eq!(
        args.common.api_url, "https://env-api.example.com",
        "with no CLI flag the env var must resolve through"
    );

    // Bool field: CLI `--offline` wins over a falsey env value.
    std::env::set_var("SOCKET_OFFLINE", "0");
    let cli = Cli::try_parse_from(["socket-patch", "list", "--offline"]).expect("parse");
    let socket_patch_cli::Commands::List(args) = cli.command else {
        panic!("expected List");
    };
    assert!(
        args.common.offline,
        "CLI --offline must win over SOCKET_OFFLINE=0"
    );

    restore_global_env(saved);
}

/// Regression: with neither CLI flags nor env vars set, clap must populate the
/// documented production defaults (the `default_value = ".."` attributes). This
/// is the production path that `GlobalArgs::default()` deliberately does *not*
/// mirror for `api_url`/`proxy_url`, so it needs its own coverage — and
/// `api_client_overrides()` must therefore forward those concrete URLs.
#[test]
#[serial_test::serial]
fn production_defaults_populate_when_unset() {
    let saved = save_and_clear_global_env();

    let cli = Cli::try_parse_from(["socket-patch", "list"]).expect("parse");
    let socket_patch_cli::Commands::List(args) = cli.command else {
        panic!("expected List");
    };
    let c = &args.common;
    assert_eq!(c.cwd, std::path::PathBuf::from("."));
    assert_eq!(c.manifest_path, ".socket/manifest.json");
    assert_eq!(c.api_url, "https://api.socket.dev");
    assert_eq!(c.proxy_url, "https://patches-api.socket.dev");
    assert_eq!(c.download_mode, "diff");
    assert!(c.api_token.is_none());
    assert!(c.org.is_none());
    assert!(c.ecosystems.is_none());
    assert!(!c.offline && !c.global && !c.json && !c.verbose && !c.silent);
    assert!(!c.dry_run && !c.yes && !c.break_lock && !c.debug && !c.no_telemetry);
    assert!(c.lock_timeout.is_none());
    assert!(c.global_prefix.is_none());

    // On the production path (unlike GlobalArgs::default()) the URLs are
    // non-empty, so api_client_overrides must forward them.
    let o = c.api_client_overrides();
    assert_eq!(o.api_url.as_deref(), Some("https://api.socket.dev"));
    assert_eq!(
        o.proxy_url.as_deref(),
        Some("https://patches-api.socket.dev")
    );
    assert!(o.api_token.is_none());
    assert!(o.org_slug.is_none());

    restore_global_env(saved);
}
