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

use clap::Parser;
use socket_patch_cli::Cli;

/// Subcommands under test. `rollback` is omitted because its only positional
/// is optional — covered by the no-positional variant. Setup is exercised
/// even though most globals are no-ops there; the point is to lock in that
/// every subcommand parses every global flag.
const SUBCOMMANDS_NO_POSITIONAL: &[&str] = &[
    "apply", "list", "scan", "setup", "repair", "rollback",
];

/// Subcommands that require a positional identifier.
const SUBCOMMANDS_WITH_IDENTIFIER: &[&str] = &["get", "remove"];

const DUMMY_IDENTIFIER: &str = "80630680-4da6-45f9-bba8-b888e0ffd58c";

/// (flag, value-or-None) pairs covering every flag on `GlobalArgs`.
fn global_flag_cases() -> Vec<(&'static str, Option<&'static str>)> {
    vec![
        ("--cwd", Some("/tmp")),
        ("--manifest-path", Some("custom.json")),
        ("--api-url", Some("https://example.com")),
        ("--api-token", Some("tok123")),
        ("--org", Some("acme")),
        ("--proxy-url", Some("https://proxy.example.com")),
        ("--ecosystems", Some("npm,pypi")),
        ("--download-mode", Some("diff")),
        ("--offline", None),
        ("--global", None),
        ("--global-prefix", Some("/opt/global")),
        ("--json", None),
        ("--verbose", None),
        ("--silent", None),
        ("--dry-run", None),
        ("--yes", None),
        ("--debug", None),
        ("--no-telemetry", None),
    ]
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
fn every_global_flag_parses_on_every_subcommand() {
    let cases = global_flag_cases();
    let all_subcommands: Vec<&str> = SUBCOMMANDS_NO_POSITIONAL
        .iter()
        .chain(SUBCOMMANDS_WITH_IDENTIFIER.iter())
        .copied()
        .collect();

    for &subcommand in &all_subcommands {
        for &(flag, value) in &cases {
            let extra: Vec<&str> = if let Some(v) = value {
                vec![flag, v]
            } else {
                vec![flag]
            };
            let result = try_parse(subcommand, &extra);
            assert!(
                result.is_ok(),
                "subcommand `{}` failed to parse global flag `{}`: {}",
                subcommand,
                flag,
                result.err().map(|e| e.to_string()).unwrap_or_default(),
            );
        }
    }
}

/// Short forms (`-s`, `-y`, etc.) are part of the contract too. `-d`
/// and `-m` were dropped after v3.0 (they were reserved as aliases for
/// `--dry-run` and `--manifest-path` but we want those letters free
/// for future flags); the corresponding rejection check lives in
/// `reserved_short_forms_are_not_assigned` below.
#[test]
fn every_global_short_form_parses_on_every_subcommand() {
    // (short, requires_value) — only flags that actually have a short.
    let shorts: &[(&str, bool)] = &[
        ("-o", true),  // --org
        ("-e", true),  // --ecosystems
        ("-g", false), // --global
        ("-j", false), // --json
        ("-v", false), // --verbose
        ("-s", false), // --silent
        ("-y", false), // --yes
    ];
    let all_subcommands: Vec<&str> = SUBCOMMANDS_NO_POSITIONAL
        .iter()
        .chain(SUBCOMMANDS_WITH_IDENTIFIER.iter())
        .copied()
        .collect();

    for &subcommand in &all_subcommands {
        for &(short, needs_value) in shorts {
            // `apply` has its own `-f` for --force; we don't test that here
            // because it's local. The shorts we test are all GlobalArgs shorts.
            // `get` has `-p` for --package (local); also not tested here.
            let extra: Vec<&str> = if needs_value {
                vec![short, "value"]
            } else {
                vec![short]
            };
            let result = try_parse(subcommand, &extra);
            assert!(
                result.is_ok(),
                "subcommand `{}` failed to parse short flag `{}`: {}",
                subcommand,
                short,
                result.err().map(|e| e.to_string()).unwrap_or_default(),
            );
        }
    }
}

/// `-d` and `-m` were intentionally dropped (formerly aliases for
/// `--dry-run` and `--manifest-path`) so those letters stay free for
/// future flags. Lock that in: clap must reject the bare shorts on
/// every subcommand. The long forms still work and are exercised by
/// `every_global_flag_parses_on_every_subcommand` above.
#[test]
fn reserved_short_forms_are_not_assigned() {
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
        ("SOCKET_ECOSYSTEMS", "npm,maven"),
        ("SOCKET_DOWNLOAD_MODE", "package"),
        ("SOCKET_OFFLINE", "true"),
        ("SOCKET_GLOBAL", "true"),
        ("SOCKET_GLOBAL_PREFIX", "/env/global"),
        ("SOCKET_JSON", "true"),
        ("SOCKET_VERBOSE", "true"),
        ("SOCKET_SILENT", "true"),
        ("SOCKET_DRY_RUN", "true"),
        ("SOCKET_YES", "true"),
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
            Some(&["npm".to_string(), "maven".to_string()][..])
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
        assert!(args.common.break_lock, "SOCKET_BREAK_LOCK=1 must parse as true");
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

/// Defensive: "0", "false", "no", "off", and empty string must NOT
/// engage a bool. Otherwise an operator unsetting via SOCKET_OFFLINE=0
/// would still get airgap mode (and various subtler shell idioms).
#[test]
#[serial_test::serial]
fn bool_env_vars_reject_zero_and_falsey() {
    let cases: &[(&str, &str)] = &[
        ("SOCKET_OFFLINE", "0"),
        ("SOCKET_DEBUG", "false"),
        ("SOCKET_TELEMETRY_DISABLED", "no"),
        ("SOCKET_JSON", "off"),
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
        assert!(!args.common.offline);
        assert!(!args.common.debug);
        assert!(!args.common.no_telemetry);
        assert!(!args.common.json);
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
