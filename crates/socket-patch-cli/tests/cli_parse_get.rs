//! Clap parser snapshot tests for the `get` subcommand.
//!
//! These tests pin the public CLI contract for `socket-patch get`: every
//! flag, every alias (including the hidden `--no-apply` and the visible
//! `download` alias), and every default. Changing any assertion here is a
//! breaking change to the CLI surface — see
//! `crates/socket-patch-cli/CLI_CONTRACT.md`.
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
//! dance can't race a concurrent parse.

use clap::Parser;
use socket_patch_cli::commands::get::GetArgs;
use socket_patch_cli::{Cli, Commands};
use std::path::PathBuf;

/// Every `SOCKET_*` env var that clap consults while parsing `get` (its own
/// flags plus the flattened `GlobalArgs`). If any of these leaks in from the
/// ambient environment it can mask a broken default or a regressed flag, so
/// the parse helpers below remove them for the duration of the parse.
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
    // GetArgs-specific
    "SOCKET_SAVE_ONLY",
    "SOCKET_ONE_OFF",
    "SOCKET_ALL_RELEASES",
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

/// Parse `socket-patch get <extra...>` and return the `GetArgs`, with the
/// ambient `SOCKET_*` environment scrubbed so the result reflects only the
/// argv. The scrub guard is held across the parse and dropped before the
/// caller's assertions run (which only inspect the returned struct).
fn parse_get(extra: &[&str]) -> GetArgs {
    let _scrub = EnvScrub::new();
    let mut argv = vec!["socket-patch", "get"];
    argv.extend_from_slice(extra);
    let cli = Cli::try_parse_from(&argv).expect("parse");
    match cli.command {
        Commands::Get(a) => a,
        _ => panic!("expected Get"),
    }
}

/// Owned, comparable snapshot of *every* parsed field in `GetArgs` — its own
/// flags plus every field of the flattened `GlobalArgs`. `GetArgs` itself does
/// not derive `PartialEq` (it's production code we may not touch), so this
/// mirror exists purely so a single `assert_eq!` can police the entire parsed
/// surface at once.
///
/// This is what makes the per-flag tests honest. A field-at-a-time assertion
/// (`assert!(a.package)`) only proves the flag set *its* field; it says nothing
/// about whether the same flag also flipped an unrelated one. A clap-derive
/// copy/paste regression (e.g. `--package` accidentally wired to `one_off`)
/// would set both and still pass a single-field check. Comparing the whole
/// snapshot against the independently-declared defaults — with only the field
/// under test mutated — fails loudly the instant any other field moves.
#[derive(Debug, Clone, PartialEq)]
struct Snap {
    identifier: String,
    cwd: PathBuf,
    manifest_path: String,
    api_url: String,
    api_token: Option<String>,
    org: Option<String>,
    proxy_url: String,
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
    id: bool,
    cve: bool,
    ghsa: bool,
    package: bool,
    save_only: bool,
    one_off: bool,
    all_releases: bool,
}

fn snapshot(a: &GetArgs) -> Snap {
    Snap {
        identifier: a.identifier.clone(),
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
        id: a.id,
        cve: a.cve,
        ghsa: a.ghsa,
        package: a.package,
        save_only: a.save_only,
        one_off: a.one_off,
        all_releases: a.all_releases,
    }
}

/// Independent oracle: the snapshot a correct parse of `get <identifier>` (with
/// no other flags) must produce. The values are transcribed by hand from the
/// `default_value`/`default_value_t` declarations on `GetArgs`/`GlobalArgs` and
/// the `DEFAULT_*` constants in `socket-patch-core` — NOT read back from a live
/// parse — so this can actually disagree with the implementation if a default
/// regresses. Every per-flag test starts from this and mutates exactly the one
/// field the flag is supposed to touch.
fn expected_defaults(identifier: &str) -> Snap {
    Snap {
        identifier: identifier.to_string(),
        cwd: PathBuf::from("."),
        manifest_path: ".socket/manifest.json".to_string(),
        api_url: "https://api.socket.dev".to_string(),
        api_token: None,
        org: None,
        proxy_url: "https://patches-api.socket.dev".to_string(),
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
        id: false,
        cve: false,
        ghsa: false,
        package: false,
        save_only: false,
        one_off: false,
        all_releases: false,
    }
}

// --- Defaults ----------------------------------------------------------------

#[test]
#[serial_test::serial]
fn defaults_with_only_required_identifier() {
    let a = parse_get(&["some-id"]);
    // Pin the *entire* default surface in one shot against the independent
    // oracle. This covers fields the old test silently skipped (manifest_path,
    // proxy_url, offline, verbose, silent, dry_run, lock_timeout, break_lock,
    // debug, no_telemetry, ecosystems) — any of which could regress to a
    // non-default and go unnoticed under a field-cherry-picked assertion.
    assert_eq!(snapshot(&a), expected_defaults("some-id"));
}

#[test]
#[serial_test::serial]
fn all_releases_flag_sets_all_releases() {
    let a = parse_get(&["some-id", "--all-releases"]);
    let mut want = expected_defaults("some-id");
    want.all_releases = true;
    // Full-snapshot equality: proves the flag set `all_releases` AND left every
    // other field at its default (env scrubbed, so the `true` is the flag's).
    assert_eq!(snapshot(&a), want);
}

#[test]
#[serial_test::serial]
fn default_download_mode_is_diff() {
    let a = parse_get(&["some-id"]);
    assert_eq!(snapshot(&a), expected_defaults("some-id"));
}

// --- Positional --------------------------------------------------------------

#[test]
#[serial_test::serial]
fn positional_identifier_stored() {
    let a = parse_get(&["pkg:npm/foo@1.0"]);
    // The positional lands in `identifier` and nothing else shifts.
    assert_eq!(snapshot(&a), expected_defaults("pkg:npm/foo@1.0"));
}

// --- Short flags -------------------------------------------------------------

#[test]
#[serial_test::serial]
fn short_p_sets_package() {
    let a = parse_get(&["some-id", "-p"]);
    let mut want = expected_defaults("some-id");
    want.package = true;
    assert_eq!(snapshot(&a), want);
}

#[test]
#[serial_test::serial]
fn long_package_sets_package() {
    let a = parse_get(&["some-id", "--package"]);
    let mut want = expected_defaults("some-id");
    want.package = true;
    assert_eq!(snapshot(&a), want);
}

#[test]
#[serial_test::serial]
fn short_y_sets_yes() {
    let a = parse_get(&["some-id", "-y"]);
    let mut want = expected_defaults("some-id");
    want.yes = true;
    assert_eq!(snapshot(&a), want);
}

#[test]
#[serial_test::serial]
fn long_yes_sets_yes() {
    let a = parse_get(&["some-id", "--yes"]);
    let mut want = expected_defaults("some-id");
    want.yes = true;
    assert_eq!(snapshot(&a), want);
}

#[test]
#[serial_test::serial]
fn short_g_sets_global() {
    let a = parse_get(&["some-id", "-g"]);
    let mut want = expected_defaults("some-id");
    want.global = true;
    assert_eq!(snapshot(&a), want);
}

#[test]
#[serial_test::serial]
fn long_global_sets_global() {
    let a = parse_get(&["some-id", "--global"]);
    let mut want = expected_defaults("some-id");
    want.global = true;
    assert_eq!(snapshot(&a), want);
}

// --- Long-only flags ---------------------------------------------------------

#[test]
#[serial_test::serial]
fn cwd_flag_sets_cwd() {
    let a = parse_get(&["some-id", "--cwd", "/tmp/project"]);
    let mut want = expected_defaults("some-id");
    want.cwd = PathBuf::from("/tmp/project");
    assert_eq!(snapshot(&a), want);
}

#[test]
#[serial_test::serial]
fn org_flag_sets_org() {
    let a = parse_get(&["some-id", "--org", "acme"]);
    let mut want = expected_defaults("some-id");
    want.org = Some("acme".to_string());
    assert_eq!(snapshot(&a), want);
}

#[test]
#[serial_test::serial]
fn id_flag_sets_id() {
    let a = parse_get(&["some-id", "--id"]);
    let mut want = expected_defaults("some-id");
    want.id = true;
    assert_eq!(snapshot(&a), want);
}

#[test]
#[serial_test::serial]
fn cve_flag_sets_cve() {
    let a = parse_get(&["some-id", "--cve"]);
    let mut want = expected_defaults("some-id");
    want.cve = true;
    assert_eq!(snapshot(&a), want);
}

#[test]
#[serial_test::serial]
fn ghsa_flag_sets_ghsa() {
    let a = parse_get(&["some-id", "--ghsa"]);
    let mut want = expected_defaults("some-id");
    want.ghsa = true;
    assert_eq!(snapshot(&a), want);
}

#[test]
#[serial_test::serial]
fn api_url_flag_sets_api_url() {
    let a = parse_get(&["some-id", "--api-url", "https://api.example.com"]);
    let mut want = expected_defaults("some-id");
    want.api_url = "https://api.example.com".to_string();
    assert_eq!(snapshot(&a), want);
}

#[test]
#[serial_test::serial]
fn api_token_flag_sets_api_token() {
    let a = parse_get(&["some-id", "--api-token", "sktsec_abc"]);
    let mut want = expected_defaults("some-id");
    want.api_token = Some("sktsec_abc".to_string());
    assert_eq!(snapshot(&a), want);
}

#[test]
#[serial_test::serial]
fn global_prefix_flag_sets_global_prefix() {
    let a = parse_get(&["some-id", "--global-prefix", "/usr/local/lib"]);
    let mut want = expected_defaults("some-id");
    want.global_prefix = Some(PathBuf::from("/usr/local/lib"));
    // `--global-prefix` must NOT imply `--global`; full-snapshot equality keeps
    // `global` pinned at its default.
    assert_eq!(snapshot(&a), want);
}

#[test]
#[serial_test::serial]
fn one_off_flag_sets_one_off() {
    let a = parse_get(&["some-id", "--one-off"]);
    let mut want = expected_defaults("some-id");
    want.one_off = true;
    // `--one-off` and `--save-only` are semantic opposites; this guards that
    // setting one does not also flip the other.
    assert_eq!(snapshot(&a), want);
}

#[test]
#[serial_test::serial]
fn json_flag_sets_json() {
    let a = parse_get(&["some-id", "--json"]);
    let mut want = expected_defaults("some-id");
    want.json = true;
    assert_eq!(snapshot(&a), want);
}

// --- save-only / --no-apply alias -------------------------------------------

#[test]
#[serial_test::serial]
fn save_only_flag_sets_save_only() {
    let a = parse_get(&["some-id", "--save-only"]);
    let mut want = expected_defaults("some-id");
    want.save_only = true;
    assert_eq!(snapshot(&a), want);
}

#[test]
#[serial_test::serial]
fn no_apply_hidden_alias_sets_save_only() {
    // `--no-apply` is a hidden alias for `--save-only`. It does not appear in
    // `--help` but is widely used in existing scripts — this is part of the
    // CLI contract. With the env scrubbed, this can only pass if the alias is
    // actually wired to `save_only` (not because SOCKET_SAVE_ONLY was set).
    let a = parse_get(&["some-id", "--no-apply"]);
    let mut want = expected_defaults("some-id");
    want.save_only = true;
    // The alias must set `save_only` and nothing else.
    assert_eq!(snapshot(&a), want);
    // ...and must be byte-for-byte equivalent to the canonical `--save-only`
    // across the *entire* parsed surface, not just the `save_only` field.
    let direct = parse_get(&["some-id", "--save-only"]);
    assert_eq!(snapshot(&a), snapshot(&direct));
}

// --- download-mode -----------------------------------------------------------

#[test]
#[serial_test::serial]
fn download_mode_package() {
    let a = parse_get(&["some-id", "--download-mode", "package"]);
    let mut want = expected_defaults("some-id");
    want.download_mode = "package".to_string();
    assert_eq!(snapshot(&a), want);
}

#[test]
#[serial_test::serial]
fn download_mode_diff() {
    let a = parse_get(&["some-id", "--download-mode", "diff"]);
    // Explicitly passing the default value must still parse to exactly defaults.
    assert_eq!(snapshot(&a), expected_defaults("some-id"));
}

#[test]
#[serial_test::serial]
fn download_mode_file() {
    let a = parse_get(&["some-id", "--download-mode", "file"]);
    let mut want = expected_defaults("some-id");
    want.download_mode = "file".to_string();
    assert_eq!(snapshot(&a), want);
}

// --- `download` visible alias for `get` -------------------------------------

#[test]
#[serial_test::serial]
fn download_visible_alias_routes_to_get() {
    let _scrub = EnvScrub::new();
    let cli = Cli::try_parse_from(["socket-patch", "download", "some-id"]).expect("parse");
    match cli.command {
        Commands::Get(a) => {
            // The alias must produce a `GetArgs` identical, across the entire
            // parsed surface, to what bare `get some-id` produces — not some
            // divergently-parsed command that merely happens to be `Get`.
            assert_eq!(snapshot(&a), expected_defaults("some-id"));
        }
        _ => panic!("expected Get from `download` alias"),
    }
}

// --- Error paths -------------------------------------------------------------

#[test]
#[serial_test::serial]
fn missing_required_identifier_errors() {
    let _scrub = EnvScrub::new();
    let err = match Cli::try_parse_from(["socket-patch", "get"]) {
        Err(e) => e,
        Ok(_) => panic!("expected parse error for missing required positional"),
    };
    assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
}

#[test]
#[serial_test::serial]
fn unknown_flag_errors() {
    let _scrub = EnvScrub::new();
    let err = match Cli::try_parse_from(["socket-patch", "get", "some-id", "--bogus"]) {
        Err(e) => e,
        Ok(_) => panic!("expected parse error for unknown flag"),
    };
    assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
}
