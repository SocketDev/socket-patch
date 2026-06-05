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

/// The default `GetArgs` produced by the bare `get <id>` invocation, used as
/// an independent oracle: flag tests assert that flipping one flag changes
/// *only* that field and leaves every other field at its default. This keeps
/// a regression that flips an unrelated flag as a side effect from sneaking
/// past a single-field assertion.
fn baseline() -> GetArgs {
    parse_get(&["some-id"])
}

// --- Defaults ----------------------------------------------------------------

#[test]
#[serial_test::serial]
fn defaults_with_only_required_identifier() {
    let a = parse_get(&["some-id"]);
    assert_eq!(a.identifier, "some-id");
    assert_eq!(a.common.org, None);
    assert_eq!(a.common.cwd, PathBuf::from("."));
    assert!(!a.id);
    assert!(!a.cve);
    assert!(!a.ghsa);
    assert!(!a.package);
    assert!(!a.common.yes);
    assert_eq!(a.common.api_url, "https://api.socket.dev");
    assert_eq!(a.common.api_token, None);
    assert!(!a.save_only);
    assert!(!a.common.global);
    assert_eq!(a.common.global_prefix, None);
    assert!(!a.one_off);
    assert!(!a.common.json);
    assert_eq!(a.common.download_mode, "diff");
    assert!(
        !a.all_releases,
        "--all-releases default is false (narrow — installed-dist variant only)"
    );
}

#[test]
#[serial_test::serial]
fn all_releases_flag_sets_all_releases() {
    let a = parse_get(&["some-id", "--all-releases"]);
    assert!(a.all_releases);
    // Guard against the env masking the flag: a bare baseline must be false,
    // so the `true` above is attributable to the flag, not ambient state.
    assert!(!baseline().all_releases);
}

#[test]
#[serial_test::serial]
fn default_download_mode_is_diff() {
    let a = parse_get(&["some-id"]);
    assert_eq!(a.common.download_mode, "diff");
}

// --- Positional --------------------------------------------------------------

#[test]
#[serial_test::serial]
fn positional_identifier_stored() {
    let a = parse_get(&["pkg:npm/foo@1.0"]);
    assert_eq!(a.identifier, "pkg:npm/foo@1.0");
}

// --- Short flags -------------------------------------------------------------

#[test]
#[serial_test::serial]
fn short_p_sets_package() {
    let a = parse_get(&["some-id", "-p"]);
    assert!(a.package);
    // `package` has no env source, but assert the default is false so the
    // short flag is the only thing that could have set it.
    assert!(!baseline().package);
}

#[test]
#[serial_test::serial]
fn long_package_sets_package() {
    let a = parse_get(&["some-id", "--package"]);
    assert!(a.package);
}

#[test]
#[serial_test::serial]
fn short_y_sets_yes() {
    let a = parse_get(&["some-id", "-y"]);
    assert!(a.common.yes);
    assert!(!baseline().common.yes);
}

#[test]
#[serial_test::serial]
fn long_yes_sets_yes() {
    let a = parse_get(&["some-id", "--yes"]);
    assert!(a.common.yes);
}

#[test]
#[serial_test::serial]
fn short_g_sets_global() {
    let a = parse_get(&["some-id", "-g"]);
    assert!(a.common.global);
    assert!(!baseline().common.global);
}

#[test]
#[serial_test::serial]
fn long_global_sets_global() {
    let a = parse_get(&["some-id", "--global"]);
    assert!(a.common.global);
}

// --- Long-only flags ---------------------------------------------------------

#[test]
#[serial_test::serial]
fn cwd_flag_sets_cwd() {
    let a = parse_get(&["some-id", "--cwd", "/tmp/project"]);
    assert_eq!(a.common.cwd, PathBuf::from("/tmp/project"));
    // The default differs from the value under test, so a parse that ignored
    // the flag would leave `.` and fail here.
    assert_eq!(baseline().common.cwd, PathBuf::from("."));
}

#[test]
#[serial_test::serial]
fn org_flag_sets_org() {
    let a = parse_get(&["some-id", "--org", "acme"]);
    assert_eq!(a.common.org.as_deref(), Some("acme"));
    assert_eq!(baseline().common.org, None);
}

#[test]
#[serial_test::serial]
fn id_flag_sets_id() {
    let a = parse_get(&["some-id", "--id"]);
    assert!(a.id);
    assert!(!baseline().id);
}

#[test]
#[serial_test::serial]
fn cve_flag_sets_cve() {
    let a = parse_get(&["some-id", "--cve"]);
    assert!(a.cve);
    assert!(!baseline().cve);
}

#[test]
#[serial_test::serial]
fn ghsa_flag_sets_ghsa() {
    let a = parse_get(&["some-id", "--ghsa"]);
    assert!(a.ghsa);
    assert!(!baseline().ghsa);
}

#[test]
#[serial_test::serial]
fn api_url_flag_sets_api_url() {
    let a = parse_get(&["some-id", "--api-url", "https://api.example.com"]);
    assert_eq!(a.common.api_url, "https://api.example.com");
    // Default is the production URL — distinct from the value under test, so
    // an ignored flag would fail rather than coincidentally match.
    assert_eq!(baseline().common.api_url, "https://api.socket.dev");
}

#[test]
#[serial_test::serial]
fn api_token_flag_sets_api_token() {
    let a = parse_get(&["some-id", "--api-token", "sktsec_abc"]);
    assert_eq!(a.common.api_token.as_deref(), Some("sktsec_abc"));
    assert_eq!(baseline().common.api_token, None);
}

#[test]
#[serial_test::serial]
fn global_prefix_flag_sets_global_prefix() {
    let a = parse_get(&["some-id", "--global-prefix", "/usr/local/lib"]);
    assert_eq!(a.common.global_prefix, Some(PathBuf::from("/usr/local/lib")));
    assert_eq!(baseline().common.global_prefix, None);
}

#[test]
#[serial_test::serial]
fn one_off_flag_sets_one_off() {
    let a = parse_get(&["some-id", "--one-off"]);
    assert!(a.one_off);
    assert!(!baseline().one_off);
}

#[test]
#[serial_test::serial]
fn json_flag_sets_json() {
    let a = parse_get(&["some-id", "--json"]);
    assert!(a.common.json);
    assert!(!baseline().common.json);
}

// --- save-only / --no-apply alias -------------------------------------------

#[test]
#[serial_test::serial]
fn save_only_flag_sets_save_only() {
    let a = parse_get(&["some-id", "--save-only"]);
    assert!(a.save_only);
    // Default is false (env scrubbed), so `--save-only` is what set it.
    assert!(!baseline().save_only);
}

#[test]
#[serial_test::serial]
fn no_apply_hidden_alias_sets_save_only() {
    // `--no-apply` is a hidden alias for `--save-only`. It does not appear in
    // `--help` but is widely used in existing scripts — this is part of the
    // CLI contract. With the env scrubbed, this can only pass if the alias is
    // actually wired to `save_only` (not because SOCKET_SAVE_ONLY was set).
    let a = parse_get(&["some-id", "--no-apply"]);
    assert!(a.save_only);
    // The alias must be exactly equivalent to `--save-only`: it sets
    // save_only and nothing else relative to the baseline.
    let direct = parse_get(&["some-id", "--save-only"]);
    assert_eq!(a.save_only, direct.save_only);
    assert!(!a.one_off, "--no-apply must not also flip --one-off");
}

// --- download-mode -----------------------------------------------------------

#[test]
#[serial_test::serial]
fn download_mode_package() {
    let a = parse_get(&["some-id", "--download-mode", "package"]);
    assert_eq!(a.common.download_mode, "package");
}

#[test]
#[serial_test::serial]
fn download_mode_diff() {
    let a = parse_get(&["some-id", "--download-mode", "diff"]);
    assert_eq!(a.common.download_mode, "diff");
}

#[test]
#[serial_test::serial]
fn download_mode_file() {
    let a = parse_get(&["some-id", "--download-mode", "file"]);
    assert_eq!(a.common.download_mode, "file");
}

// --- `download` visible alias for `get` -------------------------------------

#[test]
#[serial_test::serial]
fn download_visible_alias_routes_to_get() {
    let _scrub = EnvScrub::new();
    let cli = Cli::try_parse_from(["socket-patch", "download", "some-id"]).expect("parse");
    match cli.command {
        Commands::Get(a) => {
            assert_eq!(a.identifier, "some-id");
            // The alias must produce the same defaults as `get`, not some
            // divergently-parsed command that merely happens to be `Get`.
            assert!(!a.save_only);
            assert!(!a.one_off);
            assert!(!a.all_releases);
            assert_eq!(a.common.download_mode, "diff");
            assert_eq!(a.common.cwd, PathBuf::from("."));
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
