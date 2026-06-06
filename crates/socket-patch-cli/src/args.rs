//! Shared CLI arguments flattened into every subcommand.
//!
//! `GlobalArgs` defines the flags that apply uniformly across every
//! `socket-patch` subcommand. Each subcommand `#[command(flatten)]`s this
//! struct into its own `Args` struct so the surface stays consistent.
//!
//! Subcommands that don't actually use a given global flag still accept it
//! silently (no-op). See `CLI_CONTRACT.md` for the full contract.
//!
//! Precedence for every flag: CLI arg > env var > default.
//!
//! All env-var names use the `SOCKET_*` prefix. Three legacy `SOCKET_PATCH_*`
//! names are still read at runtime (via `socket_patch_core::env_compat`) with
//! a one-shot deprecation warning; they will be removed in the next major.

use std::path::PathBuf;

use clap::Args;

use socket_patch_core::api::client::ApiClientEnvOverrides;
use socket_patch_core::constants::{
    DEFAULT_PATCH_API_PROXY_URL, DEFAULT_PATCH_MANIFEST_PATH, DEFAULT_SOCKET_API_URL,
};
use socket_patch_core::crawlers::Ecosystem;

/// clap value-parser for each `--ecosystems` / `SOCKET_ECOSYSTEMS` token.
///
/// Rejects any name this build does not support — both typos and
/// ecosystems whose Cargo feature is not compiled in (e.g. `maven` /
/// `nuget` on a default build, which ships npm + PyPI + Ruby gems + Go +
/// Cargo). `Ecosystem::all()` is itself `#[cfg]`-gated, so the accepted
/// set tracks the compiled feature set exactly.
///
/// Without this, an unsupported name parsed fine and was then silently
/// dropped by `partition_purls`/`crawl_all_ecosystems`, so the user got a
/// "0 patches" result with no hint that the ecosystem name was the cause.
fn parse_supported_ecosystem(s: &str) -> Result<String, String> {
    if Ecosystem::all().iter().any(|e| e.cli_name() == s) {
        Ok(s.to_string())
    } else {
        let supported = Ecosystem::all()
            .iter()
            .map(|e| e.cli_name())
            .collect::<Vec<_>>()
            .join(", ");
        Err(format!(
            "unsupported ecosystem `{s}` in this build (supported: {supported})"
        ))
    }
}

/// clap value-parser for boolean flags backed by an env var.
///
/// Identical to clap's stock `BoolishValueParser` (case-insensitive
/// `true/false`, `yes/no`, `on/off`, `1/0`) **except** that an empty string is
/// treated as `false` rather than rejected.
///
/// Without this, an exported-but-empty env var — e.g. `SOCKET_OFFLINE=` or
/// `SOCKET_JSON=`, which shells and CI routinely set to mean "unset" — made
/// clap abort the whole command with `invalid value '' for '--offline': value
/// was not a boolean`. Every bool flag here reads such an env var, so a single
/// stray empty var crashed every subcommand before it could do any work.
fn parse_bool_flag(s: &str) -> Result<bool, String> {
    match s.trim().to_ascii_lowercase().as_str() {
        "" | "n" | "no" | "f" | "false" | "off" | "0" => Ok(false),
        "y" | "yes" | "t" | "true" | "on" | "1" => Ok(true),
        other => Err(format!(
            "`{other}` is not a boolean (expected one of: true, false, yes, no, on, off, 1, 0)"
        )),
    }
}

/// Arguments inherited by every subcommand via `#[command(flatten)]`.
///
/// **Every** global flag is parseable on **every** subcommand. Commands that
/// don't use a given flag ignore it silently — e.g. `list --global` parses
/// fine and the `global` field is unused at runtime.
#[derive(Args, Debug, Clone)]
pub struct GlobalArgs {
    /// Working directory.
    #[arg(long, env = "SOCKET_CWD", default_value = ".")]
    pub cwd: PathBuf,

    /// Path to patch manifest file (resolved relative to --cwd).
    #[arg(
        long = "manifest-path",
        env = "SOCKET_MANIFEST_PATH",
        default_value = DEFAULT_PATCH_MANIFEST_PATH,
    )]
    pub manifest_path: String,

    /// Socket API URL (authenticated endpoint).
    #[arg(
        long = "api-url",
        env = "SOCKET_API_URL",
        default_value = DEFAULT_SOCKET_API_URL,
    )]
    pub api_url: String,

    /// Socket API token. Absence selects the public patch proxy.
    #[arg(long = "api-token", env = "SOCKET_API_TOKEN")]
    pub api_token: Option<String>,

    /// Organization slug. Auto-resolved when omitted and a token is set.
    #[arg(long = "org", short = 'o', env = "SOCKET_ORG_SLUG")]
    pub org: Option<String>,

    /// Public proxy URL used when no API token is set.
    #[arg(
        long = "proxy-url",
        env = "SOCKET_PROXY_URL",
        default_value = DEFAULT_PATCH_API_PROXY_URL,
    )]
    pub proxy_url: String,

    /// Restrict to these ecosystems (comma-separated). Names not supported
    /// by this build (e.g. `maven`/`nuget` unless compiled in) are rejected.
    #[arg(
        long = "ecosystems",
        short = 'e',
        env = "SOCKET_ECOSYSTEMS",
        value_delimiter = ',',
        value_parser = parse_supported_ecosystem,
    )]
    pub ecosystems: Option<Vec<String>>,

    /// Which kind of patch artifact to download when local files are missing.
    /// `diff` (default) fetches the smallest delta archive; `package` fetches
    /// a full per-package tarball; `file` falls back to legacy per-file blobs.
    #[arg(
        long = "download-mode",
        env = "SOCKET_DOWNLOAD_MODE",
        default_value = "diff",
    )]
    pub download_mode: String,

    /// Strict airgap: never contact the network. Operations that need remote
    /// data fail loudly when this is set.
    #[arg(
        long,
        env = "SOCKET_OFFLINE",
        default_value_t = false,
        value_parser = parse_bool_flag,
    )]
    pub offline: bool,

    /// Operate on globally-installed packages.
    #[arg(
        long = "global",
        short = 'g',
        env = "SOCKET_GLOBAL",
        default_value_t = false,
        value_parser = parse_bool_flag,
    )]
    pub global: bool,

    /// Override the path used to discover globally-installed packages.
    #[arg(long = "global-prefix", env = "SOCKET_GLOBAL_PREFIX")]
    pub global_prefix: Option<PathBuf>,

    /// Emit machine-readable JSON output.
    #[arg(
        long = "json",
        short = 'j',
        env = "SOCKET_JSON",
        default_value_t = false,
        value_parser = parse_bool_flag,
    )]
    pub json: bool,

    /// Show extra detail in human-readable output.
    #[arg(
        long = "verbose",
        short = 'v',
        env = "SOCKET_VERBOSE",
        default_value_t = false,
        value_parser = parse_bool_flag,
    )]
    pub verbose: bool,

    /// Suppress non-error output.
    #[arg(
        long = "silent",
        short = 's',
        env = "SOCKET_SILENT",
        default_value_t = false,
        value_parser = parse_bool_flag,
    )]
    pub silent: bool,

    /// Preview the operation without making any mutations.
    #[arg(
        long = "dry-run",
        env = "SOCKET_DRY_RUN",
        default_value_t = false,
        value_parser = parse_bool_flag,
    )]
    pub dry_run: bool,

    /// Skip interactive prompts.
    #[arg(
        long = "yes",
        short = 'y',
        env = "SOCKET_YES",
        default_value_t = false,
        value_parser = parse_bool_flag,
    )]
    pub yes: bool,

    /// Seconds to wait for `<.socket>/apply.lock` before giving up.
    /// Default (`None`) and `0` both mean a single non-blocking try
    /// — failing immediately if another process holds the lock. A
    /// positive value retries with a 100 ms backoff until the lock
    /// frees or the budget elapses. Only meaningful for the mutating
    /// subcommands (`apply`, `rollback`, `repair`, `remove`); other
    /// commands accept it silently.
    #[arg(long = "lock-timeout", env = "SOCKET_LOCK_TIMEOUT")]
    pub lock_timeout: Option<u64>,

    /// Force-remove `<.socket>/apply.lock` before attempting
    /// acquisition. Use when you are certain no other socket-patch
    /// process is running (e.g. a previous run crashed in a way that
    /// stripped the OS lock but left the file). Emits a
    /// `lock_broken` warning event in the JSON envelope so the
    /// action is auditable. Only meaningful for mutating
    /// subcommands; other commands accept it silently.
    #[arg(
        long = "break-lock",
        env = "SOCKET_BREAK_LOCK",
        default_value_t = false,
        value_parser = parse_bool_flag,
    )]
    pub break_lock: bool,

    /// Emit verbose debug logs to stderr.
    #[arg(
        long = "debug",
        env = "SOCKET_DEBUG",
        default_value_t = false,
        value_parser = parse_bool_flag,
    )]
    pub debug: bool,

    /// Disable anonymous usage telemetry.
    #[arg(
        long = "no-telemetry",
        env = "SOCKET_TELEMETRY_DISABLED",
        default_value_t = false,
        value_parser = parse_bool_flag,
    )]
    pub no_telemetry: bool,
}

impl GlobalArgs {
    /// Resolve `manifest_path` against `cwd`. See
    /// `socket_patch_core::manifest::operations::resolve_manifest_path`.
    pub fn resolved_manifest_path(&self) -> PathBuf {
        socket_patch_core::manifest::operations::resolve_manifest_path(
            &self.cwd,
            &self.manifest_path,
        )
    }

    /// Build [`ApiClientEnvOverrides`] from the CLI flags.
    ///
    /// `api_token` and `org` are forwarded as `Some(_)` only when set.
    /// `api_url` and `proxy_url` are forwarded only when non-empty;
    /// `GlobalArgs::default()` leaves both empty so integration tests
    /// that mutate env vars *after* constructing args still get env-var
    /// resolution from `get_api_client_with_overrides`. In production
    /// clap always populates them with either the CLI value, the env
    /// value, or the clap-declared default — all non-empty — so the
    /// resolved value still flows through.
    pub fn api_client_overrides(&self) -> ApiClientEnvOverrides {
        ApiClientEnvOverrides {
            api_url: Some(self.api_url.clone()).filter(|s| !s.is_empty()),
            api_token: self.api_token.clone().filter(|s| !s.is_empty()),
            org_slug: self.org.clone().filter(|s| !s.is_empty()),
            proxy_url: Some(self.proxy_url.clone()).filter(|s| !s.is_empty()),
        }
    }
}

/// Apply CLI-flag toggles for env-driven knobs by mirroring them into env
/// vars. This is how `--debug` / `--no-telemetry` reach core code that
/// reads `SOCKET_DEBUG` / `SOCKET_TELEMETRY_DISABLED` directly. Idempotent
/// and a no-op when the flags are off.
pub fn apply_env_toggles(common: &GlobalArgs) {
    if common.debug {
        std::env::set_var("SOCKET_DEBUG", "1");
    }
    if common.no_telemetry {
        std::env::set_var("SOCKET_TELEMETRY_DISABLED", "1");
    }
}

impl Default for GlobalArgs {
    /// Defaults intended for **test struct literals** (e.g. `..GlobalArgs::default()`).
    ///
    /// In production every field is populated by clap (with the
    /// `default_value = ".."` attribute providing the documented defaults
    /// when neither CLI flag nor env var is set), so this `Default` is
    /// only reached from tests building `GlobalArgs` directly.
    ///
    /// `api_url` and `proxy_url` are intentionally **empty** here (not
    /// the production default URLs). That lets tests set
    /// `SOCKET_API_URL` / `SOCKET_PROXY_URL` via `std::env::set_var`
    /// *after* constructing the args struct and have those env vars
    /// flow through to the API client — `api_client_overrides` skips
    /// empty values so the underlying `get_api_client_with_overrides`
    /// falls back to env-var resolution.
    fn default() -> Self {
        Self {
            cwd: PathBuf::from("."),
            manifest_path: DEFAULT_PATCH_MANIFEST_PATH.to_string(),
            api_url: String::new(),
            api_token: None,
            org: None,
            proxy_url: String::new(),
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
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    /// Minimal harness so we can exercise clap's parse + env-var resolution of
    /// `GlobalArgs` exactly as a real subcommand would (it is `flatten`ed).
    #[derive(Parser, Debug)]
    struct TestCli {
        #[command(flatten)]
        common: GlobalArgs,
    }

    /// Full list of env vars `GlobalArgs` reads, so each clap-parse test starts
    /// from a known-clean environment (no ambient `SOCKET_*` bleed-through).
    const SOCKET_ENV_VARS: &[&str] = &[
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

    /// Snapshot/clear every `SOCKET_*` var, run `f`, then restore. Keeps the
    /// env-mutating clap tests hermetic and reversible.
    fn with_clean_socket_env(f: impl FnOnce()) {
        let saved: Vec<(&str, Option<String>)> = SOCKET_ENV_VARS
            .iter()
            .map(|&k| (k, std::env::var(k).ok()))
            .collect();
        for &k in SOCKET_ENV_VARS {
            std::env::remove_var(k);
        }
        f();
        for (k, v) in saved {
            match v {
                Some(v) => std::env::set_var(k, v),
                None => std::env::remove_var(k),
            }
        }
    }

    /// `parse_bool_flag` accepts the same vocabulary as clap's
    /// `BoolishValueParser`, case-insensitively and with surrounding whitespace
    /// trimmed.
    #[test]
    fn parse_bool_flag_accepts_boolish_vocabulary() {
        for t in ["1", "true", "TRUE", "True", "yes", "Y", "on", "  on  ", "t"] {
            assert_eq!(parse_bool_flag(t), Ok(true), "{t:?} should be true");
        }
        for f in ["0", "false", "FALSE", "no", "N", "off", "  off  ", "f"] {
            assert_eq!(parse_bool_flag(f), Ok(false), "{f:?} should be false");
        }
    }

    /// The bug fix: an empty (or whitespace-only) string is `false`, not an
    /// error. Shells/CI export `SOCKET_OFFLINE=` to mean "unset".
    #[test]
    fn parse_bool_flag_treats_empty_as_false() {
        assert_eq!(parse_bool_flag(""), Ok(false));
        assert_eq!(parse_bool_flag("   "), Ok(false));
    }

    /// Genuinely non-boolean values are still rejected (we didn't make the
    /// parser permissive — only empty is special-cased).
    #[test]
    fn parse_bool_flag_rejects_non_boolean() {
        assert!(parse_bool_flag("garbage").is_err());
        assert!(parse_bool_flag("2").is_err());
        assert!(parse_bool_flag("tru").is_err());
    }

    /// Regression: an exported-but-empty bool env var must NOT crash the parse.
    /// Before the fix, `BoolishValueParser` aborted with "value was not a
    /// boolean", taking down every subcommand. Now it resolves to `false`.
    #[test]
    #[serial_test::serial]
    fn empty_bool_env_var_parses_as_false_not_crash() {
        with_clean_socket_env(|| {
            for var in ["SOCKET_OFFLINE", "SOCKET_JSON", "SOCKET_VERBOSE", "SOCKET_GLOBAL"] {
                std::env::set_var(var, "");
            }
            let cli = TestCli::try_parse_from(["socket-patch"])
                .expect("empty bool env vars must not abort the parse");
            assert!(!cli.common.offline);
            assert!(!cli.common.json);
            assert!(!cli.common.verbose);
            assert!(!cli.common.global);
            for var in ["SOCKET_OFFLINE", "SOCKET_JSON", "SOCKET_VERBOSE", "SOCKET_GLOBAL"] {
                std::env::remove_var(var);
            }
        });
    }

    /// A truthy bool env var resolves to `true` through clap.
    #[test]
    #[serial_test::serial]
    fn truthy_bool_env_var_parses_as_true() {
        with_clean_socket_env(|| {
            std::env::set_var("SOCKET_OFFLINE", "1");
            std::env::set_var("SOCKET_JSON", "true");
            let cli = TestCli::try_parse_from(["socket-patch"]).unwrap();
            assert!(cli.common.offline);
            assert!(cli.common.json);
            std::env::remove_var("SOCKET_OFFLINE");
            std::env::remove_var("SOCKET_JSON");
        });
    }

    /// A non-boolean bool env var is still a hard parse error — the empty-string
    /// special case must not have widened into "accept anything".
    #[test]
    #[serial_test::serial]
    fn garbage_bool_env_var_is_rejected() {
        with_clean_socket_env(|| {
            std::env::set_var("SOCKET_OFFLINE", "garbage");
            assert!(TestCli::try_parse_from(["socket-patch"]).is_err());
            std::env::remove_var("SOCKET_OFFLINE");
        });
    }

    /// The bare CLI flag still toggles `true` (the value_parser applies to the
    /// env path; on the command line `--offline` remains a no-value flag).
    #[test]
    #[serial_test::serial]
    fn bare_cli_flag_sets_true() {
        with_clean_socket_env(|| {
            let cli = TestCli::try_parse_from(["socket-patch", "--offline", "--json"]).unwrap();
            assert!(cli.common.offline);
            assert!(cli.common.json);
        });
    }

    /// With nothing set, every bool defaults to `false`.
    #[test]
    #[serial_test::serial]
    fn bools_default_false_when_unset() {
        with_clean_socket_env(|| {
            let cli = TestCli::try_parse_from(["socket-patch"]).unwrap();
            assert!(!cli.common.offline);
            assert!(!cli.common.json);
            assert!(!cli.common.verbose);
            assert!(!cli.common.silent);
            assert!(!cli.common.global);
            assert!(!cli.common.dry_run);
            assert!(!cli.common.yes);
            assert!(!cli.common.break_lock);
            assert!(!cli.common.debug);
            assert!(!cli.common.no_telemetry);
        });
    }

    /// `api_client_overrides` must forward every populated value verbatim.
    #[test]
    fn api_client_overrides_forwards_set_values() {
        let args = GlobalArgs {
            api_url: "https://api.example.com".to_string(),
            api_token: Some("tok123".to_string()),
            org: Some("acme".to_string()),
            proxy_url: "https://proxy.example.com".to_string(),
            ..GlobalArgs::default()
        };
        let o = args.api_client_overrides();
        assert_eq!(o.api_url.as_deref(), Some("https://api.example.com"));
        assert_eq!(o.api_token.as_deref(), Some("tok123"));
        assert_eq!(o.org_slug.as_deref(), Some("acme"));
        assert_eq!(o.proxy_url.as_deref(), Some("https://proxy.example.com"));
    }

    /// `GlobalArgs::default()` leaves `api_url`/`proxy_url` empty and the
    /// optional fields `None`, so every override must come back `None` —
    /// this is what lets integration tests set `SOCKET_*` env vars *after*
    /// constructing args and still have env-var resolution win downstream.
    #[test]
    fn api_client_overrides_default_is_all_none() {
        let o = GlobalArgs::default().api_client_overrides();
        assert!(o.api_url.is_none(), "empty api_url must not be forwarded");
        assert!(o.proxy_url.is_none(), "empty proxy_url must not be forwarded");
        assert!(o.api_token.is_none());
        assert!(o.org_slug.is_none());
    }

    /// Empty strings for url/token/org are filtered out, not forwarded as
    /// `Some("")` — otherwise an empty CLI value would mask env-var fallback.
    #[test]
    fn api_client_overrides_filters_empty_strings() {
        let args = GlobalArgs {
            api_url: String::new(),
            api_token: Some(String::new()),
            org: Some(String::new()),
            proxy_url: String::new(),
            ..GlobalArgs::default()
        };
        let o = args.api_client_overrides();
        assert!(o.api_url.is_none());
        assert!(o.api_token.is_none());
        assert!(o.org_slug.is_none());
        assert!(o.proxy_url.is_none());
    }

    /// A relative `manifest_path` is resolved against `cwd`.
    #[test]
    fn resolved_manifest_path_joins_relative_against_cwd() {
        let args = GlobalArgs {
            cwd: PathBuf::from("/work/project"),
            manifest_path: ".socket/manifest.json".to_string(),
            ..GlobalArgs::default()
        };
        assert_eq!(
            args.resolved_manifest_path(),
            PathBuf::from("/work/project/.socket/manifest.json"),
        );
    }

    /// An absolute `manifest_path` ignores `cwd` and passes through unchanged.
    #[test]
    fn resolved_manifest_path_passes_absolute_through() {
        let args = GlobalArgs {
            cwd: PathBuf::from("/work/project"),
            manifest_path: "/etc/socket/manifest.json".to_string(),
            ..GlobalArgs::default()
        };
        assert_eq!(
            args.resolved_manifest_path(),
            PathBuf::from("/etc/socket/manifest.json"),
        );
    }

    /// `apply_env_toggles` mirrors `--debug` / `--no-telemetry` into the env
    /// vars core code reads directly, and is a no-op when the flags are off.
    /// `#[serial]` because it mutates process-global env state.
    #[test]
    #[serial_test::serial]
    fn apply_env_toggles_mirrors_flags_into_env() {
        let saved_debug = std::env::var("SOCKET_DEBUG").ok();
        let saved_telemetry = std::env::var("SOCKET_TELEMETRY_DISABLED").ok();
        std::env::remove_var("SOCKET_DEBUG");
        std::env::remove_var("SOCKET_TELEMETRY_DISABLED");

        // Flags off: no-op, env stays unset.
        apply_env_toggles(&GlobalArgs::default());
        assert!(std::env::var("SOCKET_DEBUG").is_err());
        assert!(std::env::var("SOCKET_TELEMETRY_DISABLED").is_err());

        // Flags on: mirrored into the env.
        let args = GlobalArgs {
            debug: true,
            no_telemetry: true,
            ..GlobalArgs::default()
        };
        apply_env_toggles(&args);
        assert_eq!(std::env::var("SOCKET_DEBUG").as_deref(), Ok("1"));
        assert_eq!(std::env::var("SOCKET_TELEMETRY_DISABLED").as_deref(), Ok("1"));

        match saved_debug {
            Some(v) => std::env::set_var("SOCKET_DEBUG", v),
            None => std::env::remove_var("SOCKET_DEBUG"),
        }
        match saved_telemetry {
            Some(v) => std::env::set_var("SOCKET_TELEMETRY_DISABLED", v),
            None => std::env::remove_var("SOCKET_TELEMETRY_DISABLED"),
        }
    }
}
