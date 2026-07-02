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
use socket_patch_core::patch::vendor::VendorSource;

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

/// clap value-parser for `--vendor-source` / `SOCKET_VENDOR_SOURCE`.
///
/// Validates the token against [`VendorSource`] (`auto` | `service` | `build`,
/// case-insensitive) at parse time so a typo fails the command immediately
/// rather than at vendor time, and normalizes it to the canonical lowercase
/// tag. Mirrors [`parse_supported_ecosystem`]'s fail-loud-on-typo posture.
fn parse_vendor_source(s: &str) -> Result<String, String> {
    VendorSource::parse(s).map(|v| v.as_tag().to_string())
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
pub(crate) fn parse_bool_flag(s: &str) -> Result<bool, String> {
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
        default_value = "diff"
    )]
    pub download_mode: String,

    /// Where `vendor` acquires the installable patched artifact. `auto`
    /// (default) downloads the prebuilt archive from the patch.socket.dev
    /// vendoring service and silently falls back to a local build on any miss;
    /// `service` requires the service and fails closed; `build` always builds
    /// locally (the pre-service behavior). Only `vendor` uses this; other
    /// subcommands accept it silently.
    #[arg(
        long = "vendor-source",
        env = "SOCKET_VENDOR_SOURCE",
        default_value = "auto",
        value_parser = parse_vendor_source,
    )]
    pub vendor_source: String,

    /// Base URL for the patch vendoring service's package-reference request
    /// (the step-1 POST). Defaults to the active API base (`--api-url`) when
    /// authenticated or the proxy base (`--proxy-url`) otherwise. Override to
    /// point `vendor` at staging / local dev independently of `--api-url`.
    #[arg(long = "vendor-url", env = "SOCKET_VENDOR_URL")]
    pub vendor_url: Option<String>,

    /// Override the host of the prebuilt-archive download URL the vendoring
    /// service returns (the step-2 GET). When set, the CLI rewrites the
    /// scheme + host (+ port) of the returned URL to this base, preserving the
    /// path. Mainly for local-dev / testing, where the host the server bakes
    /// into the URL is not the one to actually fetch from.
    #[arg(long = "patch-server-url", env = "SOCKET_PATCH_SERVER_URL")]
    pub patch_server_url: Option<String>,

    /// Strict airgap: never contact the network. Operations that need remote
    /// data fail loudly when this is set.
    #[arg(
        long,
        env = "SOCKET_OFFLINE",
        default_value_t = false,
        value_parser = parse_bool_flag,
    )]
    pub offline: bool,

    /// Treat a beforeHash mismatch as a hard error. By DEFAULT a file whose
    /// on-disk content matches neither the patch's beforeHash nor its
    /// afterHash is overwritten with the full verified patched content and
    /// surfaced as a stderr warning (`content_mismatch_overwritten`); this
    /// flag restores the fail-closed behavior. `--force` overrides it.
    #[arg(
        long,
        env = "SOCKET_STRICT",
        default_value_t = false,
        value_parser = parse_bool_flag,
    )]
    pub strict: bool,

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

    /// Reclaim a stale `<.socket>/apply.lock` left behind by a
    /// crashed run (the file is never deleted — deleting a lock file
    /// defeats mutual exclusion). Refuses with `lock_held` if a live
    /// socket-patch process still holds the lock. Emits a
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
    pub(crate) fn resolved_manifest_path(&self) -> PathBuf {
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
/// vars. This is how `--offline` / `--debug` / `--no-telemetry` reach core
/// code that reads `SOCKET_OFFLINE` / `SOCKET_DEBUG` /
/// `SOCKET_TELEMETRY_DISABLED` directly. Idempotent and a no-op when the
/// flags are off.
///
/// `offline` matters most: the telemetry kill-switch
/// (`socket_patch_core::utils::telemetry::is_telemetry_disabled`) honors the
/// strict-airgap contract by reading `SOCKET_OFFLINE` from the env, so
/// without this mirror a bare `--offline` flag (or a truthy spelling like
/// `SOCKET_OFFLINE=yes` that core's `"1" | "true"` match doesn't recognize)
/// still let telemetry fire a network request.
pub(crate) fn apply_env_toggles(common: &GlobalArgs) {
    if common.offline {
        std::env::set_var("SOCKET_OFFLINE", "1");
    }
    if common.debug {
        std::env::set_var("SOCKET_DEBUG", "1");
    }
    if common.no_telemetry {
        std::env::set_var("SOCKET_TELEMETRY_DISABLED", "1");
    }
}

/// Every env var `GlobalArgs` binds (one per `env = "..."` attribute above).
/// Single source of truth for [`scrub_empty_global_env_vars`] and the
/// clean-environment test harnesses.
pub const GLOBAL_ARG_ENV_VARS: &[&str] = &[
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

/// Remove exported-but-**empty** `GlobalArgs` env vars before clap parses.
///
/// `SOCKET_CWD=` — the conventional shell/CI idiom for blanking a variable
/// without unsetting it — must mean "unset, fall back to the default", not
/// abort the command. [`parse_bool_flag`] already gives the bool flags that
/// semantic, but clap rejects an empty `SOCKET_CWD` / `SOCKET_GLOBAL_PREFIX`
/// ("a value is required"), `SOCKET_LOCK_TIMEOUT` ("cannot parse integer
/// from empty string") and `SOCKET_ECOSYSTEMS` (the per-token validator)
/// outright — a single stray blank var crashed every subcommand — and an
/// empty `SOCKET_DOWNLOAD_MODE` / `SOCKET_MANIFEST_PATH` leaked `""` past
/// the documented defaults. Called from `main` after legacy-name promotion
/// and before clap runs. Only exactly-empty values are scrubbed; whitespace
/// is significant in paths, so it is left for the parsers to judge.
pub fn scrub_empty_global_env_vars() {
    for &var in GLOBAL_ARG_ENV_VARS {
        if matches!(std::env::var(var).as_deref(), Ok("")) {
            std::env::remove_var(var);
        }
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
            vendor_source: "auto".to_string(),
            vendor_url: None,
            patch_server_url: None,
            offline: false,
            strict: false,
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

    /// Snapshot/clear each var in `vars`, run `f`, then restore. Keeps the
    /// env-mutating clap tests hermetic and reversible.
    fn with_env_cleared(vars: &[&str], f: impl FnOnce()) {
        let saved: Vec<(&str, Option<String>)> =
            vars.iter().map(|&k| (k, std::env::var(k).ok())).collect();
        for &k in vars {
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

    /// Clear every env var `GlobalArgs` reads (the production list, so the
    /// scrub and the harness can't drift), giving each clap-parse test a
    /// known-clean environment with no ambient `SOCKET_*` bleed-through.
    fn with_clean_socket_env(f: impl FnOnce()) {
        with_env_cleared(GLOBAL_ARG_ENV_VARS, f);
    }

    /// Clear the extra env the core telemetry gate reads beyond the
    /// `SOCKET_*` set (`is_telemetry_disabled` also consults `VITEST` and the
    /// legacy `SOCKET_PATCH_TELEMETRY_DISABLED` name), so the airgap tests
    /// below can't pass or fail vacuously. Restores afterwards.
    fn with_clean_telemetry_env(f: impl FnOnce()) {
        with_env_cleared(&["VITEST", "SOCKET_PATCH_TELEMETRY_DISABLED"], f);
    }

    /// `--offline` promises "never contact the network", but the telemetry
    /// kill-switch (`socket_patch_core::utils::telemetry::is_telemetry_disabled`)
    /// reads the `SOCKET_OFFLINE` env var directly — it never sees the parsed
    /// flag. `apply_env_toggles` must therefore mirror `--offline` into the
    /// env exactly like `--debug` / `--no-telemetry`, or an airgapped
    /// `socket-patch apply --offline` still fires a telemetry HTTP request.
    #[test]
    #[serial_test::serial]
    fn apply_env_toggles_mirrors_offline_into_env_for_airgap() {
        with_clean_socket_env(|| {
            with_clean_telemetry_env(|| {
                let args = GlobalArgs {
                    offline: true,
                    ..GlobalArgs::default()
                };
                apply_env_toggles(&args);
                assert_eq!(std::env::var("SOCKET_OFFLINE").as_deref(), Ok("1"));
                assert!(
                    socket_patch_core::utils::telemetry::is_telemetry_disabled(),
                    "--offline must disable telemetry (strict airgap: never contact the network)",
                );
            });
        });
    }

    /// The full `SOCKET_OFFLINE` vocabulary must reach the telemetry gate.
    /// clap (via `parse_bool_flag`) accepts `yes`/`on`/`y`/`t` as true, but
    /// core's direct env read matches only `"1" | "true"` — so the toggle
    /// mirror has to re-export the parsed flag in normalized form.
    #[test]
    #[serial_test::serial]
    fn truthy_offline_env_vocabulary_reaches_telemetry_gate() {
        with_clean_socket_env(|| {
            with_clean_telemetry_env(|| {
                std::env::set_var("SOCKET_OFFLINE", "yes");
                let cli = TestCli::try_parse_from(["socket-patch"]).unwrap();
                assert!(cli.common.offline, "SOCKET_OFFLINE=yes parses as offline");
                apply_env_toggles(&cli.common);
                assert!(
                    socket_patch_core::utils::telemetry::is_telemetry_disabled(),
                    "SOCKET_OFFLINE=yes must disable telemetry like SOCKET_OFFLINE=1",
                );
            });
        });
    }

    /// `scrub_empty_global_env_vars` removes exactly-empty `SOCKET_*` globals
    /// (the `VAR=` blank-without-unsetting idiom) and nothing else: set,
    /// non-empty values — even whitespace-only ones, which are significant in
    /// paths — survive, and the previously-crashing parse then sees plain
    /// defaults.
    #[test]
    #[serial_test::serial]
    fn scrub_empty_global_env_vars_unsets_only_empties() {
        with_clean_socket_env(|| {
            std::env::set_var("SOCKET_CWD", "");
            std::env::set_var("SOCKET_LOCK_TIMEOUT", "");
            std::env::set_var("SOCKET_GLOBAL_PREFIX", "");
            std::env::set_var("SOCKET_ECOSYSTEMS", "");
            std::env::set_var("SOCKET_DOWNLOAD_MODE", "");
            std::env::set_var("SOCKET_VENDOR_SOURCE", "");
            std::env::set_var("SOCKET_MANIFEST_PATH", "keep.json");
            std::env::set_var("SOCKET_ORG_SLUG", " ");

            scrub_empty_global_env_vars();

            assert!(
                std::env::var("SOCKET_CWD").is_err(),
                "empty var is scrubbed"
            );
            assert!(std::env::var("SOCKET_LOCK_TIMEOUT").is_err());
            assert_eq!(
                std::env::var("SOCKET_MANIFEST_PATH").as_deref(),
                Ok("keep.json"),
                "non-empty values must survive the scrub",
            );
            assert_eq!(
                std::env::var("SOCKET_ORG_SLUG").as_deref(),
                Ok(" "),
                "whitespace-only values are left for the parsers to judge",
            );

            let cli = TestCli::try_parse_from(["socket-patch"])
                .expect("blank env vars must mean 'unset', not a parse abort");
            assert_eq!(cli.common.cwd, PathBuf::from("."));
            assert_eq!(cli.common.lock_timeout, None);
            assert!(cli.common.global_prefix.is_none());
            assert!(cli.common.ecosystems.is_none());
            assert_eq!(cli.common.download_mode, "diff");
            assert_eq!(
                cli.common.vendor_source, "auto",
                "empty SOCKET_VENDOR_SOURCE must fall back to the `auto` default"
            );
            assert_eq!(cli.common.manifest_path, "keep.json");
        });
    }

    /// `--vendor-source` parses every known token, normalizes case, honors the
    /// env var, and defaults to `auto`; an unknown token aborts the parse.
    #[test]
    #[serial_test::serial]
    fn vendor_source_flag_parses_normalizes_and_defaults() {
        with_clean_socket_env(|| {
            // Default when unset.
            let cli = TestCli::try_parse_from(["socket-patch"]).unwrap();
            assert_eq!(cli.common.vendor_source, "auto");

            // CLI value, case-normalized to the canonical tag.
            let cli =
                TestCli::try_parse_from(["socket-patch", "--vendor-source", "SERVICE"]).unwrap();
            assert_eq!(cli.common.vendor_source, "service");

            // Env var honored.
            std::env::set_var("SOCKET_VENDOR_SOURCE", "build");
            let cli = TestCli::try_parse_from(["socket-patch"]).unwrap();
            assert_eq!(cli.common.vendor_source, "build");
            std::env::remove_var("SOCKET_VENDOR_SOURCE");

            // Garbage is rejected at parse time.
            assert!(
                TestCli::try_parse_from(["socket-patch", "--vendor-source", "download"]).is_err(),
                "an unknown vendor source must fail the parse",
            );
        });
    }

    /// The new URL knobs flow through to the parsed args from CLI and env.
    #[test]
    #[serial_test::serial]
    fn vendor_url_and_patch_server_url_flow_from_cli_and_env() {
        with_clean_socket_env(|| {
            let cli = TestCli::try_parse_from([
                "socket-patch",
                "--vendor-url",
                "https://patch.socket-staging.dev",
                "--patch-server-url",
                "http://localhost:4026",
            ])
            .unwrap();
            assert_eq!(
                cli.common.vendor_url.as_deref(),
                Some("https://patch.socket-staging.dev")
            );
            assert_eq!(
                cli.common.patch_server_url.as_deref(),
                Some("http://localhost:4026")
            );

            std::env::set_var("SOCKET_VENDOR_URL", "https://from-env.example");
            let cli = TestCli::try_parse_from(["socket-patch"]).unwrap();
            assert_eq!(
                cli.common.vendor_url.as_deref(),
                Some("https://from-env.example")
            );
            std::env::remove_var("SOCKET_VENDOR_URL");
            // Unset by default.
            let cli = TestCli::try_parse_from(["socket-patch"]).unwrap();
            assert!(cli.common.vendor_url.is_none());
            assert!(cli.common.patch_server_url.is_none());
        });
    }

    /// Single-source-of-truth guard: the new env vars must be registered in
    /// `GLOBAL_ARG_ENV_VARS` (drives the scrub + clean-env harness).
    #[test]
    fn global_arg_env_vars_includes_vendor_knobs() {
        for var in [
            "SOCKET_VENDOR_SOURCE",
            "SOCKET_VENDOR_URL",
            "SOCKET_PATCH_SERVER_URL",
        ] {
            assert!(
                GLOBAL_ARG_ENV_VARS.contains(&var),
                "{var} must be in GLOBAL_ARG_ENV_VARS",
            );
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
            for var in [
                "SOCKET_OFFLINE",
                "SOCKET_JSON",
                "SOCKET_VERBOSE",
                "SOCKET_GLOBAL",
            ] {
                std::env::set_var(var, "");
            }
            let cli = TestCli::try_parse_from(["socket-patch"])
                .expect("empty bool env vars must not abort the parse");
            assert!(!cli.common.offline);
            assert!(!cli.common.json);
            assert!(!cli.common.verbose);
            assert!(!cli.common.global);
            for var in [
                "SOCKET_OFFLINE",
                "SOCKET_JSON",
                "SOCKET_VERBOSE",
                "SOCKET_GLOBAL",
            ] {
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
        assert!(
            o.proxy_url.is_none(),
            "empty proxy_url must not be forwarded"
        );
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

    /// `parse_supported_ecosystem` accepts every name this build compiles in
    /// and returns it verbatim.
    #[test]
    fn parse_supported_ecosystem_accepts_compiled_in_names() {
        for e in Ecosystem::all() {
            let name = e.cli_name();
            assert_eq!(
                parse_supported_ecosystem(name),
                Ok(name.to_string()),
                "{name:?} is compiled in and must be accepted",
            );
        }
    }

    /// Unsupported / misspelled ecosystem names are rejected with a message
    /// that names the offending token and lists the supported set.
    #[test]
    fn parse_supported_ecosystem_rejects_unknown_names() {
        for bad in ["bogus", "NPM", "py-pi", ""] {
            let err = parse_supported_ecosystem(bad)
                .expect_err("unsupported ecosystem name must be rejected");
            assert!(
                err.contains(bad),
                "error should echo the bad token: {err:?}"
            );
            assert!(
                err.contains("supported:"),
                "error should list the supported set: {err:?}",
            );
        }
    }

    /// End-to-end through clap: `--ecosystems` splits on commas, validates each
    /// token, and rejects the whole parse if any token is unsupported.
    #[test]
    #[serial_test::serial]
    fn ecosystems_flag_splits_and_validates() {
        with_clean_socket_env(|| {
            let cli = TestCli::try_parse_from(["socket-patch", "--ecosystems", "npm,pypi"])
                .expect("comma-separated supported ecosystems must parse");
            assert_eq!(
                cli.common.ecosystems,
                Some(vec!["npm".to_string(), "pypi".to_string()]),
            );

            // One bad token in the list aborts the whole parse.
            assert!(
                TestCli::try_parse_from(["socket-patch", "--ecosystems", "npm,bogus"]).is_err(),
                "an unsupported token must fail the parse",
            );
        });
    }

    /// Precedence contract: a CLI value wins over the env var for a string flag.
    #[test]
    #[serial_test::serial]
    fn cli_arg_overrides_env_var() {
        with_clean_socket_env(|| {
            std::env::set_var("SOCKET_MANIFEST_PATH", "from-env.json");
            let cli = TestCli::try_parse_from(["socket-patch", "--manifest-path", "from-cli.json"])
                .unwrap();
            assert_eq!(cli.common.manifest_path, "from-cli.json");
            std::env::remove_var("SOCKET_MANIFEST_PATH");
        });
    }

    /// Precedence contract: the env var is honored when no CLI value is given,
    /// and the clap-declared default applies when neither is set.
    #[test]
    #[serial_test::serial]
    fn env_var_used_then_default_applies() {
        with_clean_socket_env(|| {
            std::env::set_var("SOCKET_MANIFEST_PATH", "from-env.json");
            let cli = TestCli::try_parse_from(["socket-patch"]).unwrap();
            assert_eq!(cli.common.manifest_path, "from-env.json");
            std::env::remove_var("SOCKET_MANIFEST_PATH");

            let cli = TestCli::try_parse_from(["socket-patch"]).unwrap();
            assert_eq!(cli.common.manifest_path, DEFAULT_PATCH_MANIFEST_PATH);
            assert_eq!(cli.common.download_mode, "diff");
            assert_eq!(cli.common.cwd, PathBuf::from("."));
        });
    }

    /// `apply_env_toggles` mirrors `--debug` / `--no-telemetry` into the env
    /// vars core code reads directly, and is a no-op when the flags are off.
    /// `#[serial]` because it mutates process-global env state.
    #[test]
    #[serial_test::serial]
    fn apply_env_toggles_mirrors_flags_into_env() {
        with_env_cleared(&["SOCKET_DEBUG", "SOCKET_TELEMETRY_DISABLED"], || {
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
            assert_eq!(
                std::env::var("SOCKET_TELEMETRY_DISABLED").as_deref(),
                Ok("1")
            );
        });
    }
}
