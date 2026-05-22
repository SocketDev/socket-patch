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
        short = 'm',
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

    /// Restrict to these ecosystems (comma-separated).
    #[arg(
        long = "ecosystems",
        short = 'e',
        env = "SOCKET_ECOSYSTEMS",
        value_delimiter = ',',
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
    #[arg(long, env = "SOCKET_OFFLINE", default_value_t = false)]
    pub offline: bool,

    /// Operate on globally-installed packages.
    #[arg(
        long = "global",
        short = 'g',
        env = "SOCKET_GLOBAL",
        default_value_t = false,
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
    )]
    pub json: bool,

    /// Show extra detail in human-readable output.
    #[arg(
        long = "verbose",
        short = 'v',
        env = "SOCKET_VERBOSE",
        default_value_t = false,
    )]
    pub verbose: bool,

    /// Suppress non-error output.
    #[arg(
        long = "silent",
        short = 's',
        env = "SOCKET_SILENT",
        default_value_t = false,
    )]
    pub silent: bool,

    /// Preview the operation without making any mutations.
    #[arg(
        long = "dry-run",
        short = 'd',
        env = "SOCKET_DRY_RUN",
        default_value_t = false,
    )]
    pub dry_run: bool,

    /// Skip interactive prompts.
    #[arg(
        long = "yes",
        short = 'y',
        env = "SOCKET_YES",
        default_value_t = false,
    )]
    pub yes: bool,

    /// Emit verbose debug logs to stderr.
    #[arg(long = "debug", env = "SOCKET_DEBUG", default_value_t = false)]
    pub debug: bool,

    /// Disable anonymous usage telemetry.
    #[arg(
        long = "no-telemetry",
        env = "SOCKET_TELEMETRY_DISABLED",
        default_value_t = false,
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

    /// Build [`ApiClientEnvOverrides`] from the CLI flags. Every override
    /// is populated unconditionally — clap's `env = ".."` attribute has
    /// already resolved CLI > env > default for each field, so passing
    /// the resolved value through as `Some(_)` is correct.
    ///
    /// `api_token` and `org` remain `Option<String>` (they have no
    /// default), so the override is `None` exactly when the user did not
    /// provide one via CLI or env.
    pub fn api_client_overrides(&self) -> ApiClientEnvOverrides {
        ApiClientEnvOverrides {
            api_url: Some(self.api_url.clone()),
            api_token: self.api_token.clone().filter(|s| !s.is_empty()),
            org_slug: self.org.clone().filter(|s| !s.is_empty()),
            proxy_url: Some(self.proxy_url.clone()),
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
    /// Defaults that match the clap-derived defaults exactly.
    ///
    /// Available outside `#[cfg(test)]` because integration tests in
    /// `tests/` are external crates and can't see `cfg(test)` items.
    fn default() -> Self {
        Self {
            cwd: PathBuf::from("."),
            manifest_path: DEFAULT_PATCH_MANIFEST_PATH.to_string(),
            api_url: DEFAULT_SOCKET_API_URL.to_string(),
            api_token: None,
            org: None,
            proxy_url: DEFAULT_PATCH_API_PROXY_URL.to_string(),
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
            debug: false,
            no_telemetry: false,
        }
    }
}
