//! Shared CLI flags and their `SOCKET_*` environment bindings.
//! Commands accept unused flags as no-ops. See `CLI_CONTRACT.md` for their scope
//! and configuration precedence.

use std::path::{Path, PathBuf};

use clap::Args;

use socket_patch_core::api::client::{
    resolve_ambient_credentials, ApiClient, ApiClientEnvOverrides,
};
use socket_patch_core::constants::DEFAULT_PATCH_MANIFEST_PATH;
use socket_patch_core::crawlers::Ecosystem;
use socket_patch_core::telemetry::TelemetryAuth;
use socket_patch_core::vendor::{VendorServiceConfig, VendorSource};

/// Reject unknown ecosystems before they can produce a misleading empty scan.
fn parse_supported_ecosystem(s: &str) -> Result<String, String> {
    if Ecosystem::all().iter().any(|e| e.cli_name() == s) {
        return Ok(s.to_string());
    }
    let supported = Ecosystem::all()
        .iter()
        .map(|e| e.cli_name())
        .collect::<Vec<_>>()
        .join(", ");
    // An empty token (`--ecosystems ,npm`, a trailing comma) gets its own
    // wording: "unsupported ecosystem ``" reads like a rendering glitch.
    if s.trim().is_empty() {
        Err(format!(
            "empty ecosystem name in the list (supported: {supported})"
        ))
    } else {
        Err(format!(
            "unsupported ecosystem `{s}` (supported: {supported})"
        ))
    }
}

/// Validate the service source and normalize its compatibility alias at parse time.
fn parse_vendor_source(s: &str) -> Result<String, String> {
    VendorSource::parse(s).map(|v| v.as_tag().to_string())
}

/// Parse boolish environment values, treating an exported empty value as false.
pub(crate) fn parse_bool_flag(s: &str) -> Result<bool, String> {
    match s.trim().to_ascii_lowercase().as_str() {
        "" | "n" | "no" | "f" | "false" | "off" | "0" => Ok(false),
        "y" | "yes" | "t" | "true" | "on" | "1" => Ok(true),
        other => Err(format!(
            "`{other}` is not a boolean (expected one of: true, false, yes, no, on, off, 1, 0)"
        )),
    }
}

/// `--help` heading for every [`GlobalArgs`] flag, so each subcommand's own
/// flags (listed first, under "Options") are not buried among the ~24 shared
/// ones. Set per-arg rather than as the struct's `next_help_heading`: that
/// would leak onto the subcommand-local flags declared after the flatten.
pub(crate) const GLOBAL_OPTIONS: &str = "Global options";

// Arguments inherited by every subcommand via `#[command(flatten)]`.
//
// **Every** global flag is parseable on **every** subcommand. Commands that
// don't use a given flag ignore it silently — e.g. `list --global` parses
// fine and the `global` field is unused at runtime. The one exception is
// the path flags (`--cwd`, `--global-prefix`, `--manifest-path`): `main`
// validates them on every project command, used or not
// ([`GlobalArgs::validate_paths`]), because a path that names nothing must
// never read as an empty project.
//
// (Plain `//` comments: clap turns a doc comment here into the `--help`
// description of any subcommand that has none of its own.)
#[derive(Args, Debug, Clone)]
pub struct GlobalArgs {
    /// Working directory.
    #[arg(help_heading = GLOBAL_OPTIONS, long, env = "SOCKET_CWD", default_value = ".")]
    pub cwd: PathBuf,

    /// Path to patch manifest file (resolved relative to --cwd).
    #[arg(
        help_heading = GLOBAL_OPTIONS,
        long = "manifest-path",
        env = "SOCKET_MANIFEST_PATH",
        default_value = DEFAULT_PATCH_MANIFEST_PATH,
    )]
    pub manifest_path: String,

    /// Socket API URL (authenticated endpoint). Falls back to the socket-cli
    /// config file, then https://api.socket.dev.
    //
    // No clap default: `None` lets the core resolver fall through env and the
    // socket-cli config file before applying `DEFAULT_SOCKET_API_URL`.
    #[arg(help_heading = GLOBAL_OPTIONS, long = "api-url", env = "SOCKET_API_URL")]
    pub api_url: Option<String>,

    /// Socket API token. Absence selects the public patch proxy.
    #[arg(
        help_heading = GLOBAL_OPTIONS,
        long = "api-token",
        env = "SOCKET_API_TOKEN",
        hide_env_values = true
    )]
    pub api_token: Option<String>,

    /// Organization slug. Auto-resolved when omitted and a token is set.
    #[arg(help_heading = GLOBAL_OPTIONS, long = "org", short = 'o', env = "SOCKET_ORG_SLUG")]
    pub org: Option<String>,

    /// Public patch proxy URL used when no API token is set
    /// [default: https://patches-api.socket.dev].
    //
    // No clap default, matching `api_url` — resolution happens in
    // `get_api_client_with_overrides`.
    #[arg(help_heading = GLOBAL_OPTIONS, long = "proxy-url", env = "SOCKET_PROXY_URL")]
    pub proxy_url: Option<String>,

    /// Restrict to these ecosystems (comma-separated).
    #[arg(
        help_heading = GLOBAL_OPTIONS,
        long = "ecosystems",
        short = 'e',
        env = "SOCKET_ECOSYSTEMS",
        value_delimiter = ',',
        value_parser = parse_supported_ecosystem,
    )]
    pub ecosystems: Option<Vec<String>>,

    /// Download installable patched artifacts from the patch service.
    /// `service` is the default; `auto` is a compatibility alias. Local
    /// artifact building is no longer supported. Healthy committed artifacts
    /// can be reused offline; missing or corrupt artifacts require a download.
    #[arg(
        help_heading = GLOBAL_OPTIONS,
        long = "vendor-source",
        env = "SOCKET_VENDOR_SOURCE",
        default_value = "service",
        value_parser = parse_vendor_source,
    )]
    pub vendor_source: String,

    /// Vendored Maven: auto writes the repository tail; none uses only the file repository.
    /// The choice is preserved on subsequent runs.
    #[arg(help_heading = GLOBAL_OPTIONS, long, value_parser = ["auto", "none"])]
    pub maven_config: Option<String>,

    /// Base URL for the patch vendoring service. Defaults to the active API base (`--api-url`) when
    /// authenticated or the proxy base (`--proxy-url`) otherwise. Override to
    /// point `vendor` at staging / local dev independently of `--api-url`.
    // A dev/testing knob: listed in `--help`, left out of the `-h` summary.
    #[arg(help_heading = GLOBAL_OPTIONS, long = "vendor-url", env = "SOCKET_VENDOR_URL", hide_short_help = true)]
    pub vendor_url: Option<String>,

    /// Override the host of the prebuilt-archive download URL the vendoring
    /// service returns. When set, the CLI rewrites the
    /// scheme + host (+ port) of the returned URL to this base, preserving the
    /// path. `vex` and `scan` also accept lockfile URLs on this origin as
    /// hosted patch references (attested, and counted as live hosted wiring)
    /// next to patch.socket.dev. Mainly for local-dev / testing, where the
    /// host the server bakes into the URL is not the one to actually fetch
    /// from.
    // A dev/testing knob: listed in `--help`, left out of the `-h` summary.
    #[arg(
        help_heading = GLOBAL_OPTIONS,
        long = "patch-server-url",
        env = "SOCKET_PATCH_SERVER_URL",
        hide_short_help = true
    )]
    pub patch_server_url: Option<String>,

    /// Disable network access; fail if remote data is needed.
    #[arg(
        help_heading = GLOBAL_OPTIONS,
        long,
        env = "SOCKET_OFFLINE",
        default_value_t = false,
        value_parser = parse_bool_flag,
    )]
    pub offline: bool,

    /// Reject modified file content even with --allow-patch-conflicts. Without
    /// explicit consent, mismatches already fail by default. On commands that
    /// have --force, --force overrides this file-content check (but never the
    /// separate check for declared project patches).
    #[arg(
        help_heading = GLOBAL_OPTIONS,
        long,
        env = "SOCKET_STRICT",
        default_value_t = false,
        value_parser = parse_bool_flag,
    )]
    pub strict: bool,

    /// Accept the risk of conflicts with existing project patches or local
    /// modifications when applying Socket patches. Modified files may be
    /// overwritten; patches are not merged automatically. Backend safety
    /// refusals still apply. --yes does not approve patch composition; --force
    /// approves only file-content drift.
    #[arg(help_heading = GLOBAL_OPTIONS, long)]
    pub allow_patch_conflicts: bool,

    /// Operate on globally-installed packages.
    #[arg(
        help_heading = GLOBAL_OPTIONS,
        long = "global",
        short = 'g',
        env = "SOCKET_GLOBAL",
        default_value_t = false,
        value_parser = parse_bool_flag,
    )]
    pub global: bool,

    /// Override the path used to discover globally-installed packages.
    #[arg(help_heading = GLOBAL_OPTIONS, long = "global-prefix", env = "SOCKET_GLOBAL_PREFIX")]
    pub global_prefix: Option<PathBuf>,

    /// Emit machine-readable JSON output.
    #[arg(
        help_heading = GLOBAL_OPTIONS,
        long = "json",
        short = 'j',
        env = "SOCKET_JSON",
        default_value_t = false,
        value_parser = parse_bool_flag,
    )]
    pub json: bool,

    /// Show extra detail in human-readable output.
    #[arg(
        help_heading = GLOBAL_OPTIONS,
        long = "verbose",
        short = 'v',
        env = "SOCKET_VERBOSE",
        default_value_t = false,
        value_parser = parse_bool_flag,
    )]
    pub verbose: bool,

    /// Suppress non-error output.
    #[arg(
        help_heading = GLOBAL_OPTIONS,
        long = "silent",
        short = 's',
        env = "SOCKET_SILENT",
        default_value_t = false,
        value_parser = parse_bool_flag,
    )]
    pub silent: bool,

    /// Preview the operation without making any mutations.
    #[arg(
        help_heading = GLOBAL_OPTIONS,
        long = "dry-run",
        env = "SOCKET_DRY_RUN",
        default_value_t = false,
        value_parser = parse_bool_flag,
    )]
    pub dry_run: bool,

    /// Skip interactive prompts.
    #[arg(
        help_heading = GLOBAL_OPTIONS,
        long = "yes",
        short = 'y',
        env = "SOCKET_YES",
        default_value_t = false,
        value_parser = parse_bool_flag,
    )]
    pub yes: bool,

    /// Seconds to wait for the `.socket/apply.lock` lock before giving up.
    /// By default (or with `0`) the lock is tried once, failing immediately
    /// if another process holds it. A positive value retries with a 100 ms
    /// backoff until the lock frees or the budget elapses. Only meaningful
    /// for the commands that take the lock (`apply`, `rollback`, `repair`,
    /// `remove`, `vendor`, `get` and `scan` when they record, apply,
    /// vendor or host patches);
    /// other commands accept it silently. Every holder removes the lock file on exit, so a leftover
    /// from a crashed run never contends.
    #[arg(help_heading = GLOBAL_OPTIONS, long = "lock-timeout", env = "SOCKET_LOCK_TIMEOUT")]
    pub lock_timeout: Option<u64>,

    /// Emit verbose debug logs to stderr.
    #[arg(
        help_heading = GLOBAL_OPTIONS,
        long = "debug",
        env = "SOCKET_DEBUG",
        default_value_t = false,
        value_parser = parse_bool_flag,
    )]
    pub debug: bool,

    /// Disable anonymous usage telemetry.
    #[arg(
        help_heading = GLOBAL_OPTIONS,
        long = "no-telemetry",
        env = "SOCKET_TELEMETRY_DISABLED",
        default_value_t = false,
        value_parser = parse_bool_flag,
    )]
    pub no_telemetry: bool,

    /// Hosted mode (`scan`/`get --mode hosted`): do NOT auto-configure
    /// `trustLockfile: true` in pnpm-workspace.yaml after a pnpm-lock.yaml
    /// (lockfileVersion >= 9) is repointed at the hosted patch server.
    /// pnpm >= 11 rejects the repointed lock without that trust grant, so
    /// opting out means every install needs `pnpm install --trust-lockfile`
    /// instead (the run's warning spells out both recoveries). Only
    /// hosted-mode `scan` and `get` read this; other subcommands accept it
    /// silently.
    #[arg(
        help_heading = GLOBAL_OPTIONS,
        long = "no-trust-lockfile-config",
        env = "SOCKET_NO_TRUST_LOCKFILE_CONFIG",
        default_value_t = false,
        value_parser = parse_bool_flag,
    )]
    pub no_trust_lockfile_config: bool,

    /// Hosted mode (`scan`/`get --mode hosted`): do NOT auto-configure
    /// `allow-remote=all` in the project .npmrc after a root
    /// package-lock.json / npm-shrinkwrap.json is repointed at the hosted
    /// patch server. npm >= 12 defaults to `allow-remote=none` and refuses
    /// the repointed lock (EALLOWREMOTE), so opting out means every install
    /// needs `npm ci --allow-remote=all` instead (the run's warning spells
    /// it out). Only hosted-mode `scan` and `get` read this; other
    /// subcommands accept it silently.
    #[arg(
        help_heading = GLOBAL_OPTIONS,
        long = "no-npm-allow-remote-config",
        env = "SOCKET_NO_NPM_ALLOW_REMOTE_CONFIG",
        default_value_t = false,
        value_parser = parse_bool_flag,
    )]
    pub no_npm_allow_remote_config: bool,

    /// Hosted mode (`scan`/`get --mode hosted`, and `rollback`/`remove` of
    /// hosted patches): do NOT remove stale vlt installed copies
    /// (`node_modules/.vlt-lock.json` and the stale `node_modules/.vlt`
    /// entries) after `vlt-lock.json` is repointed or restored. vlt never
    /// refreshes an installed copy on its own, so opting out means running
    /// `vlt ci` instead (the run's `redirect_vlt_reinstall_required`
    /// advisory says so). Optional dependencies' copies are never removed.
    /// Other subcommands accept it silently.
    #[arg(
        help_heading = GLOBAL_OPTIONS,
        long = "no-vlt-install-cleanup",
        env = "SOCKET_NO_VLT_INSTALL_CLEANUP",
        default_value_t = false,
        value_parser = parse_bool_flag,
    )]
    pub no_vlt_install_cleanup: bool,
}

impl GlobalArgs {
    /// Reject path flags that name nothing, so a typo in `--cwd` never reads
    /// as an empty project that passes every check: `--cwd` and
    /// `--global-prefix` (flag or env) must be existing directories, and a
    /// `--manifest-path` other than the default must sit in an existing
    /// project directory. `main` maps `Err` to the usage exit (2).
    ///
    /// A missing manifest FILE stays legal: hosted and vendored projects
    /// have none. The commands that create the manifest
    /// (`creates_manifest`: `get`, `scan`) also create its directory.
    pub fn validate_paths(&self, creates_manifest: bool) -> Result<(), String> {
        let not_dir = |flag: &str, env: &str, path: &Path, what: &str| {
            format!("{flag} (or {env}) `{}` {what}", path.display())
        };
        let require_dir = |flag: &str, env: &str, path: &Path| {
            if path.is_dir() {
                return Ok(());
            }
            let what = if path.exists() {
                "is not a directory"
            } else {
                "does not exist"
            };
            Err(not_dir(flag, env, path, what))
        };
        require_dir("--cwd", "SOCKET_CWD", &self.cwd)?;
        if let Some(prefix) = &self.global_prefix {
            require_dir("--global-prefix", "SOCKET_GLOBAL_PREFIX", prefix)?;
        }
        // A manifest path that names a directory is not refused here: that
        // is a corrupt project, not a bad flag, and `read_manifest` refuses
        // it as `manifest_unreadable` with a `--json` document.
        if self.manifest_path != DEFAULT_PATCH_MANIFEST_PATH {
            // `.`-free for the message: `--cwd .` joined onto
            // `./.socket/manifest.json` would print `././.socket/…`.
            let manifest: PathBuf = self.resolved_manifest_path().components().collect();
            // The directory that must exist: the project of a `.socket/`
            // manifest (`.socket/` itself is created on demand), else the
            // manifest file's own directory.
            let in_socket_dir = manifest.parent().and_then(Path::file_name)
                == Some(std::ffi::OsStr::new(
                    socket_patch_core::constants::SOCKET_DIR,
                ));
            let root = if in_socket_dir {
                self.project_root()
            } else {
                self.socket_dir()
            };
            if !creates_manifest && !root.is_dir() {
                return Err(not_dir(
                    "--manifest-path",
                    "SOCKET_MANIFEST_PATH",
                    &manifest,
                    &format!(
                        "is in a project directory that does not exist ({})",
                        root.display()
                    ),
                ));
            }
        }
        Ok(())
    }

    /// The crawler options this run's `--cwd` / `--global` /
    /// `--global-prefix` select.
    pub(crate) fn crawler_options(&self) -> socket_patch_core::crawlers::CrawlerOptions {
        socket_patch_core::crawlers::CrawlerOptions {
            cwd: self.cwd.clone(),
            global: self.global,
            global_prefix: self.global_prefix.clone(),
        }
    }

    /// Whether this run targets globally installed packages (`--global` or
    /// `--global-prefix`) rather than the project at `--cwd`.
    pub(crate) fn is_global(&self) -> bool {
        self.global || self.global_prefix.is_some()
    }

    /// Whether `--ecosystems` selects `eco` (every ecosystem when unset or
    /// empty). The names are validated at parse time, so this is an exact
    /// match.
    pub(crate) fn ecosystem_selected(&self, eco: Ecosystem) -> bool {
        self.ecosystems
            .as_ref()
            .is_none_or(|list| list.is_empty() || list.iter().any(|name| name == eco.cli_name()))
    }

    /// [`Self::ecosystem_selected`] for the ecosystem of `purl`; a purl of
    /// no known ecosystem is selected only when `--ecosystems` is unset.
    pub(crate) fn purl_ecosystem_selected(&self, purl: &str) -> bool {
        match Ecosystem::from_purl(purl) {
            Some(eco) => self.ecosystem_selected(eco),
            None => self.ecosystems.as_ref().is_none_or(Vec::is_empty),
        }
    }

    /// Resolve `manifest_path` against `cwd`: absolute paths are returned
    /// as-is, relative paths are joined to `cwd`.
    pub(crate) fn resolved_manifest_path(&self) -> PathBuf {
        if Path::new(&self.manifest_path).is_absolute() {
            PathBuf::from(&self.manifest_path)
        } else {
            self.cwd.join(&self.manifest_path)
        }
    }

    /// The project root whose state stores (manifest, vendor ledger,
    /// `.socket/vendor/` artifacts) belong together: `cwd` by default, the
    /// `.socket` parent's parent for a `--manifest-path` into another
    /// project's `.socket/`, and still `cwd` for a manifest file outside any
    /// `.socket/` directory. Every command derives every store from this
    /// root, so `--manifest-path` never interleaves two projects' state.
    pub(crate) fn project_root(&self) -> PathBuf {
        project_root_of(&self.resolved_manifest_path(), &self.cwd)
    }

    /// Whether the resolved manifest belongs to a project other than
    /// `--cwd`.
    pub(crate) fn manifest_project_is_foreign(&self) -> bool {
        let root = self.project_root();
        if root == self.cwd {
            return false;
        }
        match (
            std::fs::canonicalize(&root),
            std::fs::canonicalize(&self.cwd),
        ) {
            (Ok(root), Ok(cwd)) => root != cwd,
            _ => true,
        }
    }

    /// `self` with `cwd` moved to [`Self::project_root`] and the manifest
    /// path re-expressed relative to it, so a revert or repair touches the
    /// state of one project: the manifest's.
    pub(crate) fn at_project_root(&self) -> std::borrow::Cow<'_, GlobalArgs> {
        let root = self.project_root();
        if root == self.cwd {
            return std::borrow::Cow::Borrowed(self);
        }
        let manifest = self.resolved_manifest_path();
        let mut rooted = self.clone();
        rooted.manifest_path = manifest
            .strip_prefix(&root)
            .unwrap_or(&manifest)
            .to_string_lossy()
            .into_owned();
        rooted.cwd = root;
        std::borrow::Cow::Owned(rooted)
    }

    /// The directory the manifest lives in, where `apply.lock` and `blobs/`
    /// sit (`<cwd>/.socket` by default).
    pub(crate) fn socket_dir(&self) -> PathBuf {
        socket_dir_of(&self.resolved_manifest_path(), &self.cwd)
    }

    /// The API client overrides from the CLI flags. `None` defers to env,
    /// the socket-cli config file and the built-in defaults. Empty values
    /// are dropped: `build_proxy_fallback_client` would use a blank
    /// `--proxy-url` as is.
    pub fn api_client_overrides(&self) -> ApiClientEnvOverrides {
        ApiClientEnvOverrides {
            api_url: self.api_url.clone().filter(|s| !s.is_empty()),
            api_token: self.api_token.clone().filter(|s| !s.is_empty()),
            org_slug: self.org.clone().filter(|s| !s.is_empty()),
            proxy_url: self.proxy_url.clone().filter(|s| !s.is_empty()),
        }
    }

    /// Telemetry's route for a run that built no API client, resolved
    /// through the client's own credential chain (flag, the
    /// `SOCKET_NO_API_TOKEN` veto, env, `socket login` config) without a
    /// network call, so a `socket login`-only caller's events reach their
    /// org rather than the public proxy. A run that has a client uses
    /// [`TelemetryAuth::for_client`] instead.
    pub(crate) fn telemetry_auth(&self) -> TelemetryAuth {
        let (api_token, org_slug) =
            resolve_ambient_credentials(self.api_token.clone(), self.org.clone());
        TelemetryAuth::from_credentials(api_token.as_deref(), org_slug.as_deref())
    }

    /// The vendoring-service config every vendor entry point (`vendor`,
    /// `scan`/`get --mode vendored`) builds from the same flags, so they
    /// commit byte-identical artifacts for the same patch. `vendor_source`
    /// was validated by clap, so the parse cannot fail.
    pub(crate) fn vendor_service_config(
        &self,
        client: Option<ApiClient>,
        use_public_proxy: bool,
    ) -> VendorServiceConfig {
        VendorServiceConfig {
            maven_config: self.maven_config.as_deref().map(|v| v != "none"),
            source: VendorSource::parse(&self.vendor_source).unwrap_or_default(),
            client,
            use_public_proxy,
            vendor_url: self.vendor_url.clone(),
            patch_server_url: self.patch_server_url.clone(),
            offline: self.offline,
        }
    }
}

/// [`GlobalArgs::project_root`] for a caller holding a resolved manifest
/// path: the manifest's `.socket` parent's parent in the standard layout,
/// else `cwd` (a manifest file outside any `.socket/` directory relocates
/// only the manifest, not the project).
pub(crate) fn project_root_of(manifest_path: &Path, cwd: &Path) -> PathBuf {
    manifest_path
        .parent()
        .filter(|dir| {
            dir.file_name()
                == Some(std::ffi::OsStr::new(
                    socket_patch_core::constants::SOCKET_DIR,
                ))
        })
        .and_then(Path::parent)
        .map_or_else(|| cwd.to_path_buf(), Path::to_path_buf)
}

/// [`GlobalArgs::socket_dir`] for a caller holding a manifest path: its
/// parent, falling back to `cwd` (never `"."`) for a bare file name.
pub(crate) fn socket_dir_of(manifest_path: &Path, cwd: &Path) -> PathBuf {
    manifest_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| cwd.to_path_buf())
}

/// Mirror the flags that core reads from the env (`SOCKET_OFFLINE`,
/// `SOCKET_DEBUG`, `SOCKET_TELEMETRY_DISABLED`, `SOCKET_API_URL`,
/// `SOCKET_PROXY_URL`) into it. Core's own parse matches only `"1" | "true"`,
/// and the telemetry kill-switch and endpoint resolvers never see the parsed
/// flags: without the mirror `--offline` still sent telemetry, and an
/// on-prem `--api-url` run sent it, token included, to `api.socket.dev`.
/// Empty URLs mean "unset" and are not mirrored. `--api-token` / `--org` are
/// deliberately not mirrored: exporting a secret into the process env would
/// leak it to every spawned package-manager child.
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
    if let Some(url) = common.api_url.as_deref().filter(|s| !s.is_empty()) {
        std::env::set_var("SOCKET_API_URL", url);
    }
    if let Some(url) = common.proxy_url.as_deref().filter(|s| !s.is_empty()) {
        std::env::set_var("SOCKET_PROXY_URL", url);
    }
}

/// Every env var `GlobalArgs` binds (one per `env = "..."` attribute above).
/// Single source of truth for [`scrub_empty_env_vars`] and the
/// clean-environment test harnesses.
pub const GLOBAL_ARG_ENV_VARS: &[&str] = &[
    "SOCKET_CWD",
    "SOCKET_MANIFEST_PATH",
    "SOCKET_API_URL",
    "SOCKET_API_TOKEN",
    "SOCKET_ORG_SLUG",
    "SOCKET_PROXY_URL",
    "SOCKET_ECOSYSTEMS",
    "SOCKET_VENDOR_SOURCE",
    "SOCKET_VENDOR_URL",
    "SOCKET_PATCH_SERVER_URL",
    "SOCKET_OFFLINE",
    "SOCKET_STRICT",
    "SOCKET_GLOBAL",
    "SOCKET_GLOBAL_PREFIX",
    "SOCKET_JSON",
    "SOCKET_VERBOSE",
    "SOCKET_SILENT",
    "SOCKET_DRY_RUN",
    "SOCKET_YES",
    "SOCKET_LOCK_TIMEOUT",
    "SOCKET_DEBUG",
    "SOCKET_TELEMETRY_DISABLED",
    "SOCKET_NO_TRUST_LOCKFILE_CONFIG",
    "SOCKET_NO_NPM_ALLOW_REMOTE_CONFIG",
    "SOCKET_NO_VLT_INSTALL_CLEANUP",
];

/// Every env var a subcommand-local flag binds (one per `env = "..."`
/// attribute in `commands/*.rs`), for the same users as
/// [`GLOBAL_ARG_ENV_VARS`].
pub const LOCAL_ARG_ENV_VARS: &[&str] = &[
    "SOCKET_PATCH_VERSION",
    "SOCKET_SAVE_ONLY",
    "SOCKET_ALL_RELEASES",
    "SOCKET_SKIP_ROLLBACK",
    "SOCKET_PRESERVE_STATE",
    "SOCKET_DOWNLOAD_ONLY",
    "SOCKET_VENDOR_REVERT",
    "SOCKET_BATCH_SIZE",
    "SOCKET_SCAN_PACKAGES",
    "SOCKET_VEX",
    "SOCKET_VEX_OUTPUT",
    "SOCKET_VEX_PRODUCT",
    "SOCKET_VEX_NO_VERIFY",
    "SOCKET_VEX_DOC_ID",
    "SOCKET_VEX_COMPACT",
];

/// Remove exported-but-empty flag-bound env vars before clap parses, so
/// `SOCKET_CWD=` (the shell idiom for blanking a variable) means "unset"
/// instead of aborting the parse or leaking `""` past the defaults. Called
/// from `main` after peer-alias promotion. Only exactly-empty values are
/// scrubbed: whitespace is significant in paths.
pub fn scrub_empty_env_vars() {
    for &var in GLOBAL_ARG_ENV_VARS.iter().chain(LOCAL_ARG_ENV_VARS) {
        if matches!(std::env::var(var).as_deref(), Ok("")) {
            std::env::remove_var(var);
        }
    }
}

impl Default for GlobalArgs {
    /// Defaults for test struct literals; clap populates every field in
    /// production.
    fn default() -> Self {
        Self {
            cwd: PathBuf::from("."),
            manifest_path: DEFAULT_PATCH_MANIFEST_PATH.to_string(),
            api_url: None,
            api_token: None,
            org: None,
            proxy_url: None,
            ecosystems: None,
            vendor_source: "service".to_string(),
            maven_config: None,
            vendor_url: None,
            patch_server_url: None,
            offline: false,
            strict: false,
            allow_patch_conflicts: false,
            global: false,
            global_prefix: None,
            json: false,
            verbose: false,
            silent: false,
            dry_run: false,
            yes: false,
            lock_timeout: None,
            debug: false,
            no_telemetry: false,
            no_trust_lockfile_config: false,
            no_npm_allow_remote_config: false,
            no_vlt_install_cleanup: false,
        }
    }
}

/// True for a golang PURL in local mode (no `--global` / `--global-prefix`):
/// `apply` redirects it to a project-local patched copy via a `go.mod`
/// `replace`, and `rollback` drops the same redirect.
pub(crate) fn is_local_go(purl: &str, common: &GlobalArgs) -> bool {
    !common.is_global() && Ecosystem::from_purl(purl) == Some(Ecosystem::Golang)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn ecosystem_rejection_messages() {
        let supported = Ecosystem::all()
            .iter()
            .map(|e| e.cli_name())
            .collect::<Vec<_>>()
            .join(", ");
        assert!(supported.starts_with("npm, "), "{supported}");
        for bad in ["bogus", "NPM", "py-pi"] {
            assert_eq!(
                parse_supported_ecosystem(bad),
                Err(format!(
                    "unsupported ecosystem `{bad}` (supported: {supported})"
                ))
            );
        }
        for empty in ["", "  "] {
            assert_eq!(
                parse_supported_ecosystem(empty),
                Err(format!(
                    "empty ecosystem name in the list (supported: {supported})"
                ))
            );
        }
    }

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

    /// Clear every env var a flag reads — global and subcommand-local (the
    /// production lists, so the scrub and the harness can't drift), giving
    /// each clap-parse test a known-clean environment with no ambient
    /// `SOCKET_*` bleed-through.
    fn with_clean_socket_env(f: impl FnOnce()) {
        with_env_cleared(GLOBAL_ARG_ENV_VARS, || {
            with_env_cleared(LOCAL_ARG_ENV_VARS, f);
        });
    }

    /// Clear the extra env the core telemetry gate reads beyond the
    /// `SOCKET_*` set (`is_telemetry_disabled` also consults `VITEST` — the
    /// kill-switch socket-cli's vitest suite relies on), so the airgap tests
    /// below can't pass or fail vacuously. Restores afterwards.
    fn with_clean_telemetry_env(f: impl FnOnce()) {
        with_env_cleared(&["VITEST"], f);
    }

    /// `--offline` promises "never contact the network", but the telemetry
    /// kill-switch (`socket_patch_core::telemetry::is_telemetry_disabled`)
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
                    socket_patch_core::telemetry::is_telemetry_disabled(),
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
                    socket_patch_core::telemetry::is_telemetry_disabled(),
                    "SOCKET_OFFLINE=yes must disable telemetry like SOCKET_OFFLINE=1",
                );
            });
        });
    }

    /// `--api-url` / `--proxy-url` must reach the telemetry sender, which
    /// resolves its endpoint from the env only
    /// (`socket_cli_config::resolve_api_base_url` reads `SOCKET_API_URL`,
    /// `env_compat::proxy_url_from_env` reads `SOCKET_PROXY_URL`) and never
    /// sees the parsed flags. Without the mirror,
    /// `socket-patch scan --api-url https://socket.internal --api-token <tok>
    /// --org acme` POSTs the event — `Authorization: Bearer <tok>` header
    /// included — to the default `https://api.socket.dev`, egressing an
    /// on-prem token to the very host the operator redirected away from.
    #[test]
    #[serial_test::serial]
    fn apply_env_toggles_mirrors_api_and_proxy_urls_for_telemetry() {
        with_clean_socket_env(|| {
            // Guard against a vacuous pass: the resolver must start at the
            // built-in default (the cargo `[env]` `SOCKET_NO_CONFIG=1` keeps
            // a developer's real socket-cli config out of the chain).
            assert_eq!(
                socket_patch_core::utils::socket_cli_config::resolve_api_base_url(),
                socket_patch_core::constants::DEFAULT_SOCKET_API_URL,
            );

            let args = GlobalArgs {
                api_url: Some("https://socket.internal.example".to_string()),
                proxy_url: Some("https://proxy.internal.example".to_string()),
                ..GlobalArgs::default()
            };
            apply_env_toggles(&args);
            assert_eq!(
                socket_patch_core::utils::socket_cli_config::resolve_api_base_url(),
                "https://socket.internal.example",
                "--api-url must reach the telemetry endpoint resolver",
            );
            assert_eq!(
                std::env::var("SOCKET_PROXY_URL").as_deref(),
                Ok("https://proxy.internal.example"),
                "--proxy-url must reach the tokenless telemetry endpoint resolver",
            );
        });
    }

    /// The URL mirror must not invent an override: `None` (no flag, no env
    /// var) has to stay unset so `get_api_client_with_overrides` /
    /// `resolve_api_base_url` still fall through env → socket-cli config →
    /// default, and `--api-url ""` keeps meaning "unset" exactly as
    /// [`GlobalArgs::api_client_overrides`] already treats it.
    #[test]
    #[serial_test::serial]
    fn apply_env_toggles_url_mirror_skips_unset_and_empty() {
        with_clean_socket_env(|| {
            apply_env_toggles(&GlobalArgs::default());
            assert!(std::env::var("SOCKET_API_URL").is_err());
            assert!(std::env::var("SOCKET_PROXY_URL").is_err());

            let blank = GlobalArgs {
                api_url: Some(String::new()),
                proxy_url: Some(String::new()),
                ..GlobalArgs::default()
            };
            apply_env_toggles(&blank);
            assert!(
                std::env::var("SOCKET_API_URL").is_err(),
                "an empty --api-url must not be mirrored as a blank override",
            );
            assert!(std::env::var("SOCKET_PROXY_URL").is_err());
        });
    }

    /// `scrub_empty_env_vars` removes exactly-empty `SOCKET_*` flag vars
    /// (the `VAR=` blank-without-unsetting idiom) — global and local — and
    /// nothing else: set, non-empty values — even whitespace-only ones,
    /// which are significant in paths — survive, and the parse then sees
    /// plain defaults.
    #[test]
    #[serial_test::serial]
    fn scrub_empty_env_vars_unsets_only_empties() {
        with_clean_socket_env(|| {
            std::env::set_var("SOCKET_CWD", "");
            std::env::set_var("SOCKET_LOCK_TIMEOUT", "");
            std::env::set_var("SOCKET_GLOBAL_PREFIX", "");
            std::env::set_var("SOCKET_ECOSYSTEMS", "");
            std::env::set_var("SOCKET_VENDOR_SOURCE", "");
            std::env::set_var("SOCKET_BATCH_SIZE", "");
            std::env::set_var("SOCKET_VEX_OUTPUT", "");
            std::env::set_var("SOCKET_MANIFEST_PATH", "keep.json");
            std::env::set_var("SOCKET_ORG_SLUG", " ");

            scrub_empty_env_vars();

            assert!(
                std::env::var("SOCKET_CWD").is_err(),
                "empty var is scrubbed"
            );
            assert!(std::env::var("SOCKET_LOCK_TIMEOUT").is_err());
            assert!(
                std::env::var("SOCKET_BATCH_SIZE").is_err(),
                "empty subcommand-local vars are scrubbed too"
            );
            assert!(std::env::var("SOCKET_VEX_OUTPUT").is_err());
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
            assert_eq!(
                cli.common.vendor_source, "service",
                "empty SOCKET_VENDOR_SOURCE must fall back to the default"
            );
            assert_eq!(cli.common.manifest_path, "keep.json");
        });
    }

    /// `--vendor-source` normalizes case and the `auto` alias to `service`;
    /// the removed `build` source (flag or env) and unknown tokens abort the
    /// parse.
    #[test]
    #[serial_test::serial]
    fn vendor_source_flag_normalizes_and_rejects_removed_sources() {
        with_clean_socket_env(|| {
            for token in ["SERVICE", "auto"] {
                let cli =
                    TestCli::try_parse_from(["socket-patch", "--vendor-source", token]).unwrap();
                assert_eq!(cli.common.vendor_source, "service");
            }

            std::env::set_var("SOCKET_VENDOR_SOURCE", "build");
            assert!(TestCli::try_parse_from(["socket-patch"]).is_err());
            std::env::remove_var("SOCKET_VENDOR_SOURCE");

            assert!(
                TestCli::try_parse_from(["socket-patch", "--vendor-source", "download"]).is_err(),
                "an unknown vendor source must fail the parse",
            );
        });
    }

    /// The service overrides (`--vendor-url` / `--patch-server-url` /
    /// `--offline`) thread through unchanged, so every entry point targets
    /// the same hosts.
    #[test]
    fn vendor_service_config_threads_overrides_through() {
        let common = GlobalArgs {
            vendor_source: "service".to_string(),
            vendor_url: Some("https://vendor.example".to_string()),
            patch_server_url: Some("https://patch.example".to_string()),
            offline: true,
            ..Default::default()
        };
        let cfg = common.vendor_service_config(None, false);
        assert_eq!(cfg.vendor_url.as_deref(), Some("https://vendor.example"));
        assert_eq!(
            cfg.patch_server_url.as_deref(),
            Some("https://patch.example")
        );
        assert!(cfg.offline);
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

    /// An empty (or whitespace-only) string is `false`, not an
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

    /// `api_client_overrides` must forward every populated value verbatim.
    #[test]
    fn api_client_overrides_forwards_set_values() {
        let args = GlobalArgs {
            api_url: Some("https://api.example.com".to_string()),
            api_token: Some("tok123".to_string()),
            org: Some("acme".to_string()),
            proxy_url: Some("https://proxy.example.com".to_string()),
            ..GlobalArgs::default()
        };
        let o = args.api_client_overrides();
        assert_eq!(o.api_url.as_deref(), Some("https://api.example.com"));
        assert_eq!(o.api_token.as_deref(), Some("tok123"));
        assert_eq!(o.org_slug.as_deref(), Some("acme"));
        assert_eq!(o.proxy_url.as_deref(), Some("https://proxy.example.com"));
    }

    /// Telemetry without a client uses explicit flag values verbatim (the
    /// org endpoint with a bearer), and empty values mean "unset" (the
    /// proxy, with no bearer) rather than a `/v0/orgs//telemetry` URL.
    #[test]
    #[serial_test::serial]
    fn telemetry_auth_prefers_explicit_values_and_treats_empty_as_unset() {
        with_clean_socket_env(|| {
            let explicit = GlobalArgs {
                api_token: Some("sktsec_flag_api".to_string()),
                org: Some("flag-org".to_string()),
                ..GlobalArgs::default()
            };
            let auth = explicit.telemetry_auth();
            assert_eq!(
                auth.url(),
                format!(
                    "{}/v0/orgs/flag-org/telemetry",
                    socket_patch_core::constants::DEFAULT_SOCKET_API_URL
                )
            );
            assert!(auth.is_authenticated());

            let empty = GlobalArgs {
                api_token: Some(String::new()),
                org: Some(String::new()),
                ..GlobalArgs::default()
            };
            let auth = empty.telemetry_auth();
            assert!(!auth.is_authenticated());
            assert!(auth.url().ends_with("/patch/telemetry"), "{}", auth.url());
        });
    }

    /// Empty strings for url/token/org are dropped, not forwarded as
    /// `Some("")`: an empty value would mask the env-var fallback.
    #[test]
    fn api_client_overrides_filters_empty_strings() {
        let args = GlobalArgs {
            api_url: Some(String::new()),
            api_token: Some(String::new()),
            org: Some(String::new()),
            proxy_url: Some(String::new()),
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
        let absolute = if cfg!(windows) {
            r"C:\etc\socket\manifest.json"
        } else {
            "/etc/socket/manifest.json"
        };
        let args = GlobalArgs {
            cwd: PathBuf::from("/work/project"),
            manifest_path: absolute.to_string(),
            ..GlobalArgs::default()
        };
        assert_eq!(args.resolved_manifest_path(), PathBuf::from(absolute));
    }

    /// A dotted relative `manifest_path` is joined verbatim, not normalized.
    #[test]
    fn resolved_manifest_path_joins_dotted_relative_verbatim() {
        let args = GlobalArgs {
            cwd: PathBuf::from("/work/project"),
            manifest_path: "../manifest.json".to_string(),
            ..GlobalArgs::default()
        };
        assert_eq!(
            args.resolved_manifest_path(),
            PathBuf::from("/work/project/../manifest.json"),
        );
    }

    /// The default layout: `<cwd>/.socket/manifest.json` → the project
    /// root is `cwd` and the socket dir is `<cwd>/.socket`.
    #[test]
    fn project_root_and_socket_dir_for_default_layout() {
        let args = GlobalArgs {
            cwd: PathBuf::from("/work/project"),
            ..GlobalArgs::default()
        };
        assert_eq!(args.project_root(), PathBuf::from("/work/project"));
        assert_eq!(
            args.socket_dir(),
            PathBuf::from("/work/project").join(".socket")
        );
    }

    /// `--manifest-path` into ANOTHER project's `.socket/`: every store
    /// (manifest, vendor ledger, redirect ledger, lock) resolves against
    /// that project — its `.socket` parent's parent — never the cwd.
    #[test]
    fn project_root_steps_out_of_a_foreign_socket_dir() {
        let args = GlobalArgs {
            cwd: PathBuf::from("/work/project"),
            manifest_path: "../other/.socket/manifest.json".to_string(),
            ..GlobalArgs::default()
        };
        let other = PathBuf::from("/work/project").join("../other");
        assert_eq!(args.project_root(), other);
        assert_eq!(args.socket_dir(), other.join(".socket"));
    }

    /// A bare manifest file outside any `.socket/` layout relocates only
    /// the manifest: its directory holds the lock and artifacts, while the
    /// project (vendor ledger, lockfiles) stays `cwd` (#745).
    #[test]
    fn project_root_of_a_bare_manifest_file_is_cwd() {
        let args = GlobalArgs {
            cwd: PathBuf::from("/work/project"),
            manifest_path: "custom/mp.json".to_string(),
            ..GlobalArgs::default()
        };
        let custom = PathBuf::from("/work/project").join("custom");
        assert_eq!(args.project_root(), PathBuf::from("/work/project"));
        assert_eq!(args.socket_dir(), custom);
        assert!(!args.manifest_project_is_foreign());
    }

    /// `socket_dir_of` on a raw relative file name falls back to `cwd`,
    /// never to `"."` (wrong under a non-default `--cwd`); a resolved path
    /// yields its parent.
    #[test]
    fn socket_dir_of_bare_relative_name_falls_back_to_cwd() {
        assert_eq!(
            socket_dir_of(Path::new("manifest.json"), Path::new("/work/project")),
            PathBuf::from("/work/project"),
        );
        let resolved = PathBuf::from("/work/project")
            .join(".socket")
            .join("manifest.json");
        assert_eq!(
            socket_dir_of(&resolved, Path::new("/elsewhere")),
            PathBuf::from("/work/project").join(".socket"),
        );
    }

    /// `parse_supported_ecosystem` accepts every supported ecosystem name
    /// and returns it verbatim.
    #[test]
    fn parse_supported_ecosystem_accepts_supported_names() {
        for e in Ecosystem::all() {
            let name = e.cli_name();
            assert_eq!(
                parse_supported_ecosystem(name),
                Ok(name.to_string()),
                "{name:?} is a supported ecosystem and must be accepted",
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

    /// The mirror only works if every subcommand's `run` actually calls
    /// `apply_env_toggles`. `list` fires telemetry
    /// (`track_patch_listed`) whose kill-switch reads
    /// `SOCKET_TELEMETRY_DISABLED` / `SOCKET_OFFLINE` from the env only — a
    /// run entry point that skips the mirror silently ignores
    /// `--no-telemetry` and lets `--offline` (strict airgap: never contact
    /// the network) still fire the telemetry HTTP request.
    #[test]
    #[serial_test::serial]
    fn list_run_mirrors_global_toggles_for_airgap() {
        with_clean_socket_env(|| {
            with_clean_telemetry_env(|| {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                let toggles_on = |cwd: &Path| GlobalArgs {
                    cwd: cwd.to_path_buf(),
                    offline: true,
                    no_telemetry: true,
                    silent: true,
                    ..GlobalArgs::default()
                };

                // Guard against a vacuous pass: the gate must start open.
                assert!(!socket_patch_core::telemetry::is_telemetry_disabled());

                let tmp = tempfile::tempdir().unwrap();
                rt.block_on(crate::commands::list::run(
                    crate::commands::list::ListArgs {
                        common: toggles_on(tmp.path()),
                    },
                ));
                assert!(
                    socket_patch_core::telemetry::is_telemetry_disabled(),
                    "`list --offline --no-telemetry` must mirror the toggles into the \
                     env — its telemetry kill-switch reads only SOCKET_OFFLINE / \
                     SOCKET_TELEMETRY_DISABLED",
                );
            });
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

    /// Policy invariant: EVERY env-bound boolean flag on every subcommand
    /// parses with [`parse_bool_flag`] semantics — the boolish vocabulary is
    /// accepted, exported-but-empty means false, garbage is a parse error.
    /// Table-driven against the real `Cli` so a new flag added with clap's
    /// default bool-from-env parser (accepts only `true`/`false` — the
    /// recurring "`SOCKET_X=1` aborts the parse" bug class) or with
    /// `BoolishValueParser` (rejects `VAR=`) fails here, not in the field.
    #[test]
    #[serial_test::serial]
    fn every_env_bound_bool_flag_parses_boolishly_and_tolerates_empty() {
        use clap::Parser as _;

        // (env var, argv of a subcommand that binds it) — every bool entry
        // of `LOCAL_ARG_ENV_VARS`, on each subcommand that binds it.
        const BOOL_BINDINGS: &[(&str, &[&str])] = &[
            ("SOCKET_SAVE_ONLY", &["socket-patch", "get", "x"]),
            ("SOCKET_ALL_RELEASES", &["socket-patch", "get", "x"]),
            ("SOCKET_ALL_RELEASES", &["socket-patch", "scan"]),
            ("SOCKET_SKIP_ROLLBACK", &["socket-patch", "remove", "x"]),
            // Shared by rollback and remove.
            ("SOCKET_PRESERVE_STATE", &["socket-patch", "rollback"]),
            ("SOCKET_PRESERVE_STATE", &["socket-patch", "remove", "x"]),
            ("SOCKET_DOWNLOAD_ONLY", &["socket-patch", "repair"]),
            ("SOCKET_VENDOR_REVERT", &["socket-patch", "vendor"]),
            ("SOCKET_VEX_NO_VERIFY", &["socket-patch", "vex"]),
            ("SOCKET_VEX_COMPACT", &["socket-patch", "vex"]),
            // The embedded `--vex-*` twins share the same env vars and must
            // not abort host commands (e.g. apply from a CI step).
            ("SOCKET_VEX_NO_VERIFY", &["socket-patch", "apply"]),
            ("SOCKET_VEX_COMPACT", &["socket-patch", "scan"]),
        ];

        with_clean_socket_env(|| {
            for &(var, argv) in BOOL_BINDINGS {
                for (val, should_parse) in
                    [("", true), ("1", true), ("yes", true), ("garbage", false)]
                {
                    std::env::set_var(var, val);
                    let result = crate::Cli::try_parse_from(argv.iter().copied());
                    assert_eq!(
                        result.is_ok(),
                        should_parse,
                        "{var}={val:?} on {argv:?} — expected parse {}: {:?}",
                        if should_parse { "success" } else { "failure" },
                        result.err().map(|e| e.to_string()),
                    );
                    std::env::remove_var(var);
                }
            }
        });
    }

    /// v5 retired `SOCKET_FORCE` (#615): `--force` is flag-only on `apply`,
    /// `vendor` and `--update`. A stale export must be ignored, so it can
    /// never quietly skip the beforeHash check or the managed-install
    /// refusal; the flag itself still works.
    #[test]
    #[serial_test::serial]
    fn socket_force_env_is_ignored_and_force_flag_still_works() {
        fn force_of(argv: &[&str]) -> bool {
            let argv = argv.iter().map(|s| s.to_string()).collect();
            match crate::parse_argv_with_shortcuts(argv)
                .unwrap_or_else(|e| panic!("parse failed: {e}"))
                .command
            {
                crate::Commands::Apply(a) => a.force,
                crate::Commands::Vendor(a) => a.force,
                crate::Commands::SelfUpdate(a) => a.force,
                _ => panic!("unexpected subcommand"),
            }
        }

        const ARGVS: &[&[&str]] = &[
            &["socket-patch", "apply"],
            &["socket-patch", "vendor"],
            &["socket-patch", "self-update"],
            &["socket-patch", "--update"],
        ];

        with_clean_socket_env(|| {
            with_env_cleared(&["SOCKET_FORCE"], || {
                for val in ["1", "true", "yes"] {
                    std::env::set_var("SOCKET_FORCE", val);
                    for &argv in ARGVS {
                        assert!(!force_of(argv), "SOCKET_FORCE={val} set force on {argv:?}");
                        let mut with_flag = argv.to_vec();
                        with_flag.push("--force");
                        assert!(force_of(&with_flag), "--force ignored on {argv:?}");
                    }
                }
            });
        });
    }

    /// Companion invariant for the **value-typed** local env vars: an
    /// exported-but-empty value (`VAR=`) must not crash its subcommand —
    /// [`scrub_empty_env_vars`] (run by `main` before clap) removes it, and
    /// the parse then sees plain defaults.
    #[test]
    #[serial_test::serial]
    fn empty_value_typed_local_env_vars_are_rescued_by_the_scrub() {
        use clap::Parser as _;

        const VALUE_BINDINGS: &[(&str, &[&str])] = &[
            ("SOCKET_BATCH_SIZE", &["socket-patch", "scan"]),
            ("SOCKET_SCAN_PACKAGES", &["socket-patch", "scan"]),
            ("SOCKET_PATCH_VERSION", &["socket-patch", "self-update"]),
            ("SOCKET_VEX", &["socket-patch", "apply"]),
            ("SOCKET_VEX_OUTPUT", &["socket-patch", "vex"]),
            ("SOCKET_VEX_PRODUCT", &["socket-patch", "vex"]),
            ("SOCKET_VEX_DOC_ID", &["socket-patch", "vex"]),
        ];

        with_clean_socket_env(|| {
            for &(var, argv) in VALUE_BINDINGS {
                std::env::set_var(var, "");
                scrub_empty_env_vars();
                let result = crate::Cli::try_parse_from(argv.iter().copied());
                assert!(
                    result.is_ok(),
                    "{var}= (exported empty) on {argv:?} must be scrubbed, not abort: {:?}",
                    result.err().map(|e| e.to_string()),
                );
                std::env::remove_var(var);
            }
        });
    }
}
