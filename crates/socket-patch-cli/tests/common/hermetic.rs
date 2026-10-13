//! The one hermetic environment for every child process the CLI tests spawn.
//!
//! The binary binds a wide `SOCKET_*` env surface (SOCKET_CWD,
//! SOCKET_DRY_RUN, SOCKET_STRICT, SOCKET_GLOBAL, SOCKET_MANIFEST_PATH, ...).
//! An ambient value silently changes what a test exercises:
//! `SOCKET_DRY_RUN=true` turns every real apply into a no-op,
//! `SOCKET_GLOBAL_PREFIX` flips commands into global mode (aiming mutations
//! at the host's *real* global caches), and the output-mode trio
//! (`SOCKET_JSON` / `SOCKET_SILENT` / `SOCKET_VERBOSE`) flips which printer a
//! test's assertions run against.
//!
//! [`command`] (and [`binary_command`] for the built binary) is the only way
//! a test spawns `socket-patch`; `common::run_bin_with_env` is built on it.
//! Package-manager children the same tests spawn get [`scrub_socket_vars`]
//! plus whichever [`Extra`] scrubs their tool needs.
//!
//! Files that don't need the rest of `common` pull this in on its own with
//! `#[path = "common/hermetic.rs"] mod hermetic;`.
//!
//! ## Ordering
//!
//! `Command`'s env operations are keyed by variable name and the last call
//! for a given name wins. So scrub first (the sweeps iterate the *parent*
//! environment and would otherwise remove values set earlier), then
//! `cache_env::isolate`, then any env the individual test needs.

#![allow(dead_code)]

use std::path::Path;
use std::process::Command;

/// The highest-risk `SOCKET_*` vars. [`command`] seeds each with a hostile
/// value and then removes it: `env_remove` clears the seed too, so the child
/// never sees it, but if a scrub line is ever dropped the seed (rather than a
/// developer's ambient shell, which the suites can't rely on) turns the tests
/// red immediately.
pub const HOSTILE_SEEDS: &[(&str, &str)] = &[
    ("SOCKET_CWD", "/nonexistent"),
    ("SOCKET_GLOBAL", "true"),
    ("SOCKET_GLOBAL_PREFIX", "/nonexistent"),
    ("SOCKET_DRY_RUN", "true"),
    ("SOCKET_SAVE_ONLY", "true"),
    ("SOCKET_ECOSYSTEMS", "cargo"),
    ("SOCKET_MANIFEST_PATH", "/nonexistent/manifest.json"),
    ("SOCKET_JSON", "true"),
    ("SOCKET_SILENT", "true"),
    ("SOCKET_VERBOSE", "true"),
    ("SOCKET_UPDATE_BASE_URL", "http://127.0.0.1:1"),
    ("SOCKET_UPDATE_STATE_DIR", "/nonexistent"),
];

/// The opt-outs [`command`] forces on in every child: the config layer
/// (a developer's real `socket login` must never authenticate a test
/// child), the passive update notifier (no child may fetch release metadata
/// from real GitHub; the PTY suites hand the binary a real terminal, so the
/// stderr-TTY guard doesn't hold there) and telemetry (an unauthenticated
/// child would POST to the real public proxy; the workspace `[env]` default
/// can be overridden by the developer's shell). Suites that clear the
/// environment re-apply these after the clear. Notifier and telemetry
/// suites opt back in via caller env, which lands last.
pub const FORCED_OPT_OUTS: &[(&str, &str)] = &[
    ("SOCKET_NO_CONFIG", "1"),
    ("SOCKET_NO_UPDATE_CHECK", "1"),
    ("SOCKET_TELEMETRY_DISABLED", "1"),
];

/// A `Command` for `bin` with the hermetic `SOCKET_*` environment: the
/// hostile seeds scrubbed, every flag-bound `SOCKET_*` and every other
/// ambient `SOCKET_*` removed (removing `SOCKET_API_TOKEN` also forces the
/// public proxy), and the three opt-outs (config layer, update notifier,
/// telemetry) forced on. Callers add args, cwd and their own env
/// afterwards; caller env lands last, so explicit injections survive the
/// scrub.
pub fn command(bin: &Path) -> Command {
    let mut cmd = Command::new(bin);
    for (k, v) in HOSTILE_SEEDS {
        cmd.env(k, v);
    }
    for (k, _) in HOSTILE_SEEDS {
        cmd.env_remove(k);
    }
    // The flag-bound vars are removed by name, not only when the sweep below
    // finds them: in-process tests in the same binary set some of them
    // (`apply_env_toggles`, env save/restore helpers), and one set between
    // this sweep and the spawn would otherwise reach the child.
    for k in socket_patch_cli::args::GLOBAL_ARG_ENV_VARS
        .iter()
        .chain(socket_patch_cli::args::LOCAL_ARG_ENV_VARS)
    {
        cmd.env_remove(k);
    }
    cmd.env_remove("SOCKET_API_TOKEN");
    // The `SOCKET_CLI_*` peer names too: the binary promotes each onto its
    // canonical `SOCKET_*` name, so a peer token set mid-run would put the
    // child on the authenticated path.
    for (_, peer) in socket_patch_core::utils::env_compat::PEER_ENV_ALIASES {
        cmd.env_remove(peer);
    }
    scrub_socket_vars(&mut cmd);
    // Belt-and-braces on top of the `.cargo/config.toml` `[env]` defaults
    // (see `FORCED_OPT_OUTS`): a developer's real `socket login` would flip
    // every "no token → public proxy" assertion onto the authed path.
    // Telemetry suites opt back in with `SOCKET_TELEMETRY_DISABLED=0` and a
    // wiremock endpoint.
    cmd.envs(FORCED_OPT_OUTS.iter().copied());
    cmd
}

/// [`command`] for the `socket-patch` binary cargo built for this test run.
pub fn binary_command() -> Command {
    command(Path::new(env!("CARGO_BIN_EXE_socket-patch")))
}

/// A `Command` for the package-manager tool `name` on `PATH`, resolved with
/// the CLI's `resolve_tool` (every `PATHEXT` extension on Windows). npm and Node install `pnpm`, `corepack` and `npm` as `.cmd`
/// shims there, and a bare `Command::new("corepack")` only finds
/// `corepack.exe`, so the pnpm suites' probes reported the tool missing and
/// every Windows test skipped. A tool that isn't on `PATH` keeps the bare
/// name, so spawning it still fails the way the probes expect.
pub fn tool_command(name: &str) -> Command {
    Command::new(
        socket_patch_core::utils::process::resolve_tool(name)
            .map_or_else(|| name.into(), std::path::PathBuf::into_os_string),
    )
}

/// Remove every ambient `SOCKET_*` var from `cmd`, except the telemetry
/// opt-outs (an opted-out developer stays opted out), `SOCKET_NO_CONFIG`
/// and `SOCKET_NO_UPDATE_CHECK`. [`command`] runs this; package-manager
/// children call it directly.
pub fn scrub_socket_vars(cmd: &mut Command) {
    for (key, _) in std::env::vars_os() {
        let name = key.to_string_lossy();
        if name.starts_with("SOCKET_")
            && !name.contains("TELEMETRY")
            && name != "SOCKET_NO_CONFIG"
            && name != "SOCKET_NO_UPDATE_CHECK"
        {
            cmd.env_remove(&key);
        }
    }
}

/// The in-process half, for test binaries that only parse argv with clap:
/// clap reads every env-bound `SOCKET_*` flag at parse time, so an ambient
/// value (or a `.cargo/config.toml` `[env]` default such as
/// `SOCKET_TELEMETRY_DISABLED=1`) changes what a parse yields. Removes every
/// `SOCKET_*` var from this process, once; later calls wait for the first.
/// Nothing is restored, so call it only from binaries where no test needs a
/// `SOCKET_*` var, and call it before every parse so no parse reads the
/// environment while it is being changed.
pub fn scrub_process_socket_env() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("SOCKET_") {
                std::env::remove_var(&key);
            }
        }
    });
}

/// `Cli::try_parse_from` with the ambient `SOCKET_*` environment removed
/// first (see [`scrub_process_socket_env`]): clap reads the env-bound flags
/// at parse time, so without it the workspace `SOCKET_TELEMETRY_DISABLED=1`
/// default (or a developer's shell) would set `--no-telemetry` and friends
/// in every parse.
pub fn try_parse(argv: &[&str]) -> Result<socket_patch_cli::Cli, clap::Error> {
    scrub_process_socket_env();
    <socket_patch_cli::Cli as clap::Parser>::try_parse_from(argv)
}

/// Opt-in scrubs for the ambient config of the tools a suite drives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Extra {
    /// `VIRTUAL_ENV`: an activated venv redirects Python discovery.
    Venv,
    /// Every `YARN_*` var. Yarn berry lets any `.yarnrc.yml` setting be
    /// overridden by env, so an ambient `YARN_NODE_LINKER=pnp` would build a
    /// PnP tree and void the node_modules probes. Seeded with that value and
    /// then scrubbed.
    Yarn,
    /// Every `PNPM_*` and `npm_config_*` var (any case). pnpm lets any
    /// `.npmrc` setting be overridden by an `npm_config_*` env var (env
    /// outranks the project npmrc), so an ambient
    /// `npm_config_node_linker=pnp` makes pnpm emit a `.pnp.cjs` that
    /// `vendor` refuses. Seeded with that value and then scrubbed.
    Pnpm,
    /// Yarn 1's ambient config: the cache folder in any spelling
    /// (`YARN_CACHE_FOLDER`, `yarn_cache_folder`, `npm_config_cache_folder`;
    /// the harness pins its own through `cache_env::isolate`, so run this
    /// first), any `yarn_*` / `npm_config_*` (any case) offline-mirror or
    /// `userconfig` override, and `PREFIX`. An ambient mirror setting or a
    /// redirected rc file would make both yarn and the hosted scan see a
    /// mirror the leg did not set up. This is the redirect-classic suite's
    /// old private scrub plus the cache-folder spellings; [`Extra::Yarn`] is
    /// the full `YARN_*` sweep.
    YarnClassic,
    /// Every `BUNDLE_*` var. Bundler lets any `.bundle/config` setting be
    /// overridden by env, and the gem crawler reads `BUNDLE_PATH`,
    /// `BUNDLE_APP_CONFIG` and friends, so an ambient value moves the gem
    /// store the suite points it at. Seeded with a bogus
    /// `BUNDLE_APP_CONFIG` and then scrubbed; run it before the suite sets
    /// its own `BUNDLE_*` values.
    Bundle,
    /// Every `PDM_*` var plus `UV_PROJECT_ENVIRONMENT`: PDM reads any
    /// setting from `PDM_<NAME>`, and its uv backend follows
    /// `UV_PROJECT_ENVIRONMENT` to a different venv.
    Pdm,
    /// Every `POETRY_*` var: Poetry reads any config key from
    /// `POETRY_<KEY>` (`POETRY_VIRTUALENVS_PATH`, repository URLs, ...).
    Poetry,
    /// Every `COMPOSER_*` var, then `COMPOSER_HOME` pinned to a missing
    /// directory. The crawler resolves a project's vendor directory from
    /// `COMPOSER_VENDOR_DIR`, else the user-level `config.json` in the
    /// Composer home, which it finds through `COMPOSER_HOME` or an
    /// absolute `XDG_CONFIG_HOME`; any of them moves the crawl off the
    /// fixture's `vendor/`. The pin outranks `XDG_CONFIG_HOME` and holds
    /// no config. Run it before the suite sets its own `COMPOSER_*` values.
    Composer,
}

/// Apply each of `extras` to `cmd` (see [`Extra`]). Run it before
/// `cache_env::isolate`, which sets some of the same names.
pub fn scrub_extra(cmd: &mut Command, extras: &[Extra]) {
    for extra in extras {
        match extra {
            Extra::Venv => {
                cmd.env_remove("VIRTUAL_ENV");
            }
            Extra::Yarn => {
                cmd.env("YARN_NODE_LINKER", "pnp");
                for (key, _) in std::env::vars_os() {
                    if key.to_string_lossy().starts_with("YARN_") {
                        cmd.env_remove(&key);
                    }
                }
                cmd.env_remove("YARN_NODE_LINKER");
            }
            Extra::Pnpm => {
                cmd.env("npm_config_node_linker", "pnp");
                for (key, _) in std::env::vars_os() {
                    let name = key.to_string_lossy();
                    if name.starts_with("PNPM_")
                        || name.to_ascii_lowercase().starts_with("npm_config_")
                    {
                        cmd.env_remove(&key);
                    }
                }
                cmd.env_remove("npm_config_node_linker");
            }
            Extra::YarnClassic => {
                cmd.env_remove("YARN_CACHE_FOLDER");
                for (key, _) in std::env::vars_os() {
                    let lower = key.to_string_lossy().to_ascii_lowercase();
                    let config = lower.starts_with("yarn_") || lower.starts_with("npm_config_");
                    if config
                        && (lower.contains("offline_mirror")
                            || lower.ends_with("userconfig")
                            || lower.ends_with("cache_folder"))
                    {
                        cmd.env_remove(&key);
                    }
                }
                cmd.env_remove("PREFIX");
            }
            Extra::Bundle => {
                cmd.env("BUNDLE_APP_CONFIG", "/nonexistent/.bundle");
                for (key, _) in std::env::vars_os() {
                    if key.to_string_lossy().starts_with("BUNDLE_") {
                        cmd.env_remove(&key);
                    }
                }
                cmd.env_remove("BUNDLE_APP_CONFIG");
            }
            Extra::Pdm => {
                for (key, _) in std::env::vars_os() {
                    if key.to_string_lossy().starts_with("PDM_") {
                        cmd.env_remove(&key);
                    }
                }
                cmd.env_remove("UV_PROJECT_ENVIRONMENT");
            }
            Extra::Poetry => {
                for (key, _) in std::env::vars_os() {
                    if key.to_string_lossy().starts_with("POETRY_") {
                        cmd.env_remove(&key);
                    }
                }
            }
            Extra::Composer => {
                for (key, _) in std::env::vars_os() {
                    if key.to_string_lossy().starts_with("COMPOSER_") {
                        cmd.env_remove(&key);
                    }
                }
                cmd.env("COMPOSER_HOME", "/nonexistent/composer-home");
            }
        }
    }
}
