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
const HOSTILE_SEEDS: &[(&str, &str)] = &[
    ("SOCKET_GLOBAL", "true"),
    ("SOCKET_GLOBAL_PREFIX", "/nonexistent"),
    ("SOCKET_DRY_RUN", "true"),
    ("SOCKET_MANIFEST_PATH", "/nonexistent/manifest.json"),
    ("SOCKET_JSON", "true"),
    ("SOCKET_SILENT", "true"),
    ("SOCKET_VERBOSE", "true"),
    ("SOCKET_UPDATE_BASE_URL", "http://127.0.0.1:1"),
    ("SOCKET_UPDATE_STATE_DIR", "/nonexistent"),
];

/// A `Command` for `bin` with the hermetic `SOCKET_*` environment: the
/// hostile seeds scrubbed, every other ambient `SOCKET_*` removed (removing
/// `SOCKET_API_TOKEN` also forces the public proxy), and the two opt-outs
/// forced on. Callers add args, cwd and their own env afterwards; caller env
/// lands last, so explicit injections survive the scrub.
pub fn command(bin: &Path) -> Command {
    let mut cmd = Command::new(bin);
    for (k, v) in HOSTILE_SEEDS {
        cmd.env(k, v);
    }
    for (k, _) in HOSTILE_SEEDS {
        cmd.env_remove(k);
    }
    cmd.env_remove("SOCKET_API_TOKEN");
    scrub_socket_vars(&mut cmd);
    // Belt-and-braces on top of the `.cargo/config.toml` `[env]` default:
    // a developer's real `socket login` (the socket-cli config.json token
    // fallback) must never authenticate a test child — it would flip every
    // "no token → public proxy" assertion onto the authed path.
    cmd.env("SOCKET_NO_CONFIG", "1");
    // Same posture for the passive update notifier: no test child may ever
    // fetch release metadata from real GitHub. The stderr-TTY guard covers
    // piped children, but the PTY suites hand the binary a real terminal —
    // this force-set is the layer that holds there. Notifier tests opt back
    // in via caller env (which lands last).
    cmd.env("SOCKET_NO_UPDATE_CHECK", "1");
    cmd
}

/// [`command`] for the `socket-patch` binary cargo built for this test run.
pub fn binary_command() -> Command {
    command(Path::new(env!("CARGO_BIN_EXE_socket-patch")))
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
        }
    }
}
