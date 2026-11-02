//! Shared pieces of the `cli_parse_*` suites. Includers also declare
//! `mod hermetic` (`common/hermetic.rs`) at their root.

#![allow(dead_code)]

use socket_patch_cli::args::GlobalArgs;
use socket_patch_cli::Cli;

/// [`crate::hermetic::try_parse`] with `env` set for this one parse and
/// removed after it. Every test in a binary that calls this must be
/// `#[serial]`: a concurrent parse would read the vars.
pub fn try_parse_with_env(env: &[(&str, &str)], argv: &[&str]) -> Result<Cli, clap::Error> {
    crate::hermetic::scrub_process_socket_env();
    for (k, v) in env {
        std::env::set_var(k, v);
    }
    let parsed = crate::hermetic::try_parse(argv);
    for (k, _) in env {
        std::env::remove_var(k);
    }
    parsed
}

/// `Cli::try_parse_from` for binaries that also call a command's `run()`
/// in-process, which reads the process env. Once per process, removes every
/// `SOCKET_*` var except the `hermetic::FORCED_OPT_OUTS`, and forces those
/// on, so `run()` reads no developer config and sends no telemetry. An
/// opt-out is never removed, so a concurrent `run()` can't see it missing.
/// `SOCKET_TELEMETRY_DISABLED` binds `--no-telemetry`, so every parse here
/// yields `no_telemetry: true`.
pub fn try_parse_keeping_opt_outs(argv: &[&str]) -> Result<Cli, clap::Error> {
    use crate::hermetic::FORCED_OPT_OUTS;
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        for (key, _) in std::env::vars_os() {
            let name = key.to_string_lossy();
            if name.starts_with("SOCKET_") && !FORCED_OPT_OUTS.iter().any(|(k, _)| *k == name) {
                std::env::remove_var(&key);
            }
        }
        for (k, v) in FORCED_OPT_OUTS {
            std::env::set_var(k, v);
        }
    });
    <Cli as clap::Parser>::try_parse_from(argv)
}

/// The `GlobalArgs` a parse with no global flag must yield, written out by
/// hand so it can disagree with the `default_value`s. A struct literal: a new
/// global field fails to compile here until its default is added.
pub fn global_defaults() -> Globals {
    Globals(GlobalArgs {
        cwd: ".".into(),
        manifest_path: ".socket/manifest.json".to_string(),
        // No clap default: resolved in core.
        api_url: None,
        api_token: None,
        org: None,
        // No clap default: resolved in core.
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
    })
}

/// `GlobalArgs` compared through its `Debug` output (it has no `PartialEq`),
/// so a suite's snapshot struct can hold it and still derive `PartialEq`.
#[derive(Clone)]
pub struct Globals(pub GlobalArgs);

impl PartialEq for Globals {
    fn eq(&self, other: &Self) -> bool {
        format!("{:?}", self.0) == format!("{:?}", other.0)
    }
}

impl std::fmt::Debug for Globals {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::ops::Deref for Globals {
    type Target = GlobalArgs;
    fn deref(&self) -> &GlobalArgs {
        &self.0
    }
}

impl std::ops::DerefMut for Globals {
    fn deref_mut(&mut self) -> &mut GlobalArgs {
        &mut self.0
    }
}
