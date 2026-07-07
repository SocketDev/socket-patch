//! Env-hygiene guard for setup-matrix HOST mode (`SOCKET_PATCH_TEST_HOST=1`).
//!
//! `run_case`'s host branch spawns `bash run-case.sh` as a plain child
//! process, so — unlike docker mode, where only the explicit `-e SM_*`
//! vars cross into the container — the driver, the binary under test,
//! and the native package-manager installs all inherit the parent
//! shell's environment. An ambient `SOCKET_DRY_RUN=true` turns the
//! install hook's apply into a no-op (every baseline case red for the
//! wrong reason), an ambient `SOCKET_CWD` recreates exactly the
//! workspace-breaking mode run-case.sh documents it must avoid, an
//! ambient `SM_WORKDIR` makes every parallel case share one scratch
//! dir (the blob/proj races the driver warns about), and an ambient
//! `npm_config_ignore_scripts=true` stops lifecycle hooks from firing
//! at all. This guard pins the scrub-then-seed contract of
//! `smc::host_driver_command` — the same `Command` `run_case` spawns —
//! by planting hostile decoys in the parent env and asserting each is
//! explicitly removed while the case's own seeds survive.
//!
//! Deliberately its own test binary: it mutates the process env, and
//! nothing else runs in this binary, so the decoys cannot race a live
//! matrix case in another test thread.
#![cfg(feature = "setup-e2e")]

#[path = "setup_matrix_common/mod.rs"]
mod smc;

use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::path::Path;
use std::process::Command;

/// Hostile ambient vars: each one, if inherited by the driver, flips a
/// real verdict for the wrong reason (dry-run apply, retargeted cwd or
/// manifest, global mode, shared scratch dir, stale hook wheel, dead
/// registry, disabled lifecycle scripts, hijacked venv, poisoned shim
/// PATH cleanup).
const DECOYS: &[(&str, &str)] = &[
    ("SOCKET_DRY_RUN", "true"),
    ("SOCKET_CWD", "/nonexistent/decoy"),
    ("SOCKET_MANIFEST_PATH", "/nonexistent/decoy/manifest.json"),
    ("SOCKET_GLOBAL", "true"),
    ("SM_WORKDIR", "/nonexistent/decoy-shared-workdir"),
    ("SOCKET_PATCH_HOOK_WHEEL", "/nonexistent/decoy.whl"),
    ("npm_config_ignore_scripts", "true"),
    ("NPM_CONFIG_REGISTRY", "http://127.0.0.1:9/decoy"),
    ("YARN_ENABLE_SCRIPTS", "false"),
    ("VIRTUAL_ENV", "/nonexistent/decoy-venv"),
    ("SETUP_MATRIX_SHIM_DIR", "/nonexistent/decoy-shims"),
];

/// Snapshot the command's explicit env ops: `Some(value)` = seeded,
/// `None` = removed, absent key = silently inherited from the parent.
fn env_map(cmd: &Command) -> HashMap<OsString, Option<OsString>> {
    cmd.get_envs()
        .map(|(k, v)| (k.to_os_string(), v.map(OsStr::to_os_string)))
        .collect()
}

#[test]
fn host_driver_command_scrubs_ambient_env_and_keeps_case_seeds() {
    for (k, v) in DECOYS {
        std::env::set_var(k, v);
    }

    let case_env = vec![
        ("SM_ID".to_string(), "guard/npm/decoy".to_string()),
        ("SM_ECOSYSTEM".to_string(), "npm".to_string()),
    ];

    // No wheel: SOCKET_PATCH_HOOK_WHEEL must be scrubbed, not inherited
    // stale from the shell.
    let cmd = smc::host_driver_command(&case_env, None);
    let envs = env_map(&cmd);

    for (k, _) in DECOYS {
        assert_eq!(
            envs.get(OsStr::new(k)),
            Some(&None),
            "ambient decoy {k} must be explicitly removed (env_remove) from the \
             host driver invocation; it currently leaks into run-case.sh, the \
             binary under test, and the native package-manager installs"
        );
    }

    // Scrub-then-seed ordering: the SM_* case env and the binary path are
    // set AFTER the prefix scrub, so they must survive as real values (a
    // scrub running last would wipe its own seeds — last env call wins).
    assert_eq!(
        envs.get(OsStr::new("SM_ID")).cloned().flatten().as_deref(),
        Some(OsStr::new("guard/npm/decoy")),
        "case SM_* env must survive the SM_ prefix scrub (scrub must run before seeding)"
    );
    assert!(
        matches!(envs.get(OsStr::new("SOCKET_PATCH_BIN")), Some(Some(p)) if !p.is_empty()),
        "SOCKET_PATCH_BIN must survive the SOCKET_ prefix scrub"
    );

    // With a wheel, the explicit seed must survive the scrub too.
    let wheel = Path::new("/tmp/socket_patch_hook-0.0.0-py3-none-any.whl");
    let cmd = smc::host_driver_command(&case_env, Some(wheel));
    let envs = env_map(&cmd);
    assert_eq!(
        envs.get(OsStr::new("SOCKET_PATCH_HOOK_WHEEL"))
            .cloned()
            .flatten()
            .as_deref(),
        Some(wheel.as_os_str()),
        "an explicitly provided hook wheel must survive the SOCKET_ prefix scrub"
    );

    for (k, _) in DECOYS {
        std::env::remove_var(k);
    }
}
