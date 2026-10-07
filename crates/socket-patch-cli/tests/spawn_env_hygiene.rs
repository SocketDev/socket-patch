//! Every CLI test child is spawned with the one hermetic environment in
//! `common/hermetic.rs` (#823).
//!
//! Two halves:
//!
//! * the shared builder's contract, checked on the inputs where the per-file
//!   `scrub_socket_env` copies it replaced used to differ (whether
//!   `SOCKET_NO_CONFIG` survived, whether `SOCKET_NO_UPDATE_CHECK` was
//!   forced, which package-manager vars were swept, case of `npm_config_*`);
//! * a ratchet over the test tree: no new private `scrub_socket_env`, and no
//!   new file that spawns the binary with a bare `Command::new`. Both lists
//!   below only shrink — move a file onto `hermetic::command` /
//!   `common::run*` and delete its entry.

#[path = "common/hermetic.rs"]
mod hermetic;

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::Path;
use std::process::Command;

use hermetic::Extra;
use serial_test::serial;

/// Files that still carry a private `scrub_socket_env`. Each one is changed
/// by an open fix PR; migrate it once that lands.
const PENDING_SCRUB_COPIES: &[&str] = &[
    "e2e_redirect_yarn_berry_build.rs",
    "e2e_redirect_yarn_classic_build.rs",
    "e2e_vendor_yarn_berry_build.rs",
    "e2e_vendor_yarn_classic_build.rs",
    "e2e_yarn4_pnpm_linker_build.rs",
    "e2e_yarn4_workspaces_build.rs",
    "scan/covgap_ecosystem_dispatch.rs",
];

/// Files that still spawn the binary with a bare `Command::new`, so their
/// children see whatever `SOCKET_*` the ambient shell exports unless the file
/// scrubs by hand.
const PENDING_RAW_SPAWNS: &[&str] = &[
    "apply/apply_invariants.rs",
    "apply/apply_network.rs",
    "apply/cli_gem_variant_mismatch_policy.rs",
    "apply/covgap_commands_apply.rs",
    "apply/in_process_gem_config_warning.rs",
    "apply/in_process_gem_fallback_home.rs",
    "apply/in_process_gem_multicopy.rs",
    "apply/in_process_npm_multicopy.rs",
    "apply/in_process_variant_apply_failure.rs",
    "cli/covgap_api_client.rs",
    "cli/covgap_commands_list.rs",
    "cli/telemetry_e2e.rs",
    "cli_apply_silent.rs",
    "cli_argv_non_utf8.rs",
    "cli_config_fallback.rs",
    "cli_get_silent.rs",
    "cli_global_args.rs",
    "cli_parse_list.rs",
    "cli_remove_silent.rs",
    "cli_scan_silent.rs",
    "cli_sigpipe.rs",
    "coverage_fix_apply_silent_mute_exit.rs",
    "coverage_fix_scan_hosted_dryrun_vendored.rs",
    "coverage_fix_vendor_silent_mute_exit.rs",
    "covgap_commands_rollback.rs",
    "covgap_commands_scan_mod.rs",
    "covgap_commands_vendor.rs",
    "covgap_commands_vex.rs",
    "covgap_utils_socket_cli_config.rs",
    "diff_created_file_e2e.rs",
    "e2e_cargo.rs",
    "e2e_composer.rs",
    "e2e_composer_version_identity.rs",
    "e2e_embedded_vex.rs",
    "e2e_gem.rs",
    "e2e_golang.rs",
    "e2e_golang_build.rs",
    "e2e_golang_workspace_build.rs",
    "e2e_hosted_production.rs",
    "e2e_maven.rs",
    "e2e_npm.rs",
    "e2e_nuget.rs",
    "e2e_nuget_dotnet_build.rs",
    "e2e_pypi.rs",
    "e2e_pypi_multi_copy.rs",
    "e2e_redirect_bun_build.rs",
    "e2e_redirect_cargo_build.rs",
    "e2e_redirect_cargo_shapes.rs",
    "e2e_redirect_composer_build.rs",
    "e2e_redirect_gem_build.rs",
    "e2e_redirect_maven_build.rs",
    "e2e_redirect_npm_build.rs",
    "e2e_redirect_yarn_berry_build.rs",
    "e2e_redirect_yarn_classic_build.rs",
    "e2e_scan.rs",
    "e2e_socket_yml_policy.rs",
    "e2e_vendor_bun_build.rs",
    "e2e_vendor_cargo_build.rs",
    "e2e_vendor_composer_build.rs",
    "e2e_vendor_composer_crlf.rs",
    "e2e_vendor_gem_build.rs",
    "e2e_vendor_golang_build.rs",
    "e2e_vendor_jvm_build.rs",
    "e2e_vendor_maven_build.rs",
    "e2e_vendor_npm_build.rs",
    "e2e_vendor_pypi_build.rs",
    "e2e_vendor_yarn_berry_build.rs",
    "e2e_vendor_yarn_classic_build.rs",
    "e2e_vendored_production.rs",
    "e2e_vex.rs",
    "e2e_vex_build/deno.rs",
    "e2e_vex_build/hatch.rs",
    "e2e_vex_build/poetry.rs",
    "e2e_vex_lockfile/bun.rs",
    "e2e_vex_lockfile/cargo.rs",
    "e2e_vex_lockfile/golang.rs",
    "e2e_vex_lockfile/maven.rs",
    "e2e_vex_lockfile/npm.rs",
    "e2e_vex_lockfile/nuget.rs",
    "e2e_vex_lockfile/pnpm.rs",
    "e2e_vex_lockfile/poetry.rs",
    "e2e_vex_lockfile/uv.rs",
    "e2e_vex_lockfile/yarn.rs",
    "e2e_vex_redirect.rs",
    "e2e_vex_vendor.rs",
    "e2e_yarn4_pnpm_linker_build.rs",
    "e2e_yarn4_workspaces_build.rs",
    "get/get_edge_cases_e2e.rs",
    "get/global_packages_e2e.rs",
    "hosted_memory_common/mod.rs",
    "hosted_memory_engine.rs",
    "hosted_superseding_pypi.rs",
    "in_process_redirect.rs",
    "in_process_redirect_pdm.rs",
    "in_process_redirect_pnpm.rs",
    "in_process_redirect_poetry.rs",
    "in_process_rollback_hosted.rs",
    "in_process_rollback_vendored.rs",
    "in_process_vendor.rs",
    "in_process_vendor_bun_takeover.rs",
    "in_process_vendor_npm_v1_takeover.rs",
    "mode_migration_bun.rs",
    "mode_migration_cargo.rs",
    "mode_migration_pypi.rs",
    "remove/remove_network.rs",
    "remove_rollback_api_overrides.rs",
    "repair/coverage_fix_repair_vendor_predelete.rs",
    "repair/covgap_commands_repair.rs",
    "repair/covgap_commands_repair_vendor.rs",
    "repair/repair_invariants.rs",
    "rollback/cli_rollback_silent.rs",
    "rollback/rollback_duality_invariants.rs",
    "rollback/rollback_invariants.rs",
    "rollback/rollback_multicopy_blob_gate.rs",
    "scan/coverage_fix_scan_discovery_corrupt_ledger.rs",
    "scan/covgap_commands_fetch_stage.rs",
    "scan/covgap_commands_scan_vendor_flow.rs",
    "scan/covgap_ecosystem_dispatch.rs",
    "scan/hosted_management_refusals.rs",
    "scan/scan_batch_sizing_e2e.rs",
    "scan/scan_ecosystems_scope_e2e.rs",
    "scan/scan_invariants.rs",
    "scan/scan_ordered_concurrency_e2e.rs",
    "scan/scan_paths_e2e.rs",
    "scan/scan_vendor_step_error_e2e.rs",
    "scan_api_retry_e2e.rs",
    "scan_pnpm_relocated_store_cwd_e2e.rs",
    "scan_requirements_lock_only.rs",
    "scan_rollout_e2e.rs",
    "scan_vendor_e2e.rs",
    "scan_vendor_requirements_unwired.rs",
    "vendor/e2e_golang_redirect.rs",
    "vendor/in_process_vendor_bun.rs",
    "vendor/vendor_gem_lockfile_only_e2e.rs",
    "vendor/vendor_rerun_no_network_e2e.rs",
    "vendor_crash_safety_e2e.rs",
    "vendor_eject.rs",
    "vendor_eject_bun_lockb.rs",
    "vendor_eject_fresh_checkout.rs",
    "vendor_jvm_cli.rs",
    "vendor_partial_staging_e2e.rs",
    "vex_e2e_common/uv.rs",
    "vex_pdm_hatch_common/mod.rs",
    "vex_pipenv_pip_common/mod.rs",
    "vex_terminal_output.rs",
    "vlt_e2e_common/mod.rs",
    "vlt_hosted_common/mod.rs",
    "vlt_vendor_common/mod.rs",
];

/// The environment `cmd`'s child would see: the parent environment with
/// `cmd`'s explicit sets and removals applied.
fn effective_env(cmd: &Command) -> BTreeMap<OsString, OsString> {
    let mut env: BTreeMap<OsString, OsString> = std::env::vars_os().collect();
    for (k, v) in cmd.get_envs() {
        match v {
            Some(v) => {
                env.insert(k.to_os_string(), v.to_os_string());
            }
            None => {
                env.remove(k);
            }
        }
    }
    env
}

fn get<'a>(env: &'a BTreeMap<OsString, OsString>, key: &str) -> Option<&'a str> {
    env.get(&OsString::from(key)).and_then(|v| v.to_str())
}

/// Set `vars` in this process for the duration of `f`, then restore them.
/// Callers are `#[serial]`.
fn with_ambient(vars: &[(&str, &str)], f: impl FnOnce()) {
    let saved: Vec<(String, Option<OsString>)> = vars
        .iter()
        .map(|(k, _)| (k.to_string(), std::env::var_os(k)))
        .collect();
    for (k, v) in vars {
        std::env::set_var(k, v);
    }
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    for (k, v) in saved {
        match v {
            Some(v) => std::env::set_var(&k, v),
            None => std::env::remove_var(&k),
        }
    }
    if let Err(e) = result {
        std::panic::resume_unwind(e);
    }
}

#[test]
#[serial]
fn command_scrubs_ambient_socket_vars_and_forces_the_opt_outs() {
    with_ambient(
        &[
            ("SOCKET_DRY_RUN", "true"),
            ("SOCKET_OFFLINE", "true"),
            ("SOCKET_ECOSYSTEMS", "pypi"),
            ("SOCKET_API_TOKEN", "ambient-token"),
            ("SOCKET_LOCK_TIMEOUT", "bogus"),
            ("SOCKET_VEX_OUTPUT", "/tmp/x"),
            // One copy kept these, one removed them; the shared builder
            // forces both on.
            ("SOCKET_NO_CONFIG", "0"),
            ("SOCKET_NO_UPDATE_CHECK", "0"),
            ("SOCKET_TELEMETRY_DISABLED", "1"),
        ],
        || {
            let env = effective_env(&hermetic::command(Path::new("socket-patch")));
            for gone in [
                "SOCKET_DRY_RUN",
                "SOCKET_OFFLINE",
                "SOCKET_ECOSYSTEMS",
                "SOCKET_API_TOKEN",
                "SOCKET_LOCK_TIMEOUT",
                "SOCKET_VEX_OUTPUT",
            ] {
                assert_eq!(get(&env, gone), None, "{gone} must be scrubbed");
            }
            assert_eq!(get(&env, "SOCKET_NO_CONFIG"), Some("1"));
            assert_eq!(get(&env, "SOCKET_NO_UPDATE_CHECK"), Some("1"));
            assert_eq!(
                get(&env, "SOCKET_TELEMETRY_DISABLED"),
                Some("1"),
                "telemetry opt-outs survive"
            );
        },
    );
}

/// B69: a test child must never POST telemetry to the real public proxy.
/// An ambient opt-in (`SOCKET_TELEMETRY_DISABLED=0`, or a developer shell
/// that removed the `.cargo/config.toml` default) must not reach the child;
/// a suite that asserts telemetry sets its own value after `command`.
#[test]
#[serial]
fn command_forces_telemetry_off() {
    for ambient in ["0", ""] {
        with_ambient(&[("SOCKET_TELEMETRY_DISABLED", ambient)], || {
            let env = effective_env(&hermetic::command(Path::new("socket-patch")));
            assert_eq!(
                get(&env, "SOCKET_TELEMETRY_DISABLED"),
                Some("1"),
                "ambient SOCKET_TELEMETRY_DISABLED={ambient:?} must not re-enable telemetry"
            );
        });
    }
    let mut cmd = hermetic::command(Path::new("socket-patch"));
    cmd.env("SOCKET_TELEMETRY_DISABLED", "0");
    assert_eq!(
        get(&effective_env(&cmd), "SOCKET_TELEMETRY_DISABLED"),
        Some("0"),
        "a telemetry suite's own opt-in lands last"
    );
}

/// B69: every process `cargo test` / `cargo run` starts (and every child it
/// spawns without a scrub) inherits the three opt-outs from the workspace
/// `.cargo/config.toml` `[env]` table.
#[test]
fn cargo_config_env_carries_the_opt_outs() {
    let config = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.cargo/config.toml");
    let text = std::fs::read_to_string(&config)
        .unwrap_or_else(|e| panic!("read {}: {e}", config.display()))
        .replace("\r\n", "\n");
    let env_table = text
        .split("\n[env]\n")
        .nth(1)
        .unwrap_or_else(|| panic!("{} has no [env] table", config.display()));
    let env_table = env_table.split("\n[").next().unwrap_or(env_table);
    for var in [
        "SOCKET_NO_CONFIG",
        "SOCKET_NO_UPDATE_CHECK",
        "SOCKET_TELEMETRY_DISABLED",
    ] {
        assert!(
            env_table
                .lines()
                .any(|line| line.trim() == format!("{var} = \"1\"")),
            "{} [env] must set {var} = \"1\"",
            config.display()
        );
    }
}

#[test]
#[serial]
fn command_never_leaks_its_hostile_seeds() {
    let env = effective_env(&hermetic::command(Path::new("socket-patch")));
    for key in [
        "SOCKET_GLOBAL",
        "SOCKET_GLOBAL_PREFIX",
        "SOCKET_DRY_RUN",
        "SOCKET_MANIFEST_PATH",
        "SOCKET_JSON",
        "SOCKET_SILENT",
        "SOCKET_VERBOSE",
        "SOCKET_UPDATE_BASE_URL",
        "SOCKET_UPDATE_STATE_DIR",
    ] {
        assert_eq!(get(&env, key), None, "{key} seed must be scrubbed");
    }
}

#[test]
#[serial]
fn caller_env_set_after_command_survives_the_scrub() {
    with_ambient(&[("SOCKET_API_URL", "http://ambient.invalid")], || {
        let mut cmd = hermetic::command(Path::new("socket-patch"));
        cmd.env("SOCKET_API_URL", "http://127.0.0.1:9")
            .env("SOCKET_NO_UPDATE_CHECK", "0");
        let env = effective_env(&cmd);
        assert_eq!(get(&env, "SOCKET_API_URL"), Some("http://127.0.0.1:9"));
        assert_eq!(get(&env, "SOCKET_NO_UPDATE_CHECK"), Some("0"));
    });
}

#[test]
#[serial]
fn scrub_socket_vars_is_the_package_manager_half() {
    with_ambient(
        &[
            ("SOCKET_DRY_RUN", "true"),
            ("SOCKET_NO_CONFIG", "1"),
            ("SOCKET_TELEMETRY_DISABLED", "1"),
            ("YARN_ENABLE_GLOBAL_CACHE", "true"),
        ],
        || {
            let mut cmd = Command::new("yarn");
            hermetic::scrub_socket_vars(&mut cmd);
            let env = effective_env(&cmd);
            assert_eq!(get(&env, "SOCKET_DRY_RUN"), None);
            assert_eq!(get(&env, "SOCKET_NO_CONFIG"), Some("1"));
            assert_eq!(get(&env, "SOCKET_TELEMETRY_DISABLED"), Some("1"));
            assert_eq!(
                get(&env, "YARN_ENABLE_GLOBAL_CACHE"),
                Some("true"),
                "package-manager vars are opt-in extras"
            );
        },
    );
}

#[test]
#[serial]
fn extra_scrubs_sweep_each_tools_ambient_config() {
    with_ambient(
        &[
            ("VIRTUAL_ENV", "/ambient/venv"),
            ("YARN_NODE_LINKER", "pnp"),
            ("YARN_CACHE_FOLDER", "/ambient/yarn"),
            ("PNPM_HOME", "/ambient/pnpm"),
            ("npm_config_node_linker", "pnp"),
            ("NPM_CONFIG_STORE_DIR", "/ambient/store"),
        ],
        || {
            let mut venv = Command::new("tool");
            hermetic::scrub_extra(&mut venv, &[Extra::Venv]);
            let env = effective_env(&venv);
            assert_eq!(get(&env, "VIRTUAL_ENV"), None);
            assert_eq!(get(&env, "YARN_NODE_LINKER"), Some("pnp"));

            let mut yarn = Command::new("yarn");
            hermetic::scrub_extra(&mut yarn, &[Extra::Yarn]);
            let env = effective_env(&yarn);
            assert_eq!(get(&env, "YARN_NODE_LINKER"), None);
            assert_eq!(get(&env, "YARN_CACHE_FOLDER"), None);
            assert_eq!(get(&env, "PNPM_HOME"), Some("/ambient/pnpm"));

            let mut pnpm = Command::new("pnpm");
            hermetic::scrub_extra(&mut pnpm, &[Extra::Pnpm]);
            let env = effective_env(&pnpm);
            assert_eq!(get(&env, "PNPM_HOME"), None);
            assert_eq!(get(&env, "npm_config_node_linker"), None);
            assert_eq!(get(&env, "NPM_CONFIG_STORE_DIR"), None, "any case");
            assert_eq!(get(&env, "VIRTUAL_ENV"), Some("/ambient/venv"));
        },
    );
}

#[test]
#[serial]
fn extra_seeds_are_scrubbed_whatever_the_ambient_value() {
    let mut cmd = Command::new("tool");
    hermetic::scrub_extra(&mut cmd, &[Extra::Yarn, Extra::Pnpm]);
    let env = effective_env(&cmd);
    assert_eq!(get(&env, "YARN_NODE_LINKER"), None);
    assert_eq!(get(&env, "npm_config_node_linker"), None);
}

/// Every `.rs` file under `tests/`, as `/`-separated paths relative to it.
fn test_sources() -> Vec<(String, String)> {
    fn walk(dir: &Path, root: &Path, out: &mut Vec<(String, String)>) {
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
            .map(|e| e.unwrap().path())
            .collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                walk(&path, root, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let rel = path
                    .strip_prefix(root)
                    .unwrap()
                    .components()
                    .map(|c| c.as_os_str().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("/");
                let text = std::fs::read_to_string(&path)
                    .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
                out.push((rel, text));
            }
        }
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut out = Vec::new();
    walk(&root, &root, &mut out);
    out
}

/// Whether `text` spawns the `socket-patch` binary with a bare
/// `Command::new`: `binary()` (any path prefix), the `CARGO_BIN_EXE_*`
/// literal, `socket_bin()` or a `BINARY` const.
fn has_raw_spawn(text: &str) -> bool {
    text.split("Command::new(").skip(1).any(|rest| {
        let arg = rest.trim_start_matches(|c: char| c.is_alphanumeric() || c == '_' || c == ':');
        let head = &rest[..rest.len() - arg.len()];
        let name = head.rsplit("::").next().unwrap_or(head);
        (name == "binary" || name == "socket_bin") && arg.starts_with("()")
            || head == "BINARY" && arg.starts_with(')')
            || rest.starts_with("env!(\"CARGO_BIN_EXE_socket-patch\")")
    })
}

#[test]
fn raw_spawn_detector_matches_the_spellings_in_the_tree() {
    for spawn in [
        "Command::new(binary())",
        "std::process::Command::new(common::binary())",
        "Command::new(vex_e2e_common::binary())",
        "Command::new(env!(\"CARGO_BIN_EXE_socket-patch\"))",
        "Command::new(socket_bin())",
        "Command::new(BINARY)",
    ] {
        assert!(has_raw_spawn(spawn), "{spawn}");
    }
    for ok in [
        "hermetic::command(&binary())",
        "Command::new(\"npm\")",
        "Command::new(bin)",
        "Command::new(binary_path)",
        "Command::new(BINARY_DIR)",
    ] {
        assert!(!has_raw_spawn(ok), "{ok}");
    }
}

#[test]
fn no_new_private_scrub_socket_env_copies() {
    let found: Vec<String> = test_sources()
        .into_iter()
        .filter(|(rel, text)| {
            rel != "spawn_env_hygiene.rs" && text.contains("fn scrub_socket_env(")
        })
        .map(|(rel, _)| rel)
        .collect();
    let unexpected: Vec<&String> = found
        .iter()
        .filter(|f| !PENDING_SCRUB_COPIES.contains(&f.as_str()))
        .collect();
    assert!(
        unexpected.is_empty(),
        "these test files define a private scrub_socket_env: {unexpected:?}. \
         Spawn through `tests/common/hermetic.rs` instead (hermetic::command \
         for the binary, scrub_socket_vars + scrub_extra for package-manager \
         children). Do not add them to PENDING_SCRUB_COPIES."
    );
    let stale: Vec<&&str> = PENDING_SCRUB_COPIES
        .iter()
        .filter(|f| !found.iter().any(|g| g == *f))
        .collect();
    assert!(
        stale.is_empty(),
        "these files no longer carry a scrub_socket_env copy: {stale:?}. Delete \
         them from PENDING_SCRUB_COPIES in \
         crates/socket-patch-cli/tests/spawn_env_hygiene.rs (another PR may \
         have migrated them; rebase and drop the entries)."
    );
}

#[test]
fn no_new_bare_binary_spawns() {
    let found: Vec<String> = test_sources()
        .into_iter()
        .filter(|(rel, text)| rel != "spawn_env_hygiene.rs" && has_raw_spawn(text))
        .map(|(rel, _)| rel)
        .collect();
    let unexpected: Vec<&String> = found
        .iter()
        .filter(|f| !PENDING_RAW_SPAWNS.contains(&f.as_str()))
        .collect();
    assert!(
        unexpected.is_empty(),
        "these test files spawn the binary with a bare Command::new: \
         {unexpected:?}. Use `hermetic::command(&bin)` / \
         `hermetic::binary_command()` or `common::run*` (tests/common/) so the \
         child gets the hermetic SOCKET_* environment. Do not add them to \
         PENDING_RAW_SPAWNS."
    );
    let stale: Vec<&&str> = PENDING_RAW_SPAWNS
        .iter()
        .filter(|f| !found.iter().any(|g| g == *f))
        .collect();
    assert!(
        stale.is_empty(),
        "these files no longer spawn the binary bare: {stale:?}. Delete them \
         from PENDING_RAW_SPAWNS in \
         crates/socket-patch-cli/tests/spawn_env_hygiene.rs (another PR may \
         have migrated them; rebase and drop the entries)."
    );
}
