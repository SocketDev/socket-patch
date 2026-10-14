//! Every CLI test child is spawned with the one hermetic environment in
//! `common/hermetic.rs` (#823).
//!
//! Two halves:
//!
//! * the shared builder's contract, checked on the inputs where the per-file
//!   `scrub_socket_env` copies it replaced used to differ (whether
//!   `SOCKET_NO_CONFIG` survived, whether `SOCKET_NO_UPDATE_CHECK` was
//!   forced, which package-manager vars were swept, case of `npm_config_*`);
//! * a ratchet over the test tree: no private `scrub_socket_env` copy, and
//!   no new file that spawns the binary with a bare `Command::new`. The
//!   `PENDING_RAW_SPAWNS` list below only shrinks — move a file onto
//!   `hermetic::command` / `common::run*` and delete its entry. (The copy
//!   check matches that one name; files that still sweep `SOCKET_*` by hand
//!   under another name are the bare spawns that list tracks.)

#[path = "common/hermetic.rs"]
mod hermetic;

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::Path;
use std::process::Command;

use hermetic::Extra;
use serial_test::serial;

/// Files that still spawn the binary with a bare `Command::new`, so their
/// children see whatever `SOCKET_*` the ambient shell exports unless the file
/// scrubs by hand.
const PENDING_RAW_SPAWNS: &[&str] = &[
    "e2e_hosted_production.rs",
    "e2e_vendored_production.rs",
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

/// B69: CI legs that run the prebuilt test binaries directly (not through
/// cargo) do not get the `[env]` table, so their workflow env blocks copy it
/// by hand. Any env block that copies one opt-out must copy all three.
#[test]
fn workflow_env_copies_carry_every_opt_out() {
    const OPT_OUTS: [&str; 3] = [
        "SOCKET_NO_CONFIG",
        "SOCKET_NO_UPDATE_CHECK",
        "SOCKET_TELEMETRY_DISABLED",
    ];
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.github/workflows");
    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .map(|e| e.expect("workflow dir entry").path())
        .filter(|p| p.extension().is_some_and(|x| x == "yml" || x == "yaml"))
        .collect();
    entries.sort();
    let mut copies = 0;
    let mut missing = Vec::new();
    for path in entries {
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
            .replace("\r\n", "\n");
        let lines: Vec<&str> = text.lines().collect();
        // An env block is a run of `KEY: value` lines at one indent; find
        // every run that sets any opt-out and check it sets them all.
        let mut i = 0;
        while i < lines.len() {
            let line = lines[i];
            let Some(var) = OPT_OUTS
                .iter()
                .find(|v| line.trim_start().starts_with(&format!("{v}:")))
            else {
                i += 1;
                continue;
            };
            let indent = line.len() - line.trim_start().len();
            let same_block = |l: &&str| {
                let t = l.trim_start();
                l.len() - t.len() == indent && !t.is_empty() && !t.starts_with('-')
            };
            let mut start = i;
            while start > 0 && same_block(&lines[start - 1]) {
                start -= 1;
            }
            let mut end = i;
            while end + 1 < lines.len() && same_block(&lines[end + 1]) {
                end += 1;
            }
            let block = &lines[start..=end];
            copies += 1;
            for want in OPT_OUTS {
                let set = block.iter().any(|l| l.trim() == format!("{want}: '1'"));
                if !set {
                    missing.push(format!(
                        "{}:{} (block with {var}) lacks {want}: '1'",
                        path.display(),
                        start + 1
                    ));
                }
            }
            i = end + 1;
        }
    }
    assert!(
        copies > 0,
        "found no workflow env copy of the [env] opt-outs"
    );
    assert!(
        missing.is_empty(),
        "workflow env blocks that copy .cargo/config.toml [env] must set all \
         three opt-outs:\n{}",
        missing.join("\n")
    );
}

#[test]
#[serial]
fn command_never_leaks_its_hostile_seeds() {
    let env = effective_env(&hermetic::command(Path::new("socket-patch")));
    for (key, _) in hermetic::HOSTILE_SEEDS {
        assert_eq!(get(&env, key), None, "{key} seed must be scrubbed");
    }
}

/// In-process tests set flag-bound vars in the test binary's own
/// environment (`apply_env_toggles`, save/restore helpers). One set after
/// the builder's sweep but before the spawn must still not reach the child.
#[test]
#[serial]
fn command_drops_flag_bound_vars_set_after_it_is_built() {
    let cmd = hermetic::command(Path::new("socket-patch"));
    with_ambient(
        &[
            ("SOCKET_OFFLINE", "true"),
            ("SOCKET_DEBUG", "1"),
            ("SOCKET_PROXY_URL", "http://ambient.invalid"),
            ("SOCKET_SKIP_ROLLBACK", "true"),
            // Peer aliases the binary promotes onto `SOCKET_API_TOKEN` & co.
            ("SOCKET_CLI_API_TOKEN", "late-token"),
            ("SOCKET_CLI_ORG_SLUG", "late-org"),
            ("SOCKET_CLI_API_BASE_URL", "http://ambient.invalid"),
            ("SOCKET_CLI_NO_API_TOKEN", "1"),
        ],
        || {
            let env = effective_env(&cmd);
            for key in [
                "SOCKET_OFFLINE",
                "SOCKET_DEBUG",
                "SOCKET_PROXY_URL",
                "SOCKET_SKIP_ROLLBACK",
                "SOCKET_CLI_API_TOKEN",
                "SOCKET_CLI_ORG_SLUG",
                "SOCKET_CLI_API_BASE_URL",
                "SOCKET_CLI_NO_API_TOKEN",
            ] {
                assert_eq!(get(&env, key), None, "{key} set after build leaked");
            }
        },
    );
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
fn yarn_classic_extra_sweeps_mirror_rc_and_prefix_overrides() {
    with_ambient(
        &[
            ("YARN_CACHE_FOLDER", "/ambient/yarn"),
            ("yarn_cache_folder", "/ambient/yarn"),
            ("npm_config_cache_folder", "/ambient/yarn"),
            ("YARN_YARN_OFFLINE_MIRROR", "/ambient/mirror"),
            ("npm_config_yarn_offline_mirror", "/ambient/mirror"),
            ("NPM_CONFIG_USERCONFIG", "/ambient/.npmrc"),
            ("PREFIX", "/ambient/prefix"),
            ("YARN_ENABLE_GLOBAL_CACHE", "true"),
        ],
        || {
            let mut cmd = Command::new("yarn");
            hermetic::scrub_extra(&mut cmd, &[Extra::YarnClassic]);
            let env = effective_env(&cmd);
            assert_eq!(get(&env, "YARN_CACHE_FOLDER"), None);
            assert_eq!(get(&env, "yarn_cache_folder"), None, "any case");
            assert_eq!(get(&env, "npm_config_cache_folder"), None);
            assert_eq!(get(&env, "YARN_YARN_OFFLINE_MIRROR"), None);
            assert_eq!(get(&env, "npm_config_yarn_offline_mirror"), None);
            assert_eq!(get(&env, "NPM_CONFIG_USERCONFIG"), None, "any case");
            assert_eq!(get(&env, "PREFIX"), None);
            assert_eq!(get(&env, "YARN_ENABLE_GLOBAL_CACHE"), Some("true"));
        },
    );
}

#[test]
#[serial]
fn bundle_extra_sweeps_every_bundler_override() {
    with_ambient(
        &[
            ("BUNDLE_PATH", "/ambient/bundle"),
            ("BUNDLE_APP_CONFIG", "/ambient/.bundle"),
            ("BUNDLE_GEMFILE", "/ambient/Gemfile"),
            ("GEM_HOME", "/ambient/gems"),
        ],
        || {
            let mut cmd = Command::new("bundle");
            hermetic::scrub_extra(&mut cmd, &[Extra::Bundle]);
            let env = effective_env(&cmd);
            assert_eq!(get(&env, "BUNDLE_PATH"), None);
            assert_eq!(get(&env, "BUNDLE_APP_CONFIG"), None);
            assert_eq!(get(&env, "BUNDLE_GEMFILE"), None);
            assert_eq!(get(&env, "GEM_HOME"), Some("/ambient/gems"));

            // A suite's own BUNDLE_PATH, set after the scrub, survives.
            cmd.env("BUNDLE_PATH", "/store");
            assert_eq!(get(&effective_env(&cmd), "BUNDLE_PATH"), Some("/store"));
        },
    );
}

#[test]
#[serial]
fn composer_extra_sweeps_overrides_and_pins_an_empty_home() {
    with_ambient(
        &[
            ("COMPOSER_VENDOR_DIR", "third"),
            ("COMPOSER_HOME", "/ambient/composer"),
            ("COMPOSER_CACHE_DIR", "/ambient/composer-cache"),
            ("XDG_CONFIG_HOME", "/ambient/config"),
        ],
        || {
            let mut cmd = Command::new("socket-patch");
            hermetic::scrub_extra(&mut cmd, &[Extra::Composer]);
            let env = effective_env(&cmd);
            assert_eq!(get(&env, "COMPOSER_VENDOR_DIR"), None);
            assert_eq!(get(&env, "COMPOSER_CACHE_DIR"), None);
            // The pin outranks XDG_CONFIG_HOME in the Composer home lookup.
            assert_eq!(
                get(&env, "COMPOSER_HOME"),
                Some("/nonexistent/composer-home")
            );
            assert_eq!(get(&env, "XDG_CONFIG_HOME"), Some("/ambient/config"));

            // A suite's own COMPOSER_HOME, set after the scrub, survives.
            cmd.env("COMPOSER_HOME", "/fixture/home");
            assert_eq!(
                get(&effective_env(&cmd), "COMPOSER_HOME"),
                Some("/fixture/home")
            );
        },
    );
}

#[test]
#[serial]
fn extra_seeds_are_scrubbed_whatever_the_ambient_value() {
    let mut cmd = Command::new("tool");
    hermetic::scrub_extra(&mut cmd, &[Extra::Yarn, Extra::Pnpm, Extra::Bundle]);
    let env = effective_env(&cmd);
    assert_eq!(get(&env, "YARN_NODE_LINKER"), None);
    assert_eq!(get(&env, "npm_config_node_linker"), None);
    assert_eq!(get(&env, "BUNDLE_APP_CONFIG"), None);
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
fn no_scrub_socket_env_copies() {
    let found: Vec<String> = test_sources()
        .into_iter()
        .filter(|(rel, text)| {
            rel != "spawn_env_hygiene.rs" && text.contains("fn scrub_socket_env(")
        })
        .map(|(rel, _)| rel)
        .collect();
    assert!(
        found.is_empty(),
        "these test files define a private scrub_socket_env: {found:?}. \
         Spawn through `tests/common/hermetic.rs` instead (hermetic::command \
         for the binary, scrub_socket_vars + scrub_extra for package-manager \
         children; add an `Extra` variant for a new tool's config)."
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
