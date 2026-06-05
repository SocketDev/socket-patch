//! setup-matrix: deno ecosystem (deno install against a package.json,
//! npm-via-deno layout). `setup` DOES rewrite the package.json (deno
//! projects have one), but whether `deno install` runs the root
//! postinstall hook is uncertain — so the baseline records this as a
//! GAP. If it applies, the orchestrator flags it `progress`.
//!
//! IMPORTANT — why this file carries a real assertion of its own:
//! `smc::run_pm("deno", "deno")` routes deno through the shared Docker
//! matrix harness, which *soft-skips and silently passes* whenever Docker
//! or the `deno` image is absent (the common case locally and in this
//! eval). deno is also NOT npm-family (see `is_npm_family` in the harness
//! and `run-case.sh`), so the harness's check/remove behavioral
//! round-trip is skipped entirely for it; and because deno's
//! `baseline_supported` is false in matrix.json the only thing the matrix
//! could ever assert is the coarse `actual_applied == expect_applied`
//! verdict — which, on a crashed or never-run case, defaults to the same
//! `false` that satisfies every negative-control scenario. The net
//! effect: the matrix call can never turn red for a genuine deno `setup`
//! regression. On its own it protects nothing.
//!
//! To close that loophole WITHOUT touching the shared harness or the bash
//! driver, [`host_guard::deno_setup_roundtrip_host`] runs unconditionally
//! (no Docker, no network, no deno toolchain) and pins deno `setup`'s
//! *actual current contract*: a deno project HAS a package.json, so
//! `setup` must configure the npm-style postinstall hook in it exactly as
//! it does for npm — `setup --check` fails (exit 1) before, passes (exit
//! 0) after, fails again after `setup --remove`; the injected
//! `scripts.postinstall` must actually invoke `socket-patch apply`; remove
//! must delete it; and the sibling `deno.json` must be left byte-for-byte
//! untouched throughout. It verifies on-disk state with an *independent*
//! `serde_json` probe (the documented expectation of what setup should
//! write, not a copy of the writer's output) so the oracle can disagree
//! with a broken implementation. It fails loudly if deno `setup` /
//! `setup --check` / `setup --remove` ever regress, stop rewriting the
//! package.json, mangle `deno.json`, or mis-report the configured state.
//!
//! Run: `cargo test -p socket-patch-cli --features setup-e2e --test setup_matrix_deno`
#![cfg(feature = "setup-e2e")]

#[path = "setup_matrix_common/mod.rs"]
mod smc;

/// Documentation/negative-control pass through the shared Docker matrix.
/// Kept for parity with the other ecosystems and to run the deno negative
/// controls when Docker + the `deno` image are present. NOTE: this is the
/// path that silently no-ops on skip — it is NOT a regression guard. The
/// real teeth live in [`host_guard`] below.
#[test]
// Experimental ecosystem (deno): the setup-matrix aspirational cases are a
// BASELINE GAP (setup does not wire deno's install hook yet). This passes on CI
// only because the runners lack the `deno` toolchain (the cases soft-skip); on
// any host that HAS deno it fails. Ignore it so deno can never block the
// blocking --all-features jobs. The non-skippable no-op contract is still
// guarded by `host_guard` below. Run with `--features setup-e2e -- --ignored`.
#[ignore = "experimental ecosystem (deno): not gating CI until the deno backend is implemented; run with --ignored"]
fn deno() {
    smc::run_pm("deno", "deno");
}

// ─────────────────────────────────────────────────────────────────────────
// Real, non-skippable regression guard for deno `setup`.
//
// A deno project carries a real package.json (the driver scaffolds one
// alongside deno.json), so deno is on the npm-package.json-hook surface
// that `setup` actually configures today: it must wire the postinstall
// hook into package.json, report state correctly via `--check`, undo it on
// `--remove`, and never touch the deno-native config.
// ─────────────────────────────────────────────────────────────────────────
mod host_guard {
    use std::path::Path;
    use std::process::Command;

    /// A faithful deno project fixture: a package.json declaring the same
    /// dependency the matrix targets, plus a deno-native `deno.json` with
    /// `nodeModulesDir` (mirrors `scaffold_project`'s deno branch in
    /// `tests/setup_matrix/run-case.sh`).
    const PACKAGE_JSON: &str = "{ \"name\": \"sm-proj\", \"version\": \"0.0.0\", \"private\": true, \"dependencies\": { \"minimist\": \"1.2.2\" } }\n";
    const DENO_JSON: &str =
        "{ \"name\": \"sm-proj\", \"version\": \"0.0.0\", \"nodeModulesDir\": \"auto\" }\n";

    /// Every `SOCKET_*` env var clap consults for the `setup` surface this
    /// test drives. The round-trip's whole signal is the contrast between
    /// flag-present and flag-absent runs (`--check`, `--yes`, `--cwd`,
    /// `--remove`); an ambient `SOCKET_CWD` / `SOCKET_YES` / `SOCKET_OFFLINE`
    /// / `SOCKET_MANIFEST_PATH` etc. in the shell or CI could stand in for a
    /// flag and mask a flag-handling regression (e.g. `--cwd` being ignored,
    /// or `--check` silently succeeding). Strip the full surface so behaviour
    /// reflects the explicit flags alone. Mirrors `setup_matrix_cargo.rs`.
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
        "SOCKET_SAVE_ONLY",
        "SOCKET_ONE_OFF",
        "SOCKET_ALL_RELEASES",
        "SOCKET_PATCH_ROOT",
        "SOCKET_PATCH_GUARD",
    ];

    /// Absolute path to the binary under test, via cargo's `CARGO_BIN_EXE_*`.
    fn binary() -> std::path::PathBuf {
        env!("CARGO_BIN_EXE_socket-patch").into()
    }

    /// Run the CLI with `args` in `cwd`; returns `(exit_code, stdout, stderr)`.
    /// The entire `SOCKET_*` surface is stripped so behaviour reflects the
    /// explicit flags alone (see [`SOCKET_ENV_VARS`]) — nothing reaches authed
    /// endpoints and no ambient var can stand in for a flag.
    fn run(cwd: &Path, args: &[&str]) -> (i32, String, String) {
        let mut cmd = Command::new(binary());
        cmd.args(args).current_dir(cwd);
        for var in SOCKET_ENV_VARS {
            cmd.env_remove(var);
        }
        let out = cmd
            .output()
            .expect("failed to execute socket-patch binary");
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).to_string(),
            String::from_utf8_lossy(&out.stderr).to_string(),
        )
    }

    /// Parse the CLI's `--json` stdout into a single JSON object. Panics
    /// (loudly) if stdout is not the single JSON object the command
    /// promises — a non-JSON / multi-line dump means the command did not
    /// run the path we think it did.
    fn parse_json(stdout: &str, who: &str) -> serde_json::Value {
        serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
            panic!("{who}: stdout was not a single JSON object ({e}):\n{stdout}")
        })
    }

    fn json_str_field(v: &serde_json::Value, key: &str, who: &str) -> String {
        v.get(key)
            .and_then(|s| s.as_str())
            .unwrap_or_else(|| panic!("{who}: JSON has no string `{key}` field:\n{v}"))
            .to_string()
    }

    /// Independent oracle: read package.json with `serde_json` and return
    /// `scripts.postinstall` if present. Deliberately does NOT reuse the
    /// production detection helpers (`is_setup_configured_str`) so the
    /// oracle can disagree with a broken writer.
    fn postinstall_script(root: &Path) -> Option<String> {
        let content = std::fs::read_to_string(root.join("package.json")).unwrap();
        let v: serde_json::Value = serde_json::from_str(&content)
            .unwrap_or_else(|e| panic!("package.json is not valid JSON ({e}):\n{content}"));
        v.get("scripts")
            .and_then(|s| s.get("postinstall"))
            .and_then(|p| p.as_str())
            .map(String::from)
    }

    /// `deno.json` (the deno-native config) must be byte-for-byte what we
    /// wrote — `setup` operates on package.json and must never mutate it.
    fn assert_deno_json_pristine(root: &Path, who: &str) {
        assert_eq!(
            std::fs::read_to_string(root.join("deno.json")).unwrap(),
            DENO_JSON,
            "{who}: deno.json must be left byte-for-byte unchanged by setup"
        );
    }

    #[test]
    fn deno_setup_roundtrip_host() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(root.join("package.json"), PACKAGE_JSON).unwrap();
        std::fs::write(root.join("deno.json"), DENO_JSON).unwrap();
        let root_s = root.to_str().unwrap();

        // ── check (before setup): unconfigured → must FAIL (exit 1) ─────────
        // Proves `--check` reads real state instead of hardcoding success,
        // and that a deno package.json is recognised as a configurable
        // manifest (status needs_configuration, NOT no_files — a no_files
        // here would mean setup silently ignores deno projects).
        let (code, out, err) = run(root, &["setup", "--check", "--cwd", root_s, "--json"]);
        assert_eq!(
            code, 1,
            "setup --check must FAIL (exit 1) on a pristine, unconfigured deno project.\nstdout:\n{out}\nstderr:\n{err}"
        );
        let v = parse_json(&out, "check (pristine)");
        assert_eq!(
            json_str_field(&v, "status", "check (pristine)"),
            "needs_configuration",
            "a deno project's package.json must report needs_configuration, not no_files/configured.\nstderr:\n{err}"
        );
        assert_eq!(
            v.get("needsConfiguration").and_then(|n| n.as_i64()),
            Some(1),
            "exactly the package.json must be counted as needing configuration.\n{out}"
        );
        assert!(
            postinstall_script(root).is_none(),
            "no postinstall hook must exist before setup runs"
        );
        assert_deno_json_pristine(root, "after check (pristine)");

        // ── setup: must rewrite package.json with a real apply hook ─────────
        let (code, out, err) = run(root, &["setup", "--cwd", root_s, "--yes", "--json"]);
        assert_eq!(code, 0, "setup must succeed (exit 0).\nstdout:\n{out}\nstderr:\n{err}");
        let v = parse_json(&out, "setup");
        assert_eq!(
            json_str_field(&v, "status", "setup"),
            "success",
            "setup on a deno project must report status=success.\nstderr:\n{err}"
        );
        assert_eq!(
            v.get("updated").and_then(|n| n.as_i64()),
            Some(1),
            "setup must report updating exactly one manifest (the package.json).\n{out}"
        );
        assert_eq!(
            v.get("errors").and_then(|n| n.as_i64()),
            Some(0),
            "setup must report zero errors on a deno project.\n{out}"
        );

        // Independent on-disk verification: the postinstall hook must exist
        // and must actually invoke `socket-patch apply` for the npm
        // ecosystem — an empty/foreign/echo value would be a regression that
        // a mere "key present" check would miss.
        let hook = postinstall_script(root)
            .unwrap_or_else(|| panic!("setup did not write scripts.postinstall into package.json"));
        assert!(
            hook.contains("socket-patch apply"),
            "postinstall hook must invoke `socket-patch apply`, got: {hook:?}"
        );
        assert!(
            hook.contains("--ecosystems npm"),
            "postinstall hook must target the npm ecosystem (deno installs npm deps via package.json), got: {hook:?}"
        );
        // The committed `minimist` dependency must survive the rewrite.
        let pkg = std::fs::read_to_string(root.join("package.json")).unwrap();
        let pkg_v: serde_json::Value = serde_json::from_str(&pkg).unwrap();
        assert_eq!(
            pkg_v.get("dependencies").and_then(|d| d.get("minimist")).and_then(|m| m.as_str()),
            Some("1.2.2"),
            "setup must preserve the project's existing dependencies.\n{pkg}"
        );
        assert_deno_json_pristine(root, "after setup");

        // ── check (configured): must PASS (exit 0) ──────────────────────────
        let (code, out, err) = run(root, &["setup", "--check", "--cwd", root_s, "--json"]);
        assert_eq!(
            code, 0,
            "setup --check must PASS (exit 0) after setup configured the deno project.\nstdout:\n{out}\nstderr:\n{err}"
        );
        let v = parse_json(&out, "check (configured)");
        assert_eq!(
            json_str_field(&v, "status", "check (configured)"),
            "configured",
            "check must report the deno package.json as configured after setup.\nstderr:\n{err}"
        );
        assert_eq!(
            v.get("configured").and_then(|n| n.as_i64()),
            Some(1),
            "exactly one manifest (the package.json) must be reported configured.\n{out}"
        );
        assert_eq!(
            v.get("needsConfiguration").and_then(|n| n.as_i64()),
            Some(0),
            "no manifest may still need configuration after a successful setup.\n{out}"
        );

        // ── remove: must delete the hook and succeed ────────────────────────
        let (code, out, err) = run(root, &["setup", "--remove", "--cwd", root_s, "--yes", "--json"]);
        assert_eq!(code, 0, "setup --remove must succeed (exit 0).\nstdout:\n{out}\nstderr:\n{err}");
        let v = parse_json(&out, "remove");
        assert_eq!(
            json_str_field(&v, "status", "remove"),
            "success",
            "setup --remove must report status=success on a configured deno project.\nstderr:\n{err}"
        );
        assert_eq!(
            v.get("removed").and_then(|n| n.as_i64()),
            Some(1),
            "remove must report removing exactly one hook.\n{out}"
        );
        assert!(
            postinstall_script(root).is_none(),
            "the postinstall hook must be gone from package.json after remove:\n{}",
            std::fs::read_to_string(root.join("package.json")).unwrap()
        );
        assert_deno_json_pristine(root, "after remove");

        // ── check (after remove): back to needs-configuration (exit 1) ──────
        let (code, out, err) = run(root, &["setup", "--check", "--cwd", root_s, "--json"]);
        assert_eq!(
            code, 1,
            "setup --check must FAIL (exit 1) again after remove.\nstdout:\n{out}\nstderr:\n{err}"
        );
        let v = parse_json(&out, "check (post-remove)");
        assert_eq!(
            json_str_field(&v, "status", "check (post-remove)"),
            "needs_configuration",
            "check must report needs_configuration again after the hook is removed.\nstderr:\n{err}"
        );
        assert_eq!(
            v.get("needsConfiguration").and_then(|n| n.as_i64()),
            Some(1),
            "the package.json must count as needing configuration again after remove.\n{out}"
        );
        assert_eq!(
            v.get("configured").and_then(|n| n.as_i64()),
            Some(0),
            "no manifest may report configured after the hook is removed.\n{out}"
        );
    }
}
