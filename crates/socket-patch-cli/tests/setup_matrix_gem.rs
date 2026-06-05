//! setup-matrix: gem ecosystem (bundler). No native post-install hook
//! and `setup` is a no-op, so the with-setup cases are an EXPECTED
//! BASELINE GAP.
//!
//! IMPORTANT — why this file carries a real assertion of its own:
//! `smc::run_pm("gem", "bundler")` routes gem through the shared Docker
//! matrix harness, which *soft-skips and silently passes* whenever Docker
//! or the `gem` image is absent (the common case locally and in this
//! eval). gem is also NOT npm-family (see `is_npm_family` in the harness
//! and `run-case.sh`), so the harness's check/remove behavioral
//! round-trip is skipped entirely for it; and because gem's
//! `baseline_supported` is false in matrix.json the only thing the matrix
//! could ever assert is the coarse `actual_applied == expect_applied`
//! verdict — which, on a crashed or never-run case, defaults to the same
//! `false` that satisfies every negative-control scenario. The net
//! effect: the matrix call can never turn red for a genuine gem `setup`
//! regression. On its own it protects nothing.
//!
//! To close that loophole WITHOUT touching the shared harness or the bash
//! driver, [`host_guard::gem_setup_roundtrip_host`] runs unconditionally
//! (no Docker, no network, no ruby/bundler toolchain) and pins gem
//! `setup`'s *actual current contract*: a bundler project has only a
//! `Gemfile` — a manifest `setup` does NOT support — so every `setup`
//! subcommand must report `no_files` (exit 0 for setup/remove; exit 0 for
//! `--check`, since "nothing to configure" is success not failure) and
//! must leave the `Gemfile` byte-for-byte untouched. It reads on-disk
//! state with an *independent* probe (a hand-pinned constant, not a copy
//! of any writer output) so the oracle can disagree with a broken
//! implementation. It fails loudly if gem `setup` ever starts mutating a
//! Gemfile, crashes on a bundler project, mis-classifies the Gemfile as a
//! configurable manifest, or returns the wrong exit code / status.
//!
//! If `setup` ever GROWS real bundler support, this guard's expectations
//! become wrong-by-design and must be upgraded to the deno-style positive
//! round-trip (check fails → setup configures → check passes → remove).
//! That is the intended signal: the test going red here means the baseline
//! gap closed, not that something broke.
//!
//! Run: `cargo test -p socket-patch-cli --features setup-e2e --test setup_matrix_gem`
#![cfg(feature = "setup-e2e")]

#[path = "setup_matrix_common/mod.rs"]
mod smc;

/// Documentation/negative-control pass through the shared Docker matrix.
/// Kept for parity with the other ecosystems and to run the gem negative
/// controls when Docker + the `gem` image are present. NOTE: this is the
/// path that silently no-ops on skip — it is NOT a regression guard. The
/// real teeth live in [`host_guard`] below.
#[test]
fn bundler() {
    smc::run_pm("gem", "bundler");
}

// ─────────────────────────────────────────────────────────────────────────
// Real, non-skippable regression guard for gem `setup`.
//
// A bundler project carries only a Gemfile (no package.json / Python /
// Cargo manifest), which `setup` does not support. The guard pins that
// no-op contract precisely so a regression (Gemfile mutation, crash,
// mis-detection, wrong exit code) turns this suite red even with no Docker.
// ─────────────────────────────────────────────────────────────────────────
mod host_guard {
    use std::path::Path;
    use std::process::Command;

    /// A faithful bundler project fixture, mirroring `scaffold_project`'s
    /// `bundler` branch in `tests/setup_matrix/run-case.sh` and the gem
    /// target's package/version in matrix.json (`colorize` @ `1.1.0`).
    const GEMFILE: &str = "source 'https://rubygems.org'\ngem 'colorize', '1.1.0'\n";

    /// Every `SOCKET_*` env var clap consults for the surface this test
    /// drives. Stripped from the child so the run reflects ONLY the explicit
    /// flags (`--cwd`, `--yes`, `--check`, `--remove`, `--json`). Without
    /// this, an ambient `SOCKET_CWD` / `SOCKET_JSON` / `SOCKET_OFFLINE` in
    /// the shell or CI could satisfy an assertion via the environment rather
    /// than the flag under test. (Mirrors the scrub used by the
    /// `cli_parse_*` and `setup_matrix_cargo` suites.)
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
    /// explicit flags alone — nothing reaches authed endpoints and no ambient
    /// var can stand in for a flag.
    fn run(cwd: &Path, args: &[&str]) -> (i32, String, String) {
        let mut cmd = Command::new(binary());
        cmd.args(args).current_dir(cwd);
        for var in SOCKET_ENV_VARS {
            cmd.env_remove(var);
        }
        let out = cmd.output().expect("failed to execute socket-patch binary");
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
        serde_json::from_str(stdout.trim())
            .unwrap_or_else(|e| panic!("{who}: stdout was not a single JSON object ({e}):\n{stdout}"))
    }

    fn json_str(v: &serde_json::Value, key: &str, who: &str) -> String {
        v.get(key)
            .and_then(|s| s.as_str())
            .unwrap_or_else(|| panic!("{who}: JSON has no string `{key}` field:\n{v}"))
            .to_string()
    }

    /// The Gemfile must be byte-for-byte what we wrote — `setup` (in any
    /// mode) operates on package.json / Python / Cargo manifests and must
    /// NEVER touch a bundler Gemfile.
    fn assert_gemfile_pristine(root: &Path, who: &str) {
        assert_eq!(
            std::fs::read_to_string(root.join("Gemfile")).unwrap(),
            GEMFILE,
            "{who}: Gemfile must be left byte-for-byte unchanged by setup"
        );
    }

    /// `setup`'s contract on a manifest it does not support is `no_files`
    /// with a clean exit (0) and zero side effects. This single helper pins
    /// every subcommand to that contract: a real boolean `no_files` status,
    /// exit 0, the `files` list empty, and the Gemfile untouched.
    fn assert_no_files(root: &Path, args: &[&str], who: &str) -> serde_json::Value {
        let (code, out, err) = run(root, args);
        assert_eq!(
            code, 0,
            "{who}: must exit 0 on an unsupported (Gemfile-only) project.\nstdout:\n{out}\nstderr:\n{err}"
        );
        let v = parse_json(&out, who);
        assert_eq!(
            json_str(&v, "status", who),
            "no_files",
            "{who}: a bundler project must report status=no_files (Gemfile is not a configurable manifest).\nstderr:\n{err}"
        );
        let files = v
            .get("files")
            .and_then(|f| f.as_array())
            .unwrap_or_else(|| panic!("{who}: JSON has no `files` array:\n{v}"));
        assert!(
            files.is_empty(),
            "{who}: no_files result must carry an EMPTY files list (the Gemfile must not be picked up as a manifest):\n{v}"
        );
        assert_gemfile_pristine(root, who);
        v
    }

    /// setup / setup --check / setup --remove against a real bundler project,
    /// asserting REAL on-disk + JSON state at every stage. This is the
    /// assertion the Docker matrix can never make for gem.
    #[test]
    fn gem_setup_roundtrip_host() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(root.join("Gemfile"), GEMFILE).unwrap();
        let root_s = root.to_str().unwrap();

        // ── pristine precondition ──────────────────────────────────────────
        // Pin the BEFORE state so the assertions prove the *binary* left the
        // Gemfile alone, not that the fixture happened to match afterwards.
        assert_gemfile_pristine(root, "fixture");
        assert!(
            !root.join("package.json").exists(),
            "fixture must not contain a package.json (would change the path under test)"
        );

        // ── check (before): no supported manifest → no_files, exit 0 ────────
        // `--check` returning exit 1 here would be wrong (there is nothing to
        // configure); returning `needs_configuration`/`configured` would mean
        // the Gemfile was mis-detected as an npm/python/cargo manifest.
        assert_no_files(root, &["setup", "--check", "--cwd", root_s, "--json"], "check (pristine)");

        // ── setup: must be a true no-op (no Gemfile mutation, nothing wired) ─
        let v = assert_no_files(root, &["setup", "--cwd", root_s, "--yes", "--json"], "setup");
        assert_eq!(
            v.get("updated").and_then(|n| n.as_i64()),
            Some(0),
            "setup on a bundler project must update zero manifests:\n{v}"
        );
        assert_eq!(
            v.get("errors").and_then(|n| n.as_i64()),
            Some(0),
            "setup on a bundler project must report zero errors:\n{v}"
        );
        // Defensively confirm setup created no stray hook artifacts.
        assert!(
            !root.join("package.json").exists(),
            "setup must NOT synthesize a package.json for a bundler project"
        );

        // ── check (after setup): still nothing to configure → no_files ──────
        // Proves `setup` did not silently configure something a later check
        // would then report as `configured` (which would flip exit to 0 for a
        // different, wrong reason).
        assert_no_files(
            root,
            &["setup", "--check", "--cwd", root_s, "--json"],
            "check (after setup)",
        );

        // ── remove: also a no-op on an unsupported project ──────────────────
        assert_no_files(root, &["setup", "--remove", "--cwd", root_s, "--yes", "--json"], "remove");
    }
}
