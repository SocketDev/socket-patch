//! setup-matrix: nuget ecosystem (dotnet). No native post-install hook,
//! `setup` is a no-op, and apply is additionally gated behind
//! `SOCKET_EXPERIMENTAL_NUGET` (the driver sets it). The with-setup
//! cases are an EXPECTED BASELINE GAP.
//!
//! IMPORTANT — why this file carries a real assertion of its own:
//! `smc::run_pm("nuget", "dotnet")` routes nuget through the shared Docker
//! matrix harness, which *soft-skips and silently passes* whenever Docker
//! or the `nuget` image is absent (the common case locally and in this
//! eval). nuget is also NOT npm-family (see `is_npm_family` in the harness
//! and `run-case.sh`), so the harness's check/remove behavioral
//! round-trip is skipped entirely for it; and because nuget's
//! `baseline_supported` is false in matrix.json the only thing the matrix
//! could ever assert is the coarse `actual_applied == expect_applied`
//! verdict — which, on a crashed or never-run case, defaults to the same
//! `false` that satisfies every negative-control scenario. The net
//! effect: the matrix call can never turn red for a genuine nuget `setup`
//! regression. On its own it protects nothing.
//!
//! To close that loophole WITHOUT touching the shared harness or the bash
//! driver, [`host_guard::nuget_setup_roundtrip_host`] runs unconditionally
//! (no Docker, no network, no dotnet toolchain) and pins nuget `setup`'s
//! *actual current contract*: a dotnet project carries only a `.csproj` —
//! a manifest `setup` does NOT support — so every `setup` subcommand must
//! report `no_files` (exit 0 for setup/remove; exit 0 for `--check`, since
//! "nothing to configure" is success not failure) and must leave the
//! `.csproj` byte-for-byte untouched. It reads on-disk state with an
//! *independent* probe (a hand-pinned constant, not a copy of any writer
//! output) so the oracle can disagree with a broken implementation. It
//! fails loudly if nuget `setup` ever starts mutating a `.csproj`, crashes
//! on a dotnet project, mis-classifies the `.csproj` as a configurable
//! manifest, or returns the wrong exit code / status.
//!
//! If `setup` ever GROWS real dotnet support, this guard's expectations
//! become wrong-by-design and must be upgraded to the deno-style positive
//! round-trip (check fails → setup configures → check passes → remove).
//! That is the intended signal: the test going red here means the baseline
//! gap closed, not that something broke.
//!
//! Run: `cargo test -p socket-patch-cli --features setup-e2e --test setup_matrix_nuget`
#![cfg(all(feature = "setup-e2e", feature = "nuget"))]

#[path = "setup_matrix_common/mod.rs"]
mod smc;

/// Documentation/negative-control pass through the shared Docker matrix.
/// Kept for parity with the other ecosystems and to run the nuget negative
/// controls when Docker + the `nuget` image are present. NOTE: this is the
/// path that silently no-ops on skip — it is NOT a regression guard. The
/// real teeth live in [`host_guard`] below.
#[test]
fn dotnet() {
    smc::run_pm("nuget", "dotnet");
}

// ─────────────────────────────────────────────────────────────────────────
// Real, non-skippable regression guard for nuget `setup`.
//
// A dotnet project carries only a `.csproj` (no package.json / Python /
// Cargo manifest), which `setup` does not support. The guard pins that
// no-op contract precisely so a regression (`.csproj` mutation, crash,
// mis-detection, wrong exit code) turns this suite red even with no Docker.
// ─────────────────────────────────────────────────────────────────────────
mod host_guard {
    use std::path::Path;
    use std::process::Command;

    /// Name of the project file written into the fixture.
    const CSPROJ_NAME: &str = "app.csproj";

    /// A faithful dotnet project fixture, mirroring the polyglot monorepo's
    /// `nuget-app/app.csproj` in `tests/setup_matrix/run-case.sh` and the
    /// nuget target's package/version in matrix.json
    /// (`Newtonsoft.Json` @ `13.0.3`).
    const CSPROJ: &str = "<Project Sdk=\"Microsoft.NET.Sdk\">\n  \
        <ItemGroup>\n    \
        <PackageReference Include=\"Newtonsoft.Json\" Version=\"13.0.3\" />\n  \
        </ItemGroup>\n</Project>\n";

    /// Every `SOCKET_*` env var clap consults for the surface this test
    /// drives. Stripped from the child so the run reflects ONLY the explicit
    /// flags (`--cwd`, `--yes`, `--check`, `--remove`, `--json`). Without
    /// this, an ambient `SOCKET_CWD` / `SOCKET_JSON` / `SOCKET_OFFLINE` in
    /// the shell or CI could satisfy an assertion via the environment rather
    /// than the flag under test. (Mirrors the scrub used by the
    /// `cli_parse_*` and `setup_matrix_cargo`/`setup_matrix_gem` suites.)
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
        "SOCKET_EXPERIMENTAL_NUGET",
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
    /// (loudly) if stdout is not the JSON object the command promises — a
    /// non-JSON / non-object dump means the command did not run the path we
    /// think it did.
    fn parse_json(stdout: &str, who: &str) -> serde_json::Value {
        let v: serde_json::Value = serde_json::from_str(stdout.trim())
            .unwrap_or_else(|e| panic!("{who}: stdout was not valid JSON ({e}):\n{stdout}"));
        assert!(
            v.is_object(),
            "{who}: stdout JSON must be a single object, got:\n{stdout}"
        );
        v
    }

    fn json_str(v: &serde_json::Value, key: &str, who: &str) -> String {
        v.get(key)
            .and_then(|s| s.as_str())
            .unwrap_or_else(|| panic!("{who}: JSON has no string `{key}` field:\n{v}"))
            .to_string()
    }

    /// The `.csproj` must be byte-for-byte what we wrote — `setup` (in any
    /// mode) operates on package.json / Python / Cargo manifests and must
    /// NEVER touch a dotnet project file.
    fn assert_csproj_pristine(root: &Path, who: &str) {
        assert_eq!(
            std::fs::read_to_string(root.join(CSPROJ_NAME)).unwrap(),
            CSPROJ,
            "{who}: {CSPROJ_NAME} must be left byte-for-byte unchanged by setup"
        );
    }

    /// `setup`'s contract on a manifest it does not support is `no_files`
    /// with a clean exit (0) and zero side effects. This single helper pins
    /// every subcommand to that contract: a `no_files` status, exit 0, the
    /// `files` list empty, and the `.csproj` untouched.
    fn assert_no_files(root: &Path, args: &[&str], who: &str) -> serde_json::Value {
        let (code, out, err) = run(root, args);
        assert_eq!(
            code, 0,
            "{who}: must exit 0 on an unsupported (.csproj-only) project.\nstdout:\n{out}\nstderr:\n{err}"
        );
        let v = parse_json(&out, who);
        assert_eq!(
            json_str(&v, "status", who),
            "no_files",
            "{who}: a dotnet project must report status=no_files (.csproj is not a configurable manifest).\nstderr:\n{err}"
        );
        let files = v
            .get("files")
            .and_then(|f| f.as_array())
            .unwrap_or_else(|| panic!("{who}: JSON has no `files` array:\n{v}"));
        assert!(
            files.is_empty(),
            "{who}: no_files result must carry an EMPTY files list (the .csproj must not be picked up as a manifest):\n{v}"
        );
        assert_csproj_pristine(root, who);
        v
    }

    /// setup / setup --check / setup --remove against a real dotnet project,
    /// asserting REAL on-disk + JSON state at every stage. This is the
    /// assertion the Docker matrix can never make for nuget.
    #[test]
    fn nuget_setup_roundtrip_host() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(root.join(CSPROJ_NAME), CSPROJ).unwrap();
        let root_s = root.to_str().unwrap();

        // ── pristine precondition ──────────────────────────────────────────
        // Pin the BEFORE state so the assertions prove the *binary* left the
        // .csproj alone, not that the fixture happened to match afterwards.
        assert_csproj_pristine(root, "fixture");
        assert!(
            !root.join("package.json").exists(),
            "fixture must not contain a package.json (would change the path under test)"
        );

        // ── check (before): no supported manifest → no_files, exit 0 ────────
        // `--check` returning exit 1 here would be wrong (there is nothing to
        // configure); returning `needs_configuration`/`configured` would mean
        // the .csproj was mis-detected as an npm/python/cargo manifest.
        assert_no_files(root, &["setup", "--check", "--cwd", root_s, "--json"], "check (pristine)");

        // ── setup: must be a true no-op (no .csproj mutation, nothing wired) ─
        let v = assert_no_files(root, &["setup", "--cwd", root_s, "--yes", "--json"], "setup");
        assert_eq!(
            v.get("updated").and_then(|n| n.as_i64()),
            Some(0),
            "setup on a dotnet project must update zero manifests:\n{v}"
        );
        assert_eq!(
            v.get("errors").and_then(|n| n.as_i64()),
            Some(0),
            "setup on a dotnet project must report zero errors:\n{v}"
        );
        assert_eq!(
            v.get("alreadyConfigured").and_then(|n| n.as_i64()),
            Some(0),
            "setup on a dotnet project must configure nothing (alreadyConfigured=0):\n{v}"
        );
        // Defensively confirm setup created no stray hook artifacts.
        assert!(
            !root.join("package.json").exists(),
            "setup must NOT synthesize a package.json for a dotnet project"
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

        // ── final: directory still holds exactly the one file we created ────
        // A stray sidecar/hook artifact left behind by any stage would betray
        // a non-no-op that the per-stage `files: []` check could miss.
        let entries: Vec<String> = std::fs::read_dir(root)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(
            entries,
            vec![CSPROJ_NAME.to_string()],
            "setup round-trip must leave ONLY the original {CSPROJ_NAME}; stray entries: {entries:?}"
        );
    }
}
