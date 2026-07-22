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
#![cfg(feature = "setup-e2e")]

#[path = "setup_matrix_common/mod.rs"]
mod smc;

/// Documentation/negative-control pass through the shared Docker matrix.
/// Kept for parity with the other ecosystems and to run the nuget negative
/// controls when Docker + the `nuget` image are present. NOTE: this is the
/// path that silently no-ops on skip — it is NOT a regression guard. The
/// real teeth live in [`host_guard`] below.
#[test]
// Experimental ecosystem (nuget): aspirational setup-matrix cases are a
// BASELINE GAP today; this passes on CI only because the runners lack `dotnet`
// (cases soft-skip) and fails on any host that has it. Ignore so nuget can
// never block the blocking --all-features jobs; `host_guard` below still pins
// the real no-op contract. Run with `--features setup-e2e,nuget -- --ignored`.
#[ignore = "experimental ecosystem (nuget): not gating CI until the nuget backend is implemented; run with --ignored"]
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

    /// Ambient decoys [`run`]'s prefix scrub must strip, planted by the test
    /// itself so the scrub is exercised on every run, not only in hostile
    /// shells. Three demonstrated failure classes on the old fixed-list scrub
    /// (same trio as `setup_matrix_maven`): clap parses env-bound
    /// `GlobalArgs` values on EVERY invocation whether or not the command
    /// uses the flag, so an invalid ambient `SOCKET_STRICT` /
    /// `SOCKET_VENDOR_SOURCE` aborts the parse (exit 2) before `setup` even
    /// runs; and a (perfectly valid!) ambient `SOCKET_SETUP_EXCLUDE` stands
    /// in for `setup --exclude`, which a real `setup` run PERSISTS —
    /// creating `.socket/manifest.json` inside the dotnet fixture and
    /// failing the final only-the-csproj assertion. `SOCKET_EXPERIMENTAL_NUGET`
    /// rides along so the experimental gate can never quietly change nuget's
    /// surface behind the test's back. (Safe to set process-wide: the only
    /// other test in this binary is the `#[ignore]`d matrix pass, which
    /// routes through `smc::host_driver_command`'s own `SOCKET_*` prefix
    /// scrub.)
    const HOSTILE_DECOYS: &[(&str, &str)] = &[
        ("SOCKET_STRICT", "banana"),
        ("SOCKET_VENDOR_SOURCE", "bogus-decoy"),
        ("SOCKET_SETUP_EXCLUDE", "decoy-member"),
        ("SOCKET_EXPERIMENTAL_NUGET", "true"),
    ];

    /// Absolute path to the binary under test, via cargo's `CARGO_BIN_EXE_*`.
    fn binary() -> std::path::PathBuf {
        env!("CARGO_BIN_EXE_socket-patch").into()
    }

    /// Run the CLI with `args` in `cwd`; returns `(exit_code, stdout, stderr)`.
    /// The entire `SOCKET_*` surface is stripped BY PREFIX — a fixed list rots
    /// (it missed `SOCKET_SETUP_EXCLUDE` / `SOCKET_VENDOR_SOURCE` /
    /// `SOCKET_STRICT`, all parsed on every `setup` invocation; see
    /// [`HOSTILE_DECOYS`]) — so behaviour reflects the explicit flags alone:
    /// nothing reaches authed endpoints and no ambient var can stand in for a
    /// flag.
    fn run(cwd: &Path, args: &[&str]) -> (i32, String, String) {
        let mut cmd = Command::new(binary());
        cmd.args(args).current_dir(cwd);
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("SOCKET_")
                && key.to_string_lossy() != "SOCKET_NO_CONFIG"
            {
                cmd.env_remove(&key);
            }
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
        // Committed regression guard for the env scrub itself: with the old
        // fixed-list scrub these leaked into the child — SOCKET_STRICT /
        // SOCKET_VENDOR_SOURCE aborted every parse (exit 2) and
        // SOCKET_SETUP_EXCLUDE made the real `setup` run write
        // `.socket/manifest.json` into the fixture (final entries check RED).
        for (k, v) in HOSTILE_DECOYS {
            std::env::set_var(k, v);
        }
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
        assert_no_files(
            root,
            &["setup", "--check", "--cwd", root_s, "--json"],
            "check (pristine)",
        );

        // ── setup: must be a true no-op (no .csproj mutation, nothing wired) ─
        let v = assert_no_files(
            root,
            &["setup", "--cwd", root_s, "--yes", "--json"],
            "setup",
        );
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
        assert_no_files(
            root,
            &["setup", "--remove", "--cwd", root_s, "--yes", "--json"],
            "remove",
        );

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
