//! setup-matrix: pypi ecosystem (pip / uv / poetry / pdm / hatch).
//!
//! Python installers have no native post-install hook, so `socket-patch
//! setup` instead commits a `socket-patch-hook` dependency whose wheel ships
//! a startup `.pth` that re-applies patches after install
//! (package-manager-agnostic). pip, uv and hatch are wired + verified in
//! Docker: their `baseline_with_setup` / `alt_content_patchset` cases APPLY
//! (the harness builds the hook wheel and the driver installs it + fires an
//! interpreter). poetry / pdm are resolver-based — their `add`/`install`/`run`
//! re-resolve the whole manifest (now incl. the committed `socket-patch-hook`)
//! against a package index, which the hermetic test can't provide, so they
//! remain BASELINE GAPs (the mechanism is PM-agnostic and proven by the
//! others). Nested-workspace layouts are also still gaps. The negative-control
//! / empty / wrong-target cases must NOT apply for any of them.
//!
//! IMPORTANT — why this file carries a real assertion of its own:
//! every `smc::run_pm("pypi", …)` below routes through the shared Docker
//! matrix harness, which *soft-skips and silently passes* whenever Docker
//! or the `pypi` image is absent (the common case locally and in this
//! eval). On a skip the harness `return`s before running a single case, so
//! none of the `pip`/`uv`/… tests can ever turn red for a genuine pypi
//! `setup` regression. And even when Docker IS present, pypi is NOT
//! npm-family (see `is_npm_family` in the harness), so the harness's
//! behavioral check/remove round-trip is skipped for it entirely — the
//! only thing it asserts is the coarse `actual_applied == expect_applied`
//! verdict, whose missing-result fallback is the same `false` that
//! satisfies every negative-control scenario. On its own this file
//! protects nothing.
//!
//! To close that loophole WITHOUT touching the shared harness or the bash
//! driver, [`host_guard::pypi_setup_roundtrip_host`] runs unconditionally
//! (no Docker, no network, no Python toolchain — pip's `requirements.txt`
//! manifest needs no lockfile refresh, so the path is fully hermetic) and
//! exercises the REAL `socket-patch` binary against a real pip project:
//! `setup --check` (fails) → `setup` (adds `socket-patch[hook]`) →
//! `--check` (passes) → idempotent re-`setup` → `--remove` → `--check`
//! (fails again). It verifies on-disk `requirements.txt` bytes against a
//! hand-pinned golden (NOT a copy of any writer output) so the oracle can
//! disagree with a broken implementation, and pins the JSON envelope
//! (`status`, counts, `pythonPackageManager`, per-file `pth` entry) at
//! every stage. It fails loudly if pypi `setup` ever stops wiring the hook
//! dependency, mutates the wrong line, mis-reports its status/exit code,
//! or fails to round-trip cleanly back to the original manifest.
//!
//! Run: `cargo test -p socket-patch-cli --features setup-e2e --test setup_matrix_pypi`
#![cfg(feature = "setup-e2e")]

#[path = "setup_matrix_common/mod.rs"]
mod smc;

#[test]
fn pip() {
    smc::run_pm("pypi", "pip");
}

#[test]
fn uv() {
    smc::run_pm("pypi", "uv");
}

#[test]
fn poetry() {
    smc::run_pm("pypi", "poetry");
}

#[test]
fn pdm() {
    smc::run_pm("pypi", "pdm");
}

#[test]
fn hatch() {
    smc::run_pm("pypi", "hatch");
}

// ─────────────────────────────────────────────────────────────────────────
// Real, non-skippable regression guard for pypi `setup`.
//
// A pip project carries a `requirements.txt`, which `setup` DOES support:
// it commits the `socket-patch[hook]` dependency (the `.pth` post-install
// carrier). Unlike gem/go/deno (no-op `no_files` ecosystems), pypi has a
// positive contract, so this guard asserts the full configure round-trip
// rather than a no-op. It runs with no Docker, no network, and (for pip,
// whose `lock_command` is `None`) no external toolchain.
// ─────────────────────────────────────────────────────────────────────────
mod host_guard {
    use std::path::Path;
    use std::process::Command;

    /// Initial pip manifest. A single ordinary requirement so the assertions
    /// can prove `setup` appended the hook line WITHOUT disturbing the
    /// user's existing entries (order + content preserved).
    const REQ_INITIAL: &str = "requests==2.31.0\n";

    /// The exact bytes `setup` must produce for pip's `requirements.txt`:
    /// the original line, untouched, followed by the canonical
    /// `socket-patch[hook]` requirement on its own line. This golden is
    /// hand-derived from the documented contract (append `socket-patch[hook]`),
    /// NOT copied from a run of the writer — so it can disagree with a broken
    /// implementation that reorders, rewrites, or mangles the manifest.
    const REQ_WITH_HOOK: &str = "requests==2.31.0\nsocket-patch[hook]\n";

    /// Ambient decoys [`run`]'s prefix scrub must strip, planted by
    /// [`pypi_setup_roundtrip_host`] itself so the scrub is exercised on every
    /// run, not only in hostile shells. Three demonstrated failure classes on
    /// the old fixed-list scrub: clap parses env-bound `GlobalArgs` values on
    /// EVERY invocation whether or not the command uses the flag, so an
    /// invalid ambient `SOCKET_STRICT` / `SOCKET_VENDOR_SOURCE` aborts the
    /// parse (exit 2) before `setup` even runs; and a (perfectly valid!)
    /// ambient `SOCKET_SETUP_EXCLUDE` stands in for `setup --exclude`, which
    /// a real `setup` run PERSISTS into `.socket/manifest.json` inside the
    /// fixture. (Safe to set process-wide: every other test in this binary
    /// routes through either this module's [`run`] or
    /// `smc::host_driver_command`, both of which prefix-scrub `SOCKET_*`.)
    const HOSTILE_DECOYS: &[(&str, &str)] = &[
        ("SOCKET_STRICT", "banana"),
        ("SOCKET_VENDOR_SOURCE", "bogus-decoy"),
        ("SOCKET_SETUP_EXCLUDE", "decoy-member"),
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
        // This guard's contract is "no network" (module docs): `setup` fires a
        // usage-telemetry POST when telemetry is enabled, and the scrub above
        // would strip a developer's own opt-out. Force it off for the child —
        // no assertion here concerns telemetry.
        cmd.env("SOCKET_TELEMETRY_DISABLED", "1");
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
        serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
            panic!("{who}: stdout was not a single JSON object ({e}):\n{stdout}")
        })
    }

    fn json_str(v: &serde_json::Value, key: &str, who: &str) -> String {
        v.get(key)
            .and_then(|s| s.as_str())
            .unwrap_or_else(|| panic!("{who}: JSON has no string `{key}` field:\n{v}"))
            .to_string()
    }

    fn json_i64(v: &serde_json::Value, key: &str, who: &str) -> i64 {
        v.get(key)
            .and_then(|n| n.as_i64())
            .unwrap_or_else(|| panic!("{who}: JSON has no integer `{key}` field:\n{v}"))
    }

    /// Read `requirements.txt` and assert it is byte-for-byte `expected`. The
    /// independent on-disk oracle: it never calls production parsing code, so
    /// a writer that produces a "looks-configured" but wrong manifest fails.
    fn assert_requirements(root: &Path, expected: &str, who: &str) {
        let got = std::fs::read_to_string(root.join("requirements.txt"))
            .unwrap_or_else(|e| panic!("{who}: requirements.txt unreadable: {e}"));
        assert_eq!(got, expected, "{who}: requirements.txt bytes mismatch");
    }

    /// Find the single `files[]` entry whose `kind == "pth"` (the Python
    /// manifest). Fails if absent — a setup/check that reports no `pth` entry
    /// never touched the Python manifest the test is about.
    fn pth_entry(v: &serde_json::Value, who: &str) -> serde_json::Value {
        v.get("files")
            .and_then(|f| f.as_array())
            .unwrap_or_else(|| panic!("{who}: JSON has no `files` array:\n{v}"))
            .iter()
            .find(|e| e.get("kind").and_then(|k| k.as_str()) == Some("pth"))
            .unwrap_or_else(|| panic!("{who}: no files[] entry with kind=\"pth\":\n{v}"))
            .clone()
    }

    /// Independent textual probe: is the exact `socket-patch[hook]`
    /// requirement present as its own line (comment-stripped)? Deliberately
    /// does NOT use `deps_contain_hook` (the production detector) so the
    /// oracle can disagree with a broken writer.
    fn has_hook_line(content: &str) -> bool {
        content.lines().any(|l| {
            let spec = l.split('#').next().unwrap_or("").trim();
            spec == "socket-patch[hook]"
        })
    }

    /// setup --check → setup → --check → re-setup → --remove → --check against
    /// a real pip project, asserting REAL on-disk + JSON state at every stage.
    /// This is the assertion the Docker matrix can never make for pypi.
    #[test]
    fn pypi_setup_roundtrip_host() {
        // Committed regression guard for the env scrub itself: with the old
        // fixed-list scrub these leaked into the child — SOCKET_STRICT /
        // SOCKET_VENDOR_SOURCE aborted every parse (exit 2) and
        // SOCKET_SETUP_EXCLUDE made the real `setup` run write
        // `.socket/manifest.json` into the fixture.
        for (k, v) in HOSTILE_DECOYS {
            std::env::set_var(k, v);
        }
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(root.join("requirements.txt"), REQ_INITIAL).unwrap();
        let root_s = root.to_str().unwrap();

        // ── pristine precondition ──────────────────────────────────────────
        // Pin the BEFORE state so the post-setup assertions prove `setup`
        // *added* the hook line, not that a leftover fixture already had it.
        assert_requirements(root, REQ_INITIAL, "fixture");
        assert!(
            !has_hook_line(REQ_INITIAL),
            "fixture must start WITHOUT the hook dependency"
        );
        assert!(
            !root.join("package.json").exists(),
            "fixture must not contain a package.json (would change the path under test)"
        );

        // ── check (before setup): unconfigured → exit 1, needs_configuration ─
        let (code, out, err) = run(root, &["setup", "--check", "--cwd", root_s, "--json"]);
        assert_eq!(
            code, 1,
            "setup --check must FAIL (exit 1) on a pristine pip project.\nstdout:\n{out}\nstderr:\n{err}"
        );
        let v = parse_json(&out, "check (pristine)");
        assert_eq!(
            json_str(&v, "status", "check (pristine)"),
            "needs_configuration",
            "pristine pip project must report needs_configuration:\n{v}"
        );
        assert_eq!(
            json_str(
                &pth_entry(&v, "check (pristine)"),
                "status",
                "check (pristine) pth"
            ),
            "needs_configuration",
            "the requirements.txt pth entry must read needs_configuration before setup:\n{v}"
        );
        // --check must NEVER write — manifest still pristine.
        assert_requirements(root, REQ_INITIAL, "after check (pristine)");

        // ── setup: must append the hook dep and report success ──────────────
        let (code, out, err) = run(root, &["setup", "--cwd", root_s, "--yes", "--json"]);
        assert_eq!(
            code, 0,
            "setup must succeed.\nstdout:\n{out}\nstderr:\n{err}"
        );
        let v = parse_json(&out, "setup");
        assert_eq!(
            json_str(&v, "status", "setup"),
            "success",
            "setup on a pip project must report status=success:\n{v}"
        );
        assert_eq!(
            json_i64(&v, "updated", "setup"),
            1,
            "setup must update exactly one manifest (requirements.txt):\n{v}"
        );
        assert_eq!(
            json_i64(&v, "errors", "setup"),
            0,
            "setup must report zero errors:\n{v}"
        );
        assert_eq!(
            json_str(&v, "pythonPackageManager", "setup"),
            "pip",
            "a requirements.txt-only project must be detected as pip:\n{v}"
        );
        let e = pth_entry(&v, "setup");
        assert_eq!(
            json_str(&e, "status", "setup pth"),
            "updated",
            "the requirements.txt pth entry must report updated:\n{v}"
        );
        assert!(
            json_str(&e, "path", "setup pth").ends_with("requirements.txt"),
            "the pth entry must point at requirements.txt:\n{v}"
        );
        // The decisive on-disk check: exact golden bytes (line preserved + hook
        // appended), verified WITHOUT the production parser.
        assert_requirements(root, REQ_WITH_HOOK, "after setup");
        assert!(
            !root.join("package.json").exists(),
            "setup must NOT synthesize a package.json for a pip project"
        );

        // ── check (after setup): configured → exit 0 ────────────────────────
        let (code, out, err) = run(root, &["setup", "--check", "--cwd", root_s, "--json"]);
        assert_eq!(
            code, 0,
            "setup --check must PASS (exit 0) after setup.\nstdout:\n{out}\nstderr:\n{err}"
        );
        let v = parse_json(&out, "check (configured)");
        assert_eq!(
            json_str(&v, "status", "check (configured)"),
            "configured",
            "after setup the project must report configured:\n{v}"
        );
        assert_eq!(
            json_str(
                &pth_entry(&v, "check (configured)"),
                "status",
                "check (configured) pth"
            ),
            "configured",
            "the requirements.txt pth entry must read configured after setup:\n{v}"
        );

        // ── idempotent re-setup: no further change ──────────────────────────
        let (code, out, err) = run(root, &["setup", "--cwd", root_s, "--yes", "--json"]);
        assert_eq!(
            code, 0,
            "re-setup must succeed.\nstdout:\n{out}\nstderr:\n{err}"
        );
        let v = parse_json(&out, "re-setup");
        assert_eq!(
            json_str(&v, "status", "re-setup"),
            "already_configured",
            "a second setup must be a no-op (already_configured), not re-append:\n{v}"
        );
        assert_eq!(
            json_i64(&v, "updated", "re-setup"),
            0,
            "re-setup must update zero manifests:\n{v}"
        );
        // No duplicate hook line written.
        assert_requirements(root, REQ_WITH_HOOK, "after re-setup");

        // ── remove: strip the hook dep, restore the original manifest ───────
        let (code, out, err) = run(
            root,
            &["setup", "--remove", "--cwd", root_s, "--yes", "--json"],
        );
        assert_eq!(
            code, 0,
            "setup --remove must succeed.\nstdout:\n{out}\nstderr:\n{err}"
        );
        let v = parse_json(&out, "remove");
        assert_eq!(
            json_str(&v, "status", "remove"),
            "success",
            "remove must report status=success:\n{v}"
        );
        assert_eq!(
            json_i64(&v, "removed", "remove"),
            1,
            "remove must strip exactly one hook dependency:\n{v}"
        );
        assert_eq!(
            json_str(&pth_entry(&v, "remove"), "status", "remove pth"),
            "removed",
            "the requirements.txt pth entry must report removed:\n{v}"
        );
        // Manifest must be byte-for-byte back to the original (no orphaned
        // blank line, no mangled user requirement).
        assert_requirements(root, REQ_INITIAL, "after remove");

        // ── check (after remove): back to needs-configuration → exit 1 ──────
        let (code, out, err) = run(root, &["setup", "--check", "--cwd", root_s, "--json"]);
        assert_eq!(
            code, 1,
            "setup --check must FAIL (exit 1) again after remove.\nstdout:\n{out}\nstderr:\n{err}"
        );
        let v = parse_json(&out, "check (after remove)");
        assert_eq!(
            json_str(&v, "status", "check (after remove)"),
            "needs_configuration",
            "after remove the project must report needs_configuration again:\n{v}"
        );

        for (k, _) in HOSTILE_DECOYS {
            std::env::remove_var(k);
        }
    }

    /// Regression: a commented-out hook line is NOT a configured project.
    ///
    /// pip never installs a `# socket-patch[hook]` comment, and plain `setup`
    /// (whose `requirements_add` strips comments before probing) would still
    /// append the hook — but the `--check` probe read the raw file and saw the
    /// marker inside the comment, reporting `configured` (exit 0) for a
    /// project with no hook at all. Check and setup must agree on the same
    /// bytes.
    #[test]
    fn pypi_check_ignores_commented_out_hook_host() {
        const REQ_COMMENTED: &str = "requests==2.31.0\n# socket-patch[hook]\n";
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let root_s = root.to_str().unwrap();
        std::fs::write(root.join("requirements.txt"), REQ_COMMENTED).unwrap();
        assert!(
            !has_hook_line(REQ_COMMENTED),
            "fixture: the commented-out line must not count as a hook line"
        );

        let (code, out, err) = run(root, &["setup", "--check", "--cwd", root_s, "--json"]);
        assert_eq!(
            code, 1,
            "setup --check must FAIL (exit 1): a commented-out hook dep is not \
             configured.\nstdout:\n{out}\nstderr:\n{err}"
        );
        let v = parse_json(&out, "check (commented-out)");
        assert_eq!(
            json_str(&v, "status", "check (commented-out)"),
            "needs_configuration",
            "a commented-out hook line must report needs_configuration:\n{v}"
        );
        assert_eq!(
            json_str(
                &pth_entry(&v, "check (commented-out)"),
                "status",
                "check (commented-out) pth"
            ),
            "needs_configuration",
            "the requirements.txt pth entry must read needs_configuration:\n{v}"
        );
        // --check must NEVER write.
        assert_requirements(root, REQ_COMMENTED, "after check (commented-out)");
    }

    /// Regression: classic-Poetry projects.
    ///
    /// `setup` writes the hook into a Poetry manifest as the *structural*
    /// `socket-patch = { version = "*", extras = ["hook"] }` — which has NO
    /// literal `socket-patch[hook]` substring. A `setup --check` that probes
    /// the manifest *textually* would therefore report a freshly-and-correctly
    /// configured Poetry project as `needs_configuration` (exit 1), breaking
    /// the setup→check round-trip. This guard pins the structural detection by
    /// running the real binary against a hand-authored Poetry manifest in each
    /// state. Fully hermetic: `--check` neither writes nor refreshes a lockfile.
    #[test]
    fn poetry_check_recognizes_structural_hook_host() {
        // ── configured: the exact structural form `setup` emits ─────────────
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let root_s = root.to_str().unwrap();
        std::fs::write(
            root.join("pyproject.toml"),
            "[tool.poetry]\nname = \"x\"\nversion = \"0.1.0\"\n\n\
             [tool.poetry.dependencies]\npython = \"^3.9\"\n\
             socket-patch = {version = \"*\", extras = [\"hook\"]}\n",
        )
        .unwrap();

        let (code, out, err) = run(root, &["setup", "--check", "--cwd", root_s, "--json"]);
        assert_eq!(
            code, 0,
            "setup --check must PASS (exit 0) for a Poetry project carrying the \
             structural hook extra.\nstdout:\n{out}\nstderr:\n{err}"
        );
        let v = parse_json(&out, "poetry check (configured)");
        assert_eq!(
            json_str(&v, "status", "poetry check (configured)"),
            "configured",
            "structurally-configured Poetry project must report configured:\n{v}"
        );
        assert_eq!(
            json_str(
                &pth_entry(&v, "poetry check (configured)"),
                "status",
                "poetry check (configured) pth"
            ),
            "configured",
            "the pyproject pth entry must read configured:\n{v}"
        );

        // ── unconfigured: a plain socket-patch dep (no hook) is NOT enough ──
        let tmp2 = tempfile::tempdir().unwrap();
        let root2 = tmp2.path();
        let root2_s = root2.to_str().unwrap();
        std::fs::write(
            root2.join("pyproject.toml"),
            "[tool.poetry]\nname = \"x\"\nversion = \"0.1.0\"\n\n\
             [tool.poetry.dependencies]\npython = \"^3.9\"\nsocket-patch = \"^3.3.0\"\n",
        )
        .unwrap();
        let (code, out, err) = run(root2, &["setup", "--check", "--cwd", root2_s, "--json"]);
        assert_eq!(
            code, 1,
            "setup --check must FAIL (exit 1) for a Poetry project whose \
             socket-patch dep carries no hook extra.\nstdout:\n{out}\nstderr:\n{err}"
        );
        let v = parse_json(&out, "poetry check (unconfigured)");
        assert_eq!(
            json_str(&v, "status", "poetry check (unconfigured)"),
            "needs_configuration",
            "a hook-less Poetry project must report needs_configuration:\n{v}"
        );
    }
}

// ── Nested-workspace layouts (EXPECTED BASELINE GAP) ──────────────────
// uv workspace (root + members, one shared .venv) and a pip
// nested-requirements monorepo. Python has no post-install hook, so
// these don't apply today — but the install itself must succeed.

#[test]
fn pip_workspace() {
    smc::run_workspace_pm("pypi", "pip");
}

#[test]
fn uv_workspace() {
    smc::run_workspace_pm("pypi", "uv");
}
