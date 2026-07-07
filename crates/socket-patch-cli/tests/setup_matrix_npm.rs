//! setup-matrix: npm ecosystem (npm / yarn / pnpm / bun).
//!
//! These are the ecosystems `socket-patch setup` actually supports
//! today (it writes a package.json postinstall hook), so the
//! `baseline_with_setup` / `alt_content_patchset` cases are expected to
//! PASS here. See `setup_matrix_common/mod.rs` for the harness and
//! `tests/setup_matrix/matrix.json` for the case list.
//!
//! Run: `cargo test -p socket-patch-cli --features setup-e2e --test setup_matrix_npm`
#![cfg(feature = "setup-e2e")]

#[path = "setup_matrix_common/mod.rs"]
mod smc;

#[test]
fn npm() {
    smc::run_pm("npm", "npm");
}

#[test]
fn yarn() {
    smc::run_pm("npm", "yarn");
}

#[test]
fn pnpm() {
    smc::run_pm("npm", "pnpm");
}

#[test]
fn bun() {
    smc::run_pm("npm", "bun");
}

// ── Nested-workspace layouts ──────────────────────────────────────────
// A root + several members (incl. a deeply-nested one and a member with
// no dependency on the patched package). Exercises `setup`'s workspace
// handling (npm/yarn write the hook to every member; pnpm only to the
// root) plus the cross-workspace apply on the root install. These should
// PASS — they're real regression guards, not gap documentation.

#[test]
fn npm_workspace() {
    smc::run_workspace_pm("npm", "npm");
}

#[test]
fn pnpm_workspace() {
    smc::run_workspace_pm("npm", "pnpm");
}

#[test]
fn yarn_workspace() {
    smc::run_workspace_pm("npm", "yarn");
}

// ─────────────────────────────────────────────────────────────────────────
// Real, non-skippable regression guard for npm `setup`.
//
// IMPORTANT — why this file needs an assertion of its own:
// every `smc::run_pm` / `smc::run_workspace_pm` call above routes through the
// shared Docker matrix harness, which *soft-skips and silently passes* whenever
// Docker or the `npm` image is absent (the common case locally and in this
// eval). So for the one ecosystem `setup` genuinely supports today, the matrix
// calls can be entirely green having exercised NOTHING — a broken
// package.json-hook writer would never turn this file red.
//
// To close that loophole WITHOUT touching the shared harness, the module below
// adds a self-contained, host-only (no Docker, no network, no real npm
// toolchain) exercise of the actual `socket-patch` binary against a real
// package.json. It runs unconditionally and fails loudly if npm
// `setup` / `setup --check` / `setup --remove` regress. State is verified with
// an *independent* JSON read + raw substring probes (NOT the production
// `is_setup_configured` / `update_package_json` detectors), so the oracle can
// disagree with a broken writer.
// ─────────────────────────────────────────────────────────────────────────
mod host_guard {
    use std::path::Path;
    use std::process::Command;

    /// The apply command `setup` is supposed to inject into the npm lifecycle
    /// scripts. Hardcoded HERE (not imported from production) so a regression
    /// that drops/garbles the command is caught by an independent oracle. The
    /// detector accepts several variants; we pin the canonical npm one the
    /// writer emits for a lockfile-less project.
    const NPM_APPLY_CMD: &str = "@socketsecurity/socket-patch apply";
    const NPM_ECOSYSTEM_FLAG: &str = "--ecosystems npm";
    /// A pre-existing, user-authored postinstall step `setup` must PRESERVE
    /// (prepend the patch command before it, never clobber it).
    const USER_POSTINSTALL: &str = "echo user-build-step";

    /// Ambient decoys [`run`]'s prefix scrub must strip, planted by the test
    /// itself so the scrub is exercised on every run, not only in hostile
    /// shells. Two demonstrated failure classes on the old fixed-list scrub
    /// (same as the maven twin): clap parses env-bound `GlobalArgs` values on
    /// EVERY invocation whether or not the command uses the flag, so an
    /// invalid ambient `SOCKET_STRICT` / `SOCKET_VENDOR_SOURCE` aborts the
    /// parse (exit 2) before `setup` even runs — turning the whole roundtrip
    /// red; and a (perfectly valid!) ambient `SOCKET_SETUP_EXCLUDE` stands in
    /// for `setup --exclude`, silently altering the run under test. (Safe to
    /// set process-wide: every other test in this binary routes its children
    /// through `smc::host_driver_command`'s own `SOCKET_*` prefix scrub, and
    /// the harness's only ambient `SOCKET_*` read is `SOCKET_PATCH_TEST_HOST`,
    /// which the decoys don't touch.)
    const HOSTILE_DECOYS: &[(&str, &str)] = &[
        ("SOCKET_STRICT", "banana"),
        ("SOCKET_VENDOR_SOURCE", "bogus-decoy"),
        ("SOCKET_SETUP_EXCLUDE", "decoy-member"),
    ];

    fn binary() -> std::path::PathBuf {
        env!("CARGO_BIN_EXE_socket-patch").into()
    }

    /// Run the CLI with `args` in `cwd`; returns `(exit_code, stdout, stderr)`.
    /// The entire `SOCKET_*` surface is stripped BY PREFIX — a fixed list rots
    /// (it missed `SOCKET_SETUP_EXCLUDE` / `SOCKET_VENDOR_SOURCE` /
    /// `SOCKET_STRICT`, all parsed on every `setup` invocation; see
    /// [`HOSTILE_DECOYS`]) — so behaviour reflects the explicit flags alone:
    /// no ambient var can stand in for a flag or abort the parse.
    fn run(cwd: &Path, args: &[&str]) -> (i32, String, String) {
        let mut cmd = Command::new(binary());
        cmd.args(args).current_dir(cwd);
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("SOCKET_") {
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

    /// Independent oracle: parse package.json with serde_json (a plain JSON
    /// read, NOT the production setup detector) and return a named lifecycle
    /// script, if present and a string.
    fn lifecycle_script(root: &Path, key: &str) -> Option<String> {
        let text = std::fs::read_to_string(root.join("package.json")).unwrap();
        let val: serde_json::Value = serde_json::from_str(&text).unwrap_or_else(|e| {
            panic!("package.json is not valid JSON after CLI ran: {e}\n{text}")
        });
        val.get("scripts")
            .and_then(|s| s.get(key))
            .and_then(|v| v.as_str())
            .map(str::to_string)
    }

    fn stage_project(root: &Path) {
        // A package.json with a pre-existing postinstall step. No lockfile, so
        // the npm-family detector resolves to plain npm. No Cargo.toml /
        // pyproject, so only the npm branch of `setup` fires.
        std::fs::write(
            root.join("package.json"),
            format!(
                r#"{{
  "name": "sm-npm-host-guard",
  "version": "1.0.0",
  "private": true,
  "scripts": {{
    "postinstall": "{USER_POSTINSTALL}"
  }},
  "dependencies": {{}}
}}
"#
            ),
        )
        .unwrap();
    }

    /// setup → check → remove → check, asserting REAL on-disk package.json
    /// state at every stage. This is the assertion the soft-skipping Docker
    /// matrix can never make.
    #[test]
    fn npm_setup_roundtrip_host() {
        // Committed regression guard for the env scrub itself: with the old
        // fixed-list scrub these leaked into the child — SOCKET_STRICT /
        // SOCKET_VENDOR_SOURCE aborted every parse (exit 2, so the very first
        // `--check` assertion went red) and SOCKET_SETUP_EXCLUDE stood in for
        // `setup --exclude` on the real run.
        for (k, v) in HOSTILE_DECOYS {
            std::env::set_var(k, v);
        }
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        stage_project(root);
        let root_s = root.to_str().unwrap();

        // ── pristine precondition ──────────────────────────────────────────
        // Pin the BEFORE state so post-setup assertions prove `setup` CREATED
        // the hook, not that a leftover fixture already contained it.
        let pristine = std::fs::read_to_string(root.join("package.json")).unwrap();
        assert!(
            !pristine.contains(NPM_APPLY_CMD),
            "fixture must start WITHOUT the socket-patch hook:\n{pristine}"
        );
        assert_eq!(
            lifecycle_script(root, "postinstall").as_deref(),
            Some(USER_POSTINSTALL),
            "fixture must start with only the user's postinstall step"
        );

        // ── check (before setup): unconfigured → must report non-zero ──────
        // Proves `--check` reads real state instead of hardcoding success.
        let (code, out, err) = run(root, &["setup", "--check", "--cwd", root_s]);
        assert_eq!(
            code, 1,
            "setup --check must FAIL (exit 1) on an unconfigured project.\nstdout:\n{out}\nstderr:\n{err}"
        );

        // ── setup ──────────────────────────────────────────────────────────
        let (code, out, err) = run(root, &["setup", "--cwd", root_s, "--yes"]);
        assert_eq!(
            code, 0,
            "setup must succeed.\nstdout:\n{out}\nstderr:\n{err}"
        );

        // The postinstall hook must now carry the apply command AND the npm
        // ecosystem filter, run FIRST, and PRESERVE the user's original step.
        let post = lifecycle_script(root, "postinstall")
            .unwrap_or_else(|| panic!("postinstall script missing after setup"));
        assert!(
            post.contains(NPM_APPLY_CMD) && post.contains(NPM_ECOSYSTEM_FLAG),
            "postinstall must contain the npm apply command after setup, got: {post:?}"
        );
        assert!(
            post.contains(USER_POSTINSTALL),
            "setup must PRESERVE the user's existing postinstall step, got: {post:?}"
        );
        assert!(
            post.trim_start().starts_with("npx ")
                && post.find(NPM_APPLY_CMD) < post.find(USER_POSTINSTALL),
            "the patch apply command must be prepended to run BEFORE the user's step, got: {post:?}"
        );
        // setup also wires the `dependencies` lifecycle script (created fresh,
        // since the fixture had none).
        let deps = lifecycle_script(root, "dependencies")
            .unwrap_or_else(|| panic!("dependencies script missing after setup"));
        assert!(
            deps.contains(NPM_APPLY_CMD) && deps.contains(NPM_ECOSYSTEM_FLAG),
            "the `dependencies` lifecycle script must also be configured, got: {deps:?}"
        );

        // ── check (configured): must report zero ───────────────────────────
        let (code, out, err) = run(root, &["setup", "--check", "--cwd", root_s]);
        assert_eq!(
            code, 0,
            "setup --check must PASS (exit 0) after setup.\nstdout:\n{out}\nstderr:\n{err}"
        );

        // ── remove ──────────────────────────────────────────────────────────
        let (code, out, err) = run(root, &["setup", "--remove", "--cwd", root_s, "--yes"]);
        assert_eq!(
            code, 0,
            "setup --remove must succeed.\nstdout:\n{out}\nstderr:\n{err}"
        );

        // The apply command must be gone everywhere, and the user's original
        // postinstall step restored intact (not left mangled by the removal).
        let after = std::fs::read_to_string(root.join("package.json")).unwrap();
        assert!(
            !after.contains(NPM_APPLY_CMD),
            "the socket-patch apply command must be removed from package.json:\n{after}"
        );
        assert_eq!(
            lifecycle_script(root, "postinstall").as_deref(),
            Some(USER_POSTINSTALL),
            "remove must restore the user's original postinstall step verbatim:\n{after}"
        );

        // ── check (after remove): back to needs-configuration ───────────────
        let (code, out, err) = run(root, &["setup", "--check", "--cwd", root_s]);
        assert_eq!(
            code, 1,
            "setup --check must FAIL (exit 1) again after remove.\nstdout:\n{out}\nstderr:\n{err}"
        );
    }
}
