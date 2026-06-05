//! setup-matrix: cargo ecosystem.
//!
//! This Docker-based matrix exercises the *install → apply → patched-file-on-disk*
//! flow. Cargo's local backend redirects to a project-local **copy** via
//! `[patch.crates-io]` rather than patching the installed crate in place, and
//! the patch is consumed at `cargo build` resolution time (by the
//! `socket-patch-guard` build script), so there is no in-place file mutation
//! for this harness to observe — the with-setup cases remain an EXPECTED
//! BASELINE GAP *here*. The real cargo `setup`/`apply`/`rollback`/`--check`
//! behaviour is covered by the dedicated, non-Docker suites:
//!   * `setup_cargo_roundtrip.rs` — setup → check → remove → check + user
//!     `build.rs` untouched;
//!   * `e2e_cargo_coexist.rs` — apply redirect + registry isolation, reconcile,
//!     rollback, self-heal, and `--check` drift detection.
//!
//! IMPORTANT — why this file carries a real assertion of its own:
//! `smc::run_pm("cargo", "cargo")` routes cargo through the shared Docker
//! matrix harness, which (a) *soft-skips and silently passes* whenever Docker
//! or the `cargo` image is absent (the common case locally and in this eval),
//! and (b) when it DOES run, it models "applied" as an in-place file mutation —
//! which cargo's redirect backend never performs — so every with-setup cargo
//! case is classified as a non-fatal `BASELINE GAP`. The net effect is that the
//! matrix call can *never* turn red for a genuine cargo `setup` regression: it
//! is either skipped (green) or it fails as a documented gap (also tolerated by
//! the non-blocking suite). On its own it protects nothing.
//!
//! To close that loophole WITHOUT touching the shared harness, this file adds
//! [`cargo_setup_roundtrip_host`]: a self-contained, host-only (no Docker, no
//! network, no real `cargo` toolchain) exercise of the actual `socket-patch`
//! binary against a real cargo project. It runs unconditionally and fails
//! loudly if cargo `setup` / `setup --check` / `setup --remove` regress. It
//! deliberately checks state with an *independent* hand-rolled TOML probe (not
//! the production parser) so the oracle can disagree with a broken writer.
//!
//! Run: `cargo test -p socket-patch-cli --features setup-e2e --test setup_matrix_cargo`
#![cfg(feature = "setup-e2e")]

#[path = "setup_matrix_common/mod.rs"]
mod smc;

/// Documentation/negative-control pass through the shared Docker matrix.
/// Kept for parity with the other ecosystems and to run the cargo negative
/// controls when Docker + the `cargo` image are present. NOTE: this is the
/// path that silently no-ops on skip — it is NOT a regression guard. The real
/// teeth live in [`cargo_setup_roundtrip_host`] below.
#[test]
fn cargo() {
    smc::run_pm("cargo", "cargo");
}

// ─────────────────────────────────────────────────────────────────────────
// Real, non-skippable regression guard for cargo `setup`.
//
// Only meaningful when the binary was built with the `cargo` feature (the
// default). Under `--no-default-features` the binary's cargo `setup` fails
// closed, so the assertion is intentionally compiled out there.
// ─────────────────────────────────────────────────────────────────────────
#[cfg(feature = "cargo")]
mod host_guard {
    use std::path::Path;
    use std::process::Command;

    const USER_BUILD_RS: &str = "fn main() {\n    println!(\"cargo:rerun-if-changed=build.rs\");\n}\n";

    /// Every `SOCKET_*` env var clap consults for the surface this test drives.
    /// They are stripped from the child so the run reflects ONLY the explicit
    /// flags (`--cwd`, `--yes`, `--check`, `--remove`). Without this, an ambient
    /// `SOCKET_CWD` / `SOCKET_YES` / `SOCKET_OFFLINE` in the shell or CI could
    /// satisfy an assertion via the environment rather than the flag under test
    /// — masking a regression in flag wiring. (Mirrors the scrub used by the
    /// `cli_parse_*` suites.)
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
        // cargo redirect-backend specific knobs.
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

    fn stage_single_crate(root: &Path) {
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"sm-cargo-proj\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\ncfg-if = \"=1.0.0\"\n",
        )
        .unwrap();
        std::fs::write(root.join("src/main.rs"), "fn main() {}\n").unwrap();
        // A user-authored build.rs that setup must NEVER rewrite (the
        // regression the dedicated guard crate buys us).
        std::fs::write(root.join("build.rs"), USER_BUILD_RS).unwrap();
    }

    // ── independent (dependency-free) TOML probe ──────────────────────────
    //
    // Deliberately does NOT use the production `toml_edit` parser — that is the
    // very code path under test, so reusing it would make the oracle circular.
    // A minimal hand-rolled scan keeps the test honest: it can disagree with a
    // broken writer.
    //
    /// Right-hand side of `key = <rhs>` inside the `[section]` table of `doc`,
    /// scanning only until the next table header. `None` if absent. Top-level
    /// keys use `section == ""`.
    fn toml_value_in_section(doc: &str, section: &str, key: &str) -> Option<String> {
        let header = format!("[{section}]");
        let mut in_section = section.is_empty();
        for line in doc.lines() {
            let t = line.trim();
            if t.starts_with('#') || t.is_empty() {
                continue;
            }
            if t.starts_with('[') {
                in_section = t == header;
                continue;
            }
            if in_section {
                if let Some((k, v)) = t.split_once('=') {
                    if k.trim() == key {
                        return Some(v.trim().to_string());
                    }
                }
            }
        }
        None
    }

    /// Assert the guard dep is a real `[dependencies].socket-patch-guard` entry
    /// carrying a plausible quoted `"<major>.<minor>"` version — not a substring
    /// in a comment, nor a path/table form, nor an empty value.
    fn assert_guard_dep_versioned(toml: &str, who: &str) {
        let rhs = toml_value_in_section(toml, "dependencies", "socket-patch-guard")
            .unwrap_or_else(|| panic!("no [dependencies].socket-patch-guard in {who}:\n{toml}"));
        let inner = rhs
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .unwrap_or_else(|| {
                panic!("guard dep in {who} is not a quoted version string: {rhs}\n{toml}")
            });
        let parts: Vec<&str> = inner.split('.').collect();
        assert!(
            parts.len() >= 2
                && parts
                    .iter()
                    .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())),
            "guard dep version in {who} is not a numeric major.minor: {inner:?}\n{toml}"
        );
    }

    /// setup → check → remove → check, asserting REAL on-disk state at every
    /// stage. This is the assertion the Docker matrix can never make for cargo.
    #[test]
    fn cargo_setup_roundtrip_host() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        stage_single_crate(root);
        let root_s = root.to_str().unwrap();

        // ── pristine precondition ──────────────────────────────────────────
        // Pin the BEFORE state so the post-setup assertions genuinely prove
        // that `setup` *created* the redirect config — not that a leftover
        // fixture happened to already contain it.
        let pristine_toml = std::fs::read_to_string(root.join("Cargo.toml")).unwrap();
        assert!(
            toml_value_in_section(&pristine_toml, "dependencies", "socket-patch-guard").is_none()
                && !pristine_toml.contains("socket-patch-guard"),
            "fixture must start WITHOUT the guard dep:\n{pristine_toml}"
        );
        assert!(
            !root.join(".cargo/config.toml").exists(),
            ".cargo/config.toml must not exist before setup"
        );

        // ── check (before setup): unconfigured → must report non-zero ──────
        // Proves `--check` reads real state instead of hardcoding success.
        let (code, out, err) = run(root, &["setup", "--check", "--cwd", root_s]);
        assert_eq!(
            code, 1,
            "setup --check must FAIL (exit 1) on a pristine, unconfigured project.\nstdout:\n{out}\nstderr:\n{err}"
        );

        // ── setup ──────────────────────────────────────────────────────────
        let (code, out, err) = run(root, &["setup", "--cwd", root_s, "--yes"]);
        assert_eq!(code, 0, "setup must succeed.\nstdout:\n{out}\nstderr:\n{err}");

        let toml = std::fs::read_to_string(root.join("Cargo.toml")).unwrap();
        assert_guard_dep_versioned(&toml, "Cargo.toml");

        // The redirect backend hinges on this exact relative-root [env] spec;
        // a key with an empty/absolute/non-relative value would silently break
        // build-time resolution, so pin it precisely.
        let config = std::fs::read_to_string(root.join(".cargo/config.toml"))
            .unwrap_or_else(|e| panic!(".cargo/config.toml must exist after setup: {e}"));
        let env_rhs = toml_value_in_section(&config, "env", "SOCKET_PATCH_ROOT")
            .unwrap_or_else(|| panic!("[env] SOCKET_PATCH_ROOT missing:\n{config}"));
        let normalized: String = env_rhs.split_whitespace().collect::<Vec<_>>().join(" ");
        assert_eq!(
            normalized,
            r#"{ value = ".", relative = true }"#,
            "[env] SOCKET_PATCH_ROOT must be the relative project-root spec, got: {env_rhs}\n{config}"
        );

        // The user's build.rs is untouched, byte-for-byte.
        assert_eq!(
            std::fs::read_to_string(root.join("build.rs")).unwrap(),
            USER_BUILD_RS,
            "setup must never modify a user's build.rs"
        );

        // ── check (configured): must report zero ───────────────────────────
        let (code, out, err) = run(root, &["setup", "--check", "--cwd", root_s]);
        assert_eq!(
            code, 0,
            "setup --check must PASS (exit 0) after setup.\nstdout:\n{out}\nstderr:\n{err}"
        );

        // ── remove ──────────────────────────────────────────────────────────
        let (code, out, err) = run(root, &["setup", "--remove", "--cwd", root_s, "--yes"]);
        assert_eq!(code, 0, "setup --remove must succeed.\nstdout:\n{out}\nstderr:\n{err}");

        let toml = std::fs::read_to_string(root.join("Cargo.toml")).unwrap();
        assert!(
            toml_value_in_section(&toml, "dependencies", "socket-patch-guard").is_none()
                && !toml.contains("socket-patch-guard"),
            "guard dep must be removed from Cargo.toml:\n{toml}"
        );
        let config = std::fs::read_to_string(root.join(".cargo/config.toml")).unwrap_or_default();
        assert!(
            toml_value_in_section(&config, "env", "SOCKET_PATCH_ROOT").is_none()
                && !config.contains("SOCKET_PATCH_ROOT"),
            "[env] SOCKET_PATCH_ROOT must be removed:\n{config}"
        );

        // build.rs still pristine after remove.
        assert_eq!(
            std::fs::read_to_string(root.join("build.rs")).unwrap(),
            USER_BUILD_RS,
            "setup --remove must never modify a user's build.rs"
        );

        // ── check (after remove): back to needs-configuration ───────────────
        let (code, out, err) = run(root, &["setup", "--check", "--cwd", root_s]);
        assert_eq!(
            code, 1,
            "setup --check must FAIL (exit 1) again after remove.\nstdout:\n{out}\nstderr:\n{err}"
        );
    }
}
