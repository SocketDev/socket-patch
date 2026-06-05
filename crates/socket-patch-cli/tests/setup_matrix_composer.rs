//! setup-matrix: composer ecosystem (PHP). Composer DOES expose a
//! `post-install-cmd` event hook, but `setup` does not wire it today,
//! so the with-setup cases are an EXPECTED BASELINE GAP — and a clear
//! candidate for the first non-npm ecosystem `setup` could support.
//!
//! IMPORTANT — why this file carries a real assertion of its own:
//! `smc::run_pm("composer", "composer")` routes composer through the
//! shared Docker matrix harness, which *soft-skips and silently passes*
//! whenever Docker or the `composer` image is absent (the common case
//! locally and in this eval). composer is also NOT npm-family, so the
//! harness's check/remove behavioral round-trip is skipped entirely for
//! it, and — because `baseline_supported` is false in matrix.json — the
//! only thing the matrix could ever assert is that the patch is *not*
//! applied (a verdict that defaults to the same `false` on a crashed or
//! never-run case). The net effect: the matrix call can never turn red
//! for a genuine composer `setup` regression. On its own it protects
//! nothing.
//!
//! To close that loophole WITHOUT touching the shared harness,
//! [`host_guard::composer_setup_is_a_clean_noop_host`] runs
//! unconditionally (no Docker, no network, no PHP / composer toolchain)
//! and pins composer `setup`'s *actual current contract*: because no
//! composer install hook is wired, `setup` / `setup --check` /
//! `setup --remove` against a composer-only project must each be a clean
//! no-op (`status: "no_files"`, exit 0) that leaves `composer.json`
//! byte-for-byte intact and never injects a foreign npm `package.json`
//! hook. It fails loudly if composer setup ever starts erroring,
//! crashing, mutating the PHP manifest, or silently mis-reporting the
//! project as configured — and it will also (correctly) go red the day
//! real composer support lands, flagging that this expectation must be
//! updated rather than the gap quietly persisting.
//!
//! Run: `cargo test -p socket-patch-cli --features setup-e2e --test setup_matrix_composer`
#![cfg(feature = "setup-e2e")]

#[path = "setup_matrix_common/mod.rs"]
mod smc;

/// Documentation/negative-control pass through the shared Docker matrix.
/// Kept for parity with the other ecosystems and to run the composer
/// negative controls when Docker + the `composer` image are present.
/// NOTE: this is the path that silently no-ops on skip — it is NOT a
/// regression guard. The real teeth live in [`host_guard`] below.
#[test]
fn composer() {
    smc::run_pm("composer", "composer");
}

// ─────────────────────────────────────────────────────────────────────────
// Real, non-skippable regression guard for composer `setup`.
//
// Locks in the BASELINE GAP as a concrete, machine-checkable contract:
// composer is unsupported, therefore setup must treat a composer-only
// project as "nothing to do" — exit 0, status "no_files", manifest
// untouched, and crucially WITHOUT inventing an npm package.json hook in
// a PHP project.
// ─────────────────────────────────────────────────────────────────────────
mod host_guard {
    use std::path::Path;
    use std::process::Command;

    /// A realistic composer-only project: a PHP manifest requiring the
    /// same package the matrix targets, and nothing the npm/Python/Cargo
    /// detectors would recognise.
    const COMPOSER_JSON: &str = "{\n  \"name\": \"acme/widget\",\n  \"require\": {\n    \"monolog/monolog\": \"3.5.0\"\n  }\n}\n";

    /// Absolute path to the binary under test, via cargo's `CARGO_BIN_EXE_*`.
    fn binary() -> std::path::PathBuf {
        env!("CARGO_BIN_EXE_socket-patch").into()
    }

    /// Run the CLI with `args` in `cwd`; returns `(exit_code, stdout, stderr)`.
    /// `SOCKET_API_TOKEN` is stripped so nothing reaches authed endpoints.
    fn run(cwd: &Path, args: &[&str]) -> (i32, String, String) {
        let out = Command::new(binary())
            .args(args)
            .current_dir(cwd)
            .env_remove("SOCKET_API_TOKEN")
            .output()
            .expect("failed to execute socket-patch binary");
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).to_string(),
            String::from_utf8_lossy(&out.stderr).to_string(),
        )
    }

    /// Parse the CLI's `--json` stdout into the single top-level object the
    /// command promises. Panics (loudly) if stdout is not exactly that — a
    /// non-JSON / multi-line dump means the command did not run the path we
    /// think it did.
    fn parse_obj(stdout: &str, who: &str) -> serde_json::Value {
        serde_json::from_str(stdout.trim())
            .unwrap_or_else(|e| panic!("{who}: stdout was not a single JSON object ({e}):\n{stdout}"))
    }

    /// Assert the parsed result is a genuine clean no-op for an unsupported
    /// ecosystem: `status == "no_files"` AND an *empty* `files` array. The
    /// `files` check is not redundant — a regression that mis-detected the
    /// composer manifest could keep `status: "no_files"` while listing files
    /// it touched, or vice versa; both must agree that nothing was done.
    fn assert_no_files_status(stdout: &str, who: &str) {
        let v = parse_obj(stdout, who);
        assert_eq!(
            v.get("status").and_then(|s| s.as_str()),
            Some("no_files"),
            "{who}: must report status=no_files for a composer-only project; \
             any other status (esp. \"configured\") would falsely claim composer is supported.\n{stdout}"
        );
        let files = v
            .get("files")
            .and_then(|f| f.as_array())
            .unwrap_or_else(|| panic!("{who}: JSON has no `files` array:\n{stdout}"));
        assert!(
            files.is_empty(),
            "{who}: a no_files result must carry an EMPTY files array; \
             a non-empty list means setup acted on something it claims not to have.\n{stdout}"
        );
    }

    /// Immediate entry names under `root`, sorted — for proving the directory
    /// was not littered with foreign artifacts.
    fn dir_entries(root: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(root)
            .unwrap_or_else(|e| panic!("read_dir({}): {e}", root.display()))
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    /// Assert composer.json is byte-for-byte what we wrote, AND that the
    /// project directory still contains *only* composer.json. The directory
    /// check is the real teeth: a clean no-op for an unsupported ecosystem
    /// must create NOTHING — not an npm `package.json` hook, not a `.socket/`
    /// dir, not a lockfile, not a `.pth`, nothing. Probing for one specific
    /// filename (`package.json`) would let any other foreign artifact through.
    fn assert_manifest_pristine(root: &Path, who: &str) {
        assert_eq!(
            std::fs::read_to_string(root.join("composer.json")).unwrap(),
            COMPOSER_JSON,
            "{who}: composer.json must be left byte-for-byte unchanged"
        );
        assert!(
            !root.join("package.json").exists(),
            "{who}: setup must NOT inject an npm package.json hook into a composer-only project"
        );
        assert_eq!(
            dir_entries(root),
            vec!["composer.json".to_string()],
            "{who}: a clean no-op must leave the project dir containing ONLY composer.json; \
             any extra entry means setup wrote a foreign artifact into a composer-only project"
        );
    }

    #[test]
    fn composer_setup_is_a_clean_noop_host() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(root.join("composer.json"), COMPOSER_JSON).unwrap();
        let root_s = root.to_str().unwrap();

        // ── check (before any setup) ────────────────────────────────────────
        // A composer-only project is unsupported, so check must report
        // "no_files" and exit 0 — NOT "configured" (a false positive that
        // would mask the gap), NOT "needs_configuration", NOT "error", and
        // not a non-zero crash.
        let (code, out, err) = run(root, &["setup", "--check", "--cwd", root_s, "--json"]);
        assert_eq!(
            code, 0,
            "setup --check on a composer-only project must exit 0.\nstdout:\n{out}\nstderr:\n{err}"
        );
        assert_no_files_status(&out, "check (pristine)");
        assert_manifest_pristine(root, "after check (pristine)");

        // ── setup ────────────────────────────────────────────────────────────
        let (code, out, err) = run(root, &["setup", "--cwd", root_s, "--yes", "--json"]);
        assert_eq!(
            code, 0,
            "setup on a composer-only project must exit 0 (clean no-op).\nstdout:\n{out}\nstderr:\n{err}"
        );
        assert_no_files_status(&out, "setup");
        let v = parse_obj(&out, "setup");
        // It must claim to have changed nothing — not silently report work.
        assert_eq!(
            v.get("updated").and_then(|n| n.as_i64()),
            Some(0),
            "setup must report updated=0 for a composer-only project.\n{out}"
        );
        assert_eq!(
            v.get("errors").and_then(|n| n.as_i64()),
            Some(0),
            "setup must report errors=0 for a composer-only project.\n{out}"
        );
        // ...and must NOT falsely claim the project was already configured —
        // that would mask a regression that mis-classifies composer as set up.
        assert_eq!(
            v.get("alreadyConfigured").and_then(|n| n.as_i64()),
            Some(0),
            "setup must report alreadyConfigured=0 for an unsupported composer-only project.\n{out}"
        );
        assert_manifest_pristine(root, "after setup");

        // ── check (after setup): the no-op must not have configured anything ──
        let (code, out, err) = run(root, &["setup", "--check", "--cwd", root_s, "--json"]);
        assert_eq!(
            code, 0,
            "setup --check (post-setup) must still exit 0.\nstdout:\n{out}\nstderr:\n{err}"
        );
        assert_no_files_status(&out, "check (post-setup)");
        assert_manifest_pristine(root, "after check (post-setup)");

        // ── remove: also a clean no-op, manifest still pristine ───────────────
        let (code, out, err) = run(root, &["setup", "--remove", "--cwd", root_s, "--yes", "--json"]);
        assert_eq!(
            code, 0,
            "setup --remove on a composer-only project must exit 0.\nstdout:\n{out}\nstderr:\n{err}"
        );
        assert_no_files_status(&out, "remove");
        assert_manifest_pristine(root, "after remove");
    }
}
