//! setup-matrix: composer ecosystem (PHP). `setup` wires `socket-patch
//! apply` into composer's `post-install-cmd` / `post-update-cmd` script
//! events.
//!
//! IMPORTANT — why this file carries a real assertion of its own:
//! `smc::run_pm("composer", "composer")` routes composer through the
//! shared Docker matrix harness, which *soft-skips and silently passes*
//! whenever Docker or the `composer` image is absent (the common case
//! locally and in this eval). composer is also NOT npm-family, so the
//! harness's check/remove behavioral round-trip is skipped entirely for
//! it. The net effect: the matrix call can never turn red for a genuine
//! composer `setup` regression. On its own it protects nothing.
//!
//! To close that loophole WITHOUT touching the shared harness,
//! [`host_guard::composer_setup_round_trips_host`] runs unconditionally
//! (no Docker, no network, no PHP / composer toolchain — `setup` edits
//! `composer.json` directly) and pins the full wiring contract:
//! `--check` fails pre-setup, `setup` wires the hook, `--check` then
//! passes, and `--remove` restores the manifest byte-for-byte.
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
// Real, non-skippable regression guard for composer `setup`: the full
// wire → check → remove round-trip against a composer-only project,
// driven entirely on the host (no PHP toolchain — `setup` edits
// `composer.json` directly).
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
        serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
            panic!("{who}: stdout was not a single JSON object ({e}):\n{stdout}")
        })
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

    /// Composer is a REAL setup
    /// ecosystem: `setup` wires `socket-patch apply` into `composer.json`'s
    /// post-install/post-update script events, `--check` reflects it, and
    /// `--remove` restores the manifest byte-for-byte. Non-skippable (no Docker,
    /// no PHP toolchain) — it edits composer.json directly. This is the positive
    /// twin of `composer_setup_is_a_clean_noop_host` (the two never co-exist).
    #[test]
    fn composer_setup_round_trips_host() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(root.join("composer.json"), COMPOSER_JSON).unwrap();
        let root_s = root.to_str().unwrap();

        let status =
            |v: &serde_json::Value| v.get("status").and_then(|s| s.as_str()).map(str::to_string);

        // ── check (pristine): not wired yet → needs_configuration / exit 1 ──
        let (code, out, _) = run(root, &["setup", "--check", "--cwd", root_s, "--json"]);
        assert_eq!(code, 1, "pre-setup check must fail:\n{out}");
        assert_eq!(
            status(&parse_obj(&out, "check (pristine)")).as_deref(),
            Some("needs_configuration")
        );

        // ── setup: wires the hook into composer.json → success / updated=1 ──
        let (code, out, err) = run(root, &["setup", "--cwd", root_s, "--yes", "--json"]);
        assert_eq!(
            code, 0,
            "composer setup must succeed.\nstdout:\n{out}\nstderr:\n{err}"
        );
        let v = parse_obj(&out, "setup");
        assert_eq!(
            status(&v).as_deref(),
            Some("success"),
            "setup must report success:\n{out}"
        );
        assert_eq!(
            v.get("updated").and_then(|n| n.as_i64()),
            Some(1),
            "exactly the composer.json updated:\n{out}"
        );
        // Exactly one `composer`-kind file entry, status `updated`.
        let files = v["files"].as_array().expect("files array");
        assert_eq!(files.len(), 1, "one composer file entry:\n{out}");
        assert_eq!(files[0]["kind"], "composer");
        assert_eq!(files[0]["status"], "updated");
        // The command landed in BOTH script events on disk.
        let on_disk = std::fs::read_to_string(root.join("composer.json")).unwrap();
        let cj: serde_json::Value = serde_json::from_str(&on_disk).unwrap();
        for event in ["post-install-cmd", "post-update-cmd"] {
            let arr = cj["scripts"][event]
                .as_array()
                .unwrap_or_else(|| panic!("{event} missing:\n{on_disk}"));
            assert!(
                arr.iter()
                    .any(|c| c.as_str().is_some_and(|s| s.contains("socket-patch apply"))),
                "{event} must carry the re-apply command:\n{on_disk}"
            );
        }
        assert!(
            cj["require"]["monolog/monolog"] == "3.5.0",
            "user require preserved:\n{on_disk}"
        );

        // ── idempotent re-setup: already_configured, no change ──
        let (code, out, _) = run(root, &["setup", "--cwd", root_s, "--yes", "--json"]);
        assert_eq!(code, 0);
        assert_eq!(
            status(&parse_obj(&out, "re-setup")).as_deref(),
            Some("already_configured"),
            "{out}"
        );

        // ── check (post-setup): configured / exit 0 ──
        let (code, out, _) = run(root, &["setup", "--check", "--cwd", root_s, "--json"]);
        assert_eq!(code, 0, "post-setup check must pass:\n{out}");
        assert_eq!(
            status(&parse_obj(&out, "check (post-setup)")).as_deref(),
            Some("configured")
        );

        // ── remove: strips the hook, restoring composer.json byte-for-byte ──
        let (code, out, err) = run(
            root,
            &["setup", "--remove", "--cwd", root_s, "--yes", "--json"],
        );
        assert_eq!(
            code, 0,
            "composer remove must succeed.\nstdout:\n{out}\nstderr:\n{err}"
        );
        assert_eq!(
            status(&parse_obj(&out, "remove")).as_deref(),
            Some("success")
        );
        // The `scripts` object we created is gone and the dir holds only composer.json.
        assert_manifest_pristine(root, "after remove");

        // ── check (post-remove): back to needs_configuration / exit 1 ──
        let (code, out, _) = run(root, &["setup", "--check", "--cwd", root_s, "--json"]);
        assert_eq!(code, 1, "post-remove check must fail again:\n{out}");
        assert_eq!(
            status(&parse_obj(&out, "check (post-remove)")).as_deref(),
            Some("needs_configuration")
        );
    }
}
