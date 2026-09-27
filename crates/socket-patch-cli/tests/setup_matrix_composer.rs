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

#[path = "common/mod.rs"]
mod common;

#[path = "vex_e2e_common/mod.rs"]
mod vex_e2e_common;

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

    /// A realistic composer-only project: a PHP manifest requiring the
    /// same package the matrix targets, and nothing the npm/Python/Cargo
    /// detectors would recognise. Indented with 4 spaces, the way composer
    /// itself writes the file (PHP `JSON_PRETTY_PRINT`) — so the
    /// byte-for-byte restore below also pins that `setup` does not reformat
    /// a composer-authored manifest to serde's 2-space default.
    const COMPOSER_JSON: &str = "{\n    \"name\": \"acme/widget\",\n    \"require\": {\n        \"monolog/monolog\": \"3.5.0\"\n    }\n}\n";

    /// Run the CLI with `args` in `cwd`; returns `(exit_code, stdout, stderr)`.
    /// Delegates to the shared `common::run_with_env`, which seeds-then-scrubs
    /// the binary's entire ambient `SOCKET_*` surface — stripping only
    /// `SOCKET_API_TOKEN` (as this helper originally did) left the guard at
    /// the mercy of the parent shell: an ambient `SOCKET_ECOSYSTEMS=cargo`
    /// filtered composer out of scope (first `--check` exits 0 as `no_files`),
    /// and `SOCKET_DRY_RUN=true` no-ops the very write under test.
    /// `SOCKET_TELEMETRY_DISABLED=1` is injected because this file promises
    /// "no network": each real `setup` run otherwise fire-and-forgets a live
    /// `patch_setup` POST to the telemetry endpoint.
    fn run(cwd: &Path, args: &[&str]) -> (i32, String, String) {
        super::common::run_with_env(cwd, args, &[("SOCKET_TELEMETRY_DISABLED", "1")])
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

    /// The hook `setup` wires into a MANIFEST-LESS hosted / vendored
    /// checkout (a depscan-opened PR, a `vendor --detached` or `scan
    /// --redirect` project: the patches live in composer.lock, no
    /// `.socket/manifest.json`, no ledger). composer runs the hook after
    /// every install, so it must be a silent, write-free exit 0 there — and
    /// the same `apply` with `--vex` must attest the lockfile-wired patch
    /// from the patch API record (and, under the hook's own `--offline`,
    /// report the record unavailable instead of attesting blind).
    #[test]
    fn composer_setup_hook_in_manifestless_hosted_and_vendored_checkouts() {
        use super::vex_e2e_common::{
            assert_absent, assert_attested, binary, git_sha256, patch_view, run_vex, Marker,
            PatchApi, VexRun, VexVia,
        };
        const UUID: &str = "5e5e5e5e-1234-4abc-8def-5e5e5e5e5e5e";
        const PURL: &str = "pkg:composer/monolog/monolog@3.5.0";
        const PATCHED: &[u8] = b"<?php // patched Logger\n";
        let vulns: &[(&str, &[&str])] = &[("GHSA-setp-cmps-0001", &["CVE-2026-1212"])];

        for vendored in [false, true] {
            let tag = if vendored { "vendored" } else { "hosted" };
            let tmp = tempfile::tempdir().unwrap();
            let root = tmp.path();
            let root_s = root.to_str().unwrap();
            std::fs::write(root.join("composer.json"), COMPOSER_JSON).unwrap();
            let (code, out, err) = run(root, &["setup", "--cwd", root_s, "--yes", "--json"]);
            assert_eq!(code, 0, "[{tag}] setup:\n{out}\n{err}");

            // The lockfile wiring each backend writes (no manifest, no ledger).
            let dist = if vendored {
                let rel = format!(".socket/vendor/composer/{UUID}/monolog/monolog@3.5.0");
                let file = root.join(&rel).join("src/Monolog/Logger.php");
                std::fs::create_dir_all(file.parent().unwrap()).unwrap();
                std::fs::write(&file, PATCHED).unwrap();
                serde_json::json!({ "type": "path", "url": rel, "reference": UUID })
            } else {
                serde_json::json!({
                    "type": "zip",
                    "url": format!(
                        "https://patch.socket.dev/patch/composer/monolog/monolog/3.5.0/\
                         11111111-2222-4333-8444-555555555555/{UUID}/monolog-3.5.0.zip"
                    ),
                    "reference": "0123456789abcdef0123456789abcdef01234567",
                    "shasum": "abcdef0123456789abcdef0123456789abcdef01",
                })
            };
            let lock = serde_json::json!({
                "content-hash": "abc123def456abc123def456abc123de",
                "packages": [{ "name": "monolog/monolog", "version": "3.5.0", "dist": dist }],
                "packages-dev": [],
            });
            let lock = serde_json::to_string_pretty(&lock).unwrap();
            std::fs::write(root.join("composer.lock"), &lock).unwrap();

            // Exactly the command composer runs on post-install-cmd.
            let cj: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(root.join("composer.json")).unwrap())
                    .unwrap();
            let hook = cj["scripts"]["post-install-cmd"][0]
                .as_str()
                .expect("hook")
                .to_string();
            let mut argv: Vec<&str> = hook.split_whitespace().collect();
            assert_eq!(argv.remove(0), "socket-patch", "[{tag}] hook: {hook}");
            argv.extend(["--cwd", root_s]);
            let (code, out, err) = run(root, &argv);
            assert_eq!(
                code, 0,
                "[{tag}] the hook must not fail the install:\n{out}\n{err}"
            );
            assert!(
                out.trim().is_empty(),
                "[{tag}] --silent hook prints nothing: {out}"
            );
            assert!(
                !root.join(".socket/manifest.json").exists(),
                "[{tag}] no manifest written"
            );
            assert_eq!(
                std::fs::read_to_string(root.join("composer.lock")).unwrap(),
                lock
            );

            // The hook's apply + --vex, online: the lock-wired patch attests.
            let api = PatchApi::start(vec![(
                UUID.to_string(),
                patch_view(
                    UUID,
                    PURL,
                    &[("src/Monolog/Logger.php", &git_sha256(PATCHED))],
                    vulns,
                ),
            )]);
            let flags: Vec<String> = argv
                .iter()
                .filter(|a| !["apply", "--offline", "--silent", "--cwd", root_s].contains(*a))
                .map(|a| a.to_string())
                .collect();
            assert_eq!(
                flags,
                ["--ecosystems", "composer"],
                "[{tag}] hook flags: {hook}"
            );
            let base = VexRun {
                product: Some("pkg:composer/acme/widget@1.0.0".to_string()),
                extra_args: flags,
                ..VexRun::online(&api)
            }
            .via(VexVia::Apply);
            let out = run_vex(&binary(), root, &base);
            assert_eq!(out.code, Some(0), "[{tag}] apply --vex:\n{out}");
            assert_eq!(out.envelope["status"], "noManifest", "[{tag}]:\n{out}");
            let marker = if vendored {
                Marker::Vendored
            } else {
                Marker::Redirected
            };
            assert_attested(out.doc(), PURL, UUID, marker, vulns);

            // Under the hook's own --offline there is no record to attest
            // from: a VEX failure, never a blind attestation.
            let seen = api.request_count();
            let out = run_vex(
                &binary(),
                root,
                &VexRun {
                    offline: true,
                    ..base.clone()
                },
            );
            assert_eq!(out.code, Some(1), "[{tag}] offline apply --vex:\n{out}");
            assert_eq!(
                out.envelope["error"]["code"], "no_applicable_patches",
                "{out}"
            );
            assert_absent(out.doc.as_ref(), PURL);
            assert_eq!(api.request_count(), seen, "[{tag}] --offline made requests");
        }
    }
}
