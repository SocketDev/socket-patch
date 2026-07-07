//! setup-matrix: maven ecosystem (mvn). No native post-install hook,
//! `setup` is a no-op, and apply is additionally gated behind
//! `SOCKET_EXPERIMENTAL_MAVEN` (the driver sets it). The with-setup
//! cases are an EXPECTED BASELINE GAP.
//!
//! IMPORTANT — why this file carries a real assertion of its own:
//! `smc::run_pm("maven", "mvn")` routes maven through the shared Docker
//! matrix harness, which *soft-skips and silently passes* whenever Docker
//! or the `maven` image is absent (the common case locally and in this
//! eval). maven is also NOT npm-family (see `is_npm_family` in the
//! harness), so the harness's check/remove behavioral round-trip is
//! skipped entirely for it; and because maven's `baseline_supported` is
//! false in matrix.json the only thing the matrix could ever assert is the
//! coarse `actual_applied == expect_applied` verdict — which, on a crashed
//! or never-run case, defaults to the same `false` that satisfies every
//! negative-control scenario. The net effect: the matrix call can never
//! turn red for a genuine maven `setup` regression. On its own it protects
//! nothing.
//!
//! To close that loophole WITHOUT touching the shared harness or the bash
//! driver, [`host_guard::maven_setup_is_a_clean_noop_host`] runs
//! unconditionally (no Docker, no network, no maven toolchain) and pins
//! maven `setup`'s *actual current contract*: a maven project's `pom.xml`
//! is NOT a manifest `setup` knows how to configure, so every `setup`
//! sub-command must (a) recognise the project as having no configurable
//! files (`status == "no_files"`, never `error`/`configured`/
//! `needs_configuration`), (b) exit 0 with zero errors, and (c) leave the
//! `pom.xml` byte-for-byte untouched while creating no new files. A
//! positive-control run with a real `package.json` in a sibling dir proves
//! the `no_files` verdict is a discriminating decision and not a stuck
//! constant — so a regression that makes `setup` blind to *everything*
//! cannot hide behind maven's gap. It fails loudly if maven `setup`
//! ever starts crashing, erroring, misclassifying a pom.xml as
//! configurable, or mutating the project on disk.
//!
//! Run: `cargo test -p socket-patch-cli --features setup-e2e --test setup_matrix_maven`
#![cfg(feature = "setup-e2e")]

#[path = "setup_matrix_common/mod.rs"]
mod smc;

/// Documentation/negative-control pass through the shared Docker matrix.
/// Kept for parity with the other ecosystems and to run the maven negative
/// controls when Docker + the `maven` image are present. NOTE: this is the
/// path that silently no-ops on skip — it is NOT a regression guard. The
/// real teeth live in [`host_guard`] below.
#[test]
// Experimental ecosystem (maven): aspirational setup-matrix cases are a
// BASELINE GAP today; this passes on CI only because the runners lack `mvn`
// (cases soft-skip) and fails on any host that has it. Ignore so maven can
// never block the blocking --all-features jobs; `host_guard` below still pins
// the real no-op contract. Run with `--features setup-e2e,maven -- --ignored`.
#[ignore = "experimental ecosystem (maven): not gating CI until the maven backend is implemented; run with --ignored"]
fn mvn() {
    smc::run_pm("maven", "mvn");
}

// ─────────────────────────────────────────────────────────────────────────
// Real, non-skippable regression guard for maven `setup`.
//
// maven has no post-install hook and no manifest `setup` configures, so the
// only honest contract to pin is the *negative* one: setup is a clean no-op
// on a maven project — it recognises there is nothing to configure, never
// errors, and never touches the project on disk. A positive control proves
// that verdict is discriminating, not a stuck `no_files` constant.
// ─────────────────────────────────────────────────────────────────────────
mod host_guard {
    use std::path::Path;
    use std::process::Command;

    /// A minimal but valid Maven `pom.xml`. `setup` must treat the directory
    /// as having nothing to configure and leave this file byte-for-byte.
    const POM_XML: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<project xmlns=\"http://maven.apache.org/POM/4.0.0\">\n\
  <modelVersion>4.0.0</modelVersion>\n\
  <groupId>dev.socket</groupId>\n\
  <artifactId>sm-maven-proj</artifactId>\n\
  <version>1.0.0</version>\n\
  <dependencies>\n\
    <dependency>\n\
      <groupId>com.google.guava</groupId>\n\
      <artifactId>guava</artifactId>\n\
      <version>32.1.2-jre</version>\n\
    </dependency>\n\
  </dependencies>\n\
</project>\n";

    /// Faithful npm fixture for the positive control — proves `setup`
    /// detection actually discriminates (so maven's `no_files` is a real
    /// decision, not a stuck constant).
    const PACKAGE_JSON: &str =
        "{ \"name\": \"sm-proj\", \"version\": \"0.0.0\", \"private\": true, \"dependencies\": { \"minimist\": \"1.2.2\" } }\n";

    /// Ambient decoys [`run`]'s prefix scrub must strip, planted by the test
    /// itself so the scrub is exercised on every run, not only in hostile
    /// shells. Three demonstrated failure classes on the old fixed-list scrub:
    /// clap parses env-bound `GlobalArgs` values on EVERY invocation whether
    /// or not the command uses the flag, so an invalid ambient `SOCKET_STRICT`
    /// / `SOCKET_VENDOR_SOURCE` aborts the parse (exit 2) before `setup` even
    /// runs; a (perfectly valid!) ambient `SOCKET_SETUP_EXCLUDE` stands in for
    /// `setup --exclude`, which a real `setup` run PERSISTS — creating
    /// `.socket/manifest.json` inside the maven fixture and failing
    /// `assert_pristine`; and an enabled `SOCKET_EXPERIMENTAL_MAVEN` gate in
    /// the shell/CI could quietly change maven's surface behind the test's
    /// back. (Safe to set process-wide: the only other test in this binary is
    /// the `#[ignore]`d matrix pass, which routes through
    /// `smc::host_driver_command`'s own `SOCKET_*` prefix scrub.)
    const HOSTILE_DECOYS: &[(&str, &str)] = &[
        ("SOCKET_STRICT", "banana"),
        ("SOCKET_VENDOR_SOURCE", "bogus-decoy"),
        ("SOCKET_SETUP_EXCLUDE", "decoy-member"),
        ("SOCKET_EXPERIMENTAL_MAVEN", "true"),
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

    /// The set of directory entries (names) present at `root`, sorted.
    /// Used to prove `setup` created nothing.
    fn dir_entries(root: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(root)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        names.sort();
        names
    }

    /// Assert maven `setup` was a clean no-op for the `who` stage: the
    /// pom.xml is byte-for-byte unchanged and the directory still contains
    /// ONLY the pom.xml (no package.json, no `.cargo/`, no scripts, nothing).
    fn assert_pristine(root: &Path, who: &str) {
        assert_eq!(
            std::fs::read_to_string(root.join("pom.xml")).unwrap(),
            POM_XML,
            "{who}: setup must leave pom.xml byte-for-byte unchanged"
        );
        assert_eq!(
            dir_entries(root),
            vec!["pom.xml".to_string()],
            "{who}: setup must create no files in a maven project (dir must hold only pom.xml)"
        );
    }

    /// Assert a `no_files` envelope: status is exactly `no_files`, no
    /// manifests were touched, and (when present) every count field is zero.
    /// Crucially rejects `error`, `configured`, `needs_configuration`,
    /// `success`, etc. — anything other than the documented maven no-op.
    fn assert_no_files_envelope(v: &serde_json::Value, who: &str) {
        assert_eq!(
            json_str_field(v, "status", who),
            "no_files",
            "{who}: maven pom.xml is not a configurable manifest — status must be `no_files`, \
             not error/configured/needs_configuration/success:\n{v}"
        );
        let files = v
            .get("files")
            .and_then(|f| f.as_array())
            .unwrap_or_else(|| panic!("{who}: envelope has no `files` array:\n{v}"));
        assert!(
            files.is_empty(),
            "{who}: no files may be reported for a maven project, got:\n{v}"
        );
        // Count fields are optional in the `no_files` envelope, but any that
        // ARE emitted must be zero — a non-zero count would mean setup thought
        // it had work to do on a project it does not support.
        for key in [
            "updated",
            "alreadyConfigured",
            "errors",
            "configured",
            "needsConfiguration",
        ] {
            if let Some(n) = v.get(key) {
                assert_eq!(
                    n.as_i64(),
                    Some(0),
                    "{who}: `{key}` must be 0 in a maven no_files envelope, got {n}:\n{v}"
                );
            }
        }
    }

    #[test]
    fn maven_setup_is_a_clean_noop_host() {
        // Committed regression guard for the env scrub itself: with the old
        // fixed-list scrub these leaked into the child — SOCKET_STRICT /
        // SOCKET_VENDOR_SOURCE aborted every parse (exit 2) and
        // SOCKET_SETUP_EXCLUDE made the real `setup` run write
        // `.socket/manifest.json` into the fixture (assert_pristine RED).
        for (k, v) in HOSTILE_DECOYS {
            std::env::set_var(k, v);
        }
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(root.join("pom.xml"), POM_XML).unwrap();
        let root_s = root.to_str().unwrap();

        // Precondition: the fixture is genuinely maven-only. If the temp dir
        // somehow carried an npm/cargo/python manifest the no_files asserts
        // below would be meaningless, so pin the starting state.
        assert_eq!(
            dir_entries(root),
            vec!["pom.xml".to_string()],
            "fixture must start as a maven-only project (pom.xml and nothing else)"
        );

        // ── setup --check: a maven project has nothing to configure ─────────
        // Must exit 0 (not an error / needs-configuration) AND report
        // no_files. A regression that crashes, errors, or misclassifies the
        // pom.xml as a configurable manifest fails here.
        let (code, out, err) = run(root, &["setup", "--check", "--cwd", root_s, "--json"]);
        assert_eq!(
            code, 0,
            "setup --check on a maven project must exit 0 (no_files), not error/needs-config.\nstdout:\n{out}\nstderr:\n{err}"
        );
        assert_no_files_envelope(&parse_json(&out, "check (maven)"), "check (maven)");
        assert_pristine(root, "after check");

        // ── setup (no flag): still a no-op, zero updates, zero errors ───────
        let (code, out, err) = run(root, &["setup", "--cwd", root_s, "--yes", "--json"]);
        assert_eq!(
            code, 0,
            "setup on a maven project must exit 0 and do nothing.\nstdout:\n{out}\nstderr:\n{err}"
        );
        assert_no_files_envelope(&parse_json(&out, "setup (maven)"), "setup (maven)");
        assert_pristine(root, "after setup");

        // ── setup --remove: nothing was configured, so nothing to remove ────
        let (code, out, err) = run(
            root,
            &["setup", "--remove", "--cwd", root_s, "--yes", "--json"],
        );
        assert_eq!(
            code, 0,
            "setup --remove on a maven project must exit 0 and do nothing.\nstdout:\n{out}\nstderr:\n{err}"
        );
        assert_no_files_envelope(&parse_json(&out, "remove (maven)"), "remove (maven)");
        assert_pristine(root, "after remove");

        // ── positive control: prove `no_files` is a discriminating verdict ──
        // The same binary, given a real package.json in a fresh dir, MUST
        // reach a different, non-no_files conclusion (needs_configuration,
        // exit 1). Without this, a regression that makes `setup` blind to
        // everything — always emitting `no_files` — would sail through the
        // maven asserts above. The contrast is the whole point.
        let ctrl = tempfile::tempdir().unwrap();
        let ctrl_root = ctrl.path();
        std::fs::write(ctrl_root.join("package.json"), PACKAGE_JSON).unwrap();
        let (code, out, err) = run(
            ctrl_root,
            &[
                "setup",
                "--check",
                "--cwd",
                ctrl_root.to_str().unwrap(),
                "--json",
            ],
        );
        assert_eq!(
            code, 1,
            "positive control: setup --check on an npm project must exit 1 (needs_configuration), \
             proving the maven no_files verdict above is discriminating.\nstdout:\n{out}\nstderr:\n{err}"
        );
        let v = parse_json(&out, "control (npm)");
        assert_eq!(
            json_str_field(&v, "status", "control (npm)"),
            "needs_configuration",
            "positive control: an npm project must report needs_configuration, not no_files — \
             otherwise `setup` is blind to all manifests and maven's no_files proves nothing.\nstderr:\n{err}"
        );
        assert_eq!(
            v.get("needsConfiguration").and_then(|n| n.as_i64()),
            Some(1),
            "positive control: exactly the package.json must count as needing configuration.\n{out}"
        );

        for (k, _) in HOSTILE_DECOYS {
            std::env::remove_var(k);
        }
    }
}
