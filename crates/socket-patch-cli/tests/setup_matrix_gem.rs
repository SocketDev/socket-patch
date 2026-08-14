//! setup-matrix: gem ecosystem (bundler). `setup` now has REAL bundler support
//! — it appends a managed `plugin "socket-patch"` block to the Gemfile and
//! generates a committed in-tree Bundler plugin under `.socket/bundler-plugin/`
//! whose `plugins.rb` re-runs `socket-patch apply --ecosystems gem` on every
//! `bundle install` (digest-gated load-time + per-gem `after-install`
//! triggers, forced `after-install-all` re-apply).
//!
//! The two structural reasons the with-setup Docker cases
//! (`baseline_with_setup`, `alt_content_patchset`) used to be a
//! [BASELINE GAP] are both fixed (2026-08-13): (a) the bootstrap deadlock —
//! installing the plugin evaluates `plugins.rb` BEFORE any project gems land,
//! and the old load-time `SocketPatch.apply!` treated apply's exit 1 ("No
//! packages found") as fatal (`Bundler::BundlerError`), killing the FIRST
//! `bundle install` of every fresh checkout — is gone: the generated plugin
//! now warns-and-continues on apply failures (`SOCKET_PATCH_STRICT=1`
//! restores the raise), pinned by [`plugin_runtime`] below; (b) the fixture's
//! synthetic all-zeros beforeHash — which hash-gated gem apply (no npm-style
//! mismatch-warn-and-apply path) always rejected — is replaced by the real
//! git-blob hash probed from the published .gem (`resolve_before_hash` in
//! `run-case.sh`, mirroring docker_e2e_gem). NOTE: in Docker mode the matrix
//! runs the binary BAKED INTO the local image; an image built before this fix
//! generates the old raising plugin and still red-flags these cases — rebuild
//! the image (or run with `SOCKET_PATCH_TEST_HOST=1`) to see them pass.
//!
//! IMPORTANT — why this file carries a real assertion of its own:
//! `smc::run_pm("gem", "bundler")` routes gem through the shared Docker
//! matrix harness, which *soft-skips and silently passes* whenever Docker
//! or the `gem` image is absent (the common case locally and in this
//! eval). gem is also NOT npm-family (see `is_npm_family` in the harness
//! and `run-case.sh`), so the harness's check/remove behavioral
//! round-trip is skipped entirely for it. When Docker + the image ARE
//! present the matrix does assert the coarse
//! `actual_applied == expect_applied` verdict against a real
//! `bundle install` (it caught the uncloneable `git:` plugin source), but
//! that protection is environment-conditional — a machine without the
//! image gets silent green.
//!
//! To close that loophole WITHOUT touching the shared harness or the bash
//! driver, [`host_guard::gem_setup_roundtrip_host`] runs unconditionally
//! (no Docker, no network, no ruby/bundler toolchain) and pins gem
//! `setup`'s contract with a full POSITIVE round-trip: `--check` fails on a
//! pristine Gemfile → `setup` wires the plugin → `--check` passes → `--remove`
//! restores the Gemfile *byte-for-byte* and deletes the generated plugin dir →
//! `--check` fails again. It reads on-disk state with *independent* probes
//! (hand-pinned constants + a marker scan, not a copy of any writer output) so
//! the oracle can disagree with a broken implementation. It fails loudly if
//! gem `setup` stops wiring the plugin, corrupts the Gemfile, mis-reports a
//! status / exit code, or leaves residue after `--remove`.
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
// A bundler project carries a Gemfile; `setup` wires a committed Bundler
// plugin into it. The guard pins that round-trip precisely so a regression
// (plugin no longer wired, Gemfile corrupted on add/remove, wrong exit code,
// residue after remove) turns this suite red even with no Docker / ruby.
// ─────────────────────────────────────────────────────────────────────────
mod host_guard {
    use std::path::Path;
    use std::process::Command;

    /// A faithful bundler project fixture, mirroring `scaffold_project`'s
    /// `bundler` branch in `tests/setup_matrix/run-case.sh` and the gem
    /// target's package/version in matrix.json (`colorize` @ `1.1.0`).
    const GEMFILE: &str = "source 'https://rubygems.org'\ngem 'colorize', '1.1.0'\n";

    /// The relative path of the generated in-tree plugin (independent of any
    /// production constant — a hand-pinned oracle).
    const PLUGIN_DIR: &str = ".socket/bundler-plugin";
    /// The managed-block marker `setup` appends to the Gemfile. Pinned here so
    /// the test disagrees with a renamed/removed marker rather than copying it.
    const MANAGED_MARKER: &str = "# >>> socket-patch:managed";

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
        // Prefix-scrub the whole ambient `SOCKET_*` surface (mirrors
        // `tests/common::run_with_env`). clap binds ~30 `SOCKET_*` vars across
        // the global + per-command flags and the set keeps growing, so an
        // itemized list rots: `SOCKET_STRICT`, `SOCKET_VENDOR_SOURCE`, and
        // setup's own `SOCKET_SETUP_EXCLUDE` were all missing from the list
        // this replaced — an ambient `SOCKET_VENDOR_SOURCE=bogus` aborted
        // every invocation with a clap parse error (exit 2) and turned this
        // guard red for an environmental reason.
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

    fn gemfile_body(root: &Path) -> String {
        std::fs::read_to_string(root.join("Gemfile")).unwrap()
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
        let plugins_rb = root.join(PLUGIN_DIR).join("plugins.rb");
        let gemspec = root.join(PLUGIN_DIR).join("socket-patch.gemspec");

        // ── pristine precondition ──────────────────────────────────────────
        assert_eq!(gemfile_body(root), GEMFILE, "fixture Gemfile");
        assert!(
            !root.join(PLUGIN_DIR).exists(),
            "fixture must not already contain the generated plugin dir"
        );
        assert!(
            !root.join("package.json").exists(),
            "fixture must not contain a package.json (would change the path under test)"
        );

        // ── check (pristine): plugin not wired → needs_configuration, exit 1 ─
        let (code, out, err) = run(root, &["setup", "--check", "--cwd", root_s, "--json"]);
        assert_eq!(
            code, 1,
            "check on an unconfigured bundler project must exit 1.\n{out}\n{err}"
        );
        let v = parse_json(&out, "check (pristine)");
        assert_eq!(
            json_str(&v, "status", "check (pristine)"),
            "needs_configuration"
        );
        // The Gemfile must be among the manifests reported as needing setup.
        let files = v.get("files").and_then(|f| f.as_array()).expect("files[]");
        assert!(
            files.iter().any(
                |f| f.get("kind").and_then(|k| k.as_str()) == Some("gemfile")
                    && f.get("status").and_then(|s| s.as_str()) == Some("needs_configuration")
            ),
            "check must report the Gemfile as needs_configuration:\n{v}"
        );

        // ── setup: wire the plugin (Gemfile block + generated dir) ──────────
        let (code, out, err) = run(root, &["setup", "--cwd", root_s, "--yes", "--json"]);
        assert_eq!(code, 0, "setup must exit 0.\n{out}\n{err}");
        let v = parse_json(&out, "setup");
        assert_eq!(json_str(&v, "status", "setup"), "success");
        assert!(
            json_i64(&v, "updated", "setup") >= 2,
            "Gemfile + plugin dir updated:\n{v}"
        );
        assert_eq!(json_i64(&v, "errors", "setup"), 0, "setup errors:\n{v}");

        // On-disk, via independent probes (NOT a copy of the writer output):
        // the managed block is appended (original bytes preserved as a prefix),
        let body = gemfile_body(root);
        assert!(
            body.starts_with(GEMFILE),
            "setup must only APPEND to the Gemfile:\n{body}"
        );
        assert!(
            body.contains(MANAGED_MARKER),
            "managed block marker missing:\n{body}"
        );
        assert!(
            body.contains("plugin 'socket-patch'"),
            "Gemfile must reference the socket-patch plugin:\n{body}"
        );
        // The directive must use a `path:` source. A `git:` source makes
        // Bundler `git clone` the directory, and `.socket/bundler-plugin/` is
        // a plain generated dir (committing it to the PARENT repo does not
        // give it a `.git`), so every `bundle install` on a wired project
        // fails with "repository ... does not exist" (exit 11) and the plugin
        // never loads. Verified against real Bundler in the gem Docker image.
        assert!(
            body.contains("plugin 'socket-patch', path:"),
            "the plugin directive must be `path:`-sourced (a `git:` dir source \
             is uncloneable and breaks every `bundle install`):\n{body}"
        );
        // and the generated plugin carries the two triggers + fail-loud applier.
        assert!(plugins_rb.exists(), "plugins.rb must be generated");
        assert!(gemspec.exists(), "the plugin gemspec must be generated");
        // Bundler refuses to LOAD a plugin whose gemspec require paths are
        // missing on disk ("The following plugin paths don't exist: .../lib.
        // ... Continuing without installing plugin"). The plugin dir is flat
        // (no lib/), so the gemspec must pin `require_paths = ["."]` or the
        // plugin is silently skipped on every install.
        let spec = std::fs::read_to_string(&gemspec).unwrap();
        assert!(
            spec.contains("s.require_paths = [\".\"]"),
            "gemspec must set require_paths to the flat plugin dir, or Bundler \
             silently skips loading the plugin:\n{spec}"
        );
        let rb = std::fs::read_to_string(&plugins_rb).unwrap();
        assert!(
            rb.contains("Bundler::Plugin.add_hook(\"after-install-all\")"),
            "plugins.rb must register the after-install-all hook (fresh-install trigger):\n{rb}"
        );
        assert!(
            rb.contains("SocketPatch.apply!"),
            "plugins.rb must call the applier at load time (cached/no-op-install trigger):\n{rb}"
        );
        assert!(
            rb.contains("\"--ecosystems\", \"gem\", \"--offline\""),
            "plugins.rb must shell the gem-scoped offline apply:\n{rb}"
        );
        // Tolerant by default (a raise at plugin registration deadlocks a
        // fresh checkout's first `bundle install`), with the strict escape
        // hatch still raising Bundler::BundlerError.
        assert!(
            rb.contains("SOCKET_PATCH_STRICT"),
            "plugins.rb must carry the strict-mode escape hatch:\n{rb}"
        );
        assert!(
            rb.contains("BundlerError"),
            "plugins.rb must still raise Bundler::BundlerError in strict mode:\n{rb}"
        );

        // ── check (after setup): configured, exit 0 ─────────────────────────
        let (code, out, err) = run(root, &["setup", "--check", "--cwd", root_s, "--json"]);
        assert_eq!(
            code, 0,
            "check on a configured project must exit 0.\n{out}\n{err}"
        );
        assert_eq!(
            json_str(
                &parse_json(&out, "check (configured)"),
                "status",
                "check (configured)"
            ),
            "configured"
        );

        // ── idempotent re-setup: nothing changes ────────────────────────────
        let (code, out, _) = run(root, &["setup", "--cwd", root_s, "--yes", "--json"]);
        assert_eq!(code, 0, "idempotent re-setup must exit 0");
        let v = parse_json(&out, "re-setup");
        assert_eq!(json_str(&v, "status", "re-setup"), "already_configured");
        assert_eq!(
            json_i64(&v, "updated", "re-setup"),
            0,
            "re-setup must update nothing:\n{v}"
        );

        // ── remove: byte-for-byte restore + plugin dir gone ─────────────────
        let (code, out, err) = run(
            root,
            &["setup", "--remove", "--cwd", root_s, "--yes", "--json"],
        );
        assert_eq!(code, 0, "remove must exit 0.\n{out}\n{err}");
        let v = parse_json(&out, "remove");
        assert_eq!(json_str(&v, "status", "remove"), "success");
        assert!(
            json_i64(&v, "removed", "remove") >= 2,
            "Gemfile + plugin dir removed:\n{v}"
        );
        assert_eq!(
            gemfile_body(root),
            GEMFILE,
            "remove must restore the Gemfile byte-for-byte to its pre-setup state"
        );
        assert!(
            !root.join(PLUGIN_DIR).exists(),
            "remove must delete the generated plugin dir"
        );

        // ── check (after remove): needs_configuration again, exit 1 ─────────
        let (code, out, _) = run(root, &["setup", "--check", "--cwd", root_s, "--json"]);
        assert_eq!(code, 1, "check after remove must exit 1 again");
        assert_eq!(
            json_str(
                &parse_json(&out, "check (removed)"),
                "status",
                "check (removed)"
            ),
            "needs_configuration"
        );
    }

    /// `bundle` resolves the Gemfile by walking UP from the invocation dir,
    /// and `discover_bundler_project` documents the same contract. Run from a
    /// subdirectory with NO `--cwd` flag the CLI defaults to the RELATIVE
    /// `--cwd .` — whose lexical `Path::parent()` chain is `Some("")` → `None`
    /// without ever reaching the real parent directories — so the walk-up must
    /// re-root itself on the process cwd to find the ancestor Gemfile, and the
    /// wiring must land at the Gemfile's dir, never the invocation subdir.
    #[test]
    fn gem_setup_discovers_root_project_from_subdirectory() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(root.join("Gemfile"), GEMFILE).unwrap();
        let sub = root.join("lib").join("widgets");
        std::fs::create_dir_all(&sub).unwrap();

        // check from the subdir: the (unconfigured) root project must be found.
        let (code, out, err) = run(&sub, &["setup", "--check", "--json"]);
        assert_eq!(
            code, 1,
            "check from a subdirectory must find the unconfigured ancestor \
             Gemfile (exit 1), not report no_files (exit 0).\n{out}\n{err}"
        );
        assert_eq!(
            json_str(
                &parse_json(&out, "check (subdir)"),
                "status",
                "check (subdir)"
            ),
            "needs_configuration"
        );

        // setup from the subdir: wires the ROOT project.
        let (code, out, err) = run(&sub, &["setup", "--yes", "--json"]);
        assert_eq!(
            code, 0,
            "setup from a subdirectory must exit 0.\n{out}\n{err}"
        );
        assert_eq!(
            json_str(
                &parse_json(&out, "setup (subdir)"),
                "status",
                "setup (subdir)"
            ),
            "success"
        );
        let body = gemfile_body(root);
        assert!(
            body.contains(MANAGED_MARKER),
            "managed block lands in the ROOT Gemfile:\n{body}"
        );
        assert!(
            root.join(PLUGIN_DIR).join("plugins.rb").exists(),
            "plugin dir lands at the Gemfile's dir (the project root)"
        );
        assert!(
            !sub.join(PLUGIN_DIR).exists(),
            "no plugin dir may be generated in the invocation subdir"
        );
        assert!(
            !sub.join("Gemfile").exists(),
            "no Gemfile may be synthesized in the invocation subdir"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Runtime guards for the GENERATED plugin, driven through a REAL `bundle
// install` (host bundler; validated against 4.0.15, and the same flows
// against bundler 2.7 in the gem Docker image during development). Each test
// wires a scratch project with the actual CLI binary (`setup --yes`), points
// SOCKET_PATCH_BIN at a fake apply whose exit code and invocation log we
// control, and asserts on bundler's real exit status + the on-disk state.
//
// Soft-skips (loudly, mirroring the docker_e2e_* convention) when no
// `bundle`/`ruby` toolchain is on PATH — the CI setup-matrix job and any dev
// machine with ruby run them for real.
// ─────────────────────────────────────────────────────────────────────────
#[cfg(unix)]
mod plugin_runtime {
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    /// Manifest fixture: one committed gem patch record (hashes are dummies —
    /// the fake apply never checks them; what matters is that the manifest
    /// EXISTS so the plugin's applier engages).
    const MANIFEST: &str = r#"{
  "patches": {
    "pkg:gem/colorize@1.1.0": {
      "uuid": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      "exportedAt": "2026-01-01T00:00:00Z",
      "files": { "package/lib/colorize.rb": { "beforeHash": "0000000000000000000000000000000000000000000000000000000000000000", "afterHash": "1111111111111111111111111111111111111111111111111111111111111111" } },
      "vulnerabilities": {},
      "description": "plugin-runtime fixture",
      "license": "MIT",
      "tier": "free"
    }
  }
}
"#;

    /// Hand-pinned stamp locations (independent oracles, not copies of the
    /// template constants): the project-scoped stamp the plugin must write,
    /// and the legacy fixed-name file it must never write again.
    const STAMP_REL: &str = ".socket/gem-plugin-stamp";
    const LEGACY_STAMP_NAME: &str = ".socket-patch-gem-stamp";

    fn binary() -> PathBuf {
        env!("CARGO_BIN_EXE_socket-patch").into()
    }

    fn have(cmd: &str) -> bool {
        Command::new(cmd)
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// Strip every ambient var that could flip a verdict: the CLI's SOCKET_*
    /// surface (a dev's SOCKET_PATCH_STRICT or SOCKET_DRY_RUN must not leak
    /// into the child), and bundler/rubygems config that could retarget the
    /// install (BUNDLE_GEMFILE, GEM_HOME, RUBYOPT).
    fn scrub(cmd: &mut Command) {
        for (key, _) in std::env::vars_os() {
            let name = key.to_string_lossy().into_owned();
            let hit = (name.starts_with("SOCKET_") && name != "SOCKET_NO_CONFIG")
                || name.starts_with("BUNDLE_")
                || name.starts_with("GEM_")
                || name == "RUBYOPT";
            if hit {
                cmd.env_remove(&name);
            }
        }
        cmd.env("SOCKET_TELEMETRY_DISABLED", "1");
    }

    fn run(mut cmd: Command) -> (i32, String, String) {
        let out = cmd.output().expect("spawn child process");
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).to_string(),
            String::from_utf8_lossy(&out.stderr).to_string(),
        )
    }

    /// `bundle install` in `root` with the fake apply bin + extra env.
    fn bundle_install(root: &Path, fake: &Path, extra: &[(&str, &str)]) -> (i32, String, String) {
        let mut cmd = Command::new("bundle");
        cmd.arg("install").current_dir(root);
        scrub(&mut cmd);
        cmd.env("BUNDLE_PATH", "vendor/bundle");
        cmd.env("SOCKET_PATCH_BIN", fake);
        for (k, v) in extra {
            cmd.env(k, v);
        }
        run(cmd)
    }

    /// A fake `socket-patch` that logs each invocation and exits `code`.
    /// Returns (bin path, log path).
    fn write_fake_apply(dir: &Path, code: i32) -> (PathBuf, PathBuf) {
        let log = dir.join("apply.log");
        std::fs::write(&log, "").unwrap();
        let bin = dir.join("fake-socket-patch");
        std::fs::write(
            &bin,
            format!(
                "#!/bin/sh\nprintf 'APPLY-CALLED %s\\n' \"$*\" >> '{}'\nexit {code}\n",
                log.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        (bin, log)
    }

    fn apply_calls(log: &Path) -> Vec<String> {
        std::fs::read_to_string(log)
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    /// Scaffold a setup-wired project the way a fresh clone sees it: a
    /// Gemfile, a committed manifest, and the plugin generated by the REAL
    /// binary. A zero-dependency Gemfile keeps the install offline — bundler
    /// still registers the plugin and fires `after-install-all` (verified on
    /// bundler 2.7 and 4.0.15), which is all these guards need.
    fn scaffold(root: &Path) {
        std::fs::write(root.join("Gemfile"), "# no dependencies\n").unwrap();
        std::fs::create_dir_all(root.join(".socket")).unwrap();
        std::fs::write(root.join(".socket/manifest.json"), MANIFEST).unwrap();

        let mut cmd = Command::new(binary());
        cmd.args(["setup", "--yes", "--json"]).current_dir(root);
        scrub(&mut cmd);
        let (code, out, err) = run(cmd);
        assert_eq!(code, 0, "setup --yes must wire the plugin.\n{out}\n{err}");
        assert!(
            root.join(".socket/bundler-plugin/plugins.rb").exists(),
            "setup must generate plugins.rb"
        );
    }

    /// [P0 bootstrap deadlock] On a fresh clone of a setup-wired project the
    /// FIRST `bundle install` evaluates plugins.rb at plugin REGISTRATION,
    /// before any project gem lands; apply legitimately finds nothing and
    /// exits 1. The old plugin raised Bundler::BundlerError there, so that
    /// first install (and every retry) died with "Failed to install plugin"
    /// — reproduced at exit 29 under bundler 4.0.15 / exit 1 under 2.7. The
    /// generated plugin must instead warn (with the manual remediation) and
    /// let the install succeed.
    #[test]
    fn first_bundle_install_survives_failing_apply() {
        if !have("bundle") {
            eprintln!("skip plugin_runtime: bundler not on PATH");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        scaffold(root);
        let (fake, log) = write_fake_apply(root, 1);

        let (code, out, err) = bundle_install(root, &fake, &[]);
        assert_eq!(
            code, 0,
            "the FIRST bundle install of a setup-wired fresh checkout must \
             succeed even when apply fails (bootstrap deadlock).\n{out}\n{err}"
        );
        // Anti-vacuity: the failure was real — the plugin DID shell apply.
        let calls = apply_calls(&log);
        assert!(
            calls
                .iter()
                .any(|c| c.contains("apply --ecosystems gem --offline --silent")),
            "the plugin must have invoked the (failing) gem-scoped apply:\n{calls:?}"
        );
        // The warning names what failed and how to remediate.
        assert!(
            err.contains("socket-patch:"),
            "a failing apply must be surfaced on stderr:\n{err}"
        );
        assert!(
            err.contains("socket-patch apply --ecosystems gem"),
            "the warning must name the manual remediation command:\n{err}"
        );
        assert!(
            err.contains("SOCKET_PATCH_STRICT"),
            "the warning must mention the strict escape hatch:\n{err}"
        );

        // A retry is not poisoned either (the old failure mode repeated
        // identically forever because plugin registration never completed).
        let (code, out, err) = bundle_install(root, &fake, &[]);
        assert_eq!(
            code, 0,
            "retried bundle install must also succeed.\n{out}\n{err}"
        );
    }

    /// SOCKET_PATCH_STRICT=1 restores raise-on-failure for builds that must
    /// not proceed with unpatched gems: the same failing-apply install must
    /// break the build again.
    #[test]
    fn strict_mode_fails_bundle_install_on_apply_failure() {
        if !have("bundle") {
            eprintln!("skip plugin_runtime: bundler not on PATH");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        scaffold(root);
        let (fake, log) = write_fake_apply(root, 1);

        let (code, out, err) = bundle_install(root, &fake, &[("SOCKET_PATCH_STRICT", "1")]);
        assert_ne!(
            code, 0,
            "strict mode must fail the build on a patch failure.\n{out}\n{err}"
        );
        assert!(
            !apply_calls(&log).is_empty(),
            "the strict failure must come from a real apply invocation"
        );
        assert!(
            err.contains("socket-patch"),
            "the strict failure must carry the socket-patch message:\n{err}"
        );
    }

    /// [P2 stamp location] A successful apply stamps the PROJECT
    /// (.socket/gem-plugin-stamp), not a fixed-name file under the bundle
    /// path (machine-global when no path is configured — shared and clobbered
    /// across every socket-patch project on the host). And the digest gate
    /// holds: a second, fully-cached install runs exactly one more (forced
    /// after-install-all) apply — the gated triggers stay quiet.
    #[test]
    fn successful_apply_stamps_project_scoped() {
        if !have("bundle") {
            eprintln!("skip plugin_runtime: bundler not on PATH");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        scaffold(root);
        let (fake, log) = write_fake_apply(root, 0);

        let (code, out, err) = bundle_install(root, &fake, &[]);
        assert_eq!(code, 0, "install must succeed.\n{out}\n{err}");
        assert!(
            !err.contains("socket-patch:"),
            "a successful apply must not warn:\n{err}"
        );

        let stamp = root.join(STAMP_REL);
        assert!(
            stamp.is_file(),
            "the digest stamp must land at the project-scoped {STAMP_REL}"
        );
        let content = std::fs::read_to_string(&stamp).unwrap();
        let content = content.trim();
        assert!(
            content.len() == 64 && content.bytes().all(|b| b.is_ascii_hexdigit()),
            "the stamp must hold one sha256 hex digest, got: {content:?}"
        );
        // No legacy fixed-name stamp anywhere under the bundle path.
        let legacy_hits: Vec<_> = walk(&root.join("vendor"))
            .into_iter()
            .filter(|p| p.file_name().is_some_and(|n| n == LEGACY_STAMP_NAME))
            .collect();
        assert!(
            legacy_hits.is_empty(),
            "no legacy bundle-path stamp may be written: {legacy_hits:?}"
        );

        let after_first = apply_calls(&log).len();
        let (code, out, err) = bundle_install(root, &fake, &[]);
        assert_eq!(code, 0, "cached install must succeed.\n{out}\n{err}");
        assert_eq!(
            apply_calls(&log).len(),
            after_first + 1,
            "a fully-cached install runs exactly the one forced \
             after-install-all apply; the digest-gated triggers must not \
             shell out again"
        );
    }

    /// [P1 digest honesty + migration] Drive the applier directly with plain
    /// ruby (no bundler process, no network): the digest stamp must reflect
    /// the ACTUAL on-disk gem-file state, so an out-of-band reversion
    /// (`bundle pristine`, `gem pristine`, a manual edit) flips the digest
    /// and the next trigger re-applies; and the legacy machine-global stamp
    /// must be cleaned up, never read.
    #[test]
    fn digest_tracks_gem_file_content_and_legacy_stamp_is_removed() {
        if !have("ruby") {
            eprintln!("skip plugin_runtime: ruby not on PATH");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        scaffold(root);
        let (fake, log) = write_fake_apply(root, 0);

        // Where bundler would install this project's gems (BUNDLE_PATH set,
        // so <root>/vendor/bundle/ruby/<ver>).
        let mut cmd = Command::new("ruby");
        cmd.args(["-e", "require \"bundler\"; print Bundler.bundle_path"])
            .current_dir(root);
        scrub(&mut cmd);
        cmd.env("BUNDLE_PATH", "vendor/bundle");
        let (code, bundle_path, err) = run(cmd);
        assert_eq!(code, 0, "Bundler.bundle_path probe failed: {err}");
        let bundle_path = PathBuf::from(bundle_path.trim());

        // The installed file the manifest's patch record targets.
        let target = bundle_path.join("gems/colorize-1.1.0/lib/colorize.rb");
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::write(&target, "UPSTREAM CONTENT\n").unwrap();
        // A stale stamp from the old plugin version in the shared location.
        let legacy = bundle_path.join(LEGACY_STAMP_NAME);
        std::fs::write(&legacy, "stale digest from another project\n").unwrap();

        let drive = |label: &str| {
            let mut cmd = Command::new("ruby");
            cmd.args([
                "-e",
                "require \"bundler\"; load ARGV[0]; SocketPatch.apply!",
                "--",
            ])
            .arg(root.join(".socket/bundler-plugin/plugins.rb"))
            .current_dir(root);
            scrub(&mut cmd);
            cmd.env("BUNDLE_PATH", "vendor/bundle");
            cmd.env("SOCKET_PATCH_BIN", &fake);
            let (code, out, err) = run(cmd);
            assert_eq!(
                code, 0,
                "{label}: driving the applier failed.\n{out}\n{err}"
            );
        };

        drive("initial apply");
        assert_eq!(
            apply_calls(&log).len(),
            1,
            "first drive must shell apply (nothing stamped yet)"
        );
        assert!(root.join(STAMP_REL).is_file(), "stamp written");
        assert!(
            !legacy.exists(),
            "the legacy bundle-path stamp must be deleted on the first run"
        );

        drive("stamped no-op");
        assert_eq!(
            apply_calls(&log).len(),
            1,
            "unchanged state must be digest-gated to a no-op"
        );

        // Out-of-band reversion: the committed inputs (manifest, blobs, lock)
        // are untouched — only the installed gem file changed back.
        std::fs::write(&target, "REVERTED BY PRISTINE\n").unwrap();
        drive("after reversion");
        assert_eq!(
            apply_calls(&log).len(),
            2,
            "reverting the installed gem file must flip the digest and \
             re-run apply — a manifest-only digest misses this"
        );
    }

    fn walk(dir: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let Ok(entries) = std::fs::read_dir(dir) else {
            return out;
        };
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                out.extend(walk(&p));
            } else {
                out.push(p);
            }
        }
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Guards for the RubyGems CLI launcher (gem/socket-patch), driven with the
// host ruby. Ruby-gated with a loud skip, like `plugin_runtime` above.
// ─────────────────────────────────────────────────────────────────────────
#[cfg(unix)]
mod launcher_guard {
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    fn have_ruby() -> bool {
        Command::new("ruby")
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// The launcher under test, resolved from the workspace checkout.
    fn launcher_path() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../gem/socket-patch/lib/socket_patch/launcher.rb")
            .canonicalize()
            .expect("launcher.rb must exist in the workspace")
    }

    /// Run `script` (which `load`s the launcher via the SP_LAUNCHER env) with
    /// a scratch HOME/cache so no real launcher cache is consulted.
    fn run_ruby(script: &Path, cache: &Path, envs: &[(&str, &str)]) -> (i32, String, String) {
        let mut cmd = Command::new("ruby");
        cmd.arg(script);
        cmd.env_remove("SOCKET_PATCH_BIN");
        cmd.env("SP_LAUNCHER", launcher_path());
        cmd.env("XDG_CACHE_HOME", cache);
        for (k, v) in envs {
            cmd.env(k, v);
        }
        let out = cmd.output().expect("spawn ruby");
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).to_string(),
            String::from_utf8_lossy(&out.stderr).to_string(),
        )
    }

    fn write_executable(path: &Path, body: &str) {
        std::fs::write(path, body).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// [P2a] The Windows arm must propagate the child's REAL exit code — the
    /// old `system(...) ? $?.exitstatus : 1` collapsed every non-zero exit to
    /// 1, erasing meaningful codes like `setup --check`'s needs-configuration
    /// signal. Forced onto the Windows branch by stubbing `Gem.win_platform?`.
    #[test]
    fn windows_branch_propagates_child_exit_code() {
        if !have_ruby() {
            eprintln!("skip launcher_guard: ruby not on PATH");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let child = tmp.path().join("exit7");
        write_executable(&child, "#!/bin/sh\nexit 7\n");
        let script = tmp.path().join("drive.rb");
        std::fs::write(
            &script,
            "require \"rubygems\"\n\
             def Gem.win_platform?; true; end\n\
             load ENV.fetch(\"SP_LAUNCHER\")\n\
             SocketPatch::Launcher.run([\"anything\"])\n",
        )
        .unwrap();

        let (code, out, err) = run_ruby(
            &script,
            &tmp.path().join("cache"),
            &[("SOCKET_PATCH_BIN", child.to_str().unwrap())],
        );
        assert_eq!(
            code, 7,
            "the child's exit 7 must survive the spawn+wait arm, not \
             collapse to 1.\nstdout:\n{out}\nstderr:\n{err}"
        );
    }

    /// [nit] First-run failures outside LauncherError (DNS outages, TLS
    /// errors, ...) must exit with a clean one-line message, not a raw ruby
    /// backtrace.
    #[test]
    fn unexpected_download_errors_exit_cleanly() {
        if !have_ruby() {
            eprintln!("skip launcher_guard: ruby not on PATH");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let script = tmp.path().join("drive.rb");
        std::fs::write(
            &script,
            "require \"net/http\"\n\
             def (Net::HTTP).start(*args, &block)\n\
               raise SocketError, \"simulated dns failure\"\n\
             end\n\
             load ENV.fetch(\"SP_LAUNCHER\")\n\
             SocketPatch::Launcher.run([\"--version\"])\n",
        )
        .unwrap();

        let (code, out, err) = run_ruby(&script, &tmp.path().join("cache"), &[]);
        assert_eq!(code, 1, "a download failure exits 1.\n{out}\n{err}");
        assert!(
            err.contains("socket-patch:") && err.contains("SocketError"),
            "the failure must be reported as a clean launcher message:\n{err}"
        );
        assert!(
            !err.contains("launcher.rb:"),
            "no raw backtrace frames may escape to the user:\n{err}"
        );
    }

    /// [nit] PowerShell quoting: a path containing a single quote must be
    /// escaped by doubling it, or the Expand-Archive fallback command breaks.
    #[test]
    fn powershell_quote_doubles_single_quotes() {
        if !have_ruby() {
            eprintln!("skip launcher_guard: ruby not on PATH");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let script = tmp.path().join("drive.rb");
        std::fs::write(
            &script,
            "load ENV.fetch(\"SP_LAUNCHER\")\n\
             print SocketPatch::Launcher.powershell_quote(\"C:/it's a dir/x.zip\")\n",
        )
        .unwrap();

        let (code, out, err) = run_ruby(&script, &tmp.path().join("cache"), &[]);
        assert_eq!(code, 0, "quoting helper must exist and run.\n{err}");
        assert_eq!(
            out, "'C:/it''s a dir/x.zip'",
            "single quotes must be doubled inside the single-quoted literal"
        );
        // And the Expand-Archive fallback actually routes through it.
        let launcher = std::fs::read_to_string(launcher_path()).unwrap();
        assert!(
            launcher.contains("-LiteralPath #{powershell_quote(archive_path)}")
                && launcher.contains("-DestinationPath #{powershell_quote(dir)}"),
            "extract's PowerShell fallback must quote both paths via the helper"
        );
    }

    /// [P2b] The binary-cache install must be atomic: staged in the
    /// destination dir and renamed into place, leaving no temp litter — a
    /// concurrent first run can then never exec a torn or not-yet-chmodded
    /// binary. (The rename mechanism itself is pinned by inspection since a
    /// mid-write race cannot be scheduled deterministically from a test.)
    #[test]
    fn install_executable_is_atomic_into_place() {
        if !have_ruby() {
            eprintln!("skip launcher_guard: ruby not on PATH");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("extracted-binary");
        std::fs::write(&src, "BINARY CONTENT\n").unwrap();
        let dest = tmp.path().join("cache/1.0.0/target/socket-patch");
        let script = tmp.path().join("drive.rb");
        std::fs::write(
            &script,
            "load ENV.fetch(\"SP_LAUNCHER\")\n\
             SocketPatch::Launcher.install_executable(ARGV[0], ARGV[1])\n",
        )
        .unwrap();

        let mut cmd = Command::new("ruby");
        cmd.arg(&script).arg(&src).arg(&dest);
        cmd.env("SP_LAUNCHER", launcher_path());
        let out = cmd.output().expect("spawn ruby");
        assert!(
            out.status.success(),
            "install_executable must exist and succeed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            std::fs::read_to_string(&dest).unwrap(),
            "BINARY CONTENT\n",
            "the cached binary must be byte-identical to the extracted one"
        );
        let mode = std::fs::metadata(&dest).unwrap().permissions().mode();
        assert_ne!(mode & 0o111, 0, "the cached binary must be executable");
        let litter: Vec<_> = std::fs::read_dir(dest.parent().unwrap())
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n != "socket-patch")
            .collect();
        assert!(
            litter.is_empty(),
            "no staging temp files may be left behind: {litter:?}"
        );
        let launcher = std::fs::read_to_string(launcher_path()).unwrap();
        assert!(
            launcher.contains("File.rename(tmp, dest)"),
            "the cache publish must go through a same-dir rename"
        );
    }
}
