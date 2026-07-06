//! setup-matrix: gem ecosystem (bundler). `setup` now has REAL bundler support
//! — it appends a managed `plugin "socket-patch"` block to the Gemfile and
//! generates a committed in-tree Bundler plugin under `.socket/bundler-plugin/`
//! whose `plugins.rb` re-runs `socket-patch apply --ecosystems gem` on every
//! `bundle install` (load-time digest gate + `after-install-all` hook). So the
//! with-setup cases are no longer a baseline gap.
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
            if key.to_string_lossy().starts_with("SOCKET_") {
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
        assert!(
            rb.contains("BundlerError"),
            "plugins.rb must fail loud (raise Bundler::BundlerError) on a patch failure:\n{rb}"
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
            json_str(&parse_json(&out, "check (subdir)"), "status", "check (subdir)"),
            "needs_configuration"
        );

        // setup from the subdir: wires the ROOT project.
        let (code, out, err) = run(&sub, &["setup", "--yes", "--json"]);
        assert_eq!(code, 0, "setup from a subdirectory must exit 0.\n{out}\n{err}");
        assert_eq!(
            json_str(&parse_json(&out, "setup (subdir)"), "status", "setup (subdir)"),
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
