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
        run_env(cwd, args, &[])
    }

    /// [`run`] with extra environment variables for the child (e.g. bundler's
    /// `BUNDLE_APP_CONFIG`, which relocates the machine-local registration
    /// `--remove` must clean).
    fn run_env(cwd: &Path, args: &[&str], envs: &[(&str, &str)]) -> (i32, String, String) {
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
        // An ambient BUNDLE_APP_CONFIG would relocate where `--remove` looks
        // for bundler's plugin registration — strip it so only the explicit
        // per-test env below can steer that resolution.
        cmd.env_remove("BUNDLE_APP_CONFIG");
        for (k, v) in envs {
            cmd.env(k, v);
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
        // The plugin's digest stamp is machine-local, but it lives in the
        // otherwise-committed .socket/ — setup must gitignore it, or every
        // install litters `git status` and a blanket `git add .socket`
        // commits one machine's stamp to every clone.
        let gitignore = std::fs::read_to_string(root.join(".socket/.gitignore")).unwrap();
        assert!(
            gitignore.lines().any(|l| l == "/gem-plugin-stamp"),
            ".socket/.gitignore must carry the stamp entry:\n{gitignore}"
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
        // A stamp left behind by a previous apply: `--remove`'s no-residue
        // contract covers it (it sits in the committed .socket/ dir).
        std::fs::write(root.join(".socket/gem-plugin-stamp"), "e".repeat(64)).unwrap();
        // Bundler's machine-local plugin registration, exactly as the first
        // `bundle install` after `setup` writes it (bundler's YAMLSerializer
        // dialect, verified against bundler 2.7.2 / 4.0.18): the hook
        // subscriptions + load/plugin paths in `.bundle/plugin/index`.
        // `--remove` must clear it too — a dangling registration makes every
        // later `bundle install` print bundler's "The following plugin paths
        // don't exist ... Continuing without installing plugin socket-patch"
        // block (with a misleading reinstall suggestion) forever.
        let plugin_reg_dir = root.join(".bundle").join("plugin");
        std::fs::create_dir_all(&plugin_reg_dir).unwrap();
        let index_path = plugin_reg_dir.join("index");
        std::fs::write(
            &index_path,
            format!(
                "---\ncommands:\nhooks:\n  after-install:\n  - \"socket-patch\"\n  \
                 after-install-all:\n  - \"socket-patch\"\nload_paths:\n  socket-patch:\n  \
                 - \"{root_s}/.socket/bundler-plugin/.\"\nplugin_paths:\n  \
                 socket-patch: \"{root_s}/.socket/bundler-plugin\"\nsources:\n"
            ),
        )
        .unwrap();
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
        assert!(
            !root.join(".socket/gem-plugin-stamp").exists(),
            "remove must delete the plugin's digest stamp — unwiring must not \
             orphan it in the committed .socket/"
        );
        assert!(
            !root.join(".socket/.gitignore").exists(),
            "remove must delete the .gitignore setup created (it held only our line)"
        );
        // The machine-local registration must be gone too. socket-patch was
        // the ONLY registered plugin, so nothing in the index is left worth
        // keeping — the index (and thereby every socket-patch entry) must not
        // survive.
        let residue = std::fs::read_to_string(&index_path).unwrap_or_default();
        assert!(
            !residue.contains("socket-patch"),
            "remove must clear bundler's machine-local plugin registration \
             (.bundle/plugin/index) — a dangling entry makes every later \
             `bundle install` warn \"plugin paths don't exist ... Continuing \
             without installing plugin socket-patch\":\n{residue}"
        );
        assert!(
            !index_path.exists(),
            "socket-patch was the only registered plugin: the emptied index \
             must be deleted, not left as an all-empty husk"
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

    /// `setup --remove` must clear bundler's machine-local plugin
    /// registration SURGICALLY: only the socket-patch entries leave the
    /// index; another plugin's registration (its hook subscriptions and
    /// paths) survives byte-intact. And the index location must follow
    /// bundler's own `BUNDLE_APP_CONFIG` resolution — a relative value
    /// resolves against the project root (`Bundler.app_config_path`), not
    /// the process cwd or a hardcoded `.bundle`.
    #[test]
    fn gem_setup_remove_strips_registration_surgically_under_bundle_app_config() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::write(root.join("Gemfile"), GEMFILE).unwrap();
        let root_s = root.to_str().unwrap();

        // Wire the project (the registration below is what bundler would
        // write on the first `bundle install` after this).
        let (code, out, err) = run_env(
            root,
            &["setup", "--cwd", root_s, "--yes", "--json"],
            &[("BUNDLE_APP_CONFIG", "bundle-config")],
        );
        assert_eq!(code, 0, "setup must exit 0.\n{out}\n{err}");

        // The registration lives under the RELATIVE app-config dir, resolved
        // against the project root — bundler's own resolution rule.
        let plugin_reg_dir = root.join("bundle-config").join("plugin");
        std::fs::create_dir_all(&plugin_reg_dir).unwrap();
        let index_path = plugin_reg_dir.join("index");
        std::fs::write(
            &index_path,
            format!(
                "---\ncommands:\nhooks:\n  after-install:\n  - \"other-plugin\"\n  \
                 - \"socket-patch\"\n  after-install-all:\n  - \"socket-patch\"\n  \
                 before-install-all:\n  - \"other-plugin\"\nload_paths:\n  other-plugin:\n  \
                 - \"{root_s}/plugins/other-plugin/.\"\n  socket-patch:\n  \
                 - \"{root_s}/.socket/bundler-plugin/.\"\nplugin_paths:\n  \
                 other-plugin: \"{root_s}/plugins/other-plugin\"\n  \
                 socket-patch: \"{root_s}/.socket/bundler-plugin\"\nsources:\n"
            ),
        )
        .unwrap();

        let (code, out, err) = run_env(
            root,
            &["setup", "--remove", "--cwd", root_s, "--yes", "--json"],
            &[("BUNDLE_APP_CONFIG", "bundle-config")],
        );
        assert_eq!(code, 0, "remove must exit 0.\n{out}\n{err}");
        assert_eq!(
            json_str(&parse_json(&out, "remove"), "status", "remove"),
            "success"
        );

        let index = std::fs::read_to_string(&index_path).unwrap_or_else(|e| {
            panic!(
                "the index must SURVIVE (another plugin is still registered), \
                 not be deleted wholesale: {e}"
            )
        });
        assert!(
            !index.contains("socket-patch"),
            "every socket-patch registration entry must be stripped:\n{index}"
        );
        for kept in [
            "  after-install:\n  - \"other-plugin\"",
            "  before-install-all:\n  - \"other-plugin\"",
            &format!("  other-plugin:\n  - \"{root_s}/plugins/other-plugin/.\"") as &str,
            &format!("  other-plugin: \"{root_s}/plugins/other-plugin\"") as &str,
        ] {
            assert!(
                index.contains(kept),
                "the OTHER plugin's registration must survive verbatim — \
                 missing {kept:?} in:\n{index}"
            );
        }
        assert!(
            !index.contains("after-install-all:"),
            "a hook event left with NO subscribers must be dropped, not left \
             as an empty key bundler chokes on:\n{index}"
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
        // The strict raise must tell the truth about the active mode: the
        // tolerant trailer ("`bundle install` continues; set
        // SOCKET_PATCH_STRICT=1 ...") is false on both counts while the
        // install is failing and the var is already set.
        assert!(
            err.contains("because SOCKET_PATCH_STRICT is set"),
            "the strict failure must say WHY the install is failing:\n{err}"
        );
        assert!(
            !err.contains("`bundle install` continues"),
            "the strict failure must not claim the install continues:\n{err}"
        );
    }

    /// [P0 regression: committed stale stamp] `.socket/` is a committed
    /// directory, so a stamp that reaches version control (a blanket
    /// `git add .socket`) arrives on every fresh clone BEFORE the first
    /// `bundle install`. If the bootstrap gate keyed on the stamp's
    /// existence, plugin REGISTRATION would shell the applier (targets
    /// absent -> apply fails) and a strict-mode raise there resurrects the
    /// exact deadlock this plugin exists to avoid — exit 29, "Failed to
    /// install plugin", every retry identical (reproduced on bundler
    /// 4.0.15). The gate must key on the patch targets existing on disk:
    /// registration completes, strict enforcement waits for the
    /// post-install hooks.
    #[test]
    fn committed_stale_stamp_does_not_deadlock_strict_fresh_clone() {
        if !have("bundle") {
            eprintln!("skip plugin_runtime: bundler not on PATH");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        scaffold(root);
        // The stale stamp a teammate committed, exactly as a fresh clone sees it.
        std::fs::write(root.join(STAMP_REL), "a".repeat(64)).unwrap();
        let (fake, log) = write_fake_apply(root, 1);

        let (code, out, err) = bundle_install(root, &fake, &[("SOCKET_PATCH_STRICT", "1")]);
        // Registration must complete — the strict failure may only come from
        // the post-install hooks, never from plugin registration.
        assert!(
            !err.contains("Failed to install plugin"),
            "a committed stale stamp must not fail plugin REGISTRATION.\n{out}\n{err}"
        );
        assert!(
            root.join(".bundle/plugin/index").is_file(),
            "registration must be recorded despite the strict failure.\n{out}\n{err}"
        );
        assert_ne!(
            code, 0,
            "strict mode still fails the install — from the hook.\n{out}\n{err}"
        );
        assert!(
            !apply_calls(&log).is_empty(),
            "anti-vacuity: the forced post-install apply ran (and failed)"
        );

        // The deadlock is gone: with apply working, the SAME checkout (stale
        // stamp still in place) converges on retry.
        let (fake, _log) = write_fake_apply(root, 0);
        let (code, out, err) = bundle_install(root, &fake, &[("SOCKET_PATCH_STRICT", "1")]);
        assert_eq!(
            code, 0,
            "retry with a working apply must succeed — registration was never \
             poisoned.\n{out}\n{err}"
        );
    }

    /// The bootstrap gate reads the LIVE gem tree, never the stamp. Both
    /// directions matter: with no patch target on disk the gated triggers
    /// must not shell out no matter what a (stale, possibly committed) stamp
    /// says; with the target present they must re-apply even when the stamp
    /// is missing — a `bundle pristine` run after deleting the stamp used to
    /// leave the patches silently reverted until the next `bundle install`
    /// (reproduced on bundler 4.0.15).
    #[test]
    fn bootstrap_gate_keys_on_target_presence_not_stamp() {
        if !have("ruby") {
            eprintln!("skip plugin_runtime: ruby not on PATH");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        scaffold(root);
        let (fake, log) = write_fake_apply(root, 0);

        // Drive the gated path exactly as the load-time / per-gem hooks do.
        let drive = |label: &str| {
            let mut cmd = Command::new("ruby");
            cmd.args([
                "-e",
                "require \"bundler\"; load ARGV[0]; SocketPatch.apply!(bootstrap_gate: true)",
                "--",
            ])
            .arg(root.join(".socket/bundler-plugin/plugins.rb"))
            .current_dir(root);
            scrub(&mut cmd);
            cmd.env("BUNDLE_PATH", "vendor/bundle");
            cmd.env("SOCKET_PATCH_BIN", &fake);
            let (code, out, err) = run(cmd);
            assert_eq!(code, 0, "{label}: gated drive failed.\n{out}\n{err}");
        };

        // Fresh clone: no target on disk, stale stamp committed.
        std::fs::write(root.join(STAMP_REL), "b".repeat(64)).unwrap();
        drive("no target, stale stamp");
        assert_eq!(
            apply_calls(&log).len(),
            0,
            "no target on disk -> the gated trigger must not shell out, \
             whatever the stamp says"
        );

        // Target installed, stamp deleted: the pristine-heal case.
        let mut cmd = Command::new("ruby");
        cmd.args(["-e", "require \"bundler\"; print Bundler.bundle_path"])
            .current_dir(root);
        scrub(&mut cmd);
        cmd.env("BUNDLE_PATH", "vendor/bundle");
        let (code, bundle_path, err) = run(cmd);
        assert_eq!(code, 0, "Bundler.bundle_path probe failed: {err}");
        let target = PathBuf::from(bundle_path.trim()).join("gems/colorize-1.1.0/lib/colorize.rb");
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::write(&target, "REVERTED BY PRISTINE\n").unwrap();
        std::fs::remove_file(root.join(STAMP_REL)).unwrap();

        drive("target present, no stamp");
        assert_eq!(
            apply_calls(&log).len(),
            1,
            "with the target on disk and nothing validly stamped, the gated \
             trigger must re-apply — deleting the stamp defers nothing"
        );
        drive("digest-gated no-op");
        assert_eq!(
            apply_calls(&log).len(),
            1,
            "the re-apply stamped the state; the next gated probe is a no-op"
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

    /// [P2 remove leaves registration dangling] Bundler records the plugin
    /// machine-locally at first install (`.bundle/plugin/index`: hook
    /// subscriptions + plugin/load paths). `setup --remove` unwires the
    /// Gemfile and deletes the generated plugin dir — if it leaves that
    /// registration behind, EVERY later `bundle install` prints bundler's
    /// 5-line "The following plugin paths don't exist ... Continuing without
    /// installing plugin socket-patch" block with a misleading reinstall
    /// suggestion (install still exits 0, so nothing ever heals it).
    /// Reproduced against real bundler 2.7.2 and 4.0.18 in the 2026-08 e2e
    /// campaign; this drives the same flow with the host bundler.
    #[test]
    fn setup_remove_clears_bundler_plugin_registration() {
        if !have("bundle") {
            eprintln!("skip plugin_runtime: bundler not on PATH");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        scaffold(root);
        let (fake, _log) = write_fake_apply(root, 0);

        // First install: bundler registers the plugin machine-locally.
        let (code, out, err) = bundle_install(root, &fake, &[]);
        assert_eq!(code, 0, "wired install must succeed.\n{out}\n{err}");
        let index_path = root.join(".bundle/plugin/index");
        assert!(
            std::fs::read_to_string(&index_path)
                .unwrap_or_default()
                .contains("socket-patch"),
            "precondition: bundler must have registered the plugin at {}",
            index_path.display()
        );

        // Unwire.
        let mut cmd = Command::new(binary());
        cmd.args(["setup", "--remove", "--yes", "--json"])
            .current_dir(root);
        scrub(&mut cmd);
        let (code, out, err) = run(cmd);
        assert_eq!(code, 0, "setup --remove must exit 0.\n{out}\n{err}");
        assert!(
            out.contains("\"status\": \"success\""),
            "setup --remove must report success:\n{out}"
        );

        // No socket-patch registration may survive under .bundle/plugin.
        let residue = std::fs::read_to_string(&index_path).unwrap_or_default();
        assert!(
            !residue.contains("socket-patch"),
            ".bundle/plugin must hold no socket-patch entry after remove:\n{residue}"
        );

        // And the REAL oracle: the next bundle install is silent about the
        // unwired plugin — no "plugin paths don't exist", no "Continuing
        // without installing plugin", on either stream.
        let (code, out, err) = bundle_install(root, &fake, &[]);
        assert_eq!(
            code, 0,
            "post-remove install must still succeed.\n{out}\n{err}"
        );
        let combined = format!("{out}\n{err}");
        assert!(
            !combined.contains("plugin paths don't exist"),
            "post-remove `bundle install` must not warn about the unwired \
             plugin's missing paths:\n{combined}"
        );
        assert!(
            !combined.contains("Continuing without installing plugin"),
            "post-remove `bundle install` must not print bundler's \
             skipped-plugin block:\n{combined}"
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

    /// [P2 Windows platform-gem glob] `Bundler.bundle_path` carries
    /// backslash separators through verbatim (Windows spelling), and
    /// `Dir.glob` treats `\` as an escape on EVERY platform — so the
    /// platform-install wildcard (`<gems>/<name>-<version>-*/<rel>`) built
    /// from that base escape-eats the separator, matches nothing, and
    /// platform installs (colorize-1.1.0-x64-mingw-ucrt) silently drop out
    /// of the digest: a `bundle pristine` reversion of them leaves the stamp
    /// matching and the re-apply skipped. Simulated on this host by feeding
    /// bundler a backslash-bearing BUNDLE_PATH while the real tree lives at
    /// the forward-slash spelling — exactly the two-spellings-one-directory
    /// situation Windows creates (glob escape semantics are identical
    /// everywhere). The plugin must glob a slash-normalized base; forward
    /// slashes are valid separators on Windows.
    #[test]
    fn backslash_bundle_path_still_digests_platform_gem_files() {
        if !have("ruby") {
            eprintln!("skip plugin_runtime: ruby not on PATH");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        scaffold(root);
        let (fake, log) = write_fake_apply(root, 0);

        // Where bundler puts this project's gems under the backslash spelling.
        let mut cmd = Command::new("ruby");
        cmd.args(["-e", "require \"bundler\"; print Bundler.bundle_path"])
            .current_dir(root);
        scrub(&mut cmd);
        cmd.env("BUNDLE_PATH", "vendor\\bundle");
        let (code, bundle_path, err) = run(cmd);
        assert_eq!(code, 0, "Bundler.bundle_path probe failed: {err}");
        let bundle_path = bundle_path.trim().to_string();
        assert!(
            bundle_path.contains('\\'),
            "precondition: bundler must carry the backslash spelling through \
             verbatim (the Windows behavior this test simulates), got: \
             {bundle_path:?}"
        );

        // On Windows both spellings denote the SAME directory; materialize
        // the real tree at the slash spelling — the one the normalized glob
        // must reach from the backslash-bearing base. Only a PLATFORM install
        // exists: the plain `colorize-1.1.0` direct join never globs and is
        // not at issue.
        let target = PathBuf::from(bundle_path.replace('\\', "/"))
            .join("gems/colorize-1.1.0-x64-mingw-ucrt/lib/colorize.rb");
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::write(&target, "PATCHED PLATFORM CONTENT\n").unwrap();

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
            cmd.env("BUNDLE_PATH", "vendor\\bundle");
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
        drive("stamped no-op");
        assert_eq!(
            apply_calls(&log).len(),
            1,
            "unchanged state must be digest-gated to a no-op"
        );

        // The pristine reversion the digest exists to catch — of the
        // PLATFORM install this time.
        std::fs::write(&target, "REVERTED BY PRISTINE\n").unwrap();
        drive("after platform-install reversion");
        assert_eq!(
            apply_calls(&log).len(),
            2,
            "reverting the platform gem install must flip the digest and \
             re-run apply — an escape-eaten glob omits platform installs \
             from the digest and skips this re-apply"
        );

        // And directly: the platform install is enumerated as a patch target.
        let mut cmd = Command::new("ruby");
        cmd.args([
            "-e",
            "require \"bundler\"; load ARGV[0]; puts SocketPatch.patch_target_files",
            "--",
        ])
        .arg(root.join(".socket/bundler-plugin/plugins.rb"))
        .current_dir(root);
        scrub(&mut cmd);
        cmd.env("BUNDLE_PATH", "vendor\\bundle");
        cmd.env("SOCKET_PATCH_BIN", &fake);
        let (code, out, err) = run(cmd);
        assert_eq!(code, 0, "patch_target_files probe failed.\n{out}\n{err}");
        assert!(
            out.contains("colorize-1.1.0-x64-mingw-ucrt"),
            "patch_target_files must enumerate the platform install under a \
             backslash-bearing bundle path:\n{out}"
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

    /// Strip the ambient vars that could flip a verdict, mirroring
    /// `plugin_runtime::scrub`: the CLI's SOCKET_* surface, and the
    /// bundler/rubygems config a `bundle exec cargo test` run injects
    /// (RUBYOPT=-rbundler/setup, BUNDLE_*, GEM_*) — which would activate a
    /// foreign bundle inside the child ruby under test.
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
    }

    /// Run `script` (which `load`s the launcher via the SP_LAUNCHER env) with
    /// a scratch HOME/cache so no real launcher cache is consulted.
    fn run_ruby(script: &Path, cache: &Path, envs: &[(&str, &str)]) -> (i32, String, String) {
        let mut cmd = Command::new("ruby");
        cmd.arg(script);
        scrub(&mut cmd);
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
        scrub(&mut cmd);
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
