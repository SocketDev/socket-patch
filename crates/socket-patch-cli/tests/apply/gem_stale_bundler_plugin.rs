//! #1295: a Bundler plugin registration v4's `setup` left in a checkout.
//!
//! v4's `setup --remove` cleared `.bundle/plugin/index`; v5 has no
//! `setup`, and `.bundle/` is never committed, so every other checkout
//! that ran `bundle install` under v4 still registers `socket-patch` at
//! the `.socket/bundler-plugin/` the migration commit deleted. Bundler
//! 2.3-2.5 then fail every `bundle install` with a `LoadError`. scan and
//! apply on a gem project must say so, with the one-line fix.

use crate::common::{git_sha256, run_with_env};

use std::path::Path;

const PURL: &str = "pkg:gem/rack@3.1.0";
const CODE: &str = "gem_bundler_plugin_stale";

/// A Gemfile project whose `.bundle/plugin/index` registers
/// `socket-patch` the way Bundler writes it after a v4 `setup` +
/// `bundle install`. `.socket/bundler-plugin/` exists only when
/// `plugin_dir_present`. With `with_patch`, a `vendor/bundle` store holds
/// rack@3.1.0 and the manifest carries a patch for it.
fn build_project(root: &Path, plugin_dir_present: bool, with_patch: bool) -> String {
    std::fs::write(root.join("Gemfile"), b"source 'https://rubygems.org'\n").unwrap();
    let plugin_dir = root.join(".socket").join("bundler-plugin");
    let dir = plugin_dir.display().to_string();
    let index_dir = root.join(".bundle").join("plugin");
    std::fs::create_dir_all(&index_dir).unwrap();
    std::fs::write(
        index_dir.join("index"),
        format!(
            "---\ncommands:\nhooks:\n  before-install-all:\n  - \"socket-patch\"\n\
             load_paths:\n  socket-patch:\n  - \"{dir}/lib\"\nplugin_paths:\n  \
             socket-patch: \"{dir}\"\nsources:\n"
        ),
    )
    .unwrap();
    if plugin_dir_present {
        std::fs::create_dir_all(&plugin_dir).unwrap();
    }
    if with_patch {
        let original = b"module Rack\n  VERSION = 'VULNERABLE'\nend\n";
        let mut patched = original.to_vec();
        patched.extend_from_slice(b"# SOCKET-PATCHED\n");
        let before_hash = git_sha256(original);
        let after_hash = git_sha256(&patched);
        let gem_lib = root.join("vendor/bundle/ruby/3.2.0/gems/rack-3.1.0/lib");
        std::fs::create_dir_all(&gem_lib).unwrap();
        std::fs::write(gem_lib.join("rack.rb"), original).unwrap();
        let socket = root.join(".socket");
        std::fs::create_dir_all(socket.join("blobs")).unwrap();
        std::fs::write(
            socket.join("manifest.json"),
            format!(
                r#"{{ "patches": {{
                    "{PURL}": {{
                        "uuid": "636f6e66-6967-4761-8264-000000001295",
                        "exportedAt": "2024-01-01T00:00:00Z",
                        "files": {{ "lib/rack.rb": {{
                            "beforeHash": "{before_hash}", "afterHash": "{after_hash}"
                        }}}},
                        "vulnerabilities": {{}}, "description": "stale-plugin fixture",
                        "license": "MIT", "tier": "free"
                    }}
                }}}}"#
            ),
        )
        .unwrap();
        std::fs::write(socket.join("blobs").join(&after_hash), &patched).unwrap();
    }
    dir
}

/// Run with no `gem` binary on PATH and the app config dir pinned to the
/// project's own `.bundle/`, so no ambient Bundler state is read.
fn run(root: &Path, args: &[&str]) -> (i32, String, String) {
    let empty_path = root.join("empty-bin");
    std::fs::create_dir_all(&empty_path).unwrap();
    let app_config = root.join(".bundle");
    let mut argv: Vec<&str> = args.to_vec();
    let cwd = root.display().to_string();
    argv.extend(["--cwd", cwd.as_str()]);
    run_with_env(
        root,
        &argv,
        &[
            ("PATH", empty_path.to_str().unwrap()),
            ("BUNDLE_APP_CONFIG", app_config.to_str().unwrap()),
        ],
    )
}

fn stale_warning(env: &serde_json::Value) -> Option<String> {
    env.get("warnings")?
        .as_array()?
        .iter()
        .find(|w| w.get("code").and_then(|c| c.as_str()) == Some(CODE))
        .and_then(|w| w.get("detail")?.as_str().map(str::to_string))
}

#[test]
fn scan_json_warns_about_stale_plugin_registration() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = build_project(tmp.path(), false, false);
    let (code, stdout, stderr) = run(tmp.path(), &["scan", "--json", "--yes"]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    let env: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("scan must emit JSON: {e}; stdout={stdout}"));
    let detail = stale_warning(&env)
        .unwrap_or_else(|| panic!("warnings[] must carry {CODE}.\nenvelope: {env}"));
    assert!(detail.contains(&dir), "detail names the path: {detail}");
    assert!(
        detail.contains("bundle plugin uninstall socket-patch"),
        "detail carries the remedy: {detail}"
    );
}

/// A v4 setup that is still wired loads fine: no warning.
#[test]
fn scan_json_is_quiet_while_the_plugin_dir_exists() {
    let tmp = tempfile::tempdir().unwrap();
    build_project(tmp.path(), true, false);
    let (code, stdout, stderr) = run(tmp.path(), &["scan", "--json", "--yes"]);
    assert_eq!(code, 0, "stdout:\n{stdout}\nstderr:\n{stderr}");
    let env: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(stale_warning(&env), None, "envelope: {env}");
}

#[test]
fn apply_warns_about_stale_plugin_registration() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = build_project(tmp.path(), false, true);
    let (code, stdout, stderr) = run(
        tmp.path(),
        &["apply", "--json", "--offline", "--ecosystems", "gem"],
    );
    let env: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("apply must emit JSON: {e}; stdout={stdout}"));
    assert_eq!(code, 0, "envelope: {env}\nstderr:\n{stderr}");
    assert_eq!(env["summary"]["applied"], 1, "envelope: {env}");
    let detail = stale_warning(&env)
        .unwrap_or_else(|| panic!("warnings[] must carry {CODE}.\nenvelope: {env}"));
    assert!(detail.contains(&dir), "detail names the path: {detail}");

    // Human path: one stderr line, gated on --silent.
    let (code, _out, stderr) = run(tmp.path(), &["apply", "--offline", "--ecosystems", "gem"]);
    assert_eq!(code, 0, "stderr:\n{stderr}");
    assert_eq!(
        stderr
            .matches("Warning: Bundler still registers the removed v4 socket-patch plugin")
            .count(),
        1,
        "stderr:\n{stderr}"
    );
    let (code, _out, stderr) = run(
        tmp.path(),
        &["apply", "--offline", "--ecosystems", "gem", "--silent"],
    );
    assert_eq!(code, 0, "stderr:\n{stderr}");
    assert!(
        !stderr.contains("Bundler still registers"),
        "stderr:\n{stderr}"
    );
}
