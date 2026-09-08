//! Coverage-gap integration test for `setup/gem/mod.rs` (audit at d5e1815):
//! the binary-level gem `setup` → `setup --remove` round trip that clears
//! bundler's machine-local plugin registration under `BUNDLE_APP_CONFIG`.
//!
//! The env var is read once at the pub entry point
//! (`gem/update.rs::remove_plugin_directive`) and threaded into the inner
//! `_at` functions — the inline tests all inject it explicitly, so the real
//! process-env resolution (a relative value resolving against the PROJECT
//! root, exactly like `Bundler.app_config_path`) only runs through the built
//! binary. The feature-gated `setup_matrix_gem.rs` is the only other place
//! this is driven end-to-end, and it never compiles in the default test
//! configuration.

use std::path::Path;

#[path = "common/mod.rs"]
mod common;

const GEMFILE_FIXTURE: &str = "source 'https://rubygems.org'\ngem 'colorize', '1.1.0'\n";

/// A Gemfile.lock whose `BUNDLED WITH` pins a supported bundler: the version
/// probe classifies from the lock BEFORE ever spawning `bundle`, so no host
/// `bundle --version` (a 1.x machine bundler, or none at all) can steer this
/// test.
const LOCK_2X: &str = "GEM\n  remote: https://rubygems.org/\n  specs:\n    \
                       colorize (1.1.0)\n\nPLATFORMS\n  ruby\n\nDEPENDENCIES\n  \
                       colorize (= 1.1.0)\n\nBUNDLED WITH\n   2.7.2\n";

fn write(path: &Path, content: &str) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create parent");
    }
    std::fs::write(path, content).expect("write file");
}

/// The single `files[]` entry with the given `kind` (panics on 0 or >1).
fn entry_of<'a>(v: &'a serde_json::Value, kind: &str) -> &'a serde_json::Value {
    let matches: Vec<&serde_json::Value> = v["files"]
        .as_array()
        .unwrap_or_else(|| panic!("files must be an array: {v}"))
        .iter()
        .filter(|f| f["kind"] == kind)
        .collect();
    assert_eq!(
        matches.len(),
        1,
        "expected exactly one `{kind}` entry, got {}: {v}",
        matches.len()
    );
    matches[0]
}

/// setup → plant bundler's machine-local registration at the
/// `BUNDLE_APP_CONFIG` location → `setup --remove` with that env var set.
/// The remove must resolve the relative value against the project root
/// (`<root>/bundle-config/plugin/index`), clear the registration there,
/// report it as a `gem_plugin_registration` envelope entry, and leave a
/// decoy index at the DEFAULT `.bundle` location untouched.
#[test]
fn setup_remove_clears_bundler_registration_under_bundle_app_config() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = tmp.path();
    write(&root.join("Gemfile"), GEMFILE_FIXTURE);
    write(&root.join("Gemfile.lock"), LOCK_2X);

    // Step 1: wire. (No manifest on disk: the nested materialization apply
    // treats a missing manifest as a clean exit-0 no-op, so stdout stays one
    // JSON document.)
    let (code, stdout, stderr) = common::run_with_env(
        root,
        &["setup", "--yes", "--json", "--ecosystems", "gem"],
        &[],
    );
    assert_eq!(code, 0, "gem setup must succeed.\nstdout:\n{stdout}\nstderr:\n{stderr}");
    let v = common::parse_json_envelope(&stdout);
    assert_eq!(v["status"], "success", "{v}");
    assert!(
        std::fs::read_to_string(root.join("Gemfile"))
            .unwrap()
            .contains("plugin 'socket-patch'"),
        "setup must wire the plugin directive"
    );
    assert!(
        root.join(".socket/bundler-plugin/plugins.rb").is_file(),
        "setup must generate the plugin files"
    );

    // Step 2: plant the registration bundler would write on first install —
    // at the BUNDLE_APP_CONFIG location (relative → resolves against the
    // project root), with the recorded plugin path pointing at the generated
    // plugin dir, exactly like a real `path:`-sourced install.
    let plugin_dir = root.join(".socket/bundler-plugin").display().to_string();
    let index = root.join("bundle-config/plugin/index");
    write(
        &index,
        &format!(
            "---\ncommands:\nhooks:\n  after-install:\n  - \"socket-patch\"\n  \
             after-install-all:\n  - \"socket-patch\"\nload_paths:\n  socket-patch:\n  \
             - \"{plugin_dir}/.\"\nplugin_paths:\n  socket-patch: \"{plugin_dir}\"\nsources:\n"
        ),
    );
    // A decoy at the DEFAULT app-config location: with BUNDLE_APP_CONFIG
    // pointing elsewhere it is out of scope and must survive byte-identical.
    let decoy = root.join(".bundle/plugin/index");
    let decoy_body = "---\ncommands:\nhooks:\n  after-install:\n  - \"socket-patch\"\n\
         load_paths:\n  socket-patch:\n  - \"/elsewhere/.\"\nplugin_paths:\n  \
         socket-patch: \"/elsewhere\"\nsources:\n";
    write(&decoy, decoy_body);

    // Step 3: unwire with BUNDLE_APP_CONFIG set (child-only env injection).
    let (code, stdout, stderr) = common::run_with_env(
        root,
        &["setup", "--remove", "--yes", "--json", "--ecosystems", "gem"],
        &[("BUNDLE_APP_CONFIG", "bundle-config")],
    );
    assert_eq!(
        code, 0,
        "gem remove must succeed.\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let v = common::parse_json_envelope(&stdout);
    assert_eq!(v["status"], "success", "{v}");
    assert_eq!(entry_of(&v, "gemfile")["status"], "removed", "{v}");
    assert_eq!(entry_of(&v, "gem_plugin")["status"], "removed", "{v}");
    let reg = entry_of(&v, "gem_plugin_registration");
    assert_eq!(
        reg["status"], "removed",
        "the registration cleanup must be reported: {v}"
    );
    assert!(
        reg["path"]
            .as_str()
            .expect("registration entry carries the index path")
            .ends_with(&format!(
                "bundle-config{0}plugin{0}index",
                std::path::MAIN_SEPARATOR
            )),
        "the cleaned index must be the BUNDLE_APP_CONFIG one: {v}"
    );

    // On disk: the env-resolved index is cleared and its emptied dirs pruned;
    // the default-location decoy is out of scope and untouched.
    assert!(!index.exists(), "the app-config index must be deleted");
    assert!(
        !root.join("bundle-config").exists(),
        "the emptied app-config dir must be pruned"
    );
    assert_eq!(
        std::fs::read_to_string(&decoy).unwrap(),
        decoy_body,
        "the default-location index is out of scope when BUNDLE_APP_CONFIG points elsewhere"
    );

    // And the rest of the unwire held: Gemfile restored byte-for-byte,
    // generated plugin dir gone.
    assert_eq!(
        std::fs::read_to_string(root.join("Gemfile")).unwrap(),
        GEMFILE_FIXTURE,
        "remove must restore the Gemfile byte-for-byte"
    );
    assert!(
        !root.join(".socket/bundler-plugin").exists(),
        "remove must delete the generated plugin dir"
    );
}
