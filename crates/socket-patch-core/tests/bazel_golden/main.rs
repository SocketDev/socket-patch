//! Bazel goldens: one module per ruleset or lane group, over
//! `tests/fixtures/bazel/` (`input/`, `overrides.json`, `expected/` and the
//! expected edits, warnings and confirmation per case). No Bazel, no
//! network: these prove what the rewriter group writes and that a restore
//! after a wire returns `input/` byte for byte, CRLF twins included.
//!
//! The cases never go under `tests/fixtures/redirect/`: that tree is a
//! byte-exact contract with the depscan backend's golden suite, which
//! fails on a flavor directory it does not list.
//!
//! ONE integration-test binary on purpose (each `tests/` target is its own
//! link). Every module is declared here and starts as a stub its owning
//! package replaces whole, so no later change edits this list. Run one
//! with a module filter, e.g. `cargo test -p socket-patch-core --test
//! bazel_golden rules_js::`.

mod claims;
mod common;
mod crate_substitution;
mod detect_fixtures;
mod gazelle;
mod gazelle_directory;
mod gazelle_workspace;
mod legacy;
mod pip_override;
mod rules_dotnet;
mod rules_js;
mod rules_jvm_external;
mod rules_jvm_external_restore;
mod rules_python;
mod rules_ruby;
mod rules_rust;
mod toy_lane;
mod uv_locks;

/// A file beside this one with no `mod` line above is not compiled, and
/// its tests would silently never run.
#[test]
fn every_file_is_a_declared_module() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/bazel_golden");
    let list = std::fs::read_to_string(dir.join("main.rs")).expect("read main.rs");
    let mut files = 0;
    for entry in std::fs::read_dir(&dir).expect("read bazel_golden") {
        let name = entry
            .expect("dir entry")
            .file_name()
            .to_string_lossy()
            .into_owned();
        let Some(module) = name.strip_suffix(".rs").filter(|m| *m != "main") else {
            continue;
        };
        assert!(
            list.lines().any(|l| l == format!("mod {module};")),
            "{name} is not declared in bazel_golden/main.rs"
        );
        files += 1;
    }
    assert!(files >= 18, "only {files} golden modules found");
}
