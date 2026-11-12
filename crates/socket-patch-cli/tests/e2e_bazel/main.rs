//! Bazel builds: the hermetic CLI suites, one module per hazard guard,
//! command or lane group. No Bazel, no network: the built binary runs
//! against a fake Socket API over the same fixture workspaces the
//! real-Bazel suite (`e2e_bazel_build`) builds, and every test that lets
//! the binary write asserts `bazel_common::assert_write_policy`: each
//! changed path must be a write socket-patch may make in a Bazel
//! repository.
//!
//! Children are spawned only through `common::run*` /
//! `hermetic::command`, never a bare `Command::new`, and never `bazel`:
//! socket-patch does not run Bazel, and neither does this suite.
//!
//! ONE integration-test binary on purpose (each `tests/` target is its own
//! optimized link in CI's `test-release` job). Every module is declared
//! here and starts as a stub its owning package replaces whole, so no
//! later change edits this list. A module that needs another shared
//! helper (`hosted_memory_common`, `prebuilt_common`, `vex_e2e_common`)
//! pulls it in itself with `#[path = "../<helper>/mod.rs"]`. Run one
//! module with a filter, e.g. `cargo test -p socket-patch-cli --test
//! e2e_bazel ignore::`.

#[path = "../bazel_common/mod.rs"]
mod bazel_common;
#[path = "../common/mod.rs"]
mod common;

mod agent;
mod agent_go;
mod consent;
mod crate_substitution;
mod gazelle;
mod gazelle_directory;
mod gazelle_workspace;
mod go_evidence;
mod guard_tree;
mod hosted_engine;
mod ignore;
mod legacy;
mod lines_beta;
mod lines_legacy;
mod links;
mod list;
mod memory;
mod owned_segment;
mod pip_override;
mod prune;
mod rollback;
mod roots;
mod rules_dotnet;
mod rules_js;
mod rules_jvm_external;
mod rules_jvm_external_vex;
mod rules_python;
mod rules_ruby;
mod rules_rust;
mod takeover;
mod uv_locks;
mod vendored;
mod vex;

/// A file beside this one with no `mod` line above is not compiled, and
/// its tests would silently never run.
#[test]
fn every_file_is_a_declared_module() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/e2e_bazel");
    let list = std::fs::read_to_string(dir.join("main.rs")).expect("read main.rs");
    let mut files = 0;
    for entry in std::fs::read_dir(&dir).expect("read e2e_bazel") {
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
            "{name} is not declared in e2e_bazel/main.rs"
        );
        files += 1;
    }
    assert!(files >= 33, "only {files} suite modules found");
}
