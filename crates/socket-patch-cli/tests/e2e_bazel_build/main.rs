//! Bazel builds: the real-Bazel suite. Every test here runs Bazel and is
//! `#[ignore]`: run it with `--ignored` and the `SOCKET_PATCH_BAZEL_E2E_*`
//! variables `scripts/install-bazelisk.sh` prints (see
//! `docs/testing/bazel-compatibility.md`). With no such variable a test
//! prints SKIP, writes a report of status `skipped` and passes.
//!
//! A test name starts with one of six prefixes, which the CI cells filter
//! on: `bazel_core_` (the toy fixture; zero network), `bazel_guard_`,
//! `bazel_agent_`, `bazel_hosted_`, `bazel_vendor_` and `bazel_canary_`
//! (record-only). Socket-patch never runs Bazel; these tests do, through
//! `bazel_build_common`, to prove with Bazel's own output that a build
//! consumes what socket-patch wrote, or still passes where it refused.
//!
//! ONE integration-test binary on purpose (each `tests/` target is its own
//! optimized link in CI's `test-release` job). Every module is declared
//! here and starts as a stub its owning package replaces whole, so no
//! later change edits this list. Run one module with a filter, e.g.
//! `cargo test -p socket-patch-cli --test e2e_bazel_build -- --ignored bazel_core_`.

#[path = "../bazel_build_common/mod.rs"]
mod bazel_build_common;
#[path = "../bazel_common/mod.rs"]
mod bazel_common;
#[path = "../common/mod.rs"]
mod common;

mod baseline_heavy;
mod baseline_light;
mod canary;
mod classifier;
mod core;
mod crate_substitution;
mod extras;
mod gazelle_directory;
mod gazelle_hosted;
mod gazelle_workspace;
mod go_evidence;
mod guard;
mod ignore;
mod launch;
mod legacy;
mod lines_beta;
mod lines_legacy;
mod liveness;
mod owned_segment;
mod pip_override;
mod rules_dotnet;
mod rules_js;
mod rules_jvm_external;
mod rules_python;
mod rules_ruby;
mod rules_rust;
mod stale;
mod uv_locks;

/// A file beside this one with no `mod` line above is not compiled, and
/// its tests would silently never run.
#[test]
fn every_file_is_a_declared_module() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/e2e_bazel_build");
    let list = std::fs::read_to_string(dir.join("main.rs")).expect("read main.rs");
    let mut files = 0;
    for entry in std::fs::read_dir(&dir).expect("read e2e_bazel_build") {
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
            "{name} is not declared in e2e_bazel_build/main.rs"
        );
        files += 1;
    }
    assert!(files >= 28, "only {files} suite modules found");
}
