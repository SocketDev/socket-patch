//! Coverage-gap integration tests for the gem bundler-version MACHINE probe
//! (`setup/gem/version.rs`): the `bundle --version` PATH fallback that runs
//! when no lockfile pins a `BUNDLED WITH` version. The fallback cannot be
//! exercised deterministically in-process (PATH cannot be injected into
//! `probe_bundler`, and the parallel test runner forbids `set_var`), so these
//! tests drive the built binary with a PATH-shimmed fake `bundle` — the
//! `write_pm_shim` pattern from setup_pth_invariants.rs — pinning all three
//! spawn outcomes on any host:
//!   * parseable 1.x version on stdout → setup REFUSES to wire (a `gemfile`
//!     files[] error naming the version and the `bundle --version` source);
//!   * exit 0 but unparseable stdout → the probe fails OPEN, setup wires;
//!   * nonzero exit → the probe fails OPEN, setup wires.
//!
//! Sibling host-run gem tests live in setup_invariants.rs; this file is
//! additive (coverage-audit file-ownership rules). Shims are sh scripts, so
//! the whole file is unix-only — matching every other PATH-shim suite.
#![cfg(unix)]

#[path = "common/mod.rs"]
mod common;

use std::path::Path;

const GEMFILE_FIXTURE: &str = "source 'https://rubygems.org'\ngem 'colorize', '1.1.0'\n";

fn write(path: &Path, content: &str) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create parent");
    }
    std::fs::write(path, content).expect("write file");
}

/// Lay a fake `bundle` executable into `bin_dir` that appends its argv to
/// `log` (so the test can prove the machine probe actually spawned it),
/// optionally prints `stdout_line`, and exits with `exit_code`. Never reads
/// stdin, so it can't block the probe.
fn write_bundle_shim(bin_dir: &Path, log: &Path, stdout_line: Option<&str>, exit_code: i32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(bin_dir).expect("create shim dir");
    let echo = match stdout_line {
        Some(line) => format!("printf '%s\\n' '{line}'\n"),
        None => String::new(),
    };
    let body = format!(
        "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\n{echo}exit {exit_code}\n",
        log.display()
    );
    let p = bin_dir.join("bundle");
    std::fs::write(&p, body).expect("write bundle shim");
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).expect("chmod shim");
}

/// `setup --json --yes` with the shim dir prepended to PATH so the probe's
/// `bundle --version` spawn resolves to the fake. The ambient `SOCKET_*`
/// surface is scrubbed by `common::run_with_env` (load-bearing: an ambient
/// SOCKET_DRY_RUN/SOCKET_ECOSYSTEMS would silently flip what these exercise).
fn run_setup_with_bundle_shim(cwd: &Path, bin_dir: &Path) -> (i32, serde_json::Value) {
    let path_env = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let (code, stdout, _stderr) = common::run_with_env(
        cwd,
        &["setup", "--json", "--yes"],
        &[("SOCKET_TELEMETRY_DISABLED", "1"), ("PATH", &path_env)],
    );
    let v = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout must be JSON ({e}):\n{stdout}"));
    (code, v)
}

/// Assert the shim's argv log shows the probe ran exactly `bundle --version`
/// — proof the verdict under test came from the machine probe, not from some
/// other source (or from the real host bundler further down PATH).
fn assert_probe_spawned_bundle_version(log: &Path) {
    let argvs = std::fs::read_to_string(log)
        .expect("the bundle shim must have been invoked (argv log missing)");
    assert!(
        argvs.lines().any(|l| l == "--version"),
        "the machine probe must spawn `bundle --version`; argv log:\n{argvs}"
    );
}

// ---------------------------------------------------------------------------
// Parseable 1.x version → refusal (the classify path off a real spawn).
// ---------------------------------------------------------------------------

#[test]
fn machine_probe_bundler_1x_refuses_to_wire() {
    let tmp = tempfile::tempdir().expect("tempdir");
    // Gemfile only — NO Gemfile.lock, so the lock branch cannot answer and
    // the machine probe is the sole version source.
    write(&tmp.path().join("Gemfile"), GEMFILE_FIXTURE);
    let log = tmp.path().join("bundle-argv.log");
    write_bundle_shim(
        &tmp.path().join("bin"),
        &log,
        Some("Bundler version 1.17.3"),
        0,
    );

    let (code, v) = run_setup_with_bundle_shim(tmp.path(), &tmp.path().join("bin"));
    assert_eq!(code, 1, "a detected 1.x bundler must fail setup: {v}");
    assert_eq!(v["status"], "error", "envelope: {v}");

    let files = v["files"].as_array().expect("files[]");
    let gemfile = files
        .iter()
        .find(|f| f["kind"] == "gemfile")
        .unwrap_or_else(|| panic!("gemfile entry missing from envelope: {v}"));
    assert_eq!(gemfile["status"], "error", "envelope: {v}");
    let msg = gemfile["error"]
        .as_str()
        .unwrap_or_else(|| panic!("gemfile error message missing: {v}"));
    assert!(
        msg.contains("1.17.3"),
        "refusal must name the detected version: {msg}"
    );
    assert!(
        msg.contains("`bundle --version`"),
        "refusal must name the probe source: {msg}"
    );

    assert_probe_spawned_bundle_version(&log);

    // Refusal means NOTHING was wired: Gemfile byte-identical, no plugin dir.
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("Gemfile")).unwrap(),
        GEMFILE_FIXTURE,
        "a refused setup must not modify the Gemfile"
    );
    assert!(
        !tmp.path().join(".socket/bundler-plugin").exists(),
        "a refused setup must not generate the plugin dir"
    );
}

// ---------------------------------------------------------------------------
// Fail-open regions: `bundle --version` succeeded with unparseable stdout,
// or exited nonzero → Unknown → setup wires as if no probe ran.
// ---------------------------------------------------------------------------

/// Shared assertions for the two fail-open cases: exit 0, `success` status,
/// both gem artifacts reported updated, and the wiring actually on disk.
fn assert_failed_open_and_wired(tmp: &Path, code: i32, v: &serde_json::Value) {
    assert_eq!(code, 0, "the probe must fail OPEN (wire as before): {v}");
    assert_eq!(v["status"], "success", "envelope: {v}");

    let files = v["files"].as_array().expect("files[]");
    for kind in ["gemfile", "gem_plugin"] {
        let entry = files
            .iter()
            .find(|f| f["kind"] == kind)
            .unwrap_or_else(|| panic!("{kind} entry missing from envelope: {v}"));
        assert_eq!(entry["status"], "updated", "{kind} entry: {v}");
    }

    let gemfile = std::fs::read_to_string(tmp.join("Gemfile")).unwrap();
    assert!(
        gemfile.contains("plugin 'socket-patch'"),
        "fail-open setup must wire the Gemfile:\n{gemfile}"
    );
    assert!(
        tmp.join(".socket/bundler-plugin").exists(),
        "fail-open setup must generate the plugin dir"
    );
}

#[test]
fn machine_probe_unparseable_output_fails_open_and_wires() {
    let tmp = tempfile::tempdir().expect("tempdir");
    write(&tmp.path().join("Gemfile"), GEMFILE_FIXTURE);
    let log = tmp.path().join("bundle-argv.log");
    // Exit 0 but no `digits.digits` token anywhere on stdout — the
    // parse-of-real-spawn else-region.
    write_bundle_shim(&tmp.path().join("bin"), &log, Some("no version here"), 0);

    let (code, v) = run_setup_with_bundle_shim(tmp.path(), &tmp.path().join("bin"));
    assert_probe_spawned_bundle_version(&log);
    assert_failed_open_and_wired(tmp.path(), code, &v);
}

#[test]
fn machine_probe_nonzero_exit_fails_open_and_wires() {
    let tmp = tempfile::tempdir().expect("tempdir");
    write(&tmp.path().join("Gemfile"), GEMFILE_FIXTURE);
    let log = tmp.path().join("bundle-argv.log");
    // `bundle --version` exits 1 (broken RubyGems install, missing gemset):
    // the status-success gate's else-region. No stdout at all.
    write_bundle_shim(&tmp.path().join("bin"), &log, None, 1);

    let (code, v) = run_setup_with_bundle_shim(tmp.path(), &tmp.path().join("bin"));
    assert_probe_spawned_bundle_version(&log);
    assert_failed_open_and_wired(tmp.path(), code, &v);
}
