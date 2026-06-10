//! End-to-end tests for `global_packages.rs` paths, exercised via the
//! `apply --global` / `rollback --global` flags. Two strategies:
//!
//! 1. Real-tool path: when `npm` / `yarn` / `pnpm` are on PATH, the
//!    helpers actually shell out and return a real path. Coverage hits
//!    the success branch.
//! 2. PATH-stubbed path: with PATH pointing at an empty dir, the
//!    helpers fail to spawn the command, exercising the error branch.
//!
//! With both strategies, every branch in `get_npm_global_prefix` /
//! `get_yarn_global_prefix` / `get_pnpm_global_prefix` /
//! `get_global_node_modules_paths` runs at least once.
//!
//! NOTE on assertions: none of the fixtures install a real package that
//! matches the manifest PURL, so the *correct* outcome is fully
//! deterministic — `apply --global` must exit 1 with a `partialFailure`
//! envelope whose single event is a `package_not_installed` skip, and
//! `rollback --global` must exit 0 with an empty `success` envelope. We
//! assert that exact shape rather than "exit 0 or 1", so a regression
//! that crashes, swallows the PURL, or silently reports success no
//! longer slips through.

use std::path::{Path, PathBuf};
use std::process::Command;

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

fn write_manifest(root: &Path, purl: &str) {
    let socket = root.join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    std::fs::write(
        socket.join("manifest.json"),
        format!(
            r#"{{
  "patches": {{
    "{purl}": {{
      "uuid": "11111111-1111-4111-8111-111111111111",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {{}},
      "vulnerabilities": {{}},
      "description": "global-test",
      "license": "MIT",
      "tier": "free"
    }}
  }}
}}"#
        ),
    )
    .unwrap();
}

/// Parse `stdout` as the `apply` JSON envelope and assert it is the exact
/// "package not installed in any global tree" outcome for `purl`: a
/// `partialFailure` whose single event is a `package_not_installed` skip
/// and whose summary counts everything at zero except `skipped == 1`.
fn assert_apply_not_installed(stdout: &str, purl: &str) {
    let v: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("apply --global must emit valid JSON");
    assert_eq!(v["command"], "apply", "envelope={v}");
    assert_eq!(
        v["status"], "partialFailure",
        "no matching global pkg must be partialFailure; envelope={v}"
    );
    assert_eq!(v["dryRun"], false, "envelope={v}");

    let events = v["events"].as_array().expect("events must be an array");
    assert_eq!(
        events.len(),
        1,
        "exactly the manifest PURL must be reported; envelope={v}"
    );
    let event = &events[0];
    assert_eq!(event["action"], "skipped", "envelope={v}");
    assert_eq!(
        event["purl"], purl,
        "skip event must name the manifest PURL; envelope={v}"
    );
    assert_eq!(
        event["errorCode"], "package_not_installed",
        "skip reason must be package_not_installed; envelope={v}"
    );

    let summary = &v["summary"];
    assert_eq!(summary["skipped"], 1, "envelope={v}");
    for key in [
        "discovered",
        "downloaded",
        "applied",
        "updated",
        "failed",
        "removed",
        "verified",
    ] {
        assert_eq!(summary[key], 0, "summary.{key} must be 0; envelope={v}");
    }
}

/// Parse `stdout` as the `apply` JSON envelope and assert the exact
/// "package WAS found and patched" outcome for `purl`: a `success`
/// envelope whose single event is an `applied` action and whose summary
/// counts everything at zero except `applied == 1`.
///
/// This is the *positive control* that distinguishes "the global tree was
/// actually discovered and crawled" from "the `--global` / `--global-prefix`
/// resolution was silently ignored". The package name used in the fixtures
/// (`__*__@1.0.0`) cannot exist in any real npm/yarn/pnpm global tree, so an
/// `applied` outcome can only come from the path the test explicitly seeded.
fn assert_apply_applied(stdout: &str, purl: &str) {
    let v: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("apply --global must emit valid JSON");
    assert_eq!(v["command"], "apply", "envelope={v}");
    assert_eq!(
        v["status"], "success",
        "a matching global pkg must be applied successfully; envelope={v}"
    );
    assert_eq!(v["dryRun"], false, "envelope={v}");

    let events = v["events"].as_array().expect("events must be an array");
    assert_eq!(events.len(), 1, "exactly one event expected; envelope={v}");
    let event = &events[0];
    assert_eq!(event["action"], "applied", "envelope={v}");
    assert_eq!(
        event["purl"], purl,
        "applied event must name the seeded PURL; envelope={v}"
    );

    let summary = &v["summary"];
    assert_eq!(summary["applied"], 1, "envelope={v}");
    for key in [
        "discovered",
        "downloaded",
        "updated",
        "skipped",
        "failed",
        "removed",
        "verified",
    ] {
        assert_eq!(summary[key], 0, "summary.{key} must be 0; envelope={v}");
    }
}

/// Parse `stdout` as the `rollback` JSON envelope and assert the exact
/// "nothing to roll back" success outcome (no patches were applied, so
/// none can be reverted, but the run is clean — not a failure).
fn assert_rollback_noop(stdout: &str) {
    let v: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("rollback --global must emit valid JSON");
    assert_eq!(
        v["status"], "success",
        "empty rollback must report success; envelope={v}"
    );
    assert_eq!(v["rolledBack"], 0, "envelope={v}");
    assert_eq!(v["alreadyOriginal"], 0, "envelope={v}");
    assert_eq!(v["failed"], 0, "envelope={v}");
    assert_eq!(v["dryRun"], false, "envelope={v}");
    assert_eq!(
        v["results"]
            .as_array()
            .expect("results must be an array")
            .len(),
        0,
        "no package was patched, so results must be empty; envelope={v}"
    );
}

// ---------------------------------------------------------------------------
// Real-tool path — npm/yarn/pnpm on PATH return real paths
// ---------------------------------------------------------------------------

#[test]
fn apply_global_resolves_real_npm_prefix() {
    let tmp = tempfile::tempdir().unwrap();
    write_manifest(&tmp.path(), "pkg:npm/__global_test__@1.0.0");

    let out = Command::new(binary())
        .args(["apply", "--global", "--offline", "--json", "--silent"])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .output()
        .expect("run socket-patch");
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert_eq!(
        code, 1,
        "no global pkg matches the manifest PURL → exit 1; stdout={stdout}"
    );
    assert_apply_not_installed(&stdout, "pkg:npm/__global_test__@1.0.0");
}

#[test]
fn rollback_global_resolves_real_npm_prefix() {
    let tmp = tempfile::tempdir().unwrap();
    write_manifest(&tmp.path(), "pkg:npm/__rollback_global__@1.0.0");

    let out = Command::new(binary())
        .args(["rollback", "--global", "--offline", "--json", "--silent"])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .output()
        .expect("run socket-patch");
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert_eq!(code, 0, "empty rollback → exit 0; stdout={stdout}");
    assert_rollback_noop(&stdout);
}

// ---------------------------------------------------------------------------
// --global-prefix explicit path — bypasses npm/yarn/pnpm resolution
// ---------------------------------------------------------------------------

/// `--global-prefix <dir>` must drive package discovery from `<dir>` itself
/// (the npm crawler treats the prefix as the `node_modules` root). We prove
/// the flag is *honoured* — not silently ignored in favour of the real npm
/// global tree — with two contrasting runs that share one manifest PURL:
///
///   * an empty prefix yields `package_not_installed`, and
///   * the *same* prefix with the matching package planted in it yields
///     `applied`.
///
/// If `--global-prefix` were ignored, the second run could never flip to
/// `applied` (the seeded name cannot exist in any real global tree), so the
/// positive control is what closes the "did the flag do anything?" loophole.
const PREFIX_PURL: &str = "pkg:npm/__explicit_prefix__@1.0.0";

#[test]
fn apply_global_prefix_uses_explicit_path() {
    let tmp = tempfile::tempdir().unwrap();
    let global_dir = tmp.path().join("global");
    std::fs::create_dir_all(&global_dir).unwrap();
    write_manifest(tmp.path(), PREFIX_PURL);

    let run = |cwd: &Path| {
        let out = Command::new(binary())
            .args([
                "apply",
                "--global",
                "--global-prefix",
                global_dir.to_str().unwrap(),
                "--offline",
                "--json",
                "--silent",
            ])
            .current_dir(cwd)
            .env_remove("SOCKET_API_TOKEN")
            .output()
            .expect("run socket-patch");
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).to_string(),
        )
    };

    // Negative: empty prefix → nothing to patch.
    let (code, stdout) = run(tmp.path());
    assert_eq!(code, 1, "explicit empty prefix → exit 1; stdout={stdout}");
    assert_apply_not_installed(&stdout, PREFIX_PURL);

    // Positive control: plant the matching package directly under the
    // prefix (the crawler uses the prefix as the node_modules root) and the
    // outcome must flip to `applied`, proving the prefix path was crawled.
    let pkg_dir = global_dir.join("__explicit_prefix__");
    std::fs::create_dir_all(&pkg_dir).unwrap();
    std::fs::write(
        pkg_dir.join("package.json"),
        r#"{"name":"__explicit_prefix__","version":"1.0.0"}"#,
    )
    .unwrap();

    let (code, stdout) = run(tmp.path());
    assert_eq!(code, 0, "seeded prefix → exit 0; stdout={stdout}");
    assert_apply_applied(&stdout, PREFIX_PURL);
}

#[test]
fn rollback_global_prefix_uses_explicit_path() {
    let tmp = tempfile::tempdir().unwrap();
    let global_dir = tmp.path().join("global");
    std::fs::create_dir_all(&global_dir).unwrap();
    write_manifest(tmp.path(), PREFIX_PURL);

    let run = || {
        let out = Command::new(binary())
            .args([
                "rollback",
                "--global",
                "--global-prefix",
                global_dir.to_str().unwrap(),
                "--offline",
                "--json",
                "--silent",
            ])
            .current_dir(tmp.path())
            .env_remove("SOCKET_API_TOKEN")
            .output()
            .expect("run socket-patch");
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).to_string(),
        )
    };

    // Negative: empty prefix → no package, empty results.
    let (code, stdout) = run();
    assert_eq!(code, 0, "empty rollback → exit 0; stdout={stdout}");
    assert_rollback_noop(&stdout);

    // Positive control: plant the matching package under the prefix. The
    // rollback must now report a per-package result whose `path` lives
    // inside the explicit prefix — proving the prefix (not the real npm
    // global tree) drove discovery. `rolledBack` stays 0 because the patch
    // has no files, but the presence of the result entry is the signal.
    let pkg_dir = global_dir.join("__explicit_prefix__");
    std::fs::create_dir_all(&pkg_dir).unwrap();
    std::fs::write(
        pkg_dir.join("package.json"),
        r#"{"name":"__explicit_prefix__","version":"1.0.0"}"#,
    )
    .unwrap();

    let (code, stdout) = run();
    assert_eq!(code, 0, "seeded rollback → exit 0; stdout={stdout}");
    let v: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("rollback must emit valid JSON");
    assert_eq!(v["status"], "success", "envelope={v}");
    assert_eq!(v["failed"], 0, "envelope={v}");
    let results = v["results"].as_array().expect("results must be an array");
    assert_eq!(
        results.len(),
        1,
        "the seeded package must surface exactly one result; envelope={v}"
    );
    let r = &results[0];
    assert_eq!(r["purl"], PREFIX_PURL, "envelope={v}");
    assert_eq!(r["success"], true, "envelope={v}");
    let path = r["path"].as_str().expect("result must carry a path");
    assert!(
        Path::new(path).starts_with(&global_dir),
        "result path must live inside the explicit prefix {}; got {path}; envelope={v}",
        global_dir.display(),
    );
}

// ---------------------------------------------------------------------------
// Stubbed-PATH path — npm not found, error branch in get_npm_global_prefix
// ---------------------------------------------------------------------------

#[test]
fn apply_global_with_empty_path_handles_missing_npm() {
    // Empty PATH means npm/yarn/pnpm can't be spawned. The crawler's
    // `get_global_node_modules_paths` should handle the error and
    // return an empty list rather than crash — yielding the same
    // deterministic "package_not_installed" outcome as a resolved-but-
    // empty global tree.
    let tmp = tempfile::tempdir().unwrap();
    write_manifest(&tmp.path(), "pkg:npm/__missing_npm__@1.0.0");

    let out = Command::new(binary())
        .args(["apply", "--global", "--offline", "--json", "--silent"])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        // Empty PATH so no package-manager binary can be located.
        .env("PATH", "/nonexistent-dir-for-test")
        .output()
        .expect("run socket-patch");
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert_eq!(
        code, 1,
        "missing npm → exit 1, not a crash; stdout={stdout}"
    );
    assert_apply_not_installed(&stdout, "pkg:npm/__missing_npm__@1.0.0");
}

#[test]
fn rollback_global_with_empty_path_handles_missing_npm() {
    let tmp = tempfile::tempdir().unwrap();
    write_manifest(&tmp.path(), "pkg:npm/__missing_npm__@1.0.0");

    let out = Command::new(binary())
        .args(["rollback", "--global", "--offline", "--json", "--silent"])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .env("PATH", "/nonexistent-dir-for-test")
        .output()
        .expect("run socket-patch");
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert_eq!(code, 0, "missing npm rollback → exit 0; stdout={stdout}");
    assert_rollback_noop(&stdout);
}

// ---------------------------------------------------------------------------
// Stub-script PATH — controlled npm output exercises success + empty-output
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn write_stub(dir: &Path, name: &str, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join(name);
    std::fs::write(&path, body).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// A controlled `npm root -g` stub that resolves to a tree containing the
/// matching package.
///
/// This proves the *whole* global-resolution chain end-to-end, not just that
/// npm was spawned: (1) the stub records its invocation via a marker file, so
/// a regression that short-circuits `get_npm_global_prefix` fails the marker
/// assert; and (2) the path the stub prints is seeded with the manifest
/// package, so the run must flip to `applied` — which can only happen if the
/// path npm returned was actually crawled. A regression that resolves npm but
/// then discards its output would still spawn npm (marker present) yet never
/// find the package (no `applied`), and this test would catch it.
#[cfg(unix)]
#[test]
fn apply_global_with_stub_npm_root_resolves_path() {
    let tmp = tempfile::tempdir().unwrap();
    let stub_dir = tmp.path().join("bin");
    std::fs::create_dir_all(&stub_dir).unwrap();
    let fake_global = tmp.path().join("fake-global/node_modules");
    // Seed the resolved tree with the manifest package so a successful
    // resolution-then-crawl is observable as `applied`.
    let pkg_dir = fake_global.join("__stubbed_npm__");
    std::fs::create_dir_all(&pkg_dir).unwrap();
    std::fs::write(
        pkg_dir.join("package.json"),
        r#"{"name":"__stubbed_npm__","version":"1.0.0"}"#,
    )
    .unwrap();
    let marker = tmp.path().join("npm-root-g-invoked");
    // Record invocation via shell redirection (a builtin) rather than
    // `touch` so the marker is written even under restrictive sandboxes
    // that block the spawned shell from exec'ing external binaries.
    let stub_script = format!(
        "#!/bin/sh\nif [ \"$1\" = \"root\" ] && [ \"$2\" = \"-g\" ]; then echo invoked > \"{}\"; echo \"{}\"; exit 0; fi\nexit 0\n",
        marker.display(),
        fake_global.display()
    );
    write_stub(&stub_dir, "npm", &stub_script);

    write_manifest(tmp.path(), "pkg:npm/__stubbed_npm__@1.0.0");

    let out = Command::new(binary())
        .args(["apply", "--global", "--offline", "--json", "--silent"])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .env("PATH", stub_dir.to_str().unwrap())
        .output()
        .expect("run socket-patch");
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert_eq!(
        code, 0,
        "stubbed npm root resolves seeded pkg → exit 0; stdout={stdout}"
    );
    assert_apply_applied(&stdout, "pkg:npm/__stubbed_npm__@1.0.0");
    assert!(
        marker.exists(),
        "`npm root -g` must have been invoked — the global resolution path \
         was short-circuited"
    );
}

/// A controlled `npm root -g` stub that prints empty output — exercises
/// the "empty path" error branch of `get_npm_global_prefix`.
#[cfg(unix)]
#[test]
fn apply_global_with_empty_npm_root_output_handles_error() {
    let tmp = tempfile::tempdir().unwrap();
    let stub_dir = tmp.path().join("bin");
    std::fs::create_dir_all(&stub_dir).unwrap();
    let marker = tmp.path().join("npm-invoked");
    // Empty stdout, but still records that npm was actually spawned
    // (redirection builtin, sandbox-safe — see the resolves_path test).
    write_stub(
        &stub_dir,
        "npm",
        &format!(
            "#!/bin/sh\necho invoked > \"{}\"\nexit 0\n",
            marker.display()
        ),
    );

    write_manifest(tmp.path(), "pkg:npm/__empty_npm__@1.0.0");

    let out = Command::new(binary())
        .args(["apply", "--global", "--offline", "--json", "--silent"])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .env("PATH", stub_dir.to_str().unwrap())
        .output()
        .expect("run socket-patch");
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert_eq!(code, 1, "empty npm output → exit 1; stdout={stdout}");
    assert_apply_not_installed(&stdout, "pkg:npm/__empty_npm__@1.0.0");
    assert!(marker.exists(), "npm stub must have been spawned");
}

/// `npm root -g` exits non-zero — exercises the "command failed" branch.
#[cfg(unix)]
#[test]
fn apply_global_with_failing_npm_handles_error() {
    let tmp = tempfile::tempdir().unwrap();
    let stub_dir = tmp.path().join("bin");
    std::fs::create_dir_all(&stub_dir).unwrap();
    let marker = tmp.path().join("npm-invoked");
    write_stub(
        &stub_dir,
        "npm",
        &format!(
            "#!/bin/sh\necho invoked > \"{}\"\nexit 1\n",
            marker.display()
        ),
    );

    write_manifest(tmp.path(), "pkg:npm/__failing_npm__@1.0.0");

    let out = Command::new(binary())
        .args(["apply", "--global", "--offline", "--json", "--silent"])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .env("PATH", stub_dir.to_str().unwrap())
        .output()
        .expect("run socket-patch");
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert_eq!(code, 1, "failing npm → exit 1; stdout={stdout}");
    assert_apply_not_installed(&stdout, "pkg:npm/__failing_npm__@1.0.0");
    assert!(marker.exists(), "npm stub must have been spawned");
}
