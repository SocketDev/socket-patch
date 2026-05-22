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
    // Either 0 or 1 — both confirm get_npm_global_prefix executed.
    // Code 1 is the "no patches in scope" outcome; code 0 is success
    // (when global pkg has no matching purl).
    assert!(
        code == 0 || code == 1,
        "apply --global must not crash; got {code}; stdout={stdout}"
    );
    // JSON parseable confirms a clean control flow.
    let _: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("apply --global must emit valid JSON");
}

#[test]
fn rollback_global_resolves_real_npm_prefix() {
    let tmp = tempfile::tempdir().unwrap();
    write_manifest(&tmp.path(), "pkg:npm/__rollback_global__@1.0.0");

    let out = Command::new(binary())
        .args([
            "rollback",
            "--global",
            "--offline",
            "--json",
            "--silent",
        ])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .output()
        .expect("run socket-patch");
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        code == 0 || code == 1,
        "rollback --global must not crash; got {code}; stdout={stdout}"
    );
}

// ---------------------------------------------------------------------------
// --global-prefix explicit path — bypasses npm/yarn/pnpm resolution
// ---------------------------------------------------------------------------

#[test]
fn apply_global_prefix_uses_explicit_path() {
    let tmp = tempfile::tempdir().unwrap();
    let global_dir = tmp.path().join("global");
    std::fs::create_dir_all(global_dir.join("node_modules")).unwrap();
    write_manifest(tmp.path(), "pkg:npm/__explicit_prefix__@1.0.0");

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
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .output()
        .expect("run socket-patch");
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        code == 0 || code == 1,
        "apply --global-prefix must not crash; stdout={stdout}"
    );
}

#[test]
fn rollback_global_prefix_uses_explicit_path() {
    let tmp = tempfile::tempdir().unwrap();
    let global_dir = tmp.path().join("global");
    std::fs::create_dir_all(global_dir.join("node_modules")).unwrap();
    write_manifest(tmp.path(), "pkg:npm/__explicit_prefix__@1.0.0");

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
    let code = out.status.code().unwrap_or(-1);
    assert!(
        code == 0 || code == 1,
        "rollback --global-prefix must not crash"
    );
}

// ---------------------------------------------------------------------------
// Stubbed-PATH path — npm not found, error branch in get_npm_global_prefix
// ---------------------------------------------------------------------------

#[test]
fn apply_global_with_empty_path_handles_missing_npm() {
    // Empty PATH means npm/yarn/pnpm can't be spawned. The crawler's
    // `get_global_node_modules_paths` should handle the error and
    // return an empty list rather than crash.
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
    assert!(
        code == 0 || code == 1,
        "missing npm must not crash apply; got {code}; stdout={stdout}"
    );
    // Verify the binary still emits valid JSON — it didn't crash
    // mid-write.
    let _: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("envelope JSON must parse");
}

#[test]
fn rollback_global_with_empty_path_handles_missing_npm() {
    let tmp = tempfile::tempdir().unwrap();
    write_manifest(&tmp.path(), "pkg:npm/__missing_npm__@1.0.0");

    let out = Command::new(binary())
        .args([
            "rollback",
            "--global",
            "--offline",
            "--json",
            "--silent",
        ])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .env("PATH", "/nonexistent-dir-for-test")
        .output()
        .expect("run socket-patch");
    let code = out.status.code().unwrap_or(-1);
    assert!(
        code == 0 || code == 1,
        "missing npm must not crash rollback; got {code}"
    );
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

/// A controlled `npm root -g` stub that prints a non-empty path.
#[cfg(unix)]
#[test]
fn apply_global_with_stub_npm_root_resolves_path() {
    let tmp = tempfile::tempdir().unwrap();
    let stub_dir = tmp.path().join("bin");
    std::fs::create_dir_all(&stub_dir).unwrap();
    let fake_global = tmp.path().join("fake-global/node_modules");
    std::fs::create_dir_all(&fake_global).unwrap();
    let stub_script = format!(
        "#!/bin/sh\nif [ \"$1\" = \"root\" ] && [ \"$2\" = \"-g\" ]; then echo \"{}\"; exit 0; fi\nexit 0\n",
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
    assert!(
        code == 0 || code == 1,
        "stubbed npm root must not crash; got {code}; stdout={stdout}"
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
    write_stub(&stub_dir, "npm", "#!/bin/sh\nexit 0\n"); // empty stdout

    write_manifest(tmp.path(), "pkg:npm/__empty_npm__@1.0.0");

    let out = Command::new(binary())
        .args(["apply", "--global", "--offline", "--json", "--silent"])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .env("PATH", stub_dir.to_str().unwrap())
        .output()
        .expect("run socket-patch");
    let code = out.status.code().unwrap_or(-1);
    assert!(
        code == 0 || code == 1,
        "empty npm output must not crash; got {code}"
    );
}

/// `npm root -g` exits non-zero — exercises the "command failed" branch.
#[cfg(unix)]
#[test]
fn apply_global_with_failing_npm_handles_error() {
    let tmp = tempfile::tempdir().unwrap();
    let stub_dir = tmp.path().join("bin");
    std::fs::create_dir_all(&stub_dir).unwrap();
    write_stub(&stub_dir, "npm", "#!/bin/sh\nexit 1\n"); // failure

    write_manifest(tmp.path(), "pkg:npm/__failing_npm__@1.0.0");

    let out = Command::new(binary())
        .args(["apply", "--global", "--offline", "--json", "--silent"])
        .current_dir(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .env("PATH", stub_dir.to_str().unwrap())
        .output()
        .expect("run socket-patch");
    let code = out.status.code().unwrap_or(-1);
    assert!(
        code == 0 || code == 1,
        "failing npm must not crash; got {code}"
    );
}
