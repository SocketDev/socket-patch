//! Tests for the legacy → new env-var compatibility shim.
//!
//! v3.0 renamed three env vars from the `SOCKET_PATCH_*` prefix to the
//! unified `SOCKET_*` prefix. The shim in `socket_patch_core::utils::env_compat`
//! reads the legacy name when the new name is unset and emits a one-shot
//! deprecation warning to stderr — even under `--silent` / `--json`.
//!
//! These tests run the compiled binary as a subprocess so we can observe
//! the actual stderr output. In-process testing would race with parallel
//! tests that also touch env vars.

use std::process::Command;

const BINARY: &str = env!("CARGO_BIN_EXE_socket-patch");

/// Helper: invoke `socket-patch list` (the cheapest read-only subcommand)
/// in a clean env, set the given legacy env var, and capture stderr.
fn run_with_legacy_env(legacy: &str, value: &str, extra_args: &[&str]) -> String {
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut cmd = Command::new(BINARY);
    cmd.arg("list").arg("--cwd").arg(tmp.path());
    for a in extra_args {
        cmd.arg(a);
    }
    // Wipe every relevant env var so the test is hermetic.
    for k in [
        "SOCKET_PROXY_URL",
        "SOCKET_PATCH_PROXY_URL",
        "SOCKET_DEBUG",
        "SOCKET_PATCH_DEBUG",
        "SOCKET_TELEMETRY_DISABLED",
        "SOCKET_PATCH_TELEMETRY_DISABLED",
        "SOCKET_API_TOKEN",
        "SOCKET_API_URL",
        "SOCKET_ORG_SLUG",
    ] {
        cmd.env_remove(k);
    }
    cmd.env(legacy, value);
    let out = cmd.output().expect("run socket-patch list");
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn legacy_proxy_url_warns() {
    let stderr = run_with_legacy_env("SOCKET_PATCH_PROXY_URL", "https://legacy.example", &[]);
    assert!(
        stderr.contains("SOCKET_PATCH_PROXY_URL"),
        "stderr should mention the legacy var name; stderr was:\n{stderr}"
    );
    assert!(
        stderr.contains("SOCKET_PROXY_URL"),
        "stderr should mention the new var name; stderr was:\n{stderr}"
    );
    assert!(
        stderr.to_lowercase().contains("deprecated"),
        "stderr should call the legacy var deprecated; stderr was:\n{stderr}"
    );
}

#[test]
fn legacy_debug_warns() {
    let stderr = run_with_legacy_env("SOCKET_PATCH_DEBUG", "1", &[]);
    assert!(
        stderr.contains("SOCKET_PATCH_DEBUG"),
        "stderr should mention the legacy var name; stderr was:\n{stderr}"
    );
    assert!(
        stderr.contains("SOCKET_DEBUG"),
        "stderr should mention the new var name; stderr was:\n{stderr}"
    );
}

#[test]
fn legacy_telemetry_disabled_warns() {
    let stderr = run_with_legacy_env("SOCKET_PATCH_TELEMETRY_DISABLED", "1", &[]);
    assert!(
        stderr.contains("SOCKET_PATCH_TELEMETRY_DISABLED"),
        "stderr should mention the legacy var name; stderr was:\n{stderr}"
    );
    assert!(
        stderr.contains("SOCKET_TELEMETRY_DISABLED"),
        "stderr should mention the new var name; stderr was:\n{stderr}"
    );
}

/// `--silent` suppresses informational output but the deprecation warning
/// is a transition signal users need to see, so it must still fire.
#[test]
fn legacy_warning_fires_under_silent() {
    let stderr =
        run_with_legacy_env("SOCKET_PATCH_PROXY_URL", "https://legacy.example", &["--silent"]);
    assert!(
        stderr.to_lowercase().contains("deprecated"),
        "deprecation warning must fire under --silent; stderr was:\n{stderr}"
    );
}

/// Same precedence as `--silent`: `--json` is for machine output but the
/// deprecation belongs on stderr, separate from the JSON payload on stdout.
#[test]
fn legacy_warning_fires_under_json() {
    let stderr =
        run_with_legacy_env("SOCKET_PATCH_PROXY_URL", "https://legacy.example", &["--json"]);
    assert!(
        stderr.to_lowercase().contains("deprecated"),
        "deprecation warning must fire under --json; stderr was:\n{stderr}"
    );
}

/// When the new var is set, the legacy var must be ignored — no warning.
#[test]
fn new_var_takes_precedence_and_silences_warning() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let out = Command::new(BINARY)
        .arg("list")
        .arg("--cwd")
        .arg(tmp.path())
        .env_remove("SOCKET_API_TOKEN")
        .env_remove("SOCKET_API_URL")
        .env_remove("SOCKET_ORG_SLUG")
        .env("SOCKET_PROXY_URL", "https://new.example")
        .env("SOCKET_PATCH_PROXY_URL", "https://legacy.example")
        .output()
        .expect("run socket-patch list");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.to_lowercase().contains("deprecated"),
        "no deprecation warning expected when new var is set; stderr was:\n{stderr}"
    );
}
