//! #704: every `--json` failure carries its top-level `error` as a
//! `{code, message}` object, with no top-level `errorCode`, on every
//! command. Self-enforced usage errors (exit 2) print that coded error on
//! stdout: a full envelope for the envelope commands, `{status, error}` for
//! `scan`, `get` and `rollback`. None of these cases reaches the network.

use std::path::Path;

use socket_patch_cli::args::{GLOBAL_ARG_ENV_VARS, LOCAL_ARG_ENV_VARS};

#[path = "common/hermetic.rs"]
mod hermetic;

fn run(cwd: &Path, args: &[&str], env: &[(&str, &str)]) -> (i32, String, String) {
    let mut cmd = hermetic::binary_command();
    hermetic::scrub_extra(&mut cmd, &[hermetic::Extra::Venv]);
    cmd.args(args).current_dir(cwd);
    for var in GLOBAL_ARG_ENV_VARS.iter().chain(LOCAL_ARG_ENV_VARS.iter()) {
        cmd.env_remove(var);
    }
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1");
    // Unroutable: a case that reached the network would fail differently.
    cmd.env("SOCKET_API_URL", "http://127.0.0.1:1");
    cmd.env("SOCKET_API_TOKEN", "fake-token-for-test");
    cmd.env("SOCKET_ORG_SLUG", "test-org");
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("run socket-patch");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

/// The shared assertions: `status: "error"`, an object `error` with the
/// expected code and a non-empty message, and no top-level `errorCode`.
fn assert_error_object(stdout: &str, code: &str) -> serde_json::Value {
    let v: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("stdout must be one JSON document ({e}): {stdout:?}"));
    assert_eq!(v["status"], "error", "{v}");
    assert!(v["error"].is_object(), "error must be an object: {v}");
    assert_eq!(v["error"]["code"], code, "{v}");
    assert!(
        v["error"]["message"]
            .as_str()
            .is_some_and(|m| !m.is_empty()),
        "{v}"
    );
    assert!(v.get("errorCode").is_none(), "no top-level errorCode: {v}");
    v
}

/// A legacy-shape usage error is exactly `{status, error}`.
fn assert_legacy_usage(args: &[&str], env: &[(&str, &str)], code: &str) {
    let tmp = tempfile::tempdir().unwrap();
    let (exit, stdout, stderr) = run(tmp.path(), args, env);
    assert_eq!(exit, 2, "{args:?}: stdout={stdout} stderr={stderr}");
    let v = assert_error_object(&stdout, code);
    assert_eq!(v.as_object().unwrap().len(), 2, "{args:?}: {v}");
}

/// An envelope-command usage error is a full envelope.
fn assert_envelope_usage(args: &[&str], command: &str, code: &str) {
    let tmp = tempfile::tempdir().unwrap();
    let (exit, stdout, stderr) = run(tmp.path(), args, &[]);
    assert_eq!(exit, 2, "{args:?}: stdout={stdout} stderr={stderr}");
    let v = assert_error_object(&stdout, code);
    assert_eq!(v["command"], command, "{v}");
    assert_eq!(v["events"], serde_json::json!([]), "{v}");
}

#[test]
fn scan_usage_errors_print_the_coded_error() {
    assert_legacy_usage(
        &["scan", "--mode", "hosted", "--global", "--json"],
        &[],
        "global_scope_unsupported",
    );
    assert_legacy_usage(
        &["scan", "--mode", "hosted", "missing-dir", "--json"],
        &[],
        "path_not_directory",
    );
    assert_legacy_usage(
        &["scan", "--mode", "hosted", "nothing-*", "--json"],
        &[],
        "path_glob_no_match",
    );
    assert_legacy_usage(
        &["scan", "--mode", "agent", "x[", "--json"],
        &[],
        "path_glob_invalid",
    );
    assert_legacy_usage(
        &["scan", "--mode", "agent", "--json"],
        &[("SOCKET_MAX_NEW_PATCHES", "lots")],
        "invalid_env",
    );
    assert_legacy_usage(
        &["scan", "--mode", "agent", "--json"],
        &[("SOCKET_MIN_SEVERITY", "extreme")],
        "invalid_env",
    );
}

#[test]
fn get_usage_errors_print_the_coded_error() {
    assert_legacy_usage(
        &["get", "lodash", "--id", "--cve", "--json"],
        &[],
        "invalid_args",
    );
    assert_legacy_usage(
        &["get", "lodash", "--id", "--json"],
        &[],
        "identifier_invalid",
    );
    assert_legacy_usage(
        &["get", "lodash", "--save-only", "--mode", "hosted", "--json"],
        &[],
        "invalid_args",
    );
    assert_legacy_usage(
        &["get", "lodash", "--mode", "hosted", "--global", "--json"],
        &[],
        "global_scope_unsupported",
    );
}

#[test]
fn rollback_usage_error_prints_the_coded_error() {
    assert_legacy_usage(&["rollback", "x[", "--json"], &[], "path_glob_invalid");
}

#[test]
fn envelope_command_usage_errors_print_an_envelope() {
    assert_envelope_usage(
        &[
            "remove",
            "pkg:npm/a@1.0.0",
            "--preserve-state",
            "--skip-rollback",
            "--json",
        ],
        "remove",
        "invalid_args",
    );
    assert_envelope_usage(
        &["repair", "--offline", "--download-only", "--json"],
        "repair",
        "invalid_args",
    );
    assert_envelope_usage(&["vex", "--json"], "vex", "json_requires_output");
}

#[test]
fn usage_errors_without_json_keep_stdout_empty() {
    let tmp = tempfile::tempdir().unwrap();
    for args in [
        &["scan", "--mode", "hosted", "--global"][..],
        &["rollback", "x["][..],
        &[
            "remove",
            "pkg:npm/a@1.0.0",
            "--preserve-state",
            "--skip-rollback",
        ][..],
    ] {
        let (exit, stdout, stderr) = run(tmp.path(), args, &[]);
        assert_eq!(exit, 2, "{args:?}");
        assert!(stdout.is_empty(), "{args:?}: {stdout:?}");
        assert!(stderr.starts_with("Error: "), "{args:?}: {stderr:?}");
    }
}

#[test]
fn offline_refusals_carry_a_code() {
    let tmp = tempfile::tempdir().unwrap();
    let (exit, stdout, _) = run(
        tmp.path(),
        &["scan", "--mode", "agent", "--offline", "--json"],
        &[],
    );
    assert_eq!(exit, 1);
    let v = assert_error_object(&stdout, "offline_unsupported");
    assert_eq!(v["scannedPackages"], 0, "{v}");

    let (exit, stdout, _) = run(tmp.path(), &["get", "lodash", "--offline", "--json"], &[]);
    assert_eq!(exit, 1);
    assert_error_object(&stdout, "offline_unsupported");
}

#[test]
fn rollback_on_an_empty_project_is_manifest_not_found() {
    let tmp = tempfile::tempdir().unwrap();
    let (exit, stdout, _) = run(tmp.path(), &["rollback", "--json"], &[]);
    assert_eq!(exit, 1, "{stdout}");
    let v = assert_error_object(&stdout, "manifest_not_found");
    assert_eq!(v["error"]["message"], "Manifest not found", "{v}");
    assert!(v["path"].is_string(), "{v}");
}

#[test]
fn rollback_unknown_identifier_is_patch_not_found() {
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    std::fs::write(socket.join("manifest.json"), r#"{"patches": {}}"#).unwrap();
    let (exit, stdout, _) = run(
        tmp.path(),
        &["rollback", "pkg:npm/nothing@1.0.0", "--json"],
        &[],
    );
    assert_eq!(exit, 1, "{stdout}");
    let v = assert_error_object(&stdout, "patch_not_found");
    assert_eq!(v["results"], serde_json::json!([]), "{v}");
}
