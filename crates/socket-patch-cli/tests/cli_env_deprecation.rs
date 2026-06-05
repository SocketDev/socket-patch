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

/// Every legacy/new env-var name the shim knows about. We wipe ALL of these
/// from the child env so the parent process's environment can never leak a
/// stray var that fires (or suppresses) a deprecation warning and makes a
/// test falsely pass or falsely fail.
const ALL_RENAME_VARS: &[&str] = &[
    "SOCKET_PROXY_URL",
    "SOCKET_PATCH_PROXY_URL",
    "SOCKET_DEBUG",
    "SOCKET_PATCH_DEBUG",
    "SOCKET_TELEMETRY_DISABLED",
    "SOCKET_PATCH_TELEMETRY_DISABLED",
];

/// Other env vars that perturb the run; wiped for hermeticity.
const OTHER_VARS: &[&str] = &["SOCKET_API_TOKEN", "SOCKET_API_URL", "SOCKET_ORG_SLUG"];

/// Captured output of a child invocation.
struct Output {
    stdout: String,
    stderr: String,
}

/// Count non-overlapping occurrences of `needle` in `haystack`.
fn count_occurrences(haystack: &str, needle: &str) -> usize {
    haystack.matches(needle).count()
}

/// Build a `socket-patch list` command in a hermetic env (every rename var
/// and friend removed) pointed at a fresh empty tempdir.
fn base_cmd(tmp: &std::path::Path, extra_args: &[&str]) -> Command {
    let mut cmd = Command::new(BINARY);
    cmd.arg("list").arg("--cwd").arg(tmp);
    for a in extra_args {
        cmd.arg(a);
    }
    for k in ALL_RENAME_VARS.iter().chain(OTHER_VARS.iter()) {
        cmd.env_remove(k);
    }
    cmd
}

/// Helper: invoke `socket-patch list` (the cheapest read-only subcommand)
/// in a clean env, set the given legacy env var, and capture stdout+stderr.
fn run_with_legacy_env(legacy: &str, value: &str, extra_args: &[&str]) -> Output {
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut cmd = base_cmd(tmp.path(), extra_args);
    cmd.env(legacy, value);
    let out = cmd.output().expect("run socket-patch list");
    Output {
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// Assert that `stderr` carries a *well-formed* deprecation warning for the
/// `legacy` → `new` rename: it must name the legacy var, name the new var,
/// call the legacy var "deprecated", phrase it as a "use <new> instead"
/// directive, and fire exactly once (the warning is documented as one-shot).
fn assert_deprecation_warning(stderr: &str, legacy: &str, new: &str) {
    assert!(
        stderr.contains(legacy),
        "stderr should mention the legacy var name `{legacy}`; stderr was:\n{stderr}"
    );
    assert!(
        stderr.contains(new),
        "stderr should mention the new var name `{new}`; stderr was:\n{stderr}"
    );
    assert!(
        stderr.to_lowercase().contains("deprecated"),
        "stderr should call the legacy var deprecated; stderr was:\n{stderr}"
    );
    // The message must steer the user to the *correct* replacement, not just
    // happen to contain both strings somewhere. Guard the "use `<new>` instead"
    // directive so a regression that prints the wrong replacement is caught.
    assert!(
        stderr.contains(&format!("use `{new}`")),
        "warning should direct users to `use `{new}``; stderr was:\n{stderr}"
    );
    // One-shot: exactly one deprecation line, not a duplicated/looping warn.
    assert_eq!(
        count_occurrences(&stderr.to_lowercase(), "deprecated"),
        1,
        "deprecation warning should fire exactly once; stderr was:\n{stderr}"
    );
    // The warning belongs on stderr only — never let it appear more than once
    // for a single legacy var name either.
    assert_eq!(
        count_occurrences(stderr, legacy),
        1,
        "legacy var name should appear exactly once in the warning; stderr was:\n{stderr}"
    );
}

#[test]
fn legacy_proxy_url_warns() {
    let out = run_with_legacy_env("SOCKET_PATCH_PROXY_URL", "https://legacy.example", &[]);
    assert_deprecation_warning(&out.stderr, "SOCKET_PATCH_PROXY_URL", "SOCKET_PROXY_URL");
    // The warning is diagnostic output and must not contaminate stdout.
    assert!(
        !out.stdout.to_lowercase().contains("deprecated"),
        "deprecation warning must not leak onto stdout; stdout was:\n{}",
        out.stdout
    );
}

#[test]
fn legacy_debug_warns() {
    let out = run_with_legacy_env("SOCKET_PATCH_DEBUG", "1", &[]);
    assert_deprecation_warning(&out.stderr, "SOCKET_PATCH_DEBUG", "SOCKET_DEBUG");
    assert!(
        !out.stdout.to_lowercase().contains("deprecated"),
        "deprecation warning must not leak onto stdout; stdout was:\n{}",
        out.stdout
    );
}

#[test]
fn legacy_telemetry_disabled_warns() {
    let out = run_with_legacy_env("SOCKET_PATCH_TELEMETRY_DISABLED", "1", &[]);
    assert_deprecation_warning(
        &out.stderr,
        "SOCKET_PATCH_TELEMETRY_DISABLED",
        "SOCKET_TELEMETRY_DISABLED",
    );
    assert!(
        !out.stdout.to_lowercase().contains("deprecated"),
        "deprecation warning must not leak onto stdout; stdout was:\n{}",
        out.stdout
    );
}

/// `--silent` suppresses informational output but the deprecation warning
/// is a transition signal users need to see, so it must still fire — and it
/// must still be a complete, correct warning, not a degraded one.
#[test]
fn legacy_warning_fires_under_silent() {
    let out = run_with_legacy_env("SOCKET_PATCH_PROXY_URL", "https://legacy.example", &["--silent"]);
    assert_deprecation_warning(&out.stderr, "SOCKET_PATCH_PROXY_URL", "SOCKET_PROXY_URL");
    // `--silent` must genuinely silence stdout, proving the warning survived a
    // flag that suppresses everything else (rather than the warning simply
    // riding along on output that was never silenced).
    assert!(
        out.stdout.is_empty(),
        "--silent should produce no stdout; stdout was:\n{}",
        out.stdout
    );
}

/// Same precedence as `--silent`: `--json` is for machine output but the
/// deprecation belongs on stderr, separate from the JSON payload on stdout.
#[test]
fn legacy_warning_fires_under_json() {
    let out = run_with_legacy_env("SOCKET_PATCH_PROXY_URL", "https://legacy.example", &["--json"]);
    assert_deprecation_warning(&out.stderr, "SOCKET_PATCH_PROXY_URL", "SOCKET_PROXY_URL");
    // The whole point of routing the warning to stderr under --json is that
    // stdout stays parseable. Prove stdout is untouched JSON, free of the
    // human-facing warning.
    assert!(
        !out.stdout.to_lowercase().contains("deprecated")
            && !out.stdout.contains("SOCKET_PATCH_PROXY_URL"),
        "warning must not leak into the --json stdout payload; stdout was:\n{}",
        out.stdout
    );
    let trimmed = out.stdout.trim();
    assert!(
        !trimmed.is_empty(),
        "--json should still emit a JSON document on stdout; stdout was:\n{}",
        out.stdout
    );
    let parsed: serde_json::Value =
        serde_json::from_str(trimmed).unwrap_or_else(|e| panic!("stdout must be valid JSON ({e}); stdout was:\n{}", out.stdout));
    assert!(
        parsed.get("command").is_some(),
        "JSON payload should be the structured command result; got:\n{}",
        out.stdout
    );
}

/// When the new var is set, the legacy var must be ignored — no warning, and
/// the legacy name must not even be mentioned on stderr.
#[test]
fn new_var_takes_precedence_and_silences_warning() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut cmd = base_cmd(tmp.path(), &[]);
    // New var set, legacy var also set: the new one must win, the legacy one
    // must be silently ignored.
    cmd.env("SOCKET_PROXY_URL", "https://new.example");
    cmd.env("SOCKET_PATCH_PROXY_URL", "https://legacy.example");
    let out = cmd.output().expect("run socket-patch list");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.to_lowercase().contains("deprecated"),
        "no deprecation warning expected when new var is set; stderr was:\n{stderr}"
    );
    assert!(
        !stderr.contains("SOCKET_PATCH_PROXY_URL"),
        "legacy var name must not appear when the new var takes precedence; stderr was:\n{stderr}"
    );
}

/// Sanity guard against a false-positive in the "warns" tests: with NO legacy
/// var set at all, the binary must emit zero deprecation noise. This proves
/// the warnings above are caused by the legacy var, not by ambient output the
/// substring checks would otherwise rubber-stamp.
#[test]
fn no_warning_when_no_legacy_var_set() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut cmd = base_cmd(tmp.path(), &[]);
    let out = cmd.output().expect("run socket-patch list");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.to_lowercase().contains("deprecated"),
        "no deprecation warning expected with no legacy var set; stderr was:\n{stderr}"
    );
}
