//! `apply --silent` / `apply --check` error-output contract tests.
//!
//! CLI_CONTRACT.md defines `--silent` as "Errors only" — never "nothing":
//! an exit-1 run with zero output is undiagnosable. It also requires every
//! `--json` invocation to emit exactly one envelope. Regression guards for
//! the apply error paths that gated their ONLY error print on `!silent`
//! (or skipped the JSON envelope entirely):
//!
//! 1. `apply --silent` with an unreadable manifest (the
//!    `apply_patches_inner` error path) exited 1 with zero output.
//! 2. `apply --check --silent` with an unreadable manifest (fail-closed
//!    drift) exited 1 with zero output.
//! 3. `apply --check --json` with an unreadable manifest exited 1 with NO
//!    JSON envelope at all.
//! 4. `apply --check --silent` with real redirect drift exited 1 with zero
//!    output (the OUT OF SYNC report was muted).
//!
//! Same bug class previously fixed in `scan` (`embed_vex_human`), `setup`
//! (all three modes), and apply's own yarn-PnP refusal.
//!
//! Stderr assertions ignore the "No SOCKET_API_TOKEN set" client warning:
//! it's printed unconditionally by `get_api_client_with_overrides` in core
//! for every command and is out of scope for `apply`'s `--silent` gating.

use std::path::{Path, PathBuf};
use std::process::Command;

use socket_patch_cli::args::GLOBAL_ARG_ENV_VARS;

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

/// Run `socket-patch apply` in `cwd` with a scrubbed SOCKET_* environment
/// so ambient developer/CI configuration (tokens, silent toggles) can't
/// change the branch under test.
fn run_apply(cwd: &Path, args: &[&str]) -> (i32, String, String) {
    let mut cmd = Command::new(binary());
    cmd.arg("apply").args(args).current_dir(cwd);
    for var in GLOBAL_ARG_ENV_VARS {
        cmd.env_remove(var);
    }
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1");
    let out = cmd.output().expect("run socket-patch apply");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

/// Non-error stderr lines: drop the unconditional core API-token warning
/// (both its lead line and its "Got: ... Continuing anyway" continuation)
/// and blank lines, keep everything else.
fn stderr_chatter(stderr: &str) -> Vec<String> {
    stderr
        .lines()
        .filter(|l| {
            !l.contains("SOCKET_API_TOKEN")
                && !l.contains("Continuing anyway")
                && !l.trim().is_empty()
        })
        .map(|l| l.to_string())
        .collect()
}

fn write_corrupt_manifest(root: &Path) {
    let socket = root.join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    std::fs::write(socket.join("manifest.json"), "{ not json").unwrap();
}

/// Valid manifest with one golang patch entry and NO committed copy under
/// `.socket/go-patches/` — `apply --check` must report `MissingCopy` drift.
fn write_drifted_go_manifest(root: &Path) {
    let socket = root.join(".socket");
    std::fs::create_dir_all(&socket).unwrap();
    std::fs::write(
        socket.join("manifest.json"),
        r#"{ "patches": {
            "pkg:golang/example.com/mod@v1.0.0": {
                "uuid": "go-drift-uuid-0000",
                "exportedAt": "2024-01-01T00:00:00Z",
                "files": { "file.go": {
                    "beforeHash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "afterHash":  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                }},
                "vulnerabilities": {}, "description": "x",
                "license": "MIT", "tier": "free"
            }
        }}"#,
    )
    .unwrap();
}

/// `apply --silent` with an unreadable manifest must still print the error
/// ("errors only", never "nothing" — exit 1 with no output is
/// undiagnosable in the npm postinstall hook that runs `apply` silently).
#[test]
fn apply_silent_unreadable_manifest_keeps_error_output() {
    let tmp = tempfile::tempdir().unwrap();
    write_corrupt_manifest(tmp.path());

    let (code, stdout, stderr) = run_apply(tmp.path(), &["--silent", "--offline"]);
    assert_eq!(code, 1, "unreadable manifest must fail: {stderr}");
    assert!(
        stdout.trim().is_empty(),
        "silent human mode writes errors to stderr, not stdout: {stdout}"
    );
    let chatter = stderr_chatter(&stderr);
    assert!(
        chatter.iter().any(|l| l.contains("Error")),
        "--silent must keep the error output (errors only, never nothing); \
         stderr was: {stderr:?}"
    );
}

/// `apply --check --silent` on an unreadable manifest (fail-closed drift)
/// must still print why it failed.
#[test]
fn apply_check_silent_unreadable_manifest_keeps_error_output() {
    let tmp = tempfile::tempdir().unwrap();
    write_corrupt_manifest(tmp.path());

    let (code, _stdout, stderr) = run_apply(tmp.path(), &["--check", "--silent"]);
    assert_eq!(code, 1, "unreadable manifest must fail closed: {stderr}");
    let chatter = stderr_chatter(&stderr);
    assert!(
        chatter
            .iter()
            .any(|l| l.contains("could not read the manifest")),
        "--check --silent must keep the fail-closed error output; \
         stderr was: {stderr:?}"
    );
}

/// `apply --check --json` on an unreadable manifest must emit the unified
/// envelope (CLI_CONTRACT.md: every `--json` invocation emits a single
/// JSON object) — not exit 1 with empty stdout.
#[test]
fn apply_check_json_unreadable_manifest_emits_error_envelope() {
    let tmp = tempfile::tempdir().unwrap();
    write_corrupt_manifest(tmp.path());

    let (code, stdout, stderr) = run_apply(tmp.path(), &["--check", "--json"]);
    assert_eq!(code, 1, "unreadable manifest must fail closed: {stderr}");
    let env: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("--json must emit an envelope ({e}); stdout was: {stdout:?}"));
    assert_eq!(env["command"], "apply");
    assert_eq!(env["status"], "error");
    assert_eq!(env["error"]["code"], "manifest_unreadable");
}

/// `apply --check --silent` with real redirect drift must still print the
/// OUT OF SYNC report — drift IS the error the exit code signals.
#[test]
fn apply_check_silent_drift_keeps_error_output() {
    let tmp = tempfile::tempdir().unwrap();
    write_drifted_go_manifest(tmp.path());

    let (code, _stdout, stderr) = run_apply(tmp.path(), &["--check", "--silent"]);
    assert_eq!(
        code, 1,
        "missing go-patches copy must report drift: {stderr}"
    );
    let chatter = stderr_chatter(&stderr);
    assert!(
        chatter.iter().any(|l| l.contains("OUT OF SYNC")),
        "--check --silent must keep the drift error output; stderr was: {stderr:?}"
    );
}
