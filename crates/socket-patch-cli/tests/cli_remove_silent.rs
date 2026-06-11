//! `remove --silent` contract tests.
//!
//! CLI_CONTRACT.md defines `--silent` as "Errors only". Regression
//! guard: `remove` gated all of its human-readable chatter on `!json`
//! alone, hardcoded `silent: false` into `acquire_or_emit` (so the
//! `--break-lock` stale-lock warning printed anyway), and passed only
//! `json` as `rollback_patches`' silent param — so `remove --silent`
//! printed everything. Same bug class previously fixed in `list`,
//! `repair`, and `get`. Runs fully offline: the patch record has no
//! files (so rollback fetches no blobs) and the project dir has no
//! installed packages, so the internal rollback takes the
//! "not installed" path and the manifest mutation needs no network.
//!
//! Stderr assertions ignore the "No SOCKET_API_TOKEN set" client
//! warning: it's printed unconditionally by
//! `get_api_client_with_overrides` in core for every command and is
//! out of scope for `remove`'s `--silent` gating.

use std::path::{Path, PathBuf};
use std::process::Command;

use socket_patch_cli::args::GLOBAL_ARG_ENV_VARS;

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

const ONE_PATCH_MANIFEST: &str = r#"{
  "patches": {
    "pkg:npm/__remove_silent_test__@1.0.0": {
      "uuid": "33333333-3333-4333-8333-333333333333",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {},
      "vulnerabilities": {},
      "description": "synthetic remove --silent test patch",
      "license": "MIT",
      "tier": "free"
    }
  }
}"#;

fn make_socket_dir(root: &Path) -> PathBuf {
    let socket = root.join(".socket");
    std::fs::create_dir_all(&socket).expect("create .socket");
    std::fs::write(socket.join("manifest.json"), ONE_PATCH_MANIFEST).expect("write manifest");
    socket
}

/// Run `socket-patch remove` in `cwd` with a scrubbed SOCKET_* environment
/// so ambient developer/CI configuration (tokens, silent toggles) can't
/// change the branch under test.
fn run_remove(cwd: &Path, args: &[&str]) -> (i32, String, String) {
    let mut cmd = Command::new(binary());
    cmd.arg("remove").args(args).current_dir(cwd);
    for var in GLOBAL_ARG_ENV_VARS {
        cmd.env_remove(var);
    }
    cmd.env_remove("SOCKET_SKIP_ROLLBACK");
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1");
    let out = cmd.output().expect("run socket-patch remove");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

/// A successful `remove --silent --yes` (rollback included — the package
/// is simply not installed) must produce no output on either stream:
/// no "will be removed" listing, no "Rolling back" / "No packages found
/// to rollback" progress, no "Removed N patch(es)" summary.
#[test]
fn remove_silent_produces_no_output_on_success() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = make_socket_dir(tmp.path());

    let (code, stdout, stderr) = run_remove(
        tmp.path(),
        &["pkg:npm/__remove_silent_test__@1.0.0", "--silent", "--yes"],
    );
    assert_eq!(
        code, 0,
        "remove must succeed; stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        stdout.trim().is_empty(),
        "--silent must produce no stdout; got {stdout:?}"
    );
    let stderr_rest: Vec<&str> = stderr
        .lines()
        .filter(|l| !l.contains("SOCKET_API_TOKEN") && !l.trim().is_empty())
        .collect();
    assert!(
        stderr_rest.is_empty(),
        "--silent must produce no stderr chatter on success; got {stderr_rest:?}"
    );

    // The removal must still have happened — silent suppresses output,
    // not the mutation.
    let body = std::fs::read_to_string(socket.join("manifest.json")).expect("read manifest");
    let v: serde_json::Value = serde_json::from_str(&body).expect("parse manifest");
    assert!(
        v["patches"].as_object().expect("patches object").is_empty(),
        "patch entry must be removed from the manifest"
    );

    // Control run: the same scenario WITHOUT --silent must print the
    // human messages — otherwise the assertions above pass vacuously.
    let tmp2 = tempfile::tempdir().expect("tempdir");
    make_socket_dir(tmp2.path());
    let (loud_code, loud_stdout, loud_stderr) = run_remove(
        tmp2.path(),
        &["pkg:npm/__remove_silent_test__@1.0.0", "--yes"],
    );
    assert_eq!(loud_code, 0);
    assert!(
        loud_stdout.contains("Rolling back patch before removal"),
        "non-silent run must print rollback progress; got {loud_stdout:?}"
    );
    assert!(
        loud_stdout.contains("Removed 1 patch(es) from manifest"),
        "non-silent run must print the removal summary; got {loud_stdout:?}"
    );
    assert!(
        loud_stderr.contains("will be removed"),
        "non-silent run must print the pre-removal listing; got {loud_stderr:?}"
    );
}

/// `--silent` must also reach the lock helper: reclaiming a stale
/// `apply.lock` via `--break-lock` prints a stderr warning that
/// `acquire_or_emit` gates on its `silent` param — which `remove`
/// hardcoded to `false`.
#[test]
fn remove_silent_suppresses_break_lock_warning() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = make_socket_dir(tmp.path());
    std::fs::write(socket.join("apply.lock"), b"").expect("write stale lock");

    let (code, stdout, stderr) = run_remove(
        tmp.path(),
        &[
            "pkg:npm/__remove_silent_test__@1.0.0",
            "--silent",
            "--yes",
            "--break-lock",
            "--skip-rollback",
        ],
    );
    assert_eq!(
        code, 0,
        "remove must succeed; stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        !stderr.contains("reclaimed stale"),
        "--silent must suppress the stale-lock warning; got {stderr:?}"
    );

    // Control run: without --silent the warning must appear.
    let tmp2 = tempfile::tempdir().expect("tempdir");
    let socket2 = make_socket_dir(tmp2.path());
    std::fs::write(socket2.join("apply.lock"), b"").expect("write stale lock");
    let (loud_code, _loud_stdout, loud_stderr) = run_remove(
        tmp2.path(),
        &[
            "pkg:npm/__remove_silent_test__@1.0.0",
            "--yes",
            "--break-lock",
            "--skip-rollback",
        ],
    );
    assert_eq!(loud_code, 0);
    assert!(
        loud_stderr.contains("reclaimed stale"),
        "non-silent --break-lock must print the stale-lock warning; got {loud_stderr:?}"
    );
}

/// Errors must still print under `--silent` ("errors only", not "nothing"):
/// an unknown identifier keeps its stderr message and exit 1.
#[test]
fn remove_silent_keeps_error_output() {
    let tmp = tempfile::tempdir().expect("tempdir");
    make_socket_dir(tmp.path());

    let (code, _stdout, stderr) = run_remove(
        tmp.path(),
        &["pkg:npm/__no_such_package__@9.9.9", "--silent", "--yes"],
    );
    assert_eq!(code, 1, "unknown identifier must exit 1");
    assert!(
        stderr.contains("No patch found matching identifier"),
        "--silent must NOT suppress error output; got {stderr:?}"
    );
}
