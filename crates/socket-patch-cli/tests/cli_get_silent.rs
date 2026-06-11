//! `get --silent` contract test.
//!
//! CLI_CONTRACT.md defines `--silent` as "Errors only". Regression
//! guard: `get` gated all of its human-readable chatter on `!json` alone
//! and hardcoded `silent: false` into the `DownloadParams` it builds, so
//! `get --silent` printed everything anyway. Runs fully offline: a bare
//! package-name identifier in an empty project dir takes the
//! crawl → "No packages found" path and exits 0 before any API call.

use std::path::{Path, PathBuf};
use std::process::Command;

use socket_patch_cli::args::GLOBAL_ARG_ENV_VARS;

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

/// Run `socket-patch get` in `cwd` with a scrubbed SOCKET_* environment
/// so ambient developer/CI configuration (tokens, org slugs, silent
/// toggles) can't change the branch under test.
fn run_get(cwd: &Path, args: &[&str]) -> (i32, String) {
    let mut cmd = Command::new(binary());
    cmd.arg("get").args(args).current_dir(cwd);
    for var in GLOBAL_ARG_ENV_VARS {
        cmd.env_remove(var);
    }
    for var in [
        "SOCKET_SAVE_ONLY",
        "SOCKET_ONE_OFF",
        "SOCKET_ALL_RELEASES",
        "SOCKET_PATCH_API_URL",
        "SOCKET_PATCH_API_TOKEN",
        "SOCKET_PATCH_PROXY_URL",
    ] {
        cmd.env_remove(var);
    }
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1");
    let out = cmd.output().expect("run socket-patch get");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
    )
}

#[test]
fn get_silent_produces_no_stdout() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (code, stdout) = run_get(tmp.path(), &["--silent", "no-such-package-zzz"]);
    assert_eq!(code, 0, "no-packages path must exit 0; stdout={stdout:?}");
    assert!(
        stdout.trim().is_empty(),
        "--silent must produce no stdout; got {stdout:?}"
    );

    // Control run: the same scenario WITHOUT --silent must print the
    // human messages — otherwise the assertion above passes vacuously.
    let tmp2 = tempfile::tempdir().expect("tempdir");
    let (loud_code, loud_stdout) = run_get(tmp2.path(), &["no-such-package-zzz"]);
    assert_eq!(loud_code, 0);
    assert!(
        loud_stdout.contains("No packages found"),
        "non-silent run must print the no-packages message; got {loud_stdout:?}"
    );
}
