//! `setup --silent` contract tests.
//!
//! CLI_CONTRACT.md defines `--silent` as "Errors only". Regression
//! guard: `setup` (and its `--check` / `--remove` modes) gated all of
//! its human-readable output on `!json` alone — the "Configuring..." /
//! "Searching..." headers, the previews, the summaries, the
//! configuration-status report, and the commit hints all printed under
//! `--silent`. Same bug class previously fixed in `list`, `repair`,
//! `get`, `remove`, and `scan`.
//!
//! `--silent` suppresses informational output only: the mutation still
//! happens, exit codes still distinguish states, and (matching the
//! shared `confirm()` helper) prompting is unaffected — these tests
//! pass `--yes` like the scan/remove silent suites. Runs fully offline:
//! npm-only fixtures, no API calls.

use std::path::{Path, PathBuf};
use std::process::Command;

use socket_patch_cli::args::GLOBAL_ARG_ENV_VARS;

fn binary() -> PathBuf {
    env!("CARGO_BIN_EXE_socket-patch").into()
}

const UNCONFIGURED_PACKAGE_JSON: &str = r#"{
  "name": "setup-silent-test",
  "version": "0.0.0"
}"#;

fn write_root(root: &Path) {
    std::fs::write(root.join("package.json"), UNCONFIGURED_PACKAGE_JSON).unwrap();
}

/// Run `socket-patch setup` in `cwd` with a scrubbed SOCKET_* environment
/// so ambient developer/CI configuration (tokens, silent toggles) can't
/// change the branch under test.
fn run_setup(cwd: &Path, args: &[&str]) -> (i32, String, String) {
    let mut cmd = Command::new(binary());
    cmd.arg("setup").args(args).current_dir(cwd);
    for var in GLOBAL_ARG_ENV_VARS {
        cmd.env_remove(var);
    }
    cmd.env_remove("SOCKET_SETUP_EXCLUDE");
    cmd.env("SOCKET_TELEMETRY_DISABLED", "1");
    let out = cmd.output().expect("run socket-patch setup");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

/// Non-error stderr lines: drop the unconditional core API-token warning
/// (printed by shared client/telemetry plumbing, out of scope for
/// `setup`'s `--silent` gating) and blank lines, keep everything else.
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

/// `setup --silent --yes` must wire the postinstall hook without printing
/// anything: no "Configuring socket-patch install hooks..." header, no
/// preview, no summary, no commit hints.
#[test]
fn setup_silent_configures_but_prints_nothing() {
    let tmp = tempfile::tempdir().expect("tempdir");
    write_root(tmp.path());

    let (code, stdout, stderr) = run_setup(tmp.path(), &["--silent", "--yes"]);
    assert_eq!(
        code, 0,
        "setup must succeed; stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        stdout.trim().is_empty(),
        "--silent must produce no stdout; got {stdout:?}"
    );
    let chatter = stderr_chatter(&stderr);
    assert!(
        chatter.is_empty(),
        "--silent must produce no stderr chatter on success; got {chatter:?}"
    );

    // Silent suppresses output, not the mutation: the hook must be wired.
    let pkg = std::fs::read_to_string(tmp.path().join("package.json")).expect("read package.json");
    assert!(
        pkg.contains("socket-patch"),
        "the postinstall hook must still be wired under --silent; got {pkg:?}"
    );

    // Control run: the same scenario WITHOUT --silent must print the
    // header and summary — otherwise the assertions above pass vacuously.
    let tmp2 = tempfile::tempdir().expect("tempdir");
    write_root(tmp2.path());
    let (loud_code, loud_stdout, _) = run_setup(tmp2.path(), &["--yes"]);
    assert_eq!(loud_code, 0);
    assert!(
        loud_stdout.contains("Configuring socket-patch install hooks"),
        "non-silent setup must print the header; got {loud_stdout:?}"
    );
    assert!(
        loud_stdout.contains("item(s) updated"),
        "non-silent setup must print the summary; got {loud_stdout:?}"
    );
}

/// `setup --check --silent` must print nothing in both states; the exit
/// code alone distinguishes configured (0) from needs-configuration (1),
/// mirroring the `list --silent` fix.
#[test]
fn setup_check_silent_prints_nothing_in_both_states() {
    // Unconfigured: exit 1, no output.
    let tmp = tempfile::tempdir().expect("tempdir");
    write_root(tmp.path());
    let (code, stdout, stderr) = run_setup(tmp.path(), &["--check", "--silent"]);
    assert_eq!(
        code, 1,
        "unconfigured --check must exit 1; stdout={stdout:?}"
    );
    assert!(
        stdout.trim().is_empty(),
        "--check --silent must produce no stdout; got {stdout:?}"
    );
    let chatter = stderr_chatter(&stderr);
    assert!(
        chatter.is_empty(),
        "--check --silent must produce no stderr chatter; got {chatter:?}"
    );

    // Configured (after a real setup): exit 0, no output.
    let (setup_code, _, _) = run_setup(tmp.path(), &["--silent", "--yes"]);
    assert_eq!(
        setup_code, 0,
        "setup must succeed before the configured check"
    );
    let (code2, stdout2, _) = run_setup(tmp.path(), &["--check", "--silent"]);
    assert_eq!(
        code2, 0,
        "configured --check must exit 0; stdout={stdout2:?}"
    );
    assert!(
        stdout2.trim().is_empty(),
        "configured --check --silent must produce no stdout; got {stdout2:?}"
    );

    // Control run: without --silent the status report must print.
    let (loud_code, loud_stdout, _) = run_setup(tmp.path(), &["--check"]);
    assert_eq!(loud_code, 0);
    assert!(
        loud_stdout.contains("Configuration status"),
        "non-silent --check must print the status report; got {loud_stdout:?}"
    );
}

/// `setup --remove --silent --yes` must revert the hook without printing
/// anything: no "Searching..." header, no proposed-changes preview, no
/// summary, no pip-uninstall hint.
#[test]
fn setup_remove_silent_prints_nothing_but_removes() {
    let tmp = tempfile::tempdir().expect("tempdir");
    write_root(tmp.path());
    let (setup_code, _, _) = run_setup(tmp.path(), &["--silent", "--yes"]);
    assert_eq!(setup_code, 0, "setup must succeed before remove");

    let (code, stdout, stderr) = run_setup(tmp.path(), &["--remove", "--silent", "--yes"]);
    assert_eq!(
        code, 0,
        "remove must succeed; stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        stdout.trim().is_empty(),
        "--remove --silent must produce no stdout; got {stdout:?}"
    );
    let chatter = stderr_chatter(&stderr);
    assert!(
        chatter.is_empty(),
        "--remove --silent must produce no stderr chatter on success; got {chatter:?}"
    );

    // Silent suppresses output, not the mutation: the hook must be gone.
    let pkg = std::fs::read_to_string(tmp.path().join("package.json")).expect("read package.json");
    assert!(
        !pkg.contains("socket-patch"),
        "the postinstall hook must still be removed under --silent; got {pkg:?}"
    );

    // Control run: a non-silent remove on a configured repo must print
    // the preview and summary — otherwise the assertions above pass
    // vacuously.
    let tmp2 = tempfile::tempdir().expect("tempdir");
    write_root(tmp2.path());
    let (_, _, _) = run_setup(tmp2.path(), &["--silent", "--yes"]);
    let (loud_code, loud_stdout, _) = run_setup(tmp2.path(), &["--remove", "--yes"]);
    assert_eq!(loud_code, 0);
    assert!(
        loud_stdout.contains("Proposed changes"),
        "non-silent remove must print the preview; got {loud_stdout:?}"
    );
    assert!(
        loud_stdout.contains("item(s) had socket-patch removed"),
        "non-silent remove must print the summary; got {loud_stdout:?}"
    );
}

/// Errors must still print under `--silent` ("errors only", not "nothing"),
/// mirroring the remove/scan silent suites: an invalid package.json keeps
/// its error message on stderr and exit 1 in all three modes, while the
/// informational stdout stays suppressed.
#[test]
fn setup_silent_keeps_error_output() {
    let tmp = tempfile::tempdir().expect("tempdir");
    std::fs::write(tmp.path().join("package.json"), "{ not json").unwrap();

    for mode in [&[][..], &["--check"][..], &["--remove"][..]] {
        let mut args: Vec<&str> = mode.to_vec();
        args.extend(["--silent", "--yes"]);
        let (code, stdout, stderr) = run_setup(tmp.path(), &args);
        assert_eq!(
            code, 1,
            "invalid package.json must exit 1 for {mode:?}; stdout={stdout:?} stderr={stderr:?}"
        );
        assert!(
            stdout.trim().is_empty(),
            "--silent must still suppress informational stdout for {mode:?}; got {stdout:?}"
        );
        assert!(
            stderr.contains("Invalid package.json"),
            "--silent must NOT suppress error output for {mode:?}; got {stderr:?}"
        );
    }
}

/// Same contract for the apply-phase (post-preview) failures: a package.json
/// that previews fine but cannot be rewritten (read-only directory) must
/// surface its write error on stderr under `--silent`, not just exit 1.
#[cfg(unix)]
#[test]
fn setup_silent_keeps_apply_phase_error_output() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = tempfile::tempdir().expect("tempdir");
    write_root(tmp.path());
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o555)).unwrap();

    let (code, stdout, stderr) = run_setup(tmp.path(), &["--silent", "--yes"]);

    // Restore so the tempdir can clean up regardless of the assertions.
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o755)).unwrap();

    assert_eq!(
        code, 1,
        "unwritable package.json must exit 1; stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        stdout.trim().is_empty(),
        "--silent must still suppress informational stdout; got {stdout:?}"
    );
    assert!(
        stderr_chatter(&stderr)
            .iter()
            .any(|l| l.starts_with("Error:")),
        "--silent must NOT suppress the apply-phase write error; got {stderr:?}"
    );
}

/// The `no_files` path (no project found at all) is informational, not an
/// error: under `--silent` it must print nothing and exit 0. Covers both
/// the plain-setup inline branch and the shared `report_no_files` helper
/// that `--check` / `--remove` use.
#[test]
fn setup_silent_no_files_prints_nothing() {
    let tmp = tempfile::tempdir().expect("tempdir");

    for mode in [&[][..], &["--check"][..], &["--remove"][..]] {
        let mut args: Vec<&str> = mode.to_vec();
        args.push("--silent");
        let (code, stdout, stderr) = run_setup(tmp.path(), &args);
        assert_eq!(
            code, 0,
            "no_files must exit 0 for {mode:?}; stderr={stderr:?}"
        );
        assert!(
            stdout.trim().is_empty(),
            "--silent no_files must produce no stdout for {mode:?}; got {stdout:?}"
        );
        let chatter = stderr_chatter(&stderr);
        assert!(
            chatter.is_empty(),
            "--silent no_files must produce no stderr chatter for {mode:?}; got {chatter:?}"
        );
    }

    // Control run: without --silent the hint must print.
    let (loud_code, loud_stdout, _) = run_setup(tmp.path(), &[]);
    assert_eq!(loud_code, 0);
    assert!(
        loud_stdout.contains("No package.json, Python, Bundler, or Composer project found"),
        "non-silent no_files must print the hint; got {loud_stdout:?}"
    );
}
