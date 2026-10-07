//! `--cwd`, `--global-prefix` and `--manifest-path` that name nothing are
//! usage errors (exit 2) on every project command, checked once in `main`
//! before the command runs.
//!
//! Before, nothing validated them: a typo in `--cwd` / `SOCKET_CWD` read as
//! an empty project, so `list`, `apply`, `apply --check`, `vendor`,
//! `vendor --check`, `scan` and `get` all exited 0 having checked nothing —
//! a CI gate that passes on a directory that does not exist (audit B10).
//! The positional `scan` PATH already exits 2 when it is not a directory;
//! the flags now match it.

mod common;

use std::path::Path;

/// Every project command, with the args it needs to get past clap. All are
/// offline so no case can reach the network before the check.
const COMMANDS: &[&[&str]] = &[
    &["list"],
    &["apply"],
    &["apply", "--check"],
    &["vendor"],
    &["vendor", "--check"],
    &["vendor", "--revert", "--yes"],
    &["scan"],
    &["scan", "--mode", "agent"],
    &["get", "lodash", "--yes"],
    &["vex"],
    &["rollback", "--yes"],
    &["remove", "pkg:npm/lodash@4.17.20", "--yes"],
    &["repair"],
];

fn run(cwd: &Path, command: &[&str], extra: &[&str]) -> (i32, String, String) {
    let mut args: Vec<&str> = command.to_vec();
    args.extend_from_slice(extra);
    args.push("--offline");
    common::run(cwd, &args)
}

/// A nonexistent `--cwd` fails every command with exit 2 and a message
/// naming the flag.
#[test]
fn nonexistent_cwd_is_a_usage_error_on_every_command() {
    let tmp = tempfile::tempdir().unwrap();
    let missing = tmp.path().join("no-such-dir");
    let missing = missing.to_str().unwrap();
    for command in COMMANDS {
        for json in [false, true] {
            let mut extra = vec!["--cwd", missing];
            if json {
                extra.push("--json");
            }
            let (code, stdout, stderr) = run(tmp.path(), command, &extra);
            assert_eq!(
                code, 2,
                "{command:?} {extra:?} must be a usage error\nstdout={stdout}\nstderr={stderr}"
            );
            assert!(
                stderr.contains("--cwd") && stderr.contains("does not exist"),
                "{command:?}: the error names the flag: {stderr}"
            );
            assert!(
                stdout.is_empty(),
                "{command:?}: nothing on stdout: {stdout}"
            );
        }
    }
}

/// The env spelling (`SOCKET_CWD`) is validated the same way, and a
/// `--cwd` naming a FILE is "not a directory".
#[test]
fn socket_cwd_env_and_file_cwd_are_usage_errors() {
    let tmp = tempfile::tempdir().unwrap();
    let missing = tmp.path().join("gone");
    let (code, _stdout, stderr) = common::run_with_env(
        tmp.path(),
        &["list"],
        &[("SOCKET_CWD", missing.to_str().unwrap())],
    );
    assert_eq!(code, 2, "SOCKET_CWD typo must fail: {stderr}");
    assert!(stderr.contains("SOCKET_CWD"), "{stderr}");

    let file = tmp.path().join("package.json");
    std::fs::write(&file, "{}").unwrap();
    let (code, _stdout, stderr) = run(
        tmp.path(),
        &["apply", "--check"],
        &["--cwd", file.to_str().unwrap()],
    );
    assert_eq!(code, 2, "a file --cwd must fail: {stderr}");
    assert!(stderr.contains("is not a directory"), "{stderr}");
}

/// A nonexistent `--global-prefix` fails every command with exit 2 (it
/// used to report "No global packages found." and exit 0).
#[test]
fn nonexistent_global_prefix_is_a_usage_error_on_every_command() {
    let tmp = tempfile::tempdir().unwrap();
    let missing = tmp.path().join("no-such-prefix");
    for command in COMMANDS {
        let (code, stdout, stderr) = run(
            tmp.path(),
            command,
            &["--global-prefix", missing.to_str().unwrap()],
        );
        assert_eq!(
            code, 2,
            "{command:?} must be a usage error\nstdout={stdout}\nstderr={stderr}"
        );
        assert!(stderr.contains("--global-prefix"), "{command:?}: {stderr}");
    }
}

/// A `--manifest-path` in a directory that does not exist fails every
/// command with exit 2 (`list` used to say "No patches" and exit 0); one
/// naming a directory fails too.
#[test]
fn manifest_path_in_a_missing_directory_is_a_usage_error_on_every_command() {
    let tmp = tempfile::tempdir().unwrap();
    let missing = tmp.path().join("no-such-dir/m.json");
    for command in COMMANDS {
        let (code, stdout, stderr) = run(
            tmp.path(),
            command,
            &["--manifest-path", missing.to_str().unwrap()],
        );
        assert_eq!(
            code, 2,
            "{command:?} must be a usage error\nstdout={stdout}\nstderr={stderr}"
        );
        assert!(stderr.contains("--manifest-path"), "{command:?}: {stderr}");
    }
    let (code, _stdout, stderr) = run(
        tmp.path(),
        &["list"],
        &["--manifest-path", tmp.path().to_str().unwrap()],
    );
    assert_eq!(code, 2, "a directory is no manifest file: {stderr}");
    assert!(stderr.contains("is a directory"), "{stderr}");
}

/// Anti-vacuous controls: real directories still run, and a missing
/// manifest FILE in an existing project stays legal — hosted and vendored
/// projects have none, and `get` / `scan --mode agent` create it.
#[test]
fn existing_paths_and_a_missing_manifest_file_still_run() {
    let tmp = tempfile::tempdir().unwrap();
    let project = tmp.path().join("project");
    let prefix = tmp.path().join("prefix");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::create_dir_all(&prefix).unwrap();

    let (code, _stdout, stderr) = run(tmp.path(), &["list"], &["--cwd", project.to_str().unwrap()]);
    assert_eq!(code, 0, "an existing --cwd runs: {stderr}");

    let (code, _stdout, stderr) = run(
        tmp.path(),
        &["apply"],
        &["--global-prefix", prefix.to_str().unwrap()],
    );
    assert_eq!(code, 0, "an existing --global-prefix runs: {stderr}");

    for manifest in [
        project.join("custom.json"),
        // `.socket/` itself need not exist yet: its project does.
        project.join(".socket/manifest.json"),
    ] {
        let (code, _stdout, stderr) = run(
            tmp.path(),
            &["list"],
            &["--manifest-path", manifest.to_str().unwrap()],
        );
        assert_eq!(
            code, 0,
            "a missing manifest file in an existing project stays legal: {stderr}"
        );
    }
}
