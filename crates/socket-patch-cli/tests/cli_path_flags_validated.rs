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

/// `get` and `scan` create the manifest (and its directory), so a
/// `--manifest-path` into a directory that does not exist yet is legal for
/// them.
fn creates_manifest(command: &[&str]) -> bool {
    matches!(command.first(), Some(&"get") | Some(&"scan"))
}

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
        if creates_manifest(command) {
            continue;
        }
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

/// The commands that create the manifest keep creating its directory: a
/// fresh checkout's `get --manifest-path state/patches.json` is no usage
/// error, and neither is `scan`. A directory in that position still is.
#[test]
fn manifest_creating_commands_accept_a_manifest_path_in_a_new_directory() {
    let tmp = tempfile::tempdir().unwrap();
    let missing = tmp.path().join("state/patches.json");
    for command in COMMANDS.iter().filter(|c| creates_manifest(c)) {
        let (code, stdout, stderr) = run(
            tmp.path(),
            command,
            &["--manifest-path", missing.to_str().unwrap()],
        );
        assert_ne!(
            code, 2,
            "{command:?} creates the manifest\nstdout={stdout}\nstderr={stderr}"
        );
        assert!(!stderr.contains("--manifest-path"), "{command:?}: {stderr}");
        let (code, _stdout, stderr) = run(
            tmp.path(),
            command,
            &["--manifest-path", tmp.path().to_str().unwrap()],
        );
        assert_eq!(
            code, 2,
            "{command:?}: a directory is no manifest file: {stderr}"
        );
    }
}

/// Stage the per-tool dir Deno >= 2.7 writes beside a `deno install -g`
/// tool, `<install-root>/bin/.<tool>/`, with a `node_modules` holding
/// is-odd, and return that `node_modules`.
fn stage_deno_tool_dir(root: &Path, deno_json: &str, package_json: bool) -> std::path::PathBuf {
    let tool = root.join("bin").join(".sptool");
    let pkg = tool
        .join("node_modules")
        .join(".deno")
        .join("is-odd@3.0.1")
        .join("node_modules")
        .join("is-odd");
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(
        pkg.join("package.json"),
        r#"{"name":"is-odd","version":"3.0.1"}"#,
    )
    .unwrap();
    std::fs::write(tool.join("deno.json"), deno_json).unwrap();
    std::fs::write(tool.join("deno.lock"), "{}").unwrap();
    if package_json {
        std::fs::write(tool.join("package.json"), "{}").unwrap();
    }
    std::fs::write(root.join("bin").join("sptool"), "#!/bin/sh\n").unwrap();
    tool.join("node_modules")
}

/// #444: Deno writes a per-tool `bin/.<tool>/node_modules` for a tool
/// installed from a local or JSR entrypoint, but the tool's `deno.json`
/// sets no `nodeModulesDir`, so Deno loads its npm packages from
/// `$DENO_DIR/npm` instead. A `--global-prefix` naming that tree used to
/// report `applied` and a VEX `not_affected` while the tool kept running
/// the unpatched copy; it is now a usage error pointing at `-g`.
#[test]
fn deno_tool_node_modules_deno_never_loads_is_a_usage_error() {
    let tmp = tempfile::tempdir().unwrap();
    for deno_json in [
        r#"{"imports":{}}"#,
        r#"{"nodeModulesDir":"none"}"#,
        r#"{"nodeModulesDir":false}"#,
    ] {
        let root = tempfile::tempdir().unwrap();
        let decoy = stage_deno_tool_dir(root.path(), deno_json, false);
        for command in COMMANDS.iter().filter(|c| !restores(c)) {
            let (code, stdout, stderr) = run(
                tmp.path(),
                command,
                &["--global-prefix", decoy.to_str().unwrap()],
            );
            assert_eq!(
                code, 2,
                "{deno_json} {command:?} must be a usage error\nstdout={stdout}\nstderr={stderr}"
            );
            assert!(
                stderr.contains("--global-prefix")
                    && stderr.contains("Deno does not load")
                    && stderr.contains("-g"),
                "{deno_json} {command:?}: {stderr}"
            );
            assert!(stdout.is_empty(), "{command:?}: {stdout}");
        }
    }
}

/// The commands that restore what an earlier run patched; they still
/// accept a Deno per-tool tree, so a decoy patched by an earlier release
/// can be reverted.
fn restores(command: &[&str]) -> bool {
    matches!(
        command.first(),
        Some(&"rollback") | Some(&"remove") | Some(&"repair")
    ) || command.contains(&"--revert")
}

/// #444: `rollback`, `remove`, `vendor --revert` and `repair` still
/// accept the decoy tree, so files an earlier release patched there can
/// be restored.
#[test]
fn deno_tool_node_modules_decoy_stays_restorable() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    let decoy = stage_deno_tool_dir(root.path(), r#"{"imports":{}}"#, false);
    for command in COMMANDS.iter().filter(|c| restores(c)) {
        let (code, stdout, stderr) = run(
            tmp.path(),
            command,
            &["--global-prefix", decoy.to_str().unwrap()],
        );
        assert!(
            !stderr.contains("Deno does not load"),
            "{command:?} (exit {code}) must not refuse the decoy\nstdout={stdout}\nstderr={stderr}"
        );
    }
}

/// #444: a per-tool `node_modules` Deno does load (an `npm:` entrypoint
/// tool, whose `deno.json` sets `"nodeModulesDir": "manual"`, or one with
/// a `package.json`) is still a valid `--global-prefix`.
#[test]
fn deno_tool_node_modules_deno_loads_is_accepted() {
    let tmp = tempfile::tempdir().unwrap();
    for (deno_json, package_json) in [
        (r#"{"workspace":[],"nodeModulesDir":"manual"}"#, true),
        (r#"{"nodeModulesDir":"auto"}"#, false),
        (r#"{"imports":{}}"#, true),
    ] {
        let root = tempfile::tempdir().unwrap();
        let live = stage_deno_tool_dir(root.path(), deno_json, package_json);
        let (code, stdout, stderr) = run(
            tmp.path(),
            &["list"],
            &["--global-prefix", live.to_str().unwrap()],
        );
        assert_ne!(
            code, 2,
            "{deno_json}: a live tree is no usage error\nstdout={stdout}\nstderr={stderr}"
        );
    }
}
