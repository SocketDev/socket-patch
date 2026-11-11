//! Regression tests: a closed stdout pipe must neither crash the binary nor
//! cut a mutating command short.
//!
//! The Rust runtime starts every process with SIGPIPE ignored, so a write to
//! a pipe whose reader has exited surfaces as an `EPIPE` error — and
//! `println!` turns that error into a panic. `socket-patch <cmd> | head -1`
//! therefore died with `thread 'main' panicked ... failed printing to
//! stdout: Broken pipe` and exit code 101 ("please report this bug"
//! territory) the moment `head` closed its end. Restoring the default
//! SIGPIPE disposition removed the panic but killed the process at that
//! same line, which for `apply`, `rollback` and `remove` is in the middle of
//! their writes and with `.socket/apply.lock` held. The binary now keeps
//! SIGPIPE ignored and treats a broken pipe as "stop printing"
//! (`socket_patch_core::utils::stdio`): the run finishes and exits with its
//! own code.
//!
//! These tests run the compiled binary as a subprocess because the behavior
//! is process-wide state set up in `main.rs`, upstream of everything the
//! in-process tests can reach.

#![cfg(unix)]

use std::os::unix::process::ExitStatusExt;
use std::process::Stdio;

#[path = "common/hermetic.rs"]
mod hermetic;
#[path = "common/oracle.rs"]
mod oracle;

use oracle::git_sha256;

/// `libc::SIGPIPE`, inlined so the test crate needs no libc dependency.
const SIGPIPE: i32 = 13;

/// `list` against an empty manifest is the cheapest command that writes
/// to stdout: offline, lock-free — prints "No patches in this project. Run `socket-patch scan`."
/// and exits 0 when stdout is healthy.
#[test]
fn closed_stdout_pipe_is_not_a_panic() {
    let dir = tempfile::tempdir().expect("tempdir");
    let socket = dir.path().join(".socket");
    std::fs::create_dir_all(&socket).expect("create .socket");
    std::fs::write(socket.join("manifest.json"), r#"{ "patches": {} }"#).expect("write manifest");

    // Build a pipe and close the read end BEFORE the child spawns, so the
    // child's first stdout write hits EPIPE deterministically (piping to a
    // real `head -1` would race its exit against our writes).
    let (reader, writer) = std::io::pipe().expect("pipe");
    drop(reader);

    // Hermetic env: ambient SOCKET_* vars can never perturb the invocation
    // (the assertion is about stdout plumbing).
    let mut cmd = hermetic::binary_command();
    cmd.arg("list")
        .current_dir(dir.path())
        .stdout(Stdio::from(writer))
        .stderr(Stdio::piped());
    let out = cmd.output().expect("spawn socket-patch");
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        !stderr.contains("panicked"),
        "a closed stdout pipe must not crash with a Rust panic; stderr was:\n{stderr}"
    );
    // Dying of SIGPIPE (the Unix pipeline convention) and a clean exit 0
    // (a writer that swallows EPIPE) are both acceptable; the panic
    // runtime's exit 101 is not.
    assert!(
        out.status.signal() == Some(SIGPIPE) || out.status.code() == Some(0),
        "expected death-by-SIGPIPE or exit 0, got {:?} (code {:?}); stderr was:\n{stderr}",
        out.status,
        out.status.code()
    );
}

// ---------------------------------------------------------------------------
// Mutating commands: a reader that goes away must not stop the work
// ---------------------------------------------------------------------------
//
// Dying of SIGPIPE is fine for a command that only reads. A command that
// mutates holds `.socket/apply.lock` and is partway through a sequence of
// writes when it prints: killed at a `println!`, it left the lock file
// behind (no destructor runs) and skipped whatever came after the line
// (the manifest cleanup, the VEX document, the remaining legs). So a
// closed pipe ends the printing, never the run: the command finishes,
// releases the lock and exits with the code its work earned.

const ORIGINAL: &[u8] = b"module.exports = 'original';\n";
const PATCHED: &[u8] = b"module.exports = 'patched';\n";
const PACKAGES: [&str; 3] = ["sigpipe-a", "sigpipe-b", "sigpipe-c"];

/// An npm agent project: [`PACKAGES`] installed with `installed` as their
/// `index.js`, a manifest patching each from [`ORIGINAL`] to [`PATCHED`],
/// and both blobs cached (so every command below runs `--offline`).
fn agent_project(installed: &[u8]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    std::fs::write(
        root.join("package.json"),
        r#"{ "name": "sigpipe-root", "version": "0.0.0" }"#,
    )
    .unwrap();
    let (before, after) = (git_sha256(ORIGINAL), git_sha256(PATCHED));
    let mut patches = Vec::new();
    for (i, name) in PACKAGES.iter().enumerate() {
        let pkg = root.join("node_modules").join(name);
        std::fs::create_dir_all(&pkg).unwrap();
        std::fs::write(
            pkg.join("package.json"),
            format!(r#"{{ "name": "{name}", "version": "1.0.0" }}"#),
        )
        .unwrap();
        std::fs::write(pkg.join("index.js"), installed).unwrap();
        patches.push(format!(
            r#""pkg:npm/{name}@1.0.0": {{
      "uuid": "11111111-1111-4111-8111-{i:012}",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {{ "package/index.js": {{ "beforeHash": "{before}", "afterHash": "{after}" }} }},
      "vulnerabilities": {{}},
      "description": "sigpipe fixture",
      "license": "MIT",
      "tier": "free"
    }}"#
        ));
    }
    let socket = root.join(".socket");
    std::fs::create_dir_all(socket.join("blobs")).unwrap();
    std::fs::write(
        socket.join("manifest.json"),
        format!("{{ \"patches\": {{ {} }} }}", patches.join(",\n")),
    )
    .unwrap();
    std::fs::write(socket.join("blobs").join(&before), ORIGINAL).unwrap();
    std::fs::write(socket.join("blobs").join(&after), PATCHED).unwrap();
    dir
}

/// Run `socket-patch <args>` in `root` with stdout (and, with
/// `close_stderr`, stderr too: `2>&1 | head`) connected to a pipe whose
/// read end is already closed, so the first write to it fails.
fn run_with_closed_output(
    root: &std::path::Path,
    args: &[&str],
    close_stderr: bool,
) -> std::process::Output {
    let closed = || {
        let (reader, writer) = std::io::pipe().expect("pipe");
        drop(reader);
        Stdio::from(writer)
    };
    let mut cmd = hermetic::binary_command();
    cmd.args(args).current_dir(root).stdout(closed());
    if close_stderr {
        cmd.stderr(closed());
    } else {
        cmd.stderr(Stdio::piped());
    }
    cmd.output().expect("spawn socket-patch")
}

fn installed(root: &std::path::Path) -> Vec<Vec<u8>> {
    PACKAGES
        .iter()
        .map(|name| std::fs::read(root.join("node_modules").join(name).join("index.js")).unwrap())
        .collect()
}

fn recorded_patches(root: &std::path::Path) -> usize {
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join(".socket/manifest.json")).unwrap())
            .unwrap();
    manifest["patches"].as_object().unwrap().len()
}

/// The run was not cut short: it exited (no signal) with `code`, without a
/// panic, and removed its lock.
fn assert_finished(out: &std::process::Output, root: &std::path::Path, code: i32, what: &str) {
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("panicked"),
        "{what}: a closed pipe must not panic; stderr:\n{stderr}"
    );
    assert_eq!(
        out.status.signal(),
        None,
        "{what}: a closed pipe must not kill a mutating command; stderr:\n{stderr}"
    );
    assert_eq!(out.status.code(), Some(code), "{what}; stderr:\n{stderr}");
    assert!(
        !root.join(".socket/apply.lock").exists(),
        "{what}: the lock file must not outlive the command"
    );
}

#[test]
fn closed_stdout_does_not_cut_apply_short() {
    for close_stderr in [false, true] {
        let dir = agent_project(ORIGINAL);
        let out = run_with_closed_output(dir.path(), &["apply", "--offline"], close_stderr);
        assert_finished(
            &out,
            dir.path(),
            0,
            &format!("apply (stderr closed: {close_stderr})"),
        );
        assert_eq!(
            installed(dir.path()),
            vec![PATCHED.to_vec(); PACKAGES.len()],
            "every package is patched"
        );
    }
}

#[test]
fn closed_stdout_does_not_cut_rollback_short() {
    for close_stderr in [false, true] {
        let dir = agent_project(PATCHED);
        let out = run_with_closed_output(
            dir.path(),
            &["rollback", "--yes", "--offline"],
            close_stderr,
        );
        assert_finished(
            &out,
            dir.path(),
            0,
            &format!("rollback (stderr closed: {close_stderr})"),
        );
        assert_eq!(
            installed(dir.path()),
            vec![ORIGINAL.to_vec(); PACKAGES.len()],
            "every package is restored"
        );
        assert_eq!(
            recorded_patches(dir.path()),
            0,
            "the manifest cleanup that follows the restore ran too"
        );
    }
}

#[test]
fn closed_stdout_does_not_cut_remove_short() {
    let dir = agent_project(PATCHED);
    let out = run_with_closed_output(
        dir.path(),
        &["remove", "pkg:npm/sigpipe-b@1.0.0", "--yes", "--offline"],
        false,
    );
    assert_finished(&out, dir.path(), 0, "remove");
    assert_eq!(
        installed(dir.path()),
        vec![PATCHED.to_vec(), ORIGINAL.to_vec(), PATCHED.to_vec()],
        "the removed patch is rolled back, the others untouched"
    );
    assert_eq!(recorded_patches(dir.path()), 2);
}

/// `--json`: the envelope is the one thing printed, after every mutation.
/// A reader that never takes it changes nothing about the run.
#[test]
fn closed_stdout_does_not_fail_a_json_apply() {
    let dir = agent_project(ORIGINAL);
    let out = run_with_closed_output(dir.path(), &["apply", "--offline", "--json"], false);
    assert_finished(&out, dir.path(), 0, "apply --json");
    assert_eq!(
        installed(dir.path()),
        vec![PATCHED.to_vec(); PACKAGES.len()]
    );
}
