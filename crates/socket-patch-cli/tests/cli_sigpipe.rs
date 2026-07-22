//! Regression test: a closed stdout pipe must not crash the binary.
//!
//! The Rust runtime starts every process with SIGPIPE ignored, so a write to
//! a pipe whose reader has exited surfaces as an `EPIPE` error — and
//! `println!` turns that error into a panic. `socket-patch <cmd> | head -1`
//! therefore died with `thread 'main' panicked ... failed printing to
//! stdout: Broken pipe` and exit code 101 ("please report this bug"
//! territory) the moment `head` closed its end. Every other Unix CLI in that
//! pipeline position (`grep`, `cat`, `git log`) dies quietly of SIGPIPE;
//! `main.rs` must restore the default disposition so socket-patch does too.
//!
//! This test runs the compiled binary as a subprocess because the bug lives
//! in `main.rs` itself (process-wide signal state), upstream of everything
//! the in-process tests can reach.

#![cfg(unix)]

use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Stdio};

const BINARY: &str = env!("CARGO_BIN_EXE_socket-patch");
/// `libc::SIGPIPE`, inlined so the test crate needs no libc dependency.
const SIGPIPE: i32 = 13;

/// `list` against an empty manifest is the cheapest command that writes
/// to stdout: offline, lock-free — prints "No patches found in manifest."
/// and exits 0 when stdout is healthy.
#[test]
fn closed_stdout_pipe_is_not_a_panic() {
    let dir = tempfile::tempdir().expect("tempdir");
    let socket = dir.path().join(".socket");
    std::fs::create_dir_all(&socket).expect("create .socket");
    std::fs::write(socket.join("manifest.json"), r#"{ "patches": {} }"#)
        .expect("write manifest");

    // Build a pipe and close the read end BEFORE the child spawns, so the
    // child's first stdout write hits EPIPE deterministically (piping to a
    // real `head -1` would race its exit against our writes).
    let (reader, writer) = std::io::pipe().expect("pipe");
    drop(reader);

    let mut cmd = Command::new(BINARY);
    cmd.arg("list")
        .current_dir(dir.path())
        .stdout(Stdio::from(writer))
        .stderr(Stdio::piped());
    // Scrub the global env-var surface so ambient SOCKET_* vars can never
    // perturb the invocation (the assertion is about stdout plumbing).
    for var in socket_patch_cli::args::GLOBAL_ARG_ENV_VARS {
        cmd.env_remove(var);
    }
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
