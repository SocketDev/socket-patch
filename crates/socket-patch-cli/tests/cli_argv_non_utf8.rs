//! Regression tests: non-UTF-8 bytes in argv must be a clean usage error.
//!
//! On Unix, argv is raw bytes — a junk-byte filename (or a path typed in a
//! non-UTF-8 locale) is a perfectly legal process argument. `main.rs` used to
//! collect argv via `std::env::args()`, which *panics* on the first
//! non-Unicode argument: the binary died with a Rust panic message and exit
//! code 101 ("please report this bug" territory) before clap ever saw the
//! command line. The contract treats malformed invocations as clap usage
//! errors (exit `2`, message on stderr) — see `setup --check --remove` in
//! `CLI_CONTRACT.md` — so a bad byte in argv must take that path too.
//!
//! These tests run the compiled binary as a subprocess because the bug lives
//! in `main.rs` itself (the argv collection step), upstream of everything the
//! in-process parser tests can reach.

#![cfg(unix)]

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::process::Command;

const BINARY: &str = env!("CARGO_BIN_EXE_socket-patch");

/// An argument that is valid on the OS level but not valid UTF-8.
fn non_utf8_arg() -> &'static OsStr {
    OsStr::from_bytes(b"\xff\xfe")
}

/// Run the binary with the given args in a hermetic env and capture output.
fn run(args: &[&OsStr]) -> (Option<i32>, String, String) {
    let mut cmd = Command::new(BINARY);
    for a in args {
        cmd.arg(a);
    }
    // Scrub the global env-var surface so ambient SOCKET_* vars can never
    // perturb where the invocation fails (the assertion is about the argv
    // path, not env handling).
    for var in socket_patch_cli::args::GLOBAL_ARG_ENV_VARS {
        cmd.env_remove(var);
    }
    let out = cmd.output().expect("spawn socket-patch");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Shared assertions: a clean clap-style usage error, not a panic.
fn assert_clean_usage_error(code: Option<i32>, stdout: &str, stderr: &str) {
    // Not killed by a signal, and not the panic runtime's exit 101 — the
    // contract's usage-error code is 2.
    assert_eq!(
        code,
        Some(2),
        "non-UTF-8 argv must exit with the usage-error code 2; stderr was:\n{stderr}"
    );
    assert!(
        !stderr.contains("panicked"),
        "non-UTF-8 argv must not crash with a Rust panic; stderr was:\n{stderr}"
    );
    assert!(
        stderr.to_lowercase().contains("invalid utf-8"),
        "stderr must explain the invalid UTF-8 argument; stderr was:\n{stderr}"
    );
    // Diagnostics belong on stderr; stdout must stay clean (machine-readable
    // consumers pipe stdout).
    assert!(
        stdout.is_empty(),
        "usage error must not write to stdout; stdout was:\n{stdout}"
    );
}

#[test]
fn non_utf8_arg_after_subcommand_is_clean_usage_error() {
    let (code, stdout, stderr) = run(&[OsStr::new("list"), non_utf8_arg()]);
    assert_clean_usage_error(code, &stdout, &stderr);
}

#[test]
fn non_utf8_bare_first_arg_is_clean_usage_error() {
    // First positional slot — the position `parse_with_uuid_fallback` probes
    // for the bare-UUID rewrite. The argv collection must fail cleanly before
    // any of that machinery runs.
    let (code, stdout, stderr) = run(&[non_utf8_arg()]);
    assert_clean_usage_error(code, &stdout, &stderr);
}

#[test]
fn non_utf8_cwd_value_is_clean_usage_error() {
    // A non-UTF-8 *path* handed to `--cwd` is the realistic way users hit
    // this: shell tab-completion of a junk-byte directory name.
    let (code, stdout, stderr) = run(&[OsStr::new("list"), OsStr::new("--cwd"), non_utf8_arg()]);
    assert_clean_usage_error(code, &stdout, &stderr);
}
