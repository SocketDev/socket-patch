//! Subprocess invocation seam shared by the ecosystem crawlers.
//!
//! Several crawlers ask an external CLI for a path that's hard to
//! infer otherwise — `npm root -g`, `gem env gemdir`, `python3 -c
//! "import site; ..."`, etc. The historical pattern was to embed
//! `std::process::Command::new(bin).args([...]).output()` directly
//! inside each helper, which leaves two arms untestable without
//! installing the binary: the success arm (binary present, stdout
//! parsed) and the spawn-Err arm (binary missing or unspawnable).
//!
//! This module provides a `CommandRunner` trait whose default impl,
//! `SystemCommandRunner`, performs the real spawn, and whose test
//! double (`MockCommandRunner` in `tests/common/mod.rs`) maps
//! `(bin, args)` to canned stdout. Each shell-out helper accepts a
//! `&dyn CommandRunner` argument so tests can inject the mock;
//! production callers either build the helper with the default
//! runner or thread a singleton.

use std::process::{Command, Stdio};

/// Run an external binary with the given args and return its
/// stdout, trimmed, when the spawn succeeded AND the process exited
/// with a success status AND stdout is non-empty after trimming.
///
/// Returns `None` for any of: spawn failure (binary not on PATH),
/// non-zero exit status, empty stdout after trim. Stderr is
/// captured and discarded — the crawlers treat all failures as
/// "no information", not as errors to surface.
pub trait CommandRunner: Send + Sync {
    fn run(&self, bin: &str, args: &[&str]) -> Option<String>;
}

/// Default runner: spawns the real binary via `std::process::Command`.
///
/// Stdin is set to /dev/null so the child can't block waiting for
/// input. stdout is captured; stderr is captured and dropped (we
/// don't surface CLI diagnostics — the helpers fall back to other
/// discovery paths on any failure).
pub struct SystemCommandRunner;

impl CommandRunner for SystemCommandRunner {
    fn run(&self, bin: &str, args: &[&str]) -> Option<String> {
        let output = Command::new(bin)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if stdout.is_empty() {
            None
        } else {
            Some(stdout)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Confirm the real runner returns Some for a tiny command we
    /// know is on every Unix PATH — `echo`. Skipped on Windows where
    /// `echo` isn't a real binary.
    #[cfg(unix)]
    #[test]
    fn system_runner_returns_stdout_for_real_binary() {
        let runner = SystemCommandRunner;
        let out = runner.run("echo", &["hello"]).expect("echo should succeed");
        assert_eq!(out, "hello");
    }

    /// Spawn failure → None. The binary name is intentionally one
    /// that should never be on PATH.
    #[test]
    fn system_runner_returns_none_on_spawn_failure() {
        let runner = SystemCommandRunner;
        let out = runner.run("definitely-not-a-real-binary-1234567", &[]);
        assert_eq!(out, None);
    }

    /// Non-zero exit → None. `false`(1) is in coreutils everywhere.
    #[cfg(unix)]
    #[test]
    fn system_runner_returns_none_on_non_zero_exit() {
        let runner = SystemCommandRunner;
        let out = runner.run("false", &[]);
        assert_eq!(out, None);
    }
}
