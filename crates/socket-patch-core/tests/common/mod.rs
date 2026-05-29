//! Shared helpers for integration tests. Crate-private.
//!
//! `tests/<name>/mod.rs` is treated by cargo as a non-test module
//! that other integration test files can pull in via
//! `#[path = "common/mod.rs"] mod common;` — keeping helpers out of
//! the crate's compile path but reusable across the test suite.

use std::process::Command;

/// True when the current process is running as uid 0 (root).
///
/// Used by `read_dir`/`file_type` permission-error tests to skip
/// themselves under root, because `chmod` of any mode against a
/// directory has no effect for root (root can always read anything),
/// so the Err arm we're trying to drive doesn't fire.
#[cfg(unix)]
pub fn uid_is_root() -> bool {
    Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| {
            String::from_utf8(o.stdout)
                .ok()
                .map(|s| s.trim().to_string())
        })
        .map(|s| s == "0")
        .unwrap_or(false)
}

#[cfg(not(unix))]
pub fn uid_is_root() -> bool {
    false
}

/// Set mode 0o000 on a directory so subsequent `read_dir` returns Err.
/// Used by permission-error tests; must call `chmod_readable` to
/// restore before the tempdir is dropped or cleanup will fail.
#[cfg(unix)]
pub fn chmod_unreadable(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o000);
    std::fs::set_permissions(path, perms).expect("chmod 000 must succeed");
}

#[cfg(unix)]
pub fn chmod_readable(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o700);
    let _ = std::fs::set_permissions(path, perms);
}

/// Subprocess stub for the `CommandRunner` trait.
///
/// Each test registers a `(bin, args) -> Option<String>` mapping;
/// `run()` looks up the (bin, args) tuple and returns the canned
/// response, or `None` if the test didn't register one. Lets crawler
/// tests drive the "binary present, returned this stdout" arm of
/// `get_*_global_prefix` / `run_gem_env` / `find_python_command` /
/// `get_global_python_site_packages` without depending on any
/// installed CLI.
#[allow(dead_code)]
pub struct MockCommandRunner {
    responses: std::collections::HashMap<(String, Vec<String>), Option<String>>,
}

#[allow(dead_code)]
impl MockCommandRunner {
    pub fn new() -> Self {
        Self {
            responses: std::collections::HashMap::new(),
        }
    }

    /// Register a stdout response for the given `(bin, args)`. A
    /// `Some(stdout)` simulates the binary returning success; a
    /// `None` simulates spawn failure or non-zero exit.
    pub fn with_response(mut self, bin: &str, args: &[&str], stdout: Option<&str>) -> Self {
        let key = (
            bin.to_string(),
            args.iter().map(|s| s.to_string()).collect(),
        );
        self.responses.insert(key, stdout.map(|s| s.to_string()));
        self
    }
}

impl socket_patch_core::utils::process::CommandRunner for MockCommandRunner {
    fn run(&self, bin: &str, args: &[&str]) -> Option<String> {
        let key = (
            bin.to_string(),
            args.iter().map(|s| s.to_string()).collect(),
        );
        self.responses.get(&key).cloned().unwrap_or(None)
    }
}
