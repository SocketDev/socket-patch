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

/// Set mode 0o000 on a path so a subsequent read of it returns Err.
/// Used by permission-error tests; must call `chmod_readable` to
/// restore before the tempdir is dropped or cleanup will fail.
///
/// Crucially, this *verifies the precondition actually took hold*
/// before returning: every consumer concludes "crawler returned
/// empty ⟹ it short-circuited on the read Err arm", which is only a
/// valid inference if the path is genuinely unreadable. On any
/// environment where chmod 000 is a no-op (root — callers guard with
/// `uid_is_root`, but the guard shells out to `id` and is
/// best-effort; or an exotic/overlay FS, or a process holding
/// CAP_DAC_OVERRIDE), a silent no-op would let those tests pass for
/// the wrong reason — a crawler that read the path fine and merely
/// found nothing (e.g. the composer test's empty `installed.json`)
/// would still satisfy `assert!(result.is_empty())`. We refuse to
/// hand back a falsely-prepared fixture: if the path is still
/// readable after the chmod, we panic loudly here rather than let a
/// vacuous green slip through downstream.
#[cfg(unix)]
pub fn chmod_unreadable(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o000);
    std::fs::set_permissions(path, perms).expect("chmod 000 must succeed");

    // Confirm the mode change genuinely denies reads. Branch on the
    // kind so this works for both the directory fixtures (read_dir
    // must fail) and the single-file fixture (opening for read must
    // fail). `metadata`/`is_dir` only needs traverse on the parent,
    // which the tempdir still grants, so it remains accurate here.
    let still_readable = if path.is_dir() {
        std::fs::read_dir(path).is_ok()
    } else {
        std::fs::File::open(path).is_ok()
    };
    assert!(
        !still_readable,
        "chmod 000 did not make {path:?} unreadable — permission-error \
         fixture is not actually prepared (running as root, or on a \
         filesystem/capability set that ignores mode bits). Any test \
         relying on this would pass vacuously; failing loudly instead.",
    );
}

/// Restore a path to an owner-accessible mode after a
/// `chmod_unreadable`. The restore is mandatory: tempdir teardown
/// (and any later read of the path) needs it, so a failure here must
/// be surfaced, not swallowed. Always called on a path the test owns
/// and that exists, so 0o700 reliably succeeds; if it ever doesn't,
/// that's a real regression we want to see.
#[cfg(unix)]
pub fn chmod_readable(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o700);
    std::fs::set_permissions(path, perms).expect("chmod restore (0o700) must succeed");
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
