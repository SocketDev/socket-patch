//! Emulation of `proxy.golang.org` behind `--repo_env=GOPROXY=`, and the sumdb route.
//! Unknown modules get a 404; a stub that drops connections fails the whole
//! `go_deps` extension (its go-list pass asks for about 1,700 files).
//! Stub until `wp-fixtures-heavy` (wave 1) replaces this file.

use super::super::fixture_server::FixtureServer;

/// Refuses: this registry is not emulated yet, and a test that believed
/// otherwise would send Bazel to a server that answers 404 for everything.
pub fn mount(_server: &FixtureServer) -> Result<(), String> {
    Err(super::not_landed("goproxy", "wp-fixtures-heavy"))
}
