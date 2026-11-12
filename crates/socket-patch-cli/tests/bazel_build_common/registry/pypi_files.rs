//! Emulation of `files.pythonhosted.org`: wheels and sdists.
//! Stub until `wp-fixtures-heavy` (wave 1) replaces this file.

use super::super::fixture_server::FixtureServer;

/// Refuses: this registry is not emulated yet, and a test that believed
/// otherwise would send Bazel to a server that answers 404 for everything.
pub fn mount(_server: &FixtureServer) -> Result<(), String> {
    Err(super::not_landed("pypi_files", "wp-fixtures-heavy"))
}
