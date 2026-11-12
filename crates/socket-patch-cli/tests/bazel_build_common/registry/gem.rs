//! Emulation of `rubygems.org`: `gems/<file>.gem` and the compact index, for the
//! rules_ruby fixtures.
//! Stub until `wp-fixtures-light` (wave 1) replaces this file.

use super::super::fixture_server::FixtureServer;

/// Refuses: this registry is not emulated yet, and a test that believed
/// otherwise would send Bazel to a server that answers 404 for everything.
pub fn mount(_server: &FixtureServer) -> Result<(), String> {
    Err(super::not_landed("gem", "wp-fixtures-light"))
}
