//! Emulation of `repo1.maven.org`: the jars, POMs and checksum files a pinned
//! `maven_install.json` names, and the loopback repository of the unpinned-hub guard.
//! Stub until `wp-fixtures-light` (wave 1) replaces this file.

use super::super::fixture_server::FixtureServer;

/// Refuses: this registry is not emulated yet, and a test that believed
/// otherwise would send Bazel to a server that answers 404 for everything.
pub fn mount(_server: &FixtureServer) -> Result<(), String> {
    Err(super::not_landed("maven", "wp-fixtures-light"))
}
