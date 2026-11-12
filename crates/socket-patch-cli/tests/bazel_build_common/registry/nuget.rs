//! Emulation of `api.nuget.org`: the v3 service index (fetched without a checksum on
//! every cold output base) and the flat-container `.nupkg` files.
//! Stub until `wp-fixtures-light` (wave 1) replaces this file.

use super::super::fixture_server::FixtureServer;

/// Refuses: this registry is not emulated yet, and a test that believed
/// otherwise would send Bazel to a server that answers 404 for everything.
pub fn mount(_server: &FixtureServer) -> Result<(), String> {
    Err(super::not_landed("nuget", "wp-fixtures-light"))
}
