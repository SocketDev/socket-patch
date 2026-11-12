//! Emulation of a sparse crates registry (index, `config.json`, `.crate` files): cargo
//! under crate_universe contacts it directly, not through Bazel's downloader.
//! Stub until `wp-fixtures-heavy` (wave 1) replaces this file.

use super::super::fixture_server::FixtureServer;

/// Refuses: this registry is not emulated yet, and a test that believed
/// otherwise would send Bazel to a server that answers 404 for everything.
pub fn mount(_server: &FixtureServer) -> Result<(), String> {
    Err(super::not_landed("crates", "wp-fixtures-heavy"))
}
