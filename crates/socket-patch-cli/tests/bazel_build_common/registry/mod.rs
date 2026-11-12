//! One module per upstream registry the fixture server emulates. Each
//! mounts its routes on a [`FixtureServer`](super::fixture_server::FixtureServer)
//! under the production host name, so a fixture's lock keeps the URLs a
//! real project has. A module is owned first by the fixture package that
//! needs it and then by the matching lane package; until then it refuses.

pub mod crates;
pub mod gem;
pub mod goproxy;
pub mod maven;
pub mod npm;
pub mod nuget;
pub mod pypi_files;
pub mod pypi_index;

/// The refusal of a registry stub.
pub fn not_landed(registry: &str, owner: &str) -> String {
    format!("the {registry} registry emulation has not landed (owner: {owner})")
}
