//! setup-matrix: nuget ecosystem (dotnet). No native post-install hook,
//! `setup` is a no-op, and apply is additionally gated behind
//! `SOCKET_EXPERIMENTAL_NUGET` (the driver sets it). The with-setup
//! cases are an EXPECTED BASELINE GAP.
//!
//! Run: `cargo test -p socket-patch-cli --features setup-e2e --test setup_matrix_nuget`
#![cfg(feature = "setup-e2e")]

#[path = "setup_matrix_common/mod.rs"]
mod smc;

#[test]
fn dotnet() {
    smc::run_pm("nuget", "dotnet");
}
