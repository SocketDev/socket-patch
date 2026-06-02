//! setup-matrix: polyglot all-ecosystem monorepo.
//!
//! A single repo containing an npm workspace alongside
//! python/rust/go/php/ruby/nuget/deno manifests. Confirms `socket-patch
//! setup` works in this mixed environment — it must configure the npm
//! hooks and NOT choke on the foreign manifests; a root `npm install`
//! then applies the patch to the npm slice. Runs in the npm image (the
//! only one with the npm toolchain); the foreign manifests are present
//! to test setup's robustness, not installed.
//!
//! Run: `cargo test -p socket-patch-cli --features setup-e2e --test setup_matrix_monorepo`
#![cfg(feature = "setup-e2e")]

#[path = "setup_matrix_common/mod.rs"]
mod smc;

#[test]
fn monorepo() {
    smc::run_monorepo();
}
