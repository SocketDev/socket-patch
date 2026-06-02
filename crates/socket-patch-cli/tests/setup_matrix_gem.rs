//! setup-matrix: gem ecosystem (bundler). No native post-install hook
//! and `setup` is a no-op, so the with-setup cases are an EXPECTED
//! BASELINE GAP.
//!
//! Run: `cargo test -p socket-patch-cli --features setup-e2e --test setup_matrix_gem`
#![cfg(feature = "setup-e2e")]

#[path = "setup_matrix_common/mod.rs"]
mod smc;

#[test]
fn bundler() {
    smc::run_pm("gem", "bundler");
}
