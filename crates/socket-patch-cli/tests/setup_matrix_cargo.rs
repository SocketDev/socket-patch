//! setup-matrix: cargo ecosystem. `setup` is a no-op for Rust projects
//! (no package.json) and cargo has no post-install hook, so the
//! with-setup cases are an EXPECTED BASELINE GAP.
//!
//! Run: `cargo test -p socket-patch-cli --features setup-e2e --test setup_matrix_cargo`
#![cfg(feature = "setup-e2e")]

#[path = "setup_matrix_common/mod.rs"]
mod smc;

#[test]
fn cargo() {
    smc::run_pm("cargo", "cargo");
}
