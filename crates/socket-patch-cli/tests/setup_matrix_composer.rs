//! setup-matrix: composer ecosystem (PHP). Composer DOES expose a
//! `post-install-cmd` event hook, but `setup` does not wire it today,
//! so the with-setup cases are an EXPECTED BASELINE GAP — and a clear
//! candidate for the first non-npm ecosystem `setup` could support.
//!
//! Run: `cargo test -p socket-patch-cli --features setup-e2e --test setup_matrix_composer`
#![cfg(feature = "setup-e2e")]

#[path = "setup_matrix_common/mod.rs"]
mod smc;

#[test]
fn composer() {
    smc::run_pm("composer", "composer");
}
