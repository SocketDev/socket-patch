//! setup-matrix: npm ecosystem (npm / yarn / pnpm / bun).
//!
//! These are the ecosystems `socket-patch setup` actually supports
//! today (it writes a package.json postinstall hook), so the
//! `baseline_with_setup` / `alt_content_patchset` cases are expected to
//! PASS here. See `setup_matrix_common/mod.rs` for the harness and
//! `tests/setup_matrix/matrix.json` for the case list.
//!
//! Run: `cargo test -p socket-patch-cli --features setup-e2e --test setup_matrix_npm`
#![cfg(feature = "setup-e2e")]

#[path = "setup_matrix_common/mod.rs"]
mod smc;

#[test]
fn npm() {
    smc::run_pm("npm", "npm");
}

#[test]
fn yarn() {
    smc::run_pm("npm", "yarn");
}

#[test]
fn pnpm() {
    smc::run_pm("npm", "pnpm");
}

#[test]
fn bun() {
    smc::run_pm("npm", "bun");
}
