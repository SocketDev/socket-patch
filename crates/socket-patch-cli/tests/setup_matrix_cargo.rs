//! setup-matrix: cargo ecosystem.
//!
//! This Docker-based matrix exercises the *install → apply → patched-file-on-disk*
//! flow. Cargo's local backend redirects to a project-local **copy** via
//! `[patch.crates-io]` rather than patching the installed crate in place, and
//! the patch is consumed at `cargo build` resolution time (by the
//! `socket-patch-guard` build script), so there is no in-place file mutation
//! for this harness to observe — the with-setup cases remain an EXPECTED
//! BASELINE GAP *here*. The real cargo `setup`/`apply`/`rollback`/`--check`
//! behaviour is covered by the dedicated, non-Docker suites:
//!   * `setup_cargo_roundtrip.rs` — setup → check → remove → check + user
//!     `build.rs` untouched;
//!   * `e2e_cargo_coexist.rs` — apply redirect + registry isolation, reconcile,
//!     rollback, self-heal, and `--check` drift detection.
//!
//! Run: `cargo test -p socket-patch-cli --features setup-e2e --test setup_matrix_cargo`
#![cfg(feature = "setup-e2e")]

#[path = "setup_matrix_common/mod.rs"]
mod smc;

#[test]
fn cargo() {
    smc::run_pm("cargo", "cargo");
}
