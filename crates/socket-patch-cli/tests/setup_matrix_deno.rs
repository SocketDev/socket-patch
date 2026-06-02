//! setup-matrix: deno ecosystem (deno install against a package.json,
//! npm-via-deno layout). `setup` DOES rewrite the package.json (deno
//! projects have one), but whether `deno install` runs the root
//! postinstall hook is uncertain — so the baseline records this as a
//! GAP. If it applies, the orchestrator flags it `progress`.
//!
//! Run: `cargo test -p socket-patch-cli --features setup-e2e --test setup_matrix_deno`
#![cfg(feature = "setup-e2e")]

#[path = "setup_matrix_common/mod.rs"]
mod smc;

#[test]
fn deno() {
    smc::run_pm("deno", "deno");
}
