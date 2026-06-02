//! setup-matrix: pypi ecosystem (pip / uv / poetry / pdm / hatch).
//!
//! Python installers have no native post-install hook and `socket-patch
//! setup` is a no-op for them, so the `baseline_with_setup` /
//! `alt_content_patchset` cases are EXPECTED to fail here (BASELINE
//! GAP). The negative-control / empty / wrong-target cases should pass.
//!
//! Run: `cargo test -p socket-patch-cli --features setup-e2e --test setup_matrix_pypi`
#![cfg(feature = "setup-e2e")]

#[path = "setup_matrix_common/mod.rs"]
mod smc;

#[test]
fn pip() {
    smc::run_pm("pypi", "pip");
}

#[test]
fn uv() {
    smc::run_pm("pypi", "uv");
}

#[test]
fn poetry() {
    smc::run_pm("pypi", "poetry");
}

#[test]
fn pdm() {
    smc::run_pm("pypi", "pdm");
}

#[test]
fn hatch() {
    smc::run_pm("pypi", "hatch");
}

// ── Nested-workspace layouts (EXPECTED BASELINE GAP) ──────────────────
// uv workspace (root + members, one shared .venv) and a pip
// nested-requirements monorepo. Python has no post-install hook, so
// these don't apply today — but the install itself must succeed.

#[test]
fn pip_workspace() {
    smc::run_workspace_pm("pypi", "pip");
}

#[test]
fn uv_workspace() {
    smc::run_workspace_pm("pypi", "uv");
}
