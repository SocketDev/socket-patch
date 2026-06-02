//! setup-matrix: pypi ecosystem (pip / uv / poetry / pdm / hatch).
//!
//! Python installers have no native post-install hook, so `socket-patch
//! setup` instead commits a `socket-patch-hook` dependency whose wheel ships
//! a startup `.pth` that re-applies patches after install
//! (package-manager-agnostic). pip, uv and hatch are wired + verified in
//! Docker: their `baseline_with_setup` / `alt_content_patchset` cases APPLY
//! (the harness builds the hook wheel and the driver installs it + fires an
//! interpreter). poetry / pdm are resolver-based — their `add`/`install`/`run`
//! re-resolve the whole manifest (now incl. the committed `socket-patch-hook`)
//! against a package index, which the hermetic test can't provide, so they
//! remain BASELINE GAPs (the mechanism is PM-agnostic and proven by the
//! others). Nested-workspace layouts are also still gaps. The negative-control
//! / empty / wrong-target cases must NOT apply for any of them.
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
