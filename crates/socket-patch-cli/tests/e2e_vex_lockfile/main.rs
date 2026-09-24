//! Manifest-less VEX — the hermetic suites, one module per package manager.
//!
//! `socket-patch vex` (and the embedded `apply` / `scan` / `vendor --vex`)
//! must attest hosted and vendored patches from the project's lockfiles and
//! package-manager configs alone — no `.socket/manifest.json`, and (unless a
//! cell says otherwise) no `.socket/vendor` ledgers — and must never attest a
//! patch the build does not consume. Every module here is hermetic: a
//! wiremock patch API, committed lock shapes, no package-manager toolchain,
//! no network, never `#[ignore]`d, and it runs in the default `test` job on
//! all three OSes. The real-package-manager capstones live in the gated
//! `e2e_*_build` suites.
//!
//! ONE integration-test binary on purpose: every file under `tests/` is its
//! own optimized link in CI's `test-release` job, so the per-PM suites share
//! this crate instead of adding a binary each. Run one PM with a module
//! filter, e.g. `cargo test -p socket-patch-cli --test e2e_vex_lockfile
//! golang::`.
//!
//! The shared steps and omission oracle live in `tests/vex_e2e_common/`
//! (with the PDM/Hatch and Pipenv/pip helpers beside it); `common_selftest`
//! tests those helpers themselves.

#[path = "../vex_e2e_common/mod.rs"]
mod vex_e2e_common;
#[path = "../vex_pdm_hatch_common/mod.rs"]
mod vex_pdm_hatch_common;
#[path = "../vex_pipenv_pip_common/mod.rs"]
mod vex_pipenv_pip_common;

mod bun;
mod cargo;
mod common_selftest;
mod composer;
mod deno;
mod gem;
mod golang;
mod hatch;
mod manifestless_embedded;
mod maven;
mod npm;
mod nuget;
mod pdm;
mod pip;
mod pipenv;
mod pnpm;
mod poetry;
mod uv;
mod yarn;
mod yarn_berry;
mod yarn_classic;
