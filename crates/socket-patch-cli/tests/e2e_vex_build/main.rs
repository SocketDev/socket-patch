//! Manifest-less VEX — the real-package-manager capstones that have no
//! standalone build suite of their own: one module per tool (`deno`,
//! `hatch`, `pdm`, `pip`, `pipenv`, `poetry`). Each drives a pinned release
//! of the real tool (hosted and vendored installs, or deno's negative case)
//! and finishes in manifest-less `socket-patch vex`. Every test is
//! `#[ignore]`d (real tools + a public registry); the Python modules are
//! unix-only.
//!
//! ONE integration-test binary on purpose: every file under `tests/` is its
//! own optimized link in CI's `test-release` job. CI's `e2e` matrix (and
//! `pdm-compatibility.yml`) selects one tool per leg with a module filter,
//! e.g. `cargo test -p socket-patch-cli --test e2e_vex_build -- pdm::
//! --ignored`.
//!
//! The hermetic twins of these suites are the same-named modules of
//! `tests/e2e_vex_lockfile/`.

#[path = "../vex_e2e_common/mod.rs"]
mod vex_e2e_common;
#[cfg(unix)]
#[path = "../vex_pipenv_pip_real/mod.rs"]
mod vex_pipenv_pip_real;
#[cfg(unix)]
#[path = "../vex_pipenv_pip_steps/mod.rs"]
mod vex_pipenv_pip_steps;
#[cfg(unix)]
#[path = "../vex_pypi_real_common/mod.rs"]
mod vex_pypi_real_common;

mod deno;
#[cfg(unix)]
mod hatch;
#[cfg(unix)]
mod pdm;
#[cfg(unix)]
mod pip;
#[cfg(unix)]
mod pipenv;
#[cfg(unix)]
mod poetry;
