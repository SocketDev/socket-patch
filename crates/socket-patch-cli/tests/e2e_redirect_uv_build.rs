#![cfg(unix)]
//! Real-uv capstones for HOSTED mode (`scan --redirect`), ending in
//! manifest-less VEX — the hermetic twin of the production
//! `e2e_hosted_production::pypi_uv_lock_hosted_install_proof` leg, for every
//! uv lock shape:
//!
//! * `uv.lock` + `pyproject.toml`, the patched package a direct dependency;
//! * the same with the package also in `[tool.uv] constraint-dependencies`
//!   (the lock's `[manifest] constraints` entry is repointed too; `uv sync
//!   --locked` accepts it only from uv 0.5.6);
//! * the same with the package only TRANSITIVE (`python-dateutil` → `six`),
//!   wired through `[tool.uv] override-dependencies` + `[tool.uv.sources]` —
//!   the uv 0.5.6 boundary (older uv re-resolves the override against the
//!   registry on a plain `uv sync`, and VEX must stop attesting);
//! * a PEP 723 script lock (`uv lock --script`), installed by `uv run
//!   --frozen --script` into uv's own env — so VEX attests it from the lock's
//!   sha256 pin, the not-installed hosted basis;
//! * `pylock.toml` from `uv export --format pylock.toml`, `uv pip compile -o
//!   pylock.toml` and `pip lock`, installed by `uv pip sync`.
//!
//! Each lane: real uv builds and installs the pristine project from PyPI →
//! `scan --redirect --vex` against a wiremock patch API (which also serves
//! the patched wheel at its hosted url) → a fresh checkout of ONLY the
//! committable files installs with uv from an EMPTY cache, fetching the
//! wheel from the mock and checking its pin, and imports the patched bytes →
//! manifest-less VEX: attested with/without ledgers, `record_unavailable`
//! offline with zero requests, embedded `apply --vex` / `scan --redirect
//! --vex`, NOT attested once the wiring is reverted (ledgers left behind,
//! `--no-verify` too) → `rollback` restores the files byte for byte. The
//! driver is `vex_e2e_common/uv.rs`.
//!
//! uv release: `SOCKET_PATCH_UV_E2E_BIN` / `_VERSION` / `_PYTHON` /
//! `_REQUIRED` (see the driver's docs); `scripts/uv-vex-matrix.sh` runs every
//! uv 0.N line. `#[ignore]`d: network installs from PyPI; run with
//! `--ignored` (CI: the `e2e` matrix uv legs).

#[path = "common/cache_env.rs"]
mod cache_env;
#[path = "vex_e2e_common/uv.rs"]
mod uv_vex;
#[path = "vex_e2e_common/mod.rs"]
mod vex_e2e_common;

use uv_vex::{Lane, Mode};

const SUITE: &str = "e2e_redirect_uv_build";

fn hosted(lane: Lane) {
    match uv_vex::uv_under_test() {
        Ok(uv) => uv_vex::run_lane(SUITE, &uv, Mode::Hosted, lane),
        Err(why) => uv_vex::skip(SUITE, &why),
    }
}

#[test]
#[ignore = "real uv + PyPI; run with --ignored"]
fn hosted_uv_project_manifestless_vex() {
    hosted(Lane::Project);
}

#[test]
#[ignore = "real uv + PyPI; run with --ignored"]
fn hosted_uv_constraints_manifestless_vex() {
    hosted(Lane::Constraints);
}

#[test]
#[ignore = "real uv + PyPI; run with --ignored"]
fn hosted_uv_transitive_override_manifestless_vex() {
    hosted(Lane::Transitive);
}

#[test]
#[ignore = "real uv + PyPI; run with --ignored"]
fn hosted_uv_script_lock_manifestless_vex() {
    hosted(Lane::Script);
}

#[test]
#[ignore = "real uv + PyPI; run with --ignored"]
fn hosted_uv_export_pylock_manifestless_vex() {
    hosted(Lane::ExportPylock);
}

#[test]
#[ignore = "real uv + PyPI; run with --ignored"]
fn hosted_uv_pip_compile_pylock_manifestless_vex() {
    hosted(Lane::CompilePylock);
}

#[test]
#[ignore = "real uv + pip + PyPI; run with --ignored"]
fn hosted_pip_lock_pylock_manifestless_vex() {
    hosted(Lane::PipLock);
}
