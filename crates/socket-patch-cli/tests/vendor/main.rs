//! `vendor`: lockfile-only gems, pristine fetch order, no-network re-runs, bun and the hosted redirects.
//!
//! One test binary per command: each module was its own binary.

#[path = "../common/rollback_json.rs"]
mod rollback_json;

#[path = "../vex_e2e_common/bun.rs"]
mod bun_vex;
#[path = "../common/mod.rs"]
mod common;
#[path = "../docker_vendor_common/mod.rs"]
mod docker_vendor_common;

mod docker_vendor_common_selftest;
mod e2e_golang_redirect;
mod in_process_vendor_bun;
mod redirect_npm_allow_remote;
mod vendor_gem_lockfile_only_e2e;
mod vendor_rerun_no_network_e2e;

#[path = "../prebuilt_common/mod.rs"]
mod prebuilt_common;
