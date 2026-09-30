//! `repair`: invariants and vendored-tree repair across flavors.
//!
//! One test binary per command: each module was its own binary.

#[path = "../common/mod.rs"]
mod common;
// `bun.rs` embeds its own copy of `vex_e2e_common`, which
// `repair_vendor_e2e` also loads directly.
#[allow(clippy::duplicate_mod)]
#[path = "../vex_e2e_common/bun.rs"]
mod bun_vex;
#[path = "../npm_e2e_common/manifestless.rs"]
mod npm_e2e_common;
#[path = "../vex_e2e_common/mod.rs"]
mod vex_e2e_common;
#[path = "../vlt_hosted_common/mod.rs"]
mod vlt_hosted_common;
#[path = "../vlt_hosted_common/vendored.rs"]
mod vlt_vendored;

mod coverage_fix_repair_vendor_predelete;
mod covgap_commands_repair;
mod covgap_commands_repair_vendor;
mod repair_invariants;
mod repair_vendor_e2e;
mod repair_vendor_flavors_e2e;

#[path = "../prebuilt_common/mod.rs"]
mod prebuilt_common;
