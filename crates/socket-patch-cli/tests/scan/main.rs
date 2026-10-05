//! `scan`: batching, ecosystem scope, ordering, paths, sync, hosted refusals and the vendor flow.
//!
//! One test binary per command: each module was its own binary.

#[path = "../common/mod.rs"]
mod common;
#[path = "../vlt_hosted_common/mod.rs"]
mod vlt_hosted_common;
#[path = "../vlt_hosted_common/vendored.rs"]
mod vlt_vendored;

mod coverage_fix_scan_discovery_corrupt_ledger;
mod covgap_commands_fetch_stage;
mod covgap_commands_scan_vendor_flow;
mod covgap_ecosystem_dispatch;
mod hosted_management_refusals;
mod hosted_symlinked_files;
mod hosted_wheel_metadata_order;
mod hosted_yarn_berry_manifest;
mod scan_batch_sizing_e2e;
mod scan_ecosystems_scope_e2e;
mod scan_invariants;
mod scan_ordered_concurrency_e2e;
mod scan_paths_e2e;
mod scan_sync_e2e;
mod scan_vendor_step_error_e2e;
