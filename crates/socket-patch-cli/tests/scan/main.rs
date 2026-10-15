//! `scan`: batching, ecosystem scope, ordering, paths, sync, hosted refusals,
//! the scan and hosted `--json` failure paths and their human render checks,
//! the hosted dry run over a vendored project,
//! scan on a real terminal, and the vendor flow.
//!
//! One test binary per command: each module was its own binary.

#[path = "../common/mod.rs"]
mod common;
#[path = "../prebuilt_common/mod.rs"]
mod prebuilt_common;
#[path = "../common/pty_io.rs"]
mod pty_io;
#[path = "../common/rollback_json.rs"]
mod rollback_json;
#[path = "../vlt_hosted_common/mod.rs"]
mod vlt_hosted_common;
#[path = "../vlt_hosted_common/vendored.rs"]
mod vlt_vendored;

mod coverage_fix_scan_discovery_corrupt_ledger;
mod covgap_commands_fetch_stage;
mod covgap_commands_scan_vendor_flow;
mod covgap_ecosystem_dispatch;
mod hosted_dryrun_vendored;
mod hosted_failure_paths;
mod hosted_fixture;
mod hosted_management_refusals;
mod hosted_render;
mod hosted_symlinked_files;
mod hosted_wheel_metadata_order;
mod hosted_yarn_berry_manifest;
mod hosted_yarn_classic_sha1;
mod scan_batch_sizing_e2e;
mod scan_ecosystems_scope_e2e;
mod scan_failure_paths;
mod scan_fixture;
mod scan_invariants;
mod scan_nested_project_e2e;
mod scan_ordered_concurrency_e2e;
mod scan_paths_e2e;
mod scan_render;
mod scan_sync_e2e;
#[cfg(unix)]
mod scan_tty;
mod scan_vendor_step_error_e2e;
