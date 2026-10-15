//! `get`: batch paths, edge cases, invariants, modes, nested apply flags,
//! update summaries, global packages, and the `--json` failure paths and
//! their human render checks.
//!
//! One test binary per command: each module was its own binary.

#[path = "../common/mod.rs"]
mod common;
#[path = "../npm_e2e_common/manifestless.rs"]
mod npm_e2e_common;
#[path = "../prebuilt_common/mod.rs"]
mod prebuilt_common;
#[path = "../vex_e2e_common/mod.rs"]
mod vex_e2e_common;
#[path = "../vlt_hosted_common/mod.rs"]
mod vlt_hosted_common;
#[path = "../vlt_hosted_common/vendored.rs"]
mod vlt_vendored;
use common::cache_env;

mod cli_get_silent_errors;
mod get_batch_paths_e2e;
mod get_edge_cases_e2e;
mod get_envelope_shape;
mod get_failure_paths;
mod get_fixture;
mod get_invariants;
mod get_modes_e2e;
mod get_nested_apply_api_flags_e2e;
mod get_render;
mod get_single_json_document;
mod get_update_summary_e2e;
mod global_packages_e2e;
