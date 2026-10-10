//! `get`: batch paths, edge cases, invariants, modes, nested apply flags, update summaries and global packages.
//!
//! One test binary per command: each module was its own binary.

#[path = "../common/mod.rs"]
mod common;
#[path = "../npm_e2e_common/manifestless.rs"]
mod npm_e2e_common;
#[path = "../vex_e2e_common/mod.rs"]
mod vex_e2e_common;
use common::cache_env;

mod cli_get_silent_errors;
mod coverage_fix_get_double_json;
mod get_batch_paths_e2e;
mod get_edge_cases_e2e;
mod get_envelope_shape;
mod get_invariants;
mod get_modes_e2e;
mod get_nested_apply_api_flags_e2e;
mod get_update_summary_e2e;
mod global_packages_e2e;
