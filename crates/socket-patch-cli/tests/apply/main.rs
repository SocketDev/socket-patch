//! `apply`: invariants, network behavior, silent/exit modes and the gem and npm multi-copy apply paths.
//!
//! One test binary per command: each module was its own binary.

#[path = "../common/mod.rs"]
mod common;
#[path = "../common/rollback_json.rs"]
mod rollback_json;
#[path = "../vlt_hosted_common/mod.rs"]
mod vlt_hosted_common;
#[path = "../vlt_hosted_common/vendored.rs"]
mod vlt_vendored;

mod apply_invariants;
mod apply_network;
mod bun_global_store;
mod check_verifies_installed_tree;
mod cli_gem_variant_mismatch_policy;
mod covgap_commands_apply;
mod e2e_safety_advisories;
mod gem_stale_bundler_plugin;
mod in_process_gem_config_warning;
mod in_process_gem_fallback_home;
mod in_process_gem_multicopy;
mod in_process_npm_multicopy;
mod in_process_variant_apply_failure;
mod lockfile_only_skip;
mod pnpm_global_virtual_store;
