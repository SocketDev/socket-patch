//! Global CLI behavior: API client errors, dry-run paths, output modes, prompts, telemetry and `list`.
//!
//! One test binary per command: each module was its own binary.

#[path = "../common/mod.rs"]
mod common;
#[path = "../common/pty_io.rs"]
mod pty_io;
#[path = "../vlt_hosted_common/mod.rs"]
mod vlt_hosted_common;
#[path = "../vlt_hosted_common/vendored.rs"]
mod vlt_vendored;

mod api_client_errors_e2e;
mod cli_dry_run_paths_e2e;
mod covgap_api_client;
mod covgap_commands_list;
mod covgap_output;
mod envelope_helper_copies;
mod interactive_prompts_e2e;
mod output_modes_e2e;
mod shared_helper_copies;
mod telemetry_e2e;
