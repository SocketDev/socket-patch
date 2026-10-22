//! `remove`: invariants, duality with rollback, and network behavior.
//!
//! One test binary per command: each module was its own binary.

#[path = "../common/mod.rs"]
mod common;
#[path = "../common/pty_io.rs"]
mod pty_io;
#[path = "../common/rollback_json.rs"]
mod rollback_json;
#[path = "../vlt_hosted_common/mod.rs"]
mod vlt_hosted_common;
#[path = "../vlt_hosted_common/vendored.rs"]
mod vlt_vendored;

mod pypi_name_spellings;
mod remove_duality_invariants;
mod remove_failure_paths;
mod remove_fixture;
mod remove_invariants;
mod remove_network;
mod remove_render;
