//! `remove`: invariants, duality with rollback, and network behavior.
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

mod covgap_commands_remove;
mod pypi_name_spellings;
mod remove_duality_invariants;
mod remove_invariants;
mod remove_network;
