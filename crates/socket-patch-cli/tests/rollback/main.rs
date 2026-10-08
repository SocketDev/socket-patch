//! `rollback`: invariants, duality with remove, silent mode and the multi-copy blob gate.
//!
//! One test binary per command: each module was its own binary.

#[path = "../common/mod.rs"]
mod common;
#[path = "../vlt_hosted_common/mod.rs"]
mod vlt_hosted_common;
#[path = "../vlt_hosted_common/vendored.rs"]
mod vlt_vendored;

mod cli_rollback_silent;
mod rollback_duality_invariants;
mod rollback_invariants;
mod rollback_multicopy_blob_gate;
