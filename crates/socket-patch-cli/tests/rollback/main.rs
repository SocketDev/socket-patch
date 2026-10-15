//! `rollback`: invariants, duality with remove, silent mode, the multi-copy
//! blob gate, the `--json` failure paths and their human render checks,
//! and `--ecosystems`-scoped hosted rollback.
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

mod cli_rollback_silent;
mod rollback_duality_invariants;
mod rollback_ecosystem_scoped_hosted;
mod rollback_failure_paths;
mod rollback_fixture;
mod rollback_invariants;
mod rollback_multicopy_blob_gate;
mod rollback_render;
