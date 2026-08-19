pub mod apply;
pub(crate) mod fetch_stage;
pub mod get;
pub mod list;
pub(crate) mod lock_cli;
pub mod remove;
pub mod repair;
pub(crate) mod repair_vendor;
pub mod rollback;
pub mod scan;
pub mod setup;
pub mod update;
pub mod vendor;
pub mod vex;

use std::path::Path;

/// The documented name of the mode whose ledger is
/// `.socket/vendor/redirect-state.json`. Shared by scan's `redirectState`
/// envelope block and list's hosted event labels so the two surfaces can
/// never drift, and deliberately a CONSTANT rather than an echo of the
/// ledger's own `mode` string: that string is opaque to the loader
/// (pre-rename ledgers carry `"redirect"`), and a consumer dispatching on
/// these keys must not have to know that history.
pub(crate) const HOSTED_MODE_LABEL: &str = "hosted";

/// Read-only lenient load of the hosted redirect ledger: missing → `None`
/// (a fresh start); malformed → `None` with the corruption surfaced on
/// stderr unless `silent`. This is the "read-only consumers may degrade a
/// malformed ledger to nothing-to-consult, but must surface it" posture
/// from `load_redirect_state`'s contract — the warning is advisory
/// (muted by `--silent`, "errors only"), because every path that would
/// WRITE or ATTEST from the ledger hard-errors on the same corruption
/// instead. Shared by `list` and both of scan's read-only consults.
pub(crate) async fn load_redirect_state_lenient(
    cwd: &Path,
    silent: bool,
) -> Option<socket_patch_core::patch::redirect::RedirectState> {
    match socket_patch_core::patch::redirect::load_redirect_state(cwd).await {
        Ok(state) => state,
        Err(corrupt) => {
            if !silent {
                eprintln!("Warning: {corrupt}");
            }
            None
        }
    }
}
