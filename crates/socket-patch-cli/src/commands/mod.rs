pub mod apply;
pub(crate) mod bun_preflight;
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

/// The documented name of the mode whose ledger is
/// `.socket/vendor/state.json` — `list`'s label for a vendored patch
/// record. Vendored mode is manifest-free: every `scan`/`get --mode
/// vendored` entry is written `detached: true` with its embedded patch
/// `record`, so the ledger is the only place those records live.
pub(crate) const VENDORED_MODE_LABEL: &str = "vendored";

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

/// Read-only lenient load of the vendor ledger (`.socket/vendor/state.json`):
/// missing → an empty ledger; malformed/unreadable → `None` with the
/// problem surfaced on stderr unless `silent`. The vendor twin of
/// [`load_redirect_state_lenient`], with the same posture: a read-only
/// consumer (`list`) degrades a broken ledger to nothing-to-consult but
/// must say so, while every path that writes or attests from it fails
/// closed instead.
pub(crate) async fn load_vendor_state_lenient(
    root: &Path,
    silent: bool,
) -> Option<socket_patch_core::vendor::state::VendorState> {
    match socket_patch_core::vendor::load_state(root).await {
        Ok(state) => Some(state),
        Err(e) => {
            if !silent {
                eprintln!(
                    "Warning: unreadable vendor ledger ({e}); its vendored patches are not listed"
                );
            }
            None
        }
    }
}

/// Fold the vendor ledger's DETACHED entries into a manifest view. Vendored
/// mode is manifest-free (every `scan`/`get --mode vendored` entry carries
/// `detached: true` plus its embedded patch `record`), so the ledger is the
/// only copy of those records: verification (`setup --check`, property 4)
/// and attestation (`vex`) must see them exactly like manifest entries.
/// Keyed by the ledger key; an existing manifest entry wins a collision
/// (that purl is manifest-owned and verifies against the manifest's
/// record). Entries without an embedded record (legacy manifest-tracked
/// vendoring) contribute nothing — their record IS the manifest's.
pub(crate) fn fold_detached_records(
    manifest: &mut socket_patch_core::manifest::schema::PatchManifest,
    entries: &std::collections::HashMap<String, socket_patch_core::vendor::VendorEntry>,
) {
    for (key, entry) in entries {
        if !entry.detached {
            continue;
        }
        let Some(record) = &entry.record else { continue };
        if !manifest.patches.contains_key(key) {
            manifest.patches.insert(key.clone(), record.clone());
        }
    }
}
