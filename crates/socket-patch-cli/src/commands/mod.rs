pub mod apply;
pub(crate) mod bun_preflight;
pub(crate) mod fetch_stage;
pub mod get;
pub mod hosted_bundle;
pub mod list;
pub(crate) mod lock_cli;
pub mod remove;
pub mod repair;
pub(crate) mod vendored_backend;
pub mod rollback;
pub mod scan;
pub mod update;
pub mod vendor;
pub mod vex;
pub(crate) mod vex_consumed;
pub(crate) mod vex_sources;
pub(crate) mod vlt_preflight;

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

/// Lockfile discovery of `root` (core `vex::discover`): the hosted and
/// vendored patch references its lockfiles and configs wire, with hosted
/// references counted on Socket's public patch server plus the operator's
/// `--patch-server-url` / `SOCKET_PATCH_SERVER_URL` origin. The one input to
/// every ledger-liveness verdict ([`Discovery::redirect_record_live`] /
/// [`Discovery::vendor_entry_live`]): `vex`'s attestation gates and `scan`'s
/// cross-mode takeover and hosted-wiring advisories read the lockfiles the
/// same way.
///
/// [`Discovery::redirect_record_live`]: socket_patch_core::vex::discover::Discovery::redirect_record_live
/// [`Discovery::vendor_entry_live`]: socket_patch_core::vex::discover::Discovery::vendor_entry_live
pub(crate) async fn discover_wiring(
    common: &crate::args::GlobalArgs,
    root: &Path,
) -> socket_patch_core::vex::discover::Discovery {
    let opts = socket_patch_core::vex::DiscoverOptions {
        patch_server_origins: common
            .patch_server_url
            .iter()
            .filter(|url| !url.trim().is_empty())
            .cloned()
            .collect(),
    };
    socket_patch_core::vex::discover_patched_refs_with(root, &opts).await
}

/// Read-only lenient load of the hosted redirect ledger: missing → `None`
/// (a fresh start); malformed → `None` with the corruption surfaced on
/// stderr unless `silent`. This is the "read-only consumers may degrade a
/// malformed ledger to nothing-to-consult, but must surface it" posture
/// from `load_redirect_state`'s contract — the warning is advisory
/// (muted by `--silent`, "errors only"), because every path that would
/// WRITE or ATTEST from the ledger hard-errors on the same corruption
/// instead. Used by scan's empty-discovery `redirectState` consult; the
/// main-path consult inlines the same posture so it can flush telemetry
/// before the warning.
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

/// Whether a vendor-ledger entry's embedded `record` stands on its own —
/// the rule every reader of embedded records shares (`vex`'s record plan
/// and `list`), so one
/// tree never lists "no patches" while its VEX document attests one.
///
/// A `detached` entry (every `scan`/`get --mode vendored` entry) has no
/// manifest owner: its record is the only copy. A non-detached entry was
/// written by the manifest-driven standalone `vendor`, which embeds the
/// record as a fallback copy: the manifest record stays authoritative while
/// the manifest covers the entry — its ledger key, or its base purl (the
/// claim `vex_sources`' candidate builder applies) — and the embedded copy
/// stands in only when it does not (a checkout that never committed its
/// manifest, or one that dropped the purl while the lockfile still wires
/// the artifact). `repair` deliberately stays narrower (the copy is used
/// only with no manifest at all): it rebuilds artifacts, and a purl dropped
/// from a live manifest is the reconcile's to revert, not repair's to heal.
pub(crate) fn vendor_record_is_unowned(
    key: &str,
    entry: &socket_patch_core::vendor::VendorEntry,
    manifest: Option<&socket_patch_core::manifest::schema::PatchManifest>,
) -> bool {
    entry.detached
        || manifest.is_none_or(|m| {
            !m.patches.contains_key(key) && !m.patches.contains_key(&entry.base_purl)
        })
}
