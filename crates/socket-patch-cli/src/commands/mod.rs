pub mod apply;
pub(crate) mod bun_preflight;
pub(crate) mod context;
pub(crate) mod fetch_stage;
pub mod get;
pub mod hosted_bundle;
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
    socket_patch_core::vex::discover_patched_refs_with(root, &discover_options(common)).await
}

/// [`discover_wiring`] of the snapshot's root, reading through `snapshot`.
pub(crate) async fn discover_wiring_in(
    common: &crate::args::GlobalArgs,
    snapshot: &socket_patch_core::vendor::lock_inventory::DiskSnapshot<'_>,
) -> socket_patch_core::vex::discover::Discovery {
    socket_patch_core::vex::discover_patched_refs_in(snapshot, &discover_options(common)).await
}

fn discover_options(common: &crate::args::GlobalArgs) -> socket_patch_core::vex::DiscoverOptions {
    socket_patch_core::vex::DiscoverOptions {
        patch_server_origins: common
            .patch_server_url
            .iter()
            .filter(|url| !url.trim().is_empty())
            .cloned()
            .collect(),
    }
}

/// Read-only lenient view of a loaded hosted redirect ledger: missing → `None`
/// (a fresh start); malformed → `None` with the corruption surfaced on
/// stderr unless `silent`. This is the "read-only consumers may degrade a
/// malformed ledger to nothing-to-consult, but must surface it" posture
/// from `load_redirect_state`'s contract — the warning is advisory
/// (muted by `--silent`, "errors only"), because every path that would
/// WRITE or ATTEST from the ledger hard-errors on the same corruption
/// instead. Used by scan's empty-discovery `redirectState` consult; the
/// main-path consult inlines the same posture so it can flush telemetry
/// before the warning.
pub(crate) fn redirect_state_lenient(
    loaded: &Result<
        Option<socket_patch_core::patch::redirect::RedirectState>,
        socket_patch_core::patch::redirect::CorruptRedirectState,
    >,
    silent: bool,
) -> Option<&socket_patch_core::patch::redirect::RedirectState> {
    match loaded {
        Ok(state) => state.as_ref(),
        Err(corrupt) => {
            if !silent {
                eprintln!("Warning: {corrupt}");
            }
            None
        }
    }
}

/// Read-only lenient view of a loaded vendor ledger (`.socket/vendor/state.json`):
/// missing → an empty ledger; malformed/unreadable → `None` with the
/// problem surfaced on stderr unless `silent`. The vendor twin of
/// [`redirect_state_lenient`], with the same posture: a read-only
/// consumer (`list`) degrades a broken ledger to nothing-to-consult but
/// must say so, while every path that writes or attests from it fails
/// closed instead.
pub(crate) fn vendor_state_lenient(
    loaded: &std::io::Result<socket_patch_core::vendor::state::VendorState>,
    silent: bool,
) -> Option<&socket_patch_core::vendor::state::VendorState> {
    match loaded {
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

/// Fold the vendor ledger's embedded records into a manifest view.
/// Vendored mode is manifest-free (every `scan`/`get --mode vendored` entry
/// carries `detached: true` plus its embedded patch `record`), so the
/// ledger is the only copy of those records: verification (`setup --check`,
/// property 4) must see them exactly like manifest entries. Folds exactly
/// the entries the shared owner rule
/// ([`socket_patch_core::ledgers::Ledgers::owned`]) gives the vendor ledger
/// — keyed by the ledger key; an entry the manifest claims (its key or base
/// purl) stays behind the manifest's record. Record-less legacy entries
/// never fold.
pub(crate) fn fold_vendor_records(
    manifest: &mut socket_patch_core::manifest::schema::PatchManifest,
    vendor: &socket_patch_core::vendor::VendorState,
) {
    let ledgers = socket_patch_core::ledgers::Ledgers {
        manifest: Some(&*manifest),
        vendor: Some(vendor),
        redirect: None,
    };
    let folded: Vec<(String, socket_patch_core::manifest::schema::PatchRecord)> = ledgers
        .owned()
        .into_iter()
        .filter(|o| o.store == socket_patch_core::ledgers::Store::Vendored)
        .filter_map(|o| Some((o.key.to_string(), o.record?.clone())))
        .collect();
    manifest.patches.extend(folded);
}

#[cfg(test)]
mod vendor_record_fold_tests {
    use std::collections::HashMap;

    use socket_patch_core::manifest::schema::{PatchManifest, PatchRecord};
    use socket_patch_core::vendor::VendorEntry;

    use super::fold_vendor_records;

    fn record(uuid: &str) -> PatchRecord {
        serde_json::from_value(serde_json::json!({
            "uuid": uuid,
            "exportedAt": "2026-01-01T00:00:00Z",
            "files": { "package/index.js": { "beforeHash": "b", "afterHash": "a" } },
            "vulnerabilities": {},
            "description": "fixture",
            "license": "MIT",
            "tier": "free",
        }))
        .expect("record fixture deserializes")
    }

    fn entry(base_purl: &str, uuid: &str, detached: bool, embedded: bool) -> VendorEntry {
        serde_json::from_value(serde_json::json!({
            "ecosystem": "npm",
            "basePurl": base_purl,
            "uuid": uuid,
            "artifact": { "path": format!(".socket/vendor/npm/{uuid}/pkg.tgz") },
            "wiring": [],
            "detached": detached,
            "record": embedded.then(|| record(uuid)),
        }))
        .expect("vendor entry fixture deserializes")
    }

    /// `setup --check`'s fold follows the shared owner rule: an entry folds
    /// only when the manifest covers neither its key nor its base purl, and
    /// a record-less legacy entry never folds.
    #[test]
    fn standalone_vendor_fallback_folds_only_when_uncovered() {
        let mut entries = HashMap::new();
        entries.insert(
            "pkg:npm/owned@1.0.0".to_string(),
            entry("pkg:npm/owned@1.0.0", "u-stale", false, true),
        );
        entries.insert(
            "pkg:npm/owned@1.0.0?variant=x".to_string(),
            entry("pkg:npm/owned@1.0.0", "u-variant", false, true),
        );
        entries.insert(
            "pkg:npm/dropped@1.0.0".to_string(),
            entry("pkg:npm/dropped@1.0.0", "u-dropped", false, true),
        );
        entries.insert(
            "pkg:npm/detached@1.0.0".to_string(),
            entry("pkg:npm/detached@1.0.0", "u-detached", true, true),
        );
        entries.insert(
            "pkg:npm/legacy@1.0.0".to_string(),
            entry("pkg:npm/legacy@1.0.0", "u-legacy", false, false),
        );

        let entries = socket_patch_core::vendor::VendorState {
            entries,
            ..socket_patch_core::vendor::VendorState::new()
        };
        let mut manifest = PatchManifest::default();
        manifest
            .patches
            .insert("pkg:npm/owned@1.0.0".to_string(), record("u-manifest"));
        fold_vendor_records(&mut manifest, &entries);
        let mut folded: Vec<(&str, &str)> = manifest
            .patches
            .iter()
            .map(|(k, r)| (k.as_str(), r.uuid.as_str()))
            .collect();
        folded.sort();
        assert_eq!(
            folded,
            vec![
                ("pkg:npm/detached@1.0.0", "u-detached"),
                ("pkg:npm/dropped@1.0.0", "u-dropped"),
                ("pkg:npm/owned@1.0.0", "u-manifest"),
            ],
            "a newer manifest uuid keeps winning; covered and record-less entries stay out"
        );

        // No manifest records at all: every embedded copy folds.
        let mut empty = PatchManifest::default();
        fold_vendor_records(&mut empty, &entries);
        assert_eq!(empty.patches.len(), 4, "{:?}", empty.patches.keys());
        assert_eq!(empty.patches["pkg:npm/owned@1.0.0"].uuid, "u-stale");
    }
}
