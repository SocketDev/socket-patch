//! The one vendored-mode backend: [`VendoredBackend`] with its three
//! operations, shared by every command that vendors, un-vendors or repairs.
//!
//! * [`VendoredBackend::apply`] downloads verified server artifacts and
//!   persists their wiring and ledger entries through `vendor_records_reusing`.
//! * [`VendoredBackend::revert`] restores the recorded project wiring.
//! * [`VendoredBackend::repair`] redownloads missing or corrupt artifacts,
//!   preserving their recorded identities, lockfiles and ledger.
//!
//! The backends themselves (`dispatch_vendor_one`, `dispatch_revert_one*`)
//! stay in `vendor.rs`; this module is the policy layer over them.

pub(crate) mod repair;

use std::collections::HashMap;
use std::path::Path;

use socket_patch_core::manifest::schema::{PatchManifest, PatchRecord};
use socket_patch_core::utils::group_commit::CommittedFile;
use socket_patch_core::vendor::{
    save_state, RevertOpts, VendorServiceConfig, VendorState, VendorWarning,
};

use crate::args::GlobalArgs;
use crate::commands::vendor::{dispatch_revert_one_opts, vendor_records_reusing};
use crate::ecosystem_dispatch::NpmCrawlSnapshot;
use crate::json_envelope::Envelope;

/// The vendored-mode backend for one run: the run's global args and its
/// patch-service config (`--revert` does not need one).
pub(crate) struct VendoredBackend<'a> {
    pub(crate) common: &'a GlobalArgs,
    pub(crate) service: Option<&'a VendorServiceConfig>,
}

/// What [`VendoredBackend::apply`] vendors.
pub(crate) struct ApplyRequest<'a> {
    /// Patch records keyed by manifest purl.
    pub(crate) manifest: &'a PatchManifest,
    pub(crate) socket_dir: &'a Path,
    /// Loaded once by the caller under the apply lock.
    pub(crate) ledger: std::io::Result<VendorState>,
    /// `true` for manifest-free vendoring (`scan`/`get --mode vendored`,
    /// and repair of an entry with no manifest owner).
    pub(crate) detached: bool,
    /// `vendor --force`.
    pub(crate) force: bool,
    /// The npm half of a crawl this process already made over an untouched
    /// tree (see [`vendor_records_reusing`]).
    pub(crate) prior: Option<&'a NpmCrawlSnapshot>,
    /// Receives every project file the run's group commit wrote, with the
    /// bytes it held before (the eject's rollback undoes exactly these).
    pub(crate) committed: Option<&'a mut Vec<CommittedFile>>,
}

impl<'a> VendoredBackend<'a> {
    pub(crate) fn new(common: &'a GlobalArgs, service: Option<&'a VendorServiceConfig>) -> Self {
        Self { common, service }
    }

    /// Vendor `req.manifest`'s records. The caller holds the apply lock.
    ///
    /// Each package fails closed if its server artifact is unavailable.
    /// Returns whether any package failed.
    ///
    /// The engine future is boxed here — this is its transient frame, so no
    /// caller's poll frame embeds it (Windows' 1 MiB main-thread stack; see
    /// `scan_run_fits_windows_main_thread_stack`).
    pub(crate) async fn apply(&self, req: ApplyRequest<'_>, env: &mut Envelope) -> bool {
        let common = self.common;
        let blobs = req.socket_dir.join("blobs");
        let sources = socket_patch_core::patch::apply::PatchSources {
            blobs_path: &blobs,
            diffs_path: None,
            mem_blobs: None,
        };
        let records = &req.manifest.patches;
        Box::pin(vendor_records_reusing(
            common,
            records,
            &sources,
            req.detached,
            req.force,
            env,
            self.service,
            req.ledger,
            req.prior,
            req.committed,
        ))
        .await
    }

    /// Revert the ledger entries `keys` (in order) with `opts`, mutating
    /// `state` and saving the ledger per reverted entry (crash-consistent).
    /// Silent: callers own the human lines and the event vocabulary. With
    /// `stop_on_failure` the loop ends after the first hard failure (a
    /// backend refusal or a ledger write failure), which is the last
    /// element returned — `remove` aborts there without touching the rest.
    pub(crate) async fn revert(
        &self,
        keys: &[String],
        state: &mut VendorState,
        opts: RevertOpts,
        stop_on_failure: bool,
    ) -> Vec<RevertedEntry> {
        let mut out = Vec::with_capacity(keys.len());
        for key in keys {
            // Captured before a clean revert drops the entry.
            let flavor = state.entries.get(key).and_then(|e| e.flavor.clone());
            let result = revert_vendor_entry(&self.common.cwd, key, state, opts).await;
            let hard_failure = matches!(
                result.step,
                VendorRevertStep::Failed(_) | VendorRevertStep::LedgerWriteFailed(_)
            );
            out.push(RevertedEntry {
                key: key.clone(),
                flavor,
                warnings: result.warnings,
                step: result.step,
            });
            if stop_on_failure && hard_failure {
                break;
            }
        }
        out
    }
}

/// One entry [`VendoredBackend::revert`] handled.
pub(crate) struct RevertedEntry {
    /// The ledger key.
    pub(crate) key: String,
    /// The entry's npm-family lockfile flavor, read before the revert (for
    /// the reinstall hints).
    pub(crate) flavor: Option<String>,
    /// The backend's advisories.
    pub(crate) warnings: Vec<VendorWarning>,
    pub(crate) step: VendorRevertStep,
}

/// What one vendored ledger entry's revert did. The drift-keep and
/// `--preserve-state` rules are identical for every caller by construction.
pub(crate) enum VendorRevertStep {
    /// `key` has no ledger entry (a divergent ledger, or an earlier leg
    /// already reverted it): a silent no-op.
    Missing,
    /// The backend refused; nothing changed for this entry.
    Failed(String),
    /// Drift-keep: the lock changed under us and the backend left both the
    /// wiring and the artifact alone. Per `RevertOutcome`'s contract the
    /// ledger entry — and any manifest record — must survive.
    Kept,
    /// Dry run: the revert (or, with `keep_artifact`, the unwire) would
    /// succeed. Nothing changed.
    WouldRevert,
    /// `keep_artifact`: wiring restored; artifact and ledger entry kept
    /// byte-identical. Its wiring records now describe already-reverted
    /// fragments, which later reverts replay as silent no-ops (the
    /// liveness contract), and a re-vendor re-wires from the live lock.
    Preserved,
    /// Reverted on disk, dropped from the ledger, ledger saved (per entry,
    /// so the run is crash-consistent like `vendor --revert`).
    Reverted,
    /// Reverted on disk and dropped from the in-memory ledger, but the
    /// ledger write failed.
    LedgerWriteFailed(String),
}

pub(crate) struct VendorRevertResult {
    pub(crate) warnings: Vec<VendorWarning>,
    pub(crate) step: VendorRevertStep,
}

/// Revert the vendored ledger entry `key` (see [`VendorRevertStep`]).
pub(crate) async fn revert_vendor_entry(
    cwd: &Path,
    key: &str,
    state: &mut VendorState,
    opts: RevertOpts,
) -> VendorRevertResult {
    let Some(entry) = state.entries.get(key).cloned() else {
        return VendorRevertResult {
            warnings: Vec::new(),
            step: VendorRevertStep::Missing,
        };
    };
    let outcome = dispatch_revert_one_opts(&entry, cwd, opts).await;
    let step = if !outcome.success {
        VendorRevertStep::Failed(outcome.error.unwrap_or_else(|| "unknown error".into()))
    } else if outcome.kept_artifact {
        VendorRevertStep::Kept
    } else if opts.dry_run {
        VendorRevertStep::WouldRevert
    } else if opts.keep_artifact {
        VendorRevertStep::Preserved
    } else {
        state.entries.remove(key);
        match save_state(cwd, state).await {
            Ok(()) => VendorRevertStep::Reverted,
            Err(e) => VendorRevertStep::LedgerWriteFailed(e.to_string()),
        }
    };
    VendorRevertResult {
        warnings: outcome.warnings,
        step,
    }
}

/// A patch-record map as the manifest view [`ApplyRequest::manifest`]
/// takes (no `setup` block — vendoring never reads it).
pub(crate) fn records_manifest(patches: HashMap<String, PatchRecord>) -> PatchManifest {
    PatchManifest {
        patches,
        setup: None,
    }
}
