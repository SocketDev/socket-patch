//! The one vendored-mode backend: [`VendoredBackend`] with its three
//! operations, shared by every command that vendors, un-vendors or repairs.
//!
//! * [`VendoredBackend::apply`] — stage the patch content in memory, run
//!   the vendor engine ([`vendor_records_reusing`]), persist each ledger
//!   entry. `vendor`, `scan --mode vendored` (JSON and interactive arms)
//!   and `get --mode vendored` are its callers; they differ only in where
//!   the patch records come from (the manifest, or the download phase's
//!   in-memory records) and in their output shape.
//! * [`VendoredBackend::revert`] — revert ledger entries through the
//!   per-ecosystem backends (drift-keep, `--preserve-state` and dry-run
//!   classification in one place). `vendor --revert`, the manifest
//!   reconcile, `rollback`'s vendored leg and both of `remove`'s paths map
//!   its [`VendorRevertStep`]s onto their own event vocabulary.
//! * [`VendoredBackend::repair`] — health-check the ledger and re-vendor
//!   missing or corrupt artifacts through `apply`, so a repair downloads
//!   the patch service's prebuilt artifact exactly like the original
//!   `vendor` did (local build as the `--vendor-source auto` fallback).
//!   Lockfile references with no ledger entry are reported, never
//!   re-synthesized (see [`repair`]).
//!
//! The backends themselves (`dispatch_vendor_one`, `dispatch_revert_one*`)
//! stay in `vendor.rs`; this module is the policy layer over them.

pub(crate) mod repair;

use std::collections::HashMap;
use std::path::Path;

use socket_patch_core::manifest::schema::{PatchManifest, PatchRecord};
use socket_patch_core::vendor::{
    save_state, RevertOpts, VendorServiceConfig, VendorState, VendorWarning,
};

use crate::args::GlobalArgs;
use crate::commands::fetch_stage::{
    drop_unstageable, stage_vendor_sources_in_memory, MemStageOutcome,
};
use crate::commands::vendor::{dispatch_revert_one_opts, vendor_records_reusing};
use crate::ecosystem_dispatch::NpmCrawlSnapshot;
use crate::json_envelope::Envelope;

/// The vendored-mode backend for one run: the run's global args and its
/// patch-service config (`None` = build-only; `--revert` never needs one).
pub(crate) struct VendoredBackend<'a> {
    pub(crate) common: &'a GlobalArgs,
    pub(crate) service: Option<&'a VendorServiceConfig>,
}

/// What [`VendoredBackend::apply`] vendors.
pub(crate) struct ApplyRequest<'a> {
    /// The patch records to vendor, keyed by (manifest-spelled) purl. A
    /// manifest VIEW: staging probes blobs by the records' hashes.
    pub(crate) manifest: &'a PatchManifest,
    /// The `.socket/` dir whose committed blobs/diffs/packages staging
    /// reads in place.
    pub(crate) socket_dir: &'a Path,
    /// The vendor ledger, loaded ONCE by the caller under its apply lock:
    /// the staging harvest reads it, then the engine takes it over for its
    /// persists. An unreadable one is the engine's loud report.
    pub(crate) ledger: std::io::Result<VendorState>,
    /// Blob content the caller already holds (the download phase's), so
    /// the stager fetches no view twice.
    pub(crate) seed: HashMap<String, Vec<u8>>,
    /// `true` for manifest-free vendoring (`scan`/`get --mode vendored`,
    /// and repair of an entry with no manifest owner).
    pub(crate) detached: bool,
    /// `vendor --force`.
    pub(crate) force: bool,
    /// The npm half of a crawl this process already made over an untouched
    /// tree (see [`vendor_records_reusing`]).
    pub(crate) prior: Option<&'a NpmCrawlSnapshot>,
}

/// Staging obtained no patch content at all (offline, or every view fetch
/// failed): nothing reached the engine. Callers report it as
/// `no_local_source` in their own output shape.
#[derive(Debug)]
pub(crate) struct NoLocalSource;

/// The contract message of [`NoLocalSource`].
pub(crate) const NO_LOCAL_SOURCE_MESSAGE: &str =
    "patch artifacts unavailable (offline or download failure)";

impl<'a> VendoredBackend<'a> {
    pub(crate) fn new(common: &'a GlobalArgs, service: Option<&'a VendorServiceConfig>) -> Self {
        Self { common, service }
    }

    /// Vendor `req.manifest`'s records. The caller holds the apply lock.
    ///
    /// Patch content is staged IN MEMORY (committed `.socket` artifacts read
    /// in place, the rest fetched per patch over the service config's API
    /// client) — vendoring never writes blobs. A record whose content could
    /// not be obtained is reported per package (`no_local_source`) and left
    /// out; the rest still vendors. `Ok(has_errors)` otherwise.
    ///
    /// The engine future is boxed here — this is its transient frame, so no
    /// caller's poll frame embeds it (Windows' 1 MiB main-thread stack; see
    /// `scan_run_fits_windows_main_thread_stack`).
    pub(crate) async fn apply(
        &self,
        req: ApplyRequest<'_>,
        env: &mut Envelope,
    ) -> Result<bool, NoLocalSource> {
        let common = self.common;
        let staged = match stage_vendor_sources_in_memory(
            common,
            req.manifest,
            req.socket_dir,
            &common.cwd,
            req.ledger.as_ref().map(|s| &s.entries),
            req.seed,
            self.service.and_then(|s| s.client.as_ref()),
        )
        .await
        {
            MemStageOutcome::Ready(s) => s,
            MemStageOutcome::Unavailable => return Err(NoLocalSource),
        };
        let sources = staged.as_patch_sources();
        let (records, staging_errors) =
            drop_unstageable(env, &req.manifest.patches, staged.unavailable());
        let engine_errors = Box::pin(vendor_records_reusing(
            common,
            &records,
            &sources,
            req.detached,
            req.force,
            env,
            self.service,
            req.ledger,
            req.prior,
        ))
        .await;
        Ok(staging_errors || engine_errors)
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
