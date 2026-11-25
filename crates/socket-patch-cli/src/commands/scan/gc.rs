//! The GC pass for `scan --prune`/`--sync`: manifest-entry pruning plus
//! orphan blob/diff/package-archive sweeps, in both mutating (apply) and
//! read-only (preview) forms.

use socket_patch_core::manifest::cleanup_blobs::{ArtifactReferences, CleanupResult};
use socket_patch_core::manifest::operations::{manifest_exists, read_manifest, write_manifest};
use socket_patch_core::manifest::schema::PatchManifest;
use socket_patch_core::patch::apply_lock::LockGuard;
use socket_patch_core::utils::purl_key::PurlKey;
use socket_patch_core::vendor::{purl_keys_cover, VENDOR_STATE_REL};
use std::collections::HashSet;
use std::path::Path;
use std::time::Duration;

use crate::args::GlobalArgs;
use crate::commands::lock_cli::{acquire_with_status, lock_failure};
use crate::commands::vendor::{run_vendor_gc, VendorGcSummary};
use crate::commands::vendored_backend::KeepCause;
use crate::json_envelope::{Envelope, GcReport, PatchAction, PatchEvent};
use crate::ui::{plural, sweep_failure};

/// Aggregated outcome of a GC pass (or preview), recorded into the `scan
/// --json` envelope by [`GcSummary::record_into`]. See CLI_CONTRACT.md for
/// the stable schema.
#[derive(Debug, Default)]
pub(super) struct GcSummary {
    /// PURLs removed from the manifest (apply mode) or eligible to be
    /// removed (preview mode).
    pruned: Vec<String>,
    blobs: CleanupResult,
    diffs: CleanupResult,
    packages: CleanupResult,
    /// Vendored entries reverted (or revertable, preview mode) because
    /// their patch is gone from the manifest or their dependency left the
    /// lockfile graph. Sorted.
    vendored_reverted: Vec<String>,
    /// Vendored entries the wet pass kept, each with why: a revert was
    /// due, but the lock entries drifted since vendoring (everything was
    /// retained), or the recorded wiring was restored while another project
    /// file still installs from the artifact (the artifact and the entries
    /// were retained). Sorted. Always empty in preview mode (which runs no
    /// revert), where such entries show in `vendored_reverted`.
    vendored_kept: Vec<(String, KeepCause)>,
    /// Vendored entries whose wet revert failed, each with the backend's
    /// reason: the ledger entry and the artifacts were kept. Sorted.
    /// Always empty in preview mode.
    vendored_failed: Vec<(String, String)>,
    /// Orphan `.socket/vendor/<eco>/<uuid>` dirs swept (or sweepable).
    vendor_orphan_dirs: usize,
    /// Set when a wet pass could not take the apply lock and so skipped
    /// its whole mutating half (`lock_held` or `lock_io`). Never set in
    /// preview mode.
    skipped: Option<(&'static str, String)>,
    /// A post-revert ledger rewrite that failed (`vendor_state_write_failed`:
    /// the reverts already happened on disk, so the stale record is
    /// reported, not the pass failed), a manifest prune that could not be
    /// written (`manifest_write_failed`: nothing was pruned or swept), and
    /// orphan sweeps that could not finish (`cleanup_failed`: the removed
    /// counts above are what it did reclaim). Also the vendored reverts'
    /// reinstall advisories, the `vendor_revert_residual_reference` of an
    /// entry kept for one, `manifest_invalid` / `manifest_unreadable` when
    /// the manifest half could not load the manifest,
    /// `vendor_state_unreadable` when the vendored half could not load the
    /// ledger, and `vendor_orphan_still_wired` per orphan vendor dir kept
    /// because a project file still installs from it.
    warnings: Vec<(&'static str, String)>,
    /// The entries of hosted mode's pnpm registry route that no lockfile
    /// uses any more, taken out (or, in preview mode, to take out) of
    /// pnpm-workspace.yaml and the pnpm locks. `None` when the project
    /// holds nothing of a route, so that half did not run.
    registry: Option<Vec<socket_patch_core::hosted::guidance::RegistryEntry>>,
}

impl GcSummary {
    fn total_bytes(&self) -> u64 {
        self.blobs.bytes_freed + self.diffs.bytes_freed + self.packages.bytes_freed
    }

    /// A summary carrying only the vendored-state half — the shape every
    /// early return takes when the manifest half cannot run.
    fn vendor_only(v: VendorGcSummary) -> Self {
        let mut gc = GcSummary::default();
        gc.absorb_vendor_gc(v);
        gc
    }

    /// The vendored half alone, for a pass whose manifest exists but could
    /// not be loaded: the manifest half did not run, and the load error
    /// (`manifest_invalid` / `manifest_unreadable`) joins `warnings`
    /// instead of the pass reading as "no manifest, nothing to prune".
    fn manifest_unloadable(v: VendorGcSummary, manifest_path: &Path, e: &std::io::Error) -> Self {
        let mut gc = GcSummary::vendor_only(v);
        gc.warnings.push((
            crate::json_envelope::manifest_load_error_code(e),
            crate::ui::manifest_error_message(manifest_path, e),
        ));
        gc
    }

    /// Carry what taking the pass's lock did about an interrupted run's
    /// commit (see `lock_cli::commit_recovery_warning`) into the envelope.
    /// The acquire printed it on stderr, so a human run, which prints
    /// `warnings`, is given nothing to repeat.
    fn note_commit_recovery(&mut self, common: &GlobalArgs, guard: &LockGuard) {
        if common.json {
            self.warnings.extend(
                guard
                    .commit_recovery()
                    .map(|recovery| (recovery.code, recovery.detail.clone())),
            );
        }
    }

    /// Run the registry-route half (see `commands::registry_gc`) when the
    /// project holds something of a route: from the lockfiles alone, so it
    /// is safe whatever the crawl found. A wet pass runs under the pass's
    /// apply lock. `route` is the pass's one answer to whether the project
    /// holds any.
    async fn sweep_registry(
        &mut self,
        common: &GlobalArgs,
        preview: bool,
        route: &mut crate::commands::registry_gc::RouteProbe,
    ) {
        if !route.present(common).await {
            return;
        }
        let swept = crate::commands::registry_gc::sweep(common, preview).await;
        self.warnings.extend(swept.warnings);
        self.registry = Some(swept.entries);
    }

    /// Fold a vendored-state GC pass into this summary: purl lists sorted,
    /// its failed post-revert rewrites join `warnings`.
    fn absorb_vendor_gc(&mut self, v: VendorGcSummary) {
        self.vendored_reverted = v
            .dropped_reverted
            .into_iter()
            .chain(v.unused_reverted)
            .collect();
        self.vendored_reverted.sort();
        self.vendored_kept = v.kept;
        self.vendored_kept.sort_by(|a, b| a.0.cmp(&b.0));
        self.vendored_failed = v.failed;
        self.vendored_failed.sort();
        self.warnings.extend(v.unreconciled);
        self.warnings.extend(v.write_failures);
        self.warnings.extend(v.advisories);
        self.vendor_orphan_dirs = v.orphan_dirs;
    }

    /// Record the pass into a `scan` envelope. The artifact sweep is the
    /// envelope's `gc` (the shared [`GcReport`], counts of what a preview
    /// would remove), each pruned manifest entry a `removed` event
    /// (`verified` on a preview) with `details.manifest: true`, each
    /// reverted vendored entry a `removed` (`verified`) event with
    /// `errorCode: "vendor_reverted"` and `details.mode: "vendored"`, each
    /// kept entry a `skipped` / `vendor_revert_kept` event whose reason is
    /// the keep's cause, and each entry whose revert failed a `skipped` /
    /// `vendor_revert_failed` event whose reason carries the backend's (a
    /// GC revert failure never fails the run, so it is not a `failed`
    /// event). The orphan `.socket/vendor/<eco>/<uuid>` dirs swept are
    /// counted in the top-level `removedVendorOrphanDirs`, each entry of a
    /// pnpm registry route the pass took out is an artifact-level `removed`
    /// (`verified`) event counted in `gc.removedRegistryEntries`, and the
    /// pass's warnings join the top-level `warnings`. A pass that could not run
    /// (lock held, lock I/O) records only a `gc_skipped` warning and no
    /// `gc`.
    pub(super) fn record_into(&self, env: &mut Envelope, preview: bool) {
        if let Some((code, message)) = &self.skipped {
            env.warn(GC_SKIPPED, format!("{message} ({code})"));
            return;
        }
        let removal = if preview {
            PatchAction::Verified
        } else {
            PatchAction::Removed
        };
        for purl in &self.pruned {
            env.record(
                PatchEvent::new(removal, purl.as_str())
                    .with_details(serde_json::json!({ "manifest": true })),
            );
        }
        let vendored = || serde_json::json!({ "mode": "vendored" });
        for purl in &self.vendored_reverted {
            env.record(
                PatchEvent::new(removal, purl.as_str())
                    .with_reason(
                        "vendor_reverted",
                        "vendored entry reverted by the prune GC (its patch left the \
                         manifest or its dependency left the lockfile)",
                    )
                    .with_details(vendored()),
            );
        }
        for (purl, cause) in &self.vendored_kept {
            let detail = match cause {
                KeepCause::Drift => "lock entries were re-resolved since vendoring, so the \
                                     artifact and the manifest/ledger entries were retained"
                    .to_string(),
                KeepCause::Reference => format!(
                    "{}; the artifact and the manifest/ledger entries were retained — {}",
                    cause.reason(),
                    cause.remedy(PRUNE_AGAIN)
                ),
            };
            env.record(
                PatchEvent::new(PatchAction::Skipped, purl.as_str())
                    .with_reason("vendor_revert_kept", detail)
                    .with_details(vendored()),
            );
        }
        for (purl, why) in &self.vendored_failed {
            env.record(
                PatchEvent::new(PatchAction::Skipped, purl.as_str())
                    .with_reason(
                        "vendor_revert_failed",
                        format!(
                            "the prune GC could not revert this vendored entry ({why}); its \
                             ledger entry and artifacts were kept"
                        ),
                    )
                    .with_details(vendored()),
            );
        }
        let registry = self.registry.as_deref().unwrap_or_default();
        crate::commands::registry_gc::record(env, registry, preview);
        env.set_gc(GcReport {
            removed_registry_entries: registry.len(),
            ..GcReport::from_passes(Some(&self.blobs), Some(&self.diffs), Some(&self.packages))
        });
        env.set_extra(
            "removedVendorOrphanDirs",
            serde_json::json!(self.vendor_orphan_dirs),
        );
        for (code, detail) in &self.warnings {
            env.warn(*code, detail.clone());
        }
    }
}

/// What finishes a revert the pass kept for a residual reference, once the
/// file named by its warning is fixed ([`KeepCause::remedy`]).
const PRUNE_AGAIN: &str = "re-run `scan --prune`";

/// Warning code: a requested GC pass could not run (another run holds the
/// apply lock, or the lock file could not be opened); nothing was swept.
pub(super) const GC_SKIPPED: &str = "gc_skipped";

/// The orphan blob/diff/package sweep against the (post-prune) manifest.
/// A pass that failed outright counts as empty; that failure (or a wet
/// pass's unremovable orphans) rides `warnings` as `cleanup_failed` so the
/// output never reads as a clean all-zero sweep.
async fn run_gc(
    manifest: &PatchManifest,
    pruned: Vec<String>,
    socket_dir: &Path,
    dry_run: bool,
) -> GcSummary {
    let sweep = ArtifactReferences::active(manifest)
        .sweep(socket_dir, dry_run)
        .await;
    let mut warnings = Vec::new();
    let mut take = |label: &str, pass: std::io::Result<CleanupResult>| {
        if let Some(detail) = sweep_failure(label, &pass) {
            warnings.push(("cleanup_failed", detail));
        }
        pass.unwrap_or_default()
    };
    let blobs = take("blob", sweep.blobs);
    let diffs = take("diffs", sweep.diffs);
    let packages = take("packages", sweep.packages);
    GcSummary {
        pruned,
        blobs,
        diffs,
        packages,
        warnings,
        ..Default::default()
    }
}

/// Apply-mode GC, under ONE apply-lock window: the vendored-state GC
/// (reverts manifest-dropped and lockfile-unused vendored entries, dropping
/// the latter's manifest records), then — when a manifest exists — prune
/// manifest entries for PURLs not in `scanned_purls`, write the manifest
/// back, and sweep orphan blob/diff/package files, so the sweep reclaims
/// the blobs the vendored half just orphaned in the same pass. Callers
/// gate on the `prune` flag.
pub(super) async fn run_apply_gc(
    common: &GlobalArgs,
    manifest_path: &Path,
    socket_dir: &Path,
    scanned_purls: &HashSet<String>,
    vendored: &HashSet<PurlKey>,
) -> GcSummary {
    // Existence gate BEFORE the lock: `acquire` creates `.socket/`, and a
    // pristine checkout with neither a manifest nor vendored state must not
    // gain one. A manifest that cannot be stated is not absent: the pass goes
    // on and reports it, as the locked read's load error or, when
    // `.socket/` itself is unusable, as the lock failure.
    let has_manifest = manifest_exists(manifest_path).await.unwrap_or(true);
    let mut route = crate::commands::registry_gc::RouteProbe::default();
    if !has_manifest && !has_vendored_state(common).await && !route.present(common).await {
        return GcSummary::default();
    }

    // One acquire for every half: flock is per open file description, so
    // a nested acquire in the vendored half would read as a live holder.
    let guard = match lock(common, socket_dir) {
        Ok(g) => g,
        Err(skipped) => return *skipped,
    };
    let mut gc = apply_gc_locked(common, manifest_path, socket_dir, scanned_purls, vendored).await;
    gc.sweep_registry(common, false, &mut route).await;
    gc.note_commit_recovery(common, &guard);
    gc
}

/// [`run_apply_gc`] under the lock its caller holds.
async fn apply_gc_locked(
    common: &GlobalArgs,
    manifest_path: &Path,
    socket_dir: &Path,
    scanned_purls: &HashSet<String>,
    vendored: &HashSet<PurlKey>,
) -> GcSummary {
    let vendor_gc = run_vendor_gc(common, manifest_path, /*dry_run=*/ false).await;

    // Missing or unreadable ⇒ nothing to prune, and the blob sweep has no
    // referenced set to work from.
    let mut manifest = match read_manifest(manifest_path).await {
        Ok(Some(m)) => m,
        Ok(None) => return GcSummary::vendor_only(vendor_gc),
        Err(e) => return GcSummary::manifest_unloadable(vendor_gc, manifest_path, &e),
    };
    let mut prunable = detect_prunable(&manifest, scanned_purls, vendored);
    keep_project_entries(common, &mut prunable).await;
    let mut kept = keep_patched_cargo_copies(common, &manifest, socket_dir, &mut prunable).await;
    kept.extend(keep_patched_pypi_copies(common, &manifest, socket_dir, &mut prunable).await);
    for purl in &prunable {
        manifest.patches.remove(purl);
    }
    if !prunable.is_empty() {
        if let Err(e) = write_manifest(manifest_path, &manifest).await {
            // The manifest on disk still names every entry, so nothing was
            // pruned and every blob is still referenced: no sweep.
            let mut gc = GcSummary::vendor_only(vendor_gc);
            gc.warnings.extend(kept);
            gc.warnings.push((
                "manifest_write_failed",
                format!(
                    "could not prune {}: updating {} failed ({e}); nothing was removed",
                    plural(prunable.len(), "manifest entry", "manifest entries"),
                    manifest_path.display()
                ),
            ));
            return gc;
        }
    }
    let mut gc = run_gc(&manifest, prunable, socket_dir, /*dry_run=*/ false).await;
    gc.absorb_vendor_gc(vendor_gc);
    gc.warnings.extend(kept);
    gc
}

/// Under global scope, drop from `prunable` every entry the `--cwd` project
/// still accounts for.
///
/// Both scopes share one manifest, and a global run crawls only the global
/// installs. Against that crawl alone every record of the project reads as
/// uninstalled, and pruning it deletes the blobs the project's `apply` and
/// `rollback` need. What the project accounts for is what its own `--prune`
/// judges against: its installed packages and the ones only its lockfiles
/// list (its vendored entries are exempt already).
async fn keep_project_entries(common: &GlobalArgs, prunable: &mut Vec<String>) {
    if !common.is_global() || prunable.is_empty() {
        return;
    }
    let project = GlobalArgs {
        global: false,
        global_prefix: None,
        ..common.clone()
    };
    // Every package installed where the project installs, not only the
    // ones a Python project with no environment of its own declares: a
    // record for an undeclared one (`get <name>`) is the project's too.
    let (installed, _, _) =
        crate::ecosystem_dispatch::crawl_ecosystems_for_name(&project.crawler_options(), None)
            .await;
    let ctx = crate::commands::context::ProjectContext::new(&project);
    let locked = &ctx.locks().await.entries;
    let accounted: HashSet<PurlKey> = installed
        .iter()
        .map(|pkg| PurlKey::new(&pkg.purl))
        .chain(locked.iter().map(|entry| PurlKey::new(&entry.purl)))
        .collect();
    prunable.retain(|purl| !accounted.contains(&PurlKey::new(purl)));
}

/// Whether the manifest's project may hold vendored state: the ledger's
/// directory, `.socket/vendor/`, which holds the artifacts too (a lost
/// ledger leaves them, and the pass reports the ones still installed
/// from). Checked before the lock, whose acquire would create `.socket/`.
/// Only a directory known to be missing is "nothing vendored": one that
/// cannot be stat'd goes on to the read that reports it, like the manifest
/// above.
async fn has_vendored_state(common: &GlobalArgs) -> bool {
    let ledger = common.project_root().join(VENDOR_STATE_REL);
    let dir = ledger.parent().expect("the ledger has a directory");
    !matches!(tokio::fs::try_exists(dir).await, Ok(false))
}

/// Take the apply lock for a wet pass. Both halves are read-modify-writes
/// the lock serializes everywhere else; unlocked, a stale read would
/// clobber a live holder's write and the sweep would delete its fresh
/// blobs. Contention or a lock I/O fault skips the pass: `Err` is the
/// summary recording why.
fn lock(common: &GlobalArgs, socket_dir: &Path) -> Result<LockGuard, Box<GcSummary>> {
    let timeout = Duration::from_secs(common.lock_timeout.unwrap_or(0));
    acquire_with_status(socket_dir, timeout, common.dry_run).map_err(|e| {
        Box::new(GcSummary {
            skipped: Some(lock_failure(&e, timeout)),
            ..Default::default()
        })
    })
}

/// Drop from `prunable` every Cargo entry whose agent-mode patch is still
/// on disk in a copy the crawl no longer reports: the project crawl is
/// scoped to the crates `Cargo.lock` resolves, but a crate bumped or
/// dropped from the lock keeps its patched copy in the machine-wide
/// `$CARGO_HOME/registry/src` cache, which nothing deletes. Its manifest
/// record holds the only before-blobs that can restore that copy, so it is
/// kept, with one `cargo_cache_patch_kept` warning per entry naming the
/// `rollback` that restores the copy and then drops the record.
async fn keep_patched_cargo_copies(
    common: &GlobalArgs,
    manifest: &PatchManifest,
    socket_dir: &Path,
    prunable: &mut Vec<String>,
) -> Vec<(&'static str, String)> {
    let kept = crate::ecosystem_dispatch::cargo_copies_still_patched(
        manifest,
        prunable.iter(),
        &common.crawler_options(),
        &socket_dir.join("blobs"),
        true,
    )
    .await;
    prunable.retain(|p| !kept.contains(p));
    kept.into_iter()
        .map(|purl| {
            let word = crate::ui::shell_word(&purl);
            (
                "cargo_cache_patch_kept",
                format!(
                    "kept {purl}: the project no longer resolves it, but its copy in the \
                     shared Cargo registry cache is still patched (or could not be \
                     read to tell); run `socket-patch rollback {word}` (with `--global` \
                     when a `cargo vendor` dir hides the registry cache) to restore \
                     that copy and drop the entry"
                ),
            )
        })
        .collect()
}

/// Drop from `prunable` every PyPI entry whose agent-mode patch is still
/// on disk in a copy the crawl does not report: a project with no
/// environment of its own is crawled for the packages it declares, in the
/// one interpreter it installs into, but a package it stopped declaring,
/// or one an earlier release patched in another interpreter or a tool's
/// environment, keeps its patched copy. The manifest record holds the only
/// before-blobs that can restore that copy, so it is kept, with one
/// `pypi_installed_patch_kept` warning per entry naming the `rollback` that
/// restores the copy and then drops the record.
async fn keep_patched_pypi_copies(
    common: &GlobalArgs,
    manifest: &PatchManifest,
    socket_dir: &Path,
    prunable: &mut Vec<String>,
) -> Vec<(&'static str, String)> {
    let kept = crate::ecosystem_dispatch::pypi_copies_still_patched(
        manifest,
        prunable.iter(),
        &common.crawler_options(),
        &socket_dir.join("blobs"),
    )
    .await;
    prunable.retain(|p| !kept.contains(p));
    kept.into_iter()
        .map(|purl| {
            let word = crate::ui::shell_word(&purl);
            (
                "pypi_installed_patch_kept",
                format!(
                    "kept {purl}: the scan no longer reports it as one of the project's \
                     packages, but an installed copy is still patched (or could not be \
                     read to tell); run `socket-patch rollback {word}` (with `--global` \
                     when the copy is in another interpreter or a tool's environment) \
                     to restore that copy and drop the entry"
                ),
            )
        })
        .collect()
}

/// The `pypi_installed_patch_kept` warnings of a `--prune` whose crawl
/// found nothing. The manifest half of the GC is skipped there, so no
/// record is dropped, but a recorded PyPI patch can still be on disk in a
/// copy the scan no longer reaches (another interpreter, a tool's
/// environment), and this warning is what names the `rollback` that
/// restores it. Read-only: no lock, nothing written.
pub(super) async fn kept_pypi_patch_warnings(
    common: &GlobalArgs,
    manifest_path: &Path,
    socket_dir: &Path,
) -> Vec<(&'static str, String)> {
    let Ok(Some(manifest)) = read_manifest(manifest_path).await else {
        return Vec::new();
    };
    let mut recorded: Vec<String> = manifest.patches.keys().cloned().collect();
    recorded.sort();
    keep_patched_pypi_copies(common, &manifest, socket_dir, &mut recorded).await
}

/// The vendored-state half of the GC alone, for a `--prune` whose crawl
/// found nothing (the manifest half is skipped there: pruning against an
/// empty crawl would drop every entry). Reverting entries whose patch left
/// the manifest or whose dependency left the lock asks the manifest and
/// the lockfile, not the crawl, so it stays safe. Wet passes take the
/// apply lock like [`run_apply_gc`]; `--dry-run` previews.
pub(super) async fn run_vendor_only_gc(
    common: &GlobalArgs,
    manifest_path: &Path,
    socket_dir: &Path,
) -> GcSummary {
    let mut route = crate::commands::registry_gc::RouteProbe::default();
    if common.dry_run {
        let mut gc = GcSummary::vendor_only(run_vendor_gc(common, manifest_path, true).await);
        gc.sweep_registry(common, true, &mut route).await;
        return gc;
    }
    if !has_vendored_state(common).await && !route.present(common).await {
        return GcSummary::default();
    }
    let guard = match lock(common, socket_dir) {
        Ok(g) => g,
        Err(skipped) => return *skipped,
    };
    let mut gc = GcSummary::vendor_only(run_vendor_gc(common, manifest_path, false).await);
    gc.sweep_registry(common, false, &mut route).await;
    gc.note_commit_recovery(common, &guard);
    gc
}

/// The registry-route half of the GC alone (see `commands::registry_gc`),
/// for a hosted scan whose crawl found nothing: the hosted rewrite, which
/// takes the unused entries out on every other run, does not run there.
/// `None` when the project holds nothing of a route. A wet pass takes the
/// apply lock like [`run_apply_gc`]; `--dry-run` previews.
pub(super) async fn run_registry_only_gc(
    common: &GlobalArgs,
    socket_dir: &Path,
    hosted: bool,
) -> Option<GcSummary> {
    let mut route = crate::commands::registry_gc::RouteProbe::default();
    if !route.present(common).await {
        return None;
    }
    let mut gc = GcSummary::default();
    // A hosted scan writes nothing for a root pnpm lock that a Bazel hub
    // would fail on a pin in, whatever it was granted: it takes nothing
    // of a route out there either, and says what it says with a patch.
    if hosted {
        let root = common.project_root();
        let view = socket_patch_core::vendor::lock_inventory::ProjectView::Disk(&root);
        let hidden = socket_patch_core::hosted::engine::pnpm_root_lock_left_to_bazel(&view);
        if let Some(hidden) = hidden.await {
            gc.warnings
                .push((socket_patch_core::bazel::pnpm::HIDDEN, hidden.detail));
            return Some(gc);
        }
    }
    if common.dry_run {
        gc.sweep_registry(common, true, &mut route).await;
        return Some(gc);
    }
    let guard = match lock(common, socket_dir) {
        Ok(g) => g,
        Err(skipped) => return Some(*skipped),
    };
    gc.sweep_registry(common, false, &mut route).await;
    gc.note_commit_recovery(common, &guard);
    Some(gc)
}

/// Dry-run preview of the apply-mode GC pass. Same summary as
/// [`run_apply_gc`] (what the pass would remove), with no mutation.
async fn preview_apply_gc(
    common: &GlobalArgs,
    manifest_path: &Path,
    socket_dir: &Path,
    scanned_purls: &HashSet<String>,
    vendored: &HashSet<PurlKey>,
) -> GcSummary {
    let mut gc =
        preview_artifact_gc(common, manifest_path, socket_dir, scanned_purls, vendored).await;
    let mut route = crate::commands::registry_gc::RouteProbe::default();
    gc.sweep_registry(common, true, &mut route).await;
    gc
}

/// The manifest, artifact and vendored halves of [`preview_apply_gc`].
async fn preview_artifact_gc(
    common: &GlobalArgs,
    manifest_path: &Path,
    socket_dir: &Path,
    scanned_purls: &HashSet<String>,
    vendored: &HashSet<PurlKey>,
) -> GcSummary {
    let vendor_gc = run_vendor_gc(common, manifest_path, /*dry_run=*/ true).await;

    let mut manifest = match read_manifest(manifest_path).await {
        Ok(Some(m)) => m,
        Ok(None) => return GcSummary::vendor_only(vendor_gc),
        Err(e) => return GcSummary::manifest_unloadable(vendor_gc, manifest_path, &e),
    };
    // Mirror the wet pass, which drops an unused vendored entry's manifest
    // keys before the blob sweep, or the preview under-reports orphans.
    // The dry pass reverted nothing, so the ledger still holds each entry
    // (its base purl is part of the relation: a `!x`-encoded golang key).
    if !vendor_gc.unused_reverted.is_empty() {
        if let Ok(state) = socket_patch_core::vendor::load_state(&common.project_root()).await {
            for purl in &vendor_gc.unused_reverted {
                let Some(entry) = state.entries.get(purl) else {
                    continue;
                };
                for k in crate::commands::vendor::unused_vendored_manifest_keys(
                    &manifest.patches,
                    purl,
                    entry,
                ) {
                    manifest.patches.remove(&k);
                }
            }
        }
    }
    let mut prunable = detect_prunable(&manifest, scanned_purls, vendored);
    keep_project_entries(common, &mut prunable).await;
    let _ = keep_patched_cargo_copies(common, &manifest, socket_dir, &mut prunable).await;
    let _ = keep_patched_pypi_copies(common, &manifest, socket_dir, &mut prunable).await;
    // The sweep derives the referenced set from this in-memory manifest.
    for purl in &prunable {
        manifest.patches.remove(purl);
    }
    let mut gc = run_gc(&manifest, prunable, socket_dir, /*dry_run=*/ true).await;
    gc.absorb_vendor_gc(vendor_gc);
    gc
}

/// The GC for the JSON paths, recorded into `env` (see
/// [`GcSummary::record_into`]): a read-only preview under `--dry-run`, the
/// mutating pass otherwise.
pub(super) async fn gc_into(
    common: &GlobalArgs,
    manifest_path: &Path,
    socket_dir: &Path,
    scanned_purls: &HashSet<String>,
    vendored: &HashSet<PurlKey>,
    dry_run: bool,
    env: &mut Envelope,
) {
    let gc = if dry_run {
        preview_apply_gc(common, manifest_path, socket_dir, scanned_purls, vendored).await
    } else {
        run_apply_gc(common, manifest_path, socket_dir, scanned_purls, vendored).await
    };
    gc.record_into(env, dry_run);
}

/// The main human GC line for a pass that pruned or swept something
/// (`None` when it did nothing). `preview`: the `--dry-run` wording.
pub(super) fn format_gc_line(gc: &GcSummary, preview: bool) -> Option<String> {
    let files = gc.blobs.blobs_removed + gc.diffs.blobs_removed + gc.packages.blobs_removed;
    if gc.pruned.is_empty() && files == 0 {
        return None;
    }
    let entries = plural(gc.pruned.len(), "manifest entry", "manifest entries");
    let files_s = plural(files, "orphan file", "orphan files");
    let bytes = socket_patch_core::manifest::cleanup_blobs::format_bytes(gc.total_bytes());
    Some(if preview {
        format!("[dry-run] GC would prune {entries} and remove {files_s} ({bytes}).")
    } else {
        format!("GC: pruned {entries} and removed {files_s} ({bytes}).")
    })
}

/// Human-readable lines for the vendored-state half of a GC pass, plus
/// the lock-skip reason and warnings, in order; empty when there is
/// nothing to report.
pub(super) fn format_gc_vendored_lines(gc: &GcSummary) -> Vec<String> {
    let mut lines = Vec::new();
    if let Some((_, message)) = &gc.skipped {
        lines.push(format!("GC: skipped: {message}."));
    }
    for (_, detail) in &gc.warnings {
        lines.push(format!("GC: {detail}."));
    }
    if !gc.vendored_reverted.is_empty() || gc.vendor_orphan_dirs > 0 {
        lines.push(format!(
            "GC: reverted {}; swept {}.",
            plural(
                gc.vendored_reverted.len(),
                "vendored entry",
                "vendored entries"
            ),
            plural(
                gc.vendor_orphan_dirs,
                "orphan vendor dir",
                "orphan vendor dirs"
            ),
        ));
    }
    // Drift-keeps are the one GC outcome that silently contradicts the
    // `--dry-run` preview (which cannot see drift and lists the entry as
    // revertable), so they always earn the same remediation hint every
    // other drift-keep caller prints.
    let kept = |cause: KeepCause| gc.vendored_kept.iter().filter(|(_, c)| *c == cause).count();
    let drifted = kept(KeepCause::Drift);
    if drifted > 0 {
        lines.push(format!(
            "GC: kept {}: lock entries were re-resolved since vendoring, so their \
             artifacts and manifest/ledger entries were retained; undo the drift and \
             re-run `vendor --revert` to finish.",
            plural(
                drifted,
                "drifted vendored entry",
                "drifted vendored entries"
            ),
        ));
    }
    // Not a drift: the recorded wiring was restored, and the warning above
    // names the file that still installs from the artifact.
    let referenced = kept(KeepCause::Reference);
    if referenced > 0 {
        lines.push(format!(
            "GC: kept {}: {}; {}.",
            plural(referenced, "vendored entry", "vendored entries"),
            KeepCause::Reference.reason(),
            KeepCause::Reference.remedy(PRUNE_AGAIN),
        ));
    }
    // A failed revert leaves the entry and its artifacts in place: name
    // what was not reclaimed, and why (nothing else prints the backend's
    // error).
    if !gc.vendored_failed.is_empty() {
        let failed: Vec<String> = gc
            .vendored_failed
            .iter()
            // The reason can quote the committed ledger.
            .map(|(purl, why)| format!("{purl} ({})", crate::ui::printable(why)))
            .collect();
        lines.push(format!(
            "GC: failed to revert {}: {}.",
            plural(
                gc.vendored_failed.len(),
                "vendored entry",
                "vendored entries"
            ),
            failed.join(", "),
        ));
    }
    lines
}

pub(super) fn print_gc_vendored_line(gc: &GcSummary) {
    for line in format_gc_vendored_lines(gc) {
        println!("{line}");
    }
}

/// The human path's `--prune` pass: the mutating GC, or its read-only
/// preview under `--dry-run`, with its summary lines (unless `--silent`).
/// Mirrors the JSON path, which runs the GC whether or not anything was
/// applied.
pub(super) async fn run_human_gc(
    common: &GlobalArgs,
    manifest_path: &Path,
    socket_dir: &Path,
    scanned_purls: &HashSet<String>,
    vendored: &HashSet<PurlKey>,
) {
    let preview = common.dry_run;
    let gc = if preview {
        preview_apply_gc(common, manifest_path, socket_dir, scanned_purls, vendored).await
    } else {
        run_apply_gc(common, manifest_path, socket_dir, scanned_purls, vendored).await
    };
    if common.silent {
        return;
    }
    print_human_gc(&gc, preview);
}

/// The human summary lines of a finished GC pass (`preview`: the
/// `--dry-run` wording). Callers handle `--silent`.
pub(super) fn print_human_gc(gc: &GcSummary, preview: bool) {
    if let Some(line) = format_gc_line(gc, preview) {
        println!("\n{line}");
    }
    let prefix = if preview { "[dry-run] " } else { "" };
    for line in format_gc_vendored_lines(gc) {
        println!("{prefix}{line}");
    }
    print_gc_registry_lines(gc, preview);
}

/// The registry-route half's lines: the entries taken out (`preview`:
/// that would be), one each under a headline.
pub(super) fn print_gc_registry_lines(gc: &GcSummary, preview: bool) {
    let entries = gc.registry.as_deref().unwrap_or_default();
    for line in crate::commands::registry_gc::lines(entries, preview) {
        println!("{line}");
    }
}

impl GcSummary {
    /// The entries of a pnpm registry route the pass took out (or would).
    pub(super) fn registry_entries(&self) -> &[socket_patch_core::hosted::guidance::RegistryEntry] {
        self.registry.as_deref().unwrap_or_default()
    }

    /// The files the registry-route half rewrote or deleted (or would),
    /// sorted.
    pub(super) fn registry_files(&self) -> Vec<String> {
        let files: std::collections::BTreeSet<&str> = self
            .registry_entries()
            .iter()
            .map(|entry| entry.file.as_str())
            .collect();
        files.into_iter().map(str::to_string).collect()
    }

    /// Whether the registry-route half ran (the project held a route).
    pub(super) fn swept_registry(&self) -> bool {
        self.registry.is_some()
    }

    /// The registry-route half's warnings and what kept the pass from
    /// running, as run warnings: for a caller that records the entries
    /// itself (a hosted scan, which reports no `.socket/` sweep).
    pub(super) fn run_warnings(&self) -> Vec<crate::json_envelope::RunWarning> {
        let skipped = self.skipped.iter().map(|(code, message)| {
            crate::json_envelope::RunWarning::new(GC_SKIPPED, format!("{message} ({code})"))
        });
        skipped
            .chain(
                self.warnings
                    .iter()
                    .map(|(code, detail)| crate::json_envelope::RunWarning::new(*code, detail)),
            )
            .collect()
    }
}

/// PURL strings present in the manifest but absent from `scanned_purls`:
/// packages that were once patched but are no longer installed.
///
/// Comparison is by [`PurlKey`] on both sides: a manifest may hold several
/// qualified release variants of one installed package, API keys are
/// encoded (`pkg:npm/%40scope/x@1`) and mixed-case (`pkg:nuget/Newtonsoft.Json`)
/// where crawler purls are literal (the NuGet global cache is lowercase).
/// Otherwise `--prune`/`--sync` would GC the very patches it just downloaded.
///
/// `vendored` (the ledger's purl-key set) is always exempt: a vendored
/// package is consumed from the committed `.socket/vendor/` artifact, so
/// no installed copy is its NORMAL state.
///
/// Entries the crawl never looked for are exempt too (`crawl_covers_purl`:
/// a `pkg:<type>/` this build has no crawler for, e.g. a newer CLI's
/// ecosystem in the committed manifest) — absence proves nothing there.
fn detect_prunable(
    manifest: &PatchManifest,
    scanned_purls: &HashSet<String>,
    vendored: &HashSet<PurlKey>,
) -> Vec<String> {
    let scanned_bases: HashSet<PurlKey> = scanned_purls.iter().map(|p| PurlKey::new(p)).collect();
    manifest
        .patches
        .keys()
        .filter(|p| {
            !scanned_bases.contains(&PurlKey::new(p))
                && !purl_keys_cover(vendored, p)
                && crate::ecosystem_dispatch::crawl_covers_purl(p.as_str())
        })
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::scan::tests::manifest_with;

    fn summary(pruned: usize, files: usize, bytes: u64) -> GcSummary {
        GcSummary {
            pruned: (0..pruned).map(|i| format!("pkg:npm/p{i}@1")).collect(),
            blobs: CleanupResult {
                blobs_removed: files,
                bytes_freed: bytes,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn format_gc_line_singular_plural_and_preview() {
        assert_eq!(format_gc_line(&summary(0, 0, 0), false), None);
        assert_eq!(
            format_gc_line(&summary(1, 1, 12), false).as_deref(),
            Some("GC: pruned 1 manifest entry and removed 1 orphan file (12 B).")
        );
        assert_eq!(
            format_gc_line(&summary(2, 0, 0), false).as_deref(),
            Some("GC: pruned 2 manifest entries and removed 0 orphan files (0 B).")
        );
        assert_eq!(
            format_gc_line(&summary(1, 3, 0), true).as_deref(),
            Some("[dry-run] GC would prune 1 manifest entry and remove 3 orphan files (0 B).")
        );
    }

    fn scanned(purls: &[&str]) -> HashSet<String> {
        purls.iter().map(|s| (*s).to_string()).collect()
    }

    /// The "nothing vendored" set most prune tests run with.
    fn no_vendored() -> HashSet<PurlKey> {
        HashSet::new()
    }

    /// GlobalArgs rooted at the test project dir (the vendored-state GC
    /// loads `.socket/vendor/state.json` from `cwd`; these fixtures have
    /// none, so the vendor pass is a no-op).
    fn gc_common(cwd: &Path) -> crate::args::GlobalArgs {
        crate::args::GlobalArgs {
            cwd: cwd.to_path_buf(),
            ..Default::default()
        }
    }

    #[test]
    fn detect_prunable_returns_missing_entries() {
        let m = manifest_with(&[("pkg:npm/foo@1.0", "uuid-a"), ("pkg:npm/bar@2.0", "uuid-b")]);
        let out = detect_prunable(&m, &scanned(&["pkg:npm/foo@1.0"]), &no_vendored());
        assert_eq!(out, vec!["pkg:npm/bar@2.0".to_string()]);
    }

    /// Manifest keys and crawled purls are compared by `PurlKey`: the
    /// API's encoded, mixed-case, padded-composer and qualified spellings
    /// of an installed release keep their entries; a gone release of the
    /// same package still prunes, and with nothing installed every one of
    /// them prunes.
    #[test]
    fn detect_prunable_matches_by_purl_key() {
        let m = manifest_with(&[
            ("pkg:npm/%40scope/x@1.0.0", "uuid-a"),
            ("pkg:nuget/Newtonsoft.Json@13.0.3", "uuid-b"),
            ("pkg:pypi/typing_extensions@4.12.2", "uuid-c"),
            ("pkg:composer/psr/log@3.0.2.0", "uuid-d"),
            ("pkg:composer/psr/cache@v3.0.2", "uuid-e"),
            ("pkg:composer/psr/container@1.0.0.0", "uuid-i"),
            ("pkg:pypi/six@1.16.0?artifact_id=wheel-a", "uuid-f"),
            ("pkg:pypi/six@1.16.0?artifact_id=sdist", "uuid-g"),
            ("pkg:composer/symfony/console@6.4.1.0", "uuid-h"),
        ]);
        let s = scanned(&[
            "pkg:npm/@scope/x@1.0.0",
            "pkg:nuget/newtonsoft.json@13.0.3",
            "pkg:pypi/typing-extensions@4.12.2",
            "pkg:composer/psr/log@3.0.2",
            "pkg:composer/psr/cache@3.0.2",
            "pkg:composer/psr/container@1.0",
            "pkg:pypi/six@1.16.0",
            "pkg:composer/symfony/console@6.4.10",
        ]);
        assert_eq!(
            detect_prunable(&m, &s, &no_vendored()),
            vec!["pkg:composer/symfony/console@6.4.1.0".to_string()]
        );
        let mut gone = detect_prunable(&m, &scanned(&[]), &no_vendored());
        gone.sort();
        let mut all: Vec<String> = m.patches.keys().cloned().collect();
        all.sort();
        assert_eq!(gone, all);
    }

    /// Only ecosystems this build crawls are judged: a `pkg:<type>/` with
    /// no crawler (a newer CLI's ecosystem in a committed manifest) is
    /// never looked for, so its absence proves nothing. Maven and NuGet
    /// are crawled, so they prune like npm.
    #[test]
    fn detect_prunable_keeps_entries_of_uncrawled_ecosystems() {
        let m = manifest_with(&[
            ("pkg:hex/plug@1.14.0", "uuid-a"),
            ("pkg:maven/com.example/lib@1.0.0", "uuid-b"),
            ("pkg:nuget/Some.Package@1.0.0", "uuid-c"),
            ("pkg:npm/gone@1.0.0", "uuid-d"),
        ]);
        let mut out = detect_prunable(&m, &scanned(&[]), &no_vendored());
        out.sort();
        assert_eq!(
            out,
            vec![
                "pkg:maven/com.example/lib@1.0.0".to_string(),
                "pkg:npm/gone@1.0.0".to_string(),
                "pkg:nuget/Some.Package@1.0.0".to_string(),
            ]
        );
    }

    /// A vendored package is consumed from the committed artifact, so no
    /// installed copy is its normal state. The ledger holds
    /// qualifier-stripped bases, so a qualified variant is exempt too.
    #[test]
    fn detect_prunable_exempts_vendored_purls() {
        let m = manifest_with(&[
            ("pkg:npm/foo@1.0", "uuid-a"),
            ("pkg:pypi/six@1.16.0?artifact_id=wheel-a", "uuid-b"),
            ("pkg:npm/bar@2.0", "uuid-c"),
        ]);
        let vendored: HashSet<PurlKey> = [
            PurlKey::new("pkg:npm/foo@1.0"),
            PurlKey::new("pkg:pypi/six@1.16.0"),
        ]
        .into_iter()
        .collect();
        assert_eq!(
            detect_prunable(&m, &scanned(&[]), &vendored),
            vec!["pkg:npm/bar@2.0".to_string()]
        );
    }

    /// Write a manifest holding a single entry that references one afterHash
    /// blob, plant that blob on disk, and return `(manifest_path, socket_dir,
    /// blob_path)`.
    fn seed_manifest_with_blob(
        tmp: &std::path::Path,
        purl: &str,
        after_hash: &str,
    ) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
        let socket_dir = tmp.join(".socket");
        let blobs_dir = socket_dir.join("blobs");
        std::fs::create_dir_all(&blobs_dir).unwrap();
        let blob_path = blobs_dir.join(after_hash);
        // Non-trivial size so `bytesFreed` is observably > 0.
        std::fs::write(&blob_path, vec![0u8; 64]).unwrap();

        let manifest_path = socket_dir.join("manifest.json");
        let manifest = serde_json::json!({
            "patches": {
                purl: {
                    "uuid": "11111111-1111-4111-8111-111111111111",
                    "exportedAt": "2024-01-01T00:00:00Z",
                    "files": {
                        "package/index.js": {
                            "beforeHash": "0".repeat(64),
                            "afterHash": after_hash,
                        }
                    },
                    "vulnerabilities": {},
                    "description": "seed",
                    "license": "MIT",
                    "tier": "free",
                }
            }
        });
        std::fs::write(
            &manifest_path,
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .unwrap();
        (manifest_path, socket_dir, blob_path)
    }

    /// A manifest that exists but cannot be loaded is not "no manifest".
    /// Both passes skip the manifest half (nothing is pruned or swept
    /// without a referenced set) and say why with the shared load code,
    /// instead of a clean summary that reads as nothing to prune.
    #[tokio::test]
    async fn apply_gc_reports_an_unloadable_manifest() {
        for (seed, code) in [
            (
                (|p: &std::path::Path| std::fs::write(p, r#"{"patches": {"#).unwrap())
                    as fn(&std::path::Path),
                "manifest_invalid",
            ),
            (
                |p: &std::path::Path| std::fs::create_dir_all(p).unwrap(),
                "manifest_unreadable",
            ),
        ] {
            for dry_run in [true, false] {
                let tmp = tempfile::tempdir().unwrap();
                let socket_dir = tmp.path().join(".socket");
                let blob = socket_dir.join("blobs").join("a".repeat(64));
                std::fs::create_dir_all(blob.parent().unwrap()).unwrap();
                std::fs::write(&blob, b"orphan?").unwrap();
                let manifest_path = socket_dir.join("manifest.json");
                seed(&manifest_path);
                let before = std::fs::read(&manifest_path).ok();

                let common = gc_common(tmp.path());
                let gc = if dry_run {
                    preview_apply_gc(
                        &common,
                        &manifest_path,
                        &socket_dir,
                        &HashSet::new(),
                        &no_vendored(),
                    )
                    .await
                } else {
                    run_apply_gc(
                        &common,
                        &manifest_path,
                        &socket_dir,
                        &HashSet::new(),
                        &no_vendored(),
                    )
                    .await
                };
                let codes: Vec<&str> = gc.warnings.iter().map(|(c, _)| *c).collect();
                assert_eq!(codes, vec![code], "dry_run={dry_run}: {gc:?}");
                assert!(gc.skipped.is_none(), "dry_run={dry_run}: {gc:?}");
                assert!(gc.pruned.is_empty(), "dry_run={dry_run}: {gc:?}");
                assert_eq!(gc.blobs.blobs_removed, 0, "dry_run={dry_run}: {gc:?}");
                assert_eq!(gc.diffs.blobs_removed, 0, "dry_run={dry_run}: {gc:?}");
                assert_eq!(gc.packages.blobs_removed, 0, "dry_run={dry_run}: {gc:?}");
                assert_eq!(gc.total_bytes(), 0, "dry_run={dry_run}: {gc:?}");
                assert!(
                    blob.exists(),
                    "dry_run={dry_run}: no sweep without a manifest"
                );
                assert_eq!(
                    std::fs::read(&manifest_path).ok(),
                    before,
                    "dry_run={dry_run}: the manifest is not rewritten"
                );
            }
        }
    }

    #[tokio::test]
    async fn run_apply_gc_skips_prune_and_sweep_while_apply_lock_is_held() {
        // A live holder of `<socket_dir>/apply.lock` may be mid-write:
        // contention must skip the pass, never prune or delete.
        let tmp = tempfile::tempdir().unwrap();
        let after_hash = "c".repeat(64);
        let (manifest_path, socket_dir, blob_path) =
            seed_manifest_with_blob(tmp.path(), "pkg:npm/gone@1.0.0", &after_hash);

        let _holder =
            socket_patch_core::patch::apply_lock::acquire(&socket_dir, std::time::Duration::ZERO)
                .expect("test holder must win the fresh lock");

        let scanned: HashSet<String> = HashSet::new();
        let gc = run_apply_gc(
            &gc_common(tmp.path()),
            &manifest_path,
            &socket_dir,
            &scanned,
            &no_vendored(),
        )
        .await;

        assert!(
            gc.pruned.is_empty(),
            "GC must not prune under a held apply lock; pruned {:?}",
            gc.pruned
        );
        assert_eq!(
            gc.blobs.blobs_removed, 0,
            "GC must not sweep blobs under a held apply lock"
        );
        assert!(
            blob_path.exists(),
            "blob must survive a lock-contended GC pass"
        );
        let m = read_manifest(&manifest_path).await.unwrap().unwrap();
        assert!(
            m.patches.contains_key("pkg:npm/gone@1.0.0"),
            "manifest entry must survive a lock-contended GC pass"
        );
        // The skip is RECORDED, not silent: contention is `lock_held`, and
        // with no `--lock-timeout` the message carries no waited clause.
        assert_eq!(
            gc.skipped,
            Some((
                "lock_held",
                "another socket-patch process is operating in this directory".to_string()
            )),
            "a lock-contended pass must say why it pruned nothing"
        );
        let json = recorded(&gc, false);
        assert_eq!(json["warnings"][0]["code"], GC_SKIPPED, "{json}");
        assert!(
            json["warnings"][0]["detail"]
                .as_str()
                .unwrap()
                .ends_with("(lock_held)"),
            "{json}"
        );
        assert!(json.get("gc").is_none(), "a skipped pass has no gc: {json}");
        assert_eq!(json["events"], serde_json::json!([]), "{json}");
    }

    /// `--lock-timeout` reaches the GC acquire: the pass waits (and says
    /// so) instead of silently try-once-skipping while the flag promised a
    /// wait budget.
    #[tokio::test]
    async fn run_apply_gc_honors_lock_timeout_and_reports_the_wait() {
        let tmp = tempfile::tempdir().unwrap();
        let (manifest_path, socket_dir, _blob) =
            seed_manifest_with_blob(tmp.path(), "pkg:npm/gone@1.0.0", &"c".repeat(64));
        let _holder =
            socket_patch_core::patch::apply_lock::acquire(&socket_dir, std::time::Duration::ZERO)
                .expect("test holder must win the fresh lock");
        let common = crate::args::GlobalArgs {
            lock_timeout: Some(1),
            ..gc_common(tmp.path())
        };

        let started = std::time::Instant::now();
        let gc = run_apply_gc(
            &common,
            &manifest_path,
            &socket_dir,
            &scanned(&[]),
            &no_vendored(),
        )
        .await;

        assert!(
            started.elapsed() >= std::time::Duration::from_millis(900),
            "the pass must wait out the configured budget before skipping"
        );
        assert_eq!(
            gc.skipped,
            Some((
                "lock_held",
                "another socket-patch process is operating in this directory (waited 1s)"
                    .to_string()
            ))
        );
        assert!(gc.pruned.is_empty());
    }

    /// A DIRECTORY squatting on `apply.lock` is an I/O fault, not
    /// contention: the pass skips (nothing pruned, nothing swept) and
    /// records `lock_io` — never the contention wording.
    #[tokio::test]
    async fn run_apply_gc_reports_lock_io_when_lock_file_is_unopenable() {
        let tmp = tempfile::tempdir().unwrap();
        let after_hash = "f".repeat(64);
        let (manifest_path, socket_dir, blob_path) =
            seed_manifest_with_blob(tmp.path(), "pkg:npm/gone@1.0.0", &after_hash);
        std::fs::create_dir_all(socket_dir.join("apply.lock")).unwrap();

        let gc = run_apply_gc(
            &gc_common(tmp.path()),
            &manifest_path,
            &socket_dir,
            &scanned(&[]),
            &no_vendored(),
        )
        .await;

        let (code, message) = gc.skipped.as_ref().expect("the I/O fault must be recorded");
        assert_eq!(*code, "lock_io");
        assert!(
            message.contains("apply.lock"),
            "the reason names the lock file: {message}"
        );
        assert!(gc.pruned.is_empty(), "pruned {:?}", gc.pruned);
        assert_eq!(gc.blobs.blobs_removed, 0);
        assert!(blob_path.exists(), "nothing may be swept on a lock fault");
        let m = read_manifest(&manifest_path).await.unwrap().unwrap();
        assert!(m.patches.contains_key("pkg:npm/gone@1.0.0"));
        let json = recorded(&gc, false);
        assert_eq!(json["warnings"][0]["code"], GC_SKIPPED, "{json}");
        assert!(
            json["warnings"][0]["detail"]
                .as_str()
                .unwrap()
                .ends_with("(lock_io)"),
            "{json}"
        );
    }

    /// The preview lists the uninstalled entry and counts its blob, though
    /// the not-yet-pruned entry still references it, and frees exactly what
    /// the wet run frees, without mutating anything.
    #[tokio::test]
    async fn preview_and_apply_gc_agree_on_orphan_counts() {
        let after_hash = "b".repeat(64);

        let tmp_preview = tempfile::tempdir().unwrap();
        let (mp_p, sd_p, blob_p) =
            seed_manifest_with_blob(tmp_preview.path(), "pkg:npm/gone@1.0.0", &after_hash);
        let scanned: HashSet<String> = HashSet::new();
        let preview = preview_apply_gc(
            &gc_common(tmp_preview.path()),
            &mp_p,
            &sd_p,
            &scanned,
            &no_vendored(),
        )
        .await;
        assert_eq!(preview.pruned, vec!["pkg:npm/gone@1.0.0".to_string()]);
        assert_eq!(preview.blobs.blobs_removed, 1);
        assert_eq!(preview.total_bytes(), 64);
        assert!(blob_p.exists(), "preview must not mutate");
        let m = read_manifest(&mp_p).await.unwrap().unwrap();
        assert!(m.patches.contains_key("pkg:npm/gone@1.0.0"));

        let tmp_wet = tempfile::tempdir().unwrap();
        let (mp_w, sd_w, blob_w) =
            seed_manifest_with_blob(tmp_wet.path(), "pkg:npm/gone@1.0.0", &after_hash);
        let wet = run_apply_gc(
            &gc_common(tmp_wet.path()),
            &mp_w,
            &sd_w,
            &scanned,
            &no_vendored(),
        )
        .await;

        assert_eq!(
            preview.blobs.blobs_removed, wet.blobs.blobs_removed,
            "preview and wet run must agree on the orphan-blob count"
        );
        assert_eq!(
            preview.total_bytes(),
            wet.total_bytes(),
            "preview and wet run must agree on reclaimable bytes"
        );
        assert_eq!(preview.pruned, wet.pruned, "prunable set must match");
        // The wet run actually removed the blob and pruned the entry.
        assert!(!blob_w.exists(), "wet run must delete the orphan blob");
        let m = read_manifest(&mp_w).await.unwrap().unwrap();
        assert!(
            !m.patches.contains_key("pkg:npm/gone@1.0.0"),
            "wet run must prune the entry"
        );
    }

    /// Tempdir with a `.socket/blobs/<hash>` blob planted but NO manifest
    /// written; returns `(manifest_path, socket_dir, blob_path)`.
    fn seed_blob_without_manifest(
        tmp: &std::path::Path,
        blob_hash: &str,
    ) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
        let socket_dir = tmp.join(".socket");
        let blobs_dir = socket_dir.join("blobs");
        std::fs::create_dir_all(&blobs_dir).unwrap();
        let blob_path = blobs_dir.join(blob_hash);
        std::fs::write(&blob_path, vec![0u8; 64]).unwrap();
        let manifest_path = socket_dir.join("manifest.json");
        (manifest_path, socket_dir, blob_path)
    }

    #[tokio::test]
    async fn run_apply_gc_deletes_nothing_when_manifest_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let (manifest_path, socket_dir, blob_path) =
            seed_blob_without_manifest(tmp.path(), &"e".repeat(64));

        let gc = run_apply_gc(
            &gc_common(tmp.path()),
            &manifest_path,
            &socket_dir,
            &scanned(&[]),
            &no_vendored(),
        )
        .await;

        assert!(
            gc.pruned.is_empty(),
            "nothing to prune from a missing manifest; pruned {:?}",
            gc.pruned
        );
        assert_eq!(
            gc.blobs.blobs_removed, 0,
            "a missing manifest must NOT read as an empty referenced-set"
        );
        assert_eq!(gc.total_bytes(), 0, "no bytes may be freed");
        assert!(
            blob_path.exists(),
            "the blob must survive a GC pass with no manifest to consult"
        );
        assert!(
            !manifest_path.exists(),
            "the aborted pass must not conjure a manifest file"
        );
        assert!(
            !socket_dir.join("apply.lock").exists(),
            "the manifest gate runs before the lock — no lock file may be created"
        );
        assert!(
            gc.skipped.is_none(),
            "a missing manifest is not a lock skip: {:?}",
            gc.skipped
        );
    }

    /// A project with NO `.socket/` at all (a plain `scan --prune` on a
    /// bare or manifest-free vendored checkout): the manifest gate returns
    /// before `acquire`, which would otherwise create the directory just
    /// to find nothing to prune.
    #[tokio::test]
    async fn run_apply_gc_creates_no_socket_dir_on_a_pristine_project() {
        let tmp = tempfile::tempdir().unwrap();
        let socket_dir = tmp.path().join(".socket");
        let manifest_path = socket_dir.join("manifest.json");

        let gc = run_apply_gc(
            &gc_common(tmp.path()),
            &manifest_path,
            &socket_dir,
            &scanned(&[]),
            &no_vendored(),
        )
        .await;

        assert!(gc.pruned.is_empty());
        assert_eq!(gc.total_bytes(), 0);
        assert!(gc.skipped.is_none(), "{:?}", gc.skipped);
        assert!(
            !socket_dir.exists(),
            "a prune over a pristine project must leave no .socket/ behind"
        );
    }

    #[tokio::test]
    async fn preview_apply_gc_reports_zero_and_mutates_nothing_when_manifest_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let (manifest_path, socket_dir, blob_path) =
            seed_blob_without_manifest(tmp.path(), &"e".repeat(64));
        let gc = preview_apply_gc(
            &gc_common(tmp.path()),
            &manifest_path,
            &socket_dir,
            &scanned(&[]),
            &no_vendored(),
        )
        .await;
        assert!(gc.pruned.is_empty(), "pruned {:?}", gc.pruned);
        assert_eq!(
            gc.blobs.blobs_removed, 0,
            "preview of a missing manifest must report zero orphans, \
             not the whole blob store"
        );
        assert_eq!(gc.total_bytes(), 0);
        assert!(blob_path.exists(), "preview must not delete the blob");
        assert!(
            !manifest_path.exists(),
            "preview must not create a manifest file"
        );
        // The serialized degenerate preview is the normal all-zero shape.
        let json = recorded(&gc, true);
        assert_eq!(json["events"], serde_json::json!([]));
        assert_eq!(json["gc"]["removedBlobs"], serde_json::json!(0));
        assert_eq!(json["gc"]["bytesFreed"], serde_json::json!(0));
    }

    #[tokio::test]
    async fn preview_counts_blobs_of_lockfile_unused_vendored_entry() {
        // A vendored entry whose dependency left the lockfile graph: the wet
        // pass reverts it AND drops its manifest entry, freeing its blob, so
        // the preview must count that blob. The vendored exemption set holds
        // the purl, so ONLY the vendor-gc mirror loop can surface it.
        const PURL: &str = "pkg:npm/gone@1.0.0";
        const UUID: &str = "11111111-1111-4111-8111-111111111111";

        let tmp = tempfile::tempdir().unwrap();
        let (manifest_path, socket_dir, blob_path) =
            seed_manifest_with_blob(tmp.path(), PURL, &"d".repeat(64));
        // A lockfile that parses but carries no `.socket/vendor/npm/<uuid>/`
        // reference: the in-use probe answers Some(false) — unused.
        std::fs::write(
            tmp.path().join("package-lock.json"),
            "{\"lockfileVersion\":3,\"packages\":{}}",
        )
        .unwrap();
        // The ledger: one npm package-lock entry keyed by the manifest purl.
        let mut state = socket_patch_core::vendor::VendorState::default();
        state.entries.insert(
            PURL.to_string(),
            socket_patch_core::vendor::VendorEntry {
                flavor: Some("package-lock".into()),
                ..socket_patch_core::vendor::VendorEntry::new(
                    "npm".into(),
                    PURL.into(),
                    UUID.into(),
                    socket_patch_core::vendor::state::VendorArtifact {
                        yarn_berry10c0: None,
                        path: format!(".socket/vendor/npm/{UUID}/gone-1.0.0.tgz"),
                        sha256: String::new(),
                        size: None,
                        platform_locked: None,
                        file_inventory: None,
                    },
                    Vec::new(),
                )
            },
        );
        socket_patch_core::vendor::save_state(tmp.path(), &state)
            .await
            .unwrap();
        let state_before = std::fs::read(tmp.path().join(".socket/vendor/state.json")).unwrap();

        let vendored: HashSet<PurlKey> = [PurlKey::new(PURL)].into_iter().collect();
        let gc = preview_apply_gc(
            &gc_common(tmp.path()),
            &manifest_path,
            &socket_dir,
            &scanned(&[]),
            &vendored,
        )
        .await;

        assert_eq!(
            gc.vendored_reverted,
            vec![PURL.to_string()],
            "the lockfile-unused entry must be listed as revertable"
        );
        assert!(
            gc.pruned.is_empty(),
            "the vendored exemption keeps it out of the prunable set (it is \
             reclaimed via the vendor GC, not detect_prunable); got {:?}",
            gc.pruned
        );
        assert_eq!(
            gc.blobs.blobs_removed, 1,
            "the preview must count the unused entry's blob as an orphan — \
             its manifest keys are dropped in memory before the sweep, \
             mirroring what the wet run frees"
        );
        assert!(
            gc.total_bytes() > 0,
            "bytesFreed must include the unused entry's blob"
        );
        assert_eq!(gc.vendor_orphan_dirs, 0, "no orphan uuid dirs on disk");
        // Preview is non-mutating: blob, manifest entry, and ledger intact.
        assert!(blob_path.exists(), "preview must not delete the blob");
        let m = read_manifest(&manifest_path).await.unwrap().unwrap();
        assert!(
            m.patches.contains_key(PURL),
            "preview must not prune the on-disk manifest entry"
        );
        assert_eq!(
            std::fs::read(tmp.path().join(".socket/vendor/state.json")).unwrap(),
            state_before,
            "preview must not rewrite the vendor ledger"
        );
    }

    /// A vendored entry whose lock fragment DRIFTED since vendoring (fork
    /// re-resolve): the in-use probe calls it unused, but the wet revert
    /// refuses to touch the drifted lock and keeps artifacts, ledger entry
    /// and manifest record. The preview cannot see drift and lists the
    /// entry as revertable, so the keep must surface as
    /// `keptVendoredEntries` in the apply JSON.
    #[tokio::test]
    async fn apply_gc_reports_drift_kept_vendored_entry() {
        use socket_patch_core::vendor::state::{WiringAction, WiringRecord};

        const PURL: &str = "pkg:npm/gone@1.0.0";
        const UUID: &str = "11111111-1111-4111-8111-111111111111";

        let tmp = tempfile::tempdir().unwrap();
        let (manifest_path, socket_dir, blob_path) =
            seed_manifest_with_blob(tmp.path(), PURL, &"e".repeat(64));
        // The drifted lock: the recorded key resolves to a third-party
        // fork — neither our vendored fragment nor the recorded
        // pre-vendor original (and no `.socket/vendor/npm/<uuid>/`
        // mention, so the in-use probe answers Some(false) — unused).
        std::fs::write(
            tmp.path().join("package-lock.json"),
            serde_json::to_vec(&serde_json::json!({
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/gone": {
                        "version": "1.0.0",
                        "resolved": "https://example.com/their-fork.tgz",
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();
        // The artifact the keep must preserve.
        let uuid_dir = tmp.path().join(format!(".socket/vendor/npm/{UUID}"));
        std::fs::create_dir_all(&uuid_dir).unwrap();
        std::fs::write(uuid_dir.join("gone-1.0.0.tgz"), b"tgz").unwrap();
        // The ledger: one wired package-lock entry, so the revert can
        // classify the fork fragment as third-party drift.
        let mut state = socket_patch_core::vendor::VendorState::default();
        state.entries.insert(
            PURL.to_string(),
            socket_patch_core::vendor::VendorEntry {
                flavor: Some("package-lock".into()),
                ..socket_patch_core::vendor::VendorEntry::new(
                    "npm".into(),
                    PURL.into(),
                    UUID.into(),
                    socket_patch_core::vendor::state::VendorArtifact {
                        yarn_berry10c0: None,
                        path: format!(".socket/vendor/npm/{UUID}/gone-1.0.0.tgz"),
                        sha256: String::new(),
                        size: None,
                        platform_locked: None,
                        file_inventory: None,
                    },
                    vec![WiringRecord {
                        file: "package-lock.json".into(),
                        kind: "npm_lock_entry".into(),
                        action: WiringAction::Rewritten,
                        key: Some("node_modules/gone".into()),
                        original: Some(serde_json::json!({
                            "version": "1.0.0",
                            "resolved": "https://registry.npmjs.org/gone/-/gone-1.0.0.tgz",
                        })),
                        new: Some(serde_json::json!({
                            "version": "1.0.0",
                            "resolved":
                                format!("file:.socket/vendor/npm/{UUID}/gone-1.0.0.tgz"),
                        })),
                    }],
                )
            },
        );
        socket_patch_core::vendor::save_state(tmp.path(), &state)
            .await
            .unwrap();

        let vendored: HashSet<PurlKey> = [PurlKey::new(PURL)].into_iter().collect();
        let gc = run_apply_gc(
            &gc_common(tmp.path()),
            &manifest_path,
            &socket_dir,
            &scanned(&[]),
            &vendored,
        )
        .await;

        assert!(
            gc.vendored_reverted.is_empty(),
            "a drift-kept entry must not be reported reverted: {:?}",
            gc.vendored_reverted
        );
        assert_eq!(
            gc.vendored_kept,
            vec![(PURL.to_string(), KeepCause::Drift)],
            "the keep must be counted — the only signal that the entry the \
             preview listed as revertable was deliberately not reclaimed"
        );
        let json = recorded(&gc, false);
        assert_eq!(
            json["events"],
            serde_json::json!([{
                "action": "skipped", "purl": PURL, "errorCode": "vendor_revert_kept",
                "reason": json["events"][0]["reason"], "details": {"mode": "vendored"},
            }]),
            "scan --prune --json must carry the keep"
        );
        // The revert's own drift warnings (`vendor_lock_entry_drifted`,
        // `vendor_artifact_kept`) are already said by the keep above; they
        // must not also land in `warnings[]`.
        assert!(
            json.get("warnings").is_none(),
            "a drift keep adds no warning: {json}"
        );
        // Nothing reclaimed: manifest record, blob, ledger entry, and
        // artifacts all survive (the drift-keep contract).
        assert_eq!(gc.blobs.blobs_removed, 0, "kept entry's blob is not swept");
        assert!(blob_path.exists());
        let m = read_manifest(&manifest_path).await.unwrap().unwrap();
        assert!(
            m.patches.contains_key(PURL),
            "the kept entry's manifest record must survive"
        );
        assert!(
            socket_patch_core::vendor::load_state(tmp.path())
                .await
                .unwrap()
                .entries
                .contains_key(PURL),
            "the kept entry's ledger record must survive"
        );
        assert!(uuid_dir.exists(), "kept artifacts must survive the sweep");
    }

    /// A requirements project whose `six` patch left the manifest: the
    /// vendored wheel line is still in `requirements.txt`, and
    /// `requirements-prod.txt` (an export the revert does not own) installs
    /// from the same wheel. Returns the manifest path and `.socket/`.
    async fn seed_dropped_pypi_entry_with_an_export(
        root: &Path,
        purl: &str,
        uuid: &str,
    ) -> (std::path::PathBuf, std::path::PathBuf) {
        use socket_patch_core::vendor::state::{VendorArtifact, WiringAction, WiringRecord};
        use socket_patch_core::vendor::{VendorEntry, VendorState};

        let (manifest_path, socket_dir, _) =
            seed_manifest_with_blob(root, "pkg:npm/still-here@1.0.0", &"e".repeat(64));
        let wheel = format!(".socket/vendor/pypi/{uuid}/six-1.16.0-py2.py3-none-any.whl");
        let line = format!("./{wheel}");
        std::fs::write(root.join("requirements.txt"), format!("{line}\n")).unwrap();
        std::fs::write(root.join("requirements-prod.txt"), format!("{line}\n")).unwrap();
        std::fs::create_dir_all(root.join(&wheel).parent().unwrap()).unwrap();
        std::fs::write(root.join(&wheel), b"wheel").unwrap();
        let mut state = VendorState::default();
        state.entries.insert(
            purl.to_string(),
            VendorEntry {
                flavor: Some("requirements".into()),
                ..VendorEntry::new(
                    "pypi".into(),
                    purl.into(),
                    uuid.into(),
                    VendorArtifact {
                        yarn_berry10c0: None,
                        path: wheel,
                        sha256: String::new(),
                        size: None,
                        platform_locked: None,
                        file_inventory: None,
                    },
                    vec![WiringRecord {
                        file: "requirements.txt".into(),
                        kind: "requirements_line".into(),
                        action: WiringAction::Rewritten,
                        key: Some("requirements.txt:1".into()),
                        original: Some(serde_json::json!(["six==1.16.0"])),
                        new: Some(serde_json::json!(line)),
                    }],
                )
            },
        );
        socket_patch_core::vendor::save_state(root, &state)
            .await
            .unwrap();
        (manifest_path, socket_dir)
    }

    /// A revert that restored its recorded wiring but kept the wheel
    /// because another project file still installs from it is a keep, not
    /// a drift (#1184): the pass names that file and the way out, as
    /// `remove` and `rollback` do, and never says the lock was re-resolved.
    #[tokio::test]
    async fn apply_gc_names_the_file_that_still_installs_a_kept_wheel() {
        const PURL: &str = "pkg:pypi/six@1.16.0";
        const UUID: &str = "11111111-1111-4111-8111-111111111111";

        let tmp = tempfile::tempdir().unwrap();
        let (manifest_path, socket_dir) =
            seed_dropped_pypi_entry_with_an_export(tmp.path(), PURL, UUID).await;
        let gc = run_apply_gc(
            &gc_common(tmp.path()),
            &manifest_path,
            &socket_dir,
            &scanned(&["pkg:npm/still-here@1.0.0"]),
            &no_vendored(),
        )
        .await;

        // The recorded wiring was restored; the wheel and the ledger entry
        // stay for the export that still installs from it.
        assert_eq!(
            std::fs::read_to_string(tmp.path().join("requirements.txt")).unwrap(),
            "six==1.16.0\n"
        );
        assert!(tmp
            .path()
            .join(format!(".socket/vendor/pypi/{UUID}"))
            .is_dir());
        assert!(socket_patch_core::vendor::load_state(tmp.path())
            .await
            .unwrap()
            .entries
            .contains_key(PURL));
        assert!(gc.vendored_reverted.is_empty(), "{gc:?}");
        assert_eq!(
            gc.vendored_kept,
            vec![(PURL.to_string(), KeepCause::Reference)]
        );

        let lines = format_gc_vendored_lines(&gc).join("\n");
        let json = recorded(&gc, false);
        let said_json = json.to_string();
        for (what, said) in [("human", &lines), ("--json", &said_json)] {
            assert!(
                said.contains("requirements-prod.txt"),
                "{what}: the file that still installs from the wheel is not named:\n{said}"
            );
            assert!(
                !said.contains("re-resolved") && !said.contains("drift"),
                "{what}: nothing drifted, the recorded wiring was restored:\n{said}"
            );
            assert!(said.contains("point the file"), "{what}:\n{said}");
        }
        // The warning that names the file is the one `remove` and
        // `rollback` raise, once, under the purl it is about.
        let codes: Vec<&str> = json["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|w| w["code"].as_str().unwrap())
            .collect();
        assert_eq!(codes, ["vendor_revert_residual_reference"], "{json:#}");
        let detail = json["warnings"][0]["detail"].as_str().unwrap();
        assert!(
            detail.starts_with(&format!("{PURL}: kept .socket/vendor/pypi/{UUID}/: ")),
            "{detail}"
        );
        assert_eq!(json["events"][0]["errorCode"], "vendor_revert_kept");
    }

    /// A revert the backend refused is reported with the backend's reason,
    /// in both outputs: nothing else prints it.
    #[tokio::test]
    async fn apply_gc_says_why_a_vendored_revert_failed() {
        const PURL: &str = "pkg:pypi/six@1.16.0";
        const UUID: &str = "11111111-1111-4111-8111-111111111111";

        let tmp = tempfile::tempdir().unwrap();
        let (manifest_path, socket_dir) =
            seed_dropped_pypi_entry_with_an_export(tmp.path(), PURL, UUID).await;
        // A ledger entry of an ecosystem with no revert backend (a
        // hand-edited state.json).
        let mut state = socket_patch_core::vendor::load_state(tmp.path())
            .await
            .unwrap();
        state.entries.get_mut(PURL).unwrap().ecosystem = "frobnicate".into();
        socket_patch_core::vendor::save_state(tmp.path(), &state)
            .await
            .unwrap();
        let gc = run_apply_gc(
            &gc_common(tmp.path()),
            &manifest_path,
            &socket_dir,
            &scanned(&["pkg:npm/still-here@1.0.0"]),
            &no_vendored(),
        )
        .await;

        // The edit also disowns the entry's `pypi/<uuid>` dir, which the
        // requirements files still install from: the sweep's warning leads.
        let lines = format_gc_vendored_lines(&gc);
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(
            lines[0].starts_with(&format!(
                "GC: a project lockfile still points at .socket/vendor/pypi/{UUID}, "
            )),
            "{lines:?}"
        );
        assert_eq!(
            lines[1],
            "GC: failed to revert 1 vendored entry: pkg:pypi/six@1.16.0 (this build has no \
             vendor backend for ecosystem `frobnicate`)."
        );
        let json = recorded(&gc, false);
        assert_eq!(
            json["events"],
            serde_json::json!([{
                "action": "skipped", "purl": PURL, "errorCode": "vendor_revert_failed",
                "reason": "the prune GC could not revert this vendored entry (this build has \
                           no vendor backend for ecosystem `frobnicate`); its ledger entry \
                           and artifacts were kept",
                "details": {"mode": "vendored"},
            }]),
            "{json:#}"
        );
        assert!(socket_patch_core::vendor::load_state(tmp.path())
            .await
            .unwrap()
            .entries
            .contains_key(PURL));
    }

    /// What a git merge conflict leaves of the committed vendor ledger.
    const CONFLICTED_LEDGER: &str = "{\n<<<<<<< HEAD\n";

    /// The warning codes a pass records into the `scan` envelope.
    fn warning_codes(json: &serde_json::Value) -> Vec<&str> {
        json["warnings"]
            .as_array()
            .map(|warnings| {
                warnings
                    .iter()
                    .map(|w| w["code"].as_str().unwrap())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// A vendor ledger that cannot be read is not "nothing vendored": the
    /// pass and its preview say that the vendored half did not run, under
    /// the code `rollback` and `list` report it with, instead of a clean
    /// summary. The manifest half, which never asks the ledger, still runs.
    #[tokio::test]
    async fn gc_reports_a_vendor_ledger_it_could_not_read() {
        for dry_run in [true, false] {
            let tmp = tempfile::tempdir().unwrap();
            let (manifest_path, socket_dir, blob) =
                seed_manifest_with_blob(tmp.path(), "pkg:npm/gone@1.0.0", &"a".repeat(64));
            let ledger = tmp.path().join(VENDOR_STATE_REL);
            std::fs::create_dir_all(ledger.parent().unwrap()).unwrap();
            std::fs::write(&ledger, CONFLICTED_LEDGER).unwrap();

            let common = gc_common(tmp.path());
            let gc = if dry_run {
                preview_apply_gc(
                    &common,
                    &manifest_path,
                    &socket_dir,
                    &HashSet::new(),
                    &no_vendored(),
                )
                .await
            } else {
                run_apply_gc(
                    &common,
                    &manifest_path,
                    &socket_dir,
                    &HashSet::new(),
                    &no_vendored(),
                )
                .await
            };

            let json = recorded(&gc, dry_run);
            assert_eq!(
                warning_codes(&json),
                ["vendor_state_unreadable"],
                "dry_run={dry_run}: the vendored half did not run, and the pass must say \
                 why: {json}"
            );
            let detail = json["warnings"][0]["detail"].as_str().unwrap();
            assert!(
                detail.starts_with("cannot read .socket/vendor/state.json: corrupt "),
                "dry_run={dry_run}: {detail}"
            );
            let lines = format_gc_vendored_lines(&gc);
            assert_eq!(lines, [format!("GC: {detail}.")], "dry_run={dry_run}");

            // The manifest half is the crawl's and the manifest's alone.
            assert_eq!(gc.pruned, ["pkg:npm/gone@1.0.0"], "dry_run={dry_run}");
            assert_eq!(blob.exists(), dry_run, "dry_run={dry_run}");
            assert_eq!(
                std::fs::read_to_string(&ledger).unwrap(),
                CONFLICTED_LEDGER,
                "dry_run={dry_run}: the ledger is left for the user to resolve"
            );
        }
    }

    /// Only a ledger that is not there is "no ledger". One that cannot even
    /// be stat'd (a symlink to itself) takes the pass past its existence
    /// gate, with no manifest beside it, to the read that reports it.
    #[cfg(unix)]
    #[tokio::test]
    async fn gc_takes_only_a_missing_ledger_for_no_ledger() {
        let tmp = tempfile::tempdir().unwrap();
        let socket_dir = tmp.path().join(".socket");
        let ledger = tmp.path().join(VENDOR_STATE_REL);
        std::fs::create_dir_all(ledger.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink("state.json", &ledger).unwrap();
        let manifest_path = socket_dir.join("manifest.json");
        let common = gc_common(tmp.path());

        let full = run_apply_gc(
            &common,
            &manifest_path,
            &socket_dir,
            &HashSet::new(),
            &no_vendored(),
        )
        .await;
        let vendor_only = run_vendor_only_gc(&common, &manifest_path, &socket_dir).await;
        for (pass, gc) in [("full", full), ("vendor-only", vendor_only)] {
            let json = recorded(&gc, false);
            assert_eq!(
                warning_codes(&json),
                ["vendor_state_unreadable"],
                "{pass}: {json}"
            );
        }
    }

    /// A vendored directory no ledger entry owns stays while a project file
    /// still installs from it, and the pass says so, as `vendor --revert`,
    /// `rollback` and `remove` do: the lockfile and the ledger disagree,
    /// and a clean summary would hide that. With no ledger entry at all the
    /// pass sweeps nothing, and reports the same: with a manifest, and
    /// (the shape of a vendored project that lost its ledger) without one,
    /// where the wet pass must not stop at its existence gate.
    #[tokio::test]
    async fn gc_reports_an_orphan_dir_a_project_file_still_installs_from() {
        const UUID: &str = "1a2b3c4d-5e6f-4a1b-8c2d-9e0f1a2b3c4d";
        let unit = format!(".socket/vendor/pypi/{UUID}");

        for (dry_run, with_manifest) in [(true, true), (false, true), (true, false), (false, false)]
        {
            let tmp = tempfile::tempdir().unwrap();
            let (manifest_path, socket_dir, _) =
                seed_manifest_with_blob(tmp.path(), "pkg:npm/still-here@1.0.0", &"e".repeat(64));
            if !with_manifest {
                std::fs::remove_file(&manifest_path).unwrap();
            }
            let wheel = tmp
                .path()
                .join(&unit)
                .join("six-1.16.0-py2.py3-none-any.whl");
            std::fs::create_dir_all(wheel.parent().unwrap()).unwrap();
            std::fs::write(&wheel, b"wheel").unwrap();
            std::fs::write(
                tmp.path().join("requirements.txt"),
                format!("./{unit}/six-1.16.0-py2.py3-none-any.whl\n"),
            )
            .unwrap();
            // An unreferenced orphan beside it: with no ledger the pass has
            // nothing to judge ownership by, and deletes neither.
            let loose = tmp
                .path()
                .join(".socket/vendor/npm/2b3c4d5e-6f7a-4b2c-9d3e-0f1a2b3c4d5e");
            std::fs::create_dir_all(&loose).unwrap();
            std::fs::write(loose.join("left-pad-1.3.0.tgz"), b"tgz").unwrap();

            let mut common = gc_common(tmp.path());
            common.dry_run = dry_run;
            let scanned = scanned(&["pkg:npm/still-here@1.0.0"]);
            let gc = if dry_run {
                preview_apply_gc(
                    &common,
                    &manifest_path,
                    &socket_dir,
                    &scanned,
                    &no_vendored(),
                )
                .await
            } else {
                run_apply_gc(
                    &common,
                    &manifest_path,
                    &socket_dir,
                    &scanned,
                    &no_vendored(),
                )
                .await
            };

            let case = format!("dry_run={dry_run}, with_manifest={with_manifest}");
            let json = recorded(&gc, dry_run);
            assert_eq!(
                warning_codes(&json),
                ["vendor_orphan_still_wired"],
                "{case}: {json}"
            );
            let detail = json["warnings"][0]["detail"].as_str().unwrap();
            assert!(detail.contains(&unit), "{case}: {detail}");
            assert!(
                !detail.contains("revert"),
                "{case}: a prune is not a revert, and `vendor --revert` would un-vendor \
                 the whole project: {detail}"
            );
            assert_eq!(
                format_gc_vendored_lines(&gc),
                [format!("GC: {detail}.")],
                "{case}"
            );
            assert_eq!(json["removedVendorOrphanDirs"], 0, "{case}");
            assert!(wheel.is_file() && loose.is_dir(), "{case}");
        }
    }

    /// A pass recorded into a fresh `scan` envelope, serialized.
    fn recorded(gc: &GcSummary, preview: bool) -> serde_json::Value {
        let mut env = Envelope::new(crate::json_envelope::Command::Scan);
        gc.record_into(&mut env, preview);
        env.to_value()
    }

    /// The vendored half's typed fields absorb sorted and land where they
    /// belong in the envelope: kept and failed reverts are `skipped` events
    /// (`vendor_revert_kept` / `vendor_revert_failed`, `details.mode:
    /// "vendored"`), failed rewrites top-level warnings — never mislabelled
    /// as a skipped pass; a pass that could not take the lock is only the
    /// `gc_skipped` warning, with no `gc`.
    #[test]
    fn record_into_carries_kept_failed_and_skipped_passes() {
        const LOCK_MARKER: &str = "another socket-patch process is operating in this directory";
        let mut gc = GcSummary::default();
        gc.absorb_vendor_gc(VendorGcSummary {
            kept: vec![
                ("pkg:npm/b@1.0.0".into(), KeepCause::Reference),
                ("pkg:npm/a@1.0.0".into(), KeepCause::Drift),
            ],
            failed: vec![
                ("pkg:npm/d@1.0.0".into(), "cannot read d.lock".into()),
                ("pkg:npm/c@1.0.0".into(), "cannot read c.lock".into()),
            ],
            dropped_reverted: vec!["pkg:npm/e@1.0.0".into()],
            orphan_dirs: 2,
            write_failures: vec![(
                "vendor_state_write_failed",
                "reverted vendored entries but could not update .socket/vendor/state.json: EROFS"
                    .into(),
            )],
            ..Default::default()
        });
        gc.pruned = vec!["pkg:npm/gone@1.0.0".into()];
        assert_eq!(
            gc.vendored_kept,
            vec![
                ("pkg:npm/a@1.0.0".to_string(), KeepCause::Drift),
                ("pkg:npm/b@1.0.0".to_string(), KeepCause::Reference),
            ],
            "absorb must sort, like every other purl list"
        );
        let json = recorded(&gc, false);
        let rows: Vec<(String, String, String)> = json["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| {
                (
                    e["action"].as_str().unwrap().to_string(),
                    e["purl"].as_str().unwrap().to_string(),
                    e["errorCode"].as_str().unwrap_or_default().to_string(),
                )
            })
            .collect();
        let row = |a: &str, p: &str, c: &str| (a.to_string(), p.to_string(), c.to_string());
        assert_eq!(
            rows,
            vec![
                row("removed", "pkg:npm/gone@1.0.0", ""),
                row("removed", "pkg:npm/e@1.0.0", "vendor_reverted"),
                row("skipped", "pkg:npm/a@1.0.0", "vendor_revert_kept"),
                row("skipped", "pkg:npm/b@1.0.0", "vendor_revert_kept"),
                row("skipped", "pkg:npm/c@1.0.0", "vendor_revert_failed"),
                row("skipped", "pkg:npm/d@1.0.0", "vendor_revert_failed"),
            ],
            "{json}"
        );
        assert_eq!(
            json["events"][0]["details"],
            serde_json::json!({"manifest": true})
        );
        assert_eq!(json["events"][1]["details"]["mode"], "vendored");
        // Each keep says its own cause, and each failure the backend's.
        assert_eq!(
            json["events"][2]["reason"],
            "lock entries were re-resolved since vendoring, so the artifact and the \
             manifest/ledger entries were retained"
        );
        assert_eq!(
            json["events"][3]["reason"],
            "a project file still installs from the vendored artifact (see \
             vendor_revert_residual_reference); the recorded wiring was restored; the \
             artifact and the manifest/ledger entries were retained — point the file named \
             by vendor_revert_residual_reference back at the registry release (or re-export \
             it from the restored lock), then re-run `scan --prune`"
        );
        assert_eq!(
            json["events"][4]["reason"],
            "the prune GC could not revert this vendored entry (cannot read c.lock); its \
             ledger entry and artifacts were kept"
        );
        assert_eq!(json["summary"]["removed"], 2);
        assert_eq!(json["summary"]["skipped"], 4);
        assert_eq!(
            json["summary"]["failed"], 0,
            "a GC revert failure never fails the run"
        );
        assert_eq!(json["status"], "success");
        assert_eq!(json["removedVendorOrphanDirs"], 2);
        assert_eq!(json["gc"]["removedBlobs"], 0);
        assert_eq!(
            json["warnings"],
            serde_json::json!([{
                "code": "vendor_state_write_failed",
                "detail": "reverted vendored entries but could not update \
                           .socket/vendor/state.json: EROFS",
            }]),
            "{json}"
        );
        // A preview flips the removals to `verified`.
        let preview = recorded(&gc, true);
        assert_eq!(preview["events"][0]["action"], "verified");
        assert_eq!(preview["events"][1]["action"], "verified");
        assert_eq!(preview["summary"]["removed"], 0);

        // A pass that could not take its lock: only the warning.
        let skipped = GcSummary {
            skipped: Some(("lock_held", LOCK_MARKER.into())),
            ..Default::default()
        };
        let json = recorded(&skipped, false);
        assert_eq!(
            json["warnings"],
            serde_json::json!([{
                "code": GC_SKIPPED,
                "detail": format!("{LOCK_MARKER} (lock_held)"),
            }])
        );
        assert!(json.get("gc").is_none());
        assert!(json.get("removedVendorOrphanDirs").is_none());

        // A clean pass: a zero gc, no warnings.
        let clean = recorded(&GcSummary::vendor_only(VendorGcSummary::default()), false);
        assert!(clean.get("warnings").is_none(), "{clean}");
        assert_eq!(clean["gc"]["bytesFreed"], 0);
    }

    /// The human GC vocabulary the contract pins (`GC: skipped:
    /// <message>.`, one `GC: <detail>.` per warning, the reverted/swept
    /// counts, the drift-keep hint, the keep for a file that still installs
    /// from an artifact, `GC: failed to revert N vendored entry/entries: …`
    /// with each reason), rendered in order; a clean pass prints nothing.
    #[test]
    fn gc_vendored_lines_render_the_contract_vocabulary() {
        assert!(format_gc_vendored_lines(&GcSummary::default()).is_empty());

        let mut gc = GcSummary {
            skipped: Some((
                "lock_held",
                "another socket-patch process is operating in this directory".into(),
            )),
            ..Default::default()
        };
        gc.absorb_vendor_gc(VendorGcSummary {
            failed: vec![
                ("pkg:npm/d@1.0.0".into(), "cannot read d.lock".into()),
                ("pkg:npm/c@1.0.0".into(), "cannot read c.lock".into()),
            ],
            write_failures: vec![("manifest_write_failed", "could not update manifest".into())],
            ..Default::default()
        });
        assert_eq!(
            format_gc_vendored_lines(&gc),
            vec![
                "GC: skipped: another socket-patch process is operating in this \
                 directory."
                    .to_string(),
                "GC: could not update manifest.".to_string(),
                "GC: failed to revert 2 vendored entries: pkg:npm/c@1.0.0 (cannot read \
                 c.lock), pkg:npm/d@1.0.0 (cannot read d.lock)."
                    .to_string(),
            ]
        );

        let one = GcSummary::vendor_only(VendorGcSummary {
            failed: vec![("pkg:npm/c@1.0.0".into(), "cannot read c.lock".into())],
            unused_reverted: vec!["pkg:npm/e@1.0.0".into()],
            orphan_dirs: 1,
            ..Default::default()
        });
        assert_eq!(
            format_gc_vendored_lines(&one),
            vec![
                "GC: reverted 1 vendored entry; swept 1 orphan vendor dir.".to_string(),
                "GC: failed to revert 1 vendored entry: pkg:npm/c@1.0.0 (cannot read c.lock)."
                    .to_string(),
            ]
        );

        let many = GcSummary::vendor_only(VendorGcSummary {
            kept: vec![
                ("pkg:npm/a@1.0.0".into(), KeepCause::Drift),
                ("pkg:npm/b@1.0.0".into(), KeepCause::Drift),
                ("pkg:pypi/c@1.0.0".into(), KeepCause::Reference),
            ],
            orphan_dirs: 2,
            ..Default::default()
        });
        assert_eq!(
            format_gc_vendored_lines(&many),
            vec![
                "GC: reverted 0 vendored entries; swept 2 orphan vendor dirs.".to_string(),
                "GC: kept 2 drifted vendored entries: lock entries were re-resolved since \
                 vendoring, so their artifacts and manifest/ledger entries were retained; \
                 undo the drift and re-run `vendor --revert` to finish."
                    .to_string(),
                "GC: kept 1 vendored entry: a project file still installs from the vendored \
                 artifact (see vendor_revert_residual_reference); the recorded wiring was \
                 restored; point the file named by vendor_revert_residual_reference back at \
                 the registry release (or re-export it from the restored lock), then re-run \
                 `scan --prune`."
                    .to_string(),
            ]
        );
    }

    /// A PyPI entry the crawl does not report is kept while an installed
    /// copy still carries its patch. A project with no environment of its
    /// own is crawled only for the packages it declares, so a package it
    /// stopped declaring drops out of the crawl with its copy still
    /// patched, and the record's before-blobs are the only way to restore
    /// that copy. An entry whose copy is back to the original is pruned.
    #[tokio::test]
    async fn prune_keeps_a_pypi_entry_whose_installed_copy_is_still_patched() {
        use socket_patch_core::hash::git_sha256::compute_git_sha256_from_bytes as hash;
        const ORIGINAL: &[u8] = b"VERSION = 'original'\n";
        const PATCHED: &[u8] = b"VERSION = 'patched'\n";

        let tmp = tempfile::tempdir().unwrap();
        let site = tmp.path().join("site-packages");
        for (name, module) in [("stillpatched", PATCHED), ("restored", ORIGINAL)] {
            let dist = site.join(format!("{name}-1.0.0.dist-info"));
            std::fs::create_dir_all(&dist).unwrap();
            std::fs::write(
                dist.join("METADATA"),
                format!("Metadata-Version: 2.1\nName: {name}\nVersion: 1.0.0\n"),
            )
            .unwrap();
            std::fs::create_dir_all(site.join(name)).unwrap();
            std::fs::write(site.join(name).join("__init__.py"), module).unwrap();
        }

        let project = tmp.path().join("project");
        let socket_dir = project.join(".socket");
        let blobs = socket_dir.join("blobs");
        std::fs::create_dir_all(&blobs).unwrap();
        for content in [ORIGINAL, PATCHED] {
            std::fs::write(blobs.join(hash(content)), content).unwrap();
        }
        let record = |name: &str, uuid: &str| {
            serde_json::json!({
                "uuid": uuid,
                "exportedAt": "2026-01-01T00:00:00Z",
                "files": { format!("{name}/__init__.py"): {
                    "beforeHash": hash(ORIGINAL),
                    "afterHash": hash(PATCHED),
                }},
                "vulnerabilities": {},
                "description": "seed",
                "license": "MIT",
                "tier": "free",
            })
        };
        let kept = "pkg:pypi/stillpatched@1.0.0";
        let pruned = "pkg:pypi/restored@1.0.0";
        let manifest_path = socket_dir.join("manifest.json");
        let manifest = serde_json::json!({ "patches": {
            kept: record("stillpatched", "22222222-2222-4222-8222-222222222222"),
            pruned: record("restored", "33333333-3333-4333-8333-333333333333"),
        }});
        std::fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();

        // The crawl reported neither package. `--global-prefix` names the
        // site dir their copies are looked up in by PURL.
        let scanned = scanned(&["pkg:pypi/declared@1.0.0"]);
        for dry_run in [true, false] {
            let common = crate::args::GlobalArgs {
                cwd: project.clone(),
                global_prefix: Some(site.clone()),
                dry_run,
                ..Default::default()
            };
            let gc = if dry_run {
                preview_apply_gc(
                    &common,
                    &manifest_path,
                    &socket_dir,
                    &scanned,
                    &no_vendored(),
                )
                .await
            } else {
                run_apply_gc(
                    &common,
                    &manifest_path,
                    &socket_dir,
                    &scanned,
                    &no_vendored(),
                )
                .await
            };
            assert_eq!(gc.pruned, vec![pruned.to_string()], "dry_run={dry_run}");
            if !dry_run {
                assert!(
                    gc.warnings.iter().any(|(code, detail)| {
                        *code == "pypi_installed_patch_kept" && detail.contains(kept)
                    }),
                    "the kept entry must be explained: {gc:?}"
                );
            }
        }
        let manifest = read_manifest(&manifest_path).await.unwrap().unwrap();
        assert!(manifest.patches.contains_key(kept), "{manifest:?}");
        assert!(!manifest.patches.contains_key(pruned), "{manifest:?}");
        assert!(
            blobs.join(hash(ORIGINAL)).exists(),
            "the kept entry's before-blob is its only restore data"
        );
    }
}
