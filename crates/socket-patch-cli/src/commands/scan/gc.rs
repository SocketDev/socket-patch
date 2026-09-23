//! The GC pass for `scan --prune`/`--sync`: manifest-entry pruning plus
//! orphan blob/diff/package-archive sweeps, in both mutating (apply) and
//! read-only (preview) forms.

use socket_patch_core::manifest::cleanup_blobs::CleanupResult;
use socket_patch_core::manifest::operations::{read_manifest, write_manifest};
use socket_patch_core::manifest::schema::PatchManifest;
use socket_patch_core::patch::apply_lock;
use socket_patch_core::utils::purl::{canonical_purl, strip_purl_qualifiers};
use socket_patch_core::vendor::load_state;
use std::collections::HashSet;
use std::path::Path;
use std::time::Duration;

use crate::args::GlobalArgs;
use crate::commands::lock_cli::lock_failure;
use crate::commands::rollback::{sweep_failure, sweep_unused_artifacts};
use crate::commands::vendor::{run_vendor_gc, run_vendor_gc_locked, VendorGcSummary};

/// Aggregated outcome of a GC pass (or preview). Serialized into the
/// `scan --json` output's `gc` sub-object. See CLI_CONTRACT.md for the
/// stable schema.
#[derive(Debug, Default)]
pub(super) struct GcSummary {
    /// PURLs removed from the manifest (apply mode) or eligible to be
    /// removed (preview mode).
    pub(super) pruned: Vec<String>,
    pub(super) blobs: CleanupResult,
    pub(super) diffs: CleanupResult,
    pub(super) packages: CleanupResult,
    /// Vendored entries reverted (or revertable, preview mode) because
    /// their patch is gone from the manifest or their dependency left the
    /// lockfile graph — see `vendor::run_vendor_gc`. Sorted.
    vendored_reverted: Vec<String>,
    /// Vendored entries the wet pass drift-kept
    /// (`RevertOutcome::kept_artifact`): a revert was due, but the lock
    /// entries drifted since vendoring, so artifacts, ledger entry, and
    /// manifest records were all retained — nothing reclaimed until the
    /// user undoes the drift and re-runs `vendor --revert`. Sorted.
    /// Always empty in preview mode (drift is only detected by a wet
    /// wiring replay), so the preview still lists such entries in
    /// `vendored_reverted` — this field is what lets the apply output
    /// explain the difference.
    vendored_kept: Vec<String>,
    /// Vendored entries whose wet revert FAILED: the ledger entry and the
    /// artifacts were kept, nothing reclaimed. Sorted. Always empty in
    /// preview mode (nothing is reverted there).
    vendored_failed: Vec<String>,
    /// Orphan `.socket/vendor/<eco>/<uuid>` dirs swept (or sweepable).
    vendor_orphan_dirs: usize,
    /// Set when a wet pass could not take the apply lock and so skipped
    /// its whole mutating half (vendored reverts, manifest prune, blob
    /// sweep): `lock_held` (another run holds it — the contract's
    /// skip-not-fail posture) or `lock_io` (the lock file could not be
    /// created or opened). `(code, message)` exactly as
    /// `lock_cli::lock_failure` renders them. Never set in preview mode
    /// (the preview is lock-free and read-only).
    skipped: Option<(&'static str, String)>,
    /// Post-revert/prune rewrites that failed (`vendor_state_write_failed`
    /// / `manifest_write_failed` + detail) and orphan sweeps that could not
    /// finish (`cleanup_failed`: the pass aborted, or left orphans it could
    /// not unlink — the removed counts above are what it did reclaim). The
    /// mutations already happened on disk, so the stale record is reported,
    /// not the pass failed. Serialized as additive `warnings[]` on the
    /// apply shape only.
    warnings: Vec<(&'static str, String)>,
}

impl GcSummary {
    pub(super) fn total_bytes(&self) -> u64 {
        self.blobs.bytes_freed + self.diffs.bytes_freed + self.packages.bytes_freed
    }

    /// A summary carrying only the vendored-state half — the shape every
    /// early return takes when the manifest half cannot run.
    fn vendor_only(v: VendorGcSummary) -> Self {
        let mut gc = GcSummary::default();
        gc.absorb_vendor_gc(v);
        gc
    }

    /// Fold a vendored-state GC pass into this summary: purl lists sorted,
    /// the vendored half's lock skip becomes this pass's `skipped` unless
    /// it already recorded its own reason, and its failed post-revert
    /// rewrites join `warnings`.
    fn absorb_vendor_gc(&mut self, v: VendorGcSummary) {
        self.vendored_reverted = v
            .dropped_reverted
            .into_iter()
            .chain(v.unused_reverted)
            .collect();
        self.vendored_reverted.sort();
        self.vendored_kept = v.kept;
        self.vendored_kept.sort();
        self.vendored_failed = v.failed;
        self.vendored_failed.sort();
        self.skipped = self.skipped.take().or(v.skipped);
        self.warnings.extend(v.write_failures);
        self.vendor_orphan_dirs = v.orphan_dirs;
    }

    /// Serialize for a *mutating* GC pass (post-apply). `skipped` and
    /// `warnings` are additive: present only when the lock could not be
    /// taken / a post-revert rewrite failed.
    fn to_apply_json(&self) -> serde_json::Value {
        let mut json = serde_json::json!({
            "prunedManifestEntries": self.pruned,
            "removedBlobs": self.blobs.blobs_removed,
            "removedDiffArchives": self.diffs.blobs_removed,
            "removedPackageArchives": self.packages.blobs_removed,
            "revertedVendoredEntries": self.vendored_reverted,
            "keptVendoredEntries": self.vendored_kept,
            "failedVendoredEntries": self.vendored_failed,
            "removedVendorOrphanDirs": self.vendor_orphan_dirs,
            "bytesFreed": self.total_bytes(),
        });
        if let Some((code, message)) = &self.skipped {
            json["skipped"] = serde_json::json!({ "code": code, "message": message });
        }
        if !self.warnings.is_empty() {
            json["warnings"] = self
                .warnings
                .iter()
                .map(|(code, detail)| serde_json::json!({ "code": code, "detail": detail }))
                .collect();
        }
        json
    }

    /// Serialize for a *non-mutating* GC pass (read-only preview).
    fn to_preview_json(&self) -> serde_json::Value {
        serde_json::json!({
            "prunableManifestEntries": self.pruned,
            "orphanBlobs": self.blobs.blobs_removed,
            "orphanDiffArchives": self.diffs.blobs_removed,
            "orphanPackageArchives": self.packages.blobs_removed,
            "revertableVendoredEntries": self.vendored_reverted,
            "vendorOrphanDirs": self.vendor_orphan_dirs,
            "bytesReclaimable": self.total_bytes(),
        })
    }
}

/// The orphan blob/diff/package sweep against the (post-prune) manifest.
/// `dry_run = true` for the preview path; `dry_run = false` for the apply
/// path — the shared `sweep_unused_artifacts` natively supports dry-run, so
/// the same function works for both. A pass that failed outright counts
/// as empty; that failure (or a wet pass's unremovable orphans) rides
/// `warnings` as `cleanup_failed` so the output never reads as a clean
/// all-zero sweep.
async fn run_gc(
    manifest: &PatchManifest,
    pruned: Vec<String>,
    socket_dir: &Path,
    dry_run: bool,
) -> GcSummary {
    let sweep = sweep_unused_artifacts(manifest, socket_dir, dry_run).await;
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
/// the blobs the vendored half just orphaned in the same pass (the stale
/// `vendored` exemption set is harmless: the entries it would exempt are
/// already gone). Callers must gate on the `prune` flag — when GC isn't
/// requested, simply don't call this function and don't emit a `gc`
/// sub-object.
pub(super) async fn run_apply_gc(
    common: &GlobalArgs,
    manifest_path: &Path,
    socket_dir: &Path,
    scanned_purls: &HashSet<String>,
    vendored: &HashSet<String>,
) -> GcSummary {
    // Existence gate BEFORE the lock: `acquire` creates `.socket/` when it
    // is missing, and a plain `scan --prune` on a project with neither a
    // manifest nor a ledger entry (a pristine checkout) must not conjure
    // the directory just to find nothing to do. Either store alone is
    // enough: the vendored half runs without a manifest, the manifest half
    // without a ledger.
    let has_manifest = tokio::fs::metadata(manifest_path)
        .await
        .is_ok_and(|m| m.is_file());
    let has_ledger_entries = load_state(&common.cwd)
        .await
        .is_ok_and(|s| !s.entries.is_empty());
    if !has_manifest && !has_ledger_entries {
        return GcSummary::default();
    }

    // Both halves are read-modify-writes the apply lock serializes
    // everywhere else (apply, get, remove, repair, rollback, vendor). Run
    // unlocked against a live holder mid-write, the stale manifest read
    // would clobber the holder's new entry on write-back and the sweep
    // would delete its just-downloaded blobs. Contention skips the pass
    // without failing the scan; an I/O fault on the lock file skips it
    // too — both are recorded so the output explains the untouched state
    // instead of reading as a clean all-zero pass. One acquire for both
    // halves: flock is per open file description, so a nested acquire in
    // the vendored half would read as a live holder and silently skip it.
    let timeout = Duration::from_secs(common.lock_timeout.unwrap_or(0));
    let _guard = match apply_lock::acquire(socket_dir, timeout) {
        Ok(g) => g,
        Err(e) => {
            return GcSummary {
                skipped: Some(lock_failure(&e, timeout)),
                ..Default::default()
            };
        }
    };

    // Vendored-state GC FIRST (see the fn doc), under this guard.
    let vendor_gc = run_vendor_gc_locked(common, manifest_path, /*dry_run=*/ false).await;

    // Re-read the manifest under the lock (the apply step may have added
    // or updated entries we now want to consider for pruning; the probe
    // above was only the cheap pre-lock gate). Missing or unreadable ⇒
    // nothing to prune, and the blob sweep has no referenced-set to work
    // from.
    let mut manifest = match read_manifest(manifest_path).await {
        Ok(Some(m)) => m,
        _ => return GcSummary::vendor_only(vendor_gc),
    };
    let prunable = detect_prunable(&manifest, scanned_purls, vendored);
    for purl in &prunable {
        manifest.patches.remove(purl);
    }
    let mut write_failure = None;
    if !prunable.is_empty() {
        // A failed write leaves the on-disk manifest stale (the entries
        // are still listed as pruned — they are gone from the in-memory
        // copy the sweep below works from), so it is reported, not
        // swallowed.
        if let Err(e) = write_manifest(manifest_path, &manifest).await {
            write_failure = Some((
                "manifest_write_failed",
                format!(
                    "pruned {} manifest entr{} but could not update {}: {e}",
                    prunable.len(),
                    if prunable.len() == 1 { "y" } else { "ies" },
                    manifest_path.display()
                ),
            ));
        }
    }
    let mut gc = run_gc(&manifest, prunable, socket_dir, /*dry_run=*/ false).await;
    gc.absorb_vendor_gc(vendor_gc);
    gc.warnings.extend(write_failure);
    gc
}

/// Dry-run preview of the apply-mode GC pass. Same shape as
/// [`run_apply_gc`] but emits `prunable*`/`orphan*` field names and
/// performs no mutation.
async fn preview_apply_gc(
    common: &GlobalArgs,
    manifest_path: &Path,
    socket_dir: &Path,
    scanned_purls: &HashSet<String>,
    vendored: &HashSet<String>,
) -> GcSummary {
    // Read-only preview of the vendored-state GC (lists, never reverts).
    let vendor_gc = run_vendor_gc(common, manifest_path, /*dry_run=*/ true).await;

    let mut manifest = match read_manifest(manifest_path).await {
        Ok(Some(m)) => m,
        _ => return GcSummary::vendor_only(vendor_gc),
    };
    // Mirror the wet pass: an unused vendored entry's manifest keys are
    // dropped before the blob sweep, so drop them from the in-memory copy
    // too — otherwise the preview under-reports orphan blobs/bytes
    // relative to what the real `--prune` run frees.
    for purl in &vendor_gc.unused_reverted {
        let base = strip_purl_qualifiers(purl).to_string();
        manifest
            .patches
            .retain(|k, _| k != purl && strip_purl_qualifiers(k) != base);
    }
    let prunable = detect_prunable(&manifest, scanned_purls, vendored);
    // Mirror `run_apply_gc`: drop the prunable entries from the manifest
    // *before* computing orphans (no write — this is the preview). The
    // cleanup helpers derive the "referenced" blob/archive set from the
    // manifest they're handed, so leaving the prunable entries in place
    // would keep their blobs marked as used and the preview would
    // under-report `orphan*`/`bytesReclaimable` relative to what the real
    // `--prune`/`--sync` run actually frees.
    for purl in &prunable {
        manifest.patches.remove(purl);
    }
    let mut gc = run_gc(&manifest, prunable, socket_dir, /*dry_run=*/ true).await;
    gc.absorb_vendor_gc(vendor_gc);
    gc
}

/// The `gc` sub-object for the JSON paths: a read-only preview under
/// `--dry-run`, the mutating pass otherwise, serialized with the matching
/// (`prunable*`/`orphan*` vs `pruned*`/`removed*`) field names.
pub(super) async fn gc_json(
    common: &GlobalArgs,
    manifest_path: &Path,
    socket_dir: &Path,
    scanned_purls: &HashSet<String>,
    vendored: &HashSet<String>,
    dry_run: bool,
) -> serde_json::Value {
    if dry_run {
        preview_apply_gc(common, manifest_path, socket_dir, scanned_purls, vendored)
            .await
            .to_preview_json()
    } else {
        run_apply_gc(common, manifest_path, socket_dir, scanned_purls, vendored)
            .await
            .to_apply_json()
    }
}

/// Human-readable line(s) for the vendored-state half of a GC pass (and
/// the lock-skip reason / failed rewrites, when the pass could not run or
/// persist in full); prints nothing when there is nothing to report.
pub(super) fn print_gc_vendored_line(gc: &GcSummary) {
    if let Some((code, message)) = &gc.skipped {
        println!("GC: skipped ({code}): {message}.");
    }
    for (_, detail) in &gc.warnings {
        println!("GC: {detail}.");
    }
    if !gc.vendored_reverted.is_empty() || gc.vendor_orphan_dirs > 0 {
        println!(
            "GC: reverted {} vendored entr{}; swept {} orphan vendor dir{}.",
            gc.vendored_reverted.len(),
            if gc.vendored_reverted.len() == 1 {
                "y"
            } else {
                "ies"
            },
            gc.vendor_orphan_dirs,
            if gc.vendor_orphan_dirs == 1 { "" } else { "s" },
        );
    }
    // Drift-keeps are the one GC outcome that silently contradicts the
    // `--dry-run` preview (which cannot see drift and lists the entry as
    // revertable), so they always earn the same remediation hint every
    // other drift-keep caller prints.
    if !gc.vendored_kept.is_empty() {
        println!(
            "GC: kept {} drifted vendored entr{}: lock entries were re-resolved since \
             vendoring, so their artifacts and manifest/ledger entries were retained — undo \
             the drift and re-run `vendor --revert` to finish.",
            gc.vendored_kept.len(),
            if gc.vendored_kept.len() == 1 {
                "y"
            } else {
                "ies"
            },
        );
    }
    // A failed revert leaves the entry and its artifacts in place; the
    // backend's own error was printed as it happened, so name what was
    // not reclaimed.
    if !gc.vendored_failed.is_empty() {
        println!(
            "GC: failed to revert {} vendored entr{}: {}.",
            gc.vendored_failed.len(),
            if gc.vendored_failed.len() == 1 {
                "y"
            } else {
                "ies"
            },
            gc.vendored_failed.join(", "),
        );
    }
}

/// PURL strings present in the manifest but absent from `scanned_purls`.
/// These are candidates for pruning during `scan`'s GC pass — they
/// correspond to packages that were once patched but are no longer
/// installed (or no longer reachable to the crawler). Pure / no I/O so
/// it's unit-testable.
///
/// Comparison is on the **base** PURL (qualifiers stripped) on both
/// sides: the pypi crawler reports base PURLs, but a manifest may hold
/// several qualified release variants (`?artifact_id=...`) of one
/// installed package. Matching on the base keeps every variant of an
/// installed package while still pruning all variants of one that is
/// gone — otherwise `scan --all-releases --sync` would prune the very
/// variants it just downloaded.
///
/// `vendored` (the ledger's purl-key set, see `vendored_purl_keys`) is
/// always exempt: a vendored package is consumed from the committed
/// `.socket/vendor/` artifact, so the crawler not finding an installed
/// copy is its NORMAL state, not "no longer installed". Without this, a
/// wiped node_modules would prune the manifest entry — and the next
/// `vendor` run would then reconcile-revert the vendoring itself.
///
/// Both sides are compared in percent-DECODED form (`normalize_purl`):
/// manifest keys come from the API encoded (`pkg:npm/%40scope/x@1`) while
/// crawler purls carry the literal `@scope` — comparing the raw strings
/// would make every encoded scoped entry look prunable and `--prune`/
/// `--sync` would GC the very patch it just downloaded.
///
/// Entries the crawl never even looked for are exempt too
/// (`crawl_covers_purl`): any `pkg:<type>/` this build has no crawler
/// for. The manifest is a committed, shared file, so a newer CLI's
/// ecosystem can legitimately appear in it — "absent from the crawl"
/// then says nothing about whether the package is installed, and pruning
/// would silently delete a teammate's patch (plus its blobs). Same
/// fail-safe reasoning as capturing `scanned_purls` before the
/// `--ecosystems` filter.
fn detect_prunable(
    manifest: &PatchManifest,
    scanned_purls: &HashSet<String>,
    vendored: &HashSet<String>,
) -> Vec<String> {
    let scanned_bases: HashSet<String> = scanned_purls.iter().map(|p| canonical_purl(p)).collect();
    manifest
        .patches
        .keys()
        .filter(|p| {
            !scanned_bases.contains(&canonical_purl(p))
                && !vendored.contains(p.as_str())
                && !vendored.contains(strip_purl_qualifiers(p))
                && crate::ecosystem_dispatch::crawl_covers_purl(p.as_str())
        })
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::scan::tests::manifest_with;

    // ---- detect_prunable ---------------------------------------------------

    fn scanned(purls: &[&str]) -> HashSet<String> {
        purls.iter().map(|s| (*s).to_string()).collect()
    }

    /// The "nothing vendored" set most prune tests run with.
    fn no_vendored() -> HashSet<String> {
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
    fn detect_prunable_empty_manifest_empty_scanned() {
        let m = PatchManifest::new();
        assert!(detect_prunable(&m, &scanned(&[]), &no_vendored()).is_empty());
    }

    #[test]
    fn detect_prunable_empty_manifest_nonempty_scanned() {
        let m = PatchManifest::new();
        // No manifest entries → nothing to prune even if the crawl found
        // packages that don't appear in the manifest.
        assert!(detect_prunable(&m, &scanned(&["pkg:npm/foo@1"]), &no_vendored()).is_empty());
    }

    #[test]
    fn detect_prunable_all_entries_present_in_scan() {
        let m = manifest_with(&[("pkg:npm/foo@1.0", "uuid-a"), ("pkg:npm/bar@2.0", "uuid-b")]);
        let s = scanned(&["pkg:npm/foo@1.0", "pkg:npm/bar@2.0"]);
        assert!(detect_prunable(&m, &s, &no_vendored()).is_empty());
    }

    #[test]
    fn detect_prunable_returns_missing_entries() {
        let m = manifest_with(&[("pkg:npm/foo@1.0", "uuid-a"), ("pkg:npm/bar@2.0", "uuid-b")]);
        // foo is still installed, bar is gone.
        let s = scanned(&["pkg:npm/foo@1.0"]);
        let mut out = detect_prunable(&m, &s, &no_vendored());
        out.sort();
        assert_eq!(out, vec!["pkg:npm/bar@2.0".to_string()]);
    }

    #[test]
    fn detect_prunable_returns_everything_when_scan_is_empty() {
        let m = manifest_with(&[("pkg:npm/foo@1.0", "uuid-a"), ("pkg:npm/bar@2.0", "uuid-b")]);
        let mut out = detect_prunable(&m, &scanned(&[]), &no_vendored());
        out.sort();
        assert_eq!(
            out,
            vec!["pkg:npm/bar@2.0".to_string(), "pkg:npm/foo@1.0".to_string()],
        );
    }

    #[test]
    fn detect_prunable_keeps_pypi_variants_of_installed_base() {
        // Manifest holds three qualified release variants; the crawler
        // reports only the base PURL. None should be pruned — they all
        // belong to the installed package.
        let m = manifest_with(&[
            ("pkg:pypi/six@1.16.0?artifact_id=wheel-a", "uuid-a"),
            ("pkg:pypi/six@1.16.0?artifact_id=wheel-b", "uuid-b"),
            ("pkg:pypi/six@1.16.0?artifact_id=sdist", "uuid-c"),
        ]);
        let out = detect_prunable(&m, &scanned(&["pkg:pypi/six@1.16.0"]), &no_vendored());
        assert!(
            out.is_empty(),
            "variants of an installed base must not be pruned; got {out:?}"
        );
    }

    #[test]
    fn detect_prunable_removes_all_variants_of_uninstalled_base() {
        // The package is no longer installed (empty crawl): every
        // release variant is prunable.
        let m = manifest_with(&[
            ("pkg:pypi/six@1.16.0?artifact_id=wheel-a", "uuid-a"),
            ("pkg:pypi/six@1.16.0?artifact_id=sdist", "uuid-c"),
        ]);
        let out = detect_prunable(&m, &scanned(&[]), &no_vendored());
        assert_eq!(out.len(), 2, "all variants of a gone package should prune");
    }

    #[test]
    fn detect_prunable_exempts_vendored_purls() {
        // A vendored package is consumed from the committed artifact —
        // the crawler not seeing an installed copy (wiped node_modules)
        // is its normal state. Pruning it would orphan the manifest
        // entry and let the next `vendor` run reconcile-revert the
        // vendoring itself.
        let m = manifest_with(&[("pkg:npm/foo@1.0", "uuid-a"), ("pkg:npm/bar@2.0", "uuid-b")]);
        let vendored: HashSet<String> = ["pkg:npm/foo@1.0".to_string()].into_iter().collect();
        let out = detect_prunable(&m, &scanned(&[]), &vendored);
        assert_eq!(
            out,
            vec!["pkg:npm/bar@2.0".to_string()],
            "vendored foo exempt, non-vendored bar prunable"
        );
    }

    #[test]
    fn detect_prunable_encoded_manifest_key_not_pruned() {
        // The API serves scoped purls percent-encoded and they land in the
        // manifest verbatim; the crawler reports the literal `@scope` form.
        // Comparing raw strings would make every encoded scoped entry look
        // prunable — `scan --prune` would GC the patch it just downloaded.
        let m = manifest_with(&[("pkg:npm/%40scope/x@1.0.0", "uuid-a")]);
        let s = scanned(&["pkg:npm/@scope/x@1.0.0"]);
        assert!(
            detect_prunable(&m, &s, &no_vendored()).is_empty(),
            "encoded manifest key must match the decoded scanned purl"
        );
        // A genuinely-gone encoded entry still prunes.
        let out = detect_prunable(&m, &scanned(&[]), &no_vendored());
        assert_eq!(out, vec!["pkg:npm/%40scope/x@1.0.0".to_string()]);
    }

    #[test]
    fn detect_prunable_keeps_entries_of_uncrawled_ecosystems() {
        // A manifest key whose `pkg:<type>/` this build has no crawler for
        // (a newer CLI's ecosystem in a COMMITTED manifest, read by an older
        // binary) is never looked for by the crawl, so its absence from
        // `scanned_purls` says nothing about whether it is installed.
        // Pruning it silently deletes a teammate's patch (plus its blobs)
        // from the shared manifest.
        let m = manifest_with(&[
            ("pkg:hex/plug@1.14.0", "uuid-a"),
            ("pkg:npm/gone@1.0.0", "uuid-b"),
        ]);
        let out = detect_prunable(&m, &scanned(&[]), &no_vendored());
        assert_eq!(
            out,
            vec!["pkg:npm/gone@1.0.0".to_string()],
            "only the crawled-ecosystem orphan may prune; got {out:?}"
        );
    }

    #[test]
    fn detect_prunable_judges_maven_and_nuget_like_any_ecosystem() {
        // Maven/NuGet are first-class ecosystems: every scan crawls them,
        // so their manifest entries ARE judged — absent from the scan
        // means genuinely uninstalled, and they prune like any other
        // ecosystem. (They used to be exempt behind the retired
        // `SOCKET_EXPERIMENTAL_*` runtime gates.)
        let m = manifest_with(&[
            ("pkg:maven/com.example/lib@1.0.0", "uuid-a"),
            ("pkg:nuget/Some.Package@1.0.0", "uuid-b"),
            ("pkg:npm/gone@1.0.0", "uuid-c"),
        ]);
        let mut out = detect_prunable(&m, &scanned(&[]), &no_vendored());
        out.sort();
        assert_eq!(
            out,
            vec![
                "pkg:maven/com.example/lib@1.0.0".to_string(),
                "pkg:npm/gone@1.0.0".to_string(),
                "pkg:nuget/Some.Package@1.0.0".to_string(),
            ],
            "maven/nuget orphans must prune like any other ecosystem's"
        );
    }

    #[test]
    fn detect_prunable_exempts_qualified_variant_of_vendored_base() {
        // The ledger key set carries qualifier-stripped bases (see
        // `vendored_purl_keys`), so a qualified manifest variant of a
        // vendored package is exempt via its base purl.
        let m = manifest_with(&[("pkg:pypi/six@1.16.0?artifact_id=wheel-a", "uuid-a")]);
        let vendored: HashSet<String> = ["pkg:pypi/six@1.16.0".to_string()].into_iter().collect();
        let out = detect_prunable(&m, &scanned(&[]), &vendored);
        assert!(
            out.is_empty(),
            "qualified variant of a vendored base must not prune; got {out:?}"
        );
    }

    // ---- preview_apply_gc / run_apply_gc parity ----------------------------
    // The dry-run preview MUST report the same orphan blobs/archives the real
    // (wet) prune would remove. Both delete the prunable manifest entries
    // first, then sweep; the cleanup helpers derive the "still referenced"
    // blob set from the manifest they're handed, so a preview that swept
    // against the un-pruned manifest would keep the prunable entries' blobs
    // marked "used" and under-report `orphan*`/`bytesReclaimable`.

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
        // Non-trivial size so `bytesReclaimable`/`bytesFreed` is observably > 0.
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

    #[tokio::test]
    async fn preview_apply_gc_reports_blobs_of_prunable_entry() {
        // The package is not installed (empty scan), so its entry is prunable
        // and its only blob is reclaimable. A correct PREVIEW must count that
        // blob even though it is still referenced by the not-yet-pruned entry.
        let tmp = tempfile::tempdir().unwrap();
        let after_hash = "a".repeat(64);
        let (manifest_path, socket_dir, blob_path) =
            seed_manifest_with_blob(tmp.path(), "pkg:npm/gone@1.0.0", &after_hash);

        let scanned: HashSet<String> = HashSet::new();
        let preview = preview_apply_gc(
            &gc_common(tmp.path()),
            &manifest_path,
            &socket_dir,
            &scanned,
            &no_vendored(),
        )
        .await;

        assert_eq!(
            preview.pruned,
            vec!["pkg:npm/gone@1.0.0".to_string()],
            "preview must list the uninstalled entry as prunable"
        );
        assert_eq!(
            preview.blobs.blobs_removed, 1,
            "preview must count the prunable entry's blob as an orphan \
             (regression: it was masked because the entry still referenced it)"
        );
        assert!(
            preview.total_bytes() > 0,
            "bytesReclaimable must be > 0 when an orphan blob would be freed"
        );
        // Preview is non-mutating: blob and manifest untouched.
        assert!(
            blob_path.exists(),
            "dry-run preview must not delete the blob"
        );
        let m = read_manifest(&manifest_path).await.unwrap().unwrap();
        assert!(
            m.patches.contains_key("pkg:npm/gone@1.0.0"),
            "dry-run preview must not prune the manifest entry"
        );
    }

    #[tokio::test]
    async fn run_apply_gc_skips_prune_and_sweep_while_apply_lock_is_held() {
        // A live holder of `<socket_dir>/apply.lock` (a concurrent `get`,
        // `apply`, `remove`, …) may be mid-manifest-write and mid-blob-
        // download. The wet GC pass is a manifest read-modify-write plus a
        // blob sweep: run unlocked, its stale read clobbers the holder's
        // new manifest entry on write-back, and the sweep deletes the
        // holder's fresh blobs (unreferenced by GC's stale in-memory copy).
        // Contention must skip the pass — the vendored half's posture —
        // never prune or delete.
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
        let json = gc.to_apply_json();
        assert_eq!(json["skipped"]["code"], "lock_held", "{json}");
        assert_eq!(json["prunedManifestEntries"], serde_json::json!([]), "{json}");
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
        assert_eq!(gc.to_apply_json()["skipped"]["code"], "lock_io");
    }

    #[tokio::test]
    async fn preview_and_apply_gc_agree_on_orphan_counts() {
        // The preview's reclaimable counts must equal what the wet run frees.
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
        assert!(blob_p.exists(), "preview must not mutate");

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

    // ---- missing/corrupt manifest fail-safe ---------------------------------
    // An unreadable manifest must abort the GC pass, NOT be treated as an
    // empty referenced-set: the cleanup helpers derive "still referenced"
    // from the manifest they're handed, so proceeding with an empty one
    // would sweep EVERY blob in `.socket/blobs` — including ones a healthy
    // manifest (restored from git, say) still references.

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
    async fn run_apply_gc_deletes_nothing_when_manifest_corrupt() {
        let tmp = tempfile::tempdir().unwrap();
        let (manifest_path, socket_dir, blob_path) =
            seed_blob_without_manifest(tmp.path(), &"e".repeat(64));
        std::fs::write(&manifest_path, "{ not json").unwrap();

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
            "nothing to prune from a corrupt manifest; pruned {:?}",
            gc.pruned
        );
        assert_eq!(
            gc.blobs.blobs_removed, 0,
            "a corrupt manifest must NOT read as an empty referenced-set"
        );
        assert_eq!(gc.total_bytes(), 0, "no bytes may be freed");
        assert!(
            blob_path.exists(),
            "the blob must survive a GC pass with an unreadable manifest"
        );
        assert_eq!(
            std::fs::read_to_string(&manifest_path).unwrap(),
            "{ not json",
            "the aborted pass must not rewrite the corrupt manifest"
        );
    }

    #[tokio::test]
    async fn preview_apply_gc_reports_zero_and_mutates_nothing_when_manifest_missing_or_corrupt() {
        // Missing manifest.
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
        let json = gc.to_preview_json();
        assert_eq!(json["prunableManifestEntries"], serde_json::json!([]));
        assert_eq!(json["orphanBlobs"], serde_json::json!(0));
        assert_eq!(json["bytesReclaimable"], serde_json::json!(0));

        // Corrupt manifest, fresh tempdir.
        let tmp = tempfile::tempdir().unwrap();
        let (manifest_path, socket_dir, blob_path) =
            seed_blob_without_manifest(tmp.path(), &"e".repeat(64));
        std::fs::write(&manifest_path, "{ not json").unwrap();
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
            "preview of a corrupt manifest must report zero orphans"
        );
        assert_eq!(gc.total_bytes(), 0);
        assert!(blob_path.exists(), "preview must not delete the blob");
        assert_eq!(
            std::fs::read_to_string(&manifest_path).unwrap(),
            "{ not json",
            "preview must not rewrite the corrupt manifest"
        );
    }

    // ---- lockfile-unused vendored entry in the preview ----------------------

    #[tokio::test]
    async fn preview_counts_blobs_of_lockfile_unused_vendored_entry() {
        // A vendored entry whose dependency left the lockfile graph: the wet
        // pass reverts it AND drops its manifest entry, so its blob is freed
        // in the same run. The preview must mirror that — drop the entry's
        // manifest keys in memory before the orphan sweep — or `--dry-run`
        // under-reports orphanBlobs/bytesReclaimable vs the real `--prune`.
        // Note the vendored exemption set deliberately contains the purl:
        // detect_prunable exempts it (gc.pruned stays empty), so ONLY the
        // vendor-gc mirror loop can surface the blob as reclaimable.
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
                ecosystem: "npm".into(),
                base_purl: PURL.into(),
                uuid: UUID.into(),
                artifact: socket_patch_core::vendor::state::VendorArtifact {
                    path: format!(".socket/vendor/npm/{UUID}/gone-1.0.0.tgz"),
                    sha256: String::new(),
                    size: None,
                    platform_locked: None,
                    file_inventory: None,
                },
                wiring: Vec::new(),
                lock: None,
                took_over_go_patches: false,
                detached: false,
                record: None,
                flavor: Some("package-lock".into()),
                uv: None,
                pnpm: None,
                poetry: None,
                pdm: None,
                pipenv: None,
            },
        );
        socket_patch_core::vendor::save_state(tmp.path(), &state)
            .await
            .unwrap();
        let state_before =
            std::fs::read(tmp.path().join(".socket/vendor/state.json")).unwrap();

        let vendored: HashSet<String> = [PURL.to_string()].into_iter().collect();
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
            "bytesReclaimable must include the unused entry's blob"
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

    // ---- drift-kept vendored entry in the wet pass ---------------------------

    /// A vendored entry whose lock fragment DRIFTED since vendoring (fork
    /// re-resolve): the in-use probe calls it unused, but the wet revert
    /// refuses to touch the drifted lock and keeps artifacts, ledger entry
    /// and manifest record. The preview cannot see drift and lists the
    /// entry as revertable, so the wet `scan --prune` reclaims nothing —
    /// pre-fix, with zero explanation (the kept purl was counted nowhere
    /// and both call sites dropped the backend's vendor_artifact_kept
    /// warning). The keep must surface as `keptVendoredEntries` in the
    /// apply JSON.
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
                ecosystem: "npm".into(),
                base_purl: PURL.into(),
                uuid: UUID.into(),
                artifact: socket_patch_core::vendor::state::VendorArtifact {
                    path: format!(".socket/vendor/npm/{UUID}/gone-1.0.0.tgz"),
                    sha256: String::new(),
                    size: None,
                    platform_locked: None,
                    file_inventory: None,
                },
                wiring: vec![WiringRecord {
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
                lock: None,
                took_over_go_patches: false,
                detached: false,
                record: None,
                flavor: Some("package-lock".into()),
                uv: None,
                pnpm: None,
                poetry: None,
                pdm: None,
                pipenv: None,
            },
        );
        socket_patch_core::vendor::save_state(tmp.path(), &state)
            .await
            .unwrap();

        let vendored: HashSet<String> = [PURL.to_string()].into_iter().collect();
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
            vec![PURL.to_string()],
            "the keep must be counted — the only signal that the entry the \
             preview listed as revertable was deliberately not reclaimed"
        );
        assert_eq!(
            gc.to_apply_json()["keptVendoredEntries"],
            serde_json::json!([PURL]),
            "scan --prune --json must carry the keep"
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

    /// The `keptVendoredEntries` / `failedVendoredEntries` / `skipped` /
    /// `warnings` plumbing in isolation: absorbed sorted, serialized on the
    /// apply shape, absent from the preview shape (a read-only preview
    /// cannot detect drift, reverts nothing and takes no lock, so emitting
    /// a constant `[]`/marker would claim a check that never ran). The
    /// vendored half's typed fields land where they belong: `failed` holds
    /// only purls, its lock skip becomes the `skipped` reason, its failed
    /// rewrites become `warnings` — never mislabelled as `lock_held`.
    #[test]
    fn gc_json_shapes_carry_drift_keeps_only_on_apply() {
        const LOCK_MARKER: &str = "vendor GC skipped: another socket-patch run holds the apply lock";
        let mut gc = GcSummary::default();
        gc.absorb_vendor_gc(VendorGcSummary {
            kept: vec!["pkg:npm/b@1.0.0".into(), "pkg:npm/a@1.0.0".into()],
            failed: vec!["pkg:npm/d@1.0.0".into(), "pkg:npm/c@1.0.0".into()],
            skipped: Some(("lock_held", LOCK_MARKER.into())),
            write_failures: vec![(
                "vendor_state_write_failed",
                "reverted vendored entries but could not update .socket/vendor/state.json: EROFS"
                    .into(),
            )],
            ..Default::default()
        });
        assert_eq!(
            gc.vendored_kept,
            vec!["pkg:npm/a@1.0.0".to_string(), "pkg:npm/b@1.0.0".to_string()],
            "absorb must sort, like every other purl list"
        );
        assert_eq!(
            gc.vendored_failed,
            vec!["pkg:npm/c@1.0.0".to_string(), "pkg:npm/d@1.0.0".to_string()],
            "failed reverts are absorbed sorted"
        );
        assert_eq!(
            gc.skipped,
            Some(("lock_held", LOCK_MARKER.to_string())),
            "the vendored half's lock skip is the skip reason"
        );
        let apply = gc.to_apply_json();
        assert_eq!(
            apply["keptVendoredEntries"],
            serde_json::json!(["pkg:npm/a@1.0.0", "pkg:npm/b@1.0.0"])
        );
        assert_eq!(
            apply["failedVendoredEntries"],
            serde_json::json!(["pkg:npm/c@1.0.0", "pkg:npm/d@1.0.0"])
        );
        assert_eq!(apply["revertedVendoredEntries"], serde_json::json!([]));
        assert_eq!(apply["skipped"]["code"], "lock_held", "{apply}");
        assert_eq!(
            apply["warnings"],
            serde_json::json!([{
                "code": "vendor_state_write_failed",
                "detail": "reverted vendored entries but could not update \
                           .socket/vendor/state.json: EROFS",
            }]),
            "{apply}"
        );
        let preview = gc.to_preview_json();
        for key in [
            "keptVendoredEntries",
            "failedVendoredEntries",
            "skipped",
            "warnings",
        ] {
            assert!(
                preview.get(key).is_none(),
                "preview must not claim a check it cannot run ({key}): {preview}"
            );
        }

        // A pass that took its own lock fine reports NO skip and NO
        // warnings, and the apply shape omits both keys entirely (additive:
        // absent, not null).
        let clean = GcSummary::vendor_only(VendorGcSummary::default());
        assert!(clean.skipped.is_none());
        let clean_json = clean.to_apply_json();
        assert!(clean_json.get("skipped").is_none(), "{clean_json}");
        assert!(clean_json.get("warnings").is_none(), "{clean_json}");
        // This pass's own reason wins over the vendored half's skip.
        let mut own = GcSummary {
            skipped: Some(("lock_io", "failed to open lock file".to_string())),
            ..Default::default()
        };
        own.absorb_vendor_gc(VendorGcSummary {
            skipped: Some(("lock_held", LOCK_MARKER.into())),
            ..Default::default()
        });
        assert_eq!(own.skipped.as_ref().map(|(c, _)| *c), Some("lock_io"));
        // A `lock_io` fault or a failed rewrite in the vendored half is
        // never reported as contention (the pre-fix `starts_with("pkg:")`
        // partition labelled every non-purl marker `lock_held`).
        let mut io = GcSummary::default();
        io.absorb_vendor_gc(VendorGcSummary {
            skipped: Some(("lock_io", "could not open apply.lock".into())),
            write_failures: vec![("manifest_write_failed", "could not update manifest".into())],
            ..Default::default()
        });
        assert_eq!(io.skipped.as_ref().map(|(c, _)| *c), Some("lock_io"));
        assert_eq!(io.to_apply_json()["warnings"][0]["code"], "manifest_write_failed");
        assert!(io.vendored_failed.is_empty());
    }
}
