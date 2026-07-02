use clap::Args;
use socket_patch_core::api::client::{
    build_proxy_fallback_client, get_api_client_with_overrides, is_fallback_candidate,
};
use socket_patch_core::api::types::{BatchPackagePatches, PatchSearchResult};
use socket_patch_core::crawlers::{CrawlerOptions, Ecosystem};
use socket_patch_core::manifest::operations::{read_manifest, write_manifest};
use socket_patch_core::manifest::schema::{PatchManifest, PatchRecord};
use socket_patch_core::patch::apply_lock;
use socket_patch_core::utils::cleanup_blobs::{
    cleanup_unused_archives, cleanup_unused_blobs, CleanupResult,
};
use socket_patch_core::utils::purl::{normalize_purl, strip_purl_qualifiers};
use socket_patch_core::utils::telemetry::{
    track_patch_scan_failed, track_patch_scanned, track_patch_vendor_failed, track_patch_vendored,
};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::Duration;

use crate::args::{apply_env_toggles, GlobalArgs};
use crate::commands::fetch_stage::{stage_vendor_sources_in_memory, MemStageOutcome};
use crate::commands::vex::{generate_vex_from_manifest_path, VexEmbedArgs};
use crate::ecosystem_dispatch::crawl_all_ecosystems;
use crate::json_envelope::{Command as EnvelopeCommand, Envelope};
use crate::output::{color, confirm, format_severity, stderr_is_tty, stdout_is_tty};

use super::get::{
    download_and_apply_patches, download_patch_records, select_patches, truncate_with_ellipsis,
    DownloadParams,
};
use super::vendor::{reconcile_dropped, vendor_records};

const DEFAULT_BATCH_SIZE: usize = 100;

/// Surfaced in `scan --json` output. Tells a bot which PURLs in the discovery
/// would replace an existing manifest entry with a newer UUID. Stable schema —
/// see CLI_CONTRACT.md (`scan` JSON output / `updates` field).
#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct UpdateInfo {
    pub purl: String,
    pub old_uuid: String,
    pub new_uuid: String,
}

/// Aggregated outcome of a GC pass (or preview). Serialized into the
/// `scan --json` output's `gc` sub-object. See CLI_CONTRACT.md for the
/// stable schema.
#[derive(Debug, Default)]
pub(crate) struct GcSummary {
    /// PURLs removed from the manifest (apply mode) or eligible to be
    /// removed (preview mode).
    pub pruned: Vec<String>,
    pub blobs: CleanupResult,
    pub diffs: CleanupResult,
    pub packages: CleanupResult,
    /// Vendored entries reverted (or revertable, preview mode) because
    /// their patch is gone from the manifest or their dependency left the
    /// lockfile graph — see `vendor::run_vendor_gc`. Sorted.
    pub vendored_reverted: Vec<String>,
    /// Orphan `.socket/vendor/<eco>/<uuid>` dirs swept (or sweepable).
    pub vendor_orphan_dirs: usize,
    /// `true` when `--no-prune` was set; the sub-object only carries the
    /// `skipped: true` field in that case.
    pub skipped: bool,
}

impl GcSummary {
    fn total_bytes(&self) -> u64 {
        self.blobs.bytes_freed + self.diffs.bytes_freed + self.packages.bytes_freed
    }

    /// Fold a vendored-state GC pass into this summary.
    fn absorb_vendor_gc(&mut self, v: super::vendor::VendorGcSummary) {
        self.vendored_reverted = v
            .dropped_reverted
            .into_iter()
            .chain(v.unused_reverted)
            .collect();
        self.vendored_reverted.sort();
        self.vendor_orphan_dirs = v.orphan_dirs;
    }

    /// Serialize for a *mutating* GC pass (post-apply).
    fn to_apply_json(&self) -> serde_json::Value {
        if self.skipped {
            return serde_json::json!({ "skipped": true });
        }
        serde_json::json!({
            "prunedManifestEntries": self.pruned,
            "removedBlobs": self.blobs.blobs_removed,
            "removedDiffArchives": self.diffs.blobs_removed,
            "removedPackageArchives": self.packages.blobs_removed,
            "revertedVendoredEntries": self.vendored_reverted,
            "removedVendorOrphanDirs": self.vendor_orphan_dirs,
            "bytesFreed": self.total_bytes(),
        })
    }

    /// Serialize for a *non-mutating* GC pass (read-only preview).
    fn to_preview_json(&self) -> serde_json::Value {
        if self.skipped {
            return serde_json::json!({ "skipped": true });
        }
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

/// Compute GC actions without performing them. `dry_run = true` for the
/// preview path; `dry_run = false` for the apply path. The cleanup helpers
/// from `socket_patch_core::utils::cleanup_blobs` natively support dry-run,
/// so the same function works for both.
async fn run_gc(
    manifest: &PatchManifest,
    pruned: Vec<String>,
    socket_dir: &Path,
    dry_run: bool,
) -> GcSummary {
    let blobs = cleanup_unused_blobs(manifest, &socket_dir.join("blobs"), dry_run)
        .await
        .unwrap_or_default();
    let diffs = cleanup_unused_archives(manifest, &socket_dir.join("diffs"), dry_run)
        .await
        .unwrap_or_default();
    let packages = cleanup_unused_archives(manifest, &socket_dir.join("packages"), dry_run)
        .await
        .unwrap_or_default();
    GcSummary {
        pruned,
        blobs,
        diffs,
        packages,
        skipped: false,
        ..Default::default()
    }
}

/// Apply-mode GC: re-read the manifest written by `download_and_apply_patches`,
/// prune manifest entries for PURLs not in `scanned_purls`, write the manifest
/// back, then sweep orphan blob/diff/package files. Callers must gate on the
/// `prune` flag — when GC isn't requested, simply don't call this function and
/// don't emit a `gc` sub-object.
async fn run_apply_gc(
    common: &crate::args::GlobalArgs,
    manifest_path: &Path,
    socket_dir: &Path,
    scanned_purls: &HashSet<String>,
    vendored: &HashSet<String>,
) -> GcSummary {
    // Vendored-state GC FIRST: it reverts manifest-dropped and
    // lockfile-unused vendored entries, dropping the latter's manifest
    // entries — so the manifest prune + blob sweep below reclaims their
    // blobs in this same pass (and the stale `vendored` exemption set is
    // harmless: the entries it would exempt are already gone).
    let vendor_gc = super::vendor::run_vendor_gc(common, manifest_path, /*dry_run=*/ false).await;

    // Re-read the just-written manifest (the apply step may have added
    // or updated entries we now want to consider for pruning).
    let mut manifest = match read_manifest(manifest_path).await {
        Ok(Some(m)) => m,
        _ => {
            let mut gc = GcSummary::default();
            gc.absorb_vendor_gc(vendor_gc);
            return gc;
        }
    };
    let prunable = detect_prunable(&manifest, scanned_purls, vendored);
    for purl in &prunable {
        manifest.patches.remove(purl);
    }
    if !prunable.is_empty() {
        // If pruning failed mid-write the manifest may be stale, but the
        // file-level cleanup below still operates on the in-memory copy.
        let _ = write_manifest(manifest_path, &manifest).await;
    }
    let mut gc = run_gc(&manifest, prunable, socket_dir, /*dry_run=*/ false).await;
    gc.absorb_vendor_gc(vendor_gc);
    gc
}

/// Dry-run preview of the apply-mode GC pass. Same shape as
/// [`run_apply_gc`] but emits `prunable*`/`orphan*` field names and
/// performs no mutation.
async fn preview_apply_gc(
    common: &crate::args::GlobalArgs,
    manifest_path: &Path,
    socket_dir: &Path,
    scanned_purls: &HashSet<String>,
    vendored: &HashSet<String>,
) -> GcSummary {
    // Read-only preview of the vendored-state GC (lists, never reverts).
    let vendor_gc = super::vendor::run_vendor_gc(common, manifest_path, /*dry_run=*/ true).await;

    let mut manifest = match read_manifest(manifest_path).await {
        Ok(Some(m)) => m,
        _ => {
            let mut gc = GcSummary::default();
            gc.absorb_vendor_gc(vendor_gc);
            return gc;
        }
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
pub(crate) fn detect_prunable(
    manifest: &PatchManifest,
    scanned_purls: &HashSet<String>,
    vendored: &HashSet<String>,
) -> Vec<String> {
    let scanned_bases: HashSet<String> = scanned_purls
        .iter()
        .map(|p| normalize_purl(strip_purl_qualifiers(p)).into_owned())
        .collect();
    manifest
        .patches
        .keys()
        .filter(|p| {
            let base = normalize_purl(strip_purl_qualifiers(p));
            !scanned_bases.contains(base.as_ref())
                && !vendored.contains(p.as_str())
                && !vendored.contains(strip_purl_qualifiers(p))
        })
        .cloned()
        .collect()
}

/// Lockfile-only packages: dependencies the project's lockfile resolves
/// that have no crawled (installed) counterpart.
#[derive(Default)]
struct LockfileSupplement {
    packages: Vec<socket_patch_core::crawlers::types::CrawledPackage>,
    /// Literal crawler-form purls, for fast membership tests.
    purls: HashSet<String>,
    /// The lockfile the entries came from, for messages.
    source: &'static str,
}

/// Inventory the project's lockfile(s) and fabricate crawl entries for
/// dependencies that are not installed. The fabricated `path` is the
/// WOULD-BE install dir — every consumer degrades safely on a nonexistent
/// path (hash verify → NotFound, apply → partitioned skip, vendor →
/// auto-fetch). Global scans target the machine's global tree, not this
/// project's lockfile, so they get no supplement.
async fn lockfile_supplement(
    common: &GlobalArgs,
    crawled: &[socket_patch_core::crawlers::types::CrawledPackage],
) -> LockfileSupplement {
    use socket_patch_core::patch::vendor::lock_inventory;

    let mut out = LockfileSupplement {
        source: "project lockfiles",
        ..Default::default()
    };
    if common.global || common.global_prefix.is_some() {
        return out;
    }
    let entries = lock_inventory::inventory_project(&common.cwd).await;
    if entries.is_empty() {
        return out;
    }
    let crawled_purls: HashSet<&str> = crawled.iter().map(|p| p.purl.as_str()).collect();
    for entry in entries {
        if crawled_purls.contains(entry.purl.as_str()) {
            continue;
        }
        let Some(pkg) = crawled_from_purl(&entry.purl, &common.cwd) else {
            continue;
        };
        out.purls.insert(entry.purl.clone());
        out.packages.push(pkg);
    }
    out
}

/// A displayable crawl entry fabricated from a purl (decoded form). The
/// path is a placeholder consumers degrade safely on.
fn crawled_from_purl(
    purl: &str,
    cwd: &std::path::Path,
) -> Option<socket_patch_core::crawlers::types::CrawledPackage> {
    let decoded = normalize_purl(strip_purl_qualifiers(purl)).into_owned();
    let rest = decoded.strip_prefix("pkg:")?;
    let (_eco, rest) = rest.split_once('/')?;
    let at = rest.rfind('@').filter(|&i| i > 0)?;
    let (name_part, version) = (&rest[..at], &rest[at + 1..]);
    let (namespace, name) = match name_part.rsplit_once('/') {
        Some((ns, n)) => (Some(ns.to_string()), n.to_string()),
        None => (None, name_part.to_string()),
    };
    Some(socket_patch_core::crawlers::types::CrawledPackage {
        name,
        version: version.to_string(),
        namespace,
        purl: decoded.clone(),
        path: cwd.join("node_modules").join(name_part),
    })
}

/// Vendored-ledger packages with no crawled counterpart: on a fresh clone
/// the committed artifact IS the dependency, so these stay discoverable
/// (updates[] detection, the table, and `scan --vendor` re-vendor/in-sync
/// runs all keep working before any install). They are NOT "lockfile-only"
/// — nothing needs installing; the artifact satisfies the lock.
async fn vendored_ledger_supplement(
    common: &GlobalArgs,
    crawled: &[socket_patch_core::crawlers::types::CrawledPackage],
) -> Vec<socket_patch_core::crawlers::types::CrawledPackage> {
    if common.global || common.global_prefix.is_some() {
        return Vec::new();
    }
    let Ok(state) = socket_patch_core::patch::vendor::load_state(&common.cwd).await else {
        return Vec::new();
    };
    let crawled_norm: HashSet<String> = crawled
        .iter()
        .map(|p| normalize_purl(&p.purl).into_owned())
        .collect();
    let mut seen: HashSet<String> = HashSet::new();
    let mut out = Vec::new();
    for entry in state.entries.values() {
        let base = strip_purl_qualifiers(&entry.base_purl);
        let norm = normalize_purl(base).into_owned();
        if crawled_norm.contains(&norm) || !seen.insert(norm) {
            continue;
        }
        if let Some(pkg) = crawled_from_purl(base, &common.cwd) {
            out.push(pkg);
        }
    }
    out.sort_by(|a, b| a.purl.cmp(&b.purl));
    out
}

/// Vendor-mode pre-prompt check: uuids of selected patches whose installed
/// files match NEITHER beforeHash nor afterHash — the patch was built
/// against different bytes than the installed artifact. Vendoring still
/// succeeds for these (the vendor stage force-applies the verified patched
/// content; see `force_apply_staged`), but the user should learn it BEFORE
/// the confirm prompt, not from a post-hoc warning event.
///
/// Best-effort and read-only: a detail-fetch failure or an unresolvable
/// installed path just skips the annotation — it never blocks the flow and
/// writes nothing (unlike `download_patch_records`, which stages blobs).
async fn preverify_vendor_baselines(
    api_client: &socket_patch_core::api::client::ApiClient,
    org_slug: Option<&str>,
    selected: &[PatchSearchResult],
    crawled: &[socket_patch_core::crawlers::types::CrawledPackage],
    lockfile_only: &HashSet<String>,
) -> HashSet<String> {
    use socket_patch_core::manifest::schema::PatchFileInfo;
    use socket_patch_core::patch::apply::{verify_file_patch, VerifyStatus};
    use socket_patch_core::utils::purl::purl_eq;

    let mut mismatched: HashSet<String> = HashSet::new();
    for patch in selected {
        // API purls come percent-encoded, crawler purls literal — purl_eq
        // bridges the two spellings.
        let base = strip_purl_qualifiers(&patch.purl);
        // Lockfile-only packages have no installed bytes to compare — the
        // vendor engine fetches them pristine (nothing to annotate).
        if lockfile_only.contains(normalize_purl(base).as_ref()) {
            continue;
        }
        let Some(pkg) = crawled.iter().find(|c| purl_eq(&c.purl, base)) else {
            continue;
        };
        let Ok(Some(detail)) = api_client.fetch_patch(org_slug, &patch.uuid).await else {
            continue;
        };
        for (file, info) in &detail.files {
            let info = PatchFileInfo {
                before_hash: info.before_hash.clone().unwrap_or_default(),
                after_hash: info.after_hash.clone().unwrap_or_default(),
            };
            if info.before_hash.is_empty() {
                continue; // a new file has no baseline to compare
            }
            if verify_file_patch(&pkg.path, file, &info).await.status == VerifyStatus::HashMismatch
            {
                mismatched.insert(patch.uuid.clone());
                break;
            }
        }
    }
    mismatched
}

/// Cross-reference an existing manifest against discovery results to find
/// PURLs whose newest available patch UUID differs from the locally-recorded
/// one. Used by both the discovery JSON path and the table-print path.
/// Pure / no I/O so it's unit-testable.
pub(crate) fn detect_updates(
    existing_manifest: Option<&PatchManifest>,
    packages: &[BatchPackagePatches],
) -> Vec<UpdateInfo> {
    let Some(manifest) = existing_manifest else {
        return Vec::new();
    };
    let mut updates = Vec::new();
    for pkg in packages {
        let Some(existing) = manifest.patches.get(&pkg.purl) else {
            continue;
        };
        // Treat the first patch in the batch as the candidate the apply path
        // would resolve to (mirrors `select_patches` ordering — newest-first
        // for paid users, single-patch auto-select for free).
        let Some(candidate) = pkg.patches.first() else {
            continue;
        };
        if candidate.uuid != existing.uuid {
            updates.push(UpdateInfo {
                purl: pkg.purl.clone(),
                old_uuid: existing.uuid.clone(),
                new_uuid: candidate.uuid.clone(),
            });
        }
    }
    updates
}

/// Collect the deduplicated CVE and GHSA identifiers across every patch of
/// a package, for the scan table's VULNERABILITIES column. CVEs are listed
/// before GHSAs and each group is sorted, so the rendered output is stable —
/// the per-patch ID lists and set-based dedup are otherwise nondeterministic
/// in order. Pure / no I/O so it's unit-testable.
pub(crate) fn collect_vuln_ids(pkg: &BatchPackagePatches) -> Vec<String> {
    let mut cves: HashSet<String> = HashSet::new();
    let mut ghsas: HashSet<String> = HashSet::new();
    for patch in &pkg.patches {
        for cve in &patch.cve_ids {
            cves.insert(cve.clone());
        }
        for ghsa in &patch.ghsa_ids {
            ghsas.insert(ghsa.clone());
        }
    }
    let mut cves: Vec<String> = cves.into_iter().collect();
    cves.sort();
    let mut ghsas: Vec<String> = ghsas.into_iter().collect();
    ghsas.sort();
    cves.into_iter().chain(ghsas).collect()
}

/// The three patch-application modes `scan` can drive, selectable via
/// `--mode` (the documented spelling). Each variant is equivalent to one
/// legacy boolean flag, which remains supported as an alias.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanMode {
    /// Rewrite lockfiles so ONLY patched dependencies resolve to Socket's
    /// hosted patch server (== `--redirect`): no artifact bytes land in the
    /// repo, but installs must reach the patch server.
    Hosted,
    /// Commit patched artifacts to `.socket/vendor/` (== `--vendor`):
    /// hermetic, offline-safe installs at the cost of repo size.
    Vendored,
    /// Record patches in `.socket/manifest.json` + blobs and re-apply them
    /// in place, e.g. from CI (== `--apply`): smallest repo footprint, but
    /// every install environment must run the agent.
    Agent,
}

impl ScanMode {
    /// The CLI spelling of the variant (`--mode <name>`), for error messages.
    fn cli_name(self) -> &'static str {
        match self {
            ScanMode::Hosted => "hosted",
            ScanMode::Vendored => "vendored",
            ScanMode::Agent => "agent",
        }
    }
}

/// Fold `--mode` into the legacy boolean spellings (`--redirect` /
/// `--vendor` / `--apply`) so everything downstream keeps a single source
/// of truth, and enforce the cross-flag rules clap cannot express:
///
/// * `--mode X` combined with a boolean belonging to a DIFFERENT mode is a
///   contradiction → `Err`. Clap's `conflicts_with` is value-independent —
///   it could not allow `--mode vendored --vendor` while rejecting
///   `--mode hosted --vendor` — so the check lives here.
/// * The same mode spelled both ways (`--mode vendored --vendor`) is
///   redundant but accepted: both spellings mean one thing.
/// * `--sync` implies `--apply`, so it counts as an agent-mode spelling;
///   `--prune` is an orthogonal GC knob and never conflicts.
/// * `--detached` requires vendored mode in either spelling. The former
///   clap-level `requires = "vendor"` couldn't see `--mode vendored`, so
///   the requirement moved here too.
///
/// Public (not `pub(crate)`) so the CLI-contract tests can exercise the
/// fold without driving a full `run()`.
pub fn resolve_mode_flags(args: &mut ScanArgs) -> Result<(), String> {
    if let Some(mode) = args.mode {
        // First boolean that selects a mode OTHER than the requested one.
        let mut conflicting: Option<&'static str> = None;
        if args.redirect && mode != ScanMode::Hosted {
            conflicting = Some("--redirect");
        }
        if args.vendor && mode != ScanMode::Vendored {
            conflicting = Some("--vendor");
        }
        if args.apply && mode != ScanMode::Agent {
            conflicting = Some("--apply");
        }
        if args.sync && mode != ScanMode::Agent {
            conflicting = Some("--sync");
        }
        if let Some(flag) = conflicting {
            // "cannot be used with" phrasing matches clap's conflict errors —
            // the scan_vendor_e2e contract test accepts exactly that shape.
            return Err(format!(
                "--mode {} cannot be used with {flag}: the flags select different \
                 modes (hosted == --redirect, vendored == --vendor, agent == --apply/--sync)",
                mode.cli_name(),
            ));
        }
        match mode {
            ScanMode::Hosted => args.redirect = true,
            ScanMode::Vendored => args.vendor = true,
            ScanMode::Agent => args.apply = true,
        }
    }
    if args.detached && !args.vendor {
        // "required" phrasing matches clap's requires errors — the
        // scan_vendor_e2e contract test accepts exactly that shape.
        return Err(
            "--detached requires vendored mode: --mode vendored or --vendor is required"
                .to_string(),
        );
    }
    Ok(())
}

#[derive(Args)]
pub struct ScanArgs {
    #[command(flatten)]
    pub common: GlobalArgs,

    /// Number of packages to query per API request.
    #[arg(long = "batch-size", env = "SOCKET_BATCH_SIZE", default_value_t = DEFAULT_BATCH_SIZE)]
    pub batch_size: usize,

    /// Download and apply selected patches in JSON mode (non-interactive).
    /// Without this flag, `scan --json` is read-only — it lists available
    /// patches plus an `updates` array but does not mutate the manifest.
    /// Designed for unattended workflows (cron jobs, bots that open PRs);
    /// pair with `--yes` for clarity though `--json` already implies non-
    /// interactive confirmation. No effect outside `--json` mode (the
    /// non-JSON path always prompts the user). `--mode agent` is the
    /// documented spelling of this mode.
    #[arg(long, default_value_t = false)]
    pub apply: bool,

    /// Garbage-collect after the scan: prune manifest entries for
    /// packages no longer present in the crawl, then delete orphan
    /// blob, diff, and package-archive files from `.socket/`. Off by
    /// default to preserve manifest state across temporary uninstalls;
    /// pair with `--apply` (or use `--sync`) for the auto-update
    /// workflow.
    #[arg(long, default_value_t = false)]
    pub prune: bool,

    /// Convenience flag for the auto-update workflow: implies both
    /// `--apply` and `--prune`. Designed so a cron job or CI workflow
    /// can run `socket-patch scan --json --sync --yes` and end up in a
    /// fully-reconciled state in one invocation.
    #[arg(long, default_value_t = false)]
    pub sync: bool,

    /// Vendor every patched dependency into the committable
    /// `.socket/vendor/` tree instead of applying patches in place:
    /// download the selected patches, record them in the manifest, then
    /// build + wire the vendored artifacts (the whole manifest is
    /// vendored, so a package vendored at an older patch uuid is
    /// re-vendored automatically). Conflicts with `--apply`/`--sync`
    /// (vendoring replaces the in-place apply); combine with `--prune`
    /// to drop uninstalled entries before they fail vendoring. JSON mode
    /// is non-interactive like `--apply`; the interactive path prompts
    /// before downloading. `--mode vendored` is the documented spelling
    /// of this mode.
    #[arg(long, default_value_t = false, conflicts_with_all = ["apply", "sync"])]
    pub vendor: bool,

    /// With vendored mode (`--mode vendored` / `--vendor`): do not write
    /// `.socket/manifest.json` entries — the vendor ledger
    /// (`.socket/vendor/state.json`) carries an embedded copy of each
    /// patch record instead. Detached patches are invisible to
    /// apply/rollback/repair (nothing is in the manifest); they are
    /// undone per-purl via `remove <purl>` or wholesale via
    /// `vendor --revert`, and are exempt from `vendor`'s manifest
    /// reconcile. The vendored-mode requirement is enforced in
    /// `resolve_mode_flags` (not clap `requires`) so `--mode vendored`
    /// satisfies it too.
    #[arg(long, default_value_t = false)]
    pub detached: bool,

    /// Redirect every patched dependency to Socket's HOSTED vendored patches
    /// by rewriting lockfiles/registry configs so ONLY the patched dependency
    /// points at the patch-server (`--patch-server-url`), instead of applying
    /// patches in place or ejecting local artifacts. This is the remote
    /// counterpart of `--vendor`: no artifact bytes land in the repo — the
    /// lockfile pins the hosted URL + integrity (npm/pypi/composer) or a
    /// per-dependency registry override (cargo/nuget/gem/…). Conflicts with
    /// `--apply`/`--sync`/`--vendor`. Hidden from help: the flag is
    /// unreleased and `--mode hosted` is the documented spelling.
    #[arg(long, default_value_t = false, hide = true, conflicts_with_all = ["apply", "sync", "vendor"])]
    pub redirect: bool,

    /// How discovered patches are consumed — the documented selector for
    /// the three modes (each is equivalent to one boolean flag, kept as an
    /// alias):
    ///
    /// * `hosted` (== `--redirect`): rewrite lockfiles so only patched
    ///   dependencies resolve to Socket's hosted patch server — no
    ///   artifact bytes in the repo, but installs must reach the server.
    /// * `vendored` (== `--vendor`): commit patched artifacts under
    ///   `.socket/vendor/` — hermetic, offline-safe installs at the cost
    ///   of repo size.
    /// * `agent` (== `--apply`): record patches in `.socket/manifest.json`
    ///   plus blobs and re-apply in place — smallest repo footprint, but
    ///   every environment must run the agent.
    ///
    /// Combining `--mode` with a boolean flag from a DIFFERENT mode is
    /// rejected (see `resolve_mode_flags`); the same mode spelled both
    /// ways is accepted.
    #[arg(long = "mode", value_enum)]
    pub mode: Option<ScanMode>,

    /// Download patches for every release/distribution variant of a
    /// matched package, not just the one(s) matching the locally-
    /// installed distribution. Affects ecosystems with per-release
    /// variants — PyPI (wheel/sdist via `artifact_id`), RubyGems
    /// (`platform`), and Maven (`classifier`). Off by default: narrow
    /// scans store only the patch(es) for the installed dist, keeping
    /// `.socket/` small; `--all-releases` makes the manifest portable
    /// across environments (e.g. cross-platform CI caches).
    #[arg(
        long = "all-releases",
        env = "SOCKET_ALL_RELEASES",
        default_value_t = false,
        value_parser = clap::builder::BoolishValueParser::new(),
    )]
    pub all_releases: bool,

    /// On a successful scan, also generate an OpenVEX 0.2.0 document.
    /// `--vex <path>` is the trigger; the `--vex-*` knobs mirror the
    /// standalone `vex` command. The document is built from the manifest
    /// as it stands after the scan (including any `--apply`/`--sync`
    /// writes) and verified against on-disk state. A requested-but-failed
    /// VEX makes the command exit non-zero.
    #[command(flatten)]
    pub vex: VexEmbedArgs,
}

/// Embedded-VEX side-effect for `scan`'s JSON terminal returns. When
/// `--vex` was requested and `base_code` is 0, generate the OpenVEX
/// document from the post-scan manifest and fold the outcome into
/// `result` — a `vex` object on success, or `status: "error"` + `error`
/// on failure (per the fail-the-command contract). Returns the final exit
/// code: `base_code` when not requested / skipped / on VEX success, `1`
/// when VEX generation failed. Caller prints `result` after this returns.
async fn embed_vex_into_json(
    common: &GlobalArgs,
    vex_args: &VexEmbedArgs,
    manifest_path: &Path,
    base_code: i32,
    result: &mut serde_json::Value,
) -> i32 {
    if vex_args.vex.is_none() || base_code != 0 {
        return base_code;
    }
    let params = vex_args.to_build_params();
    match generate_vex_from_manifest_path(common, &params, manifest_path).await {
        Ok(summary) => {
            result["vex"] = serde_json::json!({
                "path": vex_args.vex.as_ref().unwrap().display().to_string(),
                "statements": summary.statements,
                "format": "openvex-0.2.0",
            });
            0
        }
        Err(e) => {
            result["status"] = serde_json::json!("error");
            result["error"] = serde_json::json!({
                "code": e.code,
                "message": e.message,
            });
            1
        }
    }
}

/// Embedded-VEX side-effect for `scan`'s human-readable terminal returns.
/// Prints a one-line note (or error) and returns the final exit code:
/// `base_code` when not requested / skipped / on VEX success, `1` on VEX
/// failure. No-op unless `--vex` was set and `base_code` is 0.
async fn embed_vex_human(
    common: &GlobalArgs,
    vex_args: &VexEmbedArgs,
    manifest_path: &Path,
    base_code: i32,
) -> i32 {
    if vex_args.vex.is_none() || base_code != 0 {
        return base_code;
    }
    let params = vex_args.to_build_params();
    match generate_vex_from_manifest_path(common, &params, manifest_path).await {
        Ok(summary) => {
            if !common.silent {
                println!(
                    "Wrote OpenVEX document with {} statement(s) to {}",
                    summary.statements,
                    vex_args.vex.as_ref().unwrap().display(),
                );
            }
            0
        }
        Err(e) => {
            if !common.silent {
                eprintln!("Error: VEX generation failed: {}", e.message);
            }
            1
        }
    }
}

/// Dry-run preview for `scan --vendor`: classify each selected patch
/// against the vendor ledger without touching disk or the network beyond
/// discovery. Action values are part of the CLI contract:
/// `would_vendor` (no ledger entry), `already_vendored` (entry at this
/// uuid), `would_revendor` + `oldUuid` (entry at an older uuid).
async fn preview_vendor_json(cwd: &Path, selected: &[PatchSearchResult]) -> serde_json::Value {
    let state = socket_patch_core::patch::vendor::load_state(cwd)
        .await
        .unwrap_or_default();
    let mut patches: Vec<serde_json::Value> = selected
        .iter()
        .map(|p| {
            let entry = state
                .entries
                .get(&p.purl)
                .or_else(|| state.entries.values().find(|e| e.base_purl == p.purl));
            match entry {
                Some(e) if e.uuid == p.uuid => serde_json::json!({
                    "purl": p.purl, "uuid": p.uuid, "action": "already_vendored",
                }),
                Some(e) => serde_json::json!({
                    "purl": p.purl, "uuid": p.uuid,
                    "action": "would_revendor", "oldUuid": e.uuid,
                }),
                None => serde_json::json!({
                    "purl": p.purl, "uuid": p.uuid, "action": "would_vendor",
                }),
            }
        })
        .collect();
    patches.sort_by(|a, b| a["purl"].as_str().cmp(&b["purl"].as_str()));
    serde_json::json!({ "dryRun": true, "patches": patches })
}

/// The vendor step shared by `scan --vendor`'s JSON and interactive
/// paths: acquire the apply lock, stage patch sources, and drive
/// [`vendor_records`] — manifest mode (`detached_records: None`, records
/// come from re-reading the manifest, preceded by the same reconcile as
/// the `vendor` command) or detached mode (`Some(records)` from
/// [`download_patch_records`]; no manifest involvement at all).
///
/// `Ok((has_errors, envelope))` on a run that reached the engine;
/// `Err((code, message))` for the lock/stage/manifest failures the
/// caller folds into its own output shape (scan's ad-hoc JSON can't use
/// `acquire_or_emit`, which prints an Envelope).
async fn run_scan_vendor_step(
    common: &GlobalArgs,
    manifest_path: &Path,
    socket_dir: &Path,
    detached_records: Option<&HashMap<String, PatchRecord>>,
) -> Result<(bool, Envelope), (&'static str, String)> {
    // The download phase created `.socket/` already in every flow that
    // reaches here, but `acquire` deliberately refuses to mkdir.
    if let Err(e) = tokio::fs::create_dir_all(socket_dir).await {
        return Err(("socket_dir_unwritable", e.to_string()));
    }
    let guard = apply_lock::acquire(
        socket_dir,
        Duration::from_secs(common.lock_timeout.unwrap_or(0)),
    )
    .map_err(|e| match e {
        apply_lock::LockError::Held => (
            "lock_held",
            "another socket-patch process is operating in this directory".to_string(),
        ),
        apply_lock::LockError::Io { .. } => ("lock_io", e.to_string()),
    })?;

    let mut env = Envelope::new(EnvelopeCommand::Vendor);
    env.dry_run = common.dry_run;
    let has_errors = match detached_records {
        Some(records) => {
            // Staging probes blobs by the records' hashes; a synthetic
            // manifest view is all it needs.
            let synth = PatchManifest {
                patches: records.clone(),
                setup: None,
            };
            let staged =
                match stage_vendor_sources_in_memory(common, &synth, socket_dir, &common.cwd).await
                {
                    Ok(MemStageOutcome::Ready(s)) => s,
                    Ok(MemStageOutcome::Unavailable) => {
                        return Err((
                            "no_local_source",
                            "patch artifacts unavailable (offline or download failure)".to_string(),
                        ))
                    }
                    Err(e) => return Err(("stage_failed", e)),
                };
            let sources = staged.as_patch_sources();
            boxed_vendor_records(common, records, &sources, true, &mut env).await
        }
        None => {
            let manifest = match read_manifest(manifest_path).await {
                Ok(Some(m)) => m,
                Ok(None) => {
                    // No manifest ⇒ nothing downloaded and nothing
                    // pre-existing to vendor: a clean no-op.
                    drop(guard);
                    return Ok((false, env));
                }
                Err(e) => return Err(("invalid_manifest", e.to_string())),
            };
            // Same placement as the `vendor` command: dropped entries
            // are reverted even when zero in-scope patches remain.
            let mut has_errors = reconcile_dropped(&manifest, common, &mut env).await;
            let staged =
                match stage_vendor_sources_in_memory(common, &manifest, socket_dir, &common.cwd)
                    .await
                {
                    Ok(MemStageOutcome::Ready(s)) => s,
                    Ok(MemStageOutcome::Unavailable) => {
                        return Err((
                            "no_local_source",
                            "patch artifacts unavailable (offline or download failure)".to_string(),
                        ))
                    }
                    Err(e) => return Err(("stage_failed", e)),
                };
            let sources = staged.as_patch_sources();
            has_errors |=
                boxed_vendor_records(common, &manifest.patches, &sources, false, &mut env).await;
            has_errors
        }
    };
    drop(guard);
    if has_errors {
        env.mark_partial_failure();
    }
    Ok((has_errors, env))
}

/// The `scan --vendor` JSON path: discovery → (dry-run preview | download
/// → GC → vendor engine) → embedded VEX → print `result` → exit code.
///
/// Extracted from `run` (and called through `Box::pin`) so its sizeable
/// temporaries get their own poll frame, entered only when `--vendor` is
/// actually requested — in debug builds the enclosing frame retains stack
/// slots for never-taken branches, and `run`'s frame must fit Windows'
/// 1 MiB main-thread stack.
#[allow(clippy::too_many_arguments)]
async fn run_vendor_json_path(
    args: &ScanArgs,
    api_client: &socket_patch_core::api::client::ApiClient,
    effective_org_slug: Option<&str>,
    all_packages_with_patches: &[BatchPackagePatches],
    can_access_paid_patches: bool,
    result: &mut serde_json::Value,
    manifest_path: &Path,
    socket_dir: &Path,
    scanned_purls: &HashSet<String>,
    vendored_purls: &HashSet<String>,
    prune: bool,
    telemetry_token: Option<&str>,
    telemetry_org: Option<&str>,
) -> i32 {
    // Same discovery as `--apply`: per-package search, then the
    // selection logic that resolves the newest accessible patch.
    // Vendored purls are NOT filtered here — re-vendoring a stale
    // uuid is the point of the flag (same-uuid re-runs land on the
    // backend's `already_vendored` skip).
    let mut all_search_results: Vec<PatchSearchResult> = Vec::new();
    for pkg in all_packages_with_patches {
        match api_client
            .search_patches_by_package(effective_org_slug, &pkg.purl)
            .await
        {
            Ok(response) => all_search_results.extend(response.patches),
            Err(_) => continue,
        }
    }
    let selected = if all_search_results.is_empty() {
        Vec::new()
    } else {
        match select_patches(&all_search_results, can_access_paid_patches, false) {
            Ok(s) => s,
            Err(code) => return code,
        }
    };

    if args.common.dry_run {
        // No downloads, no backends: classify against the ledger
        // and preview the GC, exactly like `--apply`'s dry run.
        result["vendor"] = preview_vendor_json(&args.common.cwd, &selected).await;
        if prune {
            let gc = preview_apply_gc(
                &args.common,
                manifest_path,
                socket_dir,
                scanned_purls,
                vendored_purls,
            )
            .await;
            result["gc"] = gc.to_preview_json();
        }
        let final_code =
            embed_vex_into_json(&args.common, &args.vex, manifest_path, 0, result).await;
        println!("{}", serde_json::to_string_pretty(&result).unwrap());
        return final_code;
    }

    // 1) Download phase. Manifest mode reuses the `--apply`
    //    download (with `save_only` — the nested apply::run never
    //    fires); detached mode fetches records without touching
    //    the manifest. Either way the vendor step still runs when
    //    zero patches were downloaded (re-vendor after a wipe).
    let params = DownloadParams {
        cwd: args.common.cwd.clone(),
        org: args.common.org.clone(),
        save_only: true,
        one_off: false,
        global: args.common.global,
        global_prefix: args.common.global_prefix.clone(),
        json: true,
        silent: true,
        download_mode: args.common.download_mode.clone(),
        api_overrides: args.common.api_client_overrides(),
        all_releases: args.all_releases,
        strict: args.common.strict,
        persist_blobs: !args.vendor,
    };
    let mut has_errors = false;
    let detached_records: Option<HashMap<String, PatchRecord>> = if args.detached {
        let (code, mut dl_json, records) = boxed_download_patch_records(&selected, &params).await;
        has_errors |= code != 0;
        if let Some(obj) = dl_json.as_object_mut() {
            obj.remove("status");
        }
        result["download"] = dl_json;
        Some(records)
    } else if selected.is_empty() {
        result["download"] = serde_json::json!({
            "found": 0, "downloaded": 0, "skipped": 0,
            "failed": 0, "patches": [],
        });
        None
    } else {
        let (code, mut dl_json) = boxed_download_and_apply(&selected, &params).await;
        has_errors |= code != 0;
        if let Some(obj) = dl_json.as_object_mut() {
            obj.remove("status");
            // save_only: the nested apply never ran, so the
            // `applied` count is structurally zero — drop it
            // rather than report a misleading 0-applied.
            obj.remove("applied");
        }
        result["download"] = dl_json;
        None
    };

    // 2) GC BEFORE the vendor step (when --prune): stale manifest
    //    entries would otherwise fail vendoring with
    //    package_not_installed; vendored entries are exempt from
    //    the prune itself.
    if prune {
        let gc = run_apply_gc(
            &args.common,
            manifest_path,
            socket_dir,
            scanned_purls,
            vendored_purls,
        )
        .await;
        result["gc"] = gc.to_apply_json();
    }

    // 3) The vendor engine, under the same lock as apply/vendor.
    let vendor_code = match boxed_scan_vendor_step(
        &args.common,
        manifest_path,
        socket_dir,
        detached_records.as_ref(),
    )
    .await
    {
        Ok((vendor_errors, venv)) => {
            has_errors |= vendor_errors;
            track_outcomes_for_vendor(
                vendor_errors,
                &venv,
                args.common.dry_run,
                telemetry_token,
                telemetry_org,
            )
            .await;
            result["vendor"] =
                serde_json::to_value(&venv).unwrap_or_else(|_| serde_json::json!({}));
            i32::from(has_errors)
        }
        Err((code, message)) => {
            track_patch_vendor_failed(
                &message,
                args.common.dry_run,
                telemetry_token,
                telemetry_org,
            )
            .await;
            result["status"] = serde_json::json!("error");
            result["error"] = serde_json::json!({
                "code": code,
                "message": message,
            });
            println!("{}", serde_json::to_string_pretty(&result).unwrap());
            return 1;
        }
    };
    if vendor_code != 0 {
        result["status"] = serde_json::json!("partial_failure");
    }

    let final_code =
        embed_vex_into_json(&args.common, &args.vex, manifest_path, vendor_code, result).await;
    println!("{}", serde_json::to_string_pretty(&result).unwrap());
    final_code
}

/// The `scan --vendor` interactive arm: download (manifest or detached
/// mode) → pre-vendor GC → vendor engine, with human-readable output.
/// Extracted + boxed for the same Windows-1-MiB-poll-frame reason as
/// [`run_vendor_json_path`].
#[allow(clippy::too_many_arguments)]
async fn run_vendor_interactive_path(
    args: &ScanArgs,
    selected: &[PatchSearchResult],
    params: &DownloadParams,
    manifest_path: &Path,
    socket_dir: &Path,
    scanned_purls: &HashSet<String>,
    vendored_purls: &HashSet<String>,
    prune: bool,
    telemetry_token: Option<&str>,
    telemetry_org: Option<&str>,
) -> i32 {
    let mut has_errors = false;
    let detached_records: Option<HashMap<String, PatchRecord>> = if args.detached {
        let (dl_code, _, records) = boxed_download_patch_records(selected, params).await;
        has_errors |= dl_code != 0;
        Some(records)
    } else {
        if !selected.is_empty() {
            let (dl_code, _) = boxed_download_and_apply(selected, params).await;
            has_errors |= dl_code != 0;
        }
        None
    };
    // GC before the vendor step (see the JSON path): stale manifest
    // entries would fail vendoring with package_not_installed.
    if prune {
        let gc = run_apply_gc(
            &args.common,
            manifest_path,
            socket_dir,
            scanned_purls,
            vendored_purls,
        )
        .await;
        if !gc.pruned.is_empty() {
            println!("GC: pruned {} manifest entr{}.", gc.pruned.len(), {
                if gc.pruned.len() == 1 {
                    "y"
                } else {
                    "ies"
                }
            });
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
    }
    match boxed_scan_vendor_step(
        &args.common,
        manifest_path,
        socket_dir,
        detached_records.as_ref(),
    )
    .await
    {
        Ok((vendor_errors, venv)) => {
            has_errors |= vendor_errors;
            track_outcomes_for_vendor(
                vendor_errors,
                &venv,
                args.common.dry_run,
                telemetry_token,
                telemetry_org,
            )
            .await;
            i32::from(has_errors)
        }
        Err((code, message)) => {
            track_patch_vendor_failed(
                &message,
                args.common.dry_run,
                telemetry_token,
                telemetry_org,
            )
            .await;
            eprintln!("Error ({code}): {message}");
            1
        }
    }
}

/// Partition vendor-owned purls out of the selected set and pre-render
/// their `skipped`/`vendored` JSON records (sorted by purl). A plain fn
/// (not inlined into `run`) so the json! temporaries don't ride `run`'s
/// async poll frame — see [`run_vendor_json_path`]'s Windows-stack note.
fn partition_vendored_selected(
    selected: Vec<PatchSearchResult>,
    vendored_purls: &HashSet<String>,
) -> (Vec<PatchSearchResult>, Vec<serde_json::Value>) {
    let is_vendored =
        |p: &str| vendored_purls.contains(p) || vendored_purls.contains(strip_purl_qualifiers(p));
    let (vendored_selected, kept): (Vec<_>, Vec<_>) =
        selected.into_iter().partition(|p| is_vendored(&p.purl));
    let mut vendored_records: Vec<serde_json::Value> = vendored_selected
        .iter()
        .map(|p| {
            serde_json::json!({
                "purl": p.purl, "uuid": p.uuid,
                "action": "skipped", "errorCode": "vendored",
            })
        })
        .collect();
    vendored_records.sort_by(|a, b| a["purl"].as_str().cmp(&b["purl"].as_str()));
    (kept, vendored_records)
}

/// Lockfile-only patches are skipped BEFORE download in apply mode: the
/// package is not on disk to patch in place, and downloading its patch
/// into the manifest would create a not-yet-appliable entry (and flip the
/// apply path's exit code). `scan --vendor` is the route that handles them
/// (the vendor engine auto-fetches lockfile-resolved packages). Matching
/// bridges API purl encoding via `normalize_purl`. Same shape/mechanics as
/// [`partition_vendored_selected`].
fn partition_not_installed_selected(
    selected: Vec<PatchSearchResult>,
    lockfile_only: &HashSet<String>,
) -> (Vec<PatchSearchResult>, Vec<serde_json::Value>) {
    if lockfile_only.is_empty() {
        return (selected, Vec::new());
    }
    let is_lockfile_only =
        |p: &str| lockfile_only.contains(normalize_purl(strip_purl_qualifiers(p)).as_ref());
    let (not_installed, kept): (Vec<_>, Vec<_>) = selected
        .into_iter()
        .partition(|p| is_lockfile_only(&p.purl));
    let mut records: Vec<serde_json::Value> = not_installed
        .iter()
        .map(|p| {
            serde_json::json!({
                "purl": p.purl, "uuid": p.uuid,
                "action": "skipped", "errorCode": "package_not_installed",
            })
        })
        .collect();
    records.sort_by(|a, b| a["purl"].as_str().cmp(&b["purl"].as_str()));
    (kept, records)
}

/// Fold the pre-download vendored skips into the apply report returned by
/// `download_and_apply_patches`: they were "found" by discovery and
/// skipped here, never downloaded. Also strips the inner `status` (scan
/// recomputes its own). Plain fn for the same poll-frame reason as
/// [`partition_vendored_selected`].
fn fold_vendored_skips_into_apply(
    apply_obj: &mut serde_json::Value,
    vendored_records: &[serde_json::Value],
) {
    let Some(obj) = apply_obj.as_object_mut() else {
        return;
    };
    obj.remove("status");
    if vendored_records.is_empty() {
        return;
    }
    let n = vendored_records.len() as u64;
    for key in ["found", "skipped"] {
        let bumped = obj.get(key).and_then(|v| v.as_u64()).unwrap_or(0) + n;
        obj.insert(key.to_string(), serde_json::json!(bumped));
    }
    if let Some(patches) = obj.get_mut("patches").and_then(|p| p.as_array_mut()) {
        patches.extend(vendored_records.iter().cloned());
    }
}

/// Construct the (large) vendor-JSON-path future on THIS transient frame
/// and hand `run` only the heap pointer. Writing
/// `Box::pin(run_vendor_json_path(..))` inline in `run` materializes the
/// future — which embeds the whole vendor engine — as a stack temporary in
/// `run`'s poll frame: debug builds allocate slots even for never-taken
/// branches, and that frame has to fit Windows' 1 MiB main-thread stack
/// (every plain `scan` was overflowing there).
#[allow(clippy::too_many_arguments)]
fn boxed_vendor_json_path<'a>(
    args: &'a ScanArgs,
    api_client: &'a socket_patch_core::api::client::ApiClient,
    effective_org_slug: Option<&'a str>,
    all_packages_with_patches: &'a [BatchPackagePatches],
    can_access_paid_patches: bool,
    result: &'a mut serde_json::Value,
    manifest_path: &'a Path,
    socket_dir: &'a Path,
    scanned_purls: &'a HashSet<String>,
    vendored_purls: &'a HashSet<String>,
    prune: bool,
    telemetry_token: Option<&'a str>,
    telemetry_org: Option<&'a str>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = i32> + 'a>> {
    Box::pin(run_vendor_json_path(
        args,
        api_client,
        effective_org_slug,
        all_packages_with_patches,
        can_access_paid_patches,
        result,
        manifest_path,
        socket_dir,
        scanned_purls,
        vendored_purls,
        prune,
        telemetry_token,
        telemetry_org,
    ))
}

/// The interactive twin of [`boxed_vendor_json_path`] — same transient-
/// frame indirection, same Windows-stack rationale.
#[allow(clippy::too_many_arguments)]
fn boxed_vendor_interactive_path<'a>(
    args: &'a ScanArgs,
    selected: &'a [PatchSearchResult],
    params: &'a DownloadParams,
    manifest_path: &'a Path,
    socket_dir: &'a Path,
    scanned_purls: &'a HashSet<String>,
    vendored_purls: &'a HashSet<String>,
    prune: bool,
    telemetry_token: Option<&'a str>,
    telemetry_org: Option<&'a str>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = i32> + 'a>> {
    Box::pin(run_vendor_interactive_path(
        args,
        selected,
        params,
        manifest_path,
        socket_dir,
        scanned_purls,
        vendored_purls,
        prune,
        telemetry_token,
        telemetry_org,
    ))
}

/// Transient-frame boxed constructor for [`run_scan_vendor_step`] — the
/// future embeds the entire vendor engine, and the vendor-path frames it
/// would otherwise ride must themselves fit Windows' 1 MiB main-thread
/// stack (same rationale as [`boxed_vendor_json_path`], one level down).
#[allow(clippy::type_complexity)]
fn boxed_scan_vendor_step<'a>(
    common: &'a GlobalArgs,
    manifest_path: &'a Path,
    socket_dir: &'a Path,
    detached_records: Option<&'a HashMap<String, PatchRecord>>,
) -> std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<(bool, Envelope), (&'static str, String)>> + 'a>,
> {
    Box::pin(run_scan_vendor_step(
        common,
        manifest_path,
        socket_dir,
        detached_records,
    ))
}

/// Transient-frame boxed constructors for the download-phase futures used
/// inside the vendor paths — `download_and_apply_patches`'s future embeds
/// the in-process `apply::run`, and these frames must fit Windows' 1 MiB
/// main-thread stack (same rationale as [`boxed_vendor_json_path`]).
fn boxed_download_and_apply<'a>(
    selected: &'a [PatchSearchResult],
    params: &'a DownloadParams,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = (i32, serde_json::Value)> + 'a>> {
    Box::pin(download_and_apply_patches(selected, params))
}

/// See [`boxed_download_and_apply`].
#[allow(clippy::type_complexity)]
fn boxed_download_patch_records<'a>(
    selected: &'a [PatchSearchResult],
    params: &'a DownloadParams,
) -> std::pin::Pin<
    Box<
        dyn std::future::Future<Output = (i32, serde_json::Value, HashMap<String, PatchRecord>)>
            + 'a,
    >,
> {
    Box::pin(download_patch_records(selected, params))
}

/// Transient-frame boxed constructor for the vendor engine itself
/// ([`vendor_records`]) — the deepest, largest future on the scan-vendor
/// chain. See [`boxed_vendor_json_path`] for the Windows-stack rationale.
fn boxed_vendor_records<'a>(
    common: &'a GlobalArgs,
    records: &'a HashMap<String, PatchRecord>,
    sources: &'a socket_patch_core::patch::apply::PatchSources<'a>,
    detached: bool,
    env: &'a mut Envelope,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + 'a>> {
    // `scan --vendor` builds locally (no vendoring-service config); the
    // `vendor` command is the service-download entry point.
    Box::pin(vendor_records(
        common, records, sources, detached, false, env, None,
    ))
}

/// Telemetry for the scan-driven vendor step (mirrors `vendor::run`'s
/// success/failure split).
async fn track_outcomes_for_vendor(
    has_errors: bool,
    env: &Envelope,
    dry_run: bool,
    token: Option<&str>,
    org: Option<&str>,
) {
    if has_errors {
        track_patch_vendor_failed("vendor completed with failures", dry_run, token, org).await;
    } else {
        track_patch_vendored(env.summary.applied, dry_run, token, org).await;
    }
}

/// Candidate lockfiles / registry configs the redirect rewriters may touch —
/// read from the project when present and handed to `rewrite_registry_redirect`.
const REDIRECT_CANDIDATE_FILES: &[&str] = &[
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    // A berry lock's cache-config gate reads `.yarnrc.yml`; bun's text lock is
    // `bun.lock` (its binary `bun.lockb` is auto-migrated in `run_redirect`).
    ".yarnrc.yml",
    "bun.lock",
    "requirements.txt",
    "uv.lock",
    "Cargo.toml",
    "Cargo.lock",
    ".cargo/config.toml",
    "composer.lock",
    "nuget.config",
    "packages.lock.json",
    "Gemfile",
    "Gemfile.lock",
    "pom.xml",
    // Gradle build scripts are never edited — their presence only feeds the
    // maven rewriter's paste-able `exclusiveContent` snippet warning.
    "settings.gradle",
    "settings.gradle.kts",
    "build.gradle",
    "build.gradle.kts",
];

/// `pkg:<type>/<coordinate>@<version>` → `(type, coordinate, version)`. The
/// coordinate keeps its full slash-bearing form (npm `@scope/name`, composer
/// `vendor/pkg`, golang module path) — the rewriters treat that as the `name`
/// (their `full_name()` is `name` when `namespace` is `None`).
fn parse_purl_simple(purl: &str) -> Option<(String, String, String)> {
    let stripped = socket_patch_core::utils::purl::strip_purl_qualifiers(purl);
    let rest = stripped.strip_prefix("pkg:")?;
    let (typ, after) = rest.split_once('/')?;
    let (coord, version) = after.rsplit_once('@')?;
    let name = socket_patch_core::utils::purl::percent_decode_purl_component(coord).into_owned();
    Some((typ.to_string(), name, version.to_string()))
}

/// `scan --redirect`: resolve hosted-patch references for the selected patches,
/// then rewrite ONLY those dependencies' lockfile/registry-config entries to
/// point at the hosted vendored patches (the byte-identical counterpart of the
/// GitHub-app registry mode). No artifact bytes land in the repo.
async fn run_redirect(
    args: &ScanArgs,
    api_client: &socket_patch_core::api::client::ApiClient,
    effective_org_slug: Option<&str>,
    all_packages_with_patches: &[BatchPackagePatches],
    can_access_paid_patches: bool,
) -> i32 {
    use socket_patch_core::manifest::schema::PatchRecord;
    use socket_patch_core::patch::redirect::{
        rewrite_registry_redirect, DepOverride, RedirectState,
    };

    // Same discovery/selection as `--apply`/`--vendor`.
    let mut all_search_results: Vec<PatchSearchResult> = Vec::new();
    for pkg in all_packages_with_patches {
        if let Ok(response) = api_client
            .search_patches_by_package(effective_org_slug, &pkg.purl)
            .await
        {
            all_search_results.extend(response.patches);
        }
    }
    let selected = if all_search_results.is_empty() {
        Vec::new()
    } else {
        match select_patches(&all_search_results, can_access_paid_patches, false) {
            Ok(s) => s,
            Err(code) => return code,
        }
    };

    let mut skipped: Vec<serde_json::Value> = Vec::new();
    let mut overrides: Vec<DepOverride> = Vec::new();
    // (purl, uuid, artifact_url, registry index_url) per granted reference —
    // used AFTER the rewrite to decide which deps were actually redirected
    // (their target URL landed in a lockfile) before persisting records or
    // attesting anything.
    let mut candidates: Vec<(String, String, String, Option<String>)> = Vec::new();

    if !selected.is_empty() {
        let uuids: Vec<String> = selected.iter().map(|s| s.uuid.clone()).collect();
        let references = match api_client.fetch_registry_references(&uuids).await {
            Ok(r) => r,
            Err(e) => {
                eprintln!("failed to resolve patch references: {e}");
                return 1;
            }
        };
        for sel in &selected {
            let Some(reference) = references.get(&sel.uuid) else {
                skipped.push(serde_json::json!({ "purl": sel.purl, "uuid": sel.uuid, "reason": "not_found" }));
                continue;
            };
            if reference.status != "granted" && reference.status != "reused" {
                skipped.push(serde_json::json!({ "purl": sel.purl, "uuid": sel.uuid, "reason": reference.status }));
                continue;
            }
            let purl = reference.purl.as_deref().unwrap_or(&sel.purl);
            let Some((ecosystem, name, version)) = parse_purl_simple(purl) else {
                skipped.push(
                    serde_json::json!({ "purl": purl, "uuid": sel.uuid, "reason": "bad_purl" }),
                );
                continue;
            };
            let Some(url) = reference.url.clone() else {
                skipped.push(
                    serde_json::json!({ "purl": purl, "uuid": sel.uuid, "reason": "no_url" }),
                );
                continue;
            };
            let mut integrity = reference
                .artifacts
                .iter()
                .find(|a| a.kind == "tarball")
                .map(|a| a.integrity.clone())
                .unwrap_or_default();
            // The yarn-berry cache zip carries the `yarnBerry10c0` checksum the
            // berry rewriter pins (berry verifies the zip, not the tarball).
            // Merge it in and carry the zip URL (None when not stored yet).
            let berry_zip = reference
                .artifacts
                .iter()
                .find(|a| a.kind == "yarn-berry-zip");
            if let Some(c) = berry_zip.and_then(|a| a.integrity.yarn_berry10c0.clone()) {
                integrity.yarn_berry10c0 = Some(c);
            }
            candidates.push((
                purl.to_string(),
                sel.uuid.clone(),
                url.clone(),
                reference
                    .registry_override
                    .as_ref()
                    .map(|o| o.index_url.clone()),
            ));
            overrides.push(DepOverride {
                ecosystem,
                name,
                namespace: None,
                version,
                token: String::new(),
                patch_uuid: sel.uuid.clone(),
                artifact_url: url,
                berry_zip_url: berry_zip.and_then(|a| a.url.clone()),
                registry_override: reference.registry_override.clone(),
                integrity,
            });
        }
    }

    // bun.lockb auto-migration: the redirect rewriter only edits the TEXT
    // lockfile, so a project locked to a binary `bun.lockb` must be re-locked
    // to `bun.lock` first. `bun install --save-text-lockfile --frozen-lockfile
    // --lockfile-only` writes bun.lock, DELETES bun.lockb, needs no network,
    // and fails closed on drift. Dry-run only warns; a failure degrades to the
    // rewriter's own presence-only refusal (the .lockb stays a candidate file).
    let mut migration_warnings: Vec<serde_json::Value> = Vec::new();
    let mut migration_edits: Vec<socket_patch_core::patch::redirect::FileEdit> = Vec::new();
    let has_lockb = args.common.cwd.join("bun.lockb").exists();
    let has_bun_lock = args.common.cwd.join("bun.lock").exists();
    if has_lockb && !has_bun_lock {
        if args.common.dry_run {
            migration_warnings.push(serde_json::json!({
                "code": "redirect_bun_lockb_would_migrate",
                "detail": "bun.lockb would be migrated to a text bun.lock \
                           (`bun install --save-text-lockfile`) before redirecting; \
                           re-run without --dry-run to apply",
            }));
        } else {
            let status = std::process::Command::new("bun")
                .args([
                    "install",
                    "--save-text-lockfile",
                    "--frozen-lockfile",
                    "--lockfile-only",
                ])
                .current_dir(&args.common.cwd)
                .status();
            let migrated =
                matches!(status, Ok(s) if s.success()) && args.common.cwd.join("bun.lock").exists();
            if migrated {
                // bun deleted bun.lockb itself. Record the removal so `--revert`
                // knows the file was replaced (binary — git history is the
                // restore path, so no `original` bytes are captured).
                migration_edits.push(socket_patch_core::patch::redirect::FileEdit {
                    path: "bun.lockb".into(),
                    kind: "redirect_bun_lockb_migrated".into(),
                    action: "removed".into(),
                    key: None,
                    original: None,
                    new: None,
                });
            } else {
                migration_warnings.push(serde_json::json!({
                    "code": "redirect_bun_lockb_unsupported",
                    "detail": "bun.lockb could not be migrated to a text bun.lock \
                               (`bun install --save-text-lockfile` failed or is unavailable); \
                               the redirect cannot pin a binary lockfile",
                }));
            }
        }
    }

    // Read the project's candidate files, run the rewriters.
    let mut files: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    for name in REDIRECT_CANDIDATE_FILES {
        if let Ok(content) = std::fs::read_to_string(args.common.cwd.join(name)) {
            files.insert((*name).to_string(), content);
        }
    }
    let rewrite = rewrite_registry_redirect(&files, &overrides);
    let rewritten: Vec<String> = rewrite.files.keys().cloned().collect();

    // A dep counts as REDIRECTED only if its hosted-artifact URL (or its
    // per-dependency registry index URL) actually landed in the project's
    // files — either written by this run or already present from an earlier
    // one. A granted reference whose rewriter found nothing to edit (e.g. no
    // lockfile) must NOT be recorded or attested: nothing pins the patch.
    let final_texts: Vec<&String> = files
        .iter()
        .map(|(name, content)| rewrite.files.get(name).unwrap_or(content))
        .chain(
            rewrite
                .files
                .iter()
                .filter(|(name, _)| !files.contains_key(*name))
                .map(|(_, content)| content),
        )
        .collect();
    let confirmed: Vec<(String, String)> = candidates
        .iter()
        .filter(|(_, _, artifact_url, index_url)| {
            let encoded = socket_patch_core::utils::uri::encode_uri_component(artifact_url);
            final_texts.iter().any(|text| {
                text.contains(artifact_url.as_str())
                    // The berry rewriter writes the URL percent-encoded into the
                    // lock's `::__archiveUrl=` binding, so the raw form is absent.
                    || text.contains(encoded.as_str())
                    || index_url.as_deref().is_some_and(|iu| text.contains(iu))
            })
        })
        .map(|(purl, uuid, _, _)| (purl.clone(), uuid.clone()))
        .collect();

    // Fetch the full patch view (file hashes + vulnerabilities) for each
    // CONFIRMED redirect and persist it so a post-install `socket-patch vex`
    // can attest the patch. A fetch failure does not undo the redirect, but
    // it leaves the patch unattestable — surface it as a warning (JSON +
    // stderr) so CI can detect the attestation gap and re-run.
    let mut records: std::collections::BTreeMap<String, PatchRecord> =
        std::collections::BTreeMap::new();
    let mut record_warnings: Vec<serde_json::Value> = Vec::new();
    if !args.common.dry_run {
        for (purl, uuid) in &confirmed {
            match api_client.fetch_patch(effective_org_slug, uuid).await {
                Ok(Some(resp)) => {
                    let (rec_purl, record) =
                        crate::commands::get::record_from_patch_response(&resp);
                    records.insert(rec_purl, record);
                }
                Ok(None) | Err(_) => {
                    record_warnings.push(serde_json::json!({
                        "code": "record_fetch_failed",
                        "detail": format!(
                            "{purl} redirected, but its patch record could not be fetched; \
                             it will be missing from VEX until `scan --redirect` is re-run"
                        ),
                    }));
                }
            }
        }
    }

    if !args.common.dry_run {
        for (rel, content) in &rewrite.files {
            let path = args.common.cwd.join(rel);
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if let Err(e) = std::fs::write(&path, content) {
                eprintln!("failed to write {rel}: {e}");
                return 1;
            }
        }
        // Ledger (mirrors the vendor state.json shape): recorded edits for a
        // future revert + the patch records (file hashes + vulnerabilities) so
        // a post-install `socket-patch vex` can attest the redirected patches.
        // MERGE with any existing ledger rather than overwriting: an idempotent
        // re-run produces no new edits (the lockfile already points at the
        // hosted patch), and clobbering the file would lose the original
        // pre-redirect values a future revert needs. New edits APPEND (revert
        // walks them in reverse); records are keyed by PURL, newest wins.
        if !rewrite.edits.is_empty() || !records.is_empty() || !migration_edits.is_empty() {
            let vendor_dir = args.common.cwd.join(".socket").join("vendor");
            let _ = std::fs::create_dir_all(&vendor_dir);
            let mut ledger =
                socket_patch_core::patch::redirect::load_redirect_state(&args.common.cwd)
                    .await
                    .unwrap_or_else(RedirectState::new);
            // Ledgers written before the mode-string rename carry
            // `"mode": "redirect"`; normalize on rewrite so the on-disk
            // ledger converges on the documented "hosted" name (the
            // loader accepts either — mode is an opaque string to it).
            ledger.mode = "hosted".to_string();
            // The bun.lockb→bun.lock migration removal precedes the rewrite
            // edits so `--revert` unwinds it last (after restoring bun.lock).
            ledger.edits.extend(migration_edits.iter().cloned());
            ledger.edits.extend(rewrite.edits.iter().cloned());
            ledger.records.extend(records.clone());
            let _ = std::fs::write(
                vendor_dir.join("redirect-state.json"),
                format!("{}\n", serde_json::to_string_pretty(&ledger).unwrap()),
            );
        }
    }

    // Emit an OpenVEX attestation when `--vex` was requested. The redirected
    // bytes are fetched from the hosted patch server at install time, so the
    // PURLs CONFIRMED REDIRECTED BY THIS RUN are attested from the ledger
    // records WITHOUT hash verification (`assume_applied` — the integrity
    // pins written into the lockfile are the evidence), while any OTHER
    // manifest patches (previously applied / vendored — and any stale ledger
    // records this run did not confirm) still verify normally. A post-install
    // `socket-patch vex` hash-verifies the redirected patches against the
    // installed tree (it reads the records back from the redirect ledger via
    // augment_with_redirect). Requested-but-failed VEX (including "nothing to
    // attest") flips the exit code, matching `scan --vex`.
    let mut vex_statements: Option<usize> = None;
    let mut vex_error: Option<(&'static str, String)> = None;
    let mut vex_code = 0;
    if args.vex.vex.is_some() && !args.common.dry_run {
        let mut params = args.vex.to_build_params();
        params.assume_applied = confirmed.iter().map(|(purl, _)| purl.clone()).collect();
        let manifest_path = args.common.resolved_manifest_path();
        match generate_vex_from_manifest_path(&args.common, &params, &manifest_path).await {
            Ok(summary) => vex_statements = Some(summary.statements),
            Err(e) => {
                vex_code = 1;
                vex_error = Some((e.code, e.message));
            }
        }
    }

    if args.common.json {
        let mut warnings: Vec<serde_json::Value> = rewrite
            .warnings
            .iter()
            .map(|w| {
                serde_json::json!({
                    "code": w.code, "detail": w.detail,
                })
            })
            .collect();
        warnings.extend(record_warnings.iter().cloned());
        warnings.extend(migration_warnings.iter().cloned());
        let mut result = serde_json::json!({
            "status": "success",
            "redirect": {
                // Final mode naming: `--redirect` IS hosted mode. Additive
                // key so JSON consumers can dispatch on the mode without
                // inferring it from which sub-object is present.
                "mode": "hosted",
                "redirected": confirmed.len(),
                "rewrittenFiles": rewritten,
                "skipped": skipped,
                "warnings": warnings,
                "dryRun": args.common.dry_run,
            }
        });
        if let Some(statements) = vex_statements {
            result["vex"] = serde_json::json!({
                "path": args.vex.vex.as_ref().unwrap().display().to_string(),
                "statements": statements,
                "format": "openvex-0.2.0",
                "verified": false,
            });
        } else if let Some((code, message)) = &vex_error {
            result["status"] = serde_json::json!("error");
            result["error"] = serde_json::json!({ "code": code, "message": message });
        }
        println!("{}", serde_json::to_string_pretty(&result).unwrap());
    } else if !args.common.silent {
        let verb = if args.common.dry_run {
            "would rewrite"
        } else {
            "rewrote"
        };
        println!(
            "Redirected {} package(s); {verb} {} file(s).",
            confirmed.len(),
            rewritten.len()
        );
        for s in &skipped {
            eprintln!("  skipped {} ({})", s["purl"], s["reason"]);
        }
        for w in &record_warnings {
            eprintln!("  warning: {}", w["detail"]);
        }
        for w in &migration_warnings {
            eprintln!("  warning: {}", w["detail"]);
        }
        if let Some(statements) = vex_statements {
            eprintln!(
                "Wrote OpenVEX document with {} statement(s) to {} (redirected patches are \
                 attested from the ledger, not hash-verified — their bytes are fetched at \
                 install time; run `socket-patch vex` after installing to verify against \
                 the installed tree).",
                statements,
                args.vex.vex.as_ref().unwrap().display(),
            );
        } else if let Some((_, message)) = &vex_error {
            eprintln!("Error: VEX generation failed: {message}");
        } else if args.vex.vex.is_some() && args.common.dry_run {
            eprintln!("Skipping VEX generation (--dry-run).");
        }
    }
    vex_code
}

pub async fn run(mut args: ScanArgs) -> i32 {
    apply_env_toggles(&args.common);

    // Fold `--mode` into the legacy mode booleans before anything reads
    // them, so every branch below keeps a single source of truth. Cross-
    // mode combinations get a usage-style error (exit 2, matching clap's
    // conflict exit code) — see `resolve_mode_flags` for why clap itself
    // can't express them.
    if let Err(message) = resolve_mode_flags(&mut args) {
        eprintln!("error: {message}");
        return 2;
    }

    // `--sync` is sugar for `--apply --prune`. Derive locals once and
    // use them everywhere downstream so the flag interactions are
    // expressed in one place. `--apply --prune --sync` is redundant
    // but legal (all three end up true).
    let apply = args.apply || args.sync;
    let prune = args.prune || args.sync;

    // A zero batch size would panic the API-query loop below: both
    // `all_purls.len().div_ceil(batch_size)` and `all_purls.chunks(batch_size)`
    // abort the process on a divisor/chunk-size of 0. `--batch-size 0`
    // (or `SOCKET_BATCH_SIZE=0`) is otherwise unvalidated, so clamp to a
    // floor of 1 — degrade to one-package batches rather than crash.
    let batch_size = args.batch_size.max(1);

    // Resolved up-front (rather than at the GC site) because the embedded
    // `--vex` side-effect reads the manifest at several terminal returns,
    // including the early "no packages" exit before the GC block.
    let manifest_path = args.common.resolved_manifest_path();
    let socket_dir = manifest_path.parent().unwrap().to_path_buf();

    let overrides = args.common.api_client_overrides();
    let (mut api_client, mut use_public_proxy) =
        get_api_client_with_overrides(overrides.clone()).await;
    let telemetry_token = api_client.api_token().cloned();
    let telemetry_org = api_client.org_slug().cloned();
    // Tracks whether scan was downgraded from the authenticated
    // endpoint to the public proxy mid-run after a 401/403. Surfaces
    // in the final `patch_scanned` telemetry event so we can measure
    // how often stale-token fallbacks fire in the wild.
    let mut fallback_to_proxy = false;

    // org slug is already stored in the client
    let effective_org_slug: Option<&str> = None;

    let crawler_options = CrawlerOptions {
        cwd: args.common.cwd.clone(),
        global: args.common.global,
        global_prefix: args.common.global_prefix.clone(),
        batch_size,
    };

    let scan_target = if args.common.global || args.common.global_prefix.is_some() {
        "global packages"
    } else {
        "packages"
    };

    // `--silent` is "errors only" (CLI_CONTRACT.md): progress, the crawl
    // summary, the results table, and the per-patch listing are all
    // suppressed below, mirroring `list`/`get`/`repair`/`remove`. Errors
    // and the JSON envelope are unaffected.
    let show_progress = !args.common.json && !args.common.silent && stderr_is_tty();

    if show_progress {
        eprint!("Scanning {scan_target}...");
    }

    // Crawl packages
    let (mut all_crawled, mut eco_counts) = crawl_all_ecosystems(&crawler_options).await;

    // Lockfile supplement: dependencies the project's lockfile resolves
    // that have NO installed copy (fresh clone, partial install). They join
    // discovery — counts, API lookup, table, the prune "scanned" set — and
    // are flagged "not yet installed" everywhere a user could act on them.
    let lockfile_only = lockfile_supplement(&args.common, &all_crawled).await;
    if !lockfile_only.packages.is_empty() {
        for pkg in &lockfile_only.packages {
            if let Some(eco) = Ecosystem::from_purl(&pkg.purl) {
                *eco_counts.entry(eco).or_insert(0) += 1;
            }
        }
        all_crawled.extend(lockfile_only.packages.iter().cloned());
    }
    let ledger_supplement = vendored_ledger_supplement(&args.common, &all_crawled).await;
    for pkg in &ledger_supplement {
        if let Some(eco) = Ecosystem::from_purl(&pkg.purl) {
            *eco_counts.entry(eco).or_insert(0) += 1;
        }
    }
    all_crawled.extend(ledger_supplement);

    // Every PURL the crawl found, captured BEFORE the `--ecosystems`
    // display/query filter is applied. Prune (below) must reference the
    // full installed set: `--ecosystems npm` narrows what we *query and
    // show*, but packages of other ecosystems are still installed. If
    // prune used the filtered set instead, `scan --ecosystems npm --prune`
    // would treat every cargo/go/pypi/gem manifest entry as "uninstalled"
    // and delete it (plus its blobs) — silent cross-ecosystem data loss.
    // Lockfile-only purls are deliberately included: a dependency the
    // lockfile still resolves must not be pruned just because node_modules
    // is wiped or partially installed.
    let installed_purls: HashSet<String> = all_crawled.iter().map(|p| p.purl.clone()).collect();

    // Vendor-ledger purl keys, loaded once and shared by the prune
    // exemption (a vendored package is consumed from the committed
    // artifact, so "absent from the crawl" is its normal state, not
    // grounds for pruning) and the vendored-skip in the apply path.
    let vendored_purls =
        socket_patch_core::patch::vendor::vendored_purl_keys(&args.common.cwd).await;

    // Filter by --ecosystems if provided
    let filtered_crawled: Vec<_> = if let Some(ref allowed) = args.common.ecosystems {
        all_crawled
            .into_iter()
            .filter(|pkg| {
                if let Some(eco) = Ecosystem::from_purl(&pkg.purl) {
                    allowed.iter().any(|a| a == eco.cli_name())
                } else {
                    false
                }
            })
            .collect()
    } else {
        all_crawled
    };

    let all_purls: Vec<String> = filtered_crawled.iter().map(|p| p.purl.clone()).collect();
    let package_count = all_purls.len();

    if package_count == 0 {
        if show_progress {
            eprintln!();
        }
        // Telemetry: empty-scan still counts as a successful scan.
        track_patch_scanned(
            0,
            0,
            0,
            false,
            args.common
                .ecosystems
                .clone()
                .unwrap_or_default()
                .as_slice(),
            false,
            telemetry_token.as_deref(),
            telemetry_org.as_deref(),
        )
        .await;
        if args.common.json {
            // When the crawler finds nothing, GC is intentionally skipped
            // — pruning every manifest entry on the assumption that the
            // user "uninstalled everything" is too destructive. Bots
            // that need full cleanup can call `repair` explicitly. No
            // `gc` field emitted because the user didn't request one.
            let mut result = serde_json::json!({
                "status": "success",
                "scannedPackages": 0,
                "lockfileOnlyPackages": 0,
                "packagesWithPatches": 0,
                "totalPatches": 0,
                "freePatches": 0,
                "paidPatches": 0,
                "canAccessPaidPatches": false,
                "packages": [],
                "updates": [],
            });
            let code =
                embed_vex_into_json(&args.common, &args.vex, &manifest_path, 0, &mut result).await;
            println!("{}", serde_json::to_string_pretty(&result).unwrap());
            return code;
        } else if args.common.silent {
            // Errors only: the empty-scan hint is informational.
        } else if args.common.global || args.common.global_prefix.is_some() {
            println!("No global packages found.");
        } else {
            #[allow(unused_mut)]
            let mut install_cmds = String::from("npm/yarn/pnpm/pip");
            #[cfg(feature = "cargo")]
            install_cmds.push_str("/cargo");
            #[cfg(feature = "golang")]
            install_cmds.push_str("/go");
            #[cfg(feature = "maven")]
            install_cmds.push_str("/mvn");
            #[cfg(feature = "composer")]
            install_cmds.push_str("/composer");
            println!("No packages found. Run {install_cmds} install first.");
        }
        return embed_vex_human(&args.common, &args.vex, &manifest_path, 0).await;
    }

    // Build ecosystem summary
    let mut eco_parts = Vec::new();
    for eco in Ecosystem::all() {
        let count = if args.common.ecosystems.is_some() {
            // When filtering, count the filtered packages
            filtered_crawled
                .iter()
                .filter(|p| Ecosystem::from_purl(&p.purl) == Some(*eco))
                .count()
        } else {
            eco_counts.get(eco).copied().unwrap_or(0)
        };
        if count > 0 {
            eco_parts.push(format!("{count} {}", eco.display_name()));
        }
    }
    let eco_summary = if eco_parts.is_empty() {
        String::new()
    } else {
        format!(" ({})", eco_parts.join(", "))
    };

    if !args.common.json && !args.common.silent {
        if show_progress {
            eprintln!("\rFound {package_count} packages{eco_summary}");
        } else {
            eprintln!("Found {package_count} packages{eco_summary}");
        }
        if !lockfile_only.purls.is_empty() {
            eprintln!(
                "Note: {} package(s) from {} are not yet installed (lockfile-only).",
                lockfile_only.purls.len(),
                lockfile_only.source,
            );
        }
    }

    // Query API in batches
    let mut all_packages_with_patches: Vec<BatchPackagePatches> = Vec::new();
    let mut can_access_paid_patches = false;
    let total_batches = all_purls.len().div_ceil(batch_size);
    let mut batch_error_count = 0usize;
    let mut last_batch_error: Option<String> = None;

    if show_progress {
        eprint!("Querying API for patches... (batch 1/{total_batches})");
    }

    for (batch_idx, chunk) in all_purls.chunks(batch_size).enumerate() {
        if show_progress {
            eprint!(
                "\rQuerying API for patches... (batch {}/{})",
                batch_idx + 1,
                total_batches
            );
        }

        let purls: Vec<String> = chunk.to_vec();
        let mut result = api_client
            .search_patches_batch(effective_org_slug, &purls)
            .await;

        // Fallback: a 401/403 against the authenticated endpoint can
        // mean a stale/revoked token. Retry against the public proxy
        // (free patches only) once, then continue the rest of the
        // loop with the downgraded client. Only triggers on the
        // first authenticated batch; subsequent iterations are
        // already on the proxy.
        if !use_public_proxy {
            if let Err(ref e) = result {
                if is_fallback_candidate(e) {
                    eprintln!(
                        "Warning: authenticated API returned {e}; \
                         falling back to public patch API proxy (free patches only)."
                    );
                    api_client = build_proxy_fallback_client(&overrides);
                    use_public_proxy = true;
                    fallback_to_proxy = true;
                    result = api_client
                        .search_patches_batch(effective_org_slug, &purls)
                        .await;
                }
            }
        }

        match result {
            Ok(response) => {
                if response.can_access_paid_patches {
                    can_access_paid_patches = true;
                }
                for pkg in response.packages {
                    if !pkg.patches.is_empty() {
                        all_packages_with_patches.push(pkg);
                    }
                }
            }
            Err(e) => {
                batch_error_count += 1;
                last_batch_error = Some(e.to_string());
                if !args.common.json {
                    eprintln!("\nError querying batch {}: {e}", batch_idx + 1);
                }
            }
        }
    }

    // If every batch errored, surface this as a full scan failure rather
    // than silently reporting zero patches (which historically looked
    // identical to "no patches for these packages").
    if total_batches > 0 && batch_error_count == total_batches {
        let err = last_batch_error.unwrap_or_else(|| "all batches failed".to_string());
        track_patch_scan_failed(
            &err,
            fallback_to_proxy,
            telemetry_token.as_deref(),
            telemetry_org.as_deref(),
        )
        .await;

        // A scan in which *every* batch failed produced no trustworthy
        // patch data. Surfacing `status: "success"` / exit 0 here would be
        // indistinguishable from a genuine "no patches" result and would
        // mask a total API outage. Report the failure explicitly and bail
        // before writing any manifest or attempting apply/prune.
        if args.common.json {
            let result = serde_json::json!({
                "status": "error",
                "error": err,
                "scannedPackages": package_count,
                "packagesWithPatches": 0,
                "totalPatches": 0,
                "freePatches": 0,
                "paidPatches": 0,
                "canAccessPaidPatches": false,
                "packages": [],
                "updates": [],
            });
            println!("{}", serde_json::to_string_pretty(&result).unwrap());
        } else {
            eprintln!("Error: all {total_batches} API batch queries failed: {err}");
        }
        return 1;
    }

    let total_patches_found: usize = all_packages_with_patches
        .iter()
        .map(|p| p.patches.len())
        .sum();

    if !args.common.json && !args.common.silent {
        if total_patches_found > 0 {
            if show_progress {
                eprintln!(
                    "\rFound {total_patches_found} patches for {} packages",
                    all_packages_with_patches.len()
                );
            } else {
                eprintln!(
                    "Found {total_patches_found} patches for {} packages",
                    all_packages_with_patches.len()
                );
            }
        } else if show_progress {
            eprintln!("\rAPI query complete");
        } else {
            eprintln!("API query complete");
        }
    }

    // Calculate patch counts
    let mut free_patches = 0usize;
    let mut paid_patches = 0usize;
    for pkg in &all_packages_with_patches {
        for patch in &pkg.patches {
            if patch.tier == "free" {
                free_patches += 1;
            } else {
                paid_patches += 1;
            }
        }
    }
    let total_patches = free_patches + paid_patches;

    // Telemetry: record the scan outcome once we have the canonical
    // per-tier counts. `fallback_to_proxy` is `true` iff the batch
    // loop downgraded from the authenticated endpoint to the public
    // proxy after a 401/403.
    track_patch_scanned(
        package_count,
        free_patches,
        paid_patches,
        can_access_paid_patches,
        args.common
            .ecosystems
            .clone()
            .unwrap_or_default()
            .as_slice(),
        fallback_to_proxy,
        telemetry_token.as_deref(),
        telemetry_org.as_deref(),
    )
    .await;

    // Registry-redirect mode is a distinct, self-contained flow (rewrite
    // lockfiles → hosted vendored patches). It reuses discovery above, then
    // returns — it must NOT fall through to the apply/vendor branches.
    if args.redirect {
        return run_redirect(
            &args,
            &api_client,
            effective_org_slug,
            &all_packages_with_patches,
            can_access_paid_patches,
        )
        .await;
    }

    // Read existing manifest once for update detection. Used by both the
    // JSON-mode emission (always includes an `updates` array) and the
    // non-JSON table-print path (counts `updates_available`).
    // (`manifest_path`/`socket_dir` are resolved at the top of `run`.)
    let existing_manifest = read_manifest(&manifest_path).await.ok().flatten();
    let updates = detect_updates(existing_manifest.as_ref(), &all_packages_with_patches);

    // Crawl PURLs as a set for prunable detection (manifest entries whose
    // PURL is not installed). Uses `installed_purls` — the UNFILTERED crawl
    // — not the `--ecosystems`-narrowed `all_purls`, so a display/query
    // filter never makes an installed package look prunable.
    let scanned_purls: HashSet<String> = installed_purls;

    if args.common.json {
        let mut result = serde_json::json!({
            "status": "success",
            "scannedPackages": package_count,
            "lockfileOnlyPackages": lockfile_only.purls.len(),
            "packagesWithPatches": all_packages_with_patches.len(),
            "totalPatches": total_patches,
            "freePatches": free_patches,
            "paidPatches": paid_patches,
            "canAccessPaidPatches": can_access_paid_patches,
            "packages": all_packages_with_patches,
            "updates": updates.iter().map(|u| serde_json::json!({
                "purl": u.purl,
                "oldUuid": u.old_uuid,
                "newUuid": u.new_uuid,
            })).collect::<Vec<_>>(),
        });
        // Flag lockfile-only packages so JSON consumers can tell "patch
        // available but not installed" from the installed case. Additive
        // field; absent means installed.
        if let Some(packages) = result["packages"].as_array_mut() {
            for pkg in packages {
                let is_lockfile_only = pkg["purl"]
                    .as_str()
                    .is_some_and(|p| lockfile_only.purls.contains(p));
                if is_lockfile_only {
                    pkg["notInstalled"] = serde_json::json!(true);
                }
            }
        }

        // `apply` and `prune` are computed once at the top of run()
        // (factoring in --sync, which implies both). They're independent
        // here: a bot can `--apply` without `--prune`, or `--prune`
        // without `--apply` (just GC-sweep), or both (full sync).
        let dry = args.common.dry_run;

        // --- Apply path (if requested) -----------------------------------
        if apply {
            let mut all_search_results: Vec<PatchSearchResult> = Vec::new();
            for pkg in &all_packages_with_patches {
                match api_client
                    .search_patches_by_package(effective_org_slug, &pkg.purl)
                    .await
                {
                    Ok(response) => all_search_results.extend(response.patches),
                    Err(_) => continue,
                }
            }

            // For scan-driven bot workflows there's no "specify --id"
            // option — we're scanning the whole project. Pass
            // `is_json = false` so `select_one` auto-selects the newest
            // patch in non-TTY mode rather than erroring with
            // `selection_required`.
            let selected = if all_search_results.is_empty() {
                Vec::new()
            } else {
                match select_patches(&all_search_results, can_access_paid_patches, false) {
                    Ok(s) => s,
                    Err(code) => return code,
                }
            };

            // Vendor-owned purls are skipped BEFORE download (any uuid):
            // the patch is consumed from the committed artifact, and
            // moving the manifest past the vendored uuid would break VEX
            // verification (`vendor_uuid_mismatch`) until a vendor run.
            // A newer patch still surfaces in `updates[]` — the
            // operator's signal to run `scan --vendor` (or `vendor`).
            let (selected, vendored_records) =
                partition_vendored_selected(selected, &vendored_purls);
            // Lockfile-only purls leave the apply selection here (calm
            // skip records, never an error); the union rides the same
            // bookkeeping as the vendored skips.
            let (selected, vendored_records) = {
                let (kept, not_installed) =
                    partition_not_installed_selected(selected, &lockfile_only.purls);
                let mut all = vendored_records;
                all.extend(not_installed);
                all.sort_by(|a, b| a["purl"].as_str().cmp(&b["purl"].as_str()));
                (kept, all)
            };

            let mut apply_code = 0i32;
            if dry {
                // Synthesize the per-patch outcome without touching disk.
                // `decide_patch_action` consults the existing manifest,
                // so it accurately reports what `--apply` *would* do.
                let manifest_for_preview =
                    existing_manifest.clone().unwrap_or_else(PatchManifest::new);
                let mut patches: Vec<serde_json::Value> = selected
                    .iter()
                    .map(|p| {
                        match super::get::decide_patch_action(
                            &manifest_for_preview,
                            &p.purl,
                            &p.uuid,
                        ) {
                            super::get::PatchAction::Added => serde_json::json!({
                                "purl": p.purl, "uuid": p.uuid, "action": "added",
                            }),
                            super::get::PatchAction::Updated { old_uuid } => serde_json::json!({
                                "purl": p.purl, "uuid": p.uuid,
                                "action": "updated", "oldUuid": old_uuid,
                            }),
                            super::get::PatchAction::Skipped => serde_json::json!({
                                "purl": p.purl, "uuid": p.uuid, "action": "skipped",
                            }),
                        }
                    })
                    .collect();
                patches.extend(vendored_records.iter().cloned());
                let added = patches.iter().filter(|p| p["action"] == "added").count();
                let updated = patches.iter().filter(|p| p["action"] == "updated").count();
                let skipped = patches.iter().filter(|p| p["action"] == "skipped").count();
                result["apply"] = serde_json::json!({
                    "found": selected.len() + vendored_records.len(),
                    "downloaded": 0,
                    "skipped": skipped,
                    "failed": 0,
                    "applied": 0,
                    "updated": updated,
                    "added": added,
                    "patches": patches,
                    "dryRun": true,
                });
            } else if selected.is_empty() {
                // No patches left to download (e.g. all paid for a free
                // user, no packages had patches, or everything selected is
                // vendor-owned). Emit a stable-shape `apply` carrying any
                // vendored skips, then fall through to GC if requested.
                result["apply"] = serde_json::json!({
                    "found": vendored_records.len(),
                    "downloaded": 0,
                    "skipped": vendored_records.len(),
                    "failed": 0, "applied": 0, "updated": 0,
                    "patches": vendored_records,
                });
            } else {
                let params = DownloadParams {
                    cwd: args.common.cwd.clone(),
                    org: args.common.org.clone(),
                    save_only: false,
                    one_off: false,
                    global: args.common.global,
                    global_prefix: args.common.global_prefix.clone(),
                    json: true,
                    silent: true,
                    download_mode: args.common.download_mode.clone(),
                    api_overrides: args.common.api_client_overrides(),
                    all_releases: args.all_releases,
                    strict: args.common.strict,
                    persist_blobs: !args.vendor,
                };
                let (code, apply_json) = download_and_apply_patches(&selected, &params).await;
                apply_code = code;
                let mut apply_obj = apply_json;
                fold_vendored_skips_into_apply(&mut apply_obj, &vendored_records);
                result["apply"] = apply_obj;
                if apply_code != 0 {
                    result["status"] = serde_json::json!("partial_failure");
                }
            }

            // --- GC (if requested) --------------------------------------
            if prune {
                let gc = if dry {
                    preview_apply_gc(
                        &args.common,
                        &manifest_path,
                        &socket_dir,
                        &scanned_purls,
                        &vendored_purls,
                    )
                    .await
                } else {
                    run_apply_gc(
                        &args.common,
                        &manifest_path,
                        &socket_dir,
                        &scanned_purls,
                        &vendored_purls,
                    )
                    .await
                };
                result["gc"] = if dry {
                    gc.to_preview_json()
                } else {
                    gc.to_apply_json()
                };
            }

            let final_code = embed_vex_into_json(
                &args.common,
                &args.vex,
                &manifest_path,
                apply_code,
                &mut result,
            )
            .await;
            println!("{}", serde_json::to_string_pretty(&result).unwrap());
            return final_code;
        }

        // --- Vendor path (if requested) ----------------------------------
        if args.vendor {
            // Extracted into its own boxed fn — and it must STAY extracted:
            // this branch's temporaries (json! trees, DownloadParams, the
            // engine dispatch) live in the enclosing poll frame in debug
            // builds even when the branch is never taken, and that frame
            // has to fit Windows' 1 MiB main-thread stack (regression-
            // pinned by `scan_run_fits_windows_main_thread_stack`).
            return boxed_vendor_json_path(
                &args,
                &api_client,
                effective_org_slug,
                &all_packages_with_patches,
                can_access_paid_patches,
                &mut result,
                &manifest_path,
                &socket_dir,
                &scanned_purls,
                &vendored_purls,
                prune,
                telemetry_token.as_deref(),
                telemetry_org.as_deref(),
            )
            .await;
        }

        // --- GC-only path (no --apply, just --prune) --------------------
        if prune {
            let gc = if dry {
                preview_apply_gc(
                    &args.common,
                    &manifest_path,
                    &socket_dir,
                    &scanned_purls,
                    &vendored_purls,
                )
                .await
            } else {
                run_apply_gc(
                    &args.common,
                    &manifest_path,
                    &socket_dir,
                    &scanned_purls,
                    &vendored_purls,
                )
                .await
            };
            result["gc"] = if dry {
                gc.to_preview_json()
            } else {
                gc.to_apply_json()
            };
        }

        let final_code =
            embed_vex_into_json(&args.common, &args.vex, &manifest_path, 0, &mut result).await;
        println!("{}", serde_json::to_string_pretty(&result).unwrap());
        return final_code;
    }

    let use_color = stdout_is_tty();

    if all_packages_with_patches.is_empty() {
        if !args.common.silent {
            println!("\nNo patches available for installed packages.");
        }
        return embed_vex_human(&args.common, &args.vex, &manifest_path, 0).await;
    }

    // The whole table + summary section is presentational only (nothing
    // computed inside is consumed downstream), so `--silent` skips it
    // wholesale.
    if !args.common.silent {
        let mut updates_available = 0usize;

        // Canonical set of PURLs with a newer patch available, computed once via
        // `detect_updates` (the same source the JSON `updates` array uses). The
        // table path MUST agree with the JSON path, so reuse that result rather
        // than re-deriving it: comparing against *any* batch patch (instead of the
        // first/candidate one `select_patches` would resolve to) over-reports
        // updates whenever the manifest already holds the newest patch but older
        // patches also appear in the batch.
        let update_purls: HashSet<&str> = updates.iter().map(|u| u.purl.as_str()).collect();

        // Print table
        println!("\n{}", "=".repeat(100));
        println!(
            "{}  {}  {}  VULNERABILITIES",
            "PACKAGE".to_string() + &" ".repeat(33),
            "PATCHES".to_string() + " ",
            "SEVERITY".to_string() + &" ".repeat(8),
        );
        println!("{}", "=".repeat(100));

        for pkg in &all_packages_with_patches {
            // Char-safe truncation: a byte slice (`&pkg.purl[..37]`) panics
            // when the cut lands mid-codepoint. PURLs can carry non-ASCII
            // names/qualifiers, so route through the shared helper.
            let display_purl = truncate_with_ellipsis(&pkg.purl, 40);

            let pkg_free = pkg.patches.iter().filter(|p| p.tier == "free").count();
            let pkg_paid = pkg.patches.iter().filter(|p| p.tier == "paid").count();

            let count_str = if pkg_paid > 0 {
                if can_access_paid_patches {
                    format!("{}+{}", pkg_free, pkg_paid)
                } else {
                    format!(
                        "{}+{}",
                        pkg_free,
                        color(&pkg_paid.to_string(), "33", use_color)
                    )
                }
            } else {
                format!("{}", pkg_free)
            };

            // Get highest severity
            let severity = pkg
                .patches
                .iter()
                .filter_map(|p| p.severity.as_deref())
                .min_by_key(|s| severity_order(s))
                .unwrap_or("unknown");

            // Collect vuln IDs (deterministic: deduped, CVEs then GHSAs,
            // each group sorted — see collect_vuln_ids).
            let vuln_ids = collect_vuln_ids(pkg);
            let vuln_str = if vuln_ids.len() > 2 {
                format!("{} (+{})", vuln_ids[..2].join(", "), vuln_ids.len() - 2)
            } else if vuln_ids.is_empty() {
                "-".to_string()
            } else {
                vuln_ids.join(", ")
            };

            // Check for updates — consult the canonical `detect_updates` result
            // (mirrored into `update_purls`) so the human table and JSON `updates`
            // array never disagree.
            let has_update = update_purls.contains(pkg.purl.as_str());
            if has_update {
                updates_available += 1;
            }

            let update_marker = if has_update {
                color(" [UPDATE]", "33", use_color)
            } else {
                String::new()
            };
            // Lockfile-only packages can be patched by `scan --vendor`
            // (which fetches them pristine) but not applied in place.
            let not_installed_marker = if lockfile_only.purls.contains(pkg.purl.as_str()) {
                color(" [NOT INSTALLED]", "33", use_color)
            } else {
                String::new()
            };

            println!(
                "{:<40}  {:>8}  {:<16}  {}{}{}",
                display_purl,
                count_str,
                format_severity(severity, use_color),
                vuln_str,
                update_marker,
                not_installed_marker,
            );
        }

        println!("{}", "=".repeat(100));

        // Summary
        if can_access_paid_patches {
            println!(
                "\nSummary: {} package(s) with {} available patch(es)",
                all_packages_with_patches.len(),
                total_patches,
            );
        } else {
            println!(
                "\nSummary: {} package(s) with {} free patch(es)",
                all_packages_with_patches.len(),
                free_patches,
            );
            if paid_patches > 0 {
                println!(
                    "{}",
                    color(
                        &format!(
                            "         + {} additional patch(es) available with paid subscription",
                            paid_patches
                        ),
                        "33",
                        use_color,
                    ),
                );
                println!(
                    "\nUpgrade to Socket's paid plan to access all patches: https://socket.dev/pricing"
                );
            }
        }

        if updates_available > 0 {
            println!(
                "\n{}",
                color(
                    &format!("{updates_available} package(s) have newer patches available."),
                    "33",
                    use_color,
                ),
            );
        }
    }

    // Count downloadable patches
    let downloadable_count = if can_access_paid_patches {
        all_packages_with_patches.len()
    } else {
        all_packages_with_patches
            .iter()
            .filter(|pkg| pkg.patches.iter().any(|p| p.tier == "free"))
            .count()
    };

    if downloadable_count == 0 {
        if !args.common.silent {
            println!("\nNo downloadable patches (paid subscription required).");
        }
        return embed_vex_human(&args.common, &args.vex, &manifest_path, 0).await;
    }

    // Fetch full PatchSearchResult for each package that has patches
    if show_progress {
        eprint!("\nFetching patch details...");
    }

    let mut all_search_results: Vec<PatchSearchResult> = Vec::new();
    for (i, pkg) in all_packages_with_patches.iter().enumerate() {
        if show_progress {
            eprint!(
                "\rFetching patch details... ({}/{})",
                i + 1,
                all_packages_with_patches.len()
            );
        }
        match api_client
            .search_patches_by_package(effective_org_slug, &pkg.purl)
            .await
        {
            Ok(response) => {
                all_search_results.extend(response.patches);
            }
            Err(e) => {
                if !args.common.silent {
                    eprintln!("\n  Warning: could not fetch details for {}: {e}", pkg.purl);
                }
            }
        }
    }

    if show_progress {
        eprintln!();
    }

    if all_search_results.is_empty() {
        eprintln!("Could not fetch patch details.");
        return 1;
    }

    // Smart selection
    let selected: Vec<PatchSearchResult> =
        match select_patches(&all_search_results, can_access_paid_patches, false) {
            Ok(s) => s,
            Err(code) => return code,
        };

    // Vendor-owned purls never download/apply here (mirrors the JSON
    // path): the committed artifact is the patch, and a manifest moved
    // past the vendored uuid would break VEX verification until a vendor
    // run refreshes the artifact. In `--vendor` mode the partition is a
    // no-op — re-vendoring a stale uuid is exactly what the flag is for.
    let is_vendored =
        |p: &str| vendored_purls.contains(p) || vendored_purls.contains(strip_purl_qualifiers(p));
    let (vendored_selected, selected): (Vec<_>, Vec<_>) = if args.vendor {
        (Vec::new(), selected)
    } else {
        selected.into_iter().partition(|p| is_vendored(&p.purl))
    };
    if !args.common.silent {
        for p in &vendored_selected {
            println!(
                "  [skip] {} (vendored — run scan --vendor to update)",
                normalize_purl(&p.purl)
            );
        }
    }

    // Lockfile-only purls leave the in-place apply selection (calm skip,
    // mirrors the JSON path). In `--vendor` mode they stay: the vendor
    // engine fetches lockfile-resolved packages pristine.
    let (selected, not_installed_selected): (Vec<_>, Vec<String>) = if args.vendor {
        (selected, Vec::new())
    } else {
        let (kept, skipped) = partition_not_installed_selected(selected, &lockfile_only.purls);
        let printed: Vec<String> = skipped
            .iter()
            .filter_map(|r| r["purl"].as_str().map(str::to_string))
            .collect();
        (kept, printed)
    };
    if !args.common.silent {
        for purl in &not_installed_selected {
            println!(
                "  [skip] {} (not installed — run your package manager's install first, \
                 or `scan --vendor` to vendor it from the lockfile)",
                normalize_purl(purl)
            );
        }
    }

    if selected.is_empty() && !args.vendor {
        if !args.common.silent {
            println!("No patches selected.");
        }
        return embed_vex_human(&args.common, &args.vex, &manifest_path, 0).await;
    }

    // Vendor mode: pre-verify baselines so a content mismatch surfaces
    // BEFORE the confirm prompt (vendoring still proceeds for these —
    // the stage force-applies the verified patched content).
    let mismatched_baselines: HashSet<String> = if args.vendor && !args.common.silent {
        preverify_vendor_baselines(
            &api_client,
            effective_org_slug,
            &selected,
            &filtered_crawled,
            &lockfile_only.purls,
        )
        .await
    } else {
        HashSet::new()
    };

    // Display detailed summary of selected patches before confirming
    // (presentational only — skipped wholesale under --silent).
    if !args.common.silent {
        if args.vendor {
            println!("\nPatches to vendor:\n");
        } else {
            println!("\nPatches to apply:\n");
        }
        for patch in &selected {
            // Collect CVE/GHSA IDs and highest severity from vulnerabilities
            let mut vuln_ids: Vec<String> = Vec::new();
            let mut highest_severity: Option<&str> = None;
            for (id, vuln) in &patch.vulnerabilities {
                if vuln.cves.is_empty() {
                    vuln_ids.push(id.clone());
                } else {
                    for cve in &vuln.cves {
                        vuln_ids.push(cve.clone());
                    }
                }
                let sev = vuln.severity.as_str();
                if highest_severity.is_none_or(|cur| severity_order(sev) < severity_order(cur)) {
                    highest_severity = Some(sev);
                }
            }

            let sev_display = highest_severity.unwrap_or("unknown");
            let sev_colored = format_severity(sev_display, use_color);

            // Char-safe: descriptions come straight from the API and routinely
            // contain non-ASCII text; a `&desc[..69]` byte slice would panic.
            let desc = truncate_with_ellipsis(&patch.description, 72);

            println!(
                "  {} [{}] {}",
                // Human display only: show the decoded form of an
                // API-encoded purl (`%40scope` → `@scope`). JSON output
                // keeps the verbatim key.
                normalize_purl(&patch.purl),
                patch.tier.to_uppercase(),
                sev_colored,
            );
            if mismatched_baselines.contains(&patch.uuid) {
                println!(
                    "    (installed content differs from patch baseline — will vendor patched content)"
                );
            }
            if !vuln_ids.is_empty() {
                println!("    Fixes: {}", vuln_ids.join(", "));
            }
            // Show per-vulnerability summaries
            for vuln in patch.vulnerabilities.values() {
                if !vuln.summary.is_empty() {
                    // Char-safe: vulnerability summaries are API-sourced free
                    // text; a `&summary[..73]` byte slice would panic mid-codepoint.
                    let summary = truncate_with_ellipsis(&vuln.summary, 76);
                    let cve_label = if vuln.cves.is_empty() {
                        String::new()
                    } else {
                        format!("{}: ", vuln.cves.join(", "))
                    };
                    println!("    - {cve_label}{summary}");
                }
            }
            if !desc.is_empty() {
                println!("    {desc}");
            }
            println!();
        }
    }

    // `--dry-run` is a non-mutating preview (see the global flag's doc and
    // the JSON path's `dryRun` envelope). The interactive path must honor it
    // too: stop here, having printed the table and the per-patch plan above,
    // before the confirm prompt, the download/apply, and the prune GC — all
    // of which mutate the manifest and `.socket/` on disk.
    if args.common.dry_run {
        if !args.common.silent {
            let action = if args.vendor {
                "download and vendor"
            } else {
                "download and apply"
            };
            println!(
                "\n[dry-run] Would {action} {} patch(es). No changes made.",
                selected.len()
            );
        }
        return embed_vex_human(&args.common, &args.vex, &manifest_path, 0).await;
    }

    // Prompt to download
    let verb = if args.vendor { "vendor" } else { "apply" };
    let prompt = format!("Download and {verb} {} patch(es)?", selected.len());
    if !confirm(&prompt, true, args.common.yes, args.common.json) {
        if !args.common.silent {
            println!("\nTo apply a patch, run:");
            println!("  socket-patch get <package-name-or-purl>");
            println!("  socket-patch get <CVE-ID>");
        }
        return embed_vex_human(&args.common, &args.vex, &manifest_path, 0).await;
    }

    // Download, then apply in place — or vendor (`--vendor`).
    let params = DownloadParams {
        cwd: args.common.cwd.clone(),
        org: args.common.org.clone(),
        // Vendor mode downloads only; the vendor step below does the rest.
        save_only: args.vendor,
        one_off: false,
        global: args.common.global,
        global_prefix: args.common.global_prefix.clone(),
        json: false,
        silent: args.common.silent,
        download_mode: args.common.download_mode.clone(),
        api_overrides: args.common.api_client_overrides(),
        all_releases: args.all_releases,
        strict: args.common.strict,
        persist_blobs: !args.vendor,
    };

    let code = if args.vendor {
        // Extracted + boxed for the same Windows-1-MiB-frame reason as the
        // JSON path (see `run_vendor_json_path`).
        boxed_vendor_interactive_path(
            &args,
            &selected,
            &params,
            &manifest_path,
            &socket_dir,
            &scanned_purls,
            &vendored_purls,
            prune,
            telemetry_token.as_deref(),
            telemetry_org.as_deref(),
        )
        .await
    } else {
        let (code, _) = download_and_apply_patches(&selected, &params).await;
        code
    };

    // Post-apply GC: only runs when the user opted in via `--prune` or
    // `--sync`. Default `scan --yes` no longer touches the manifest
    // beyond what `--apply` added — users wanting to clean up should
    // run `socket-patch gc` (or `repair`) explicitly. (Vendor mode
    // already ran its GC before the vendor step.)
    if prune && !args.vendor {
        let gc = run_apply_gc(
            &args.common,
            &manifest_path,
            &socket_dir,
            &scanned_purls,
            &vendored_purls,
        )
        .await;
        let total = gc.blobs.blobs_removed + gc.diffs.blobs_removed + gc.packages.blobs_removed;
        if !args.common.silent && (!gc.pruned.is_empty() || total > 0) {
            println!(
                "\nGC: pruned {} manifest entr{} and removed {} orphan file{} ({}).",
                gc.pruned.len(),
                if gc.pruned.len() == 1 { "y" } else { "ies" },
                total,
                if total == 1 { "" } else { "s" },
                socket_patch_core::utils::cleanup_blobs::format_bytes(gc.total_bytes()),
            );
        }
        if !args.common.silent && (!gc.vendored_reverted.is_empty() || gc.vendor_orphan_dirs > 0) {
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
    }

    embed_vex_human(&args.common, &args.vex, &manifest_path, code).await
}

pub(crate) fn severity_order(s: &str) -> u8 {
    match s.to_lowercase().as_str() {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        _ => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use socket_patch_core::api::types::{BatchPackagePatches, BatchPatchInfo};
    use socket_patch_core::manifest::schema::{PatchManifest, PatchRecord};
    use std::collections::HashMap;

    // ---- severity_order ----------------------------------------------------

    #[test]
    fn severity_order_critical_is_zero() {
        assert_eq!(severity_order("critical"), 0);
    }

    #[test]
    fn severity_order_is_case_insensitive() {
        assert_eq!(severity_order("Critical"), 0);
        assert_eq!(severity_order("CRITICAL"), 0);
        assert_eq!(severity_order("High"), 1);
    }

    #[test]
    fn severity_order_known_levels() {
        assert_eq!(severity_order("high"), 1);
        assert_eq!(severity_order("medium"), 2);
        assert_eq!(severity_order("low"), 3);
    }

    #[test]
    fn severity_order_unknown_is_four() {
        assert_eq!(severity_order("unknown"), 4);
        assert_eq!(severity_order(""), 4);
        assert_eq!(severity_order("informational"), 4);
    }

    // ---- detect_updates -----------------------------------------------------

    fn manifest_with(entries: &[(&str, &str)]) -> PatchManifest {
        let mut m = PatchManifest::new();
        for (purl, uuid) in entries {
            m.patches.insert(
                (*purl).to_string(),
                PatchRecord {
                    uuid: (*uuid).to_string(),
                    exported_at: String::new(),
                    files: HashMap::new(),
                    vulnerabilities: HashMap::new(),
                    description: String::new(),
                    license: String::new(),
                    tier: "free".to_string(),
                },
            );
        }
        m
    }

    fn batch_with(purl: &str, uuids: &[&str]) -> BatchPackagePatches {
        BatchPackagePatches {
            purl: purl.to_string(),
            patches: uuids
                .iter()
                .map(|u| BatchPatchInfo {
                    uuid: (*u).to_string(),
                    purl: purl.to_string(),
                    tier: "free".to_string(),
                    cve_ids: Vec::new(),
                    ghsa_ids: Vec::new(),
                    severity: None,
                    title: String::new(),
                })
                .collect(),
        }
    }

    #[test]
    fn detect_updates_returns_empty_when_no_manifest() {
        let pkgs = vec![batch_with("pkg:npm/foo@1.0", &["uuid-a"])];
        assert!(detect_updates(None, &pkgs).is_empty());
    }

    #[test]
    fn detect_updates_returns_empty_for_empty_packages() {
        let m = manifest_with(&[("pkg:npm/foo@1.0", "uuid-a")]);
        assert!(detect_updates(Some(&m), &[]).is_empty());
    }

    #[test]
    fn detect_updates_returns_empty_when_no_overlap() {
        let m = manifest_with(&[("pkg:npm/foo@1.0", "uuid-a")]);
        let pkgs = vec![batch_with("pkg:npm/bar@2.0", &["uuid-z"])];
        assert!(detect_updates(Some(&m), &pkgs).is_empty());
    }

    #[test]
    fn detect_updates_skips_same_uuid() {
        let m = manifest_with(&[("pkg:npm/foo@1.0", "uuid-a")]);
        let pkgs = vec![batch_with("pkg:npm/foo@1.0", &["uuid-a"])];
        assert!(detect_updates(Some(&m), &pkgs).is_empty());
    }

    #[test]
    fn detect_updates_flags_different_uuid() {
        let m = manifest_with(&[("pkg:npm/foo@1.0", "uuid-a")]);
        let pkgs = vec![batch_with("pkg:npm/foo@1.0", &["uuid-b"])];
        let updates = detect_updates(Some(&m), &pkgs);
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].purl, "pkg:npm/foo@1.0");
        assert_eq!(updates[0].old_uuid, "uuid-a");
        assert_eq!(updates[0].new_uuid, "uuid-b");
    }

    #[test]
    fn detect_updates_reports_multiple_updates() {
        let m = manifest_with(&[("pkg:npm/foo@1.0", "uuid-a"), ("pkg:npm/bar@2.0", "uuid-c")]);
        let pkgs = vec![
            batch_with("pkg:npm/foo@1.0", &["uuid-b"]),
            batch_with("pkg:npm/bar@2.0", &["uuid-d"]),
        ];
        let updates = detect_updates(Some(&m), &pkgs);
        assert_eq!(updates.len(), 2);
    }

    #[test]
    fn detect_updates_skips_packages_with_empty_patch_list() {
        let m = manifest_with(&[("pkg:npm/foo@1.0", "uuid-a")]);
        // No candidate patches means we can't tell what the new UUID would
        // be, so there's nothing to compare against. Correct behavior is to
        // skip these silently.
        let pkgs = vec![batch_with("pkg:npm/foo@1.0", &[])];
        assert!(detect_updates(Some(&m), &pkgs).is_empty());
    }

    #[test]
    fn detect_updates_uses_first_patch_as_candidate() {
        // `detect_updates` mirrors `select_patches` by picking the first
        // patch in the batch as the candidate UUID. Locking this in so a
        // future select_patches refactor doesn't silently drift the two.
        let m = manifest_with(&[("pkg:npm/foo@1.0", "uuid-a")]);
        let pkgs = vec![batch_with("pkg:npm/foo@1.0", &["uuid-b", "uuid-c"])];
        let updates = detect_updates(Some(&m), &pkgs);
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].new_uuid, "uuid-b");
    }

    #[test]
    fn detect_updates_no_update_when_manifest_holds_candidate_despite_other_patches() {
        // Regression: the human-readable table once flagged `[UPDATE]` (and
        // bumped `updates_available`) whenever *any* batch patch differed from
        // the manifest UUID. But the apply path resolves to the FIRST patch,
        // so a manifest already holding that candidate is up to date even when
        // the batch also lists older patches. The table and the JSON `updates`
        // array must agree; both derive from this function, which compares the
        // candidate (first) patch only.
        let m = manifest_with(&[("pkg:npm/foo@1.0", "uuid-newest")]);
        let pkgs = vec![batch_with(
            "pkg:npm/foo@1.0",
            &["uuid-newest", "uuid-older", "uuid-oldest"],
        )];
        assert!(
            detect_updates(Some(&m), &pkgs).is_empty(),
            "manifest already holds the candidate (first) patch — no update"
        );
    }

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

    // ---- collect_vuln_ids --------------------------------------------------

    /// Build a single-patch package whose patch carries the given CVE and
    /// GHSA identifier lists.
    fn batch_with_vulns(purl: &str, cves: &[&str], ghsas: &[&str]) -> BatchPackagePatches {
        BatchPackagePatches {
            purl: purl.to_string(),
            patches: vec![BatchPatchInfo {
                uuid: "uuid".to_string(),
                purl: purl.to_string(),
                tier: "free".to_string(),
                cve_ids: cves.iter().map(|s| (*s).to_string()).collect(),
                ghsa_ids: ghsas.iter().map(|s| (*s).to_string()).collect(),
                severity: None,
                title: String::new(),
            }],
        }
    }

    #[test]
    fn collect_vuln_ids_empty_when_no_vulns() {
        let pkg = batch_with_vulns("pkg:npm/foo@1.0", &[], &[]);
        assert!(collect_vuln_ids(&pkg).is_empty());
    }

    #[test]
    fn collect_vuln_ids_lists_cves_before_ghsas_each_sorted() {
        // Deliberately unsorted input; output must be CVEs (sorted) then
        // GHSAs (sorted) so the rendered table column is deterministic.
        let pkg = batch_with_vulns(
            "pkg:npm/foo@1.0",
            &["CVE-2024-2", "CVE-2024-1"],
            &["GHSA-zzzz-zzzz-zzzz", "GHSA-aaaa-aaaa-aaaa"],
        );
        assert_eq!(
            collect_vuln_ids(&pkg),
            vec![
                "CVE-2024-1".to_string(),
                "CVE-2024-2".to_string(),
                "GHSA-aaaa-aaaa-aaaa".to_string(),
                "GHSA-zzzz-zzzz-zzzz".to_string(),
            ],
        );
    }

    #[test]
    fn collect_vuln_ids_dedups_across_patches() {
        // The same CVE appears on two patches of one package; it must be
        // reported once.
        let pkg = BatchPackagePatches {
            purl: "pkg:npm/foo@1.0".to_string(),
            patches: vec![
                BatchPatchInfo {
                    uuid: "u1".to_string(),
                    purl: "pkg:npm/foo@1.0".to_string(),
                    tier: "free".to_string(),
                    cve_ids: vec!["CVE-2024-1".to_string()],
                    ghsa_ids: vec![],
                    severity: None,
                    title: String::new(),
                },
                BatchPatchInfo {
                    uuid: "u2".to_string(),
                    purl: "pkg:npm/foo@1.0".to_string(),
                    tier: "free".to_string(),
                    cve_ids: vec!["CVE-2024-1".to_string()],
                    ghsa_ids: vec!["GHSA-aaaa-aaaa-aaaa".to_string()],
                    severity: None,
                    title: String::new(),
                },
            ],
        };
        assert_eq!(
            collect_vuln_ids(&pkg),
            vec!["CVE-2024-1".to_string(), "GHSA-aaaa-aaaa-aaaa".to_string(),],
        );
    }

    // ---- truncate_with_ellipsis (scan's display columns) -------------------
    // scan.rs renders PURLs, descriptions, and vulnerability summaries — all
    // API-sourced and potentially non-ASCII — into fixed-width columns. These
    // pin scan's use of the char-safe helper; a raw `&s[..n]` byte slice
    // would panic when the cut lands mid-codepoint.

    #[test]
    fn truncate_multibyte_purl_does_not_panic() {
        // 30 three-byte chars (90 bytes, 30 chars). The old purl path sliced
        // `&purl[..37]` once `len() > 40`; byte 37 splits a codepoint here.
        let purl = format!("pkg:npm/{}", "日".repeat(30));
        let out = truncate_with_ellipsis(&purl, 40);
        assert!(out.chars().count() <= 40);
    }

    #[test]
    fn truncate_multibyte_description_truncates_on_char_boundary() {
        // 100 two-byte chars; description column truncates at 72.
        let desc = "é".repeat(100);
        let out = truncate_with_ellipsis(&desc, 72);
        assert_eq!(out.chars().count(), 72);
        assert!(out.ends_with("..."));
    }

    #[test]
    fn truncate_multibyte_summary_truncates_on_char_boundary() {
        // Summary column truncates at 76.
        let summary = "—".repeat(100); // em dash, 3 bytes each
        let out = truncate_with_ellipsis(&summary, 76);
        assert_eq!(out.chars().count(), 76);
        assert!(out.ends_with("..."));
    }
}
