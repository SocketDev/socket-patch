use clap::Args;
use socket_patch_core::api::client::{
    build_proxy_fallback_client, get_api_client_with_overrides, is_fallback_candidate,
};
use socket_patch_core::api::types::{BatchPackagePatches, PatchSearchResult};
use socket_patch_core::crawlers::{CrawlerOptions, Ecosystem};
use socket_patch_core::manifest::operations::{read_manifest, write_manifest};
use socket_patch_core::manifest::schema::PatchManifest;
use socket_patch_core::utils::cleanup_blobs::{
    cleanup_unused_archives, cleanup_unused_blobs, CleanupResult,
};
use socket_patch_core::utils::purl::strip_purl_qualifiers;
use socket_patch_core::utils::telemetry::{track_patch_scan_failed, track_patch_scanned};
use std::collections::HashSet;
use std::path::Path;

use crate::args::{apply_env_toggles, GlobalArgs};
use crate::commands::vex::{generate_vex_from_manifest_path, VexEmbedArgs};
use crate::ecosystem_dispatch::crawl_all_ecosystems;
use crate::output::{color, confirm, format_severity, stderr_is_tty, stdout_is_tty};

use super::get::{
    download_and_apply_patches, select_patches, truncate_with_ellipsis, DownloadParams,
};

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
    /// `true` when `--no-prune` was set; the sub-object only carries the
    /// `skipped: true` field in that case.
    pub skipped: bool,
}

impl GcSummary {
    fn total_bytes(&self) -> u64 {
        self.blobs.bytes_freed + self.diffs.bytes_freed + self.packages.bytes_freed
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
    }
}

/// Apply-mode GC: re-read the manifest written by `download_and_apply_patches`,
/// prune manifest entries for PURLs not in `scanned_purls`, write the manifest
/// back, then sweep orphan blob/diff/package files. Callers must gate on the
/// `prune` flag — when GC isn't requested, simply don't call this function and
/// don't emit a `gc` sub-object.
async fn run_apply_gc(
    manifest_path: &Path,
    socket_dir: &Path,
    scanned_purls: &HashSet<String>,
) -> GcSummary {
    // Re-read the just-written manifest (the apply step may have added
    // or updated entries we now want to consider for pruning).
    let mut manifest = match read_manifest(manifest_path).await {
        Ok(Some(m)) => m,
        _ => return GcSummary::default(),
    };
    let prunable = detect_prunable(&manifest, scanned_purls);
    for purl in &prunable {
        manifest.patches.remove(purl);
    }
    if !prunable.is_empty() {
        // If pruning failed mid-write the manifest may be stale, but the
        // file-level cleanup below still operates on the in-memory copy.
        let _ = write_manifest(manifest_path, &manifest).await;
    }
    run_gc(&manifest, prunable, socket_dir, /*dry_run=*/false).await
}

/// Dry-run preview of the apply-mode GC pass. Same shape as
/// [`run_apply_gc`] but emits `prunable*`/`orphan*` field names and
/// performs no mutation.
async fn preview_apply_gc(
    manifest_path: &Path,
    socket_dir: &Path,
    scanned_purls: &HashSet<String>,
) -> GcSummary {
    let mut manifest = match read_manifest(manifest_path).await {
        Ok(Some(m)) => m,
        _ => return GcSummary::default(),
    };
    let prunable = detect_prunable(&manifest, scanned_purls);
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
    run_gc(&manifest, prunable, socket_dir, /*dry_run=*/true).await
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
pub(crate) fn detect_prunable(
    manifest: &PatchManifest,
    scanned_purls: &HashSet<String>,
) -> Vec<String> {
    let scanned_bases: HashSet<&str> =
        scanned_purls.iter().map(|p| strip_purl_qualifiers(p)).collect();
    manifest
        .patches
        .keys()
        .filter(|p| !scanned_bases.contains(strip_purl_qualifiers(p)))
        .cloned()
        .collect()
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
    /// non-JSON path always prompts the user).
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

pub async fn run(args: ScanArgs) -> i32 {
    apply_env_toggles(&args.common);

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

    let show_progress = !args.common.json && stderr_is_tty();

    if show_progress {
        eprint!("Scanning {scan_target}...");
    }

    // Crawl packages
    let (all_crawled, eco_counts) = crawl_all_ecosystems(&crawler_options).await;

    // Every PURL the crawl found, captured BEFORE the `--ecosystems`
    // display/query filter is applied. Prune (below) must reference the
    // full installed set: `--ecosystems npm` narrows what we *query and
    // show*, but packages of other ecosystems are still installed. If
    // prune used the filtered set instead, `scan --ecosystems npm --prune`
    // would treat every cargo/go/pypi/gem manifest entry as "uninstalled"
    // and delete it (plus its blobs) — silent cross-ecosystem data loss.
    let installed_purls: HashSet<String> =
        all_crawled.iter().map(|p| p.purl.clone()).collect();

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
            args.common.ecosystems.clone().unwrap_or_default().as_slice(),
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
            filtered_crawled.iter().filter(|p| Ecosystem::from_purl(&p.purl) == Some(*eco)).count()
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

    if !args.common.json {
        if show_progress {
            eprintln!("\rFound {package_count} packages{eco_summary}");
        } else {
            eprintln!("Found {package_count} packages{eco_summary}");
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
        let err = last_batch_error
            .unwrap_or_else(|| "all batches failed".to_string());
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

    if !args.common.json {
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
        args.common.ecosystems.clone().unwrap_or_default().as_slice(),
        fallback_to_proxy,
        telemetry_token.as_deref(),
        telemetry_org.as_deref(),
    )
    .await;

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

            let mut apply_code = 0i32;
            if dry {
                // Synthesize the per-patch outcome without touching disk.
                // `decide_patch_action` consults the existing manifest,
                // so it accurately reports what `--apply` *would* do.
                let manifest_for_preview = existing_manifest
                    .clone()
                    .unwrap_or_else(PatchManifest::new);
                let patches: Vec<serde_json::Value> = selected
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
                let added = patches.iter().filter(|p| p["action"] == "added").count();
                let updated = patches.iter().filter(|p| p["action"] == "updated").count();
                let skipped = patches.iter().filter(|p| p["action"] == "skipped").count();
                result["apply"] = serde_json::json!({
                    "found": selected.len(),
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
                // No patches selected (e.g. all paid for a free user, or
                // no packages had patches). Emit empty `apply` so JSON
                // shape is stable, then fall through to GC if requested.
                result["apply"] = serde_json::json!({
                    "found": 0, "downloaded": 0, "skipped": 0,
                    "failed": 0, "applied": 0, "updated": 0,
                    "patches": [],
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
                };
                let (code, apply_json) = download_and_apply_patches(&selected, &params).await;
                apply_code = code;
                let mut apply_obj = apply_json;
                if let Some(obj) = apply_obj.as_object_mut() {
                    obj.remove("status");
                }
                result["apply"] = apply_obj;
                if apply_code != 0 {
                    result["status"] = serde_json::json!("partial_failure");
                }
            }

            // --- GC (if requested) --------------------------------------
            if prune {
                let gc = if dry {
                    preview_apply_gc(&manifest_path, &socket_dir, &scanned_purls).await
                } else {
                    run_apply_gc(&manifest_path, &socket_dir, &scanned_purls).await
                };
                result["gc"] = if dry {
                    gc.to_preview_json()
                } else {
                    gc.to_apply_json()
                };
            }

            let final_code =
                embed_vex_into_json(&args.common, &args.vex, &manifest_path, apply_code, &mut result)
                    .await;
            println!("{}", serde_json::to_string_pretty(&result).unwrap());
            return final_code;
        }

        // --- GC-only path (no --apply, just --prune) --------------------
        if prune {
            let gc = if dry {
                preview_apply_gc(&manifest_path, &socket_dir, &scanned_purls).await
            } else {
                run_apply_gc(&manifest_path, &socket_dir, &scanned_purls).await
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
        println!("\nNo patches available for installed packages.");
        return embed_vex_human(&args.common, &args.vex, &manifest_path, 0).await;
    }

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
                format!("{}+{}", pkg_free, color(&pkg_paid.to_string(), "33", use_color))
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
            format!(
                "{} (+{})",
                vuln_ids[..2].join(", "),
                vuln_ids.len() - 2
            )
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

        println!(
            "{:<40}  {:>8}  {:<16}  {}{}",
            display_purl,
            count_str,
            format_severity(severity, use_color),
            vuln_str,
            update_marker,
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
                    &format!("         + {} additional patch(es) available with paid subscription", paid_patches),
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
        println!("\nNo downloadable patches (paid subscription required).");
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
                eprintln!("\n  Warning: could not fetch details for {}: {e}", pkg.purl);
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

    if selected.is_empty() {
        println!("No patches selected.");
        return embed_vex_human(&args.common, &args.vex, &manifest_path, 0).await;
    }

    // Display detailed summary of selected patches before confirming
    println!("\nPatches to apply:\n");
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
            if highest_severity
                .is_none_or(|cur| severity_order(sev) < severity_order(cur))
            {
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
            patch.purl,
            patch.tier.to_uppercase(),
            sev_colored,
        );
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

    // `--dry-run` is a non-mutating preview (see the global flag's doc and
    // the JSON path's `dryRun` envelope). The interactive path must honor it
    // too: stop here, having printed the table and the per-patch plan above,
    // before the confirm prompt, the download/apply, and the prune GC — all
    // of which mutate the manifest and `.socket/` on disk.
    if args.common.dry_run {
        println!(
            "\n[dry-run] Would download and apply {} patch(es). No changes made.",
            selected.len()
        );
        return embed_vex_human(&args.common, &args.vex, &manifest_path, 0).await;
    }

    // Prompt to download
    let prompt = format!("Download and apply {} patch(es)?", selected.len());
    if !confirm(&prompt, true, args.common.yes, args.common.json) {
        println!("\nTo apply a patch, run:");
        println!("  socket-patch get <package-name-or-purl>");
        println!("  socket-patch get <CVE-ID>");
        return embed_vex_human(&args.common, &args.vex, &manifest_path, 0).await;
    }

    // Download and apply
    let params = DownloadParams {
        cwd: args.common.cwd.clone(),
        org: args.common.org.clone(),
        save_only: false,
        one_off: false,
        global: args.common.global,
        global_prefix: args.common.global_prefix.clone(),
        json: false,
        silent: false,
        download_mode: args.common.download_mode.clone(),
        api_overrides: args.common.api_client_overrides(),
        all_releases: args.all_releases,
    };

    let (code, _) = download_and_apply_patches(&selected, &params).await;

    // Post-apply GC: only runs when the user opted in via `--prune` or
    // `--sync`. Default `scan --yes` no longer touches the manifest
    // beyond what `--apply` added — users wanting to clean up should
    // run `socket-patch gc` (or `repair`) explicitly.
    if prune {
        let gc = run_apply_gc(&manifest_path, &socket_dir, &scanned_purls).await;
        let total = gc.blobs.blobs_removed + gc.diffs.blobs_removed + gc.packages.blobs_removed;
        if !gc.pruned.is_empty() || total > 0 {
            println!(
                "\nGC: pruned {} manifest entr{} and removed {} orphan file{} ({}).",
                gc.pruned.len(),
                if gc.pruned.len() == 1 { "y" } else { "ies" },
                total,
                if total == 1 { "" } else { "s" },
                socket_patch_core::utils::cleanup_blobs::format_bytes(gc.total_bytes()),
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
        let m = manifest_with(&[
            ("pkg:npm/foo@1.0", "uuid-a"),
            ("pkg:npm/bar@2.0", "uuid-c"),
        ]);
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

    #[test]
    fn detect_prunable_empty_manifest_empty_scanned() {
        let m = PatchManifest::new();
        assert!(detect_prunable(&m, &scanned(&[])).is_empty());
    }

    #[test]
    fn detect_prunable_empty_manifest_nonempty_scanned() {
        let m = PatchManifest::new();
        // No manifest entries → nothing to prune even if the crawl found
        // packages that don't appear in the manifest.
        assert!(detect_prunable(&m, &scanned(&["pkg:npm/foo@1"])).is_empty());
    }

    #[test]
    fn detect_prunable_all_entries_present_in_scan() {
        let m = manifest_with(&[
            ("pkg:npm/foo@1.0", "uuid-a"),
            ("pkg:npm/bar@2.0", "uuid-b"),
        ]);
        let s = scanned(&["pkg:npm/foo@1.0", "pkg:npm/bar@2.0"]);
        assert!(detect_prunable(&m, &s).is_empty());
    }

    #[test]
    fn detect_prunable_returns_missing_entries() {
        let m = manifest_with(&[
            ("pkg:npm/foo@1.0", "uuid-a"),
            ("pkg:npm/bar@2.0", "uuid-b"),
        ]);
        // foo is still installed, bar is gone.
        let s = scanned(&["pkg:npm/foo@1.0"]);
        let mut out = detect_prunable(&m, &s);
        out.sort();
        assert_eq!(out, vec!["pkg:npm/bar@2.0".to_string()]);
    }

    #[test]
    fn detect_prunable_returns_everything_when_scan_is_empty() {
        let m = manifest_with(&[
            ("pkg:npm/foo@1.0", "uuid-a"),
            ("pkg:npm/bar@2.0", "uuid-b"),
        ]);
        let mut out = detect_prunable(&m, &scanned(&[]));
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
        let out = detect_prunable(&m, &scanned(&["pkg:pypi/six@1.16.0"]));
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
        let out = detect_prunable(&m, &scanned(&[]));
        assert_eq!(out.len(), 2, "all variants of a gone package should prune");
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
        let preview = preview_apply_gc(&manifest_path, &socket_dir, &scanned).await;

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
        assert!(blob_path.exists(), "dry-run preview must not delete the blob");
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
        let preview = preview_apply_gc(&mp_p, &sd_p, &scanned).await;
        assert!(blob_p.exists(), "preview must not mutate");

        let tmp_wet = tempfile::tempdir().unwrap();
        let (mp_w, sd_w, blob_w) =
            seed_manifest_with_blob(tmp_wet.path(), "pkg:npm/gone@1.0.0", &after_hash);
        let wet = run_apply_gc(&mp_w, &sd_w, &scanned).await;

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
            vec![
                "CVE-2024-1".to_string(),
                "GHSA-aaaa-aaaa-aaaa".to_string(),
            ],
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
