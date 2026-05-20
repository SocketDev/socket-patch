use clap::Args;
use socket_patch_core::api::client::get_api_client_from_env;
use socket_patch_core::api::types::{BatchPackagePatches, PatchSearchResult};
use socket_patch_core::crawlers::{CrawlerOptions, Ecosystem};
use socket_patch_core::manifest::operations::{read_manifest, resolve_manifest_path};
use socket_patch_core::manifest::schema::PatchManifest;
use std::collections::HashSet;
use std::path::PathBuf;

use crate::ecosystem_dispatch::crawl_all_ecosystems;
use crate::output::{color, confirm, format_severity, stderr_is_tty, stdout_is_tty};

use super::get::{download_and_apply_patches, select_patches, DownloadParams};

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

#[derive(Args)]
pub struct ScanArgs {
    /// Working directory
    #[arg(long, default_value = ".")]
    pub cwd: PathBuf,

    /// Organization slug
    #[arg(long)]
    pub org: Option<String>,

    /// Output results as JSON
    #[arg(long, default_value_t = false)]
    pub json: bool,

    /// Skip confirmation prompts
    #[arg(short = 'y', long, default_value_t = false)]
    pub yes: bool,

    /// Scan globally installed npm packages
    #[arg(short = 'g', long, default_value_t = false)]
    pub global: bool,

    /// Custom path to global node_modules
    #[arg(long = "global-prefix")]
    pub global_prefix: Option<PathBuf>,

    /// Number of packages to query per API request
    #[arg(long = "batch-size", default_value_t = DEFAULT_BATCH_SIZE)]
    pub batch_size: usize,

    /// Socket API URL (overrides SOCKET_API_URL env var)
    #[arg(long = "api-url")]
    pub api_url: Option<String>,

    /// Socket API token (overrides SOCKET_API_TOKEN env var)
    #[arg(long = "api-token")]
    pub api_token: Option<String>,

    /// Restrict scanning to specific ecosystems (comma-separated: npm,pypi,cargo,maven)
    #[arg(long, value_delimiter = ',')]
    pub ecosystems: Option<Vec<String>>,

    /// Which kind of patch artifact to download. `diff` (default) fetches
    /// the smallest delta archive; `package` fetches a full per-package
    /// tarball; `file` falls back to legacy per-file blob downloads.
    #[arg(long = "download-mode", default_value = "diff")]
    pub download_mode: String,

    /// Download and apply selected patches in JSON mode (non-interactive).
    /// Without this flag, `scan --json` is read-only — it lists available
    /// patches plus an `updates` array but does not mutate the manifest.
    /// Designed for unattended workflows (cron jobs, bots that open PRs);
    /// pair with `--yes` for clarity though `--json` already implies non-
    /// interactive confirmation. No effect outside `--json` mode (the
    /// non-JSON path always prompts the user).
    #[arg(long, default_value_t = false)]
    pub apply: bool,
}

pub async fn run(args: ScanArgs) -> i32 {
    // Override env vars if CLI options provided
    if let Some(ref url) = args.api_url {
        std::env::set_var("SOCKET_API_URL", url);
    }
    if let Some(ref token) = args.api_token {
        std::env::set_var("SOCKET_API_TOKEN", token);
    }

    let (api_client, _use_public_proxy) = get_api_client_from_env(args.org.as_deref()).await;

    // org slug is already stored in the client
    let effective_org_slug: Option<&str> = None;

    let crawler_options = CrawlerOptions {
        cwd: args.cwd.clone(),
        global: args.global,
        global_prefix: args.global_prefix.clone(),
        batch_size: args.batch_size,
    };

    let scan_target = if args.global || args.global_prefix.is_some() {
        "global packages"
    } else {
        "packages"
    };

    let show_progress = !args.json && stderr_is_tty();

    if show_progress {
        eprint!("Scanning {scan_target}...");
    }

    // Crawl packages
    let (all_crawled, eco_counts) = crawl_all_ecosystems(&crawler_options).await;

    // Filter by --ecosystems if provided
    let filtered_crawled: Vec<_> = if let Some(ref allowed) = args.ecosystems {
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
        if args.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "status": "success",
                    "scannedPackages": 0,
                    "packagesWithPatches": 0,
                    "totalPatches": 0,
                    "freePatches": 0,
                    "paidPatches": 0,
                    "canAccessPaidPatches": false,
                    "packages": [],
                    "updates": [],
                }))
                .unwrap()
            );
        } else if args.global || args.global_prefix.is_some() {
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
        return 0;
    }

    // Build ecosystem summary
    let mut eco_parts = Vec::new();
    for eco in Ecosystem::all() {
        let count = if args.ecosystems.is_some() {
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

    if !args.json {
        if show_progress {
            eprintln!("\rFound {package_count} packages{eco_summary}");
        } else {
            eprintln!("Found {package_count} packages{eco_summary}");
        }
    }

    // Query API in batches
    let mut all_packages_with_patches: Vec<BatchPackagePatches> = Vec::new();
    let mut can_access_paid_patches = false;
    let total_batches = all_purls.len().div_ceil(args.batch_size);

    if show_progress {
        eprint!("Querying API for patches... (batch 1/{total_batches})");
    }

    for (batch_idx, chunk) in all_purls.chunks(args.batch_size).enumerate() {
        if show_progress {
            eprint!(
                "\rQuerying API for patches... (batch {}/{})",
                batch_idx + 1,
                total_batches
            );
        }

        let purls: Vec<String> = chunk.to_vec();
        match api_client
            .search_patches_batch(effective_org_slug, &purls)
            .await
        {
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
                if !args.json {
                    eprintln!("\nError querying batch {}: {e}", batch_idx + 1);
                }
            }
        }
    }

    let total_patches_found: usize = all_packages_with_patches
        .iter()
        .map(|p| p.patches.len())
        .sum();

    if !args.json {
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

    // Read existing manifest once for update detection. Used by both the
    // JSON-mode emission (always includes an `updates` array) and the
    // non-JSON table-print path (counts `updates_available`).
    let manifest_path = resolve_manifest_path(&args.cwd, ".socket/manifest.json");
    let existing_manifest = read_manifest(&manifest_path).await.ok().flatten();
    let updates = detect_updates(existing_manifest.as_ref(), &all_packages_with_patches);

    if args.json {
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

        // --apply opts JSON callers into the full discover → select → apply
        // pipeline. Without it `scan --json` stays read-only (the prior
        // contract). When --apply is set we delegate to the same selection
        // and download path the non-JSON branch uses below, then graft the
        // apply summary onto the discovery result as a sub-object.
        if args.apply && !all_packages_with_patches.is_empty() {
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

            let selected = match select_patches(&all_search_results, can_access_paid_patches, true) {
                Ok(s) => s,
                Err(code) => return code,
            };

            if selected.is_empty() {
                result["apply"] = serde_json::json!({
                    "found": 0,
                    "downloaded": 0,
                    "skipped": 0,
                    "failed": 0,
                    "applied": 0,
                    "updated": 0,
                    "patches": [],
                });
                println!("{}", serde_json::to_string_pretty(&result).unwrap());
                return 0;
            }

            let params = DownloadParams {
                cwd: args.cwd.clone(),
                org: args.org.clone(),
                save_only: false,
                one_off: false,
                global: args.global,
                global_prefix: args.global_prefix.clone(),
                json: true,
                silent: true,
                download_mode: args.download_mode.clone(),
            };
            let (apply_code, apply_json) = download_and_apply_patches(&selected, &params).await;
            // Strip the `status` field — the outer scan JSON owns it. Keep
            // everything else so bots can summarize per-patch outcomes.
            let mut apply_obj = apply_json;
            if let Some(obj) = apply_obj.as_object_mut() {
                obj.remove("status");
            }
            result["apply"] = apply_obj;
            if apply_code != 0 {
                result["status"] = serde_json::json!("partial_failure");
            }
            println!("{}", serde_json::to_string_pretty(&result).unwrap());
            return apply_code;
        }

        println!("{}", serde_json::to_string_pretty(&result).unwrap());
        return 0;
    }

    let use_color = stdout_is_tty();

    if all_packages_with_patches.is_empty() {
        println!("\nNo patches available for installed packages.");
        return 0;
    }

    let mut updates_available = 0usize;

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
        let max_purl_len = 40;
        let display_purl = if pkg.purl.len() > max_purl_len {
            format!("{}...", &pkg.purl[..max_purl_len - 3])
        } else {
            pkg.purl.clone()
        };

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

        // Collect vuln IDs
        let mut all_cves = HashSet::new();
        let mut all_ghsas = HashSet::new();
        for patch in &pkg.patches {
            for cve in &patch.cve_ids {
                all_cves.insert(cve.clone());
            }
            for ghsa in &patch.ghsa_ids {
                all_ghsas.insert(ghsa.clone());
            }
        }
        let vuln_ids: Vec<_> = all_cves.into_iter().chain(all_ghsas).collect();
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

        // Check for updates
        let has_update = if let Some(ref manifest) = existing_manifest {
            if let Some(existing) = manifest.patches.get(&pkg.purl) {
                // If any patch in the batch has a different UUID than what's in manifest, update available
                pkg.patches.iter().any(|p| p.uuid != existing.uuid)
            } else {
                false
            }
        } else {
            false
        };
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
        return 0;
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
        return 0;
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

        let desc = if patch.description.len() > 72 {
            format!("{}...", &patch.description[..69])
        } else {
            patch.description.clone()
        };

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
                let summary = if vuln.summary.len() > 76 {
                    format!("{}...", &vuln.summary[..73])
                } else {
                    vuln.summary.clone()
                };
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

    // Prompt to download
    let prompt = format!("Download and apply {} patch(es)?", selected.len());
    if !confirm(&prompt, true, args.yes, args.json) {
        println!("\nTo apply a patch, run:");
        println!("  socket-patch get <package-name-or-purl>");
        println!("  socket-patch get <CVE-ID>");
        return 0;
    }

    // Download and apply
    let params = DownloadParams {
        cwd: args.cwd.clone(),
        org: args.org.clone(),
        save_only: false,
        one_off: false,
        global: args.global,
        global_prefix: args.global_prefix.clone(),
        json: false,
        silent: false,
        download_mode: args.download_mode.clone(),
    };

    let (code, _) = download_and_apply_patches(&selected, &params).await;
    code
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
}
