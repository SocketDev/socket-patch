use clap::Args;
use socket_patch_core::api::client::get_api_client_from_env;
use socket_patch_core::api::types::BatchPackagePatches;
use socket_patch_core::crawlers::{CrawlerOptions, Ecosystem};
use std::collections::HashSet;
use std::path::PathBuf;

use crate::ecosystem_dispatch::crawl_all_ecosystems;

const DEFAULT_BATCH_SIZE: usize = 100;

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
}

pub async fn run(args: ScanArgs) -> i32 {
    // Override env vars if CLI options provided
    if let Some(ref url) = args.api_url {
        std::env::set_var("SOCKET_API_URL", url);
    }
    if let Some(ref token) = args.api_token {
        std::env::set_var("SOCKET_API_TOKEN", token);
    }

    let (api_client, use_public_proxy) = get_api_client_from_env(args.org.as_deref());

    if !use_public_proxy && args.org.is_none() {
        eprintln!("Error: --org is required when using SOCKET_API_TOKEN. Provide an organization slug.");
        return 1;
    }

    let effective_org_slug = if use_public_proxy {
        None
    } else {
        args.org.as_deref()
    };

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

    if !args.json {
        eprint!("Scanning {scan_target}...");
    }

    // Crawl packages
    let (all_crawled, eco_counts) = crawl_all_ecosystems(&crawler_options).await;

    let all_purls: Vec<String> = all_crawled.iter().map(|p| p.purl.clone()).collect();
    let package_count = all_purls.len();

    if package_count == 0 {
        if !args.json {
            eprintln!();
        }
        if args.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "scannedPackages": 0,
                    "packagesWithPatches": 0,
                    "totalPatches": 0,
                    "freePatches": 0,
                    "paidPatches": 0,
                    "canAccessPaidPatches": false,
                    "packages": [],
                }))
                .unwrap()
            );
        } else if args.global || args.global_prefix.is_some() {
            println!("No global packages found.");
        } else {
            #[cfg(feature = "cargo")]
            let install_cmds = "npm/yarn/pnpm/pip/cargo";
            #[cfg(not(feature = "cargo"))]
            let install_cmds = "npm/yarn/pnpm/pip";
            println!("No packages found. Run {install_cmds} install first.");
        }
        return 0;
    }

    // Build ecosystem summary
    let mut eco_parts = Vec::new();
    for eco in Ecosystem::all() {
        let count = eco_counts.get(eco).copied().unwrap_or(0);
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
        eprintln!("\rFound {package_count} packages{eco_summary}");
    }

    // Query API in batches
    let mut all_packages_with_patches: Vec<BatchPackagePatches> = Vec::new();
    let mut can_access_paid_patches = false;
    let total_batches = all_purls.len().div_ceil(args.batch_size);

    if !args.json {
        eprint!("Querying API for patches... (batch 1/{total_batches})");
    }

    for (batch_idx, chunk) in all_purls.chunks(args.batch_size).enumerate() {
        if !args.json {
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
            eprintln!(
                "\rFound {total_patches_found} patches for {} packages",
                all_packages_with_patches.len()
            );
        } else {
            eprintln!("\rAPI query complete");
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

    if args.json {
        let result = serde_json::json!({
            "scannedPackages": package_count,
            "packagesWithPatches": all_packages_with_patches.len(),
            "totalPatches": total_patches,
            "freePatches": free_patches,
            "paidPatches": paid_patches,
            "canAccessPaidPatches": can_access_paid_patches,
            "packages": all_packages_with_patches,
        });
        println!("{}", serde_json::to_string_pretty(&result).unwrap());
        return 0;
    }

    if all_packages_with_patches.is_empty() {
        println!("\nNo patches available for installed packages.");
        return 0;
    }

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
                format!("{}\x1b[33m+{}\x1b[0m", pkg_free, pkg_paid)
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

        println!(
            "{:<40}  {:>8}  {:<16}  {}",
            display_purl,
            count_str,
            format_severity(severity),
            vuln_str,
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
                "\x1b[33m         + {} additional patch(es) available with paid subscription\x1b[0m",
                paid_patches,
            );
            println!(
                "\nUpgrade to Socket's paid plan to access all patches: https://socket.dev/pricing"
            );
        }
    }

    println!("\nTo apply a patch, run:");
    println!("  socket-patch get <package-name-or-purl>");
    println!("  socket-patch get <CVE-ID>");

    0
}

fn severity_order(s: &str) -> u8 {
    match s.to_lowercase().as_str() {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        _ => 4,
    }
}

fn format_severity(s: &str) -> String {
    match s.to_lowercase().as_str() {
        "critical" => "\x1b[31mcritical\x1b[0m".to_string(),
        "high" => "\x1b[91mhigh\x1b[0m".to_string(),
        "medium" => "\x1b[33mmedium\x1b[0m".to_string(),
        "low" => "\x1b[36mlow\x1b[0m".to_string(),
        other => other.to_string(),
    }
}
