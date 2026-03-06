use clap::Args;
use regex::Regex;
use socket_patch_core::api::client::get_api_client_from_env;
use socket_patch_core::api::types::{PatchSearchResult, SearchResponse};
use socket_patch_core::crawlers::CrawlerOptions;
use socket_patch_core::manifest::operations::{read_manifest, write_manifest};
use socket_patch_core::manifest::schema::{
    PatchFileInfo, PatchManifest, PatchRecord, VulnerabilityInfo,
};
use socket_patch_core::utils::fuzzy_match::fuzzy_match_packages;
use socket_patch_core::utils::purl::is_purl;
use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;

use crate::ecosystem_dispatch::crawl_all_ecosystems;
use crate::output::{confirm, select_one, SelectError};

#[derive(Args)]
pub struct GetArgs {
    /// Patch identifier (UUID, CVE ID, GHSA ID, PURL, or package name)
    pub identifier: String,

    /// Organization slug
    #[arg(long)]
    pub org: Option<String>,

    /// Working directory
    #[arg(long, default_value = ".")]
    pub cwd: PathBuf,

    /// Force identifier to be treated as a patch UUID
    #[arg(long, default_value_t = false)]
    pub id: bool,

    /// Force identifier to be treated as a CVE ID
    #[arg(long, default_value_t = false)]
    pub cve: bool,

    /// Force identifier to be treated as a GHSA ID
    #[arg(long, default_value_t = false)]
    pub ghsa: bool,

    /// Force identifier to be treated as a package name
    #[arg(short = 'p', long = "package", default_value_t = false)]
    pub package: bool,

    /// Skip confirmation prompt for multiple patches
    #[arg(short = 'y', long, default_value_t = false)]
    pub yes: bool,

    /// Socket API URL (overrides SOCKET_API_URL env var)
    #[arg(long = "api-url")]
    pub api_url: Option<String>,

    /// Socket API token (overrides SOCKET_API_TOKEN env var)
    #[arg(long = "api-token")]
    pub api_token: Option<String>,

    /// Download patch without applying it
    #[arg(long = "save-only", alias = "no-apply", default_value_t = false)]
    pub save_only: bool,

    /// Apply patch to globally installed npm packages
    #[arg(short = 'g', long, default_value_t = false)]
    pub global: bool,

    /// Custom path to global node_modules
    #[arg(long = "global-prefix")]
    pub global_prefix: Option<PathBuf>,

    /// Apply patch immediately without saving to .socket folder
    #[arg(long = "one-off", default_value_t = false)]
    pub one_off: bool,

    /// Output results as JSON
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

#[derive(Debug, PartialEq)]
enum IdentifierType {
    Uuid,
    Cve,
    Ghsa,
    Purl,
    Package,
}

impl fmt::Display for IdentifierType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdentifierType::Uuid => write!(f, "UUID"),
            IdentifierType::Cve => write!(f, "CVE"),
            IdentifierType::Ghsa => write!(f, "GHSA"),
            IdentifierType::Purl => write!(f, "PURL"),
            IdentifierType::Package => write!(f, "package name"),
        }
    }
}

fn detect_identifier_type(identifier: &str) -> Option<IdentifierType> {
    let uuid_re = Regex::new(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$").unwrap();
    let cve_re = Regex::new(r"(?i)^CVE-\d{4}-\d+$").unwrap();
    let ghsa_re = Regex::new(r"(?i)^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$").unwrap();

    if uuid_re.is_match(identifier) {
        Some(IdentifierType::Uuid)
    } else if cve_re.is_match(identifier) {
        Some(IdentifierType::Cve)
    } else if ghsa_re.is_match(identifier) {
        Some(IdentifierType::Ghsa)
    } else if is_purl(identifier) {
        Some(IdentifierType::Purl)
    } else {
        None
    }
}

/// Select one patch per PURL from available patches.
///
/// - Paid users: auto-select the most recent paid patch per PURL.
/// - Free users with one patch: auto-select it.
/// - Free users with multiple patches: interactive selection via dialoguer.
/// - JSON mode with multiple free patches: returns an error with options list.
///
/// Returns `Ok(selected_patches)` or `Err(exit_code)` if selection fails.
pub fn select_patches(
    patches: &[PatchSearchResult],
    can_access_paid: bool,
    is_json: bool,
) -> Result<Vec<PatchSearchResult>, i32> {
    // Group accessible patches by PURL
    let mut by_purl: HashMap<String, Vec<&PatchSearchResult>> = HashMap::new();
    for p in patches {
        if p.tier == "free" || can_access_paid {
            by_purl.entry(p.purl.clone()).or_default().push(p);
        }
    }

    let mut selected = Vec::new();

    for (purl, mut group) in by_purl {
        // Sort by published_at descending (most recent first)
        group.sort_by(|a, b| b.published_at.cmp(&a.published_at));

        if can_access_paid {
            // Paid user: prefer most recent paid patch, fallback to most recent free
            let choice = group
                .iter()
                .find(|p| p.tier == "paid")
                .or_else(|| group.first())
                .unwrap();
            selected.push((*choice).clone());
        } else if group.len() == 1 {
            selected.push(group[0].clone());
        } else {
            // Free user with multiple patches: interactive selection
            let options: Vec<String> = group
                .iter()
                .map(|p| {
                    let vuln_summary: Vec<String> = p
                        .vulnerabilities
                        .iter()
                        .map(|(id, v)| {
                            if v.cves.is_empty() {
                                id.clone()
                            } else {
                                v.cves.join(", ")
                            }
                        })
                        .collect();
                    let vulns = if vuln_summary.is_empty() {
                        String::new()
                    } else {
                        format!(" (fixes: {})", vuln_summary.join(", "))
                    };
                    let desc = if p.description.len() > 60 {
                        format!("{}...", &p.description[..57])
                    } else {
                        p.description.clone()
                    };
                    format!("{} [{}]{} - {}", p.uuid, p.tier, vulns, desc)
                })
                .collect();

            match select_one(
                &format!("Multiple patches available for {purl}. Select one:"),
                &options,
                is_json,
            ) {
                Ok(idx) => {
                    selected.push(group[idx].clone());
                }
                Err(SelectError::JsonModeNeedsExplicit) => {
                    let options_json: Vec<serde_json::Value> = group
                        .iter()
                        .map(|p| {
                            let vulns: Vec<serde_json::Value> = p
                                .vulnerabilities
                                .iter()
                                .map(|(id, v)| {
                                    serde_json::json!({
                                        "id": id,
                                        "cves": v.cves,
                                        "severity": v.severity,
                                        "summary": v.summary,
                                    })
                                })
                                .collect();
                            serde_json::json!({
                                "uuid": p.uuid,
                                "tier": p.tier,
                                "published_at": p.published_at,
                                "description": p.description,
                                "vulnerabilities": vulns,
                            })
                        })
                        .collect();
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "status": "selection_required",
                            "error": format!("Multiple patches available for {purl}. Specify --id <UUID> to select one."),
                            "purl": purl,
                            "options": options_json,
                        }))
                        .unwrap()
                    );
                    return Err(1);
                }
                Err(SelectError::Cancelled) => {
                    eprintln!("Selection cancelled.");
                    return Err(0);
                }
            }
        }
    }

    Ok(selected)
}

/// Download parameters shared between get and scan commands.
#[allow(dead_code)]
pub struct DownloadParams {
    pub cwd: PathBuf,
    pub org: Option<String>,
    pub save_only: bool,
    pub one_off: bool,
    pub global: bool,
    pub global_prefix: Option<PathBuf>,
    pub json: bool,
    pub silent: bool,
}

/// Download and apply a set of selected patches.
///
/// Used by both `get` and `scan` commands. Returns (exit_code, json_result).
pub async fn download_and_apply_patches(
    selected: &[PatchSearchResult],
    params: &DownloadParams,
) -> (i32, serde_json::Value) {
    let (api_client, _) = get_api_client_from_env(params.org.as_deref()).await;
    let effective_org: Option<&str> = None;

    let socket_dir = params.cwd.join(".socket");
    let blobs_dir = socket_dir.join("blobs");
    let manifest_path = socket_dir.join("manifest.json");

    tokio::fs::create_dir_all(&socket_dir).await.ok();
    tokio::fs::create_dir_all(&blobs_dir).await.ok();

    let mut manifest = match read_manifest(&manifest_path).await {
        Ok(Some(m)) => m,
        _ => PatchManifest::new(),
    };

    if !params.json && !params.silent {
        eprintln!("\nDownloading {} patch(es)...", selected.len());
    }

    let mut patches_added = 0;
    let mut patches_skipped = 0;
    let mut patches_failed = 0;
    let mut downloaded_patches: Vec<serde_json::Value> = Vec::new();
    let mut updates: Vec<String> = Vec::new();

    for search_result in selected {
        // Check for updates: existing patch with different UUID
        if let Some(existing) = manifest.patches.get(&search_result.purl) {
            if existing.uuid != search_result.uuid {
                updates.push(search_result.purl.clone());
                if !params.json && !params.silent {
                    eprintln!(
                        "  [update] {} (replacing {})",
                        search_result.purl,
                        &existing.uuid[..8]
                    );
                }
            }
        }

        match api_client
            .fetch_patch(effective_org, &search_result.uuid)
            .await
        {
            Ok(Some(patch)) => {
                // Check if already in manifest with same UUID
                if manifest
                    .patches
                    .get(&patch.purl)
                    .is_some_and(|p| p.uuid == patch.uuid)
                {
                    if !params.json && !params.silent {
                        eprintln!("  [skip] {} (already in manifest)", patch.purl);
                    }
                    downloaded_patches.push(serde_json::json!({
                        "purl": patch.purl,
                        "uuid": patch.uuid,
                        "action": "skipped",
                    }));
                    patches_skipped += 1;
                    continue;
                }

                // Save blob contents
                let mut files = HashMap::new();
                for (file_path, file_info) in &patch.files {
                    if let (Some(ref before), Some(ref after)) =
                        (&file_info.before_hash, &file_info.after_hash)
                    {
                        files.insert(
                            file_path.clone(),
                            PatchFileInfo {
                                before_hash: before.clone(),
                                after_hash: after.clone(),
                            },
                        );
                    }

                    if let (Some(ref blob_content), Some(ref after_hash)) =
                        (&file_info.blob_content, &file_info.after_hash)
                    {
                        if let Ok(decoded) = base64_decode(blob_content) {
                            let blob_path = blobs_dir.join(after_hash);
                            tokio::fs::write(&blob_path, &decoded).await.ok();
                        }
                    }

                    // Also store beforeHash blob if present (needed for rollback)
                    if let (Some(ref before_blob), Some(ref before_hash)) =
                        (&file_info.before_blob_content, &file_info.before_hash)
                    {
                        if let Ok(decoded) = base64_decode(before_blob) {
                            tokio::fs::write(blobs_dir.join(before_hash), &decoded)
                                .await
                                .ok();
                        }
                    }
                }

                let vulnerabilities: HashMap<String, VulnerabilityInfo> = patch
                    .vulnerabilities
                    .iter()
                    .map(|(id, v)| {
                        (
                            id.clone(),
                            VulnerabilityInfo {
                                cves: v.cves.clone(),
                                summary: v.summary.clone(),
                                severity: v.severity.clone(),
                                description: v.description.clone(),
                            },
                        )
                    })
                    .collect();

                manifest.patches.insert(
                    patch.purl.clone(),
                    PatchRecord {
                        uuid: patch.uuid.clone(),
                        exported_at: patch.published_at.clone(),
                        files,
                        vulnerabilities,
                        description: patch.description.clone(),
                        license: patch.license.clone(),
                        tier: patch.tier.clone(),
                    },
                );

                if !params.json && !params.silent {
                    eprintln!("  [add] {}", patch.purl);
                }
                downloaded_patches.push(serde_json::json!({
                    "purl": patch.purl,
                    "uuid": patch.uuid,
                    "action": "added",
                }));
                patches_added += 1;
            }
            Ok(None) => {
                if !params.json && !params.silent {
                    eprintln!("  [fail] {} (could not fetch details)", search_result.purl);
                }
                downloaded_patches.push(serde_json::json!({
                    "purl": search_result.purl,
                    "uuid": search_result.uuid,
                    "action": "failed",
                    "error": "could not fetch details",
                }));
                patches_failed += 1;
            }
            Err(e) => {
                if !params.json && !params.silent {
                    eprintln!("  [fail] {} ({e})", search_result.purl);
                }
                downloaded_patches.push(serde_json::json!({
                    "purl": search_result.purl,
                    "uuid": search_result.uuid,
                    "action": "failed",
                    "error": e.to_string(),
                }));
                patches_failed += 1;
            }
        }
    }

    // Write manifest
    if let Err(e) = write_manifest(&manifest_path, &manifest).await {
        let err_json = serde_json::json!({
            "status": "error",
            "error": format!("Error writing manifest: {e}"),
        });
        if params.json {
            println!("{}", serde_json::to_string_pretty(&err_json).unwrap());
        } else {
            eprintln!("Error writing manifest: {e}");
        }
        return (1, err_json);
    }

    if !params.json && !params.silent {
        eprintln!("\nPatches saved to {}", manifest_path.display());
        eprintln!("  Added: {patches_added}");
        if patches_skipped > 0 {
            eprintln!("  Skipped: {patches_skipped}");
        }
        if patches_failed > 0 {
            eprintln!("  Failed: {patches_failed}");
        }
        if !updates.is_empty() {
            eprintln!("  Updated: {}", updates.len());
        }
    }

    // Auto-apply unless --save-only
    if !params.save_only && patches_added > 0 {
        if !params.json && !params.silent {
            eprintln!("\nApplying patches...");
        }
        let apply_args = super::apply::ApplyArgs {
            cwd: params.cwd.clone(),
            dry_run: false,
            silent: params.json || params.silent,
            manifest_path: manifest_path.display().to_string(),
            offline: false,
            global: params.global,
            global_prefix: params.global_prefix.clone(),
            ecosystems: None,
            force: false,
            json: false,
            verbose: false,
        };
        let code = super::apply::run(apply_args).await;
        if code != 0 && !params.json && !params.silent {
            eprintln!("\nSome patches could not be applied.");
        }
    }

    let result_json = serde_json::json!({
        "status": "success",
        "found": selected.len(),
        "downloaded": patches_added,
        "skipped": patches_skipped,
        "failed": patches_failed,
        "applied": if !params.save_only && patches_added > 0 { patches_added } else { 0 },
        "updated": updates.len(),
        "patches": downloaded_patches,
    });

    (0, result_json)
}

pub async fn run(args: GetArgs) -> i32 {
    // Validate flags
    let type_flags = [args.id, args.cve, args.ghsa, args.package]
        .iter()
        .filter(|&&f| f)
        .count();
    if type_flags > 1 {
        if args.json {
            println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                "status": "error",
                "error": "Only one of --id, --cve, --ghsa, or --package can be specified",
            })).unwrap());
        } else {
            eprintln!("Error: Only one of --id, --cve, --ghsa, or --package can be specified");
        }
        return 1;
    }
    if args.one_off && args.save_only {
        if args.json {
            println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                "status": "error",
                "error": "--one-off and --save-only cannot be used together",
            })).unwrap());
        } else {
            eprintln!("Error: --one-off and --save-only cannot be used together");
        }
        return 1;
    }

    // Override env vars
    if let Some(ref url) = args.api_url {
        std::env::set_var("SOCKET_API_URL", url);
    }
    if let Some(ref token) = args.api_token {
        std::env::set_var("SOCKET_API_TOKEN", token);
    }

    let (api_client, use_public_proxy) = get_api_client_from_env(args.org.as_deref()).await;

    // org slug is already stored in the client
    let effective_org_slug: Option<&str> = None;

    // Determine identifier type
    let id_type = if args.id {
        IdentifierType::Uuid
    } else if args.cve {
        IdentifierType::Cve
    } else if args.ghsa {
        IdentifierType::Ghsa
    } else if args.package {
        IdentifierType::Package
    } else {
        match detect_identifier_type(&args.identifier) {
            Some(t) => t,
            None => {
                if !args.json {
                    println!("Treating \"{}\" as a package name search", args.identifier);
                }
                IdentifierType::Package
            }
        }
    };

    // Handle UUID: fetch and download directly
    if id_type == IdentifierType::Uuid {
        if !args.json {
            println!("Fetching patch by UUID: {}", args.identifier);
        }
        match api_client
            .fetch_patch(effective_org_slug, &args.identifier)
            .await
        {
            Ok(Some(patch)) => {
                if patch.tier == "paid" && use_public_proxy {
                    if args.json {
                        println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                            "status": "paid_required",
                            "found": 1,
                            "downloaded": 0,
                            "applied": 0,
                            "patches": [{
                                "purl": patch.purl,
                                "uuid": patch.uuid,
                                "tier": "paid",
                            }],
                        })).unwrap());
                    } else {
                        println!("\nThis patch requires a paid subscription to download.");
                        println!("\n  Patch: {}", patch.purl);
                        println!("  Tier:  paid");
                        println!("\n  Upgrade at: https://socket.dev/pricing\n");
                    }
                    return 0;
                }

                // Save to manifest
                return save_and_apply_patch(&args, &patch.purl, &patch.uuid, effective_org_slug)
                    .await;
            }
            Ok(None) => {
                if args.json {
                    println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                        "status": "not_found",
                        "found": 0,
                        "downloaded": 0,
                        "applied": 0,
                        "patches": [],
                    })).unwrap());
                } else {
                    println!("No patch found with UUID: {}", args.identifier);
                }
                return 0;
            }
            Err(e) => {
                if args.json {
                    println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                        "status": "error",
                        "error": e.to_string(),
                    })).unwrap());
                } else {
                    eprintln!("Error: {e}");
                }
                return 1;
            }
        }
    }

    // For CVE/GHSA/PURL/package, search first
    let search_response: SearchResponse = match id_type {
        IdentifierType::Cve => {
            if !args.json {
                println!("Searching patches for CVE: {}", args.identifier);
            }
            match api_client
                .search_patches_by_cve(effective_org_slug, &args.identifier)
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    if args.json {
                        println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                            "status": "error",
                            "error": e.to_string(),
                        })).unwrap());
                    } else {
                        eprintln!("Error: {e}");
                    }
                    return 1;
                }
            }
        }
        IdentifierType::Ghsa => {
            if !args.json {
                println!("Searching patches for GHSA: {}", args.identifier);
            }
            match api_client
                .search_patches_by_ghsa(effective_org_slug, &args.identifier)
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    if args.json {
                        println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                            "status": "error",
                            "error": e.to_string(),
                        })).unwrap());
                    } else {
                        eprintln!("Error: {e}");
                    }
                    return 1;
                }
            }
        }
        IdentifierType::Purl => {
            if !args.json {
                println!("Searching patches for PURL: {}", args.identifier);
            }
            match api_client
                .search_patches_by_package(effective_org_slug, &args.identifier)
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    if args.json {
                        println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                            "status": "error",
                            "error": e.to_string(),
                        })).unwrap());
                    } else {
                        eprintln!("Error: {e}");
                    }
                    return 1;
                }
            }
        }
        IdentifierType::Package => {
            if !args.json {
                println!("Enumerating packages...");
            }
            let crawler_options = CrawlerOptions {
                cwd: args.cwd.clone(),
                global: args.global,
                global_prefix: args.global_prefix.clone(),
                batch_size: 100,
            };
            let (all_packages, _) = crawl_all_ecosystems(&crawler_options).await;

            if all_packages.is_empty() {
                if args.json {
                    println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                        "status": "no_packages",
                        "found": 0,
                        "downloaded": 0,
                        "applied": 0,
                        "patches": [],
                    })).unwrap());
                } else if args.global {
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

            if !args.json {
                println!("Found {} packages", all_packages.len());
            }

            let matches = fuzzy_match_packages(&args.identifier, &all_packages, 20);

            if matches.is_empty() {
                if args.json {
                    println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                        "status": "no_match",
                        "found": 0,
                        "downloaded": 0,
                        "applied": 0,
                        "patches": [],
                    })).unwrap());
                } else {
                    println!("No packages matching \"{}\" found.", args.identifier);
                }
                return 0;
            }

            if !args.json {
                println!(
                    "Found {} matching package(s), checking for available patches...",
                    matches.len()
                );
            }

            // Search for patches for the best match
            let best_match = &matches[0];
            match api_client
                .search_patches_by_package(effective_org_slug, &best_match.purl)
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    if args.json {
                        println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                            "status": "error",
                            "error": e.to_string(),
                        })).unwrap());
                    } else {
                        eprintln!("Error: {e}");
                    }
                    return 1;
                }
            }
        }
        _ => unreachable!(),
    };

    if search_response.patches.is_empty() {
        if args.json {
            println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                "status": "not_found",
                "found": 0,
                "downloaded": 0,
                "applied": 0,
                "patches": [],
            })).unwrap());
        } else {
            println!(
                "No patches found for {}: {}",
                id_type, args.identifier
            );
        }
        return 0;
    }

    if !args.json {
        display_search_results(&search_response.patches, search_response.can_access_paid_patches);
    }

    // Filter accessible patches
    let accessible: Vec<_> = search_response
        .patches
        .iter()
        .filter(|p| p.tier == "free" || search_response.can_access_paid_patches)
        .cloned()
        .collect();

    if accessible.is_empty() {
        if args.json {
            println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                "status": "paid_required",
                "found": search_response.patches.len(),
                "downloaded": 0,
                "applied": 0,
                "patches": search_response.patches.iter().map(|p| serde_json::json!({
                    "purl": p.purl,
                    "uuid": p.uuid,
                    "tier": p.tier,
                })).collect::<Vec<_>>(),
            })).unwrap());
        } else {
            println!("\nAll available patches require a paid subscription.");
            println!("\n  Upgrade at: https://socket.dev/pricing\n");
        }
        return 0;
    }

    // Smart patch selection: pick one patch per PURL
    let selected = match select_patches(
        &accessible,
        search_response.can_access_paid_patches,
        args.json,
    ) {
        Ok(s) => s,
        Err(code) => return code,
    };

    if selected.is_empty() {
        if !args.json {
            println!("No patches selected.");
        }
        return 0;
    }

    // Confirm before downloading (default YES)
    let prompt = format!("Download {} patch(es)?", selected.len());
    if !confirm(&prompt, true, args.yes, args.json) {
        if !args.json {
            println!("Download cancelled.");
        }
        return 0;
    }

    // Download and apply
    let params = DownloadParams {
        cwd: args.cwd.clone(),
        org: args.org.clone(),
        save_only: args.save_only,
        one_off: args.one_off,
        global: args.global,
        global_prefix: args.global_prefix.clone(),
        json: args.json,
        silent: false,
    };

    let (code, result_json) = download_and_apply_patches(&selected, &params).await;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&result_json).unwrap());
    }

    code
}

fn display_search_results(patches: &[PatchSearchResult], can_access_paid: bool) {
    println!("\nFound patches:\n");

    for (i, patch) in patches.iter().enumerate() {
        let tier_label = if patch.tier == "paid" {
            " [PAID]"
        } else {
            " [FREE]"
        };
        let access_label = if patch.tier == "paid" && !can_access_paid {
            " (no access)"
        } else {
            ""
        };

        println!("  {}. {}{}{}", i + 1, patch.purl, tier_label, access_label);
        println!("     UUID: {}", patch.uuid);
        if !patch.description.is_empty() {
            let desc = if patch.description.len() > 80 {
                format!("{}...", &patch.description[..77])
            } else {
                patch.description.clone()
            };
            println!("     Description: {desc}");
        }

        let vuln_ids: Vec<_> = patch.vulnerabilities.keys().collect();
        if !vuln_ids.is_empty() {
            let vuln_summary: Vec<String> = patch
                .vulnerabilities
                .iter()
                .map(|(id, vuln)| {
                    let cves = if vuln.cves.is_empty() {
                        id.to_string()
                    } else {
                        vuln.cves.join(", ")
                    };
                    format!("{cves} ({})", vuln.severity)
                })
                .collect();
            println!("     Fixes: {}", vuln_summary.join(", "));
        }
        println!();
    }
}

async fn save_and_apply_patch(
    args: &GetArgs,
    _purl: &str,
    uuid: &str,
    _org_slug: Option<&str>,
) -> i32 {
    // For UUID mode, fetch and save
    let (api_client, _) = get_api_client_from_env(args.org.as_deref()).await;
    let effective_org: Option<&str> = None; // org slug is already stored in the client

    let patch = match api_client.fetch_patch(effective_org, uuid).await {
        Ok(Some(p)) => p,
        Ok(None) => {
            if args.json {
                println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                    "status": "not_found",
                    "found": 0,
                    "downloaded": 0,
                    "applied": 0,
                    "patches": [],
                })).unwrap());
            } else {
                println!("No patch found with UUID: {uuid}");
            }
            return 0;
        }
        Err(e) => {
            if args.json {
                println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                    "status": "error",
                    "error": e.to_string(),
                })).unwrap());
            } else {
                eprintln!("Error: {e}");
            }
            return 1;
        }
    };

    let socket_dir = args.cwd.join(".socket");
    let blobs_dir = socket_dir.join("blobs");
    let manifest_path = socket_dir.join("manifest.json");

    tokio::fs::create_dir_all(&blobs_dir).await.ok();

    let mut manifest = match read_manifest(&manifest_path).await {
        Ok(Some(m)) => m,
        _ => PatchManifest::new(),
    };

    // Build and save patch record
    let mut files = HashMap::new();
    for (file_path, file_info) in &patch.files {
        if let Some(ref after) = file_info.after_hash {
            files.insert(
                file_path.clone(),
                PatchFileInfo {
                    before_hash: file_info
                        .before_hash
                        .clone()
                        .unwrap_or_default(),
                    after_hash: after.clone(),
                },
            );
        }
        if let (Some(ref blob_content), Some(ref after_hash)) =
            (&file_info.blob_content, &file_info.after_hash)
        {
            if let Ok(decoded) = base64_decode(blob_content) {
                tokio::fs::write(blobs_dir.join(after_hash), &decoded)
                    .await
                    .ok();
            }
        }
        // Also store beforeHash blob if present (needed for rollback)
        if let (Some(ref before_blob), Some(ref before_hash)) =
            (&file_info.before_blob_content, &file_info.before_hash)
        {
            if let Ok(decoded) = base64_decode(before_blob) {
                tokio::fs::write(blobs_dir.join(before_hash), &decoded)
                    .await
                    .ok();
            }
        }
    }

    let vulnerabilities: HashMap<String, VulnerabilityInfo> = patch
        .vulnerabilities
        .iter()
        .map(|(id, v)| {
            (
                id.clone(),
                VulnerabilityInfo {
                    cves: v.cves.clone(),
                    summary: v.summary.clone(),
                    severity: v.severity.clone(),
                    description: v.description.clone(),
                },
            )
        })
        .collect();

    let added = manifest
        .patches
        .get(&patch.purl)
        .is_none_or(|p| p.uuid != patch.uuid);

    manifest.patches.insert(
        patch.purl.clone(),
        PatchRecord {
            uuid: patch.uuid.clone(),
            exported_at: patch.published_at.clone(),
            files,
            vulnerabilities,
            description: patch.description.clone(),
            license: patch.license.clone(),
            tier: patch.tier.clone(),
        },
    );

    if let Err(e) = write_manifest(&manifest_path, &manifest).await {
        if args.json {
            println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                "status": "error",
                "error": format!("Error writing manifest: {e}"),
            })).unwrap());
        } else {
            eprintln!("Error writing manifest: {e}");
        }
        return 1;
    }

    if !args.json {
        println!("\nPatch saved to {}", manifest_path.display());
        if added {
            println!("  Added: 1");
        } else {
            println!("  Skipped: 1 (already exists)");
        }
    }

    if !args.save_only {
        if !args.json {
            println!("\nApplying patches...");
        }
        let apply_args = super::apply::ApplyArgs {
            cwd: args.cwd.clone(),
            dry_run: false,
            silent: args.json,
            manifest_path: manifest_path.display().to_string(),
            offline: false,
            global: args.global,
            global_prefix: args.global_prefix.clone(),
            ecosystems: None,
            force: false,
            json: false,
            verbose: false,
        };
        let code = super::apply::run(apply_args).await;
        if code != 0 && !args.json {
            eprintln!("\nSome patches could not be applied.");
        }
    }

    if args.json {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({
            "status": "success",
            "found": 1,
            "downloaded": if added { 1 } else { 0 },
            "applied": if !args.save_only && added { 1 } else { 0 },
            "patches": [{
                "purl": patch.purl,
                "uuid": patch.uuid,
                "action": if added { "added" } else { "skipped" },
            }],
        })).unwrap());
    }

    0
}

fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    let chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut table = [255u8; 256];
    for (i, &c) in chars.iter().enumerate() {
        table[c as usize] = i as u8;
    }

    let input = input.as_bytes();
    let mut output = Vec::with_capacity(input.len() * 3 / 4);

    let mut buf = 0u32;
    let mut bits = 0u32;

    for &b in input {
        if b == b'=' || b == b'\n' || b == b'\r' {
            continue;
        }
        let val = table[b as usize];
        if val == 255 {
            return Err(format!("Invalid base64 character: {}", b as char));
        }
        buf = (buf << 6) | val as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }

    Ok(output)
}
