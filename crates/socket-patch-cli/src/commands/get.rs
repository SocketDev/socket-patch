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
use std::io::{self, Write};
use std::path::PathBuf;

use crate::ecosystem_dispatch::crawl_all_ecosystems;

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
}

#[derive(Debug, PartialEq)]
enum IdentifierType {
    Uuid,
    Cve,
    Ghsa,
    Purl,
    Package,
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

pub async fn run(args: GetArgs) -> i32 {
    // Validate flags
    let type_flags = [args.id, args.cve, args.ghsa, args.package]
        .iter()
        .filter(|&&f| f)
        .count();
    if type_flags > 1 {
        eprintln!("Error: Only one of --id, --cve, --ghsa, or --package can be specified");
        return 1;
    }
    if args.one_off && args.save_only {
        eprintln!("Error: --one-off and --save-only cannot be used together");
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
            Some(t) => {
                println!("Detected identifier type: {:?}", t);
                t
            }
            None => {
                println!("Treating \"{}\" as a package name search", args.identifier);
                IdentifierType::Package
            }
        }
    };

    // Handle UUID: fetch and download directly
    if id_type == IdentifierType::Uuid {
        println!("Fetching patch by UUID: {}", args.identifier);
        match api_client
            .fetch_patch(effective_org_slug, &args.identifier)
            .await
        {
            Ok(Some(patch)) => {
                if patch.tier == "paid" && use_public_proxy {
                    println!("\n\x1b[33mThis patch requires a paid subscription to download.\x1b[0m");
                    println!("\n  Patch: {}", patch.purl);
                    println!("  Tier:  \x1b[33mpaid\x1b[0m");
                    println!("\n  Upgrade at: \x1b[36mhttps://socket.dev/pricing\x1b[0m\n");
                    return 0;
                }

                // Save to manifest
                return save_and_apply_patch(&args, &patch.purl, &patch.uuid, effective_org_slug)
                    .await;
            }
            Ok(None) => {
                println!("No patch found with UUID: {}", args.identifier);
                return 0;
            }
            Err(e) => {
                eprintln!("Error: {e}");
                return 1;
            }
        }
    }

    // For CVE/GHSA/PURL/package, search first
    let search_response: SearchResponse = match id_type {
        IdentifierType::Cve => {
            println!("Searching patches for CVE: {}", args.identifier);
            match api_client
                .search_patches_by_cve(effective_org_slug, &args.identifier)
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("Error: {e}");
                    return 1;
                }
            }
        }
        IdentifierType::Ghsa => {
            println!("Searching patches for GHSA: {}", args.identifier);
            match api_client
                .search_patches_by_ghsa(effective_org_slug, &args.identifier)
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("Error: {e}");
                    return 1;
                }
            }
        }
        IdentifierType::Purl => {
            println!("Searching patches for PURL: {}", args.identifier);
            match api_client
                .search_patches_by_package(effective_org_slug, &args.identifier)
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("Error: {e}");
                    return 1;
                }
            }
        }
        IdentifierType::Package => {
            println!("Enumerating packages...");
            let crawler_options = CrawlerOptions {
                cwd: args.cwd.clone(),
                global: args.global,
                global_prefix: args.global_prefix.clone(),
                batch_size: 100,
            };
            let (all_packages, _) = crawl_all_ecosystems(&crawler_options).await;

            if all_packages.is_empty() {
                if args.global {
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

            println!("Found {} packages", all_packages.len());

            let matches = fuzzy_match_packages(&args.identifier, &all_packages, 20);

            if matches.is_empty() {
                println!("No packages matching \"{}\" found.", args.identifier);
                return 0;
            }

            println!(
                "Found {} matching package(s), checking for available patches...",
                matches.len()
            );

            // Search for patches for the best match
            let best_match = &matches[0];
            match api_client
                .search_patches_by_package(effective_org_slug, &best_match.purl)
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("Error: {e}");
                    return 1;
                }
            }
        }
        _ => unreachable!(),
    };

    if search_response.patches.is_empty() {
        println!(
            "No patches found for {:?}: {}",
            id_type, args.identifier
        );
        return 0;
    }

    // Display results
    display_search_results(&search_response.patches, search_response.can_access_paid_patches);

    // Filter accessible patches
    let accessible: Vec<_> = search_response
        .patches
        .iter()
        .filter(|p| p.tier == "free" || search_response.can_access_paid_patches)
        .collect();

    if accessible.is_empty() {
        println!("\n\x1b[33mAll available patches require a paid subscription.\x1b[0m");
        println!("\n  Upgrade at: \x1b[36mhttps://socket.dev/pricing\x1b[0m\n");
        return 0;
    }

    // Prompt for confirmation
    if accessible.len() > 1 && !args.yes {
        print!("Download {} patch(es)? [y/N] ", accessible.len());
        io::stdout().flush().unwrap();
        let mut answer = String::new();
        io::stdin().read_line(&mut answer).unwrap();
        let answer = answer.trim().to_lowercase();
        if answer != "y" && answer != "yes" {
            println!("Download cancelled.");
            return 0;
        }
    }

    // Download and save patches
    let socket_dir = args.cwd.join(".socket");
    let blobs_dir = socket_dir.join("blobs");
    let manifest_path = socket_dir.join("manifest.json");

    tokio::fs::create_dir_all(&socket_dir).await.ok();
    tokio::fs::create_dir_all(&blobs_dir).await.ok();

    let mut manifest = match read_manifest(&manifest_path).await {
        Ok(Some(m)) => m,
        _ => PatchManifest::new(),
    };

    println!("\nDownloading {} patch(es)...", accessible.len());

    let mut patches_added = 0;
    let mut patches_skipped = 0;
    let mut patches_failed = 0;

    for search_result in &accessible {
        match api_client
            .fetch_patch(effective_org_slug, &search_result.uuid)
            .await
        {
            Ok(Some(patch)) => {
                // Check if already in manifest
                if manifest
                    .patches
                    .get(&patch.purl)
                    .is_some_and(|p| p.uuid == patch.uuid)
                {
                    println!("  [skip] {} (already in manifest)", patch.purl);
                    patches_skipped += 1;
                    continue;
                }

                // Save blob contents (afterHash only)
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

                    // Save after blob content
                    if let (Some(ref blob_content), Some(ref after_hash)) =
                        (&file_info.blob_content, &file_info.after_hash)
                    {
                        if let Ok(decoded) =
                            base64_decode(blob_content)
                        {
                            let blob_path = blobs_dir.join(after_hash);
                            tokio::fs::write(&blob_path, &decoded).await.ok();
                        }
                    }
                }

                // Build vulnerabilities
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

                println!("  [add] {}", patch.purl);
                patches_added += 1;
            }
            Ok(None) => {
                println!("  [fail] {} (could not fetch details)", search_result.purl);
                patches_failed += 1;
            }
            Err(e) => {
                println!("  [fail] {} ({e})", search_result.purl);
                patches_failed += 1;
            }
        }
    }

    // Write manifest
    if let Err(e) = write_manifest(&manifest_path, &manifest).await {
        eprintln!("Error writing manifest: {e}");
        return 1;
    }

    println!("\nPatches saved to {}", manifest_path.display());
    println!("  Added: {patches_added}");
    if patches_skipped > 0 {
        println!("  Skipped: {patches_skipped}");
    }
    if patches_failed > 0 {
        println!("  Failed: {patches_failed}");
    }

    // Auto-apply unless --save-only
    if !args.save_only && patches_added > 0 {
        println!("\nApplying patches...");
        let apply_args = super::apply::ApplyArgs {
            cwd: args.cwd.clone(),
            dry_run: false,
            silent: false,
            manifest_path: manifest_path.display().to_string(),
            offline: false,
            global: args.global,
            global_prefix: args.global_prefix.clone(),
            ecosystems: None,
            force: false,
        };
        let code = super::apply::run(apply_args).await;
        if code != 0 {
            eprintln!("\nSome patches could not be applied.");
        }
    }

    0
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
            println!("No patch found with UUID: {uuid}");
            return 0;
        }
        Err(e) => {
            eprintln!("Error: {e}");
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
        eprintln!("Error writing manifest: {e}");
        return 1;
    }

    println!("\nPatch saved to {}", manifest_path.display());
    if added {
        println!("  Added: 1");
    } else {
        println!("  Skipped: 1 (already exists)");
    }

    if !args.save_only {
        println!("\nApplying patches...");
        let apply_args = super::apply::ApplyArgs {
            cwd: args.cwd.clone(),
            dry_run: false,
            silent: false,
            manifest_path: manifest_path.display().to_string(),
            offline: false,
            global: args.global,
            global_prefix: args.global_prefix.clone(),
            ecosystems: None,
            force: false,
        };
        let code = super::apply::run(apply_args).await;
        if code != 0 {
            eprintln!("\nSome patches could not be applied.");
        }
    }

    0
}

fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    // Simple base64 decoder
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
