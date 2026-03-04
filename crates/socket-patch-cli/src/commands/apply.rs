use clap::Args;
use socket_patch_core::api::blob_fetcher::{
    fetch_missing_blobs, format_fetch_result, get_missing_blobs,
};
use socket_patch_core::api::client::get_api_client_from_env;
use socket_patch_core::constants::DEFAULT_PATCH_MANIFEST_PATH;
use socket_patch_core::crawlers::{CrawlerOptions, Ecosystem};
use socket_patch_core::manifest::operations::read_manifest;
use socket_patch_core::patch::apply::{apply_package_patch, verify_file_patch, ApplyResult};
use socket_patch_core::utils::cleanup_blobs::{cleanup_unused_blobs, format_cleanup_result};
use socket_patch_core::utils::purl::strip_purl_qualifiers;
use socket_patch_core::utils::telemetry::{track_patch_applied, track_patch_apply_failed};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::ecosystem_dispatch::{find_packages_for_purls, partition_purls};

#[derive(Args)]
pub struct ApplyArgs {
    /// Working directory
    #[arg(long, default_value = ".")]
    pub cwd: PathBuf,

    /// Verify patches can be applied without modifying files
    #[arg(short = 'd', long = "dry-run", default_value_t = false)]
    pub dry_run: bool,

    /// Only output errors
    #[arg(short = 's', long, default_value_t = false)]
    pub silent: bool,

    /// Path to patch manifest file
    #[arg(short = 'm', long = "manifest-path", default_value = DEFAULT_PATCH_MANIFEST_PATH)]
    pub manifest_path: String,

    /// Do not download missing blobs, fail if any are missing
    #[arg(long, default_value_t = false)]
    pub offline: bool,

    /// Apply patches to globally installed npm packages
    #[arg(short = 'g', long, default_value_t = false)]
    pub global: bool,

    /// Custom path to global node_modules
    #[arg(long = "global-prefix")]
    pub global_prefix: Option<PathBuf>,

    /// Restrict patching to specific ecosystems
    #[arg(long, value_delimiter = ',')]
    pub ecosystems: Option<Vec<String>>,

    /// Skip pre-application hash verification (apply even if package version differs)
    #[arg(short = 'f', long, default_value_t = false)]
    pub force: bool,
}

pub async fn run(args: ApplyArgs) -> i32 {
    let (telemetry_client, _) = get_api_client_from_env(None).await;
    let api_token = telemetry_client.api_token().cloned();
    let org_slug = telemetry_client.org_slug().cloned();

    let manifest_path = if Path::new(&args.manifest_path).is_absolute() {
        PathBuf::from(&args.manifest_path)
    } else {
        args.cwd.join(&args.manifest_path)
    };

    // Check if manifest exists - exit successfully if no .socket folder is set up
    if tokio::fs::metadata(&manifest_path).await.is_err() {
        if !args.silent {
            println!("No .socket folder found, skipping patch application.");
        }
        return 0;
    }

    match apply_patches_inner(&args, &manifest_path).await {
        Ok((success, results)) => {
            // Print results
            if !args.silent && !results.is_empty() {
                let patched: Vec<_> = results.iter().filter(|r| r.success).collect();
                let already_patched: Vec<_> = results
                    .iter()
                    .filter(|r| {
                        r.files_verified
                            .iter()
                            .all(|f| f.status == socket_patch_core::patch::apply::VerifyStatus::AlreadyPatched)
                    })
                    .collect();

                if args.dry_run {
                    println!("\nPatch verification complete:");
                    println!("  {} package(s) can be patched", patched.len());
                    if !already_patched.is_empty() {
                        println!("  {} package(s) already patched", already_patched.len());
                    }
                } else {
                    println!("\nPatched packages:");
                    for result in &patched {
                        if !result.files_patched.is_empty() {
                            println!("  {}", result.package_key);
                        } else if result.files_verified.iter().all(|f| {
                            f.status == socket_patch_core::patch::apply::VerifyStatus::AlreadyPatched
                        }) {
                            println!("  {} (already patched)", result.package_key);
                        }
                    }
                }
            }

            // Track telemetry
            let patched_count = results
                .iter()
                .filter(|r| r.success && !r.files_patched.is_empty())
                .count();
            if success {
                track_patch_applied(patched_count, args.dry_run, api_token.as_deref(), org_slug.as_deref()).await;
            } else {
                track_patch_apply_failed("One or more patches failed to apply", args.dry_run, api_token.as_deref(), org_slug.as_deref()).await;
            }

            if success { 0 } else { 1 }
        }
        Err(e) => {
            track_patch_apply_failed(&e, args.dry_run, api_token.as_deref(), org_slug.as_deref()).await;
            if !args.silent {
                eprintln!("Error: {e}");
            }
            1
        }
    }
}

async fn apply_patches_inner(
    args: &ApplyArgs,
    manifest_path: &Path,
) -> Result<(bool, Vec<ApplyResult>), String> {
    let manifest = read_manifest(manifest_path)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "Invalid manifest".to_string())?;

    let socket_dir = manifest_path.parent().unwrap();
    let blobs_path = socket_dir.join("blobs");
    tokio::fs::create_dir_all(&blobs_path)
        .await
        .map_err(|e| e.to_string())?;

    // Check for and download missing blobs
    let missing_blobs = get_missing_blobs(&manifest, &blobs_path).await;
    if !missing_blobs.is_empty() {
        if args.offline {
            if !args.silent {
                eprintln!(
                    "Error: {} blob(s) are missing and --offline mode is enabled.",
                    missing_blobs.len()
                );
                eprintln!("Run \"socket-patch repair\" to download missing blobs.");
            }
            return Ok((false, Vec::new()));
        }

        if !args.silent {
            println!("Downloading {} missing blob(s)...", missing_blobs.len());
        }

        let (client, _) = get_api_client_from_env(None).await;
        let fetch_result = fetch_missing_blobs(&manifest, &blobs_path, &client, None).await;

        if !args.silent {
            println!("{}", format_fetch_result(&fetch_result));
        }

        if fetch_result.failed > 0 {
            if !args.silent {
                eprintln!("Some blobs could not be downloaded. Cannot apply patches.");
            }
            return Ok((false, Vec::new()));
        }
    }

    // Partition manifest PURLs by ecosystem
    let manifest_purls: Vec<String> = manifest.patches.keys().cloned().collect();
    let partitioned =
        partition_purls(&manifest_purls, args.ecosystems.as_deref());

    let crawler_options = CrawlerOptions {
        cwd: args.cwd.clone(),
        global: args.global,
        global_prefix: args.global_prefix.clone(),
        batch_size: 100,
    };

    let all_packages =
        find_packages_for_purls(&partitioned, &crawler_options, args.silent).await;

    let has_any_purls = !partitioned.is_empty();

    if all_packages.is_empty() && !has_any_purls {
        if !args.silent {
            if args.global || args.global_prefix.is_some() {
                eprintln!("No global packages found");
            } else {
                eprintln!("No package directories found");
            }
        }
        return Ok((false, Vec::new()));
    }

    if all_packages.is_empty() {
        if !args.silent {
            println!("No packages found that match available patches");
        }
        return Ok((true, Vec::new()));
    }

    // Apply patches
    let mut results: Vec<ApplyResult> = Vec::new();
    let mut has_errors = false;

    // Group pypi PURLs by base (for variant matching with qualifiers)
    let mut pypi_qualified_groups: HashMap<String, Vec<String>> = HashMap::new();
    if let Some(pypi_purls) = partitioned.get(&Ecosystem::Pypi) {
        for purl in pypi_purls {
            let base = strip_purl_qualifiers(purl).to_string();
            pypi_qualified_groups
                .entry(base)
                .or_default()
                .push(purl.clone());
        }
    }

    let mut applied_base_purls: HashSet<String> = HashSet::new();

    for (purl, pkg_path) in &all_packages {
        if Ecosystem::from_purl(purl) == Some(Ecosystem::Pypi) {
            let base_purl = strip_purl_qualifiers(purl).to_string();
            if applied_base_purls.contains(&base_purl) {
                continue;
            }

            let variants = pypi_qualified_groups
                .get(&base_purl)
                .cloned()
                .unwrap_or_else(|| vec![base_purl.clone()]);
            let mut applied = false;

            for variant_purl in &variants {
                let patch = match manifest.patches.get(variant_purl) {
                    Some(p) => p,
                    None => continue,
                };

                // Check first file hash match (skip when --force)
                if !args.force {
                    if let Some((file_name, file_info)) = patch.files.iter().next() {
                        let verify = verify_file_patch(pkg_path, file_name, file_info).await;
                        if verify.status == socket_patch_core::patch::apply::VerifyStatus::HashMismatch {
                            continue;
                        }
                    }
                }

                let result = apply_package_patch(
                    variant_purl,
                    pkg_path,
                    &patch.files,
                    &blobs_path,
                    args.dry_run,
                    args.force,
                )
                .await;

                if result.success {
                    applied = true;
                    applied_base_purls.insert(base_purl.clone());
                    results.push(result);
                    break;
                } else {
                    results.push(result);
                }
            }

            if !applied {
                has_errors = true;
                if !args.silent {
                    eprintln!("Failed to patch {base_purl}: no matching variant found");
                }
            }
        } else {
            // npm PURLs: direct lookup
            let patch = match manifest.patches.get(purl) {
                Some(p) => p,
                None => continue,
            };

            let result = apply_package_patch(
                purl,
                pkg_path,
                &patch.files,
                &blobs_path,
                args.dry_run,
                args.force,
            )
            .await;

            if !result.success {
                has_errors = true;
                if !args.silent {
                    eprintln!(
                        "Failed to patch {}: {}",
                        purl,
                        result.error.as_deref().unwrap_or("unknown error")
                    );
                }
            }
            results.push(result);
        }
    }

    // Clean up unused blobs
    if !args.silent {
        if let Ok(cleanup_result) = cleanup_unused_blobs(&manifest, &blobs_path, args.dry_run).await {
            if cleanup_result.blobs_removed > 0 {
                println!("\n{}", format_cleanup_result(&cleanup_result, args.dry_run));
            }
        }
    }

    Ok((!has_errors, results))
}
