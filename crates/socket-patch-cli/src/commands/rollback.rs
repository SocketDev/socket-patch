use clap::Args;
use socket_patch_core::api::blob_fetcher::{
    fetch_blobs_by_hash, format_fetch_result,
};
use socket_patch_core::api::client::get_api_client_from_env;
use socket_patch_core::constants::DEFAULT_PATCH_MANIFEST_PATH;
use socket_patch_core::crawlers::CrawlerOptions;
use socket_patch_core::manifest::operations::read_manifest;
use socket_patch_core::manifest::schema::{PatchManifest, PatchRecord};
use socket_patch_core::patch::rollback::{rollback_package_patch, RollbackResult, VerifyRollbackStatus};
use socket_patch_core::utils::telemetry::{track_patch_rolled_back, track_patch_rollback_failed};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::ecosystem_dispatch::{find_packages_for_rollback, partition_purls};

#[derive(Args)]
pub struct RollbackArgs {
    /// Package PURL or patch UUID to rollback. Omit to rollback all patches.
    pub identifier: Option<String>,

    /// Working directory
    #[arg(long, default_value = ".")]
    pub cwd: PathBuf,

    /// Verify rollback can be performed without modifying files
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

    /// Rollback patches from globally installed npm packages
    #[arg(short = 'g', long, default_value_t = false)]
    pub global: bool,

    /// Custom path to global node_modules
    #[arg(long = "global-prefix")]
    pub global_prefix: Option<PathBuf>,

    /// Rollback a patch by fetching beforeHash blobs from API (no manifest required)
    #[arg(long = "one-off", default_value_t = false)]
    pub one_off: bool,

    /// Organization slug
    #[arg(long)]
    pub org: Option<String>,

    /// Socket API URL (overrides SOCKET_API_URL env var)
    #[arg(long = "api-url")]
    pub api_url: Option<String>,

    /// Socket API token (overrides SOCKET_API_TOKEN env var)
    #[arg(long = "api-token")]
    pub api_token: Option<String>,

    /// Restrict rollback to specific ecosystems
    #[arg(long, value_delimiter = ',')]
    pub ecosystems: Option<Vec<String>>,

    /// Output results as JSON
    #[arg(long, default_value_t = false)]
    pub json: bool,

    /// Show detailed per-file verification information
    #[arg(short = 'v', long, default_value_t = false)]
    pub verbose: bool,
}

struct PatchToRollback {
    purl: String,
    patch: PatchRecord,
}

fn find_patches_to_rollback(
    manifest: &PatchManifest,
    identifier: Option<&str>,
) -> Vec<PatchToRollback> {
    match identifier {
        None => manifest
            .patches
            .iter()
            .map(|(purl, patch)| PatchToRollback {
                purl: purl.clone(),
                patch: patch.clone(),
            })
            .collect(),
        Some(id) => {
            let mut patches = Vec::new();
            if id.starts_with("pkg:") {
                if let Some(patch) = manifest.patches.get(id) {
                    patches.push(PatchToRollback {
                        purl: id.to_string(),
                        patch: patch.clone(),
                    });
                }
            } else {
                for (purl, patch) in &manifest.patches {
                    if patch.uuid == id {
                        patches.push(PatchToRollback {
                            purl: purl.clone(),
                            patch: patch.clone(),
                        });
                    }
                }
            }
            patches
        }
    }
}

fn get_before_hash_blobs(manifest: &PatchManifest) -> HashSet<String> {
    let mut blobs = HashSet::new();
    for patch in manifest.patches.values() {
        for file_info in patch.files.values() {
            blobs.insert(file_info.before_hash.clone());
        }
    }
    blobs
}

async fn get_missing_before_blobs(
    manifest: &PatchManifest,
    blobs_path: &Path,
) -> HashSet<String> {
    let before_blobs = get_before_hash_blobs(manifest);
    let mut missing = HashSet::new();
    for hash in before_blobs {
        let blob_path = blobs_path.join(&hash);
        if tokio::fs::metadata(&blob_path).await.is_err() {
            missing.insert(hash);
        }
    }
    missing
}

fn verify_rollback_status_str(status: &VerifyRollbackStatus) -> &'static str {
    match status {
        VerifyRollbackStatus::Ready => "ready",
        VerifyRollbackStatus::AlreadyOriginal => "already_original",
        VerifyRollbackStatus::HashMismatch => "hash_mismatch",
        VerifyRollbackStatus::NotFound => "not_found",
        VerifyRollbackStatus::MissingBlob => "missing_blob",
    }
}

fn result_to_json(result: &RollbackResult) -> serde_json::Value {
    serde_json::json!({
        "purl": result.package_key,
        "path": result.package_path,
        "success": result.success,
        "error": result.error,
        "filesRolledBack": result.files_rolled_back,
        "filesVerified": result.files_verified.iter().map(|f| {
            serde_json::json!({
                "file": f.file,
                "status": verify_rollback_status_str(&f.status),
                "message": f.message,
                "currentHash": f.current_hash,
                "expectedHash": f.expected_hash,
                "targetHash": f.target_hash,
            })
        }).collect::<Vec<_>>(),
    })
}

pub async fn run(args: RollbackArgs) -> i32 {
    // Override env vars if CLI options provided (before building client)
    if let Some(ref url) = args.api_url {
        std::env::set_var("SOCKET_API_URL", url);
    }
    if let Some(ref token) = args.api_token {
        std::env::set_var("SOCKET_API_TOKEN", token);
    }

    let (telemetry_client, _) = get_api_client_from_env(args.org.as_deref()).await;
    let api_token = telemetry_client.api_token().cloned();
    let org_slug = telemetry_client.org_slug().cloned();

    // Validate one-off requires identifier
    if args.one_off && args.identifier.is_none() {
        if args.json {
            println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                "status": "error",
                "error": "--one-off requires an identifier (UUID or PURL)",
            })).unwrap());
        } else {
            eprintln!("Error: --one-off requires an identifier (UUID or PURL)");
        }
        return 1;
    }

    // Handle one-off mode
    if args.one_off {
        if args.json {
            println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                "status": "error",
                "error": "One-off rollback mode is not yet implemented",
            })).unwrap());
        } else {
            eprintln!("One-off rollback mode: fetching patch data...");
        }
        return 1;
    }

    let manifest_path = if Path::new(&args.manifest_path).is_absolute() {
        PathBuf::from(&args.manifest_path)
    } else {
        args.cwd.join(&args.manifest_path)
    };

    if tokio::fs::metadata(&manifest_path).await.is_err() {
        if args.json {
            println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                "status": "error",
                "error": "Manifest not found",
                "path": manifest_path.display().to_string(),
            })).unwrap());
        } else if !args.silent {
            eprintln!("Manifest not found at {}", manifest_path.display());
        }
        return 1;
    }

    match rollback_patches_inner(&args, &manifest_path).await {
        Ok((success, results)) => {
            let rolled_back_count = results
                .iter()
                .filter(|r| r.success && !r.files_rolled_back.is_empty())
                .count();
            let already_original_count = results
                .iter()
                .filter(|r| {
                    r.success
                        && r.files_verified.iter().all(|f| {
                            f.status == VerifyRollbackStatus::AlreadyOriginal
                        })
                })
                .count();
            let failed_count = results.iter().filter(|r| !r.success).count();

            if args.json {
                println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                    "status": if success { "success" } else { "partial_failure" },
                    "rolledBack": rolled_back_count,
                    "alreadyOriginal": already_original_count,
                    "failed": failed_count,
                    "dryRun": args.dry_run,
                    "results": results.iter().map(result_to_json).collect::<Vec<_>>(),
                })).unwrap());
            } else if !args.silent && !results.is_empty() {
                let rolled_back: Vec<_> = results
                    .iter()
                    .filter(|r| r.success && !r.files_rolled_back.is_empty())
                    .collect();
                let already_original: Vec<_> = results
                    .iter()
                    .filter(|r| {
                        r.success
                            && r.files_verified.iter().all(|f| {
                                f.status == VerifyRollbackStatus::AlreadyOriginal
                            })
                    })
                    .collect();
                let failed: Vec<_> = results.iter().filter(|r| !r.success).collect();

                if args.dry_run {
                    println!("\nRollback verification complete:");
                    let can_rollback = results.iter().filter(|r| r.success).count();
                    println!("  {can_rollback} package(s) can be rolled back");
                    if !already_original.is_empty() {
                        println!(
                            "  {} package(s) already in original state",
                            already_original.len()
                        );
                    }
                    if !failed.is_empty() {
                        println!("  {} package(s) cannot be rolled back", failed.len());
                    }
                } else {
                    if !rolled_back.is_empty() || !already_original.is_empty() {
                        println!("\nRolled back packages:");
                        for result in &rolled_back {
                            println!("  {}", result.package_key);
                        }
                        for result in &already_original {
                            println!("  {} (already original)", result.package_key);
                        }
                    }
                    if !failed.is_empty() {
                        println!("\nFailed to rollback:");
                        for result in &failed {
                            println!(
                                "  {}: {}",
                                result.package_key,
                                result.error.as_deref().unwrap_or("unknown error")
                            );
                        }
                    }
                }

                if args.verbose {
                    println!("\nDetailed verification:");
                    for result in &results {
                        println!("  {}:", result.package_key);
                        for f in &result.files_verified {
                            let status_str = match f.status {
                                VerifyRollbackStatus::Ready => "ready",
                                VerifyRollbackStatus::AlreadyOriginal => "already original",
                                VerifyRollbackStatus::HashMismatch => "hash mismatch",
                                VerifyRollbackStatus::NotFound => "not found",
                                VerifyRollbackStatus::MissingBlob => "missing blob",
                            };
                            println!("    {} [{}]", f.file, status_str);
                            if let Some(ref msg) = f.message {
                                println!("      message: {msg}");
                            }
                            if let Some(ref h) = f.current_hash {
                                println!("      current:  {h}");
                            }
                            if let Some(ref h) = f.expected_hash {
                                println!("      expected: {h}");
                            }
                            if let Some(ref h) = f.target_hash {
                                println!("      target:   {h}");
                            }
                        }
                    }
                }
            }

            if success {
                track_patch_rolled_back(rolled_back_count, api_token.as_deref(), org_slug.as_deref()).await;
            } else {
                track_patch_rollback_failed("One or more rollbacks failed", api_token.as_deref(), org_slug.as_deref()).await;
            }

            if success { 0 } else { 1 }
        }
        Err(e) => {
            track_patch_rollback_failed(&e, api_token.as_deref(), org_slug.as_deref()).await;
            if args.json {
                println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                    "status": "error",
                    "error": e,
                    "rolledBack": 0,
                    "alreadyOriginal": 0,
                    "failed": 0,
                    "dryRun": args.dry_run,
                    "results": [],
                })).unwrap());
            } else if !args.silent {
                eprintln!("Error: {e}");
            }
            1
        }
    }
}

async fn rollback_patches_inner(
    args: &RollbackArgs,
    manifest_path: &Path,
) -> Result<(bool, Vec<RollbackResult>), String> {
    let manifest = read_manifest(manifest_path)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "Invalid manifest".to_string())?;

    let socket_dir = manifest_path.parent().unwrap();
    let blobs_path = socket_dir.join("blobs");
    tokio::fs::create_dir_all(&blobs_path)
        .await
        .map_err(|e| e.to_string())?;

    let patches_to_rollback =
        find_patches_to_rollback(&manifest, args.identifier.as_deref());

    if patches_to_rollback.is_empty() {
        if args.identifier.is_some() {
            return Err(format!(
                "No patch found matching identifier: {}",
                args.identifier.as_deref().unwrap()
            ));
        }
        if !args.silent && !args.json {
            println!("No patches found in manifest");
        }
        return Ok((true, Vec::new()));
    }

    // Create filtered manifest
    let filtered_manifest = PatchManifest {
        patches: patches_to_rollback
            .iter()
            .map(|p| (p.purl.clone(), p.patch.clone()))
            .collect(),
    };

    // Check for missing beforeHash blobs
    let missing_blobs = get_missing_before_blobs(&filtered_manifest, &blobs_path).await;
    if !missing_blobs.is_empty() {
        if args.offline {
            if !args.silent && !args.json {
                eprintln!(
                    "Error: {} blob(s) are missing and --offline mode is enabled.",
                    missing_blobs.len()
                );
                eprintln!("Run \"socket-patch repair\" to download missing blobs.");
            }
            return Ok((false, Vec::new()));
        }

        if !args.silent && !args.json {
            println!("Downloading {} missing blob(s)...", missing_blobs.len());
        }

        let (client, _) = get_api_client_from_env(None).await;
        let fetch_result = fetch_blobs_by_hash(&missing_blobs, &blobs_path, &client, None).await;

        if !args.silent && !args.json {
            println!("{}", format_fetch_result(&fetch_result));
        }

        let still_missing = get_missing_before_blobs(&filtered_manifest, &blobs_path).await;
        if !still_missing.is_empty() {
            if !args.silent && !args.json {
                eprintln!(
                    "{} blob(s) could not be downloaded. Cannot rollback.",
                    still_missing.len()
                );
            }
            return Ok((false, Vec::new()));
        }
    }

    // Partition PURLs by ecosystem
    let rollback_purls: Vec<String> = patches_to_rollback.iter().map(|p| p.purl.clone()).collect();
    let partitioned =
        partition_purls(&rollback_purls, args.ecosystems.as_deref());

    let crawler_options = CrawlerOptions {
        cwd: args.cwd.clone(),
        global: args.global,
        global_prefix: args.global_prefix.clone(),
        batch_size: 100,
    };

    let all_packages =
        find_packages_for_rollback(&partitioned, &crawler_options, args.silent || args.json).await;

    if all_packages.is_empty() {
        if !args.silent && !args.json {
            println!("No packages found that match patches to rollback");
        }
        return Ok((true, Vec::new()));
    }

    // Rollback patches
    let mut results: Vec<RollbackResult> = Vec::new();
    let mut has_errors = false;

    for (purl, pkg_path) in &all_packages {
        let patch = match filtered_manifest.patches.get(purl) {
            Some(p) => p,
            None => continue,
        };

        let result = rollback_package_patch(
            purl,
            pkg_path,
            &patch.files,
            &blobs_path,
            args.dry_run,
        )
        .await;

        if !result.success {
            has_errors = true;
            if !args.silent && !args.json {
                eprintln!(
                    "Failed to rollback {}: {}",
                    purl,
                    result.error.as_deref().unwrap_or("unknown error")
                );
            }
        }
        results.push(result);
    }

    Ok((!has_errors, results))
}

// Export for use by remove command
#[allow(clippy::too_many_arguments)]
pub async fn rollback_patches(
    cwd: &Path,
    manifest_path: &Path,
    identifier: Option<&str>,
    dry_run: bool,
    silent: bool,
    offline: bool,
    global: bool,
    global_prefix: Option<PathBuf>,
    ecosystems: Option<Vec<String>>,
) -> Result<(bool, Vec<RollbackResult>), String> {
    let args = RollbackArgs {
        identifier: identifier.map(String::from),
        cwd: cwd.to_path_buf(),
        dry_run,
        silent,
        manifest_path: manifest_path.display().to_string(),
        offline,
        global,
        global_prefix,
        one_off: false,
        org: None,
        api_url: None,
        api_token: None,
        ecosystems,
        json: false,
        verbose: false,
    };
    rollback_patches_inner(&args, manifest_path).await
}
