use clap::Args;
use socket_patch_core::constants::DEFAULT_PATCH_MANIFEST_PATH;
use socket_patch_core::manifest::operations::{read_manifest, write_manifest};
use socket_patch_core::manifest::schema::PatchManifest;
use socket_patch_core::utils::cleanup_blobs::{cleanup_unused_blobs, format_cleanup_result};
use socket_patch_core::utils::telemetry::{track_patch_removed, track_patch_remove_failed};
use std::path::{Path, PathBuf};

use super::rollback::rollback_patches;

#[derive(Args)]
pub struct RemoveArgs {
    /// Package PURL or patch UUID
    pub identifier: String,

    /// Working directory
    #[arg(long, default_value = ".")]
    pub cwd: PathBuf,

    /// Path to patch manifest file
    #[arg(short = 'm', long = "manifest-path", default_value = DEFAULT_PATCH_MANIFEST_PATH)]
    pub manifest_path: String,

    /// Skip rolling back files before removing (only update manifest)
    #[arg(long = "skip-rollback", default_value_t = false)]
    pub skip_rollback: bool,

    /// Remove patches from globally installed npm packages
    #[arg(short = 'g', long, default_value_t = false)]
    pub global: bool,

    /// Custom path to global node_modules
    #[arg(long = "global-prefix")]
    pub global_prefix: Option<PathBuf>,
}

pub async fn run(args: RemoveArgs) -> i32 {
    let (telemetry_client, _) =
        socket_patch_core::api::client::get_api_client_from_env(None).await;
    let api_token = telemetry_client.api_token().cloned();
    let org_slug = telemetry_client.org_slug().cloned();

    let manifest_path = if Path::new(&args.manifest_path).is_absolute() {
        PathBuf::from(&args.manifest_path)
    } else {
        args.cwd.join(&args.manifest_path)
    };

    if tokio::fs::metadata(&manifest_path).await.is_err() {
        eprintln!("Manifest not found at {}", manifest_path.display());
        return 1;
    }

    // First, rollback the patch if not skipped
    if !args.skip_rollback {
        println!("Rolling back patch before removal...");
        match rollback_patches(
            &args.cwd,
            &manifest_path,
            Some(&args.identifier),
            false,
            false,
            false,
            args.global,
            args.global_prefix.clone(),
            None,
        )
        .await
        {
            Ok((success, results)) => {
                if !success {
                    track_patch_remove_failed(
                        "Rollback failed during patch removal",
                        api_token.as_deref(),
                        org_slug.as_deref(),
                    )
                    .await;
                    eprintln!("\nRollback failed. Use --skip-rollback to remove from manifest without restoring files.");
                    return 1;
                }

                let rolled_back = results
                    .iter()
                    .filter(|r| r.success && !r.files_rolled_back.is_empty())
                    .count();
                let already_original = results
                    .iter()
                    .filter(|r| {
                        r.success
                            && r.files_verified.iter().all(|f| {
                                f.status
                                    == socket_patch_core::patch::rollback::VerifyRollbackStatus::AlreadyOriginal
                            })
                    })
                    .count();

                if rolled_back > 0 {
                    println!("Rolled back {rolled_back} package(s)");
                }
                if already_original > 0 {
                    println!("{already_original} package(s) already in original state");
                }
                if results.is_empty() {
                    println!("No packages found to rollback (not installed)");
                }
                println!();
            }
            Err(e) => {
                track_patch_remove_failed(&e, api_token.as_deref(), org_slug.as_deref()).await;
                eprintln!("Error during rollback: {e}");
                eprintln!("\nRollback failed. Use --skip-rollback to remove from manifest without restoring files.");
                return 1;
            }
        }
    }

    // Now remove from manifest
    match remove_patch_from_manifest(&args.identifier, &manifest_path).await {
        Ok((removed, manifest)) => {
            if removed.is_empty() {
                track_patch_remove_failed(
                    &format!("No patch found matching identifier: {}", args.identifier),
                    api_token.as_deref(),
                    org_slug.as_deref(),
                )
                .await;
                eprintln!(
                    "No patch found matching identifier: {}",
                    args.identifier
                );
                return 1;
            }

            println!("Removed {} patch(es) from manifest:", removed.len());
            for purl in &removed {
                println!("  - {purl}");
            }

            println!("\nManifest updated at {}", manifest_path.display());

            // Clean up unused blobs
            let socket_dir = manifest_path.parent().unwrap();
            let blobs_path = socket_dir.join("blobs");
            if let Ok(cleanup_result) = cleanup_unused_blobs(&manifest, &blobs_path, false).await {
                if cleanup_result.blobs_removed > 0 {
                    println!("\n{}", format_cleanup_result(&cleanup_result, false));
                }
            }

            track_patch_removed(removed.len(), api_token.as_deref(), org_slug.as_deref()).await;
            0
        }
        Err(e) => {
            track_patch_remove_failed(&e, api_token.as_deref(), org_slug.as_deref()).await;
            eprintln!("Error: {e}");
            1
        }
    }
}

async fn remove_patch_from_manifest(
    identifier: &str,
    manifest_path: &Path,
) -> Result<(Vec<String>, PatchManifest), String> {
    let mut manifest = read_manifest(manifest_path)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "Invalid manifest".to_string())?;

    let mut removed = Vec::new();

    if identifier.starts_with("pkg:") {
        if manifest.patches.remove(identifier).is_some() {
            removed.push(identifier.to_string());
        }
    } else {
        let purls_to_remove: Vec<String> = manifest
            .patches
            .iter()
            .filter(|(_, patch)| patch.uuid == identifier)
            .map(|(purl, _)| purl.clone())
            .collect();

        for purl in purls_to_remove {
            manifest.patches.remove(&purl);
            removed.push(purl);
        }
    }

    if !removed.is_empty() {
        write_manifest(manifest_path, &manifest)
            .await
            .map_err(|e| e.to_string())?;
    }

    Ok((removed, manifest))
}
