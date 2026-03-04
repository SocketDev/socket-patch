use clap::Args;
use socket_patch_core::api::blob_fetcher::{
    fetch_missing_blobs, format_fetch_result, get_missing_blobs,
};
use socket_patch_core::api::client::get_api_client_from_env;
use socket_patch_core::constants::DEFAULT_PATCH_MANIFEST_PATH;
use socket_patch_core::manifest::operations::read_manifest;
use socket_patch_core::utils::cleanup_blobs::{cleanup_unused_blobs, format_cleanup_result};
use std::path::{Path, PathBuf};

#[derive(Args)]
pub struct RepairArgs {
    /// Working directory
    #[arg(long, default_value = ".")]
    pub cwd: PathBuf,

    /// Path to patch manifest file
    #[arg(short = 'm', long = "manifest-path", default_value = DEFAULT_PATCH_MANIFEST_PATH)]
    pub manifest_path: String,

    /// Show what would be done without actually doing it
    #[arg(short = 'd', long = "dry-run", default_value_t = false)]
    pub dry_run: bool,

    /// Skip network operations (cleanup only)
    #[arg(long, default_value_t = false)]
    pub offline: bool,

    /// Only download missing blobs, do not clean up
    #[arg(long = "download-only", default_value_t = false)]
    pub download_only: bool,
}

pub async fn run(args: RepairArgs) -> i32 {
    let manifest_path = if Path::new(&args.manifest_path).is_absolute() {
        PathBuf::from(&args.manifest_path)
    } else {
        args.cwd.join(&args.manifest_path)
    };

    if tokio::fs::metadata(&manifest_path).await.is_err() {
        eprintln!("Manifest not found at {}", manifest_path.display());
        return 1;
    }

    match repair_inner(&args, &manifest_path).await {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("Error: {e}");
            1
        }
    }
}

async fn repair_inner(args: &RepairArgs, manifest_path: &Path) -> Result<(), String> {
    let manifest = read_manifest(manifest_path)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "Invalid manifest".to_string())?;

    let socket_dir = manifest_path.parent().unwrap();
    let blobs_path = socket_dir.join("blobs");

    // Step 1: Check for and download missing blobs
    if !args.offline {
        let missing_blobs = get_missing_blobs(&manifest, &blobs_path).await;

        if !missing_blobs.is_empty() {
            println!("Found {} missing blob(s)", missing_blobs.len());

            if args.dry_run {
                println!("\nDry run - would download:");
                for hash in missing_blobs.iter().take(10) {
                    println!("  - {}...", &hash[..12.min(hash.len())]);
                }
                if missing_blobs.len() > 10 {
                    println!("  ... and {} more", missing_blobs.len() - 10);
                }
            } else {
                println!("\nDownloading missing blobs...");
                let (client, _) = get_api_client_from_env(None).await;
                let fetch_result = fetch_missing_blobs(&manifest, &blobs_path, &client, None).await;
                println!("{}", format_fetch_result(&fetch_result));
            }
        } else {
            println!("All blobs are present locally.");
        }
    } else {
        let missing_blobs = get_missing_blobs(&manifest, &blobs_path).await;
        if !missing_blobs.is_empty() {
            println!(
                "Warning: {} blob(s) are missing (offline mode - not downloading)",
                missing_blobs.len()
            );
            for hash in missing_blobs.iter().take(5) {
                println!("  - {}...", &hash[..12.min(hash.len())]);
            }
            if missing_blobs.len() > 5 {
                println!("  ... and {} more", missing_blobs.len() - 5);
            }
        } else {
            println!("All blobs are present locally.");
        }
    }

    // Step 2: Clean up unused blobs
    if !args.download_only {
        println!();
        match cleanup_unused_blobs(&manifest, &blobs_path, args.dry_run).await {
            Ok(cleanup_result) => {
                if cleanup_result.blobs_checked == 0 {
                    println!("No blobs directory found, nothing to clean up.");
                } else if cleanup_result.blobs_removed == 0 {
                    println!(
                        "Checked {} blob(s), all are in use.",
                        cleanup_result.blobs_checked
                    );
                } else {
                    println!("{}", format_cleanup_result(&cleanup_result, args.dry_run));
                }
            }
            Err(e) => {
                eprintln!("Warning: cleanup failed: {e}");
            }
        }
    }

    if !args.dry_run {
        println!("\nRepair complete.");
    }

    Ok(())
}
