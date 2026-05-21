use clap::Args;
use socket_patch_core::api::blob_fetcher::{
    fetch_missing_sources, format_fetch_result, get_missing_archives, get_missing_blobs,
    DownloadMode,
};
use socket_patch_core::api::client::get_api_client_from_env;
use socket_patch_core::constants::DEFAULT_PATCH_MANIFEST_PATH;
use socket_patch_core::manifest::operations::{read_manifest, resolve_manifest_path};
use socket_patch_core::patch::apply::PatchSources;
use socket_patch_core::utils::cleanup_blobs::{
    cleanup_unused_archives, cleanup_unused_blobs, format_cleanup_result,
};
use std::path::{Path, PathBuf};

use crate::json_envelope::{Command, Envelope, EnvelopeError, PatchAction, PatchEvent};

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

    /// Output results as JSON
    #[arg(long, default_value_t = false)]
    pub json: bool,

    /// Which kind of patch artifact to download. `file` (default for
    /// repair) restores the legacy per-file blobs needed to apply any
    /// patch. `diff` and `package` fetch the smaller archive formats.
    #[arg(long = "download-mode", default_value = "file")]
    pub download_mode: String,
}

pub async fn run(args: RepairArgs) -> i32 {
    let manifest_path = resolve_manifest_path(&args.cwd, &args.manifest_path);

    if tokio::fs::metadata(&manifest_path).await.is_err() {
        if args.json {
            let mut env = Envelope::new(Command::Repair);
            env.dry_run = args.dry_run;
            env.mark_error(EnvelopeError::new(
                "manifest_not_found",
                format!("Manifest not found at {}", manifest_path.display()),
            ));
            println!("{}", env.to_pretty_json());
        } else {
            eprintln!("Manifest not found at {}", manifest_path.display());
        }
        return 1;
    }

    match repair_inner(&args, &manifest_path).await {
        Ok(env) => {
            if args.json {
                println!("{}", env.to_pretty_json());
            }
            0
        }
        Err(e) => {
            if args.json {
                let mut env = Envelope::new(Command::Repair);
                env.dry_run = args.dry_run;
                env.mark_error(EnvelopeError::new("repair_failed", e));
                println!("{}", env.to_pretty_json());
            } else {
                eprintln!("Error: {e}");
            }
            1
        }
    }
}

async fn repair_inner(args: &RepairArgs, manifest_path: &Path) -> Result<Envelope, String> {
    let manifest = read_manifest(manifest_path)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "Invalid manifest".to_string())?;

    let socket_dir = manifest_path.parent().unwrap();
    let blobs_path = socket_dir.join("blobs");
    let diffs_path = socket_dir.join("diffs");
    let packages_path = socket_dir.join("packages");

    let download_mode = DownloadMode::parse(&args.download_mode).map_err(|e| e.to_string())?;

    let mut downloaded_count = 0usize;
    let mut download_failed_count = 0usize;
    let mut blobs_cleaned = 0usize;
    let mut blobs_checked = 0usize;

    // Step 1: Check for and download missing artifacts in the requested
    // mode. Counts below refer to whatever kind of artifact was requested
    // (file blobs, diff archives, or package archives).
    let missing_artifacts: Vec<String> = match download_mode {
        DownloadMode::File => get_missing_blobs(&manifest, &blobs_path)
            .await
            .into_iter()
            .collect(),
        DownloadMode::Diff => get_missing_archives(&manifest, &diffs_path)
            .await
            .into_iter()
            .collect(),
        DownloadMode::Package => get_missing_archives(&manifest, &packages_path)
            .await
            .into_iter()
            .collect(),
    };
    let missing_count = missing_artifacts.len();

    if !args.offline {
        if !missing_artifacts.is_empty() {
            if !args.json {
                println!(
                    "Found {} missing {} artifact(s)",
                    missing_artifacts.len(),
                    download_mode.as_tag()
                );
            }

            if args.dry_run {
                if !args.json {
                    println!("\nDry run - would download:");
                    for id in missing_artifacts.iter().take(10) {
                        println!("  - {}...", &id[..12.min(id.len())]);
                    }
                    if missing_artifacts.len() > 10 {
                        println!("  ... and {} more", missing_artifacts.len() - 10);
                    }
                }
            } else {
                if !args.json {
                    println!("\nDownloading missing {}s...", download_mode.as_tag());
                }
                let (client, _) = get_api_client_from_env(None).await;
                let sources = PatchSources {
                    blobs_path: &blobs_path,
                    packages_path: Some(&packages_path),
                    diffs_path: Some(&diffs_path),
                };
                let fetch_result =
                    fetch_missing_sources(&manifest, &sources, download_mode, &client, None).await;
                downloaded_count = fetch_result.downloaded;
                download_failed_count = fetch_result.failed;
                if !args.json {
                    println!("{}", format_fetch_result(&fetch_result));
                }
            }
        } else if !args.json {
            println!(
                "All {} artifacts are present locally.",
                download_mode.as_tag()
            );
        }
    } else if !missing_artifacts.is_empty() {
        if !args.json {
            println!(
                "Warning: {} {} artifact(s) are missing (offline mode - not downloading)",
                missing_artifacts.len(),
                download_mode.as_tag()
            );
            for id in missing_artifacts.iter().take(5) {
                println!("  - {}...", &id[..12.min(id.len())]);
            }
            if missing_artifacts.len() > 5 {
                println!("  ... and {} more", missing_artifacts.len() - 5);
            }
        }
    } else if !args.json {
        println!(
            "All {} artifacts are present locally.",
            download_mode.as_tag()
        );
    }

    // Step 2: Clean up unused artifacts across all three directories.
    if !args.download_only {
        if !args.json {
            println!();
        }
        match cleanup_unused_blobs(&manifest, &blobs_path, args.dry_run).await {
            Ok(cleanup_result) => {
                blobs_checked += cleanup_result.blobs_checked;
                blobs_cleaned += cleanup_result.blobs_removed;
                if !args.json {
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
            }
            Err(e) => {
                if !args.json {
                    eprintln!("Warning: blob cleanup failed: {e}");
                }
            }
        }

        // Diff archives.
        match cleanup_unused_archives(&manifest, &diffs_path, args.dry_run).await {
            Ok(cleanup_result) => {
                blobs_checked += cleanup_result.blobs_checked;
                blobs_cleaned += cleanup_result.blobs_removed;
                if !args.json && cleanup_result.blobs_removed > 0 {
                    println!(
                        "{}",
                        format_cleanup_result(&cleanup_result, args.dry_run)
                            .replace("blob(s)", "diff archive(s)")
                    );
                }
            }
            Err(e) => {
                if !args.json {
                    eprintln!("Warning: diff cleanup failed: {e}");
                }
            }
        }

        // Package archives.
        match cleanup_unused_archives(&manifest, &packages_path, args.dry_run).await {
            Ok(cleanup_result) => {
                blobs_checked += cleanup_result.blobs_checked;
                blobs_cleaned += cleanup_result.blobs_removed;
                if !args.json && cleanup_result.blobs_removed > 0 {
                    println!(
                        "{}",
                        format_cleanup_result(&cleanup_result, args.dry_run)
                            .replace("blob(s)", "package archive(s)")
                    );
                }
            }
            Err(e) => {
                if !args.json {
                    eprintln!("Warning: package cleanup failed: {e}");
                }
            }
        }
    }

    if !args.dry_run && !args.json {
        println!("\nRepair complete.");
    }

    // Translate the aggregate counts into envelope events. `repair`
    // operates on artifacts (not specific patches), so events use the
    // `PatchEvent::artifact` form (no PURL/UUID).
    let mut env = Envelope::new(Command::Repair);
    env.dry_run = args.dry_run;
    let action_for_repair = if args.dry_run {
        PatchAction::Verified
    } else {
        PatchAction::Downloaded
    };
    if downloaded_count > 0 || (args.dry_run && missing_count > 0) {
        let count = if args.dry_run {
            missing_count
        } else {
            downloaded_count
        };
        env.record(
            PatchEvent::artifact(action_for_repair).with_details(serde_json::json!({
                "count": count,
                "mode": download_mode.as_tag(),
            })),
        );
    }
    if download_failed_count > 0 {
        env.record(
            PatchEvent::artifact(PatchAction::Failed).with_error(
                "download_failed",
                format!("{} artifact(s) failed to download", download_failed_count),
            ),
        );
        env.mark_partial_failure();
    }
    if blobs_cleaned > 0 {
        let cleanup_action = if args.dry_run {
            PatchAction::Verified
        } else {
            PatchAction::Removed
        };
        env.record(PatchEvent::artifact(cleanup_action).with_details(serde_json::json!({
            "count": blobs_cleaned,
            "checked": blobs_checked,
        })));
    }
    Ok(env)
}
