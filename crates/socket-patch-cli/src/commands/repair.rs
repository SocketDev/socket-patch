use clap::Args;
use socket_patch_core::api::blob_fetcher::{
    fetch_missing_sources, format_fetch_result, get_missing_archives, get_missing_blobs,
    DownloadMode,
};
use socket_patch_core::api::client::get_api_client_with_overrides;
use socket_patch_core::manifest::operations::read_manifest;
use socket_patch_core::patch::apply::PatchSources;
use socket_patch_core::utils::cleanup_blobs::{
    cleanup_unused_archives, cleanup_unused_blobs, format_cleanup_result,
};
use std::path::Path;

use crate::args::{apply_env_toggles, GlobalArgs};
use crate::commands::lock_cli::acquire_or_emit;
use crate::json_envelope::{Command, Envelope, EnvelopeError, PatchAction, PatchEvent};

#[derive(Args)]
pub struct RepairArgs {
    #[command(flatten)]
    pub common: GlobalArgs,

    /// Only download missing artifacts; skip the cleanup phase.
    /// Incompatible with `--offline`.
    #[arg(long = "download-only", env = "SOCKET_DOWNLOAD_ONLY", default_value_t = false)]
    pub download_only: bool,
}

pub async fn run(args: RepairArgs) -> i32 {
    apply_env_toggles(&args.common);

    // --offline implies strict airgap: no network calls. `--download-only`
    // is the inverse (network-only). The two are now mutually exclusive.
    if args.common.offline && args.download_only {
        let msg =
            "--offline and --download-only are mutually exclusive".to_string();
        if args.common.json {
            let mut env = Envelope::new(Command::Repair);
            env.dry_run = args.common.dry_run;
            env.mark_error(EnvelopeError::new("invalid_args", msg));
            println!("{}", env.to_pretty_json());
        } else {
            eprintln!("Error: {msg}");
        }
        return 2;
    }

    let manifest_path = args.common.resolved_manifest_path();

    if tokio::fs::metadata(&manifest_path).await.is_err() {
        if args.common.json {
            let mut env = Envelope::new(Command::Repair);
            env.dry_run = args.common.dry_run;
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

    // Serialize against concurrent socket-patch runs targeting the
    // same `.socket/` directory. See `apply_lock`.
    let socket_dir = manifest_path.parent().unwrap_or(Path::new("."));
    let _lock = match acquire_or_emit(
        socket_dir,
        Command::Repair,
        args.common.json,
        args.common.silent,
        args.common.dry_run,
    ) {
        Ok(guard) => guard,
        Err(code) => return code,
    };

    match repair_inner(&args, &manifest_path).await {
        Ok(env) => {
            if args.common.json {
                println!("{}", env.to_pretty_json());
            }
            0
        }
        Err(e) => {
            if args.common.json {
                let mut env = Envelope::new(Command::Repair);
                env.dry_run = args.common.dry_run;
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

    let download_mode = DownloadMode::parse(&args.common.download_mode).map_err(|e| e.to_string())?;

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

    if !args.common.offline {
        if !missing_artifacts.is_empty() {
            if !args.common.json {
                println!(
                    "Found {} missing {} artifact(s)",
                    missing_artifacts.len(),
                    download_mode.as_tag()
                );
            }

            if args.common.dry_run {
                if !args.common.json {
                    println!("\nDry run - would download:");
                    for id in missing_artifacts.iter().take(10) {
                        println!("  - {}...", &id[..12.min(id.len())]);
                    }
                    if missing_artifacts.len() > 10 {
                        println!("  ... and {} more", missing_artifacts.len() - 10);
                    }
                }
            } else {
                if !args.common.json {
                    println!("\nDownloading missing {}s...", download_mode.as_tag());
                }
                let (client, _) =
                    get_api_client_with_overrides(args.common.api_client_overrides()).await;
                let sources = PatchSources {
                    blobs_path: &blobs_path,
                    packages_path: Some(&packages_path),
                    diffs_path: Some(&diffs_path),
                };
                let fetch_result =
                    fetch_missing_sources(&manifest, &sources, download_mode, &client, None).await;
                downloaded_count = fetch_result.downloaded;
                download_failed_count = fetch_result.failed;
                if !args.common.json {
                    println!("{}", format_fetch_result(&fetch_result));
                }
            }
        } else if !args.common.json {
            println!(
                "All {} artifacts are present locally.",
                download_mode.as_tag()
            );
        }
    } else if !missing_artifacts.is_empty() {
        if !args.common.json {
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
    } else if !args.common.json {
        println!(
            "All {} artifacts are present locally.",
            download_mode.as_tag()
        );
    }

    // Step 2: Clean up unused artifacts across all three directories.
    if !args.download_only {
        if !args.common.json {
            println!();
        }
        match cleanup_unused_blobs(&manifest, &blobs_path, args.common.dry_run).await {
            Ok(cleanup_result) => {
                blobs_checked += cleanup_result.blobs_checked;
                blobs_cleaned += cleanup_result.blobs_removed;
                if !args.common.json {
                    if cleanup_result.blobs_checked == 0 {
                        println!("No blobs directory found, nothing to clean up.");
                    } else if cleanup_result.blobs_removed == 0 {
                        println!(
                            "Checked {} blob(s), all are in use.",
                            cleanup_result.blobs_checked
                        );
                    } else {
                        println!("{}", format_cleanup_result(&cleanup_result, args.common.dry_run));
                    }
                }
            }
            Err(e) => {
                if !args.common.json {
                    eprintln!("Warning: blob cleanup failed: {e}");
                }
            }
        }

        // Diff archives.
        match cleanup_unused_archives(&manifest, &diffs_path, args.common.dry_run).await {
            Ok(cleanup_result) => {
                blobs_checked += cleanup_result.blobs_checked;
                blobs_cleaned += cleanup_result.blobs_removed;
                if !args.common.json && cleanup_result.blobs_removed > 0 {
                    println!(
                        "{}",
                        format_cleanup_result(&cleanup_result, args.common.dry_run)
                            .replace("blob(s)", "diff archive(s)")
                    );
                }
            }
            Err(e) => {
                if !args.common.json {
                    eprintln!("Warning: diff cleanup failed: {e}");
                }
            }
        }

        // Package archives.
        match cleanup_unused_archives(&manifest, &packages_path, args.common.dry_run).await {
            Ok(cleanup_result) => {
                blobs_checked += cleanup_result.blobs_checked;
                blobs_cleaned += cleanup_result.blobs_removed;
                if !args.common.json && cleanup_result.blobs_removed > 0 {
                    println!(
                        "{}",
                        format_cleanup_result(&cleanup_result, args.common.dry_run)
                            .replace("blob(s)", "package archive(s)")
                    );
                }
            }
            Err(e) => {
                if !args.common.json {
                    eprintln!("Warning: package cleanup failed: {e}");
                }
            }
        }
    }

    if !args.common.dry_run && !args.common.json {
        println!("\nRepair complete.");
    }

    // Translate the aggregate counts into envelope events. `repair`
    // operates on artifacts (not specific patches), so events use the
    // `PatchEvent::artifact` form (no PURL/UUID).
    let mut env = Envelope::new(Command::Repair);
    env.dry_run = args.common.dry_run;
    let action_for_repair = if args.common.dry_run {
        PatchAction::Verified
    } else {
        PatchAction::Downloaded
    };
    if downloaded_count > 0 || (args.common.dry_run && missing_count > 0) {
        let count = if args.common.dry_run {
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
        let cleanup_action = if args.common.dry_run {
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
