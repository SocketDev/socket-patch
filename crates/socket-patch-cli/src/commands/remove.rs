use clap::Args;
use socket_patch_core::api::client::get_api_client_with_overrides;
use socket_patch_core::manifest::operations::{read_manifest, write_manifest};
use socket_patch_core::manifest::schema::PatchManifest;
use socket_patch_core::utils::cleanup_blobs::{cleanup_unused_blobs, format_cleanup_result};
use socket_patch_core::utils::telemetry::{track_patch_removed, track_patch_remove_failed};
use std::path::Path;
use std::time::Duration;

use super::rollback::rollback_patches;
use crate::args::{apply_env_toggles, GlobalArgs};
use crate::commands::lock_cli::{acquire_or_emit, lock_broken_event};
use crate::json_envelope::{
    Command, Envelope, EnvelopeError, PatchAction, PatchEvent, Status,
};
use crate::output::confirm;

/// Emit a `remove` error envelope and return. Used by the many error
/// paths in `run` so they all share the same JSON shape.
fn emit_error_envelope(json: bool, code: &str, message: String) {
    if json {
        let mut env = Envelope::new(Command::Remove);
        env.mark_error(EnvelopeError::new(code, message));
        println!("{}", env.to_pretty_json());
    } else {
        eprintln!("Error: {message}");
    }
}

#[derive(Args)]
pub struct RemoveArgs {
    /// Package PURL or patch UUID.
    pub identifier: String,

    #[command(flatten)]
    pub common: GlobalArgs,

    /// Skip rolling back files before removing (only update manifest).
    #[arg(long = "skip-rollback", env = "SOCKET_SKIP_ROLLBACK", default_value_t = false)]
    pub skip_rollback: bool,
}

pub async fn run(args: RemoveArgs) -> i32 {
    apply_env_toggles(&args.common);
    let (telemetry_client, _) =
        get_api_client_with_overrides(args.common.api_client_overrides()).await;
    let api_token = telemetry_client.api_token().cloned();
    let org_slug = telemetry_client.org_slug().cloned();

    let manifest_path = args.common.resolved_manifest_path();

    if tokio::fs::metadata(&manifest_path).await.is_err() {
        emit_error_envelope(
            args.common.json,
            "manifest_not_found",
            format!("Manifest not found at {}", manifest_path.display()),
        );
        return 1;
    }

    // Serialize against concurrent socket-patch runs targeting the
    // same `.socket/` directory. Note: `rollback_patches` (which
    // `remove` calls into) does NOT acquire the lock — that would
    // self-deadlock — so the outer remove invocation holds it for
    // both the rollback and the manifest mutation.
    let socket_dir = manifest_path.parent().unwrap_or(Path::new("."));
    let acquired = match acquire_or_emit(
        socket_dir,
        Command::Remove,
        args.common.json,
        false, // remove has no --silent on its own; use false
        false, // remove has no --dry-run
        Duration::from_secs(args.common.lock_timeout.unwrap_or(0)),
        args.common.break_lock,
    ) {
        Ok(acquired) => acquired,
        Err(code) => return code,
    };
    let _lock = acquired.guard;
    let lock_was_broken = acquired.broke_lock;

    // Read manifest to show what will be removed and confirm
    let manifest = match read_manifest(&manifest_path).await {
        Ok(Some(m)) => m,
        Ok(None) => {
            emit_error_envelope(args.common.json, "manifest_invalid", "Invalid manifest".to_string());
            return 1;
        }
        Err(e) => {
            emit_error_envelope(args.common.json, "manifest_unreadable", e.to_string());
            return 1;
        }
    };

    // Find matching patches to show what will be removed
    let matching: Vec<(&String, &socket_patch_core::manifest::schema::PatchRecord)> =
        if args.identifier.starts_with("pkg:") {
            manifest
                .patches
                .iter()
                .filter(|(purl, _)| *purl == &args.identifier)
                .collect()
        } else {
            manifest
                .patches
                .iter()
                .filter(|(_, patch)| patch.uuid == args.identifier)
                .collect()
        };

    if matching.is_empty() {
        let msg = format!("No patch found matching identifier: {}", args.identifier);
        track_patch_remove_failed(&msg, api_token.as_deref(), org_slug.as_deref()).await;
        if args.common.json {
            let mut env = Envelope::new(Command::Remove);
            env.status = Status::NotFound;
            env.error = Some(EnvelopeError::new("not_found", msg));
            println!("{}", env.to_pretty_json());
        } else {
            eprintln!(
                "No patch found matching identifier: {}",
                args.identifier
            );
        }
        return 1;
    }

    // Show what will be removed and confirm
    if !args.common.json {
        eprintln!("The following patch(es) will be removed:");
        for (purl, patch) in &matching {
            let file_count = patch.files.len();
            eprintln!("  - {} (UUID: {}, {} file(s))", purl, &patch.uuid[..8], file_count);
        }
        eprintln!();
    }

    let prompt = format!(
        "Remove {} patch(es) and rollback files?",
        matching.len()
    );
    if !confirm(&prompt, true, args.common.yes, args.common.json) {
        if !args.common.json {
            println!("Removal cancelled.");
        }
        return 0;
    }

    // First, rollback the patch if not skipped
    let mut rollback_count = 0;
    if !args.skip_rollback {
        if !args.common.json {
            println!("Rolling back patch before removal...");
        }
        match rollback_patches(
            &args.common.cwd,
            &manifest_path,
            Some(&args.identifier),
            false,
            args.common.json, // silent when JSON
            false,
            args.common.global,
            args.common.global_prefix.clone(),
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
                    emit_error_envelope(
                        args.common.json,
                        "rollback_failed",
                        "Rollback failed during patch removal. Use --skip-rollback to remove from manifest without restoring files.".to_string(),
                    );
                    return 1;
                }

                rollback_count = results
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

                if !args.common.json {
                    if rollback_count > 0 {
                        println!("Rolled back {rollback_count} package(s)");
                    }
                    if already_original > 0 {
                        println!("{already_original} package(s) already in original state");
                    }
                    if results.is_empty() {
                        println!("No packages found to rollback (not installed)");
                    }
                    println!();
                }
            }
            Err(e) => {
                track_patch_remove_failed(&e, api_token.as_deref(), org_slug.as_deref()).await;
                emit_error_envelope(
                    args.common.json,
                    "rollback_failed",
                    format!("Error during rollback: {e}. Use --skip-rollback to remove from manifest without restoring files."),
                );
                return 1;
            }
        }
    }

    // Now remove from manifest
    match remove_patch_from_manifest(&args.identifier, &manifest_path).await {
        Ok((removed, manifest)) => {
            if removed.is_empty() {
                let msg = format!("No patch found matching identifier: {}", args.identifier);
                track_patch_remove_failed(&msg, api_token.as_deref(), org_slug.as_deref()).await;
                if args.common.json {
                    let mut env = Envelope::new(Command::Remove);
                    env.status = Status::NotFound;
                    env.error = Some(EnvelopeError::new("not_found", msg));
                    println!("{}", env.to_pretty_json());
                } else {
                    eprintln!(
                        "No patch found matching identifier: {}",
                        args.identifier
                    );
                }
                return 1;
            }

            if !args.common.json {
                println!("Removed {} patch(es) from manifest:", removed.len());
                for purl in &removed {
                    println!("  - {purl}");
                }
                println!("\nManifest updated at {}", manifest_path.display());
            }

            // Clean up unused blobs
            let socket_dir = manifest_path.parent().unwrap();
            let blobs_path = socket_dir.join("blobs");
            let mut blobs_removed = 0;
            if let Ok(cleanup_result) = cleanup_unused_blobs(&manifest, &blobs_path, false).await {
                blobs_removed = cleanup_result.blobs_removed;
                if !args.common.json && cleanup_result.blobs_removed > 0 {
                    println!("\n{}", format_cleanup_result(&cleanup_result, false));
                }
            }

            if args.common.json {
                let mut env = Envelope::new(Command::Remove);
                if lock_was_broken {
                    env.record(lock_broken_event(socket_dir));
                }
                // One Removed event per purl whose manifest entry was deleted.
                for purl in &removed {
                    env.record(PatchEvent::new(PatchAction::Removed, purl.clone()));
                }
                // One artifact-level Removed event covering swept blobs.
                if blobs_removed > 0 {
                    env.record(
                        PatchEvent::artifact(PatchAction::Removed).with_details(serde_json::json!({
                            "blobsRemoved": blobs_removed,
                            "rolledBack": rollback_count,
                        })),
                    );
                }
                println!("{}", env.to_pretty_json());
            }

            track_patch_removed(removed.len(), api_token.as_deref(), org_slug.as_deref()).await;
            0
        }
        Err(e) => {
            track_patch_remove_failed(&e, api_token.as_deref(), org_slug.as_deref()).await;
            emit_error_envelope(args.common.json, "remove_failed", e);
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
