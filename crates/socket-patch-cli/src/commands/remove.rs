use clap::Args;
use socket_patch_core::api::client::get_api_client_with_overrides;
use socket_patch_core::manifest::operations::{read_manifest, write_manifest};
use socket_patch_core::manifest::schema::PatchManifest;
use socket_patch_core::utils::cleanup_blobs::{cleanup_unused_blobs, format_cleanup_result};
use socket_patch_core::utils::purl::purl_matches_identifier;
use socket_patch_core::utils::telemetry::{track_patch_remove_failed, track_patch_removed};
use std::path::Path;
use std::time::Duration;

use super::rollback::{all_files_already_original, rollback_patches};
use crate::args::{apply_env_toggles, GlobalArgs};
use crate::commands::lock_cli::{acquire_or_emit, lock_broken_event};
use crate::json_envelope::{Command, Envelope, EnvelopeError, PatchAction, PatchEvent, Status};
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
    #[arg(
        long = "skip-rollback",
        env = "SOCKET_SKIP_ROLLBACK",
        default_value_t = false
    )]
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
        args.common.silent,
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
            emit_error_envelope(
                args.common.json,
                "manifest_invalid",
                "Invalid manifest".to_string(),
            );
            return 1;
        }
        Err(e) => {
            emit_error_envelope(args.common.json, "manifest_unreadable", e.to_string());
            return 1;
        }
    };

    // Find matching patches to show what will be removed. A base PURL
    // (no `?`) matches every release variant of that package@version; a
    // qualified PURL or a UUID targets a single patch.
    let matching: Vec<(&String, &socket_patch_core::manifest::schema::PatchRecord)> =
        if args.identifier.starts_with("pkg:") {
            manifest
                .patches
                .iter()
                .filter(|(purl, _)| purl_matches_identifier(purl, &args.identifier))
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
            eprintln!("No patch found matching identifier: {}", args.identifier);
        }
        return 1;
    }

    // Show what will be removed and confirm. When a base PURL expanded
    // to multiple manifest entries (PyPI release variants), make the
    // blast radius explicit so the user understands why a single
    // `remove pkg:pypi/foo@1.0` is removing several variants.
    if !args.common.json && !args.common.silent {
        if args.identifier.starts_with("pkg:")
            && !args.identifier.contains('?')
            && matching.len() > 1
        {
            eprintln!(
                "{} matches {} release variant(s) — all will be removed:",
                args.identifier,
                matching.len()
            );
        } else {
            eprintln!("The following patch(es) will be removed:");
        }
        for (purl, patch) in &matching {
            let file_count = patch.files.len();
            // Short-UUID for display only. Slice on a char boundary and
            // tolerate UUIDs shorter than 8 chars — a malformed manifest
            // must not panic the whole command in the display path.
            let short_uuid = patch.uuid.get(..8).unwrap_or(patch.uuid.as_str());
            eprintln!(
                "  - {} (UUID: {}, {} file(s))",
                purl, short_uuid, file_count
            );
        }
        eprintln!();
    }

    let prompt = format!("Remove {} patch(es) and rollback files?", matching.len());
    if !confirm(&prompt, true, args.common.yes, args.common.json) {
        if !args.common.json && !args.common.silent {
            println!("Removal cancelled.");
        }
        return 0;
    }

    // First, rollback the patch if not skipped
    let mut rollback_count = 0;
    if !args.skip_rollback {
        if !args.common.json && !args.common.silent {
            println!("Rolling back patch before removal...");
        }
        match rollback_patches(
            &args.common.cwd,
            &manifest_path,
            Some(&args.identifier),
            false,
            args.common.json || args.common.silent,
            args.common.offline,
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
                // Reuse rollback's canonical predicate rather than
                // re-deriving it: the `!files_verified.is_empty()` guard
                // inside `all_files_already_original` is essential —
                // `Iterator::all` over an empty slice is vacuously `true`,
                // so a zero-file (or not-installed) result would otherwise
                // be miscounted as "already in original state".
                let already_original = results
                    .iter()
                    .filter(|r| r.success && all_files_already_original(r))
                    .count();

                if !args.common.json && !args.common.silent {
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
                    eprintln!("No patch found matching identifier: {}", args.identifier);
                }
                return 1;
            }

            if !args.common.json && !args.common.silent {
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
                if !args.common.json && !args.common.silent && cleanup_result.blobs_removed > 0 {
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
                // One artifact-level Removed event carrying the
                // blob-sweep and rollback counts. Emitted whenever either
                // is non-zero so the `rolledBack` count is still reported
                // even when no blobs happened to be swept (e.g. the removed
                // patch's afterHash blobs are still referenced elsewhere).
                //
                // Pushed directly rather than via `env.record`: this is a
                // purl-less metadata carrier, not a removed manifest entry.
                // The per-purl events above are the authoritative
                // patch-removal count, so `summary.removed` must equal the
                // number of entries deleted (`removed.len()`) — letting this
                // carrier bump `removed` too would double-count, reporting
                // e.g. `removed: 2` for a single-patch removal that happened
                // to sweep an orphan blob. Consumers read the blob/rollback
                // totals from `details`, never from `summary.removed`.
                if blobs_removed > 0 || rollback_count > 0 {
                    env.events
                        .push(PatchEvent::artifact(PatchAction::Removed).with_details(
                            serde_json::json!({
                                "blobsRemoved": blobs_removed,
                                "rolledBack": rollback_count,
                            }),
                        ));
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

    let purls_to_remove: Vec<String> = if identifier.starts_with("pkg:") {
        // Base PURL removes every release variant; qualified PURL removes one.
        manifest
            .patches
            .keys()
            .filter(|purl| purl_matches_identifier(purl, identifier))
            .cloned()
            .collect()
    } else {
        manifest
            .patches
            .iter()
            .filter(|(_, patch)| patch.uuid == identifier)
            .map(|(purl, _)| purl.clone())
            .collect()
    };

    for purl in purls_to_remove {
        manifest.patches.remove(&purl);
        removed.push(purl);
    }

    if !removed.is_empty() {
        write_manifest(manifest_path, &manifest)
            .await
            .map_err(|e| e.to_string())?;
    }

    Ok((removed, manifest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use socket_patch_core::manifest::schema::PatchRecord;
    use std::collections::HashMap;

    fn make_record(uuid: &str) -> PatchRecord {
        PatchRecord {
            uuid: uuid.to_string(),
            exported_at: "2024-01-01T00:00:00Z".to_string(),
            files: HashMap::new(),
            vulnerabilities: HashMap::new(),
            description: "test".to_string(),
            license: "MIT".to_string(),
            tier: "free".to_string(),
        }
    }

    /// Write a manifest with three PyPI release variants of one
    /// package@version plus an unrelated npm package, returning the
    /// temp dir (kept alive) and the manifest path.
    async fn write_multi_variant(dir: &Path) {
        let mut patches = HashMap::new();
        patches.insert(
            "pkg:pypi/six@1.16.0?artifact_id=wheel-cp311".to_string(),
            make_record("uuid-cp311"),
        );
        patches.insert(
            "pkg:pypi/six@1.16.0?artifact_id=sdist".to_string(),
            make_record("uuid-sdist"),
        );
        patches.insert(
            "pkg:pypi/six@1.16.0?artifact_id=wheel-cp312".to_string(),
            make_record("uuid-cp312"),
        );
        patches.insert("pkg:npm/foo@1.0".to_string(), make_record("uuid-foo"));
        let manifest = PatchManifest {
            patches,
            setup: None,
        };
        write_manifest(&dir.join("manifest.json"), &manifest)
            .await
            .expect("write manifest");
    }

    #[tokio::test]
    async fn remove_base_purl_removes_all_variants() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write_multi_variant(tmp.path()).await;
        let manifest_path = tmp.path().join("manifest.json");

        let (removed, manifest) = remove_patch_from_manifest("pkg:pypi/six@1.16.0", &manifest_path)
            .await
            .expect("remove ok");

        // All three release variants removed; the npm package untouched.
        assert_eq!(removed.len(), 3);
        assert!(removed.iter().all(|p| p.contains("six@1.16.0")));
        assert_eq!(manifest.patches.len(), 1);
        assert!(manifest.patches.contains_key("pkg:npm/foo@1.0"));
    }

    #[tokio::test]
    async fn remove_qualified_purl_removes_single_variant() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write_multi_variant(tmp.path()).await;
        let manifest_path = tmp.path().join("manifest.json");

        let (removed, manifest) =
            remove_patch_from_manifest("pkg:pypi/six@1.16.0?artifact_id=sdist", &manifest_path)
                .await
                .expect("remove ok");

        // Only the sdist variant removed; the two wheels + npm remain.
        assert_eq!(removed, vec!["pkg:pypi/six@1.16.0?artifact_id=sdist"]);
        assert_eq!(manifest.patches.len(), 3);
        assert!(!manifest
            .patches
            .contains_key("pkg:pypi/six@1.16.0?artifact_id=sdist"));
    }

    #[tokio::test]
    async fn remove_by_uuid_removes_single_variant() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write_multi_variant(tmp.path()).await;
        let manifest_path = tmp.path().join("manifest.json");

        let (removed, manifest) = remove_patch_from_manifest("uuid-cp312", &manifest_path)
            .await
            .expect("remove ok");

        assert_eq!(removed, vec!["pkg:pypi/six@1.16.0?artifact_id=wheel-cp312"]);
        assert_eq!(manifest.patches.len(), 3);
    }

    /// A plain (qualifier-free) npm PURL removes exactly its own entry and
    /// must not accidentally match same-prefix neighbours like
    /// `foobar@1.0`. Guards the `strip_purl_qualifiers == identifier`
    /// exact-equality path for non-PyPI keys.
    #[tokio::test]
    async fn remove_npm_purl_is_exact_and_does_not_prefix_match() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut patches = HashMap::new();
        patches.insert("pkg:npm/foo@1.0".to_string(), make_record("uuid-foo"));
        patches.insert("pkg:npm/foobar@1.0".to_string(), make_record("uuid-foobar"));
        let manifest = PatchManifest {
            patches,
            setup: None,
        };
        let manifest_path = tmp.path().join("manifest.json");
        write_manifest(&manifest_path, &manifest)
            .await
            .expect("write manifest");

        let (removed, manifest) = remove_patch_from_manifest("pkg:npm/foo@1.0", &manifest_path)
            .await
            .expect("remove ok");

        assert_eq!(removed, vec!["pkg:npm/foo@1.0"]);
        assert_eq!(manifest.patches.len(), 1);
        assert!(manifest.patches.contains_key("pkg:npm/foobar@1.0"));
    }

    /// An identifier that matches nothing removes nothing and — crucially
    /// — must NOT rewrite the manifest file. We assert byte-identity of
    /// the on-disk manifest before/after so a future change that always
    /// re-serializes (churning mtime / formatting) is caught.
    #[tokio::test]
    async fn remove_no_match_leaves_manifest_file_untouched() {
        let tmp = tempfile::tempdir().expect("tempdir");
        write_multi_variant(tmp.path()).await;
        let manifest_path = tmp.path().join("manifest.json");
        let before_bytes = tokio::fs::read(&manifest_path).await.expect("read before");

        let (removed, manifest) =
            remove_patch_from_manifest("pkg:npm/not-here@9.9.9", &manifest_path)
                .await
                .expect("remove ok");

        assert!(removed.is_empty(), "nothing should match");
        assert_eq!(manifest.patches.len(), 4, "manifest left intact");
        let after_bytes = tokio::fs::read(&manifest_path).await.expect("read after");
        assert_eq!(
            before_bytes, after_bytes,
            "a no-op remove must not rewrite the manifest file"
        );
    }

    /// A base PURL must not bleed across versions: removing `six@1.16.0`
    /// leaves `six@1.17.0` (and its variants) in place.
    #[tokio::test]
    async fn remove_base_purl_does_not_touch_other_versions() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut patches = HashMap::new();
        patches.insert(
            "pkg:pypi/six@1.16.0?artifact_id=sdist".to_string(),
            make_record("uuid-16-sdist"),
        );
        patches.insert(
            "pkg:pypi/six@1.17.0?artifact_id=sdist".to_string(),
            make_record("uuid-17-sdist"),
        );
        let manifest = PatchManifest {
            patches,
            setup: None,
        };
        let manifest_path = tmp.path().join("manifest.json");
        write_manifest(&manifest_path, &manifest)
            .await
            .expect("write manifest");

        let (removed, manifest) = remove_patch_from_manifest("pkg:pypi/six@1.16.0", &manifest_path)
            .await
            .expect("remove ok");

        assert_eq!(removed, vec!["pkg:pypi/six@1.16.0?artifact_id=sdist"]);
        assert_eq!(manifest.patches.len(), 1);
        assert!(manifest
            .patches
            .contains_key("pkg:pypi/six@1.17.0?artifact_id=sdist"));
    }
}
