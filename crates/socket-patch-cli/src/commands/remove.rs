use clap::Args;
use socket_patch_core::api::client::get_api_client_with_overrides;
use socket_patch_core::manifest::operations::{read_manifest, write_manifest};
use socket_patch_core::manifest::schema::PatchManifest;
use socket_patch_core::patch::vendor::{load_state, save_state, VendorEntry, VendorState};
use socket_patch_core::utils::cleanup_blobs::{cleanup_unused_blobs, format_cleanup_result};
use socket_patch_core::utils::purl::purl_matches_identifier;
use socket_patch_core::utils::telemetry::{track_patch_remove_failed, track_patch_removed};
use std::path::Path;
use std::time::Duration;

use super::get::short_uuid;
use super::rollback::{all_files_already_original, rollback_patches};
use super::vendor::dispatch_revert_one;
use crate::args::{apply_env_toggles, GlobalArgs};
use crate::commands::lock_cli::{acquire_or_emit, lock_broken_event};
use crate::json_envelope::{Command, Envelope, EnvelopeError, PatchAction, PatchEvent, Status};
use crate::output::confirm;

/// A remove/rollback identifier matches a patch by PURL for `pkg:`
/// identifiers (a base PURL matches every release variant of that
/// package@version; a qualified PURL targets a single patch), or by patch
/// uuid otherwise.
pub(crate) fn patch_matches(purl: &str, uuid: &str, identifier: &str) -> bool {
    if identifier.starts_with("pkg:") {
        purl_matches_identifier(purl, identifier)
    } else {
        uuid == identifier
    }
}

/// Vendor-ledger entries matching a remove identifier: by ledger key or
/// base purl (mirroring the manifest matching). Sorted by key for
/// deterministic event order.
fn vendor_entries_matching(state: &VendorState, identifier: &str) -> Vec<(String, VendorEntry)> {
    let mut matches: Vec<(String, VendorEntry)> = state
        .entries
        .iter()
        .filter(|(key, entry)| {
            patch_matches(key, &entry.uuid, identifier)
                || patch_matches(&entry.base_purl, &entry.uuid, identifier)
        })
        .map(|(k, e)| (k.clone(), e.clone()))
        .collect();
    matches.sort_by(|a, b| a.0.cmp(&b.0));
    matches
}

/// Emit the `not_found` envelope (or stderr line) for an identifier that
/// matched nothing, tracking the failure. Both the pre-flight match and
/// the post-rollback manifest mutation share this exit path. `dry_run`
/// rides the envelope so a preview's failures still report `dryRun: true`
/// (matching apply's error envelopes and remove's own success envelope).
async fn emit_not_found(
    json: bool,
    dry_run: bool,
    identifier: &str,
    api_token: Option<&str>,
    org_slug: Option<&str>,
) {
    let msg = format!("No patch found matching identifier: {identifier}");
    track_patch_remove_failed(&msg, api_token, org_slug).await;
    if json {
        let mut env = Envelope::new(Command::Remove);
        env.dry_run = dry_run;
        env.status = Status::NotFound;
        env.error = Some(EnvelopeError::new("not_found", msg));
        println!("{}", env.to_pretty_json());
    } else {
        eprintln!("{msg}");
    }
}

/// Emit a `remove` error envelope and return. Used by the many error
/// paths in `run` so they all share the same JSON shape. `dry_run` rides
/// the envelope so preview failures report `dryRun: true`.
fn emit_error_envelope(json: bool, dry_run: bool, code: &str, message: String) {
    if json {
        let mut env = Envelope::new(Command::Remove);
        env.dry_run = dry_run;
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
    ///
    /// `value_parser = parse_bool_flag` matches the `GlobalArgs` bool flags:
    /// clap's default bool parser accepts only the literal strings
    /// `true`/`false` from the env binding, so `SOCKET_SKIP_ROLLBACK=1` (or
    /// an exported-but-empty `SOCKET_SKIP_ROLLBACK=`) aborted every
    /// `remove` invocation.
    #[arg(
        long = "skip-rollback",
        env = "SOCKET_SKIP_ROLLBACK",
        default_value_t = false,
        value_parser = crate::args::parse_bool_flag,
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

    let manifest_missing = tokio::fs::metadata(&manifest_path).await.is_err();
    if manifest_missing {
        // A pure-detached project (`scan --vendor --detached`) has a
        // vendor ledger but deliberately no manifest, and `remove` is the
        // per-purl exit path for its entries — so a missing manifest is
        // only fatal when the ledger has no detached match either. An
        // unreadable ledger falls through to the error: nothing is
        // mutated on that path.
        let has_detached_match = load_state(&args.common.cwd)
            .await
            .map(|s| {
                vendor_entries_matching(&s, &args.identifier)
                    .iter()
                    .any(|(_, e)| e.detached)
            })
            .unwrap_or(false);
        if !has_detached_match {
            emit_error_envelope(
                args.common.json,
                args.common.dry_run,
                "manifest_not_found",
                format!("Manifest not found at {}", manifest_path.display()),
            );
            return 1;
        }
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
        args.common.dry_run,
        Duration::from_secs(args.common.lock_timeout.unwrap_or(0)),
        args.common.break_lock,
    ) {
        Ok(acquired) => acquired,
        Err(code) => return code,
    };
    let _lock = acquired.guard;
    let lock_was_broken = acquired.broke_lock;

    // Read manifest to show what will be removed and confirm. On the
    // pure-detached path there is no manifest to read or mutate; an empty
    // view routes the flow to the detached-only removal below.
    let manifest = if manifest_missing {
        PatchManifest::new()
    } else {
        match read_manifest(&manifest_path).await {
            Ok(Some(m)) => m,
            Ok(None) => {
                emit_error_envelope(
                    args.common.json,
                    args.common.dry_run,
                    "manifest_invalid",
                    "Invalid manifest".to_string(),
                );
                return 1;
            }
            Err(e) => {
                emit_error_envelope(
                    args.common.json,
                    args.common.dry_run,
                    "manifest_unreadable",
                    e.to_string(),
                );
                return 1;
            }
        }
    };

    // Find matching patches to show what will be removed.
    let matching: Vec<_> = manifest
        .patches
        .iter()
        .filter(|(purl, patch)| patch_matches(purl, &patch.uuid, &args.identifier))
        .collect();

    if matching.is_empty() {
        // Detached vendored patches (`scan --vendor --detached`) have no
        // manifest entry — `remove` is their per-purl exit path (alongside
        // `vendor --revert`'s all-at-once). An unreadable ledger falls
        // through to `not_found`: nothing is mutated on that path.
        let detached_state = load_state(&args.common.cwd).await.unwrap_or_default();
        let detached: Vec<(String, VendorEntry)> =
            vendor_entries_matching(&detached_state, &args.identifier)
                .into_iter()
                .filter(|(_, e)| e.detached)
                .collect();
        if !detached.is_empty() {
            return remove_detached_only(
                &args,
                detached,
                detached_state,
                lock_was_broken,
                socket_dir,
                api_token.as_deref(),
                org_slug.as_deref(),
            )
            .await;
        }

        emit_not_found(
            args.common.json,
            args.common.dry_run,
            &args.identifier,
            api_token.as_deref(),
            org_slug.as_deref(),
        )
        .await;
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
            eprintln!(
                "  - {} (UUID: {}, {} file(s))",
                purl,
                short_uuid(&patch.uuid),
                patch.files.len()
            );
        }
        eprintln!();
    }

    // `--dry-run` previews without mutating, so there is nothing to
    // confirm — skip the prompt (matching the global contract row:
    // "Preview, no mutations").
    let prompt = format!("Remove {} patch(es) and rollback files?", matching.len());
    if !args.common.dry_run && !confirm(&prompt, true, args.common.yes, args.common.json) {
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
            &args.common,
            &manifest_path,
            Some(&args.identifier),
            args.common.dry_run,
            args.common.json || args.common.silent,
            None,
        )
        .await
        {
            Ok((success, results, _vendored_skipped)) => {
                if !success {
                    track_patch_remove_failed(
                        "Rollback failed during patch removal",
                        api_token.as_deref(),
                        org_slug.as_deref(),
                    )
                    .await;
                    emit_error_envelope(
        args.common.json,
        args.common.dry_run,
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
        args.common.dry_run,
                    "rollback_failed",
                    format!("Error during rollback: {e}. Use --skip-rollback to remove from manifest without restoring files."),
                );
                return 1;
            }
        }
    }

    // Vendor-owned purls: removing the patch means reverting the vendoring
    // (restore the recorded lockfile fragments, delete the artifact, drop
    // the ledger entry) — otherwise the lockfile keeps consuming the
    // patched artifact after the manifest forgot the patch. Runs AFTER the
    // file rollback above (which benignly skips still-vendored purls and
    // must not see them dropped from the ledger — its before-blob gate
    // would demand blobs the vendor flow never downloaded) and BEFORE the
    // manifest mutation, so a revert failure aborts with the manifest
    // intact (mirroring the `rollback_failed` contract). A corrupt ledger
    // is a hard error: we are about to mutate and cannot know what we
    // would leave wired. `--skip-rollback` ("don't touch my tree") skips
    // the revert too — the wiring stays until the next `vendor` run
    // reconciles the then-dropped entry.
    let mut vendor_state = match load_state(&args.common.cwd).await {
        Ok(s) => s,
        Err(e) => {
            emit_error_envelope(
                args.common.json,
                args.common.dry_run,
                "vendor_state_unreadable",
                format!("cannot read .socket/vendor/state.json: {e}"),
            );
            return 1;
        }
    };
    let vendored_matches = vendor_entries_matching(&vendor_state, &args.identifier);
    // Reverted entries ride the final envelope as Removed/vendor_reverted
    // events WITHOUT bumping summary.removed (that count stays "manifest
    // entries deleted", same as the blob-sweep carrier). Retained/warning
    // events are Skipped and bump normally.
    let mut vendor_reverted_events: Vec<PatchEvent> = Vec::new();
    let mut vendor_skipped_events: Vec<PatchEvent> = Vec::new();
    if !vendored_matches.is_empty() {
        if args.skip_rollback {
            for (key, _) in &vendored_matches {
                if !args.common.json && !args.common.silent {
                    eprintln!(
                        "Note: {key} is vendored; --skip-rollback leaves the vendor wiring and \
                         artifact in place (the next `vendor` run will reconcile-revert it)."
                    );
                }
                vendor_skipped_events.push(
                    PatchEvent::new(PatchAction::Skipped, key.clone()).with_reason(
                        "vendor_state_retained",
                        "vendor wiring and artifact left in place (--skip-rollback)",
                    ),
                );
            }
        } else {
            for (key, entry) in &vendored_matches {
                let outcome =
                    dispatch_revert_one(entry, &args.common.cwd, args.common.dry_run).await;
                for w in &outcome.warnings {
                    if !args.common.json && !args.common.silent {
                        eprintln!("Warning ({}): {}", w.code, w.detail);
                    }
                    vendor_skipped_events.push(
                        PatchEvent::new(PatchAction::Skipped, key.clone())
                            .with_reason(w.code, w.detail.clone()),
                    );
                }
                if !outcome.success {
                    track_patch_remove_failed(
                        "vendor revert failed during patch removal",
                        api_token.as_deref(),
                        org_slug.as_deref(),
                    )
                    .await;
                    emit_error_envelope(
                        args.common.json,
                        args.common.dry_run,
                        "vendor_revert_failed",
                        format!(
                            "could not revert vendoring for {key}: {}. The manifest was not \
                             modified.",
                            outcome.error.as_deref().unwrap_or("unknown error")
                        ),
                    );
                    return 1;
                }
                if args.common.dry_run {
                    if !args.common.json && !args.common.silent {
                        println!("Would revert vendoring for {key}");
                    }
                    // Dry-run flips the would-be Removed to a Verified
                    // preview, same convention as apply/vendor/repair.
                    vendor_reverted_events.push(
                        PatchEvent::new(PatchAction::Verified, key.clone()).with_reason(
                            "vendor_would_revert",
                            "vendoring would be reverted on remove",
                        ),
                    );
                    continue;
                }
                vendor_state.entries.remove(key);
                if let Err(e) = save_state(&args.common.cwd, &vendor_state).await {
                    emit_error_envelope(
                        args.common.json,
                        args.common.dry_run,
                        "vendor_state_write_failed",
                        e.to_string(),
                    );
                    return 1;
                }
                if !args.common.json && !args.common.silent {
                    println!("Reverted vendoring for {key}");
                }
                vendor_reverted_events.push(
                    PatchEvent::new(PatchAction::Removed, key.clone())
                        .with_reason("vendor_reverted", "vendoring reverted on remove"),
                );
            }
        }
    }

    // Now remove from manifest. On --dry-run the removal is simulated in
    // memory (manifest untouched) so the blob sweep below can still
    // preview against the post-removal reference set.
    let removal = if args.common.dry_run {
        let removed: Vec<String> = matching.iter().map(|(purl, _)| (*purl).clone()).collect();
        let mut simulated = manifest.clone();
        simulated.patches.retain(|purl, _| !removed.contains(purl));
        Ok((removed, simulated))
    } else {
        remove_patch_from_manifest(&args.identifier, &manifest_path).await
    };
    match removal {
        Ok((removed, manifest)) => {
            if removed.is_empty() {
                emit_not_found(
                    args.common.json,
                    args.common.dry_run,
                    &args.identifier,
                    api_token.as_deref(),
                    org_slug.as_deref(),
                )
                .await;
                return 1;
            }

            if !args.common.json && !args.common.silent {
                if args.common.dry_run {
                    println!("Would remove {} patch(es) from manifest:", removed.len());
                } else {
                    println!("Removed {} patch(es) from manifest:", removed.len());
                }
                for purl in &removed {
                    println!("  - {purl}");
                }
                if args.common.dry_run {
                    println!("\nDry run — nothing was changed.");
                } else {
                    println!("\nManifest updated at {}", manifest_path.display());
                }
            }

            // Clean up unused blobs (previewed, not deleted, on --dry-run).
            let blobs_path = socket_dir.join("blobs");
            let mut blobs_removed = 0;
            if let Ok(cleanup_result) =
                cleanup_unused_blobs(&manifest, &blobs_path, args.common.dry_run).await
            {
                blobs_removed = cleanup_result.blobs_removed;
                if !args.common.json && !args.common.silent && cleanup_result.blobs_removed > 0 {
                    println!(
                        "\n{}",
                        format_cleanup_result(&cleanup_result, args.common.dry_run)
                    );
                }
            }

            if args.common.json {
                let mut env = Envelope::new(Command::Remove);
                env.dry_run = args.common.dry_run;
                // Dry-run flips would-be Removed events to Verified
                // previews (the apply/vendor/repair convention), so
                // `summary.removed` stays "manifest entries actually
                // deleted" — zero on a preview.
                let removal_action = if args.common.dry_run {
                    PatchAction::Verified
                } else {
                    PatchAction::Removed
                };
                if lock_was_broken {
                    env.record(lock_broken_event(socket_dir));
                }
                // Chronological: the vendor revert ran before the rollback
                // and the manifest mutation. Reverted events bypass
                // `record` so `summary.removed` stays equal to the number
                // of manifest entries deleted (same rule as the blob-sweep
                // carrier below); retained/warning Skipped events bump
                // `summary.skipped` normally.
                for ev in vendor_reverted_events {
                    env.events.push(ev);
                }
                for ev in vendor_skipped_events {
                    env.record(ev);
                }
                // One Removed event per purl whose manifest entry was
                // deleted (Verified on --dry-run).
                for purl in &removed {
                    env.record(PatchEvent::new(removal_action, purl.clone()));
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
                        .push(PatchEvent::artifact(removal_action).with_details(
                            serde_json::json!({
                                "blobsRemoved": blobs_removed,
                                "rolledBack": rollback_count,
                            }),
                        ));
                }
                println!("{}", env.to_pretty_json());
            }

            if !args.common.dry_run {
                track_patch_removed(removed.len(), api_token.as_deref(), org_slug.as_deref()).await;
            }
            0
        }
        Err(e) => {
            track_patch_remove_failed(&e, api_token.as_deref(), org_slug.as_deref()).await;
            emit_error_envelope(args.common.json, args.common.dry_run, "remove_failed", e);
            1
        }
    }
}

/// Remove path for identifiers that match ONLY detached vendored entries
/// (no manifest record): confirm, revert each entry's wiring + artifact,
/// drop it from the ledger, and report `Removed`/`vendor_reverted` events.
/// Unlike the manifest path, the reverts here ARE the removal, so they go
/// through `env.record` and bump `summary.removed`. `--skip-rollback` is
/// refused: with no manifest entry to delete, removing a detached patch
/// can only mean reverting its vendoring.
async fn remove_detached_only(
    args: &RemoveArgs,
    detached: Vec<(String, VendorEntry)>,
    mut state: VendorState,
    lock_was_broken: bool,
    socket_dir: &Path,
    api_token: Option<&str>,
    org_slug: Option<&str>,
) -> i32 {
    if args.skip_rollback {
        emit_error_envelope(
            args.common.json,
            args.common.dry_run,
            "vendor_state_retained",
            format!(
                "{} matches only detached vendored patch(es); removing one means reverting \
                 its vendoring, which --skip-rollback prevents",
                args.identifier
            ),
        );
        return 1;
    }

    if !args.common.json && !args.common.silent {
        eprintln!("The following detached vendored patch(es) will be reverted and removed:");
        for (key, entry) in &detached {
            eprintln!("  - {key} (UUID: {})", short_uuid(&entry.uuid));
        }
        eprintln!();
    }
    // `--dry-run` previews without mutating — nothing to confirm.
    let prompt = format!(
        "Remove {} vendored patch(es) and revert their vendoring?",
        detached.len()
    );
    if !args.common.dry_run && !confirm(&prompt, true, args.common.yes, args.common.json) {
        if !args.common.json {
            println!("Removal cancelled.");
        }
        return 0;
    }

    let mut env = Envelope::new(Command::Remove);
    env.dry_run = args.common.dry_run;
    if lock_was_broken {
        env.record(lock_broken_event(socket_dir));
    }
    for (key, entry) in &detached {
        let outcome = dispatch_revert_one(entry, &args.common.cwd, args.common.dry_run).await;
        for w in &outcome.warnings {
            if !args.common.json && !args.common.silent {
                eprintln!("Warning ({}): {}", w.code, w.detail);
            }
            env.record(
                PatchEvent::new(PatchAction::Skipped, key.clone())
                    .with_reason(w.code, w.detail.clone()),
            );
        }
        if !outcome.success {
            track_patch_remove_failed(
                "vendor revert failed during patch removal",
                api_token,
                org_slug,
            )
            .await;
            emit_error_envelope(
                args.common.json,
                args.common.dry_run,
                "vendor_revert_failed",
                format!(
                    "could not revert vendoring for {key}: {}",
                    outcome.error.as_deref().unwrap_or("unknown error")
                ),
            );
            return 1;
        }
        if args.common.dry_run {
            if !args.common.json && !args.common.silent {
                println!("Would revert vendoring for {key}");
            }
            // Verified preview (the dry-run convention); still recorded
            // so `summary.verified` counts the would-be removals.
            env.record(
                PatchEvent::new(PatchAction::Verified, key.clone()).with_reason(
                    "vendor_would_revert",
                    "vendoring would be reverted on remove",
                ),
            );
            continue;
        }
        state.entries.remove(key);
        if let Err(e) = save_state(&args.common.cwd, &state).await {
            emit_error_envelope(
                args.common.json,
                args.common.dry_run,
                "vendor_state_write_failed",
                e.to_string(),
            );
            return 1;
        }
        if !args.common.json && !args.common.silent {
            println!("Reverted vendoring for {key}");
        }
        env.record(
            PatchEvent::new(PatchAction::Removed, key.clone())
                .with_reason("vendor_reverted", "vendoring reverted on remove"),
        );
    }
    if args.common.json {
        println!("{}", env.to_pretty_json());
    }
    if !args.common.dry_run {
        track_patch_removed(detached.len(), api_token, org_slug).await;
    }
    0
}

async fn remove_patch_from_manifest(
    identifier: &str,
    manifest_path: &Path,
) -> Result<(Vec<String>, PatchManifest), String> {
    let mut manifest = read_manifest(manifest_path)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "Invalid manifest".to_string())?;

    let removed: Vec<String> = manifest
        .patches
        .iter()
        .filter(|(purl, patch)| patch_matches(purl, &patch.uuid, identifier))
        .map(|(purl, _)| purl.clone())
        .collect();

    for purl in &removed {
        manifest.patches.remove(purl);
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
