use clap::Args;
use socket_patch_core::api::client::get_api_client_with_overrides;
use socket_patch_core::manifest::cleanup_blobs::{
    cleanup_unused_archives, cleanup_unused_blobs, format_cleanup_result,
};
use socket_patch_core::manifest::operations::{read_manifest, write_manifest};
use socket_patch_core::manifest::schema::PatchManifest;
use socket_patch_core::telemetry::{track_patch_remove_failed, track_patch_removed};
use socket_patch_core::utils::purl::{purl_matches_identifier, strip_purl_qualifiers};
use socket_patch_core::vendor::{load_state, save_state, VendorEntry, VendorState};
use std::path::Path;
use std::time::Duration;

use super::get::short_uuid;
use super::rollback::{all_files_already_original, pin_before_hash_blobs, rollback_patches};
use super::vendor::{dispatch_revert_one, dispatch_revert_one_opts};
use crate::args::{apply_env_toggles, GlobalArgs};
use socket_patch_core::vendor::RevertOpts;
use crate::commands::lock_cli::acquire_or_emit;
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

    /// Restore the system (files and lockfiles) but PRESERVE the local
    /// patch state for a later re-apply: the manifest entry is kept,
    /// vendored artifacts and their ledger entries are kept (only the
    /// lockfile wiring is reverted), and no blob/archive cleanup runs —
    /// the single-patch twin of `rollback --preserve-state`. Conflicts
    /// with `--skip-rollback` (keeping the tree AND the state would be a
    /// no-op).
    #[arg(
        long = "preserve-state",
        env = "SOCKET_PRESERVE_STATE",
        default_value_t = false,
        value_parser = crate::args::parse_bool_flag,
    )]
    pub preserve_state: bool,
}

pub async fn run(args: RemoveArgs) -> i32 {
    apply_env_toggles(&args.common);

    // Self-enforced usage error (exit 2, like scan's mode conflicts):
    // `--skip-rollback` keeps the tree and drops the state,
    // `--preserve-state` restores the tree and keeps the state — together
    // they select the do-nothing quadrant.
    if args.preserve_state && args.skip_rollback {
        eprintln!(
            "error: --preserve-state cannot be used with --skip-rollback: the \
             combination would be a no-op (nothing would change)"
        );
        return 2;
    }

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
        // Hosted redirects likewise live outside the manifest (the
        // redirect ledger is the only persistence), so a hosted-only
        // project's `remove` proceeds manifest-less too.
        let has_hosted_match = socket_patch_core::patch::redirect::load_redirect_state(
            &args.common.cwd,
        )
        .await
        .ok()
        .flatten()
        .is_some_and(|st| {
            st.records
                .iter()
                .any(|(purl, rec)| patch_matches(purl, &rec.uuid, &args.identifier))
        });
        if !has_detached_match && !has_hosted_match {
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
    let _lock = match acquire_or_emit(
        socket_dir,
        Command::Remove,
        args.common.json,
        args.common.dry_run,
        Duration::from_secs(args.common.lock_timeout.unwrap_or(0)),
    ) {
        Ok(guard) => guard,
        Err(code) => return code,
    };

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
                // A manifest that exists but is unparseable (bad JSON or a
                // schema violation) surfaces as `ErrorKind::InvalidData` —
                // the contract's `manifest_invalid`. Everything else is a
                // genuine I/O failure (`manifest_unreadable`). See the
                // CLI_CONTRACT.md error-code table; `list` shares the split.
                let code = if e.kind() == std::io::ErrorKind::InvalidData {
                    "manifest_invalid"
                } else {
                    "manifest_unreadable"
                };
                emit_error_envelope(args.common.json, args.common.dry_run, code, e.to_string());
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
                api_token.as_deref(),
                org_slug.as_deref(),
            )
            .await;
        }

        // Hosted-only patches likewise have no manifest entry — the
        // redirect ledger is their only persistence, and `remove` is
        // their per-purl exit path (the unwind IS the removal). An
        // unreadable ledger falls through to `not_found`: nothing is
        // mutated on that path.
        if let Ok(Some(redirect_state)) =
            socket_patch_core::patch::redirect::load_redirect_state(&args.common.cwd).await
        {
            let mut hosted_matches: Vec<String> = redirect_state
                .records
                .iter()
                .filter(|(purl, rec)| patch_matches(purl, &rec.uuid, &args.identifier))
                .map(|(purl, _)| purl.clone())
                .collect();
            hosted_matches.sort();
            if !hosted_matches.is_empty() {
                return remove_hosted_only(
                    &args,
                    hosted_matches,
                    redirect_state,
                    api_token.as_deref(),
                    org_slug.as_deref(),
                )
                .await;
            }
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
    let prompt = if args.preserve_state {
        format!(
            "Rollback files for {} patch(es)? (patch records will be preserved)",
            matching.len()
        )
    } else {
        format!("Remove {} patch(es) and rollback files?", matching.len())
    };
    if !args.common.dry_run && !confirm(&prompt, true, args.common.yes, args.common.json) {
        if !args.common.json && !args.common.silent {
            println!("Removal cancelled.");
        }
        return 0;
    }

    // First, rollback the patch if not skipped
    let mut rollback_count = 0;
    // In-scope manifest entries the nested rollback SKIPPED because the
    // crawler found no installed package (`RollbackOutcome::not_installed`,
    // sorted). These were NOT reverted — and "not installed" can also mean
    // "installed but missed by the crawler" (layout gaps are a documented
    // reality), leaving patched bytes on disk. The removal below still
    // drops them from the manifest (the long-uninstalled contract), but
    // their beforeHash blobs are kept out of the cleanup sweep and a
    // warning event rides the envelope. Empty under `--skip-rollback`
    // (no rollback ran, so nothing is known — semantics unchanged).
    let mut rollback_not_installed: Vec<String> = Vec::new();
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
            Ok((success, results, _vendored_skipped, not_installed)) => {
                rollback_not_installed = not_installed;
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
    // Ledger keys whose revert drift-kept: their manifest entries are
    // EXCLUDED from the removal below (dropping a record whose vendored
    // state survives would hand `vendor`'s reconcile a revert with no
    // backing record).
    let mut vendor_kept_purls: std::collections::HashSet<String> =
        std::collections::HashSet::new();
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
                let outcome = dispatch_revert_one_opts(
                    entry,
                    &args.common.cwd,
                    RevertOpts {
                        dry_run: args.common.dry_run,
                        keep_artifact: args.preserve_state,
                    },
                )
                .await;
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
                if outcome.kept_artifact {
                    // Drift-keep: the lock changed under us and the backend
                    // left both the wiring and the artifact alone. Per the
                    // RevertOutcome contract the ledger entry stays — and so
                    // must the manifest entry, or `vendor`'s reconcile would
                    // re-revert an entry whose backing record is gone.
                    if !args.common.json && !args.common.silent {
                        eprintln!(
                            "Kept vendored state for {key}: lockfile wiring drifted; \
                             its manifest entry was kept too"
                        );
                    }
                    vendor_kept_purls.insert(key.clone());
                    vendor_skipped_events.push(
                        PatchEvent::new(PatchAction::Skipped, key.clone()).with_reason(
                            "vendor_revert_kept",
                            "lockfile wiring drifted; vendored state and manifest entry kept",
                        ),
                    );
                    continue;
                }
                if args.common.dry_run {
                    if !args.common.json && !args.common.silent {
                        if args.preserve_state {
                            println!("Would unwire vendoring for {key} (artifact preserved)");
                        } else {
                            println!("Would revert vendoring for {key}");
                        }
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
                if args.preserve_state {
                    // Entry kept byte-identical: its already-reverted wiring
                    // records replay as silent no-ops later (the liveness
                    // contract) and a re-vendor re-wires from the live lock.
                    if !args.common.json && !args.common.silent {
                        println!("Unwired vendoring for {key} (artifact preserved)");
                    }
                    vendor_skipped_events.push(
                        PatchEvent::new(PatchAction::Skipped, key.clone()).with_reason(
                            "vendor_state_preserved",
                            "lockfile unwired; artifact and ledger entry preserved \
                             (--preserve-state)",
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

    // Hosted-redirect leg: an identifier can also (or only) match hosted
    // records in the redirect ledger. Supported ecosystems (cargo,
    // npm-family) unwind per-purl; when the identifier covers EVERY record
    // the whole-ledger replay serves the rest; otherwise unsupported
    // targets fail closed BEFORE the manifest mutation. A corrupt ledger
    // skips the leg with a warning (the identifier may still match other
    // stores). `--skip-rollback` leaves hosted wiring untouched, like the
    // vendor wiring above; `--preserve-state` still unwinds — hosted has
    // no preservable local state.
    let mut hosted_reverted_events: Vec<PatchEvent> = Vec::new();
    if !args.skip_rollback {
        match socket_patch_core::patch::redirect::load_redirect_state(&args.common.cwd).await {
            Err(e) => {
                if !args.common.silent && !args.common.json {
                    eprintln!(
                        "Warning: cannot read the hosted redirect ledger ({e}); hosted \
                         redirects were not examined"
                    );
                }
            }
            Ok(None) => {}
            Ok(Some(mut redirect_state)) => {
                let mut hosted_matches: Vec<String> = redirect_state
                    .records
                    .iter()
                    .filter(|(purl, rec)| patch_matches(purl, &rec.uuid, &args.identifier))
                    .map(|(purl, _)| purl.clone())
                    .collect();
                hosted_matches.sort();
                if !hosted_matches.is_empty() {
                    let replay_eligible = redirect_state
                        .records
                        .keys()
                        .all(|p| hosted_matches.contains(p));
                    let before =
                        (redirect_state.edits.len(), redirect_state.records.len());
                    let leg = super::rollback::run_hosted_leg(
                        &args.common,
                        &hosted_matches,
                        &mut redirect_state,
                        replay_eligible,
                    )
                    .await;
                    // Persist FIRST, failure or not: per-purl reverts flush
                    // lockfile writes as they go, so an early error return
                    // without persisting would strand already-reverted
                    // purls' records in the on-disk ledger (lockfiles and
                    // ledger desynced; `list`/VEX attest dead wiring).
                    if !args.common.dry_run
                        && (redirect_state.edits.len(), redirect_state.records.len()) != before
                    {
                        if let Err(e) =
                            socket_patch_core::patch::redirect::persist_redirect_state(
                                &args.common.cwd,
                                &redirect_state,
                            )
                            .await
                        {
                            emit_error_envelope(
                                args.common.json,
                                args.common.dry_run,
                                "hosted_revert_failed",
                                format!("failed to persist the hosted redirect ledger: {e}"),
                            );
                            return 1;
                        }
                    }
                    if !leg.unsupported.is_empty() {
                        emit_error_envelope(
                            args.common.json,
                            args.common.dry_run,
                            "hosted_revert_unsupported",
                            format!(
                                "no per-purl hosted-redirect revert exists for: {}. Run an \
                                 unscoped `socket-patch rollback` to unwind ALL hosted \
                                 redirects, or re-run `scan --mode hosted` to normalize. \
                                 The manifest was not modified.",
                                leg.unsupported.join(", ")
                            ),
                        );
                        return 1;
                    }
                    if let Some((what, why)) = leg.failed.first() {
                        emit_error_envelope(
                            args.common.json,
                            args.common.dry_run,
                            "hosted_revert_failed",
                            format!(
                                "could not unwind hosted redirect for {what}: {why}. The \
                                 manifest was not modified."
                            ),
                        );
                        return 1;
                    }
                    if args.preserve_state
                        && !leg.reverted.is_empty()
                        && !args.common.silent
                        && !args.common.json
                    {
                        eprintln!(
                            "Note: hosted redirects have no preservable local state; \
                             their ledger records were dropped with the unwound wiring."
                        );
                    }
                    let hosted_action = if args.common.dry_run {
                        PatchAction::Verified
                    } else {
                        PatchAction::Removed
                    };
                    for purl in &leg.reverted {
                        hosted_reverted_events.push(
                            PatchEvent::new(hosted_action, purl.clone()).with_reason(
                                "hosted_reverted",
                                "hosted lockfile redirect unwound on remove",
                            ),
                        );
                    }
                }
            }
        }
    }

    // Manifest entries excluded from the removal: drift-kept vendored
    // purls (kept ledger key / base-purl / qualifier-stripped matching).
    let excluded_kept: std::collections::HashSet<String> = matching
        .iter()
        .map(|(purl, _)| (*purl).clone())
        .filter(|purl| {
            vendor_kept_purls.iter().any(|key| {
                key == purl
                    || strip_purl_qualifiers(key) == strip_purl_qualifiers(purl)
                    || vendored_matches
                        .iter()
                        .find(|(k, _)| k == key)
                        .is_some_and(|(_, e)| e.base_purl == strip_purl_qualifiers(purl))
            })
        })
        .collect();

    // Now remove from manifest. On --dry-run the removal is simulated in
    // memory (manifest untouched) so the blob sweep below can still
    // preview against the post-removal reference set. `--preserve-state`
    // deliberately touches neither the manifest nor the blobs.
    let removal = if args.preserve_state {
        Ok((Vec::new(), manifest.clone()))
    } else if args.common.dry_run {
        let removed: Vec<String> = matching
            .iter()
            .map(|(purl, _)| (*purl).clone())
            .filter(|p| !excluded_kept.contains(p))
            .collect();
        let mut simulated = manifest.clone();
        simulated.patches.retain(|purl, _| !removed.contains(purl));
        Ok((removed, simulated))
    } else {
        remove_patch_from_manifest(&args.identifier, &manifest_path, &excluded_kept).await
    };
    match removal {
        Ok((removed, updated_manifest)) => {
            if removed.is_empty() && !args.preserve_state {
                if !excluded_kept.is_empty() {
                    // Every matching entry was drift-kept: the remove did
                    // not happen. NOT not_found — the identifier matched;
                    // partialFailure keeps `summary.removed` honest at 0.
                    let msg = format!(
                        "{}: every matching entry's vendored state drift-kept; nothing was \
                         removed (re-run `scan --mode vendored` to normalize, then remove)",
                        args.identifier
                    );
                    track_patch_remove_failed(&msg, api_token.as_deref(), org_slug.as_deref())
                        .await;
                    if args.common.json {
                        let mut env = Envelope::new(Command::Remove);
                        env.dry_run = args.common.dry_run;
                        for ev in vendor_skipped_events {
                            env.record(ev);
                        }
                        env.status = Status::PartialFailure;
                        env.error = Some(EnvelopeError::new("vendor_revert_kept", msg));
                        println!("{}", env.to_pretty_json());
                    } else {
                        eprintln!("Error: {msg}");
                    }
                    return 1;
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

            if !args.common.json && !args.common.silent {
                if args.preserve_state {
                    println!(
                        "Manifest entries and vendored artifacts preserved \
                         (--preserve-state); re-apply with `socket-patch apply` or \
                         `socket-patch vendor`."
                    );
                } else if args.common.dry_run {
                    println!("Would remove {} patch(es) from manifest:", removed.len());
                } else {
                    println!("Removed {} patch(es) from manifest:", removed.len());
                }
                for purl in &removed {
                    println!("  - {purl}");
                }
                if args.common.dry_run {
                    println!("\nDry run — nothing was changed.");
                } else if !args.preserve_state {
                    println!("\nManifest updated at {}", manifest_path.display());
                }
            }

            // FAIL-CLOSED (crawler-miss guard): dropped entries whose nested
            // rollback was skipped as not-installed were never actually
            // reverted, and the miss may be a crawler layout gap with the
            // patched bytes still on disk. Sweeping their beforeHash blobs
            // would permanently destroy the only local revert data, so they
            // are pinned into the sweep's keep set; a warning event + stderr
            // line surface each one. Entries genuinely rolled back (or
            // already original) appear in `results`, never here.
            let retained_not_installed: Vec<&str> = rollback_not_installed
                .iter()
                .map(String::as_str)
                .filter(|p| removed.iter().any(|r| r == p))
                .collect();
            if !args.common.json && !args.common.silent && !retained_not_installed.is_empty() {
                eprintln!(
                    "\nWarning: {} removed patch(es) had no matching installed package, so \
                     their rollback was skipped (a crawler miss would look the same); their \
                     revert data (beforeHash blobs) was kept in .socket/blobs:",
                    retained_not_installed.len()
                );
                for purl in &retained_not_installed {
                    eprintln!("  - {purl}");
                }
            }

            // Clean up unused blobs (previewed, not deleted, on --dry-run).
            // The reference manifest is the post-removal manifest PLUS one
            // synthetic keep record per retained entry above:
            // `cleanup_unused_blobs` keeps only afterHash blobs (beforeHash
            // blobs are normally re-downloadable on demand), so each pinned
            // before-hash is listed in an afterHash slot. Scoped to REVERT
            // data only — the retained entries' real afterHash blobs stay
            // sweepable like any other orphan.
            let mut cleanup_reference = updated_manifest.clone();
            let pinned_purls: Vec<String> = retained_not_installed
                .iter()
                .map(|p| (*p).to_string())
                .collect();
            pin_before_hash_blobs(&mut cleanup_reference, &manifest, pinned_purls.iter());
            let blobs_path = socket_dir.join("blobs");
            let mut blobs_removed = 0;
            let mut archives_removed = 0;
            if !args.preserve_state {
                match cleanup_unused_blobs(&cleanup_reference, &blobs_path, args.common.dry_run)
                    .await
                {
                    Ok(cleanup_result) => {
                        blobs_removed = cleanup_result.blobs_removed;
                        if !args.common.json
                            && !args.common.silent
                            && cleanup_result.blobs_removed > 0
                        {
                            println!(
                                "\n{}",
                                format_cleanup_result(&cleanup_result, args.common.dry_run)
                            );
                        }
                    }
                    Err(e) => {
                        // repair's posture: warn and continue, never fatal.
                        if !args.common.silent && !args.common.json {
                            eprintln!("Warning: blob cleanup failed: {e}");
                        }
                    }
                }
                // Diff/package archives use the same manifest-uuid keep rule
                // (parity with repair and scan --prune).
                for dir in ["diffs", "packages"] {
                    match cleanup_unused_archives(
                        &cleanup_reference,
                        &socket_dir.join(dir),
                        args.common.dry_run,
                    )
                    .await
                    {
                        Ok(r) => archives_removed += r.blobs_removed,
                        Err(e) => {
                            if !args.common.silent && !args.common.json {
                                eprintln!("Warning: {dir} cleanup failed: {e}");
                            }
                        }
                    }
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
                // The crawler-miss warnings first (the rollback skip is the
                // earliest outcome chronologically). Recorded — they bump
                // `summary.skipped` like the vendor retained/warning events
                // — and additive: runs with every target genuinely rolled
                // back (or already original) emit none, leaving existing
                // consumers byte-identical output.
                for purl in &retained_not_installed {
                    let mut kept: Vec<String> = manifest
                        .patches
                        .get(*purl)
                        .map(|record| {
                            record
                                .files
                                .values()
                                .filter(|info| !info.before_hash.is_empty())
                                .map(|info| info.before_hash.clone())
                                .collect()
                        })
                        .unwrap_or_default();
                    kept.sort();
                    kept.dedup();
                    env.record(
                        PatchEvent::new(PatchAction::Skipped, (*purl).to_string())
                            .with_reason(
                                "rollback_not_installed",
                                "rollback skipped: no installed package found (a crawler \
                                 miss would look the same); beforeHash blobs kept in \
                                 .socket/blobs so a later rollback/repair can still restore",
                            )
                            .with_details(serde_json::json!({ "beforeBlobsRetained": kept })),
                    );
                }
                // Chronological: the vendor revert ran before the manifest
                // mutation. Reverted events bypass
                // `record` so `summary.removed` stays equal to the number
                // of manifest entries deleted (same rule as the blob-sweep
                // carrier below); retained/warning Skipped events bump
                // `summary.skipped` normally.
                for ev in vendor_reverted_events {
                    env.events.push(ev);
                }
                // Hosted unwinds likewise bypass `record` — summary.removed
                // stays "manifest entries deleted".
                for ev in hosted_reverted_events {
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
                if blobs_removed > 0 || rollback_count > 0 || archives_removed > 0 {
                    env.events
                        .push(PatchEvent::artifact(removal_action).with_details(
                            serde_json::json!({
                                "blobsRemoved": blobs_removed,
                                "rolledBack": rollback_count,
                                "archivesRemoved": archives_removed,
                            }),
                        ));
                }
                // Any drift-kept entry means part of the requested removal
                // did NOT happen: the run is a partialFailure (exit 1) even
                // when sibling entries were removed.
                if !vendor_kept_purls.is_empty() {
                    env.status = Status::PartialFailure;
                }
                println!("{}", env.to_pretty_json());
            }

            if !args.common.dry_run {
                track_patch_removed(removed.len(), api_token.as_deref(), org_slug.as_deref()).await;
            }
            if vendor_kept_purls.is_empty() {
                0
            } else {
                // Errors print even under --silent; the per-key drift-keep
                // lines above are gated, so name the outcome once here.
                if !args.common.json {
                    eprintln!(
                        "Error: {} matching entr{} drift-kept (vendored state and manifest \
                         record retained); re-run `scan --mode vendored` to normalize, then \
                         remove again",
                        vendor_kept_purls.len(),
                        if vendor_kept_purls.len() == 1 { "y was" } else { "ies were" }
                    );
                }
                1
            }
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
/// Remove path for identifiers that match ONLY hosted redirect records
/// (no manifest entry, no detached vendor entry): confirm, unwind each
/// record's lockfile wiring, drop it from the redirect ledger, and report
/// `Removed`/`hosted_reverted` events. Like the detached path, the unwind
/// IS the removal, so events go through `env.record` and bump
/// `summary.removed`. `--skip-rollback` is refused (with no manifest
/// entry to delete, removing a hosted patch can only mean unwinding its
/// redirect); `--preserve-state` still unwinds — hosted has no
/// preservable local state.
async fn remove_hosted_only(
    args: &RemoveArgs,
    hosted_matches: Vec<String>,
    mut redirect_state: socket_patch_core::patch::redirect::RedirectState,
    api_token: Option<&str>,
    org_slug: Option<&str>,
) -> i32 {
    if args.skip_rollback {
        emit_error_envelope(
            args.common.json,
            args.common.dry_run,
            "hosted_state_retained",
            format!(
                "{} matches only hosted redirect record(s); removing one means unwinding \
                 its lockfile redirect, which --skip-rollback prevents",
                args.identifier
            ),
        );
        return 1;
    }

    if !args.common.json && !args.common.silent {
        eprintln!("The following hosted redirect(s) will be unwound and removed:");
        for purl in &hosted_matches {
            eprintln!("  - {purl}");
        }
        eprintln!();
    }
    // `--dry-run` previews without mutating — nothing to confirm.
    let prompt = format!(
        "Remove {} hosted redirect(s) and unwind their lockfile wiring?",
        hosted_matches.len()
    );
    if !args.common.dry_run && !confirm(&prompt, true, args.common.yes, args.common.json) {
        if !args.common.json && !args.common.silent {
            println!("Removal cancelled.");
        }
        return 0;
    }

    let replay_eligible = redirect_state
        .records
        .keys()
        .all(|p| hosted_matches.contains(p));
    let before = (redirect_state.edits.len(), redirect_state.records.len());
    let leg = super::rollback::run_hosted_leg(
        &args.common,
        &hosted_matches,
        &mut redirect_state,
        replay_eligible,
    )
    .await;
    // Persist FIRST, failure or not (see the main-flow hosted leg): the
    // per-purl reverts already flushed lockfile writes, so the on-disk
    // ledger must reflect them even when a later match failed.
    if !args.common.dry_run
        && (redirect_state.edits.len(), redirect_state.records.len()) != before
    {
        if let Err(e) = socket_patch_core::patch::redirect::persist_redirect_state(
            &args.common.cwd,
            &redirect_state,
        )
        .await
        {
            emit_error_envelope(
                args.common.json,
                args.common.dry_run,
                "hosted_revert_failed",
                format!("failed to persist the hosted redirect ledger: {e}"),
            );
            return 1;
        }
    }
    if !leg.unsupported.is_empty() {
        track_patch_remove_failed(
            "hosted redirect revert unsupported",
            api_token,
            org_slug,
        )
        .await;
        emit_error_envelope(
            args.common.json,
            args.common.dry_run,
            "hosted_revert_unsupported",
            format!(
                "no per-purl hosted-redirect revert exists for: {}. Run an unscoped \
                 `socket-patch rollback` to unwind ALL hosted redirects, or re-run \
                 `scan --mode hosted` to normalize.",
                leg.unsupported.join(", ")
            ),
        );
        return 1;
    }
    if let Some((what, why)) = leg.failed.first() {
        track_patch_remove_failed("hosted redirect revert failed", api_token, org_slug).await;
        emit_error_envelope(
            args.common.json,
            args.common.dry_run,
            "hosted_revert_failed",
            format!("could not unwind hosted redirect for {what}: {why}"),
        );
        return 1;
    }
    let mut env = Envelope::new(Command::Remove);
    env.dry_run = args.common.dry_run;
    let action = if args.common.dry_run {
        PatchAction::Verified
    } else {
        PatchAction::Removed
    };
    // Human per-purl lines already printed inside `run_hosted_leg`.
    for purl in &leg.reverted {
        env.record(
            PatchEvent::new(action, purl.clone()).with_reason(
                "hosted_reverted",
                "hosted lockfile redirect unwound on remove",
            ),
        );
    }
    if args.common.json {
        println!("{}", env.to_pretty_json());
    }
    if !args.common.dry_run {
        track_patch_removed(leg.reverted.len(), api_token, org_slug).await;
    }
    0
}

async fn remove_detached_only(
    args: &RemoveArgs,
    detached: Vec<(String, VendorEntry)>,
    mut state: VendorState,
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
        if !args.common.json && !args.common.silent {
            println!("Removal cancelled.");
        }
        return 0;
    }

    let mut env = Envelope::new(Command::Remove);
    env.dry_run = args.common.dry_run;
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
    // Matching entries to KEEP anyway — drift-kept vendored purls whose
    // vendored state survived the revert (the record must survive with it).
    exclusions: &std::collections::HashSet<String>,
) -> Result<(Vec<String>, PatchManifest), String> {
    let mut manifest = read_manifest(manifest_path)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "Invalid manifest".to_string())?;

    let removed: Vec<String> = manifest
        .patches
        .iter()
        .filter(|(purl, patch)| {
            patch_matches(purl, &patch.uuid, identifier) && !exclusions.contains(*purl)
        })
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

        let (removed, manifest) = remove_patch_from_manifest("pkg:pypi/six@1.16.0", &manifest_path, &Default::default())
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
            remove_patch_from_manifest("pkg:pypi/six@1.16.0?artifact_id=sdist", &manifest_path, &Default::default())
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

        let (removed, manifest) = remove_patch_from_manifest("uuid-cp312", &manifest_path, &Default::default())
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

        let (removed, manifest) = remove_patch_from_manifest("pkg:npm/foo@1.0", &manifest_path, &Default::default())
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
            remove_patch_from_manifest("pkg:npm/not-here@9.9.9", &manifest_path, &Default::default())
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

        let (removed, manifest) = remove_patch_from_manifest("pkg:pypi/six@1.16.0", &manifest_path, &Default::default())
            .await
            .expect("remove ok");

        assert_eq!(removed, vec!["pkg:pypi/six@1.16.0?artifact_id=sdist"]);
        assert_eq!(manifest.patches.len(), 1);
        assert!(manifest
            .patches
            .contains_key("pkg:pypi/six@1.17.0?artifact_id=sdist"));
    }
}
