use clap::Args;
use socket_patch_core::api::client::get_api_client_with_overrides;
use socket_patch_core::manifest::cleanup_blobs::format_cleanup_result;
use socket_patch_core::manifest::operations::{read_manifest, write_manifest};
use socket_patch_core::manifest::schema::PatchManifest;
use socket_patch_core::patch::redirect::{
    load_redirect_state, persist_redirect_state, RedirectState, REDIRECT_STATE_REL,
};
use socket_patch_core::telemetry::{track_patch_remove_failed, track_patch_removed};
use socket_patch_core::utils::purl::patch_matches;
use socket_patch_core::vendor::{
    load_state, RevertOpts, VendorEntry, VendorState, VENDOR_STATE_REL,
};
use std::collections::HashSet;
use std::time::Duration;

use super::get::short_uuid;
use super::rollback::{
    all_files_already_original, pin_before_hash_blobs, revert_vendor_entry, rollback_patches_inner,
    run_hosted_leg, sweep_failure, sweep_unused_artifacts, HostedLegOutcome, InnerSelection,
    VendorRevertStep,
};
use crate::args::{apply_env_toggles, GlobalArgs};
use crate::commands::lock_cli::acquire_or_emit;
use crate::json_envelope::{Command, Envelope, EnvelopeError, PatchAction, PatchEvent, Status};
use crate::output::confirm;

/// Vendor-ledger entries matching a remove identifier (by ledger key,
/// base purl or uuid — `VendorEntry::matches_identifier`), sorted by key
/// for deterministic event order.
fn vendor_entries_matching(state: &VendorState, identifier: &str) -> Vec<(String, VendorEntry)> {
    let mut matches: Vec<(String, VendorEntry)> = state
        .entries
        .iter()
        .filter(|(key, entry)| entry.matches_identifier(key, identifier))
        .map(|(k, e)| (k.clone(), e.clone()))
        .collect();
    matches.sort_by(|a, b| a.0.cmp(&b.0));
    matches
}

/// Hosted redirect records matching a remove identifier, sorted.
fn hosted_records_matching(state: &RedirectState, identifier: &str) -> Vec<String> {
    let mut matches: Vec<String> = state
        .records
        .iter()
        .filter(|(purl, rec)| patch_matches(purl, &rec.uuid, identifier))
        .map(|(purl, _)| purl.clone())
        .collect();
    matches.sort();
    matches
}

/// Drop every manifest entry matching `identifier` except `exclusions`
/// (drift-kept vendored purls, whose record must survive with their
/// vendored state). Returns the removed purls, sorted.
fn remove_matching(
    manifest: &mut PatchManifest,
    identifier: &str,
    exclusions: &HashSet<String>,
) -> Vec<String> {
    let mut removed: Vec<String> = manifest
        .patches
        .iter()
        .filter(|(purl, patch)| {
            patch_matches(purl, &patch.uuid, identifier) && !exclusions.contains(*purl)
        })
        .map(|(purl, _)| purl.clone())
        .collect();
    removed.sort();
    for purl in &removed {
        manifest.patches.remove(purl);
    }
    removed
}

/// Emit the `not_found` envelope (or stderr line) for an identifier that
/// matched nothing in any store, tracking the failure. `dry_run` rides the
/// envelope so a preview's failures still report `dryRun: true` (matching
/// apply's error envelopes and remove's own success envelope).
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
    let loud = !args.common.json && !args.common.silent;

    let manifest_path = args.common.resolved_manifest_path();
    let cwd = &args.common.cwd;

    // ── state discovery ─────────────────────────────────────────────────
    // A ledger-only project (vendored mode keeps its records in the vendor
    // ledger, hosted mode in the redirect ledger — neither writes a
    // manifest) proceeds manifest-less: `remove` is the per-purl exit path
    // for those entries. Only cheap EXISTENCE probes run before the lock —
    // they decide the truly-empty error path, which never locks (a bare
    // project must not see `.socket/` created and pruned again). The
    // stores themselves are loaded under the lock below.
    let manifest_missing = tokio::fs::metadata(&manifest_path).await.is_err();
    if manifest_missing {
        let vendor_ledger_exists = tokio::fs::metadata(cwd.join(VENDOR_STATE_REL))
            .await
            .is_ok();
        let redirect_ledger_exists = tokio::fs::metadata(cwd.join(REDIRECT_STATE_REL))
            .await
            .is_ok();
        if !vendor_ledger_exists && !redirect_ledger_exists {
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
    // same `.socket/` directory. The nested in-place rollback does NOT
    // acquire the lock (that would self-deadlock): this one guard covers
    // the rollback, the ledger reverts and the manifest mutation, and its
    // drop removes `apply.lock` (and an emptied `.socket/`) on every exit
    // path.
    let socket_dir = crate::args::socket_dir_of(&manifest_path, &args.common.cwd);
    let _lock = match acquire_or_emit(
        &socket_dir,
        Command::Remove,
        args.common.json,
        args.common.dry_run,
        Duration::from_secs(args.common.lock_timeout.unwrap_or(0)),
    ) {
        Ok(guard) => guard,
        Err(code) => return code,
    };

    // Read the manifest to show what will be removed and confirm. On the
    // ledger-only path there is no manifest to read or mutate; an empty
    // view routes the flow to the ledger-only removals below.
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

    // The vendor ledger, loaded ONCE under the lock: it scopes the nested
    // rollback (vendor-owned purls are not restored in place) and drives
    // the vendored leg. An unreadable ledger degrades to "nothing vendored"
    // for the rollback and fails closed at the vendored leg — exactly where
    // the run is about to mutate vendored state.
    let vendor_state_result = load_state(cwd).await;

    if matching.is_empty() {
        // Ledger-only entries (vendored mode keeps no manifest record) —
        // `remove` is their per-purl exit path (alongside `vendor
        // --revert`'s all-at-once). An unreadable ledger falls through to
        // `not_found`: nothing is mutated on that path.
        if let Ok(state) = vendor_state_result {
            let ledger_matches = vendor_entries_matching(&state, &args.identifier);
            if !ledger_matches.is_empty() {
                return remove_ledger_only(
                    &args,
                    ledger_matches,
                    state,
                    api_token.as_deref(),
                    org_slug.as_deref(),
                )
                .await;
            }
        }

        // Hosted-only patches likewise have no manifest entry — the
        // redirect ledger is their only persistence, and `remove` is
        // their per-purl exit path (the unwind IS the removal). An
        // unreadable ledger falls through to `not_found`: nothing is
        // mutated on that path.
        if let Ok(Some(redirect_state)) = load_redirect_state(cwd).await {
            let hosted_matches = hosted_records_matching(&redirect_state, &args.identifier);
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
    if loud {
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
        if loud {
            println!("Removal cancelled.");
        }
        return 0;
    }

    // ── nested in-place rollback ────────────────────────────────────────
    // Vendor-owned purls are excluded from the in-place restore (the
    // vendored leg below reverts them); an unreadable ledger degrades to
    // "nothing vendored" here and fails closed at that leg.
    let vendored_keys: HashSet<String> = vendor_state_result
        .as_ref()
        .map(socket_patch_core::vendor::VendorState::purl_keys)
        .unwrap_or_default();
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
        if loud {
            println!("Rolling back patch before removal...");
        }
        // The delegation runs muted under --json/--silent (the envelope,
        // or the silence, is ours) and unscoped by --ecosystems (the
        // identifier IS the scope).
        let delegated = GlobalArgs {
            silent: args.common.json || args.common.silent,
            ecosystems: None,
            ..args.common.clone()
        };
        match rollback_patches_inner(
            &delegated,
            &socket_dir,
            &manifest,
            &vendored_keys,
            InnerSelection::Identifier(Some(&args.identifier)),
            Some(&telemetry_client),
        )
        .await
        {
            Ok(outcome) => {
                rollback_not_installed = outcome.not_installed;
                if !outcome.success {
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

                rollback_count = outcome
                    .results
                    .iter()
                    .filter(|r| r.success && !r.files_rolled_back.is_empty())
                    .count();
                // Reuse rollback's canonical predicate rather than
                // re-deriving it: the `!files_verified.is_empty()` guard
                // inside `all_files_already_original` is essential —
                // `Iterator::all` over an empty slice is vacuously `true`,
                // so a zero-file (or not-installed) result would otherwise
                // be miscounted as "already in original state".
                let already_original = outcome
                    .results
                    .iter()
                    .filter(|r| r.success && all_files_already_original(r))
                    .count();

                if loud {
                    if rollback_count > 0 {
                        println!("Rolled back {rollback_count} package(s)");
                    }
                    if already_original > 0 {
                        println!("{already_original} package(s) already in original state");
                    }
                    // Vendor-owned targets say nothing here: the vendored
                    // leg below reports each key's own disposition.
                    if !rollback_not_installed.is_empty() {
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

    // ── vendored leg ────────────────────────────────────────────────────
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
    let mut vendor_state = match vendor_state_result {
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
    let mut vendor_leg = RemoveVendorLeg::default();
    if !vendored_matches.is_empty() {
        if args.skip_rollback {
            for (key, _) in &vendored_matches {
                if loud {
                    eprintln!(
                        "Note: {key} is vendored; --skip-rollback leaves the vendor wiring and \
                         artifact in place (the next `vendor` run will reconcile-revert it)."
                    );
                }
                vendor_leg.skipped.push(
                    PatchEvent::new(PatchAction::Skipped, key.clone()).with_reason(
                        "vendor_state_retained",
                        "vendor wiring and artifact left in place (--skip-rollback)",
                    ),
                );
            }
        } else {
            let keys: Vec<String> = vendored_matches.iter().map(|(k, _)| k.clone()).collect();
            vendor_leg = match revert_vendored_matches(
                &args,
                &keys,
                &mut vendor_state,
                api_token.as_deref(),
                org_slug.as_deref(),
                true,
            )
            .await
            {
                Ok(leg) => leg,
                Err(code) => return code,
            };
        }
    }

    // ── hosted leg ──────────────────────────────────────────────────────
    // An identifier can also (or only) match hosted records in the
    // redirect ledger. Supported ecosystems (cargo, npm-family) unwind
    // per-purl; when the identifier covers EVERY record the whole-ledger
    // replay serves the rest; otherwise unsupported targets fail closed
    // BEFORE the manifest mutation. A corrupt ledger skips the leg with a
    // warning (the identifier may still match other stores).
    // `--skip-rollback` leaves hosted wiring untouched, like the vendor
    // wiring above; `--preserve-state` still unwinds — hosted has no
    // preservable local state.
    let mut hosted_reverted_events: Vec<PatchEvent> = Vec::new();
    if !args.skip_rollback {
        match load_redirect_state(cwd).await {
            Err(e) => {
                if loud {
                    eprintln!(
                        "Warning: cannot read the hosted redirect ledger ({e}); hosted \
                         redirects were not examined"
                    );
                }
            }
            Ok(None) => {}
            Ok(Some(mut redirect_state)) => {
                let hosted_matches = hosted_records_matching(&redirect_state, &args.identifier);
                if !hosted_matches.is_empty() {
                    let leg =
                        match unwind_hosted(&args.common, &hosted_matches, &mut redirect_state)
                            .await
                        {
                            Ok(leg) => leg,
                            Err(err) => {
                                let (code, msg) = hosted_unwind_error(err, true);
                                emit_error_envelope(
                                    args.common.json,
                                    args.common.dry_run,
                                    code,
                                    msg,
                                );
                                return 1;
                            }
                        };
                    if args.preserve_state && !leg.reverted.is_empty() && loud {
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

    // ── manifest mutation ───────────────────────────────────────────────
    // Drift-kept vendored purls are EXCLUDED from the removal (dropping a
    // record whose vendored state survives would hand `vendor`'s reconcile
    // a revert with no backing record); the matching mirrors the
    // ledger-key / base-purl / qualifier-stripped triple.
    let excluded_kept: HashSet<String> = matching
        .iter()
        .map(|(purl, _)| (*purl).clone())
        .filter(|purl| {
            vendor_leg.kept.iter().any(|key| {
                vendored_matches
                    .iter()
                    .find(|(k, _)| k == key)
                    .is_some_and(|(k, e)| e.covers_purl(k, purl))
            })
        })
        .collect();

    // The removal is computed ONCE, from the manifest read under the lock
    // (nothing rewrites it in between); on --dry-run it stays in memory so
    // the blob sweep below can still preview against the post-removal
    // reference set. `--preserve-state` deliberately touches neither the
    // manifest nor the blobs. An emptied manifest stays on disk as
    // `{"patches": {}}` — it carries the setup block and the
    // empty-vs-missing exit codes of `list`/`apply`/`repair`.
    let mut updated_manifest = manifest.clone();
    let removed = if args.preserve_state {
        Vec::new()
    } else {
        remove_matching(&mut updated_manifest, &args.identifier, &excluded_kept)
    };
    if removed.is_empty() && !args.preserve_state {
        // Every matching entry was drift-kept (the identifier matched, so
        // this is the only way the removal can be empty): the remove did
        // not happen. NOT not_found; partialFailure keeps `summary.removed`
        // honest at 0.
        let msg = format!(
            "{}: every matching entry's vendored state drift-kept; nothing was \
             removed (re-run `scan --mode vendored` to normalize, then remove)",
            args.identifier
        );
        track_patch_remove_failed(&msg, api_token.as_deref(), org_slug.as_deref()).await;
        if args.common.json {
            let mut env = Envelope::new(Command::Remove);
            env.dry_run = args.common.dry_run;
            for ev in vendor_leg.skipped {
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
    if !args.common.dry_run && !removed.is_empty() {
        if let Err(e) = write_manifest(&manifest_path, &updated_manifest).await {
            let msg = e.to_string();
            track_patch_remove_failed(&msg, api_token.as_deref(), org_slug.as_deref()).await;
            emit_error_envelope(args.common.json, args.common.dry_run, "remove_failed", msg);
            return 1;
        }
    }

    if loud {
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
    // rollback was skipped as not-installed were never actually reverted,
    // and the miss may be a crawler layout gap with the patched bytes
    // still on disk. Sweeping their beforeHash blobs would permanently
    // destroy the only local revert data, so they are pinned into the
    // sweep's keep set; a warning event + stderr line surface each one.
    // Entries genuinely rolled back (or already original) appear in the
    // rollback's results, never here.
    let retained_not_installed: Vec<&str> = rollback_not_installed
        .iter()
        .map(String::as_str)
        .filter(|p| removed.iter().any(|r| r == p))
        .collect();
    if loud && !retained_not_installed.is_empty() {
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

    // ── GC ──────────────────────────────────────────────────────────────
    // Clean up unused blobs (previewed, not deleted, on --dry-run). The
    // reference manifest is the post-removal manifest PLUS one synthetic
    // keep record per retained entry above: `cleanup_unused_blobs` keeps
    // only afterHash blobs (beforeHash blobs are normally re-downloadable
    // on demand), so each pinned before-hash is listed in an afterHash
    // slot. Scoped to REVERT data only — the retained entries' real
    // afterHash blobs stay sweepable like any other orphan.
    let mut cleanup_reference = updated_manifest;
    let pinned_purls: Vec<String> = retained_not_installed
        .iter()
        .map(|p| (*p).to_string())
        .collect();
    pin_before_hash_blobs(&mut cleanup_reference, &manifest, pinned_purls.iter());
    let mut blobs_removed = 0;
    let mut archives_removed = 0;
    if !args.preserve_state {
        let sweep =
            sweep_unused_artifacts(&cleanup_reference, &socket_dir, args.common.dry_run).await;
        // repair's posture: a failed pass (or a pass that could not unlink
        // every orphan) warns and continues, never fatal; its partial
        // counts still stand.
        if let Some(detail) = sweep_failure("blob", &sweep.blobs) {
            if loud {
                eprintln!("Warning: {detail}");
            }
        }
        if let Ok(r) = sweep.blobs {
            blobs_removed = r.blobs_removed;
            if loud && r.blobs_removed > 0 {
                println!("\n{}", format_cleanup_result(&r, args.common.dry_run));
            }
        }
        // Diff/package archives use the same manifest-uuid keep rule
        // (parity with repair and scan --prune).
        for (dir, result) in [("diffs", sweep.diffs), ("packages", sweep.packages)] {
            if let Some(detail) = sweep_failure(dir, &result) {
                if loud {
                    eprintln!("Warning: {detail}");
                }
            }
            if let Ok(r) = result {
                archives_removed += r.blobs_removed;
            }
        }
    }

    if args.common.json {
        let mut env = Envelope::new(Command::Remove);
        env.dry_run = args.common.dry_run;
        // Dry-run flips would-be Removed events to Verified previews (the
        // apply/vendor/repair convention), so `summary.removed` stays
        // "manifest entries actually deleted" — zero on a preview.
        let removal_action = if args.common.dry_run {
            PatchAction::Verified
        } else {
            PatchAction::Removed
        };
        // The crawler-miss warnings first (the rollback skip is the
        // earliest outcome chronologically). Recorded — they bump
        // `summary.skipped` like the vendor retained/warning events — and
        // additive: runs with every target genuinely rolled back (or
        // already original) emit none, leaving existing consumers
        // byte-identical output.
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
        // mutation. Reverted events bypass `record` so `summary.removed`
        // stays equal to the number of manifest entries deleted (same rule
        // as the blob-sweep carrier below); retained/warning Skipped
        // events bump `summary.skipped` normally.
        for ev in vendor_leg.reverted {
            env.events.push(ev);
        }
        // Hosted unwinds likewise bypass `record` — summary.removed stays
        // "manifest entries deleted".
        for ev in hosted_reverted_events {
            env.events.push(ev);
        }
        for ev in vendor_leg.skipped {
            env.record(ev);
        }
        // One Removed event per purl whose manifest entry was deleted
        // (Verified on --dry-run).
        for purl in &removed {
            env.record(PatchEvent::new(removal_action, purl.clone()));
        }
        // One artifact-level Removed event carrying the blob-sweep and
        // rollback counts. Emitted whenever either is non-zero so the
        // `rolledBack` count is still reported even when no blobs happened
        // to be swept (e.g. the removed patch's afterHash blobs are still
        // referenced elsewhere).
        //
        // Pushed directly rather than via `env.record`: this is a
        // purl-less metadata carrier, not a removed manifest entry. The
        // per-purl events above are the authoritative patch-removal
        // count, so `summary.removed` must equal the number of entries
        // deleted (`removed.len()`) — letting this carrier bump `removed`
        // too would double-count, reporting e.g. `removed: 2` for a
        // single-patch removal that happened to sweep an orphan blob.
        // Consumers read the blob/rollback totals from `details`, never
        // from `summary.removed`.
        if blobs_removed > 0 || rollback_count > 0 || archives_removed > 0 {
            env.events.push(
                PatchEvent::artifact(removal_action).with_details(serde_json::json!({
                    "blobsRemoved": blobs_removed,
                    "rolledBack": rollback_count,
                    "archivesRemoved": archives_removed,
                })),
            );
        }
        // Any drift-kept entry means part of the requested removal did
        // NOT happen: the run is a partialFailure (exit 1) even when
        // sibling entries were removed.
        if !vendor_leg.kept.is_empty() {
            env.status = Status::PartialFailure;
        }
        println!("{}", env.to_pretty_json());
    }

    if !args.common.dry_run {
        track_patch_removed(removed.len(), api_token.as_deref(), org_slug.as_deref()).await;
    }
    if vendor_leg.kept.is_empty() {
        0
    } else {
        // Errors print even under --silent; the per-key drift-keep lines
        // above are gated, so name the outcome once here.
        if !args.common.json {
            eprintln!(
                "Error: {} matching entr{} drift-kept (vendored state and manifest \
                 record retained); re-run `scan --mode vendored` to normalize, then \
                 remove again",
                vendor_leg.kept.len(),
                if vendor_leg.kept.len() == 1 {
                    "y was"
                } else {
                    "ies were"
                }
            );
        }
        1
    }
}

/// The vendored leg's envelope material, collected by
/// [`revert_vendored_matches`].
#[derive(Default)]
struct RemoveVendorLeg {
    /// `Removed`/`vendor_reverted` events (`Verified`/`vendor_would_revert`
    /// on --dry-run), one per reverted key.
    reverted: Vec<PatchEvent>,
    /// Backend warnings, drift-keeps and preserved entries — `Skipped`
    /// events.
    skipped: Vec<PatchEvent>,
    /// Ledger keys whose revert drift-kept: entry, artifact and any
    /// manifest record stay.
    kept: Vec<String>,
    /// Entries actually reverted and dropped from the ledger (wet runs).
    reverted_count: usize,
}

/// The vendored-revert loop shared by the manifest-backed and ledger-only
/// remove paths: revert each key (see `revert_vendor_entry` for the
/// drift-keep / `--preserve-state` / dry-run classification), print the
/// human lines, collect the envelope events. The first hard failure — a
/// backend refusal or a ledger write failure — emits its error envelope
/// and returns `Err(1)`; `manifest_backed` callers' messages add that the
/// manifest was not touched.
async fn revert_vendored_matches(
    args: &RemoveArgs,
    keys: &[String],
    state: &mut VendorState,
    api_token: Option<&str>,
    org_slug: Option<&str>,
    manifest_backed: bool,
) -> Result<RemoveVendorLeg, i32> {
    let loud = !args.common.json && !args.common.silent;
    let opts = RevertOpts {
        dry_run: args.common.dry_run,
        keep_artifact: args.preserve_state,
    };
    let mut leg = RemoveVendorLeg::default();
    for key in keys {
        let result = revert_vendor_entry(&args.common.cwd, key, state, opts).await;
        for w in &result.warnings {
            if loud {
                eprintln!("Warning ({}): {}", w.code, w.detail);
            }
            leg.skipped.push(
                PatchEvent::new(PatchAction::Skipped, key.clone())
                    .with_reason(w.code, w.detail.clone()),
            );
        }
        match result.step {
            VendorRevertStep::Missing => {}
            VendorRevertStep::Failed(why) => {
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
                        "could not revert vendoring for {key}: {why}{}",
                        if manifest_backed {
                            ". The manifest was not modified."
                        } else {
                            ""
                        }
                    ),
                );
                return Err(1);
            }
            VendorRevertStep::Kept => {
                // Drift-keep: the lock changed under us and the backend
                // left both the wiring and the artifact alone. Per the
                // RevertOutcome contract the ledger entry stays — and so
                // must any manifest entry, or `vendor`'s reconcile would
                // re-revert an entry whose backing record is gone.
                let (note, detail) = if manifest_backed {
                    (
                        "; its manifest entry was kept too",
                        "lockfile wiring drifted; vendored state and manifest entry kept",
                    )
                } else {
                    (
                        "",
                        "lockfile wiring drifted; vendored state and ledger entry kept",
                    )
                };
                if loud {
                    eprintln!("Kept vendored state for {key}: lockfile wiring drifted{note}");
                }
                leg.kept.push(key.clone());
                leg.skipped.push(
                    PatchEvent::new(PatchAction::Skipped, key.clone())
                        .with_reason("vendor_revert_kept", detail),
                );
            }
            VendorRevertStep::WouldRevert => {
                if loud {
                    if args.preserve_state {
                        println!("Would unwire vendoring for {key} (artifact preserved)");
                    } else {
                        println!("Would revert vendoring for {key}");
                    }
                }
                // Dry-run flips the would-be Removed to a Verified preview,
                // same convention as apply/vendor/repair.
                leg.reverted.push(
                    PatchEvent::new(PatchAction::Verified, key.clone()).with_reason(
                        "vendor_would_revert",
                        "vendoring would be reverted on remove",
                    ),
                );
            }
            VendorRevertStep::Preserved => {
                if loud {
                    println!("Unwired vendoring for {key} (artifact preserved)");
                }
                leg.skipped.push(
                    PatchEvent::new(PatchAction::Skipped, key.clone()).with_reason(
                        "vendor_state_preserved",
                        "lockfile unwired; artifact and ledger entry preserved \
                         (--preserve-state)",
                    ),
                );
            }
            VendorRevertStep::Reverted => {
                if loud {
                    println!("Reverted vendoring for {key}");
                }
                leg.reverted_count += 1;
                leg.reverted.push(
                    PatchEvent::new(PatchAction::Removed, key.clone())
                        .with_reason("vendor_reverted", "vendoring reverted on remove"),
                );
            }
            VendorRevertStep::LedgerWriteFailed(e) => {
                emit_error_envelope(
                    args.common.json,
                    args.common.dry_run,
                    "vendor_state_write_failed",
                    e,
                );
                return Err(1);
            }
        }
    }
    Ok(leg)
}

/// Why a hosted unwind stopped. Each caller renders its own message (the
/// manifest-backed path adds that the manifest was not touched).
enum HostedUnwindError {
    /// The ledger could not be persisted after the reverts flushed.
    Persist(String),
    /// Scoped targets whose ecosystem has no per-purl hosted revert.
    Unsupported(Vec<String>),
    /// A per-purl revert (or the whole-ledger replay) refused.
    Failed { what: String, why: String },
}

/// Unwind the hosted redirect records in `hosted_matches` and persist the
/// ledger — FIRST, failure or not: the per-purl reverts flush lockfile
/// writes as they go, so an early error return without persisting would
/// strand already-reverted purls' records in the on-disk ledger (lockfiles
/// and ledger desynced; `list`/VEX attest dead wiring). When the matches
/// cover EVERY record the whole-ledger replay serves the ecosystems without
/// a per-purl revert. Shared by the manifest-backed and hosted-only remove
/// paths.
async fn unwind_hosted(
    common: &GlobalArgs,
    hosted_matches: &[String],
    state: &mut RedirectState,
) -> Result<HostedLegOutcome, HostedUnwindError> {
    let replay_eligible = state.records.keys().all(|p| hosted_matches.contains(p));
    let before = (state.edits.len(), state.records.len());
    let leg = run_hosted_leg(common, hosted_matches, state, replay_eligible).await;
    if !common.dry_run && (state.edits.len(), state.records.len()) != before {
        if let Err(e) = persist_redirect_state(&common.cwd, state).await {
            return Err(HostedUnwindError::Persist(e.to_string()));
        }
    }
    if !leg.unsupported.is_empty() {
        return Err(HostedUnwindError::Unsupported(leg.unsupported));
    }
    if let Some((what, why)) = leg.failed.first().cloned() {
        return Err(HostedUnwindError::Failed { what, why });
    }
    Ok(leg)
}

/// Error code + message for a stopped hosted unwind.
fn hosted_unwind_error(err: HostedUnwindError, manifest_backed: bool) -> (&'static str, String) {
    let note = if manifest_backed {
        " The manifest was not modified."
    } else {
        ""
    };
    match err {
        HostedUnwindError::Persist(e) => (
            "hosted_revert_failed",
            format!("failed to persist the hosted redirect ledger: {e}"),
        ),
        HostedUnwindError::Unsupported(purls) => (
            "hosted_revert_unsupported",
            format!(
                "no per-purl hosted-redirect revert exists for: {}. Run an unscoped \
                 `socket-patch rollback` to unwind ALL hosted redirects, or re-run \
                 `scan --mode hosted` to normalize.{note}",
                purls.join(", ")
            ),
        ),
        HostedUnwindError::Failed { what, why } => (
            "hosted_revert_failed",
            if manifest_backed {
                format!("could not unwind hosted redirect for {what}: {why}.{note}")
            } else {
                format!("could not unwind hosted redirect for {what}: {why}")
            },
        ),
    }
}

/// Remove path for identifiers that match ONLY hosted redirect records
/// (no manifest entry, no vendor-ledger entry): confirm, unwind each
/// record's lockfile wiring, drop it from the redirect ledger, and report
/// `Removed`/`hosted_reverted` events. Like the ledger-only vendored path,
/// the unwind IS the removal, so events go through `env.record` and bump
/// `summary.removed`. `--skip-rollback` is refused (with no manifest
/// entry to delete, removing a hosted patch can only mean unwinding its
/// redirect); `--preserve-state` still unwinds — hosted has no
/// preservable local state.
async fn remove_hosted_only(
    args: &RemoveArgs,
    hosted_matches: Vec<String>,
    mut redirect_state: RedirectState,
    api_token: Option<&str>,
    org_slug: Option<&str>,
) -> i32 {
    let loud = !args.common.json && !args.common.silent;
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

    if loud {
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
        if loud {
            println!("Removal cancelled.");
        }
        return 0;
    }

    let leg = match unwind_hosted(&args.common, &hosted_matches, &mut redirect_state).await {
        Ok(leg) => leg,
        Err(err) => {
            match &err {
                HostedUnwindError::Unsupported(_) => {
                    track_patch_remove_failed(
                        "hosted redirect revert unsupported",
                        api_token,
                        org_slug,
                    )
                    .await;
                }
                HostedUnwindError::Failed { .. } => {
                    track_patch_remove_failed("hosted redirect revert failed", api_token, org_slug)
                        .await;
                }
                HostedUnwindError::Persist(_) => {}
            }
            let (code, msg) = hosted_unwind_error(err, false);
            emit_error_envelope(args.common.json, args.common.dry_run, code, msg);
            return 1;
        }
    };
    let mut env = Envelope::new(Command::Remove);
    env.dry_run = args.common.dry_run;
    let action = if args.common.dry_run {
        PatchAction::Verified
    } else {
        PatchAction::Removed
    };
    // Human per-purl lines already printed inside `run_hosted_leg`.
    for purl in &leg.reverted {
        env.record(PatchEvent::new(action, purl.clone()).with_reason(
            "hosted_reverted",
            "hosted lockfile redirect unwound on remove",
        ));
    }
    if args.common.json {
        println!("{}", env.to_pretty_json());
    }
    if !args.common.dry_run {
        track_patch_removed(leg.reverted.len(), api_token, org_slug).await;
    }
    0
}

/// Remove path for identifiers that match ONLY vendor-ledger entries (no
/// manifest record — the shape every `scan/get --mode vendored` entry
/// has): confirm, revert each entry's wiring + artifact, drop it from the
/// ledger, and report `Removed`/`vendor_reverted` events. Unlike the
/// manifest path, the reverts here ARE the removal, so they go through
/// `env.record` and bump `summary.removed`. Drift-keeps and
/// `--preserve-state` follow the manifest path's rules exactly (the loop is
/// shared): a kept entry stays in the ledger and fails the run,
/// `--preserve-state` unwires and keeps everything. `--skip-rollback` is
/// refused: with no manifest entry to delete, removing a ledger-only
/// patch can only mean reverting its vendoring.
async fn remove_ledger_only(
    args: &RemoveArgs,
    matches: Vec<(String, VendorEntry)>,
    mut state: VendorState,
    api_token: Option<&str>,
    org_slug: Option<&str>,
) -> i32 {
    let loud = !args.common.json && !args.common.silent;
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

    if loud {
        if args.preserve_state {
            eprintln!(
                "The following detached vendored patch(es) will be unwired (artifacts and \
                 ledger entries preserved):"
            );
        } else {
            eprintln!("The following detached vendored patch(es) will be reverted and removed:");
        }
        for (key, entry) in &matches {
            eprintln!("  - {key} (UUID: {})", short_uuid(&entry.uuid));
        }
        eprintln!();
    }
    // `--dry-run` previews without mutating — nothing to confirm.
    let prompt = if args.preserve_state {
        format!(
            "Unwire vendoring for {} vendored patch(es)? (artifacts and ledger entries will \
             be preserved)",
            matches.len()
        )
    } else {
        format!(
            "Remove {} vendored patch(es) and revert their vendoring?",
            matches.len()
        )
    };
    if !args.common.dry_run && !confirm(&prompt, true, args.common.yes, args.common.json) {
        if loud {
            println!("Removal cancelled.");
        }
        return 0;
    }

    let keys: Vec<String> = matches.iter().map(|(k, _)| k.clone()).collect();
    let leg =
        match revert_vendored_matches(args, &keys, &mut state, api_token, org_slug, false).await {
            Ok(leg) => leg,
            Err(code) => return code,
        };

    let mut env = Envelope::new(Command::Remove);
    env.dry_run = args.common.dry_run;
    // The reverts ARE the removal: every event is recorded, so
    // `summary.removed` counts the reverted entries (`summary.verified`
    // the would-be removals on --dry-run).
    for ev in leg.reverted {
        env.record(ev);
    }
    for ev in leg.skipped {
        env.record(ev);
    }
    if !leg.kept.is_empty() {
        // Any drift-kept entry means part of the requested removal did
        // NOT happen: partialFailure (exit 1). When EVERY match kept, the
        // top-level error names the outcome — nothing was removed.
        env.mark_partial_failure();
        if leg.kept.len() == keys.len() {
            let msg = format!(
                "{}: every matching entry's vendored state drift-kept; nothing was \
                 removed (re-run `scan --mode vendored` to normalize, then remove)",
                args.identifier
            );
            track_patch_remove_failed(&msg, api_token, org_slug).await;
            env.error = Some(EnvelopeError::new("vendor_revert_kept", msg));
        }
    }
    if args.common.json {
        println!("{}", env.to_pretty_json());
    }
    if !args.common.dry_run {
        track_patch_removed(leg.reverted_count, api_token, org_slug).await;
    }
    if leg.kept.is_empty() {
        0
    } else {
        // Errors print even under --silent; the per-key drift-keep lines
        // are gated, so name the outcome once here.
        if !args.common.json {
            eprintln!(
                "Error: {} matching entr{} drift-kept (vendored state and ledger record \
                 retained); re-run `scan --mode vendored` to normalize, then remove again",
                leg.kept.len(),
                if leg.kept.len() == 1 {
                    "y was"
                } else {
                    "ies were"
                }
            );
        }
        1
    }
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

    /// A manifest with three PyPI release variants of one package@version
    /// plus an unrelated npm package.
    fn multi_variant_manifest() -> PatchManifest {
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
        PatchManifest {
            patches,
            setup: None,
        }
    }

    #[test]
    fn remove_base_purl_removes_all_variants() {
        let mut manifest = multi_variant_manifest();

        let removed = remove_matching(&mut manifest, "pkg:pypi/six@1.16.0", &Default::default());

        // All three release variants removed (sorted); the npm package untouched.
        assert_eq!(removed.len(), 3);
        assert!(removed.iter().all(|p| p.contains("six@1.16.0")));
        assert!(
            removed.windows(2).all(|w| w[0] < w[1]),
            "sorted: {removed:?}"
        );
        assert_eq!(manifest.patches.len(), 1);
        assert!(manifest.patches.contains_key("pkg:npm/foo@1.0"));
    }

    #[test]
    fn remove_qualified_purl_removes_single_variant() {
        let mut manifest = multi_variant_manifest();

        let removed = remove_matching(
            &mut manifest,
            "pkg:pypi/six@1.16.0?artifact_id=sdist",
            &Default::default(),
        );

        // Only the sdist variant removed; the two wheels + npm remain.
        assert_eq!(removed, vec!["pkg:pypi/six@1.16.0?artifact_id=sdist"]);
        assert_eq!(manifest.patches.len(), 3);
        assert!(!manifest
            .patches
            .contains_key("pkg:pypi/six@1.16.0?artifact_id=sdist"));
    }

    #[test]
    fn remove_by_uuid_removes_single_variant() {
        let mut manifest = multi_variant_manifest();

        let removed = remove_matching(&mut manifest, "uuid-cp312", &Default::default());

        assert_eq!(removed, vec!["pkg:pypi/six@1.16.0?artifact_id=wheel-cp312"]);
        assert_eq!(manifest.patches.len(), 3);
    }

    /// A plain (qualifier-free) npm PURL removes exactly its own entry and
    /// must not accidentally match same-prefix neighbours like
    /// `foobar@1.0`. Guards the `strip_purl_qualifiers == identifier`
    /// exact-equality path for non-PyPI keys.
    #[test]
    fn remove_npm_purl_is_exact_and_does_not_prefix_match() {
        let mut patches = HashMap::new();
        patches.insert("pkg:npm/foo@1.0".to_string(), make_record("uuid-foo"));
        patches.insert("pkg:npm/foobar@1.0".to_string(), make_record("uuid-foobar"));
        let mut manifest = PatchManifest {
            patches,
            setup: None,
        };

        let removed = remove_matching(&mut manifest, "pkg:npm/foo@1.0", &Default::default());

        assert_eq!(removed, vec!["pkg:npm/foo@1.0"]);
        assert_eq!(manifest.patches.len(), 1);
        assert!(manifest.patches.contains_key("pkg:npm/foobar@1.0"));
    }

    /// An identifier that matches nothing removes nothing and leaves the
    /// manifest intact. `run` gates the manifest write on a non-empty
    /// removal, so a no-op remove never rewrites the file (the on-disk
    /// byte-identity is pinned end-to-end by `cli_parse_remove`'s no-match
    /// test).
    #[test]
    fn remove_no_match_leaves_manifest_untouched() {
        let mut manifest = multi_variant_manifest();
        let before = manifest.clone();

        let removed = remove_matching(&mut manifest, "pkg:npm/not-here@9.9.9", &Default::default());

        assert!(removed.is_empty(), "nothing should match");
        assert_eq!(manifest, before, "manifest left intact");
    }

    /// A base PURL must not bleed across versions: removing `six@1.16.0`
    /// leaves `six@1.17.0` (and its variants) in place.
    #[test]
    fn remove_base_purl_does_not_touch_other_versions() {
        let mut patches = HashMap::new();
        patches.insert(
            "pkg:pypi/six@1.16.0?artifact_id=sdist".to_string(),
            make_record("uuid-16-sdist"),
        );
        patches.insert(
            "pkg:pypi/six@1.17.0?artifact_id=sdist".to_string(),
            make_record("uuid-17-sdist"),
        );
        let mut manifest = PatchManifest {
            patches,
            setup: None,
        };

        let removed = remove_matching(&mut manifest, "pkg:pypi/six@1.16.0", &Default::default());

        assert_eq!(removed, vec!["pkg:pypi/six@1.16.0?artifact_id=sdist"]);
        assert_eq!(manifest.patches.len(), 1);
        assert!(manifest
            .patches
            .contains_key("pkg:pypi/six@1.17.0?artifact_id=sdist"));
    }

    /// Drift-kept exclusions survive the removal of their matching
    /// siblings: the record whose vendored state was kept stays.
    #[test]
    fn remove_matching_honors_exclusions() {
        let mut manifest = multi_variant_manifest();
        let exclusions: HashSet<String> =
            ["pkg:pypi/six@1.16.0?artifact_id=sdist".to_string()].into();

        let removed = remove_matching(&mut manifest, "pkg:pypi/six@1.16.0", &exclusions);

        assert_eq!(
            removed.len(),
            2,
            "the two wheels go, the excluded sdist stays"
        );
        assert!(manifest
            .patches
            .contains_key("pkg:pypi/six@1.16.0?artifact_id=sdist"));
        assert!(manifest.patches.contains_key("pkg:npm/foo@1.0"));
        assert_eq!(manifest.patches.len(), 2);
    }
}
