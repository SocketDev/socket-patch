//! `socket-patch vendor` — committable vendoring of patched dependencies.
//!
//! Works like `apply`, but instead of patching installed packages in place it
//! ejects each patched package into `.socket/vendor/<eco>/<patch-uuid>/…` and
//! rewires the ecosystem's lockfile/config so the project consumes the
//! vendored copy. After committing `.socket/vendor/` + the lockfile edits, a
//! fresh checkout builds with the patched dependency on machines with no
//! socket-patch and no Socket API access. `--revert` restores the recorded
//! original lockfile fragments and removes the artifacts. `rollback`/`remove`
//! stay vendoring-unaware by design — this command owns the whole lifecycle.

use clap::Args;
use socket_patch_core::api::client::get_api_client_with_overrides;
use socket_patch_core::crawlers::{CrawlerOptions, Ecosystem};
use socket_patch_core::manifest::operations::read_manifest;
use socket_patch_core::manifest::schema::{PatchManifest, PatchRecord};
use socket_patch_core::patch::apply::{verify_file_patch, PatchSources};
use socket_patch_core::patch::copy_tree::remove_tree;
use socket_patch_core::patch::vendor::{
    self, ecosystem_dir_for_purl, load_state, save_state, RevertOutcome, VendorEntry,
    VendorOutcome, VendorWarning,
};
use socket_patch_core::utils::purl::strip_purl_qualifiers;
use socket_patch_core::utils::telemetry::{track_patch_vendor_failed, track_patch_vendored};
use socket_patch_core::vex::time::now_rfc3339;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::Duration;

use crate::args::{apply_env_toggles, GlobalArgs};
use crate::commands::apply::{result_to_event, variant_matches_installed};
use crate::commands::fetch_stage::{stage_patch_sources, StageOutcome};
use crate::commands::lock_cli::{acquire_or_emit, lock_broken_event};
use crate::commands::vex::{generate_vex_from_manifest_path, VexEmbedArgs};
use crate::ecosystem_dispatch::{find_packages_for_purls, partition_purls};
use crate::json_envelope::{
    Command, Envelope, EnvelopeError, PatchAction, PatchEvent, Status, VexSummary,
};

#[derive(Args)]
pub struct VendorArgs {
    #[command(flatten)]
    pub common: GlobalArgs,

    /// Skip pre-vendor hash verification (vendor even if the installed
    /// package's files differ from the patch's beforeHash).
    #[arg(
        short = 'f',
        long,
        env = "SOCKET_FORCE",
        default_value_t = false,
        value_parser = crate::args::parse_bool_flag,
    )]
    pub force: bool,

    /// Undo vendoring: restore the recorded original lockfile fragments and
    /// remove the `.socket/vendor/` artifacts. Works without a manifest.
    #[arg(
        long = "revert",
        env = "SOCKET_VENDOR_REVERT",
        default_value_t = false,
        value_parser = crate::args::parse_bool_flag,
    )]
    pub revert: bool,

    /// On a successful vendor, also generate an OpenVEX 0.2.0 document
    /// (same contract as `apply --vex`).
    #[command(flatten)]
    pub vex: VexEmbedArgs,
}

/// Refusal codes that are expected skips, not command failures: the user's
/// request is still fully satisfied when these are the only non-successes.
fn refusal_is_benign(code: &str) -> bool {
    matches!(code, "vendor_unsupported_ecosystem" | "already_vendored")
}

/// Dispatch one purl to its ecosystem backend. `pkg_path` is the crawler's
/// installed location (site-packages root for pypi, the package dir
/// otherwise). Returns `None` for purls with no vendor backend in this build.
#[allow(clippy::too_many_arguments)]
async fn dispatch_vendor_one(
    purl: &str,
    pkg_path: &Path,
    project_root: &Path,
    record: &PatchRecord,
    sources: &PatchSources<'_>,
    vendored_at: &str,
    dry_run: bool,
    force: bool,
) -> Option<VendorOutcome> {
    let eco = ecosystem_dir_for_purl(purl)?;
    Some(match eco {
        "npm" => {
            // The flavor router probes the project's lockfile (package-lock /
            // yarn / pnpm / bun) and dispatches or refuses per flavor.
            socket_patch_core::patch::vendor::npm_flavor::vendor_npm_any(
                purl,
                pkg_path,
                project_root,
                record,
                sources,
                vendored_at,
                dry_run,
                force,
            )
            .await
        }
        "pypi" => {
            socket_patch_core::patch::vendor::pypi::vendor_pypi(
                purl,
                pkg_path,
                project_root,
                record,
                sources,
                vendored_at,
                dry_run,
                force,
            )
            .await
        }
        "gem" => {
            socket_patch_core::patch::vendor::gem::vendor_gem(
                purl,
                pkg_path,
                project_root,
                record,
                sources,
                vendored_at,
                dry_run,
                force,
            )
            .await
        }
        #[cfg(feature = "cargo")]
        "cargo" => {
            socket_patch_core::patch::vendor::cargo::vendor_cargo_crate(
                purl,
                pkg_path,
                project_root,
                record,
                sources,
                vendored_at,
                dry_run,
                force,
            )
            .await
        }
        #[cfg(feature = "golang")]
        "golang" => {
            socket_patch_core::patch::vendor::golang::vendor_go_module(
                purl,
                pkg_path,
                project_root,
                record,
                sources,
                vendored_at,
                dry_run,
                force,
            )
            .await
        }
        #[cfg(feature = "composer")]
        "composer" => {
            socket_patch_core::patch::vendor::composer_lock::vendor_composer(
                purl,
                pkg_path,
                project_root,
                record,
                sources,
                vendored_at,
                dry_run,
                force,
            )
            .await
        }
        _ => return None,
    })
}

/// Dispatch one recorded entry to its ecosystem's revert.
pub(crate) async fn dispatch_revert_one(
    entry: &VendorEntry,
    project_root: &Path,
    dry_run: bool,
) -> RevertOutcome {
    match entry.ecosystem.as_str() {
        "npm" => {
            socket_patch_core::patch::vendor::npm_flavor::revert_npm_any(
                entry,
                project_root,
                dry_run,
            )
            .await
        }
        "pypi" => {
            socket_patch_core::patch::vendor::pypi::revert_pypi(entry, project_root, dry_run).await
        }
        "gem" => {
            socket_patch_core::patch::vendor::gem::revert_gem(entry, project_root, dry_run).await
        }
        #[cfg(feature = "cargo")]
        "cargo" => {
            socket_patch_core::patch::vendor::cargo::revert_cargo_vendor(
                entry,
                project_root,
                dry_run,
            )
            .await
        }
        #[cfg(feature = "golang")]
        "golang" => {
            socket_patch_core::patch::vendor::golang::revert_go_vendor(entry, project_root, dry_run)
                .await
        }
        #[cfg(feature = "composer")]
        "composer" => {
            socket_patch_core::patch::vendor::composer_lock::revert_composer(
                entry,
                project_root,
                dry_run,
            )
            .await
        }
        other => RevertOutcome::failed(format!(
            "this build has no vendor backend for ecosystem `{other}`"
        )),
    }
}

/// Surface a backend warning: stderr line for humans, a Skipped event with
/// the stable code for JSON consumers (Skipped never flips the status).
fn record_warning(env: &mut Envelope, purl: &str, warning: &VendorWarning, common: &GlobalArgs) {
    if !common.silent && !common.json {
        eprintln!("Warning ({}): {}", warning.code, warning.detail);
    }
    env.record(
        PatchEvent::new(PatchAction::Skipped, purl.to_string())
            .with_reason(warning.code, warning.detail.clone()),
    );
}

pub async fn run(args: VendorArgs) -> i32 {
    apply_env_toggles(&args.common);
    let (telemetry_client, _) =
        get_api_client_with_overrides(args.common.api_client_overrides()).await;
    let api_token = telemetry_client.api_token().cloned();
    let org_slug = telemetry_client.org_slug().cloned();

    let manifest_path = args.common.resolved_manifest_path();
    let socket_dir = manifest_path
        .parent()
        .unwrap_or(Path::new("."))
        .to_path_buf();

    // `--revert` derives everything from state.json + the vendor tree; it
    // must work after the manifest was deleted. Plain vendor needs the
    // manifest and exits clean without one (same contract as apply).
    if !args.revert && tokio::fs::metadata(&manifest_path).await.is_err() {
        if args.common.json {
            let mut env = Envelope::new(Command::Vendor);
            env.status = Status::NoManifest;
            env.dry_run = args.common.dry_run;
            println!("{}", env.to_pretty_json());
        } else if !args.common.silent {
            println!("No .socket folder found, nothing to vendor.");
        }
        return 0;
    }

    // Same lock as apply/rollback: vendor mutates the same lockfiles and
    // `.socket/` tree, so a separate lock would allow an apply↔vendor race.
    let acquired = match acquire_or_emit(
        &socket_dir,
        Command::Vendor,
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

    let mut env = Envelope::new(Command::Vendor);
    env.dry_run = args.common.dry_run;
    if lock_was_broken {
        env.record(lock_broken_event(&socket_dir));
    }

    let exit = if args.revert {
        run_revert(&args, &mut env).await
    } else {
        run_vendor(&args, &manifest_path, &mut env).await
    };

    // Embedded VEX: same contract as `apply --vex` — only on success, and a
    // requested-but-failed VEX flips the exit code.
    let mut exit = exit;
    if exit == 0 && !args.revert {
        if let Some(vex_path) = args.vex.vex.as_ref() {
            let params = args.vex.to_build_params();
            match generate_vex_from_manifest_path(&args.common, &params, &manifest_path).await {
                Ok(summary) => {
                    env.vex = Some(VexSummary {
                        path: vex_path.display().to_string(),
                        statements: summary.statements,
                        format: "openvex-0.2.0".to_string(),
                    });
                }
                Err(e) => {
                    env.mark_error(EnvelopeError::new(e.code, e.message.clone()));
                    exit = 1;
                }
            }
        }
    }

    if args.common.json {
        println!("{}", env.to_pretty_json());
    }

    if !args.revert {
        if exit == 0 {
            track_patch_vendored(
                env.summary.applied,
                args.common.dry_run,
                api_token.as_deref(),
                org_slug.as_deref(),
            )
            .await;
        } else {
            track_patch_vendor_failed(
                "vendor completed with failures",
                args.common.dry_run,
                api_token.as_deref(),
                org_slug.as_deref(),
            )
            .await;
        }
    }

    exit
}

async fn run_vendor(args: &VendorArgs, manifest_path: &Path, env: &mut Envelope) -> i32 {
    let common = &args.common;
    let manifest = match read_manifest(manifest_path).await {
        Ok(Some(m)) => m,
        Ok(None) => return 0, // vanished since the existence check (TOCTOU)
        Err(e) => {
            env.mark_error(EnvelopeError::new("invalid_manifest", e.to_string()));
            if !common.json && !common.silent {
                eprintln!("Error: could not read manifest: {e}");
            }
            return 1;
        }
    };

    // Reconcile first (mirrors apply's placement): entries vendored by a
    // previous run whose patches were dropped from the manifest are reverted
    // even when zero in-scope patches remain.
    let mut has_errors = reconcile_dropped(&manifest, common, env).await;

    let socket_dir = manifest_path.parent().unwrap_or(Path::new("."));
    let staged = match stage_patch_sources(common, &manifest, socket_dir).await {
        Ok(StageOutcome::Ready(s)) => s,
        Ok(StageOutcome::Unavailable) => {
            env.mark_error(EnvelopeError::new(
                "no_local_source",
                "patch artifacts unavailable (offline or download failure)",
            ));
            return 1;
        }
        Err(e) => {
            env.mark_error(EnvelopeError::new("stage_failed", e));
            return 1;
        }
    };
    let sources = staged.as_patch_sources();

    has_errors |=
        vendor_records(common, &manifest.patches, &sources, false, args.force, env).await;

    if has_errors {
        env.mark_partial_failure();
        1
    } else {
        0
    }
}

/// The vendoring engine, decoupled from the manifest file. `records` is the
/// purl → [`PatchRecord`] view to vendor: `manifest.patches` for the
/// manifest-driven `vendor` command (and `scan --vendor`), or the
/// freshly-fetched record map for `scan --vendor --detached`. Entries written
/// in `detached` mode carry [`VendorEntry::detached`] plus an embedded copy
/// of their record, so revert/verify/VEX work without a manifest entry.
///
/// Does NOT lock, read the manifest, or print the envelope — callers own all
/// three. Returns whether any non-benign failure occurred.
pub(crate) async fn vendor_records(
    common: &GlobalArgs,
    records: &HashMap<String, PatchRecord>,
    sources: &PatchSources<'_>,
    detached: bool,
    force: bool,
    env: &mut Envelope,
) -> bool {
    let mut has_errors = false;
    let manifest_purls: Vec<String> = records.keys().cloned().collect();
    let partitioned = partition_purls(&manifest_purls, common.ecosystems.as_deref());
    let target_manifest_purls: HashSet<String> = partitioned
        .values()
        .flat_map(|p| p.iter().cloned())
        .collect();

    // Purls with no vendor backend (maven/nuget/jsr, or compiled-out
    // ecosystems) are expected skips, not failures.
    let (vendorable, unsupported): (Vec<String>, Vec<String>) = target_manifest_purls
        .iter()
        .cloned()
        .partition(|p| vendor::is_vendorable(p));
    for purl in &unsupported {
        env.record(
            PatchEvent::new(PatchAction::Skipped, purl.clone()).with_reason(
                "vendor_unsupported_ecosystem",
                "vendoring is not supported for this ecosystem",
            ),
        );
    }

    if vendorable.is_empty() {
        if !common.json && !common.silent {
            println!("No vendorable patches in scope.");
        }
        return has_errors;
    }

    let vendorable_partition: HashMap<Ecosystem, Vec<String>> = partitioned
        .into_iter()
        .map(|(eco, purls)| {
            (
                eco,
                purls
                    .into_iter()
                    .filter(|p| vendor::is_vendorable(p))
                    .collect(),
            )
        })
        .collect();

    let crawler_options = CrawlerOptions {
        cwd: common.cwd.clone(),
        global: common.global,
        global_prefix: common.global_prefix.clone(),
        batch_size: 100,
    };
    let all_packages = find_packages_for_purls(
        &vendorable_partition,
        &crawler_options,
        common.silent || common.json,
    )
    .await;

    let vendored_at = now_rfc3339();
    let mut state = match load_state(&common.cwd).await {
        Ok(s) => s,
        Err(e) => {
            env.mark_error(EnvelopeError::new("vendor_state_unreadable", e.to_string()));
            return true;
        }
    };

    // Release-variant grouping (pypi `?artifact_id=`, gem `?platform=`):
    // the crawler emits base purls; match the manifest's qualified variants
    // against the installed distribution via the first-file probe.
    let mut variant_groups: HashMap<String, Vec<String>> = HashMap::new();
    for purl in &vendorable {
        if Ecosystem::from_purl(purl).is_some_and(|e| e.supports_release_variants()) {
            variant_groups
                .entry(strip_purl_qualifiers(purl).to_string())
                .or_default()
                .push(purl.clone());
        }
    }

    let mut matched: HashSet<String> = HashSet::new();
    let mut handled_bases: HashSet<String> = HashSet::new();

    for (purl, pkg_path) in &all_packages {
        let is_variant_eco =
            Ecosystem::from_purl(purl).is_some_and(|e| e.supports_release_variants());
        let candidates: Vec<String> = if is_variant_eco {
            let base = strip_purl_qualifiers(purl).to_string();
            if !handled_bases.insert(base.clone()) {
                continue;
            }
            variant_groups
                .get(&base)
                .cloned()
                .unwrap_or_else(|| vec![base])
        } else {
            vec![purl.clone()]
        };

        for candidate in &candidates {
            let Some(record) = records.get(candidate) else {
                continue;
            };

            // Variant probe: only the installed distribution's variant is
            // vendored (mirrors apply / select_installed_variants).
            if is_variant_eco && !force {
                let first = match record.files.iter().next() {
                    Some((f, info)) => Some(verify_file_patch(pkg_path, f, info).await.status),
                    None => None,
                };
                if !variant_matches_installed(first.as_ref()) {
                    continue;
                }
            }
            matched.insert(candidate.clone());

            let outcome = dispatch_vendor_one(
                candidate,
                pkg_path,
                &common.cwd,
                record,
                sources,
                &vendored_at,
                common.dry_run,
                force,
            )
            .await;

            match outcome {
                None => {
                    env.record(
                        PatchEvent::new(PatchAction::Skipped, candidate.clone()).with_reason(
                            "vendor_unsupported_ecosystem",
                            "vendoring is not supported for this ecosystem",
                        ),
                    );
                }
                Some(VendorOutcome::Refused { code, detail }) => {
                    if refusal_is_benign(code) {
                        env.record(
                            PatchEvent::new(PatchAction::Skipped, candidate.clone())
                                .with_reason(code, detail.clone()),
                        );
                    } else {
                        has_errors = true;
                        env.record(
                            PatchEvent::new(PatchAction::Failed, candidate.clone())
                                .with_error(code, detail.clone()),
                        );
                    }
                    if !common.silent && !common.json {
                        eprintln!("Cannot vendor {candidate}: {detail}");
                    }
                }
                Some(VendorOutcome::Done {
                    result,
                    entry,
                    warnings,
                }) => {
                    if !result.success {
                        has_errors = true;
                        if !common.silent && !common.json {
                            eprintln!(
                                "Failed to vendor {}: {}",
                                candidate,
                                result.error.as_deref().unwrap_or("unknown error")
                            );
                        }
                    }
                    let mut event = result_to_event(&result, common.dry_run);
                    // The shared translator's in-sync classification reads
                    // `already_patched`; under `vendor` the contract tag is
                    // `already_vendored` (artifact + wiring already in sync).
                    if event.action == PatchAction::Skipped
                        && event.error_code.as_deref() == Some("already_patched")
                    {
                        event = PatchEvent::new(PatchAction::Skipped, candidate.clone())
                            .with_reason(
                                "already_vendored",
                                "artifact and lockfile wiring already in sync",
                            );
                    }
                    env.record(event);
                    for w in &warnings {
                        record_warning(env, candidate, w, common);
                    }
                    if let Some(mut entry) = entry {
                        entry.detached = detached;
                        entry.record = detached.then(|| record.clone());
                        // A re-vendor run re-derives the entry from current
                        // disk state, where the takeover already happened —
                        // preserve the prior flag or the revert-time
                        // "takeover_not_restored" hint is lost.
                        let prev = state.entries.get(candidate).cloned();
                        if let Some(prev) = &prev {
                            entry.took_over_go_patches =
                                entry.took_over_go_patches || prev.took_over_go_patches;
                            // A re-vendor (new patch uuid) rewrites our own
                            // stale wiring, so the backend records
                            // `original: None` (it must never record a
                            // dangling `.socket/vendor/` pointer as the
                            // pre-vendor fragment). The TRUE pre-vendor
                            // original lives in the entry being replaced —
                            // carry it forward by wiring identity, or a
                            // later `--revert` can only shrug
                            // (`vendor_lock_entry_drifted`) instead of
                            // restoring the registry fragment.
                            for rec in &mut entry.wiring {
                                if rec.action
                                    == socket_patch_core::patch::vendor::state::WiringAction::Rewritten
                                    && rec.original.is_none()
                                {
                                    if let Some(prev_rec) = prev.wiring.iter().find(|p| {
                                        p.file == rec.file
                                            && p.kind == rec.kind
                                            && p.key == rec.key
                                    }) {
                                        rec.original = prev_rec.original.clone();
                                    }
                                }
                            }
                        }
                        let new_uuid = entry.uuid.clone();
                        state.entries.insert(candidate.clone(), entry);
                        // Persist per-package so a crash mid-run leaves a
                        // ledger that matches what's already wired.
                        if let Err(e) = save_state(&common.cwd, &state).await {
                            has_errors = true;
                            env.record(
                                PatchEvent::new(PatchAction::Failed, candidate.clone())
                                    .with_error("vendor_state_write_failed", e.to_string()),
                            );
                        } else if let Some(prev) = prev.filter(|p| p.uuid != new_uuid) {
                            // Re-vendor under a newer patch uuid: the old
                            // uuid's dir is an orphan now — the wiring and
                            // ledger both point at the new uuid — unless
                            // another entry still shares it (the same
                            // `(eco, uuid)` ownership test as `--revert`'s
                            // orphan sweep). Only the live entry would
                            // otherwise reclaim it, and that never happens.
                            let still_referenced = state.entries.values().any(|e| {
                                e.ecosystem == prev.ecosystem && e.uuid == prev.uuid
                            });
                            let stale_rel = vendor::path::vendor_uuid_dir_rel(
                                &prev.ecosystem,
                                &prev.uuid,
                            );
                            if let Some(rel) = stale_rel.filter(|_| !still_referenced) {
                                if !common.dry_run {
                                    let _ = remove_tree(&common.cwd.join(rel)).await;
                                }
                                env.record(
                                    PatchEvent::new(PatchAction::Removed, candidate.clone())
                                        .with_reason(
                                            "vendor_stale_artifact_removed",
                                            "previous patch uuid's vendored artifact removed",
                                        ),
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    // Manifest entries that targeted in-scope ecosystems but had no
    // installed package on disk.
    let mut unmatched: Vec<String> = vendorable
        .iter()
        .filter(|p| !matched.contains(*p))
        .cloned()
        .collect();
    unmatched.sort();
    // A base that vendored one variant accounts for its qualified siblings.
    let vendored_bases: HashSet<String> = matched
        .iter()
        .map(|p| strip_purl_qualifiers(p).to_string())
        .collect();
    unmatched.retain(|p| !vendored_bases.contains(strip_purl_qualifiers(p)));
    if !unmatched.is_empty() {
        has_errors = true;
        for purl in &unmatched {
            env.record(
                PatchEvent::new(PatchAction::Skipped, purl.clone())
                    .with_reason("package_not_installed", "no installed package found"),
            );
            if !common.silent && !common.json {
                eprintln!("Cannot vendor {purl}: package not installed");
            }
        }
    }

    if !common.json && !common.silent {
        let verb = if common.dry_run {
            "Would vendor"
        } else {
            "Vendored"
        };
        println!(
            "{verb} {} package(s); {} skipped; {} failed.",
            env.summary.applied, env.summary.skipped, env.summary.failed
        );
        if env.summary.applied > 0 && !common.dry_run {
            println!(
                "Commit .socket/vendor/ and the updated lockfiles to make the patches portable."
            );
        }
    }

    has_errors
}

/// Revert vendored entries whose patches were dropped from the manifest.
/// Shared with `scan --vendor` (which runs the same engine in-process).
pub(crate) async fn reconcile_dropped(
    manifest: &PatchManifest,
    common: &GlobalArgs,
    env: &mut Envelope,
) -> bool {
    let mut state = match load_state(&common.cwd).await {
        Ok(s) => s,
        Err(_) => return false, // unreadable state is reported by the main path
    };
    // Respect this run's --ecosystems scope: a `vendor --ecosystems npm`
    // invocation must not silently revert a cargo/go entry (restoring its
    // lockfile and deleting its artifact) as a cross-ecosystem side effect.
    let in_scope = |eco: &str| match common.ecosystems.as_deref() {
        None => true,
        Some(list) => list.iter().any(|e| {
            e.eq_ignore_ascii_case(eco) || (eco == "golang" && e.eq_ignore_ascii_case("go"))
        }),
    };
    let stale: Vec<String> = state
        .entries
        .iter()
        .filter(|(purl, entry)| {
            // Detached entries (`scan --vendor --detached`) are never
            // manifest-tracked, so "absent from the manifest" is their
            // normal state, not a drop — only `vendor --revert` or
            // `remove` may undo them.
            !entry.detached
                && in_scope(&entry.ecosystem)
                && !manifest.patches.contains_key(*purl)
                && !manifest.patches.contains_key(&entry.base_purl)
        })
        .map(|(purl, _)| purl.clone())
        .collect();
    let mut had_error = false;
    for purl in stale {
        let entry = state.entries.get(&purl).cloned().expect("listed above");
        let outcome = dispatch_revert_one(&entry, &common.cwd, common.dry_run).await;
        for w in &outcome.warnings {
            record_warning(env, &purl, w, common);
        }
        if outcome.success {
            env.record(
                PatchEvent::new(PatchAction::Removed, purl.clone())
                    .with_reason("vendor_reconciled", "patch no longer in manifest"),
            );
            if !common.dry_run {
                state.entries.remove(&purl);
            }
        } else {
            had_error = true;
            env.record(
                PatchEvent::new(PatchAction::Failed, purl.clone()).with_error(
                    "revert_failed",
                    outcome.error.unwrap_or_else(|| "unknown error".into()),
                ),
            );
        }
    }
    if !common.dry_run {
        let _ = save_state(&common.cwd, &state).await;
    }
    had_error
}

async fn run_revert(args: &VendorArgs, env: &mut Envelope) -> i32 {
    let common = &args.common;
    let mut state = match load_state(&common.cwd).await {
        Ok(s) => s,
        Err(e) => {
            env.mark_error(EnvelopeError::new("vendor_state_unreadable", e.to_string()));
            if !common.json && !common.silent {
                eprintln!("Error: could not read .socket/vendor/state.json: {e}");
            }
            return 1;
        }
    };

    let mut has_errors = false;
    let recorded: Vec<String> = {
        let mut keys: Vec<String> = state.entries.keys().cloned().collect();
        keys.sort();
        keys
    };

    for purl in &recorded {
        let entry = state.entries.get(purl).cloned().expect("key listed above");
        let outcome = dispatch_revert_one(&entry, &common.cwd, common.dry_run).await;
        for w in &outcome.warnings {
            record_warning(env, purl, w, common);
        }
        if outcome.success {
            env.record(PatchEvent::new(PatchAction::Removed, purl.clone()));
            if !common.dry_run {
                state.entries.remove(purl);
                if let Err(e) = save_state(&common.cwd, &state).await {
                    has_errors = true;
                    env.record(
                        PatchEvent::new(PatchAction::Failed, purl.clone())
                            .with_error("vendor_state_write_failed", e.to_string()),
                    );
                }
            }
        } else {
            has_errors = true;
            env.record(
                PatchEvent::new(PatchAction::Failed, purl.clone()).with_error(
                    "revert_failed",
                    outcome.error.unwrap_or_else(|| "unknown error".into()),
                ),
            );
            if !common.silent && !common.json {
                eprintln!("Failed to revert {purl}");
            }
        }
    }

    // Orphan sweep: uuid dirs on disk with no ledger entry (a hand-edited
    // state file, or artifacts left by an interrupted run). The lockfile
    // wiring for these is already gone or owned by a recorded entry, so
    // removal is safe; unparseable dirs are reported, never deleted.
    let swept = vendor::path::sweep_vendor_dirs(&common.cwd).await;
    let recorded_units: HashSet<(&str, &str)> = state
        .entries
        .values()
        .map(|e| (e.ecosystem.as_str(), e.uuid.as_str()))
        .collect();
    for unit in swept {
        if recorded_units.contains(&(unit.eco.as_str(), unit.uuid.as_str())) {
            continue;
        }
        if !common.dry_run {
            let _ = remove_tree(&unit.dir).await;
        }
        let label = unit
            .purls
            .first()
            .cloned()
            .unwrap_or_else(|| format!("{}/{}", unit.eco, unit.uuid));
        env.record(
            PatchEvent::new(PatchAction::Removed, label)
                .with_reason("vendor_orphan_removed", "vendored dir had no ledger entry"),
        );
    }

    if env.events.is_empty() {
        if !common.json && !common.silent {
            println!("Nothing vendored to revert.");
        }
        return 0;
    }

    if !common.json && !common.silent {
        let verb = if common.dry_run {
            "Would revert"
        } else {
            "Reverted"
        };
        println!(
            "{verb} {} vendored package(s); {} failed.",
            env.summary.removed, env.summary.failed
        );
    }

    if has_errors {
        env.mark_partial_failure();
        1
    } else {
        0
    }
}
