use clap::Args;
use socket_patch_core::api::blob_fetcher::{fetch_blobs_by_hash, format_fetch_result};
use socket_patch_core::api::client::get_api_client_with_overrides;
use socket_patch_core::crawlers::CrawlerOptions;
use socket_patch_core::manifest::operations::{get_before_hash_blobs, read_manifest};
use socket_patch_core::manifest::schema::{PatchFileInfo, PatchManifest, PatchRecord};
use socket_patch_core::patch::apply::select_installed_variants;
use socket_patch_core::patch::rollback::{
    rollback_package_patch, RollbackResult, VerifyRollbackStatus,
};
use socket_patch_core::utils::purl::strip_purl_qualifiers;
use socket_patch_core::utils::telemetry::{track_patch_rollback_failed, track_patch_rolled_back};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::args::{apply_env_toggles, parse_bool_flag, GlobalArgs};
use crate::commands::apply::is_local_go;
use crate::commands::lock_cli::{acquire_or_emit, LOCK_BROKEN_CODE};
use crate::commands::remove::patch_matches;
use crate::ecosystem_dispatch::{find_packages_for_rollback, partition_purls};
use crate::json_envelope::Command as EnvelopeCommand;

#[derive(Args)]
pub struct RollbackArgs {
    /// Package PURL or patch UUID to rollback. Omit to rollback all patches.
    pub identifier: Option<String>,

    #[command(flatten)]
    pub common: GlobalArgs,

    /// Rollback a patch by fetching beforeHash blobs from API (no manifest required).
    ///
    /// `value_parser = parse_bool_flag` matches the `GlobalArgs` bool flags:
    /// clap's default bool parser accepts only the literal strings
    /// `true`/`false` from the env binding, so `SOCKET_ONE_OFF=1` (or an
    /// exported-but-empty `SOCKET_ONE_OFF=`) aborted every `rollback`
    /// invocation. This flag is also outside `GLOBAL_ARG_ENV_VARS`, so
    /// `main`'s empty-var scrub never rescues it.
    #[arg(
        long = "one-off",
        env = "SOCKET_ONE_OFF",
        default_value_t = false,
        value_parser = parse_bool_flag,
    )]
    pub one_off: bool,
}

struct PatchToRollback {
    purl: String,
    patch: PatchRecord,
}

// ── local-redirect rollback helpers (go only) ────────────────────────────────
// Local go rolls back by dropping the project-local redirect (go's `replace`
// directive) + the patched copy — no in-place restore, no before-blob. Cargo
// patches in place (vendored or registry cache), so it rolls back in place from
// before-blobs like npm/pypi. The helper is an inert stub without `golang`.
// `is_local_go` is shared with `apply`, which creates the same redirects.

/// True when `purl` rolls back by dropping a project-local redirect (local-mode
/// go) rather than restoring bytes from a before-blob. The before-blob gate uses
/// this to skip those PURLs — they read no blobs, so a missing before-blob must
/// not block (or trigger a needless download for) an offline redirect rollback.
fn is_local_redirect(purl: &str, common: &GlobalArgs) -> bool {
    if is_local_go(purl, common) {
        return true;
    }
    let _ = (purl, common);
    false
}

/// Copy of `manifest` with local-redirect PURLs (local-mode go) removed — used
/// for the before-blob gate, which those PURLs never need. Avoids blocking an
/// offline redirect rollback on absent blobs.
fn exclude_local_redirects(manifest: &PatchManifest, common: &GlobalArgs) -> PatchManifest {
    PatchManifest {
        patches: manifest
            .patches
            .iter()
            .filter(|(purl, _)| !is_local_redirect(purl, common))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        setup: manifest.setup.clone(),
    }
}

/// Roll back a local-go redirect (drop the `go.mod` `replace` directive + the
/// patched copy under `.socket/go-patches/`), or `None` if `purl` isn't a
/// local-go target (caller falls back to in-place rollback). The module cache
/// is left pristine by the redirect, so there is no before-blob to restore;
/// mirrors apply's `try_local_go_apply`. Go has no `vendor/` fallthrough (apply
/// always redirects local go), so there is no vendored discriminator here.
async fn try_rollback_local_go(
    purl: &str,
    pkg_path: &Path,
    patch: &PatchRecord,
    common: &GlobalArgs,
) -> Option<RollbackResult> {
    use socket_patch_core::patch::go_mod_edit::{ReplaceOwner, GO_PATCHES_DIR};
    use socket_patch_core::patch::go_redirect::remove_go_redirect;
    if !is_local_go(purl, common) {
        return None;
    }
    let mut result = RollbackResult {
        package_key: purl.to_string(),
        package_path: pkg_path.display().to_string(),
        success: true,
        files_verified: Vec::new(),
        // The engine leaves `files_rolled_back` empty on dry-run (verify
        // only); match it so the JSON `rolledBack` count never claims a dry
        // run mutated anything.
        files_rolled_back: if common.dry_run {
            Vec::new()
        } else {
            patch.files.keys().cloned().collect()
        },
        error: None,
        // The go redirect leaves the module cache pristine — no in-place
        // bytes changed, so there is no sidecar state to resync.
        sidecar: None,
    };
    if let Err(e) = remove_go_redirect(
        purl,
        &common.cwd,
        GO_PATCHES_DIR,
        ReplaceOwner::GoPatches,
        common.dry_run,
    )
    .await
    {
        result.success = false;
        result.files_rolled_back.clear();
        result.error = Some(e.to_string());
    }
    Some(result)
}

fn find_patches_to_rollback(
    manifest: &PatchManifest,
    identifier: Option<&str>,
) -> Vec<PatchToRollback> {
    manifest
        .patches
        .iter()
        .filter(|(purl, patch)| identifier.is_none_or(|id| patch_matches(purl, &patch.uuid, id)))
        .map(|(purl, patch)| PatchToRollback {
            purl: purl.clone(),
            patch: patch.clone(),
        })
        .collect()
}

async fn get_missing_before_blobs(manifest: &PatchManifest, blobs_path: &Path) -> HashSet<String> {
    let before_blobs = get_before_hash_blobs(manifest);
    let mut missing = HashSet::new();
    for hash in before_blobs {
        let blob_path = blobs_path.join(&hash);
        if tokio::fs::metadata(&blob_path).await.is_err() {
            missing.insert(hash);
        }
    }
    missing
}

fn verify_rollback_status_str(status: &VerifyRollbackStatus) -> &'static str {
    match status {
        VerifyRollbackStatus::Ready => "ready",
        VerifyRollbackStatus::AlreadyOriginal => "already_original",
        VerifyRollbackStatus::HashMismatch => "hash_mismatch",
        VerifyRollbackStatus::NotFound => "not_found",
        VerifyRollbackStatus::MissingBlob => "missing_blob",
    }
}

/// True when every file the engine verified for this package is already
/// at its original (`beforeHash`) state — i.e. the rollback is a complete
/// no-op on disk.
///
/// This is the rollback-side mirror of apply's `all_files_already_patched`.
/// The `!is_empty()` guard is essential: `Iterator::all` over an empty
/// slice is vacuously `true`. Without it a result with no verified files
/// — a zero-file patch record, or a result whose `files_verified` came
/// back empty — would be mislabeled "already original" and miscounted as
/// a no-op even though nothing matched `beforeHash`.
pub(crate) fn all_files_already_original(result: &RollbackResult) -> bool {
    !result.files_verified.is_empty()
        && result
            .files_verified
            .iter()
            .all(|f| f.status == VerifyRollbackStatus::AlreadyOriginal)
}

/// Number of packages that have files which actually need restoring,
/// used by the dry-run summary. Successful-but-already-original packages
/// are no-ops reported on their own line, so they are excluded here —
/// mirroring apply's dry-run split — to avoid double-counting them
/// against "can be rolled back".
fn can_rollback_count(results: &[RollbackResult]) -> usize {
    let successful = results.iter().filter(|r| r.success).count();
    let already_original = results
        .iter()
        .filter(|r| r.success && all_files_already_original(r))
        .count();
    successful.saturating_sub(already_original)
}

fn result_to_json(result: &RollbackResult) -> serde_json::Value {
    serde_json::json!({
        "purl": result.package_key,
        "path": result.package_path,
        "success": result.success,
        "error": result.error,
        "filesRolledBack": result.files_rolled_back,
        // Rollback-side sidecar resync record (e.g. cargo's
        // `.cargo-checksum.json` rewritten back to original hashes), or
        // an error-severity advisory when the resync failed. Null when
        // no sidecar applied — same serialization as `error` above.
        "sidecar": result.sidecar,
        "filesVerified": result.files_verified.iter().map(|f| {
            serde_json::json!({
                "file": f.file,
                "status": verify_rollback_status_str(&f.status),
                "message": f.message,
                "currentHash": f.current_hash,
                "expectedHash": f.expected_hash,
                "targetHash": f.target_hash,
            })
        }).collect::<Vec<_>>(),
    })
}

pub async fn run(args: RollbackArgs) -> i32 {
    apply_env_toggles(&args.common);

    // Bail on the unimplemented flag BEFORE constructing the API client:
    // client construction can auto-resolve the org slug over the network,
    // and the contract promises the one-off stub fails before any network
    // or disk activity.
    if args.one_off {
        let msg = if args.identifier.is_none() {
            "--one-off requires an identifier (UUID or PURL)"
        } else {
            "One-off rollback mode is not yet implemented"
        };
        if args.common.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "status": "error",
                    "error": msg,
                }))
                .unwrap()
            );
        } else {
            eprintln!("Error: {msg}");
        }
        return 1;
    }

    let (telemetry_client, _) =
        get_api_client_with_overrides(args.common.api_client_overrides()).await;
    let api_token = telemetry_client.api_token().cloned();
    let org_slug = telemetry_client.org_slug().cloned();

    let manifest_path = args.common.resolved_manifest_path();

    if tokio::fs::metadata(&manifest_path).await.is_err() {
        if args.common.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "status": "error",
                    "error": "Manifest not found",
                    "path": manifest_path.display().to_string(),
                }))
                .unwrap()
            );
        } else {
            // Errors print even under --silent ("errors only", never
            // "nothing"): exit 1 with no message would be undiagnosable.
            eprintln!("Manifest not found at {}", manifest_path.display());
        }
        return 1;
    }

    // Serialize against concurrent socket-patch runs targeting the
    // same `.socket/` directory. See
    // `socket_patch_core::patch::apply_lock`.
    let socket_dir = manifest_path.parent().unwrap_or(Path::new("."));
    let acquired = match acquire_or_emit(
        socket_dir,
        EnvelopeCommand::Rollback,
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

    match rollback_patches_inner(&args, &manifest_path).await {
        Ok((success, results, vendored)) => {
            let rolled_back_count = results
                .iter()
                .filter(|r| r.success && !r.files_rolled_back.is_empty())
                .count();
            let already_original_count = results
                .iter()
                .filter(|r| r.success && all_files_already_original(r))
                .count();
            let failed_count = results.iter().filter(|r| !r.success).count();

            if args.common.json {
                // `warnings` carries non-fatal audit info — currently
                // just the `lock_broken` notice when --break-lock fired.
                // Empty array stays present in the JSON shape so
                // consumers can rely on `.warnings[]` without
                // null-checking.
                let mut warnings = Vec::new();
                if lock_was_broken {
                    warnings.push(serde_json::json!({
                        "code": LOCK_BROKEN_CODE,
                        "message": format!(
                            "--break-lock reclaimed stale {}/apply.lock (no live holder)",
                            socket_dir.display()
                        ),
                    }));
                }
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "status": if success { "success" } else { "partial_failure" },
                        "rolledBack": rolled_back_count,
                        "alreadyOriginal": already_original_count,
                        "failed": failed_count,
                        "dryRun": args.common.dry_run,
                        "warnings": warnings,
                        // Vendor-owned purls excluded from in-place rollback
                        // (benign — `remove` or `vendor --revert` undo them).
                        "vendored": vendored,
                        "results": results.iter().map(result_to_json).collect::<Vec<_>>(),
                    }))
                    .unwrap()
                );
            } else if !args.common.silent && !results.is_empty() {
                let rolled_back: Vec<_> = results
                    .iter()
                    .filter(|r| r.success && !r.files_rolled_back.is_empty())
                    .collect();
                let already_original: Vec<_> = results
                    .iter()
                    .filter(|r| r.success && all_files_already_original(r))
                    .collect();
                let failed: Vec<_> = results.iter().filter(|r| !r.success).collect();

                if args.common.dry_run {
                    println!("\nRollback verification complete:");
                    // Exclude already-original packages — they are
                    // reported separately just below, so counting them
                    // here too would double-report each no-op.
                    let can_rollback = can_rollback_count(&results);
                    println!("  {can_rollback} package(s) can be rolled back");
                    if !already_original.is_empty() {
                        println!(
                            "  {} package(s) already in original state",
                            already_original.len()
                        );
                    }
                    if !failed.is_empty() {
                        println!("  {} package(s) cannot be rolled back", failed.len());
                    }
                } else {
                    if !rolled_back.is_empty() || !already_original.is_empty() {
                        println!("\nRolled back packages:");
                        for result in &rolled_back {
                            println!("  {}", result.package_key);
                        }
                        for result in &already_original {
                            println!("  {} (already original)", result.package_key);
                        }
                    }
                    if !failed.is_empty() {
                        println!("\nFailed to rollback:");
                        for result in &failed {
                            println!(
                                "  {}: {}",
                                result.package_key,
                                result.error.as_deref().unwrap_or("unknown error")
                            );
                        }
                    }
                }

                if args.common.verbose {
                    println!("\nDetailed verification:");
                    for result in &results {
                        println!("  {}:", result.package_key);
                        for f in &result.files_verified {
                            // Same labels as the JSON status strings, with the
                            // underscores humanized (`already_original` →
                            // `already original`).
                            let status_str =
                                verify_rollback_status_str(&f.status).replace('_', " ");
                            println!("    {} [{}]", f.file, status_str);
                            if let Some(ref msg) = f.message {
                                println!("      message: {msg}");
                            }
                            if let Some(ref h) = f.current_hash {
                                println!("      current:  {h}");
                            }
                            if let Some(ref h) = f.expected_hash {
                                println!("      expected: {h}");
                            }
                            if let Some(ref h) = f.target_hash {
                                println!("      target:   {h}");
                            }
                        }
                    }
                }
            }

            if !args.common.json && !args.common.silent && !vendored.is_empty() {
                println!(
                    "\n{} vendored package(s) skipped (managed by socket-patch vendor; \
                     use `remove` or `vendor --revert`):",
                    vendored.len()
                );
                for purl in &vendored {
                    println!("  {purl}");
                }
            }

            if success {
                track_patch_rolled_back(
                    rolled_back_count,
                    api_token.as_deref(),
                    org_slug.as_deref(),
                )
                .await;
            } else {
                track_patch_rollback_failed(
                    "One or more rollbacks failed",
                    api_token.as_deref(),
                    org_slug.as_deref(),
                )
                .await;
            }

            if success {
                0
            } else {
                1
            }
        }
        Err(e) => {
            track_patch_rollback_failed(&e, api_token.as_deref(), org_slug.as_deref()).await;
            if args.common.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "status": "error",
                        "error": e,
                        "rolledBack": 0,
                        "alreadyOriginal": 0,
                        "failed": 0,
                        "dryRun": args.common.dry_run,
                        "vendored": [],
                        "results": [],
                    }))
                    .unwrap()
                );
            } else {
                // Errors print even under --silent ("errors only", never
                // "nothing"): exit 1 with no message would be undiagnosable.
                eprintln!("Error: {e}");
            }
            1
        }
    }
}

async fn rollback_patches_inner(
    args: &RollbackArgs,
    manifest_path: &Path,
) -> Result<(bool, Vec<RollbackResult>, Vec<String>), String> {
    let manifest = read_manifest(manifest_path)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "Invalid manifest".to_string())?;

    let socket_dir = manifest_path.parent().unwrap();
    let mut blobs_path = socket_dir.join("blobs");
    // `--dry-run` must not mutate `.socket/` ("Preview, no mutations"):
    // don't create the blobs dir; a throwaway stage replaces it below.
    if !args.common.dry_run {
        tokio::fs::create_dir_all(&blobs_path)
            .await
            .map_err(|e| e.to_string())?;
    }

    let patches_to_rollback = find_patches_to_rollback(&manifest, args.identifier.as_deref());

    if patches_to_rollback.is_empty() {
        if args.identifier.is_some() {
            return Err(format!(
                "No patch found matching identifier: {}",
                args.identifier.as_deref().unwrap()
            ));
        }
        if !args.common.silent && !args.common.json {
            println!("No patches found in manifest");
        }
        return Ok((true, Vec::new(), Vec::new()));
    }

    // Vendor-owned purls are excluded from in-place rollback: their patch
    // lives in the committed `.socket/vendor/` artifact + lock wiring, not
    // in the installed tree, so before-blob restoration is meaningless
    // there (and would only hash-mismatch). `remove` reverts vendoring;
    // `vendor --revert` undoes it wholesale. Matching mirrors apply's
    // ledger-key / base-purl / qualifier-stripped triple; unreadable state
    // degrades to "nothing vendored".
    let vendored_keys =
        socket_patch_core::patch::vendor::vendored_purl_keys(&args.common.cwd).await;
    let is_vendored =
        |p: &str| vendored_keys.contains(p) || vendored_keys.contains(strip_purl_qualifiers(p));
    let (vendored_targets, patches_to_rollback): (Vec<_>, Vec<_>) = patches_to_rollback
        .into_iter()
        .partition(|p| is_vendored(&p.purl));
    let mut vendored_skipped: Vec<String> = vendored_targets.into_iter().map(|p| p.purl).collect();
    vendored_skipped.sort();
    if patches_to_rollback.is_empty() {
        // Everything targeted is vendor-owned: a benign skip, not an error
        // (and not `not_found` — the identifier did match).
        return Ok((true, Vec::new(), vendored_skipped));
    }

    // Create filtered manifest (a synthetic rollback-target subset, never
    // written to disk, so it carries no persisted setup state).
    let filtered_manifest = PatchManifest {
        patches: patches_to_rollback
            .iter()
            .map(|p| (p.purl.clone(), p.patch.clone()))
            .collect(),
        setup: None,
    };

    // Partition PURLs by ecosystem up front. The before-blob gate and the
    // download below must only consider patches this run can actually roll
    // back — the `--ecosystems` filter. An out-of-scope patch with an
    // absent before-blob must not abort
    // (or trigger fetches for) a run that will never restore it. Mirrors
    // apply's `scoped_manifest`.
    let rollback_purls: Vec<String> = patches_to_rollback.iter().map(|p| p.purl.clone()).collect();
    let partitioned = partition_purls(&rollback_purls, args.common.ecosystems.as_deref());
    let in_scope: HashSet<String> = partitioned
        .values()
        .flat_map(|purls| purls.iter().cloned())
        .collect();
    let mut scoped_manifest = filtered_manifest.clone();
    scoped_manifest
        .patches
        .retain(|purl, _| in_scope.contains(purl));

    // Check for missing beforeHash blobs. Local-redirect PURLs (local-mode go)
    // are excluded: their rollback just drops the project-local redirect + copy
    // and reads no blobs, so a missing before-blob must not block an offline
    // redirect rollback.
    let gate_manifest = exclude_local_redirects(&scoped_manifest, &args.common);

    // `--dry-run`: verification needs real blob content for an accurate
    // preview, but the preview must not leave new files in the committable
    // `.socket/blobs` (a wet run's sweep would have removed them) — so stage
    // blob reads in a throwaway sibling dir: hardlink (or copy) the
    // already-cached before-blobs in, and let any download below land there
    // too. `tempdir_in(socket_dir)` keeps it on the same filesystem for
    // hardlinks and is auto-removed on drop, like the `.socket-stage-*`
    // atomic-write siblings.
    let _dry_run_blob_stage: Option<tempfile::TempDir> = if args.common.dry_run {
        let stage = tempfile::Builder::new()
            .prefix(".socket-stage-dryrun-blobs-")
            .tempdir_in(socket_dir)
            .map_err(|e| e.to_string())?;
        let staged_path = stage.path().to_path_buf();
        for patch in gate_manifest.patches.values() {
            for info in patch.files.values() {
                if info.before_hash.is_empty() {
                    continue; // created-by-patch marker: no blob to read
                }
                let src = blobs_path.join(&info.before_hash);
                let dst = staged_path.join(&info.before_hash);
                if tokio::fs::metadata(&src).await.is_ok()
                    && !dst.exists()
                    && tokio::fs::hard_link(&src, &dst).await.is_err()
                {
                    let _ = tokio::fs::copy(&src, &dst).await;
                }
            }
        }
        blobs_path = staged_path;
        Some(stage)
    } else {
        None
    };

    let missing_blobs = get_missing_before_blobs(&gate_manifest, &blobs_path).await;
    if !missing_blobs.is_empty() {
        if args.common.offline {
            // Errors print even under --silent ("errors only", never
            // "nothing"): this bail is the run's ONLY diagnostic — the JSON
            // envelope carries a contentless partial_failure.
            if !args.common.json {
                eprintln!(
                    "Error: {} blob(s) are missing and --offline mode is enabled.",
                    missing_blobs.len()
                );
                eprintln!("Run \"socket-patch repair\" to download missing blobs.");
            }
            return Ok((false, Vec::new(), vendored_skipped));
        }

        if !args.common.silent && !args.common.json {
            println!("Downloading {} missing blob(s)...", missing_blobs.len());
        }

        let (client, _) = get_api_client_with_overrides(args.common.api_client_overrides()).await;
        let fetch_result = fetch_blobs_by_hash(&missing_blobs, &blobs_path, &client, None).await;

        if !args.common.silent && !args.common.json {
            println!("{}", format_fetch_result(&fetch_result));
        }

        // Re-check against `gate_manifest` (NOT `filtered_manifest`): the
        // download only targeted blobs from the local-go-excluded gate, so
        // local-go before-hashes must stay excluded here too. Re-checking
        // the full filtered manifest would re-introduce those never-needed
        // blobs and spuriously abort a mixed local-go rollback.
        let still_missing = get_missing_before_blobs(&gate_manifest, &blobs_path).await;
        if !still_missing.is_empty() {
            // Errors print even under --silent — same contract as the
            // offline bail above.
            if !args.common.json {
                eprintln!(
                    "{} blob(s) could not be downloaded. Cannot rollback.",
                    still_missing.len()
                );
            }
            return Ok((false, Vec::new(), vendored_skipped));
        }
    }

    let crawler_options = CrawlerOptions {
        cwd: args.common.cwd.clone(),
        global: args.common.global,
        global_prefix: args.common.global_prefix.clone(),
    };

    let all_packages = find_packages_for_rollback(
        &partitioned,
        &crawler_options,
        args.common.silent || args.common.json,
    )
    .await;

    if all_packages.is_empty() {
        if !args.common.silent && !args.common.json {
            println!("No packages found that match patches to rollback");
        }
        return Ok((true, Vec::new(), vendored_skipped));
    }

    // Group discovered packages by base PURL. A release-variant
    // `package@version` (PyPI/RubyGems/Maven) may have several variants
    // in the manifest that `merge_qualified` resolves to the same
    // installed package dir. Rolling back a variant that is *not* present
    // on disk would HashMismatch and report a spurious failure, so —
    // mirroring apply — we collapse each group to the variant(s) whose
    // hashes actually match the installed bytes. PyPI/RubyGems yield one
    // such variant; Maven's coexisting classifier jars may yield several.
    let mut groups: HashMap<String, Vec<(&String, &PathBuf)>> = HashMap::new();
    for (purl, pkg_path) in &all_packages {
        groups
            .entry(strip_purl_qualifiers(purl).to_string())
            .or_default()
            .push((purl, pkg_path));
    }

    // Rollback patches
    let mut results: Vec<RollbackResult> = Vec::new();
    let mut has_errors = false;

    for (_base, entries) in groups {
        // Resolve which variant(s) to roll back for this base PURL.
        let to_rollback: Vec<(&String, &PathBuf)> = if entries.len() == 1 {
            entries
        } else {
            // All variants in a group resolve to the same installed path.
            let pkg_path = entries[0].1;
            let candidates: Vec<(&str, &HashMap<String, PatchFileInfo>)> = entries
                .iter()
                .filter_map(|(purl, _)| {
                    filtered_manifest
                        .patches
                        .get(*purl)
                        .map(|p| (purl.as_str(), &p.files))
                })
                .collect();
            let matched = select_installed_variants(pkg_path, &candidates).await;
            if matched.is_empty() {
                // No variant matches the installed distribution (e.g. a
                // locally-modified file). Fall back to attempting every
                // variant so the per-file verification surfaces the
                // mismatch rather than silently skipping the package.
                entries
            } else {
                let winners: HashSet<String> = matched
                    .iter()
                    .map(|&i| candidates[i].0.to_string())
                    .collect();
                entries
                    .into_iter()
                    .filter(|(p, _)| winners.contains(*p))
                    .collect()
            }
        };

        for (purl, pkg_path) in to_rollback {
            let patch = match filtered_manifest.patches.get(purl) {
                Some(p) => p,
                None => continue,
            };

            // Local go drops the project-local `replace`-redirect; everything
            // else — npm/pypi/gem and cargo (vendored or registry cache) —
            // restores in place from before-blobs.
            let result = match try_rollback_local_go(purl, pkg_path, patch, &args.common).await {
                Some(r) => r,
                None => {
                    rollback_package_patch(
                        purl,
                        pkg_path,
                        &patch.files,
                        &blobs_path,
                        args.common.dry_run,
                    )
                    .await
                }
            };

            if !result.success {
                has_errors = true;
                // Errors print even under --silent ("errors only", never
                // "nothing"): with the summary muted, this line is the
                // silent run's only failure diagnostic.
                if !args.common.json {
                    eprintln!(
                        "Failed to rollback {}: {}",
                        purl,
                        result.error.as_deref().unwrap_or("unknown error")
                    );
                }
            }
            results.push(result);
        }
    }

    Ok((!has_errors, results, vendored_skipped))
}

// Export for use by remove command. The third tuple element lists
// vendor-owned purls that were excluded from in-place rollback (benign).
//
// Takes the caller's `GlobalArgs` as the base (only the per-call fields are
// overridden): the nested missing-blob download builds its API client from
// `api_client_overrides()`, so flag-passed `--api-url` / `--api-token` /
// `--org` / `--proxy-url` must flow through. A from-scratch
// `GlobalArgs::default()` here silently dropped them — with credentials
// passed as flags the nested client was unauthenticated and pointed at the
// public proxy, so the download failed and the whole `remove` aborted with
// `rollback_failed` (see tests/remove_rollback_api_overrides.rs).
pub(crate) async fn rollback_patches(
    common: &crate::args::GlobalArgs,
    manifest_path: &Path,
    identifier: Option<&str>,
    dry_run: bool,
    silent: bool,
    ecosystems: Option<Vec<String>>,
) -> Result<(bool, Vec<RollbackResult>, Vec<String>), String> {
    let args = RollbackArgs {
        identifier: identifier.map(String::from),
        common: crate::args::GlobalArgs {
            manifest_path: manifest_path.display().to_string(),
            ecosystems,
            silent,
            dry_run,
            ..common.clone()
        },
        one_off: false,
    };
    rollback_patches_inner(&args, manifest_path).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use socket_patch_core::manifest::schema::{PatchManifest, PatchRecord};
    use std::collections::HashMap;

    fn make_record(uuid: &str) -> PatchRecord {
        PatchRecord {
            uuid: uuid.to_string(),
            exported_at: "2024-01-01T00:00:00Z".to_string(),
            files: HashMap::new(),
            vulnerabilities: HashMap::new(),
            description: "test patch".to_string(),
            license: "MIT".to_string(),
            tier: "free".to_string(),
        }
    }

    fn make_manifest() -> PatchManifest {
        let mut patches = HashMap::new();
        patches.insert("pkg:npm/foo@1.0".to_string(), make_record("uuid-foo"));
        patches.insert("pkg:npm/bar@2.0".to_string(), make_record("uuid-bar"));
        patches.insert("pkg:pypi/baz@3.0".to_string(), make_record("uuid-baz"));
        PatchManifest {
            patches,
            setup: None,
        }
    }

    #[test]
    fn test_find_patches_to_rollback_none_returns_all() {
        let manifest = make_manifest();
        let result = find_patches_to_rollback(&manifest, None);
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn test_find_patches_to_rollback_purl_match() {
        let manifest = make_manifest();
        let result = find_patches_to_rollback(&manifest, Some("pkg:npm/foo@1.0"));
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].purl, "pkg:npm/foo@1.0");
    }

    #[test]
    fn test_find_patches_to_rollback_purl_no_match() {
        let manifest = make_manifest();
        let result = find_patches_to_rollback(&manifest, Some("pkg:npm/nonexistent@1"));
        assert!(result.is_empty());
    }

    #[test]
    fn test_find_patches_to_rollback_uuid_match() {
        let manifest = make_manifest();
        let result = find_patches_to_rollback(&manifest, Some("uuid-bar"));
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].patch.uuid, "uuid-bar");
        assert_eq!(result[0].purl, "pkg:npm/bar@2.0");
    }

    #[test]
    fn test_find_patches_to_rollback_uuid_no_match() {
        let manifest = make_manifest();
        let result = find_patches_to_rollback(&manifest, Some("uuid-does-not-exist"));
        assert!(result.is_empty());
    }

    /// A manifest holding several PyPI release variants of one
    /// package@version (broad mode).
    fn make_multi_variant_manifest() -> PatchManifest {
        let mut patches = HashMap::new();
        patches.insert(
            "pkg:pypi/six@1.16.0?artifact_id=wheel-cp311".to_string(),
            make_record("uuid-wheel-cp311"),
        );
        patches.insert(
            "pkg:pypi/six@1.16.0?artifact_id=wheel-cp312".to_string(),
            make_record("uuid-wheel-cp312"),
        );
        patches.insert(
            "pkg:pypi/six@1.16.0?artifact_id=sdist".to_string(),
            make_record("uuid-sdist"),
        );
        patches.insert("pkg:npm/foo@1.0".to_string(), make_record("uuid-foo"));
        PatchManifest {
            patches,
            setup: None,
        }
    }

    #[test]
    fn test_find_patches_to_rollback_base_purl_matches_all_variants() {
        let manifest = make_multi_variant_manifest();
        let result = find_patches_to_rollback(&manifest, Some("pkg:pypi/six@1.16.0"));
        // Base PURL (no qualifier) expands to every release variant.
        assert_eq!(result.len(), 3);
        for p in &result {
            assert!(p.purl.starts_with("pkg:pypi/six@1.16.0?artifact_id="));
        }
    }

    #[test]
    fn test_find_patches_to_rollback_qualified_purl_matches_one_variant() {
        let manifest = make_multi_variant_manifest();
        let result =
            find_patches_to_rollback(&manifest, Some("pkg:pypi/six@1.16.0?artifact_id=sdist"));
        // A fully-qualified PURL targets exactly one variant.
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].purl, "pkg:pypi/six@1.16.0?artifact_id=sdist");
    }

    #[test]
    fn test_find_patches_to_rollback_base_purl_does_not_leak_other_packages() {
        let manifest = make_multi_variant_manifest();
        let result = find_patches_to_rollback(&manifest, Some("pkg:pypi/six@1.16.0"));
        assert!(result.iter().all(|p| p.purl.contains("six@1.16.0")));
    }

    // --- Summary-counting regressions -----------------------------------
    //
    // These pin the rollback summary to the same contract apply uses:
    // an "already original" result must have at least one verified file,
    // and the dry-run "can be rolled back" count must not double-report
    // packages that are already in their original state.

    use socket_patch_core::patch::rollback::VerifyRollbackResult;

    fn verified(status: VerifyRollbackStatus) -> VerifyRollbackResult {
        VerifyRollbackResult {
            file: "package/index.js".to_string(),
            status,
            message: None,
            current_hash: None,
            expected_hash: None,
            target_hash: None,
        }
    }

    /// Build a `RollbackResult` from verification statuses and the list of
    /// files reported rolled back. `success` defaults to whether every
    /// verified file is Ready/AlreadyOriginal, matching the engine.
    fn make_result(
        verified_statuses: &[VerifyRollbackStatus],
        rolled_back: &[&str],
    ) -> RollbackResult {
        let files_verified: Vec<_> = verified_statuses.iter().cloned().map(verified).collect();
        let success = files_verified.iter().all(|f| {
            f.status == VerifyRollbackStatus::Ready
                || f.status == VerifyRollbackStatus::AlreadyOriginal
        });
        RollbackResult {
            package_key: "pkg:npm/foo@1.0.0".to_string(),
            package_path: "/tmp/foo".to_string(),
            success,
            files_verified,
            files_rolled_back: rolled_back.iter().map(|s| s.to_string()).collect(),
            error: None,
            sidecar: None,
        }
    }

    #[test]
    fn all_files_already_original_true_when_every_file_matches() {
        let r = make_result(
            &[
                VerifyRollbackStatus::AlreadyOriginal,
                VerifyRollbackStatus::AlreadyOriginal,
            ],
            &[],
        );
        assert!(all_files_already_original(&r));
    }

    #[test]
    fn all_files_already_original_false_when_any_file_differs() {
        let r = make_result(
            &[
                VerifyRollbackStatus::AlreadyOriginal,
                VerifyRollbackStatus::Ready,
            ],
            &[],
        );
        assert!(!all_files_already_original(&r));
    }

    /// Regression: `Iterator::all` over an empty slice is vacuously true.
    /// A successful result with no verified files (a zero-file patch
    /// record) must NOT be reported as "already original" — the
    /// `!is_empty()` guard enforces this, matching apply.
    #[test]
    fn all_files_already_original_false_when_no_verified_files() {
        let r = make_result(&[], &[]);
        assert!(r.files_verified.is_empty());
        assert!(r.success);
        assert!(!all_files_already_original(&r));
    }

    /// Regression: the dry-run "can be rolled back" count must exclude
    /// already-original packages, which are reported on their own line.
    /// Otherwise each no-op is double-counted (once as can-rollback, once
    /// as already-original).
    #[test]
    fn can_rollback_count_excludes_already_original() {
        let results = vec![
            // Genuinely needs restoring.
            make_result(&[VerifyRollbackStatus::Ready], &[]),
            // No-op: already at beforeHash.
            make_result(&[VerifyRollbackStatus::AlreadyOriginal], &[]),
            // Mixed → still needs restoring.
            make_result(
                &[
                    VerifyRollbackStatus::Ready,
                    VerifyRollbackStatus::AlreadyOriginal,
                ],
                &[],
            ),
            // Failed (e.g. HashMismatch) → not counted as rollbackable.
            make_result(&[VerifyRollbackStatus::HashMismatch], &[]),
        ];
        // 2 successful non-no-op packages; the already-original one is
        // excluded and the failed one was never successful.
        assert_eq!(can_rollback_count(&results), 2);
    }

    /// A summary made entirely of no-ops reports zero rollbackable
    /// packages (and `saturating_sub` keeps it from underflowing).
    #[test]
    fn can_rollback_count_all_already_original_is_zero() {
        let results = vec![
            make_result(&[VerifyRollbackStatus::AlreadyOriginal], &[]),
            make_result(&[VerifyRollbackStatus::AlreadyOriginal], &[]),
        ];
        assert_eq!(can_rollback_count(&results), 0);
    }

    // --- Missing-blob gate consistency ----------------------------------
    //
    // The before-blob gate excludes local-go PURLs (redirect rollback
    // reads no blobs). Both the initial missing-blob check AND the
    // post-download re-check (`still_missing`) must run against the SAME
    // local-go-excluded gate manifest. Re-checking the full filtered
    // manifest re-introduces local-go before-hashes that were never
    // downloaded, spuriously aborting a mixed rollback.

    fn record_with_file(uuid: &str, path: &str, before_hash: &str) -> PatchRecord {
        let mut rec = make_record(uuid);
        let mut files = HashMap::new();
        files.insert(
            path.to_string(),
            PatchFileInfo {
                before_hash: before_hash.to_string(),
                after_hash: "after".to_string(),
            },
        );
        rec.files = files;
        rec
    }

    /// Regression: an empty `beforeHash` (the "file created by the patch"
    /// sentinel) is not a blob. The missing-before-blob gate must ignore it:
    /// `blobs_path.join("")` resolves to the blobs directory itself, so when
    /// the blobs dir does not exist yet (fresh checkout of a committed
    /// manifest, or a cache that was cleaned) the phantom "" counted as a
    /// missing blob -- an `--offline` rollback of a new-file-only patch
    /// aborted with "1 blob(s) are missing" even though it needs zero blobs,
    /// and an online rollback fired a pointless download of blob "".
    #[tokio::test]
    async fn missing_before_blobs_ignores_new_file_sentinel() {
        let mut patches = HashMap::new();
        patches.insert(
            "pkg:npm/foo@1.0.0".to_string(),
            record_with_file("uuid-npm", "created.js", ""),
        );
        let manifest = PatchManifest {
            patches,
            setup: None,
        };

        // Blobs dir does NOT exist (nothing ever downloaded).
        let tmp = tempfile::tempdir().unwrap();
        let blobs = tmp.path().join("blobs");

        let missing = get_missing_before_blobs(&manifest, &blobs).await;
        assert!(
            missing.is_empty(),
            "a new-file-only patch needs no before-blobs, got {missing:?}"
        );
    }

    /// Cargo now patches in place (vendored or registry cache) and rolls back
    /// by restoring from before-blobs — exactly like npm/pypi. So a cargo PURL
    /// must NOT be excluded by the before-blob gate: a missing cargo before-blob
    /// IS a real problem the gate should surface. This guards against cargo
    /// being mistakenly reclassified as a redirect again.
    #[tokio::test]
    async fn gate_manifest_keeps_cargo_before_blobs_in_missing_check() {
        let mut patches = HashMap::new();
        patches.insert(
            "pkg:cargo/serde@1.0.0".to_string(),
            record_with_file("uuid-cargo", "src/lib.rs", "cargo_before"),
        );
        patches.insert(
            "pkg:npm/foo@1.0.0".to_string(),
            record_with_file("uuid-npm", "index.js", "npm_before"),
        );
        let manifest = PatchManifest {
            patches,
            setup: None,
        };

        // Local mode (no --global / --global-prefix).
        let common = crate::args::GlobalArgs::default();
        assert!(!common.global && common.global_prefix.is_none());

        // Blobs dir holds only the npm before-blob; the cargo one is absent.
        let tmp = tempfile::tempdir().unwrap();
        let blobs = tmp.path();
        tokio::fs::write(blobs.join("npm_before"), b"x")
            .await
            .unwrap();

        // The gate must STILL report the cargo before-blob as missing — cargo
        // is an in-place rollback that genuinely needs it.
        let gate = exclude_local_redirects(&manifest, &common);
        let gate_missing = get_missing_before_blobs(&gate, blobs).await;
        assert!(
            gate_missing.contains("cargo_before"),
            "gate must keep cargo before-blobs (in-place rollback), got {gate_missing:?}"
        );
        // And the cargo PURL must not be classified as a redirect.
        assert!(!is_local_redirect("pkg:cargo/serde@1.0.0", &common));
    }

    /// Regression: local-GO redirects must be excluded from the before-blob
    /// gate exactly like local-cargo. A go redirect drops the `go.mod`
    /// `replace` directive + the patched copy and reads no before-blob, so a
    /// missing before-blob must not abort (nor trigger a needless download for)
    /// an offline local-go rollback. Before the fix only cargo was excluded, so
    /// a local-go patch with an absent before-blob aborted the whole rollback
    /// under `--offline`.
    #[tokio::test]
    async fn gate_manifest_excludes_local_go_before_blobs_from_missing_check() {
        let mut patches = HashMap::new();
        patches.insert(
            "pkg:golang/github.com%2Fpkg%2Ferrors@0.9.1".to_string(),
            record_with_file("uuid-go", "errors.go", "go_before"),
        );
        patches.insert(
            "pkg:npm/foo@1.0.0".to_string(),
            record_with_file("uuid-npm", "index.js", "npm_before"),
        );
        let manifest = PatchManifest {
            patches,
            setup: None,
        };

        // Local mode (no --global / --global-prefix).
        let common = crate::args::GlobalArgs::default();
        assert!(!common.global && common.global_prefix.is_none());

        // Blobs dir holds only the npm before-blob; the go one is absent.
        let tmp = tempfile::tempdir().unwrap();
        let blobs = tmp.path();
        tokio::fs::write(blobs.join("npm_before"), b"x")
            .await
            .unwrap();

        // Full manifest: the go before-blob shows up as missing — exactly what
        // the buggy (cargo-only) gate left in, spuriously aborting rollback.
        let full_missing = get_missing_before_blobs(&manifest, blobs).await;
        assert!(full_missing.contains("go_before"));

        // Gate manifest: the local-go PURL is excluded, so its before-blob is
        // not counted as missing. With the npm blob present, the gate reports
        // nothing missing.
        let gate = exclude_local_redirects(&manifest, &common);
        let gate_missing = get_missing_before_blobs(&gate, blobs).await;
        assert!(
            gate_missing.is_empty(),
            "gate must exclude local-go before-blobs, got {gate_missing:?}"
        );

        // And `is_local_redirect` must classify the go PURL as a redirect in
        // local mode but a global PURL as in-place (gate must keep the latter).
        assert!(is_local_redirect(
            "pkg:golang/github.com%2Fpkg%2Ferrors@0.9.1",
            &common
        ));
        let global = crate::args::GlobalArgs {
            global: true,
            ..crate::args::GlobalArgs::default()
        };
        assert!(!is_local_redirect(
            "pkg:golang/github.com%2Fpkg%2Ferrors@0.9.1",
            &global
        ));
    }

    /// Regression: rolling back a local-GO patch must DROP the project-local
    /// redirect (the `go.mod` `replace` directive + the patched copy under
    /// `.socket/go-patches/`), not fall through to in-place rollback.
    ///
    /// Before the fix, `rollback` only had a cargo redirect backend; a go PURL
    /// fell through to `rollback_package_patch` against the pristine module
    /// cache, every file verified `AlreadyOriginal`, and the redirect was left
    /// active — a silent no-op that reported "already original" while the build
    /// kept using the patched copy.
    #[tokio::test]
    async fn try_rollback_local_go_drops_redirect_and_copy() {
        use socket_patch_core::patch::go_mod_edit::{
            ensure_replace_entry, read_replace_entries, GO_PATCHES_DIR,
        };

        const MODULE: &str = "github.com/foo/bar";
        const VERSION: &str = "v1.4.2";
        const PURL: &str = "pkg:golang/github.com/foo/bar@v1.4.2";

        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();

        // A go.mod with a require directive (NOT socket-owned) plus the
        // socket-owned replace directive a prior apply would have written.
        tokio::fs::write(
            root.join("go.mod"),
            "module myproj\n\ngo 1.21\n\nrequire github.com/foo/bar v1.4.2\n",
        )
        .await
        .unwrap();
        let changed = ensure_replace_entry(root, MODULE, VERSION, GO_PATCHES_DIR, false)
            .await
            .unwrap();
        assert!(changed, "fixture must install a socket-owned replace");

        // The patched copy the redirect points at.
        let copy_dir = root.join(".socket/go-patches/github.com/foo/bar@v1.4.2");
        tokio::fs::create_dir_all(&copy_dir).await.unwrap();
        tokio::fs::write(copy_dir.join("errors.go"), b"// patched\n")
            .await
            .unwrap();

        // Sanity: the redirect is in place before rollback.
        assert!(read_replace_entries(root)
            .await
            .iter()
            .any(|e| e.module == MODULE && e.socket_owned()));

        let patch = record_with_file("uuid-go", "errors.go", "go_before");
        let common = crate::args::GlobalArgs {
            cwd: root.to_path_buf(),
            ..crate::args::GlobalArgs::default()
        };

        // `pkg_path` is the (unused for go) pristine module-cache dir.
        let result = try_rollback_local_go(PURL, root, &patch, &common)
            .await
            .expect("go PURL in local mode must be handled by the go backend");

        assert!(result.success, "rollback failed: {:?}", result.error);
        assert!(
            result.files_rolled_back.contains(&"errors.go".to_string()),
            "the patched file must be reported rolled back, got {:?}",
            result.files_rolled_back
        );

        // The socket-owned replace directive is gone...
        assert!(
            read_replace_entries(root)
                .await
                .iter()
                .all(|e| !(e.module == MODULE && e.socket_owned())),
            "socket-owned replace directive must be dropped"
        );
        // ...the require directive (user-authored) survives...
        assert!(tokio::fs::read_to_string(root.join("go.mod"))
            .await
            .unwrap()
            .contains("require github.com/foo/bar v1.4.2"));
        // ...and the patched copy is removed.
        assert!(
            !copy_dir.exists(),
            "patched copy under .socket/go-patches must be removed"
        );
    }

    /// Regression: a dry-run local-go rollback must not CLAIM files were
    /// rolled back. The engine leaves `files_rolled_back` empty on dry-run
    /// (verify only — `rollback_package_patch` pushes into it only on the
    /// mutating path), and the JSON envelope counts `rolledBack` from a
    /// non-empty `files_rolled_back`. Before the fix the go backend populated
    /// it unconditionally, so `rollback --dry-run --json` reported
    /// `rolledBack: 1` (with the files listed in `filesRolledBack`) for a run
    /// that mutated nothing.
    #[tokio::test]
    async fn try_rollback_local_go_dry_run_reports_no_files_rolled_back() {
        use socket_patch_core::patch::go_mod_edit::{
            ensure_replace_entry, read_replace_entries, GO_PATCHES_DIR,
        };

        const MODULE: &str = "github.com/foo/bar";
        const VERSION: &str = "v1.4.2";
        const PURL: &str = "pkg:golang/github.com/foo/bar@v1.4.2";

        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        tokio::fs::write(
            root.join("go.mod"),
            "module myproj\n\ngo 1.21\n\nrequire github.com/foo/bar v1.4.2\n",
        )
        .await
        .unwrap();
        assert!(
            ensure_replace_entry(root, MODULE, VERSION, GO_PATCHES_DIR, false)
                .await
                .unwrap()
        );
        let copy_dir = root.join(".socket/go-patches/github.com/foo/bar@v1.4.2");
        tokio::fs::create_dir_all(&copy_dir).await.unwrap();

        let patch = record_with_file("uuid-go", "errors.go", "go_before");
        let common = crate::args::GlobalArgs {
            cwd: root.to_path_buf(),
            dry_run: true,
            ..crate::args::GlobalArgs::default()
        };
        let result = try_rollback_local_go(PURL, root, &patch, &common)
            .await
            .expect("go PURL in local mode must be handled by the go backend");

        assert!(
            result.success,
            "dry-run rollback failed: {:?}",
            result.error
        );
        assert!(
            result.files_rolled_back.is_empty(),
            "dry-run must not claim files were rolled back (the JSON \
             `rolledBack` count is derived from this), got {:?}",
            result.files_rolled_back
        );
        // And dry-run must not have mutated anything: the redirect and the
        // patched copy both survive.
        assert!(
            read_replace_entries(root)
                .await
                .iter()
                .any(|e| e.module == MODULE && e.socket_owned()),
            "dry-run must leave the replace directive in place"
        );
        assert!(copy_dir.exists(), "dry-run must leave the patched copy");
    }

    /// A go PURL under `--global` is an in-place module-cache rollback, NOT a
    /// redirect — `try_rollback_local_go` must decline it so the caller falls
    /// through to `rollback_package_patch`.
    #[tokio::test]
    async fn try_rollback_local_go_declines_global() {
        let patch = record_with_file("uuid-go", "errors.go", "go_before");
        let global = crate::args::GlobalArgs {
            global: true,
            ..crate::args::GlobalArgs::default()
        };
        let result = try_rollback_local_go(
            "pkg:golang/github.com/foo/bar@v1.4.2",
            Path::new("/nonexistent"),
            &patch,
            &global,
        )
        .await;
        assert!(
            result.is_none(),
            "global go must not use the redirect backend"
        );
    }

    // --- Before-blob gate `--ecosystems` scoping --------------------------
    //
    // Twin of apply's (fixed) "offline guard unscoped" bug: the gate must
    // only consider patches this run can actually roll back — the
    // `--ecosystems` filter.

    /// Regression: an out-of-scope patch's missing before-blob must not abort
    /// an `--ecosystems`-scoped rollback. Before the fix the gate ran on the
    /// identifier-filtered manifest BEFORE `partition_purls`, so
    /// `rollback --ecosystems npm --offline` aborted the whole run because a
    /// pypi patch — which this run would never touch — was missing its
    /// before-blob (and online, the gate triggered needless downloads for it).
    #[tokio::test]
    async fn before_blob_gate_ignores_ecosystem_filtered_patches() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let socket = root.join(".socket");
        let blobs = socket.join("blobs");
        tokio::fs::create_dir_all(&blobs).await.unwrap();

        // npm patch (in scope): before-blob present.
        // pypi patch (filtered out by `--ecosystems npm`): before-blob ABSENT.
        let mut patches = HashMap::new();
        patches.insert(
            "pkg:npm/foo@1.0.0".to_string(),
            record_with_file("uuid-npm", "package/index.js", "npm_before_hash"),
        );
        patches.insert(
            "pkg:pypi/six@1.16.0".to_string(),
            record_with_file("uuid-pypi", "six.py", "pypi_before_hash"),
        );
        let manifest = PatchManifest {
            patches,
            setup: None,
        };
        let manifest_path = socket.join("manifest.json");
        tokio::fs::write(&manifest_path, serde_json::to_string(&manifest).unwrap())
            .await
            .unwrap();
        tokio::fs::write(blobs.join("npm_before_hash"), b"x")
            .await
            .unwrap();

        // With no npm package installed under the tempdir the run finds
        // nothing to do — but it must get past the gate and report success,
        // not abort over a blob it would never read.
        let common = crate::args::GlobalArgs {
            cwd: root.to_path_buf(),
            offline: true,
            ..crate::args::GlobalArgs::default()
        };
        let (success, results, _vendored_skipped) = rollback_patches(
            &common,
            &manifest_path,
            None,
            false, // dry_run
            true,  // silent
            Some(vec!["npm".to_string()]),
        )
        .await
        .expect("rollback must not error");
        assert!(results.is_empty(), "nothing installed, nothing rolled back");
        assert!(
            success,
            "an out-of-scope patch's missing before-blob must not abort an \
             --ecosystems-scoped offline rollback"
        );
    }

    /// The scoped gate still protects in-scope patches: with no
    /// `--ecosystems` filter, a missing before-blob for an in-scope npm patch
    /// must abort the offline run exactly as before.
    #[tokio::test]
    async fn before_blob_gate_still_blocks_in_scope_missing_blob() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let socket = root.join(".socket");
        let blobs = socket.join("blobs");
        tokio::fs::create_dir_all(&blobs).await.unwrap();

        let mut patches = HashMap::new();
        patches.insert(
            "pkg:npm/foo@1.0.0".to_string(),
            record_with_file("uuid-npm", "package/index.js", "npm_before_hash"),
        );
        let manifest = PatchManifest {
            patches,
            setup: None,
        };
        let manifest_path = socket.join("manifest.json");
        tokio::fs::write(&manifest_path, serde_json::to_string(&manifest).unwrap())
            .await
            .unwrap();
        // The npm before-blob is deliberately absent.

        let common = crate::args::GlobalArgs {
            cwd: root.to_path_buf(),
            offline: true,
            ..crate::args::GlobalArgs::default()
        };
        let (success, results, _vendored_skipped) = rollback_patches(
            &common,
            &manifest_path,
            None,
            false, // dry_run
            true,  // silent
            None,  // no ecosystem filter — the npm patch is in scope
        )
        .await
        .expect("rollback must not error");
        assert!(results.is_empty());
        assert!(
            !success,
            "an in-scope missing before-blob must still abort the offline run"
        );
    }
}
