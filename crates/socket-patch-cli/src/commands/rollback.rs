use clap::Args;
use socket_patch_core::api::blob_fetcher::{fetch_blobs_by_hash, format_fetch_result};
use socket_patch_core::api::client::get_api_client_with_overrides;
use socket_patch_core::crawlers::CrawlerOptions;
use socket_patch_core::manifest::operations::read_manifest;
use socket_patch_core::manifest::schema::{PatchFileInfo, PatchManifest, PatchRecord};
use socket_patch_core::patch::apply::select_installed_variants;
use socket_patch_core::patch::rollback::{
    rollback_package_patch, RollbackResult, VerifyRollbackStatus,
};
use socket_patch_core::utils::purl::{purl_matches_identifier, strip_purl_qualifiers};
use socket_patch_core::utils::telemetry::{track_patch_rollback_failed, track_patch_rolled_back};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::args::{apply_env_toggles, GlobalArgs};
use crate::commands::lock_cli::{acquire_or_emit, LOCK_BROKEN_CODE};
use crate::ecosystem_dispatch::{find_packages_for_rollback, partition_purls};
use crate::json_envelope::Command as EnvelopeCommand;

#[derive(Args)]
pub struct RollbackArgs {
    /// Package PURL or patch UUID to rollback. Omit to rollback all patches.
    pub identifier: Option<String>,

    #[command(flatten)]
    pub common: GlobalArgs,

    /// Rollback a patch by fetching beforeHash blobs from API (no manifest required).
    #[arg(long = "one-off", env = "SOCKET_ONE_OFF", default_value_t = false)]
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

/// True for a golang PURL in local mode (no `--global` / `--global-prefix`).
#[cfg(feature = "golang")]
fn is_local_go(purl: &str, common: &GlobalArgs) -> bool {
    use socket_patch_core::crawlers::Ecosystem;
    !common.global
        && common.global_prefix.is_none()
        && Ecosystem::from_purl(purl) == Some(Ecosystem::Golang)
}

/// True when `purl` rolls back by dropping a project-local redirect (local-mode
/// go) rather than restoring bytes from a before-blob. The before-blob gate uses
/// this to skip those PURLs — they read no blobs, so a missing before-blob must
/// not block (or trigger a needless download for) an offline redirect rollback.
fn is_local_redirect(purl: &str, common: &GlobalArgs) -> bool {
    #[cfg(feature = "golang")]
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
#[cfg(feature = "golang")]
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
        files_rolled_back: patch.files.keys().cloned().collect(),
        error: None,
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

#[cfg(not(feature = "golang"))]
async fn try_rollback_local_go(
    _purl: &str,
    _pkg_path: &Path,
    _patch: &PatchRecord,
    _common: &GlobalArgs,
) -> Option<RollbackResult> {
    None
}

fn find_patches_to_rollback(
    manifest: &PatchManifest,
    identifier: Option<&str>,
) -> Vec<PatchToRollback> {
    match identifier {
        None => manifest
            .patches
            .iter()
            .map(|(purl, patch)| PatchToRollback {
                purl: purl.clone(),
                patch: patch.clone(),
            })
            .collect(),
        Some(id) => {
            let mut patches = Vec::new();
            if id.starts_with("pkg:") {
                // A base PURL (no `?`) matches every release variant of
                // that package@version; a qualified PURL targets one.
                for (purl, patch) in &manifest.patches {
                    if purl_matches_identifier(purl, id) {
                        patches.push(PatchToRollback {
                            purl: purl.clone(),
                            patch: patch.clone(),
                        });
                    }
                }
            } else {
                for (purl, patch) in &manifest.patches {
                    if patch.uuid == id {
                        patches.push(PatchToRollback {
                            purl: purl.clone(),
                            patch: patch.clone(),
                        });
                    }
                }
            }
            patches
        }
    }
}

fn get_before_hash_blobs(manifest: &PatchManifest) -> HashSet<String> {
    let mut blobs = HashSet::new();
    for patch in manifest.patches.values() {
        for file_info in patch.files.values() {
            blobs.insert(file_info.before_hash.clone());
        }
    }
    blobs
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

    let (telemetry_client, _) =
        get_api_client_with_overrides(args.common.api_client_overrides()).await;
    let api_token = telemetry_client.api_token().cloned();
    let org_slug = telemetry_client.org_slug().cloned();

    // Validate one-off requires identifier
    if args.one_off && args.identifier.is_none() {
        if args.common.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "status": "error",
                    "error": "--one-off requires an identifier (UUID or PURL)",
                }))
                .unwrap()
            );
        } else {
            eprintln!("Error: --one-off requires an identifier (UUID or PURL)");
        }
        return 1;
    }

    // Handle one-off mode
    if args.one_off {
        if args.common.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "status": "error",
                    "error": "One-off rollback mode is not yet implemented",
                }))
                .unwrap()
            );
        } else {
            eprintln!("One-off rollback mode: fetching patch data...");
        }
        return 1;
    }

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
        } else if !args.common.silent {
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
        Ok((success, results)) => {
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
                            "--break-lock removed {}/apply.lock before acquisition",
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
                            let status_str = match f.status {
                                VerifyRollbackStatus::Ready => "ready",
                                VerifyRollbackStatus::AlreadyOriginal => "already original",
                                VerifyRollbackStatus::HashMismatch => "hash mismatch",
                                VerifyRollbackStatus::NotFound => "not found",
                                VerifyRollbackStatus::MissingBlob => "missing blob",
                            };
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
                        "results": [],
                    }))
                    .unwrap()
                );
            } else if !args.common.silent {
                eprintln!("Error: {e}");
            }
            1
        }
    }
}

async fn rollback_patches_inner(
    args: &RollbackArgs,
    manifest_path: &Path,
) -> Result<(bool, Vec<RollbackResult>), String> {
    let manifest = read_manifest(manifest_path)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "Invalid manifest".to_string())?;

    let socket_dir = manifest_path.parent().unwrap();
    let blobs_path = socket_dir.join("blobs");
    tokio::fs::create_dir_all(&blobs_path)
        .await
        .map_err(|e| e.to_string())?;

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
        return Ok((true, Vec::new()));
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

    // Check for missing beforeHash blobs. Local-redirect PURLs (local-mode go)
    // are excluded: their rollback just drops the project-local redirect + copy
    // and reads no blobs, so a missing before-blob must not block an offline
    // redirect rollback.
    let gate_manifest = exclude_local_redirects(&filtered_manifest, &args.common);
    let missing_blobs = get_missing_before_blobs(&gate_manifest, &blobs_path).await;
    if !missing_blobs.is_empty() {
        if args.common.offline {
            if !args.common.silent && !args.common.json {
                eprintln!(
                    "Error: {} blob(s) are missing and --offline mode is enabled.",
                    missing_blobs.len()
                );
                eprintln!("Run \"socket-patch repair\" to download missing blobs.");
            }
            return Ok((false, Vec::new()));
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
            if !args.common.silent && !args.common.json {
                eprintln!(
                    "{} blob(s) could not be downloaded. Cannot rollback.",
                    still_missing.len()
                );
            }
            return Ok((false, Vec::new()));
        }
    }

    // Partition PURLs by ecosystem
    let rollback_purls: Vec<String> = patches_to_rollback.iter().map(|p| p.purl.clone()).collect();
    let partitioned = partition_purls(&rollback_purls, args.common.ecosystems.as_deref());

    let crawler_options = CrawlerOptions {
        cwd: args.common.cwd.clone(),
        global: args.common.global,
        global_prefix: args.common.global_prefix.clone(),
        batch_size: 100,
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
        return Ok((true, Vec::new()));
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
            // restores in place from before-blobs. Without the `golang` feature
            // `try_rollback_local_go` is an inert `None`.
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
                if !args.common.silent && !args.common.json {
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

    Ok((!has_errors, results))
}

// Export for use by remove command
#[allow(clippy::too_many_arguments)]
pub async fn rollback_patches(
    cwd: &Path,
    manifest_path: &Path,
    identifier: Option<&str>,
    dry_run: bool,
    silent: bool,
    offline: bool,
    global: bool,
    global_prefix: Option<PathBuf>,
    ecosystems: Option<Vec<String>>,
) -> Result<(bool, Vec<RollbackResult>), String> {
    let args = RollbackArgs {
        identifier: identifier.map(String::from),
        common: crate::args::GlobalArgs {
            cwd: cwd.to_path_buf(),
            manifest_path: manifest_path.display().to_string(),
            offline,
            global,
            global_prefix,
            ecosystems,
            silent,
            dry_run,
            ..crate::args::GlobalArgs::default()
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

    #[cfg(any(feature = "cargo", feature = "golang"))]
    use socket_patch_core::manifest::schema::PatchFileInfo;

    // Only the cargo/golang-gated before-blob gate tests use this helper.
    #[cfg(any(feature = "cargo", feature = "golang"))]
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

    /// Cargo now patches in place (vendored or registry cache) and rolls back
    /// by restoring from before-blobs — exactly like npm/pypi. So a cargo PURL
    /// must NOT be excluded by the before-blob gate: a missing cargo before-blob
    /// IS a real problem the gate should surface. This guards against cargo
    /// being mistakenly reclassified as a redirect again.
    #[cfg(feature = "cargo")]
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
    #[cfg(feature = "golang")]
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
    #[cfg(feature = "golang")]
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

    /// A go PURL under `--global` is an in-place module-cache rollback, NOT a
    /// redirect — `try_rollback_local_go` must decline it so the caller falls
    /// through to `rollback_package_patch`.
    #[cfg(feature = "golang")]
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
}
