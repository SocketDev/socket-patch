use clap::Args;
use socket_patch_core::api::blob_fetcher::{
    fetch_missing_blobs, fetch_missing_sources, format_fetch_result, get_missing_archives,
    get_missing_blobs, DownloadMode,
};
use socket_patch_core::api::client::get_api_client_from_env;
use socket_patch_core::constants::DEFAULT_PATCH_MANIFEST_PATH;
use socket_patch_core::crawlers::{CrawlerOptions, Ecosystem};
use socket_patch_core::manifest::operations::{read_manifest, resolve_manifest_path};
use socket_patch_core::patch::apply::{
    apply_package_patch, verify_file_patch, ApplyResult, PatchSources, VerifyStatus,
};
use socket_patch_core::utils::cleanup_blobs::{cleanup_unused_blobs, format_cleanup_result};
use socket_patch_core::utils::purl::strip_purl_qualifiers;
use socket_patch_core::utils::telemetry::{track_patch_applied, track_patch_apply_failed};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::ecosystem_dispatch::{find_packages_for_purls, partition_purls};

#[derive(Args)]
pub struct ApplyArgs {
    /// Working directory
    #[arg(long, default_value = ".")]
    pub cwd: PathBuf,

    /// Verify patches can be applied without modifying files
    #[arg(short = 'd', long = "dry-run", default_value_t = false)]
    pub dry_run: bool,

    /// Only output errors
    #[arg(short = 's', long, default_value_t = false)]
    pub silent: bool,

    /// Path to patch manifest file
    #[arg(short = 'm', long = "manifest-path", default_value = DEFAULT_PATCH_MANIFEST_PATH)]
    pub manifest_path: String,

    /// Do not download missing blobs, fail if any are missing
    #[arg(long, default_value_t = false)]
    pub offline: bool,

    /// Apply patches to globally installed npm packages
    #[arg(short = 'g', long, default_value_t = false)]
    pub global: bool,

    /// Custom path to global node_modules
    #[arg(long = "global-prefix")]
    pub global_prefix: Option<PathBuf>,

    /// Restrict patching to specific ecosystems
    #[arg(long, value_delimiter = ',')]
    pub ecosystems: Option<Vec<String>>,

    /// Skip pre-application hash verification (apply even if package version differs)
    #[arg(short = 'f', long, default_value_t = false)]
    pub force: bool,

    /// Output results as JSON
    #[arg(long, default_value_t = false)]
    pub json: bool,

    /// Show detailed per-file verification information
    #[arg(short = 'v', long, default_value_t = false)]
    pub verbose: bool,

    /// Which kind of patch artifact to download when local files are
    /// missing. `diff` (default) fetches the smallest delta archive;
    /// `package` fetches a full per-package tarball; `file` falls back to
    /// the legacy per-file blob behavior. The apply pipeline always tries
    /// already-downloaded sources in the order package → diff → blob.
    #[arg(long = "download-mode", default_value = "diff")]
    pub download_mode: String,
}

fn verify_status_str(status: &VerifyStatus) -> &'static str {
    match status {
        VerifyStatus::Ready => "ready",
        VerifyStatus::AlreadyPatched => "already_patched",
        VerifyStatus::HashMismatch => "hash_mismatch",
        VerifyStatus::NotFound => "not_found",
    }
}

fn result_to_json(result: &ApplyResult) -> serde_json::Value {
    let applied_via: HashMap<&String, &str> = result
        .applied_via
        .iter()
        .map(|(k, v)| (k, v.as_tag()))
        .collect();
    serde_json::json!({
        "purl": result.package_key,
        "path": result.package_path,
        "success": result.success,
        "error": result.error,
        "filesPatched": result.files_patched,
        "appliedVia": applied_via,
        "filesVerified": result.files_verified.iter().map(|f| {
            serde_json::json!({
                "file": f.file,
                "status": verify_status_str(&f.status),
                "message": f.message,
                "currentHash": f.current_hash,
                "expectedHash": f.expected_hash,
                "targetHash": f.target_hash,
            })
        }).collect::<Vec<_>>(),
    })
}

pub async fn run(args: ApplyArgs) -> i32 {
    let (telemetry_client, _) = get_api_client_from_env(None).await;
    let api_token = telemetry_client.api_token().cloned();
    let org_slug = telemetry_client.org_slug().cloned();

    let manifest_path = resolve_manifest_path(&args.cwd, &args.manifest_path);

    // Check if manifest exists - exit successfully if no .socket folder is set up
    if tokio::fs::metadata(&manifest_path).await.is_err() {
        if args.json {
            println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                "status": "no_manifest",
                "patchesApplied": 0,
                "alreadyPatched": 0,
                "failed": 0,
                "dryRun": args.dry_run,
                "results": [],
            })).unwrap());
        } else if !args.silent {
            println!("No .socket folder found, skipping patch application.");
        }
        return 0;
    }

    match apply_patches_inner(&args, &manifest_path).await {
        Ok((success, results, unmatched)) => {
            let patched_count = results
                .iter()
                .filter(|r| r.success && !r.files_patched.is_empty())
                .count();
            let already_patched_count = results
                .iter()
                .filter(|r| {
                    r.files_verified
                        .iter()
                        .all(|f| f.status == VerifyStatus::AlreadyPatched)
                })
                .count();
            let failed_count = results.iter().filter(|r| !r.success).count();

            if args.json {
                println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                    "status": if success { "success" } else { "partial_failure" },
                    "patchesApplied": patched_count,
                    "alreadyPatched": already_patched_count,
                    "failed": failed_count,
                    "unmatchedPatches": unmatched.len(),
                    "unmatchedPurls": unmatched,
                    "dryRun": args.dry_run,
                    "results": results.iter().map(result_to_json).collect::<Vec<_>>(),
                })).unwrap());
            } else if !args.silent && !results.is_empty() {
                let patched: Vec<_> = results.iter().filter(|r| r.success).collect();
                let already_patched: Vec<_> = results
                    .iter()
                    .filter(|r| {
                        r.files_verified
                            .iter()
                            .all(|f| f.status == VerifyStatus::AlreadyPatched)
                    })
                    .collect();

                if args.dry_run {
                    println!("\nPatch verification complete:");
                    println!("  {} package(s) can be patched", patched.len());
                    if !already_patched.is_empty() {
                        println!("  {} package(s) already patched", already_patched.len());
                    }
                } else {
                    println!("\nPatched packages:");
                    for result in &patched {
                        if !result.files_patched.is_empty() {
                            // Summarize the per-file strategy used by this
                            // package: if everything came from the same
                            // source, show just that tag; otherwise list
                            // distinct sources.
                            let mut tags: Vec<&'static str> = result
                                .applied_via
                                .values()
                                .map(|v| v.as_tag())
                                .collect();
                            tags.sort_unstable();
                            tags.dedup();
                            let suffix = if tags.is_empty() {
                                String::new()
                            } else {
                                format!(" (via {})", tags.join("+"))
                            };
                            println!("  {}{}", result.package_key, suffix);
                        } else if result.files_verified.iter().all(|f| {
                            f.status == VerifyStatus::AlreadyPatched
                        }) {
                            println!("  {} (already patched)", result.package_key);
                        }
                    }
                }

                if args.verbose {
                    println!("\nDetailed verification:");
                    for result in &results {
                        println!("  {}:", result.package_key);
                        for f in &result.files_verified {
                            let status_str = match f.status {
                                VerifyStatus::Ready => "ready",
                                VerifyStatus::AlreadyPatched => "already patched",
                                VerifyStatus::HashMismatch => "hash mismatch",
                                VerifyStatus::NotFound => "not found",
                            };
                            println!("    {} [{}]", f.file, status_str);
                            if let Some(ref msg) = f.message {
                                println!("      message: {msg}");
                            }
                            if args.verbose {
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
            }

            // Track telemetry
            if success {
                track_patch_applied(patched_count, args.dry_run, api_token.as_deref(), org_slug.as_deref()).await;
            } else {
                track_patch_apply_failed("One or more patches failed to apply", args.dry_run, api_token.as_deref(), org_slug.as_deref()).await;
            }

            if success { 0 } else { 1 }
        }
        Err(e) => {
            track_patch_apply_failed(&e, args.dry_run, api_token.as_deref(), org_slug.as_deref()).await;
            if args.json {
                println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                    "status": "error",
                    "error": e,
                    "patchesApplied": 0,
                    "alreadyPatched": 0,
                    "failed": 0,
                    "dryRun": args.dry_run,
                    "results": [],
                })).unwrap());
            } else if !args.silent {
                eprintln!("Error: {e}");
            }
            1
        }
    }
}

async fn apply_patches_inner(
    args: &ApplyArgs,
    manifest_path: &Path,
) -> Result<(bool, Vec<ApplyResult>, Vec<String>), String> {
    let manifest = read_manifest(manifest_path)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "Invalid manifest".to_string())?;

    let socket_dir = manifest_path.parent().unwrap();
    let blobs_path = socket_dir.join("blobs");
    let diffs_path = socket_dir.join("diffs");
    let packages_path = socket_dir.join("packages");
    tokio::fs::create_dir_all(&blobs_path)
        .await
        .map_err(|e| e.to_string())?;

    let download_mode = DownloadMode::parse(&args.download_mode).map_err(|e| e.to_string())?;

    // Compute per-patch source availability so both the offline guard
    // (next block) and the `download_needed` decision below share the
    // same notion of what's already on disk.
    let missing_blobs = get_missing_blobs(&manifest, &blobs_path).await;
    let missing_diff_archives = get_missing_archives(&manifest, &diffs_path).await;
    let missing_package_archives = get_missing_archives(&manifest, &packages_path).await;

    // A patch is "locally applicable" iff at least one of:
    //   - every `after_hash` blob it references is on disk, OR
    //   - its diff archive is on disk, OR
    //   - its package archive is on disk.
    // The apply pipeline will pick whichever is present per file.
    let patches_without_source: Vec<&str> = manifest
        .patches
        .iter()
        .filter_map(|(purl, record)| {
            let all_blobs_present = record
                .files
                .values()
                .all(|f| !missing_blobs.contains(&f.after_hash));
            let diff_present = !missing_diff_archives.contains(&record.uuid);
            let pkg_present = !missing_package_archives.contains(&record.uuid);
            if all_blobs_present || diff_present || pkg_present {
                None
            } else {
                Some(purl.as_str())
            }
        })
        .collect();

    if args.offline {
        // Offline: bail only if some patch has no usable local source.
        // Note: with `--force`, the apply pipeline can short-circuit
        // verification on its own; we still surface the no-source
        // diagnosis so the user runs `repair` before retrying.
        if !patches_without_source.is_empty() {
            if !args.silent && !args.json {
                eprintln!(
                    "Error: {} patch(es) have no local source and --offline is set:",
                    patches_without_source.len()
                );
                for purl in patches_without_source.iter().take(5) {
                    eprintln!("  - {}", purl);
                }
                if patches_without_source.len() > 5 {
                    eprintln!("  ... and {} more", patches_without_source.len() - 5);
                }
                eprintln!("Run \"socket-patch repair\" to download missing artifacts.");
            }
            return Ok((false, Vec::new(), Vec::new()));
        }
    }

    // Decide what (if anything) needs downloading.
    //
    // The apply pipeline tries sources in the order package → diff →
    // blob locally. We honor `--download-mode` for the primary fetch
    // when there's actually a gap to close. Skip the archive fetch
    // entirely when all file blobs are already present locally —
    // apply will succeed via the blob path, and the archive endpoints
    // would just 404 (current server doesn't serve them yet).
    let download_needed = !args.offline
        && match download_mode {
            DownloadMode::File => !missing_blobs.is_empty(),
            DownloadMode::Diff | DownloadMode::Package if missing_blobs.is_empty() => false,
            DownloadMode::Diff => !missing_diff_archives.is_empty(),
            DownloadMode::Package => !missing_package_archives.is_empty(),
        };

    if download_needed {
        if !args.silent && !args.json {
            println!(
                "Downloading missing patch artifacts (mode: {})...",
                download_mode.as_tag()
            );
        }

        let (client, _) = get_api_client_from_env(None).await;
        let sources = PatchSources {
            blobs_path: &blobs_path,
            packages_path: Some(&packages_path),
            diffs_path: Some(&diffs_path),
        };
        let fetch_result =
            fetch_missing_sources(&manifest, &sources, download_mode, &client, None).await;

        if !args.silent && !args.json {
            println!("{}", format_fetch_result(&fetch_result));
        }

        // For non-file modes, automatically fetch any still-missing file
        // blobs as a fallback. Patches that lack the requested mode on
        // the server will still apply via the legacy blob path.
        if download_mode != DownloadMode::File {
            let still_missing_blobs = get_missing_blobs(&manifest, &blobs_path).await;
            if !still_missing_blobs.is_empty() {
                if !args.silent && !args.json {
                    println!(
                        "Falling back to per-file blob downloads for {} blob(s)...",
                        still_missing_blobs.len()
                    );
                }
                let blob_result =
                    fetch_missing_blobs(&manifest, &blobs_path, &client, None).await;
                if !args.silent && !args.json {
                    println!("{}", format_fetch_result(&blob_result));
                }
                if blob_result.failed > 0 && fetch_result.failed > 0 {
                    if !args.silent && !args.json {
                        eprintln!("Some artifacts could not be downloaded. Cannot apply patches.");
                    }
                    return Ok((false, Vec::new(), Vec::new()));
                }
            }
        } else if fetch_result.failed > 0 {
            if !args.silent && !args.json {
                eprintln!("Some blobs could not be downloaded. Cannot apply patches.");
            }
            return Ok((false, Vec::new(), Vec::new()));
        }
    }

    // Partition manifest PURLs by ecosystem
    let manifest_purls: Vec<String> = manifest.patches.keys().cloned().collect();
    let partitioned =
        partition_purls(&manifest_purls, args.ecosystems.as_deref());

    let target_manifest_purls: HashSet<String> = partitioned
        .values()
        .flat_map(|purls| purls.iter().cloned())
        .collect();

    let crawler_options = CrawlerOptions {
        cwd: args.cwd.clone(),
        global: args.global,
        global_prefix: args.global_prefix.clone(),
        batch_size: 100,
    };

    let all_packages =
        find_packages_for_purls(&partitioned, &crawler_options, args.silent || args.json).await;

    let has_any_purls = !partitioned.is_empty();

    if all_packages.is_empty() && !has_any_purls {
        if !args.silent && !args.json {
            if args.global || args.global_prefix.is_some() {
                eprintln!("No global packages found");
            } else {
                eprintln!("No package directories found");
            }
        }
        return Ok((false, Vec::new(), Vec::new()));
    }

    if all_packages.is_empty() {
        if !args.silent && !args.json {
            eprintln!("Warning: No packages found that match available patches");
            eprintln!(
                "  {} targeted manifest patch(es) were in scope, but no matching packages were found on disk.",
                target_manifest_purls.len()
            );
            eprintln!("  Check that packages are installed and --cwd points to the right directory.");
        }
        let unmatched: Vec<String> = target_manifest_purls.iter().cloned().collect();
        return Ok((false, Vec::new(), unmatched));
    }

    // Apply patches
    let mut results: Vec<ApplyResult> = Vec::new();
    let mut has_errors = false;

    // Group pypi PURLs by base (for variant matching with qualifiers)
    let mut pypi_qualified_groups: HashMap<String, Vec<String>> = HashMap::new();
    if let Some(pypi_purls) = partitioned.get(&Ecosystem::Pypi) {
        for purl in pypi_purls {
            let base = strip_purl_qualifiers(purl).to_string();
            pypi_qualified_groups
                .entry(base)
                .or_default()
                .push(purl.clone());
        }
    }

    let mut applied_base_purls: HashSet<String> = HashSet::new();
    let mut matched_manifest_purls: HashSet<String> = HashSet::new();

    for (purl, pkg_path) in &all_packages {
        if Ecosystem::from_purl(purl) == Some(Ecosystem::Pypi) {
            let base_purl = strip_purl_qualifiers(purl).to_string();
            if applied_base_purls.contains(&base_purl) {
                continue;
            }

            let variants = pypi_qualified_groups
                .get(&base_purl)
                .cloned()
                .unwrap_or_else(|| vec![base_purl.clone()]);
            let mut applied = false;

            for variant_purl in &variants {
                let patch = match manifest.patches.get(variant_purl) {
                    Some(p) => p,
                    None => continue,
                };

                // Check first file hash match (skip when --force)
                if !args.force {
                    if let Some((file_name, file_info)) = patch.files.iter().next() {
                        let verify = verify_file_patch(pkg_path, file_name, file_info).await;
                        if verify.status == VerifyStatus::HashMismatch {
                            continue;
                        }
                    }
                }

                let sources = PatchSources {
                    blobs_path: &blobs_path,
                    packages_path: Some(&packages_path),
                    diffs_path: Some(&diffs_path),
                };
                let result = apply_package_patch(
                    variant_purl,
                    pkg_path,
                    &patch.files,
                    &sources,
                    Some(&patch.uuid),
                    args.dry_run,
                    args.force,
                )
                .await;

                if result.success {
                    applied = true;
                    applied_base_purls.insert(base_purl.clone());
                    results.push(result);
                    matched_manifest_purls.insert(variant_purl.clone());
                    break;
                } else {
                    results.push(result);
                }
            }

            if !applied {
                has_errors = true;
                if !args.silent && !args.json {
                    eprintln!("Failed to patch {base_purl}: no matching variant found");
                }
            }
        } else {
            // npm PURLs: direct lookup
            let patch = match manifest.patches.get(purl) {
                Some(p) => p,
                None => continue,
            };

            let sources = PatchSources {
                blobs_path: &blobs_path,
                packages_path: Some(&packages_path),
                diffs_path: Some(&diffs_path),
            };
            let result = apply_package_patch(
                purl,
                pkg_path,
                &patch.files,
                &sources,
                Some(&patch.uuid),
                args.dry_run,
                args.force,
            )
            .await;

            if !result.success {
                has_errors = true;
                if !args.silent && !args.json {
                    eprintln!(
                        "Failed to patch {}: {}",
                        purl,
                        result.error.as_deref().unwrap_or("unknown error")
                    );
                }
            }
            results.push(result);
            matched_manifest_purls.insert(purl.clone());
        }
    }

    // Check if targeted manifest entries had no matches
    let unmatched: Vec<String> = target_manifest_purls
        .iter()
        .filter(|p| !matched_manifest_purls.contains(*p))
        .cloned()
        .collect();

    if !unmatched.is_empty() && !args.silent && !args.json {
        eprintln!("\nWarning: {} manifest patch(es) had no matching installed package:", unmatched.len());
        for purl in &unmatched {
            eprintln!("  - {}", purl);
        }
    }

    if !target_manifest_purls.is_empty() && matched_manifest_purls.is_empty() && !all_packages.is_empty() {
        if !args.silent && !args.json {
            eprintln!("Warning: None of the targeted manifest patches matched installed packages.");
        }
        has_errors = true;
    }

    // Post-apply summary
    if !args.silent && !args.json {
        let applied_count = results.iter().filter(|r| r.success && !r.files_patched.is_empty()).count();
        let already_count = results.iter().filter(|r| {
            r.files_verified.iter().all(|f| f.status == VerifyStatus::AlreadyPatched)
        }).count();
        println!(
            "\nSummary: {}/{} targeted patches applied, {} already patched, {} not found on disk",
            applied_count,
            target_manifest_purls.len(),
            already_count,
            unmatched.len()
        );
    }

    // Clean up unused blobs
    if !args.silent && !args.json {
        if let Ok(cleanup_result) = cleanup_unused_blobs(&manifest, &blobs_path, args.dry_run).await {
            if cleanup_result.blobs_removed > 0 {
                println!("\n{}", format_cleanup_result(&cleanup_result, args.dry_run));
            }
        }
    }

    Ok((!has_errors, results, unmatched))
}

#[cfg(test)]
mod tests {
    //! Pure-helper tests for the `apply` subcommand. These pin the JSON
    //! key shape produced by `result_to_json` and the lowercase string
    //! tags emitted by `verify_status_str` — both part of the public
    //! contract documented in `CLI_CONTRACT.md`.
    use super::*;
    use socket_patch_core::patch::apply::{
        ApplyResult, AppliedVia, VerifyResult, VerifyStatus,
    };

    // -----------------------------------------------------------------
    // verify_status_str — every VerifyStatus variant must map to the
    // exact lowercase tag documented in the JSON contract.
    // -----------------------------------------------------------------

    #[test]
    fn verify_status_str_ready() {
        assert_eq!(verify_status_str(&VerifyStatus::Ready), "ready");
    }

    #[test]
    fn verify_status_str_already_patched() {
        assert_eq!(
            verify_status_str(&VerifyStatus::AlreadyPatched),
            "already_patched"
        );
    }

    #[test]
    fn verify_status_str_hash_mismatch() {
        assert_eq!(
            verify_status_str(&VerifyStatus::HashMismatch),
            "hash_mismatch"
        );
    }

    #[test]
    fn verify_status_str_not_found() {
        assert_eq!(verify_status_str(&VerifyStatus::NotFound), "not_found");
    }

    // -----------------------------------------------------------------
    // result_to_json — top-level keys and filesVerified[0] keys are part
    // of the JSON output contract. Wrappers and CI scripts read these.
    // -----------------------------------------------------------------

    /// Build an `ApplyResult` with a single fully-populated VerifyResult
    /// so we can exercise every JSON key in one shot.
    fn sample_result_with_verify(status: VerifyStatus) -> ApplyResult {
        ApplyResult {
            package_key: "pkg:npm/minimist@1.2.2".to_string(),
            package_path: "/tmp/node_modules/minimist".to_string(),
            success: true,
            files_verified: vec![VerifyResult {
                file: "package/index.js".to_string(),
                status,
                message: Some("ok".to_string()),
                current_hash: Some("aaa".to_string()),
                expected_hash: Some("bbb".to_string()),
                target_hash: Some("ccc".to_string()),
            }],
            files_patched: vec!["package/index.js".to_string()],
            applied_via: HashMap::new(),
            error: None,
        }
    }

    #[test]
    fn result_to_json_top_level_keys() {
        let result = sample_result_with_verify(VerifyStatus::Ready);
        let v = result_to_json(&result);
        let obj = v.as_object().expect("top-level must be a JSON object");

        // The exact set of top-level keys is contract; any addition or
        // rename here is a breaking change for downstream wrappers.
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort();
        assert_eq!(
            keys,
            vec![
                "appliedVia",
                "error",
                "filesPatched",
                "filesVerified",
                "path",
                "purl",
                "success",
            ]
        );

        // Spot-check value mapping for the simple scalar fields.
        assert_eq!(v["purl"], "pkg:npm/minimist@1.2.2");
        assert_eq!(v["path"], "/tmp/node_modules/minimist");
        assert_eq!(v["success"], true);
        assert_eq!(v["error"], serde_json::Value::Null);
        assert_eq!(v["filesPatched"][0], "package/index.js");
    }

    #[test]
    fn result_to_json_files_verified_entry_keys() {
        let result = sample_result_with_verify(VerifyStatus::Ready);
        let v = result_to_json(&result);
        let entry = v["filesVerified"][0]
            .as_object()
            .expect("filesVerified[0] must be a JSON object");

        let mut keys: Vec<&str> = entry.keys().map(String::as_str).collect();
        keys.sort();
        assert_eq!(
            keys,
            vec![
                "currentHash",
                "expectedHash",
                "file",
                "message",
                "status",
                "targetHash",
            ]
        );

        assert_eq!(v["filesVerified"][0]["file"], "package/index.js");
        assert_eq!(v["filesVerified"][0]["status"], "ready");
        assert_eq!(v["filesVerified"][0]["message"], "ok");
        assert_eq!(v["filesVerified"][0]["currentHash"], "aaa");
        assert_eq!(v["filesVerified"][0]["expectedHash"], "bbb");
        assert_eq!(v["filesVerified"][0]["targetHash"], "ccc");
    }

    #[test]
    fn result_to_json_hash_mismatch_status_tag() {
        // The `hash_mismatch` snake_case tag is the contract value.
        // `verify_status_str` produces it; verify it survives the round
        // trip through `result_to_json`.
        let result = sample_result_with_verify(VerifyStatus::HashMismatch);
        let v = result_to_json(&result);
        assert_eq!(v["filesVerified"][0]["status"], "hash_mismatch");
    }

    #[test]
    fn result_to_json_applied_via_uses_camel_case_key() {
        // `appliedVia` must be camelCase in JSON output, not snake_case
        // `applied_via`. This is divergent from the Rust struct field
        // name and is part of the contract — wrappers parse this key.
        let mut applied_via = HashMap::new();
        applied_via.insert("package/index.js".to_string(), AppliedVia::Diff);
        applied_via.insert("package/lib/foo.js".to_string(), AppliedVia::Package);

        let result = ApplyResult {
            package_key: "pkg:npm/minimist@1.2.2".to_string(),
            package_path: "/tmp/node_modules/minimist".to_string(),
            success: true,
            files_verified: Vec::new(),
            files_patched: vec![
                "package/index.js".to_string(),
                "package/lib/foo.js".to_string(),
            ],
            applied_via,
            error: None,
        };
        let v = result_to_json(&result);

        // Key must be `appliedVia`, not `applied_via`.
        assert!(v.get("appliedVia").is_some());
        assert!(v.get("applied_via").is_none());

        // Value must serialize as a JSON object map (not array).
        let map = v["appliedVia"]
            .as_object()
            .expect("appliedVia must serialize as a JSON object");
        assert_eq!(map.len(), 2);
        // The lowercase tags from `AppliedVia::as_tag` are themselves
        // contract values (`diff`, `package`, `blob`).
        assert_eq!(map.get("package/index.js").and_then(|v| v.as_str()), Some("diff"));
        assert_eq!(
            map.get("package/lib/foo.js").and_then(|v| v.as_str()),
            Some("package"),
        );
    }
}
