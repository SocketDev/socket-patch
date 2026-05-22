use clap::Args;
use socket_patch_core::api::blob_fetcher::{
    fetch_missing_blobs, fetch_missing_sources, format_fetch_result, get_missing_archives,
    get_missing_blobs, DownloadMode,
};
use socket_patch_core::api::client::get_api_client_with_overrides;
use socket_patch_core::crawlers::{
    detect_npm_pkg_manager, CrawlerOptions, Ecosystem, NpmPkgManager,
};
use socket_patch_core::manifest::operations::read_manifest;
use socket_patch_core::patch::apply::{
    apply_package_patch, verify_file_patch, ApplyResult, PatchSources, VerifyStatus,
};

use crate::commands::lock_cli::acquire_or_emit;
use socket_patch_core::utils::purl::strip_purl_qualifiers;
use socket_patch_core::utils::telemetry::{track_patch_applied, track_patch_apply_failed};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use tempfile::TempDir;

use crate::args::{apply_env_toggles, GlobalArgs};
use crate::json_envelope::{
    AppliedVia, Command, Envelope, EnvelopeError, PatchAction, PatchEvent, PatchEventFile, Status,
};

/// Overlay every regular file from `src` into `dst` via hard link (falling
/// back to copy if hard linking fails — e.g. cross-filesystem, permission
/// quirk). Skips files that already exist at `dst`. Silently no-ops if
/// `src` doesn't exist so fresh projects with no `.socket/` cache work.
///
/// Used by `apply` to stage a transient overlay of the persistent
/// `.socket/` cache inside a tempdir so the apply pipeline can read
/// pre-cached artifacts and freshly-fetched ones from the same path
/// without ever mutating `.socket/`.
async fn overlay_dir(src: &Path, dst: &Path) {
    let mut entries = match tokio::fs::read_dir(src).await {
        Ok(e) => e,
        Err(_) => return,
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let file_type = match entry.file_type().await {
            Ok(t) => t,
            Err(_) => continue,
        };
        if !file_type.is_file() {
            continue;
        }
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if tokio::fs::metadata(&to).await.is_ok() {
            continue;
        }
        if tokio::fs::hard_link(&from, &to).await.is_err() {
            let _ = tokio::fs::copy(&from, &to).await;
        }
    }
}

use crate::ecosystem_dispatch::{find_packages_for_purls, partition_purls};

#[derive(Args)]
pub struct ApplyArgs {
    #[command(flatten)]
    pub common: GlobalArgs,

    /// Skip pre-application hash verification (apply even if package version differs).
    #[arg(short = 'f', long, env = "SOCKET_FORCE", default_value_t = false)]
    pub force: bool,
}

/// Translate the core engine's per-package [`ApplyResult`] into a single
/// patch-level [`PatchEvent`] for the unified envelope.
///
/// Action mapping (in priority order):
///   * `!result.success`                         → `Failed`
///   * `dry_run` and any file was Ready/Patched → `Verified`
///   * all `files_verified` are AlreadyPatched   → `Skipped` (already_patched)
///   * something was actually patched on disk    → `Applied`
///
/// `files` enumerates only the files that participated in the action —
/// for `Applied`, the patched ones with their `applied_via` strategy;
/// for `Verified`, every file the engine confirmed could be patched.
pub(crate) fn result_to_event(result: &ApplyResult, dry_run: bool) -> PatchEvent {
    let purl = result.package_key.clone();
    if !result.success {
        return PatchEvent::new(PatchAction::Failed, purl).with_error(
            "apply_failed",
            result
                .error
                .clone()
                .unwrap_or_else(|| "unknown error".to_string()),
        );
    }

    let all_already_patched = !result.files_verified.is_empty()
        && result
            .files_verified
            .iter()
            .all(|f| f.status == VerifyStatus::AlreadyPatched);

    if all_already_patched {
        return PatchEvent::new(PatchAction::Skipped, purl)
            .with_reason("already_patched", "All files already match afterHash");
    }

    if dry_run {
        let files = result
            .files_verified
            .iter()
            .filter(|f| {
                f.status == VerifyStatus::Ready || f.status == VerifyStatus::AlreadyPatched
            })
            .map(|f| PatchEventFile {
                path: f.file.clone(),
                verified: true,
                applied_via: None,
            })
            .collect();
        return PatchEvent::new(PatchAction::Verified, purl).with_files(files);
    }

    let files = result
        .files_patched
        .iter()
        .map(|f| PatchEventFile {
            path: f.clone(),
            verified: true,
            applied_via: result
                .applied_via
                .get(f)
                .copied()
                .map(AppliedVia::from_core),
        })
        .collect();
    // Sidecar data is NOT attached here — it's surfaced at the
    // envelope level under `Envelope.sidecars[]` by the run loop.
    // See `Envelope::record_sidecar`. Keeping events clean of
    // sidecar info means each event describes only the apply
    // action; sidecar reporting is a separate, JOIN-able list.
    PatchEvent::new(PatchAction::Applied, purl).with_files(files)
}

pub async fn run(args: ApplyArgs) -> i32 {
    apply_env_toggles(&args.common);
    let (telemetry_client, _) =
        get_api_client_with_overrides(args.common.api_client_overrides()).await;
    let api_token = telemetry_client.api_token().cloned();
    let org_slug = telemetry_client.org_slug().cloned();

    let manifest_path = args.common.resolved_manifest_path();

    // Check if manifest exists - exit successfully if no .socket folder is set up
    if tokio::fs::metadata(&manifest_path).await.is_err() {
        if args.common.json {
            let mut env = Envelope::new(Command::Apply);
            env.status = Status::NoManifest;
            env.dry_run = args.common.dry_run;
            println!("{}", env.to_pretty_json());
        } else if !args.common.silent {
            println!("No .socket folder found, skipping patch application.");
        }
        return 0;
    }

    // Serialize against concurrent socket-patch runs targeting the same
    // `.socket/` directory. The guard releases on function return; see
    // `socket_patch_core::patch::apply_lock`.
    let socket_dir = manifest_path.parent().unwrap_or(Path::new("."));
    let _lock = match acquire_or_emit(
        socket_dir,
        Command::Apply,
        args.common.json,
        args.common.silent,
        args.common.dry_run,
    ) {
        Ok(guard) => guard,
        Err(code) => return code,
    };

    // Package-manager layout detection. yarn-berry PnP keeps packages
    // inside `.yarn/cache/*.zip` and resolves them via `.pnp.cjs` —
    // the npm crawler can't reach them and rewriting zips is a
    // different operation entirely. Refuse with a clear pointer to
    // `yarn patch`. pnpm gets an informational event; the CoW guard
    // in `apply_file_patch` does the substantive safety work.
    let pkg_manager = detect_npm_pkg_manager(&args.common.cwd);
    match pkg_manager {
        NpmPkgManager::YarnBerryPnP => {
            if args.common.json {
                let mut env = Envelope::new(Command::Apply);
                env.dry_run = args.common.dry_run;
                env.mark_error(EnvelopeError::new(
                    "yarn_pnp_unsupported",
                    "yarn-berry Plug'n'Play layout is not supported by socket-patch (packages live inside .yarn/cache zips). Use `yarn patch <pkg>` instead.",
                ));
                println!("{}", env.to_pretty_json());
            } else if !args.common.silent {
                eprintln!("Error: yarn-berry Plug'n'Play layout is not supported.");
                eprintln!(
                    "  Packages live inside .yarn/cache/*.zip — socket-patch cannot rewrite them in place."
                );
                eprintln!("  Use `yarn patch <pkg>` instead.");
            }
            return 1;
        }
        NpmPkgManager::Pnpm => {
            if !args.common.json && !args.common.silent {
                eprintln!(
                    "Note: pnpm layout detected. Copy-on-write will keep the global store untouched."
                );
            }
            // Non-fatal — CoW handles the safety. JSON consumers see
            // the layout-detected info in the apply envelope's
            // existing events (no separate event added here yet).
        }
        _ => {}
    }

    match apply_patches_inner(&args, &manifest_path).await {
        Ok((success, results, unmatched)) => {
            let patched_count = results
                .iter()
                .filter(|r| r.success && !r.files_patched.is_empty())
                .count();

            if args.common.json {
                let mut env = Envelope::new(Command::Apply);
                env.dry_run = args.common.dry_run;
                for result in &results {
                    env.record(result_to_event(result, args.common.dry_run));
                    // Sidecar records live on the envelope, not on
                    // individual events. Consumers iterate
                    // `envelope.sidecars[]` and JOIN against
                    // `events[]` by `purl` for per-package context.
                    if let Some(ref sidecar) = result.sidecar {
                        env.record_sidecar(sidecar.clone());
                    }
                }
                // Manifest entries that targeted in-scope ecosystems but
                // had no installed package on disk — emit one Skipped
                // event per purl so downstream consumers can surface them.
                for purl in &unmatched {
                    env.record(
                        PatchEvent::new(PatchAction::Skipped, purl.clone()).with_reason(
                            "package_not_installed",
                            "No installed package matches this PURL",
                        ),
                    );
                }
                if !success {
                    env.mark_partial_failure();
                }
                println!("{}", env.to_pretty_json());
            } else if !args.common.silent && !results.is_empty() {
                let patched: Vec<_> = results.iter().filter(|r| r.success).collect();
                let already_patched: Vec<_> = results
                    .iter()
                    .filter(|r| {
                        r.files_verified
                            .iter()
                            .all(|f| f.status == VerifyStatus::AlreadyPatched)
                    })
                    .collect();

                if args.common.dry_run {
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

                if args.common.verbose {
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
                            if args.common.verbose {
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
                track_patch_applied(patched_count, args.common.dry_run, api_token.as_deref(), org_slug.as_deref()).await;
            } else {
                track_patch_apply_failed("One or more patches failed to apply", args.common.dry_run, api_token.as_deref(), org_slug.as_deref()).await;
            }

            if success { 0 } else { 1 }
        }
        Err(e) => {
            track_patch_apply_failed(&e, args.common.dry_run, api_token.as_deref(), org_slug.as_deref()).await;
            if args.common.json {
                let mut env = Envelope::new(Command::Apply);
                env.dry_run = args.common.dry_run;
                env.mark_error(EnvelopeError::new("apply_failed", e.clone()));
                println!("{}", env.to_pretty_json());
            } else if !args.common.silent {
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

    // The persistent cache directories under `.socket/`. Apply only ever
    // *reads* from these — writes (downloads, cleanup) happen against a
    // transient overlay tempdir constructed below when fetching is needed.
    let socket_dir = manifest_path.parent().unwrap();
    let socket_blobs_path = socket_dir.join("blobs");
    let socket_diffs_path = socket_dir.join("diffs");
    let socket_packages_path = socket_dir.join("packages");

    let download_mode = DownloadMode::parse(&args.common.download_mode).map_err(|e| e.to_string())?;

    // Compute per-patch source availability so both the offline guard
    // (next block) and the `download_needed` decision below share the
    // same notion of what's already on disk. These probes are read-only.
    let missing_blobs = get_missing_blobs(&manifest, &socket_blobs_path).await;
    let missing_diff_archives = get_missing_archives(&manifest, &socket_diffs_path).await;
    let missing_package_archives = get_missing_archives(&manifest, &socket_packages_path).await;

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

    if args.common.offline {
        // Offline: bail only if some patch has no usable local source.
        // Note: with `--force`, the apply pipeline can short-circuit
        // verification on its own; we still surface the no-source
        // diagnosis so the user runs `repair` before retrying.
        if !patches_without_source.is_empty() {
            if !args.common.silent && !args.common.json {
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
    let download_needed = !args.common.offline
        && match download_mode {
            DownloadMode::File => !missing_blobs.is_empty(),
            DownloadMode::Diff | DownloadMode::Package if missing_blobs.is_empty() => false,
            DownloadMode::Diff => !missing_diff_archives.is_empty(),
            DownloadMode::Package => !missing_package_archives.is_empty(),
        };

    // Determine where the apply pipeline should read patch sources from.
    //
    // - If nothing needs downloading (offline mode, or every required
    //   artifact is already in `.socket/`), read straight from `.socket/`.
    //   Apply is purely read-only against the persistent cache.
    // - Otherwise, stage a transient overlay tempdir that hardlinks every
    //   existing `.socket/` artifact and receives fresh downloads. Apply
    //   reads exclusively from the tempdir; `.socket/` is never mutated.
    //
    // `_stage_dir` keeps the `TempDir` handle alive for the rest of this
    // function — on drop the OS removes the directory and any downloaded
    // bytes go with it.
    let (blobs_path, diffs_path, packages_path, _stage_dir): (
        PathBuf,
        PathBuf,
        PathBuf,
        Option<TempDir>,
    ) = if download_needed {
        let stage = tempfile::tempdir().map_err(|e| e.to_string())?;
        let stage_blobs = stage.path().join("blobs");
        let stage_diffs = stage.path().join("diffs");
        let stage_packages = stage.path().join("packages");
        for dir in [&stage_blobs, &stage_diffs, &stage_packages] {
            tokio::fs::create_dir_all(dir)
                .await
                .map_err(|e| e.to_string())?;
        }
        overlay_dir(&socket_blobs_path, &stage_blobs).await;
        overlay_dir(&socket_diffs_path, &stage_diffs).await;
        overlay_dir(&socket_packages_path, &stage_packages).await;

        if !args.common.silent && !args.common.json {
            println!(
                "Downloading missing patch artifacts (mode: {})...",
                download_mode.as_tag()
            );
        }

        let (client, _) =
            get_api_client_with_overrides(args.common.api_client_overrides()).await;
        let sources = PatchSources {
            blobs_path: &stage_blobs,
            packages_path: Some(&stage_packages),
            diffs_path: Some(&stage_diffs),
        };
        let fetch_result =
            fetch_missing_sources(&manifest, &sources, download_mode, &client, None).await;

        if !args.common.silent && !args.common.json {
            println!("{}", format_fetch_result(&fetch_result));
        }

        // For non-file modes, automatically fetch any still-missing file
        // blobs as a fallback. Patches that lack the requested mode on
        // the server will still apply via the legacy blob path.
        if download_mode != DownloadMode::File {
            let still_missing_blobs = get_missing_blobs(&manifest, &stage_blobs).await;
            if !still_missing_blobs.is_empty() {
                if !args.common.silent && !args.common.json {
                    println!(
                        "Falling back to per-file blob downloads for {} blob(s)...",
                        still_missing_blobs.len()
                    );
                }
                let blob_result =
                    fetch_missing_blobs(&manifest, &stage_blobs, &client, None).await;
                if !args.common.silent && !args.common.json {
                    println!("{}", format_fetch_result(&blob_result));
                }
                if blob_result.failed > 0 && fetch_result.failed > 0 {
                    if !args.common.silent && !args.common.json {
                        eprintln!("Some artifacts could not be downloaded. Cannot apply patches.");
                    }
                    return Ok((false, Vec::new(), Vec::new()));
                }
            }
        } else if fetch_result.failed > 0 {
            if !args.common.silent && !args.common.json {
                eprintln!("Some blobs could not be downloaded. Cannot apply patches.");
            }
            return Ok((false, Vec::new(), Vec::new()));
        }

        (stage_blobs, stage_diffs, stage_packages, Some(stage))
    } else {
        (
            socket_blobs_path.clone(),
            socket_diffs_path.clone(),
            socket_packages_path.clone(),
            None,
        )
    };

    // Partition manifest PURLs by ecosystem
    let manifest_purls: Vec<String> = manifest.patches.keys().cloned().collect();
    let partitioned =
        partition_purls(&manifest_purls, args.common.ecosystems.as_deref());

    let target_manifest_purls: HashSet<String> = partitioned
        .values()
        .flat_map(|purls| purls.iter().cloned())
        .collect();

    let crawler_options = CrawlerOptions {
        cwd: args.common.cwd.clone(),
        global: args.common.global,
        global_prefix: args.common.global_prefix.clone(),
        batch_size: 100,
    };

    let all_packages =
        find_packages_for_purls(&partitioned, &crawler_options, args.common.silent || args.common.json).await;

    let has_any_purls = !partitioned.is_empty();

    if all_packages.is_empty() && !has_any_purls {
        if !args.common.silent && !args.common.json {
            if args.common.global || args.common.global_prefix.is_some() {
                eprintln!("No global packages found");
            } else {
                eprintln!("No package directories found");
            }
        }
        return Ok((false, Vec::new(), Vec::new()));
    }

    if all_packages.is_empty() {
        if !args.common.silent && !args.common.json {
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
                    args.common.dry_run,
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
                if !args.common.silent && !args.common.json {
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
                args.common.dry_run,
                args.force,
            )
            .await;

            if !result.success {
                has_errors = true;
                if !args.common.silent && !args.common.json {
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

    if !unmatched.is_empty() && !args.common.silent && !args.common.json {
        eprintln!("\nWarning: {} manifest patch(es) had no matching installed package:", unmatched.len());
        for purl in &unmatched {
            eprintln!("  - {}", purl);
        }
    }

    if !target_manifest_purls.is_empty() && matched_manifest_purls.is_empty() && !all_packages.is_empty() {
        if !args.common.silent && !args.common.json {
            eprintln!("Warning: None of the targeted manifest patches matched installed packages.");
        }
        has_errors = true;
    }

    // Post-apply summary
    if !args.common.silent && !args.common.json {
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

    // Note: `apply` deliberately does NOT garbage-collect unused blobs in
    // `.socket/`. GC is the responsibility of `socket-patch repair` /
    // `gc` / `scan --prune`. Keeping apply read-only against `.socket/`
    // means it can run repeatedly (CI dry-runs, deploy hooks) without
    // mutating patch state.

    Ok((!has_errors, results, unmatched))
}

#[cfg(test)]
mod tests {
    //! Tests for `result_to_event` — the per-package → per-patch event
    //! translator that feeds apply's unified JSON envelope. Every
    //! contract value here (action tags, `errorCode` reasons, `files[].path`
    //! shape) is documented in `CLI_CONTRACT.md`.
    use super::*;
    use socket_patch_core::patch::apply::{
        AppliedVia as CoreAppliedVia, ApplyResult, VerifyResult, VerifyStatus,
    };

    /// Build a successful `ApplyResult` with one patched file and one
    /// verified file. Used as the base for action-routing tests.
    fn sample_applied(status: VerifyStatus) -> ApplyResult {
        let mut applied_via = HashMap::new();
        applied_via.insert("package/index.js".to_string(), CoreAppliedVia::Diff);
        ApplyResult {
            package_key: "pkg:npm/minimist@1.2.2".to_string(),
            package_path: "/tmp/node_modules/minimist".to_string(),
            success: true,
            files_verified: vec![VerifyResult {
                file: "package/index.js".to_string(),
                status,
                message: None,
                current_hash: None,
                expected_hash: None,
                target_hash: None,
            }],
            files_patched: vec!["package/index.js".to_string()],
            applied_via,
            error: None,
            sidecar: None,
        }
    }

    #[test]
    fn failed_result_maps_to_failed_action() {
        let mut result = sample_applied(VerifyStatus::Ready);
        result.success = false;
        result.error = Some("hash mismatch".into());

        let event = result_to_event(&result, false);
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&event).unwrap()).unwrap();
        assert_eq!(v["action"], "failed");
        assert_eq!(v["errorCode"], "apply_failed");
        assert_eq!(v["error"], "hash mismatch");
    }

    #[test]
    fn all_already_patched_maps_to_skipped() {
        let result = sample_applied(VerifyStatus::AlreadyPatched);
        let event = result_to_event(&result, false);
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&event).unwrap()).unwrap();
        assert_eq!(v["action"], "skipped");
        assert_eq!(v["errorCode"], "already_patched");
    }

    #[test]
    fn dry_run_maps_to_verified() {
        let result = sample_applied(VerifyStatus::Ready);
        let event = result_to_event(&result, true);
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&event).unwrap()).unwrap();
        assert_eq!(v["action"], "verified");
        // Dry-run events list verified files but never an `appliedVia`
        // — nothing was actually written.
        assert_eq!(v["files"][0]["path"], "package/index.js");
        assert!(v["files"][0].as_object().unwrap().get("appliedVia").is_none());
    }

    #[test]
    fn successful_apply_maps_to_applied_with_files() {
        let result = sample_applied(VerifyStatus::Ready);
        let event = result_to_event(&result, false);
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&event).unwrap()).unwrap();
        assert_eq!(v["action"], "applied");
        assert_eq!(v["purl"], "pkg:npm/minimist@1.2.2");
        let files = v["files"].as_array().unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0]["path"], "package/index.js");
        assert_eq!(files[0]["verified"], true);
        // `appliedVia` is camelCase + lowercase tag — contract value.
        assert_eq!(files[0]["appliedVia"], "diff");
    }

    #[test]
    fn applied_event_emits_one_file_entry_per_patched_file() {
        let mut applied_via = HashMap::new();
        applied_via.insert("package/a.js".to_string(), CoreAppliedVia::Diff);
        applied_via.insert("package/b.js".to_string(), CoreAppliedVia::Package);
        applied_via.insert("package/c.js".to_string(), CoreAppliedVia::Blob);
        let result = ApplyResult {
            package_key: "pkg:npm/foo@1.0.0".to_string(),
            package_path: "/tmp/foo".to_string(),
            success: true,
            files_verified: Vec::new(),
            files_patched: vec![
                "package/a.js".to_string(),
                "package/b.js".to_string(),
                "package/c.js".to_string(),
            ],
            applied_via,
            error: None,
            sidecar: None,
        };

        let event = result_to_event(&result, false);
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&event).unwrap()).unwrap();
        let files = v["files"].as_array().unwrap();
        assert_eq!(files.len(), 3);
        let by_path: std::collections::HashMap<String, &serde_json::Value> = files
            .iter()
            .map(|f| (f["path"].as_str().unwrap().to_string(), f))
            .collect();
        assert_eq!(by_path["package/a.js"]["appliedVia"], "diff");
        assert_eq!(by_path["package/b.js"]["appliedVia"], "package");
        assert_eq!(by_path["package/c.js"]["appliedVia"], "blob");
    }
}
