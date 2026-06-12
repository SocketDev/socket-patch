//! Shared patch-source staging for the mutating commands (`apply`, `vendor`).
//!
//! Resolves where the patch pipeline should read blob/diff/package artifacts
//! from, downloading what's missing into a transient overlay tempdir. The
//! persistent `.socket/{blobs,diffs,packages}` cache is only ever *read* —
//! downloads land in the tempdir and are discarded when it drops (filling the
//! cache is `repair`'s job, keeping these commands read-only against
//! `.socket/`).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use socket_patch_core::api::blob_fetcher::{
    fetch_missing_blobs, fetch_missing_sources, format_fetch_result, get_missing_archives,
    get_missing_blobs, DownloadMode,
};
use socket_patch_core::api::client::get_api_client_with_overrides;
use socket_patch_core::manifest::schema::PatchManifest;
use socket_patch_core::patch::apply::PatchSources;
use tempfile::TempDir;

use crate::args::GlobalArgs;

/// Resolved artifact locations for the patch pipeline. Holds the overlay
/// `TempDir` alive — sources become invalid when this is dropped.
pub struct StagedSources {
    pub blobs: PathBuf,
    pub diffs: PathBuf,
    pub packages: PathBuf,
    _stage: Option<TempDir>,
}

impl StagedSources {
    /// Borrow as the core pipeline's source set.
    pub fn as_patch_sources(&self) -> PatchSources<'_> {
        PatchSources {
            blobs_path: &self.blobs,
            packages_path: Some(&self.packages),
            diffs_path: Some(&self.diffs),
            mem_blobs: None,
        }
    }
}

/// The staging outcome.
pub enum StageOutcome {
    /// Every patch has a readable source at the returned paths.
    Ready(StagedSources),
    /// Sources are unavailable (offline with missing artifacts, or downloads
    /// failed). User-facing diagnostics were already printed; the caller
    /// reports command failure.
    Unavailable,
}

/// Mirror `src`'s files into `dst` by hardlink (copy fallback). Pre-seeds the
/// overlay tempdir with everything already cached so only the gap downloads.
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

/// Resolve patch sources for `manifest`: read straight from `.socket/` when
/// everything needed is cached (or `--offline`), else stage an overlay
/// tempdir and fetch the gap. `Err` is a hard setup failure (bad
/// `--download-mode`, tempdir creation); `Ok(Unavailable)` is the soft
/// "cannot proceed" path with diagnostics already printed.
pub async fn stage_patch_sources(
    common: &GlobalArgs,
    manifest: &PatchManifest,
    socket_dir: &Path,
) -> Result<StageOutcome, String> {
    let socket_blobs_path = socket_dir.join("blobs");
    let socket_diffs_path = socket_dir.join("diffs");
    let socket_packages_path = socket_dir.join("packages");

    let download_mode = DownloadMode::parse(&common.download_mode).map_err(|e| e.to_string())?;

    // Compute per-patch source availability so both the offline guard and
    // the `download_needed` decision share the same notion of what's already
    // on disk. These probes are read-only.
    let missing_blobs = get_missing_blobs(manifest, &socket_blobs_path).await;
    let missing_diff_archives = get_missing_archives(manifest, &socket_diffs_path).await;
    let missing_package_archives = get_missing_archives(manifest, &socket_packages_path).await;

    // A patch is "locally applicable" iff at least one of:
    //   - every `after_hash` blob it references is on disk, OR
    //   - its diff archive is on disk, OR
    //   - its package archive is on disk.
    // The patch pipeline picks whichever is present per file.
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

    if common.offline {
        // Offline: bail only if some patch has no usable local source.
        // Note: with `--force`, the patch pipeline can short-circuit
        // verification on its own; we still surface the no-source
        // diagnosis so the user runs `repair` before retrying.
        if !patches_without_source.is_empty() {
            if !common.silent && !common.json {
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
            return Ok(StageOutcome::Unavailable);
        }
    }

    // Decide what (if anything) needs downloading.
    //
    // The patch pipeline tries sources in the order package → diff → blob
    // locally. We honor `--download-mode` for the primary fetch when there's
    // actually a gap to close. Skip the archive fetch entirely when all file
    // blobs are already present locally — the pipeline will succeed via the
    // blob path, and the archive endpoints would just 404 (current server
    // doesn't serve them yet).
    let download_needed = !common.offline
        && match download_mode {
            DownloadMode::File => !missing_blobs.is_empty(),
            DownloadMode::Diff | DownloadMode::Package if missing_blobs.is_empty() => false,
            DownloadMode::Diff => !missing_diff_archives.is_empty(),
            DownloadMode::Package => !missing_package_archives.is_empty(),
        };

    if !download_needed {
        return Ok(StageOutcome::Ready(StagedSources {
            blobs: socket_blobs_path,
            diffs: socket_diffs_path,
            packages: socket_packages_path,
            _stage: None,
        }));
    }

    // Stage a transient overlay tempdir that hardlinks every existing
    // `.socket/` artifact and receives fresh downloads. The pipeline reads
    // exclusively from the tempdir; `.socket/` is never mutated. Dropping
    // `StagedSources` removes the directory and any downloaded bytes.
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

    if !common.silent && !common.json {
        println!(
            "Downloading missing patch artifacts (mode: {})...",
            download_mode.as_tag()
        );
    }

    let (client, _) = get_api_client_with_overrides(common.api_client_overrides()).await;
    let sources = PatchSources {
        blobs_path: &stage_blobs,
        packages_path: Some(&stage_packages),
        diffs_path: Some(&stage_diffs),
        mem_blobs: None,
    };
    let fetch_result =
        fetch_missing_sources(manifest, &sources, download_mode, &client, None).await;

    if !common.silent && !common.json {
        println!("{}", format_fetch_result(&fetch_result));
    }

    // For non-file modes, automatically fetch any still-missing file blobs as
    // a fallback. Patches that lack the requested mode on the server will
    // still apply via the legacy blob path.
    if download_mode != DownloadMode::File {
        let still_missing_blobs = get_missing_blobs(manifest, &stage_blobs).await;
        if !still_missing_blobs.is_empty() {
            if !common.silent && !common.json {
                println!(
                    "Falling back to per-file blob downloads for {} blob(s)...",
                    still_missing_blobs.len()
                );
            }
            let blob_result = fetch_missing_blobs(manifest, &stage_blobs, &client, None).await;
            if !common.silent && !common.json {
                println!("{}", format_fetch_result(&blob_result));
            }
            if blob_result.failed > 0 && fetch_result.failed > 0 {
                if !common.silent && !common.json {
                    eprintln!("Some artifacts could not be downloaded. Cannot apply patches.");
                }
                return Ok(StageOutcome::Unavailable);
            }
        }
    } else if fetch_result.failed > 0 {
        if !common.silent && !common.json {
            eprintln!("Some blobs could not be downloaded. Cannot apply patches.");
        }
        return Ok(StageOutcome::Unavailable);
    }

    Ok(StageOutcome::Ready(StagedSources {
        blobs: stage_blobs,
        diffs: stage_diffs,
        packages: stage_packages,
        _stage: Some(stage),
    }))
}

/// In-memory staged sources for the VENDOR flows.
///
/// Existing `.socket/` artifacts are read in place (never copied, never
/// rewritten); patch content that is missing locally is fetched into
/// MEMORY via the patch view endpoint — vendoring writes no
/// `.socket/blobs` entries and no temporary files. The committed
/// `.socket/vendor/` artifact is the patch; nothing else should land on
/// disk.
pub struct MemStagedSources {
    blobs: PathBuf,
    diffs: PathBuf,
    packages: PathBuf,
    mem: HashMap<String, Vec<u8>>,
}

impl MemStagedSources {
    /// Borrow as the core pipeline's source set (memory overlay first,
    /// on-disk artifacts as the read-only fallback).
    pub fn as_patch_sources(&self) -> PatchSources<'_> {
        PatchSources {
            blobs_path: &self.blobs,
            packages_path: Some(&self.packages),
            diffs_path: Some(&self.diffs),
            mem_blobs: Some(&self.mem),
        }
    }
}

/// The in-memory staging outcome (mirror of [`StageOutcome`]).
pub enum MemStageOutcome {
    Ready(MemStagedSources),
    Unavailable,
}

/// Stage patch sources for a VENDOR run without writing anything:
/// per-record availability follows the same rule as
/// [`stage_patch_sources`] (all after-blobs on disk, or a diff/package
/// archive on disk), and records with no usable local source have their
/// full per-file content fetched into memory from the patch view
/// endpoint (`blobContent`). Offline runs with missing sources are
/// `Unavailable` with the same diagnostics as the disk stager.
pub async fn stage_vendor_sources_in_memory(
    common: &GlobalArgs,
    manifest: &PatchManifest,
    socket_dir: &Path,
    project_root: &Path,
) -> Result<MemStageOutcome, String> {
    let blobs = socket_dir.join("blobs");
    let diffs = socket_dir.join("diffs");
    let packages = socket_dir.join("packages");

    let missing_blobs = get_missing_blobs(manifest, &blobs).await;
    let missing_diff_archives = get_missing_archives(manifest, &diffs).await;
    let missing_package_archives = get_missing_archives(manifest, &packages).await;

    let mut to_fetch: Vec<(&str, &str)> = manifest
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
                Some((purl.as_str(), record.uuid.as_str()))
            }
        })
        .collect();

    if to_fetch.is_empty() {
        return Ok(MemStageOutcome::Ready(MemStagedSources {
            blobs,
            diffs,
            packages,
            mem: HashMap::new(),
        }));
    }

    // The committed vendor artifact IS the patched content: harvest its
    // afterHash blobs into memory so in-sync re-runs and fresh clones of
    // already-vendored projects stage with no network and no disk blobs.
    let mut mem =
        socket_patch_core::patch::vendor::harvest_artifact_blobs(project_root, &manifest.patches)
            .await;
    if !mem.is_empty() {
        to_fetch.retain(|(purl, _)| {
            manifest.patches.get(*purl).is_none_or(|record| {
                !record.files.values().all(|f| {
                    !missing_blobs.contains(&f.after_hash) || mem.contains_key(&f.after_hash)
                })
            })
        });
        if to_fetch.is_empty() {
            return Ok(MemStageOutcome::Ready(MemStagedSources {
                blobs,
                diffs,
                packages,
                mem,
            }));
        }
    }

    if common.offline {
        if !common.silent && !common.json {
            eprintln!(
                "Error: {} patch(es) have no local source and --offline is set:",
                to_fetch.len()
            );
            for (purl, _) in to_fetch.iter().take(5) {
                eprintln!("  - {}", purl);
            }
            if to_fetch.len() > 5 {
                eprintln!("  ... and {} more", to_fetch.len() - 5);
            }
            eprintln!("Run \"socket-patch repair\" to download missing artifacts.");
        }
        return Ok(MemStageOutcome::Unavailable);
    }

    if !common.silent && !common.json {
        println!(
            "Fetching {} patch(es)' content (kept in memory)...",
            to_fetch.len()
        );
    }

    let (client, _) = get_api_client_with_overrides(common.api_client_overrides()).await;
    let mut failed: Vec<&str> = Vec::new();
    for (purl, uuid) in &to_fetch {
        match client.fetch_patch(common.org.as_deref(), uuid).await {
            Ok(Some(patch)) => {
                let mut complete = true;
                for (file, info) in &patch.files {
                    let (Some(b64), Some(hash)) = (&info.blob_content, &info.after_hash) else {
                        if !common.silent && !common.json {
                            eprintln!("  [error] {purl}: no blob content served for {file}");
                        }
                        complete = false;
                        break;
                    };
                    // Same key guard as the disk writer: the hash names the
                    // lookup key the apply pipeline gates writes on.
                    if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
                        complete = false;
                        break;
                    }
                    match super::get::base64_decode(b64) {
                        Ok(bytes) => {
                            mem.insert(hash.clone(), bytes);
                        }
                        Err(_) => {
                            complete = false;
                            break;
                        }
                    }
                }
                if !complete {
                    failed.push(purl);
                }
            }
            _ => failed.push(purl),
        }
    }
    if !failed.is_empty() {
        if !common.silent && !common.json {
            eprintln!(
                "Error: could not fetch patch content for {} patch(es):",
                failed.len()
            );
            for purl in failed.iter().take(5) {
                eprintln!("  - {}", purl);
            }
        }
        return Ok(MemStageOutcome::Unavailable);
    }

    Ok(MemStageOutcome::Ready(MemStagedSources {
        blobs,
        diffs,
        packages,
        mem,
    }))
}
