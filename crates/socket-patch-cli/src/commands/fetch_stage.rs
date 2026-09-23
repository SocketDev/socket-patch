//! Shared patch-source staging for the mutating commands (`apply`, `vendor`).
//!
//! Resolves where the patch pipeline should read blob/diff/package artifacts
//! from, downloading what's missing into a transient overlay tempdir. The
//! persistent `.socket/{blobs,diffs,packages}` cache is only ever *read* —
//! downloads land in the tempdir and are discarded when it drops (filling the
//! cache is `repair`'s job, keeping these commands read-only against
//! `.socket/`).

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use socket_patch_core::api::blob_fetcher::{
    fetch_missing_blobs, fetch_missing_sources, format_fetch_result, get_missing_archives,
    get_missing_blobs, DownloadMode,
};
use socket_patch_core::api::client::{get_api_client_with_overrides, ApiClient};
use socket_patch_core::manifest::schema::{PatchManifest, PatchRecord};
use socket_patch_core::patch::apply::{is_valid_blob_hash, PatchSources};
use tempfile::TempDir;

use super::get::base64_decode;
use crate::args::GlobalArgs;
use crate::commands::bun_preflight::LedgerLoad;

/// Resolved artifact locations for the patch pipeline. Holds the overlay
/// `TempDir` alive — sources become invalid when this is dropped.
pub(crate) struct StagedSources {
    pub(crate) blobs: PathBuf,
    diffs: PathBuf,
    packages: PathBuf,
    _stage: Option<TempDir>,
}

impl StagedSources {
    /// Borrow as the core pipeline's source set.
    pub(crate) fn as_patch_sources(&self) -> PatchSources<'_> {
        PatchSources {
            blobs_path: &self.blobs,
            packages_path: Some(&self.packages),
            diffs_path: Some(&self.diffs),
            mem_blobs: None,
        }
    }

    /// Blob destination for post-stage, on-demand fetches (apply's mismatch
    /// blob top-up). When sources are read directly from `.socket/` (no
    /// overlay was staged), promote `blobs` to a transient overlay tempdir
    /// first — a late download must never land in the persistent
    /// `.socket/blobs/` cache (this module's read-only contract). `None`
    /// when the overlay cannot be created; the caller skips the fetch and
    /// the affected files fail as they would offline.
    pub(crate) async fn writable_blobs(&mut self) -> Option<&Path> {
        if self._stage.is_none() {
            let stage = tempfile::tempdir().ok()?;
            let blobs = stage.path().join("blobs");
            tokio::fs::create_dir_all(&blobs).await.ok()?;
            overlay_dir(&self.blobs, &blobs).await;
            self.blobs = blobs;
            self._stage = Some(stage);
        }
        Some(&self.blobs)
    }
}

/// The staging outcome.
pub(crate) enum StageOutcome {
    /// Every patch has a readable source at the returned paths.
    Ready(StagedSources),
    /// Sources are unavailable (offline with missing artifacts, or downloads
    /// failed). User-facing diagnostics were already printed; the caller
    /// reports command failure.
    Unavailable,
}

/// The disk stager's remedy: `repair` fills the persistent `.socket/`
/// cache `apply` reads from.
const APPLY_OFFLINE_REMEDY: &str = "Run \"socket-patch repair\" to download missing artifacts.";

/// The memory stager's remedy. Vendored content is fetched into memory and
/// never lands under `.socket/`; sending a vendored project to `repair`
/// instead would populate `.socket/blobs/` — exactly the residue vendored
/// mode promises not to leave (and from inside `repair --offline` the hint
/// was self-referential).
const VENDOR_OFFLINE_REMEDY: &str = "Re-run without --offline to fetch the missing patch \
                                     content (kept in memory; nothing is written under .socket/).";

/// Shared offline diagnostic: patches with no usable local source while
/// `--offline` is set (first five PURLs, then the caller's `remedy` line).
/// Prints even under `--silent` (errors only, NEVER nothing — an exit-1
/// run with zero output is undiagnosable); `--json` mutes stderr and the
/// caller's envelope is the machine channel instead.
fn report_offline_missing(common: &GlobalArgs, purls: &[&str], remedy: &str) {
    if common.json {
        return;
    }
    eprintln!(
        "Error: {} patch(es) have no local source and --offline is set:",
        purls.len()
    );
    for purl in purls.iter().take(5) {
        eprintln!("  - {}", purl);
    }
    if purls.len() > 5 {
        eprintln!("  ... and {} more", purls.len() - 5);
    }
    eprintln!("{remedy}");
}

/// The manifest PURLs with no usable local source. A patch is "locally
/// applicable" iff at least one of:
///   - every `after_hash` blob it references is on disk, OR
///   - its diff archive is on disk, OR
///   - its package archive is on disk.
///
/// The patch pipeline picks whichever is present per file. Shared by the
/// offline gate (probed against `.socket/`) and the post-download gate
/// (probed against the staged overlay).
fn patches_without_source<'m>(
    manifest: &'m PatchManifest,
    missing_blobs: &HashSet<String>,
    missing_diff_archives: &HashSet<String>,
    missing_package_archives: &HashSet<String>,
) -> Vec<&'m str> {
    manifest
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
        .collect()
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
/// tempdir and fetch the gap through `client` (the run's one API client —
/// building another here repeated its advisory and org-slug resolution).
/// `Err` is a hard setup failure (bad `--download-mode`, tempdir creation);
/// `Ok(Unavailable)` is the soft "cannot proceed" path with diagnostics
/// already printed.
pub(crate) async fn stage_patch_sources(
    common: &GlobalArgs,
    manifest: &PatchManifest,
    socket_dir: &Path,
    client: &ApiClient,
) -> Result<StageOutcome, String> {
    let quiet = common.silent || common.json;
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

    let no_source_purls = patches_without_source(
        manifest,
        &missing_blobs,
        &missing_diff_archives,
        &missing_package_archives,
    );

    if common.offline {
        // Offline: bail only if some patch has no usable local source.
        // Note: with `--force`, the patch pipeline can short-circuit
        // verification on its own; we still surface the no-source
        // diagnosis so the user runs `repair` before retrying.
        if !no_source_purls.is_empty() {
            report_offline_missing(common, &no_source_purls, APPLY_OFFLINE_REMEDY);
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
            DownloadMode::Diff if missing_blobs.is_empty() => false,
            DownloadMode::Diff => !missing_diff_archives.is_empty(),
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
    let staged = StagedSources {
        blobs: stage.path().join("blobs"),
        diffs: stage.path().join("diffs"),
        packages: stage.path().join("packages"),
        _stage: Some(stage),
    };
    for dir in [&staged.blobs, &staged.diffs, &staged.packages] {
        tokio::fs::create_dir_all(dir)
            .await
            .map_err(|e| e.to_string())?;
    }
    overlay_dir(&socket_blobs_path, &staged.blobs).await;
    overlay_dir(&socket_diffs_path, &staged.diffs).await;
    overlay_dir(&socket_packages_path, &staged.packages).await;

    if !quiet {
        println!(
            "Downloading missing patch artifacts (mode: {})...",
            download_mode.as_tag()
        );
    }

    let sources = staged.as_patch_sources();
    let fetch_result = fetch_missing_sources(manifest, &sources, download_mode, client, None).await;

    if !quiet {
        println!("{}", format_fetch_result(&fetch_result));
    }

    // For non-file modes, automatically fetch any still-missing file blobs as
    // a fallback. Patches that lack the requested mode on the server will
    // still apply via the legacy blob path.
    let mut blob_fetch_failed = false;
    if download_mode != DownloadMode::File {
        let still_missing_blobs = get_missing_blobs(manifest, &staged.blobs).await;
        if !still_missing_blobs.is_empty() {
            if !quiet {
                println!(
                    "Falling back to per-file blob downloads for {} blob(s)...",
                    still_missing_blobs.len()
                );
            }
            let blob_result = fetch_missing_blobs(manifest, &staged.blobs, client, None).await;
            if !quiet {
                println!("{}", format_fetch_result(&blob_result));
            }
            blob_fetch_failed = blob_result.failed > 0;
        }
    }

    // Download failures only matter per patch: bail iff some patch is left
    // with no usable source at the staged paths — the same coverage rule as
    // the offline gate. Aggregate counters can't decide this (a patch whose
    // diff failed may be covered by its blobs and vice versa, and a local
    // package archive covers its patch even though packages are never
    // downloaded).
    if fetch_result.failed > 0 || blob_fetch_failed {
        let missing_blobs = get_missing_blobs(manifest, &staged.blobs).await;
        let missing_diff_archives = get_missing_archives(manifest, &staged.diffs).await;
        let missing_package_archives = get_missing_archives(manifest, &staged.packages).await;
        let uncovered = patches_without_source(
            manifest,
            &missing_blobs,
            &missing_diff_archives,
            &missing_package_archives,
        );
        if !uncovered.is_empty() {
            // An error, not progress chatter: prints even under --silent
            // (same rule as report_offline_missing above).
            if !common.json {
                eprintln!("Some artifacts could not be downloaded. Cannot apply patches.");
            }
            return Ok(StageOutcome::Unavailable);
        }
    }

    Ok(StageOutcome::Ready(staged))
}

/// In-memory staged sources for the VENDOR flows.
///
/// Existing `.socket/` artifacts are read in place (never copied, never
/// rewritten); patch content that is missing locally is fetched into
/// MEMORY via the patch view endpoint — vendoring writes no
/// `.socket/blobs` entries and no temporary files. The committed
/// `.socket/vendor/` artifact is the patch; nothing else should land on
/// disk.
pub(crate) struct MemStagedSources {
    blobs: PathBuf,
    diffs: PathBuf,
    packages: PathBuf,
    mem: HashMap<String, Vec<u8>>,
}

impl MemStagedSources {
    /// Borrow as the core pipeline's source set (memory overlay first,
    /// on-disk artifacts as the read-only fallback).
    pub(crate) fn as_patch_sources(&self) -> PatchSources<'_> {
        PatchSources {
            blobs_path: &self.blobs,
            packages_path: Some(&self.packages),
            diffs_path: Some(&self.diffs),
            mem_blobs: Some(&self.mem),
        }
    }
}

/// The in-memory staging outcome (mirror of [`StageOutcome`]).
pub(crate) enum MemStageOutcome {
    Ready(MemStagedSources),
    Unavailable,
}

/// Stage patch sources for a VENDOR run without writing anything:
/// a record is locally satisfied when all its after-blobs are on disk or
/// a package archive is (a diff archive is NOT sufficient — vendor's
/// auto-force policy can need the full after-blob for files a diff cannot
/// reproduce); anything else has its full per-file content fetched into
/// memory from the patch view endpoint (`blobContent`), preceded by the
/// committed-artifact harvest. Offline runs with missing sources are
/// `Unavailable` with the same diagnostics as the disk stager. Unlike the
/// disk stager there is no hard-failure mode (no download-mode parse, no
/// tempdir), so this returns the outcome directly — every failure is the
/// soft `Unavailable`.
///
/// `ledger` is the caller's single `load_state` outcome (the harvest reads
/// the committed artifacts it names; an unreadable ledger harvests
/// nothing). `seed` pre-populates the in-memory blob set — the vendored
/// download phase already holds every fetched view's `blobContent`, so a
/// fresh `scan`/`get --mode vendored` never fetches a view a second time
/// here; manifest-driven callers pass an empty map. `client` is the run's
/// one API client (every CLI caller has one — building another here
/// repeated its token advisory and org-slug round-trip, under the apply
/// lock in `vendor`'s case); `None` builds one on demand, only once a fetch
/// is actually needed (the unit tests' offline arms never get that far).
pub(crate) async fn stage_vendor_sources_in_memory(
    common: &GlobalArgs,
    manifest: &PatchManifest,
    socket_dir: &Path,
    project_root: &Path,
    ledger: LedgerLoad<'_>,
    seed: HashMap<String, Vec<u8>>,
    client: Option<&ApiClient>,
) -> MemStageOutcome {
    let quiet = common.silent || common.json;
    let blobs = socket_dir.join("blobs");
    let diffs = socket_dir.join("diffs");
    let packages = socket_dir.join("packages");

    let missing_blobs = get_missing_blobs(manifest, &blobs).await;
    let missing_package_archives = get_missing_archives(manifest, &packages).await;
    let mut mem = seed;

    // A diff archive alone is NOT a sufficient source here, unlike the disk
    // stager: vendoring runs the auto-force policy, where a beforeHash
    // mismatch (already-applied tree, patch built against different bytes)
    // is overwritten with the FULL after-blob — which a diff cannot
    // produce. On-disk diffs still serve Strategy 2 for clean files; the
    // after-blob content must additionally exist (disk, seed/harvest, or
    // fetch).
    let covered = |record: &PatchRecord, mem: &HashMap<String, Vec<u8>>| {
        record
            .files
            .values()
            .all(|f| !missing_blobs.contains(&f.after_hash) || mem.contains_key(&f.after_hash))
            || !missing_package_archives.contains(&record.uuid)
    };
    let mut to_fetch: Vec<(&str, &str)> = manifest
        .patches
        .iter()
        .filter(|(_, record)| !covered(record, &mem))
        .map(|(purl, record)| (purl.as_str(), record.uuid.as_str()))
        .collect();

    if !to_fetch.is_empty() {
        // The committed vendor artifact IS the patched content: harvest its
        // afterHash blobs into memory so in-sync re-runs and fresh clones of
        // already-vendored projects stage with no network and no disk blobs.
        // Harvested bytes are hash-verified, so they win over a same-hash
        // seed entry.
        if let Ok(entries) = ledger {
            mem.extend(
                socket_patch_core::vendor::harvest_artifact_blobs_from(
                    project_root,
                    entries,
                    &manifest.patches,
                )
                .await,
            );
        }
        to_fetch.retain(|(purl, _)| {
            manifest
                .patches
                .get(*purl)
                .is_none_or(|record| !covered(record, &mem))
        });
    }

    if !to_fetch.is_empty() {
        if common.offline {
            let purls: Vec<&str> = to_fetch.iter().map(|(purl, _)| *purl).collect();
            report_offline_missing(common, &purls, VENDOR_OFFLINE_REMEDY);
            return MemStageOutcome::Unavailable;
        }

        if !quiet {
            println!(
                "Fetching {} patch(es)' content (kept in memory)...",
                to_fetch.len()
            );
        }

        let built;
        let client = match client {
            Some(client) => client,
            None => {
                built = get_api_client_with_overrides(common.api_client_overrides())
                    .await
                    .0;
                &built
            }
        };
        let mut failed: Vec<&str> = Vec::new();
        for (purl, uuid) in &to_fetch {
            match client.fetch_patch(uuid).await {
                Ok(Some(patch)) => {
                    let mut complete = true;
                    for (file, info) in &patch.files {
                        let (Some(b64), Some(hash)) = (&info.blob_content, &info.after_hash) else {
                            // An error, not progress chatter: prints even
                            // under --silent (same rule as
                            // report_offline_missing above).
                            if !common.json {
                                eprintln!("  [error] {purl}: no blob content served for {file}");
                            }
                            complete = false;
                            break;
                        };
                        // Same key guard as the disk writer: the hash names the
                        // lookup key the apply pipeline gates writes on.
                        if !is_valid_blob_hash(hash) {
                            complete = false;
                            break;
                        }
                        match base64_decode(b64) {
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
            // An error, not progress chatter: the vendor caller only marks
            // the envelope (printed exclusively under --json), so muting
            // this under --silent meant exit 1 with zero output — the
            // CLI_CONTRACT violation ("errors only", NEVER nothing) fixed
            // for the disk stager's arms above.
            if !common.json {
                eprintln!(
                    "Error: could not fetch patch content for {} patch(es):",
                    failed.len()
                );
                for purl in failed.iter().take(5) {
                    eprintln!("  - {}", purl);
                }
            }
            return MemStageOutcome::Unavailable;
        }
    }

    MemStageOutcome::Ready(MemStagedSources {
        blobs,
        diffs,
        packages,
        mem,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use socket_patch_core::manifest::schema::{PatchFileInfo, PatchRecord};

    const UUID: &str = "11111111-1111-4111-8111-111111111111";
    // 64 ascii-hex, the shape `is_valid_blob_hash` accepts.
    const HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn manifest_with_one_patch() -> PatchManifest {
        let mut files = HashMap::new();
        files.insert(
            "index.js".to_string(),
            PatchFileInfo {
                before_hash: "b".repeat(64),
                after_hash: HASH.to_string(),
            },
        );
        let mut manifest = PatchManifest::new();
        manifest.patches.insert(
            "pkg:npm/left-pad@1.3.0".to_string(),
            PatchRecord {
                uuid: UUID.to_string(),
                exported_at: "2026-01-01T00:00:00Z".to_string(),
                files,
                vulnerabilities: HashMap::new(),
                description: String::new(),
                license: "MIT".to_string(),
                tier: "free".to_string(),
            },
        );
        manifest
    }

    fn offline_args() -> GlobalArgs {
        GlobalArgs {
            offline: true,
            silent: true,
            ..GlobalArgs::default()
        }
    }

    /// A network-free client for the offline arms (never used: they return
    /// before any fetch), built directly so no ambient token or socket-cli
    /// config can leak into a unit test.
    fn offline_client() -> ApiClient {
        ApiClient::new(socket_patch_core::api::client::ApiClientOptions {
            api_url: "http://127.0.0.1:1".to_string(),
            api_token: None,
            use_public_proxy: false,
            org_slug: None,
        })
    }

    /// The client `dead_endpoint_args` describes (see there).
    async fn dead_endpoint_client(args: &GlobalArgs) -> ApiClient {
        get_api_client_with_overrides(args.api_client_overrides())
            .await
            .0
    }

    /// Everything cached → read `.socket/` in place: no overlay tempdir, and
    /// the returned paths are the persistent cache dirs themselves.
    #[tokio::test]
    async fn stage_reads_socket_dir_in_place_when_fully_cached() {
        let tmp = tempfile::tempdir().unwrap();
        let socket_dir = tmp.path().join(".socket");
        std::fs::create_dir_all(socket_dir.join("blobs")).unwrap();
        std::fs::write(socket_dir.join("blobs").join(HASH), b"patched").unwrap();

        let outcome = stage_patch_sources(
            &offline_args(),
            &manifest_with_one_patch(),
            &socket_dir,
            &offline_client(),
        )
        .await
        .expect("no hard failure");
        let StageOutcome::Ready(staged) = outcome else {
            panic!("fully-cached staging must be Ready");
        };
        assert!(staged._stage.is_none(), "no overlay when nothing to fetch");
        assert_eq!(staged.blobs, socket_dir.join("blobs"));
    }

    /// Offline with no usable source → Unavailable, and the read-only
    /// contract holds: staging must not create or write `.socket/`.
    #[tokio::test]
    async fn stage_offline_with_missing_sources_is_unavailable_and_writes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let socket_dir = tmp.path().join(".socket");

        let outcome = stage_patch_sources(
            &offline_args(),
            &manifest_with_one_patch(),
            &socket_dir,
            &offline_client(),
        )
        .await
        .expect("no hard failure");
        assert!(
            matches!(outcome, StageOutcome::Unavailable),
            "offline + no local source must be Unavailable"
        );
        assert!(
            !socket_dir.exists(),
            "the stager is read-only against .socket/ — it must not create it"
        );
    }

    /// A diff archive alone satisfies the disk stager (the pipeline can apply
    /// via the diff path), even with every blob missing.
    #[tokio::test]
    async fn stage_offline_accepts_diff_archive_as_sole_source() {
        let tmp = tempfile::tempdir().unwrap();
        let socket_dir = tmp.path().join(".socket");
        std::fs::create_dir_all(socket_dir.join("diffs")).unwrap();
        std::fs::write(
            socket_dir.join("diffs").join(format!("{UUID}.tar.gz")),
            b"x",
        )
        .unwrap();

        let outcome = stage_patch_sources(
            &offline_args(),
            &manifest_with_one_patch(),
            &socket_dir,
            &offline_client(),
        )
        .await
        .expect("no hard failure");
        assert!(
            matches!(outcome, StageOutcome::Ready(_)),
            "a present diff archive is a usable source for the disk stager"
        );
    }

    /// The vendor (in-memory) stager documents the opposite policy: a diff
    /// archive is NOT sufficient (auto-force can need the full after-blob),
    /// so the same fixture that satisfies the disk stager is Unavailable
    /// offline here. Pins the asymmetry both module docs describe.
    #[tokio::test]
    async fn mem_stage_offline_rejects_diff_archive_as_sole_source() {
        let tmp = tempfile::tempdir().unwrap();
        let socket_dir = tmp.path().join(".socket");
        std::fs::create_dir_all(socket_dir.join("diffs")).unwrap();
        std::fs::write(
            socket_dir.join("diffs").join(format!("{UUID}.tar.gz")),
            b"x",
        )
        .unwrap();
        let project_root = tmp.path().join("proj");
        std::fs::create_dir_all(&project_root).unwrap();

        let outcome = stage_vendor_sources_in_memory(
            &offline_args(),
            &manifest_with_one_patch(),
            &socket_dir,
            &project_root,
            Ok(&HashMap::new()),
            HashMap::new(),
            None,
        )
        .await;
        assert!(
            matches!(outcome, MemStageOutcome::Unavailable),
            "vendor staging must not treat a diff archive as a usable source"
        );
    }

    /// The download phase's blob seed IS a source: with every after-hash
    /// seeded, an offline run with no disk blobs, no archives and no
    /// committed artifact is Ready and stages the seeded bytes (no fetch,
    /// no harvest needed) — the vendored flows never fetch a view twice.
    #[tokio::test]
    async fn mem_stage_seeded_blobs_are_ready_offline_without_any_disk_source() {
        let tmp = tempfile::tempdir().unwrap();
        let socket_dir = tmp.path().join(".socket");
        let project_root = tmp.path().join("proj");
        std::fs::create_dir_all(&project_root).unwrap();
        let seed: HashMap<String, Vec<u8>> = [(HASH.to_string(), b"seeded".to_vec())].into();

        let outcome = stage_vendor_sources_in_memory(
            &offline_args(),
            &manifest_with_one_patch(),
            &socket_dir,
            &project_root,
            Ok(&HashMap::new()),
            seed,
            None,
        )
        .await;
        let MemStageOutcome::Ready(staged) = outcome else {
            panic!("a fully seeded stage must be Ready");
        };
        assert_eq!(
            staged.mem.get(HASH).map(Vec::as_slice),
            Some(&b"seeded"[..]),
            "the seeded bytes are the staged content"
        );
        assert!(
            !socket_dir.exists(),
            "in-memory staging must not create .socket/"
        );
    }

    /// A seed covering only SOME hashes still leaves the rest to the
    /// ladder: offline with nothing else, the record is Unavailable (the
    /// seed is merged, never treated as complete coverage).
    #[tokio::test]
    async fn mem_stage_partial_seed_still_needs_the_missing_hash() {
        let tmp = tempfile::tempdir().unwrap();
        let socket_dir = tmp.path().join(".socket");
        let project_root = tmp.path().join("proj");
        std::fs::create_dir_all(&project_root).unwrap();
        let mut manifest = manifest_with_one_patch();
        manifest
            .patches
            .get_mut("pkg:npm/left-pad@1.3.0")
            .unwrap()
            .files
            .insert(
                "other.js".to_string(),
                PatchFileInfo {
                    before_hash: "d".repeat(64),
                    after_hash: "e".repeat(64),
                },
            );
        let seed: HashMap<String, Vec<u8>> = [(HASH.to_string(), b"seeded".to_vec())].into();

        let outcome = stage_vendor_sources_in_memory(
            &offline_args(),
            &manifest,
            &socket_dir,
            &project_root,
            Ok(&HashMap::new()),
            seed,
            None,
        )
        .await;
        assert!(
            matches!(outcome, MemStageOutcome::Unavailable),
            "one seeded hash out of two is not coverage"
        );
    }

    /// An unreadable ledger (`Err`) harvests nothing — and is not an
    /// error here: the caller reports the corrupt ledger itself.
    #[tokio::test]
    async fn mem_stage_unreadable_ledger_skips_the_harvest() {
        let tmp = tempfile::tempdir().unwrap();
        let socket_dir = tmp.path().join(".socket");
        let project_root = tmp.path().join("proj");
        std::fs::create_dir_all(&project_root).unwrap();
        let err = std::io::Error::other("corrupt state.json");

        let outcome = stage_vendor_sources_in_memory(
            &offline_args(),
            &manifest_with_one_patch(),
            &socket_dir,
            &project_root,
            Err(&err),
            HashMap::new(),
            None,
        )
        .await;
        assert!(matches!(outcome, MemStageOutcome::Unavailable));
    }

    /// GlobalArgs wired to a guaranteed-unreachable API endpoint: explicit
    /// token + org overrides keep client construction network-free, and the
    /// URL points at a port that was just bound and released, so every fetch
    /// fails fast with connection-refused.
    fn dead_endpoint_args() -> GlobalArgs {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        GlobalArgs {
            silent: true,
            api_url: Some(format!("http://127.0.0.1:{port}")),
            api_token: Some(format!("sktsec_{}_api", "x".repeat(44))),
            org: Some("test-org".to_string()),
            ..GlobalArgs::default()
        }
    }

    /// A local package archive is a usable source (the pipeline's Strategy 1,
    /// and exactly what the offline gate rules), so an online run whose
    /// downloads all fail must still be Ready when the package archive covers
    /// every patch. Regression: the failure gate used aggregate fetch
    /// counters and never consulted package archives, so this cache state was
    /// Unavailable online while succeeding with --offline.
    #[tokio::test]
    async fn stage_online_fetch_failure_accepts_local_package_archive() {
        let tmp = tempfile::tempdir().unwrap();
        let socket_dir = tmp.path().join(".socket");
        std::fs::create_dir_all(socket_dir.join("packages")).unwrap();
        std::fs::write(
            socket_dir.join("packages").join(format!("{UUID}.tar.gz")),
            b"x",
        )
        .unwrap();

        let args = dead_endpoint_args();
        let outcome = stage_patch_sources(
            &args,
            &manifest_with_one_patch(),
            &socket_dir,
            &dead_endpoint_client(&args).await,
        )
        .await
        .expect("no hard failure");
        assert!(
            matches!(outcome, StageOutcome::Ready(_)),
            "a local package archive covers the patch even when every download fails"
        );
    }

    /// Same coverage rule in file mode: a local diff archive is a usable
    /// source (pinned offline by `stage_offline_accepts_diff_archive_as_sole_source`),
    /// so a failed blob download must not flip the outcome to Unavailable.
    #[tokio::test]
    async fn stage_online_file_mode_blob_failure_accepts_local_diff_archive() {
        let tmp = tempfile::tempdir().unwrap();
        let socket_dir = tmp.path().join(".socket");
        std::fs::create_dir_all(socket_dir.join("diffs")).unwrap();
        std::fs::write(
            socket_dir.join("diffs").join(format!("{UUID}.tar.gz")),
            b"x",
        )
        .unwrap();

        let args = GlobalArgs {
            download_mode: "file".to_string(),
            ..dead_endpoint_args()
        };
        let outcome = stage_patch_sources(
            &args,
            &manifest_with_one_patch(),
            &socket_dir,
            &dead_endpoint_client(&args).await,
        )
        .await
        .expect("no hard failure");
        assert!(
            matches!(outcome, StageOutcome::Ready(_)),
            "a local diff archive covers the patch even when the blob download fails"
        );
    }

    /// Overshoot guard for the per-patch coverage gate: with no local source
    /// at all, failed downloads must still yield Unavailable.
    #[tokio::test]
    async fn stage_online_fetch_failure_with_no_local_source_is_unavailable() {
        let tmp = tempfile::tempdir().unwrap();
        let socket_dir = tmp.path().join(".socket");

        let args = dead_endpoint_args();
        let outcome = stage_patch_sources(
            &args,
            &manifest_with_one_patch(),
            &socket_dir,
            &dead_endpoint_client(&args).await,
        )
        .await
        .expect("no hard failure");
        assert!(
            matches!(outcome, StageOutcome::Unavailable),
            "no source anywhere + failed downloads must be Unavailable"
        );
    }

    /// An unknown `--download-mode` is a hard setup failure (Err), not a
    /// soft Unavailable.
    #[tokio::test]
    async fn stage_rejects_unknown_download_mode() {
        let tmp = tempfile::tempdir().unwrap();
        let args = GlobalArgs {
            download_mode: "bogus".to_string(),
            silent: true,
            ..GlobalArgs::default()
        };
        let Err(err) = stage_patch_sources(
            &args,
            &manifest_with_one_patch(),
            tmp.path(),
            &offline_client(),
        )
        .await
        else {
            panic!("an unparseable download mode is a hard failure");
        };
        assert!(
            err.contains("bogus"),
            "diagnostic names the bad mode: {err}"
        );
    }

    /// `writable_blobs` promotes an in-place (no-overlay) source set to a
    /// transient overlay: the returned dir is NOT `.socket/blobs`, existing
    /// blobs are pre-seeded into it, and a late download that lands there
    /// leaves the persistent cache untouched.
    #[tokio::test]
    async fn writable_blobs_promotes_to_overlay_and_preserves_cache() {
        let tmp = tempfile::tempdir().unwrap();
        let socket_dir = tmp.path().join(".socket");
        std::fs::create_dir_all(socket_dir.join("blobs")).unwrap();
        std::fs::write(socket_dir.join("blobs").join(HASH), b"cached").unwrap();

        let outcome = stage_patch_sources(
            &offline_args(),
            &manifest_with_one_patch(),
            &socket_dir,
            &offline_client(),
        )
        .await
        .expect("no hard failure");
        let StageOutcome::Ready(mut staged) = outcome else {
            panic!("fully-cached staging must be Ready");
        };

        let writable = staged.writable_blobs().await.expect("overlay created");
        assert_ne!(
            writable,
            socket_dir.join("blobs"),
            "late downloads must never target the persistent cache"
        );
        assert!(
            writable.join(HASH).exists(),
            "the overlay is pre-seeded with the cached blobs"
        );

        std::fs::write(writable.join("late-download"), b"new").unwrap();
        assert!(
            !socket_dir.join("blobs").join("late-download").exists(),
            "a write into the overlay must not appear in .socket/blobs"
        );
        // Stable across calls: a second call reuses the same overlay.
        let again = staged.writable_blobs().await.unwrap().to_path_buf();
        assert!(again.join("late-download").exists());
    }

    /// `overlay_dir` mirrors regular files only, and never clobbers a file
    /// already present at the destination.
    #[tokio::test]
    async fn overlay_dir_mirrors_files_skips_dirs_and_existing() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        let dst = tmp.path().join("dst");
        std::fs::create_dir_all(src.join("subdir")).unwrap();
        std::fs::create_dir_all(&dst).unwrap();
        std::fs::write(src.join("a"), b"from-src").unwrap();
        std::fs::write(src.join("b"), b"from-src").unwrap();
        std::fs::write(dst.join("b"), b"already-there").unwrap();

        overlay_dir(&src, &dst).await;

        assert_eq!(std::fs::read(dst.join("a")).unwrap(), b"from-src");
        assert_eq!(
            std::fs::read(dst.join("b")).unwrap(),
            b"already-there",
            "existing destination files are never overwritten"
        );
        assert!(!dst.join("subdir").exists(), "directories are not mirrored");
    }

    /// The hardlink-failure copy fallback — the PRIMARY mirror path when
    /// `.socket/` and the overlay tempdir sit on different filesystems
    /// (EXDEV; e.g. tmpfs /tmp on Linux). Same-volume tempdirs always
    /// hardlink, so force the arm deterministically: a DANGLING symlink at
    /// the destination makes `metadata` err (follows the link — the
    /// existing-file skip does not fire), makes `hard_link` fail (the link
    /// occupies the path), and lets `copy` succeed by writing THROUGH the
    /// link into its target.
    #[cfg(unix)]
    #[tokio::test]
    async fn overlay_dir_falls_back_to_copy_when_hardlink_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        let dst = tmp.path().join("dst");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::create_dir_all(&dst).unwrap();
        std::fs::write(src.join("a"), b"from-src").unwrap();
        // Dangling link: the target does not exist yet.
        let resolved = tmp.path().join("resolved");
        std::os::unix::fs::symlink(&resolved, dst.join("a")).unwrap();

        overlay_dir(&src, &dst).await;

        // hard_link never replaces an occupied path, so the entry must
        // still be the symlink — the bytes can only have arrived via the
        // copy arm.
        assert!(
            dst.join("a")
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink(),
            "the destination entry stays a symlink (hard_link cannot have run)"
        );
        assert_eq!(
            std::fs::read(dst.join("a")).unwrap(),
            b"from-src",
            "the mirrored bytes are readable at the destination path"
        );
        assert_eq!(
            std::fs::read(&resolved).unwrap(),
            b"from-src",
            "proof the copy arm ran: only a write-through-the-link copy \
             creates the link target"
        );
    }
}
