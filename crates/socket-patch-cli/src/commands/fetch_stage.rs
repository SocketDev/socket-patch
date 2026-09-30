//! Shared patch-source staging for the mutating commands (`apply`, `vendor`).
//!
//! Resolves where the patch pipeline should read blob/diff artifacts from,
//! downloading what's missing into a transient overlay tempdir. The
//! persistent `.socket/{blobs,diffs}` cache is only ever *read* —
//! downloads land in the tempdir and are discarded when it drops (filling the
//! cache is `repair`'s job, keeping these commands read-only against
//! `.socket/`).

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use socket_patch_core::api::blob_fetcher::{
    fetch_missing_blobs, fetch_missing_sources, get_missing_archives, get_missing_blobs,
    DownloadMode, FetchMissingBlobsResult,
};
use socket_patch_core::api::client::ApiClient;
use socket_patch_core::manifest::schema::PatchManifest;
use socket_patch_core::patch::apply::PatchSources;
use tempfile::TempDir;

use crate::args::GlobalArgs;
use crate::ui::{plural, StatusLine};

/// Resolved artifact locations for the patch pipeline. Holds the overlay
/// `TempDir` alive — sources become invalid when this is dropped.
pub(crate) struct StagedSources {
    pub(crate) blobs: PathBuf,
    diffs: PathBuf,
    _stage: Option<TempDir>,
}

impl StagedSources {
    /// Borrow as the core pipeline's source set.
    pub(crate) fn as_patch_sources(&self) -> PatchSources<'_> {
        PatchSources {
            blobs_path: &self.blobs,
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
const APPLY_OFFLINE_REMEDY: &str = "Run `socket-patch repair` to download missing artifacts.";

/// Shared offline diagnostic: patches with no usable local source while
/// `--offline` is set (first five PURLs, then the caller's `remedy` line).
/// Prints even under `--silent` (errors only, NEVER nothing — an exit-1
/// run with zero output is undiagnosable); `--json` mutes stderr and the
/// caller's envelope is the machine channel instead.
fn report_offline_missing(common: &GlobalArgs, purls: &[&str], remedy: &str) {
    if common.json {
        return;
    }
    let n = purls.len();
    let (count, verb) = (
        plural(n, "patch", "patches"),
        if n == 1 { "has" } else { "have" },
    );
    eprintln!("Error: {count} {verb} no local source and --offline is set:");
    for line in format_purl_list(purls, 5) {
        eprintln!("{line}");
    }
    eprintln!("{remedy}");
}

/// `  - <purl>` for the first `max` purls, then `  ... and N more`.
fn format_purl_list(purls: &[&str], max: usize) -> Vec<String> {
    let mut lines: Vec<String> = purls.iter().take(max).map(|p| format!("  - {p}")).collect();
    if purls.len() > max {
        lines.push(format!("  ... and {} more", purls.len() - max));
    }
    lines
}

/// Singular and plural names of one kind of downloaded artifact.
type Noun = (&'static str, &'static str);
const BLOB: Noun = ("blob", "blobs");
const DIFF_ARCHIVE: Noun = ("diff archive", "diff archives");

/// What a fetch did, one line per non-zero outcome (`Downloaded 2 diff
/// archives`, `1 blob already present locally`), plus the failures (up to
/// five, then `... and N more`) when `with_failures`. The core formatter
/// always says "blob(s)", whatever was fetched.
fn format_fetch_summary(
    result: &FetchMissingBlobsResult,
    (one, many): Noun,
    with_failures: bool,
) -> Vec<String> {
    if result.total == 0 {
        return vec![format!("All {many} are present locally.")];
    }
    let mut lines = Vec::new();
    if result.downloaded > 0 {
        lines.push(format!(
            "Downloaded {}",
            plural(result.downloaded, one, many)
        ));
    }
    if result.skipped > 0 {
        lines.push(format!(
            "{} already present locally",
            plural(result.skipped, one, many)
        ));
    }
    if with_failures && result.failed > 0 {
        lines.extend(format_fetch_failures(result, (one, many)));
    }
    lines
}

/// `Failed to download N <noun>:` and the per-item reasons.
fn format_fetch_failures(result: &FetchMissingBlobsResult, (one, many): Noun) -> Vec<String> {
    let mut lines = vec![format!(
        "Failed to download {}:",
        plural(result.failed, one, many)
    )];
    let failed: Vec<_> = result.results.iter().filter(|r| !r.success).collect();
    for r in failed.iter().take(5) {
        // Chars, not bytes: the hash is an unvalidated manifest string.
        let short: String = r.hash.chars().take(12).collect();
        let err = r.error.as_deref().unwrap_or("unknown error");
        lines.push(format!("  - {short}...: {err}"));
    }
    if failed.len() > 5 {
        lines.push(format!("  ... and {} more", failed.len() - 5));
    }
    lines
}

/// The disk stager's status line while it downloads what `.socket/` lacks.
const DOWNLOADING_ARTIFACTS: &str = "Downloading missing patch artifacts...";

/// Announce the per-file blob top-up that follows a diff-mode fetch. It
/// runs even when every diff archive arrived — a diff cannot patch a file
/// whose bytes differ from `beforeHash`, and the pipeline then falls back
/// to the blob — so it is worded as a complement, not a failure, unless
/// some archives really were unavailable.
fn format_blob_fallback(diff_failed: usize, blobs: usize) -> String {
    let blobs = plural(blobs, "per-file blob", "per-file blobs");
    if diff_failed == 0 {
        format!("Also fetching {blobs} (used where a diff does not apply)...")
    } else {
        format!(
            "{} unavailable; fetching {blobs} instead...",
            plural(diff_failed, "diff archive", "diff archives")
        )
    }
}

/// The manifest PURLs with no usable local source. A patch is "locally
/// applicable" iff every file it touches has its `after_hash` blob on
/// disk or is covered by the patch's diff archive. A diff covers only files
/// that exist before the patch: a created file (empty `before_hash`) has
/// nothing to diff against, so it always needs its blob.
///
/// The patch pipeline picks whichever is present per file. Shared by the
/// offline gate (probed against `.socket/`) and the post-download gate
/// (probed against the staged overlay).
fn patches_without_source<'m>(
    manifest: &'m PatchManifest,
    missing_blobs: &HashSet<String>,
    missing_diff_archives: &HashSet<String>,
) -> Vec<&'m str> {
    manifest
        .patches
        .iter()
        .filter_map(|(purl, record)| {
            let diff_present = !missing_diff_archives.contains(&record.uuid);
            let files_covered = record.files.values().all(|f| {
                !missing_blobs.contains(&f.after_hash)
                    || (diff_present && !f.before_hash.is_empty())
            });
            if files_covered {
                None
            } else {
                Some(purl.as_str())
            }
        })
        .collect()
}

/// `manifest` cut down to the files a diff archive cannot patch (created
/// files, whose `before_hash` is empty): the blobs a diff-mode fetch still
/// needs even when every diff archive is present.
pub(crate) fn files_diffs_cannot_cover(manifest: &PatchManifest) -> PatchManifest {
    let patches = manifest
        .patches
        .iter()
        .filter_map(|(purl, record)| {
            let files: HashMap<_, _> = record
                .files
                .iter()
                .filter(|(_, f)| f.before_hash.is_empty())
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            (!files.is_empty()).then(|| {
                let mut record = record.clone();
                record.files = files;
                (purl.clone(), record)
            })
        })
        .collect();
    PatchManifest {
        patches,
        setup: manifest.setup.clone(),
    }
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

    let download_mode = DownloadMode::parse(&common.download_mode).map_err(|e| e.to_string())?;

    // Compute per-patch source availability so both the offline guard and
    // the `download_needed` decision share the same notion of what's already
    // on disk. These probes are read-only.
    let missing_blobs = get_missing_blobs(manifest, &socket_blobs_path).await;
    let missing_diff_archives = get_missing_archives(manifest, &socket_diffs_path).await;

    let no_source_purls = patches_without_source(manifest, &missing_blobs, &missing_diff_archives);

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
    // The patch pipeline tries sources in the order diff → blob
    // locally. We honor `--download-mode` for the primary fetch when there's
    // actually a gap to close. Skip the archive fetch entirely when all file
    // blobs are already present locally — the pipeline will succeed via the
    // blob path, so an archive fetch would be wasted round-trips. Cached
    // diff archives can still leave a patch uncovered (a created file), and
    // the blob top-up below closes that gap.
    let download_needed = !common.offline
        && match download_mode {
            DownloadMode::File => !missing_blobs.is_empty(),
            DownloadMode::Diff if missing_blobs.is_empty() => false,
            DownloadMode::Diff => !missing_diff_archives.is_empty() || !no_source_purls.is_empty(),
        };

    if !download_needed {
        return Ok(StageOutcome::Ready(StagedSources {
            blobs: socket_blobs_path,
            diffs: socket_diffs_path,
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
        _stage: Some(stage),
    };
    for dir in [&staged.blobs, &staged.diffs] {
        tokio::fs::create_dir_all(dir)
            .await
            .map_err(|e| e.to_string())?;
    }
    overlay_dir(&socket_blobs_path, &staged.blobs).await;
    overlay_dir(&socket_diffs_path, &staged.diffs).await;

    // Progress: a transient status line on stderr (stdout is data); the
    // result lines below are what stays on screen.
    let mut status = StatusLine::stderr(common.json, common.silent);
    status.set(DOWNLOADING_ARTIFACTS);

    let sources = staged.as_patch_sources();
    let fetch_result = fetch_missing_sources(manifest, &sources, download_mode, client, None).await;
    status.finish();

    // In diff mode an unavailable archive is routine (the blob top-up
    // below covers it), so its failure detail is held back and printed
    // only if the patch really ends up with no source.
    let primary_noun = match download_mode {
        DownloadMode::File => BLOB,
        DownloadMode::Diff => DIFF_ARCHIVE,
    };
    let defer_failures = download_mode != DownloadMode::File;
    if !quiet {
        for line in format_fetch_summary(&fetch_result, primary_noun, !defer_failures) {
            eprintln!("{line}");
        }
    }

    // For non-file modes, automatically fetch any still-missing file blobs as
    // a fallback. Patches that lack the requested mode on the server will
    // still apply via the legacy blob path.
    //
    // With every diff archive already cached, only the files no diff can
    // patch are fetched: that is the gap that triggered this download.
    let mut blob_fetch_failed = false;
    if download_mode != DownloadMode::File {
        let created_only;
        let blob_scope = if missing_diff_archives.is_empty() {
            created_only = files_diffs_cannot_cover(manifest);
            &created_only
        } else {
            manifest
        };
        let still_missing_blobs = get_missing_blobs(blob_scope, &staged.blobs).await;
        if !still_missing_blobs.is_empty() {
            status.set(format_blob_fallback(
                fetch_result.failed,
                still_missing_blobs.len(),
            ));
            let blob_result = fetch_missing_blobs(blob_scope, &staged.blobs, client, None).await;
            status.finish();
            if !quiet {
                for line in format_fetch_summary(&blob_result, BLOB, true) {
                    eprintln!("{line}");
                }
            }
            blob_fetch_failed = blob_result.failed > 0;
        }
    }

    // Download failures only matter per patch: bail iff some patch is left
    // with no usable source at the staged paths — the same coverage rule as
    // the offline gate. Aggregate counters can't decide this (a patch whose
    // diff failed may be covered by its blobs and vice versa).
    if fetch_result.failed > 0 || blob_fetch_failed {
        let missing_blobs = get_missing_blobs(manifest, &staged.blobs).await;
        let missing_diff_archives = get_missing_archives(manifest, &staged.diffs).await;
        let uncovered = patches_without_source(manifest, &missing_blobs, &missing_diff_archives);
        if !uncovered.is_empty() {
            // An error, not progress chatter: prints even under --silent
            // (same rule as report_offline_missing above).
            if !common.json {
                eprintln!(
                    "Error: Some patch artifacts could not be downloaded; cannot apply patches."
                );
                if defer_failures && fetch_result.failed > 0 {
                    for line in format_fetch_failures(&fetch_result, primary_noun) {
                        eprintln!("{line}");
                    }
                }
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
#[cfg(test)]
mod tests {
    use super::*;
    use socket_patch_core::api::client::get_api_client_with_overrides;

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

    /// A diff archive cannot patch a file the patch creates (nothing to diff
    /// against), so it covers such a patch only together with the created
    /// file's blob: without it, offline staging is Unavailable up front
    /// instead of passing the gate and failing mid-apply.
    #[tokio::test]
    async fn stage_offline_diff_archive_does_not_cover_a_created_file() {
        let tmp = tempfile::tempdir().unwrap();
        let socket_dir = tmp.path().join(".socket");
        std::fs::create_dir_all(socket_dir.join("diffs")).unwrap();
        std::fs::write(
            socket_dir.join("diffs").join(format!("{UUID}.tar.gz")),
            b"x",
        )
        .unwrap();
        let created = "c".repeat(64);
        let mut manifest = manifest_with_one_patch();
        manifest
            .patches
            .get_mut("pkg:npm/left-pad@1.3.0")
            .unwrap()
            .files
            .insert(
                "new.js".to_string(),
                PatchFileInfo {
                    before_hash: String::new(),
                    after_hash: created.clone(),
                },
            );

        let outcome =
            stage_patch_sources(&offline_args(), &manifest, &socket_dir, &offline_client())
                .await
                .expect("no hard failure");
        assert!(matches!(outcome, StageOutcome::Unavailable));

        std::fs::create_dir_all(socket_dir.join("blobs")).unwrap();
        std::fs::write(socket_dir.join("blobs").join(&created), b"new").unwrap();
        let outcome =
            stage_patch_sources(&offline_args(), &manifest, &socket_dir, &offline_client())
                .await
                .expect("no hard failure");
        assert!(
            matches!(outcome, StageOutcome::Ready(_)),
            "diff for the modified file + blob for the created one covers the patch"
        );
    }

    #[test]
    fn files_diffs_cannot_cover_keeps_only_created_files() {
        let mut manifest = manifest_with_one_patch();
        assert!(files_diffs_cannot_cover(&manifest).patches.is_empty());
        let record = manifest.patches.get_mut("pkg:npm/left-pad@1.3.0").unwrap();
        record.files.insert(
            "new.js".to_string(),
            PatchFileInfo {
                before_hash: String::new(),
                after_hash: "c".repeat(64),
            },
        );
        let cut = files_diffs_cannot_cover(&manifest);
        let files: Vec<&String> = cut.patches["pkg:npm/left-pad@1.3.0"].files.keys().collect();
        assert_eq!(files, ["new.js"]);
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

    /// A leftover legacy `.socket/packages/<uuid>.tar.gz` is not a source:
    /// nothing reads it, so it must not mask failed downloads.
    #[tokio::test]
    async fn stage_online_fetch_failure_ignores_legacy_package_archive() {
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
            matches!(outcome, StageOutcome::Unavailable),
            "a legacy package archive must not cover the patch"
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

/// Exact-string tests for the staging progress / error lines.
#[cfg(test)]
mod ui_format_tests {
    use super::*;
    use socket_patch_core::api::blob_fetcher::BlobFetchResult;

    fn result(
        downloaded: usize,
        skipped: usize,
        failures: &[(&str, &str)],
    ) -> FetchMissingBlobsResult {
        let mut results: Vec<BlobFetchResult> = failures
            .iter()
            .map(|(hash, err)| BlobFetchResult {
                hash: hash.to_string(),
                success: false,
                error: Some(err.to_string()),
            })
            .collect();
        results.push(BlobFetchResult {
            hash: "ok".into(),
            success: true,
            error: None,
        });
        FetchMissingBlobsResult {
            total: downloaded + skipped + failures.len(),
            downloaded,
            failed: failures.len(),
            skipped,
            results,
        }
    }

    #[test]
    fn fetch_summary_uses_the_right_noun_and_plurals() {
        assert_eq!(
            format_fetch_summary(&result(0, 0, &[]), BLOB, true),
            vec!["All blobs are present locally."]
        );
        assert_eq!(
            format_fetch_summary(&result(1, 0, &[]), DIFF_ARCHIVE, true),
            vec!["Downloaded 1 diff archive"]
        );
        assert_eq!(
            format_fetch_summary(&result(7, 1, &[]), BLOB, true),
            vec!["Downloaded 7 blobs", "1 blob already present locally"]
        );
    }

    #[test]
    fn fetch_summary_failures_are_optional_and_capped() {
        let fails: Vec<(String, String)> = (0..7)
            .map(|i| (format!("{i}{}", "a".repeat(20)), "404".to_string()))
            .collect();
        let refs: Vec<(&str, &str)> = fails
            .iter()
            .map(|(h, e)| (h.as_str(), e.as_str()))
            .collect();
        let r = result(1, 0, &refs);
        assert_eq!(
            format_fetch_summary(&r, DIFF_ARCHIVE, false),
            vec!["Downloaded 1 diff archive"]
        );
        let lines = format_fetch_summary(&r, DIFF_ARCHIVE, true);
        assert_eq!(lines[1], "Failed to download 7 diff archives:");
        assert_eq!(lines[2], "  - 0aaaaaaaaaaa...: 404");
        assert_eq!(lines.last().unwrap(), "  ... and 2 more");
        assert_eq!(lines.len(), 1 + 1 + 5 + 1);
        // A multibyte hash is cut by chars, never mid-byte.
        let r = result(0, 0, &[("é".repeat(20).as_str(), "boom")]);
        assert_eq!(
            format_fetch_failures(&r, BLOB),
            vec![
                "Failed to download 1 blob:".to_string(),
                format!("  - {}...: boom", "é".repeat(12))
            ]
        );
    }

    #[test]
    fn blob_fallback_wording() {
        assert_eq!(
            format_blob_fallback(0, 1),
            "Also fetching 1 per-file blob (used where a diff does not apply)..."
        );
        assert_eq!(
            format_blob_fallback(0, 7),
            "Also fetching 7 per-file blobs (used where a diff does not apply)..."
        );
        assert_eq!(
            format_blob_fallback(1, 3),
            "1 diff archive unavailable; fetching 3 per-file blobs instead..."
        );
        assert_eq!(
            format_blob_fallback(2, 1),
            "2 diff archives unavailable; fetching 1 per-file blob instead..."
        );
    }

    #[test]
    fn purl_list_caps_at_max_with_remainder() {
        assert!(format_purl_list(&[], 5).is_empty());
        assert_eq!(
            format_purl_list(&["pkg:npm/a@1"], 5),
            vec!["  - pkg:npm/a@1"]
        );
        let many = ["a", "b", "c", "d", "e", "f", "g"];
        let lines = format_purl_list(&many, 5);
        assert_eq!(lines.len(), 6);
        assert_eq!(lines[4], "  - e");
        assert_eq!(lines[5], "  ... and 2 more");
        assert_eq!(format_purl_list(&many[..5], 5).len(), 5);
    }
}
