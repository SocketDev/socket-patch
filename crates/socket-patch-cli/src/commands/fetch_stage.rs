//! Shared patch-source staging for the mutating commands (`apply`, `vendor`).
//!
//! Resolves where the patch pipeline should read per-file blobs from,
//! downloading what's missing into a transient overlay tempdir. The
//! persistent `.socket/blobs` cache is only ever *read* —
//! downloads land in the tempdir and are discarded when it drops (filling the
//! cache is `repair`'s job, keeping these commands read-only against
//! `.socket/`).

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use socket_patch_core::api::blob_fetcher::{
    fetch_missing_blobs, get_missing_blobs, FetchMissingBlobsResult,
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
    blobs: PathBuf,
    _stage: Option<TempDir>,
}

impl StagedSources {
    /// Borrow as the core pipeline's source set.
    pub(crate) fn as_patch_sources(&self) -> PatchSources<'_> {
        PatchSources {
            blobs_path: &self.blobs,
            mem_blobs: None,
        }
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

/// What a blob fetch did, one line per non-zero outcome (`Downloaded 2
/// blobs`, `1 blob already present locally`), plus the failures (up to
/// five, then `... and N more`).
fn format_fetch_summary(result: &FetchMissingBlobsResult) -> Vec<String> {
    if result.total == 0 {
        return vec!["All blobs are present locally.".to_string()];
    }
    let mut lines = Vec::new();
    if result.downloaded > 0 {
        lines.push(format!(
            "Downloaded {}",
            plural(result.downloaded, "blob", "blobs")
        ));
    }
    if result.skipped > 0 {
        lines.push(format!(
            "{} already present locally",
            plural(result.skipped, "blob", "blobs")
        ));
    }
    if result.failed > 0 {
        lines.extend(format_fetch_failures(result));
    }
    lines
}

/// `Failed to download N blobs:` and the per-item reasons.
fn format_fetch_failures(result: &FetchMissingBlobsResult) -> Vec<String> {
    let mut lines = vec![format!(
        "Failed to download {}:",
        plural(result.failed, "blob", "blobs")
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

/// The manifest PURLs with no usable local source: some file the patch
/// touches has no `after_hash` blob in `missing_blobs`' directory. Shared by
/// the offline gate (probed against `.socket/`) and the post-download gate
/// (probed against the staged overlay).
fn patches_without_source<'m>(
    manifest: &'m PatchManifest,
    missing_blobs: &HashSet<String>,
) -> Vec<&'m str> {
    manifest
        .patches
        .iter()
        .filter(|(_, record)| {
            record
                .files
                .values()
                .any(|f| missing_blobs.contains(&f.after_hash))
        })
        .map(|(purl, _)| purl.as_str())
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
/// every blob needed is cached (or `--offline`), else stage an overlay
/// tempdir and fetch the missing blobs through `client` (the run's one API
/// client — building another here repeated its advisory and org-slug
/// resolution). `Err` is a hard setup failure (tempdir creation);
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

    // Read-only probe of what is already on disk.
    let missing_blobs = get_missing_blobs(manifest, &socket_blobs_path).await;

    if common.offline {
        // Offline: bail only if some patch has no usable local source.
        // Note: with `--force`, the patch pipeline can short-circuit
        // verification on its own; we still surface the no-source
        // diagnosis so the user runs `repair` before retrying.
        let no_source_purls = patches_without_source(manifest, &missing_blobs);
        if !no_source_purls.is_empty() {
            report_offline_missing(common, &no_source_purls, APPLY_OFFLINE_REMEDY);
            return Ok(StageOutcome::Unavailable);
        }
    }

    if common.offline || missing_blobs.is_empty() {
        return Ok(StageOutcome::Ready(StagedSources {
            blobs: socket_blobs_path,
            _stage: None,
        }));
    }

    // Stage a transient overlay tempdir that hardlinks every existing
    // `.socket/blobs` entry and receives fresh downloads. The pipeline reads
    // exclusively from the tempdir; `.socket/` is never mutated. Dropping
    // `StagedSources` removes the directory and any downloaded bytes.
    let stage = tempfile::tempdir().map_err(|e| e.to_string())?;
    let staged = StagedSources {
        blobs: stage.path().join("blobs"),
        _stage: Some(stage),
    };
    tokio::fs::create_dir_all(&staged.blobs)
        .await
        .map_err(|e| e.to_string())?;
    overlay_dir(&socket_blobs_path, &staged.blobs).await;

    // Progress: a transient status line on stderr (stdout is data); the
    // result lines below are what stays on screen.
    let mut status = StatusLine::stderr(common.json, common.silent);
    status.set(DOWNLOADING_ARTIFACTS);
    let fetch_result = fetch_missing_blobs(manifest, &staged.blobs, client, None).await;
    status.finish();
    if !quiet {
        for line in format_fetch_summary(&fetch_result) {
            eprintln!("{line}");
        }
    }

    // Download failures only matter per patch: bail iff some patch is left
    // with no usable source at the staged path — the same coverage rule as
    // the offline gate.
    if fetch_result.failed > 0 {
        let missing_blobs = get_missing_blobs(manifest, &staged.blobs).await;
        if !patches_without_source(manifest, &missing_blobs).is_empty() {
            // An error, not progress chatter: prints even under --silent
            // (same rule as report_offline_missing above), with the
            // per-blob reasons the quiet summary above held back.
            if !common.json {
                if quiet {
                    for line in format_fetch_failures(&fetch_result) {
                        eprintln!("{line}");
                    }
                }
                eprintln!(
                    "Error: Some patch artifacts could not be downloaded; cannot apply patches."
                );
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
    use std::collections::HashMap;

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
            route: socket_patch_core::api::client::ApiRoute::Proxy,
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

    /// A leftover `.socket/diffs/<uuid>.tar.gz` is not a source: v5 reads
    /// only per-file blobs, so offline staging with the blob missing is
    /// Unavailable even when the old diff archive is on disk.
    #[tokio::test]
    async fn stage_offline_ignores_obsolete_diff_archive() {
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
            matches!(outcome, StageOutcome::Unavailable),
            "an obsolete diff archive must not cover the patch"
        );
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
    fn fetch_summary_uses_plurals() {
        assert_eq!(
            format_fetch_summary(&result(0, 0, &[])),
            vec!["All blobs are present locally."]
        );
        assert_eq!(
            format_fetch_summary(&result(1, 0, &[])),
            vec!["Downloaded 1 blob"]
        );
        assert_eq!(
            format_fetch_summary(&result(7, 1, &[])),
            vec!["Downloaded 7 blobs", "1 blob already present locally"]
        );
    }

    #[test]
    fn fetch_summary_failures_are_capped() {
        let fails: Vec<(String, String)> = (0..7)
            .map(|i| (format!("{i}{}", "a".repeat(20)), "404".to_string()))
            .collect();
        let refs: Vec<(&str, &str)> = fails
            .iter()
            .map(|(h, e)| (h.as_str(), e.as_str()))
            .collect();
        let r = result(1, 0, &refs);
        let lines = format_fetch_summary(&r);
        assert_eq!(lines[0], "Downloaded 1 blob");
        assert_eq!(lines[1], "Failed to download 7 blobs:");
        assert_eq!(lines[2], "  - 0aaaaaaaaaaa...: 404");
        assert_eq!(lines.last().unwrap(), "  ... and 2 more");
        assert_eq!(lines.len(), 1 + 1 + 5 + 1);
        // A multibyte hash is cut by chars, never mid-byte.
        let r = result(0, 0, &[("é".repeat(20).as_str(), "boom")]);
        assert_eq!(
            format_fetch_failures(&r),
            vec![
                "Failed to download 1 blob:".to_string(),
                format!("  - {}...: boom", "é".repeat(12))
            ]
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
