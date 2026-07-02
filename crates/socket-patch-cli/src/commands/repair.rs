use clap::Args;
use socket_patch_core::api::blob_fetcher::{
    fetch_missing_sources, format_fetch_result, get_missing_archives, get_missing_blobs,
    DownloadMode,
};
use socket_patch_core::api::client::get_api_client_with_overrides;
use socket_patch_core::manifest::operations::read_manifest;
use socket_patch_core::patch::apply::PatchSources;
use socket_patch_core::utils::cleanup_blobs::{
    cleanup_unused_archives, cleanup_unused_blobs, format_cleanup_result,
};
use socket_patch_core::utils::telemetry::{track_patch_repair_failed, track_patch_repaired};
use std::path::Path;
use std::time::Duration;

use crate::args::{apply_env_toggles, parse_bool_flag, GlobalArgs};
use crate::commands::lock_cli::{acquire_or_emit, lock_broken_event};
use crate::json_envelope::{Command, Envelope, EnvelopeError, PatchAction, PatchEvent, Status};

#[derive(Args)]
pub struct RepairArgs {
    #[command(flatten)]
    pub common: GlobalArgs,

    /// Only download missing artifacts; skip the cleanup phase.
    /// Incompatible with `--offline`.
    ///
    /// `value_parser = parse_bool_flag` matches the `GlobalArgs` bool flags:
    /// clap's default bool parser accepts only the literal strings
    /// `true`/`false` from the env binding, so `SOCKET_DOWNLOAD_ONLY=1` (or
    /// an exported-but-empty `SOCKET_DOWNLOAD_ONLY=`) aborted every `repair`
    /// invocation. This flag is also outside `GLOBAL_ARG_ENV_VARS`, so
    /// `main`'s empty-var scrub never rescues it.
    #[arg(
        long = "download-only",
        env = "SOCKET_DOWNLOAD_ONLY",
        default_value_t = false,
        value_parser = parse_bool_flag,
    )]
    pub download_only: bool,
}

pub async fn run(args: RepairArgs) -> i32 {
    apply_env_toggles(&args.common);

    // --offline implies strict airgap: no network calls. `--download-only`
    // is the inverse (network-only). The two are now mutually exclusive.
    if args.common.offline && args.download_only {
        let msg = "--offline and --download-only are mutually exclusive".to_string();
        if args.common.json {
            let mut env = Envelope::new(Command::Repair);
            env.dry_run = args.common.dry_run;
            env.mark_error(EnvelopeError::new("invalid_args", msg));
            println!("{}", env.to_pretty_json());
        } else {
            eprintln!("Error: {msg}");
        }
        return 2;
    }

    let manifest_path = args.common.resolved_manifest_path();

    if tokio::fs::metadata(&manifest_path).await.is_err() {
        // Hosted (redirect) mode leaves no local artifacts to repair: the
        // lockfiles point at patch.socket.dev URLs, not `.socket/vendor/...`,
        // and there is no manifest or vendor ledger. A project whose only
        // trace is `redirect-state.json` is therefore a no-op for repair —
        // exit success with an informational skip rather than the
        // `manifest_not_found` error a bare directory would get.
        let redirect_state = args
            .common
            .cwd
            .join(socket_patch_core::patch::redirect::REDIRECT_STATE_REL);
        let state_file = args
            .common
            .cwd
            .join(socket_patch_core::patch::vendor::VENDOR_STATE_REL);
        let has_vendor_traces = tokio::fs::metadata(&state_file).await.is_ok()
            || !crate::commands::repair_vendor::scan_vendor_references(&args.common.cwd)
                .await
                .is_empty();
        if !has_vendor_traces {
            if tokio::fs::metadata(&redirect_state).await.is_ok() {
                let msg = "hosted redirects need no local repair; re-run \
                           `scan --mode hosted` to refresh the lockfile redirects";
                if args.common.json {
                    let mut env = Envelope::new(Command::Repair);
                    env.dry_run = args.common.dry_run;
                    env.record(
                        PatchEvent::artifact(PatchAction::Skipped)
                            .with_reason("redirect_only_project", msg),
                    );
                    println!("{}", env.to_pretty_json());
                } else if !args.common.silent {
                    println!("{msg}");
                }
                return 0;
            }
            if args.common.json {
                let mut env = Envelope::new(Command::Repair);
                env.dry_run = args.common.dry_run;
                env.mark_error(EnvelopeError::new(
                    "manifest_not_found",
                    format!("Manifest not found at {}", manifest_path.display()),
                ));
                println!("{}", env.to_pretty_json());
            } else {
                eprintln!("Manifest not found at {}", manifest_path.display());
            }
            return 1;
        }
        // The vendor-only repair still serializes on the .socket lock; the
        // lock layer deliberately refuses to mkdir.
        if let Some(dir) = manifest_path.parent() {
            let _ = tokio::fs::create_dir_all(dir).await;
        }
    }

    // Serialize against concurrent socket-patch runs targeting the
    // same `.socket/` directory. See `apply_lock`.
    let socket_dir = manifest_path.parent().unwrap_or(Path::new("."));
    let acquired = match acquire_or_emit(
        socket_dir,
        Command::Repair,
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

    match repair_inner(&args, &manifest_path).await {
        Ok((mut env, counts)) => {
            if lock_was_broken {
                // Audit trail for `--break-lock`. Event ordering is
                // documented as best-effort; appending keeps the
                // `Envelope::record` invariant intact (events + summary
                // stay in sync).
                env.record(lock_broken_event(socket_dir));
            }
            // A repair where some artifacts failed to download is marked a
            // partial failure inside `repair_inner` (a `Failed` event plus
            // `mark_partial_failure`). Mirror `apply`: surface that as a
            // non-zero exit and the failure telemetry, so a CI guarding on
            // the exit code doesn't treat a half-finished repair as success.
            let had_failure = matches!(env.status, Status::PartialFailure | Status::Error);
            if had_failure {
                track_patch_repair_failed(
                    "One or more artifacts failed to download",
                    args.common.api_token.as_deref(),
                    args.common.org.as_deref(),
                )
                .await;
            } else {
                track_patch_repaired(
                    counts.downloaded,
                    counts.cleaned,
                    counts.bytes_freed,
                    args.common.api_token.as_deref(),
                    args.common.org.as_deref(),
                )
                .await;
            }
            if args.common.json {
                println!("{}", env.to_pretty_json());
            }
            if had_failure {
                1
            } else {
                0
            }
        }
        Err(e) => {
            track_patch_repair_failed(
                &e,
                args.common.api_token.as_deref(),
                args.common.org.as_deref(),
            )
            .await;
            if args.common.json {
                let mut env = Envelope::new(Command::Repair);
                env.dry_run = args.common.dry_run;
                env.mark_error(EnvelopeError::new("repair_failed", e));
                println!("{}", env.to_pretty_json());
            } else {
                eprintln!("Error: {e}");
            }
            1
        }
    }
}

/// Aggregate counts surfaced by `repair_inner` for telemetry use.
pub(crate) struct RepairCounts {
    downloaded: usize,
    cleaned: usize,
    bytes_freed: u64,
}

pub(crate) async fn repair_inner(
    args: &RepairArgs,
    manifest_path: &Path,
) -> Result<(Envelope, RepairCounts), String> {
    // `Ok(None)` = no manifest (vendor-only repair); present-but-invalid
    // stays a hard error.
    let manifest = read_manifest(manifest_path)
        .await
        .map_err(|e| e.to_string())?;

    let socket_dir = manifest_path.parent().unwrap();
    let blobs_path = socket_dir.join("blobs");
    let diffs_path = socket_dir.join("diffs");
    let packages_path = socket_dir.join("packages");

    let download_mode =
        DownloadMode::parse(&args.common.download_mode).map_err(|e| e.to_string())?;

    // `--silent` ("suppress non-error output") must mute the human-readable
    // progress just like `--json` does — otherwise a silent repair still
    // floods stdout with "Found N missing", "Downloading…", cleanup
    // summaries and "Repair complete.". Gate every informational print on
    // both, mirroring `get`/`apply`. (The JSON envelope is emitted by the
    // caller, so nothing here depends on `json` alone.)
    let quiet = args.common.json || args.common.silent;

    let mut downloaded_count = 0usize;
    let mut download_failed_count = 0usize;
    let mut blobs_cleaned = 0usize;
    let mut blobs_checked = 0usize;
    let mut bytes_freed = 0u64;

    // The envelope is built up-front: the vendored-artifact phase records
    // its events inline; the download/cleanup aggregates are appended at
    // the end (event ordering is documented best-effort).
    let mut env = Envelope::new(Command::Repair);
    env.dry_run = args.common.dry_run;

    // Step 1: Check for and download missing artifacts in the requested
    // mode. Counts below refer to whatever kind of artifact was requested
    // (file blobs, diff archives, or package archives).
    //
    // VENDORED-in-sync manifest entries are excluded: vendor flows keep
    // patch content in memory and the committed artifact IS the patch, so
    // a fully-vendored project legitimately has no `.socket/blobs|diffs|
    // packages` — repair must not re-litter them (or fail trying). The
    // cleanup phase below still uses the FULL manifest, so it never sweeps
    // sources an in-place apply may need for rollback.
    let vendor_state = socket_patch_core::patch::vendor::load_state(&args.common.cwd)
        .await
        .unwrap_or_default();
    // Lockfile vendor references count as vendored even before the ledger
    // is reconstructed, so a no-ledger repair doesn't download sources for
    // entries the vendored phase is about to own.
    let referenced_uuids: std::collections::HashSet<String> =
        crate::commands::repair_vendor::scan_vendor_references(&args.common.cwd)
            .await
            .into_iter()
            .map(|(_, uuid, _)| uuid)
            .collect();
    let scoped_manifest = manifest.as_ref().map(|m| {
        let patches = m
            .patches
            .iter()
            .filter(|(purl, rec)| {
                !referenced_uuids.contains(&rec.uuid)
                    && vendor_state
                        .entries
                        .get(*purl)
                        .or_else(|| {
                            vendor_state
                                .entries
                                .values()
                                .find(|e| &e.base_purl == *purl)
                        })
                        .is_none_or(|e| e.uuid != rec.uuid)
            })
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        socket_patch_core::manifest::schema::PatchManifest {
            patches,
            setup: m.setup.clone(),
        }
    });
    let missing_artifacts: Vec<String> = match (&scoped_manifest, download_mode) {
        (None, _) => Vec::new(),
        (Some(m), DownloadMode::File) => get_missing_blobs(m, &blobs_path)
            .await
            .into_iter()
            .collect(),
        (Some(m), DownloadMode::Diff) => get_missing_archives(m, &diffs_path)
            .await
            .into_iter()
            .collect(),
        (Some(m), DownloadMode::Package) => get_missing_archives(m, &packages_path)
            .await
            .into_iter()
            .collect(),
    };
    let missing_count = missing_artifacts.len();

    if !args.common.offline {
        if !missing_artifacts.is_empty() {
            if !quiet {
                println!(
                    "Found {} missing {} artifact(s)",
                    missing_artifacts.len(),
                    download_mode.as_tag()
                );
            }

            if args.common.dry_run {
                if !quiet {
                    println!("\nDry run - would download:");
                    for id in missing_artifacts.iter().take(10) {
                        println!("  - {}...", &id[..12.min(id.len())]);
                    }
                    if missing_artifacts.len() > 10 {
                        println!("  ... and {} more", missing_artifacts.len() - 10);
                    }
                }
            } else {
                if !quiet {
                    println!("\nDownloading missing {}s...", download_mode.as_tag());
                }
                let (client, _) =
                    get_api_client_with_overrides(args.common.api_client_overrides()).await;
                let sources = PatchSources {
                    blobs_path: &blobs_path,
                    packages_path: Some(&packages_path),
                    diffs_path: Some(&diffs_path),
                    mem_blobs: None,
                };
                // Step 1 only runs with a manifest (missing_artifacts is
                // empty otherwise), so the expect is unreachable.
                let m = scoped_manifest
                    .as_ref()
                    .expect("step 1 requires a manifest");
                let fetch_result =
                    fetch_missing_sources(m, &sources, download_mode, &client, None).await;
                downloaded_count = fetch_result.downloaded;
                download_failed_count = fetch_result.failed;
                if !quiet {
                    println!("{}", format_fetch_result(&fetch_result));
                }
            }
        } else if !quiet {
            println!(
                "All {} artifacts are present locally.",
                download_mode.as_tag()
            );
        }
    } else if !missing_artifacts.is_empty() {
        if !quiet {
            println!(
                "Warning: {} {} artifact(s) are missing (offline mode - not downloading)",
                missing_artifacts.len(),
                download_mode.as_tag()
            );
            for id in missing_artifacts.iter().take(5) {
                println!("  - {}...", &id[..12.min(id.len())]);
            }
            if missing_artifacts.len() > 5 {
                println!("  ... and {} more", missing_artifacts.len() - 5);
            }
        }
    } else if !quiet {
        println!(
            "All {} artifacts are present locally.",
            download_mode.as_tag()
        );
    }

    // Step 1.5: vendored artifacts — health-check the ledger (and any
    // lockfile vendor references with no ledger coverage) and rebuild
    // missing/corrupt artifacts. Runs under `--download-only` too:
    // restoring artifacts IS repair's download half.
    let vendor_counts = crate::commands::repair_vendor::repair_vendored_artifacts(
        &args.common,
        manifest.as_ref(),
        socket_dir,
        &mut env,
    )
    .await;
    if !quiet && vendor_counts.rebuilt > 0 {
        println!("Rebuilt {} vendored artifact(s).", vendor_counts.rebuilt);
    }

    // Step 2: Clean up unused artifacts across all three directories.
    if let (false, Some(manifest)) = (args.download_only, manifest.as_ref()) {
        let manifest = manifest.clone();
        if !quiet {
            println!();
        }
        match cleanup_unused_blobs(&manifest, &blobs_path, args.common.dry_run).await {
            Ok(cleanup_result) => {
                blobs_checked += cleanup_result.blobs_checked;
                blobs_cleaned += cleanup_result.blobs_removed;
                bytes_freed += cleanup_result.bytes_freed;
                if !quiet {
                    if cleanup_result.blobs_checked == 0 {
                        println!("No blobs directory found, nothing to clean up.");
                    } else if cleanup_result.blobs_removed == 0 {
                        println!(
                            "Checked {} blob(s), all are in use.",
                            cleanup_result.blobs_checked
                        );
                    } else {
                        println!(
                            "{}",
                            format_cleanup_result(&cleanup_result, args.common.dry_run)
                        );
                    }
                }
            }
            Err(e) => {
                if !quiet {
                    eprintln!("Warning: blob cleanup failed: {e}");
                }
            }
        }

        // Diff archives.
        match cleanup_unused_archives(&manifest, &diffs_path, args.common.dry_run).await {
            Ok(cleanup_result) => {
                blobs_checked += cleanup_result.blobs_checked;
                blobs_cleaned += cleanup_result.blobs_removed;
                bytes_freed += cleanup_result.bytes_freed;
                if !quiet && cleanup_result.blobs_removed > 0 {
                    println!(
                        "{}",
                        format_cleanup_result(&cleanup_result, args.common.dry_run)
                            .replace("blob(s)", "diff archive(s)")
                    );
                }
            }
            Err(e) => {
                if !quiet {
                    eprintln!("Warning: diff cleanup failed: {e}");
                }
            }
        }

        // Package archives.
        match cleanup_unused_archives(&manifest, &packages_path, args.common.dry_run).await {
            Ok(cleanup_result) => {
                blobs_checked += cleanup_result.blobs_checked;
                blobs_cleaned += cleanup_result.blobs_removed;
                bytes_freed += cleanup_result.bytes_freed;
                if !quiet && cleanup_result.blobs_removed > 0 {
                    println!(
                        "{}",
                        format_cleanup_result(&cleanup_result, args.common.dry_run)
                            .replace("blob(s)", "package archive(s)")
                    );
                }
            }
            Err(e) => {
                if !quiet {
                    eprintln!("Warning: package cleanup failed: {e}");
                }
            }
        }
    }

    if !args.common.dry_run && !quiet {
        println!("\nRepair complete.");
    }

    // Translate the aggregate counts into envelope events. `repair`
    // operates on artifacts (not specific patches), so events use the
    // `PatchEvent::artifact` form (no PURL/UUID).
    let action_for_repair = if args.common.dry_run {
        PatchAction::Verified
    } else {
        PatchAction::Downloaded
    };
    // Only the online path downloads (or, in dry-run, *would* download).
    // In offline mode nothing is fetched even when artifacts are missing,
    // so don't record a download/would-download event there — that would
    // contradict the human-readable path, which only prints a warning.
    if downloaded_count > 0 || (!args.common.offline && args.common.dry_run && missing_count > 0) {
        let count = if args.common.dry_run {
            missing_count
        } else {
            downloaded_count
        };
        env.record(
            PatchEvent::artifact(action_for_repair).with_details(serde_json::json!({
                "count": count,
                "mode": download_mode.as_tag(),
            })),
        );
    }
    if download_failed_count > 0 {
        env.record(PatchEvent::artifact(PatchAction::Failed).with_error(
            "download_failed",
            format!("{} artifact(s) failed to download", download_failed_count),
        ));
        env.mark_partial_failure();
    }
    if blobs_cleaned > 0 {
        let cleanup_action = if args.common.dry_run {
            PatchAction::Verified
        } else {
            PatchAction::Removed
        };
        env.record(
            PatchEvent::artifact(cleanup_action).with_details(serde_json::json!({
                "count": blobs_cleaned,
                "checked": blobs_checked,
            })),
        );
    }
    Ok((
        env,
        RepairCounts {
            downloaded: downloaded_count,
            cleaned: blobs_cleaned,
            bytes_freed,
        },
    ))
}

#[cfg(test)]
mod tests {
    //! Unit tests for `repair_inner` — the offline cleanup / event-recording
    //! core. These run without a network (all use `--offline`), exercising
    //! the orphan-cleanup and envelope-building paths directly so the
    //! contract is pinned independently of the binary harness.
    use super::*;
    use crate::args::GlobalArgs;
    use std::path::PathBuf;

    const MANIFEST_JSON: &str = r#"{
      "patches": {
        "pkg:npm/__repair_unit__@1.0.0": {
          "uuid": "11111111-1111-4111-8111-111111111111",
          "exportedAt": "2024-01-01T00:00:00Z",
          "files": {
            "package/index.js": {
              "beforeHash": "0000000000000000000000000000000000000000000000000000000000000000",
              "afterHash":  "1111111111111111111111111111111111111111111111111111111111111111"
            }
          },
          "vulnerabilities": {},
          "description": "unit test patch",
          "license": "MIT",
          "tier": "free"
        }
      }
    }"#;

    const REFERENCED_HASH: &str =
        "1111111111111111111111111111111111111111111111111111111111111111";

    /// Write a `.socket/manifest.json` under `root` and return the socket dir.
    fn make_socket(root: &Path) -> PathBuf {
        let socket = root.join(".socket");
        std::fs::create_dir_all(&socket).unwrap();
        std::fs::write(socket.join("manifest.json"), MANIFEST_JSON).unwrap();
        socket
    }

    fn write_blob(socket: &Path, hash: &str, content: &[u8]) {
        let blobs = socket.join("blobs");
        std::fs::create_dir_all(&blobs).unwrap();
        std::fs::write(blobs.join(hash), content).unwrap();
    }

    /// Write an archive (`<name>.tar.gz`) under `socket/<subdir>`.
    fn write_archive(socket: &Path, subdir: &str, name: &str, content: &[u8]) {
        let dir = socket.join(subdir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(format!("{name}.tar.gz")), content).unwrap();
    }

    // The single UUID referenced by `MANIFEST_JSON` above.
    const REFERENCED_UUID: &str = "11111111-1111-4111-8111-111111111111";

    fn offline_args(cwd: &Path) -> RepairArgs {
        RepairArgs {
            common: GlobalArgs {
                cwd: cwd.to_path_buf(),
                manifest_path: ".socket/manifest.json".to_string(),
                offline: true,
                json: true,
                download_mode: "file".to_string(),
                ..GlobalArgs::default()
            },
            download_only: false,
        }
    }

    /// True when `env` carries the download / would-download artifact event
    /// (identified by its `details.mode` field, unique to that event).
    fn has_download_event(env: &Envelope) -> bool {
        env.events
            .iter()
            .any(|e| e.details.as_ref().and_then(|d| d.get("mode")).is_some())
    }

    /// Regression for the offline + dry-run leak: with `--offline` set, the
    /// download phase is skipped entirely, so even in dry-run mode a missing
    /// artifact must NOT produce a "would-download" (verified) event. Before
    /// the fix the event was recorded unconditionally on `dry_run &&
    /// missing > 0`, contradicting the human-readable path (which only warns).
    #[tokio::test]
    async fn offline_dry_run_does_not_record_download_event() {
        let tmp = tempfile::tempdir().unwrap();
        let socket = make_socket(tmp.path());
        // No blob on disk → the manifest's afterHash is "missing".
        let mut args = offline_args(tmp.path());
        args.common.dry_run = true;

        let (env, counts) = repair_inner(&args, &socket.join("manifest.json"))
            .await
            .expect("repair_inner");

        assert!(
            !has_download_event(&env),
            "offline dry-run must not emit a download/would-download event; events={:?}",
            env.events
        );
        assert_eq!(counts.downloaded, 0);
        assert_eq!(env.status, Status::Success);
    }

    /// The online dry-run path *should* still preview the download — this
    /// pins that the offline gate didn't over-correct. We can't hit the
    /// network here, but `repair_inner`'s dry-run branch records the event
    /// from the missing-artifact list without contacting the server.
    #[tokio::test]
    async fn online_dry_run_records_would_download_event() {
        let tmp = tempfile::tempdir().unwrap();
        let socket = make_socket(tmp.path());
        let mut args = offline_args(tmp.path());
        args.common.offline = false;
        args.common.dry_run = true;

        let (env, _counts) = repair_inner(&args, &socket.join("manifest.json"))
            .await
            .expect("repair_inner");

        assert!(
            has_download_event(&env),
            "online dry-run must preview the download; events={:?}",
            env.events
        );
    }

    /// Regression for the dropped `bytes_freed`: cleanup of an orphan blob
    /// must report the reclaimed byte count up through `RepairCounts` so the
    /// telemetry `bytes_freed` field is non-zero (it was hardcoded to 0).
    #[tokio::test]
    async fn cleanup_reports_bytes_freed_and_removed_count() {
        let tmp = tempfile::tempdir().unwrap();
        let socket = make_socket(tmp.path());
        write_blob(&socket, REFERENCED_HASH, b"kept");
        let orphan_hash = "deadbeef".repeat(8); // 64 hex chars
        let orphan_bytes = b"orphaned content bytes";
        write_blob(&socket, &orphan_hash, orphan_bytes);

        let args = offline_args(tmp.path());
        let (env, counts) = repair_inner(&args, &socket.join("manifest.json"))
            .await
            .expect("repair_inner");

        assert_eq!(counts.cleaned, 1, "one orphan should be cleaned");
        assert_eq!(
            counts.bytes_freed,
            orphan_bytes.len() as u64,
            "bytes_freed must reflect the reclaimed orphan size"
        );
        // The referenced blob survives; the orphan is gone.
        assert!(socket.join("blobs").join(REFERENCED_HASH).exists());
        assert!(!socket.join("blobs").join(&orphan_hash).exists());
        // A Removed event is recorded for the swept orphan.
        assert_eq!(env.summary.removed, 1);
    }

    /// `--download-only` skips the cleanup pass, so an orphan blob survives
    /// and `bytes_freed` stays zero. (Run without `--offline`, which is
    /// mutually exclusive; the manifest's blob is present so the online
    /// download phase has nothing to fetch and never touches the network.)
    #[tokio::test]
    async fn download_only_skips_cleanup() {
        let tmp = tempfile::tempdir().unwrap();
        let socket = make_socket(tmp.path());
        write_blob(&socket, REFERENCED_HASH, b"kept");
        let orphan_hash = "feedface".repeat(8);
        write_blob(&socket, &orphan_hash, b"orphan");

        let mut args = offline_args(tmp.path());
        args.common.offline = false;
        args.download_only = true;

        let (_env, counts) = repair_inner(&args, &socket.join("manifest.json"))
            .await
            .expect("repair_inner");

        assert_eq!(counts.cleaned, 0, "download-only must skip cleanup");
        assert_eq!(counts.bytes_freed, 0);
        assert!(
            socket.join("blobs").join(&orphan_hash).exists(),
            "orphan must survive when cleanup is skipped"
        );
    }

    /// Cleanup must sweep orphaned diff *and* package archives in addition to
    /// blobs, and the reclaimed counts/bytes from all three directories must
    /// aggregate into a single `RepairCounts`. Guards against a regression
    /// where a cleanup pass uses the wrong directory or drops its tallies.
    #[tokio::test]
    async fn cleanup_sweeps_diff_and_package_archives() {
        let tmp = tempfile::tempdir().unwrap();
        let socket = make_socket(tmp.path());

        // Referenced archives (named after the manifest UUID) must survive.
        write_archive(&socket, "diffs", REFERENCED_UUID, b"kept-diff");
        write_archive(&socket, "packages", REFERENCED_UUID, b"kept-package");

        // Orphan archives (unknown UUIDs) must be swept.
        let orphan_diff = b"orphan diff archive bytes"; // 25 bytes
        let orphan_pkg = b"orphan package bytes!!"; // 22 bytes
        write_archive(
            &socket,
            "diffs",
            "99999999-9999-4999-8999-999999999999",
            orphan_diff,
        );
        write_archive(
            &socket,
            "packages",
            "88888888-8888-4888-8888-888888888888",
            orphan_pkg,
        );

        let args = offline_args(tmp.path());
        let (env, counts) = repair_inner(&args, &socket.join("manifest.json"))
            .await
            .expect("repair_inner");

        // Two orphans removed (one diff, one package); the referenced ones stay.
        assert_eq!(counts.cleaned, 2, "both orphan archives should be swept");
        assert_eq!(
            counts.bytes_freed,
            (orphan_diff.len() + orphan_pkg.len()) as u64,
            "bytes_freed must aggregate diff + package reclaim"
        );
        // Cleanup is reported as a SINGLE batched `removed` artifact event whose
        // `details.count` carries the tally — so the event-count summary is 1
        // (`Summary::bump` increments once per event), and the 2-artifact count
        // is asserted via `counts.cleaned` above and the event details here.
        assert_eq!(env.summary.removed, 1, "one batched removal event");
        let removed = env
            .events
            .iter()
            .find(|e| matches!(e.action, PatchAction::Removed))
            .expect("a Removed artifact event");
        assert_eq!(
            removed
                .details
                .as_ref()
                .and_then(|d| d.get("count"))
                .and_then(serde_json::Value::as_u64),
            Some(2),
            "the batched removal event must report 2 swept artifacts"
        );

        assert!(socket
            .join("diffs")
            .join(format!("{REFERENCED_UUID}.tar.gz"))
            .exists());
        assert!(socket
            .join("packages")
            .join(format!("{REFERENCED_UUID}.tar.gz"))
            .exists());
        assert!(!socket
            .join("diffs")
            .join("99999999-9999-4999-8999-999999999999.tar.gz")
            .exists());
        assert!(!socket
            .join("packages")
            .join("88888888-8888-4888-8888-888888888888.tar.gz")
            .exists());
    }

    /// Offline mode with a missing artifact: the run must succeed (a warning,
    /// not a failure), record NO download event, and report zero downloads —
    /// nothing is fetched and the airgap is honoured. Cleanup still runs.
    #[tokio::test]
    async fn offline_missing_artifact_warns_without_failure() {
        let tmp = tempfile::tempdir().unwrap();
        let socket = make_socket(tmp.path());
        // No blob on disk → manifest afterHash is "missing". Not dry-run.
        let args = offline_args(tmp.path());

        let (env, counts) = repair_inner(&args, &socket.join("manifest.json"))
            .await
            .expect("repair_inner");

        assert!(
            !has_download_event(&env),
            "offline mode must not record a download event; events={:?}",
            env.events
        );
        assert_eq!(counts.downloaded, 0);
        assert_eq!(
            env.status,
            Status::Success,
            "missing artifacts in offline mode are a warning, not a failure"
        );
    }
}
