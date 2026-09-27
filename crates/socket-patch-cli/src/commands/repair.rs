use clap::Args;
use socket_patch_core::api::blob_fetcher::{
    fetch_missing_sources, format_fetch_failures, format_fetch_successes, get_missing_archives,
    get_missing_blobs, ArtifactNoun, DownloadMode, BLOB, DIFF_ARCHIVE, PACKAGE_ARCHIVE,
};
use socket_patch_core::api::client::{get_api_client_with_overrides, ApiClient};
use socket_patch_core::manifest::cleanup_blobs::{
    format_all_in_use, format_cleanup_result_for, CleanupResult,
};
use socket_patch_core::manifest::operations::read_manifest;
use socket_patch_core::patch::apply::PatchSources;
use socket_patch_core::telemetry::{track_patch_repair_failed, track_patch_repaired};
use std::path::Path;
use std::time::Duration;

use crate::args::{apply_env_toggles, parse_bool_flag, GlobalArgs};
use crate::commands::lock_cli::{acquire_or_emit, error_envelope};
use crate::commands::rollback::{sweep_failure, sweep_unused_artifacts};
use crate::json_envelope::{Command, Envelope, PatchAction, PatchEvent, Status};

#[derive(Args)]
pub struct RepairArgs {
    #[command(flatten)]
    pub common: GlobalArgs,

    /// Only download missing artifacts; skip the cleanup phase.
    /// Incompatible with `--offline`.
    //
    // `value_parser = parse_bool_flag` matches the `GlobalArgs` bool flags:
    // clap's default bool parser accepts only the literal strings
    // `true`/`false` from the env binding, so `SOCKET_DOWNLOAD_ONLY=1` (or
    // an exported-but-empty `SOCKET_DOWNLOAD_ONLY=`) aborted every `repair`
    // invocation. This flag is also outside `GLOBAL_ARG_ENV_VARS`, so
    // `main`'s empty-var scrub never rescues it.
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
        let msg = "--offline and --download-only are mutually exclusive";
        if args.common.json {
            let env = error_envelope(Command::Repair, args.common.dry_run, "invalid_args", msg);
            println!("{}", env.to_pretty_json());
        } else {
            eprintln!("Error: {msg}");
        }
        return 2;
    }

    let manifest_path = args.common.resolved_manifest_path();

    // The lockfile scan (`scan_vendor_references` opens every wiring file)
    // runs at most once per repair: the existence gate below needs it only
    // for a ledger-less project, and that result is reused under the lock.
    let mut vendor_references: Option<Vec<(String, String, String)>> = None;

    if tokio::fs::metadata(&manifest_path).await.is_err() {
        // Hosted (redirect) mode leaves no local artifacts to repair: the
        // lockfiles point at patch.socket.dev URLs, not `.socket/vendor/...`,
        // and there is no manifest or vendor ledger. A project whose only
        // trace is `redirect-state.json` is therefore a no-op for repair —
        // exit success with an informational skip rather than the
        // `manifest_not_found` error a bare directory would get. Only cheap
        // existence probes (and the read-only lockfile scan) run before the
        // lock, so a project with nothing to repair never grows `.socket/`.
        let redirect_state = args
            .common
            .cwd
            .join(socket_patch_core::patch::redirect::REDIRECT_STATE_REL);
        let state_file = args
            .common
            .cwd
            .join(socket_patch_core::vendor::VENDOR_STATE_REL);
        let mut has_vendor_traces = tokio::fs::metadata(&state_file).await.is_ok();
        if !has_vendor_traces {
            let refs =
                crate::commands::repair_vendor::scan_vendor_references(&args.common.cwd).await;
            has_vendor_traces = !refs.is_empty();
            vendor_references = Some(refs);
        }
        if !has_vendor_traces {
            if tokio::fs::metadata(&redirect_state).await.is_ok() {
                let msg = HOSTED_ONLY_REASON;
                if args.common.json {
                    let mut env = Envelope::new(Command::Repair);
                    env.dry_run = args.common.dry_run;
                    env.record(
                        PatchEvent::artifact(PatchAction::Skipped)
                            .with_reason("redirect_only_project", msg),
                    );
                    println!("{}", env.to_pretty_json());
                } else if !args.common.silent {
                    // A sentence on the terminal; the JSON reason keeps
                    // its historical, period-less text.
                    println!("{msg}.");
                }
                return 0;
            }
            let msg = format!("Manifest not found at {}", manifest_path.display());
            if args.common.json {
                let env = error_envelope(
                    Command::Repair,
                    args.common.dry_run,
                    "manifest_not_found",
                    &msg,
                );
                println!("{}", env.to_pretty_json());
            } else {
                eprintln!("Error: {msg}");
            }
            return 1;
        }
    }

    // Serialize against concurrent socket-patch runs targeting the
    // same `.socket/` directory. See `apply_lock`: acquire creates the
    // directory when needed (the vendor-only repair of a ledger-less
    // project), and the guard's drop removes `apply.lock` — and an
    // otherwise-empty `.socket/` — on every exit path, dry-run included.
    // A live holder makes repair refuse with `lock_held`; it never steals
    // the lock.
    let socket_dir = crate::args::socket_dir_of(&manifest_path, &args.common.cwd);
    let _lock = match acquire_or_emit(
        &socket_dir,
        Command::Repair,
        args.common.json,
        args.common.dry_run,
        Duration::from_secs(args.common.lock_timeout.unwrap_or(0)),
    ) {
        Ok(guard) => guard,
        Err(code) => return code,
    };

    // Lockfile references are read under the lock (a concurrent vendor run
    // rewrites them under the same lock) unless the gate above already
    // scanned this ledger-less project.
    let vendor_references = match vendor_references {
        Some(refs) => refs,
        None => crate::commands::repair_vendor::scan_vendor_references(&args.common.cwd).await,
    };

    // The API client is built lazily: `repair_inner` constructs it only on
    // the download branch, so a run that downloads nothing (an invalid or
    // empty manifest, every artifact present, a dry run) never prints the
    // client's public-proxy advisory ahead of its own output.
    let mut client: Option<ApiClient> = None;
    let result = repair_inner(&args, &manifest_path, &mut client, vendor_references).await;

    // Resolve telemetry credentials through the API client the way
    // apply/rollback/remove do: passing the raw `--api-token`/`--org` flag
    // values meant env-provided SOCKET_API_TOKEN/SOCKET_ORG_SLUG (the
    // standard configuration) never reached telemetry, which then fell
    // back to the anonymous public-proxy endpoint instead of the
    // org-scoped one. Reuse the download phase's client when there was
    // one. Otherwise build one only when a token is available (so the
    // org auto-resolve still attributes the event, and no proxy advisory
    // is printed): without a token telemetry goes to the public endpoint
    // whatever the org slug, so `(None, None)` is equivalent.
    if client.is_none() && api_token_available(&args.common) {
        client = Some(
            get_api_client_with_overrides(args.common.api_client_overrides())
                .await
                .0,
        );
    }
    let (api_token, org_slug) = client.as_ref().map_or((None, None), |c| {
        (c.api_token().cloned(), c.org_slug().cloned())
    });

    match result {
        Ok((env, counts)) => {
            // A repair where some artifacts failed to download is marked a
            // partial failure inside `repair_inner` (a `Failed` event plus
            // `mark_partial_failure`). Mirror `apply`: surface that as a
            // non-zero exit and the failure telemetry, so a CI guarding on
            // the exit code doesn't treat a half-finished repair as success.
            let had_failure = matches!(env.status, Status::PartialFailure | Status::Error);
            if had_failure {
                track_patch_repair_failed(
                    "One or more artifacts failed to download",
                    api_token.as_deref(),
                    org_slug.as_deref(),
                )
                .await;
            } else {
                track_patch_repaired(
                    counts.downloaded,
                    counts.cleaned,
                    counts.bytes_freed,
                    api_token.as_deref(),
                    org_slug.as_deref(),
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
            track_patch_repair_failed(&e, api_token.as_deref(), org_slug.as_deref()).await;
            if args.common.json {
                let env = error_envelope(Command::Repair, args.common.dry_run, "repair_failed", &e);
                println!("{}", env.to_pretty_json());
            } else {
                eprintln!("Error: {e}");
            }
            1
        }
    }
}

/// Aggregate counts surfaced by `repair_inner` for telemetry use.
struct RepairCounts {
    downloaded: usize,
    cleaned: usize,
    bytes_freed: u64,
}

/// How many missing ids the offline warning lists.
const OFFLINE_LIST_CAP: usize = 5;
/// How many missing ids the dry-run preview lists.
const DRY_RUN_LIST_CAP: usize = 10;

/// `  - <id>` lines for `ids`, sorted (they come from a `HashSet`), at
/// most `cap` of them, then `  ... and N more`.
fn format_id_list(ids: &[String], noun: ArtifactNoun, cap: usize) -> Vec<String> {
    let mut sorted: Vec<&String> = ids.iter().collect();
    sorted.sort();
    let mut lines: Vec<String> = sorted
        .iter()
        .take(cap)
        .map(|id| format!("  - {}", noun.display_id(id)))
        .collect();
    if sorted.len() > cap {
        lines.push(format!("  ... and {} more", sorted.len() - cap));
    }
    lines
}

/// `Found 2 missing diff archives` / `Found 1 missing blob`.
fn format_found_missing(n: usize, noun: ArtifactNoun) -> String {
    format!("Found {}", noun.count(n).replacen(' ', " missing ", 1))
}

/// Why a hosted-only project has nothing to repair (the JSON skip
/// reason; the human line adds the period).
const HOSTED_ONLY_REASON: &str = "Hosted redirects need no local repair; re-run \
    `scan --mode hosted` to refresh the lockfile redirects (it also re-checks for stale \
    pre-redirect installs)";

/// Step 1's line when no patch artifact is missing: why there is nothing
/// to download (no manifest, as in a vendored-only project, or an empty
/// one), or that everything is on disk.
fn format_nothing_missing(
    manifest: Option<&socket_patch_core::manifest::schema::PatchManifest>,
    noun: ArtifactNoun,
) -> String {
    match manifest {
        None => "No manifest; no patch artifacts to download.".to_string(),
        Some(m) if m.patches.is_empty() => {
            "No patches in manifest; nothing to download.".to_string()
        }
        Some(_) => format!("All {} are present locally.", noun.many),
    }
}

/// The `--offline` warning (stderr) for artifacts that cannot be fetched.
fn format_offline_warning(ids: &[String], noun: ArtifactNoun) -> String {
    let verb = if ids.len() == 1 { "is" } else { "are" };
    let mut lines = vec![format!(
        "Warning: {} {verb} missing (offline mode - not downloading):",
        noun.count(ids.len())
    )];
    lines.extend(format_id_list(ids, noun, OFFLINE_LIST_CAP));
    lines.join("\n")
}

/// The cleanup phase's summary: one result block per kind that had
/// something to remove; otherwise a single line saying what was checked.
fn format_cleanup_summary(results: &[(ArtifactNoun, CleanupResult)], dry_run: bool) -> String {
    let removed: Vec<String> = results
        .iter()
        .filter(|(_, r)| r.blobs_removed > 0)
        .map(|(noun, r)| format_cleanup_result_for(r, dry_run, *noun))
        .collect();
    if !removed.is_empty() {
        return removed.join("\n");
    }
    let checked: Vec<String> = results
        .iter()
        .filter(|(_, r)| r.blobs_checked > 0)
        .map(|(noun, r)| noun.count(r.blobs_checked))
        .collect();
    if checked.is_empty() {
        return "Nothing to clean up.".to_string();
    }
    let total = results.iter().map(|(_, r)| r.blobs_checked).sum();
    format_all_in_use(&checked, total)
}

/// The closing line of a human repair run. `other_failure` is a failure
/// recorded elsewhere in the run (a vendored artifact that could not be
/// rebuilt): the run exits 1, so it must not close on "Repair complete.".
fn format_final_line(
    download_failed: usize,
    other_failure: bool,
    noun: ArtifactNoun,
    dry_run: bool,
) -> String {
    if download_failed > 0 {
        let verb = if download_failed == 1 { "was" } else { "were" };
        format!(
            "Repair finished with errors: {} {verb} not downloaded.",
            noun.count(download_failed)
        )
    } else if other_failure {
        "Repair finished with errors.".to_string()
    } else if dry_run {
        "Dry run: no changes made.".to_string()
    } else {
        "Repair complete.".to_string()
    }
}

/// Whether an API token will be found, mirroring the client's chain: the
/// `--api-token` flag (clap also maps SOCKET_API_TOKEN into it), then —
/// unless `SOCKET_NO_API_TOKEN` vetoes ambient tokens — the env var and the
/// socket-cli config. Checked without building a client, which would print
/// the public-proxy advisory when there is none.
fn api_token_available(common: &GlobalArgs) -> bool {
    use socket_patch_core::utils::socket_cli_config;
    if common.api_token.as_deref().is_some_and(|t| !t.is_empty()) {
        return true;
    }
    if socket_cli_config::no_api_token_veto() {
        return false;
    }
    std::env::var("SOCKET_API_TOKEN").is_ok_and(|t| !t.is_empty())
        || socket_cli_config::load().is_some_and(|c| c.api_token.is_some())
}

async fn repair_inner(
    args: &RepairArgs,
    manifest_path: &Path,
    // Built lazily on the download branch (see `run`) and handed on to
    // the vendored phase, so one repair constructs at most one client and
    // prints the core client's "No SOCKET_API_TOKEN set" notice at most
    // once. Unit tests pass `&mut None`.
    client: &mut Option<ApiClient>,
    // `(eco, uuid, rel)` lockfile vendor references, scanned once by `run`.
    vendor_references: Vec<(String, String, String)>,
) -> Result<(Envelope, RepairCounts), String> {
    // `Ok(None)` = no manifest (vendor-only repair); present-but-invalid
    // stays a hard error.
    let manifest = read_manifest(manifest_path)
        .await
        .map_err(|e| crate::commands::list::manifest_error_message(manifest_path, &e))?;

    let socket_dir = crate::args::socket_dir_of(manifest_path, &args.common.cwd);
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
    // Loaded ONCE under the lock; the vendored phase below takes the raw
    // result (an unreadable ledger is ITS loud failure), while this scoping
    // degrades to "nothing vendored" — a corrupt ledger must not hide the
    // manifest's own missing sources.
    let ledger = socket_patch_core::vendor::load_state(&args.common.cwd).await;
    let no_entries = std::collections::HashMap::new();
    let vendor_entries = ledger.as_ref().map(|s| &s.entries).unwrap_or(&no_entries);
    // Lockfile vendor references count as vendored even before the ledger
    // is reconstructed, so a no-ledger repair doesn't download sources for
    // entries the vendored phase is about to own.
    let referenced_uuids: std::collections::HashSet<String> = vendor_references
        .iter()
        .map(|(_, uuid, _)| uuid.clone())
        .collect();
    let scoped_manifest = manifest.as_ref().map(|m| {
        let patches = m
            .patches
            .iter()
            .filter(|(purl, rec)| {
                !referenced_uuids.contains(&rec.uuid)
                    && socket_patch_core::vendor::lookup_entry(vendor_entries, purl)
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
    };
    let missing_count = missing_artifacts.len();
    let noun = download_mode.noun();
    // Whether stdout already carries a line, so the blank separators
    // between sections never open the output (the offline warning goes
    // to stderr).
    let mut stdout_started = true;

    if missing_artifacts.is_empty() {
        if !quiet {
            println!("{}", format_nothing_missing(manifest.as_ref(), noun));
        }
    } else if args.common.offline {
        if !quiet {
            eprintln!("{}", format_offline_warning(&missing_artifacts, noun));
        }
        stdout_started = false;
    } else {
        if !quiet {
            println!("{}", format_found_missing(missing_artifacts.len(), noun));
        }

        if args.common.dry_run {
            if !quiet {
                println!();
                println!("Would download:");
                for line in format_id_list(&missing_artifacts, noun, DRY_RUN_LIST_CAP) {
                    println!("{line}");
                }
            }
        } else {
            let mut status = crate::ui::StatusLine::stderr(args.common.json, args.common.silent);
            status.set(format!(
                "Downloading {}...",
                noun.count(missing_artifacts.len())
            ));
            if client.is_none() {
                *client = Some(
                    get_api_client_with_overrides(args.common.api_client_overrides())
                        .await
                        .0,
                );
            }
            let client = client.as_ref().expect("client built just above");
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
                fetch_missing_sources(m, &sources, download_mode, client, None).await;
            status.finish();
            downloaded_count = fetch_result.downloaded;
            download_failed_count = fetch_result.failed;
            if !quiet {
                for line in format_fetch_successes(&fetch_result, noun) {
                    println!("{line}");
                }
            }
            // Failures are error output: stderr, and not muted by
            // `--silent` (`--json` runs carry them in the envelope).
            if !args.common.json {
                for (i, line) in format_fetch_failures(&fetch_result, noun)
                    .iter()
                    .enumerate()
                {
                    if i == 0 {
                        eprintln!("Error: {line}");
                    } else {
                        eprintln!("{line}");
                    }
                }
            }
        }
    }

    // Step 1.5: vendored artifacts — health-check the ledger (and any
    // lockfile vendor references with no ledger coverage) and rebuild
    // missing/corrupt artifacts. Runs under `--download-only` too:
    // restoring artifacts IS repair's download half. The reference scan
    // and ledger load above are handed over, not repeated.
    let vendor_rebuilt = crate::commands::repair_vendor::repair_vendored_artifacts_with_references(
        &args.common,
        manifest.as_ref(),
        &socket_dir,
        &mut env,
        &vendor_references,
        ledger,
        client.as_ref(),
    )
    .await;
    if !quiet && vendor_rebuilt > 0 {
        stdout_started = true;
        println!(
            "Rebuilt {}.",
            crate::ui::plural(vendor_rebuilt, "vendored artifact", "vendored artifacts")
        );
    }

    // Step 2: Clean up unused artifacts across all three directories. The
    // summary prints once all three passes are in, so "nothing to clean
    // up" is only said when all three really are empty.
    if let (false, Some(manifest)) = (args.download_only, manifest.as_ref()) {
        let sweep = sweep_unused_artifacts(manifest, &socket_dir, args.common.dry_run).await;
        let passes = [
            ("blob", BLOB, sweep.blobs),
            ("diff", DIFF_ARCHIVE, sweep.diffs),
            ("package", PACKAGE_ARCHIVE, sweep.packages),
        ];
        let mut results: Vec<(ArtifactNoun, CleanupResult)> = Vec::new();
        for (label, noun, result) in passes {
            // A failed cleanup — the pass aborted, or it could not unlink
            // every orphan — is error output: `--silent` (suppress
            // NON-error output) must not mute it, and the JSON envelope
            // must carry it — a bare `status: success` with no events is
            // indistinguishable from "nothing to clean". Recorded as an
            // informational skip (not `Failed`) to preserve the human
            // path's warn-and-continue contract: status stays success,
            // exit stays 0, and the loop goes on to the next directory.
            // A pass that swept past unlink failures still counts what it
            // did reclaim.
            if let Some(detail) = sweep_failure(label, &result) {
                if !args.common.json {
                    eprintln!("Warning: {detail}");
                }
                env.record(
                    PatchEvent::artifact(PatchAction::Skipped)
                        .with_reason("cleanup_failed", detail),
                );
            }
            if let Ok(cleanup_result) = result {
                results.push((noun, cleanup_result));
            }
        }

        for (_, r) in &results {
            blobs_checked += r.blobs_checked;
            blobs_cleaned += r.blobs_removed;
            bytes_freed += r.bytes_freed;
        }
        if !quiet {
            if stdout_started {
                println!();
            }
            stdout_started = true;
            println!("{}", format_cleanup_summary(&results, args.common.dry_run));
        }
    }

    if !quiet {
        // The blank separator goes to the same stream as the final line,
        // so a piped stdout never ends in a stray blank line when the
        // line itself goes to stderr.
        let other_failure = matches!(env.status, Status::PartialFailure | Status::Error);
        let line = format_final_line(
            download_failed_count,
            other_failure,
            noun,
            args.common.dry_run,
        );
        if download_failed_count > 0 || other_failure {
            if stdout_started {
                eprintln!();
            }
            eprintln!("{line}");
        } else {
            if stdout_started {
                println!();
            }
            println!("{line}");
        }
    }

    // Translate the aggregate counts into envelope events. `repair`
    // operates on artifacts (not specific patches), so events use the
    // `PatchEvent::artifact` form (no PURL/UUID).
    //
    // Only the online path downloads (or, in dry-run, *would* download).
    // In offline mode nothing is fetched even when artifacts are missing,
    // so don't record a download/would-download event there — that would
    // contradict the human-readable path, which only prints a warning.
    if downloaded_count > 0 || (!args.common.offline && args.common.dry_run && missing_count > 0) {
        let (action, count) = if args.common.dry_run {
            (PatchAction::Verified, missing_count)
        } else {
            (PatchAction::Downloaded, downloaded_count)
        };
        env.record(
            PatchEvent::artifact(action).with_details(serde_json::json!({
                "count": count,
                "mode": download_mode.as_tag(),
            })),
        );
    }
    if download_failed_count > 0 {
        env.record(PatchEvent::artifact(PatchAction::Failed).with_error(
            "download_failed",
            format!("{} failed to download", noun.count(download_failed_count)),
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

    #[test]
    fn nothing_missing_line_says_why() {
        use socket_patch_core::manifest::schema::PatchManifest;
        assert_eq!(
            format_nothing_missing(None, DIFF_ARCHIVE),
            "No manifest; no patch artifacts to download."
        );
        let empty = PatchManifest::new();
        assert_eq!(
            format_nothing_missing(Some(&empty), DIFF_ARCHIVE),
            "No patches in manifest; nothing to download."
        );
        let one: PatchManifest =
            serde_json::from_str(MANIFEST_JSON).expect("fixture manifest parses");
        assert!(!one.patches.is_empty());
        assert_eq!(
            format_nothing_missing(Some(&one), DIFF_ARCHIVE),
            "All diff archives are present locally."
        );
        assert_eq!(
            HOSTED_ONLY_REASON,
            "Hosted redirects need no local repair; re-run `scan --mode hosted` to refresh \
             the lockfile redirects (it also re-checks for stale pre-redirect installs)"
        );
    }

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

        let (env, counts) =
            repair_inner(&args, &socket.join("manifest.json"), &mut None, Vec::new())
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

        let (env, _counts) =
            repair_inner(&args, &socket.join("manifest.json"), &mut None, Vec::new())
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
        let (env, counts) =
            repair_inner(&args, &socket.join("manifest.json"), &mut None, Vec::new())
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

        let (_env, counts) =
            repair_inner(&args, &socket.join("manifest.json"), &mut None, Vec::new())
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
        let (env, counts) =
            repair_inner(&args, &socket.join("manifest.json"), &mut None, Vec::new())
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

    /// A manifest "hash" that is NOT a hex digest: manifest hashes are
    /// unvalidated strings (serde only), and byte index 12 of this one lands
    /// inside a multibyte char — so a byte slice `&id[..12]` panics on it.
    /// 1 ASCII byte + 8×2-byte `é` = 17 bytes; boundaries at 11 and 13.
    const MULTIBYTE_HASH: &str = "aéééééééé";

    /// Write a `.socket/manifest.json` whose afterHash is `MULTIBYTE_HASH`.
    fn make_socket_multibyte(root: &Path) -> PathBuf {
        let socket = root.join(".socket");
        std::fs::create_dir_all(&socket).unwrap();
        std::fs::write(
            socket.join("manifest.json"),
            MANIFEST_JSON.replace(REFERENCED_HASH, MULTIBYTE_HASH),
        )
        .unwrap();
        socket
    }

    /// Regression: the human-readable offline warning truncates each missing
    /// artifact id for display. Truncation must be by characters, not bytes —
    /// `&id[..12]` panics when byte 12 falls inside a multibyte char, so a
    /// corrupt or hand-edited manifest crashed `repair --offline` instead of
    /// warning. (Same class as the `format_fetch_result` fix in blob_fetcher.)
    #[tokio::test]
    async fn offline_warning_survives_multibyte_manifest_hash() {
        let tmp = tempfile::tempdir().unwrap();
        let socket = make_socket_multibyte(tmp.path());
        // The truncating print only runs on the human-readable path.
        let mut args = offline_args(tmp.path());
        args.common.json = false;

        let (env, counts) =
            repair_inner(&args, &socket.join("manifest.json"), &mut None, Vec::new())
                .await
                .expect("repair_inner");

        assert_eq!(counts.downloaded, 0);
        assert_eq!(env.status, Status::Success);
    }

    /// Regression twin for the dry-run preview print, which truncated ids the
    /// same byte-sliced way (its list caps at 10 instead of 5).
    #[tokio::test]
    async fn dry_run_preview_survives_multibyte_manifest_hash() {
        let tmp = tempfile::tempdir().unwrap();
        let socket = make_socket_multibyte(tmp.path());
        let mut args = offline_args(tmp.path());
        args.common.offline = false;
        args.common.dry_run = true;
        args.common.json = false;

        let (env, _counts) =
            repair_inner(&args, &socket.join("manifest.json"), &mut None, Vec::new())
                .await
                .expect("repair_inner");

        // The preview event is still recorded once the print survives.
        assert!(
            has_download_event(&env),
            "dry-run must still preview the download; events={:?}",
            env.events
        );
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

        let (env, counts) =
            repair_inner(&args, &socket.join("manifest.json"), &mut None, Vec::new())
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

    fn ids(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn id_list_is_sorted_capped_and_honest_about_truncation() {
        let uuids = ids(&[
            "22222222-2222-4222-8222-222222222222",
            "11111111-1111-4111-8111-111111111111",
        ]);
        // Diff-mode UUIDs print in full, in sorted order.
        assert_eq!(
            format_id_list(&uuids, DIFF_ARCHIVE, 5),
            vec![
                "  - 11111111-1111-4111-8111-111111111111",
                "  - 22222222-2222-4222-8222-222222222222",
            ]
        );
        // File-mode hashes: 64-hex cut to 12 + "...", a short one kept whole.
        let hashes = ids(&[&"b".repeat(64), "22"]);
        assert_eq!(
            format_id_list(&hashes, BLOB, 5),
            vec!["  - 22", "  - bbbbbbbbbbbb..."]
        );
        let many: Vec<String> = (0..7).map(|i| format!("id{i}")).collect();
        let lines = format_id_list(&many, BLOB, 5);
        assert_eq!(lines.len(), 6);
        assert_eq!(lines[5], "  ... and 2 more");
        assert!(format_id_list(&[], BLOB, 5).is_empty());
        // Multibyte ids never panic and are counted in chars.
        assert_eq!(
            format_id_list(&ids(&[MULTIBYTE_HASH]), BLOB, 5),
            vec!["  - aéééééééé"]
        );
    }

    #[test]
    fn found_missing_line() {
        assert_eq!(format_found_missing(1, BLOB), "Found 1 missing blob");
        assert_eq!(
            format_found_missing(12, DIFF_ARCHIVE),
            "Found 12 missing diff archives"
        );
    }

    #[test]
    fn offline_warning_singular_and_plural() {
        assert_eq!(
            format_offline_warning(
                &ids(&["11111111-1111-4111-8111-111111111111"]),
                DIFF_ARCHIVE
            ),
            "Warning: 1 diff archive is missing (offline mode - not downloading):\n\
             \x20 - 11111111-1111-4111-8111-111111111111"
        );
        assert_eq!(
            format_offline_warning(&ids(&["b", "a"]), BLOB),
            "Warning: 2 blobs are missing (offline mode - not downloading):\n  - a\n  - b"
        );
    }

    #[test]
    fn cleanup_summary_names_each_kind() {
        let checked = |n: usize| CleanupResult {
            blobs_checked: n,
            ..Default::default()
        };
        assert_eq!(
            format_cleanup_summary(
                &[
                    (BLOB, checked(0)),
                    (DIFF_ARCHIVE, checked(0)),
                    (PACKAGE_ARCHIVE, checked(0))
                ],
                false
            ),
            "Nothing to clean up."
        );
        assert_eq!(format_cleanup_summary(&[], false), "Nothing to clean up.");
        assert_eq!(
            format_cleanup_summary(&[(BLOB, checked(1)), (DIFF_ARCHIVE, checked(0))], false),
            "Checked 1 blob: in use."
        );
        assert_eq!(
            format_cleanup_summary(
                &[
                    (BLOB, checked(2)),
                    (DIFF_ARCHIVE, checked(1)),
                    (PACKAGE_ARCHIVE, checked(3))
                ],
                false
            ),
            "Checked 2 blobs, 1 diff archive and 3 package archives: all in use."
        );
        let orphan = CleanupResult {
            blobs_checked: 2,
            blobs_removed: 1,
            bytes_freed: 3,
            removed_blobs: vec!["3333.tar.gz".into()],
            ..Default::default()
        };
        let pkg = CleanupResult {
            blobs_checked: 1,
            blobs_removed: 1,
            bytes_freed: 2,
            removed_blobs: vec!["4444.tar.gz".into()],
            ..Default::default()
        };
        assert_eq!(
            format_cleanup_summary(
                &[
                    (BLOB, checked(0)),
                    (DIFF_ARCHIVE, orphan),
                    (PACKAGE_ARCHIVE, pkg)
                ],
                true
            ),
            "Would remove 1 unused diff archive (3 B freed)\n\
             Unused diff archives:\n  - 3333.tar.gz\n\
             Would remove 1 unused package archive (2 B freed)\n\
             Unused package archives:\n  - 4444.tar.gz"
        );
    }

    #[test]
    fn final_line_reflects_failures_and_dry_run() {
        assert_eq!(format_final_line(0, false, BLOB, false), "Repair complete.");
        assert_eq!(
            format_final_line(0, false, BLOB, true),
            "Dry run: no changes made."
        );
        assert_eq!(
            format_final_line(1, false, DIFF_ARCHIVE, false),
            "Repair finished with errors: 1 diff archive was not downloaded."
        );
        assert_eq!(
            format_final_line(2, true, BLOB, false),
            "Repair finished with errors: 2 blobs were not downloaded."
        );
        // A failed vendored rebuild (exit 1) never closes on "complete".
        assert_eq!(
            format_final_line(0, true, BLOB, false),
            "Repair finished with errors."
        );
        assert_eq!(
            format_final_line(0, true, BLOB, true),
            "Repair finished with errors."
        );
    }

    #[test]
    fn help_has_no_developer_commentary() {
        use clap::CommandFactory;
        let mut cmd = crate::Cli::command();
        let help = cmd
            .find_subcommand_mut("repair")
            .expect("repair subcommand")
            .render_long_help()
            .to_string();
        assert!(
            help.contains("Only download missing artifacts; skip the cleanup phase."),
            "{help}"
        );
        for internal in [
            "value_parser",
            "GLOBAL_ARG_ENV_VARS",
            "`main`'s",
            "parse_bool_flag",
        ] {
            assert!(!help.contains(internal), "leaked {internal:?} into --help");
        }
    }
}
