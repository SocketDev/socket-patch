//! The agent-mode download engine shared by `get` and `scan`: select →
//! fetch → write the manifest and blobs → run the nested apply. A helper
//! module, not a command, so `scan` reaches it without importing `get`
//! (#894 child 2). The nested apply still builds `ApplyArgs` and calls
//! `apply::run_locked`; the typed entry point that replaces it is #894
//! child 3 (waits on #793).

use futures_util::StreamExt;
use socket_patch_core::api::client::{hold_back_debug, ApiClient};
use socket_patch_core::api::ranking::severity_order;
use socket_patch_core::api::types::{PatchResponse, PatchSearchResult, VulnerabilityResponse};
use socket_patch_core::crawlers::{CrawlerOptions, Ecosystem};
use socket_patch_core::manifest::operations::{read_manifest, write_manifest};
use socket_patch_core::manifest::records::{build_patch_record, files_for_manifest};
use socket_patch_core::manifest::schema::{PatchFileInfo, PatchManifest, PatchRecord};
use socket_patch_core::patch::apply::{is_valid_blob_hash, select_installed_variants_any};
use socket_patch_core::patch::apply_lock::{LockError, LockGuard};
use socket_patch_core::utils::concurrent::{api_concurrency_for, ordered_concurrent};
use socket_patch_core::utils::purl::{normalize_purl, strip_purl_qualifiers};
use socket_patch_core::utils::purl_key::PurlKey;
use socket_patch_core::vendor::{load_state, lookup_entry, VendorEntry, VendorState};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::args::GlobalArgs;
use crate::commands::apply::ApplyRunReport;
use crate::commands::bun_preflight::{bun_vendor_preflight_with_ledger, BunVendorRefusal};
use crate::commands::lock_cli::lock_failure;
use crate::commands::vlt_preflight::{
    vlt_refusal_for, vlt_vendor_preflight_selected, VltVendorRefusal,
};
use crate::ecosystem_dispatch::{find_all_packages_for_rollback, partition_purls};
use crate::json_envelope::{
    Command as EnvelopeCommand, Envelope, EnvelopeError, PatchAction as EventAction, PatchEvent,
    RunWarning,
};

/// The closing error printed when the nested apply failed. Apply's own
/// per-package `Error: Failed to patch …` lines print above it, even
/// under `--silent`, so this line needs no "re-run" hint.
pub(crate) const APPLY_FAILED: &str = "Error: Some patches could not be applied.";

/// Per-patch outcome reported in the JSON output of `download_and_apply_patches_with`.
/// `Updated` carries the previous UUID so a bot can diff a manifest update against
/// what was there before — see CLI_CONTRACT.md for the stable vocabulary.
#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) enum PatchAction {
    /// Patch did not exist in the manifest at this PURL.
    Added,
    /// Patch existed under this PURL with a different UUID; the new UUID
    /// replaces the old one. `old_uuid` is the UUID being overwritten.
    Updated { old_uuid: String },
    /// Patch already exists with the same UUID; download is a no-op.
    Skipped,
}

/// The exit code of a download+apply run: 1 when a patch failed to
/// download or the nested apply failed. Every such run also records a
/// `failed` event ([`record_apply_outcome`] guarantees one for a failed
/// apply), so the envelope's `partialFailure` status and `$?` agree.
pub(crate) fn run_outcome(patches_failed: bool, apply_failed: bool) -> i32 {
    i32::from(patches_failed || apply_failed)
}

/// Classify what `download_and_apply_patches_with` will do to a given PURL based on
/// the manifest state *before* any insert. Pure / no I/O so it's unit-testable.
pub(crate) fn decide_patch_action(
    manifest: &PatchManifest,
    purl: &str,
    new_uuid: &str,
) -> PatchAction {
    match manifest.patches.get(purl) {
        Some(existing) if existing.uuid == new_uuid => PatchAction::Skipped,
        Some(existing) => PatchAction::Updated {
            old_uuid: existing.uuid.clone(),
        },
        None => PatchAction::Added,
    }
}

/// Ordinal rank for severity strings. Higher = worse — the inverse of
/// core's [`severity_order`], which this derives from so the two ladders
/// cannot drift. Unknown labels (including GHSA's `moderate`, which maps to
/// `medium`) get sensible defaults so the max-severity selector still works.
pub(crate) fn severity_rank(severity: &str) -> u8 {
    // severity_order: 0 = critical … 4 = unknown. Flip it so 4 = critical
    // and unknown lands at 0, which callers below treat as "no signal".
    4 - severity_order(Some(severity))
}

/// Return the highest-severity label from a vulnerabilities map.
/// Returns `None` when the map is empty or every entry's severity is
/// unrecognized.
pub(crate) fn max_vuln_severity(vulns: &HashMap<String, VulnerabilityResponse>) -> Option<String> {
    vulns
        .values()
        .max_by_key(|v| severity_rank(&v.severity))
        // `max_by_key` only yields `None` for an empty map; a non-empty
        // map of exclusively unrecognized severities (all rank 0) would
        // otherwise leak a garbage label like "" or "unknown". Drop it so
        // the documented "every entry unrecognized → None" contract holds
        // and `patch_event_metadata` omits `severity` rather than emitting
        // a meaningless value.
        .filter(|v| severity_rank(&v.severity) > 0)
        .map(|v| v.severity.clone())
}

/// Build the metadata payload spliced into per-patch JSON action records
/// (`added` / `updated`). Surfaces what consumers need to render a patch
/// to end users: human-readable description, license, tier, exportedAt;
/// a top-level severity computed as the max across all vulnerabilities;
/// and a flattened vulnerability list with the canonical advisory IDs
/// (GHSA, CVE) front and center so consumers can route on severity or
/// open a specific advisory.
///
/// Output keys are JSON-camelCase to match the rest of the envelope.
/// The vulnerability list is sorted by ID for stable test snapshots.
pub(crate) fn patch_event_metadata(patch: &PatchResponse) -> serde_json::Value {
    let mut vulns: Vec<serde_json::Value> = patch
        .vulnerabilities
        .iter()
        .map(|(id, v)| {
            serde_json::json!({
                "id": id,
                "cves": v.cves,
                "severity": v.severity,
                "summary": v.summary,
                "description": v.description,
            })
        })
        .collect();
    // Stable ordering — HashMap iteration is otherwise nondeterministic
    // and consumers diff this output in CI logs.
    vulns.sort_by(|a, b| {
        a["id"]
            .as_str()
            .unwrap_or("")
            .cmp(b["id"].as_str().unwrap_or(""))
    });

    let mut meta = serde_json::Map::new();
    meta.insert(
        "description".into(),
        serde_json::Value::String(patch.description.clone()),
    );
    meta.insert(
        "license".into(),
        serde_json::Value::String(patch.license.clone()),
    );
    meta.insert("tier".into(), serde_json::Value::String(patch.tier.clone()));
    meta.insert(
        "exportedAt".into(),
        serde_json::Value::String(patch.published_at.clone()),
    );
    if let Some(sev) = max_vuln_severity(&patch.vulnerabilities) {
        meta.insert("severity".into(), serde_json::Value::String(sev));
    }
    meta.insert("vulnerabilities".into(), serde_json::Value::Array(vulns));
    serde_json::Value::Object(meta)
}

/// Merge `mode` (`"vendored"` / `"hosted"`) into an event's `details`, the
/// leg tag every vendored- and hosted-leg event carries (rule shared with
/// `list`). Agent-mode events carry no mode.
pub(crate) fn tag_mode(mut event: PatchEvent, mode: Option<&str>) -> PatchEvent {
    if let Some(mode) = mode {
        let mut details = event
            .details
            .take()
            .filter(serde_json::Value::is_object)
            .unwrap_or_else(|| serde_json::json!({}));
        details["mode"] = serde_json::json!(mode);
        event.details = Some(details);
    }
    event
}

/// Report a failed apply-lock acquire: the human lock error on stderr
/// (unless `json`), and the `{code, message}` (`lock_held` / `lock_io`) the
/// caller's envelope carries as its top-level `error`. The message/code
/// mapping is [`crate::commands::lock_cli::lock_failure`]'s, so the waited
/// clause and the I/O rendering cannot drift from `apply`'s.
pub(crate) fn report_lock_failure(
    json: bool,
    socket_dir: &Path,
    err: &LockError,
    timeout: Duration,
) -> EnvelopeError {
    let (code, message) = lock_failure(err, timeout);
    if !json {
        eprint!(
            "{}",
            crate::commands::lock_cli::format_lock_error(socket_dir, err, timeout)
        );
    }
    EnvelopeError::new(code, message)
}

/// Decode a base64 string and store it as the blob `blobs_dir/hash`
/// through the one verified writer,
/// [`store_verified_blob`](socket_patch_core::api::blob_fetcher::store_verified_blob):
/// the bytes must hash to `hash`, a linked `.socket/blobs` or
/// `.socket/blobs/<hash>` is refused, and the entry is staged and renamed
/// (#726). Returns whether the blob file was NEWLY created (`false`: a
/// verified blob with this hash already existed and was left untouched),
/// or a formatted error string referencing `file_path` and `label` on
/// failure.
///
/// `blobs_dir` is created there, lazily — only once a blob is actually
/// about to be persisted — so a run that records nothing (every fetch
/// failed, every patch skipped, undecodable content) leaves no empty
/// `.socket/blobs/` behind.
pub(crate) async fn write_blob_entry(
    blobs_dir: &Path,
    b64: &str,
    hash: &str,
    file_path: &str,
    label: &str,
) -> Result<bool, String> {
    if !is_valid_blob_hash(hash) {
        return Err(format!(
            "Refusing to write {label} for {file_path}: invalid blob hash {hash:?} (expected 64 hex chars)"
        ));
    }
    let decoded =
        base64_decode(b64).map_err(|e| format!("Failed to decode {label} for {file_path}: {e}"))?;
    socket_patch_core::api::blob_fetcher::store_verified_blob(blobs_dir, hash, &decoded)
        .await
        .map_err(|e| format!("Failed to write {label} for {file_path} ({hash}): {e}"))
}

/// Write every after/before blob for `patch` into `blobs_dir`, reporting
/// per-file failures on stderr unless `quiet` is set. Returns the hashes
/// this call NEWLY created (the caller unwinds them if it then fails to
/// record the patch), or `Err(())` on the first failure — after removing
/// the blobs this same call had already created and pruning an emptied
/// `blobs/` (`is_empty_dir` semantics: a pre-existing blob is never touched),
/// so a patch that fails half-way leaves no orphan `.socket/blobs/<hash>`
/// with no record pointing at it; callers handle the bookkeeping that
/// follows.
pub(crate) async fn write_all_patch_blobs(
    blobs_dir: &Path,
    patch: &PatchResponse,
    quiet: bool,
) -> Result<Vec<String>, ()> {
    let mut created: Vec<String> = Vec::new();
    for (file_path, file_info) in &patch.files {
        for (blob, hash, label) in [
            (&file_info.blob_content, &file_info.after_hash, "blob"),
            (
                &file_info.before_blob_content,
                &file_info.before_hash,
                "before-blob",
            ),
        ] {
            if let (Some(blob), Some(hash)) = (blob, hash) {
                match write_blob_entry(blobs_dir, blob, hash, file_path, label).await {
                    Ok(true) => created.push(hash.clone()),
                    Ok(false) => {}
                    Err(e) => {
                        if !quiet {
                            eprintln!("  [error] {e}");
                        }
                        unwind_new_blobs(blobs_dir, &created).await;
                        return Err(());
                    }
                }
            }
        }
    }
    Ok(created)
}

/// Remove the blobs a failed run NEWLY created (`write_all_patch_blobs`'s
/// return value — never a pre-existing blob, which some record may still
/// reference), then prune an emptied `blobs/` up to but excluding `.socket/`,
/// so an all-failed run on a fresh project leaves no `.socket/` behind
/// (contract: `.socket/blobs/` exists only when a record is persisted).
/// Best-effort; the caller's error is what gets reported.
pub(crate) async fn unwind_new_blobs(blobs_dir: &Path, hashes: &[String]) {
    for hash in hashes {
        let _ = tokio::fs::remove_file(blobs_dir.join(hash)).await;
    }
    if let Some(stop_dir) = blobs_dir.parent() {
        socket_patch_core::utils::socket_dir::prune_empty_dirs(blobs_dir, stop_dir).await;
    }
}

/// Build a file map keyed by path, keeping only files that carry BOTH
/// hashes — the rule used ONLY for installed-distribution matching in
/// [`filter_to_installed_releases`]. New files (no `beforeHash`) can
/// neither identify nor disqualify an installed variant, so they are
/// excluded here; [`select_installed_variants`] then discriminates on a
/// non-empty `beforeHash`. Do NOT use this to build manifest records —
/// see [`files_for_manifest`], which retains patch-added files.
pub(crate) fn files_with_both_hashes(patch: &PatchResponse) -> HashMap<String, PatchFileInfo> {
    let mut files = HashMap::new();
    for (file_path, file_info) in &patch.files {
        if let (Some(before), Some(after)) = (&file_info.before_hash, &file_info.after_hash) {
            files.insert(
                file_path.clone(),
                PatchFileInfo {
                    before_hash: before.clone(),
                    after_hash: after.clone(),
                },
            );
        }
    }
    files
}

/// The summary after the multi-patch download loop. A run that changed
/// nothing says so instead of claiming the patches were "saved".
pub(crate) fn format_save_summary(
    manifest_path: &Path,
    added: usize,
    updated: usize,
    skipped: usize,
    failed: usize,
) -> String {
    let mut out = if added + updated > 0 {
        format!("Patches saved to {}", manifest_path.display())
    } else {
        format!("No changes to {}", manifest_path.display())
    };
    out.push_str(&format!("\n  Added: {added}"));
    for (label, n) in [
        ("Updated", updated),
        ("Skipped", skipped),
        ("Failed", failed),
    ] {
        if n > 0 {
            out.push_str(&format!("\n  {label}: {n}"));
        }
    }
    out
}

/// `  [skip] <purl> (<why>)` for a record the download phase reuses, with
/// the purl decoded for display (`%40scope` reads as `@scope`).
pub(crate) fn format_record_skip(purl: &str, why: &str) -> String {
    format!("  [skip] {} ({why})", normalize_purl(purl))
}

/// Download parameters shared between get and scan commands.
pub struct DownloadParams {
    pub cwd: PathBuf,
    /// Resolved manifest location (`GlobalArgs::resolved_manifest_path`).
    /// The blobs directory is its parent's `blobs/` — the same layout
    /// apply/rollback resolve from — so `--manifest-path` is honored here
    /// like on every other command, not silently replaced with
    /// `<cwd>/.socket/manifest.json`.
    pub manifest_path: PathBuf,
    pub save_only: bool,
    pub global: bool,
    pub global_prefix: Option<PathBuf>,
    pub json: bool,
    pub silent: bool,
    /// When `false` (the default — narrow), a release-variant package (PyPI
    /// `?artifact_id=`, RubyGems `?platform=`, Maven `?classifier=`) is
    /// filtered down to the variant(s) matching the locally-installed
    /// distribution before download. When `true` (`--all-releases`), every
    /// variant is downloaded. No effect on ecosystems without per-release
    /// variants.
    pub all_releases: bool,
    /// `--strict` forwarded to the nested apply (a beforeHash mismatch
    /// fails instead of warn-and-overwrite).
    pub strict: bool,
    /// `--ecosystems` forwarded to the nested apply, so it never touches
    /// other ecosystems' packages the user filtered out.
    pub ecosystems: Option<Vec<String>>,
    /// Persist downloaded blob content into `.socket/blobs` (the apply
    /// flows need it for later hook/rollback runs). Vendor flows pass
    /// `false`: their patch content is staged in memory and the committed
    /// artifact is the patch — nothing should land in `.socket/blobs`.
    pub persist_blobs: bool,
    /// `--patch-server-url`: the extra origin whose URLs count as hosted
    /// when lockfile discovery reads the project's hosted pins.
    pub patch_server_url: Option<String>,
}

impl DownloadParams {
    /// `--silent` is "errors only" and `--json` owns stdout: every
    /// informational print in the engines is gated on this.
    fn quiet(&self) -> bool {
        self.json || self.silent
    }

    /// The `.socket/` directory the manifest lives in (lock + blobs root) —
    /// the one derivation every lock acquire and artifact probe uses.
    fn socket_dir(&self) -> PathBuf {
        crate::args::socket_dir_of(&self.manifest_path, &self.cwd)
    }

    fn crawler_options(&self) -> CrawlerOptions {
        CrawlerOptions {
            cwd: self.cwd.clone(),
            global: self.global,
            global_prefix: self.global_prefix.clone(),
        }
    }
}

/// Run-level context the download engines need beside `DownloadParams`:
/// the run's API client — built once, proxy fallback included, so the
/// engines never rebuild it from flags and repeat the org auto-resolve
/// round-trip — and the flags the nested apply must inherit.
pub struct DownloadRun<'a> {
    /// The run's one API client; the nested apply runs on it too.
    pub api_client: &'a ApiClient,
    /// `--lock-timeout`: the wait budget for the apply lock, taken once
    /// around the manifest write and the nested apply.
    pub lock_timeout: Option<u64>,
    /// `--verbose`, forwarded to the nested apply.
    pub verbose: bool,
}

/// Narrow a selection of patches down to the release variant(s) present
/// in each locally-installed distribution.
///
/// A release-variant ecosystem `package@version` can resolve to several
/// patch variants — one per qualified PURL: PyPI `?artifact_id=`
/// (wheel/sdist), RubyGems `?platform=`, Maven `?classifier=&ext=`. With
/// `--all-releases` off (the default) we keep only the variant(s) whose
/// first patched file's hash matches what's on disk, dropping the rest so
/// they are never downloaded or written to the manifest. PyPI/RubyGems
/// install one distribution per environment (≤1 kept); Maven classifier
/// jars coexist, so several may be kept. Ecosystems that ship one
/// artifact per version never carry qualifiers and pass through untouched.
///
/// Fallbacks (keep all variants of the base, i.e. behave as broad):
///   * the base package is not installed on disk (nothing to match
///     against — e.g. `get` for an absent package), or
///   * the installed distribution matches none of the variants (a local
///     modification, or no patch exists for the installed release).
///
/// Both fallbacks push a human-readable warning.
///
/// Returns the kept patches, any warnings to surface to the caller (also
/// printed to stderr here unless `quiet`), and the patch views fetched to
/// hash-match the KEPT variants (uuid-keyed) — the download loop serves
/// those from memory instead of fetching every view a second time. Only
/// successful fetches are cached: a variant whose view errored or 404'd is
/// re-fetched by the loop so the failure surfaces per patch as before.
/// With `--all-releases` set no variant is narrowed away and no view is
/// fetched — the whole selection comes back, in the same purl order
/// ([`sort_by_purl`]) as the narrowed arm, so both arms of this function
/// share one output contract.
pub(crate) async fn filter_to_installed_releases(
    selected: &[PatchSearchResult],
    all_releases: bool,
    crawler_options: &CrawlerOptions,
    quiet: bool,
    api_client: &ApiClient,
) -> (
    Vec<PatchSearchResult>,
    Vec<String>,
    HashMap<String, PatchResponse>,
) {
    let mut views: HashMap<String, PatchResponse> = HashMap::new();
    if all_releases {
        let mut kept = selected.to_vec();
        sort_by_purl(&mut kept);
        return (kept, Vec::new(), views);
    }

    // Group release-variant ecosystem selections (PyPI / RubyGems / Maven)
    // by their base PURL (qualifiers stripped). Anything that can't have
    // release variants, or whose base has a single variant, is kept
    // verbatim and needs no installed-dist resolution.
    let mut variant_groups: HashMap<String, Vec<PatchSearchResult>> = HashMap::new();
    let mut kept: Vec<PatchSearchResult> = Vec::new();
    for sr in selected {
        if Ecosystem::from_purl(&sr.purl).is_some_and(|e| e.supports_release_variants()) {
            variant_groups
                .entry(strip_purl_qualifiers(&sr.purl).to_string())
                .or_default()
                .push(sr.clone());
        } else {
            kept.push(sr.clone());
        }
    }

    let mut warnings: Vec<String> = Vec::new();

    // Singleton bases have nothing to disambiguate — keep as-is.
    // Collect the multi-variant bases that actually need resolution.
    let mut multi: Vec<(String, Vec<PatchSearchResult>)> = Vec::new();
    for (base, variants) in variant_groups {
        if variants.len() <= 1 {
            kept.extend(variants);
        } else {
            multi.push((base, variants));
        }
    }
    // `variant_groups` is a HashMap, so both drains above are in bucket
    // order — which is this function's OUTPUT order, and therefore the
    // order the download loop emits `download.patches` / `apply.patches`
    // in. Sort the multi-variant bases so their warnings and kept variants
    // are stable, and sort the whole kept list by purl before returning
    // (below and at the early return): every sibling collection in the same envelope —
    // scan's `packages`, the agent flow's `skip_records` — is purl-sorted.
    multi.sort_by(|a, b| a.0.cmp(&b.0));

    if multi.is_empty() {
        sort_by_purl(&mut kept);
        return (kept, warnings, views);
    }

    // Discover the on-disk path for each multi-variant base. The crawler
    // is queried with base PURLs and the result is fanned back out to
    // every qualified variant. For PyPI/RubyGems all variants of one
    // installed package resolve to the same dir; for Maven the variants
    // share a version dir but target distinct jar files within it.
    let all_qualified: Vec<String> = multi
        .iter()
        .flat_map(|(_, variants)| variants.iter().map(|s| s.purl.clone()))
        .collect();
    // Release-variant PURLs only (PyPI / RubyGems / Maven); partition_purls
    // splits them by ecosystem, so no filter is needed.
    let partitioned = partition_purls(&all_qualified, None);
    // Every copy: a Maven base can sit in `~/.m2` and in each Gradle cache,
    // with different classifiers in each (narrowing takes a variant any copy
    // holds); the other ecosystems narrow on their first copy, as before.
    let paths = find_all_packages_for_rollback(&partitioned, crawler_options, true).await;

    // Every installed base's variant views, fetched concurrently (at most
    // `api_concurrency` in flight) in the order the loop below consumes
    // them: bases in `multi` order, skipping the uninstalled ones, each
    // base's variants in order. Nothing here prints between fetches, and
    // each request's `--debug` lines are released at its turn in that order.
    let installed_variants: Vec<String> = multi
        .iter()
        .filter(|(_, variants)| variants.iter().any(|s| paths.contains_key(&s.purl)))
        .flat_map(|(_, variants)| variants.iter().map(|s| s.uuid.clone()))
        .collect();
    let window_len = installed_variants.len();
    let mut variant_views = std::pin::pin!(ordered_concurrent(
        installed_variants,
        api_concurrency_for(api_client.uses_public_proxy(), window_len),
        |uuid| async move {
            let view = hold_back_debug(api_client.fetch_patch(&uuid)).await;
            (uuid, view)
        },
    ));

    for (base, variants) in multi {
        // Any variant's resolved paths work — they all map to the same
        // installed package directories.
        let pkg_paths = variants
            .iter()
            .find_map(|s| paths.get(&s.purl))
            .filter(|p| !p.is_empty())
            .map(|p| {
                if base.starts_with("pkg:maven/") {
                    p.clone()
                } else {
                    p[..1].to_vec()
                }
            });
        let Some(pkg_paths) = pkg_paths else {
            // Not installed: cannot determine the relevant release. Keep
            // every variant so the patch is still obtainable.
            warnings.push(format!(
                "{base} is not installed locally; keeping all {}.",
                crate::ui::plural(variants.len(), "release variant", "release variants")
            ));
            kept.extend(variants);
            continue;
        };

        // Fetch each variant's file hashes (the view carries them) so we
        // can hash-match against the installed distribution. The view is
        // kept for the download loop — it is the same GET it would issue.
        let mut candidates: Vec<(String, HashMap<String, PatchFileInfo>)> = Vec::new();
        for s in &variants {
            let view = match variant_views.next().await {
                Some((planned, view)) if planned == s.uuid => view.release(),
                // Unreachable: the plan holds one view per variant of
                // every installed base. Checking matters — a plan out of
                // step would hash-match this variant against ANOTHER
                // release's files and store that response under this
                // uuid for the download engine.
                _ => {
                    debug_assert!(
                        false,
                        "variant view prefetch plan out of step with the variants"
                    );
                    api_client.fetch_patch(&s.uuid).await
                }
            };
            match view {
                Ok(Some(patch)) => {
                    candidates.push((s.purl.clone(), files_with_both_hashes(&patch)));
                    views.insert(s.uuid.clone(), patch);
                }
                // On a fetch error/miss, keep the variant so the main
                // download loop records the failure.
                _ => candidates.push((s.purl.clone(), HashMap::new())),
            }
        }

        let refs: Vec<(&str, &HashMap<String, PatchFileInfo>)> = candidates
            .iter()
            .map(|(purl, files)| (purl.as_str(), files))
            .collect();

        // Keep every variant present on disk. PyPI/RubyGems install one
        // distribution per env (≤1 match); Maven classifier jars coexist
        // so several may match.
        let matched = select_installed_variants_any(&pkg_paths, &refs).await;
        if matched.is_empty() {
            // Installed, but no variant matches the on-disk bytes. Fall
            // back to broad rather than silently dropping a package the
            // user asked about.
            warnings.push(format!(
                "No release variant of {base} matches the installed distribution; keeping all {}.",
                crate::ui::plural(variants.len(), "variant", "variants")
            ));
            kept.extend(variants);
        } else {
            let winners: std::collections::HashSet<String> =
                matched.iter().map(|&i| candidates[i].0.clone()).collect();
            kept.extend(variants.into_iter().filter(|s| winners.contains(&s.purl)));
        }
    }

    if !quiet {
        for w in &warnings {
            eprintln!("  [note] {w}");
        }
    }
    // Narrowed-out variants are never downloaded: drop their views (each
    // carries every file's base64 content) so only the kept ones ride on.
    let kept_uuids: std::collections::HashSet<&str> =
        kept.iter().map(|s| s.uuid.as_str()).collect();
    views.retain(|uuid, _| kept_uuids.contains(uuid.as_str()));
    sort_by_purl(&mut kept);
    (kept, warnings, views)
}

/// Order a patch selection the way every other collection in the JSON
/// envelope is ordered: by purl, uuid breaking a tie (a release-variant
/// base can keep several qualified purls, and `--all-releases` can keep
/// several patches for one purl).
pub(crate) fn sort_by_purl(patches: &mut [PatchSearchResult]) {
    patches.sort_by(|a, b| a.purl.cmp(&b.purl).then_with(|| a.uuid.cmp(&b.uuid)));
}

/// Which state store the shared fetch loop classifies each selected patch
/// against — the one non-presentational difference between the vendored
/// and agent download engines.
#[derive(Clone, Copy)]
pub(crate) enum RecordStore<'a> {
    /// The vendor ledger (`scan` / `get --mode vendored`, the detached
    /// posture): a detached entry already at the selected uuid is reused
    /// without a fetch (`skipped`); a fetched patch is `downloaded`, with
    /// `oldUuid` when the ledger wires the purl at another uuid.
    Ledger(&'a HashMap<String, VendorEntry>),
    /// `.socket/manifest.json` (agent mode): the fetched view is classified
    /// by [`decide_patch_action`] — `added` / `updated` (+ `oldUuid`) /
    /// `skipped` (the same uuid is already recorded).
    Manifest(&'a PatchManifest),
}

/// A fetched patch the shared loop accepted — recordable files, blobs
/// persisted when asked — handed to the engine wrapper to record.
pub(crate) struct FetchedPatch {
    patch: PatchResponse,
    files: HashMap<String, PatchFileInfo>,
    action: PatchAction,
    /// Blob hashes this fetch NEWLY wrote under `.socket/blobs/` (empty
    /// when blobs are not persisted) — what a failed record write unwinds.
    new_blobs: Vec<String>,
}

/// What the shared fetch loop produced over one selection.
pub(crate) struct FetchBatch {
    skipped: usize,
    /// Manifest store only: the `skipped` patches whose same uuid is
    /// already recorded — still owed a nested apply, since the installed
    /// copy may have been reinstalled since the record was written.
    already_recorded: usize,
    failed: usize,
    /// Fetched, recordable patches in selection order.
    fetched: Vec<FetchedPatch>,
    /// Ledger store only: `(purl, record)` reused from a detached entry
    /// already at the selected uuid (no fetch).
    reused: Vec<(String, PatchRecord)>,
    /// Per-patch events in selection order (the envelope vocabulary):
    /// `downloaded` / `updated` (+ `oldUuid`) with the patch metadata in
    /// `details`, `skipped` (`already_in_manifest`), `failed` (+ code).
    /// Ledger-store events carry `details.mode: "vendored"`.
    events: Vec<PatchEvent>,
    /// Release-narrowing fallbacks (uninstalled base, no matching variant).
    warnings: Vec<String>,
    /// `Some("vendored")` for the ledger store (see [`tag_mode`]).
    mode: Option<&'static str>,
}

impl FetchBatch {
    /// Record a per-patch failure. `line` is the stderr text — an error, so
    /// exempt from `--silent`; JSON runs carry the detail in the envelope
    /// instead — or `None` when the failure already printed its own detail.
    fn fail(
        &mut self,
        json: bool,
        line: Option<String>,
        (purl, uuid): (&str, &str),
        error_code: &str,
        error: &str,
    ) {
        if let (false, Some(line)) = (json, line) {
            eprintln!("  {line}");
        }
        self.events.push(tag_mode(
            PatchEvent::new(EventAction::Failed, purl)
                .with_uuid(uuid)
                .with_error(error_code, error),
            self.mode,
        ));
        self.failed += 1;
    }
}

/// `errorCode` of a patch whose view could not be fetched (network error,
/// 404).
pub(crate) const DOWNLOAD_FAILED: &str = "download_failed";
/// `errorCode` of a fetched patch with no file it could record.
pub(crate) const PATCH_NO_APPLICABLE_FILES: &str = "patch_no_applicable_files";
/// `errorCode` of a patch whose blob content could not be decoded or
/// written.
pub(crate) const BLOB_WRITE_FAILED: &str = "blob_write_failed";
/// `errorCode` of the `skipped` event for a selected patch the manifest
/// already records at the same uuid (agent mode still re-applies it).
pub(crate) const ALREADY_IN_MANIFEST: &str = "already_in_manifest";

/// The vendored-mode preflight verdicts the download phase refuses by
/// (Bun's project-level one, vlt's per purl); agent downloads pass none.
#[derive(Clone, Copy, Default)]
pub(crate) struct VendorRefusals<'a> {
    pub(crate) bun: Option<&'a BunVendorRefusal>,
    pub(crate) vlt: &'a [(String, VltVendorRefusal)],
}

impl VendorRefusals<'_> {
    fn for_purl(&self, purl: &str) -> Option<(&'static str, &str)> {
        self.bun
            .filter(|r| r.applies_to(purl))
            .map(|r| (r.code, r.detail.as_str()))
            .or_else(|| vlt_refusal_for(self.vlt, purl).map(|r| (r.code, r.detail.as_str())))
    }
}

/// Selected purls the vendor backend will refuse on the project's lock
/// text alone, with the backend's `(code, detail)`.
pub(crate) type LockRefusals = HashMap<String, (&'static str, String)>;

/// The lock-text refusals of the vendored download phase (see
/// [`socket_patch_core::vendor::lock_text_refusals`]: the pnpm / yarn
/// classic / yarn berry gates and cargo's locked-version gate), over the
/// patches the phase would otherwise fetch a view for — past the Bun
/// refusal and the ledger's idempotency skip, which take precedence in the
/// fetch loop. A purl the lockfiles pin hosted is left to the vendor loop:
/// its takeover restores the upstream lock entry first, and the restore
/// rewrites the very text the gates read. The one exception is a hosted
/// gem the takeover would refuse ([`gem_takeover_refusals_for`]), which
/// is refused here with the takeover's code instead of after its fetch.
///
/// [`gem_takeover_refusals_for`]: crate::commands::vendor::gem_takeover_refusals_for
///
/// Only a package the vendor loop would hand to its backend is refused
/// here (see [`crate::commands::vendor::lock_refusals_reaching_backend`]):
/// one installed on disk, or one the lockfile resolves to a verifiable
/// registry source. A package with neither — absent from the lock and not
/// installed — never reaches its backend: the loop reports it `skipped` /
/// `package_not_installed`, and so it still does. `prior` is scan's npm
/// crawl, when the caller has it (the installed-copy lookup reuses it).
pub(crate) async fn lock_text_refusals_for(
    params: &DownloadParams,
    selected: &[PatchSearchResult],
    ledger: &VendorState,
    bun_refusal: Option<&BunVendorRefusal>,
    prior: Option<&crate::ecosystem_dispatch::NpmCrawlSnapshot>,
) -> LockRefusals {
    let cwd = params.cwd.as_path();
    let origins =
        crate::commands::hosted_unwind::patch_server_origins_of(params.patch_server_url.as_deref());
    let pins = hosted_pins(cwd, origins.clone()).await;
    let claimed = claimed_purls(&pins);
    let fetchable: Vec<&PatchSearchResult> = selected
        .iter()
        .filter(|sr| bun_refusal.filter(|r| r.applies_to(&sr.purl)).is_none())
        .filter(|sr| {
            detached_ledger_record(RecordStore::Ledger(&ledger.entries), &sr.purl, &sr.uuid)
                .is_none()
        })
        .collect();
    let candidates: Vec<(&str, &str)> = fetchable
        .iter()
        .filter(|sr| !claimed.contains(&PurlKey::new(&sr.purl)))
        .map(|sr| (sr.purl.as_str(), sr.uuid.as_str()))
        .collect();
    let refused = socket_patch_core::vendor::lock_text_refusals(cwd, &candidates).await;
    let options = params.crawler_options();
    let mut refusals =
        crate::commands::vendor::lock_refusals_reaching_backend(
            cwd,
            refused,
            &ledger.entries,
            |purls| async move {
                crate::commands::vendor::installed_purls(&options, &purls, prior).await
            },
        )
        .await;
    // A hosted gem the takeover will refuse (#775) is refused here too, so
    // its view is never fetched for a package the run cannot vendor. The
    // download phase only runs online (`--offline` refuses `get` and `scan`
    // before it), so the dry-run restore may resolve the registry entry.
    refusals.extend(
        crate::commands::vendor::gem_takeover_refusals_for(
            cwd,
            fetchable
                .iter()
                .filter(|sr| claimed.contains(&PurlKey::new(&sr.purl)))
                .map(|sr| sr.purl.as_str()),
            &pins,
            false,
            origins,
        )
        .await,
    );
    refusals
}

/// The purl keys the project's lockfiles pin hosted (a patch-server
/// tarball, Socket's own or one of `origins`): the purls whose vendored
/// run is a hosted → vendored takeover.
/// The fetch-phase gate ([`lock_text_refusals_for`]) and the scan preview
/// (`scan/vendor_flow.rs`) both read the takeovers through here, so the dry
/// run and the wet run agree on which purls they are.
pub(crate) async fn hosted_claimed_purls(
    cwd: &Path,
    origins: Vec<String>,
) -> std::collections::HashSet<PurlKey> {
    claimed_purls(&hosted_pins(cwd, origins).await)
}

/// The project's hosted pins (see [`hosted_claimed_purls`]).
async fn hosted_pins(
    cwd: &Path,
    origins: Vec<String>,
) -> Vec<socket_patch_core::patch::redirect::upstream::HostedPin> {
    socket_patch_core::patch::redirect::upstream::HostedPin::all(
        &socket_patch_core::vex::discover_patched_refs_with(
            cwd,
            &socket_patch_core::vex::DiscoverOptions {
                patch_server_origins: origins,
            },
        )
        .await,
    )
}

/// The purl keys of `pins`.
fn claimed_purls(
    pins: &[socket_patch_core::patch::redirect::upstream::HostedPin],
) -> std::collections::HashSet<PurlKey> {
    pins.iter().map(|pin| PurlKey::new(&pin.purl)).collect()
}

/// The record a detached ledger entry already carries for `purl` at
/// exactly `uuid` — the ledger store's idempotency skip (no view fetch).
/// Always `None` for the manifest store.
pub(crate) fn detached_ledger_record<'a>(
    store: RecordStore<'a>,
    purl: &str,
    uuid: &str,
) -> Option<&'a PatchRecord> {
    let RecordStore::Ledger(entries) = store else {
        return None;
    };
    lookup_entry(entries, purl)
        .filter(|e| e.detached && e.uuid == uuid)
        .and_then(|e| e.record.as_ref())
}

/// The fetch loop both download engines share: installed-release
/// narrowing, the caller's Bun and vlt refusals, the per-store skip
/// decision, the view fetch (served from `prefetched` when the narrowing or
/// the caller already holds the view), the no-applicable-files guardrail,
/// optional blob persistence, and every per-patch failure record. Every
/// pinned stderr line and JSON action lives here once.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn fetch_selected_patches(
    selected: &[PatchSearchResult],
    params: &DownloadParams,
    api_client: &ApiClient,
    store: RecordStore<'_>,
    blobs_dir: Option<&Path>,
    refusals: VendorRefusals<'_>,
    lock_refusals: &LockRefusals,
    mut prefetched: HashMap<String, PatchResponse>,
) -> FetchBatch {
    let quiet = params.quiet();
    // Narrow multi-release selections to the installed distribution unless
    // --all-releases was passed (a no-op for non-variant ecosystems and
    // single-variant packages). The views it fetched serve the loop below.
    // The narrowing queries the API: show that something is happening
    // once selection (and get's confirm prompt) is done.
    let mut status = crate::ui::StatusLine::stderr(params.json, params.silent);
    status.set("Preparing download...");
    let (selected, warnings, views) = filter_to_installed_releases(
        selected,
        params.all_releases,
        &params.crawler_options(),
        quiet,
        api_client,
    )
    .await;
    status.finish();
    prefetched.extend(views);
    // No leading blank line: the caller's prompt or summary already ended
    // its line.
    if matches!(store, RecordStore::Manifest(_)) && !quiet {
        eprintln!(
            "Downloading {}...",
            crate::ui::plural(selected.len(), "patch", "patches")
        );
    }

    let mut batch = FetchBatch {
        skipped: 0,
        already_recorded: 0,
        failed: 0,
        fetched: Vec::new(),
        reused: Vec::new(),
        events: Vec::new(),
        warnings,
        mode: match store {
            RecordStore::Ledger(_) => Some("vendored"),
            RecordStore::Manifest(_) => None,
        },
    };

    // The view GETs the loop below makes — every patch past the refusal
    // and the ledger skip whose view is not already held in `prefetched`
    // (the same three checks, in the loop's order, over inputs the loop
    // never mutates) — run concurrently ahead of it, at most
    // `api_concurrency` in flight, and come back in selection order. The
    // loop takes the next one where it would await the request, and each
    // request's `--debug` lines print there too, so stdout, the per-patch
    // stderr lines and the JSON records fold in selection order.
    let mut held: std::collections::HashSet<&str> = prefetched.keys().map(String::as_str).collect();
    let to_fetch: Vec<&str> = selected
        .iter()
        .filter(|sr| {
            refusals.for_purl(&sr.purl).is_none()
                && detached_ledger_record(store, &sr.purl, &sr.uuid).is_none()
                && !lock_refusals.contains_key(&sr.purl)
                && !held.remove(sr.uuid.as_str())
        })
        .map(|sr| sr.uuid.as_str())
        .collect();
    let window_len = to_fetch.len();
    let mut views = std::pin::pin!(ordered_concurrent(
        to_fetch,
        api_concurrency_for(api_client.uses_public_proxy(), window_len),
        |uuid| async move { (uuid, hold_back_debug(api_client.fetch_patch(uuid)).await) },
    ));

    for search_result in &selected {
        let (purl, uuid) = (search_result.purl.as_str(), search_result.uuid.as_str());

        // Refusal FIRST (the dry-run preview's precedence): a preserved
        // ledger can name this exact uuid after `rollback --preserve-state`
        // unwired it, so UUID equality alone never exempts a purl — the
        // lock-derived exemption inside `applies_to` decides. Code-tagged so
        // a `--silent` operator can grep the stable code.
        if let Some((code, detail)) = refusals.for_purl(purl) {
            batch.fail(
                params.json,
                Some(format!("[error] {purl} ({code}): {detail}")),
                (purl, uuid),
                code,
                detail,
            );
            continue;
        }

        // Idempotency (ledger store): a detached entry already at this uuid
        // carries its own record — no view fetch needed.
        if let Some(record) = detached_ledger_record(store, purl, uuid).cloned() {
            if !quiet {
                eprintln!("{}", format_record_skip(purl, "already vendored"));
            }
            // No event: the reused record goes to the vendor engine, whose
            // own event (`already_vendored`, `rebuilt`, …) is the package's
            // account.
            batch.reused.push((purl.to_string(), record));
            batch.skipped += 1;
            continue;
        }

        // Lock-text refusal (see `lock_text_refusals_for`): the vendor
        // backend refuses this package on the project's lock alone, so its
        // view is never fetched (nor, downstream, its pristine source) —
        // reported with the backend's code and words, as the Bun refusal is.
        if let Some((code, detail)) = lock_refusals.get(purl) {
            batch.fail(
                params.json,
                Some(format!("[error] {purl} ({code}): {detail}")),
                (purl, uuid),
                code,
                detail,
            );
            continue;
        }

        // The view: from memory when the narrowing (or the uuid path's own
        // identifier fetch) already fetched it, else the network — the next
        // of the concurrent GETs above, which were planned for exactly
        // these turns.
        let view = match prefetched.remove(uuid) {
            Some(patch) => Ok(Some(patch)),
            None => match views.next().await {
                Some((planned, view)) if planned == uuid => view.release(),
                // Unreachable (the plan mirrors this loop's checks); a
                // live fetch keeps the outcome right regardless.
                _ => {
                    debug_assert!(
                        false,
                        "view prefetch plan out of step with the download loop"
                    );
                    api_client.fetch_patch(uuid).await
                }
            },
        };
        let patch = match view {
            Ok(Some(patch)) => patch,
            Ok(None) => {
                batch.fail(
                    params.json,
                    Some(format!("[fail] {purl} (could not fetch details)")),
                    (purl, uuid),
                    DOWNLOAD_FAILED,
                    "could not fetch details",
                );
                continue;
            }
            Err(e) => {
                batch.fail(
                    params.json,
                    Some(format!("[fail] {purl} ({e})")),
                    (purl, uuid),
                    DOWNLOAD_FAILED,
                    &e.to_string(),
                );
                continue;
            }
        };

        // Classify against the store BEFORE anything is written. `Skipped`
        // early-continues; `Updated` is preserved so the per-patch record
        // can carry `oldUuid`.
        let action = match store {
            RecordStore::Manifest(manifest) => {
                decide_patch_action(manifest, &patch.purl, &patch.uuid)
            }
            RecordStore::Ledger(entries) => match lookup_entry(entries, &patch.purl) {
                Some(entry) if entry.uuid != patch.uuid => PatchAction::Updated {
                    old_uuid: entry.uuid.clone(),
                },
                _ => PatchAction::Added,
            },
        };
        if action == PatchAction::Skipped {
            if !quiet {
                eprintln!("{}", format_record_skip(&patch.purl, "already in manifest"));
            }
            batch.events.push(
                PatchEvent::new(EventAction::Skipped, patch.purl.as_str())
                    .with_uuid(patch.uuid.as_str())
                    .with_reason(ALREADY_IN_MANIFEST, "already in manifest"),
            );
            batch.skipped += 1;
            batch.already_recorded += 1;
            continue;
        }

        // Record every file the patch touches, added files included
        // (empty-beforeHash sentinel); see `files_for_manifest`.
        let files = files_for_manifest(&patch);
        // GUARDRAIL: a patch that yields NO recordable files cannot be
        // applied or vendored — recording an empty `files` map and then
        // reporting it protected would claim protection while writing
        // nothing. Count it as a failure so the status/exit code degrade.
        if files.is_empty() {
            batch.fail(
                params.json,
                Some(format!(
                    "[fail] {} (patch has no applicable files)",
                    patch.purl
                )),
                (&patch.purl, &patch.uuid),
                PATCH_NO_APPLICABLE_FILES,
                "patch has no applicable files",
            );
            continue;
        }
        // Blob failures are errors: only JSON mode suppresses the per-file
        // detail line (the envelope carries the error). Vendor flows pass no
        // blobs dir — their content stays in memory for the vendor step.
        let mut new_blobs = Vec::new();
        if let Some(blobs_dir) = blobs_dir {
            match write_all_patch_blobs(blobs_dir, &patch, params.json).await {
                Ok(created) => new_blobs = created,
                Err(()) => {
                    batch.fail(
                        params.json,
                        None,
                        (&patch.purl, &patch.uuid),
                        BLOB_WRITE_FAILED,
                        "Blob decode or write failed",
                    );
                    continue;
                }
            }
        }

        let tag = match (store, &action) {
            (RecordStore::Ledger(_), _) => "fetch",
            (RecordStore::Manifest(_), PatchAction::Updated { .. }) => "update",
            (RecordStore::Manifest(_), _) => "add",
        };
        // Description / severity / vulnerability IDs ride `details` so
        // PR-comment bots, dashboards, and CLI consumers can render the
        // patch without a second round-trip to the API.
        let mut details = patch_event_metadata(&patch);
        let mut event = match (store, &action) {
            // A manifest replacement is the envelope's `updated` (+ oldUuid).
            (RecordStore::Manifest(_), PatchAction::Updated { old_uuid }) => {
                PatchEvent::new(EventAction::Updated, patch.purl.as_str()).with_old_uuid(old_uuid)
            }
            // The vendor ledger tracks patch generations, not the download:
            // a fetched replacement is still `downloaded`, naming the uuid
            // it will replace in `details.oldUuid`.
            (RecordStore::Ledger(_), PatchAction::Updated { old_uuid }) => {
                details["oldUuid"] = serde_json::json!(old_uuid);
                PatchEvent::new(EventAction::Downloaded, patch.purl.as_str())
            }
            _ => PatchEvent::new(EventAction::Downloaded, patch.purl.as_str()),
        };
        if let PatchAction::Updated { old_uuid } = &action {
            if !quiet {
                // Defensive: a malformed/short UUID in the store must not
                // panic the loop — `short_uuid` never does.
                eprintln!(
                    "  [{tag}] {} (replacing {})",
                    normalize_purl(&patch.purl),
                    crate::ui::short_uuid(old_uuid)
                );
            }
        } else if !quiet {
            eprintln!("  [{tag}] {}", normalize_purl(&patch.purl));
        }
        event = event.with_uuid(patch.uuid.as_str()).with_details(details);
        batch.events.push(tag_mode(event, batch.mode));
        batch.fetched.push(FetchedPatch {
            patch,
            files,
            action,
            new_blobs,
        });
    }
    batch
}

/// What the detached (vendored) download phase produced: its exit code
/// (1 when a patch failed or was refused), the per-patch events (each
/// `details.mode: "vendored"`) and run-level warnings for the caller's
/// envelope, how many patches failed, and the records the vendor step
/// consumes.
pub(crate) struct DetachedDownload {
    pub(crate) code: i32,
    pub(crate) events: Vec<PatchEvent>,
    pub(crate) warnings: Vec<RunWarning>,
    pub(crate) failed: usize,
    pub(crate) records: HashMap<String, PatchRecord>,
}

impl DetachedDownload {
    /// Fold the phase's events and warnings into `env` (records via
    /// [`Envelope::record`], so `summary` and `status` follow) and hand back
    /// the exit code and the records.
    pub(crate) fn into_envelope(
        self,
        env: &mut Envelope,
    ) -> (i32, usize, HashMap<String, PatchRecord>) {
        for event in self.events {
            env.record(event);
        }
        env.warnings.extend(self.warnings);
        (self.code, self.failed, self.records)
    }
}

/// The release-narrowing fallbacks as run-level warnings.
fn release_warnings(warnings: Vec<String>) -> Vec<RunWarning> {
    warnings
        .into_iter()
        .map(|w| RunWarning::new(RELEASE_NARROWING, w))
        .collect()
}

/// Warning code: release narrowing kept every variant of a base (the base
/// is not installed, or no variant matches the installed distribution).
pub(crate) const RELEASE_NARROWING: &str = "release_narrowing";

/// [`download_patch_records_with`], handing `prior` (scan's npm crawl of
/// the untouched tree) to the lock-text refusals' installed-copy lookup.
pub(crate) async fn download_patch_records_reusing(
    selected: &[PatchSearchResult],
    params: &DownloadParams,
    api_client: &ApiClient,
    prefetched: HashMap<String, PatchResponse>,
    prior: Option<&crate::ecosystem_dispatch::NpmCrawlSnapshot>,
) -> DetachedDownload {
    // The ledger load outcome is handed to the preflight AS a result: an
    // unreadable ledger must surface as `vendor_state_unreadable` from the
    // one refusal this phase emits (fail closed, nothing exempt), not be
    // flattened into an empty ledger that then reports a Bun lock remedy.
    // For the classification below it degrades to empty (no detached entry
    // to reuse — the vendor step reports the corruption itself).
    let vendor_state = load_state(&params.cwd).await;
    // Bun preflight (see `BunVendorRefusal`): this phase feeds the vendor
    // engine, so it must refuse the same projects BEFORE fetching —
    // otherwise the view is downloaded for nothing and a package
    // resolvable only through the unreadable bun.lockb inventory is
    // misreported as `package_not_installed` instead of the real
    // `vendor_bun_*` code. npm-only, so release narrowing (PyPI / RubyGems /
    // Maven variants) cannot change its verdict.
    let bun_refusal = bun_vendor_preflight_with_ledger(
        &params.cwd,
        selected,
        vendor_state.as_ref().map(|s| &s.entries),
    )
    .await;
    // The vlt twin: every lock-, manifest- and ledger-decidable vlt refusal
    // (see `crate::commands::vlt_preflight`), per purl.
    let vlt_refusals = vlt_vendor_preflight_selected(
        &params.cwd,
        selected,
        vendor_state.as_ref().map(|s| &s.entries),
    )
    .await;
    download_patch_records_preflighted(
        selected,
        params,
        api_client,
        prefetched,
        vendor_state,
        VendorRefusals {
            bun: bun_refusal.as_ref(),
            vlt: &vlt_refusals,
        },
        prior,
    )
    .await
}

/// [`download_patch_records_with`] after its two reads: the caller's own
/// ledger load and Bun preflight outcome. The `get <uuid>` path runs the
/// preflight itself (it owns the pre-record refusal shape) and hands the
/// UNFILTERED outcome down, so the lock is read once per run and the
/// refused-but-exempt case still reaches the per-purl `applies_to` gate.
pub(crate) async fn download_patch_records_preflighted(
    selected: &[PatchSearchResult],
    params: &DownloadParams,
    api_client: &ApiClient,
    prefetched: HashMap<String, PatchResponse>,
    vendor_state: std::io::Result<VendorState>,
    refusals: VendorRefusals<'_>,
    prior: Option<&crate::ecosystem_dispatch::NpmCrawlSnapshot>,
) -> DetachedDownload {
    let vendor_state = vendor_state.unwrap_or_default();
    let lock_refusals =
        lock_text_refusals_for(params, selected, &vendor_state, refusals.bun, prior).await;

    let blobs_dir = params.socket_dir().join("blobs");
    let batch = fetch_selected_patches(
        selected,
        params,
        api_client,
        RecordStore::Ledger(&vendor_state.entries),
        params.persist_blobs.then_some(blobs_dir.as_path()),
        refusals,
        &lock_refusals,
        prefetched,
    )
    .await;

    let mut records: HashMap<String, PatchRecord> = batch.reused.into_iter().collect();
    for FetchedPatch { patch, files, .. } in batch.fetched {
        records.insert(patch.purl.clone(), build_patch_record(&patch, files));
    }
    DetachedDownload {
        code: i32::from(batch.failed > 0),
        events: batch.events,
        warnings: release_warnings(batch.warnings),
        failed: batch.failed,
        records,
    }
}

/// Warning code: the manifest now records a patch uuid the vendor ledger
/// does not wire for that purl (see [`warn_on_vendored_uuid_drift`]).
pub(crate) const VENDORED_UUID_DRIFT: &str = "vendored_uuid_drift";

/// Emit a warning (stderr `[note]` + `warnings[]`) for every recorded
/// (`downloaded` / `updated`) `(purl, uuid)` whose purl the vendor ledger
/// still wires at a DIFFERENT uuid — VEX verification fails closed
/// (`vendor_uuid_mismatch`) until a `vendor` run refreshes the committed
/// artifact.
///
/// Kept out of [`download_and_apply_patches_with`]'s body on purpose: that
/// function sits on the in-process scan→download→apply chain, whose summed
/// poll frames must fit Windows' 1 MiB main-thread stack in debug builds.
pub(crate) async fn warn_on_vendored_uuid_drift(
    cwd: &Path,
    quiet: bool,
    recorded: &[(String, String)],
    warnings: &mut Vec<RunWarning>,
) {
    let Ok(vendor_state) = load_state(cwd).await else {
        return;
    };
    if vendor_state.entries.is_empty() {
        return;
    }
    for (purl, uuid) in recorded {
        let entry = lookup_entry(&vendor_state.entries, purl);
        if let Some(entry) = entry.filter(|e| &e.uuid != uuid) {
            let w = format!(
                "{purl} is vendored at patch {} but the manifest now records {uuid}; \
                 run `socket-patch vendor` to refresh the committed artifact",
                entry.uuid
            );
            if !quiet {
                eprintln!("  [note] {w}");
            }
            warnings.push(RunWarning::new(VENDORED_UUID_DRIFT, w));
        }
    }
}

/// The `GlobalArgs` a nested apply runs with: the caller's flags verbatim
/// (`--verbose`, `--strict`, `--ecosystems` … all flow
/// through; the API flags ride along but are inert — the nested apply runs
/// on the caller's client), with the fields `get` owns overridden: the
/// already-resolved manifest path (apply re-resolves a
/// relative path against ITS `--cwd`, which double-joins ours — absolutize
/// so it passes through verbatim), `silent` = quiet and `json: false` (the
/// nested apply must never print a second JSON document), and `dry_run:
/// false` — agent-mode `get` ignores `--dry-run` by contract, and the
/// manifest + blobs it just wrote for real must be applied for real too.
pub(crate) fn nested_apply_args(
    common: &GlobalArgs,
    manifest_path: &Path,
    quiet: bool,
) -> GlobalArgs {
    let manifest_path =
        std::path::absolute(manifest_path).unwrap_or_else(|_| manifest_path.to_path_buf());
    GlobalArgs {
        manifest_path: manifest_path.display().to_string(),
        silent: quiet,
        json: false,
        dry_run: false,
        ..common.clone()
    }
}

/// The caller flags a `DownloadParams` + [`DownloadRun`] pair reconstructs
/// for the nested apply (the engine never sees a `GlobalArgs`). No API
/// fields: the nested apply runs on the run's client (`run.api_client`),
/// which was built from the caller's flags.
pub(crate) fn nested_apply_args_from_params(
    params: &DownloadParams,
    run: &DownloadRun<'_>,
    manifest_path: &Path,
) -> GlobalArgs {
    let common = GlobalArgs {
        cwd: params.cwd.clone(),
        global: params.global,
        global_prefix: params.global_prefix.clone(),
        strict: params.strict,
        // Scope the nested apply like the caller was scoped: `None` would
        // apply the WHOLE manifest, mutating other ecosystems' packages the
        // user filtered out.
        ecosystems: params.ecosystems.clone(),
        lock_timeout: run.lock_timeout,
        verbose: run.verbose,
        ..GlobalArgs::default()
    };
    nested_apply_args(&common, manifest_path, params.quiet())
}

/// Run the nested `apply` step with `common` (see [`nested_apply_args`])
/// on the caller's `client`, under the apply `lock` the caller took for
/// its manifest write — one lock window for download → manifest write →
/// apply (a same-process re-acquire would contend), released by apply once
/// its last mutation is done. Returns apply's report: its exit code and
/// what failed, for the caller's envelope (see [`fold_apply_failures`]).
/// Callers print their own "Applying patches..." line. `json` is the
/// caller's flag: a JSON caller gets no human error lines, from this
/// function or from the nested apply (`common` itself is never JSON). The
/// read-only `--check` redirect verifier stays off and embedded VEX is
/// opt-in on the top-level command only, never on this internal
/// invocation.
pub(crate) async fn run_nested_apply(
    common: GlobalArgs,
    json: bool,
    client: &ApiClient,
    lock: LockGuard,
) -> ApplyRunReport {
    let manifest_path = common.resolved_manifest_path();
    let apply_args = super::apply::ApplyArgs {
        common,
        force: false,
        check: false,
        vex: Default::default(),
        nested: Some(super::apply::NestedApply { caller_json: json }),
    };
    let report = super::apply::run_locked(apply_args, manifest_path, client, lock).await;
    // An error, so exempt from --silent ("errors only": a failing exit must
    // say why); JSON runs carry the failure in the envelope instead.
    if report.code != 0 && !json {
        eprintln!("{APPLY_FAILED}");
    }
    report
}

/// Whether apply's package key `key` covers the patch record purl
/// `record`: the same purl, or `key` is the unqualified base of a
/// qualified record (apply keys a release-variant base by its base purl).
/// A qualified key never covers a sibling variant.
pub(crate) fn apply_key_covers(key: &str, record: &str) -> bool {
    PurlKey::qualified(key) == PurlKey::qualified(record)
        || (!key.trim().contains(['?', '#']) && PurlKey::same(key, record))
}

/// Record what the nested apply did to the run's recorded patches
/// (`recorded`: `(purl, uuid)` of every selected patch now in the manifest)
/// into `env`, so `--json` says what the human run prints (#424). A clean
/// apply is one `applied` event per recorded patch. A failed one records a
/// `failed` event (apply's `errorCode` / `error`) for each recorded patch a
/// failure covers, `applied` for each one apply reports patched (or already
/// patched), a `failed` event for each other failing manifest patch (one
/// this run did not select — the nested apply covers the whole
/// `--ecosystems`-scoped manifest; `uuid_of` looks up its uuid), and a
/// purl-less `failed` event for a run-level reason (unreadable manifest,
/// the yarn PnP refusal, unavailable sources) — so a failed apply always
/// leaves a `failed` event and the envelope's `partialFailure` agrees with
/// exit 1. The apply's non-fatal warnings (`content_mismatch_overwritten`,
/// #1004) join `env.warnings`: a JSON caller's nested apply is silent, so
/// the envelope is their only channel. `None` (no apply ran) records
/// nothing.
pub(crate) fn record_apply_outcome(
    env: &mut Envelope,
    recorded: &[(String, String)],
    report: Option<&ApplyRunReport>,
    uuid_of: impl Fn(&str) -> Option<String>,
) {
    let Some(report) = report else {
        return;
    };
    env.warnings.extend(report.warnings.iter().cloned());
    if report.code == 0 {
        for (purl, uuid) in recorded {
            env.record(
                PatchEvent::new(EventAction::Applied, purl.as_str()).with_uuid(uuid.as_str()),
            );
        }
        return;
    }
    let mut failed_any = false;
    for (purl, uuid) in recorded {
        if let Some(failure) = report
            .failures
            .iter()
            .find(|f| apply_key_covers(&f.purl, purl))
        {
            env.record(
                PatchEvent::new(EventAction::Failed, purl.as_str())
                    .with_uuid(uuid.as_str())
                    .with_error(failure.code.as_str(), failure.error.as_str()),
            );
            failed_any = true;
        } else if report.applied.iter().any(|k| apply_key_covers(k, purl)) {
            env.record(
                PatchEvent::new(EventAction::Applied, purl.as_str()).with_uuid(uuid.as_str()),
            );
        }
    }
    let mut appended: Vec<&str> = Vec::new();
    for failure in &report.failures {
        let explained = recorded
            .iter()
            .any(|(purl, _)| apply_key_covers(&failure.purl, purl));
        let repeated = appended
            .iter()
            .any(|p| PurlKey::qualified(p) == PurlKey::qualified(&failure.purl));
        if explained || repeated {
            continue;
        }
        appended.push(&failure.purl);
        let mut event = PatchEvent::new(EventAction::Failed, failure.purl.as_str())
            .with_error(failure.code.as_str(), failure.error.as_str());
        if let Some(uuid) = uuid_of(&failure.purl) {
            event = event.with_uuid(uuid);
        }
        env.record(event);
        failed_any = true;
    }
    if let Some((code, error)) = &report.run_error {
        env.record(
            PatchEvent::artifact(EventAction::Failed).with_error(code.as_str(), error.as_str()),
        );
        failed_any = true;
    }
    if !failed_any {
        env.record(
            PatchEvent::artifact(EventAction::Failed)
                .with_error("apply_failed", "the nested apply failed"),
        );
    }
}

/// [`download_and_apply_patches_into`] over a fresh `get` envelope: the
/// public entry the in-process tests and embedders drive. Returns `(exit
/// code, envelope)`; nothing is printed on stdout.
pub async fn download_and_apply_patches_with(
    selected: &[PatchSearchResult],
    params: &DownloadParams,
    run: &DownloadRun<'_>,
) -> (i32, Envelope) {
    let mut env = Envelope::new(EnvelopeCommand::Get);
    let code = download_and_apply_patches_into(selected, params, run, &mut env).await;
    (code, env)
}

/// Download the selected patches into `.socket/` (manifest records +
/// blobs) and, unless `save_only`, apply them in place — the agent-mode
/// engine behind `get` and `scan --mode agent`, over the caller's
/// run-level context (`run`: the client the run already built, plus the
/// `--lock-timeout` / `--verbose` the manifest lock and the nested apply
/// honor). Every outcome is recorded into `env` (per-patch events, run
/// warnings, or — for a hard failure: the lock refused, an unloadable
/// manifest, a failed manifest write — its top-level `error`); the CALLER
/// prints it, so a run never puts two JSON documents on stdout. Returns
/// the exit code.
pub async fn download_and_apply_patches_into(
    selected: &[PatchSearchResult],
    params: &DownloadParams,
    run: &DownloadRun<'_>,
    env: &mut Envelope,
) -> i32 {
    let quiet = params.quiet();
    let manifest_path = params.manifest_path.clone();
    let socket_dir = params.socket_dir();
    let lock_timeout = Duration::from_secs(run.lock_timeout.unwrap_or(0));

    // The manifest read-modify-write — and the blob writes it records —
    // runs under the apply lock: `remove`/`rollback` RMW the same file under
    // it, and an unlocked writer here would lose their update or have its
    // own record clobbered. `acquire` creates `.socket/` itself; the guard's
    // drop removes `apply.lock` and prunes an otherwise-empty `.socket/`, so
    // a run that records nothing leaves no residue. The nested apply runs
    // under this SAME guard (one lock window; see `run_nested_apply`).
    let guard = match crate::commands::lock_cli::acquire_with_status(&socket_dir, lock_timeout) {
        Ok(guard) => guard,
        Err(e) => {
            env.mark_error(report_lock_failure(
                params.json,
                &socket_dir,
                &e,
                lock_timeout,
            ));
            return 1;
        }
    };

    let mut manifest = match read_manifest(&manifest_path).await {
        Ok(Some(m)) => m,
        Ok(None) => PatchManifest::new(),
        // Fail closed on a manifest that exists but can't be read/parsed:
        // treating it as empty would let the write below replace the file
        // and destroy every tracked patch record.
        Err(e) => {
            if !params.json {
                eprintln!("Error: Failed to read manifest: {e}");
            }
            env.mark_error(crate::json_envelope::manifest_load_error(
                &manifest_path,
                &e,
            ));
            return 1;
        }
    };

    // No Bun preflight here: this is the agent (manifest) engine, and
    // agent/save-only flows keep their record-only intent. The vendored
    // download phase (`download_patch_records_with`) runs its own.
    let blobs_dir = socket_dir.join("blobs");
    let batch = fetch_selected_patches(
        selected,
        params,
        run.api_client,
        RecordStore::Manifest(&manifest),
        params.persist_blobs.then_some(blobs_dir.as_path()),
        VendorRefusals::default(),
        &HashMap::new(),
        HashMap::new(),
    )
    .await;

    // `added` and `updated` are DISJOINT — one patch lands in exactly one,
    // matching the per-patch event (`downloaded` / `updated`) and the
    // single-uuid flow's summary in `save_and_apply_patch`; their sum gates
    // the apply step.
    let downloaded = batch.fetched.len();
    let mut updated = 0usize;
    let mut new_blobs: Vec<String> = Vec::new();
    // `(purl, uuid)` of every selected patch now recorded: the fetched ones
    // and the already-recorded (`skipped`) ones.
    let mut recorded: Vec<(String, String)> = Vec::new();
    let mut changed: Vec<(String, String)> = Vec::new();
    for event in &batch.events {
        if event.action == EventAction::Skipped
            && event.error_code.as_deref() == Some(ALREADY_IN_MANIFEST)
        {
            if let (Some(purl), Some(uuid)) = (&event.purl, &event.uuid) {
                recorded.push((purl.clone(), uuid.clone()));
            }
        }
    }
    for FetchedPatch {
        patch,
        files,
        action,
        new_blobs: created,
    } in batch.fetched
    {
        if matches!(action, PatchAction::Updated { .. }) {
            updated += 1;
        }
        new_blobs.extend(created);
        changed.push((patch.purl.clone(), patch.uuid.clone()));
        manifest
            .patches
            .insert(patch.purl.clone(), build_patch_record(&patch, files));
    }
    let added = downloaded - updated;
    // Write only when a record changed: an all-skipped or all-failed run
    // leaves the manifest bytes (and a fresh project's tree) untouched.
    if downloaded > 0 {
        if let Err(e) = write_manifest(&manifest_path, &manifest).await {
            // The blobs this run just wrote have no record pointing at them:
            // unwind exactly those (a pre-existing record's blobs stay).
            unwind_new_blobs(&blobs_dir, &new_blobs).await;
            let msg = format!("Failed to write manifest: {e}");
            if !params.json {
                eprintln!("Error: {msg}");
            }
            env.mark_error(EnvelopeError::new("manifest_write_failed", msg));
            return 1;
        }
    }
    for event in batch.events {
        env.record(event);
    }
    recorded.extend(changed.iter().cloned());
    // Every selected patch that is now recorded is owed the nested apply:
    // the fetched ones AND the already-recorded (`skipped`) ones, whose
    // installed copy may be pristine again after a reinstall or a failed
    // earlier apply (#454). Apply is idempotent on already-patched files,
    // so an in-sync re-run stays a no-op on disk.
    let to_apply = recorded.len();
    // The lock outlives the manifest write only when a nested apply follows
    // (it is handed the guard and releases it after its last mutation);
    // otherwise nothing more is written and it is released here.
    let apply_lock = if !params.save_only && to_apply > 0 {
        Some(guard)
    } else {
        drop(guard);
        None
    };

    // Vendored-uuid drift: an explicit `get` is allowed to move the
    // manifest past the patch uuid the vendor ledger still wires (the user
    // asked for that patch by name). Verification then fails closed
    // (`vendor_uuid_mismatch`) until a `vendor` run re-vendors at the new
    // uuid — tell the operator now instead of letting VEX surprise them
    // later. (`scan` never hits this: it filters vendored purls before
    // download.) The nested apply below skips the vendored purl either way.
    let mut warnings = release_warnings(batch.warnings);
    warn_on_vendored_uuid_drift(&params.cwd, quiet, &changed, &mut warnings).await;
    env.warnings.extend(warnings);

    if !quiet {
        eprintln!();
        eprintln!(
            "{}",
            format_save_summary(&manifest_path, added, updated, batch.skipped, batch.failed)
        );
    }

    // Auto-apply unless --save-only (the lock decision above).
    let mut apply_report: Option<ApplyRunReport> = None;
    if let Some(lock) = apply_lock {
        if !quiet {
            eprintln!();
            eprintln!("Applying patches...");
        }
        apply_report = Some(
            run_nested_apply(
                nested_apply_args_from_params(params, run, &manifest_path),
                params.json,
                run.api_client,
                lock,
            )
            .await,
        );
    }
    let apply_failed = apply_report.as_ref().is_some_and(|r| r.code != 0);
    // A failed apply records at least one `failed` event, so the status
    // (`partialFailure`) agrees with the exit code.
    record_apply_outcome(env, &recorded, apply_report.as_ref(), |purl| {
        manifest.patches.get(purl).map(|r| r.uuid.clone())
    });
    run_outcome(batch.failed > 0, apply_failed)
}

/// Decode a patch view's `blobContent` (canonical base64 as the API
/// produces it; line breaks and missing padding are tolerated). An invalid
/// byte keeps the `Invalid base64 character: <b>` message (pinned by a
/// unit test).
pub(crate) fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    use base64::engine::{general_purpose, DecodePaddingMode, GeneralPurpose};
    use base64::Engine;
    const ENGINE: GeneralPurpose = GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        general_purpose::PAD.with_decode_padding_mode(DecodePaddingMode::Indifferent),
    );
    let compact: String = input
        .chars()
        .filter(|c| !matches!(c, '\n' | '\r'))
        .collect();
    ENGINE.decode(compact).map_err(|e| match e {
        base64::DecodeError::InvalidByte(_, b) => {
            format!("Invalid base64 character: {}", b as char)
        }
        other => format!("Invalid base64: {other}"),
    })
}
