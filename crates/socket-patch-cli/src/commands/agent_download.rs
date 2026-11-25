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
use socket_patch_core::vendor::refusals::{
    vendor_refusals, LedgerLoad, RefusalScope, VendorRefusal, VendorRefusals,
};
use socket_patch_core::vendor::{load_state, lookup_entry, VendorEntry, VendorState};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::args::GlobalArgs;
use crate::commands::apply::ApplyRunReport;
use crate::commands::lock_cli::lock_failure;
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

/// The result line of a download that applies nothing after the save
/// (`--save-only`): `Saved 2 patches to .socket/manifest.json (1 updated,
/// 1 skipped).` A run that changed nothing says so instead of claiming the
/// patches were saved.
pub(crate) fn format_save_line(
    manifest_path: &Path,
    added: usize,
    updated: usize,
    skipped: usize,
    failed: usize,
) -> String {
    let saved = added + updated;
    let mut out = if saved > 0 {
        format!(
            "Saved {} to {}",
            crate::ui::plural(saved, "patch", "patches"),
            manifest_path.display()
        )
    } else {
        format!("No changes to {}", manifest_path.display())
    };
    let notes: Vec<String> = [
        (updated, "updated"),
        (skipped, "skipped"),
        (failed, "failed"),
    ]
    .into_iter()
    .filter(|(n, _)| *n > 0)
    .map(|(n, what)| format!("{n} {what}"))
    .collect();
    if !notes.is_empty() {
        out.push_str(&format!(" ({})", notes.join(", ")));
    }
    out.push('.');
    out
}

/// `  [skip] <purl> (<why>)` for a record the download phase reuses, with
/// the purl decoded for display (`%40scope` reads as `@scope`).
pub(crate) fn format_record_skip(purl: &str, why: &str) -> String {
    format!("  [skip] {} ({why})", normalize_purl(purl))
}

/// `[skip]` line for a patch a vendored run doesn't download because its
/// refusal is an expected skip (`code`, see `socket_patch_core::vendor::refusals::refusal_is_benign`).
pub(crate) fn format_refusal_skip(purl: &str, code: &str, detail: &str) -> String {
    format!("  [skip] {} ({code}): {detail}", normalize_purl(purl))
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
    pub allow_patch_conflicts: bool,
    /// The caller already reported every installed package the user-patch
    /// gate holds (`scan`), so the nested apply need not repeat the
    /// manifest entries it skips for them. `get` checks only its selection.
    pub user_patch_skips_reported: bool,
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
    /// `--patch-mirror-url`: the patch-server mirror whose origin counts as
    /// hosted the same way.
    pub patch_mirror_url: Option<String>,
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

    /// The manifest's project, where the vendor ledger lives
    /// ([`crate::args::GlobalArgs::project_root`]; #745).
    pub(crate) fn project_root(&self) -> PathBuf {
        crate::args::project_root_of(&self.manifest_path, &self.cwd)
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
/// round-trip — and the caller's flags, which the nested apply inherits.
pub struct DownloadRun<'a> {
    /// The run's one API client; the nested apply runs on it too.
    pub api_client: &'a ApiClient,
    /// The caller's global flags. The engine reads `--lock-timeout` from
    /// them (the wait budget for the apply lock, taken once around the
    /// manifest write and the nested apply); the nested apply starts from
    /// all of them (see [`nested_apply_args_from_params`]).
    pub common: &'a GlobalArgs,
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
    /// Manifest store only: the patches left out because conda built every
    /// installed copy as something other than the PyPI release (see
    /// [`leave_out_patches_no_conda_build_takes`]), as `<purl>: <reason>`.
    conda_refusals: Vec<String>,
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

/// `errorCode` of a patch that would have replaced a recorded one which
/// could not be rolled back first (see [`roll_back_replaced_patches`]).
pub(crate) const REPLACED_PATCH_NOT_RESTORED: &str = "replaced_patch_not_restored";

/// How to get the original files of the package `purl` back, as the start
/// of a sentence. `bundle install` keeps an installed gem as it is, edits
/// included, so a gem names the commands that reinstall it.
pub(crate) fn reinstall_remedy(purl: &str) -> String {
    match strip_purl_qualifiers(purl)
        .strip_prefix("pkg:gem/")
        .and_then(|rest| rest.split('@').next())
    {
        Some(gem) => format!("Run `bundle pristine {gem}` (or `gem pristine {gem}`)"),
        None => "Reinstall the package".to_string(),
    }
}

/// Run warning for an installed copy a replaced patch was not rolled back
/// in, because the copy holds none of that patch's bytes.
pub(crate) const REPLACED_PATCH_NOT_ON_COPY: &str = "replaced_patch_not_on_copy";

/// Appended to the manifest-write error of a run that had already rolled
/// replaced patches back: the manifest still records them.
pub(crate) const REPLACED_ROLLED_BACK_UNRECORDED: &str =
    ". The patches this run was replacing were rolled back and are still the recorded ones: \
     run `socket-patch apply` to put them back";

/// What [`roll_back_replaced_patches`] did for the records about to be
/// replaced.
#[derive(Default)]
pub(crate) struct ReplacedRollback {
    /// Purl -> why its recorded patch could not be rolled back. The caller
    /// keeps the record of each.
    pub(crate) refused: HashMap<String, String>,
    /// The refused purls whose rollback failed after the verification
    /// passed: some of their files may already be restored.
    pub(crate) partial: std::collections::HashSet<String>,
    /// Purl -> how many files were restored, over every installed copy.
    pub(crate) restored: HashMap<String, usize>,
    /// The rollback engine's run warnings `(code, detail)`.
    pub(crate) warnings: Vec<(String, String)>,
}

impl ReplacedRollback {
    /// The error text of the replacement of `purl` (recorded at
    /// `old_uuid`) this rollback refused; `None` when it did not.
    pub(crate) fn refusal(&self, purl: &str, old_uuid: &str) -> Option<String> {
        let why = self.refused.get(purl)?.trim_end_matches('.');
        let old = crate::ui::short_uuid(old_uuid);
        Some(if self.partial.contains(purl) {
            format!(
                "the recorded patch {old} could not be rolled back first: {why}. That \
                 patch stays recorded, but some of its files were restored before the \
                 failure. Run `socket-patch apply` to put it back, fix the cause, then \
                 run this command again."
            )
        } else {
            let remedy = reinstall_remedy(purl);
            format!(
                "the recorded patch {old} could not be rolled back first: {why}. That \
                 patch stays recorded and applied. {remedy} to get the original files \
                 back, then run this command again."
            )
        })
    }

    /// Print what the rollback restored and warned about (stderr, unless
    /// `quiet`) and hand back the warnings for the caller's envelope.
    pub(crate) fn report(&self, quiet: bool) -> Vec<RunWarning> {
        if !quiet {
            let mut restored: Vec<(&String, &usize)> = self.restored.iter().collect();
            restored.sort();
            for (purl, files) in restored {
                eprintln!(
                    "  [restore] {} ({} of the replaced patch)",
                    normalize_purl(purl),
                    crate::ui::plural(*files, "file", "files")
                );
            }
        }
        self.warnings
            .iter()
            .map(|(code, detail)| {
                if !quiet {
                    eprintln!("Warning: {detail}");
                }
                RunWarning::new(code.as_str(), detail.as_str())
            })
            .collect()
    }
}

/// The flags the engine's steps on installed packages start from: the
/// caller's own (`run.common`) with the scope `DownloadParams` owns laid
/// over them and the resolved manifest path, so the project they read
/// state from is the one the manifest belongs to.
fn engine_common(params: &DownloadParams, run: &DownloadRun<'_>) -> GlobalArgs {
    let manifest_path =
        std::path::absolute(&params.manifest_path).unwrap_or_else(|_| params.manifest_path.clone());
    GlobalArgs {
        cwd: params.cwd.clone(),
        global: params.global,
        global_prefix: params.global_prefix.clone(),
        manifest_path: manifest_path.display().to_string(),
        ..run.common.clone()
    }
}

/// What both passes of [`roll_back_replaced_patches`] run the engine with.
struct RollbackContext<'a> {
    socket_dir: &'a Path,
    vendored_keys: std::collections::HashSet<PurlKey>,
    hosted_pins: Vec<socket_patch_core::patch::redirect::upstream::HostedPin>,
    api_client: crate::args::RunApiClient,
}

/// What one pass decided for the purls of its records.
#[derive(Default)]
struct PassOutcome {
    /// Purl -> the failure of a copy that holds the record's patched bytes
    /// (or may), or of the pass itself.
    failed: HashMap<String, String>,
    /// Purl -> files restored (a wet pass).
    restored: HashMap<String, usize>,
    /// Purls with a copy the record's patch is on (a dry pass).
    patched: std::collections::HashSet<String>,
    /// Purls with a copy this pass wrote to, or may have (a wet pass).
    wrote: std::collections::HashSet<String>,
    /// `(purl, copy, failure)` of each copy left alone because it holds
    /// none of the record's patched bytes.
    not_on_copy: Vec<(String, String, String)>,
    warnings: Vec<(String, String)>,
}

/// Whether the copy at `dir` belongs to a release variant recorded beside
/// `purl` that this run does not roll back: the sibling's record accounts
/// for every one of its files there. The engine narrows variants only
/// among the records it is handed, so it would otherwise judge `purl`'s
/// record against its sibling's distribution, whose files can share
/// bytes with it.
async fn sibling_variant_owns(
    manifest: &PatchManifest,
    rolled_back: &PatchManifest,
    purl: &str,
    dir: &Path,
) -> bool {
    let base = strip_purl_qualifiers(purl);
    for (other, record) in &manifest.patches {
        if other != purl
            && strip_purl_qualifiers(other) == base
            && !rolled_back.patches.contains_key(other)
            && super::rollback::copy_carries_record(dir, &record.files).await
        {
            return true;
        }
    }
    false
}

/// One muted pass of the in-place rollback engine over `records` (taken
/// from `manifest`).
///
/// A copy that failed without holding any of the record's patched bytes
/// is not a failure here: the patch is not on it (it was never applied
/// there, or the copy is another distribution's), so there is nothing of
/// it to roll back, and the engine wrote nothing to it. The same goes for
/// a copy a sibling release variant's record owns
/// ([`sibling_variant_owns`]). A copy the patch may be on (a patched or
/// unreadable file) fails its purl.
///
/// When the engine stops at its before-blob gate it has restored nothing
/// and reports only the packages that need a missing blob: those fail,
/// and the pass runs again over the rest.
async fn rollback_pass(
    common: &GlobalArgs,
    context: &RollbackContext<'_>,
    records: &PatchManifest,
    manifest: &PatchManifest,
) -> PassOutcome {
    let mut pass = PassOutcome::default();
    let mut todo = records.clone();
    while !todo.patches.is_empty() {
        let purls: std::collections::HashSet<String> = todo.patches.keys().cloned().collect();
        let outcome = super::rollback::rollback_patches_inner(
            common,
            context.socket_dir,
            &todo,
            &context.vendored_keys,
            super::rollback::InnerSelection::Scope {
                purls: &purls,
                announce_empty: false,
            },
            &super::rollback::superseded_by_hosted(&todo, &context.hosted_pins),
            &context.api_client,
        )
        .await;
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(e) => {
                pass.failed
                    .extend(purls.into_iter().map(|purl| (purl, e.clone())));
                break;
            }
        };
        if outcome.aborted {
            let mut gated = false;
            for result in outcome.results {
                gated |= todo.patches.remove(&result.package_key).is_some();
                pass.failed.entry(result.package_key).or_insert(
                    result
                        .error
                        .unwrap_or_else(|| "an original blob is missing".to_string()),
                );
            }
            if gated {
                continue;
            }
            // The gate named no package of this pass: fail them all.
            pass.failed.extend(purls.into_iter().map(|purl| {
                (
                    purl,
                    "the rollback stopped before it restored anything".to_string(),
                )
            }));
            break;
        }
        for result in outcome.results {
            let purl = result.package_key;
            let dir = Path::new(&result.package_path);
            // A Go redirect and a Maven copy are undone as a unit; their
            // results do not say what the copy holds.
            let unit = matches!(
                Ecosystem::from_purl(&purl),
                Some(Ecosystem::Golang | Ecosystem::Maven)
            );
            if !result.files_rolled_back.is_empty() || (unit && !result.success) {
                pass.wrote.insert(purl.clone());
            }
            let siblings = !unit
                && result.files_rolled_back.is_empty()
                && sibling_variant_owns(manifest, records, &purl, dir).await;
            if result.success {
                let patched = unit
                    || result.files_verified.is_empty()
                    || result.files_verified.iter().any(|file| {
                        file.status
                            == socket_patch_core::patch::rollback::VerifyRollbackStatus::Ready
                    });
                if patched && !siblings {
                    pass.patched.insert(purl.clone());
                }
                *pass.restored.entry(purl).or_default() += result.files_rolled_back.len();
                continue;
            }
            let holds_patch = !siblings
                && (unit
                    || !result.files_rolled_back.is_empty()
                    || match records.patches.get(&purl) {
                        Some(record) => {
                            super::rollback::copy_holds_patched_bytes(&purl, dir, &record.files)
                                .await
                        }
                        None => true,
                    });
            let why = result
                .error
                .unwrap_or_else(|| "the rollback failed".to_string());
            if holds_patch {
                pass.failed.entry(purl).or_insert(why);
            } else if !siblings {
                pass.not_on_copy.push((purl, result.package_path, why));
            }
        }
        pass.warnings = outcome.warnings;
        break;
    }
    pass
}

/// Before the manifest records of `replaced` (each purl with the files of
/// the patch that replaces its record) are replaced: where the new patch
/// does not list every file the recorded one changed, roll the recorded
/// patch back in every installed copy (#2096), so that replacement is
/// "roll back the old patch, record the new one, apply it".
///
/// Once the record is replaced nothing lists a file the new patch dropped,
/// so one left patched would pass `apply --check` and `vex`, and no
/// `rollback` could restore it. Rolling back the whole record (not those
/// files alone) keeps the
/// engine on records as `rollback` and `remove` run it: a Go redirect, a
/// swapped jar and a rebuilt gem extension are undone as one unit, and
/// the nested apply starts from the original files.
///
/// Runs the engine muted, under the apply lock the caller holds, in two
/// passes: a dry run that verifies every copy first, so a package that
/// cannot be rolled back is refused with nothing of it changed, then the
/// rollback of the packages the dry run found the patch on. A package
/// that is not installed, whose copies are already original, or whose
/// copies hold none of the recorded patch's bytes has nothing to roll
/// back (see [`rollback_pass`]).
pub(crate) async fn roll_back_replaced_patches(
    common: &GlobalArgs,
    socket_dir: &Path,
    manifest: &PatchManifest,
    replaced: &[(&str, &HashMap<String, PatchFileInfo>)],
    api_client: &ApiClient,
) -> ReplacedRollback {
    let mut rollback = ReplacedRollback::default();
    let mut records = PatchManifest::new();
    for (purl, new_files) in replaced {
        let Some(old) = manifest.patches.get(*purl) else {
            continue;
        };
        // A new patch that lists every file of the recorded one leaves
        // nothing unrecorded: the nested apply moves each file to it, as
        // it always has, and needs no original blob to do so.
        if old.files.keys().any(|file| !new_files.contains_key(file)) {
            records.patches.insert((*purl).to_string(), old.clone());
        }
    }
    if records.patches.is_empty() {
        return rollback;
    }
    // The purls are the scope, so `--ecosystems` does not narrow them.
    let muted = GlobalArgs {
        silent: true,
        json: true,
        ecosystems: None,
        ..common.clone()
    };
    let project_root = muted.project_root();
    let context = RollbackContext {
        socket_dir,
        vendored_keys: crate::commands::vendor_owned_keys(
            &muted,
            &socket_patch_core::vendor::vendored_purl_keys(&project_root).await,
        )
        .await,
        // A record a live hosted pin superseded is left to the hosted leg
        // where its copy holds neither side of it, as `rollback` and
        // `remove` do.
        hosted_pins: if crate::commands::project_state_in_scope(&muted) {
            crate::commands::hosted_inventory(&muted, &project_root)
                .await
                .unwindable()
        } else {
            Vec::new()
        },
        api_client: crate::args::RunApiClient::new_with(Some(api_client.clone())),
    };

    let verify = GlobalArgs {
        dry_run: true,
        ..muted.clone()
    };
    let verified = rollback_pass(&verify, &context, &records, manifest).await;
    rollback.refused = verified.failed;
    // A copy left alone may hold a file edited after the patch was
    // applied: say so, once, for the purls this run goes on to replace.
    let mut not_on_copy = verified.not_on_copy;
    not_on_copy.sort();
    for (purl, copy, why) in not_on_copy {
        if rollback.refused.contains_key(&purl) {
            continue;
        }
        let old = records
            .patches
            .get(&purl)
            .map(|record| crate::ui::short_uuid(&record.uuid).to_string())
            .unwrap_or_default();
        rollback.warnings.push((
            REPLACED_PATCH_NOT_ON_COPY.to_string(),
            format!(
                "{}: the replaced patch {old} was not rolled back in {copy}: no file \
                 there holds its patched bytes ({}). A file edited after that patch was \
                 applied stays as it is. {} to get the original files back.",
                normalize_purl(&purl),
                why.trim_end_matches('.'),
                reinstall_remedy(&purl)
            ),
        ));
    }
    records
        .patches
        .retain(|purl, _| verified.patched.contains(purl) && !rollback.refused.contains_key(purl));
    if records.patches.is_empty() {
        return rollback;
    }
    let wet = GlobalArgs {
        dry_run: false,
        ..muted
    };
    let done = rollback_pass(&wet, &context, &records, manifest).await;
    for (purl, why) in done.failed {
        // A failure before anything of the package was written (an
        // original blob that could not be downloaded a second time) left
        // it as it was.
        if done.wrote.contains(&purl) {
            rollback.partial.insert(purl.clone());
        }
        rollback.refused.insert(purl, why);
    }
    rollback.restored = done.restored;
    let refused = &rollback.refused;
    rollback
        .restored
        .retain(|purl, files| *files > 0 && !refused.contains_key(purl));
    rollback.warnings.extend(done.warnings);
    rollback
}

/// `selected` as the `(purl, uuid)` pairs the vendor refusals judge.
pub(crate) fn selection_pairs(selected: &[PatchSearchResult]) -> Vec<(&str, &str)> {
    selected
        .iter()
        .map(|s| (s.purl.as_str(), s.uuid.as_str()))
        .collect()
}

/// Every refusal the vendored download phase raises before it fetches a
/// view: [`vendor_refusals`] over the selection, plus a hosted gem the
/// takeover would refuse (#775, [`gem_takeover_refusals_for`]), refused
/// here with the takeover's code instead of after its fetch. The download
/// phase only runs online (`--offline` refuses `get` and `scan` before it),
/// so the gem's dry-run restore may resolve the registry entry. `prior` is
/// scan's npm crawl, when the caller has it (the installed-copy lookup
/// reuses it).
///
/// [`gem_takeover_refusals_for`]: crate::commands::vendor::gem_takeover_refusals_for
pub(crate) async fn vendored_download_refusals(
    params: &DownloadParams,
    selected: &[PatchSearchResult],
    ledger: LedgerLoad<'_>,
    prior: Option<&crate::ecosystem_dispatch::NpmCrawlSnapshot>,
) -> VendorRefusals {
    let cwd = params.cwd.as_path();
    let origins = crate::commands::hosted_unwind::patch_server_origins_of(
        params.patch_server_url.as_deref(),
        params.patch_mirror_url.as_deref(),
    );
    let pins = hosted_pins(cwd, origins.clone()).await;
    let options = params.crawler_options();
    let installed = crate::commands::vendor::installed_lookup(&options, prior);
    let mut refusals = vendor_refusals(
        cwd,
        &selection_pairs(selected),
        ledger,
        &RefusalScope {
            hosted_pins: &pins,
            installed: &installed,
        },
    )
    .await;
    let claimed = claimed_purls(&pins);
    let empty = HashMap::new();
    let entries = ledger.unwrap_or(&empty);
    let takeovers: Vec<&str> = selected
        .iter()
        .filter(|sr| {
            !refusals.contains_key(&sr.purl)
                && claimed.contains(&PurlKey::new(&sr.purl))
                && detached_ledger_record(RecordStore::Ledger(entries), &sr.purl, &sr.uuid)
                    .is_none()
        })
        .map(|sr| sr.purl.as_str())
        .collect();
    let gem = crate::commands::vendor::gem_takeover_refusals_for(
        cwd,
        takeovers.into_iter(),
        &pins,
        false,
        origins,
    )
    .await;
    for (purl, (code, detail)) in gem {
        refusals
            .entry(purl)
            .or_insert(VendorRefusal { code, detail });
    }
    refusals
}

/// The project's hosted pins: the purls whose vendored run is a hosted →
/// vendored takeover (a patch-server tarball, Socket's own or one of
/// `origins`). The download phase and the scan preview
/// (`scan/vendor_flow.rs`) both read the takeovers through here, so the dry
/// run and the wet run agree on which purls they are.
pub(crate) async fn hosted_pins(
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
pub(crate) fn claimed_purls(
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
/// narrowing, the caller's vendored refusals, the per-store skip
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
    refusals: &VendorRefusals,
    mut prefetched: HashMap<String, PatchResponse>,
) -> FetchBatch {
    let quiet = params.quiet();
    // Narrow multi-release selections to the installed distribution unless
    // --all-releases was passed (a no-op for non-variant ecosystems and
    // single-variant packages). The views it fetched serve the loop below.
    // The narrowing queries the API: show that something is happening
    // once selection (and get's confirm prompt) is done.
    let mut status = crate::ui::StatusLine::stderr(params.json, params.silent);
    status.set("Preparing download");
    let (selected, warnings, views) = filter_to_installed_releases(
        selected,
        params.all_releases,
        &params.crawler_options(),
        quiet,
        api_client,
    )
    .await;
    // Agent mode writes into the installed copies. A patch no copy can
    // take, because conda built each of them as something other than the
    // pure-Python PyPI release, is left out here instead of being recorded
    // and then refused by every later `apply`. `--all-releases` asks for
    // records other environments use, so it keeps them.
    let (selected, conda_refusals) =
        if matches!(store, RecordStore::Manifest(_)) && !params.all_releases {
            leave_out_patches_no_conda_build_takes(selected, &params.crawler_options(), quiet).await
        } else {
            (selected, Vec::new())
        };
    status.finish();
    prefetched.extend(views);
    // The callers have already listed the patches (`scan`'s rows, `get`'s
    // listing), so a downloaded patch is not named again here: the
    // download shows on the status line. It shows only across each network
    // wait below and is cleared before anything else can print, so a skip
    // or error line never lands on it.
    let mut progress = crate::ui::StatusLine::stderr(params.json, params.silent);

    let mut batch = FetchBatch {
        skipped: 0,
        already_recorded: 0,
        failed: 0,
        fetched: Vec::new(),
        reused: Vec::new(),
        events: Vec::new(),
        warnings,
        conda_refusals,
        mode: match store {
            RecordStore::Ledger(_) => Some("vendored"),
            RecordStore::Manifest(_) => None,
        },
    };

    // The view GETs the loop below makes — every patch past the refusal
    // and the ledger skip whose view is not already held in `prefetched`
    // (the same checks, in the loop's order, over inputs the loop never
    // mutates) — run concurrently ahead of it, at most
    // `api_concurrency` in flight, and come back in selection order. The
    // loop takes the next one where it would await the request, and each
    // request's `--debug` lines print there too, so stdout, the per-patch
    // stderr lines and the JSON records fold in selection order.
    let mut held: std::collections::HashSet<&str> = prefetched.keys().map(String::as_str).collect();
    let to_fetch: Vec<&str> = selected
        .iter()
        .filter(|sr| {
            !refusals.contains_key(&sr.purl)
                && detached_ledger_record(store, &sr.purl, &sr.uuid).is_none()
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

    for (done, search_result) in selected.iter().enumerate() {
        let (purl, uuid) = (search_result.purl.as_str(), search_result.uuid.as_str());

        // Refusal FIRST (the dry-run preview's precedence): a preserved
        // ledger can name this exact uuid after `rollback --preserve-state`
        // unwired it, so UUID equality alone never exempts a purl — the
        // refusals' own lock-derived exemption decides. The backend refuses
        // the package before it reads the patch, so its view is never
        // fetched (nor, downstream, its pristine source). Code-tagged so a
        // `--silent` operator can grep the stable code.
        if let Some(VendorRefusal { code, detail }) = refusals.get(purl) {
            // An expected skip (a gem version this project doesn't lock)
            // is the package's whole account: no view, no record, and no
            // failure, as in the vendor loop.
            if socket_patch_core::vendor::refusals::refusal_is_benign(code) {
                if !quiet {
                    eprintln!("{}", format_refusal_skip(purl, code, detail));
                }
                batch.events.push(tag_mode(
                    PatchEvent::new(EventAction::Skipped, purl)
                        .with_uuid(uuid)
                        .with_reason(*code, detail.as_str()),
                    batch.mode,
                ));
                batch.skipped += 1;
                continue;
            }
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

        // The view: from memory when the narrowing (or the uuid path's own
        // identifier fetch) already fetched it, else the network — the next
        // of the concurrent GETs above, which were planned for exactly
        // these turns.
        let view = match prefetched.remove(uuid) {
            Some(patch) => Ok(Some(patch)),
            None => {
                progress.progress("Downloading patches", done, selected.len());
                let next = views.next().await;
                progress.finish();
                match next {
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
                }
            }
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
            // No line of its own: the caller has listed the patch, and the
            // run's result says it (`Applied 0 of 1 patch: 1 already
            // patched.`, `No changes to <manifest> (1 skipped).`).
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
        // A replaced record is worth its line; a new one has been listed.
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
    /// The patches the phase could not download, as the run's telemetry
    /// names them: the vendor step never sees these (it works from the
    /// records that did download), so its event adds them.
    pub(crate) fn failed_outcomes(&self) -> Vec<socket_patch_core::telemetry::PatchOutcome> {
        crate::telemetry_outcomes::patch_outcomes_of(
            self.events
                .iter()
                .filter(|event| event.action == EventAction::Failed),
            socket_patch_core::telemetry::MODE_VENDORED,
        )
    }

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

/// Warning code: a PyPI patch was left out of an agent-mode run because
/// conda built every installed copy as something other than the PyPI
/// release the patch was made from.
pub(crate) const CONDA_BUILD_NOT_PYPI_RELEASE: &str =
    socket_patch_core::patch::conda_copy::REFUSAL_CODE;

/// The PyPI patches of `selected` that at least one installed copy can
/// take, and a `<purl>: <reason>` line for each one left out: every copy
/// of its package is a conda build the patch is never applied to (a
/// compiled build, or one nothing shows to be pure Python; see
/// `socket_patch_core::patch::conda_copy`). A package that is not
/// installed, or has a copy pip or uv installed, keeps its patch. Whether
/// a pure-Python conda build's files are the release's is the apply
/// engine's check, as for any other copy.
///
/// A record left out beside a kept one of the same release has no line:
/// it is only not the installed distribution (the platform wheel's record
/// beside the pure wheel's, for a pure-Python conda build), and the kept
/// record patches the package.
async fn leave_out_patches_no_conda_build_takes(
    selected: Vec<PatchSearchResult>,
    crawler_options: &CrawlerOptions,
    quiet: bool,
) -> (Vec<PatchSearchResult>, Vec<String>) {
    use socket_patch_core::patch::conda_copy::static_refusal;
    let pypi: Vec<String> = selected
        .iter()
        .filter(|sr| Ecosystem::from_purl(&sr.purl) == Some(Ecosystem::Pypi))
        .map(|sr| sr.purl.clone())
        .collect();
    if pypi.is_empty() {
        return (selected, Vec::new());
    }
    let copies =
        find_all_packages_for_rollback(&partition_purls(&pypi, None), crawler_options, true).await;
    let mut kept = Vec::with_capacity(selected.len());
    // (base purl, line) of each record left out.
    let mut left_out: Vec<(String, String)> = Vec::new();
    for sr in selected {
        let mut reason = None;
        for copy in copies.get(&sr.purl).map(Vec::as_slice).unwrap_or_default() {
            reason = static_refusal(&sr.purl, copy).await;
            if reason.is_none() {
                break;
            }
        }
        match reason {
            Some(reason) => left_out.push((
                strip_purl_qualifiers(&sr.purl).to_string(),
                format!("{}: {reason}", normalize_purl(&sr.purl)),
            )),
            None => kept.push(sr),
        }
    }
    let refused: Vec<String> = left_out
        .into_iter()
        .filter(|(base, _)| {
            !kept
                .iter()
                .any(|sr| strip_purl_qualifiers(&sr.purl) == base.as_str())
        })
        .map(|(_, line)| line)
        .collect();
    if !quiet {
        for line in &refused {
            eprintln!("  [note] {line}");
        }
    }
    (kept, refused)
}

/// Warning code: release narrowing kept every variant of a base (the base
/// is not installed, or no variant matches the installed distribution).
pub(crate) const RELEASE_NARROWING: &str = "release_narrowing";

/// [`download_patch_records_with`], handing `prior` (scan's npm crawl of
/// the untouched tree) to the refusals' installed-copy lookup.
pub(crate) async fn download_patch_records_reusing(
    selected: &[PatchSearchResult],
    params: &DownloadParams,
    api_client: &ApiClient,
    prefetched: HashMap<String, PatchResponse>,
    prior: Option<&crate::ecosystem_dispatch::NpmCrawlSnapshot>,
) -> DetachedDownload {
    // The ledger load outcome is handed to the refusals AS a result: an
    // unreadable ledger must surface as `vendor_state_unreadable` from the
    // one refusal this phase emits (fail closed, nothing exempt), not be
    // flattened into an empty ledger that then reports a lock remedy. For
    // the classification below it degrades to empty (no detached entry to
    // reuse — the vendor step reports the corruption itself). This phase
    // feeds the vendor engine, so it refuses what the engine would BEFORE
    // fetching: otherwise the view is downloaded for nothing, and a package
    // resolvable only through an unreadable lock inventory is misreported
    // as `package_not_installed` instead of the real code.
    let vendor_state = load_state(&params.project_root()).await;
    let refusals = vendored_download_refusals(
        params,
        selected,
        vendor_state.as_ref().map(|s| &s.entries),
        prior,
    )
    .await;
    download_patch_records_preflighted(
        selected,
        params,
        api_client,
        prefetched,
        vendor_state,
        &refusals,
    )
    .await
}

/// [`download_patch_records_with`] after its two reads: the caller's own
/// ledger load and [`vendored_download_refusals`] outcome. The `get <uuid>`
/// path computes the refusals itself (it owns the pre-record refusal
/// shape) and hands them down, so the project is judged once per run.
pub(crate) async fn download_patch_records_preflighted(
    selected: &[PatchSearchResult],
    params: &DownloadParams,
    api_client: &ApiClient,
    prefetched: HashMap<String, PatchResponse>,
    vendor_state: std::io::Result<VendorState>,
    refusals: &VendorRefusals,
) -> DetachedDownload {
    let vendor_state = vendor_state.unwrap_or_default();
    let blobs_dir = params.socket_dir().join("blobs");
    let batch = fetch_selected_patches(
        selected,
        params,
        api_client,
        RecordStore::Ledger(&vendor_state.entries),
        params.persist_blobs.then_some(blobs_dir.as_path()),
        refusals,
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

/// Warning code: git would not commit the manifest (see
/// [`warn_if_manifest_gitignored`]).
pub(crate) const MANIFEST_GITIGNORED: &str = "manifest_gitignored";

/// Warn (stderr `[warn]` + `warnings[]`) when git's ignore rules keep the
/// manifest this run recorded patches in out of the commit (#1638): the
/// blobs are committed, but a fresh checkout's `socket-patch apply` finds
/// no manifest, applies nothing and exits 0. Only a warning, because a
/// pipeline that scans and applies in one job never commits `.socket/`.
/// A manifest outside the project root is not checked.
pub(crate) async fn warn_if_manifest_gitignored(
    project_root: &Path,
    manifest_path: &Path,
    quiet: bool,
    warnings: &mut Vec<RunWarning>,
) {
    let Ok(rel) = manifest_path.strip_prefix(project_root) else {
        return;
    };
    let rel: Vec<String> = rel
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    let rel = rel.join("/");
    let Some(rules) = socket_patch_core::vendor::file_gitignored(project_root, &rel).await else {
        return;
    };
    let w = format!(
        "git would not commit {rel} ({rules}), so `socket-patch apply` in other checkouts \
         (CI, a fresh clone) would find no manifest and apply nothing; remove or narrow that \
         rule (a `!{rel}` line re-includes the file only when no parent directory is \
         ignored)"
    );
    if !quiet {
        eprintln!("  [warn] {w}");
    }
    warnings.push(RunWarning::new(MANIFEST_GITIGNORED, w));
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
    project_root: &Path,
    quiet: bool,
    recorded: &[(String, String)],
    warnings: &mut Vec<RunWarning>,
) {
    let Ok(vendor_state) = load_state(project_root).await else {
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

/// The nested apply's flags for an engine run: the caller's own
/// (`run.common`), so a flag only apply reads (`--no-gem-native-rebuild`,
/// the Maven patch-service flags, …) reaches it without being named here
/// (#2069), with the scope and consent fields `DownloadParams` owns laid
/// over them, then [`nested_apply_args`]'s overrides. The nested apply
/// runs on the run's client (`run.api_client`), never one rebuilt from
/// these flags.
pub(crate) fn nested_apply_args_from_params(
    params: &DownloadParams,
    run: &DownloadRun<'_>,
    manifest_path: &Path,
) -> GlobalArgs {
    let common = GlobalArgs {
        strict: params.strict,
        allow_patch_conflicts: params.allow_patch_conflicts,
        // Scope the nested apply like the caller was scoped: `None` would
        // apply the WHOLE manifest, mutating other ecosystems' packages the
        // user filtered out.
        ecosystems: params.ecosystems.clone(),
        ..engine_common(params, run)
    };
    nested_apply_args(&common, manifest_path, params.quiet())
}

/// The patches an agent-mode download pass reached, as its telemetry
/// names them: a patch fetched in place of an older one is `downloaded`
/// like any other.
fn fetched_outcomes(events: &[PatchEvent]) -> Vec<socket_patch_core::telemetry::PatchOutcome> {
    let events: Vec<PatchEvent> = events
        .iter()
        .map(|event| PatchEvent {
            action: match event.action {
                EventAction::Updated => EventAction::Downloaded,
                action => action,
            },
            ..event.clone()
        })
        .collect();
    crate::telemetry_outcomes::patch_outcomes_of(&events, socket_patch_core::telemetry::MODE_AGENT)
}

/// The command an engine run's telemetry reports: the one whose envelope
/// it fills. `scan` and `get` are the engine's two callers; both pass
/// their own envelope, printed or not.
pub(crate) fn telemetry_command(env: &Envelope) -> &'static str {
    match env.command {
        EnvelopeCommand::Scan => "scan",
        _ => "get",
    }
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
    command: &'static str,
    common: GlobalArgs,
    json: bool,
    report_user_patch_skips: bool,
    recorded: &[(String, String)],
    client: &ApiClient,
    lock: LockGuard,
) -> ApplyRunReport {
    let quiet = common.silent || json;
    let manifest_path = common.resolved_manifest_path();
    let apply_args = super::apply::ApplyArgs {
        common,
        force: false,
        check: false,
        vex: Default::default(),
        nested: Some(super::apply::NestedApply {
            caller_json: json,
            report_user_patch_skips,
            command,
        }),
    };
    // The nested apply runs on the host's client: seeded, never rebuilt.
    let client = crate::args::RunApiClient::new_with(Some(client.clone()));
    let mut report = super::apply::run_locked(apply_args, manifest_path, &client, lock).await;
    // Scan already printed its selection-time skips. A selected package that
    // the locked recheck now skips is NEW evidence and must still be visible.
    if !report_user_patch_skips {
        for skip in &report.skipped {
            if skip.error_code.as_deref() == Some(super::user_patches::CONFLICT)
                && skip
                    .purl
                    .as_deref()
                    .is_some_and(|key| recorded.iter().any(|(purl, _)| apply_key_covers(key, purl)))
            {
                if let Some(reason) = &skip.reason {
                    report
                        .warnings
                        .push(RunWarning::new(super::user_patches::CONFLICT, reason));
                    if !quiet {
                        eprintln!("Warning: {reason}");
                    }
                }
            }
        }
    }
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
/// into `env`, so `--json` says what the human run prints (#424). Only a
/// reported write counts as `applied`, even when apply exits 0. Skips retain
/// their `reason` and `errorCode`; of the patches this run did not select,
/// only a `user_patch_conflict` skip (a conflict found after selection) is
/// recorded.
/// A failed run records a
/// `failed` event (apply's `errorCode` / `error`) for each recorded patch a
/// failure covers, `applied` for each one apply reports patched, a `failed`
/// event for each other failing manifest patch (one
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
    // The caller may already carry the same run-level advisory (scan reports
    // the gem `.bundle/config` / stale-plugin warnings from its own crawl).
    let reported = env.warnings.len();
    for warning in &report.warnings {
        if !env.warnings[..reported]
            .iter()
            .any(|w| w.code == warning.code && w.detail == warning.detail)
        {
            env.warnings.push(warning.clone());
        }
    }
    // A copy skipped as not supported yet (a compiled conda build) is one
    // copy's outcome, not its package's: another copy of the same record
    // may have been patched. Its events are recorded on their own below,
    // one per copy.
    let unsupported_copy =
        |skip: &PatchEvent| skip.error_code.as_deref() == Some(CONDA_BUILD_NOT_PYPI_RELEASE);
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
        } else if let Some(skip) = report.skipped.iter().find(|skip| {
            !unsupported_copy(skip)
                && skip
                    .purl
                    .as_deref()
                    .is_some_and(|key| apply_key_covers(key, purl))
        }) {
            let mut event = skip.clone().with_uuid(uuid);
            event.purl = Some(purl.clone());
            record_apply_skip(env, event);
        } else if report.applied.iter().any(|k| apply_key_covers(k, purl)) {
            env.record(
                PatchEvent::new(EventAction::Applied, purl.as_str()).with_uuid(uuid.as_str()),
            );
        } else if report.skipped.iter().any(|skip| {
            unsupported_copy(skip)
                && skip
                    .purl
                    .as_deref()
                    .is_some_and(|key| apply_key_covers(key, purl))
        }) {
            // Every copy of it was skipped that way: said below.
        } else if report.code == 0 {
            record_apply_skip(
                env,
                PatchEvent::new(EventAction::Skipped, purl)
                    .with_uuid(uuid)
                    .with_reason(
                        "apply_not_attempted",
                        "The nested apply did not report applying this package",
                    ),
            );
        }
    }
    // The nested apply covers the whole manifest, so its other skips
    // (`already_patched`, `vendored`, ...) belong to packages this run did
    // not select. Two are news all the same: a user-patch conflict found
    // after selection, and a copy left unpatched because it is not
    // supported yet (a compiled conda build), which would otherwise go
    // unsaid, the nested apply being silent under `--json`.
    for skip in &report.skipped {
        let Some(key) = skip.purl.as_deref() else {
            continue;
        };
        if unsupported_copy(skip) {
            let mut event = skip.clone();
            if let Some((purl, uuid)) = recorded
                .iter()
                .find(|(purl, _)| apply_key_covers(key, purl))
            {
                event.purl = Some(purl.clone());
                event.uuid = Some(uuid.clone());
            } else if event.uuid.is_none() {
                event.uuid = uuid_of(key);
            }
            // Once per copy: the reason names it.
            let said = env.events.iter().any(|existing| {
                existing.action == EventAction::Skipped
                    && existing.error_code == event.error_code
                    && existing.purl == event.purl
                    && existing.reason == event.reason
            });
            if !said {
                env.record(event);
            }
            continue;
        }
        if skip.error_code.as_deref() != Some(super::user_patches::CONFLICT)
            || recorded.iter().any(|(purl, _)| apply_key_covers(key, purl))
            || report
                .failures
                .iter()
                .any(|failure| apply_key_covers(&failure.purl, key))
        {
            continue;
        }
        let mut event = skip.clone();
        if event.uuid.is_none() {
            event.uuid = uuid_of(key);
        }
        record_apply_skip(env, event);
    }
    if report.code == 0 {
        return;
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

/// Scan can already carry the same selection-time skip. Keep one event, adding
/// the manifest UUID when the locked apply knows it, without double-counting.
fn record_apply_skip(env: &mut Envelope, event: PatchEvent) {
    if let Some(existing) = env.events.iter_mut().find(|existing| {
        existing.action == EventAction::Skipped
            && existing.error_code == event.error_code
            && existing
                .purl
                .as_deref()
                .zip(event.purl.as_deref())
                .is_some_and(|(a, b)| PurlKey::qualified(a) == PurlKey::qualified(b))
    }) {
        if existing.uuid.is_none() {
            existing.uuid = event.uuid;
        }
    } else {
        env.record(event);
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
    let lock_timeout = Duration::from_secs(run.common.lock_timeout.unwrap_or(0));

    // The manifest read-modify-write — and the blob writes it records —
    // runs under the apply lock: `remove`/`rollback` RMW the same file under
    // it, and an unlocked writer here would lose their update or have its
    // own record clobbered. `acquire` creates `.socket/` itself; the guard's
    // drop removes `apply.lock` and prunes an otherwise-empty `.socket/`, so
    // a run that records nothing leaves no residue. The nested apply runs
    // under this SAME guard (one lock window; see `run_nested_apply`).
    // This is the wet download: a dry run previews without it.
    let guard =
        match crate::commands::lock_cli::acquire_with_status(&socket_dir, lock_timeout, false) {
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
    env.warnings
        .extend(crate::commands::lock_cli::commit_recovery_warning(&guard));

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

    // No vendored refusals here: this is the agent (manifest) engine, and
    // agent/save-only flows keep their record-only intent. The vendored
    // download phase (`download_patch_records_with`) computes its own.
    let blobs_dir = socket_dir.join("blobs");
    let batch = fetch_selected_patches(
        selected,
        params,
        run.api_client,
        RecordStore::Manifest(&manifest),
        params.persist_blobs.then_some(blobs_dir.as_path()),
        &VendorRefusals::new(),
        HashMap::new(),
    )
    .await;
    let mut batch = batch;

    // A record about to be replaced by another patch: roll the recorded
    // patch back first, or keep its record (#2096). Boxed: this runs the
    // rollback engine on the scan → download → apply chain, whose futures
    // must fit the main thread's stack.
    let replaced: Vec<(&str, &HashMap<String, PatchFileInfo>)> = batch
        .fetched
        .iter()
        .filter(|f| matches!(f.action, PatchAction::Updated { .. }))
        .map(|f| (f.patch.purl.as_str(), &f.files))
        .collect();
    if !replaced.is_empty() {
        // About to write to installed packages: a hot-patch pass is no
        // longer dropped at its time limit.
        crate::hot_patch::mark_apply_started();
    }
    let rollback = Box::pin(roll_back_replaced_patches(
        &engine_common(params, run),
        &socket_dir,
        &manifest,
        &replaced,
        run.api_client,
    ))
    .await;
    let rollback_warnings = rollback.report(quiet);
    let (kept, refused): (Vec<FetchedPatch>, Vec<FetchedPatch>) = batch
        .fetched
        .drain(..)
        .partition(|f| !rollback.refused.contains_key(&f.patch.purl));
    batch.fetched = kept;
    // A blob a kept patch also lists stays: the fetch that wrote it first
    // may have been the refused patch's.
    let kept_blobs: std::collections::HashSet<&str> = batch
        .fetched
        .iter()
        .flat_map(|f| f.files.values())
        .flat_map(|info| [info.before_hash.as_str(), info.after_hash.as_str()])
        .collect();
    let mut refused_blobs: Vec<String> = Vec::new();
    let mut refusals: Vec<(String, String, String)> = Vec::new();
    for FetchedPatch {
        patch,
        action,
        new_blobs,
        ..
    } in refused
    {
        refused_blobs.extend(
            new_blobs
                .into_iter()
                .filter(|hash| !kept_blobs.contains(hash.as_str())),
        );
        let old_uuid = match &action {
            PatchAction::Updated { old_uuid } => old_uuid.as_str(),
            _ => "",
        };
        let detail = rollback.refusal(&patch.purl, old_uuid).unwrap_or_default();
        refusals.push((patch.purl, patch.uuid, detail));
    }
    // Nothing records a refused patch: its blobs go, and its `updated`
    // event becomes the failure.
    unwind_new_blobs(&blobs_dir, &refused_blobs).await;
    for (purl, uuid, detail) in &refusals {
        batch.events.retain(|event| {
            !(event.action == EventAction::Updated
                && event.purl.as_deref() == Some(purl.as_str())
                && event.uuid.as_deref() == Some(uuid.as_str()))
        });
        batch.fail(
            params.json,
            Some(format!("[fail] {} ({detail})", normalize_purl(purl))),
            (purl, uuid),
            REPLACED_PATCH_NOT_RESTORED,
            detail,
        );
    }

    // `added` and `updated` are DISJOINT — one patch lands in exactly one,
    // matching the per-patch event (`downloaded` / `updated`) and the
    // single-uuid flow's summary in `save_and_apply_patch`; their sum gates
    // the apply step.
    let downloaded = batch.fetched.len();
    // Telemetry: the patch records this run fetched. `get <uuid>` reports
    // its own fetch; every other agent-mode download comes through here.
    socket_patch_core::telemetry::track_patches_fetched(
        telemetry_command(env),
        &fetched_outcomes(&batch.events),
        &socket_patch_core::telemetry::TelemetryAuth::for_client(run.api_client),
    )
    .await;
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
            let mut msg = format!("Failed to write manifest: {e}");
            if !rollback.restored.is_empty() {
                msg.push_str(REPLACED_ROLLED_BACK_UNRECORDED);
            }
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
    warnings.extend(
        batch
            .conda_refusals
            .into_iter()
            .map(|detail| RunWarning::new(CONDA_BUILD_NOT_PYPI_RELEASE, detail)),
    );
    warnings.extend(rollback_warnings);
    warn_on_vendored_uuid_drift(&params.project_root(), quiet, &changed, &mut warnings).await;
    if !recorded.is_empty() {
        warn_if_manifest_gitignored(&params.project_root(), &manifest_path, quiet, &mut warnings)
            .await;
    }
    env.warnings.extend(warnings);

    // The apply below says the run's result. With no apply to follow
    // (`--save-only`), the save is the result.
    if !quiet && apply_lock.is_none() {
        eprintln!(
            "{}",
            format_save_line(&manifest_path, added, updated, batch.skipped, batch.failed)
        );
    }

    // Auto-apply unless --save-only (the lock decision above).
    let mut apply_report: Option<ApplyRunReport> = None;
    if let Some(lock) = apply_lock {
        // Past the network, about to write to installed packages: a
        // hot-patch pass is no longer dropped at its time limit.
        crate::hot_patch::mark_apply_started();
        apply_report = Some(
            run_nested_apply(
                telemetry_command(env),
                nested_apply_args_from_params(params, run, &manifest_path),
                params.json,
                !params.user_patch_skips_reported,
                &recorded,
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

/// The install commands whose fresh run undoes the in-place patches of an
/// ecosystem's packages: the package manager the project's lockfile names
/// (`has_file` answers for the project root), else the ecosystem's default.
/// Empty where no one install step does (Maven, Gradle, sbt), or where
/// none undoes the patch (Go builds from the committed copies). A Python
/// project pixi installs gets `pixi install` beside any other tool's
/// install: pixi keeps its own environments, whatever venv that tool
/// fills. Beside pixi's files `pip install` is named only when a file pip
/// installs from is there too.
fn install_commands(ecosystem: Ecosystem, has_file: &dyn Fn(&str) -> bool) -> Vec<&'static str> {
    use socket_patch_core::constants::npm_family::{BUN_LOCK, BUN_LOCKB, PNPM_LOCK, VLT_LOCK};
    let one = |command: &'static str| vec![command];
    match ecosystem {
        Ecosystem::Npm if has_file(PNPM_LOCK) => one("pnpm install"),
        Ecosystem::Npm if has_file("yarn.lock") => one("yarn install"),
        Ecosystem::Npm if has_file(BUN_LOCK) || has_file(BUN_LOCKB) => one("bun install"),
        Ecosystem::Npm if has_file(VLT_LOCK) => one("vlt install"),
        Ecosystem::Npm => one("npm install"),
        Ecosystem::Pypi => {
            let mut commands: Vec<&'static str> = [
                ("uv.lock", "uv sync"),
                ("poetry.lock", "poetry install"),
                ("Pipfile.lock", "pipenv install"),
                ("pdm.lock", "pdm install"),
            ]
            .into_iter()
            .find(|(lock, _)| has_file(lock))
            .map(|(_, command)| command)
            .into_iter()
            .collect();
            let other_tool = !commands.is_empty();
            // pixi links the packages of a project into its own
            // environments, conda and PyPI ones alike.
            use socket_patch_core::crawlers::pixi_env::{PIP_INSTALL_FILES, PIXI_FILES};
            let pixi = PIXI_FILES.iter().any(|file| has_file(file));
            if pixi {
                commands.push("pixi install");
            }
            // With no other tool's lock, pip installs the project; beside
            // pixi's files only when a file pip installs from is there too
            // (the crawl then also reads the interpreter on `PATH`).
            let pip_files = PIP_INSTALL_FILES.iter().any(|file| has_file(file));
            if !other_tool && (!pixi || pip_files) {
                commands.push("pip install");
            }
            commands
        }
        Ecosystem::Gem => one("bundle install"),
        Ecosystem::Composer => one("composer install"),
        Ecosystem::Cargo => one("cargo fetch"),
        Ecosystem::Nuget => one("dotnet restore"),
        Ecosystem::Golang | Ecosystem::Maven | Ecosystem::Deno => Vec::new(),
    }
}

/// The "Next steps:" block that ends a wet agent-mode run (`get`,
/// `scan --mode agent`) which recorded the patches `recorded` (purls) in
/// the manifest: commit `.socket/`, and run `socket-patch apply` after
/// every install, named for the package managers of the patched
/// ecosystems. Empty when the run recorded nothing: there is nothing new
/// to commit. `save_only` is a `--save-only` run, which has not applied
/// the patches yet.
pub(crate) fn next_steps(
    recorded: &[&str],
    socket_dir: &Path,
    project_root: &Path,
    save_only: bool,
) -> Vec<String> {
    if recorded.is_empty() {
        return Vec::new();
    }
    let mut ecosystems: Vec<Ecosystem> = Vec::new();
    for purl in recorded {
        // A purl of an ecosystem this CLI does not know names no install.
        if let Some(ecosystem) = Ecosystem::from_purl(purl) {
            if !ecosystems.contains(&ecosystem) {
                ecosystems.push(ecosystem);
            }
        }
    }
    let has_file = |name: &str| project_root.join(name).is_file();
    let mut installs: Vec<&str> = ecosystems
        .iter()
        .flat_map(|ecosystem| install_commands(*ecosystem, &has_file))
        .collect();
    installs.sort_unstable();
    installs.dedup();
    let shown_dir = socket_dir
        .strip_prefix(project_root)
        .unwrap_or(socket_dir)
        .to_string_lossy()
        .replace('\\', "/");
    // An in-place Go patch is a committed copy under `.socket/go-patches/`
    // plus a `replace` in go.mod (go.work for a workspace's shared module).
    let go = ecosystems.contains(&Ecosystem::Golang);
    let commit = if go {
        format!("{shown_dir}/ and go.mod (or go.work)")
    } else {
        format!("{shown_dir}/")
    };
    // No install removes a Go patch, so a Go-only run has nothing to
    // re-apply.
    let reapply = ecosystems.iter().any(|e| *e != Ecosystem::Golang) || ecosystems.is_empty();
    crate::ui::agent_next_steps(&commit, &installs, save_only, reapply)
}

/// The purls of the patches a run recorded in the manifest: its
/// `downloaded` (new record) and `updated` (replaced record) events.
pub(crate) fn recorded_purls(env: &Envelope) -> Vec<&str> {
    env.events
        .iter()
        .filter(|e| matches!(e.action, EventAction::Downloaded | EventAction::Updated))
        .filter_map(|e| e.purl.as_deref())
        .collect()
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

#[cfg(test)]
mod tests {
    use super::*;

    fn steps(recorded: &[&str], root: &Path) -> Vec<String> {
        next_steps(recorded, &root.join(".socket"), root, false)
    }

    #[test]
    fn next_steps_name_the_install_of_each_patched_ecosystem() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        assert!(steps(&[], root).is_empty());

        // The defaults, with no lockfile to say otherwise.
        let gem = steps(&["pkg:gem/rack@2.2.3?platform=ruby"], root);
        assert_eq!(gem[1], "  1. Commit .socket/ to keep the patches.");
        assert!(gem[2].contains("after every `bundle install`,"), "{gem:?}");
        let mixed = steps(
            &[
                "pkg:pypi/urllib3@1.26.18",
                "pkg:npm/minimist@1.2.2",
                "pkg:npm/lodash@4.17.20",
            ],
            root,
        );
        assert!(
            mixed[2].contains("after every `npm install` and `pip install`,"),
            "{mixed:?}"
        );

        // The project's lockfile names its package manager.
        for (lock, purl, install) in [
            ("pnpm-lock.yaml", "pkg:npm/a@1", "pnpm install"),
            ("yarn.lock", "pkg:npm/a@1", "yarn install"),
            ("bun.lock", "pkg:npm/a@1", "bun install"),
            ("uv.lock", "pkg:pypi/a@1", "uv sync"),
            ("poetry.lock", "pkg:pypi/a@1", "poetry install"),
            ("pixi.lock", "pkg:pypi/a@1", "pixi install"),
            ("pixi.toml", "pkg:pypi/a@1", "pixi install"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(dir.path().join(lock), "").unwrap();
            let named = steps(&[purl], dir.path());
            assert!(
                named[2].contains(&format!("after every `{install}`,")),
                "{lock}: {named:?}"
            );
        }

        // pixi keeps its own environments beside another tool's venv: both
        // installs undo a patch.
        let both = tempfile::tempdir().unwrap();
        for file in ["uv.lock", "pixi.toml"] {
            std::fs::write(both.path().join(file), "").unwrap();
        }
        let named = steps(&["pkg:pypi/a@1"], both.path());
        assert!(
            named[2].contains("after every `pixi install` and `uv sync`,"),
            "{named:?}"
        );

        // A file pip installs from beside pixi's: pip fills the
        // interpreter on `PATH`, which the crawl reads too.
        let pip_too = tempfile::tempdir().unwrap();
        for file in ["requirements.txt", "pixi.toml"] {
            std::fs::write(pip_too.path().join(file), "").unwrap();
        }
        let named = steps(&["pkg:pypi/a@1"], pip_too.path());
        assert!(
            named[2].contains("after every `pip install` and `pixi install`,"),
            "{named:?}"
        );

        // No single install command: the step still says when to re-apply.
        let maven = steps(&["pkg:maven/g/a@1"], root);
        assert!(
            maven[2].contains("after every dependency install,"),
            "{maven:?}"
        );
    }

    /// Agent mode records only what an installed copy can take. A compiled
    /// conda build takes no PyPI patch, so its patch is left out with the
    /// reason; a pure-Python conda build, a wheel uv installed into the
    /// same environment, a package that is not installed and another
    /// ecosystem's patch are all kept.
    #[tokio::test]
    async fn patches_no_conda_build_takes_are_left_out_of_an_agent_run() {
        fn selection(purl: &str) -> PatchSearchResult {
            PatchSearchResult {
                uuid: "20000001-0000-4001-8001-000000000099".to_string(),
                purl: purl.to_string(),
                published_at: String::new(),
                description: String::new(),
                license: String::new(),
                tier: "free".to_string(),
                vulnerabilities: HashMap::new(),
            }
        }
        let tmp = tempfile::tempdir().unwrap();
        let project = tmp.path();
        std::fs::write(project.join("pixi.toml"), "[workspace]\n").unwrap();
        let prefix = project.join(".pixi").join("envs").join("default");
        std::fs::create_dir_all(prefix.join("conda-meta")).unwrap();
        let site = if cfg!(windows) {
            prefix.join("Lib").join("site-packages")
        } else {
            prefix.join("lib").join("python3.13").join("site-packages")
        };
        let install = |name: &str, version: &str, installer: &str, purelib: bool| {
            let dist = site.join(format!("{name}-{version}.dist-info"));
            std::fs::create_dir_all(&dist).unwrap();
            std::fs::write(
                dist.join("METADATA"),
                format!("Metadata-Version: 2.4\nName: {name}\nVersion: {version}\n"),
            )
            .unwrap();
            std::fs::write(dist.join("INSTALLER"), format!("{installer}\n")).unwrap();
            std::fs::write(
                dist.join("WHEEL"),
                format!("Wheel-Version: 1.0\nRoot-Is-Purelib: {purelib}\n"),
            )
            .unwrap();
        };
        install("pillow", "12.3.0", "conda", false);
        install("certifi", "2026.7.22", "conda", true);
        install("numpy", "2.4.4", "uv-pixi", false);

        let compiled = "pkg:pypi/pillow@12.3.0?artifact_id=cp313-cp313-manylinux_2_28_x86_64-whl";
        let kept = [
            "pkg:npm/minimist@1.2.2",
            "pkg:pypi/certifi@2026.7.22?artifact_id=py3-none-any-whl",
            "pkg:pypi/numpy@2.4.4?artifact_id=cp313-cp313-manylinux_2_28_x86_64-whl",
            "pkg:pypi/requests@2.33.1?artifact_id=py3-none-any-whl",
        ];
        let mut selected: Vec<PatchSearchResult> = kept.iter().map(|p| selection(p)).collect();
        selected.insert(2, selection(compiled));
        // The platform wheel's record of a release whose pure wheel's
        // record is kept: left out too (a conda build is never a platform
        // wheel), with nothing to report, since the package is patched.
        selected.insert(
            1,
            selection(
                "pkg:pypi/certifi@2026.7.22?artifact_id=cp313-cp313-manylinux_2_28_x86_64-whl",
            ),
        );
        let options = CrawlerOptions {
            cwd: project.to_path_buf(),
            global: false,
            global_prefix: None,
        };
        let (taken, refused) =
            leave_out_patches_no_conda_build_takes(selected, &options, true).await;
        let taken: Vec<&str> = taken.iter().map(|sr| sr.purl.as_str()).collect();
        assert_eq!(taken, kept);
        assert_eq!(refused.len(), 1, "{refused:?}");
        assert!(
            refused[0].starts_with("pkg:pypi/pillow@12.3.0")
                && refused[0].contains(CONDA_BUILD_NOT_PYPI_RELEASE)
                && refused[0].contains("compiled conda package"),
            "{refused:?}"
        );
    }

    #[test]
    fn next_steps_for_go_commit_the_replace_and_skip_the_reapply() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        assert_eq!(
            steps(&["pkg:golang/github.com/jackc/pgx/v5@v5.7.0"], root),
            [
                "Next steps:",
                "  1. Commit .socket/ and go.mod (or go.work) to keep the patches.",
            ]
        );
        // Beside another ecosystem the re-apply step is back.
        let both = steps(
            &["pkg:golang/example.com/m@v1.0.0", "pkg:gem/rack@2.2.3"],
            root,
        );
        assert_eq!(both.len(), 3, "{both:?}");
        assert!(
            both[2].contains("after every `bundle install`,"),
            "{both:?}"
        );

        // A manifest outside the default directory is named as it is.
        let elsewhere = next_steps(
            &["pkg:gem/rack@2.2.3"],
            &root.join("ops/patches"),
            root,
            false,
        );
        assert_eq!(
            elsewhere[1],
            "  1. Commit ops/patches/ to keep the patches."
        );
    }
}
