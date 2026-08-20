use clap::Args;
use regex::Regex;
use socket_patch_core::api::client::{
    build_proxy_fallback_client, get_api_client_with_overrides, is_fallback_candidate,
};
use socket_patch_core::api::ranking::{cmp_search_results, severity_order};
use socket_patch_core::api::types::{
    PatchResponse, PatchSearchResult, SearchResponse, VulnerabilityResponse,
};
use socket_patch_core::crawlers::fuzzy_match::fuzzy_match_packages;
use socket_patch_core::crawlers::{CrawlerOptions, Ecosystem};
use socket_patch_core::manifest::operations::{read_manifest, write_manifest};
use socket_patch_core::manifest::schema::{
    PatchFileInfo, PatchManifest, PatchRecord, VulnerabilityInfo,
};
use socket_patch_core::patch::apply::select_installed_variants;
use socket_patch_core::telemetry::{track_patch_fetch_failed, track_patch_fetched};
use socket_patch_core::utils::purl::{is_purl, normalize_purl, strip_purl_qualifiers};
use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};

use crate::args::{apply_env_toggles, GlobalArgs};
use crate::ecosystem_dispatch::{
    crawl_all_ecosystems, find_packages_for_rollback, partition_purls,
};
use crate::output::{confirm, select_one, SelectError};

/// Best-effort ecosystem extractor for a `pkg:<eco>/...` PURL. Used as
/// the telemetry `ecosystem` field. Returns an empty string when the
/// PURL is malformed — telemetry events should never block on input
/// validation.
fn ecosystem_from_purl(purl: &str) -> String {
    purl.strip_prefix("pkg:")
        .and_then(|rest| rest.split('/').next())
        .unwrap_or("")
        .to_string()
}

/// Per-patch outcome reported in the JSON output of `download_and_apply_patches`.
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

/// Compute the `(status, exit_code)` pair for a download+apply run.
///
/// A non-zero exit code must ALWAYS pair with a non-`success` status:
/// both are derived from the same predicate here so a JSON consumer
/// reading `status` and a shell reading `$?` can never disagree. The
/// historical bug was a `status` of `success` (keyed only on download
/// failures) sitting next to an exit code of `1` produced by a failed
/// *apply* step.
fn run_outcome(patches_failed: bool, apply_failed: bool) -> (&'static str, i32) {
    if patches_failed || apply_failed {
        ("partial_failure", 1)
    } else {
        ("success", 0)
    }
}

/// Classify what `download_and_apply_patches` will do to a given PURL based on
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
fn severity_rank(severity: &str) -> u8 {
    // severity_order: 0 = critical … 4 = unknown. Flip it so 4 = critical
    // and unknown lands at 0, which callers below treat as "no signal".
    4 - severity_order(Some(severity))
}

/// Return the highest-severity label from a vulnerabilities map.
/// Returns `None` when the map is empty or every entry's severity is
/// unrecognized.
fn max_vuln_severity(vulns: &HashMap<String, VulnerabilityResponse>) -> Option<String> {
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
fn patch_event_metadata(patch: &PatchResponse) -> serde_json::Value {
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

/// Merge a metadata object (from [`patch_event_metadata`]) into a
/// per-patch action record. Convenience wrapper that handles the
/// unwrap of `Value::Object`.
fn merge_metadata(record: &mut serde_json::Value, meta: serde_json::Value) {
    if let (Some(record_obj), serde_json::Value::Object(meta_obj)) = (record.as_object_mut(), meta)
    {
        for (k, v) in meta_obj {
            record_obj.insert(k, v);
        }
    }
}

/// Print a `serde_json::Value` as pretty JSON to stdout.
fn print_json(v: &serde_json::Value) {
    println!(
        "{}",
        serde_json::to_string_pretty(v).expect("serializing an in-memory JSON value cannot fail")
    );
}

/// Truncate `s` to at most `limit` displayed characters, appending an
/// ellipsis when it was longer (so the result is never wider than
/// `limit`). Operates on `char` boundaries, NOT bytes: a byte-index slice
/// like `&s[..n]` panics when `n` lands in the middle of a multi-byte
/// UTF-8 sequence, and patch descriptions come straight from the API and
/// routinely contain non-ASCII text.
pub(crate) fn truncate_with_ellipsis(s: &str, limit: usize) -> String {
    if s.chars().count() <= limit {
        s.to_string()
    } else {
        let head: String = s.chars().take(limit.saturating_sub(3)).collect();
        format!("{head}...")
    }
}

/// Short, display-only prefix of a UUID for log lines. Returns
/// the first 8 bytes when they fall on a char boundary, otherwise the
/// whole string. A naive `&uuid[..8]` panics on a malformed/short UUID in
/// the manifest (out-of-bounds or mid-codepoint); this never does. Pure
/// so the no-panic guarantee is unit-testable.
pub(crate) fn short_uuid(uuid: &str) -> &str {
    uuid.get(..8).unwrap_or(uuid)
}

/// Build a no-results JSON envelope with the given status code. Used in
/// the `no_packages`, `no_match`, and `not_found` branches of `get`,
/// which all share the same `{status, counts, patches: []}` shape.
fn empty_result_json(status: &str) -> serde_json::Value {
    serde_json::json!({
        "status": status,
        "found": 0,
        "downloaded": 0,
        "applied": 0,
        "patches": [],
    })
}

/// Fire a `patch_fetch_failed` telemetry event and surface the error to
/// the caller (JSON envelope or stderr). Returns `1` so callers can
/// just `return report_fetch_failure(...).await;`.
async fn report_fetch_failure(
    identifier: &str,
    error: impl std::fmt::Display,
    fallback_to_proxy: bool,
    api_token: Option<&str>,
    org_slug: Option<&str>,
    json: bool,
) -> i32 {
    let msg = error.to_string();
    track_patch_fetch_failed(identifier, &msg, fallback_to_proxy, api_token, org_slug).await;
    report_error(json, msg);
    1
}

/// Report an error to the caller: a `{status, error}` envelope on
/// stdout when `json` is true, otherwise a plain `Error: ...` on stderr.
fn report_error(json: bool, message: impl std::fmt::Display) {
    let message = message.to_string();
    if json {
        print_json(&serde_json::json!({"status": "error", "error": message}));
    } else {
        eprintln!("Error: {message}");
    }
}

/// A blob hash must be a SHA-256 hex string — the same shape `fetch_blob`
/// enforces before splicing a hash into a URL. Enforced here because the
/// hash comes from an untrusted API response and is used as a filesystem
/// path component: anything else (`../../x`, an absolute path) would
/// escape the blobs directory via `Path::join`.
pub(crate) fn is_valid_blob_hash(hash: &str) -> bool {
    hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Decode a base64 string and write it to `blobs_dir/hash`. Returns a
/// formatted error string referencing `file_path` and `label` on failure.
async fn write_blob_entry(
    blobs_dir: &Path,
    b64: &str,
    hash: &str,
    file_path: &str,
    label: &str,
) -> Result<(), String> {
    if !is_valid_blob_hash(hash) {
        return Err(format!(
            "Refusing to write {label} for {file_path}: invalid blob hash {hash:?} (expected 64 hex chars)"
        ));
    }
    let decoded =
        base64_decode(b64).map_err(|e| format!("Failed to decode {label} for {file_path}: {e}"))?;
    tokio::fs::write(blobs_dir.join(hash), &decoded)
        .await
        .map_err(|e| format!("Failed to write {label} for {file_path}: {e}"))
}

/// Write every after/before blob for `patch` into `blobs_dir`, reporting
/// per-file failures on stderr unless `quiet` is set. Returns `Err(())`
/// on the first failure; callers handle the bookkeeping that follows.
async fn write_all_patch_blobs(
    blobs_dir: &Path,
    patch: &PatchResponse,
    quiet: bool,
) -> Result<(), ()> {
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
                if let Err(e) = write_blob_entry(blobs_dir, blob, hash, file_path, label).await {
                    if !quiet {
                        eprintln!("  [error] {e}");
                    }
                    return Err(());
                }
            }
        }
    }
    Ok(())
}

/// Convert the API-shaped vulnerability map on `PatchResponse` into the
/// serialization-shaped map stored in the manifest.
fn vulnerabilities_for_manifest(
    vulns: &HashMap<String, VulnerabilityResponse>,
) -> HashMap<String, VulnerabilityInfo> {
    vulns
        .iter()
        .map(|(id, v)| {
            (
                id.clone(),
                VulnerabilityInfo {
                    cves: v.cves.clone(),
                    summary: v.summary.clone(),
                    severity: v.severity.clone(),
                    description: v.description.clone(),
                },
            )
        })
        .collect()
}

/// Build the `PatchRecord` that will be inserted into the manifest for
/// `patch`. `files` is the (purl-keyed) before/after-hash map the
/// caller built — semantics for what counts as a "patchable file" differ
/// between the get and download flows, so the caller owns that decision.
fn build_patch_record(patch: &PatchResponse, files: HashMap<String, PatchFileInfo>) -> PatchRecord {
    PatchRecord {
        uuid: patch.uuid.clone(),
        exported_at: patch.published_at.clone(),
        files,
        vulnerabilities: vulnerabilities_for_manifest(&patch.vulnerabilities),
        description: patch.description.clone(),
        license: patch.license.clone(),
        tier: patch.tier.clone(),
    }
}

/// Build a file map keyed by path, keeping only files that carry BOTH
/// hashes — the rule used ONLY for installed-distribution matching in
/// [`filter_to_installed_releases`]. New files (no `beforeHash`) can
/// neither identify nor disqualify an installed variant, so they are
/// excluded here; [`select_installed_variants`] then discriminates on a
/// non-empty `beforeHash`. Do NOT use this to build manifest records —
/// see [`files_for_manifest`], which retains patch-added files.
fn files_with_both_hashes(patch: &PatchResponse) -> HashMap<String, PatchFileInfo> {
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

/// Build the manifest-shaped `files` map from a fetched patch view,
/// keeping EVERY file the patch touches — including net-new files the
/// patch ADDS, which carry an `afterHash` but no `beforeHash`. A new
/// file is recorded with an empty-string `beforeHash` sentinel, the same
/// convention `save_and_apply_patch`'s by-uuid path relies on: apply
/// treats an empty `beforeHash` as "create this file" and
/// [`select_installed_variants`] treats it as non-discriminating.
///
/// This is the shared record-building rule for the scan/download/vendor
/// flows AND the single-uuid apply path, so `get <uuid>` and
/// `scan`/`apply`/`vendor` all record and write the same set of files.
/// The previous both-hashes-only rule silently dropped every added file,
/// e.g. the whole-crate cargo export where ALL files lack a `beforeHash`
/// (recorded `files:{}` → reported `applied:1` while writing nothing) and
/// a gem patch's genuinely-new runtime-guard file.
fn files_for_manifest(patch: &PatchResponse) -> HashMap<String, PatchFileInfo> {
    let mut files = HashMap::new();
    for (file_path, file_info) in &patch.files {
        if let Some(after) = &file_info.after_hash {
            files.insert(
                file_path.clone(),
                PatchFileInfo {
                    before_hash: file_info.before_hash.clone().unwrap_or_default(),
                    after_hash: after.clone(),
                },
            );
        }
    }
    files
}

/// `(purl, manifest record)` from a fetched patch view — retains
/// patch-added new files via [`files_for_manifest`].
pub(crate) fn record_from_patch_response(patch: &PatchResponse) -> (String, PatchRecord) {
    (
        patch.purl.clone(),
        build_patch_record(patch, files_for_manifest(patch)),
    )
}

#[derive(Args)]
pub struct GetArgs {
    /// Patch identifier (UUID, CVE ID, GHSA ID, PURL, or package name).
    pub identifier: String,

    #[command(flatten)]
    pub common: GlobalArgs,

    /// Force identifier to be treated as a patch UUID.
    #[arg(long, default_value_t = false)]
    pub id: bool,

    /// Force identifier to be treated as a CVE ID.
    #[arg(long, default_value_t = false)]
    pub cve: bool,

    /// Force identifier to be treated as a GHSA ID.
    #[arg(long, default_value_t = false)]
    pub ghsa: bool,

    /// Force identifier to be treated as a package name.
    #[arg(short = 'p', long = "package", default_value_t = false)]
    pub package: bool,

    /// Download patch without applying it.
    ///
    /// `value_parser = parse_bool_flag` matches the `GlobalArgs` bool flags:
    /// clap's default bool parser accepts only the literal strings
    /// `true`/`false` from the env binding, so `SOCKET_SAVE_ONLY=1` (or an
    /// exported-but-empty `SOCKET_SAVE_ONLY=`) aborted every `get`
    /// invocation.
    #[arg(
        long = "save-only",
        alias = "no-apply",
        env = "SOCKET_SAVE_ONLY",
        default_value_t = false,
        value_parser = crate::args::parse_bool_flag,
    )]
    pub save_only: bool,

    /// Apply patch immediately without saving to .socket folder.
    ///
    /// `value_parser = parse_bool_flag`: same env-crash fix as `--save-only`
    /// above — and `SOCKET_ONE_OFF` is shared with `rollback --one-off`,
    /// which already parses boolishly; the two must not diverge.
    #[arg(
        long = "one-off",
        env = "SOCKET_ONE_OFF",
        default_value_t = false,
        value_parser = crate::args::parse_bool_flag,
    )]
    pub one_off: bool,

    /// Download patches for every release/distribution variant of a
    /// matched package, not just the one(s) matching the locally-
    /// installed distribution. Affects ecosystems with per-release
    /// variants — PyPI (wheel/sdist via `artifact_id`), RubyGems
    /// (`platform`), and Maven (`classifier`). Off by default: only the
    /// patch(es) for the installed dist are fetched. Also disables the
    /// coarse installed-VERSION narrowing of CVE/GHSA fan-outs (see
    /// `--mode`): every version's patch is fetched, installed or not.
    #[arg(
        long = "all-releases",
        env = "SOCKET_ALL_RELEASES",
        default_value_t = false,
        value_parser = crate::args::parse_bool_flag,
    )]
    pub all_releases: bool,

    /// How to consume the patch(es) — the same three modes as `scan`:
    /// `agent` (default; record in `.socket/manifest.json` + blobs and
    /// apply in place), `hosted` (rewrite lockfiles so the patched deps
    /// resolve to Socket's hosted patch server; no manifest, no blobs —
    /// state lives in the redirect ledger), or `vendored` (record in the
    /// manifest, then commit patched artifacts under `.socket/vendor/` and
    /// rewire the lockfile). Hosted/vendored runs produce the same on-disk
    /// result as `scan --mode hosted|vendored` selecting the same patch.
    /// No env binding, matching `scan --mode`.
    #[arg(long = "mode", value_enum)]
    pub mode: Option<super::scan::ScanMode>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum IdentifierType {
    Uuid,
    Cve,
    Ghsa,
    Purl,
    Package,
}

impl fmt::Display for IdentifierType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdentifierType::Uuid => write!(f, "UUID"),
            IdentifierType::Cve => write!(f, "CVE"),
            IdentifierType::Ghsa => write!(f, "GHSA"),
            IdentifierType::Purl => write!(f, "PURL"),
            IdentifierType::Package => write!(f, "package name"),
        }
    }
}

fn detect_identifier_type(identifier: &str) -> Option<IdentifierType> {
    let uuid_re = Regex::new(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
        .expect("hardcoded UUID regex must compile");
    let cve_re = Regex::new(r"(?i)^CVE-\d{4}-\d+$").expect("hardcoded CVE regex must compile");
    let ghsa_re = Regex::new(r"(?i)^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$")
        .expect("hardcoded GHSA regex must compile");

    if uuid_re.is_match(identifier) {
        Some(IdentifierType::Uuid)
    } else if cve_re.is_match(identifier) {
        Some(IdentifierType::Cve)
    } else if ghsa_re.is_match(identifier) {
        Some(IdentifierType::Ghsa)
    } else if is_purl(identifier) {
        Some(IdentifierType::Purl)
    } else {
        None
    }
}

/// Select one patch per PURL from available patches.
///
/// Within a PURL, candidates are ranked by [`cmp_search_results`]: merged
/// patches first, then by severity (critical → low), then most recently
/// published. `tier` is an access filter here, not a ranking signal — a
/// free critical patch outranks a paid low one.
///
/// - Users with paid access: auto-select the top-ranked patch per PURL.
/// - Free users with one patch: auto-select it.
/// - Free users with multiple patches: interactive selection via dialoguer,
///   with the options presented in ranked order so the best patch is both
///   the highlighted default and what a non-TTY run auto-picks.
/// - JSON mode with multiple free patches: returns an error with options list.
///
/// The returned vec is sorted by PURL. It is assembled from a `HashMap`,
/// whose iteration order is randomized per process; without the sort the
/// download order — and every `--json` array derived from it — would differ
/// run to run.
///
/// Returns `Ok(selected_patches)` or `Err(exit_code)` if selection fails.
pub(crate) fn select_patches(
    patches: &[PatchSearchResult],
    can_access_paid: bool,
    is_json: bool,
) -> Result<Vec<PatchSearchResult>, i32> {
    // Group accessible patches by PURL
    let mut by_purl: HashMap<String, Vec<&PatchSearchResult>> = HashMap::new();
    for p in patches {
        if p.tier == "free" || can_access_paid {
            by_purl.entry(p.purl.clone()).or_default().push(p);
        }
    }

    let mut selected = Vec::new();

    // Iterate PURLs in a fixed order too: the interactive prompts below are
    // presented to a human one after another, and a randomized sequence
    // would be disorienting across otherwise identical runs.
    let mut groups: Vec<(String, Vec<&PatchSearchResult>)> = by_purl.into_iter().collect();
    groups.sort_by(|a, b| a.0.cmp(&b.0));

    for (purl, mut group) in groups {
        // Canonical best-first order (see `api::ranking`). The API client
        // already sorts each response, but this call site merges results
        // across several queries, so re-sort the assembled group.
        group.sort_by(|a, b| cmp_search_results(a, b));

        if can_access_paid {
            // Take the top-ranked patch. Note this is NOT "prefer paid":
            // tier only breaks ties once merge status, severity and recency
            // have all tied.
            selected.push(group[0].clone());
        } else if group.len() == 1 {
            selected.push(group[0].clone());
        } else {
            // Free user with multiple patches: interactive selection
            let options: Vec<String> = group
                .iter()
                .map(|p| {
                    let vuln_summary: Vec<String> = p
                        .vulnerabilities
                        .iter()
                        .map(|(id, v)| {
                            if v.cves.is_empty() {
                                id.clone()
                            } else {
                                v.cves.join(", ")
                            }
                        })
                        .collect();
                    let vulns = if vuln_summary.is_empty() {
                        String::new()
                    } else {
                        format!(" (fixes: {})", vuln_summary.join(", "))
                    };
                    let desc = truncate_with_ellipsis(&p.description, 60);
                    format!("{} [{}]{} - {}", p.uuid, p.tier, vulns, desc)
                })
                .collect();

            match select_one(
                &format!("Multiple patches available for {purl}. Select one:"),
                &options,
                is_json,
            ) {
                Ok(idx) => {
                    selected.push(group[idx].clone());
                }
                Err(SelectError::JsonModeNeedsExplicit) => {
                    let options_json: Vec<serde_json::Value> = group
                        .iter()
                        .map(|p| {
                            let vulns: Vec<serde_json::Value> = p
                                .vulnerabilities
                                .iter()
                                .map(|(id, v)| {
                                    serde_json::json!({
                                        "id": id,
                                        "cves": v.cves,
                                        "severity": v.severity,
                                        "summary": v.summary,
                                    })
                                })
                                .collect();
                            serde_json::json!({
                                "uuid": p.uuid,
                                "tier": p.tier,
                                "published_at": p.published_at,
                                "description": p.description,
                                "vulnerabilities": vulns,
                            })
                        })
                        .collect();
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "status": "selection_required",
                            "error": format!("Multiple patches available for {purl}. Re-run with the chosen UUID as the identifier (`socket-patch get <uuid>`) to select one."),
                            "purl": purl,
                            "options": options_json,
                        }))
                        .expect("serializing an in-memory JSON value cannot fail")
                    );
                    return Err(1);
                }
                Err(SelectError::Cancelled) => {
                    eprintln!("Selection cancelled.");
                    return Err(0);
                }
            }
        }
    }

    // PURL-sorted by construction: `groups` was sorted above and this loop
    // pushes at most one entry per group.
    Ok(selected)
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
    pub org: Option<String>,
    pub save_only: bool,
    pub global: bool,
    pub global_prefix: Option<PathBuf>,
    pub json: bool,
    pub silent: bool,
    /// `--download-mode` value forwarded to the apply step.
    pub download_mode: String,
    /// API client overrides — propagates the caller's CLI flags
    /// (`--api-url`, `--api-token`, `--proxy-url`) into the nested API
    /// client constructed here. Without this, `download_and_apply_patches`
    /// would only honor env vars and ignore the user's flags.
    pub api_overrides: socket_patch_core::api::client::ApiClientEnvOverrides,
    /// When `false` (the default — narrow), a PyPI package with multiple
    /// release variants (`?artifact_id=...`) is filtered down to the one
    /// matching the locally-installed distribution before download. When
    /// `true` (`--all-releases`), every variant is downloaded. No effect
    /// on ecosystems without per-release artifact_id variants.
    pub all_releases: bool,
    /// `--strict` forwarded to the nested apply (a beforeHash mismatch
    /// fails instead of warn-and-overwrite).
    pub strict: bool,
    /// `--ecosystems` forwarded to the nested apply. Without this the
    /// nested apply ran UNSCOPED over the whole manifest, so
    /// `scan --ecosystems gem --sync` could mutate other ecosystems'
    /// packages the user had explicitly filtered out.
    pub ecosystems: Option<Vec<String>>,
    /// Persist downloaded blob content into `.socket/blobs` (the apply
    /// flows need it for later hook/rollback runs). Vendor flows pass
    /// `false`: their patch content is staged in memory and the committed
    /// artifact is the patch — nothing should land in `.socket/blobs`.
    pub persist_blobs: bool,
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
/// Returns the kept patches plus any warnings to surface to the caller
/// (also printed to stderr here, in human mode). With `--all-releases`
/// set this is a verbatim pass-through.
async fn filter_to_installed_releases(
    selected: &[PatchSearchResult],
    params: &DownloadParams,
    api_client: &socket_patch_core::api::client::ApiClient,
) -> (Vec<PatchSearchResult>, Vec<String>) {
    if params.all_releases {
        return (selected.to_vec(), Vec::new());
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

    if multi.is_empty() {
        return (kept, warnings);
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
    // All collected PURLs are PyPI; no ecosystem filter needed.
    let partitioned = partition_purls(&all_qualified, None);
    let crawler_options = CrawlerOptions {
        cwd: params.cwd.clone(),
        global: params.global,
        global_prefix: params.global_prefix.clone(),
    };
    let paths = find_packages_for_rollback(&partitioned, &crawler_options, true).await;

    for (base, variants) in multi {
        // Any variant's resolved path works — they all map to the same
        // installed package directory.
        let pkg_path = variants.iter().find_map(|s| paths.get(&s.purl)).cloned();
        let Some(pkg_path) = pkg_path else {
            // Not installed: cannot determine the relevant release. Keep
            // every variant so the patch is still obtainable.
            warnings.push(format!(
                "{base} is not installed locally; keeping all {} release variant(s).",
                variants.len()
            ));
            kept.extend(variants);
            continue;
        };

        // Fetch each variant's file hashes (the view carries them) so we
        // can hash-match against the installed distribution.
        let mut candidates: Vec<(String, HashMap<String, PatchFileInfo>)> = Vec::new();
        for s in &variants {
            // org slug is already stored in the client.
            match api_client.fetch_patch(None, &s.uuid).await {
                Ok(Some(patch)) => {
                    candidates.push((s.purl.clone(), files_with_both_hashes(&patch)));
                }
                // On a fetch error/miss, keep the variant so the main
                // download loop can record the failure as it would today.
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
        let matched = select_installed_variants(&pkg_path, &refs).await;
        if matched.is_empty() {
            // Installed, but no variant matches the on-disk bytes. Fall
            // back to broad rather than silently dropping a package the
            // user asked about.
            warnings.push(format!(
                "No release variant of {base} matches the installed distribution; keeping all {} variant(s).",
                variants.len()
            ));
            kept.extend(variants);
        } else {
            let winners: std::collections::HashSet<String> =
                matched.iter().map(|&i| candidates[i].0.clone()).collect();
            kept.extend(variants.into_iter().filter(|s| winners.contains(&s.purl)));
        }
    }

    if !params.json && !params.silent {
        for w in &warnings {
            eprintln!("  [note] {w}");
        }
    }
    (kept, warnings)
}

/// Does this purl carry an exact version (`pkg:type/name@version`)? An
/// exact-versioned PURL identifier is exempt from the coarse installed-
/// version narrowing, like a UUID: the user named the version explicitly.
/// npm scope `@`s don't count (`pkg:npm/@scope/name` is versionless — the
/// candidate "version" after the last `@` still contains a `/`).
fn purl_has_version(purl: &str) -> bool {
    let stripped = strip_purl_qualifiers(purl);
    stripped
        .strip_prefix("pkg:")
        .and_then(|rest| rest.split_once('/'))
        .and_then(|(_, coord)| coord.rsplit_once('@'))
        .is_some_and(|(head, version)| {
            !head.is_empty() && !version.is_empty() && !version.contains('/')
        })
}

/// Outcome of the coarse installed-VERSION narrowing over a CVE/GHSA/PURL
/// search fan-out (see [`filter_to_installed_purls`]).
struct InstalledNarrowing {
    /// Results whose package version is present (kept for selection).
    kept: Vec<PatchSearchResult>,
    /// Contract-shaped skip records for the filtered-out results
    /// (`action: "skipped"` + `errorCode`), purl-sorted.
    skip_records: Vec<serde_json::Value>,
    /// Run-level `(code, detail)` warnings (PnP layout refusals), for both
    /// stderr and the JSON `warnings[]`.
    warnings: Vec<(String, String)>,
}

/// Narrow a search fan-out to the package VERSIONS actually present, so a
/// GHSA with patches for dozens of versions acts only on what this system
/// runs — the coarse layer above [`filter_to_installed_releases`]'s
/// per-release variant narrowing (which still runs later, unchanged).
///
/// Presence evidence per result purl (compared on
/// `normalize_purl(strip_purl_qualifiers(..))` — API purls are
/// percent-encoded/qualified, crawler purls literal):
/// * installed on disk — `find_packages_for_rollback` over the deduped base
///   purls (the qualified-aware resolver; memory invariant);
/// * already tracked in the manifest — the user opted this purl in earlier,
///   and updating its record must keep working on hosts without an
///   installed copy (CI manifest-maintenance);
/// * hosted/vendored modes only: resolved in the project lockfile(s)
///   (hosted rewrites the lock; vendored auto-fetches pristine) or claimed
///   by the vendor ledger (fresh-clone re-vendor) — mirroring scan's
///   lockfile/vendored-ledger discovery supplements, including their
///   global-scan gate.
///
/// PnP layouts are surfaced, never silently misreported: yarn PnP packages
/// are structurally unpatchable in every mode (skip records carry
/// `yarn_pnp_unsupported`, not a false "not installed"); pnpm PnP skips
/// carry `pnpm_pnp_unsupported` except in hosted mode, which KEEPS them —
/// the refusal's own remedy text blesses the hosted lockfile rewrite.
///
/// Callers exempt UUID identifiers, exact-versioned PURLs, `--save-only`
/// (record-only has no installation precondition), `--all-releases`, and
/// the package-name path (already installed-derived).
async fn filter_to_installed_purls(
    accessible: &[PatchSearchResult],
    common: &GlobalArgs,
    mode: super::scan::ScanMode,
) -> InstalledNarrowing {
    use socket_patch_core::vendor::lock_inventory;
    use std::collections::HashSet;

    let canon = |p: &str| normalize_purl(strip_purl_qualifiers(p)).into_owned();

    // Deduped base purls, probed against the installed tree. The resolver
    // keys its result by the purls we pass, so canonicalize the found keys
    // the same way as the membership probes below.
    let bases: Vec<String> = {
        let mut seen = HashSet::new();
        accessible
            .iter()
            .map(|p| strip_purl_qualifiers(&p.purl).to_string())
            .filter(|b| seen.insert(b.clone()))
            .collect()
    };
    let partitioned = partition_purls(&bases, None);
    let crawler_options = CrawlerOptions {
        cwd: common.cwd.clone(),
        global: common.global,
        global_prefix: common.global_prefix.clone(),
    };
    let found = find_packages_for_rollback(&partitioned, &crawler_options, true).await;
    let mut present: HashSet<String> = found.keys().map(|k| canon(k)).collect();

    // Manifest membership counts as presence (read-only probe: a corrupt
    // manifest degrades to "no extension" here — the download path's
    // fail-closed read still guards every write).
    if let Ok(Some(manifest)) = read_manifest(&common.resolved_manifest_path()).await {
        present.extend(manifest.patches.keys().map(|k| canon(k)));
    }

    // Lockfile + vendor-ledger supplements (scan's discovery gate: never on
    // global scans, which target the machine tree, not this project).
    let mut pnp_diags: Vec<lock_inventory::UnsupportedNpmLayout> = Vec::new();
    if !common.global && common.global_prefix.is_none() {
        let (entries, unsupported) = lock_inventory::inventory_project_diagnosed(&common.cwd).await;
        pnp_diags = unsupported;
        if mode != super::scan::ScanMode::Agent {
            present.extend(entries.iter().map(|e| canon(&e.purl)));
            if let Ok(state) = socket_patch_core::vendor::load_state(&common.cwd).await {
                present.extend(state.entries.values().map(|e| canon(&e.base_purl)));
            }
        }
    }

    let warnings = super::scan::unsupported_layout_warnings(&pnp_diags);
    let pnp_yarn = pnp_diags
        .iter()
        .any(|d| d.code == "vendor_yarn_berry_unsupported");
    let pnp_pnpm = pnp_diags
        .iter()
        .any(|d| d.code == "vendor_pnpm_pnp_unsupported");

    let mut out = InstalledNarrowing {
        kept: Vec::new(),
        skip_records: Vec::new(),
        warnings,
    };
    for result in accessible {
        if present.contains(&canon(&result.purl)) {
            out.kept.push(result.clone());
            continue;
        }
        // An ecosystem THIS binary has no crawler for (a newer patch
        // server's `pkg:<type>/`) was silently absent from the probe —
        // absence carries no information there (the same fail-safe as
        // scan's prune GC), so keep the result instead of claiming
        // "not installed" about a package we cannot see.
        if !crate::ecosystem_dispatch::crawl_covers_purl(&result.purl) {
            out.kept.push(result.clone());
            continue;
        }
        let is_npm = strip_purl_qualifiers(&result.purl).starts_with("pkg:npm/");
        let error_code = if is_npm && pnp_yarn {
            // Structurally invisible, in EVERY mode — never claim "not
            // installed" when the truth is "cannot see".
            "yarn_pnp_unsupported"
        } else if is_npm && pnp_pnpm {
            if mode == super::scan::ScanMode::Hosted {
                // The pnpm PnP refusal's own remedy is the hosted lockfile
                // rewrite — keep the result and let the rewriter's per-dep
                // confirmation decide.
                out.kept.push(result.clone());
                continue;
            }
            "pnpm_pnp_unsupported"
        } else {
            "package_not_installed"
        };
        out.skip_records.push(serde_json::json!({
            "purl": result.purl, "uuid": result.uuid,
            "action": "skipped", "errorCode": error_code,
        }));
    }
    out.skip_records
        .sort_by(|a, b| a["purl"].as_str().cmp(&b["purl"].as_str()));
    out
}

/// Fold the coarse-narrowing skip records + PnP warnings into a get JSON
/// envelope: they were "found" by the search and skipped before download,
/// mirroring scan's vendored/not-installed fold. Warnings land as strings
/// (get's `warnings[]` is a string array — unlike scan's `{code, detail}`
/// objects) with the stable code prefixed for greppability.
fn fold_narrowing_into_result(
    result: &mut serde_json::Value,
    skip_records: &[serde_json::Value],
    warnings: &[(String, String)],
) {
    let Some(obj) = result.as_object_mut() else {
        return;
    };
    // Only success-shaped envelopes carry a patches[] array to fold into —
    // error envelopes ({status, error}) keep their minimal shape.
    if !skip_records.is_empty() && obj.get("patches").and_then(|p| p.as_array()).is_some() {
        let n = skip_records.len() as u64;
        for key in ["found", "skipped"] {
            let bumped = obj.get(key).and_then(|v| v.as_u64()).unwrap_or(0) + n;
            obj.insert(key.to_string(), serde_json::json!(bumped));
        }
        if let Some(patches) = obj.get_mut("patches").and_then(|p| p.as_array_mut()) {
            patches.extend(skip_records.iter().cloned());
        }
    }
    if !warnings.is_empty() {
        let mut merged: Vec<String> = obj
            .get("warnings")
            .and_then(|w| w.as_array())
            .map(|w| {
                w.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        merged.extend(
            warnings
                .iter()
                .map(|(code, detail)| format!("({code}) {detail}")),
        );
        obj.insert("warnings".to_string(), serde_json::json!(merged));
    }
}

/// The API-client overrides for a download run: the caller's CLI flags with
/// the override org slug defaulted to `--org` when none was given.
///
/// Shared by the client built here AND by the nested `apply` step, which
/// constructs its own client and must resolve to the same endpoint/token —
/// see [`run_nested_apply`].
fn resolved_api_overrides(
    params: &DownloadParams,
) -> socket_patch_core::api::client::ApiClientEnvOverrides {
    let mut overrides = params.api_overrides.clone();
    if overrides.org_slug.is_none() {
        overrides.org_slug = params.org.clone();
    }
    overrides
}

/// Build the API client for a download run.
async fn api_client_for(params: &DownloadParams) -> socket_patch_core::api::client::ApiClient {
    get_api_client_with_overrides(resolved_api_overrides(params))
        .await
        .0
}

/// Download and apply a set of selected patches.
///
/// Used by both `get` and `scan` commands. Returns (exit_code, json_result).
/// Download patches and their blobs WITHOUT touching the manifest, and
/// return the fetched records keyed by purl — the `scan --vendor
/// --detached` download phase, where the vendor ledger (not the manifest)
/// carries the records. Honors the same installed-release narrowing as
/// [`download_and_apply_patches`]. A purl already vendored DETACHED at the
/// selected uuid skips the network fetch and reuses the ledger's embedded
/// record, so idempotent re-runs stay cheap (mirrors what
/// `decide_patch_action` does for the manifest-tracked flow).
pub(crate) async fn download_patch_records(
    selected: &[PatchSearchResult],
    params: &DownloadParams,
) -> (i32, serde_json::Value, HashMap<String, PatchRecord>) {
    let api_client = api_client_for(params).await;

    let socket_dir = params
        .manifest_path
        .parent()
        .unwrap_or(Path::new("."))
        .to_path_buf();
    let blobs_dir = socket_dir.join("blobs");
    if params.persist_blobs {
        if let Err(e) = tokio::fs::create_dir_all(&blobs_dir).await {
            let err = format!("Failed to create blobs directory: {}", e);
            report_error(params.json, &err);
            return (
                1,
                serde_json::json!({"status": "error", "error": err}),
                HashMap::new(),
            );
        }
    }

    let (selected, narrow_warnings) =
        filter_to_installed_releases(selected, params, &api_client).await;

    let vendor_state = socket_patch_core::vendor::load_state(&params.cwd)
        .await
        .unwrap_or_default();

    let mut records: HashMap<String, PatchRecord> = HashMap::new();
    let mut downloaded = 0usize;
    let mut skipped = 0usize;
    let mut failed = 0usize;
    let mut patch_records_json: Vec<serde_json::Value> = Vec::new();

    for search_result in &selected {
        // Idempotency: a detached entry already at this uuid carries its
        // own record — no view fetch needed.
        let existing =
            socket_patch_core::vendor::lookup_entry(&vendor_state.entries, &search_result.purl)
                .filter(|e| e.detached && e.uuid == search_result.uuid);
        if let Some(record) = existing.and_then(|e| e.record.clone()) {
            if !params.json && !params.silent {
                eprintln!("  [skip] {} (already vendored)", search_result.purl);
            }
            patch_records_json.push(serde_json::json!({
                "purl": search_result.purl,
                "uuid": search_result.uuid,
                "action": "skipped",
            }));
            records.insert(search_result.purl.clone(), record);
            skipped += 1;
            continue;
        }

        // org slug is already stored in the client.
        match api_client.fetch_patch(None, &search_result.uuid).await {
            Ok(Some(patch)) => {
                // Record every file the patch touches, added files
                // included (empty-beforeHash sentinel); see
                // `files_for_manifest`.
                let files = files_for_manifest(&patch);
                // GUARDRAIL: a patch that yields NO recordable files
                // cannot be vendored — recording an empty `files` map and
                // reporting the purl as vendored would claim protection
                // while writing nothing. Fail loudly instead.
                if files.is_empty() {
                    // Errors are exempt from --silent ("errors only");
                    // JSON runs carry them in the envelope instead.
                    if !params.json {
                        eprintln!(
                            "  [fail] {} (patch has no applicable files)",
                            search_result.purl
                        );
                    }
                    failed += 1;
                    patch_records_json.push(serde_json::json!({
                        "purl": patch.purl,
                        "uuid": patch.uuid,
                        "action": "failed",
                        "error": "patch has no applicable files",
                    }));
                    continue;
                }
                // Blob failures are errors: only JSON mode suppresses the
                // per-file detail line (the envelope carries the error).
                let quiet = params.json;
                // Vendor flows keep blob content in memory (the vendor
                // step re-fetches what it needs); persisting blobs here
                // would litter .socket/blobs for no consumer.
                if params.persist_blobs
                    && write_all_patch_blobs(&blobs_dir, &patch, quiet)
                        .await
                        .is_err()
                {
                    failed += 1;
                    patch_records_json.push(serde_json::json!({
                        "purl": patch.purl,
                        "uuid": patch.uuid,
                        "action": "failed",
                        "error": "Blob decode or write failed",
                    }));
                    continue;
                }
                if !params.json && !params.silent {
                    eprintln!("  [fetch] {}", patch.purl);
                }
                let mut record_json = serde_json::json!({
                    "purl": patch.purl,
                    "uuid": patch.uuid,
                    "action": "downloaded",
                });
                merge_metadata(&mut record_json, patch_event_metadata(&patch));
                patch_records_json.push(record_json);
                records.insert(patch.purl.clone(), build_patch_record(&patch, files));
                downloaded += 1;
            }
            Ok(None) => {
                if !params.json {
                    eprintln!("  [fail] {} (could not fetch details)", search_result.purl);
                }
                failed += 1;
                patch_records_json.push(serde_json::json!({
                    "purl": search_result.purl,
                    "uuid": search_result.uuid,
                    "action": "failed",
                    "error": "could not fetch details",
                }));
            }
            Err(e) => {
                if !params.json {
                    eprintln!("  [fail] {} ({e})", search_result.purl);
                }
                failed += 1;
                patch_records_json.push(serde_json::json!({
                    "purl": search_result.purl,
                    "uuid": search_result.uuid,
                    "action": "failed",
                    "error": e.to_string(),
                }));
            }
        }
    }

    let mut result_json = serde_json::json!({
        "found": selected.len(),
        "downloaded": downloaded,
        "skipped": skipped,
        "failed": failed,
        "detached": true,
        "patches": patch_records_json,
    });
    if !narrow_warnings.is_empty() {
        result_json["warnings"] = serde_json::json!(narrow_warnings);
    }
    (i32::from(failed > 0), result_json, records)
}

/// Emit a warning (stderr `[note]` + `warnings[]`) for every added/updated
/// patch record whose purl the vendor ledger still wires at a DIFFERENT
/// uuid — VEX verification fails closed (`vendor_uuid_mismatch`) until a
/// `vendor` run refreshes the committed artifact.
///
/// Kept out of [`download_and_apply_patches`]'s body on purpose: that
/// function sits on the in-process scan→download→apply chain, whose summed
/// poll frames must fit Windows' 1 MiB main-thread stack in debug builds.
async fn warn_on_vendored_uuid_drift(
    cwd: &Path,
    quiet: bool,
    downloaded_patches: &[serde_json::Value],
    warnings: &mut Vec<String>,
) {
    let Ok(vendor_state) = socket_patch_core::vendor::load_state(cwd).await else {
        return;
    };
    if vendor_state.entries.is_empty() {
        return;
    }
    for rec in downloaded_patches {
        let (Some(purl), Some(uuid)) = (rec["purl"].as_str(), rec["uuid"].as_str()) else {
            continue;
        };
        if !matches!(rec["action"].as_str(), Some("added" | "updated")) {
            continue;
        }
        let entry = socket_patch_core::vendor::lookup_entry(&vendor_state.entries, purl);
        if let Some(entry) = entry.filter(|e| e.uuid != uuid) {
            let w = format!(
                "{purl} is vendored at patch {} but the manifest now records {uuid}; \
                 run `socket-patch vendor` to refresh the committed artifact",
                entry.uuid
            );
            if !quiet {
                eprintln!("  [note] {w}");
            }
            warnings.push(w);
        }
    }
}

/// Run the nested `apply` step over the manifest under `cwd`. Returns
/// whether apply exited 0. Callers print their own "Applying patches..."
/// line (they differ on stdout vs stderr). `get` drives apply internally:
/// the read-only cargo-redirect verifier stays off and embedded VEX is
/// opt-in on the top-level command only, never on this internal
/// invocation.
///
/// `api` carries the caller's API-client flags and is NOT optional: apply
/// builds its own clients from the `GlobalArgs` handed to it (its telemetry
/// client, and `fetch_stage`'s artifact fetcher), and those only ever see
/// this struct. Leaving the fields at their `GlobalArgs::default()` `None`
/// dropped `--api-url` / `--api-token` / `--org` / `--proxy-url` on the
/// floor, so a token supplied purely as a CLI flag fell through to env →
/// socket-cli config → the token-less public proxy. That breaks the flow
/// for real: a patch view that omits `blobContent` for a file (`Option` on
/// the wire, which is why `--download-mode diff` exists) leaves `get` with
/// no blob to write, and the nested apply must download it — with the wrong
/// client, against the wrong host.
#[allow(clippy::too_many_arguments)]
async fn run_nested_apply(
    cwd: &Path,
    manifest_path: &Path,
    global: bool,
    global_prefix: Option<PathBuf>,
    quiet: bool,
    download_mode: String,
    strict: bool,
    api: socket_patch_core::api::client::ApiClientEnvOverrides,
    ecosystems: Option<Vec<String>>,
) -> bool {
    // Apply re-resolves a relative manifest path against ITS `--cwd`
    // (`resolved_manifest_path`), but ours is already cwd-resolved —
    // passing it through relative double-joins the cwd (`proj/proj/...`),
    // and apply then no-ops on the missing manifest while reporting
    // success. Absolutize so it passes through verbatim.
    let manifest_path =
        std::path::absolute(manifest_path).unwrap_or_else(|_| manifest_path.to_path_buf());
    let apply_args = super::apply::ApplyArgs {
        common: crate::args::GlobalArgs {
            manifest_path: manifest_path.display().to_string(),
            cwd: cwd.to_path_buf(),
            global,
            global_prefix,
            silent: quiet,
            download_mode,
            strict,
            api_url: api.api_url,
            api_token: api.api_token,
            org: api.org_slug,
            proxy_url: api.proxy_url,
            // Scope the nested apply like the caller was scoped: leaving
            // this at the default `None` made `scan --ecosystems gem --sync`
            // apply the WHOLE manifest, mutating other ecosystems' packages
            // the user filtered out.
            ecosystems,
            ..crate::args::GlobalArgs::default()
        },
        force: false,
        check: false,
        vex: Default::default(),
    };
    let code = super::apply::run(apply_args).await;
    if code != 0 && !quiet {
        eprintln!("\nSome patches could not be applied.");
    }
    code == 0
}

pub async fn download_and_apply_patches(
    selected: &[PatchSearchResult],
    params: &DownloadParams,
) -> (i32, serde_json::Value) {
    let api_client = api_client_for(params).await;

    let manifest_path = params.manifest_path.clone();
    let socket_dir = manifest_path
        .parent()
        .unwrap_or(Path::new("."))
        .to_path_buf();
    let blobs_dir = socket_dir.join("blobs");

    if let Err(e) = tokio::fs::create_dir_all(&socket_dir).await {
        let err = format!("Failed to create .socket directory: {}", e);
        report_error(params.json, &err);
        return (1, serde_json::json!({"status": "error", "error": err}));
    }
    if params.persist_blobs {
        if let Err(e) = tokio::fs::create_dir_all(&blobs_dir).await {
            let err = format!("Failed to create blobs directory: {}", e);
            report_error(params.json, &err);
            return (1, serde_json::json!({"status": "error", "error": err}));
        }
    }

    let mut manifest = match read_manifest(&manifest_path).await {
        Ok(Some(m)) => m,
        Ok(None) => PatchManifest::new(),
        // Fail closed on a manifest that exists but can't be read/parsed:
        // treating it as empty would let the unconditional write below
        // replace the file and destroy every tracked patch record.
        Err(e) => {
            let err = format!("Failed to read manifest: {e}");
            report_error(params.json, &err);
            return (1, serde_json::json!({"status": "error", "error": err}));
        }
    };

    // Narrow multi-release selections to the installed distribution
    // unless --all-releases was passed. `filter_to_installed_releases`
    // is a no-op for non-variant ecosystems and single-variant packages.
    let (selected, mut narrow_warnings) =
        filter_to_installed_releases(selected, params, &api_client).await;

    if !params.json && !params.silent {
        eprintln!("\nDownloading {} patch(es)...", selected.len());
    }

    // `patches_added` and `patches_updated` are DISJOINT — one patch lands in
    // exactly one of them, matching the per-patch `action` vocabulary
    // (CLI_CONTRACT.md: `added` | `updated` | ...) and the single-UUID flow's
    // summary in `save_and_apply_patch`. `patches_downloaded` is their sum:
    // the JSON `downloaded` / `applied` counts cover both (a replacement was
    // fetched and applied just like a new record), and it gates the apply
    // step. Counting an update in `patches_added` too made the human summary
    // print `Added: 1` AND `Updated: 1` for the one entry it had swapped.
    let mut patches_added = 0;
    let mut patches_skipped = 0;
    let mut patches_failed = 0;
    let mut patches_updated = 0;
    let mut patches_downloaded = 0;
    let mut downloaded_patches: Vec<serde_json::Value> = Vec::new();

    for search_result in &selected {
        // org slug is already stored in the client.
        match api_client.fetch_patch(None, &search_result.uuid).await {
            Ok(Some(patch)) => {
                // Classify against the manifest state BEFORE we touch it.
                // `Skipped` early-returns; `Updated` is preserved so the
                // per-patch JSON record below can include `oldUuid`.
                let action = decide_patch_action(&manifest, &patch.purl, &patch.uuid);
                if let PatchAction::Skipped = action {
                    if !params.json && !params.silent {
                        eprintln!(
                            "  [skip] {} (already in manifest)",
                            normalize_purl(&patch.purl)
                        );
                    }
                    downloaded_patches.push(serde_json::json!({
                        "purl": patch.purl,
                        "uuid": patch.uuid,
                        "action": "skipped",
                    }));
                    patches_skipped += 1;
                    continue;
                }

                // Build the manifest `files` map. Retains patch-added new
                // files (empty-beforeHash sentinel) so scan/apply/vendor
                // record and write them; see `files_for_manifest`.
                let files = files_for_manifest(&patch);

                // GUARDRAIL: a patch that yields NO recordable files
                // cannot be applied — recording an empty `files` map and
                // then reporting `applied` would tell the user we protected
                // them while writing nothing. Count it as a failure so the
                // status/exit code degrade and it is never auto-applied.
                if files.is_empty() {
                    // Errors are exempt from --silent ("errors only");
                    // JSON runs carry them in the envelope instead.
                    if !params.json {
                        eprintln!("  [fail] {} (patch has no applicable files)", patch.purl);
                    }
                    downloaded_patches.push(serde_json::json!({
                        "purl": patch.purl,
                        "uuid": patch.uuid,
                        "action": "failed",
                        "error": "patch has no applicable files",
                    }));
                    patches_failed += 1;
                    continue;
                }

                // Blob failures are errors: only JSON mode suppresses the
                // per-file detail line (the envelope carries the error).
                let quiet = params.json;
                // Vendor flows keep blob content in memory (the vendor
                // step re-fetches what it needs); persisting blobs here
                // would litter .socket/blobs for no consumer.
                if params.persist_blobs
                    && write_all_patch_blobs(&blobs_dir, &patch, quiet)
                        .await
                        .is_err()
                {
                    patches_failed += 1;
                    downloaded_patches.push(serde_json::json!({
                        "purl": patch.purl,
                        "uuid": patch.uuid,
                        "action": "failed",
                        "error": "Blob decode or write failed",
                    }));
                    continue;
                }

                manifest
                    .patches
                    .insert(patch.purl.clone(), build_patch_record(&patch, files));

                let mut action_record = match &action {
                    PatchAction::Updated { old_uuid } => {
                        patches_updated += 1;
                        if !params.json && !params.silent {
                            // Defensive: a malformed/short UUID in the manifest
                            // must not panic the download loop. `&uuid[..8]`
                            // would; `short_uuid` falls back to the whole string.
                            eprintln!(
                                "  [update] {} (replacing {})",
                                patch.purl,
                                short_uuid(old_uuid)
                            );
                        }
                        serde_json::json!({
                            "purl": patch.purl,
                            "uuid": patch.uuid,
                            "action": "updated",
                            "oldUuid": old_uuid,
                        })
                    }
                    _ => {
                        patches_added += 1;
                        if !params.json && !params.silent {
                            eprintln!("  [add] {}", patch.purl);
                        }
                        serde_json::json!({
                            "purl": patch.purl,
                            "uuid": patch.uuid,
                            "action": "added",
                        })
                    }
                };
                // Splice description / severity / vulnerability IDs into
                // the per-patch record so PR-comment bots, dashboards, and
                // CLI consumers can render the patch without a second
                // round-trip to the API.
                merge_metadata(&mut action_record, patch_event_metadata(&patch));
                downloaded_patches.push(action_record);
                patches_downloaded += 1;
            }
            Ok(None) => {
                if !params.json {
                    eprintln!("  [fail] {} (could not fetch details)", search_result.purl);
                }
                downloaded_patches.push(serde_json::json!({
                    "purl": search_result.purl,
                    "uuid": search_result.uuid,
                    "action": "failed",
                    "error": "could not fetch details",
                }));
                patches_failed += 1;
            }
            Err(e) => {
                if !params.json {
                    eprintln!("  [fail] {} ({e})", search_result.purl);
                }
                downloaded_patches.push(serde_json::json!({
                    "purl": search_result.purl,
                    "uuid": search_result.uuid,
                    "action": "failed",
                    "error": e.to_string(),
                }));
                patches_failed += 1;
            }
        }
    }

    // Write manifest
    if let Err(e) = write_manifest(&manifest_path, &manifest).await {
        let msg = format!("Error writing manifest: {e}");
        let err_json = serde_json::json!({ "status": "error", "error": &msg });
        if params.json {
            print_json(&err_json);
        } else {
            eprintln!("{msg}");
        }
        return (1, err_json);
    }

    // Vendored-uuid drift: an explicit `get` is allowed to move the
    // manifest past the patch uuid the vendor ledger still wires (the user
    // asked for that patch by name). Verification then fails closed
    // (`vendor_uuid_mismatch`) until a `vendor` run re-vendors at the new
    // uuid — tell the operator now instead of letting VEX surprise them
    // later. (`scan` never hits this: it filters vendored purls before
    // download.) The nested apply below skips the vendored purl either way.
    warn_on_vendored_uuid_drift(
        &params.cwd,
        params.json || params.silent,
        &downloaded_patches,
        &mut narrow_warnings,
    )
    .await;

    if !params.json && !params.silent {
        eprintln!("\nPatches saved to {}", manifest_path.display());
        eprintln!("  Added: {patches_added}");
        if patches_skipped > 0 {
            eprintln!("  Skipped: {patches_skipped}");
        }
        if patches_failed > 0 {
            eprintln!("  Failed: {patches_failed}");
        }
        if patches_updated > 0 {
            eprintln!("  Updated: {patches_updated}");
        }
    }

    // Auto-apply unless --save-only
    let mut apply_succeeded = false;
    if !params.save_only && patches_downloaded > 0 {
        if !params.json && !params.silent {
            eprintln!("\nApplying patches...");
        }
        apply_succeeded = run_nested_apply(
            &params.cwd,
            &manifest_path,
            params.global,
            params.global_prefix.clone(),
            params.json || params.silent,
            params.download_mode.clone(),
            params.strict,
            resolved_api_overrides(params),
            params.ecosystems.clone(),
        )
        .await;
    }

    // An apply step that ran (patches were added, not --save-only) but
    // failed is a partial failure too — not just download failures. The
    // `status` field must agree with `exit_code`; reporting `success`
    // alongside a non-zero exit code misleads JSON consumers (the scan
    // wrapper recomputes status from the exit code for exactly this
    // reason, but `get` surfaces this envelope directly).
    let apply_failed = !apply_succeeded && patches_downloaded > 0 && !params.save_only;
    let (status, exit_code) = run_outcome(patches_failed > 0, apply_failed);
    let mut result_json = serde_json::json!({
        "status": status,
        "found": selected.len(),
        "downloaded": patches_downloaded,
        "skipped": patches_skipped,
        "failed": patches_failed,
        "applied": if apply_succeeded { patches_downloaded } else { 0 },
        "updated": patches_updated,
        "patches": downloaded_patches,
    });
    // Surface release-narrowing fallbacks (uninstalled package / no
    // matching variant) so JSON consumers can see why all variants were
    // kept. Omitted entirely when narrowing was clean.
    if !narrow_warnings.is_empty() {
        result_json["warnings"] = serde_json::json!(narrow_warnings);
    }

    (exit_code, result_json)
}

pub async fn run(args: GetArgs) -> i32 {
    // Validate flags
    let type_flags = [args.id, args.cve, args.ghsa, args.package]
        .iter()
        .filter(|&&f| f)
        .count();
    if type_flags > 1 {
        report_error(
            args.common.json,
            "Only one of --id, --cve, --ghsa, or --package can be specified",
        );
        return 1;
    }
    if args.one_off && args.save_only {
        report_error(
            args.common.json,
            "--one-off and --save-only cannot be used together",
        );
        return 1;
    }
    // Mode resolution mirrors scan's enum (default = agent, today's
    // behavior). Conflicts use get's established exit-1 report_error style
    // (scan's self-enforced conflicts exit 2; get's have always been 1 —
    // documented carve-out in CLI_CONTRACT.md).
    let mode = args.mode.unwrap_or(super::scan::ScanMode::Agent);
    if args.save_only && mode != super::scan::ScanMode::Agent {
        report_error(
            args.common.json,
            format!(
                "--save-only cannot be used with --mode {}: hosted mode never writes the \
                 manifest, and vendored mode's vendor step IS the persistence (plain \
                 `get --save-only` already records without applying)",
                mode.cli_name()
            ),
        );
        return 1;
    }
    if args.one_off {
        // Honest failure instead of the historical silent no-op: the flag
        // parsed but was never implemented, so the patch was saved to the
        // manifest anyway — lying to the user about persistence. Mirrors
        // `rollback --one-off`'s not-yet-implemented contract; rejected
        // before any network or disk activity.
        report_error(args.common.json, "One-off get mode is not yet implemented");
        return 1;
    }
    // Strict airgap (CLI_CONTRACT.md `--offline`: never contact the
    // network; operations that need remote data fail loudly). Every `get`
    // mode fetches remote patch data — proceeding would hit the API (and
    // save the fetched patch into the manifest) — so refuse before the
    // client is built (org auto-resolve is itself a network call). No
    // telemetry fires here: offline gates `is_telemetry_disabled` too.
    if args.common.offline {
        report_error(
            args.common.json,
            "get requires network access to fetch patches and cannot run with \
             --offline/SOCKET_OFFLINE (strict airgap)",
        );
        return 1;
    }

    apply_env_toggles(&args.common);
    // `--silent` is "errors only" (CLI_CONTRACT.md): every informational
    // print below is gated on this; errors and JSON envelopes are not.
    let quiet = args.common.json || args.common.silent;
    let overrides = args.common.api_client_overrides();
    let (mut api_client, mut use_public_proxy) =
        get_api_client_with_overrides(overrides.clone()).await;
    let telemetry_token = api_client.api_token().cloned();
    let telemetry_org = api_client.org_slug().cloned();
    let download_mode = args.common.download_mode.clone();
    // Set to `true` after the first 401/403 from the authenticated
    // endpoint triggered a rebuild against the public proxy. Plumbed
    // through to every subsequent telemetry event so we can track the
    // incidence of stale-token fallbacks.
    let mut fallback_to_proxy = false;

    // org slug is already stored in the client
    let effective_org_slug: Option<&str> = None;

    // Determine identifier type
    let id_type = if args.id {
        IdentifierType::Uuid
    } else if args.cve {
        IdentifierType::Cve
    } else if args.ghsa {
        IdentifierType::Ghsa
    } else if args.package {
        IdentifierType::Package
    } else {
        match detect_identifier_type(&args.identifier) {
            Some(t) => t,
            None => {
                if !quiet {
                    println!("Treating \"{}\" as a package name search", args.identifier);
                }
                IdentifierType::Package
            }
        }
    };

    // Handle UUID: fetch and download directly
    if id_type == IdentifierType::Uuid {
        if !quiet {
            println!("Fetching patch by UUID: {}", args.identifier);
        }
        let mut fetch_result = api_client
            .fetch_patch(effective_org_slug, &args.identifier)
            .await;
        // 401/403 from the auth endpoint → swap to the public proxy
        // and retry once. Free patches still surface; paid patches
        // come back as the existing "paid_required" branch below.
        if !use_public_proxy {
            if let Err(ref e) = fetch_result {
                if is_fallback_candidate(e) {
                    eprintln!(
                        "Warning: authenticated API returned {e}; \
                         falling back to public patch API proxy (free patches only)."
                    );
                    api_client = build_proxy_fallback_client(&overrides);
                    use_public_proxy = true;
                    fallback_to_proxy = true;
                    fetch_result = api_client
                        .fetch_patch(effective_org_slug, &args.identifier)
                        .await;
                }
            }
        }
        match fetch_result {
            Ok(Some(patch)) => {
                if patch.tier == "paid" && use_public_proxy {
                    track_patch_fetch_failed(
                        &patch.uuid,
                        "paid_required",
                        fallback_to_proxy,
                        telemetry_token.as_deref(),
                        telemetry_org.as_deref(),
                    )
                    .await;
                    if args.common.json {
                        print_json(&serde_json::json!({
                            "status": "paid_required",
                            "found": 1,
                            "downloaded": 0,
                            "applied": 0,
                            "patches": [{
                                "purl": patch.purl,
                                "uuid": patch.uuid,
                                "tier": "paid",
                            }],
                        }));
                    } else if !args.common.silent {
                        println!("\nThis patch requires a paid subscription to download.");
                        println!("\n  Patch: {}", patch.purl);
                        println!("  Tier:  paid");
                        println!("\n  Upgrade at: https://socket.dev/pricing\n");
                    }
                    return 0;
                }

                // Record the fetch BEFORE the save+apply step so the
                // event captures patch identity even if a downstream
                // file-system error trips up save_and_apply. The save
                // step has its own apply-side telemetry (track_patch_applied)
                // so we don't lose visibility into the rest of the pipeline.
                track_patch_fetched(
                    &patch.uuid,
                    &patch.tier,
                    &ecosystem_from_purl(&patch.purl),
                    &download_mode,
                    fallback_to_proxy,
                    telemetry_token.as_deref(),
                    telemetry_org.as_deref(),
                )
                .await;
                // Mode dispatch. All three reuse THIS fetched patch (and,
                // for hosted, this possibly-proxy-fallback client) rather
                // than re-fetching with a fresh client, which would re-hit
                // the 401/403 the fallback just recovered from. An explicit
                // UUID is exempt from installed narrowing (exact intent).
                return match mode {
                    // Save to manifest and apply in place (today's flow).
                    super::scan::ScanMode::Agent => save_and_apply_patch(&args, &patch).await,
                    super::scan::ScanMode::Hosted => {
                        let selected = vec![search_result_from_response(&patch)];
                        run_get_hosted(&args, &api_client, effective_org_slug, &selected, &[], &[])
                            .await
                    }
                    super::scan::ScanMode::Vendored => {
                        run_get_vendored_uuid(
                            &args,
                            &patch,
                            telemetry_token.as_deref(),
                            telemetry_org.as_deref(),
                        )
                        .await
                    }
                };
            }
            Ok(None) => {
                track_patch_fetch_failed(
                    &args.identifier,
                    "not_found",
                    fallback_to_proxy,
                    telemetry_token.as_deref(),
                    telemetry_org.as_deref(),
                )
                .await;
                if args.common.json {
                    print_json(&empty_result_json("not_found"));
                } else if !args.common.silent {
                    println!("No patch found with UUID: {}", args.identifier);
                }
                return 0;
            }
            Err(e) => {
                return report_fetch_failure(
                    &args.identifier,
                    e,
                    fallback_to_proxy,
                    telemetry_token.as_deref(),
                    telemetry_org.as_deref(),
                    args.common.json,
                )
                .await;
            }
        }
    }

    // For CVE/GHSA/PURL/package, search first.
    // CVE / GHSA / PURL share the same path: log the search, dispatch to
    // the matching endpoint, and surface errors via `report_fetch_failure`.
    let search_response: SearchResponse = match id_type {
        IdentifierType::Cve | IdentifierType::Ghsa | IdentifierType::Purl => {
            if !quiet {
                let label = match id_type {
                    IdentifierType::Cve => "CVE",
                    IdentifierType::Ghsa => "GHSA",
                    IdentifierType::Purl => "PURL",
                    _ => unreachable!(),
                };
                println!("Searching patches for {label}: {}", args.identifier);
            }
            let result = match id_type {
                IdentifierType::Cve => {
                    api_client
                        .search_patches_by_cve(effective_org_slug, &args.identifier)
                        .await
                }
                IdentifierType::Ghsa => {
                    api_client
                        .search_patches_by_ghsa(effective_org_slug, &args.identifier)
                        .await
                }
                IdentifierType::Purl => {
                    api_client
                        .search_patches_by_package(effective_org_slug, &args.identifier)
                        .await
                }
                _ => unreachable!(),
            };
            match result {
                Ok(r) => r,
                Err(e) => {
                    return report_fetch_failure(
                        &args.identifier,
                        e,
                        fallback_to_proxy,
                        telemetry_token.as_deref(),
                        telemetry_org.as_deref(),
                        args.common.json,
                    )
                    .await;
                }
            }
        }
        IdentifierType::Package => {
            if !quiet {
                println!("Enumerating packages...");
            }
            let crawler_options = CrawlerOptions {
                cwd: args.common.cwd.clone(),
                global: args.common.global,
                global_prefix: args.common.global_prefix.clone(),
            };
            let (all_packages, _) = crawl_all_ecosystems(&crawler_options).await;

            if all_packages.is_empty() {
                if args.common.json {
                    print_json(&empty_result_json("no_packages"));
                } else if !args.common.silent {
                    if args.common.global {
                        println!("No global packages found.");
                    } else {
                        #[allow(unused_mut)]
                        let mut install_cmds = String::from("npm/yarn/pnpm/pip");
                        install_cmds.push_str("/cargo");
                        install_cmds.push_str("/go");
                        install_cmds.push_str("/mvn");
                        install_cmds.push_str("/composer");
                        println!("No packages found. Run {install_cmds} install first.");
                    }
                }
                return 0;
            }

            if !quiet {
                println!("Found {} packages", all_packages.len());
            }

            let matches = fuzzy_match_packages(&args.identifier, &all_packages, 20);

            if matches.is_empty() {
                if args.common.json {
                    print_json(&empty_result_json("no_match"));
                } else if !args.common.silent {
                    println!("No packages matching \"{}\" found.", args.identifier);
                }
                return 0;
            }

            if !quiet {
                println!(
                    "Found {} matching package(s), checking for available patches...",
                    matches.len()
                );
            }

            // Search for patches for the best match
            let best_match = &matches[0];
            match api_client
                .search_patches_by_package(effective_org_slug, &best_match.purl)
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    return report_fetch_failure(
                        &args.identifier,
                        e,
                        fallback_to_proxy,
                        telemetry_token.as_deref(),
                        telemetry_org.as_deref(),
                        args.common.json,
                    )
                    .await;
                }
            }
        }
        _ => unreachable!(),
    };

    if search_response.patches.is_empty() {
        if args.common.json {
            print_json(&empty_result_json("not_found"));
        } else if !args.common.silent {
            println!("No patches found for {}: {}", id_type, args.identifier);
        }
        return 0;
    }

    if !quiet {
        display_search_results(
            &search_response.patches,
            search_response.can_access_paid_patches,
        );
    }

    // Filter accessible patches
    let accessible: Vec<_> = search_response
        .patches
        .iter()
        .filter(|p| p.tier == "free" || search_response.can_access_paid_patches)
        .cloned()
        .collect();

    if accessible.is_empty() {
        if args.common.json {
            print_json(&serde_json::json!({
                "status": "paid_required",
                "found": search_response.patches.len(),
                "downloaded": 0,
                "applied": 0,
                "patches": search_response.patches.iter().map(|p| serde_json::json!({
                    "purl": p.purl,
                    "uuid": p.uuid,
                    "tier": p.tier,
                })).collect::<Vec<_>>(),
            }));
        } else if !args.common.silent {
            println!("\nAll available patches require a paid subscription.");
            println!("\n  Upgrade at: https://socket.dev/pricing\n");
        }
        return 0;
    }

    // Coarse installed-VERSION narrowing of the fan-out (a GHSA/CVE search
    // returns one record per patched version — only the versions present
    // here should be acted on). Exempt: --all-releases (the documented
    // escape), --save-only (record-only has no installation precondition —
    // the fresh-clone `get --save-only` → `vendor` flow must keep working),
    // exact-versioned PURL identifiers (explicit intent, like a UUID), and
    // the package-name path (its search key IS an installed purl). Runs
    // AFTER the paid gate above: a paid-only result is `paid_required`,
    // never "not installed".
    let narrowing_exempt = args.all_releases
        || args.save_only
        || id_type == IdentifierType::Package
        || (id_type == IdentifierType::Purl && purl_has_version(&args.identifier));
    let (accessible, narrow_skips, narrow_warnings) = if narrowing_exempt {
        (accessible, Vec::new(), Vec::new())
    } else {
        let narrowing = filter_to_installed_purls(&accessible, &args.common, mode).await;
        (narrowing.kept, narrowing.skip_records, narrowing.warnings)
    };
    // Layout refusals print even when informational output is quieted only
    // by --json (stderr; the envelope carries them too) — but --silent
    // mutes them like scan does.
    if !args.common.silent {
        for (code, detail) in &narrow_warnings {
            eprintln!("Warning ({code}): {detail}");
        }
    }
    if !quiet {
        for rec in &narrow_skips {
            let reason = match rec["errorCode"].as_str() {
                Some("package_not_installed") | None => "version not installed",
                Some(code) => code,
            };
            eprintln!(
                "  [skip] {} ({reason})",
                rec["purl"].as_str().unwrap_or_default()
            );
        }
    }
    if accessible.is_empty() {
        // Every accessible patch targets a version this system doesn't
        // have. Additive status (never `no_match`, which is pinned to the
        // fuzzy package-name path): exit 0, the skips carry the detail.
        if args.common.json {
            let mut result = serde_json::json!({
                "status": "not_installed",
                "found": narrow_skips.len(),
                "downloaded": 0,
                "applied": 0,
                "patches": narrow_skips,
            });
            fold_narrowing_into_result(&mut result, &[], &narrow_warnings);
            print_json(&result);
        } else if !args.common.silent {
            println!(
                "Patches exist for {} package version(s), but none of those versions are \
                 installed here. Use --all-releases to fetch them anyway.",
                narrow_skips.len()
            );
        }
        return 0;
    }

    // Smart patch selection: pick one patch per PURL
    let selected = match select_patches(
        &accessible,
        search_response.can_access_paid_patches,
        args.common.json,
    ) {
        Ok(s) => s,
        Err(code) => return code,
    };

    if selected.is_empty() {
        if !quiet {
            println!("No patches selected.");
        }
        return 0;
    }

    // Confirm before acting (default YES), with mode-appropriate wording.
    // Hosted/vendored dry-runs skip the prompt — nothing mutates (scan's
    // dry-run posture); agent mode keeps today's behavior.
    let prompt = match mode {
        super::scan::ScanMode::Agent => format!("Download {} patch(es)?", selected.len()),
        super::scan::ScanMode::Vendored => {
            format!("Download and vendor {} patch(es)?", selected.len())
        }
        super::scan::ScanMode::Hosted => format!(
            "Redirect {} package(s) to the hosted patch server?",
            selected.len()
        ),
    };
    let skip_confirm = mode != super::scan::ScanMode::Agent && args.common.dry_run;
    if !skip_confirm && !confirm(&prompt, true, args.common.yes, args.common.json) {
        if !quiet {
            println!("Download cancelled.");
        }
        return 0;
    }

    match mode {
        super::scan::ScanMode::Hosted => {
            return run_get_hosted(
                &args,
                &api_client,
                effective_org_slug,
                &selected,
                &narrow_skips,
                &narrow_warnings,
            )
            .await;
        }
        super::scan::ScanMode::Vendored => {
            return run_get_vendored_search(
                &args,
                &selected,
                &narrow_skips,
                &narrow_warnings,
                telemetry_token.as_deref(),
                telemetry_org.as_deref(),
            )
            .await;
        }
        super::scan::ScanMode::Agent => {}
    }

    // Download and apply (agent mode)
    let params = DownloadParams {
        cwd: args.common.cwd.clone(),
        manifest_path: args.common.resolved_manifest_path(),
        org: args.common.org.clone(),
        save_only: args.save_only,
        global: args.common.global,
        global_prefix: args.common.global_prefix.clone(),
        json: args.common.json,
        silent: args.common.silent,
        download_mode: args.common.download_mode.clone(),
        api_overrides: args.common.api_client_overrides(),
        all_releases: args.all_releases,
        strict: args.common.strict,
        ecosystems: args.common.ecosystems.clone(),
        persist_blobs: true,
    };

    let (code, mut result_json) = download_and_apply_patches(&selected, &params).await;
    fold_narrowing_into_result(&mut result_json, &narrow_skips, &narrow_warnings);

    if args.common.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&result_json)
                .expect("serializing an in-memory JSON value cannot fail")
        );
    }

    code
}

/// Print the patches a search turned up, grouped by PURL and best-first
/// within each PURL — the same order [`select_patches`] resolves in, so the
/// listing's first entry for a package is the one that will be applied.
/// A `by-cve` / `by-ghsa` search can span several packages, hence the PURL
/// grouping.
fn display_search_results(patches: &[PatchSearchResult], can_access_paid: bool) {
    println!("\nFound patches:\n");

    let mut patches: Vec<&PatchSearchResult> = patches.iter().collect();
    patches.sort_by(|a, b| a.purl.cmp(&b.purl).then_with(|| cmp_search_results(a, b)));

    for (i, patch) in patches.iter().enumerate() {
        let tier_label = if patch.tier == "paid" {
            " [PAID]"
        } else {
            " [FREE]"
        };
        let access_label = if patch.tier == "paid" && !can_access_paid {
            " (no access)"
        } else {
            ""
        };

        println!("  {}. {}{}{}", i + 1, patch.purl, tier_label, access_label);
        println!("     UUID: {}", patch.uuid);
        if !patch.description.is_empty() {
            let desc = truncate_with_ellipsis(&patch.description, 80);
            println!("     Description: {desc}");
        }

        let vuln_ids: Vec<_> = patch.vulnerabilities.keys().collect();
        if !vuln_ids.is_empty() {
            let vuln_summary: Vec<String> = patch
                .vulnerabilities
                .iter()
                .map(|(id, vuln)| {
                    let cves = if vuln.cves.is_empty() {
                        id.to_string()
                    } else {
                        vuln.cves.join(", ")
                    };
                    format!("{cves} ({})", vuln.severity)
                })
                .collect();
            println!("     Fixes: {}", vuln_summary.join(", "));
        }
        println!();
    }
}

/// Save an already-fetched patch to the manifest and (unless
/// `--save-only`) apply it. Takes the `PatchResponse` the caller fetched
/// rather than re-fetching by UUID: the caller's client may have fallen
/// back to the public proxy after a 401/403, and a fresh client built
/// here would hit the same auth failure again, breaking the fallback
/// end to end.
/// The manifest-record half of the single-uuid save — blobs dir + blob
/// writes (when `persist_blobs`), fail-closed manifest read, the
/// no-applicable-files guardrail, action classification, and the manifest
/// write — WITHOUT the nested apply, drift warning, or terminal JSON
/// envelope. Shared by the agent-mode [`save_and_apply_patch`] terminal
/// (`persist_blobs: true`, `insert_when_skipped: true` — today's exact
/// behavior, a same-uuid re-get still rewrites the record bytes) and the
/// `--mode vendored` uuid path (`false`/`false`: the vendor step stages
/// patch content in memory so nothing lands in `.socket/blobs`, and an
/// idempotent re-get leaves the manifest bytes untouched, matching the
/// multi-patch download loop's Skipped `continue`).
///
/// Errors are reported here exactly as before the extraction and surface
/// as `Err(exit_code)`.
async fn save_patch_record(
    args: &GetArgs,
    patch: &PatchResponse,
    persist_blobs: bool,
    insert_when_skipped: bool,
) -> Result<PatchAction, i32> {
    let manifest_path = args.common.resolved_manifest_path();
    let socket_dir = manifest_path
        .parent()
        .unwrap_or(Path::new("."))
        .to_path_buf();

    if persist_blobs {
        if let Err(e) = tokio::fs::create_dir_all(socket_dir.join("blobs")).await {
            report_error(
                args.common.json,
                format!("Failed to create blobs directory: {e}"),
            );
            return Err(1);
        }
    } else if let Err(e) = tokio::fs::create_dir_all(&socket_dir).await {
        // No blobs dir in vendored mode, but the manifest write below (and
        // the vendor step's apply lock) still need `.socket/` itself.
        report_error(
            args.common.json,
            format!("Failed to create .socket directory: {e}"),
        );
        return Err(1);
    }

    let mut manifest = match read_manifest(&manifest_path).await {
        Ok(Some(m)) => m,
        Ok(None) => PatchManifest::new(),
        // Fail closed like the download flow: an unreadable manifest
        // treated as empty would be rewritten below with only this one
        // patch, destroying every tracked record.
        Err(e) => {
            report_error(args.common.json, format!("Failed to read manifest: {e}"));
            return Err(1);
        }
    };

    // Build the manifest `files` map, retaining patch-added new files
    // (a file with after_hash but no before_hash records an empty
    // `before_hash` sentinel, which apply treats as a new-file insert).
    let files = files_for_manifest(patch);

    // GUARDRAIL: a patch that yields NO recordable files cannot be
    // applied — recording an empty `files` map and reporting the patch
    // as applied would claim protection while writing nothing. Fail
    // loudly instead of counting a defective patch as `applied:1`.
    if files.is_empty() {
        report_error(
            args.common.json,
            format!(
                "Patch {} has no applicable files; nothing to apply",
                patch.purl
            ),
        );
        return Err(1);
    }

    if persist_blobs
        && write_all_patch_blobs(&socket_dir.join("blobs"), patch, args.common.json)
            .await
            .is_err()
    {
        if args.common.json {
            print_json(&serde_json::json!({
                "status": "error",
                "found": 1,
                "downloaded": 0,
                "applied": 0,
                "error": "Blob decode or write failed",
                "patches": [{
                    "purl": patch.purl,
                    "uuid": patch.uuid,
                    "action": "failed",
                    "error": "Blob decode or write failed",
                }],
            }));
        } else {
            eprintln!(
                "Error: Blob decode or write failed for patch {}",
                patch.purl
            );
        }
        return Err(1);
    }

    // Classify against the manifest state BEFORE the insert, with the same
    // vocabulary `download_and_apply_patches` emits (CLI_CONTRACT.md): a
    // different uuid already recorded at this purl is `updated` (+`oldUuid`),
    // not `added` — consumers diff manifest replacements on that action.
    let action = decide_patch_action(&manifest, &patch.purl, &patch.uuid);

    if insert_when_skipped || action != PatchAction::Skipped {
        manifest
            .patches
            .insert(patch.purl.clone(), build_patch_record(patch, files));

        if let Err(e) = write_manifest(&manifest_path, &manifest).await {
            report_error(args.common.json, format!("Error writing manifest: {e}"));
            return Err(1);
        }
    }
    Ok(action)
}

async fn save_and_apply_patch(args: &GetArgs, patch: &PatchResponse) -> i32 {
    // Same "errors only" gate as `run` — informational prints respect
    // `--silent`; errors and the JSON envelope do not.
    let quiet = args.common.json || args.common.silent;
    let manifest_path = args.common.resolved_manifest_path();

    let action = match save_patch_record(args, patch, true, true).await {
        Ok(action) => action,
        Err(code) => return code,
    };
    let changed = action != PatchAction::Skipped;
    let action_label = match &action {
        PatchAction::Added => "added",
        PatchAction::Updated { .. } => "updated",
        PatchAction::Skipped => "skipped",
    };

    // Vendored-uuid drift (mirrors `download_and_apply_patches`): the user
    // explicitly fetched this uuid; if the vendor ledger still wires a
    // different one, VEX verification fails closed (`vendor_uuid_mismatch`)
    // until a `vendor` run refreshes the committed artifact.
    let mut warnings: Vec<String> = Vec::new();
    if changed {
        warn_on_vendored_uuid_drift(
            &args.common.cwd,
            quiet,
            &[serde_json::json!({
                "purl": patch.purl,
                "uuid": patch.uuid,
                "action": action_label,
            })],
            &mut warnings,
        )
        .await;
    }

    if !quiet {
        println!("\nPatch saved to {}", manifest_path.display());
        match &action {
            PatchAction::Added => println!("  Added: 1"),
            PatchAction::Updated { old_uuid } => {
                println!("  Updated: 1 (replacing {})", short_uuid(old_uuid));
            }
            PatchAction::Skipped => println!("  Skipped: 1 (already exists)"),
        }
    }

    let mut apply_succeeded = false;
    if !args.save_only && changed {
        if !quiet {
            println!("\nApplying patches...");
        }
        apply_succeeded = run_nested_apply(
            &args.common.cwd,
            &manifest_path,
            args.common.global,
            args.common.global_prefix.clone(),
            quiet,
            args.common.download_mode.clone(),
            args.common.strict,
            args.common.api_client_overrides(),
            args.common.ecosystems.clone(),
        )
        .await;
    }

    // The apply step ran (patch added, not --save-only) but failed →
    // partial failure. The `status` field must agree with the exit code
    // returned below; a hardcoded `success` alongside a non-zero exit
    // misleads JSON consumers.
    let apply_failed = !apply_succeeded && changed && !args.save_only;
    // No "download failed" concept here — a blob failure early-returns
    // with status `error` above — so only the apply step can degrade us.
    let (status, exit_code) = run_outcome(false, apply_failed);

    if args.common.json {
        let mut patch_record = serde_json::json!({
            "purl": patch.purl,
            "uuid": patch.uuid,
            "action": action_label,
        });
        if let PatchAction::Updated { old_uuid } = &action {
            patch_record["oldUuid"] = serde_json::json!(old_uuid);
        }
        if changed {
            // Only enrich added/updated records — a `skipped` record means
            // the consumer already saw the metadata last time.
            merge_metadata(&mut patch_record, patch_event_metadata(patch));
        }
        let mut result_json = serde_json::json!({
            "status": status,
            "found": 1,
            "downloaded": if changed { 1 } else { 0 },
            "applied": if apply_succeeded { 1 } else { 0 },
            "patches": [patch_record],
        });
        // Same contract as `download_and_apply_patches`: omitted when clean.
        if !warnings.is_empty() {
            result_json["warnings"] = serde_json::json!(warnings);
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&result_json)
                .expect("serializing an in-memory JSON value cannot fail")
        );
    }

    exit_code
}

/// Bridge a fetched patch view to the search shape the mode flows consume —
/// the uuid path fetches the view directly and never runs a search.
fn search_result_from_response(patch: &PatchResponse) -> PatchSearchResult {
    PatchSearchResult {
        uuid: patch.uuid.clone(),
        purl: patch.purl.clone(),
        published_at: patch.published_at.clone(),
        description: patch.description.clone(),
        license: patch.license.clone(),
        tier: patch.tier.clone(),
        vulnerabilities: patch.vulnerabilities.clone(),
    }
}

/// Transient-frame boxed constructor for the vendored-mode download phase —
/// `download_and_apply_patches`' future embeds the in-process apply engine,
/// and `run_get_vendored_search`'s poll frame must not carry it inline
/// (Windows 1 MiB main-thread stack; scan's vendor flow boxes the same call).
fn boxed_download_and_apply<'a>(
    selected: &'a [PatchSearchResult],
    params: &'a DownloadParams,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = (i32, serde_json::Value)> + 'a>> {
    Box::pin(download_and_apply_patches(selected, params))
}

/// Print the whole-manifest blast-radius note for `--mode vendored`: the
/// vendor step is scan's — it reconciles and (re)vendors EVERY manifest
/// record, not just the one(s) this get selected.
async fn note_vendored_whole_manifest_scope(
    manifest_path: &Path,
    selected_purls: &[&str],
    quiet: bool,
) {
    if quiet {
        return;
    }
    let Ok(Some(manifest)) = read_manifest(manifest_path).await else {
        return;
    };
    let canon = |p: &str| normalize_purl(strip_purl_qualifiers(p)).into_owned();
    let selected_canon: std::collections::HashSet<String> =
        selected_purls.iter().map(|p| canon(p)).collect();
    let others = manifest
        .patches
        .keys()
        .filter(|k| !selected_canon.contains(&canon(k)))
        .count();
    if others > 0 {
        eprintln!(
            "  [note] --mode vendored runs the vendor engine over the whole manifest: \
             {others} existing record(s) will also be verified/re-vendored, and records \
             whose packages left the manifest may have their vendored state reverted \
             (same behavior as `scan --mode vendored`)."
        );
    }
}

/// `get … --mode hosted`: hand the selected (purl, uuid) pairs to scan's
/// hosted engine ([`super::scan::boxed_run_redirect_selected`]) — lockfile
/// rewrite + redirect ledger, no manifest, no blobs — so the on-disk result
/// matches `scan --mode hosted` selecting the same patches. The engine owns
/// all output (and honors `--dry-run` internally); in JSON mode it nests its
/// `redirect` block into the get base envelope passed as `scan_result`.
async fn run_get_hosted(
    args: &GetArgs,
    api_client: &socket_patch_core::api::client::ApiClient,
    effective_org_slug: Option<&str>,
    selected: &[PatchSearchResult],
    narrow_skips: &[serde_json::Value],
    narrow_warnings: &[(String, String)],
) -> i32 {
    let pairs: Vec<(String, String)> = selected
        .iter()
        .map(|s| (s.purl.clone(), s.uuid.clone()))
        .collect();
    // `scan_result` iff --json: the engine's human/JSON split keys on
    // common.json, and a --json caller passing None would get a minimal
    // envelope that drops get's keys (see run_redirect_selected's doc).
    let scan_result = args.common.json.then(|| {
        let mut result = serde_json::json!({
            "status": "success",
            "found": pairs.len() + narrow_skips.len(),
            "patches": narrow_skips,
        });
        fold_narrowing_into_result(&mut result, &[], narrow_warnings);
        result
    });
    // Embedded VEX stays a scan/vendor feature (get has no --vex): a
    // default-off VexEmbedArgs — deliberately NOT env-bound here, so an
    // ambient SOCKET_VEX only affects commands that declare the flag.
    let vex = crate::commands::vex::VexEmbedArgs::default();
    super::scan::boxed_run_redirect_selected(
        &args.common,
        &vex,
        /*prune_requested=*/ false,
        api_client,
        effective_org_slug,
        &pairs,
        scan_result,
    )
    .await
}

/// `get … --mode vendored` (search path): scan's vendored posture end to
/// end — download phase writing ONLY the manifest (blobs in memory), then
/// scan's whole-manifest vendor step, telemetry included — so the result
/// matches `scan --mode vendored` selecting the same patches.
async fn run_get_vendored_search(
    args: &GetArgs,
    selected: &[PatchSearchResult],
    narrow_skips: &[serde_json::Value],
    narrow_warnings: &[(String, String)],
    telemetry_token: Option<&str>,
    telemetry_org: Option<&str>,
) -> i32 {
    let quiet = args.common.json || args.common.silent;
    let manifest_path = args.common.resolved_manifest_path();
    let socket_dir = manifest_path
        .parent()
        .unwrap_or(Path::new("."))
        .to_path_buf();

    // Dry run: ledger-classification preview only (scan's posture) — no
    // download, no vendor step, no writes.
    if args.common.dry_run {
        let preview = super::scan::preview_vendor_json(&args.common.cwd, selected).await;
        if args.common.json {
            let mut result = serde_json::json!({
                "status": "success",
                "found": selected.len() + narrow_skips.len(),
                "patches": narrow_skips,
            });
            fold_narrowing_into_result(&mut result, &[], narrow_warnings);
            result["vendor"] = preview;
            print_json(&result);
        } else if !args.common.silent {
            println!(
                "[dry-run] Would download and vendor {} patch(es).",
                selected.len()
            );
        }
        return 0;
    }

    let selected_purls: Vec<&str> = selected.iter().map(|s| s.purl.as_str()).collect();
    note_vendored_whole_manifest_scope(&manifest_path, &selected_purls, quiet).await;

    // Download phase — scan's vendored posture: manifest-only writes, blobs
    // held in memory, the nested apply never runs (save_only).
    let params = DownloadParams {
        cwd: args.common.cwd.clone(),
        manifest_path: manifest_path.clone(),
        org: args.common.org.clone(),
        save_only: true,
        global: args.common.global,
        global_prefix: args.common.global_prefix.clone(),
        json: args.common.json,
        silent: args.common.silent,
        download_mode: args.common.download_mode.clone(),
        api_overrides: args.common.api_client_overrides(),
        all_releases: args.all_releases,
        strict: args.common.strict,
        ecosystems: args.common.ecosystems.clone(),
        persist_blobs: false,
    };
    let (dl_code, mut result) = boxed_download_and_apply(selected, &params).await;
    // A download-phase HARD error (unreadable manifest, unwritable
    // .socket, failed manifest write — an `error`-status envelope the
    // engine has ALREADY printed) aborts before the vendor step: get's
    // `--json` contract is exactly one JSON document per run, and the
    // vendor step would only re-fail on the same broken state and print a
    // second, different document. Per-patch failures are NOT this case —
    // they ride a success-shaped envelope and the vendor step still runs
    // (scan parity: previously-recorded patches still (re)vendor).
    if result["status"] == "error" {
        return dl_code;
    }
    let mut has_errors = dl_code != 0;
    fold_narrowing_into_result(&mut result, narrow_skips, narrow_warnings);
    if let Some(obj) = result.as_object_mut() {
        // save_only: the nested apply structurally never ran, so `applied`
        // would misleadingly report 0 — drop it (scan's vendored download
        // sub-object gets the same surgery).
        obj.remove("applied");
    }

    // The vendor step (scan's, verbatim): apply lock, whole-manifest
    // reconcile + staging + engine. A per-patch download failure does not
    // skip it — previously-recorded patches still (re)vendor, like scan.
    match super::scan::boxed_scan_vendor_step(&args.common, &manifest_path, &socket_dir, None).await
    {
        Ok((vendor_errors, venv)) => {
            has_errors |= vendor_errors;
            crate::commands::vendor::track_outcomes_for_vendor(
                vendor_errors,
                &venv,
                args.common.dry_run,
                telemetry_token,
                telemetry_org,
            )
            .await;
            if args.common.json {
                result["status"] = serde_json::json!(if has_errors {
                    "partial_failure"
                } else {
                    "success"
                });
                result["vendor"] =
                    serde_json::to_value(&venv).unwrap_or_else(|_| serde_json::json!({}));
                print_json(&result);
            }
            i32::from(has_errors)
        }
        Err((code, message, venv)) => {
            socket_patch_core::telemetry::track_patch_vendor_failed(
                &message,
                args.common.dry_run,
                telemetry_token,
                telemetry_org,
            )
            .await;
            if args.common.json {
                // A pre-failure reconcile already mutated the vendor ledger
                // on disk; its envelope (events included) must reach the
                // JSON consumer even though the run aborts here.
                if let Some(venv) = venv {
                    result["vendor"] =
                        serde_json::to_value(&*venv).unwrap_or_else(|_| serde_json::json!({}));
                }
                result["status"] = serde_json::json!("error");
                result["error"] = serde_json::json!({ "code": code, "message": message });
                print_json(&result);
            } else {
                eprintln!("Error ({code}): {message}");
            }
            1
        }
    }
}

/// `get <uuid> --mode vendored`: record the ALREADY-FETCHED patch in the
/// manifest (no blobs, no nested apply — the vendor step stages content in
/// memory), then run scan's whole-manifest vendor step. Reuses the fetched
/// `PatchResponse` so the uuid path's proxy-fallback survives the record
/// save; the vendor step builds its own client from the flags, exactly as
/// scan's does.
async fn run_get_vendored_uuid(
    args: &GetArgs,
    patch: &PatchResponse,
    telemetry_token: Option<&str>,
    telemetry_org: Option<&str>,
) -> i32 {
    let quiet = args.common.json || args.common.silent;
    let manifest_path = args.common.resolved_manifest_path();
    let socket_dir = manifest_path
        .parent()
        .unwrap_or(Path::new("."))
        .to_path_buf();

    if args.common.dry_run {
        let selected = vec![search_result_from_response(patch)];
        let preview = super::scan::preview_vendor_json(&args.common.cwd, &selected).await;
        if args.common.json {
            let mut result = serde_json::json!({
                "status": "success",
                "found": 1,
                "patches": [],
            });
            result["vendor"] = preview;
            print_json(&result);
        } else if !args.common.silent {
            println!("[dry-run] Would download and vendor 1 patch.");
        }
        return 0;
    }

    note_vendored_whole_manifest_scope(&manifest_path, &[patch.purl.as_str()], quiet).await;

    let action = match save_patch_record(args, patch, false, false).await {
        Ok(action) => action,
        Err(code) => return code,
    };
    let changed = action != PatchAction::Skipped;
    let action_label = match &action {
        PatchAction::Added => "added",
        PatchAction::Updated { .. } => "updated",
        PatchAction::Skipped => "skipped",
    };
    if !quiet {
        println!("\nPatch record saved to {}", manifest_path.display());
        match &action {
            PatchAction::Added => println!("  Added: 1"),
            PatchAction::Updated { old_uuid } => {
                println!("  Updated: 1 (replacing {})", short_uuid(old_uuid));
            }
            PatchAction::Skipped => println!("  Skipped: 1 (already exists)"),
        }
    }

    let mut result = if args.common.json {
        let mut patch_record = serde_json::json!({
            "purl": patch.purl,
            "uuid": patch.uuid,
            "action": action_label,
        });
        if let PatchAction::Updated { old_uuid } = &action {
            patch_record["oldUuid"] = serde_json::json!(old_uuid);
        }
        if changed {
            merge_metadata(&mut patch_record, patch_event_metadata(patch));
        }
        serde_json::json!({
            "status": "success",
            "found": 1,
            "downloaded": if changed { 1 } else { 0 },
            "skipped": if changed { 0 } else { 1 },
            "patches": [patch_record],
        })
    } else {
        serde_json::Value::Null
    };

    match super::scan::boxed_scan_vendor_step(&args.common, &manifest_path, &socket_dir, None).await
    {
        Ok((vendor_errors, venv)) => {
            crate::commands::vendor::track_outcomes_for_vendor(
                vendor_errors,
                &venv,
                args.common.dry_run,
                telemetry_token,
                telemetry_org,
            )
            .await;
            if args.common.json {
                result["status"] = serde_json::json!(if vendor_errors {
                    "partial_failure"
                } else {
                    "success"
                });
                result["vendor"] =
                    serde_json::to_value(&venv).unwrap_or_else(|_| serde_json::json!({}));
                print_json(&result);
            }
            i32::from(vendor_errors)
        }
        Err((code, message, venv)) => {
            socket_patch_core::telemetry::track_patch_vendor_failed(
                &message,
                args.common.dry_run,
                telemetry_token,
                telemetry_org,
            )
            .await;
            if args.common.json {
                if let Some(venv) = venv {
                    result["vendor"] =
                        serde_json::to_value(&*venv).unwrap_or_else(|_| serde_json::json!({}));
                }
                result["status"] = serde_json::json!("error");
                result["error"] = serde_json::json!({ "code": code, "message": message });
                print_json(&result);
            } else {
                eprintln!("Error ({code}): {message}");
            }
            1
        }
    }
}

pub(crate) fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    let chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut table = [255u8; 256];
    for (i, &c) in chars.iter().enumerate() {
        table[c as usize] = i as u8;
    }

    let input = input.as_bytes();
    let mut output = Vec::with_capacity(input.len() * 3 / 4);

    let mut buf = 0u32;
    let mut bits = 0u32;

    for &b in input {
        if b == b'=' || b == b'\n' || b == b'\r' {
            continue;
        }
        let val = table[b as usize];
        if val == 255 {
            return Err(format!("Invalid base64 character: {}", b as char));
        }
        buf = (buf << 6) | val as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use socket_patch_core::api::types::{PatchFileResponse, VulnerabilityResponse};
    use std::collections::HashMap;

    // --- detect_identifier_type -------------------------------------------

    #[test]
    fn detect_uuid_lowercase() {
        assert_eq!(
            detect_identifier_type("80630680-4da6-45f9-bba8-b888e0ffd58c"),
            Some(IdentifierType::Uuid)
        );
    }

    #[test]
    fn detect_uuid_uppercase() {
        // Case-insensitive UUID regex per contract.
        assert_eq!(
            detect_identifier_type("80630680-4DA6-45F9-BBA8-B888E0FFD58C"),
            Some(IdentifierType::Uuid)
        );
    }

    #[test]
    fn detect_cve_uppercase() {
        assert_eq!(
            detect_identifier_type("CVE-2021-44906"),
            Some(IdentifierType::Cve)
        );
    }

    #[test]
    fn detect_cve_lowercase() {
        // Load-bearing: CVE detection must be case-insensitive.
        assert_eq!(
            detect_identifier_type("cve-2021-44906"),
            Some(IdentifierType::Cve)
        );
    }

    #[test]
    fn detect_ghsa_uppercase() {
        assert_eq!(
            detect_identifier_type("GHSA-abcd-1234-wxyz"),
            Some(IdentifierType::Ghsa)
        );
    }

    #[test]
    fn detect_ghsa_lowercase() {
        // Load-bearing: GHSA detection must be case-insensitive.
        assert_eq!(
            detect_identifier_type("ghsa-abcd-1234-wxyz"),
            Some(IdentifierType::Ghsa)
        );
    }

    #[test]
    fn detect_purl() {
        assert_eq!(
            detect_identifier_type("pkg:npm/foo@1.0"),
            Some(IdentifierType::Purl)
        );
    }

    #[test]
    fn detect_package_name_returns_none() {
        // Bare package names don't match any pattern; caller treats this as
        // Package via the `else` branch in run().
        assert_eq!(detect_identifier_type("minimist"), None);
    }

    #[test]
    fn detect_malformed_cve_returns_none() {
        assert_eq!(detect_identifier_type("CVE-not-a-year"), None);
    }

    #[test]
    fn detect_empty_string_returns_none() {
        assert_eq!(detect_identifier_type(""), None);
    }

    // --- select_patches ---------------------------------------------------

    fn mk_patch(uuid: &str, purl: &str, tier: &str, published_at: &str) -> PatchSearchResult {
        PatchSearchResult {
            uuid: uuid.into(),
            purl: purl.into(),
            published_at: published_at.into(),
            description: format!("desc-{uuid}"),
            license: "MIT".into(),
            tier: tier.into(),
            vulnerabilities: HashMap::<String, VulnerabilityResponse>::new(),
        }
    }

    /// `mk_patch` with a single vulnerability at the given severity, so the
    /// severity rung of the ranking is exercised.
    fn mk_patch_sev(
        uuid: &str,
        purl: &str,
        tier: &str,
        published_at: &str,
        severity: &str,
    ) -> PatchSearchResult {
        let mut p = mk_patch(uuid, purl, tier, published_at);
        p.vulnerabilities.insert(
            format!("GHSA-{uuid}"),
            VulnerabilityResponse {
                cves: vec![],
                summary: String::new(),
                severity: severity.into(),
                description: String::new(),
            },
        );
        p
    }

    #[test]
    fn select_free_user_one_free_patch_returns_it() {
        let patches = vec![mk_patch("u1", "pkg:npm/foo@1.0", "free", "2024-01-01")];
        let out = select_patches(&patches, false, false).expect("ok");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].uuid, "u1");
    }

    #[test]
    fn select_paid_user_picks_highest_severity_not_most_recent() {
        // The reported bug. An authorized user's package has a fresh `low`
        // patch and an older `critical` one; the old selector took the
        // newest and silently left the critical unfixed.
        let patches = vec![
            mk_patch_sev("new_low", "pkg:npm/foo@1.0", "paid", "2026-06-01", "low"),
            mk_patch_sev(
                "old_crit",
                "pkg:npm/foo@1.0",
                "paid",
                "2024-01-01",
                "critical",
            ),
        ];
        let out = select_patches(&patches, true, false).expect("ok");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].uuid, "old_crit");
    }

    #[test]
    fn select_paid_user_picks_free_critical_over_paid_low() {
        // Severity outranks tier: `tier` gates *access*, it does not rank.
        // A paid subscriber must not be handed a low-severity paid patch
        // when a critical free one exists for the same package.
        let patches = vec![
            mk_patch_sev("paid_low", "pkg:npm/foo@1.0", "paid", "2026-06-01", "low"),
            mk_patch_sev(
                "free_crit",
                "pkg:npm/foo@1.0",
                "free",
                "2024-01-01",
                "critical",
            ),
        ];
        let out = select_patches(&patches, true, false).expect("ok");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].uuid, "free_crit");
        assert_eq!(out[0].tier, "free");
    }

    /// `mk_patch_sev` with one advisory per severity — two or more makes it
    /// a *merged* patch (see `api::ranking::merged_coverage`), which is
    /// inferred from the advisory count, not from any API flag.
    fn mk_patch_multi(
        uuid: &str,
        purl: &str,
        tier: &str,
        published_at: &str,
        severities: &[&str],
    ) -> PatchSearchResult {
        let mut p = mk_patch(uuid, purl, tier, published_at);
        for (i, sev) in severities.iter().enumerate() {
            p.vulnerabilities.insert(
                format!("GHSA-{uuid}-{i}"),
                VulnerabilityResponse {
                    cves: vec![],
                    summary: String::new(),
                    severity: (*sev).into(),
                    description: String::new(),
                },
            );
        }
        p
    }

    #[test]
    fn select_prefers_merged_patch_when_severities_tie() {
        // The general preference: `z_merged` remediates two HIGH advisories
        // in one blob, `a_single` only one. Severities tie, so breadth
        // decides. `a_single` is both newer AND earlier by uuid, so only
        // the coverage rung can produce this result.
        let patches = vec![
            mk_patch_sev("a_single", "pkg:npm/foo@1.0", "paid", "2026-06-01", "high"),
            mk_patch_multi(
                "z_merged",
                "pkg:npm/foo@1.0",
                "free",
                "2020-01-01",
                &["high", "high"],
            ),
        ];
        let out = select_patches(&patches, true, false).expect("ok");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].uuid, "z_merged");
    }

    #[test]
    fn select_prefers_a_higher_severity_patch_over_the_merged_one() {
        // The exception. A merged patch must not shadow a worse
        // vulnerability: `z_critical` addresses a CRITICAL the merged patch
        // does not cover, so it wins despite being older, single-advisory,
        // and last by uuid.
        let patches = vec![
            mk_patch_multi(
                "a_merged",
                "pkg:npm/foo@1.0",
                "free",
                "2026-06-01",
                &["high", "high"],
            ),
            mk_patch_sev(
                "z_critical",
                "pkg:npm/foo@1.0",
                "free",
                "2020-01-01",
                "critical",
            ),
        ];
        let out = select_patches(&patches, true, false).expect("ok");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].uuid, "z_critical");
    }

    #[test]
    fn select_recency_is_chronological_not_lexicographic() {
        // `publishedAt` is RFC 2822 on the wire, so the old raw-string
        // compare ordered by weekday name. With equal severities the newer
        // patch must win regardless of which weekday it fell on.
        let older = "Wed, 01 Jan 2025 00:00:00 GMT";
        let newer = "Fri, 01 Aug 2026 00:00:00 GMT";
        assert!(older > newer, "precondition: raw strings sort backwards");
        // Adversarial UUIDs: `a_older` sorts first, so the final uuid
        // tiebreak points at the wrong patch and cannot rescue this test if
        // the date rung breaks.
        let patches = vec![
            mk_patch_sev("a_older", "pkg:npm/foo@1.0", "paid", older, "high"),
            mk_patch_sev("z_newer", "pkg:npm/foo@1.0", "paid", newer, "high"),
        ];
        let out = select_patches(&patches, true, false).expect("ok");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].uuid, "z_newer");
    }

    #[test]
    fn select_recency_uses_the_patch_date_not_the_package_release_date() {
        // Real production pair: both patches are for `axios@1.6.0` — one
        // package version, one upstream release date (2023-10-26) — yet
        // they carry different publish dates because the field describes
        // the PATCH. Severities tie, so the date is the deciding rung.
        //
        // Non-vacuity: `0bc312a6` < `83f5a654`, so if the ranking ever fell
        // back to the UUID tiebreak (which is what a package-level date
        // would cause, both keys being equal) this would select the OLDER
        // patch and fail.
        let patches = vec![
            mk_patch_sev(
                "0bc312a6",
                "pkg:npm/axios@1.6.0",
                "free",
                "Fri, 27 Mar 2026 19:12:42 GMT",
                "HIGH",
            ),
            mk_patch_sev(
                "83f5a654",
                "pkg:npm/axios@1.6.0",
                "free",
                "Mon, 03 Aug 2026 20:23:06 GMT",
                "HIGH",
            ),
        ];
        let out = select_patches(&patches, true, false).expect("ok");
        assert_eq!(out.len(), 1, "one patch per PURL");
        assert_eq!(out[0].uuid, "83f5a654");
    }

    #[test]
    fn select_returns_purl_sorted_output() {
        // The grouping map has randomized iteration order; without an
        // explicit sort the download sequence (and every JSON array derived
        // from it) would differ run to run.
        let patches = vec![
            mk_patch("c", "pkg:npm/ccc@1.0", "paid", "2024-01-01"),
            mk_patch("a", "pkg:npm/aaa@1.0", "paid", "2024-01-01"),
            mk_patch("b", "pkg:npm/bbb@1.0", "paid", "2024-01-01"),
        ];
        for _ in 0..8 {
            let out = select_patches(&patches, true, false).expect("ok");
            let purls: Vec<&str> = out.iter().map(|p| p.purl.as_str()).collect();
            assert_eq!(
                purls,
                ["pkg:npm/aaa@1.0", "pkg:npm/bbb@1.0", "pkg:npm/ccc@1.0"]
            );
        }
    }

    #[test]
    fn select_paid_user_prefers_paid_when_everything_else_ties() {
        // Tier survives only as a late tiebreak: same merge status, same
        // (absent) severity, same publish date → paid wins.
        let patches = vec![
            mk_patch("free1", "pkg:npm/foo@1.0", "free", "2024-01-01"),
            mk_patch("paid1", "pkg:npm/foo@1.0", "paid", "2024-01-01"),
        ];
        let out = select_patches(&patches, true, false).expect("ok");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].uuid, "paid1");
        assert_eq!(out[0].tier, "paid");
    }

    #[test]
    fn select_paid_user_picks_most_recent_paid() {
        let patches = vec![
            mk_patch("old", "pkg:npm/foo@1.0", "paid", "2024-01-01"),
            mk_patch("new", "pkg:npm/foo@1.0", "paid", "2024-06-01"),
        ];
        let out = select_patches(&patches, true, false).expect("ok");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].uuid, "new");
    }

    #[test]
    fn select_paid_user_falls_back_to_most_recent_free_when_no_paid() {
        let patches = vec![
            mk_patch("old", "pkg:npm/foo@1.0", "free", "2024-01-01"),
            mk_patch("new", "pkg:npm/foo@1.0", "free", "2024-06-01"),
        ];
        let out = select_patches(&patches, true, false).expect("ok");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].uuid, "new");
    }

    #[test]
    fn select_free_user_multi_free_json_mode_errors() {
        // JSON mode requires explicit selection; multiple free patches in JSON
        // mode means the caller must pass --id.
        let patches = vec![
            mk_patch("a", "pkg:npm/foo@1.0", "free", "2024-01-01"),
            mk_patch("b", "pkg:npm/foo@1.0", "free", "2024-06-01"),
        ];
        let err = select_patches(&patches, false, true).expect_err("should fail");
        assert_eq!(err, 1);
    }

    #[test]
    fn select_empty_input_returns_empty() {
        let out = select_patches(&[], false, false).expect("ok");
        assert!(out.is_empty());
        let out = select_patches(&[], true, false).expect("ok");
        assert!(out.is_empty());
        let out = select_patches(&[], false, true).expect("ok");
        assert!(out.is_empty());
    }

    #[test]
    fn select_free_user_paid_filtered_out_then_single_free_auto_selects() {
        // Free user: paid patch is filtered out before grouping; only the free
        // patch survives, and since the group has exactly one entry it
        // auto-selects without hitting the interactive path.
        let patches = vec![
            mk_patch("paid", "pkg:npm/foo@1.0", "paid", "2024-06-01"),
            mk_patch("free", "pkg:npm/foo@1.0", "free", "2024-01-01"),
        ];
        let out = select_patches(&patches, false, false).expect("ok");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].uuid, "free");
        assert_eq!(out[0].tier, "free");
    }

    // --- decide_patch_action ---------------------------------------------
    // Locks in the per-patch action vocabulary surfaced by
    // download_and_apply_patches in JSON mode. See CLI_CONTRACT.md.

    fn manifest_with_entry(purl: &str, uuid: &str) -> PatchManifest {
        let mut m = PatchManifest::new();
        m.patches.insert(
            purl.to_string(),
            PatchRecord {
                uuid: uuid.to_string(),
                exported_at: String::new(),
                files: HashMap::new(),
                vulnerabilities: HashMap::new(),
                description: String::new(),
                license: String::new(),
                tier: "free".to_string(),
            },
        );
        m
    }

    #[test]
    fn decide_patch_action_added_when_purl_absent() {
        let manifest = PatchManifest::new();
        assert_eq!(
            decide_patch_action(&manifest, "pkg:npm/foo@1.0", "uuid-a"),
            PatchAction::Added,
        );
    }

    #[test]
    fn decide_patch_action_skipped_when_same_uuid() {
        let manifest = manifest_with_entry("pkg:npm/foo@1.0", "uuid-a");
        assert_eq!(
            decide_patch_action(&manifest, "pkg:npm/foo@1.0", "uuid-a"),
            PatchAction::Skipped,
        );
    }

    #[test]
    fn decide_patch_action_updated_when_different_uuid() {
        let manifest = manifest_with_entry("pkg:npm/foo@1.0", "uuid-a");
        assert_eq!(
            decide_patch_action(&manifest, "pkg:npm/foo@1.0", "uuid-b"),
            PatchAction::Updated {
                old_uuid: "uuid-a".to_string()
            },
        );
    }

    #[test]
    fn decide_patch_action_added_for_different_purl_even_with_overlapping_manifest() {
        // Ensure update detection keys on PURL, not UUID. A new PURL with a
        // UUID that happens to match an existing entry under a different
        // PURL must still be `Added`.
        let manifest = manifest_with_entry("pkg:npm/foo@1.0", "uuid-a");
        assert_eq!(
            decide_patch_action(&manifest, "pkg:npm/bar@2.0", "uuid-a"),
            PatchAction::Added,
        );
    }

    // --- severity_rank / max_vuln_severity / patch_event_metadata --------
    // Pins the JSON shape of the metadata spliced into `added` / `updated`
    // per-patch records by `download_and_apply_patches`. PR-comment bots
    // rely on these fields — see CLI_CONTRACT.md (`get` / `scan` JSON
    // output, patches array).

    #[test]
    fn severity_rank_orders_canonical_labels() {
        assert!(severity_rank("critical") > severity_rank("high"));
        assert!(severity_rank("high") > severity_rank("medium"));
        assert!(severity_rank("medium") > severity_rank("low"));
        // GHSA's `moderate` is treated as medium.
        assert_eq!(severity_rank("moderate"), severity_rank("medium"));
        // Unknown / blank labels rank below all known severities.
        assert!(severity_rank("low") > severity_rank(""));
        assert!(severity_rank("low") > severity_rank("unknown"));
    }

    #[test]
    fn max_vuln_severity_picks_highest() {
        let mut vulns = HashMap::new();
        vulns.insert(
            "GHSA-low".into(),
            VulnerabilityResponse {
                cves: vec!["CVE-low".into()],
                summary: String::new(),
                severity: "low".into(),
                description: String::new(),
            },
        );
        vulns.insert(
            "GHSA-crit".into(),
            VulnerabilityResponse {
                cves: vec!["CVE-crit".into()],
                summary: String::new(),
                severity: "critical".into(),
                description: String::new(),
            },
        );
        vulns.insert(
            "GHSA-mod".into(),
            VulnerabilityResponse {
                cves: vec!["CVE-mod".into()],
                summary: String::new(),
                severity: "moderate".into(),
                description: String::new(),
            },
        );
        assert_eq!(max_vuln_severity(&vulns).as_deref(), Some("critical"));
    }

    #[test]
    fn max_vuln_severity_returns_none_for_empty() {
        assert_eq!(max_vuln_severity(&HashMap::new()), None);
    }

    #[test]
    fn max_vuln_severity_returns_none_when_all_unrecognized() {
        // Non-empty map but every severity is off-canon (rank 0). Per the
        // doc contract this must be `None` — NOT `Some("")`/`Some("unknown")`.
        // Regression guard: `max_by_key` alone returns the element for any
        // non-empty map, leaking a garbage severity label.
        let mut vulns = HashMap::new();
        vulns.insert(
            "GHSA-a".into(),
            VulnerabilityResponse {
                cves: Vec::new(),
                summary: String::new(),
                severity: "informational".into(),
                description: String::new(),
            },
        );
        vulns.insert(
            "GHSA-b".into(),
            VulnerabilityResponse {
                cves: Vec::new(),
                summary: String::new(),
                severity: String::new(),
                description: String::new(),
            },
        );
        assert_eq!(max_vuln_severity(&vulns), None);
    }

    #[test]
    fn max_vuln_severity_recognized_wins_over_unrecognized() {
        // A single recognized severity alongside unrecognized ones must
        // surface — the rank-0 filter only suppresses the all-unrecognized
        // case, never a real label.
        let mut vulns = HashMap::new();
        vulns.insert(
            "GHSA-junk".into(),
            VulnerabilityResponse {
                cves: Vec::new(),
                summary: String::new(),
                severity: "unknown".into(),
                description: String::new(),
            },
        );
        vulns.insert(
            "GHSA-real".into(),
            VulnerabilityResponse {
                cves: Vec::new(),
                summary: String::new(),
                severity: "low".into(),
                description: String::new(),
            },
        );
        assert_eq!(max_vuln_severity(&vulns).as_deref(), Some("low"));
    }

    #[test]
    fn patch_event_metadata_omits_severity_when_all_unrecognized() {
        // The consumer-facing contract: a patch whose vulnerabilities all
        // carry non-canonical severities must NOT emit a `severity` key
        // (it would otherwise be `""`), while still listing the vulns.
        let mut vulns = HashMap::new();
        vulns.insert(
            "GHSA-aaaa-bbbb-cccc".into(),
            VulnerabilityResponse {
                cves: vec!["CVE-2024-0001".into()],
                summary: "Something".into(),
                severity: "informational".into(),
                description: String::new(),
            },
        );
        let patch = PatchResponse {
            uuid: String::new(),
            purl: String::new(),
            published_at: "ts".into(),
            files: HashMap::new(),
            vulnerabilities: vulns,
            description: "desc".into(),
            license: "MIT".into(),
            tier: "free".into(),
        };
        let meta = patch_event_metadata(&patch);
        assert!(meta.as_object().unwrap().get("severity").is_none());
        // The vulnerability itself is still surfaced (with its raw label).
        let vulns_out = meta["vulnerabilities"].as_array().unwrap();
        assert_eq!(vulns_out.len(), 1);
        assert_eq!(vulns_out[0]["severity"], "informational");
    }

    #[test]
    fn patch_event_metadata_includes_all_keys() {
        let mut vulns = HashMap::new();
        vulns.insert(
            "GHSA-aaaa-bbbb-cccc".into(),
            VulnerabilityResponse {
                cves: vec!["CVE-2024-12345".into()],
                summary: "Prototype Pollution".into(),
                severity: "high".into(),
                description: "merge() does not check Object.prototype".into(),
            },
        );
        let patch = PatchResponse {
            uuid: "11111111-1111-4111-8111-111111111111".into(),
            purl: "pkg:npm/minimist@1.2.2".into(),
            published_at: "2024-01-01T00:00:00Z".into(),
            files: HashMap::new(),
            vulnerabilities: vulns,
            description: "Fixes prototype pollution in minimist".into(),
            license: "MIT".into(),
            tier: "free".into(),
        };
        let meta = patch_event_metadata(&patch);
        assert_eq!(meta["description"], "Fixes prototype pollution in minimist");
        assert_eq!(meta["license"], "MIT");
        assert_eq!(meta["tier"], "free");
        assert_eq!(meta["exportedAt"], "2024-01-01T00:00:00Z");
        assert_eq!(meta["severity"], "high");
        let vulns_out = meta["vulnerabilities"].as_array().unwrap();
        assert_eq!(vulns_out.len(), 1);
        assert_eq!(vulns_out[0]["id"], "GHSA-aaaa-bbbb-cccc");
        assert_eq!(vulns_out[0]["cves"][0], "CVE-2024-12345");
        assert_eq!(vulns_out[0]["severity"], "high");
        assert_eq!(vulns_out[0]["summary"], "Prototype Pollution");
    }

    #[test]
    fn patch_event_metadata_sorts_vulnerabilities_by_id() {
        // HashMap iteration is otherwise nondeterministic — verify the
        // output is stable so test snapshots and consumer diffs don't
        // flap.
        let mut vulns = HashMap::new();
        for id in ["GHSA-zzz", "GHSA-aaa", "GHSA-mmm"] {
            vulns.insert(
                id.into(),
                VulnerabilityResponse {
                    cves: Vec::new(),
                    summary: String::new(),
                    severity: "low".into(),
                    description: String::new(),
                },
            );
        }
        let patch = PatchResponse {
            uuid: String::new(),
            purl: String::new(),
            published_at: String::new(),
            files: HashMap::new(),
            vulnerabilities: vulns,
            description: String::new(),
            license: String::new(),
            tier: String::new(),
        };
        let meta = patch_event_metadata(&patch);
        let ids: Vec<&str> = meta["vulnerabilities"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, ["GHSA-aaa", "GHSA-mmm", "GHSA-zzz"]);
    }

    #[test]
    fn patch_event_metadata_omits_severity_when_no_vulns() {
        let patch = PatchResponse {
            uuid: String::new(),
            purl: String::new(),
            published_at: "ts".into(),
            files: HashMap::new(),
            vulnerabilities: HashMap::new(),
            description: "desc".into(),
            license: "MIT".into(),
            tier: "free".into(),
        };
        let meta = patch_event_metadata(&patch);
        // `severity` is intentionally omitted (not null) when there
        // aren't any vulnerabilities to derive it from — consumers
        // should treat absence as "no severity available".
        assert!(meta.as_object().unwrap().get("severity").is_none());
        // The empty vulnerabilities array is still present so the
        // shape stays consistent.
        assert_eq!(meta["vulnerabilities"].as_array().unwrap().len(), 0);
    }

    // --- run_outcome -----------------------------------------------------
    // The `status` field and the process exit code are derived from the
    // same predicate. Regression guard: a failed *apply* step (no download
    // failures) must still report `partial_failure` AND exit 1 — the old
    // code keyed `status` only on download failures, so it printed
    // `success` next to a non-zero exit code.

    #[test]
    fn run_outcome_clean_is_success_exit_zero() {
        assert_eq!(run_outcome(false, false), ("success", 0));
    }

    #[test]
    fn run_outcome_download_failure_is_partial_exit_one() {
        assert_eq!(run_outcome(true, false), ("partial_failure", 1));
    }

    #[test]
    fn run_outcome_apply_failure_alone_is_partial_exit_one() {
        // The load-bearing case: nothing failed to download, but the apply
        // step failed. status MUST agree with the non-zero exit code.
        assert_eq!(run_outcome(false, true), ("partial_failure", 1));
    }

    #[test]
    fn run_outcome_both_failures_is_partial_exit_one() {
        assert_eq!(run_outcome(true, true), ("partial_failure", 1));
    }

    #[test]
    fn run_outcome_status_and_exit_never_disagree() {
        // Exhaustive: a `success` status iff exit 0, `partial_failure` iff
        // exit 1, for every input combination.
        for pf in [false, true] {
            for af in [false, true] {
                let (status, code) = run_outcome(pf, af);
                assert_eq!(
                    status == "success",
                    code == 0,
                    "status/exit disagree for patches_failed={pf}, apply_failed={af}"
                );
            }
        }
    }

    // --- truncate_with_ellipsis ------------------------------------------
    // Patch descriptions come from the API and may contain multi-byte
    // UTF-8. The old `&desc[..n]` byte slicing panicked when `n` fell mid
    // codepoint; these lock in char-safe behavior.

    #[test]
    fn truncate_short_string_unchanged() {
        assert_eq!(truncate_with_ellipsis("hello", 60), "hello");
    }

    #[test]
    fn truncate_at_limit_unchanged() {
        let s = "a".repeat(60);
        assert_eq!(truncate_with_ellipsis(&s, 60), s);
    }

    #[test]
    fn truncate_long_ascii_adds_ellipsis_and_respects_limit() {
        let s = "a".repeat(100);
        let out = truncate_with_ellipsis(&s, 60);
        // 57 content chars + "..." == 60, never wider than the limit.
        assert_eq!(out.chars().count(), 60);
        assert!(out.ends_with("..."));
        assert_eq!(out, format!("{}...", "a".repeat(57)));
    }

    #[test]
    fn truncate_multibyte_does_not_panic_and_is_char_safe() {
        // 90 bytes (30 * 3-byte chars) but only 30 chars: the byte length
        // exceeds 80 while the char count does not. A `&s[..77]` byte slice
        // would land mid-codepoint and panic; this must return the string
        // untouched because it fits within the char limit.
        let s = "日".repeat(30);
        let out = truncate_with_ellipsis(&s, 80);
        assert_eq!(out, s);
    }

    #[test]
    fn truncate_multibyte_long_truncates_on_char_boundary() {
        // 100 multi-byte chars (300 bytes) — must truncate to 77 chars plus
        // the ellipsis without ever slicing through a codepoint.
        let s = "é".repeat(100);
        let out = truncate_with_ellipsis(&s, 80);
        assert_eq!(out.chars().count(), 80);
        assert!(out.ends_with("..."));
        assert_eq!(out, format!("{}...", "é".repeat(77)));
    }

    // --- write_blob_entry ------------------------------------------------
    // Blob hashes come straight from the API response and are used as
    // filesystem path components (`blobs_dir.join(hash)`). A hostile or
    // compromised API/proxy returning `afterHash: "../../x"` must not be
    // able to write outside the blobs directory.

    // "patched\n" in base64 — a valid payload so only the hash is at fault.
    const BLOB_B64: &str = "cGF0Y2hlZAo=";

    #[tokio::test]
    async fn write_blob_entry_rejects_relative_traversal_hash() {
        let tmp = tempfile::tempdir().unwrap();
        let blobs_dir = tmp.path().join("blobs");
        tokio::fs::create_dir_all(&blobs_dir).await.unwrap();

        let res = write_blob_entry(
            &blobs_dir,
            BLOB_B64,
            "../escaped",
            "package/index.js",
            "blob",
        )
        .await;
        assert!(
            res.is_err(),
            "a traversal hash must be rejected, got {res:?}"
        );
        assert!(
            !tmp.path().join("escaped").exists(),
            "traversal hash must not write outside the blobs dir"
        );
    }

    #[tokio::test]
    async fn write_blob_entry_rejects_absolute_path_hash() {
        let tmp = tempfile::tempdir().unwrap();
        let blobs_dir = tmp.path().join("blobs");
        tokio::fs::create_dir_all(&blobs_dir).await.unwrap();

        // An absolute "hash" makes Path::join discard blobs_dir entirely.
        let target = tmp.path().join("abs_escape");
        let res = write_blob_entry(
            &blobs_dir,
            BLOB_B64,
            target.to_str().unwrap(),
            "package/index.js",
            "blob",
        )
        .await;
        assert!(
            res.is_err(),
            "an absolute-path hash must be rejected, got {res:?}"
        );
        assert!(
            !target.exists(),
            "absolute-path hash must not write outside the blobs dir"
        );
    }

    #[tokio::test]
    async fn write_blob_entry_accepts_valid_sha256_hash() {
        let tmp = tempfile::tempdir().unwrap();
        let blobs_dir = tmp.path().join("blobs");
        tokio::fs::create_dir_all(&blobs_dir).await.unwrap();

        let hash = "1111111111111111111111111111111111111111111111111111111111111111";
        write_blob_entry(&blobs_dir, BLOB_B64, hash, "package/index.js", "blob")
            .await
            .expect("a canonical 64-hex hash must be accepted");
        let written = std::fs::read(blobs_dir.join(hash)).unwrap();
        assert_eq!(written, b"patched\n");
    }

    // --- short_uuid ------------------------------------------------------
    // The `[update]` log line prints the first 8 chars of the manifest's
    // existing UUID. A naive `&uuid[..8]` panics on a short or non-ASCII
    // value; `short_uuid` must never panic.

    #[test]
    fn short_uuid_truncates_normal_uuid() {
        assert_eq!(
            short_uuid("80630680-4da6-45f9-bba8-b888e0ffd58c"),
            "80630680"
        );
    }

    #[test]
    fn short_uuid_returns_whole_string_when_shorter_than_eight() {
        // `&"abc"[..8]` would panic; the helper falls back to the whole value.
        assert_eq!(short_uuid("abc"), "abc");
        assert_eq!(short_uuid(""), "");
    }

    #[test]
    fn short_uuid_does_not_panic_on_multibyte_boundary() {
        // Byte 8 lands mid-codepoint (each "é" is 2 bytes, so byte 8 is a
        // char boundary here — but byte 7 would not be). Use a value whose
        // 8th byte splits a char to exercise the None fallback.
        let s = "ab€cd"; // '€' is 3 bytes: bytes are a b € c d -> len 7
                         // get(..8) is out of range -> None -> whole string, no panic.
        assert_eq!(short_uuid(s), s);
        // A value where byte 8 splits the trailing multibyte char.
        let s2 = "abcdef€"; // 6 ascii + 3-byte '€' = 9 bytes; byte 8 mid-char
        assert_eq!(short_uuid(s2), s2);
    }

    // --- files_for_manifest / files_with_both_hashes ---------------------
    // Regression guards for the download/scan/vendor record builder: a
    // net-new file (afterHash, NO beforeHash) that the patch ADDS must be
    // retained in the manifest record, not silently dropped. Real prod
    // repro: the whole-crate cargo export for `pkg:cargo/traitobject@0.1.1`
    // publishes ALL files with only an afterHash — the old both-hashes rule
    // recorded `files:{}` and reported `applied:1` while writing nothing.

    fn file_resp(before: Option<&str>, after: Option<&str>) -> PatchFileResponse {
        PatchFileResponse {
            before_hash: before.map(|s| s.to_string()),
            after_hash: after.map(|s| s.to_string()),
            socket_blob: None,
            blob_content: None,
            before_blob_content: None,
        }
    }

    fn patch_with_files(files: HashMap<String, PatchFileResponse>) -> PatchResponse {
        PatchResponse {
            uuid: "cf2e6f58-0000-4000-8000-000000000000".into(),
            purl: "pkg:cargo/traitobject@0.1.1".into(),
            published_at: "Fri, 27 Mar 2026 19:12:42 GMT".into(),
            files,
            vulnerabilities: HashMap::new(),
            description: "desc".into(),
            license: "MIT".into(),
            tier: "free".into(),
        }
    }

    #[test]
    fn files_for_manifest_retains_new_file_without_before_hash() {
        // A patch that ADDS a new file (afterHash, no beforeHash) — e.g.
        // the gem `lib/rubygems_plugin.rb` runtime guard — must be kept.
        let mut files = HashMap::new();
        files.insert(
            "lib/rubygems_plugin.rb".to_string(),
            file_resp(None, Some("a".repeat(64).as_str())),
        );
        files.insert(
            "lib/existing.rb".to_string(),
            file_resp(Some(&"b".repeat(64)), Some(&"c".repeat(64))),
        );
        let patch = patch_with_files(files);

        let kept = files_for_manifest(&patch);
        // Both files retained: the modified one AND the added one.
        assert_eq!(kept.len(), 2);
        let added = kept
            .get("lib/rubygems_plugin.rb")
            .expect("new file must be retained in the manifest record");
        // New files record an empty-string beforeHash sentinel.
        assert_eq!(added.before_hash, "");
        assert_eq!(added.after_hash, "a".repeat(64));

        // The old both-hashes rule (still used for installed-variant
        // matching) DROPS the added file — this is the behavior we fixed.
        let strict = files_with_both_hashes(&patch);
        assert_eq!(strict.len(), 1);
        assert!(!strict.contains_key("lib/rubygems_plugin.rb"));
    }

    #[test]
    fn files_for_manifest_keeps_all_new_file_whole_crate_export() {
        // The P0 cargo case: EVERY file is a whole-crate export with only
        // an afterHash. The old rule produced `files:{}`; the fix retains
        // all 9 so the record is non-empty and can actually be applied.
        let mut files = HashMap::new();
        for i in 0..9 {
            files.insert(
                format!("src/file{i}.rs"),
                file_resp(None, Some(&format!("{i:064x}"))),
            );
        }
        let patch = patch_with_files(files);

        let kept = files_for_manifest(&patch);
        assert_eq!(kept.len(), 9, "all whole-crate-export files must be kept");
        assert!(kept.values().all(|f| f.before_hash.is_empty()));

        // Guardrail precondition: with the old rule this map was empty.
        assert!(files_with_both_hashes(&patch).is_empty());
    }

    #[test]
    fn build_patch_record_from_new_files_is_not_empty() {
        // The record built from a new-files-only patch must carry files —
        // an empty `files` map is what the guardrail treats as a
        // non-applicable (failed), never a successful `applied:1`, patch.
        let mut files = HashMap::new();
        files.insert(
            "src/lib.rs".to_string(),
            file_resp(None, Some(&"d".repeat(64))),
        );
        let patch = patch_with_files(files);

        let (purl, record) = record_from_patch_response(&patch);
        assert_eq!(purl, "pkg:cargo/traitobject@0.1.1");
        assert!(
            !record.files.is_empty(),
            "record_from_patch_response must retain patch-added files"
        );

        // A genuinely empty patch (no afterHash anywhere) yields an empty
        // record — the guardrail-triggering condition the download/apply
        // flows now count as failed rather than applied.
        let mut broken = HashMap::new();
        broken.insert(
            "src/lib.rs".to_string(),
            file_resp(Some(&"e".repeat(64)), None),
        );
        let broken_patch = patch_with_files(broken);
        assert!(
            files_for_manifest(&broken_patch).is_empty(),
            "a patch with no afterHash produces an empty (guardrail) files map"
        );
    }
}
