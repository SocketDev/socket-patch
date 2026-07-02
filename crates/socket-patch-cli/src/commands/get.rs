use clap::Args;
use regex::Regex;
use socket_patch_core::api::client::{
    build_proxy_fallback_client, get_api_client_with_overrides, is_fallback_candidate,
};
use socket_patch_core::api::types::{
    PatchResponse, PatchSearchResult, SearchResponse, VulnerabilityResponse,
};
use socket_patch_core::crawlers::{CrawlerOptions, Ecosystem};
use socket_patch_core::manifest::operations::{read_manifest, write_manifest};
use socket_patch_core::manifest::schema::{
    PatchFileInfo, PatchManifest, PatchRecord, VulnerabilityInfo,
};
use socket_patch_core::patch::apply::select_installed_variants;
use socket_patch_core::utils::fuzzy_match::fuzzy_match_packages;
use socket_patch_core::utils::purl::{is_purl, normalize_purl, strip_purl_qualifiers};
use socket_patch_core::utils::telemetry::{track_patch_fetch_failed, track_patch_fetched};
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

/// Ordinal rank for severity strings. Higher = worse. Unknown labels
/// (including GHSA's `moderate` which maps to `medium`) get sensible
/// defaults so the max-severity selector still works.
fn severity_rank(severity: &str) -> u8 {
    match severity.to_ascii_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        // GHSA emits `moderate`; treat it as the medium-tier signal.
        "moderate" | "medium" => 2,
        "low" => 1,
        _ => 0,
    }
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
    println!("{}", serde_json::to_string_pretty(v).unwrap());
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

/// Build the manifest-shaped `files` map from a fetched patch view,
/// keeping only files that carry BOTH hashes — the download-flow rule
/// shared by the record builders and installed-distribution matching
/// (new files with no `beforeHash` are excluded; `save_and_apply_patch`
/// has the new-file-tolerant variant). A file with an empty-string
/// `beforeHash` is still kept so first-file verification can treat it
/// as Ready.
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

/// `(purl, manifest record)` from a fetched patch view — the both-hashes
/// file rule shared with the download flows (new files with no beforeHash
/// are not part of the record).
pub(crate) fn record_from_patch_response(patch: &PatchResponse) -> (String, PatchRecord) {
    (
        patch.purl.clone(),
        build_patch_record(patch, files_with_both_hashes(patch)),
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
    #[arg(
        long = "save-only",
        alias = "no-apply",
        env = "SOCKET_SAVE_ONLY",
        default_value_t = false
    )]
    pub save_only: bool,

    /// Apply patch immediately without saving to .socket folder.
    #[arg(long = "one-off", env = "SOCKET_ONE_OFF", default_value_t = false)]
    pub one_off: bool,

    /// Download patches for every release/distribution variant of a
    /// matched package, not just the one(s) matching the locally-
    /// installed distribution. Affects ecosystems with per-release
    /// variants — PyPI (wheel/sdist via `artifact_id`), RubyGems
    /// (`platform`), and Maven (`classifier`). Off by default: only the
    /// patch(es) for the installed dist are fetched.
    #[arg(
        long = "all-releases",
        env = "SOCKET_ALL_RELEASES",
        default_value_t = false,
        value_parser = clap::builder::BoolishValueParser::new(),
    )]
    pub all_releases: bool,
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
    let uuid_re =
        Regex::new(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$").unwrap();
    let cve_re = Regex::new(r"(?i)^CVE-\d{4}-\d+$").unwrap();
    let ghsa_re = Regex::new(r"(?i)^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$").unwrap();

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
/// - Paid users: auto-select the most recent paid patch per PURL.
/// - Free users with one patch: auto-select it.
/// - Free users with multiple patches: interactive selection via dialoguer.
/// - JSON mode with multiple free patches: returns an error with options list.
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

    for (purl, mut group) in by_purl {
        // Sort by published_at descending (most recent first)
        group.sort_by(|a, b| b.published_at.cmp(&a.published_at));

        if can_access_paid {
            // Paid user: prefer most recent paid patch, fallback to most recent free
            let choice = group
                .iter()
                .find(|p| p.tier == "paid")
                .or_else(|| group.first())
                .unwrap();
            selected.push((*choice).clone());
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
                            "error": format!("Multiple patches available for {purl}. Specify --id <UUID> to select one."),
                            "purl": purl,
                            "options": options_json,
                        }))
                        .unwrap()
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

    Ok(selected)
}

/// Download parameters shared between get and scan commands.
pub struct DownloadParams {
    pub cwd: PathBuf,
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
        batch_size: 100,
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

/// Build the API client for a download run, defaulting the override org
/// slug to the caller's `--org` when no explicit override was given.
async fn api_client_for(params: &DownloadParams) -> socket_patch_core::api::client::ApiClient {
    let mut overrides = params.api_overrides.clone();
    if overrides.org_slug.is_none() {
        overrides.org_slug = params.org.clone();
    }
    get_api_client_with_overrides(overrides).await.0
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

    let socket_dir = params.cwd.join(".socket");
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

    let vendor_state = socket_patch_core::patch::vendor::load_state(&params.cwd)
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
        let existing = vendor_state
            .entries
            .get(&search_result.purl)
            .or_else(|| {
                vendor_state
                    .entries
                    .values()
                    .find(|e| e.base_purl == search_result.purl)
            })
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
                // Same both-hashes rule as the download flow: new files
                // (no beforeHash) are skipped from the record.
                let files = files_with_both_hashes(&patch);
                let quiet = params.json || params.silent;
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
                failed += 1;
                patch_records_json.push(serde_json::json!({
                    "purl": search_result.purl,
                    "uuid": search_result.uuid,
                    "action": "failed",
                    "error": "could not fetch details",
                }));
            }
            Err(e) => {
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
    let Ok(vendor_state) = socket_patch_core::patch::vendor::load_state(cwd).await else {
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
        let entry = vendor_state
            .entries
            .get(purl)
            .or_else(|| vendor_state.entries.values().find(|e| e.base_purl == purl));
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
async fn run_nested_apply(
    cwd: &Path,
    global: bool,
    global_prefix: Option<PathBuf>,
    quiet: bool,
    download_mode: String,
    strict: bool,
) -> bool {
    let apply_args = super::apply::ApplyArgs {
        common: crate::args::GlobalArgs {
            manifest_path: cwd
                .join(".socket")
                .join("manifest.json")
                .display()
                .to_string(),
            cwd: cwd.to_path_buf(),
            global,
            global_prefix,
            silent: quiet,
            download_mode,
            strict,
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

    let socket_dir = params.cwd.join(".socket");
    let blobs_dir = socket_dir.join("blobs");
    let manifest_path = socket_dir.join("manifest.json");

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
        _ => PatchManifest::new(),
    };

    // Narrow multi-release selections to the installed distribution
    // unless --all-releases was passed. `filter_to_installed_releases`
    // is a no-op for non-variant ecosystems and single-variant packages.
    let (selected, mut narrow_warnings) =
        filter_to_installed_releases(selected, params, &api_client).await;

    if !params.json && !params.silent {
        eprintln!("\nDownloading {} patch(es)...", selected.len());
    }

    let mut patches_added = 0;
    let mut patches_skipped = 0;
    let mut patches_failed = 0;
    let mut patches_updated = 0;
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

                // Build the manifest `files` map. Download flow requires
                // BOTH before+after hash (skips new files); see
                // `save_and_apply_patch` for the new-file-tolerant variant.
                let files = files_with_both_hashes(&patch);

                let quiet = params.json || params.silent;
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
                patches_added += 1;
            }
            Ok(None) => {
                if !params.json && !params.silent {
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
                if !params.json && !params.silent {
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
    if !params.save_only && patches_added > 0 {
        if !params.json && !params.silent {
            eprintln!("\nApplying patches...");
        }
        apply_succeeded = run_nested_apply(
            &params.cwd,
            params.global,
            params.global_prefix.clone(),
            params.json || params.silent,
            params.download_mode.clone(),
            params.strict,
        )
        .await;
    }

    // An apply step that ran (patches were added, not --save-only) but
    // failed is a partial failure too — not just download failures. The
    // `status` field must agree with `exit_code`; reporting `success`
    // alongside a non-zero exit code misleads JSON consumers (the scan
    // wrapper recomputes status from the exit code for exactly this
    // reason, but `get` surfaces this envelope directly).
    let apply_failed = !apply_succeeded && patches_added > 0 && !params.save_only;
    let (status, exit_code) = run_outcome(patches_failed > 0, apply_failed);
    let mut result_json = serde_json::json!({
        "status": status,
        "found": selected.len(),
        "downloaded": patches_added,
        "skipped": patches_skipped,
        "failed": patches_failed,
        "applied": if apply_succeeded { patches_added } else { 0 },
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
                // Save to manifest. Pass the fetched patch through so the
                // save step reuses this (possibly proxy-fallback) result
                // instead of re-fetching with a fresh client.
                return save_and_apply_patch(&args, &patch).await;
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
                batch_size: 100,
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
                        #[cfg(feature = "cargo")]
                        install_cmds.push_str("/cargo");
                        #[cfg(feature = "golang")]
                        install_cmds.push_str("/go");
                        #[cfg(feature = "maven")]
                        install_cmds.push_str("/mvn");
                        #[cfg(feature = "composer")]
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

    // Confirm before downloading (default YES)
    let prompt = format!("Download {} patch(es)?", selected.len());
    if !confirm(&prompt, true, args.common.yes, args.common.json) {
        if !quiet {
            println!("Download cancelled.");
        }
        return 0;
    }

    // Download and apply
    let params = DownloadParams {
        cwd: args.common.cwd.clone(),
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
        persist_blobs: true,
    };

    let (code, result_json) = download_and_apply_patches(&selected, &params).await;

    if args.common.json {
        println!("{}", serde_json::to_string_pretty(&result_json).unwrap());
    }

    code
}

fn display_search_results(patches: &[PatchSearchResult], can_access_paid: bool) {
    println!("\nFound patches:\n");

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
async fn save_and_apply_patch(args: &GetArgs, patch: &PatchResponse) -> i32 {
    // Same "errors only" gate as `run` — informational prints respect
    // `--silent`; errors and the JSON envelope do not.
    let quiet = args.common.json || args.common.silent;
    let socket_dir = args.common.cwd.join(".socket");
    let blobs_dir = socket_dir.join("blobs");
    let manifest_path = socket_dir.join("manifest.json");

    if let Err(e) = tokio::fs::create_dir_all(&blobs_dir).await {
        report_error(
            args.common.json,
            format!("Failed to create blobs directory: {e}"),
        );
        return 1;
    }

    let mut manifest = match read_manifest(&manifest_path).await {
        Ok(Some(m)) => m,
        _ => PatchManifest::new(),
    };

    // Build the manifest `files` map. UUID flow is more permissive than
    // the download flow: a file with after_hash but no before_hash is a
    // new file; we record an empty `before_hash` and let apply treat it
    // as a new-file insert.
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

    if write_all_patch_blobs(&blobs_dir, patch, args.common.json)
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
        return 1;
    }

    let added = manifest
        .patches
        .get(&patch.purl)
        .is_none_or(|p| p.uuid != patch.uuid);

    manifest
        .patches
        .insert(patch.purl.clone(), build_patch_record(patch, files));

    if let Err(e) = write_manifest(&manifest_path, &manifest).await {
        report_error(args.common.json, format!("Error writing manifest: {e}"));
        return 1;
    }

    // Vendored-uuid drift (mirrors `download_and_apply_patches`): the user
    // explicitly fetched this uuid; if the vendor ledger still wires a
    // different one, VEX verification fails closed (`vendor_uuid_mismatch`)
    // until a `vendor` run refreshes the committed artifact.
    let mut warnings: Vec<String> = Vec::new();
    if added {
        warn_on_vendored_uuid_drift(
            &args.common.cwd,
            quiet,
            &[serde_json::json!({
                "purl": patch.purl,
                "uuid": patch.uuid,
                "action": "added",
            })],
            &mut warnings,
        )
        .await;
    }

    if !quiet {
        println!("\nPatch saved to {}", manifest_path.display());
        if added {
            println!("  Added: 1");
        } else {
            println!("  Skipped: 1 (already exists)");
        }
    }

    let mut apply_succeeded = false;
    if !args.save_only && added {
        if !quiet {
            println!("\nApplying patches...");
        }
        apply_succeeded = run_nested_apply(
            &args.common.cwd,
            args.common.global,
            args.common.global_prefix.clone(),
            quiet,
            args.common.download_mode.clone(),
            args.common.strict,
        )
        .await;
    }

    // The apply step ran (patch added, not --save-only) but failed →
    // partial failure. The `status` field must agree with the exit code
    // returned below; a hardcoded `success` alongside a non-zero exit
    // misleads JSON consumers.
    let apply_failed = !apply_succeeded && added && !args.save_only;
    // No "download failed" concept here — a blob failure early-returns
    // with status `error` above — so only the apply step can degrade us.
    let (status, exit_code) = run_outcome(false, apply_failed);

    if args.common.json {
        let mut patch_record = serde_json::json!({
            "purl": patch.purl,
            "uuid": patch.uuid,
            "action": if added { "added" } else { "skipped" },
        });
        if added {
            // Only enrich when the patch was actually added — a `skipped`
            // record means the consumer already saw the metadata last time.
            merge_metadata(&mut patch_record, patch_event_metadata(patch));
        }
        let mut result_json = serde_json::json!({
            "status": status,
            "found": 1,
            "downloaded": if added { 1 } else { 0 },
            "applied": if apply_succeeded { 1 } else { 0 },
            "patches": [patch_record],
        });
        // Same contract as `download_and_apply_patches`: omitted when clean.
        if !warnings.is_empty() {
            result_json["warnings"] = serde_json::json!(warnings);
        }
        println!("{}", serde_json::to_string_pretty(&result_json).unwrap());
    }

    exit_code
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
    use socket_patch_core::api::types::VulnerabilityResponse;
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

    #[test]
    fn select_free_user_one_free_patch_returns_it() {
        let patches = vec![mk_patch("u1", "pkg:npm/foo@1.0", "free", "2024-01-01")];
        let out = select_patches(&patches, false, false).expect("ok");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].uuid, "u1");
    }

    #[test]
    fn select_paid_user_prefers_paid_over_free_same_purl() {
        let patches = vec![
            mk_patch("free1", "pkg:npm/foo@1.0", "free", "2024-06-01"),
            mk_patch("paid1", "pkg:npm/foo@1.0", "paid", "2024-01-01"),
        ];
        let out = select_patches(&patches, true, false).expect("ok");
        assert_eq!(out.len(), 1);
        // Paid wins even if free is more recent.
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
}
