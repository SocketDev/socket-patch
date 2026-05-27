use clap::Args;
use regex::Regex;
use socket_patch_core::api::client::{
    build_proxy_fallback_client, get_api_client_with_overrides, is_fallback_candidate,
};
use socket_patch_core::api::types::{
    PatchResponse, PatchSearchResult, SearchResponse, VulnerabilityResponse,
};
use socket_patch_core::crawlers::CrawlerOptions;
use socket_patch_core::manifest::operations::{read_manifest, write_manifest};
use socket_patch_core::manifest::schema::{
    PatchFileInfo, PatchManifest, PatchRecord, VulnerabilityInfo,
};
use socket_patch_core::utils::fuzzy_match::fuzzy_match_packages;
use socket_patch_core::utils::purl::is_purl;
use socket_patch_core::utils::telemetry::{track_patch_fetch_failed, track_patch_fetched};
use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};

use crate::args::{apply_env_toggles, GlobalArgs};
use crate::ecosystem_dispatch::crawl_all_ecosystems;
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
pub(crate) fn severity_rank(severity: &str) -> u8 {
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
pub(crate) fn max_vuln_severity(
    vulns: &HashMap<String, VulnerabilityResponse>,
) -> Option<String> {
    vulns
        .values()
        .max_by_key(|v| severity_rank(&v.severity))
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
    meta.insert(
        "tier".into(),
        serde_json::Value::String(patch.tier.clone()),
    );
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
    if let (Some(record_obj), serde_json::Value::Object(meta_obj)) =
        (record.as_object_mut(), meta)
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

/// Decode a base64 string and write it to `blobs_dir/hash`. Returns a
/// formatted error string referencing `file_path` and `label` on failure.
async fn write_blob_entry(
    blobs_dir: &Path,
    b64: &str,
    hash: &str,
    file_path: &str,
    label: &str,
) -> Result<(), String> {
    let decoded = base64_decode(b64)
        .map_err(|e| format!("Failed to decode {label} for {file_path}: {e}"))?;
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
        if let (Some(blob), Some(hash)) =
            (&file_info.blob_content, &file_info.after_hash)
        {
            if let Err(e) = write_blob_entry(blobs_dir, blob, hash, file_path, "blob").await {
                if !quiet {
                    eprintln!("  [error] {e}");
                }
                return Err(());
            }
        }
        if let (Some(blob), Some(hash)) =
            (&file_info.before_blob_content, &file_info.before_hash)
        {
            if let Err(e) =
                write_blob_entry(blobs_dir, blob, hash, file_path, "before-blob").await
            {
                if !quiet {
                    eprintln!("  [error] {e}");
                }
                return Err(());
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
fn build_patch_record(
    patch: &PatchResponse,
    files: HashMap<String, PatchFileInfo>,
) -> PatchRecord {
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
    #[arg(long = "save-only", alias = "no-apply", env = "SOCKET_SAVE_ONLY", default_value_t = false)]
    pub save_only: bool,

    /// Apply patch immediately without saving to .socket folder.
    #[arg(long = "one-off", env = "SOCKET_ONE_OFF", default_value_t = false)]
    pub one_off: bool,
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
    let uuid_re = Regex::new(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$").unwrap();
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
pub fn select_patches(
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
                    let desc = if p.description.len() > 60 {
                        format!("{}...", &p.description[..57])
                    } else {
                        p.description.clone()
                    };
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
    pub one_off: bool,
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
}

/// Download and apply a set of selected patches.
///
/// Used by both `get` and `scan` commands. Returns (exit_code, json_result).
pub async fn download_and_apply_patches(
    selected: &[PatchSearchResult],
    params: &DownloadParams,
) -> (i32, serde_json::Value) {
    let mut overrides = params.api_overrides.clone();
    if overrides.org_slug.is_none() {
        overrides.org_slug = params.org.clone();
    }
    let (api_client, _) =
        socket_patch_core::api::client::get_api_client_with_overrides(overrides).await;
    let effective_org: Option<&str> = None;

    let socket_dir = params.cwd.join(".socket");
    let blobs_dir = socket_dir.join("blobs");
    let manifest_path = socket_dir.join("manifest.json");

    if let Err(e) = tokio::fs::create_dir_all(&socket_dir).await {
        let err = format!("Failed to create .socket directory: {}", e);
        report_error(params.json, &err);
        return (1, serde_json::json!({"status": "error", "error": err}));
    }
    if let Err(e) = tokio::fs::create_dir_all(&blobs_dir).await {
        let err = format!("Failed to create blobs directory: {}", e);
        report_error(params.json, &err);
        return (1, serde_json::json!({"status": "error", "error": err}));
    }

    let mut manifest = match read_manifest(&manifest_path).await {
        Ok(Some(m)) => m,
        _ => PatchManifest::new(),
    };

    if !params.json && !params.silent {
        eprintln!("\nDownloading {} patch(es)...", selected.len());
    }

    let mut patches_added = 0;
    let mut patches_skipped = 0;
    let mut patches_failed = 0;
    let mut downloaded_patches: Vec<serde_json::Value> = Vec::new();
    let mut updates: Vec<String> = Vec::new();

    for search_result in selected {
        // Check for updates: existing patch with different UUID
        if let Some(existing) = manifest.patches.get(&search_result.purl) {
            if existing.uuid != search_result.uuid {
                updates.push(search_result.purl.clone());
                if !params.json && !params.silent {
                    eprintln!(
                        "  [update] {} (replacing {})",
                        search_result.purl,
                        &existing.uuid[..8]
                    );
                }
            }
        }

        match api_client
            .fetch_patch(effective_org, &search_result.uuid)
            .await
        {
            Ok(Some(patch)) => {
                // Classify against the manifest state BEFORE we touch it.
                // `Skipped` early-returns; `Updated` is preserved so the
                // per-patch JSON record below can include `oldUuid`.
                let action = decide_patch_action(&manifest, &patch.purl, &patch.uuid);
                if let PatchAction::Skipped = action {
                    if !params.json && !params.silent {
                        eprintln!("  [skip] {} (already in manifest)", patch.purl);
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
                let mut files = HashMap::new();
                for (file_path, file_info) in &patch.files {
                    if let (Some(before), Some(after)) =
                        (&file_info.before_hash, &file_info.after_hash)
                    {
                        files.insert(
                            file_path.clone(),
                            PatchFileInfo {
                                before_hash: before.clone(),
                                after_hash: after.clone(),
                            },
                        );
                    }
                }

                let quiet = params.json || params.silent;
                if write_all_patch_blobs(&blobs_dir, &patch, quiet).await.is_err() {
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
                        if !params.json && !params.silent {
                            eprintln!("  [update] {}", patch.purl);
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

    if !params.json && !params.silent {
        eprintln!("\nPatches saved to {}", manifest_path.display());
        eprintln!("  Added: {patches_added}");
        if patches_skipped > 0 {
            eprintln!("  Skipped: {patches_skipped}");
        }
        if patches_failed > 0 {
            eprintln!("  Failed: {patches_failed}");
        }
        if !updates.is_empty() {
            eprintln!("  Updated: {}", updates.len());
        }
    }

    // Auto-apply unless --save-only
    let mut apply_succeeded = false;
    if !params.save_only && patches_added > 0 {
        if !params.json && !params.silent {
            eprintln!("\nApplying patches...");
        }
        let apply_args = super::apply::ApplyArgs {
            common: crate::args::GlobalArgs {
                cwd: params.cwd.clone(),
                manifest_path: manifest_path.display().to_string(),
                global: params.global,
                global_prefix: params.global_prefix.clone(),
                silent: params.json || params.silent,
                download_mode: params.download_mode.clone(),
                ..crate::args::GlobalArgs::default()
            },
            force: false,
        };
        let code = super::apply::run(apply_args).await;
        apply_succeeded = code == 0;
        if code != 0 && !params.json && !params.silent {
            eprintln!("\nSome patches could not be applied.");
        }
    }

    let result_json = serde_json::json!({
        "status": if patches_failed > 0 { "partial_failure" } else { "success" },
        "found": selected.len(),
        "downloaded": patches_added,
        "skipped": patches_skipped,
        "failed": patches_failed,
        "applied": if apply_succeeded { patches_added } else { 0 },
        "updated": updates.len(),
        "patches": downloaded_patches,
    });

    let exit_code = if patches_failed > 0 || (!apply_succeeded && patches_added > 0 && !params.save_only) { 1 } else { 0 };
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
        if args.common.json {
            print_json(&serde_json::json!({
                "status": "error",
                "error": "--one-off and --save-only cannot be used together",
            }));
        } else {
            eprintln!("Error: --one-off and --save-only cannot be used together");
        }
        return 1;
    }

    apply_env_toggles(&args.common);
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
                if !args.common.json {
                    println!("Treating \"{}\" as a package name search", args.identifier);
                }
                IdentifierType::Package
            }
        }
    };

    // Handle UUID: fetch and download directly
    if id_type == IdentifierType::Uuid {
        if !args.common.json {
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
                    } else {
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
                // Save to manifest
                return save_and_apply_patch(&args, &patch.purl, &patch.uuid, effective_org_slug)
                    .await;
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
                } else {
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
            if !args.common.json {
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
            if !args.common.json {
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
                } else if args.common.global {
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
                return 0;
            }

            if !args.common.json {
                println!("Found {} packages", all_packages.len());
            }

            let matches = fuzzy_match_packages(&args.identifier, &all_packages, 20);

            if matches.is_empty() {
                if args.common.json {
                    print_json(&empty_result_json("no_match"));
                } else {
                    println!("No packages matching \"{}\" found.", args.identifier);
                }
                return 0;
            }

            if !args.common.json {
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
        } else {
            println!(
                "No patches found for {}: {}",
                id_type, args.identifier
            );
        }
        return 0;
    }

    if !args.common.json {
        display_search_results(&search_response.patches, search_response.can_access_paid_patches);
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
        } else {
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
        if !args.common.json {
            println!("No patches selected.");
        }
        return 0;
    }

    // Confirm before downloading (default YES)
    let prompt = format!("Download {} patch(es)?", selected.len());
    if !confirm(&prompt, true, args.common.yes, args.common.json) {
        if !args.common.json {
            println!("Download cancelled.");
        }
        return 0;
    }

    // Download and apply
    let params = DownloadParams {
        cwd: args.common.cwd.clone(),
        org: args.common.org.clone(),
        save_only: args.save_only,
        one_off: args.one_off,
        global: args.common.global,
        global_prefix: args.common.global_prefix.clone(),
        json: args.common.json,
        silent: false,
        download_mode: args.common.download_mode.clone(),
        api_overrides: args.common.api_client_overrides(),
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
            let desc = if patch.description.len() > 80 {
                format!("{}...", &patch.description[..77])
            } else {
                patch.description.clone()
            };
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

async fn save_and_apply_patch(
    args: &GetArgs,
    _purl: &str,
    uuid: &str,
    _org_slug: Option<&str>,
) -> i32 {
    // For UUID mode, fetch and save
    let (api_client, _) =
        get_api_client_with_overrides(args.common.api_client_overrides()).await;
    let effective_org: Option<&str> = None; // org slug is already stored in the client

    let patch = match api_client.fetch_patch(effective_org, uuid).await {
        Ok(Some(p)) => p,
        Ok(None) => {
            if args.common.json {
                print_json(&empty_result_json("not_found"));
            } else {
                println!("No patch found with UUID: {uuid}");
            }
            return 0;
        }
        Err(e) => {
            report_error(args.common.json, e);
            return 1;
        }
    };

    let socket_dir = args.common.cwd.join(".socket");
    let blobs_dir = socket_dir.join("blobs");
    let manifest_path = socket_dir.join("manifest.json");

    if let Err(e) = tokio::fs::create_dir_all(&blobs_dir).await {
        report_error(args.common.json, format!("Failed to create blobs directory: {e}"));
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

    if write_all_patch_blobs(&blobs_dir, &patch, args.common.json)
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
            eprintln!("Error: Blob decode or write failed for patch {}", patch.purl);
        }
        return 1;
    }

    let added = manifest
        .patches
        .get(&patch.purl)
        .is_none_or(|p| p.uuid != patch.uuid);

    manifest
        .patches
        .insert(patch.purl.clone(), build_patch_record(&patch, files));

    if let Err(e) = write_manifest(&manifest_path, &manifest).await {
        report_error(args.common.json, format!("Error writing manifest: {e}"));
        return 1;
    }

    if !args.common.json {
        println!("\nPatch saved to {}", manifest_path.display());
        if added {
            println!("  Added: 1");
        } else {
            println!("  Skipped: 1 (already exists)");
        }
    }

    let mut apply_succeeded = false;
    if !args.save_only && added {
        if !args.common.json {
            println!("\nApplying patches...");
        }
        let apply_args = super::apply::ApplyArgs {
            common: crate::args::GlobalArgs {
                cwd: args.common.cwd.clone(),
                manifest_path: manifest_path.display().to_string(),
                global: args.common.global,
                global_prefix: args.common.global_prefix.clone(),
                silent: args.common.json,
                download_mode: args.common.download_mode.clone(),
                ..crate::args::GlobalArgs::default()
            },
            force: false,
        };
        let code = super::apply::run(apply_args).await;
        apply_succeeded = code == 0;
        if code != 0 && !args.common.json {
            eprintln!("\nSome patches could not be applied.");
        }
    }

    if args.common.json {
        let mut patch_record = serde_json::json!({
            "purl": patch.purl,
            "uuid": patch.uuid,
            "action": if added { "added" } else { "skipped" },
        });
        if added {
            // Only enrich when the patch was actually added — a `skipped`
            // record means the consumer already saw the metadata last time.
            merge_metadata(&mut patch_record, patch_event_metadata(&patch));
        }
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({
            "status": "success",
            "found": 1,
            "downloaded": if added { 1 } else { 0 },
            "applied": if apply_succeeded { 1 } else { 0 },
            "patches": [patch_record],
        })).unwrap());
    }

    if !apply_succeeded && added && !args.save_only { 1 } else { 0 }
}

fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
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

    fn mk_patch(
        uuid: &str,
        purl: &str,
        tier: &str,
        published_at: &str,
    ) -> PatchSearchResult {
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
}
