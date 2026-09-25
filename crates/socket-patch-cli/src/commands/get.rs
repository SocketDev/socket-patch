use clap::Args;
use regex::Regex;
use socket_patch_core::api::client::{
    build_proxy_fallback_client, get_api_client_with_overrides, is_fallback_candidate, ApiClient,
    ApiError,
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
use socket_patch_core::patch::apply::{is_valid_blob_hash, select_installed_variants};
use socket_patch_core::patch::apply_lock::{LockError, LockGuard};
use socket_patch_core::telemetry::{track_patch_fetch_failed, track_patch_fetched};
use socket_patch_core::utils::purl::{
    canonical_purl, is_purl, normalize_purl, strip_purl_qualifiers,
};
use socket_patch_core::vendor::{load_state, lookup_entry, VendorEntry, VendorState};
use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::time::Duration;

use crate::args::{apply_env_toggles, GlobalArgs};
use crate::commands::bun_preflight::{
    bun_vendor_preflight, bun_vendor_preflight_with_ledger, BunVendorRefusal,
};
use crate::commands::lock_cli::lock_failure;
use crate::ecosystem_dispatch::{
    crawl_all_ecosystems, find_packages_for_rollback, partition_purls,
};
use crate::ui::{print_json, select_one, SelectError};

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

/// Report a failed apply-lock acquire in get's legacy error shape — the
/// `{status: "error", error: "<message>"}` envelope every other hard error
/// here uses, plus the stable `errorCode` (`lock_held` / `lock_io`) the
/// other lock sites emit — and return the envelope for the caller's
/// early-return guard. The message/code mapping is
/// [`crate::commands::lock_cli::lock_failure`]'s, so the waited clause and
/// the I/O rendering cannot drift from `apply`'s.
fn report_lock_failure(
    json: bool,
    socket_dir: &Path,
    err: &LockError,
    timeout: Duration,
) -> serde_json::Value {
    let (code, message) = lock_failure(err, timeout);
    let envelope = serde_json::json!({
        "status": "error",
        "errorCode": code,
        "error": message,
    });
    if json {
        print_json(&envelope);
    } else {
        eprint!(
            "{}",
            crate::commands::lock_cli::format_lock_error(socket_dir, err, timeout)
        );
    }
    envelope
}

/// Decode a base64 string and write it to `blobs_dir/hash`. Returns whether
/// the blob file was NEWLY created (`false`: a blob with this hash already
/// existed — content-addressed, so it is the same bytes — and was
/// overwritten in place), or a formatted error string referencing
/// `file_path` and `label` on failure.
///
/// `blobs_dir` is created here, lazily — only once a blob is actually
/// about to be persisted — so a run that records nothing (every fetch
/// failed, every patch skipped, undecodable content) leaves no empty
/// `.socket/blobs/` behind.
async fn write_blob_entry(
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
    tokio::fs::create_dir_all(blobs_dir)
        .await
        .map_err(|e| format!("Failed to create blobs directory: {e}"))?;
    let target = blobs_dir.join(hash);
    // Probed BEFORE the (overwriting) write: a blob that already existed —
    // a live record's revert data, or a sibling patch's shared after-blob
    // written earlier this run — is never this call's to remove on unwind.
    let existed = tokio::fs::try_exists(&target).await.unwrap_or(false);
    tokio::fs::write(&target, &decoded)
        .await
        .map_err(|e| format!("Failed to write {label} for {file_path}: {e}"))?;
    Ok(!existed)
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
async fn write_all_patch_blobs(
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
async fn unwind_new_blobs(blobs_dir: &Path, hashes: &[String]) {
    for hash in hashes {
        let _ = tokio::fs::remove_file(blobs_dir.join(hash)).await;
    }
    if let Some(stop_dir) = blobs_dir.parent() {
        socket_patch_core::utils::socket_dir::prune_empty_dirs(blobs_dir, stop_dir).await;
    }
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

    /// Download the patch and record it in the manifest without applying it.
    // `value_parser = parse_bool_flag` matches the `GlobalArgs` bool flags:
    // clap's default bool parser accepts only the literal strings
    // `true`/`false` from the env binding, so `SOCKET_SAVE_ONLY=1` (or an
    // exported-but-empty `SOCKET_SAVE_ONLY=`) aborted every `get`
    // invocation.
    #[arg(
        long = "save-only",
        alias = "no-apply",
        env = "SOCKET_SAVE_ONLY",
        default_value_t = false,
        value_parser = crate::args::parse_bool_flag,
    )]
    pub save_only: bool,

    /// Apply the patch without saving it to the .socket folder (not yet
    /// implemented).
    // Hidden: it always fails with "not yet implemented" (see `run`), but
    // stays parseable so scripts and `SOCKET_ONE_OFF` keep getting that
    // explicit error instead of a clap parse failure.
    // `value_parser = parse_bool_flag`: same env-crash fix as `--save-only`
    // above — and `SOCKET_ONE_OFF` is shared with `rollback --one-off`,
    // which already parses boolishly; the two must not diverge.
    #[arg(
        long = "one-off",
        env = "SOCKET_ONE_OFF",
        default_value_t = false,
        value_parser = crate::args::parse_bool_flag,
        hide = true,
    )]
    pub one_off: bool,

    /// Download patches for every release variant of a matched package,
    /// not just the one matching the locally-installed distribution.
    ///
    /// Affects ecosystems with per-release variants: PyPI (wheel/sdist),
    /// RubyGems (platform) and Maven (classifier). Also turns off the
    /// installed-version filter for CVE/GHSA searches, so every version's
    /// patch is fetched, installed or not.
    // Variant keys: PyPI `artifact_id`, RubyGems `platform`, Maven
    // `classifier`. Off by default: only the patch(es) for the installed
    // dist are fetched.
    #[arg(
        long = "all-releases",
        env = "SOCKET_ALL_RELEASES",
        default_value_t = false,
        value_parser = crate::args::parse_bool_flag,
    )]
    pub all_releases: bool,

    /// How to consume the patches: the same modes as `scan --mode`
    /// (default: agent).
    // agent = record in .socket/manifest.json + blobs and apply in place;
    // hosted = rewrite lockfiles so the patched deps resolve to Socket's
    // hosted patch server (no manifest, no blobs; state lives in the
    // redirect ledger); vendored = commit patched artifacts under
    // .socket/vendor/ and rewire the lockfile (no manifest, no blobs; the
    // vendor ledger carries the records). Hosted/vendored runs produce the
    // same on-disk result as `scan --mode hosted|vendored` selecting the
    // same patch. The per-value help comes from `ScanMode`'s variant docs.
    // No env binding, matching `scan --mode`.
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

/// Case-insensitive advisory-id shapes, compiled once. The UUID shape is
/// [`crate::looks_like_uuid`] (the same 8-4-4-4-12 hex check the argv
/// rewrite uses), so the two detectors cannot drift.
static CVE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^CVE-\d{4}-\d+$").expect("hardcoded CVE regex must compile"));
static GHSA_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$")
        .expect("hardcoded GHSA regex must compile")
});

fn detect_identifier_type(identifier: &str) -> Option<IdentifierType> {
    if crate::looks_like_uuid(identifier) {
        Some(IdentifierType::Uuid)
    } else if CVE_RE.is_match(identifier) {
        Some(IdentifierType::Cve)
    } else if GHSA_RE.is_match(identifier) {
        Some(IdentifierType::Ghsa)
    } else if is_purl(identifier) {
        Some(IdentifierType::Purl)
    } else {
        None
    }
}

/// Advisory labels for a patch: every advisory's CVE ids, or the advisory
/// id itself when it has no CVE assigned yet (a fresh GHSA). Sorted and
/// deduplicated, so the text never depends on `HashMap` iteration order.
fn vuln_labels(vulns: &HashMap<String, VulnerabilityResponse>) -> Vec<String> {
    let mut labels: Vec<String> = vulns
        .iter()
        .flat_map(|(id, v)| {
            if v.cves.is_empty() {
                vec![id.clone()]
            } else {
                v.cves.clone()
            }
        })
        .collect();
    labels.sort();
    labels.dedup();
    labels
}

/// Render one patch as an interactive-selection option line:
/// `<uuid> [<TIER>] (fixes: <ids>) - <description>`.
///
/// The `(fixes: …)` segment is omitted for a patch with no
/// vulnerabilities, and ` - <description>` for an empty description (no
/// dangling dash). The tier is upper-cased to match the search listing.
/// The description is truncated to 60 characters.
fn format_patch_option(p: &PatchSearchResult) -> String {
    let labels = vuln_labels(&p.vulnerabilities);
    let vulns = if labels.is_empty() {
        String::new()
    } else {
        format!(" (fixes: {})", labels.join(", "))
    };
    let desc = crate::ui::truncate(&p.description, 60);
    let desc = if desc.is_empty() {
        String::new()
    } else {
        format!(" - {desc}")
    };
    format!("{} [{}]{vulns}{desc}", p.uuid, p.tier.to_uppercase())
}

/// One-line human summary of a patch:
/// `<purl> [<TIER>] <short uuid>: fixes <id> (<SEVERITY>)`, or with
/// several advisories `fixes <ids> (highest: <SEVERITY>)` — a bare
/// `(HIGH)` after a list reads as the last id's severity.
///
/// `patch_id` is omitted (with its colon) when `None`, the `fixes` part
/// when the patch has no advisories, and the severity when none is known.
/// The severity is colored when `color` is on. The purl is shown decoded
/// (`%40scope` → `@scope`).
fn format_patch_summary(
    purl: &str,
    tier: &str,
    patch_id: Option<&str>,
    vulns: &HashMap<String, VulnerabilityResponse>,
    color: bool,
) -> String {
    let mut line = format!("{} [{}]", normalize_purl(purl), tier.to_uppercase());
    if let Some(id) = patch_id {
        line.push(' ');
        line.push_str(short_uuid(id));
    }
    let labels = vuln_labels(vulns);
    if !labels.is_empty() {
        let sep = if patch_id.is_some() { ": " } else { " " };
        line.push_str(&format!("{sep}fixes {}", labels.join(", ")));
        if let Some(sev) = max_vuln_severity(vulns) {
            let sev = crate::ui::severity(&sev.to_uppercase(), color);
            if labels.len() > 1 {
                line.push_str(&format!(" (highest: {sev})"));
            } else {
                line.push_str(&format!(" ({sev})"));
            }
        }
    }
    line
}

/// Compare two strings the way a person sorts versions: runs of ASCII
/// digits compare as numbers (`4.17.2` < `4.17.10`), everything else
/// character by character. Ties on numeric value (`01` vs `1`) fall back
/// to plain string order so the result is a total order.
fn natural_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    let (mut x, mut y) = (a.as_bytes(), b.as_bytes());
    loop {
        match (x.first(), y.first()) {
            (None, None) => return a.cmp(b),
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(c), Some(d)) if c.is_ascii_digit() && d.is_ascii_digit() => {
                let xl = x.iter().take_while(|c| c.is_ascii_digit()).count();
                let yl = y.iter().take_while(|c| c.is_ascii_digit()).count();
                let trim = |s: &[u8]| -> usize { s.iter().take_while(|&&c| c == b'0').count() };
                let (xn, yn) = (&x[trim(&x[..xl])..xl], &y[trim(&y[..yl])..yl]);
                let ord = xn.len().cmp(&yn.len()).then_with(|| xn.cmp(yn));
                if ord != Ordering::Equal {
                    return ord;
                }
                x = &x[xl..];
                y = &y[yl..];
            }
            (Some(c), Some(d)) => {
                if c != d {
                    return c.cmp(d);
                }
                x = &x[1..];
                y = &y[1..];
            }
        }
    }
}

/// The search listing printed before selection: grouped by PURL (in
/// natural version order) and best-first within each PURL — the same
/// order [`select_patches`] resolves in, so a package's first entry is the
/// one that will be applied. A `by-cve` / `by-ghsa` search can span
/// several packages, hence the grouping. Severities are colored when
/// `color` is on. Ends with a blank line.
fn format_search_results(
    patches: &[&PatchSearchResult],
    can_access_paid: bool,
    color: bool,
) -> String {
    let mut patches: Vec<&PatchSearchResult> = patches.to_vec();
    patches.sort_by(|a, b| natural_cmp(&a.purl, &b.purl).then_with(|| cmp_search_results(a, b)));

    let mut out = format!(
        "Found {}:\n\n",
        crate::ui::plural(patches.len(), "patch", "patches")
    );
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
        out.push_str(&format!(
            "  {}. {}{tier_label}{access_label}\n",
            i + 1,
            normalize_purl(&patch.purl)
        ));
        out.push_str(&format!("     UUID: {}\n", patch.uuid));
        let desc = crate::ui::truncate(&patch.description, 80);
        if !desc.is_empty() {
            out.push_str(&format!("     Description: {desc}\n"));
        }
        let mut fixes: Vec<(String, String)> = patch
            .vulnerabilities
            .iter()
            .map(|(id, vuln)| {
                let ids = if vuln.cves.is_empty() {
                    id.to_string()
                } else {
                    let mut cves = vuln.cves.clone();
                    cves.sort();
                    cves.join(", ")
                };
                (ids, vuln.severity.clone())
            })
            .collect();
        fixes.sort();
        if !fixes.is_empty() {
            let fixes: Vec<String> = fixes
                .iter()
                .map(|(ids, sev)| {
                    if sev.is_empty() {
                        ids.clone()
                    } else {
                        format!("{ids} ({})", crate::ui::severity(sev, color))
                    }
                })
                .collect();
            out.push_str(&format!("     Fixes: {}\n", fixes.join(", ")));
        }
        out.push('\n');
    }
    out
}

/// The stderr line naming the package a package-name search went with
/// (only the best fuzzy match is searched).
fn format_best_match(purl: &str, matches: usize) -> String {
    if matches > 1 {
        format!(
            "Best match: {} (of {} matching packages)",
            normalize_purl(purl),
            matches
        )
    } else {
        format!("Best match: {}", normalize_purl(purl))
    }
}

/// The `--verbose` per-version detail behind [`format_skip_summary`]: one
/// `[skip]` line per purl (a free and a paid patch for the same version
/// would otherwise repeat it), in natural version order.
fn format_verbose_skips(skips: &[serde_json::Value]) -> Vec<String> {
    let mut by_purl: std::collections::BTreeMap<&str, &str> = std::collections::BTreeMap::new();
    for rec in skips {
        let purl = rec["purl"].as_str().unwrap_or_default();
        let reason = match rec["errorCode"].as_str() {
            Some("package_not_installed") | None => "version not installed",
            Some(code) => code,
        };
        by_purl.entry(purl).or_insert(reason);
    }
    let mut rows: Vec<(String, &str)> = by_purl
        .into_iter()
        .map(|(purl, reason)| (normalize_purl(purl).into_owned(), reason))
        .collect();
    rows.sort_by(|a, b| natural_cmp(&a.0, &b.0));
    rows.into_iter()
        .map(|(purl, reason)| format!("  [skip] {purl} ({reason})"))
        .collect()
}

/// Whether [`select_patches`] has a choice to make that nobody made in
/// advance: a free user, several accessible patches for one purl, and no
/// `--yes`/`--json`. It then shows a menu (interactive stdin) or prints
/// the non-interactive note (unless `--silent`).
pub(crate) fn selection_has_choice(
    candidates: &[PatchSearchResult],
    can_access_paid: bool,
    common: &GlobalArgs,
) -> bool {
    if can_access_paid || common.yes || common.json {
        return false;
    }
    let mut seen = std::collections::HashSet::new();
    candidates
        .iter()
        .filter(|p| p.tier == "free")
        .any(|p| !seen.insert(p.purl.as_str()))
}

/// Whether [`select_patches`] will put a menu in front of the user for
/// these candidates: [`selection_has_choice`] and an interactive stdin
/// (mirrors `select_one`).
fn selection_prompted(
    candidates: &[PatchSearchResult],
    can_access_paid: bool,
    common: &GlobalArgs,
) -> bool {
    use std::io::IsTerminal;
    selection_has_choice(candidates, can_access_paid, common) && std::io::stdin().is_terminal()
}

/// The "which patch will be installed" block printed before the prompt
/// when the listing above showed more patches than were selected (a paid
/// user's auto-pick, or narrowing): one [`format_patch_summary`] line per
/// selected patch. Ends with a blank line.
fn format_selected_patches(selected: &[PatchSearchResult], color: bool) -> String {
    let mut out = String::from("Selected:\n");
    for p in selected {
        out.push_str(&format!(
            "  {}\n",
            format_patch_summary(&p.purl, &p.tier, Some(&p.uuid), &p.vulnerabilities, color)
        ));
    }
    out.push('\n');
    out
}

/// Number of distinct purls among skip records.
fn distinct_skip_purls(skips: &[serde_json::Value]) -> usize {
    let purls: std::collections::BTreeSet<&str> = skips
        .iter()
        .map(|r| r["purl"].as_str().unwrap_or_default())
        .collect();
    purls.len()
}

/// Summary lines for the patches the installed-version narrowing dropped,
/// one line per reason (instead of one `[skip]` line per version), in a
/// fixed order: not installed first, then each layout code alphabetically.
fn format_skip_summary(skips: &[serde_json::Value]) -> Vec<String> {
    let mut by_code: std::collections::BTreeMap<&str, Vec<serde_json::Value>> =
        std::collections::BTreeMap::new();
    for rec in skips {
        let code = rec["errorCode"].as_str().unwrap_or("package_not_installed");
        by_code.entry(code).or_default().push(rec.clone());
    }
    let mut lines = Vec::new();
    if let Some(recs) = by_code.remove("package_not_installed") {
        let n = recs.len();
        let versions = distinct_skip_purls(&recs);
        lines.push(format!(
            "Skipped {} for {} not installed here (use --all-releases to include {}).",
            crate::ui::plural(n, "patch", "patches"),
            crate::ui::plural(versions, "package version", "package versions"),
            if n == 1 { "it" } else { "them" },
        ));
    }
    for (code, recs) in by_code {
        lines.push(format!(
            "Skipped {} for {} ({code}; see the warning above).",
            crate::ui::plural(recs.len(), "patch", "patches"),
            crate::ui::plural(
                distinct_skip_purls(&recs),
                "package version",
                "package versions"
            ),
        ));
    }
    lines
}

/// The result line when the installed-version narrowing dropped EVERY
/// accessible patch.
fn format_all_narrowed(skips: &[serde_json::Value]) -> String {
    // When every skip is a PnP layout refusal, "not installed" and the
    // --all-releases advice would both be wrong: the packages were never
    // judged (structurally invisible), and the escape hatch cannot make a
    // PnP layout patchable — point at the layout warning instead.
    let pnp_only = skips.iter().all(|rec| {
        matches!(
            rec["errorCode"].as_str(),
            Some("yarn_pnp_unsupported" | "pnpm_pnp_unsupported")
        )
    });
    if pnp_only {
        return format!(
            "Found {}, but this project's Plug'n'Play layout makes its npm packages \
             unpatchable here; see the layout warning above for the remedy.",
            crate::ui::plural(skips.len(), "patch", "patches")
        );
    }
    match distinct_skip_purls(skips) {
        1 => "Patches exist for 1 package version, but it is not installed here. \
              Use --all-releases to fetch it anyway."
            .to_string(),
        n => format!(
            "Patches exist for {n} package versions, but none of them are installed here. \
             Use --all-releases to fetch them anyway."
        ),
    }
}

/// The confirmation question for `n` selected patches.
fn format_confirm_prompt(mode: super::scan::ScanMode, n: usize, save_only: bool) -> String {
    let patches = crate::ui::plural(n, "patch", "patches");
    match mode {
        super::scan::ScanMode::Agent if save_only => format!("Download {patches}?"),
        super::scan::ScanMode::Agent => format!("Download and apply {patches}?"),
        super::scan::ScanMode::Vendored => format!("Download and vendor {patches}?"),
        super::scan::ScanMode::Hosted => format!(
            "Redirect {} to the hosted patch server?",
            crate::ui::plural(n, "package", "packages")
        ),
    }
}

/// The `--dry-run` result line: `[dry-run] Would <action> N patches. No
/// changes made.`
fn format_dry_run(action: &str, n: usize) -> String {
    format!(
        "[dry-run] Would {action} {}. No changes made.",
        crate::ui::plural(n, "patch", "patches")
    )
}

/// What a package-name search says when the crawl found nothing: scan's
/// empty-crawl line (get has no ecosystem or path filter to name).
fn no_packages_message(global: bool) -> String {
    crate::commands::scan::render::no_packages_message(global, None, &[])
}

/// The human result for a patch the caller's plan cannot download.
/// `patch` names it (a purl, or the uuid when the purl is unknown).
fn format_paid_required(patch: &str) -> String {
    format!(
        "This patch requires a paid subscription to download.\n  \
         Patch: {patch}\n  \
         Upgrade at: https://socket.dev/pricing"
    )
}

/// The summary after the multi-patch download loop. A run that changed
/// nothing says so instead of claiming the patches were "saved".
fn format_save_summary(
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

/// The summary after a single-uuid save. `what` is `"Patch"` or `"Patch
/// record"`. `ends_run` says an unchanged record really ends the run (the
/// agent path skips apply); the vendored path still runs its vendor step,
/// so it must not promise "nothing to update".
fn format_single_save(
    what: &str,
    action: &PatchAction,
    manifest_path: &Path,
    purl: &str,
    ends_run: bool,
) -> String {
    match action {
        PatchAction::Added => format!("{what} saved to {}\n  Added: 1", manifest_path.display()),
        PatchAction::Updated { old_uuid } => format!(
            "{what} saved to {}\n  Updated: 1 (replacing {})",
            manifest_path.display(),
            short_uuid(old_uuid)
        ),
        PatchAction::Skipped => format!(
            "{} already has this patch recorded in {}{}",
            normalize_purl(purl),
            manifest_path.display(),
            if ends_run {
                "; nothing to update."
            } else {
                "."
            }
        ),
    }
}

/// `  [skip] <purl> (<why>)` for a record the download phase reuses, with
/// the purl decoded for display (`%40scope` reads as `@scope`).
fn format_record_skip(purl: &str, why: &str) -> String {
    format!("  [skip] {} ({why})", normalize_purl(purl))
}

/// The closing error printed when the nested apply failed. Apply's own
/// per-package `Error: Failed to patch …` lines print above it, even
/// under `--silent`, so this line needs no "re-run" hint.
const APPLY_FAILED: &str = "Error: Some patches could not be applied.";

/// Local shape check for an identifier forced with `--id` / `--cve` /
/// `--ghsa`, so a typo fails fast with a readable message instead of a raw
/// API 400 body. `None` when it is well-formed (or the type is not
/// shape-checked).
fn forced_identifier_error(identifier: &str, id_type: IdentifierType) -> Option<String> {
    let (ok, what, form) = match id_type {
        IdentifierType::Uuid => (
            crate::looks_like_uuid(identifier),
            "patch UUID",
            "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        ),
        IdentifierType::Cve => (CVE_RE.is_match(identifier), "CVE ID", "CVE-YYYY-NNNN"),
        IdentifierType::Ghsa => (
            GHSA_RE.is_match(identifier),
            "GHSA ID",
            "GHSA-xxxx-xxxx-xxxx",
        ),
        IdentifierType::Purl | IdentifierType::Package => return None,
    };
    (!ok).then(|| format!("\"{identifier}\" is not a valid {what} (expected {form})"))
}

/// Select one patch per PURL from available patches.
///
/// Within a PURL, candidates are ranked by [`cmp_search_results`]: merged
/// patches first, then by severity (critical → low), then most recently
/// published. `tier` is an access filter here, not a ranking signal — a
/// free critical patch outranks a paid low one.
///
/// - Users with paid access: auto-select the top-ranked patch per PURL.
/// - Free users with one patch, or with `--yes`: auto-select the
///   top-ranked one.
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
    common: &GlobalArgs,
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
        } else if group.len() == 1 || (common.yes && !common.json) {
            // One candidate, or `--yes` (which answers every prompt with its
            // default — the menu's default is the top-ranked patch). JSON
            // mode keeps its `selection_required` contract below.
            selected.push(group[0].clone());
        } else {
            // Free user with multiple patches: interactive selection
            let options: Vec<String> = group.iter().map(|p| format_patch_option(p)).collect();

            match select_one(
                &format!("Multiple patches available for {purl}. Select one:"),
                &options,
                common,
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
                    print_json(&serde_json::json!({
                        "status": "selection_required",
                        "error": format!("Multiple patches available for {purl}. Re-run with the chosen UUID as the identifier (`socket-patch get <uuid>`) to select one."),
                        "purl": purl,
                        "options": options_json,
                    }));
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
    pub save_only: bool,
    pub global: bool,
    pub global_prefix: Option<PathBuf>,
    pub json: bool,
    pub silent: bool,
    /// `--download-mode` value forwarded to the apply step.
    pub download_mode: String,
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

fn crawler_options_for(common: &GlobalArgs) -> CrawlerOptions {
    CrawlerOptions {
        cwd: common.cwd.clone(),
        global: common.global,
        global_prefix: common.global_prefix.clone(),
    }
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
/// With `--all-releases` set this is a verbatim pass-through.
async fn filter_to_installed_releases(
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
    // in. Two identical runs produced different JSON. Sort the multi-
    // variant bases so their warnings and kept variants are stable, and
    // sort the whole kept list by purl before returning (below and at the
    // early return): every sibling collection in the same envelope —
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
    // All collected PURLs are PyPI; no ecosystem filter needed.
    let partitioned = partition_purls(&all_qualified, None);
    let paths = find_packages_for_rollback(&partitioned, crawler_options, true).await;

    for (base, variants) in multi {
        // Any variant's resolved path works — they all map to the same
        // installed package directory.
        let pkg_path = variants.iter().find_map(|s| paths.get(&s.purl)).cloned();
        let Some(pkg_path) = pkg_path else {
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
            match api_client.fetch_patch(&s.uuid).await {
                Ok(Some(patch)) => {
                    candidates.push((s.purl.clone(), files_with_both_hashes(&patch)));
                    views.insert(s.uuid.clone(), patch);
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
fn sort_by_purl(patches: &mut [PatchSearchResult]) {
    patches.sort_by(|a, b| a.purl.cmp(&b.purl).then_with(|| a.uuid.cmp(&b.uuid)));
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

/// Does the raw pnpm-lock text RESOLVE `name@version`? Boundary-anchored
/// probes over the three lock grammars — a plain `contains` collided on
/// version prefixes (`left-pad@1.3.0` matched inside
/// `left-pad@1.3.0-beta.1`), name suffixes (`pad@1.3.0` inside
/// `left-pad@1.3.0`), and unscoped-inside-scoped names (`name@1.0.0` inside
/// `@scope/name@1.0.0`). The needles cover v6/v9's `name@version` and v5's
/// `/name/version` key spellings; a match counts only when the preceding
/// char cannot extend the name (start/whitespace/quote, or a `/` delimiter
/// itself preceded by such a boundary) and the following char cannot extend
/// the version (so `:`, `'`, `(`, and v5's `_peer` suffix all accept).
/// Heuristic by design: a false negative degrades to a calm skip, a false
/// positive costs one grant request the rewriter's per-dep confirmation
/// then ignores.
fn pnpm_lock_resolves(text: &str, name: &str, version: &str) -> bool {
    let version_boundary = |c: char| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+'));
    let name_boundary = |c: char| matches!(c, ' ' | '\t' | '\n' | '\r' | '\'' | '"');
    for needle in [format!("{name}@{version}"), format!("/{name}/{version}")] {
        for (pos, _) in text.match_indices(needle.as_str()) {
            let before_ok = match text[..pos].chars().next_back() {
                None => true,
                // v5/v6's leading key delimiter — legitimate only when the
                // char before it is itself a boundary (otherwise this is a
                // scoped `@scope/<name>` tail: a DIFFERENT package).
                Some('/') => text[..pos - 1]
                    .chars()
                    .next_back()
                    .is_none_or(name_boundary),
                Some(c) => name_boundary(c),
            };
            let after_ok = text[pos + needle.len()..]
                .chars()
                .next()
                .is_none_or(version_boundary);
            if before_ok && after_ok {
                return true;
            }
        }
    }
    false
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
/// `yarn_pnp_unsupported`, not a false "not installed"). pnpm PnP skips
/// carry `pnpm_pnp_unsupported` in agent/vendored modes; hosted mode — the
/// refusal's own remedy — keeps the versions the raw pnpm-lock.yaml text
/// resolves ([`pnpm_lock_resolves`]), labels a judged miss
/// `package_not_installed` like any other mode, and reserves the layout
/// code for an unreadable lock (no judgment possible).
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

    let canon = canonical_purl;

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
    let found = find_packages_for_rollback(&partitioned, &crawler_options_for(common), true).await;
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
    // pnpm PnP + hosted: the lock inventory REFUSED, so nothing above could
    // mark the installed version — but the pnpm-lock.yaml the hosted
    // rewriter will edit is right there. Read its raw text once and gate the
    // keep-branch below on version membership, so a large advisory fan-out
    // doesn't request grants for every version ever patched (raw
    // `read_to_string` matches the hosted flow's own candidate-file reads).
    let pnpm_pnp_lock_text: Option<String> = (pnp_pnpm && mode == super::scan::ScanMode::Hosted)
        .then(|| std::fs::read_to_string(common.cwd.join("pnpm-lock.yaml")).ok())
        .flatten();

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
            // The pnpm PnP refusal's own remedy is the hosted lockfile
            // rewrite — but only for versions the lock ACTUALLY resolves:
            // keeping the whole fan-out would request grants for every
            // version ever patched. Anchored probe over the raw lock text
            // (see `pnpm_lock_resolves`); a hit is kept (the rewriter's
            // per-dep confirmation still decides). A judged MISS is a
            // genuine "version not resolved" verdict — the layout blocked
            // nothing — so it carries the same `package_not_installed` code
            // a non-PnP pnpm project would get; only an UNREADABLE lock
            // (no judgment possible) keeps the layout-refusal code.
            let decoded = canon(&result.purl);
            let coord = decoded.strip_prefix("pkg:npm/").unwrap_or(&decoded);
            if mode == super::scan::ScanMode::Hosted {
                match (pnpm_pnp_lock_text.as_deref(), coord.rsplit_once('@')) {
                    (Some(text), Some((name, version))) => {
                        if pnpm_lock_resolves(text, name, version) {
                            out.kept.push(result.clone());
                            continue;
                        }
                        "package_not_installed"
                    }
                    _ => "pnpm_pnp_unsupported",
                }
            } else {
                "pnpm_pnp_unsupported"
            }
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

/// Which state store the shared fetch loop classifies each selected patch
/// against — the one non-presentational difference between the vendored
/// and agent download engines.
#[derive(Clone, Copy)]
enum RecordStore<'a> {
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
struct FetchedPatch {
    patch: PatchResponse,
    files: HashMap<String, PatchFileInfo>,
    action: PatchAction,
    /// Blob hashes this fetch NEWLY wrote under `.socket/blobs/` (empty
    /// when blobs are not persisted) — what a failed record write unwinds.
    new_blobs: Vec<String>,
}

/// What the shared fetch loop produced over one selection.
struct FetchBatch {
    /// Selection size after installed-release narrowing.
    found: usize,
    skipped: usize,
    failed: usize,
    /// Fetched, recordable patches in selection order.
    fetched: Vec<FetchedPatch>,
    /// Ledger store only: `(purl, record)` reused from a detached entry
    /// already at the selected uuid (no fetch).
    reused: Vec<(String, PatchRecord)>,
    /// Per-patch JSON records in selection order (the contract vocabulary).
    patches_json: Vec<serde_json::Value>,
    /// Release-narrowing fallbacks (uninstalled base, no matching variant).
    warnings: Vec<String>,
}

impl FetchBatch {
    /// Record a per-patch failure. `line` is the stderr text — an error, so
    /// exempt from `--silent`; JSON runs carry the detail in the envelope
    /// instead — or `None` when the failure already printed its own detail.
    fn fail(
        &mut self,
        json: bool,
        line: Option<String>,
        purl: &str,
        uuid: &str,
        error: &str,
        error_code: Option<&str>,
    ) {
        if let (false, Some(line)) = (json, line) {
            eprintln!("  {line}");
        }
        let mut record = serde_json::json!({
            "purl": purl,
            "uuid": uuid,
            "action": "failed",
        });
        if let Some(code) = error_code {
            record["errorCode"] = serde_json::json!(code);
        }
        record["error"] = serde_json::json!(error);
        self.patches_json.push(record);
        self.failed += 1;
    }
}

/// The fetch loop both download engines share: installed-release
/// narrowing, the caller's Bun refusal, the per-store skip decision, the
/// view fetch (served from `prefetched` when the narrowing or the caller
/// already holds the view), the no-applicable-files guardrail, optional
/// blob persistence, and every per-patch failure record. Every pinned
/// stderr line and JSON action lives here once.
async fn fetch_selected_patches(
    selected: &[PatchSearchResult],
    params: &DownloadParams,
    api_client: &ApiClient,
    store: RecordStore<'_>,
    blobs_dir: Option<&Path>,
    bun_refusal: Option<&BunVendorRefusal>,
    mut prefetched: HashMap<String, PatchResponse>,
) -> FetchBatch {
    let quiet = params.quiet();
    // Narrow multi-release selections to the installed distribution unless
    // --all-releases was passed (a no-op for non-variant ecosystems and
    // single-variant packages). The views it fetched serve the loop below.
    // The narrowing queries the API: show that something is happening
    // right after the confirm prompt.
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
    // No leading blank line: the prompt's answer already ended its line.
    if matches!(store, RecordStore::Manifest(_)) && !quiet {
        eprintln!(
            "Downloading {}...",
            crate::ui::plural(selected.len(), "patch", "patches")
        );
    }

    let mut batch = FetchBatch {
        found: selected.len(),
        skipped: 0,
        failed: 0,
        fetched: Vec::new(),
        reused: Vec::new(),
        patches_json: Vec::new(),
        warnings,
    };

    for search_result in &selected {
        let (purl, uuid) = (search_result.purl.as_str(), search_result.uuid.as_str());

        // Refusal FIRST (the dry-run preview's precedence): a preserved
        // ledger can name this exact uuid after `rollback --preserve-state`
        // unwired it, so UUID equality alone never exempts a purl — the
        // lock-derived exemption inside `applies_to` decides. Code-tagged so
        // a `--silent` operator can grep the stable code.
        if let Some(refusal) = bun_refusal.filter(|r| r.applies_to(purl)) {
            batch.fail(
                params.json,
                Some(format!(
                    "[error] {purl} ({}): {}",
                    refusal.code, refusal.detail
                )),
                purl,
                uuid,
                &refusal.detail,
                Some(refusal.code),
            );
            continue;
        }

        // Idempotency (ledger store): a detached entry already at this uuid
        // carries its own record — no view fetch needed.
        if let RecordStore::Ledger(entries) = store {
            if let Some(record) = lookup_entry(entries, purl)
                .filter(|e| e.detached && e.uuid == uuid)
                .and_then(|e| e.record.clone())
            {
                if !quiet {
                    eprintln!("{}", format_record_skip(purl, "already vendored"));
                }
                batch.patches_json.push(serde_json::json!({
                    "purl": purl,
                    "uuid": uuid,
                    "action": "skipped",
                }));
                batch.reused.push((purl.to_string(), record));
                batch.skipped += 1;
                continue;
            }
        }

        // The view: from memory when the narrowing (or the uuid path's own
        // identifier fetch) already fetched it, else the network.
        let view = match prefetched.remove(uuid) {
            Some(patch) => Ok(Some(patch)),
            None => api_client.fetch_patch(uuid).await,
        };
        let patch = match view {
            Ok(Some(patch)) => patch,
            Ok(None) => {
                batch.fail(
                    params.json,
                    Some(format!("[fail] {purl} (could not fetch details)")),
                    purl,
                    uuid,
                    "could not fetch details",
                    None,
                );
                continue;
            }
            Err(e) => {
                batch.fail(
                    params.json,
                    Some(format!("[fail] {purl} ({e})")),
                    purl,
                    uuid,
                    &e.to_string(),
                    None,
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
            batch.patches_json.push(serde_json::json!({
                "purl": patch.purl,
                "uuid": patch.uuid,
                "action": "skipped",
            }));
            batch.skipped += 1;
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
                &patch.purl,
                &patch.uuid,
                "patch has no applicable files",
                None,
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
                        &patch.purl,
                        &patch.uuid,
                        "Blob decode or write failed",
                        None,
                    );
                    continue;
                }
            }
        }

        let (label, tag) = match (store, &action) {
            (RecordStore::Ledger(_), _) => ("downloaded", "fetch"),
            (RecordStore::Manifest(_), PatchAction::Updated { .. }) => ("updated", "update"),
            (RecordStore::Manifest(_), _) => ("added", "add"),
        };
        let mut record = serde_json::json!({
            "purl": patch.purl,
            "uuid": patch.uuid,
            "action": label,
        });
        if let PatchAction::Updated { old_uuid } = &action {
            if !quiet {
                // Defensive: a malformed/short UUID in the store must not
                // panic the loop — `short_uuid` never does.
                eprintln!(
                    "  [{tag}] {} (replacing {})",
                    normalize_purl(&patch.purl),
                    short_uuid(old_uuid)
                );
            }
            record["oldUuid"] = serde_json::json!(old_uuid);
        } else if !quiet {
            eprintln!("  [{tag}] {}", normalize_purl(&patch.purl));
        }
        // Splice description / severity / vulnerability IDs into the record
        // so PR-comment bots, dashboards, and CLI consumers can render the
        // patch without a second round-trip to the API.
        merge_metadata(&mut record, patch_event_metadata(&patch));
        batch.patches_json.push(record);
        batch.fetched.push(FetchedPatch {
            patch,
            files,
            action,
            new_blobs,
        });
    }
    batch
}

/// The vendored download phase's result: `(exit code, download JSON,
/// records by purl, blob seed)` — the seed is every fetched view's decoded
/// `blobContent` keyed by after-hash, for the vendor stager
/// (`fetch_stage::stage_vendor_sources_in_memory`), so the step never
/// fetches a view this phase already holds.
pub(crate) type DetachedDownload = (
    i32,
    serde_json::Value,
    HashMap<String, PatchRecord>,
    HashMap<String, Vec<u8>>,
);

/// Download patches WITHOUT touching the manifest and return the fetched
/// records keyed by purl — the download phase of every vendored run
/// (`scan` / `get --mode vendored`), where the vendor ledger carries the
/// records (`detached`). Honors the same installed-release narrowing as
/// [`download_and_apply_patches_with`]. A purl already vendored detached at the
/// selected uuid skips the network fetch and reuses the ledger's embedded
/// record, so idempotent re-runs stay cheap.
///
/// `api_client` is the run's client (built once, proxy fallback included).
/// `prefetched` maps uuid → an already-fetched view: the `get <uuid>` path
/// resolved its identifier by fetching the view, and scan's interactive
/// arm pre-verified baselines from the views — neither must fetch again (a
/// fresh fetch could re-hit the 401 the proxy fallback just recovered
/// from). The ledger idempotency check runs before the cache lookup, and a
/// cache miss still fetches.
///
/// The blob seed is best-effort: an undecodable or missing `blobContent`
/// contributes nothing and is NOT a failed record (the stager reports what
/// it cannot source).
pub(crate) async fn download_patch_records_with(
    selected: &[PatchSearchResult],
    params: &DownloadParams,
    api_client: &ApiClient,
    prefetched: HashMap<String, PatchResponse>,
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
    // otherwise the view was downloaded for nothing and a package
    // resolvable only through the unreadable bun.lockb inventory
    // misreported `package_not_installed` instead of the real
    // `vendor_bun_*` code. npm-only, so release narrowing (PyPI / RubyGems /
    // Maven variants) cannot change its verdict.
    let bun_refusal = bun_vendor_preflight_with_ledger(
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
        bun_refusal.as_ref(),
    )
    .await
}

/// [`download_patch_records_with`] after its two reads: the caller's own
/// ledger load and Bun preflight outcome. The `get <uuid>` path runs the
/// preflight itself (it owns the pre-record refusal shape) and hands the
/// UNFILTERED outcome down, so the lock is read once per run and the
/// refused-but-exempt case still reaches the per-purl `applies_to` gate.
async fn download_patch_records_preflighted(
    selected: &[PatchSearchResult],
    params: &DownloadParams,
    api_client: &ApiClient,
    prefetched: HashMap<String, PatchResponse>,
    vendor_state: std::io::Result<VendorState>,
    bun_refusal: Option<&BunVendorRefusal>,
) -> DetachedDownload {
    let vendor_state = vendor_state.unwrap_or_default();

    let blobs_dir = params.socket_dir().join("blobs");
    let batch = fetch_selected_patches(
        selected,
        params,
        api_client,
        RecordStore::Ledger(&vendor_state.entries),
        params.persist_blobs.then_some(blobs_dir.as_path()),
        bun_refusal,
        prefetched,
    )
    .await;

    let downloaded = batch.fetched.len();
    let mut records: HashMap<String, PatchRecord> = batch.reused.into_iter().collect();
    let mut blobs: HashMap<String, Vec<u8>> = HashMap::new();
    for FetchedPatch { patch, files, .. } in batch.fetched {
        for info in patch.files.values() {
            // Same key guard as the blob writers: the hash names the lookup
            // key the apply pipeline gates writes on.
            let (Some(b64), Some(hash)) = (&info.blob_content, &info.after_hash) else {
                continue;
            };
            if !is_valid_blob_hash(hash) || blobs.contains_key(hash) {
                continue;
            }
            if let Ok(bytes) = base64_decode(b64) {
                blobs.insert(hash.clone(), bytes);
            }
        }
        records.insert(patch.purl.clone(), build_patch_record(&patch, files));
    }
    let mut result_json = serde_json::json!({
        "found": batch.found,
        "downloaded": downloaded,
        "skipped": batch.skipped,
        "failed": batch.failed,
        "detached": true,
        "patches": batch.patches_json,
    });
    if !batch.warnings.is_empty() {
        result_json["warnings"] = serde_json::json!(batch.warnings);
    }
    (i32::from(batch.failed > 0), result_json, records, blobs)
}

/// Emit a warning (stderr `[note]` + `warnings[]`) for every added/updated
/// patch record whose purl the vendor ledger still wires at a DIFFERENT
/// uuid — VEX verification fails closed (`vendor_uuid_mismatch`) until a
/// `vendor` run refreshes the committed artifact.
///
/// Kept out of [`download_and_apply_patches_with`]'s body on purpose: that
/// function sits on the in-process scan→download→apply chain, whose summed
/// poll frames must fit Windows' 1 MiB main-thread stack in debug builds.
async fn warn_on_vendored_uuid_drift(
    cwd: &Path,
    quiet: bool,
    downloaded_patches: &[serde_json::Value],
    warnings: &mut Vec<String>,
) {
    let Ok(vendor_state) = load_state(cwd).await else {
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
        let entry = lookup_entry(&vendor_state.entries, purl);
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

/// The `GlobalArgs` a nested apply runs with: the caller's flags verbatim
/// (`--verbose`, `--strict`, `--ecosystems`, `--download-mode` … all flow
/// through; the API flags ride along but are inert — the nested apply runs
/// on the caller's client), with the fields `get` owns overridden: the
/// already-resolved manifest path (apply re-resolves a
/// relative path against ITS `--cwd`, which double-joins ours — absolutize
/// so it passes through verbatim), `silent` = quiet and `json: false` (the
/// nested apply must never print a second JSON document), and `dry_run:
/// false` — agent-mode `get` ignores `--dry-run` by contract, and the
/// manifest + blobs it just wrote for real must be applied for real too.
fn nested_apply_args(common: &GlobalArgs, manifest_path: &Path, quiet: bool) -> GlobalArgs {
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
fn nested_apply_args_from_params(
    params: &DownloadParams,
    run: &DownloadRun<'_>,
    manifest_path: &Path,
) -> GlobalArgs {
    let common = GlobalArgs {
        cwd: params.cwd.clone(),
        global: params.global,
        global_prefix: params.global_prefix.clone(),
        download_mode: params.download_mode.clone(),
        strict: params.strict,
        // Scope the nested apply like the caller was scoped: leaving this
        // at the default `None` made `scan --ecosystems gem --sync` apply
        // the WHOLE manifest, mutating other ecosystems' packages the user
        // filtered out.
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
/// its last mutation is done. Returns whether apply exited 0. Callers print
/// their own "Applying patches..." line. `json` is the caller's flag: a
/// JSON caller gets no human error lines, from this function or from the
/// nested apply (`common` itself is never JSON). The read-only cargo-redirect verifier stays off
/// and embedded VEX is opt-in on the top-level command only, never on this
/// internal invocation.
async fn run_nested_apply(
    common: GlobalArgs,
    json: bool,
    client: &ApiClient,
    lock: LockGuard,
) -> bool {
    let manifest_path = common.resolved_manifest_path();
    let apply_args = super::apply::ApplyArgs {
        common,
        force: false,
        check: false,
        vex: Default::default(),
        nested: Some(super::apply::NestedApply { caller_json: json }),
    };
    let code = super::apply::run_locked(apply_args, manifest_path, client, lock).await;
    // An error, so exempt from --silent ("errors only": a failing exit must
    // say why); JSON runs carry the failure in the envelope instead.
    if code != 0 && !json {
        eprintln!("{APPLY_FAILED}");
    }
    code == 0
}

/// Download the selected patches into `.socket/` (manifest records +
/// blobs) and, unless `save_only`, apply them in place — the agent-mode
/// engine behind `get` and `scan --apply/--sync`, over the caller's
/// run-level context (`run`: the client the run already built, plus the
/// `--lock-timeout` / `--verbose` the manifest lock and the nested apply
/// honor). Returns `(exit_code, json)`.
pub async fn download_and_apply_patches_with(
    selected: &[PatchSearchResult],
    params: &DownloadParams,
    run: &DownloadRun<'_>,
) -> (i32, serde_json::Value) {
    let quiet = params.quiet();
    let manifest_path = params.manifest_path.clone();
    let socket_dir = params.socket_dir();
    let lock_timeout = Duration::from_secs(run.lock_timeout.unwrap_or(0));

    // The manifest read-modify-write — and the blob writes it records —
    // runs under the apply lock: `remove`/`rollback` RMW the same file under
    // it, and an unlocked writer here lost their update or had its own
    // record clobbered. `acquire` creates `.socket/` itself; the guard's
    // drop removes `apply.lock` and prunes an otherwise-empty `.socket/`, so
    // a run that records nothing leaves no residue. The nested apply runs
    // under this SAME guard (one lock window; see `run_nested_apply`).
    let guard = match crate::commands::lock_cli::acquire_with_status(&socket_dir, lock_timeout) {
        Ok(guard) => guard,
        Err(e) => {
            return (
                1,
                report_lock_failure(params.json, &socket_dir, &e, lock_timeout),
            )
        }
    };

    let mut manifest = match read_manifest(&manifest_path).await {
        Ok(Some(m)) => m,
        Ok(None) => PatchManifest::new(),
        // Fail closed on a manifest that exists but can't be read/parsed:
        // treating it as empty would let the write below replace the file
        // and destroy every tracked patch record.
        Err(e) => {
            let err = format!("Failed to read manifest: {e}");
            report_error(params.json, &err);
            return (1, serde_json::json!({"status": "error", "error": err}));
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
        None,
        HashMap::new(),
    )
    .await;

    // `added` and `updated` are DISJOINT — one patch lands in exactly one,
    // matching the per-patch `action` vocabulary (CLI_CONTRACT.md) and the
    // single-uuid flow's summary in `save_and_apply_patch`; `downloaded` is
    // their sum (a replacement was fetched and applied just like a new
    // record) and gates the apply step.
    let downloaded = batch.fetched.len();
    let mut updated = 0usize;
    let mut new_blobs: Vec<String> = Vec::new();
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
            report_error(params.json, &msg);
            return (1, serde_json::json!({ "status": "error", "error": msg }));
        }
    }
    // The lock outlives the manifest write only when a nested apply follows
    // (it is handed the guard and releases it after its last mutation);
    // otherwise nothing more is written and it is released here.
    let apply_lock = if !params.save_only && downloaded > 0 {
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
    let mut warnings = batch.warnings;
    warn_on_vendored_uuid_drift(&params.cwd, quiet, &batch.patches_json, &mut warnings).await;

    if !quiet {
        eprintln!();
        eprintln!(
            "{}",
            format_save_summary(&manifest_path, added, updated, batch.skipped, batch.failed)
        );
    }

    // Auto-apply unless --save-only (the lock decision above).
    let mut apply_succeeded = false;
    if let Some(lock) = apply_lock {
        if !quiet {
            eprintln!();
            eprintln!("Applying patches...");
        }
        apply_succeeded = run_nested_apply(
            nested_apply_args_from_params(params, run, &manifest_path),
            params.json,
            run.api_client,
            lock,
        )
        .await;
    }

    // An apply step that ran (patches were added, not --save-only) but
    // failed is a partial failure too — not just download failures. The
    // `status` field must agree with `exit_code`; reporting `success`
    // alongside a non-zero exit code misleads JSON consumers (the scan
    // wrapper recomputes status from the exit code for exactly this
    // reason, but `get` surfaces this envelope directly).
    let apply_failed = !apply_succeeded && downloaded > 0 && !params.save_only;
    let (status, exit_code) = run_outcome(batch.failed > 0, apply_failed);
    let mut result_json = serde_json::json!({
        "status": status,
        "found": batch.found,
        "downloaded": downloaded,
        "skipped": batch.skipped,
        "failed": batch.failed,
        "applied": if apply_succeeded { downloaded } else { 0 },
        "updated": updated,
        "patches": batch.patches_json,
    });
    // Surface release-narrowing fallbacks (uninstalled package / no
    // matching variant) so JSON consumers can see why all variants were
    // kept. Omitted entirely when narrowing was clean.
    if !warnings.is_empty() {
        result_json["warnings"] = serde_json::json!(warnings);
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
            "Fetching patches needs network access, so `get` cannot run with \
             --offline/SOCKET_OFFLINE (strict airgap)",
        );
        return 1;
    }

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
        detect_identifier_type(&args.identifier).unwrap_or(IdentifierType::Package)
    };
    // A forced type is shape-checked locally, before any network call, so
    // a typo reads as a plain message instead of a raw API 400 body.
    if args.id || args.cve || args.ghsa {
        if let Some(err) = forced_identifier_error(&args.identifier, id_type) {
            report_error(args.common.json, err);
            return 1;
        }
    }

    apply_env_toggles(&args.common);
    // `--silent` is "errors only" (CLI_CONTRACT.md): every informational
    // print below is gated on this; errors and JSON envelopes are not.
    let quiet = args.common.json || args.common.silent;
    if !quiet && id_type == IdentifierType::Package && !args.package {
        eprintln!("Treating \"{}\" as a package name search", args.identifier);
    }
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

    // Progress for the network/crawl phases below. Built after the client:
    // building it may print core advisories straight to stderr, which
    // would land on the end of a live line.
    let mut status = crate::ui::StatusLine::stderr(args.common.json, args.common.silent);

    // Handle UUID: fetch and download directly
    if id_type == IdentifierType::Uuid {
        status.set(format!("Fetching patch {}...", args.identifier));
        let mut fetch_result = api_client.fetch_patch(&args.identifier).await;
        // 401/403 from the auth endpoint → swap to the public proxy
        // and retry once. Free patches still surface; paid patches
        // come back as the existing "paid_required" branch below.
        if !use_public_proxy {
            if let Err(ref e) = fetch_result {
                if is_fallback_candidate(e) {
                    // Errors-only under --silent; --json keeps it on stderr
                    // (same gate as scan's batch fallback).
                    if !args.common.silent {
                        status.println(format!(
                            "Warning: authenticated API returned {e}; \
                             falling back to public patch API proxy (free patches only)."
                        ));
                    }
                    // Building the proxy client may print core's proxy
                    // notice straight to stderr: take the line down first.
                    status.finish();
                    api_client = build_proxy_fallback_client(&overrides);
                    use_public_proxy = true;
                    fallback_to_proxy = true;
                    status.set(format!("Fetching patch {}...", args.identifier));
                    fetch_result = api_client.fetch_patch(&args.identifier).await;
                }
            }
        }
        status.finish();
        match fetch_result {
            Ok(Some(patch)) => {
                if patch.tier == "paid" && use_public_proxy {
                    return report_paid_required_uuid(
                        &args,
                        Some(&patch.purl),
                        &patch.uuid,
                        fallback_to_proxy,
                        telemetry_token.as_deref(),
                        telemetry_org.as_deref(),
                    )
                    .await;
                }
                if !quiet {
                    eprintln!(
                        "Found patch for {}",
                        format_patch_summary(
                            &patch.purl,
                            &patch.tier,
                            None,
                            &patch.vulnerabilities,
                            crate::ui::stderr_color(),
                        )
                    );
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
                // Mode dispatch. All three reuse THIS fetched patch and
                // this possibly-proxy-fallback client rather than
                // re-fetching with a fresh one, which would re-hit the
                // 401/403 the fallback just recovered from. An explicit
                // UUID is exempt from installed narrowing (exact intent).
                return match mode {
                    // Save to manifest and apply in place (today's flow).
                    super::scan::ScanMode::Agent => {
                        save_and_apply_patch(&args, &api_client, &patch).await
                    }
                    super::scan::ScanMode::Hosted => {
                        let selected = vec![search_result_from_response(&patch)];
                        run_get_hosted(&args, &api_client, &selected, &[], &[]).await
                    }
                    super::scan::ScanMode::Vendored => {
                        let selected = vec![search_result_from_response(&patch)];
                        run_get_vendored(
                            &args,
                            &api_client,
                            use_public_proxy,
                            &selected,
                            Some(&patch),
                            &[],
                            &[],
                            telemetry_token.as_deref(),
                            telemetry_org.as_deref(),
                        )
                        .await
                    }
                };
            }
            // The public proxy answers a paid patch with 403 rather than
            // a tier=paid view: the same outcome as the branch above, not
            // a raw "Forbidden" error.
            Err(ApiError::Forbidden(_)) if use_public_proxy => {
                return report_paid_required_uuid(
                    &args,
                    None,
                    &args.identifier,
                    fallback_to_proxy,
                    telemetry_token.as_deref(),
                    telemetry_org.as_deref(),
                )
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
            status.set(format!(
                "Searching patches for {id_type} {}...",
                args.identifier
            ));
            let result = match id_type {
                IdentifierType::Cve => api_client.search_patches_by_cve(&args.identifier).await,
                IdentifierType::Ghsa => api_client.search_patches_by_ghsa(&args.identifier).await,
                IdentifierType::Purl => {
                    api_client.search_patches_by_package(&args.identifier).await
                }
                _ => unreachable!(),
            };
            status.finish();
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
            status.set("Enumerating packages...");
            let (all_packages, _, _) =
                crawl_all_ecosystems(&crawler_options_for(&args.common)).await;

            if all_packages.is_empty() {
                status.finish();
                if args.common.json {
                    print_json(&empty_result_json("no_packages"));
                } else if !args.common.silent {
                    println!("{}", no_packages_message(args.common.global));
                }
                return 0;
            }

            status.finish_with(format!(
                "Found {}",
                crate::ui::plural(all_packages.len(), "package", "packages")
            ));

            let matches = fuzzy_match_packages(&args.identifier, &all_packages, 20);

            if matches.is_empty() {
                if args.common.json {
                    print_json(&empty_result_json("no_match"));
                } else if !args.common.silent {
                    println!("No packages matching \"{}\" found.", args.identifier);
                }
                return 0;
            }

            // Only the best match is searched: name it, so a fuzzy pick
            // of the wrong package is visible.
            let best_match = &matches[0];
            if !quiet {
                eprintln!("{}", format_best_match(&best_match.purl, matches.len()));
            }
            status.set(format!(
                "Searching patches for {}...",
                normalize_purl(&best_match.purl)
            ));
            let result = api_client.search_patches_by_package(&best_match.purl).await;
            status.finish();
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
        _ => unreachable!(),
    };
    drop(status);

    if search_response.patches.is_empty() {
        if args.common.json {
            print_json(&empty_result_json("not_found"));
        } else if !args.common.silent {
            println!("No patches found for {}: {}", id_type, args.identifier);
        }
        return 0;
    }

    let color = crate::ui::stdout_color();

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
            let all: Vec<&PatchSearchResult> = search_response.patches.iter().collect();
            if id_type == IdentifierType::Package && !quiet {
                // Separate the stderr `Best match` line above on a terminal;
                // stdout itself starts with the result.
                eprintln!();
            }
            print!(
                "{}",
                format_search_results(&all, search_response.can_access_paid_patches, color)
            );
            println!("All available patches require a paid subscription.");
            println!("  Upgrade at: https://socket.dev/pricing");
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
    // The narrowing runs over EVERY result (one crawl), paid no-access ones
    // included, so the listing can still show an installed package's paid
    // fix as `[PAID] (no access)`; selection, the skip records and the
    // JSON envelope only ever see the accessible share.
    let (accessible, listed, narrow_skips, narrow_warnings) = if narrowing_exempt {
        let listed: Vec<PatchSearchResult> = search_response.patches.clone();
        (accessible, listed, Vec::new(), Vec::new())
    } else {
        let narrowing =
            filter_to_installed_purls(&search_response.patches, &args.common, mode).await;
        let accessible_uuids: std::collections::HashSet<&str> =
            accessible.iter().map(|p| p.uuid.as_str()).collect();
        let kept_accessible: Vec<PatchSearchResult> = narrowing
            .kept
            .iter()
            .filter(|p| accessible_uuids.contains(p.uuid.as_str()))
            .cloned()
            .collect();
        let skips: Vec<serde_json::Value> = narrowing
            .skip_records
            .into_iter()
            .filter(|r| accessible_uuids.contains(r["uuid"].as_str().unwrap_or_default()))
            .collect();
        (kept_accessible, narrowing.kept, skips, narrowing.warnings)
    };
    // Layout refusals print even when informational output is quieted only
    // by --json (stderr; the envelope carries them too) — but --silent
    // mutes them like scan does.
    if !args.common.silent {
        for (code, detail) in &narrow_warnings {
            eprintln!("Warning ({code}): {detail}");
        }
    }
    if accessible.is_empty() {
        // Every accessible patch was narrowed out. Additive status (never
        // `no_match`, which is pinned to the fuzzy package-name path):
        // exit 0, the skips carry the detail via their errorCode.
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
            println!("{}", format_all_narrowed(&narrow_skips));
            if !quiet && args.common.verbose {
                for line in format_verbose_skips(&narrow_skips) {
                    eprintln!("{line}");
                }
            }
        }
        return 0;
    }

    // The listing shows only what survived the narrowing (a CVE fan-out
    // can span dozens of versions that are not installed here): the
    // skipped ones are summarized in one line each instead, with the
    // per-version detail after the summary under --verbose.
    let listed: Vec<&PatchSearchResult> = listed.iter().collect();
    if !quiet {
        if id_type == IdentifierType::Package || !narrow_warnings.is_empty() {
            // Separate the stderr lines above (`Best match`, warnings) on a
            // terminal; stdout itself starts with the result.
            eprintln!();
        }
        print!(
            "{}",
            format_search_results(&listed, search_response.can_access_paid_patches, color)
        );
        let mut skip_lines = format_skip_summary(&narrow_skips);
        if args.common.verbose {
            skip_lines.extend(format_verbose_skips(&narrow_skips));
        }
        for line in &skip_lines {
            eprintln!("{line}");
        }
        if !skip_lines.is_empty() {
            eprintln!();
        }
    }

    // Smart patch selection: pick one patch per PURL. `accessible` is
    // non-empty here and every entry passes the selector's tier filter, so
    // the selection is never empty (one patch per purl group, or `Err`).
    let selected = match select_patches(
        &accessible,
        search_response.can_access_paid_patches,
        &args.common,
    ) {
        Ok(s) => s,
        Err(code) => return code,
    };

    // The candidates can hold several patches per package and the pick
    // was made without the user (paid auto-pick, `--yes`, non-TTY): say
    // which will be installed. A menu pick is not echoed back, and paid
    // no-access entries (never candidates) do not count.
    if !quiet
        && accessible.len() > selected.len()
        && !selection_prompted(
            &accessible,
            search_response.can_access_paid_patches,
            &args.common,
        )
    {
        print!("{}", format_selected_patches(&selected, color));
    }

    // Agent-mode dry run: preview against the manifest, write nothing.
    // (Hosted/vendored dry runs are handled inside their engines.) The
    // per-release variant narrowing the wet run applies inside the
    // download engine runs here too, so the preview names only the
    // variants a wet run would fetch.
    if args.common.dry_run && mode == super::scan::ScanMode::Agent {
        let (selected, variant_warnings, _views) = filter_to_installed_releases(
            &selected,
            args.all_releases,
            &crawler_options_for(&args.common),
            quiet,
            &api_client,
        )
        .await;
        let mut narrow_warnings = narrow_warnings;
        narrow_warnings.extend(
            variant_warnings
                .into_iter()
                .map(|w| ("release_narrowing".to_string(), w)),
        );
        return agent_dry_run(&args, &selected, &narrow_skips, &narrow_warnings).await;
    }

    // Confirm before acting (default YES), with mode-appropriate wording.
    // Dry runs skip the prompt: nothing mutates, so nothing to confirm.
    let prompt = format_confirm_prompt(mode, selected.len(), args.save_only);
    if !args.common.dry_run && !crate::ui::confirm(&prompt, true, &args.common) {
        if !quiet {
            eprintln!("Cancelled; no changes made.");
        }
        return 0;
    }

    match mode {
        super::scan::ScanMode::Hosted => {
            // Per-release VARIANT narrowing (the finer layer under the
            // coarse version narrowing above). Agent/vendored runs get it
            // inside the download engines; hosted never downloads, so run
            // it here — otherwise every PyPI wheel/sdist, gem platform, and
            // Maven classifier variant of the installed version would be
            // granted and rewritten, not just the installed distribution.
            // Same fallbacks as everywhere else: uninstalled/unmatched
            // bases keep all variants with a warning; --all-releases
            // passes through. (The views it fetched are not needed here:
            // hosted never downloads.)
            let (selected, variant_warnings, _views) = filter_to_installed_releases(
                &selected,
                args.all_releases,
                &crawler_options_for(&args.common),
                quiet,
                &api_client,
            )
            .await;
            let mut narrow_warnings = narrow_warnings;
            narrow_warnings.extend(
                variant_warnings
                    .into_iter()
                    .map(|w| ("release_narrowing".to_string(), w)),
            );
            return run_get_hosted(
                &args,
                &api_client,
                &selected,
                &narrow_skips,
                &narrow_warnings,
            )
            .await;
        }
        super::scan::ScanMode::Vendored => {
            return run_get_vendored(
                &args,
                &api_client,
                use_public_proxy,
                &selected,
                None,
                &narrow_skips,
                &narrow_warnings,
                telemetry_token.as_deref(),
                telemetry_org.as_deref(),
            )
            .await;
        }
        super::scan::ScanMode::Agent => {}
    }

    // Download and apply (agent mode), with the run's client and flags.
    let params = get_download_params(&args, args.save_only, /*persist_blobs=*/ true);
    let run = DownloadRun {
        api_client: &api_client,
        lock_timeout: args.common.lock_timeout,
        verbose: args.common.verbose,
    };
    let (code, mut result_json) = download_and_apply_patches_with(&selected, &params, &run).await;
    // A download-phase HARD error (lock refused, unreadable manifest,
    // failed manifest write) is an `error`-status envelope the engine has
    // ALREADY printed — printing below would put a second JSON document on
    // stdout (get's `--json` contract is exactly one per run). Per-patch
    // failures are NOT this case: they ride a success-shaped
    // (`partial_failure`) envelope the engine leaves for us to print.
    if result_json["status"] == "error" {
        return code;
    }
    fold_narrowing_into_result(&mut result_json, &narrow_skips, &narrow_warnings);

    if args.common.json {
        print_json(&result_json);
    }

    code
}

/// `paid_required` for the uuid path: the patch exists but the caller
/// (on the public proxy) cannot download it. A clean outcome, exit 0.
/// `purl` is `None` when the proxy refused with 403 before naming it.
async fn report_paid_required_uuid(
    args: &GetArgs,
    purl: Option<&str>,
    patch_id: &str,
    fallback_to_proxy: bool,
    telemetry_token: Option<&str>,
    telemetry_org: Option<&str>,
) -> i32 {
    track_patch_fetch_failed(
        patch_id,
        "paid_required",
        fallback_to_proxy,
        telemetry_token,
        telemetry_org,
    )
    .await;
    if args.common.json {
        let mut record = serde_json::json!({ "uuid": patch_id, "tier": "paid" });
        if let Some(purl) = purl {
            record["purl"] = serde_json::json!(purl);
        }
        print_json(&serde_json::json!({
            "status": "paid_required",
            "found": 1,
            "downloaded": 0,
            "applied": 0,
            "patches": [record],
        }));
    } else if !args.common.silent {
        let name = purl.map(|p| normalize_purl(p).into_owned());
        println!(
            "{}",
            format_paid_required(name.as_deref().unwrap_or(patch_id))
        );
    }
    0
}

/// Agent-mode `--dry-run`: classify each selected patch against the
/// manifest (read-only) and report what a wet run would do — no download,
/// no manifest or blob write, no apply, no prompt. JSON carries
/// `dryRun: true` and per-patch `would_add` / `would_update` (+`oldUuid`)
/// / `skipped` records, plus the narrowing skips.
async fn agent_dry_run(
    args: &GetArgs,
    selected: &[PatchSearchResult],
    narrow_skips: &[serde_json::Value],
    narrow_warnings: &[(String, String)],
) -> i32 {
    // Fail closed like the wet run: a preview over an unreadable manifest
    // would promise an outcome the wet run refuses.
    let manifest = match read_manifest(&args.common.resolved_manifest_path()).await {
        Ok(m) => m.unwrap_or_else(PatchManifest::new),
        Err(e) => {
            report_error(args.common.json, format!("Failed to read manifest: {e}"));
            return 1;
        }
    };
    let mut records = Vec::new();
    let mut lines = Vec::new();
    let mut changing = 0usize;
    let mut skipped = 0usize;
    for p in selected {
        let shown = normalize_purl(&p.purl);
        match decide_patch_action(&manifest, &p.purl, &p.uuid) {
            PatchAction::Added => {
                changing += 1;
                lines.push(format!("  [would-add] {shown}"));
                records.push(serde_json::json!({
                    "purl": p.purl, "uuid": p.uuid, "action": "would_add",
                }));
            }
            PatchAction::Updated { old_uuid } => {
                changing += 1;
                lines.push(format!(
                    "  [would-update] {shown} (replacing {})",
                    short_uuid(&old_uuid)
                ));
                records.push(serde_json::json!({
                    "purl": p.purl, "uuid": p.uuid, "action": "would_update",
                    "oldUuid": old_uuid,
                }));
            }
            PatchAction::Skipped => {
                skipped += 1;
                lines.push(format!("  [skip] {shown} (already in manifest)"));
                records.push(serde_json::json!({
                    "purl": p.purl, "uuid": p.uuid, "action": "skipped",
                }));
            }
        }
    }
    if args.common.json {
        let mut result = serde_json::json!({
            "status": "success",
            "dryRun": true,
            "found": selected.len(),
            "downloaded": 0,
            "skipped": skipped,
            "applied": 0,
            "patches": records,
        });
        fold_narrowing_into_result(&mut result, narrow_skips, narrow_warnings);
        print_json(&result);
    } else if !args.common.silent {
        for line in &lines {
            println!("{line}");
        }
        let action = if args.save_only {
            "download and record"
        } else {
            "download and apply"
        };
        println!("{}", format_dry_run(action, changing));
    }
    0
}

/// The manifest-record half of the agent single-uuid save, under the apply
/// lock: fail-closed manifest read, the no-applicable-files guardrail,
/// action classification against the manifest, and — unless the same uuid
/// is already recorded — the blob writes and the manifest write. Takes the
/// `PatchResponse` the caller fetched rather than re-fetching by UUID: the
/// caller's client may have fallen back to the public proxy after a
/// 401/403, and a fresh client would hit the same auth failure again. A
/// same-uuid re-get writes nothing (matching the multi-patch engine's
/// `skipped`). Runs under the apply lock the caller (`save_and_apply_patch`)
/// holds — the RMW must be serialized against `remove`/`rollback`, and the
/// nested apply then runs under that same guard.
///
/// Errors are reported here and surface as `Err(exit_code)`.
async fn save_patch_record(
    args: &GetArgs,
    manifest_path: &Path,
    socket_dir: &Path,
    patch: &PatchResponse,
) -> Result<PatchAction, i32> {
    let mut manifest = match read_manifest(manifest_path).await {
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

    // Classify against the manifest state BEFORE the insert, with the same
    // vocabulary `download_and_apply_patches_with` emits (CLI_CONTRACT.md): a
    // different uuid already recorded at this purl is `updated` (+`oldUuid`),
    // not `added` — consumers diff manifest replacements on that action.
    let action = decide_patch_action(&manifest, &patch.purl, &patch.uuid);
    if action == PatchAction::Skipped {
        return Ok(action);
    }

    let blobs_dir = socket_dir.join("blobs");
    let Ok(new_blobs) = write_all_patch_blobs(&blobs_dir, patch, args.common.json).await else {
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
    };

    manifest
        .patches
        .insert(patch.purl.clone(), build_patch_record(patch, files));
    if let Err(e) = write_manifest(manifest_path, &manifest).await {
        // No record points at the blobs just written: unwind exactly those.
        unwind_new_blobs(&blobs_dir, &new_blobs).await;
        report_error(args.common.json, format!("Failed to write manifest: {e}"));
        return Err(1);
    }
    Ok(action)
}

/// The uuid path's agent arm: record `patch` in the manifest and, unless
/// `--save-only`, apply it — under ONE apply lock, on the `client` the
/// fetch used (a fresh client could re-hit the 401/403 its proxy fallback
/// just recovered from).
async fn save_and_apply_patch(args: &GetArgs, client: &ApiClient, patch: &PatchResponse) -> i32 {
    // Same "errors only" gate as `run` — informational prints respect
    // `--silent`; errors and the JSON envelope do not.
    let quiet = args.common.json || args.common.silent;
    let manifest_path = args.common.resolved_manifest_path();
    let socket_dir = args.common.socket_dir();
    let lock_timeout = Duration::from_secs(args.common.lock_timeout.unwrap_or(0));
    // A dry run previews against the manifest and writes nothing — not
    // even the lock (which would create `.socket/`).
    if args.common.dry_run {
        return agent_dry_run(args, &[search_result_from_response(patch)], &[], &[]).await;
    }
    // See `download_and_apply_patches_with`: the RMW runs under the lock,
    // which also creates `.socket/` and prunes it again when nothing lands;
    // an error return below drops the guard.
    let guard = match crate::commands::lock_cli::acquire_with_status(&socket_dir, lock_timeout) {
        Ok(guard) => guard,
        Err(e) => {
            report_lock_failure(args.common.json, &socket_dir, &e, lock_timeout);
            return 1;
        }
    };

    let action = match save_patch_record(args, &manifest_path, &socket_dir, patch).await {
        Ok(action) => action,
        Err(code) => return code,
    };
    let changed = action != PatchAction::Skipped;
    // Carried into the nested apply when one follows (it releases the lock
    // after its last mutation), released here otherwise.
    let apply_lock = if !args.save_only && changed {
        Some(guard)
    } else {
        drop(guard);
        None
    };
    let action_label = match &action {
        PatchAction::Added => "added",
        PatchAction::Updated { .. } => "updated",
        PatchAction::Skipped => "skipped",
    };

    // Vendored-uuid drift (mirrors `download_and_apply_patches_with`): the user
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

    // Progress narration goes to stderr, like the search path's.
    if !quiet {
        eprintln!(
            "{}",
            format_single_save("Patch", &action, &manifest_path, &patch.purl, true)
        );
    }

    let mut apply_succeeded = false;
    if let Some(lock) = apply_lock {
        if !quiet {
            eprintln!();
            eprintln!("Applying patches...");
        }
        apply_succeeded = run_nested_apply(
            nested_apply_args(&args.common, &manifest_path, quiet),
            args.common.json,
            client,
            lock,
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
        // Same contract as `download_and_apply_patches_with`: omitted when clean.
        if !warnings.is_empty() {
            result_json["warnings"] = serde_json::json!(warnings);
        }
        print_json(&result_json);
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

/// The `DownloadParams` a `get` run hands its download engine. Only the
/// posture differs per mode: agent persists blobs and applies unless
/// `--save-only`; vendored holds content in memory (`save_only`, no blobs)
/// because the vendor step is the persistence.
fn get_download_params(args: &GetArgs, save_only: bool, persist_blobs: bool) -> DownloadParams {
    DownloadParams {
        cwd: args.common.cwd.clone(),
        manifest_path: args.common.resolved_manifest_path(),
        save_only,
        global: args.common.global,
        global_prefix: args.common.global_prefix.clone(),
        json: args.common.json,
        silent: args.common.silent,
        download_mode: args.common.download_mode.clone(),
        all_releases: args.all_releases,
        strict: args.common.strict,
        ecosystems: args.common.ecosystems.clone(),
        persist_blobs,
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
    api_client: &ApiClient,
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
        &pairs,
        scan_result,
    )
    .await
}

/// `get … --mode vendored`, both identifier paths: scan's vendored posture
/// end to end — the detached download phase ([`download_patch_records_with`]:
/// records fetched into memory, no manifest, no blobs) feeding scan's
/// detached vendor step (apply lock, in-memory staging seeded with the
/// downloaded blobs, the vendor engine over the same run-level client; the
/// ledger carries every record `detached: true`), telemetry included — so
/// the result matches `scan --mode vendored` selecting the same patches.
/// `.socket/manifest.json` is never read or written here.
///
/// `prefetched` is the `get <uuid>` path's already-fetched view: it resolved
/// the identifier by fetching it (with the possibly-proxy-fallback client)
/// and the engine serves the record from it instead of fetching again. That
/// path also refuses a Bun project BEFORE the engine, with the contract's
/// exact pre-record envelope, so a refused run writes nothing at all; the
/// search path lets the engine record the refusal per patch and still runs
/// the vendor step (scan parity).
#[allow(clippy::too_many_arguments)]
async fn run_get_vendored(
    args: &GetArgs,
    api_client: &ApiClient,
    use_public_proxy: bool,
    selected: &[PatchSearchResult],
    prefetched: Option<&PatchResponse>,
    narrow_skips: &[serde_json::Value],
    narrow_warnings: &[(String, String)],
    telemetry_token: Option<&str>,
    telemetry_org: Option<&str>,
) -> i32 {
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
            println!("{}", format_dry_run("download and vendor", selected.len()));
            super::scan::print_dry_run_refusals(&preview);
        }
        return 0;
    }

    // The uuid path's Bun preflight, run ONCE here and handed to the download
    // phase below (which otherwise runs its own): the pre-record refusal
    // shape is this path's, so it owns the read.
    let mut bun_refusal: Option<BunVendorRefusal> = None;
    if let Some(patch) = prefetched {
        // Bun preflight (see `BunVendorRefusal`): refuse BEFORE the engine
        // and the vendor step, so the tree stays exactly as it was (no
        // `.socket/` is created on a fresh project). The already-fetched
        // patch is the only network traffic of a refused run.
        //
        // JSON shape (contract: `get <uuid> --mode vendored` pre-record
        // refusal; the record carries BOTH `errorCode` and `error` like the
        // search path's failed records, and the envelope carries `skipped`
        // like this path's success shape):
        //
        // {
        //   "status": "error",
        //   "found": 1, "downloaded": 0, "skipped": 0, "failed": 1,
        //   "error": { "code": "<vendor code>", "message": "<detail>" },
        //   "patches": [{ "purl": "…", "uuid": "…", "action": "failed",
        //                 "errorCode": "<vendor code>", "error": "<detail>" }]
        // }
        //
        // Human: `Error (<code>): <detail>` on stderr — an error, so it is
        // exempt from `--silent` like every other `Error (…)` line here.
        bun_refusal = bun_vendor_preflight(&args.common.cwd, selected).await;
        if let Some(refusal) = bun_refusal.as_ref().filter(|r| r.applies_to(&patch.purl)) {
            let BunVendorRefusal { code, detail, .. } = refusal;
            // Same failure telemetry as the vendor-step Err arm below: this
            // run exits 1 without vendoring anything.
            socket_patch_core::telemetry::track_patch_vendor_failed(
                &detail,
                args.common.dry_run,
                telemetry_token,
                telemetry_org,
            )
            .await;
            if args.common.json {
                print_json(&serde_json::json!({
                    "status": "error",
                    "found": 1,
                    "downloaded": 0,
                    "skipped": 0,
                    "failed": 1,
                    "error": { "code": code, "message": detail },
                    "patches": [{
                        "purl": patch.purl,
                        "uuid": patch.uuid,
                        "action": "failed",
                        "errorCode": code,
                        "error": detail,
                    }],
                }));
            } else {
                eprintln!(
                    "{}",
                    crate::commands::scan::vendor_flow::format_vendor_step_error(code, detail)
                );
            }
            return 1;
        }
    }

    // Download phase — records in memory, blobs never persisted, the nested
    // apply structurally never runs (save_only): the vendor step IS the
    // persistence. Boxed: the future embeds the narrowing + fetch loop, and
    // `run`'s poll frame must fit Windows' 1 MiB main-thread stack.
    let params = get_download_params(
        args, /*save_only=*/ true, /*persist_blobs=*/ false,
    );
    let prefetched_views: HashMap<String, PatchResponse> = prefetched
        .map(|p| HashMap::from([(p.uuid.clone(), p.clone())]))
        .unwrap_or_default();
    let (dl_code, mut result, records, blobs) = if prefetched.is_some() {
        // The preflight above already read the lock: hand its outcome down.
        let vendor_state = load_state(&args.common.cwd).await;
        Box::pin(download_patch_records_preflighted(
            selected,
            &params,
            api_client,
            prefetched_views,
            vendor_state,
            bun_refusal.as_ref(),
        ))
        .await
    } else {
        Box::pin(download_patch_records_with(
            selected,
            &params,
            api_client,
            prefetched_views,
        ))
        .await
    };
    let mut has_errors = dl_code != 0;
    fold_narrowing_into_result(&mut result, narrow_skips, narrow_warnings);

    // The vendor step (scan's, verbatim): apply lock, in-memory staging
    // seeded with the blobs fetched above, the engine over exactly the
    // records fetched above (moved in — nothing here needs them afterwards)
    // and over this run's client. A per-patch download failure does not
    // skip it (scan parity).
    match super::scan::boxed_scan_vendor_step(
        &args.common,
        records,
        blobs,
        api_client.clone(),
        use_public_proxy,
    )
    .await
    {
        Ok((vendor_errors, venv)) => {
            has_errors |= vendor_errors;
            // Telemetry follows the RUN outcome, not the vendor step alone:
            // a download-phase refusal/failure exits 1 and must not report
            // a successful vendoring of zero patches (scan's arms agree).
            crate::commands::vendor::track_outcomes_for_vendor(
                has_errors,
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
                // A vendor envelope built before the failure (events
                // included) must reach the JSON consumer even though the
                // run aborts here.
                if let Some(venv) = venv {
                    result["vendor"] =
                        serde_json::to_value(&*venv).unwrap_or_else(|_| serde_json::json!({}));
                }
                result["status"] = serde_json::json!("error");
                result["error"] = serde_json::json!({ "code": code, "message": message });
                print_json(&result);
            } else {
                eprintln!(
                    "{}",
                    crate::commands::scan::vendor_flow::format_vendor_step_error(code, &message)
                );
            }
            1
        }
    }
}

/// Decode a patch view's `blobContent` (canonical, padded base64 as the API
/// produces it). Hand-rolled only because `base64` is a dev-dependency of
/// this crate today — once it is a plain dependency (it already is one of
/// `socket-patch-core`, pinned workspace-wide), this body should become
/// `base64::engine::general_purpose::STANDARD.decode(input)` with
/// `DecodeError::InvalidByte(_, b)` mapped to the
/// `Invalid base64 character: <b>` message below (pinned by a unit test).
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

    /// The pnpm-PnP hosted lock probe must be boundary-anchored: plain
    /// substring matching collided on version prefixes, name suffixes, and
    /// unscoped-inside-scoped names (follow-up review finding).
    #[test]
    fn pnpm_lock_resolves_is_boundary_anchored() {
        // v9/v6/v5 key spellings all resolve.
        assert!(pnpm_lock_resolves(
            "lockfileVersion: '9.0'\n\nsnapshots:\n\n  left-pad@1.3.0:\n",
            "left-pad",
            "1.3.0"
        ));
        assert!(pnpm_lock_resolves(
            "  /left-pad@1.3.0:\n    resolution: {}\n",
            "left-pad",
            "1.3.0"
        ));
        assert!(pnpm_lock_resolves(
            "  /left-pad/1.3.0:\n    resolution: {}\n",
            "left-pad",
            "1.3.0"
        ));
        // Peer-qualified keys still resolve: v9 `(peer)` and v5 `_peer`.
        assert!(pnpm_lock_resolves(
            "  'left-pad@1.3.0(react@18.0.0)':\n",
            "left-pad",
            "1.3.0"
        ));
        assert!(pnpm_lock_resolves(
            "  /left-pad/1.3.0_react@18.0.0:\n",
            "left-pad",
            "1.3.0"
        ));
        // Scoped names resolve in both quoted-v9 and v6 spellings.
        assert!(pnpm_lock_resolves(
            "  '@scope/name@1.0.0':\n",
            "@scope/name",
            "1.0.0"
        ));
        assert!(pnpm_lock_resolves(
            "  /@scope/name@1.0.0:\n",
            "@scope/name",
            "1.0.0"
        ));

        // Version-prefix collision: 1.3.0 must NOT match 1.3.0-beta.1.
        assert!(!pnpm_lock_resolves(
            "  left-pad@1.3.0-beta.1:\n",
            "left-pad",
            "1.3.0"
        ));
        // Name-suffix collision: `pad` must NOT match inside `left-pad`.
        assert!(!pnpm_lock_resolves("  left-pad@1.3.0:\n", "pad", "1.3.0"));
        assert!(!pnpm_lock_resolves("  /left-pad/1.3.0:\n", "pad", "1.3.0"));
        // Unscoped-inside-scoped: `name` must NOT match `@scope/name`.
        assert!(!pnpm_lock_resolves(
            "  '@scope/name@1.0.0':\n",
            "name",
            "1.0.0"
        ));
        assert!(!pnpm_lock_resolves(
            "  /@scope/name@1.0.0:\n",
            "name",
            "1.0.0"
        ));
        // Absent version: never resolves.
        assert!(!pnpm_lock_resolves(
            "  left-pad@1.3.0:\n",
            "left-pad",
            "2.0.0"
        ));
    }
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

    fn human_args() -> GlobalArgs {
        GlobalArgs::default()
    }

    fn json_args() -> GlobalArgs {
        GlobalArgs {
            json: true,
            ..GlobalArgs::default()
        }
    }

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
        let out = select_patches(&patches, false, &human_args()).expect("ok");
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
        let out = select_patches(&patches, true, &human_args()).expect("ok");
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
        let out = select_patches(&patches, true, &human_args()).expect("ok");
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
        let out = select_patches(&patches, true, &human_args()).expect("ok");
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
        let out = select_patches(&patches, true, &human_args()).expect("ok");
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
        let out = select_patches(&patches, true, &human_args()).expect("ok");
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
        let out = select_patches(&patches, true, &human_args()).expect("ok");
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
            let out = select_patches(&patches, true, &human_args()).expect("ok");
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
        let out = select_patches(&patches, true, &human_args()).expect("ok");
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
        let out = select_patches(&patches, true, &human_args()).expect("ok");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].uuid, "new");
    }

    #[test]
    fn select_paid_user_falls_back_to_most_recent_free_when_no_paid() {
        let patches = vec![
            mk_patch("old", "pkg:npm/foo@1.0", "free", "2024-01-01"),
            mk_patch("new", "pkg:npm/foo@1.0", "free", "2024-06-01"),
        ];
        let out = select_patches(&patches, true, &human_args()).expect("ok");
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
        let err = select_patches(&patches, false, &json_args()).expect_err("should fail");
        assert_eq!(err, 1);
    }

    #[test]
    fn select_empty_input_returns_empty() {
        let out = select_patches(&[], false, &human_args()).expect("ok");
        assert!(out.is_empty());
        let out = select_patches(&[], true, &human_args()).expect("ok");
        assert!(out.is_empty());
        let out = select_patches(&[], false, &json_args()).expect("ok");
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
        let out = select_patches(&patches, false, &human_args()).expect("ok");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].uuid, "free");
        assert_eq!(out[0].tier, "free");
    }

    // --- decide_patch_action ---------------------------------------------
    // Locks in the per-patch action vocabulary surfaced by
    // download_and_apply_patches_with in JSON mode. See CLI_CONTRACT.md.

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
    // per-patch records by `download_and_apply_patches_with`. PR-comment bots
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

    // --- base64_decode -----------------------------------------------------
    // Blob content comes straight from the API; a corrupted payload must
    // surface as a decode error (which write_blob_entry turns into a
    // per-file failure), never as garbage bytes silently written to disk.

    #[test]
    fn base64_decode_rejects_invalid_character() {
        let err = base64_decode("ab!cd").expect_err("'!' is not in the base64 alphabet");
        assert!(
            err.contains("Invalid base64 character"),
            "error must say what went wrong; got: {err}"
        );
        assert!(
            err.contains('!'),
            "error must name the offending character; got: {err}"
        );
    }

    // --- pnpm_lock_resolves: needle at byte 0 ------------------------------
    // The boundary probe reads the char BEFORE the match; a match at the very
    // start of the text has none (`None => true`). A regression that indexes
    // `text[..pos - 1]` unconditionally would underflow/panic here.

    #[test]
    fn pnpm_lock_resolves_needle_at_start_of_text() {
        // pos == 0, plain v9 spelling: no preceding char is a valid boundary.
        assert!(pnpm_lock_resolves("left-pad@1.3.0:\n", "left-pad", "1.3.0"));
        // pos == 0, v5/v6 `/name/version` and `/name@version` spellings: the
        // leading `/` delimiter itself has nothing before it.
        assert!(pnpm_lock_resolves(
            "/left-pad/1.3.0:\n",
            "left-pad",
            "1.3.0"
        ));
        assert!(pnpm_lock_resolves(
            "/left-pad@1.3.0:\n",
            "left-pad",
            "1.3.0"
        ));
        // Still boundary-checked at the start of text: a scoped tail whose
        // name begins mid-token must NOT match.
        assert!(!pnpm_lock_resolves(
            "@scope/left-pad@1.3.0:\n",
            "left-pad",
            "1.3.0"
        ));
    }

    // --- write_all_patch_blobs ---------------------------------------------
    // The per-patch fan-out over write_blob_entry: the FIRST bad entry must
    // fail the whole patch (Err(())) and leave nothing outside the blobs
    // dir. This is the branch every blob-failure flow downstream keys on.

    #[tokio::test]
    async fn write_all_patch_blobs_traversal_hash_fails_and_writes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let blobs_dir = tmp.path().join("blobs");
        tokio::fs::create_dir_all(&blobs_dir).await.unwrap();

        let mut files = HashMap::new();
        let mut info = file_resp(None, Some("../escaped"));
        info.blob_content = Some(BLOB_B64.to_string());
        files.insert("package/index.js".to_string(), info);
        let patch = patch_with_files(files);

        let res = write_all_patch_blobs(&blobs_dir, &patch, /*quiet=*/ true).await;
        assert_eq!(res, Err(()), "a traversal afterHash must fail the patch");
        assert!(
            !tmp.path().join("escaped").exists(),
            "nothing may be written outside the blobs dir"
        );
        assert!(
            !blobs_dir.exists(),
            "no blob may be written for a rejected patch, and the empty blobs/ husk is pruned"
        );
    }

    /// A patch that fails HALF-WAY (its after-blob landed, its before-blob is
    /// rejected) must not leave the first blob behind as an orphan no record
    /// points at: the blobs this call created are unwound and the emptied
    /// `blobs/` pruned. The after entry is always written before the before
    /// entry of the same file, so one file suffices to pin the order.
    #[tokio::test]
    async fn write_all_patch_blobs_unwinds_its_own_blobs_on_a_later_failure() {
        let tmp = tempfile::tempdir().unwrap();
        let blobs_dir = tmp.path().join(".socket/blobs");

        let after = "a".repeat(64);
        let mut files = HashMap::new();
        let mut info = file_resp(Some("../escaped"), Some(&after));
        info.blob_content = Some(BLOB_B64.to_string());
        info.before_blob_content = Some(BLOB_B64.to_string());
        files.insert("package/index.js".to_string(), info);
        let patch = patch_with_files(files);

        let res = write_all_patch_blobs(&blobs_dir, &patch, /*quiet=*/ true).await;
        assert_eq!(res, Err(()));
        assert!(
            !blobs_dir.join(&after).exists(),
            "the after-blob written before the failure is unwound"
        );
        assert!(!blobs_dir.exists(), "the emptied blobs/ husk is pruned");
        assert!(
            tmp.path().join(".socket").is_dir(),
            "the prune stops at .socket/ (the lock guard's to remove)"
        );
    }

    /// The unwind removes only blobs THIS call created: a blob that already
    /// existed (a live record's revert data, content-addressed and shared)
    /// survives a later failure of the same patch byte-identical.
    #[tokio::test]
    async fn write_all_patch_blobs_unwind_spares_preexisting_blobs() {
        let tmp = tempfile::tempdir().unwrap();
        let blobs_dir = tmp.path().join(".socket/blobs");
        tokio::fs::create_dir_all(&blobs_dir).await.unwrap();
        let after = "a".repeat(64);
        tokio::fs::write(blobs_dir.join(&after), b"patched\n")
            .await
            .unwrap();

        let mut files = HashMap::new();
        let mut info = file_resp(Some("../escaped"), Some(&after));
        info.blob_content = Some(BLOB_B64.to_string());
        info.before_blob_content = Some(BLOB_B64.to_string());
        files.insert("package/index.js".to_string(), info);
        let patch = patch_with_files(files);

        let res = write_all_patch_blobs(&blobs_dir, &patch, /*quiet=*/ true).await;
        assert_eq!(res, Err(()));
        assert_eq!(
            tokio::fs::read(blobs_dir.join(&after)).await.unwrap(),
            b"patched\n",
            "a pre-existing blob is never this call's to remove"
        );

        // And a fully successful write reports exactly the NEW hashes.
        let before = "b".repeat(64);
        let mut files = HashMap::new();
        let mut info = file_resp(Some(&before), Some(&after));
        info.blob_content = Some(BLOB_B64.to_string());
        info.before_blob_content = Some(BLOB_B64.to_string());
        files.insert("package/index.js".to_string(), info);
        let created = write_all_patch_blobs(&blobs_dir, &patch_with_files(files), true)
            .await
            .unwrap();
        assert_eq!(
            created,
            vec![before.clone()],
            "the pre-existing after-blob is not new"
        );
        assert!(blobs_dir.join(&before).is_file());
    }

    // --- fold_narrowing_into_result ----------------------------------------
    // Hosted runs stack release-variant warnings (already in the envelope as
    // strings) with coarse-narrowing PnP warnings folded in later; the merge
    // must PRESERVE the existing strings and append the new `(code) detail`
    // ones, while skip records bump found/skipped and extend patches[].

    #[test]
    fn fold_narrowing_merges_into_existing_warnings_and_counts() {
        let mut result = serde_json::json!({
            "status": "success",
            "found": 1,
            "skipped": 0,
            "patches": [{"purl": "pkg:npm/kept@1.0.0", "action": "added"}],
            "warnings": ["existing variant warning"],
        });
        let skips = vec![serde_json::json!({
            "purl": "pkg:npm/skipped@1.0.0", "uuid": "u",
            "action": "skipped", "errorCode": "package_not_installed",
        })];
        let warnings = vec![(
            "yarn_pnp_unsupported".to_string(),
            "PnP layout detail".to_string(),
        )];
        fold_narrowing_into_result(&mut result, &skips, &warnings);

        assert_eq!(result["found"], 2, "skip records count as found");
        assert_eq!(result["skipped"], 1);
        let patches = result["patches"].as_array().unwrap();
        assert_eq!(patches.len(), 2, "skip record folded into patches[]");
        assert_eq!(patches[1]["errorCode"], "package_not_installed");
        assert_eq!(
            result["warnings"],
            serde_json::json!([
                "existing variant warning",
                "(yarn_pnp_unsupported) PnP layout detail"
            ]),
            "existing warning strings must survive the merge, new ones appended"
        );
    }

    /// Engine params for the nested-apply arg tests below.
    fn dl_params() -> DownloadParams {
        DownloadParams {
            cwd: PathBuf::from("."),
            manifest_path: PathBuf::from(".socket/manifest.json"),
            save_only: true,
            global: false,
            global_prefix: None,
            json: true,
            silent: true,
            download_mode: "diff".to_string(),
            all_releases: false,
            strict: false,
            ecosystems: None,
            persist_blobs: false,
        }
    }

    // --- format_patch_option: vulnerability summaries in the option lines --

    #[test]
    fn patch_option_line_joins_cves_when_advisory_has_them() {
        // An advisory WITH CVEs is summarized by the CVE ids joined with
        // ", " — the advisory id itself is not shown.
        let mut a = mk_patch("a", "pkg:npm/foo@1.0", "free", "2024-01-01");
        a.vulnerabilities.insert(
            "GHSA-with-cves".into(),
            VulnerabilityResponse {
                cves: vec!["CVE-2024-0001".into(), "CVE-2024-0002".into()],
                summary: "s".into(),
                severity: "high".into(),
                description: String::new(),
            },
        );
        assert_eq!(
            format_patch_option(&a),
            "a [FREE] (fixes: CVE-2024-0001, CVE-2024-0002) - desc-a"
        );
    }

    #[test]
    fn patch_option_line_falls_back_to_advisory_id_without_cves() {
        // An advisory WITHOUT CVEs (e.g. a GHSA with no CVE assigned yet)
        // falls back to the advisory id.
        let mut b = mk_patch("b", "pkg:npm/foo@1.0", "free", "2024-06-01");
        b.vulnerabilities.insert(
            "GHSA-no-cves".into(),
            VulnerabilityResponse {
                cves: vec![],
                summary: "s".into(),
                severity: "low".into(),
                description: String::new(),
            },
        );
        assert_eq!(
            format_patch_option(&b),
            "b [FREE] (fixes: GHSA-no-cves) - desc-b"
        );
    }

    #[test]
    fn patch_option_line_omits_fixes_segment_without_vulnerabilities() {
        let c = mk_patch("c", "pkg:npm/foo@1.0", "paid", "2024-06-01");
        assert_eq!(format_patch_option(&c), "c [PAID] - desc-c");
    }

    // --- terminal-UI text helpers ------------------------------------------

    fn vuln(cves: &[&str], severity: &str, summary: &str) -> VulnerabilityResponse {
        VulnerabilityResponse {
            cves: cves.iter().map(|c| c.to_string()).collect(),
            summary: summary.into(),
            severity: severity.into(),
            description: String::new(),
        }
    }

    fn with_vulns(
        mut p: PatchSearchResult,
        vulns: &[(&str, VulnerabilityResponse)],
    ) -> PatchSearchResult {
        for (id, v) in vulns {
            p.vulnerabilities.insert(id.to_string(), v.clone());
        }
        p
    }

    #[test]
    fn patch_option_line_has_no_dangling_dash_for_empty_description() {
        let mut p = mk_patch("u1", "pkg:npm/nuxt@4.5.0", "free", "2024-01-01");
        p.description = String::new();
        let p = with_vulns(p, &[("GHSA-x", vuln(&["CVE-2026-71315"], "high", ""))]);
        assert_eq!(format_patch_option(&p), "u1 [FREE] (fixes: CVE-2026-71315)");
        // Whitespace-only descriptions collapse to nothing too.
        let mut q = mk_patch("u2", "pkg:npm/nuxt@4.5.0", "free", "2024-01-01");
        q.description = "  \n ".into();
        assert_eq!(format_patch_option(&q), "u2 [FREE]");
    }

    #[test]
    fn patch_option_line_sorts_ids_across_advisories_and_truncates_multibyte() {
        let mut p = mk_patch("u", "pkg:npm/a@1", "free", "2024-01-01");
        p.description = "é".repeat(100);
        let p = with_vulns(
            p,
            &[
                ("GHSA-b", vuln(&["CVE-2026-2"], "low", "")),
                ("GHSA-a", vuln(&["CVE-2026-1", "CVE-2025-9"], "high", "")),
                ("GHSA-z", vuln(&[], "low", "")),
            ],
        );
        assert_eq!(
            format_patch_option(&p),
            format!(
                "u [FREE] (fixes: CVE-2025-9, CVE-2026-1, CVE-2026-2, GHSA-z) - {}...",
                "é".repeat(57)
            )
        );
    }

    #[test]
    fn vuln_labels_dedup_and_sort() {
        let mut m = HashMap::new();
        m.insert("GHSA-1".to_string(), vuln(&["CVE-2", "CVE-1"], "high", ""));
        m.insert("GHSA-2".to_string(), vuln(&["CVE-1"], "low", ""));
        assert_eq!(vuln_labels(&m), vec!["CVE-1", "CVE-2"]);
        assert!(vuln_labels(&HashMap::new()).is_empty());
    }

    #[test]
    fn patch_summary_line_shapes() {
        let mut m = HashMap::new();
        m.insert(
            "GHSA-1".to_string(),
            vuln(&["CVE-2021-44906"], "critical", ""),
        );
        assert_eq!(
            format_patch_summary("pkg:npm/minimist@1.2.5", "free", None, &m, false),
            "pkg:npm/minimist@1.2.5 [FREE] fixes CVE-2021-44906 (CRITICAL)"
        );
        assert_eq!(
            format_patch_summary(
                "pkg:npm/%40scope/x@1.0.0",
                "paid",
                Some("a8b05a61-1e2f-4c5f-a65b-93e71deba1ae"),
                &m,
                false
            ),
            "pkg:npm/@scope/x@1.0.0 [PAID] a8b05a61: fixes CVE-2021-44906 (CRITICAL)"
        );
        // No advisories: no `fixes`, no colon.
        assert_eq!(
            format_patch_summary(
                "pkg:npm/a@1",
                "free",
                Some("abcdef0123"),
                &HashMap::new(),
                false
            ),
            "pkg:npm/a@1 [FREE] abcdef01"
        );
        // Unknown severity: ids without a severity suffix.
        let mut u = HashMap::new();
        u.insert("GHSA-2".to_string(), vuln(&[], "", ""));
        assert_eq!(
            format_patch_summary("pkg:npm/a@1", "free", None, &u, false),
            "pkg:npm/a@1 [FREE] fixes GHSA-2"
        );
        // Several advisories: the max severity is labeled as such, and
        // colored like the listing when color is on.
        let mut several = HashMap::new();
        several.insert("GHSA-1".to_string(), vuln(&["CVE-2026-1"], "high", ""));
        several.insert("GHSA-2".to_string(), vuln(&["CVE-2026-2"], "moderate", ""));
        assert_eq!(
            format_patch_summary(
                "pkg:npm/nuxt@4.5.0",
                "paid",
                Some("884e9f6d-x"),
                &several,
                false
            ),
            "pkg:npm/nuxt@4.5.0 [PAID] 884e9f6d: fixes CVE-2026-1, CVE-2026-2 (highest: HIGH)"
        );
        assert_eq!(
            format_patch_summary("pkg:npm/minimist@1.2.5", "free", None, &m, true),
            "pkg:npm/minimist@1.2.5 [FREE] fixes CVE-2021-44906 (\x1b[91mCRITICAL\x1b[0m)"
        );
    }

    #[test]
    fn natural_cmp_orders_versions_numerically() {
        let mut v = vec![
            "pkg:npm/lodash@4.17.10",
            "pkg:npm/lodash@4.2.0",
            "pkg:npm/lodash@4.17.2",
            "pkg:npm/lodash@4.10.0",
            "pkg:npm/lodash@4.9.0",
            "pkg:npm/lodash-amd@4.0.0",
        ];
        v.sort_by(|a, b| natural_cmp(a, b));
        assert_eq!(
            v,
            vec![
                "pkg:npm/lodash-amd@4.0.0",
                "pkg:npm/lodash@4.2.0",
                "pkg:npm/lodash@4.9.0",
                "pkg:npm/lodash@4.10.0",
                "pkg:npm/lodash@4.17.2",
                "pkg:npm/lodash@4.17.10",
            ]
        );
        use std::cmp::Ordering;
        assert_eq!(natural_cmp("a1", "a01"), "a1".cmp("a01"));
        assert_ne!(natural_cmp("a1", "a01"), Ordering::Equal);
        assert_eq!(natural_cmp("", ""), Ordering::Equal);
        assert_eq!(natural_cmp("a", "a1"), Ordering::Less);
        assert_eq!(
            natural_cmp("x99999999999999999999999", "x1"),
            Ordering::Greater
        );
        assert_eq!(natural_cmp("é2", "é10"), Ordering::Less);
    }

    #[test]
    fn search_results_listing_exact_text() {
        let a = with_vulns(
            mk_patch("uuid-a", "pkg:npm/lodash@4.17.10", "free", "2024-01-01"),
            &[
                ("GHSA-b", vuln(&["CVE-2026-2"], "MODERATE", "")),
                ("GHSA-a", vuln(&["CVE-2026-1"], "HIGH", "")),
            ],
        );
        let mut b = mk_patch("uuid-b", "pkg:npm/lodash@4.17.2", "paid", "2024-01-01");
        b.description = String::new();
        let out = format_search_results(&[&a, &b], false, false);
        assert_eq!(
            out,
            "Found 2 patches:\n\n\
             \x20 1. pkg:npm/lodash@4.17.2 [PAID] (no access)\n\
             \x20    UUID: uuid-b\n\n\
             \x20 2. pkg:npm/lodash@4.17.10 [FREE]\n\
             \x20    UUID: uuid-a\n\
             \x20    Description: desc-uuid-a\n\
             \x20    Fixes: CVE-2026-1 (HIGH), CVE-2026-2 (MODERATE)\n\n"
        );
        let one = format_search_results(&[&a], true, false);
        assert!(one.starts_with("Found 1 patch:\n\n"), "{one}");
        assert_eq!(
            format_search_results(&[], true, false),
            "Found 0 patches:\n\n"
        );
        let colored = format_search_results(&[&a], true, true);
        assert!(
            colored.contains("CVE-2026-1 (\x1b[31mHIGH\x1b[0m)"),
            "{colored:?}"
        );
    }

    #[test]
    fn selected_block_names_uuid_and_fixes() {
        let a = with_vulns(
            mk_patch(
                "6332e781-0a42-4b0e-95c4-61f834461268",
                "pkg:npm/lodash@4.17.20",
                "free",
                "2024-01-01",
            ),
            &[("GHSA-a", vuln(&["CVE-2026-4800"], "HIGH", ""))],
        );
        assert_eq!(
            format_selected_patches(&[a], false),
            "Selected:\n  pkg:npm/lodash@4.17.20 [FREE] 6332e781: fixes CVE-2026-4800 (HIGH)\n\n"
        );
        assert_eq!(format_selected_patches(&[], false), "Selected:\n\n");
    }

    fn skip(purl: &str, code: &str) -> serde_json::Value {
        serde_json::json!({"purl": purl, "uuid": "u", "action": "skipped", "errorCode": code})
    }

    #[test]
    fn skip_summary_one_line_per_reason() {
        assert!(format_skip_summary(&[]).is_empty());
        assert_eq!(
            format_skip_summary(&[skip("pkg:npm/a@1", "package_not_installed")]),
            vec![
                "Skipped 1 patch for 1 package version not installed here \
                 (use --all-releases to include it)."
            ]
        );
        let many = vec![
            skip("pkg:npm/a@1", "package_not_installed"),
            skip("pkg:npm/a@1", "package_not_installed"),
            skip("pkg:npm/a@2", "package_not_installed"),
            skip("pkg:npm/b@1", "yarn_pnp_unsupported"),
        ];
        assert_eq!(
            format_skip_summary(&many),
            vec![
                "Skipped 3 patches for 2 package versions not installed here \
                 (use --all-releases to include them)."
                    .to_string(),
                "Skipped 1 patch for 1 package version (yarn_pnp_unsupported; \
                 see the warning above)."
                    .to_string(),
            ]
        );
    }

    #[test]
    fn all_narrowed_message_plurals_and_pnp() {
        assert_eq!(
            format_all_narrowed(&[skip("pkg:npm/a@1", "package_not_installed")]),
            "Patches exist for 1 package version, but it is not installed here. \
             Use --all-releases to fetch it anyway."
        );
        assert_eq!(
            format_all_narrowed(&[
                skip("pkg:npm/a@1", "package_not_installed"),
                skip("pkg:npm/a@2", "package_not_installed"),
                skip("pkg:npm/a@2", "package_not_installed"),
            ]),
            "Patches exist for 2 package versions, but none of them are installed here. \
             Use --all-releases to fetch them anyway."
        );
        assert_eq!(
            format_all_narrowed(&[skip("pkg:npm/a@1", "pnpm_pnp_unsupported")]),
            "Found 1 patch, but this project's Plug'n'Play layout makes its npm packages \
             unpatchable here; see the layout warning above for the remedy."
        );
    }

    #[test]
    fn confirm_prompts_per_mode() {
        use super::super::scan::ScanMode;
        assert_eq!(
            format_confirm_prompt(ScanMode::Agent, 1, false),
            "Download and apply 1 patch?"
        );
        assert_eq!(
            format_confirm_prompt(ScanMode::Agent, 2, false),
            "Download and apply 2 patches?"
        );
        assert_eq!(
            format_confirm_prompt(ScanMode::Agent, 1, true),
            "Download 1 patch?"
        );
        assert_eq!(
            format_confirm_prompt(ScanMode::Vendored, 3, false),
            "Download and vendor 3 patches?"
        );
        assert_eq!(
            format_confirm_prompt(ScanMode::Hosted, 1, false),
            "Redirect 1 package to the hosted patch server?"
        );
        assert_eq!(
            format_confirm_prompt(ScanMode::Hosted, 0, false),
            "Redirect 0 packages to the hosted patch server?"
        );
    }

    #[test]
    fn dry_run_line_plurals() {
        assert_eq!(
            format_dry_run("download and apply", 1),
            "[dry-run] Would download and apply 1 patch. No changes made."
        );
        assert_eq!(
            format_dry_run("download and vendor", 0),
            "[dry-run] Would download and vendor 0 patches. No changes made."
        );
    }

    #[test]
    fn no_packages_message_points_at_the_package_manager() {
        assert_eq!(no_packages_message(true), "No global packages found.");
        assert_eq!(
            no_packages_message(false),
            "No packages found. Run your package manager's install first."
        );
    }

    #[test]
    fn paid_required_text() {
        assert_eq!(
            format_paid_required("pkg:npm/a@1"),
            "This patch requires a paid subscription to download.\n  \
             Patch: pkg:npm/a@1\n  \
             Upgrade at: https://socket.dev/pricing"
        );
    }

    #[test]
    fn save_summary_lines() {
        let m = Path::new(".socket/manifest.json");
        assert_eq!(
            format_save_summary(m, 2, 0, 0, 0),
            "Patches saved to .socket/manifest.json\n  Added: 2"
        );
        assert_eq!(
            format_save_summary(m, 1, 1, 1, 1),
            "Patches saved to .socket/manifest.json\n  Added: 1\n  Updated: 1\n  Skipped: 1\n  Failed: 1"
        );
        assert_eq!(
            format_save_summary(m, 0, 0, 2, 0),
            "No changes to .socket/manifest.json\n  Added: 0\n  Skipped: 2"
        );
        assert_eq!(
            format_save_summary(m, 0, 0, 0, 1),
            "No changes to .socket/manifest.json\n  Added: 0\n  Failed: 1"
        );
    }

    #[test]
    fn best_match_line_names_the_count_only_when_there_was_a_choice() {
        assert_eq!(
            format_best_match("pkg:npm/%40s/a@1", 1),
            "Best match: pkg:npm/@s/a@1"
        );
        assert_eq!(
            format_best_match("pkg:npm/a@1", 3),
            "Best match: pkg:npm/a@1 (of 3 matching packages)"
        );
    }

    #[test]
    fn verbose_skips_dedupe_and_sort_naturally() {
        let rec = |purl: &str, code: Option<&str>| {
            let mut r = serde_json::json!({"purl": purl, "action": "skipped"});
            if let Some(c) = code {
                r["errorCode"] = serde_json::json!(c);
            }
            r
        };
        let skips = vec![
            rec("pkg:npm/a@4.10.0", Some("package_not_installed")),
            rec("pkg:npm/a@4.2.0", None),
            rec("pkg:npm/a@4.10.0", Some("package_not_installed")),
            rec("pkg:npm/a@4.1.0", Some("yarn_pnp_unsupported")),
        ];
        assert_eq!(
            format_verbose_skips(&skips),
            vec![
                "  [skip] pkg:npm/a@4.1.0 (yarn_pnp_unsupported)",
                "  [skip] pkg:npm/a@4.2.0 (version not installed)",
                "  [skip] pkg:npm/a@4.10.0 (version not installed)",
            ]
        );
        assert!(format_verbose_skips(&[]).is_empty());
    }

    #[test]
    fn selection_prompted_only_for_an_interactive_free_choice() {
        let two = vec![
            mk_patch("a", "pkg:npm/x@1", "free", "2024-01-01"),
            mk_patch("b", "pkg:npm/x@1", "free", "2024-02-01"),
        ];
        let one_plus_paid = vec![
            mk_patch("a", "pkg:npm/x@1", "free", "2024-01-01"),
            mk_patch("b", "pkg:npm/x@1", "paid", "2024-02-01"),
        ];
        let plain = GlobalArgs::default();
        let yes = GlobalArgs {
            yes: true,
            ..GlobalArgs::default()
        };
        let json = GlobalArgs {
            json: true,
            ..GlobalArgs::default()
        };
        // Paid users, --yes and --json never see a menu.
        assert!(!selection_prompted(&two, true, &plain));
        assert!(!selection_prompted(&two, false, &yes));
        assert!(!selection_prompted(&two, false, &json));
        // A single free candidate is auto-picked.
        assert!(!selection_prompted(&one_plus_paid, false, &plain));
        // Several free candidates prompt exactly when stdin is a terminal.
        use std::io::IsTerminal;
        assert_eq!(
            selection_prompted(&two, false, &plain),
            std::io::stdin().is_terminal()
        );
    }

    #[test]
    fn single_save_lines() {
        let m = Path::new("p/.socket/manifest.json");
        assert_eq!(
            format_single_save("Patch", &PatchAction::Added, m, "pkg:npm/a@1", true),
            "Patch saved to p/.socket/manifest.json\n  Added: 1"
        );
        assert_eq!(
            format_single_save(
                "Patch record",
                &PatchAction::Updated {
                    old_uuid: "0123456789abcdef".into()
                },
                m,
                "pkg:npm/a@1",
                false
            ),
            "Patch record saved to p/.socket/manifest.json\n  Updated: 1 (replacing 01234567)"
        );
        // A malformed short uuid never panics.
        assert!(format_single_save(
            "Patch",
            &PatchAction::Updated {
                old_uuid: "é".into()
            },
            m,
            "x",
            true
        )
        .ends_with("(replacing é)"));
        assert_eq!(
            format_single_save("Patch", &PatchAction::Skipped, m, "pkg:npm/%40s/a@1", true),
            "pkg:npm/@s/a@1 already has this patch recorded in p/.socket/manifest.json; \
             nothing to update."
        );
        // The vendored path still runs its vendor step: no "nothing to
        // update" promise.
        assert_eq!(
            format_single_save(
                "Patch record",
                &PatchAction::Skipped,
                m,
                "pkg:npm/a@1",
                false
            ),
            "pkg:npm/a@1 already has this patch recorded in p/.socket/manifest.json."
        );
    }

    #[test]
    fn record_skip_line_decodes_the_purl() {
        assert_eq!(
            format_record_skip("pkg:npm/%40scope/a@1.0.0", "already vendored"),
            "  [skip] pkg:npm/@scope/a@1.0.0 (already vendored)"
        );
        assert_eq!(
            format_record_skip("pkg:npm/a@1", "already in manifest"),
            "  [skip] pkg:npm/a@1 (already in manifest)"
        );
    }

    #[test]
    fn apply_failed_line_is_an_error_even_when_silent() {
        assert_eq!(APPLY_FAILED, "Error: Some patches could not be applied.");
    }

    #[test]
    fn forced_identifier_shapes() {
        assert_eq!(
            forced_identifier_error("lodash", IdentifierType::Uuid).as_deref(),
            Some("\"lodash\" is not a valid patch UUID (expected xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)")
        );
        assert_eq!(
            forced_identifier_error("lodash", IdentifierType::Cve).as_deref(),
            Some("\"lodash\" is not a valid CVE ID (expected CVE-YYYY-NNNN)")
        );
        assert_eq!(
            forced_identifier_error("GHSA-1", IdentifierType::Ghsa).as_deref(),
            Some("\"GHSA-1\" is not a valid GHSA ID (expected GHSA-xxxx-xxxx-xxxx)")
        );
        assert_eq!(
            forced_identifier_error("a8b05a61-1e2f-4c5f-a65b-93e71deba1ae", IdentifierType::Uuid),
            None
        );
        assert_eq!(
            forced_identifier_error("cve-2021-44906", IdentifierType::Cve),
            None
        );
        assert_eq!(
            forced_identifier_error("GHSA-xvch-5gv4-984h", IdentifierType::Ghsa),
            None
        );
        assert_eq!(
            forced_identifier_error("anything", IdentifierType::Package),
            None
        );
        assert_eq!(
            forced_identifier_error("anything", IdentifierType::Purl),
            None
        );
    }

    #[test]
    fn yes_auto_picks_the_top_ranked_free_patch_without_a_prompt() {
        // Two free patches for one purl would open the interactive menu;
        // --yes answers it with its default (the top-ranked patch).
        let patches = vec![
            mk_patch("old", "pkg:npm/foo@1.0", "free", "2024-01-01"),
            mk_patch("new", "pkg:npm/foo@1.0", "free", "2024-06-01"),
        ];
        let yes = GlobalArgs {
            yes: true,
            ..GlobalArgs::default()
        };
        let out = select_patches(&patches, false, &yes).expect("ok");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].uuid, "new");
        // --json keeps its selection_required contract even with --yes.
        let json_yes = GlobalArgs {
            yes: true,
            json: true,
            ..GlobalArgs::default()
        };
        assert_eq!(select_patches(&patches, false, &json_yes).unwrap_err(), 1);
    }

    #[test]
    fn help_text_has_no_implementation_notes() {
        use clap::CommandFactory;
        let mut cmd = crate::Cli::command();
        let get = cmd
            .find_subcommand_mut("get")
            .expect("get subcommand")
            .clone();
        let mut get = get;
        let help = get.render_long_help().to_string();
        for leak in [
            "value_parser",
            "parse_bool_flag",
            "No env binding",
            "locally- installed",
            "SOCKET_ONE_OFF",
            "--one-off",
        ] {
            assert!(!help.contains(leak), "get --help leaks {leak:?}:\n{help}");
        }
        assert!(help.contains("locally-installed distribution"), "{help}");
    }

    // --- download_patch_records (detached download phase) ------------------
    // pub(crate), so its branches are pinned here. wiremock is a dev-dep and
    // available to unit tests. Every override field is set explicitly so no
    // ambient SOCKET_* env can steer the client; the env guard below scrubs
    // the two vars the client constructor still consults for gaps.

    struct EnvVarGuard {
        saved: Vec<(&'static str, Option<String>)>,
    }

    impl EnvVarGuard {
        fn scrub(keys: &[&'static str]) -> Self {
            let saved = keys
                .iter()
                .map(|k| {
                    let old = std::env::var(k).ok();
                    std::env::remove_var(k);
                    (*k, old)
                })
                .collect();
            Self { saved }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            for (k, v) in &self.saved {
                match v {
                    Some(v) => std::env::set_var(k, v),
                    None => std::env::remove_var(k),
                }
            }
        }
    }

    fn detached_params(root: &Path) -> DownloadParams {
        DownloadParams {
            cwd: root.to_path_buf(),
            manifest_path: root.join(".socket/manifest.json"),
            save_only: true,
            global: false,
            global_prefix: None,
            json: true,
            silent: true,
            download_mode: "diff".to_string(),
            all_releases: false,
            strict: false,
            ecosystems: None,
            // The vendor-detached posture this fn exists for.
            persist_blobs: false,
        }
    }

    /// The test client every hermetic engine test drives: the mock server
    /// as API URL, a fake token, the fixture org — every override explicit
    /// so no ambient `SOCKET_*` can steer it.
    async fn test_client(server_url: &str) -> ApiClient {
        get_api_client_with_overrides(socket_patch_core::api::client::ApiClientEnvOverrides {
            api_url: Some(server_url.to_string()),
            api_token: Some("fake".to_string()),
            org_slug: Some("test-org".to_string()),
            proxy_url: None,
        })
        .await
        .0
    }

    /// The 3-arg shape the vendored-download unit tests below drive: builds
    /// the run's client against `server_url`, and drops the blob seed (the
    /// stager's concern, pinned by fetch_stage's tests).
    async fn download_patch_records(
        selected: &[PatchSearchResult],
        params: &DownloadParams,
        server_url: &str,
    ) -> (i32, serde_json::Value, HashMap<String, PatchRecord>) {
        let api_client = test_client(server_url).await;
        let (code, json, records, _blobs) =
            download_patch_records_with(selected, params, &api_client, HashMap::new()).await;
        (code, json, records)
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn download_patch_records_no_applicable_files_is_failed_and_unrecorded() {
        use wiremock::matchers::{method, path as wm_path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let _env = EnvVarGuard::scrub(&["SOCKET_PROXY_URL", "SOCKET_PATCH_PROXY_URL"]);
        let server = MockServer::start().await;
        let uuid = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let purl = "pkg:npm/covgap-no-after@1.0.0";
        // Every file lacks an afterHash -> files_for_manifest is empty ->
        // the no-applicable-files guardrail must count a failure, return
        // no record, and never claim the purl was downloaded.
        Mock::given(method("GET"))
            .and(wm_path(format!("/v0/orgs/test-org/patches/view/{uuid}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "uuid": uuid, "purl": purl,
                "publishedAt": "2024-01-01T00:00:00Z",
                "files": {
                    "package/index.js": { "beforeHash": "e".repeat(64), "afterHash": null }
                },
                "vulnerabilities": {}, "description": "d", "license": "MIT", "tier": "free",
            })))
            .mount(&server)
            .await;

        let tmp = tempfile::tempdir().unwrap();
        let selected = vec![mk_patch(uuid, purl, "free", "2024-01-01")];
        let (code, json, records) =
            download_patch_records(&selected, &detached_params(tmp.path()), &server.uri()).await;

        assert_eq!(code, 1, "guardrail failure must exit 1; json={json}");
        assert_eq!(json["failed"], 1, "json={json}");
        assert_eq!(json["downloaded"], 0, "json={json}");
        assert!(
            records.is_empty(),
            "no record may be handed to the vendor step"
        );
        assert_eq!(json["patches"][0]["action"], "failed", "json={json}");
        assert_eq!(
            json["patches"][0]["error"], "patch has no applicable files",
            "json={json}"
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn download_patch_records_view_404_is_fetch_miss() {
        use wiremock::MockServer;

        let _env = EnvVarGuard::scrub(&["SOCKET_PROXY_URL", "SOCKET_PATCH_PROXY_URL"]);
        // No view mock mounted: wiremock answers 404, which the API client
        // maps to Ok(None) — the "could not fetch details" fetch-miss arm.
        let server = MockServer::start().await;
        let tmp = tempfile::tempdir().unwrap();
        let uuid = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
        let purl = "pkg:npm/covgap-missing-view@1.0.0";
        let selected = vec![mk_patch(uuid, purl, "free", "2024-01-01")];

        let (code, json, records) =
            download_patch_records(&selected, &detached_params(tmp.path()), &server.uri()).await;

        assert_eq!(code, 1, "a fetch miss must exit 1; json={json}");
        assert_eq!(json["failed"], 1, "json={json}");
        assert!(records.is_empty());
        assert_eq!(json["patches"][0]["action"], "failed", "json={json}");
        assert_eq!(
            json["patches"][0]["error"], "could not fetch details",
            "json={json}"
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn download_patch_records_uninstalled_variant_base_warns_and_keeps_all() {
        use wiremock::MockServer;

        let _env = EnvVarGuard::scrub(&["SOCKET_PROXY_URL", "SOCKET_PATCH_PROXY_URL"]);
        // Two qualified PyPI variants sharing an UNINSTALLED base: release
        // narrowing must keep both (with the not-installed warning), and the
        // warnings key must ride the detached envelope. Views stay unmounted
        // (404) so both then fail — proving both were kept for the loop.
        let server = MockServer::start().await;
        let tmp = tempfile::tempdir().unwrap();
        let base = "pkg:pypi/covgap-sixish@1.0.0";
        let selected = vec![
            mk_patch(
                "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
                &format!("{base}?artifact_id=wheel"),
                "free",
                "2024-01-01",
            ),
            mk_patch(
                "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
                &format!("{base}?artifact_id=sdist"),
                "free",
                "2024-01-01",
            ),
        ];

        let (code, json, records) =
            download_patch_records(&selected, &detached_params(tmp.path()), &server.uri()).await;

        assert_eq!(code, 1, "json={json}");
        assert_eq!(json["found"], 2, "both variants must be kept; json={json}");
        assert_eq!(json["failed"], 2, "json={json}");
        assert!(records.is_empty());
        let warnings = json["warnings"]
            .as_array()
            .unwrap_or_else(|| panic!("keep-all fallback must surface warnings; json={json}"));
        assert!(
            warnings.iter().any(|w| w
                .as_str()
                .unwrap_or_default()
                .contains("not installed locally")),
            "warning must explain the keep-all fallback; json={json}"
        );
    }

    // --- coverage mop-up (2026-09 final wave) -------------------------------

    /// `merge_metadata` is a best-effort splice: a non-object record (or a
    /// non-object metadata value) must be left untouched, never panic —
    /// callers hand it freshly-built json! values, but the contract is
    /// defensive on both sides.
    #[test]
    fn merge_metadata_leaves_non_object_inputs_untouched() {
        // Non-object record: nothing to insert into.
        let mut record = serde_json::Value::Null;
        merge_metadata(&mut record, serde_json::json!({"severity": "high"}));
        assert!(record.is_null(), "a non-object record must stay untouched");

        // Non-object metadata: nothing to splice from.
        let mut record = serde_json::json!({"purl": "pkg:npm/x@1.0.0"});
        merge_metadata(&mut record, serde_json::Value::String("nope".into()));
        assert_eq!(record, serde_json::json!({"purl": "pkg:npm/x@1.0.0"}));
    }

    /// The `IdentifierType` Display labels are user-facing vocabulary (the
    /// "No patches found for {type}: {id}" terminal) — pin all five.
    #[test]
    fn identifier_type_display_labels_are_stable() {
        assert_eq!(IdentifierType::Uuid.to_string(), "UUID");
        assert_eq!(IdentifierType::Cve.to_string(), "CVE");
        assert_eq!(IdentifierType::Ghsa.to_string(), "GHSA");
        assert_eq!(IdentifierType::Purl.to_string(), "PURL");
        assert_eq!(IdentifierType::Package.to_string(), "package name");
    }

    /// JSON mode with multiple free patches for one purl: the
    /// `selection_required` options must carry each patch's vulnerability
    /// details (id/cves/severity/summary) so a bot can choose without a
    /// second query. The existing json-mode test used vuln-less patches, so
    /// the serialization closure never ran.
    #[test]
    fn select_json_mode_multi_free_options_serialize_vulnerabilities() {
        let mut a = mk_patch("a", "pkg:npm/foo@1.0", "free", "2024-01-01");
        a.vulnerabilities.insert(
            "GHSA-aaaa-bbbb-cccc".to_string(),
            VulnerabilityResponse {
                cves: vec!["CVE-2024-1111".to_string()],
                summary: "summary-a".to_string(),
                severity: "high".to_string(),
                description: "desc-a".to_string(),
            },
        );
        let mut b = mk_patch("b", "pkg:npm/foo@1.0", "free", "2024-02-01");
        b.vulnerabilities.insert(
            "GHSA-dddd-eeee-ffff".to_string(),
            VulnerabilityResponse {
                cves: vec![],
                summary: "summary-b".to_string(),
                severity: "low".to_string(),
                description: "desc-b".to_string(),
            },
        );
        let result = select_patches(&[a, b], false, &json_args());
        assert_eq!(
            result.err(),
            Some(1),
            "json mode with multiple free candidates must error with exit 1"
        );
    }

    /// `fold_narrowing_into_result` on a non-object envelope (the error
    /// shapes are the callers' concern) must be a calm no-op.
    #[test]
    fn fold_narrowing_ignores_non_object_result() {
        let mut result = serde_json::json!(["not", "an", "object"]);
        fold_narrowing_into_result(
            &mut result,
            &[serde_json::json!({"purl": "p", "action": "skipped"})],
            &[("code".to_string(), "detail".to_string())],
        );
        assert_eq!(result, serde_json::json!(["not", "an", "object"]));
    }

    /// A corrupt vendor ledger must degrade the coarse narrowing to "no
    /// ledger extension" (the download path's fail-closed read still guards
    /// writes): a purl claimed by nothing else is skipped as not installed,
    /// never kept on the strength of an unreadable state file.
    #[tokio::test]
    async fn filter_to_installed_purls_corrupt_vendor_state_degrades_to_no_extension() {
        let tmp = tempfile::tempdir().unwrap();
        let vendor = tmp.path().join(".socket/vendor");
        std::fs::create_dir_all(&vendor).unwrap();
        std::fs::write(vendor.join("state.json"), b"{ not json").unwrap();

        let common = crate::args::GlobalArgs {
            cwd: tmp.path().to_path_buf(),
            ..Default::default()
        };
        let accessible = vec![mk_patch(
            "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
            "pkg:npm/covgap-ledger-only@1.0.0",
            "free",
            "2024-01-01",
        )];
        let out = filter_to_installed_purls(
            &accessible,
            &common,
            crate::commands::scan::ScanMode::Hosted,
        )
        .await;
        assert!(
            out.kept.is_empty(),
            "nothing may be kept via a corrupt ledger"
        );
        assert_eq!(out.skip_records.len(), 1);
        assert_eq!(out.skip_records[0]["errorCode"], "package_not_installed");
    }

    /// The lockfile/vendor-ledger supplements are gated OFF for
    /// machine-tree-scoped runs (`--global` / `--global-prefix`): a version
    /// resolved only by the PROJECT lockfile must not count as present
    /// there — those runs target the machine tree, not this project.
    #[tokio::test]
    async fn filter_to_installed_purls_prefix_scoped_run_skips_lock_supplement() {
        let tmp = tempfile::tempdir().unwrap();
        let prefix = tempfile::tempdir().unwrap();
        // The project lockfile resolves the exact version under test.
        std::fs::write(
            tmp.path().join("package-lock.json"),
            serde_json::json!({
                "name": "consumer", "version": "0.0.0", "lockfileVersion": 3,
                "packages": {
                    "": { "name": "consumer", "version": "0.0.0" },
                    "node_modules/covgap-lock-only": {
                        "version": "1.0.0",
                        "resolved": "https://registry.npmjs.org/covgap-lock-only/-/covgap-lock-only-1.0.0.tgz",
                        "integrity": "sha512-AAAA=="
                    }
                }
            })
            .to_string(),
        )
        .unwrap();

        let common = crate::args::GlobalArgs {
            cwd: tmp.path().to_path_buf(),
            global_prefix: Some(prefix.path().to_path_buf()),
            ..Default::default()
        };
        let accessible = vec![mk_patch(
            "ffffffff-ffff-4fff-8fff-ffffffffffff",
            "pkg:npm/covgap-lock-only@1.0.0",
            "free",
            "2024-01-01",
        )];
        let out = filter_to_installed_purls(
            &accessible,
            &common,
            crate::commands::scan::ScanMode::Hosted,
        )
        .await;
        assert!(
            out.kept.is_empty(),
            "a prefix-scoped run must not treat lockfile resolution as presence"
        );
        assert_eq!(out.skip_records.len(), 1);
        assert_eq!(out.skip_records[0]["errorCode"], "package_not_installed");
    }

    /// pnpm-PnP + hosted: a purl the lock probe CANNOT judge (no `@version`
    /// coordinate to look for) must keep the layout-refusal code — the same
    /// no-judgment fallback as an unreadable lock — never a false
    /// "not installed" verdict; a judgeable-but-absent version is a genuine
    /// miss and carries `package_not_installed`.
    #[tokio::test]
    async fn filter_to_installed_purls_pnpm_pnp_hosted_unjudgeable_purl_keeps_layout_code() {
        let tmp = tempfile::tempdir().unwrap();
        // pnpm's own node-linker=pnp layout: PnP loader + pnpm-lock.yaml +
        // installed pnpm store marker, no yarn.lock.
        std::fs::write(tmp.path().join(".pnp.cjs"), b"// pnp loader\n").unwrap();
        std::fs::write(
            tmp.path().join("pnpm-lock.yaml"),
            b"lockfileVersion: '9.0'\n\nsnapshots:\n\n  some-other-pkg@2.0.0:\n",
        )
        .unwrap();
        std::fs::create_dir_all(tmp.path().join("node_modules")).unwrap();
        std::fs::write(tmp.path().join("node_modules/.modules.yaml"), b"").unwrap();

        let common = crate::args::GlobalArgs {
            cwd: tmp.path().to_path_buf(),
            ..Default::default()
        };
        let accessible = vec![
            // Versionless: the probe has no version to anchor on.
            mk_patch(
                "99999999-9999-4999-8999-999999999999",
                "pkg:npm/covgap-noversion",
                "free",
                "2024-01-01",
            ),
            // Versioned but absent from the lock: a judged miss.
            mk_patch(
                "88888888-8888-4888-8888-888888888888",
                "pkg:npm/covgap-judged@1.0.0",
                "free",
                "2024-01-01",
            ),
        ];
        let out = filter_to_installed_purls(
            &accessible,
            &common,
            crate::commands::scan::ScanMode::Hosted,
        )
        .await;
        assert!(out.kept.is_empty(), "neither purl may be kept");
        assert!(
            out.warnings.iter().any(|(code, _)| code.contains("pnp")),
            "the layout refusal must surface as a run-level warning; got {:?}",
            out.warnings
        );
        let code_for = |purl: &str| {
            out.skip_records
                .iter()
                .find(|r| r["purl"] == purl)
                .unwrap_or_else(|| panic!("missing skip record for {purl}"))["errorCode"]
                .clone()
        };
        assert_eq!(
            code_for("pkg:npm/covgap-noversion"),
            "pnpm_pnp_unsupported",
            "an unjudgeable purl must keep the layout code"
        );
        assert_eq!(
            code_for("pkg:npm/covgap-judged@1.0.0"),
            "package_not_installed",
            "a judged miss is a genuine not-installed verdict"
        );
    }

    /// `download_patch_records` with `persist_blobs` on a tree whose
    /// `.socket` path is squatted by a regular file: the blobs dir is created
    /// lazily, at the first blob actually persisted, so the failure surfaces
    /// as the per-patch `Blob decode or write failed` after the view fetch —
    /// no record handed to the caller, the squatting file left untouched.
    #[tokio::test]
    #[serial_test::serial]
    async fn download_patch_records_persist_blobs_unwritable_blobs_dir_is_failed_and_unrecorded() {
        use wiremock::matchers::{method, path as wm_path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let _env = EnvVarGuard::scrub(&["SOCKET_PROXY_URL", "SOCKET_PATCH_PROXY_URL"]);
        let server = MockServer::start().await;
        let uuid = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let purl = "pkg:npm/covgap-blobfail@1.0.0";
        Mock::given(method("GET"))
            .and(wm_path(format!("/v0/orgs/test-org/patches/view/{uuid}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "uuid": uuid, "purl": purl,
                "publishedAt": "2024-01-01T00:00:00Z",
                "files": { "package/index.js": {
                    "beforeHash": "0".repeat(64), "afterHash": "1".repeat(64),
                    "blobContent": "cGF0Y2hlZAo=",
                }},
                "vulnerabilities": {}, "description": "d", "license": "MIT", "tier": "free",
            })))
            .mount(&server)
            .await;
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join(".socket"), b"not a dir").unwrap();

        let selected = vec![mk_patch(uuid, purl, "free", "2024-01-01")];
        let mut params = detached_params(tmp.path());
        params.persist_blobs = true;
        let (code, json, records) = download_patch_records(&selected, &params, &server.uri()).await;

        assert_eq!(code, 1, "json={json}");
        assert_eq!(json["failed"], 1, "json={json}");
        assert_eq!(
            json["patches"][0]["error"], "Blob decode or write failed",
            "json={json}"
        );
        assert!(
            records.is_empty(),
            "a blob failure must not hand back a record"
        );
        assert_eq!(
            std::fs::read(tmp.path().join(".socket")).unwrap(),
            b"not a dir",
            "the squatting file must be left untouched"
        );
    }

    /// `download_patch_records` with `persist_blobs`: undecodable blob
    /// content is a per-patch failure — `Blob decode or write failed`, no
    /// record returned, nothing written into `.socket/blobs`.
    #[tokio::test]
    #[serial_test::serial]
    async fn download_patch_records_persist_blobs_bad_base64_is_failed_and_unrecorded() {
        use wiremock::matchers::{method, path as wm_path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let _env = EnvVarGuard::scrub(&["SOCKET_PROXY_URL", "SOCKET_PATCH_PROXY_URL"]);
        let server = MockServer::start().await;
        let uuid = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let purl = "pkg:npm/covgap-badblob@1.0.0";
        Mock::given(method("GET"))
            .and(wm_path(format!("/v0/orgs/test-org/patches/view/{uuid}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "uuid": uuid, "purl": purl,
                "publishedAt": "2024-01-01T00:00:00Z",
                "files": {
                    "package/index.js": {
                        "beforeHash": "0".repeat(64),
                        "afterHash": "1".repeat(64),
                        "blobContent": "%%%not-base64%%%",
                    }
                },
                "vulnerabilities": {}, "description": "d", "license": "MIT", "tier": "free",
            })))
            .mount(&server)
            .await;

        let tmp = tempfile::tempdir().unwrap();
        let selected = vec![mk_patch(uuid, purl, "free", "2024-01-01")];
        let mut params = detached_params(tmp.path());
        params.persist_blobs = true;
        let (code, json, records) = download_patch_records(&selected, &params, &server.uri()).await;

        assert_eq!(code, 1, "json={json}");
        assert_eq!(json["failed"], 1, "json={json}");
        assert_eq!(
            json["patches"][0]["error"], "Blob decode or write failed",
            "json={json}"
        );
        assert!(
            records.is_empty(),
            "a blob failure must not hand back a record"
        );
        assert!(
            !tmp.path().join(".socket").exists(),
            "the blobs dir is created only once a blob decodes, so undecodable \
             content must leave no `.socket/` behind at all"
        );
    }

    /// Human-mode `download_patch_records` (json=false, silent=false): the
    /// `[fetch]`, no-applicable-files `[fail]`, and fetch-miss `[fail]`
    /// print paths all execute, and the envelope keeps exact per-action
    /// counts alongside them.
    #[tokio::test]
    #[serial_test::serial]
    async fn download_patch_records_human_mode_mixed_outcomes() {
        use wiremock::matchers::{method, path as wm_path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let _env = EnvVarGuard::scrub(&["SOCKET_PROXY_URL", "SOCKET_PATCH_PROXY_URL"]);
        let server = MockServer::start().await;
        let good_uuid = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let good_purl = "pkg:npm/covgap-good@1.0.0";
        let nofiles_uuid = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
        let nofiles_purl = "pkg:npm/covgap-nofiles@1.0.0";
        let missing_uuid = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
        let missing_purl = "pkg:npm/covgap-missing@1.0.0";

        Mock::given(method("GET"))
            .and(wm_path(format!(
                "/v0/orgs/test-org/patches/view/{good_uuid}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "uuid": good_uuid, "purl": good_purl,
                "publishedAt": "2024-01-01T00:00:00Z",
                "files": {
                    "package/index.js": {
                        "beforeHash": "0".repeat(64),
                        "afterHash": "1".repeat(64),
                        "blobContent": "cGF0Y2hlZAo=",
                    }
                },
                "vulnerabilities": {}, "description": "d", "license": "MIT", "tier": "free",
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(wm_path(format!(
                "/v0/orgs/test-org/patches/view/{nofiles_uuid}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "uuid": nofiles_uuid, "purl": nofiles_purl,
                "publishedAt": "2024-01-01T00:00:00Z",
                "files": {
                    "package/index.js": { "beforeHash": "e".repeat(64), "afterHash": null }
                },
                "vulnerabilities": {}, "description": "d", "license": "MIT", "tier": "free",
            })))
            .mount(&server)
            .await;
        // missing_uuid's view stays unmounted -> 404 -> fetch miss.

        let tmp = tempfile::tempdir().unwrap();
        let selected = vec![
            mk_patch(good_uuid, good_purl, "free", "2024-01-01"),
            mk_patch(nofiles_uuid, nofiles_purl, "free", "2024-01-01"),
            mk_patch(missing_uuid, missing_purl, "free", "2024-01-01"),
        ];
        let mut params = detached_params(tmp.path());
        params.json = false;
        params.silent = false;
        let (code, json, records) = download_patch_records(&selected, &params, &server.uri()).await;

        assert_eq!(code, 1, "json={json}");
        assert_eq!(json["downloaded"], 1, "json={json}");
        assert_eq!(json["failed"], 2, "json={json}");
        assert_eq!(records.len(), 1, "only the good patch yields a record");
        assert!(records.contains_key(good_purl), "json={json}");
        let errors: Vec<&str> = json["patches"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|p| p["error"].as_str())
            .collect();
        assert!(
            errors.contains(&"patch has no applicable files"),
            "json={json}"
        );
        assert!(errors.contains(&"could not fetch details"), "json={json}");
    }

    /// A purl already vendored DETACHED at the selected uuid is served from
    /// the ledger's embedded record with ZERO network traffic — the
    /// idempotent re-run contract (human mode, so the `[skip]` print runs).
    #[tokio::test]
    #[serial_test::serial]
    async fn download_patch_records_already_vendored_detached_skips_offline() {
        use wiremock::MockServer;

        let _env = EnvVarGuard::scrub(&["SOCKET_PROXY_URL", "SOCKET_PATCH_PROXY_URL"]);
        let server = MockServer::start().await; // trap: no mounts
        let tmp = tempfile::tempdir().unwrap();
        let uuid = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let purl = "pkg:npm/covgap-vendored@1.0.0";

        let vendor = tmp.path().join(".socket/vendor");
        std::fs::create_dir_all(&vendor).unwrap();
        std::fs::write(
            vendor.join("state.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "version": 1,
                "entries": { purl: {
                    "ecosystem": "npm",
                    "basePurl": purl,
                    "uuid": uuid,
                    "artifact": {
                        "path": format!(".socket/vendor/npm/{uuid}/covgap-vendored-1.0.0.tgz"),
                    },
                    "wiring": [],
                    "detached": true,
                    "record": {
                        "uuid": uuid,
                        "exportedAt": "2024-01-01T00:00:00Z",
                        "files": {
                            "package/index.js": {
                                "beforeHash": "0".repeat(64),
                                "afterHash": "1".repeat(64),
                            }
                        },
                        "vulnerabilities": {},
                        "description": "embedded",
                        "license": "MIT",
                        "tier": "free",
                    }
                }}
            }))
            .unwrap(),
        )
        .unwrap();

        let selected = vec![mk_patch(uuid, purl, "free", "2024-01-01")];
        let mut params = detached_params(tmp.path());
        params.json = false;
        params.silent = false;
        let (code, json, records) = download_patch_records(&selected, &params, &server.uri()).await;

        assert_eq!(code, 0, "json={json}");
        assert_eq!(json["skipped"], 1, "json={json}");
        assert_eq!(json["patches"][0]["action"], "skipped", "json={json}");
        assert_eq!(
            records.get(purl).map(|r| r.uuid.as_str()),
            Some(uuid),
            "the ledger's embedded record must be reused"
        );
        assert!(
            server
                .received_requests()
                .await
                .unwrap_or_default()
                .is_empty(),
            "an already-vendored entry must never touch the network"
        );
    }

    // --- download_patch_records: Bun preflight (detached parity) -----------
    // The detached download phase must refuse the same Bun projects the
    // manifest-tracked one does, BEFORE any view fetch (request-log oracle),
    // and with the vendor code (never the downstream `package_not_installed`
    // the alias-shaped lockb project used to degrade to).

    /// A real bun 1.3.14 lockfileVersion-1 workspace lock (matrix capture
    /// grammar): 1-tuple `workspace:` entry, blank line between entries,
    /// trailing commas.
    const BUN_V1_WORKSPACE_LOCK: &str = r#"{
  "lockfileVersion": 1,
  "configVersion": 1,
  "workspaces": {
    "": {
      "name": "unit-fixture",
      "dependencies": {
        "consumer": "workspace:*",
      },
    },
    "packages/consumer": {
      "name": "consumer",
      "version": "1.0.0",
      "dependencies": {
        "covgap-bun": "1.0.0",
      },
    },
  },
  "packages": {
    "consumer": ["consumer@workspace:packages/consumer"],

    "covgap-bun": ["covgap-bun@1.0.0", "", {}, "sha512-AAAA=="],
  }
}
"#;

    #[tokio::test]
    #[serial_test::serial]
    async fn download_patch_records_malformed_bun_lockb_refuses_before_fetch() {
        use wiremock::matchers::{method, path as wm_path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let _env = EnvVarGuard::scrub(&["SOCKET_PROXY_URL", "SOCKET_PATCH_PROXY_URL"]);
        let server = MockServer::start().await;
        let uuid = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
        let purl = "pkg:npm/covgap-bun@1.0.0";
        // A view that WOULD succeed — proves the refusal is decided before
        // the fetch, not by a failed fetch.
        Mock::given(method("GET"))
            .and(wm_path(format!("/v0/orgs/test-org/patches/view/{uuid}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "uuid": uuid, "purl": purl,
                "publishedAt": "2024-01-01T00:00:00Z",
                "files": { "package/index.js": {
                    "beforeHash": "0".repeat(64), "afterHash": "1".repeat(64),
                    "blobContent": "cGF0Y2hlZAo=",
                }},
                "vulnerabilities": {}, "description": "d", "license": "MIT", "tier": "free",
            })))
            .mount(&server)
            .await;

        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("bun.lockb"), b"\x00binary").unwrap();
        let selected = vec![mk_patch(uuid, purl, "free", "2024-01-01")];
        let (code, json, records) =
            download_patch_records(&selected, &detached_params(tmp.path()), &server.uri()).await;

        assert_eq!(code, 1, "json={json}");
        assert_eq!(json["found"], 1, "json={json}");
        assert_eq!(json["downloaded"], 0, "json={json}");
        assert_eq!(json["failed"], 1, "json={json}");
        assert_eq!(json["patches"][0]["action"], "failed", "json={json}");
        assert_eq!(
            json["patches"][0]["errorCode"], "vendor_bun_lockb_invalid",
            "json={json}"
        );
        assert!(
            json["patches"][0]["error"]
                .as_str()
                .is_some_and(|d| !d.is_empty()),
            "the record must carry the engine's detail; json={json}"
        );
        assert!(records.is_empty(), "no record may reach the vendor step");
        assert!(
            server
                .received_requests()
                .await
                .unwrap_or_default()
                .is_empty(),
            "a refused Bun project must never fetch the patch view"
        );
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn download_patch_records_bun_v1_workspace_refuses_before_fetch() {
        use wiremock::MockServer;

        let _env = EnvVarGuard::scrub(&["SOCKET_PROXY_URL", "SOCKET_PATCH_PROXY_URL"]);
        let server = MockServer::start().await; // trap: no mounts
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("bun.lock"), BUN_V1_WORKSPACE_LOCK).unwrap();
        let uuid = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
        let purl = "pkg:npm/covgap-bun@1.0.0";
        let selected = vec![mk_patch(uuid, purl, "free", "2024-01-01")];

        let (code, json, records) =
            download_patch_records(&selected, &detached_params(tmp.path()), &server.uri()).await;

        assert_eq!(code, 1, "json={json}");
        assert_eq!(json["failed"], 1, "json={json}");
        assert_eq!(
            json["patches"][0]["errorCode"], "vendor_bun_workspace_unsupported",
            "json={json}"
        );
        assert!(records.is_empty());
        assert!(
            server
                .received_requests()
                .await
                .unwrap_or_default()
                .is_empty(),
            "refused before any fetch"
        );
        assert_eq!(
            std::fs::read_to_string(tmp.path().join("bun.lock")).unwrap(),
            BUN_V1_WORKSPACE_LOCK,
            "the preflight is read-only"
        );
    }

    /// The preflight is npm-only: a non-npm purl on a Bun-refused tree is
    /// fetched as usual (here: the view is unmounted, so it fails as a fetch
    /// miss — proving it reached the network, not the refusal).
    #[tokio::test]
    #[serial_test::serial]
    async fn download_patch_records_bun_refusal_skips_non_npm_purls() {
        use wiremock::MockServer;

        let _env = EnvVarGuard::scrub(&["SOCKET_PROXY_URL", "SOCKET_PATCH_PROXY_URL"]);
        let server = MockServer::start().await;
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("bun.lockb"), b"\x00binary").unwrap();
        let uuid = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
        let purl = "pkg:pypi/covgap-not-bun@1.0.0";
        let selected = vec![mk_patch(uuid, purl, "free", "2024-01-01")];

        let (code, json, _) =
            download_patch_records(&selected, &detached_params(tmp.path()), &server.uri()).await;

        assert_eq!(code, 1, "json={json}");
        assert_eq!(
            json["patches"][0]["error"], "could not fetch details",
            "a pypi purl must reach the fetch, not the Bun refusal; json={json}"
        );
        assert!(json["patches"][0].get("errorCode").is_none(), "json={json}");
        assert_eq!(
            server.received_requests().await.unwrap_or_default().len(),
            1,
            "exactly the view fetch"
        );
    }

    /// Ledger entries at either the selected or an older UUID must not
    /// bypass the refusal when the live lock contains registry wiring.
    #[tokio::test]
    #[serial_test::serial]
    async fn download_patch_records_bun_refusal_rejects_unwired_ledger_entries() {
        use wiremock::MockServer;

        let _env = EnvVarGuard::scrub(&["SOCKET_PROXY_URL", "SOCKET_PATCH_PROXY_URL"]);
        let server = MockServer::start().await;
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("bun.lock"), BUN_V1_WORKSPACE_LOCK).unwrap();
        let same = "ffffffff-ffff-4fff-8fff-ffffffffffff";
        let older = "abababab-abab-4bab-8bab-abababababab";
        let newer = "cdcdcdcd-cdcd-4dcd-8dcd-cdcdcdcdcdcd";
        let in_sync = "pkg:npm/covgap-bun@1.0.0";
        let stale = "pkg:npm/covgap-bun-stale@1.0.0";
        // Two ledger entries: one in sync with the selection, one stale.
        let vendor = tmp.path().join(".socket/vendor");
        std::fs::create_dir_all(&vendor).unwrap();
        let entry = |purl: &str, uuid: &str| {
            serde_json::json!({
                "ecosystem": "npm", "basePurl": purl, "uuid": uuid,
                "artifact": { "path": format!(".socket/vendor/npm/{uuid}/x.tgz") },
                "wiring": [], "flavor": "bun",
            })
        };
        // The in-sync entry carries the D2 shape every vendored run writes
        // (detached + embedded record): exactly what the ledger idempotency
        // skip keys on — the refusal must still win over that skip.
        let mut in_sync_entry = entry(in_sync, same);
        in_sync_entry["detached"] = serde_json::json!(true);
        in_sync_entry["record"] = serde_json::json!({
            "uuid": same,
            "exportedAt": "2026-01-01T00:00:00Z",
            "files": {},
            "vulnerabilities": {},
            "description": "fixture",
            "license": "MIT",
            "tier": "free",
        });
        std::fs::write(
            vendor.join("state.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "version": 1,
                "entries": { in_sync: in_sync_entry, stale: entry(stale, older) },
            }))
            .unwrap(),
        )
        .unwrap();

        let selected = vec![
            mk_patch(same, in_sync, "free", "2024-01-01"),
            mk_patch(newer, stale, "free", "2024-01-01"),
        ];
        let (code, json, _) =
            download_patch_records(&selected, &detached_params(tmp.path()), &server.uri()).await;

        assert_eq!(code, 1, "json={json}");
        let by_purl = |purl: &str| {
            json["patches"]
                .as_array()
                .unwrap()
                .iter()
                .find(|p| p["purl"] == purl)
                .cloned()
                .unwrap_or_else(|| panic!("no record for {purl}: {json}"))
        };
        let refused_same = by_purl(in_sync);
        assert_eq!(
            refused_same["errorCode"], "vendor_bun_workspace_unsupported",
            "UUID equality alone cannot bypass the refusal; json={json}"
        );
        let refused = by_purl(stale);
        assert_eq!(
            refused["errorCode"], "vendor_bun_workspace_unsupported",
            "a stale-uuid entry is refused like a fresh vendoring; json={json}"
        );
        let paths: Vec<String> = server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .map(|r| r.url.path().to_string())
            .collect();
        assert!(paths.is_empty(), "no refused purl may fetch: {paths:?}");
    }

    /// An unreadable vendor ledger silences the drift warning (the main
    /// vendor path reports unreadable state itself) instead of panicking or
    /// fabricating a warning.
    #[tokio::test]
    async fn warn_on_vendored_uuid_drift_unreadable_state_warns_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let vendor = tmp.path().join(".socket/vendor");
        std::fs::create_dir_all(&vendor).unwrap();
        std::fs::write(vendor.join("state.json"), b"{ not json").unwrap();

        let mut warnings = Vec::new();
        warn_on_vendored_uuid_drift(
            tmp.path(),
            true,
            &[serde_json::json!({
                "purl": "pkg:npm/x@1.0.0",
                "uuid": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "action": "added",
            })],
            &mut warnings,
        )
        .await;
        assert!(warnings.is_empty(), "unreadable state must warn nothing");
    }

    /// Malformed per-patch records (missing purl/uuid) are skipped without
    /// panicking, while a well-formed drifting record still warns.
    #[tokio::test]
    async fn warn_on_vendored_uuid_drift_skips_malformed_records_and_flags_drift() {
        let tmp = tempfile::tempdir().unwrap();
        let purl = "pkg:npm/covgap-drift@1.0.0";
        let vendored_uuid = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let new_uuid = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
        let vendor = tmp.path().join(".socket/vendor");
        std::fs::create_dir_all(&vendor).unwrap();
        std::fs::write(
            vendor.join("state.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "version": 1,
                "entries": { purl: {
                    "ecosystem": "npm",
                    "basePurl": purl,
                    "uuid": vendored_uuid,
                    "artifact": {
                        "path": format!(".socket/vendor/npm/{vendored_uuid}/covgap-drift-1.0.0.tgz"),
                    },
                    "wiring": []
                }}
            }))
            .unwrap(),
        )
        .unwrap();

        let mut warnings = Vec::new();
        warn_on_vendored_uuid_drift(
            tmp.path(),
            true,
            &[
                // Malformed: no purl/uuid — must be skipped, not panic.
                serde_json::json!({"action": "added"}),
                // Genuine drift: manifest moved to a different uuid.
                serde_json::json!({"purl": purl, "uuid": new_uuid, "action": "added"}),
            ],
            &mut warnings,
        )
        .await;
        assert_eq!(warnings.len(), 1, "warnings={warnings:?}");
        assert!(
            warnings[0].contains(purl) && warnings[0].contains("is vendored at patch"),
            "warnings={warnings:?}"
        );
    }

    /// The nested apply inherits the caller's flags verbatim (`--verbose`
    /// and `--strict` were dropped when its args were rebuilt from Default),
    /// with `json`/`dry_run` forced off — one JSON document per run, and
    /// agent-mode `get` ignores `--dry-run` — `silent` following the caller's
    /// quiet gate, and the manifest path absolutized so apply does not
    /// re-resolve it against its own `--cwd`.
    #[test]
    fn nested_apply_args_flow_caller_flags_and_force_a_real_quiet_apply() {
        let common = GlobalArgs {
            verbose: true,
            strict: true,
            json: true,
            dry_run: true,
            ..GlobalArgs::default()
        };
        let nested = nested_apply_args(&common, Path::new("proj/.socket/manifest.json"), true);
        assert!(
            nested.verbose && nested.strict,
            "--verbose / --strict must flow through"
        );
        assert!(
            !nested.json && !nested.dry_run,
            "the nested apply is always a real, non-JSON run"
        );
        assert!(nested.silent, "silent follows the caller's quiet gate");
        assert!(
            Path::new(&nested.manifest_path).is_absolute(),
            "got {}",
            nested.manifest_path
        );
    }

    /// The engine's variant rebuilds the same shape from `DownloadParams` +
    /// `DownloadRun`: the run's verbosity flag, the caller's scope/mode
    /// flags, and quiet = json || silent. No API fields: the nested apply
    /// runs on the run's client, so `--org` need not be re-threaded.
    #[test]
    fn nested_apply_args_from_params_carry_run_flags() {
        let client = ApiClient::new(socket_patch_core::api::client::ApiClientOptions {
            api_url: "http://127.0.0.1:1".into(),
            api_token: None,
            use_public_proxy: false,
            org_slug: None,
        });
        let run = DownloadRun {
            api_client: &client,
            lock_timeout: Some(7),
            verbose: true,
        };
        let params = dl_params();
        let nested =
            nested_apply_args_from_params(&params, &run, Path::new(".socket/manifest.json"));
        assert!(nested.verbose);
        assert!(
            nested.org.is_none() && nested.api_token.is_none(),
            "API fields are never threaded through params: the nested apply runs on the run's client"
        );
        assert_eq!(nested.download_mode, "diff");
        assert!(nested.silent, "json || silent params run a quiet apply");
        assert!(!nested.json && !nested.dry_run);
    }

    /// The uuid path hands the engine the view it already fetched: the
    /// record is served from `prefetched` with ZERO network traffic (a
    /// fresh fetch could re-hit the 401 the proxy fallback recovered from),
    /// and the ledger-free classification reports it `downloaded`.
    #[tokio::test]
    #[serial_test::serial]
    async fn download_patch_records_with_prefetched_view_never_fetches() {
        use wiremock::MockServer;

        let _env = EnvVarGuard::scrub(&["SOCKET_PROXY_URL", "SOCKET_PATCH_PROXY_URL"]);
        let server = MockServer::start().await; // trap: no mounts
        let tmp = tempfile::tempdir().unwrap();
        // Two files: one with served `blobContent` (→ the blob seed), one
        // without (→ contributes nothing, and is NOT a failure).
        let mut seeded = file_resp(Some(&"0".repeat(64)), Some(&"1".repeat(64)));
        seeded.blob_content = Some("cGF0Y2hlZA==".to_string()); // "patched"
        let mut patch = patch_with_files(HashMap::from([
            ("package/index.js".to_string(), seeded),
            (
                "package/other.js".to_string(),
                file_resp(Some(&"2".repeat(64)), Some(&"3".repeat(64))),
            ),
        ]));
        patch.uuid = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into();
        patch.purl = "pkg:npm/covgap-prefetched@1.0.0".into();
        let selected = vec![mk_patch(&patch.uuid, &patch.purl, "free", "2024-01-01")];
        let params = detached_params(tmp.path());
        let client = test_client(&server.uri()).await;
        let prefetched = HashMap::from([(patch.uuid.clone(), patch.clone())]);

        let (code, json, records, blobs) =
            download_patch_records_with(&selected, &params, &client, prefetched).await;

        assert_eq!(code, 0, "json={json}");
        assert_eq!(json["downloaded"], 1, "json={json}");
        // The blob seed carries every served `blobContent` by after-hash —
        // decoded — and only those; the vendor stager starts from it.
        assert_eq!(
            blobs.get(&"1".repeat(64)).map(Vec::as_slice),
            Some(&b"patched"[..]),
            "the served blob is seeded under its after-hash"
        );
        assert_eq!(blobs.len(), 1, "a file with no blobContent seeds nothing");
        assert_eq!(json["detached"], true, "json={json}");
        assert_eq!(json["patches"][0]["action"], "downloaded", "json={json}");
        assert!(
            json["patches"][0].get("oldUuid").is_none(),
            "no ledger entry, no oldUuid; json={json}"
        );
        assert_eq!(
            records.get(&patch.purl).map(|r| r.uuid.as_str()),
            Some(patch.uuid.as_str()),
            "the record must be built from the prefetched view"
        );
        assert!(
            server
                .received_requests()
                .await
                .unwrap_or_default()
                .is_empty(),
            "a prefetched view must never be fetched again"
        );
        assert!(
            !tmp.path().join(".socket").exists(),
            "the detached download phase writes nothing"
        );
    }

    /// A ledger entry at an OLDER uuid: the fetched record is `downloaded`
    /// and carries `oldUuid` — the re-vendor the vendor step will perform —
    /// derived from the ledger, since the vendored flows have no manifest.
    #[tokio::test]
    #[serial_test::serial]
    async fn download_patch_records_superseding_uuid_carries_old_uuid_from_ledger() {
        use wiremock::matchers::{method, path as wm_path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let _env = EnvVarGuard::scrub(&["SOCKET_PROXY_URL", "SOCKET_PATCH_PROXY_URL"]);
        let server = MockServer::start().await;
        let purl = "pkg:npm/covgap-supersede@1.0.0";
        let old_uuid = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        let new_uuid = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
        Mock::given(method("GET"))
            .and(wm_path(format!(
                "/v0/orgs/test-org/patches/view/{new_uuid}"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "uuid": new_uuid, "purl": purl,
                "publishedAt": "2024-01-01T00:00:00Z",
                "files": { "package/index.js": {
                    "beforeHash": "0".repeat(64), "afterHash": "1".repeat(64),
                    "blobContent": "cGF0Y2hlZAo=",
                }},
                "vulnerabilities": {}, "description": "d", "license": "MIT", "tier": "free",
            })))
            .mount(&server)
            .await;

        let tmp = tempfile::tempdir().unwrap();
        let vendor = tmp.path().join(".socket/vendor");
        std::fs::create_dir_all(&vendor).unwrap();
        std::fs::write(
            vendor.join("state.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "version": 1,
                "entries": { purl: {
                    "ecosystem": "npm",
                    "basePurl": purl,
                    "uuid": old_uuid,
                    "artifact": {
                        "path": format!(".socket/vendor/npm/{old_uuid}/covgap-supersede-1.0.0.tgz"),
                    },
                    "wiring": []
                }}
            }))
            .unwrap(),
        )
        .unwrap();

        let selected = vec![mk_patch(new_uuid, purl, "free", "2024-01-01")];
        let (code, json, records) =
            download_patch_records(&selected, &detached_params(tmp.path()), &server.uri()).await;

        assert_eq!(code, 0, "json={json}");
        assert_eq!(json["downloaded"], 1, "json={json}");
        assert_eq!(json["skipped"], 0, "json={json}");
        assert_eq!(json["patches"][0]["action"], "downloaded", "json={json}");
        assert_eq!(json["patches"][0]["oldUuid"], old_uuid, "json={json}");
        assert_eq!(
            records.get(purl).map(|r| r.uuid.as_str()),
            Some(new_uuid),
            "the superseding record is what the vendor step receives"
        );
    }

    /// The env guard must RESTORE a variable that was set before the scrub —
    /// the suite depends on it not leaking scrubbed state across tests.
    #[test]
    #[serial_test::serial]
    fn env_var_guard_restores_previously_set_values() {
        std::env::set_var("COVGAP_GET_GUARD_PROBE", "original");
        {
            let _guard = EnvVarGuard::scrub(&["COVGAP_GET_GUARD_PROBE"]);
            assert!(
                std::env::var("COVGAP_GET_GUARD_PROBE").is_err(),
                "scrub must remove the var"
            );
        }
        assert_eq!(
            std::env::var("COVGAP_GET_GUARD_PROBE").as_deref(),
            Ok("original"),
            "drop must restore the pre-scrub value"
        );
        std::env::remove_var("COVGAP_GET_GUARD_PROBE");
    }

    /// Release-variant narrowing must not randomize the selection order.
    ///
    /// `filter_to_installed_releases` buckets every release-variant purl
    /// (PyPI / RubyGems / Maven) into a `HashMap` keyed by base purl and
    /// then drains it, so the singleton bases — the common case — came back
    /// in `HashMap` iteration order. That order is the download loop's
    /// order, which is the order `download.patches` / `apply.patches` are
    /// emitted in, so two identical runs produced different JSON. Every
    /// sibling collection in the same envelope is purl-sorted
    /// (`scan`'s `packages`, the agent flow's `skip_records`), so this one
    /// must be too.
    #[tokio::test]
    async fn release_narrowing_keeps_a_stable_purl_order() {
        let names = [
            "urllib3",
            "requests",
            "idna",
            "certifi",
            "charset-normalizer",
            "jinja2",
            "markupsafe",
            "werkzeug",
            "click",
            "itsdangerous",
            "blinker",
            "flask",
        ];
        let selected: Vec<PatchSearchResult> = {
            let mut v: Vec<PatchSearchResult> = names
                .iter()
                .enumerate()
                .map(|(i, n)| {
                    mk_patch(
                        &format!("uuid-{i}"),
                        &format!("pkg:pypi/{n}@1.0.0?artifact_id=wheel"),
                        "free",
                        "2026-01-01T00:00:00Z",
                    )
                })
                .collect();
            v.sort_by(|a, b| a.purl.cmp(&b.purl));
            v
        };
        let tmp = tempfile::tempdir().expect("tempdir");
        let options = CrawlerOptions {
            cwd: tmp.path().to_path_buf(),
            global: false,
            global_prefix: None,
        };
        // No mock server is needed: every base has exactly one variant, so
        // the narrowing returns before it queries the crawler or the API.
        let client = test_client("http://127.0.0.1:1").await;
        let (kept, _warnings, _views) =
            filter_to_installed_releases(&selected, false, &options, true, &client).await;
        let got: Vec<&str> = kept.iter().map(|p| p.purl.as_str()).collect();
        let want: Vec<&str> = selected.iter().map(|p| p.purl.as_str()).collect();
        assert_eq!(
            got, want,
            "the narrowing must preserve the caller's purl order, not the \
             HashMap's bucket order"
        );
    }

    /// The vendored/agent envelope's `download.patches` array must come out
    /// in the same order on every run. It is built by walking the narrowed
    /// selection, so the `HashMap`-ordered narrowing above leaked straight
    /// into the JSON: two identical runs of the same project emitted the
    /// same records in different orders. No view is mounted — wiremock
    /// answers 404, so every purl lands on the fetch-miss arm and records
    /// one `patches[]` entry, which is all this pins.
    #[tokio::test]
    #[serial_test::serial]
    async fn download_patches_json_is_purl_ordered() {
        use wiremock::MockServer;

        let _env = EnvVarGuard::scrub(&["SOCKET_PROXY_URL", "SOCKET_PATCH_PROXY_URL"]);
        let server = MockServer::start().await;
        let tmp = tempfile::tempdir().unwrap();
        let names = [
            "urllib3",
            "requests",
            "idna",
            "certifi",
            "charset-normalizer",
            "jinja2",
            "markupsafe",
            "werkzeug",
            "click",
            "itsdangerous",
            "blinker",
            "flask",
        ];
        let mut selected: Vec<PatchSearchResult> = names
            .iter()
            .enumerate()
            .map(|(i, n)| {
                mk_patch(
                    &format!("{:08x}-aaaa-4aaa-8aaa-aaaaaaaaaaaa", i),
                    &format!("pkg:pypi/{n}@1.0.0?artifact_id=wheel"),
                    "free",
                    "2026-01-01T00:00:00Z",
                )
            })
            .collect();
        selected.sort_by(|a, b| a.purl.cmp(&b.purl));

        let (_code, json, _records) =
            download_patch_records(&selected, &detached_params(tmp.path()), &server.uri()).await;

        let got: Vec<&str> = json["patches"]
            .as_array()
            .expect("patches[]")
            .iter()
            .map(|p| p["purl"].as_str().expect("purl"))
            .collect();
        let want: Vec<&str> = selected.iter().map(|p| p.purl.as_str()).collect();
        assert_eq!(
            got, want,
            "download.patches must be emitted in the selection's purl order; json={json}"
        );
    }
}
