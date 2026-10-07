//! The `policy` JSON block (4.7) both engines report: disk scans and the
//! in-memory engine build the same entries and render them here.

use super::{severity_name, FilterReason, PolicySource, SelectionPolicy};

/// One `policy.filtered[]` entry.
#[derive(Debug, Clone)]
pub struct FilteredEntry {
    pub purl: Option<String>,
    pub uuid: Option<String>,
    pub project: String,
    pub reason: FilterReason,
    /// The would-be patch's severity order, when a patch was looked up.
    pub severity: Option<u8>,
}

/// One `policy.retained[]` entry.
#[derive(Debug, Clone)]
pub struct RetainedEntry {
    pub purl: String,
    pub project: String,
    pub recorded_uuid: String,
    pub reason: FilterReason,
    pub upgrade_available: bool,
}

/// The top-level `policy` block (4.7), shared by disk scans and the
/// in-memory engine.
pub fn policy_block(
    policy: &SelectionPolicy,
    filtered: &[FilteredEntry],
    retained: &[RetainedEntry],
) -> serde_json::Value {
    let (path, sha256) = match policy.source() {
        PolicySource::File { path, sha256 } => (serde_json::json!(path), serde_json::json!(sha256)),
        _ => (serde_json::Value::Null, serde_json::Value::Null),
    };
    let (floor, floor_source) = policy.min_severity();
    // Sorted: crawl order is filesystem order, and the two engines differ.
    let mut filtered: Vec<&FilteredEntry> = filtered.iter().collect();
    filtered.sort_by(|a, b| (&a.project, &a.purl, a.reason.code()).cmp(&(&b.project, &b.purl, b.reason.code())));
    let mut retained: Vec<&RetainedEntry> = retained.iter().collect();
    retained.sort_by(|a, b| (&a.project, &a.purl).cmp(&(&b.project, &b.purl)));
    let filtered: Vec<serde_json::Value> = filtered
        .iter()
        .map(|f| {
            serde_json::json!({
                "purl": f.purl,
                "uuid": f.uuid,
                "project": f.project,
                "reason": f.reason.code(),
                "detail": f.reason.detail(),
            })
        })
        .collect();
    let retained: Vec<serde_json::Value> = retained
        .iter()
        .map(|r| {
            serde_json::json!({
                "purl": r.purl,
                "project": r.project,
                "recordedUuid": r.recorded_uuid,
                "reason": r.reason.code(),
                "detail": r.reason.detail(),
                "upgradeAvailable": r.upgrade_available,
            })
        })
        .collect();
    serde_json::json!({
        "source": policy.source().as_str(),
        "path": path,
        "sha256": sha256,
        "enabled": policy.enabled(),
        "minSeverity": {
            "value": floor.and_then(severity_name),
            "source": floor_source.as_str(),
        },
        "counts": { "filtered": filtered.len(), "retained": retained.len() },
        "filtered": filtered,
        "retained": retained,
    })
}
