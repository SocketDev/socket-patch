//! Manifest records built from fetched patch views: the ONE rule every
//! flow (get, scan, vendor, repair, hosted) uses to turn a `PatchResponse`
//! into the `PatchRecord` it persists.

use std::collections::HashMap;

use crate::api::types::{PatchResponse, VulnerabilityResponse};
use crate::manifest::schema::{PatchFileInfo, PatchRecord, VulnerabilityInfo};

/// Convert the API-shaped vulnerability map on `PatchResponse` into the
/// serialization-shaped map stored in the manifest.
pub fn vulnerabilities_for_manifest(
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
pub fn build_patch_record(
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

/// Build the manifest-shaped `files` map from a fetched patch view,
/// keeping EVERY file the patch touches — including net-new files the
/// patch ADDS, which carry an `afterHash` but no `beforeHash`. A new
/// file is recorded with an empty-string `beforeHash` sentinel, the same
/// convention `save_and_apply_patch`'s by-uuid path relies on: apply
/// treats an empty `beforeHash` as "create this file" and
/// [`select_installed_variants`](crate::patch::apply::select_installed_variants) treats it as non-discriminating.
///
/// This is the shared record-building rule for the scan/download/vendor
/// flows AND the single-uuid apply path, so `get <uuid>` and
/// `scan`/`apply`/`vendor` all record and write the same set of files.
/// A both-hashes rule here would drop every added file (e.g. a whole-crate
/// cargo export where ALL files lack a `beforeHash`, recorded as `files:{}`
/// while reporting `applied:1`).
pub fn files_for_manifest(patch: &PatchResponse) -> HashMap<String, PatchFileInfo> {
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
pub fn record_from_patch_response(patch: &PatchResponse) -> (String, PatchRecord) {
    (
        patch.purl.clone(),
        build_patch_record(patch, files_for_manifest(patch)),
    )
}
