use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Full patch response with blob content (from view endpoint).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PatchResponse {
    pub uuid: String,
    pub purl: String,
    pub published_at: String,
    pub files: HashMap<String, PatchFileResponse>,
    pub vulnerabilities: HashMap<String, VulnerabilityResponse>,
    pub description: String,
    pub license: String,
    pub tier: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PatchFileResponse {
    pub before_hash: Option<String>,
    pub after_hash: Option<String>,
    pub socket_blob: Option<String>,
    pub blob_content: Option<String>,
    pub before_blob_content: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityResponse {
    pub cves: Vec<String>,
    pub summary: String,
    pub severity: String,
    pub description: String,
}

/// Lightweight search result.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PatchSearchResult {
    pub uuid: String,
    pub purl: String,
    pub published_at: String,
    pub description: String,
    pub license: String,
    pub tier: String,
    pub vulnerabilities: HashMap<String, VulnerabilityResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchResponse {
    pub patches: Vec<PatchSearchResult>,
    pub can_access_paid_patches: bool,
}

/// Minimal patch info from batch search.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchPatchInfo {
    pub uuid: String,
    pub purl: String,
    pub tier: String,
    pub cve_ids: Vec<String>,
    pub ghsa_ids: Vec<String>,
    pub severity: Option<String>,
    pub title: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchPackagePatches {
    pub purl: String,
    pub patches: Vec<BatchPatchInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchSearchResponse {
    pub packages: Vec<BatchPackagePatches>,
    pub can_access_paid_patches: bool,
}
