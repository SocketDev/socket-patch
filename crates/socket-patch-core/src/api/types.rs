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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_patch_response_camel_case() {
        let pr = PatchResponse {
            uuid: "u1".into(),
            purl: "pkg:npm/x@1".into(),
            published_at: "2024-01-01".into(),
            files: HashMap::new(),
            vulnerabilities: HashMap::new(),
            description: "desc".into(),
            license: "MIT".into(),
            tier: "free".into(),
        };
        let json = serde_json::to_string(&pr).unwrap();
        assert!(json.contains("publishedAt"));
        assert!(!json.contains("published_at"));
    }

    #[test]
    fn test_patch_response_deserialize() {
        let json = r#"{
            "uuid": "u1",
            "purl": "pkg:npm/x@1",
            "publishedAt": "2024-01-01",
            "files": {},
            "vulnerabilities": {},
            "description": "A patch",
            "license": "MIT",
            "tier": "free"
        }"#;
        let pr: PatchResponse = serde_json::from_str(json).unwrap();
        assert_eq!(pr.uuid, "u1");
        assert_eq!(pr.published_at, "2024-01-01");
    }

    #[test]
    fn test_patch_file_response_optional_fields() {
        let pfr = PatchFileResponse {
            before_hash: None,
            after_hash: None,
            socket_blob: None,
            blob_content: None,
            before_blob_content: None,
        };
        let json = serde_json::to_string(&pfr).unwrap();
        let back: PatchFileResponse = serde_json::from_str(&json).unwrap();
        assert!(back.before_hash.is_none());
        assert!(back.after_hash.is_none());
        assert!(back.socket_blob.is_none());
        assert!(back.blob_content.is_none());
        assert!(back.before_blob_content.is_none());
        // Verify camelCase field names
        assert!(json.contains("beforeHash"));
        assert!(json.contains("afterHash"));
        assert!(json.contains("socketBlob"));
        assert!(json.contains("blobContent"));
        assert!(json.contains("beforeBlobContent"));
    }

    #[test]
    fn test_search_response_camel_case() {
        let sr = SearchResponse {
            patches: Vec::new(),
            can_access_paid_patches: true,
        };
        let json = serde_json::to_string(&sr).unwrap();
        assert!(json.contains("canAccessPaidPatches"));
        assert!(!json.contains("can_access_paid_patches"));
    }

    #[test]
    fn test_batch_search_response_roundtrip() {
        let bsr = BatchSearchResponse {
            packages: vec![BatchPackagePatches {
                purl: "pkg:npm/x@1".into(),
                patches: vec![BatchPatchInfo {
                    uuid: "u1".into(),
                    purl: "pkg:npm/x@1".into(),
                    tier: "free".into(),
                    cve_ids: vec!["CVE-2024-0001".into()],
                    ghsa_ids: vec!["GHSA-1111-2222-3333".into()],
                    severity: Some("high".into()),
                    title: "Test".into(),
                }],
            }],
            can_access_paid_patches: false,
        };
        let json = serde_json::to_string(&bsr).unwrap();
        let back: BatchSearchResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(back.packages.len(), 1);
        assert_eq!(back.packages[0].patches.len(), 1);
        assert!(!back.can_access_paid_patches);
    }

    #[test]
    fn test_batch_patch_info_camel_case() {
        let bpi = BatchPatchInfo {
            uuid: "u1".into(),
            purl: "pkg:npm/x@1".into(),
            tier: "free".into(),
            cve_ids: vec!["CVE-2024-0001".into()],
            ghsa_ids: vec!["GHSA-1111-2222-3333".into()],
            severity: Some("high".into()),
            title: "Test".into(),
        };
        let json = serde_json::to_string(&bpi).unwrap();
        assert!(json.contains("cveIds"));
        assert!(json.contains("ghsaIds"));
        assert!(!json.contains("cve_ids"));
        assert!(!json.contains("ghsa_ids"));
    }

    #[test]
    fn test_vulnerability_response_no_rename() {
        // VulnerabilityResponse does NOT have rename_all, so fields are snake_case
        let vr = VulnerabilityResponse {
            cves: vec!["CVE-2024-0001".into()],
            summary: "Test".into(),
            severity: "high".into(),
            description: "A vulnerability".into(),
        };
        let json = serde_json::to_string(&vr).unwrap();
        // Without rename_all, field names stay as-is (already lowercase single-word)
        assert!(json.contains("\"cves\""));
        assert!(json.contains("\"summary\""));
        assert!(json.contains("\"severity\""));
        assert!(json.contains("\"description\""));
    }

    #[test]
    fn test_patch_search_result_roundtrip() {
        let psr = PatchSearchResult {
            uuid: "u1".into(),
            purl: "pkg:npm/test@1.0.0".into(),
            published_at: "2024-06-15".into(),
            description: "A test patch".into(),
            license: "MIT".into(),
            tier: "free".into(),
            vulnerabilities: HashMap::new(),
        };
        let json = serde_json::to_string(&psr).unwrap();
        let back: PatchSearchResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.uuid, "u1");
        assert_eq!(back.published_at, "2024-06-15");
        assert!(json.contains("publishedAt"));
    }
}
