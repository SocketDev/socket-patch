use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Information about a vulnerability fixed by a patch.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VulnerabilityInfo {
    pub cves: Vec<String>,
    pub summary: String,
    pub severity: String,
    pub description: String,
}

/// Hash information for a single patched file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PatchFileInfo {
    pub before_hash: String,
    pub after_hash: String,
}

/// A single patch record in the manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PatchRecord {
    pub uuid: String,
    pub exported_at: String,
    /// Maps relative file path -> hash info.
    pub files: HashMap<String, PatchFileInfo>,
    /// Maps vulnerability ID (e.g., "GHSA-...") -> vulnerability info.
    pub vulnerabilities: HashMap<String, VulnerabilityInfo>,
    pub description: String,
    pub license: String,
    pub tier: String,
}

/// The top-level patch manifest structure.
/// Stored as `.socket/manifest.json`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PatchManifest {
    /// Maps package PURL (e.g., "pkg:npm/lodash@4.17.21") -> patch record.
    pub patches: HashMap<String, PatchRecord>,
}

impl PatchManifest {
    /// Create an empty manifest.
    pub fn new() -> Self {
        Self {
            patches: HashMap::new(),
        }
    }
}

impl Default for PatchManifest {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_manifest_roundtrip() {
        let manifest = PatchManifest::new();
        let json = serde_json::to_string_pretty(&manifest).unwrap();
        let parsed: PatchManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.patches.len(), 0);
    }

    #[test]
    fn test_manifest_with_patch_roundtrip() {
        let json = r#"{
  "patches": {
    "pkg:npm/simplehttpserver@0.0.6": {
      "uuid": "12345678-1234-1234-1234-123456789abc",
      "exportedAt": "2024-01-15T10:00:00Z",
      "files": {
        "package/lib/server.js": {
          "beforeHash": "aaaa000000000000000000000000000000000000000000000000000000000000",
          "afterHash": "bbbb000000000000000000000000000000000000000000000000000000000000"
        }
      },
      "vulnerabilities": {
        "GHSA-jrhj-2j3q-xf3v": {
          "cves": ["CVE-2024-1234"],
          "summary": "Path traversal vulnerability",
          "severity": "high",
          "description": "A path traversal vulnerability exists in simplehttpserver"
        }
      },
      "description": "Fix path traversal vulnerability",
      "license": "MIT",
      "tier": "free"
    }
  }
}"#;

        let manifest: PatchManifest = serde_json::from_str(json).unwrap();
        assert_eq!(manifest.patches.len(), 1);

        let patch = manifest.patches.get("pkg:npm/simplehttpserver@0.0.6").unwrap();
        assert_eq!(patch.uuid, "12345678-1234-1234-1234-123456789abc");
        assert_eq!(patch.files.len(), 1);
        assert_eq!(patch.vulnerabilities.len(), 1);
        assert_eq!(patch.tier, "free");

        let file_info = patch.files.get("package/lib/server.js").unwrap();
        assert_eq!(
            file_info.before_hash,
            "aaaa000000000000000000000000000000000000000000000000000000000000"
        );

        let vuln = patch.vulnerabilities.get("GHSA-jrhj-2j3q-xf3v").unwrap();
        assert_eq!(vuln.cves, vec!["CVE-2024-1234"]);
        assert_eq!(vuln.severity, "high");

        // Verify round-trip
        let serialized = serde_json::to_string_pretty(&manifest).unwrap();
        let reparsed: PatchManifest = serde_json::from_str(&serialized).unwrap();
        assert_eq!(manifest, reparsed);
    }

    #[test]
    fn test_camel_case_serialization() {
        let file_info = PatchFileInfo {
            before_hash: "aaa".to_string(),
            after_hash: "bbb".to_string(),
        };
        let json = serde_json::to_string(&file_info).unwrap();
        assert!(json.contains("beforeHash"));
        assert!(json.contains("afterHash"));
        assert!(!json.contains("before_hash"));
        assert!(!json.contains("after_hash"));
    }

    #[test]
    fn test_patch_record_camel_case() {
        let record = PatchRecord {
            uuid: "test-uuid".to_string(),
            exported_at: "2024-01-01T00:00:00Z".to_string(),
            files: HashMap::new(),
            vulnerabilities: HashMap::new(),
            description: "test".to_string(),
            license: "MIT".to_string(),
            tier: "free".to_string(),
        };
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("exportedAt"));
        assert!(!json.contains("exported_at"));
    }
}
