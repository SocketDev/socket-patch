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

/// Persisted `setup` configuration (CLI_CONTRACT property 9). Lives under the
/// manifest's `setup` key so a fresh clone's `setup` / `setup --check` honors it
/// without re-passing flags.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct SetupConfig {
    /// Workspace-member paths (relative to the repo root, forward-slashed) that
    /// `setup` must NOT configure — and `setup --check` must not flag as
    /// needing configuration.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude: Vec<String>,
}

impl SetupConfig {
    /// Whether this carries no setup state (so the manifest can omit the key).
    pub fn is_empty(&self) -> bool {
        self.exclude.is_empty()
    }
}

/// The top-level patch manifest structure.
/// Stored as `.socket/manifest.json`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PatchManifest {
    /// Maps package PURL (e.g., "pkg:npm/lodash@4.17.21") -> patch record.
    pub patches: HashMap<String, PatchRecord>,
    /// Optional persisted `setup` state (e.g. excluded workspace members).
    /// Absent on manifests that predate / don't use it (serde default), and
    /// omitted from the serialized form when empty so existing manifests are
    /// byte-stable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setup: Option<SetupConfig>,
}

impl PatchManifest {
    /// Create an empty manifest.
    pub fn new() -> Self {
        Self {
            patches: HashMap::new(),
            setup: None,
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

        let patch = manifest
            .patches
            .get("pkg:npm/simplehttpserver@0.0.6")
            .unwrap();
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

    // ── Regression: pin the on-the-wire JSON contract with the TS schema ──
    //
    // schema.rs is a pure serde DTO whose only job is to match the
    // camelCase shape that the legacy TS tool (manifest-schema.ts) reads and
    // writes. The tests below lock that contract so a dropped or mistyped
    // `rename_all`, a renamed field, or a removed field fails loudly rather
    // than silently producing a manifest the TS tooling can't read.

    // The camelCase rename must be ENFORCED on input, not merely emitted on
    // output. A manifest carrying snake_case keys (as a naive serializer
    // without `rename_all` would produce) must be rejected, otherwise the two
    // implementations could silently drift apart.
    #[test]
    fn test_patch_file_info_rejects_snake_case_keys() {
        let snake = r#"{"before_hash": "a", "after_hash": "b"}"#;
        assert!(
            serde_json::from_str::<PatchFileInfo>(snake).is_err(),
            "snake_case keys must not deserialize -- the wire contract is camelCase"
        );

        let camel = r#"{"beforeHash": "a", "afterHash": "b"}"#;
        let parsed: PatchFileInfo = serde_json::from_str(camel).unwrap();
        assert_eq!(parsed.before_hash, "a");
        assert_eq!(parsed.after_hash, "b");
    }

    // Likewise for `exportedAt` on a record: snake_case must be rejected.
    #[test]
    fn test_patch_record_rejects_snake_case_exported_at() {
        let json = r#"{
            "uuid": "11111111-1111-4111-8111-111111111111",
            "exported_at": "2024-01-01T00:00:00Z",
            "files": {},
            "vulnerabilities": {},
            "description": "d",
            "license": "MIT",
            "tier": "free"
        }"#;
        assert!(
            serde_json::from_str::<PatchRecord>(json).is_err(),
            "exported_at must be rejected; the contract field is exportedAt"
        );
    }

    // VulnerabilityInfo intentionally has NO `rename_all` (all fields are
    // single lowercase words). Pin its exact keys so nobody "helpfully" adds a
    // rename that would break the contract, and exercise an empty `cves` array
    // (the medium-severity shape from the TS test suite).
    #[test]
    fn test_vulnerability_info_exact_keys_and_empty_cves() {
        let json = r#"{
            "cves": [],
            "summary": "Some vuln",
            "severity": "medium",
            "description": "A medium severity vulnerability"
        }"#;
        let vuln: VulnerabilityInfo = serde_json::from_str(json).unwrap();
        assert!(vuln.cves.is_empty());
        assert_eq!(vuln.severity, "medium");

        let serialized = serde_json::to_string(&vuln).unwrap();
        for key in ["\"cves\"", "\"summary\"", "\"severity\"", "\"description\""] {
            assert!(serialized.contains(key), "missing key {key}");
        }
    }

    // Every PatchRecord field is required (mirroring the TS zod schema, which
    // rejects records missing any field). Dropping any one must fail.
    #[test]
    fn test_patch_record_requires_all_fields() {
        // A complete record, used as the baseline.
        let complete = serde_json::json!({
            "uuid": "11111111-1111-4111-8111-111111111111",
            "exportedAt": "2024-01-01T00:00:00Z",
            "files": {},
            "vulnerabilities": {},
            "description": "d",
            "license": "MIT",
            "tier": "free"
        });
        assert!(serde_json::from_value::<PatchRecord>(complete.clone()).is_ok());

        for field in [
            "uuid",
            "exportedAt",
            "files",
            "vulnerabilities",
            "description",
            "license",
            "tier",
        ] {
            let mut partial = complete.clone();
            partial.as_object_mut().unwrap().remove(field);
            assert!(
                serde_json::from_value::<PatchRecord>(partial).is_err(),
                "a record missing `{field}` must be rejected"
            );
        }
    }

    // A multi-patch manifest mirroring the TS test suite (a free/MIT patch and
    // a paid/Apache-2.0 patch) must survive a full deserialize -> serialize ->
    // deserialize round-trip with deep equality, guarding against a serializer
    // that drops nested records, files, or vulnerabilities.
    #[test]
    fn test_multi_patch_manifest_deep_roundtrip() {
        let json = r#"{
  "patches": {
    "pkg:npm/pkg-a@1.0.0": {
      "uuid": "550e8400-e29b-41d4-a716-446655440001",
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {
        "package/lib/index.js": { "beforeHash": "aaa", "afterHash": "bbb" }
      },
      "vulnerabilities": {},
      "description": "Patch A",
      "license": "MIT",
      "tier": "free"
    },
    "pkg:npm/pkg-b@2.0.0": {
      "uuid": "550e8400-e29b-41d4-a716-446655440002",
      "exportedAt": "2024-02-01T00:00:00Z",
      "files": {
        "package/src/main.js": { "beforeHash": "ccc", "afterHash": "ddd" }
      },
      "vulnerabilities": {
        "GHSA-xxxx-yyyy-zzzz": {
          "cves": [],
          "summary": "Some vuln",
          "severity": "medium",
          "description": "A medium severity vulnerability"
        }
      },
      "description": "Patch B",
      "license": "Apache-2.0",
      "tier": "paid"
    }
  }
}"#;

        let manifest: PatchManifest = serde_json::from_str(json).unwrap();
        assert_eq!(manifest.patches.len(), 2);

        let serialized = serde_json::to_string_pretty(&manifest).unwrap();
        let reparsed: PatchManifest = serde_json::from_str(&serialized).unwrap();
        assert_eq!(manifest, reparsed);

        let b = reparsed.patches.get("pkg:npm/pkg-b@2.0.0").unwrap();
        assert_eq!(b.license, "Apache-2.0");
        assert_eq!(b.tier, "paid");
        assert_eq!(b.vulnerabilities.len(), 1);
        assert!(b
            .vulnerabilities
            .get("GHSA-xxxx-yyyy-zzzz")
            .unwrap()
            .cves
            .is_empty());
    }

    // A manifest missing the top-level `patches` key must be rejected (the TS
    // schema requires it; `{}` is not a valid manifest).
    #[test]
    fn test_manifest_requires_patches_field() {
        assert!(
            serde_json::from_str::<PatchManifest>("{}").is_err(),
            "a manifest without a `patches` field must be rejected"
        );
    }
}
