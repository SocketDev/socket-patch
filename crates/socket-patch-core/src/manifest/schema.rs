use crate::utils::serde::serialize_sorted;
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
    #[serde(serialize_with = "serialize_sorted")]
    pub files: HashMap<String, PatchFileInfo>,
    /// Maps vulnerability ID (e.g., "GHSA-...") -> vulnerability info.
    #[serde(serialize_with = "serialize_sorted")]
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
    /// Ecosystems (by `Ecosystem::cli_name`, e.g. `"pypi"`) the user runs
    /// `socket-patch apply` for by hand, so their patches are still attested in
    /// VEX even though no auto-install hook is wired (CLI_CONTRACT property 7).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub manual: Vec<String>,
}

impl SetupConfig {
    /// Whether this carries no setup state (so the manifest can omit the key).
    fn is_empty(&self) -> bool {
        self.exclude.is_empty() && self.manual.is_empty()
    }
}

/// Whether the optional `setup` block should be omitted from the serialized
/// manifest. It's omitted both when absent (`None`) *and* when present but
/// carrying no state (`Some` of an empty [`SetupConfig`]) — the two are
/// logically identical ("no setup state"), so collapsing them keeps the
/// on-disk `.socket/manifest.json` byte-stable regardless of which in-memory
/// representation produced it.
fn setup_is_absent(setup: &Option<SetupConfig>) -> bool {
    setup.as_ref().is_none_or(SetupConfig::is_empty)
}

/// The top-level patch manifest structure.
/// Stored as `.socket/manifest.json`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct PatchManifest {
    /// Maps package PURL (e.g., "pkg:npm/lodash@4.17.21") -> patch record.
    #[serde(serialize_with = "serialize_sorted")]
    pub patches: HashMap<String, PatchRecord>,
    /// Optional persisted `setup` state (e.g. excluded workspace members).
    /// Absent on manifests that predate / don't use it (serde default), and
    /// omitted from the serialized form when empty so existing manifests are
    /// byte-stable.
    #[serde(default, skip_serializing_if = "setup_is_absent")]
    pub setup: Option<SetupConfig>,
}

impl PatchManifest {
    /// Create an empty manifest.
    pub fn new() -> Self {
        Self::default()
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

    // ── Regression: deterministic, sorted serialization ──
    //
    // The manifest is persisted as `.socket/manifest.json` and committed to git.
    // The maps are `HashMap`s, whose iteration order is randomized per instance,
    // so a naive derive would emit keys in arbitrary order and churn the file on
    // every write. `serialize_sorted` pins the keys to sorted order. These tests
    // guard that contract (and would fail if the `serialize_with` attribute were
    // dropped, surfacing the non-deterministic order).

    // Top-level `patches` keys (PURLs) must be emitted in sorted order, no matter
    // what order they were inserted in.
    #[test]
    fn test_manifest_patches_serialize_in_sorted_order() {
        let mk = |uuid: &str| PatchRecord {
            uuid: uuid.to_string(),
            exported_at: "2024-01-01T00:00:00Z".to_string(),
            files: HashMap::new(),
            vulnerabilities: HashMap::new(),
            description: "d".to_string(),
            license: "MIT".to_string(),
            tier: "free".to_string(),
        };

        // Insert in deliberately reverse-sorted order.
        let mut patches = HashMap::new();
        patches.insert("pkg:npm/zzz@1.0.0".to_string(), mk("u-z"));
        patches.insert("pkg:npm/mmm@1.0.0".to_string(), mk("u-m"));
        patches.insert("pkg:npm/aaa@1.0.0".to_string(), mk("u-a"));
        let manifest = PatchManifest {
            patches,
            setup: None,
        };

        let json = serde_json::to_string(&manifest).unwrap();
        let a = json.find("pkg:npm/aaa@1.0.0").unwrap();
        let m = json.find("pkg:npm/mmm@1.0.0").unwrap();
        let z = json.find("pkg:npm/zzz@1.0.0").unwrap();
        assert!(
            a < m && m < z,
            "patches must serialize in sorted key order, got: {json}"
        );
    }

    // Serialization must be byte-stable: two distinct HashMaps (which may have
    // different internal iteration orders) holding the same logical content must
    // produce identical JSON. Re-inserting in a different order proves the output
    // doesn't depend on HashMap iteration order.
    #[test]
    fn test_manifest_serialization_is_byte_stable() {
        let mk = |uuid: &str| {
            let mut files = HashMap::new();
            files.insert(
                "package/z.js".to_string(),
                PatchFileInfo {
                    before_hash: "b1".to_string(),
                    after_hash: "a1".to_string(),
                },
            );
            files.insert(
                "package/a.js".to_string(),
                PatchFileInfo {
                    before_hash: "b2".to_string(),
                    after_hash: "a2".to_string(),
                },
            );
            let mut vulns = HashMap::new();
            vulns.insert(
                "GHSA-zzzz".to_string(),
                VulnerabilityInfo {
                    cves: vec![],
                    summary: "s".to_string(),
                    severity: "low".to_string(),
                    description: "d".to_string(),
                },
            );
            vulns.insert(
                "GHSA-aaaa".to_string(),
                VulnerabilityInfo {
                    cves: vec![],
                    summary: "s".to_string(),
                    severity: "low".to_string(),
                    description: "d".to_string(),
                },
            );
            PatchRecord {
                uuid: uuid.to_string(),
                exported_at: "2024-01-01T00:00:00Z".to_string(),
                files,
                vulnerabilities: vulns,
                description: "d".to_string(),
                license: "MIT".to_string(),
                tier: "free".to_string(),
            }
        };

        // Two manifests with the same content but opposite patch-insertion order.
        let mut p1 = HashMap::new();
        p1.insert("pkg:npm/aaa@1.0.0".to_string(), mk("u-a"));
        p1.insert("pkg:npm/zzz@1.0.0".to_string(), mk("u-z"));
        let m1 = PatchManifest {
            patches: p1,
            setup: None,
        };

        let mut p2 = HashMap::new();
        p2.insert("pkg:npm/zzz@1.0.0".to_string(), mk("u-z"));
        p2.insert("pkg:npm/aaa@1.0.0".to_string(), mk("u-a"));
        let m2 = PatchManifest {
            patches: p2,
            setup: None,
        };

        assert_eq!(
            serde_json::to_string_pretty(&m1).unwrap(),
            serde_json::to_string_pretty(&m2).unwrap(),
            "manifest JSON must be byte-stable regardless of HashMap order"
        );

        // And the nested `files` / `vulnerabilities` keys must themselves be sorted.
        let json = serde_json::to_string(&m1).unwrap();
        assert!(json.find("package/a.js").unwrap() < json.find("package/z.js").unwrap());
        assert!(json.find("GHSA-aaaa").unwrap() < json.find("GHSA-zzzz").unwrap());
    }

    // ── Regression: the optional `setup` block is omitted when it carries no
    // state ──
    //
    // The field doc promises `setup` is "omitted from the serialized form when
    // empty so existing manifests are byte-stable." Before the fix, the skip
    // predicate was `Option::is_none`, so a `Some` of an empty `SetupConfig`
    // (which a load of `"setup": {}` produces, and which the also-then-dead
    // `SetupConfig::is_empty` was written to detect) leaked a spurious
    // `"setup":{}` key, breaking that contract.

    // A `Some` of an empty config must serialize byte-identically to `None`:
    // no `setup` key at all.
    #[test]
    fn test_empty_setup_some_serializes_identically_to_none() {
        let with_none = PatchManifest {
            patches: HashMap::new(),
            setup: None,
        };
        let with_empty_some = PatchManifest {
            patches: HashMap::new(),
            setup: Some(SetupConfig::default()),
        };

        let none_json = serde_json::to_string_pretty(&with_none).unwrap();
        let empty_some_json = serde_json::to_string_pretty(&with_empty_some).unwrap();

        assert!(
            !none_json.contains("setup"),
            "a None setup must not emit a `setup` key, got: {none_json}"
        );
        assert!(
            !empty_some_json.contains("setup"),
            "a Some(empty) setup must also be omitted (byte-stability), got: {empty_some_json}"
        );
        assert_eq!(
            none_json, empty_some_json,
            "None and Some(empty) setup must serialize byte-identically"
        );
    }

    // A manifest deserialized from a literal `"setup": {}` must re-serialize
    // without the empty block (the normalization the byte-stability contract
    // depends on).
    #[test]
    fn test_loaded_empty_setup_object_is_dropped_on_reserialize() {
        let json = r#"{ "patches": {}, "setup": {} }"#;
        let manifest: PatchManifest = serde_json::from_str(json).unwrap();
        // The empty object parses into a (logically empty) config...
        assert!(manifest.setup.as_ref().is_none_or(SetupConfig::is_empty));
        // ...but must not survive into the serialized form.
        let reserialized = serde_json::to_string(&manifest).unwrap();
        assert!(
            !reserialized.contains("setup"),
            "an empty `setup` block must be dropped on re-serialize, got: {reserialized}"
        );
    }

    // A *non-empty* setup block must still round-trip in full — the fix must
    // omit only the empty case, never drop real state.
    #[test]
    fn test_populated_setup_roundtrips() {
        let manifest = PatchManifest {
            patches: HashMap::new(),
            setup: Some(SetupConfig {
                exclude: vec!["crates/member-a".to_string()],
                manual: vec!["pypi".to_string()],
            }),
        };
        let json = serde_json::to_string(&manifest).unwrap();
        assert!(
            json.contains("\"setup\""),
            "populated setup must be emitted"
        );
        assert!(json.contains("crates/member-a"));
        assert!(json.contains("pypi"));

        let reparsed: PatchManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(
            manifest, reparsed,
            "populated setup must round-trip exactly"
        );
        let setup = reparsed.setup.unwrap();
        assert_eq!(setup.exclude, vec!["crates/member-a".to_string()]);
        assert_eq!(setup.manual, vec!["pypi".to_string()]);
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
