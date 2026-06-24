use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Organization info returned by the `/v0/organizations` endpoint.
#[derive(Debug, Clone, Deserialize)]
pub struct OrganizationInfo {
    pub id: String,
    pub name: Option<String>,
    pub image: Option<String>,
    pub plan: String,
    pub slug: String,
}

/// Response from `GET /v0/organizations`.
#[derive(Debug, Clone, Deserialize)]
pub struct OrganizationsResponse {
    pub organizations: HashMap<String, OrganizationInfo>,
}

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

/// Request body for the package-vendor endpoint: `POST
/// /v0/orgs/{slug}/patches/package` (authenticated) and `POST /patch/package`
/// (public proxy). Resolves published-patch UUIDs into prebuilt vendored-archive
/// download URLs + integrity. The public proxy forces `free_only`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageVendorRequest {
    pub uuids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub free_only: Option<bool>,
}

/// Response from the package-vendor endpoint: one result per requested UUID,
/// keyed by the UUID string.
#[derive(Debug, Clone, Deserialize)]
pub struct PackageVendorResponse {
    pub results: HashMap<String, PackageVendorResult>,
}

/// One package-vendor result. `status` is the discriminator; `url` / `purl` /
/// `artifacts` are populated only for `granted` / `reused`.
///
/// `status` values: `granted` | `reused` | `pending_build` | `build_failed`
/// | `withdrawn` | `forbidden` | `not_found`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageVendorResult {
    pub status: String,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub purl: Option<String>,
    #[serde(default)]
    pub artifacts: Option<Vec<PackageVendorArtifact>>,
}

/// One served artifact: the native tarball (`kind: "tarball"`), or a
/// second artifact — npm's yarn-berry cache zip (`kind: "yarn-berry-zip"`) or
/// gem's path-source stub gemspec (`kind: "gem-stub-gemspec"`). `url` is null
/// only when the artifact isn't stored yet (e.g. an unbuilt berry zip).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageVendorArtifact {
    pub kind: String,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub content_type: Option<String>,
    #[serde(default)]
    pub size_bytes: Option<u64>,
    #[serde(default)]
    pub integrity: PackageVendorIntegrity,
}

/// Per-artifact integrity hashes. Every ecosystem's tarball populates `sha512`
/// (npm SRI form `sha512-<b64>`) + `sha1` + `md5`; golang additionally
/// `dirhash_h1` (`h1:<b64>`); the npm yarn-berry zip carries only
/// `yarn_berry10c0` (`10c0/<sha512-hex>`). No ecosystem exposes a plain sha256.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageVendorIntegrity {
    #[serde(default)]
    pub sha512: Option<String>,
    #[serde(default)]
    pub sha1: Option<String>,
    #[serde(default)]
    pub md5: Option<String>,
    #[serde(default)]
    pub dirhash_h1: Option<String>,
    #[serde(default)]
    pub yarn_berry10c0: Option<String>,
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

    // ── Regression: deserialize from realistic, server-shaped payloads ──
    //
    // The structs above are pure serde DTOs, so the only thing that can
    // break is the JSON field-name contract with the Socket API. The tests
    // below pin that contract by deserializing payloads in the *exact*
    // camelCase shape the live endpoints emit (mirroring the integration
    // fixtures under crates/socket-patch-cli/tests). A dropped or mistyped
    // `rename_all` / field rename would fail these.

    #[test]
    fn test_patch_response_full_view_payload_deserialize() {
        // Mirrors GET /v0/orgs/<slug>/patches/view/<uuid>: populated files
        // (every PatchFileResponse field present) and a populated
        // vulnerabilities map keyed by GHSA id.
        let json = r#"{
            "uuid": "11111111-1111-4111-8111-111111111111",
            "purl": "pkg:npm/x@1.0.0",
            "publishedAt": "2024-01-01T00:00:00Z",
            "files": {
                "package/index.js": {
                    "beforeHash": "aaaa000000000000000000000000000000000000000000000000000000000000",
                    "afterHash": "bbbb000000000000000000000000000000000000000000000000000000000000",
                    "socketBlob": "blob-ref",
                    "blobContent": "YWZ0ZXIK",
                    "beforeBlobContent": "YmVmb3JlCg=="
                }
            },
            "vulnerabilities": {
                "GHSA-jrhj-2j3q-xf3v": {
                    "cves": ["CVE-2024-1234"],
                    "summary": "Path traversal",
                    "severity": "high",
                    "description": "A path traversal vulnerability"
                }
            },
            "description": "Fix path traversal",
            "license": "MIT",
            "tier": "free"
        }"#;
        let pr: PatchResponse = serde_json::from_str(json).unwrap();
        assert_eq!(pr.published_at, "2024-01-01T00:00:00Z");

        let file = pr.files.get("package/index.js").expect("file present");
        assert_eq!(
            file.before_hash.as_deref(),
            Some("aaaa000000000000000000000000000000000000000000000000000000000000")
        );
        assert_eq!(
            file.after_hash.as_deref(),
            Some("bbbb000000000000000000000000000000000000000000000000000000000000")
        );
        assert_eq!(file.socket_blob.as_deref(), Some("blob-ref"));
        assert_eq!(file.blob_content.as_deref(), Some("YWZ0ZXIK"));
        assert_eq!(file.before_blob_content.as_deref(), Some("YmVmb3JlCg=="));

        let vuln = pr
            .vulnerabilities
            .get("GHSA-jrhj-2j3q-xf3v")
            .expect("vuln present");
        assert_eq!(vuln.cves, vec!["CVE-2024-1234"]);
        assert_eq!(vuln.severity, "high");
        assert_eq!(vuln.summary, "Path traversal");
    }

    #[test]
    fn test_patch_file_response_absent_optional_keys_are_none() {
        // serde treats absent Option fields as None. The existing optional-
        // fields test only round-trips explicit `null`s; this pins the
        // (distinct) absent-key path the server actually uses when a blob
        // isn't inlined.
        let pfr: PatchFileResponse = serde_json::from_str("{}").unwrap();
        assert!(pfr.before_hash.is_none());
        assert!(pfr.after_hash.is_none());
        assert!(pfr.socket_blob.is_none());
        assert!(pfr.blob_content.is_none());
        assert!(pfr.before_blob_content.is_none());
    }

    #[test]
    fn test_batch_search_response_api_payload_deserialize() {
        // Mirrors POST /v0/orgs/<slug>/patches/batch. One patch carries a
        // severity, the other omits it (Option<String> -> None).
        let json = r#"{
            "packages": [{
                "purl": "pkg:npm/x@1.0.0",
                "patches": [
                    {
                        "uuid": "u1",
                        "purl": "pkg:npm/x@1.0.0",
                        "tier": "free",
                        "cveIds": ["CVE-2024-0001"],
                        "ghsaIds": ["GHSA-1111-2222-3333"],
                        "severity": "high",
                        "title": "Patch one"
                    },
                    {
                        "uuid": "u2",
                        "purl": "pkg:npm/x@1.0.0",
                        "tier": "paid",
                        "cveIds": [],
                        "ghsaIds": [],
                        "title": "Patch two"
                    }
                ]
            }],
            "canAccessPaidPatches": true
        }"#;
        let bsr: BatchSearchResponse = serde_json::from_str(json).unwrap();
        assert!(bsr.can_access_paid_patches);
        assert_eq!(bsr.packages.len(), 1);
        let patches = &bsr.packages[0].patches;
        assert_eq!(patches.len(), 2);
        assert_eq!(patches[0].cve_ids, vec!["CVE-2024-0001"]);
        assert_eq!(patches[0].ghsa_ids, vec!["GHSA-1111-2222-3333"]);
        assert_eq!(patches[0].severity.as_deref(), Some("high"));
        assert!(patches[1].severity.is_none());
        assert!(patches[1].cve_ids.is_empty());
    }

    #[test]
    fn test_organizations_response_deserialize() {
        // Mirrors GET /v0/organizations: an object keyed by org id. `name`
        // and `image` are optional (one org omits both).
        let json = r#"{
            "organizations": {
                "org-abc": {
                    "id": "org-abc",
                    "name": "Acme",
                    "image": "https://example.com/a.png",
                    "plan": "team",
                    "slug": "acme"
                },
                "org-def": {
                    "id": "org-def",
                    "plan": "free",
                    "slug": "beta"
                }
            }
        }"#;
        let resp: OrganizationsResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.organizations.len(), 2);
        let acme = resp.organizations.get("org-abc").unwrap();
        assert_eq!(acme.slug, "acme");
        assert_eq!(acme.name.as_deref(), Some("Acme"));
        let beta = resp.organizations.get("org-def").unwrap();
        assert_eq!(beta.slug, "beta");
        assert!(beta.name.is_none());
        assert!(beta.image.is_none());
    }

    #[test]
    fn test_patch_response_rejects_snake_case_published_at() {
        // Pins that the camelCase rename is *strict* on the wire: a payload
        // using the Rust field name (`published_at`) instead of the API's
        // `publishedAt` must fail with a missing-field error. Guards against
        // anyone "relaxing" the contract with serde aliases — which would let
        // a server/field-name drift go unnoticed.
        let json = r#"{
            "uuid": "u1",
            "purl": "pkg:npm/x@1",
            "published_at": "2024-01-01",
            "files": {},
            "vulnerabilities": {},
            "description": "A patch",
            "license": "MIT",
            "tier": "free"
        }"#;
        let err = serde_json::from_str::<PatchResponse>(json).unwrap_err();
        assert!(
            err.to_string().contains("publishedAt"),
            "expected a missing-`publishedAt` error, got: {err}"
        );
    }

    #[test]
    fn test_batch_package_patches_field_names() {
        // BatchPackagePatches deliberately has no rename_all (both fields are
        // single lowercase words). Pin the on-the-wire key names in both
        // directions so an accidental rename can't silently break the
        // batch-endpoint contract.
        let bpp = BatchPackagePatches {
            purl: "pkg:npm/x@1.0.0".into(),
            patches: Vec::new(),
        };
        let json = serde_json::to_string(&bpp).unwrap();
        assert!(json.contains("\"purl\""));
        assert!(json.contains("\"patches\""));

        let back: BatchPackagePatches =
            serde_json::from_str(r#"{"purl":"pkg:npm/y@2","patches":[]}"#).unwrap();
        assert_eq!(back.purl, "pkg:npm/y@2");
        assert!(back.patches.is_empty());
    }

    #[test]
    fn test_vulnerability_response_deserialize_standalone() {
        // VulnerabilityResponse has no rename_all; confirm it deserializes
        // from the snake/lowercase keys the API emits (the existing test only
        // exercised the serialize direction in isolation).
        let json = r#"{
            "cves": ["CVE-2024-0001", "CVE-2024-0002"],
            "summary": "Prototype pollution",
            "severity": "critical",
            "description": "A prototype pollution vulnerability"
        }"#;
        let vr: VulnerabilityResponse = serde_json::from_str(json).unwrap();
        assert_eq!(vr.cves, vec!["CVE-2024-0001", "CVE-2024-0002"]);
        assert_eq!(vr.summary, "Prototype pollution");
        assert_eq!(vr.severity, "critical");
        assert_eq!(vr.description, "A prototype pollution vulnerability");
    }

    #[test]
    fn test_search_response_populated_roundtrip() {
        // The existing camelCase test round-trips an *empty* patches vec; this
        // pins a populated PatchSearchResult survives a full serialize ->
        // deserialize cycle inside its SearchResponse envelope.
        let sr = SearchResponse {
            patches: vec![PatchSearchResult {
                uuid: "u1".into(),
                purl: "pkg:npm/test@1.0.0".into(),
                published_at: "2024-06-15T00:00:00Z".into(),
                description: "A test patch".into(),
                license: "MIT".into(),
                tier: "free".into(),
                vulnerabilities: HashMap::new(),
            }],
            can_access_paid_patches: true,
        };
        let json = serde_json::to_string(&sr).unwrap();
        let back: SearchResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(back.patches.len(), 1);
        assert_eq!(back.patches[0].uuid, "u1");
        assert_eq!(back.patches[0].published_at, "2024-06-15T00:00:00Z");
        assert!(back.can_access_paid_patches);
    }

    #[test]
    fn test_search_response_api_payload_deserialize() {
        // Mirrors GET /v0/orgs/<slug>/patches/by-package/<purl>.
        let json = r#"{
            "patches": [{
                "uuid": "u1",
                "purl": "pkg:npm/x@1.0.0",
                "publishedAt": "2024-01-01T00:00:00Z",
                "description": "A patch",
                "license": "MIT",
                "tier": "free",
                "vulnerabilities": {}
            }],
            "canAccessPaidPatches": false
        }"#;
        let sr: SearchResponse = serde_json::from_str(json).unwrap();
        assert_eq!(sr.patches.len(), 1);
        assert!(!sr.can_access_paid_patches);
        assert_eq!(sr.patches[0].published_at, "2024-01-01T00:00:00Z");
    }
}
