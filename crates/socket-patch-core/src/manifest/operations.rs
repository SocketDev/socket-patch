use std::collections::HashSet;
use std::path::Path;

use crate::manifest::schema::PatchManifest;

/// Get all blob hashes referenced by a manifest (both beforeHash and afterHash).
/// Used for garbage collection and validation.
pub fn get_referenced_blobs(manifest: &PatchManifest) -> HashSet<String> {
    let mut blobs = HashSet::new();

    for record in manifest.patches.values() {
        for file_info in record.files.values() {
            blobs.insert(file_info.before_hash.clone());
            blobs.insert(file_info.after_hash.clone());
        }
    }

    blobs
}

/// Get only afterHash blobs referenced by a manifest.
/// Used for apply operations -- we only need the patched file content, not the original.
/// This saves disk space since beforeHash blobs are not needed for applying patches.
pub fn get_after_hash_blobs(manifest: &PatchManifest) -> HashSet<String> {
    let mut blobs = HashSet::new();

    for record in manifest.patches.values() {
        for file_info in record.files.values() {
            blobs.insert(file_info.after_hash.clone());
        }
    }

    blobs
}

/// Get only beforeHash blobs referenced by a manifest.
/// Used for rollback operations -- we need the original file content to restore.
pub fn get_before_hash_blobs(manifest: &PatchManifest) -> HashSet<String> {
    let mut blobs = HashSet::new();

    for record in manifest.patches.values() {
        for file_info in record.files.values() {
            blobs.insert(file_info.before_hash.clone());
        }
    }

    blobs
}

/// Differences between two manifests.
#[derive(Debug, Clone)]
pub struct ManifestDiff {
    /// PURLs present in new but not old.
    pub added: HashSet<String>,
    /// PURLs present in old but not new.
    pub removed: HashSet<String>,
    /// PURLs present in both but with different UUIDs.
    pub modified: HashSet<String>,
}

/// Calculate differences between two manifests.
/// Patches are compared by UUID: if the PURL exists in both manifests but the
/// UUID changed, the patch is considered modified.
pub fn diff_manifests(old_manifest: &PatchManifest, new_manifest: &PatchManifest) -> ManifestDiff {
    let old_purls: HashSet<&String> = old_manifest.patches.keys().collect();
    let new_purls: HashSet<&String> = new_manifest.patches.keys().collect();

    let mut added = HashSet::new();
    let mut removed = HashSet::new();
    let mut modified = HashSet::new();

    // Find added and modified
    for purl in &new_purls {
        if !old_purls.contains(purl) {
            added.insert((*purl).clone());
        } else {
            let old_patch = &old_manifest.patches[*purl];
            let new_patch = &new_manifest.patches[*purl];
            if old_patch.uuid != new_patch.uuid {
                modified.insert((*purl).clone());
            }
        }
    }

    // Find removed
    for purl in &old_purls {
        if !new_purls.contains(purl) {
            removed.insert((*purl).clone());
        }
    }

    ManifestDiff {
        added,
        removed,
        modified,
    }
}

/// Validate a parsed JSON value as a PatchManifest.
/// Returns Ok(manifest) if valid, or Err(message) if invalid.
pub fn validate_manifest(value: &serde_json::Value) -> Result<PatchManifest, String> {
    serde_json::from_value::<PatchManifest>(value.clone())
        .map_err(|e| format!("Invalid manifest: {}", e))
}

/// Read and parse a manifest from the filesystem.
/// Returns Ok(None) if the file does not exist or cannot be parsed.
pub async fn read_manifest(path: impl AsRef<Path>) -> Result<Option<PatchManifest>, std::io::Error> {
    let path = path.as_ref();

    let content = match tokio::fs::read_to_string(path).await {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Ok(None),
    };

    let parsed: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return Ok(None),
    };

    match validate_manifest(&parsed) {
        Ok(manifest) => Ok(Some(manifest)),
        Err(_) => Ok(None),
    }
}

/// Write a manifest to the filesystem with pretty-printed JSON.
pub async fn write_manifest(
    path: impl AsRef<Path>,
    manifest: &PatchManifest,
) -> Result<(), std::io::Error> {
    let content = serde_json::to_string_pretty(manifest)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    tokio::fs::write(path, content).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::schema::{PatchFileInfo, PatchRecord};
    use std::collections::HashMap;

    const TEST_UUID_1: &str = "11111111-1111-4111-8111-111111111111";
    const TEST_UUID_2: &str = "22222222-2222-4222-8222-222222222222";

    const BEFORE_HASH_1: &str =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1111";
    const AFTER_HASH_1: &str =
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb1111";
    const BEFORE_HASH_2: &str =
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc2222";
    const AFTER_HASH_2: &str =
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd2222";
    const BEFORE_HASH_3: &str =
        "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee3333";
    const AFTER_HASH_3: &str =
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3333";

    fn create_test_manifest() -> PatchManifest {
        let mut patches = HashMap::new();

        let mut files_a = HashMap::new();
        files_a.insert(
            "package/index.js".to_string(),
            PatchFileInfo {
                before_hash: BEFORE_HASH_1.to_string(),
                after_hash: AFTER_HASH_1.to_string(),
            },
        );
        files_a.insert(
            "package/lib/utils.js".to_string(),
            PatchFileInfo {
                before_hash: BEFORE_HASH_2.to_string(),
                after_hash: AFTER_HASH_2.to_string(),
            },
        );

        patches.insert(
            "pkg:npm/pkg-a@1.0.0".to_string(),
            PatchRecord {
                uuid: TEST_UUID_1.to_string(),
                exported_at: "2024-01-01T00:00:00Z".to_string(),
                files: files_a,
                vulnerabilities: HashMap::new(),
                description: "Test patch 1".to_string(),
                license: "MIT".to_string(),
                tier: "free".to_string(),
            },
        );

        let mut files_b = HashMap::new();
        files_b.insert(
            "package/main.js".to_string(),
            PatchFileInfo {
                before_hash: BEFORE_HASH_3.to_string(),
                after_hash: AFTER_HASH_3.to_string(),
            },
        );

        patches.insert(
            "pkg:npm/pkg-b@2.0.0".to_string(),
            PatchRecord {
                uuid: TEST_UUID_2.to_string(),
                exported_at: "2024-01-01T00:00:00Z".to_string(),
                files: files_b,
                vulnerabilities: HashMap::new(),
                description: "Test patch 2".to_string(),
                license: "MIT".to_string(),
                tier: "free".to_string(),
            },
        );

        PatchManifest { patches }
    }

    #[test]
    fn test_get_referenced_blobs_returns_all() {
        let manifest = create_test_manifest();
        let blobs = get_referenced_blobs(&manifest);

        assert_eq!(blobs.len(), 6);
        assert!(blobs.contains(BEFORE_HASH_1));
        assert!(blobs.contains(AFTER_HASH_1));
        assert!(blobs.contains(BEFORE_HASH_2));
        assert!(blobs.contains(AFTER_HASH_2));
        assert!(blobs.contains(BEFORE_HASH_3));
        assert!(blobs.contains(AFTER_HASH_3));
    }

    #[test]
    fn test_get_referenced_blobs_empty_manifest() {
        let manifest = PatchManifest::new();
        let blobs = get_referenced_blobs(&manifest);
        assert_eq!(blobs.len(), 0);
    }

    #[test]
    fn test_get_referenced_blobs_deduplicates() {
        let mut files = HashMap::new();
        files.insert(
            "package/file1.js".to_string(),
            PatchFileInfo {
                before_hash: BEFORE_HASH_1.to_string(),
                after_hash: AFTER_HASH_1.to_string(),
            },
        );
        files.insert(
            "package/file2.js".to_string(),
            PatchFileInfo {
                before_hash: BEFORE_HASH_1.to_string(), // same as file1
                after_hash: AFTER_HASH_2.to_string(),
            },
        );

        let mut patches = HashMap::new();
        patches.insert(
            "pkg:npm/pkg-a@1.0.0".to_string(),
            PatchRecord {
                uuid: TEST_UUID_1.to_string(),
                exported_at: "2024-01-01T00:00:00Z".to_string(),
                files,
                vulnerabilities: HashMap::new(),
                description: "Test".to_string(),
                license: "MIT".to_string(),
                tier: "free".to_string(),
            },
        );

        let manifest = PatchManifest { patches };
        let blobs = get_referenced_blobs(&manifest);
        // 3 unique hashes, not 4
        assert_eq!(blobs.len(), 3);
    }

    #[test]
    fn test_get_after_hash_blobs() {
        let manifest = create_test_manifest();
        let blobs = get_after_hash_blobs(&manifest);

        assert_eq!(blobs.len(), 3);
        assert!(blobs.contains(AFTER_HASH_1));
        assert!(blobs.contains(AFTER_HASH_2));
        assert!(blobs.contains(AFTER_HASH_3));
        assert!(!blobs.contains(BEFORE_HASH_1));
        assert!(!blobs.contains(BEFORE_HASH_2));
        assert!(!blobs.contains(BEFORE_HASH_3));
    }

    #[test]
    fn test_get_after_hash_blobs_empty() {
        let manifest = PatchManifest::new();
        let blobs = get_after_hash_blobs(&manifest);
        assert_eq!(blobs.len(), 0);
    }

    #[test]
    fn test_get_before_hash_blobs() {
        let manifest = create_test_manifest();
        let blobs = get_before_hash_blobs(&manifest);

        assert_eq!(blobs.len(), 3);
        assert!(blobs.contains(BEFORE_HASH_1));
        assert!(blobs.contains(BEFORE_HASH_2));
        assert!(blobs.contains(BEFORE_HASH_3));
        assert!(!blobs.contains(AFTER_HASH_1));
        assert!(!blobs.contains(AFTER_HASH_2));
        assert!(!blobs.contains(AFTER_HASH_3));
    }

    #[test]
    fn test_get_before_hash_blobs_empty() {
        let manifest = PatchManifest::new();
        let blobs = get_before_hash_blobs(&manifest);
        assert_eq!(blobs.len(), 0);
    }

    #[test]
    fn test_after_plus_before_equals_all() {
        let manifest = create_test_manifest();
        let all_blobs = get_referenced_blobs(&manifest);
        let after_blobs = get_after_hash_blobs(&manifest);
        let before_blobs = get_before_hash_blobs(&manifest);

        let union: HashSet<String> = after_blobs.union(&before_blobs).cloned().collect();
        assert_eq!(union.len(), all_blobs.len());
        for blob in &all_blobs {
            assert!(union.contains(blob));
        }
    }

    #[test]
    fn test_diff_manifests_added() {
        let old = PatchManifest::new();
        let new_manifest = create_test_manifest();

        let diff = diff_manifests(&old, &new_manifest);
        assert_eq!(diff.added.len(), 2);
        assert!(diff.added.contains("pkg:npm/pkg-a@1.0.0"));
        assert!(diff.added.contains("pkg:npm/pkg-b@2.0.0"));
        assert_eq!(diff.removed.len(), 0);
        assert_eq!(diff.modified.len(), 0);
    }

    #[test]
    fn test_diff_manifests_removed() {
        let old = create_test_manifest();
        let new_manifest = PatchManifest::new();

        let diff = diff_manifests(&old, &new_manifest);
        assert_eq!(diff.added.len(), 0);
        assert_eq!(diff.removed.len(), 2);
        assert!(diff.removed.contains("pkg:npm/pkg-a@1.0.0"));
        assert!(diff.removed.contains("pkg:npm/pkg-b@2.0.0"));
        assert_eq!(diff.modified.len(), 0);
    }

    #[test]
    fn test_diff_manifests_modified() {
        let old = create_test_manifest();
        let mut new_manifest = create_test_manifest();
        // Change UUID of pkg-a
        new_manifest
            .patches
            .get_mut("pkg:npm/pkg-a@1.0.0")
            .unwrap()
            .uuid = "33333333-3333-4333-8333-333333333333".to_string();

        let diff = diff_manifests(&old, &new_manifest);
        assert_eq!(diff.added.len(), 0);
        assert_eq!(diff.removed.len(), 0);
        assert_eq!(diff.modified.len(), 1);
        assert!(diff.modified.contains("pkg:npm/pkg-a@1.0.0"));
    }

    #[test]
    fn test_diff_manifests_same() {
        let old = create_test_manifest();
        let new_manifest = create_test_manifest();

        let diff = diff_manifests(&old, &new_manifest);
        assert_eq!(diff.added.len(), 0);
        assert_eq!(diff.removed.len(), 0);
        assert_eq!(diff.modified.len(), 0);
    }

    #[test]
    fn test_validate_manifest_valid() {
        let json = serde_json::json!({
            "patches": {
                "pkg:npm/test@1.0.0": {
                    "uuid": "11111111-1111-4111-8111-111111111111",
                    "exportedAt": "2024-01-01T00:00:00Z",
                    "files": {},
                    "vulnerabilities": {},
                    "description": "test",
                    "license": "MIT",
                    "tier": "free"
                }
            }
        });

        let result = validate_manifest(&json);
        assert!(result.is_ok());
        let manifest = result.unwrap();
        assert_eq!(manifest.patches.len(), 1);
    }

    #[test]
    fn test_validate_manifest_invalid() {
        let json = serde_json::json!({
            "patches": "not-an-object"
        });

        let result = validate_manifest(&json);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_manifest_missing_fields() {
        let json = serde_json::json!({
            "patches": {
                "pkg:npm/test@1.0.0": {
                    "uuid": "test"
                }
            }
        });

        let result = validate_manifest(&json);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_read_manifest_not_found() {
        let result = read_manifest("/nonexistent/path/manifest.json").await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_write_and_read_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manifest.json");

        let manifest = create_test_manifest();
        write_manifest(&path, &manifest).await.unwrap();

        let read_back = read_manifest(&path).await.unwrap();
        assert!(read_back.is_some());
        let read_back = read_back.unwrap();
        assert_eq!(read_back.patches.len(), 2);
    }
}
