use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::manifest::schema::PatchManifest;

/// Resolve a manifest path: absolute paths are returned as-is, relative paths
/// are joined to `cwd`. Centralizes the duplicate block previously inlined in
/// apply/rollback/list/remove/repair commands.
pub fn resolve_manifest_path(cwd: &Path, manifest_path: &str) -> PathBuf {
    if Path::new(manifest_path).is_absolute() {
        PathBuf::from(manifest_path)
    } else {
        cwd.join(manifest_path)
    }
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

/// Validate a parsed JSON value as a PatchManifest.
/// Returns Ok(manifest) if valid, or Err(message) if invalid.
pub fn validate_manifest(value: &serde_json::Value) -> Result<PatchManifest, String> {
    serde_json::from_value::<PatchManifest>(value.clone())
        .map_err(|e| format!("Invalid manifest: {}", e))
}

/// Read and parse a manifest from the filesystem.
/// Returns Ok(None) if the file does not exist.
/// Returns Err for I/O errors, JSON parse errors, or validation errors.
pub async fn read_manifest(path: impl AsRef<Path>) -> Result<Option<PatchManifest>, std::io::Error> {
    let path = path.as_ref();

    let content = match tokio::fs::read_to_string(path).await {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),   // FIX: propagate actual I/O error
    };

    let parsed: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(e) => return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Failed to parse manifest JSON: {}", e),
        )),
    };

    match validate_manifest(&parsed) {
        Ok(manifest) => Ok(Some(manifest)),
        Err(e) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            e,
        )),
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

    #[test]
    fn test_resolve_manifest_path_relative_joins_cwd() {
        let cwd = Path::new("/tmp/proj");
        let resolved = resolve_manifest_path(cwd, ".socket/manifest.json");
        assert_eq!(resolved, PathBuf::from("/tmp/proj/.socket/manifest.json"));
    }

    #[test]
    fn test_resolve_manifest_path_absolute_unchanged() {
        let cwd = Path::new("/tmp/proj");
        let absolute = if cfg!(windows) {
            r"C:\custom\manifest.json"
        } else {
            "/etc/custom/manifest.json"
        };
        let resolved = resolve_manifest_path(cwd, absolute);
        assert_eq!(resolved, PathBuf::from(absolute));
    }

    #[test]
    fn test_resolve_manifest_path_relative_dotted() {
        let cwd = Path::new("/tmp/proj");
        let resolved = resolve_manifest_path(cwd, "../manifest.json");
        assert_eq!(resolved, PathBuf::from("/tmp/proj/../manifest.json"));
    }
}
