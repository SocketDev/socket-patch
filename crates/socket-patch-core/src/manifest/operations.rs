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
///
/// An empty `beforeHash` is the "file created by the patch" sentinel, not a
/// blob reference (rollback deletes the file instead of restoring content),
/// so it is excluded from the set.
pub fn get_before_hash_blobs(manifest: &PatchManifest) -> HashSet<String> {
    let mut blobs = HashSet::new();

    for record in manifest.patches.values() {
        for file_info in record.files.values() {
            if !file_info.before_hash.is_empty() {
                blobs.insert(file_info.before_hash.clone());
            }
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
pub async fn read_manifest(
    path: impl AsRef<Path>,
) -> Result<Option<PatchManifest>, std::io::Error> {
    let path = path.as_ref();

    let content = match tokio::fs::read_to_string(path).await {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e), // FIX: propagate actual I/O error
    };

    let parsed: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(e) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Failed to parse manifest JSON: {}", e),
            ))
        }
    };

    match validate_manifest(&parsed) {
        Ok(manifest) => Ok(Some(manifest)),
        Err(e) => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
    }
}

/// Write a manifest to the filesystem with pretty-printed JSON.
///
/// The write is atomic: the JSON is staged in a sibling temp file, fsync'd,
/// then renamed over `path`. A bare `tokio::fs::write` would truncate the
/// existing manifest up front and stream the bytes in place, so a crash (or
/// ENOSPC) mid-write leaves a half-written file on disk. That matters here
/// because [`read_manifest`] treats malformed JSON as a hard `InvalidData`
/// error -- a torn manifest would brick every subsequent command
/// (apply/list/remove/rollback/repair) rather than degrading gracefully.
/// Staging + rename guarantees readers only ever observe the old or the new
/// manifest, never a partial one.
pub async fn write_manifest(
    path: impl AsRef<Path>,
    manifest: &PatchManifest,
) -> Result<(), std::io::Error> {
    let path = path.as_ref();
    let content = serde_json::to_string_pretty(manifest)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let stem = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "manifest.json".to_string());
    let stage = parent.join(format!(".socket-stage-{}-{}", stem, uuid::Uuid::new_v4()));

    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&stage)
        .await?;

    use tokio::io::AsyncWriteExt;
    if let Err(e) = file.write_all(content.as_bytes()).await {
        let _ = tokio::fs::remove_file(&stage).await;
        return Err(e);
    }
    if let Err(e) = file.sync_all().await {
        let _ = tokio::fs::remove_file(&stage).await;
        return Err(e);
    }
    drop(file);

    if let Err(e) = tokio::fs::rename(&stage, path).await {
        let _ = tokio::fs::remove_file(&stage).await;
        return Err(e);
    }

    // Durability: `sync_all` flushed the file's data, but the rename only
    // updated the parent directory entry. fsync the directory so the rename
    // itself survives a crash. Unix only; best-effort, since a directory we
    // can't open for fsync must not fail an otherwise-successful write.
    #[cfg(unix)]
    {
        if let Ok(dir) = tokio::fs::File::open(parent).await {
            let _ = dir.sync_all().await;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::schema::{PatchFileInfo, PatchRecord};
    use std::collections::HashMap;

    const TEST_UUID_1: &str = "11111111-1111-4111-8111-111111111111";
    const TEST_UUID_2: &str = "22222222-2222-4222-8222-222222222222";

    const BEFORE_HASH_1: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1111";
    const AFTER_HASH_1: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb1111";
    const BEFORE_HASH_2: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc2222";
    const AFTER_HASH_2: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd2222";
    const BEFORE_HASH_3: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee3333";
    const AFTER_HASH_3: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3333";

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

        PatchManifest {
            patches,
            setup: None,
        }
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

    // Regression: an empty `beforeHash` is the documented "file created by the
    // patch" sentinel (get records it, apply/rollback branch on it) -- it is
    // valid manifest data, not a blob reference. The before-blob set must skip
    // it: a caller that treats every entry as fetchable would try to download
    // blob "", and an existence probe via `blobs_path.join("")` resolves to
    // the blobs directory itself, turning "is this blob on disk" into "does
    // the directory exist".
    #[test]
    fn test_get_before_hash_blobs_skips_new_file_sentinel() {
        let mut manifest = create_test_manifest();
        let record = manifest.patches.get_mut("pkg:npm/pkg-a@1.0.0").unwrap();
        record.files.insert(
            "package/created-by-patch.js".to_string(),
            PatchFileInfo {
                before_hash: String::new(), // new-file sentinel
                after_hash: AFTER_HASH_1.to_string(),
            },
        );

        let blobs = get_before_hash_blobs(&manifest);
        assert!(
            !blobs.contains(""),
            "the empty new-file sentinel is not a blob and must not be in the set"
        );
        // The real before-hashes all survive.
        assert_eq!(blobs.len(), 3);
        for b in [BEFORE_HASH_1, BEFORE_HASH_2, BEFORE_HASH_3] {
            assert!(blobs.contains(b));
        }
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

    // Regression: a missing file maps to Ok(None), but malformed JSON must
    // surface as an InvalidData error -- NOT be silently swallowed as Ok(None).
    // The original implementation returned Ok(None) for every failure mode,
    // which hid corrupt manifests from callers.
    #[tokio::test]
    async fn test_read_manifest_malformed_json_is_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manifest.json");
        tokio::fs::write(&path, "{ not valid json").await.unwrap();

        let result = read_manifest(&path).await;
        assert!(
            result.is_err(),
            "malformed JSON must be an error, not Ok(None)"
        );
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidData);
    }

    // Regression: well-formed JSON that doesn't satisfy the schema (missing
    // required fields) must also surface as an InvalidData error.
    #[tokio::test]
    async fn test_read_manifest_invalid_schema_is_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manifest.json");
        // Valid JSON, but `patches` has the wrong shape.
        tokio::fs::write(&path, r#"{"patches": "not-an-object"}"#)
            .await
            .unwrap();

        let result = read_manifest(&path).await;
        assert!(
            result.is_err(),
            "schema-invalid manifest must be an error, not Ok(None)"
        );
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidData);
    }

    // Regression: the two blob extractors must not be swapped. Each must return
    // exactly its own side of the hash pair with zero cross-contamination.
    #[test]
    fn test_blob_extractors_do_not_cross_contaminate() {
        let manifest = create_test_manifest();
        let after = get_after_hash_blobs(&manifest);
        let before = get_before_hash_blobs(&manifest);

        // The two sets are disjoint for this fixture.
        assert!(after.is_disjoint(&before));
        // Every after-blob is an afterHash from the fixture, never a beforeHash.
        for b in [BEFORE_HASH_1, BEFORE_HASH_2, BEFORE_HASH_3] {
            assert!(!after.contains(b));
        }
        for a in [AFTER_HASH_1, AFTER_HASH_2, AFTER_HASH_3] {
            assert!(!before.contains(a));
        }
    }

    // Regression: a non-NotFound I/O error must propagate as Err -- it must NOT
    // be collapsed into Ok(None). Only a genuinely-missing file is Ok(None).
    // Reading a directory as if it were a file produces such an I/O error, which
    // directly exercises the `Err(e) => return Err(e)` arm. (The malformed-JSON
    // and invalid-schema tests cover the parse/validate arms but not this one.)
    #[tokio::test]
    async fn test_read_manifest_io_error_propagates() {
        let dir = tempfile::tempdir().unwrap();
        // Path exists but is a directory, so read_to_string fails with an I/O
        // error whose kind is NOT NotFound.
        let result = read_manifest(dir.path()).await;
        assert!(
            result.is_err(),
            "a non-NotFound I/O error must surface as Err, not Ok(None)"
        );
        assert_ne!(
            result.unwrap_err().kind(),
            std::io::ErrorKind::NotFound,
            "an existing-but-unreadable path is not a 'missing file'"
        );
    }

    // Regression: write_manifest -> read_manifest must preserve the full record,
    // not merely the patch count. Guards against a serializer that drops nested
    // fields (file hashes, vulnerabilities) while still round-tripping the keys.
    #[tokio::test]
    async fn test_write_manifest_preserves_full_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manifest.json");

        let manifest = create_test_manifest();
        write_manifest(&path, &manifest).await.unwrap();

        let read_back = read_manifest(&path).await.unwrap().unwrap();
        // Deep equality: every patch, file, hash, and vulnerability survives.
        assert_eq!(read_back, manifest);

        // Spot-check a nested hash to make the intent explicit.
        let record = read_back.patches.get("pkg:npm/pkg-a@1.0.0").unwrap();
        let file_info = record.files.get("package/index.js").unwrap();
        assert_eq!(file_info.before_hash, BEFORE_HASH_1);
        assert_eq!(file_info.after_hash, AFTER_HASH_1);
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

    // Regression: write_manifest must be atomic -- it stages a temp file and
    // renames it over the target. After a successful write, no `.socket-stage-*`
    // litter may remain in the directory (a leaked stage file would accumulate
    // and could be mistaken for a manifest by directory walkers).
    #[tokio::test]
    async fn test_write_manifest_leaves_no_stage_litter() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manifest.json");

        let manifest = create_test_manifest();
        write_manifest(&path, &manifest).await.unwrap();
        // Overwrite a second time to exercise the rename-over-existing path.
        write_manifest(&path, &manifest).await.unwrap();

        let mut entries = tokio::fs::read_dir(dir.path()).await.unwrap();
        while let Some(entry) = entries.next_entry().await.unwrap() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            assert!(
                !name.starts_with(".socket-stage-"),
                "atomic write must not leave a staging file behind, found {name}"
            );
        }
        // Final file must be a single, fully-readable manifest.
        assert_eq!(read_manifest(&path).await.unwrap().unwrap(), manifest);
    }

    // Regression: a failed write_manifest must NOT clobber an existing, valid
    // manifest. Because the new content is staged in a temp file and only
    // rename()d over the target on success, a write that fails before the
    // rename (here: the target's parent directory does not exist, so even
    // staging fails) leaves any prior manifest untouched. This is the property
    // that prevents a half-written manifest from bricking later commands.
    #[tokio::test]
    async fn test_write_manifest_failure_preserves_existing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manifest.json");

        // Establish a valid, on-disk manifest.
        let original = create_test_manifest();
        write_manifest(&path, &original).await.unwrap();

        // A write that fails before the rename: target's parent dir is missing,
        // so staging the temp file (create_new in the missing parent) errors.
        let bad = dir.path().join("does-not-exist").join("manifest.json");
        let mut other = create_test_manifest();
        other.patches.clear(); // a different payload, so we'd notice a clobber
        let result = write_manifest(&bad, &other).await;
        assert!(result.is_err(), "writing into a missing dir must fail");

        // The pre-existing manifest is untouched (atomicity: nothing is mutated
        // unless the staged write fully succeeds and renames into place).
        assert_eq!(read_manifest(&path).await.unwrap().unwrap(), original);

        // No stage litter leaked into the dir alongside the good manifest.
        let mut entries = tokio::fs::read_dir(dir.path()).await.unwrap();
        while let Some(entry) = entries.next_entry().await.unwrap() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            assert!(
                !name.starts_with(".socket-stage-"),
                "a failed write must not leave stage litter, found {name}"
            );
        }
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
