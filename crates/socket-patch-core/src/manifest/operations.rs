use std::collections::HashSet;
use std::path::Path;

use crate::manifest::schema::PatchManifest;

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

/// Parse and validate a manifest directly, without an intermediate JSON tree.
fn parse_manifest(content: &str) -> Result<PatchManifest, std::io::Error> {
    serde_json::from_str(content).map_err(|e| {
        let context = if e.is_data() {
            "Invalid manifest"
        } else {
            "Failed to parse manifest JSON"
        };
        std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{context}: {e}"))
    })
}

/// Read and parse a manifest from the filesystem.
/// Returns Ok(None) if the file does not exist.
/// Returns Err for I/O errors, JSON parse errors, or validation errors.
pub async fn read_manifest(
    path: impl AsRef<Path>,
) -> Result<Option<PatchManifest>, std::io::Error> {
    let content = match crate::utils::fs::read_regular_to_string(path.as_ref()).await {
        Ok(content) => content,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    // Tolerate a UTF-8 byte-order mark (Windows editors add one on save):
    // the file looks fine in an editor, yet serde_json rejects it with an
    // opaque "expected value at line 1 column 1".
    let json = crate::formats::text::strip_bom(&content);
    parse_manifest(json).map(Some)
}

/// Whether a manifest exists at `path`, by [`read_manifest`]'s rule: only
/// `NotFound` is absence. Any other stat error (an unsearchable `.socket/`,
/// `.socket` as a plain file, a symlink loop) is returned, so a caller's
/// "no manifest" path never runs for a manifest it merely cannot read.
/// Something that is not a regular file still counts as present:
/// [`read_manifest`] then refuses it, whatever the path's spelling.
///
/// Windows reports a path under a plain file as not found, so there (as in
/// [`read_manifest`]) `.socket` as a file reads as no manifest.
pub async fn manifest_exists(path: impl AsRef<Path>) -> Result<bool, std::io::Error> {
    tokio::fs::try_exists(path.as_ref()).await
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
///
/// The manifest is a file the project commits and other tools write (a
/// newer CLI, the TS tool), so a rewrite keeps what this version does not
/// own: the file's permission bits and owner, and every top-level and
/// per-record field it does not know, where the file had them (see
/// [`keep_unknown_fields`]). A manifest without such fields is written
/// exactly as the schema serializes it.
pub async fn write_manifest(
    path: impl AsRef<Path>,
    manifest: &PatchManifest,
) -> Result<(), std::io::Error> {
    let path = path.as_ref();
    let invalid = |e| std::io::Error::new(std::io::ErrorKind::InvalidData, e);
    let merged = match existing_document(path).await {
        Some(existing) => {
            let mut document = serde_json::to_value(manifest).map_err(invalid)?;
            keep_unknown_fields(&existing, &mut document).then_some(document)
        }
        None => None,
    };
    let content = match merged {
        Some(document) => serde_json::to_string_pretty(&document),
        None => serde_json::to_string_pretty(manifest),
    }
    .map_err(invalid)?;
    crate::utils::fs::atomic_write_bytes_preserving_mode(path, content.as_bytes()).await
}

/// The keys this version writes at the top level of a manifest and in a
/// patch record. Any other key in a manifest on disk belongs to another
/// writer.
const MANIFEST_KEYS: &[&str] = &["patches", "setup"];
const RECORD_KEYS: &[&str] = &[
    "uuid",
    "exportedAt",
    "files",
    "vulnerabilities",
    "description",
    "license",
    "tier",
];

/// The manifest now at `path` as a JSON object; `None` when there is none
/// or it is not one (nothing to keep).
async fn existing_document(path: &Path) -> Option<serde_json::Map<String, serde_json::Value>> {
    let text = crate::utils::fs::read_regular_to_string(path).await.ok()?;
    match serde_json::from_str(crate::formats::text::strip_bom(&text)).ok()? {
        serde_json::Value::Object(document) => Some(document),
        _ => None,
    }
}

/// Carry the fields of `existing` (the manifest on disk) that this version
/// does not know into `document` (the manifest about to replace it): the
/// top-level ones, and those of every record that is still the same patch
/// (same `uuid`; a record another patch replaced does not inherit them, and
/// a removed record takes its own along). Returns whether there were any.
fn keep_unknown_fields(
    existing: &serde_json::Map<String, serde_json::Value>,
    document: &mut serde_json::Value,
) -> bool {
    use serde_json::Value;
    let Some(document) = document.as_object_mut() else {
        return false;
    };
    let mut kept = false;
    if let (Some(old_records), Some(records)) = (
        existing.get("patches").and_then(Value::as_object),
        document.get_mut("patches").and_then(Value::as_object_mut),
    ) {
        for (purl, record) in records.iter_mut() {
            let (Some(old), Some(record)) = (
                old_records.get(purl).and_then(Value::as_object),
                record.as_object_mut(),
            ) else {
                continue;
            };
            if old.get("uuid") == record.get("uuid") {
                kept |= keep_unknown_keys(old, record, RECORD_KEYS);
            }
        }
    }
    kept |= keep_unknown_keys(existing, document, MANIFEST_KEYS);
    kept
}

/// Rebuild `new` with the keys of `old` outside `known` put back at the
/// positions `old` had them: `old`'s key order, each known key holding
/// `new`'s value, then the keys only `new` has. Untouched (and `false`)
/// when `old` has no such key, so the common manifest keeps the schema's
/// own key order.
fn keep_unknown_keys(
    old: &serde_json::Map<String, serde_json::Value>,
    new: &mut serde_json::Map<String, serde_json::Value>,
    known: &[&str],
) -> bool {
    if old.keys().all(|key| known.contains(&key.as_str())) {
        return false;
    }
    let mut merged = serde_json::Map::new();
    for (key, value) in old {
        match new.get(key) {
            Some(value) => merged.insert(key.clone(), value.clone()),
            None if !known.contains(&key.as_str()) => merged.insert(key.clone(), value.clone()),
            // A known key the new manifest no longer has.
            None => None,
        };
    }
    for (key, value) in new.iter() {
        if !merged.contains_key(key) {
            merged.insert(key.clone(), value.clone());
        }
    }
    *new = merged;
    true
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
    fn test_parse_manifest_valid() {
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

        let result = parse_manifest(&json.to_string());
        assert!(result.is_ok());
        let manifest = result.unwrap();
        assert_eq!(manifest.patches.len(), 1);
    }

    /// Well-formed JSON that violates the schema is a DATA error: it keeps
    /// the historical "Invalid manifest" prefix (the syntax class below keeps
    /// "Failed to parse manifest JSON"); both are `InvalidData`. The split
    /// is decided by `serde_json::Error::is_data`, so pin it here — no
    /// external test does.
    #[test]
    fn test_parse_manifest_invalid() {
        let json = serde_json::json!({
            "patches": "not-an-object"
        });

        let err = parse_manifest(&json.to_string()).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(
            err.to_string().starts_with("Invalid manifest: "),
            "schema errors keep the data-class prefix: {err}"
        );

        let err = parse_manifest("{ not json").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(
            err.to_string()
                .starts_with("Failed to parse manifest JSON: "),
            "syntax errors keep the parse-class prefix: {err}"
        );
    }

    /// Deserializing straight into the struct rejects a REPEATED struct field
    /// (a `Value` round-trip would silently keep the last value). A
    /// hand-edited manifest with two `uuid` keys in one record is malformed
    /// and classified as a data error. The fixture is a raw string on purpose:
    /// `json!` would collapse the duplicate before the parser ever saw it.
    #[test]
    fn test_parse_manifest_rejects_duplicate_struct_field() {
        let raw = r#"{"patches":{"pkg:npm/a@1.0.0":{"uuid":"x","uuid":"y",
            "exportedAt":"t","files":{},"vulnerabilities":{},
            "description":"","license":"MIT","tier":"free"}}}"#;
        let err = parse_manifest(raw).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(
            err.to_string()
                .starts_with("Invalid manifest: duplicate field `uuid`"),
            "{err}"
        );
    }

    #[test]
    fn test_parse_manifest_missing_fields() {
        let json = serde_json::json!({
            "patches": {
                "pkg:npm/test@1.0.0": {
                    "uuid": "test"
                }
            }
        });

        let result = parse_manifest(&json.to_string());
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_read_manifest_not_found() {
        let result = read_manifest("/nonexistent/path/manifest.json").await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    // A manifest saved with a UTF-8 BOM (as some Windows editors do) reads
    // like any other; a BOM anywhere but the start stays invalid.
    #[tokio::test]
    async fn test_read_manifest_tolerates_leading_bom() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manifest.json");
        tokio::fs::write(&path, "\u{feff}{\"patches\":{}}")
            .await
            .unwrap();
        let manifest = read_manifest(&path).await.unwrap().unwrap();
        assert!(manifest.patches.is_empty());

        tokio::fs::write(&path, "{\"patches\":{}}\u{feff}\u{feff}")
            .await
            .unwrap();
        let err = read_manifest(&path).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
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

    /// mkfifo(2) directly, not the /usr/bin/mkfifo binary: spawning a child
    /// flakes under heavy parallel load (fork/exec starvation) and the
    /// syscall needs no process at all.
    #[cfg(unix)]
    fn mkfifo(path: &Path) {
        use std::os::unix::ffi::OsStrExt;
        let c_path =
            std::ffi::CString::new(path.as_os_str().as_bytes()).expect("fifo path has no NUL");
        let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o644) };
        assert_eq!(
            rc,
            0,
            "mkfifo(2) failed: {}",
            std::io::Error::last_os_error()
        );
    }

    /// A FIFO planted as `.socket/manifest.json` must not wedge
    /// `read_manifest`: a plain `read_to_string` open(2)s the FIFO with
    /// `O_RDONLY` and waits for a writer that never comes — and
    /// `read_manifest` is the single manifest choke point for `list`,
    /// `apply`, `remove`, and `repair`, with `apply` running from install
    /// hooks, so one special file hangs `npm install` forever with no
    /// output. It must fail fast (`InvalidInput` from the regular-file
    /// guard) while a missing file keeps mapping to `Ok(None)`.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_read_manifest_fifo_fails_fast_instead_of_wedging() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manifest.json");
        mkfifo(&path);

        let deadline = std::time::Duration::from_secs(5);
        let Ok(result) = tokio::time::timeout(deadline, read_manifest(&path)).await else {
            // Release the reader wedged in open(2) so the test binary can
            // exit cleanly, then fail loudly.
            use std::os::unix::fs::OpenOptionsExt;
            let _ = std::fs::OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&path);
            panic!("read_manifest must fail fast on a FIFO manifest, not wedge in open(2)");
        };
        let err = result.expect_err("a FIFO manifest must be an error, not a manifest");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
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

    // #998: `manifest_exists` keeps `read_manifest`'s rule. Only a missing
    // file is absent; a stat error is returned, never read as "no manifest".
    #[tokio::test]
    async fn test_manifest_exists_only_not_found_is_absent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manifest.json");
        assert!(!manifest_exists(&path).await.unwrap());

        write_manifest(&path, &create_test_manifest())
            .await
            .unwrap();
        assert!(manifest_exists(&path).await.unwrap());

        // A directory is present; `read_manifest` refuses it.
        let as_dir = dir.path().join("dir").join("manifest.json");
        std::fs::create_dir_all(&as_dir).unwrap();
        assert!(manifest_exists(&as_dir).await.unwrap());
        assert!(read_manifest(&as_dir).await.is_err());
    }

    // `.socket` as a plain file: ENOTDIR, not NotFound (Windows reports
    // such a path as not found, for both functions alike).
    #[cfg(unix)]
    #[tokio::test]
    async fn test_manifest_exists_under_a_file_is_error() {
        let dir = tempfile::tempdir().unwrap();
        let socket_file = dir.path().join("socket-file");
        std::fs::write(&socket_file, "x").unwrap();
        let under_file = socket_file.join("manifest.json");
        let err = manifest_exists(&under_file).await.unwrap_err();
        assert_ne!(err.kind(), std::io::ErrorKind::NotFound);
        assert!(read_manifest(&under_file).await.is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_manifest_exists_symlink_loop_is_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manifest.json");
        std::os::unix::fs::symlink("manifest.json", &path).unwrap();
        let err = manifest_exists(&path).await.unwrap_err();
        assert_ne!(err.kind(), std::io::ErrorKind::NotFound);
        assert!(read_manifest(&path).await.is_err());
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

    /// A manifest carrying fields this version does not know (a newer
    /// CLI's, the TS tool's), at the top level and in a record.
    const MANIFEST_WITH_UNKNOWN_FIELDS: &str = r#"{
  "schemaVersion": 2,
  "patches": {
    "pkg:npm/pkg-a@1.0.0": {
      "uuid": "11111111-1111-4111-8111-111111111111",
      "futureRecordField": {
        "kept": [
          1,
          "two"
        ]
      },
      "exportedAt": "2024-01-01T00:00:00Z",
      "files": {},
      "vulnerabilities": {},
      "description": "a",
      "license": "MIT",
      "tier": "free"
    },
    "pkg:npm/pkg-b@2.0.0": {
      "uuid": "22222222-2222-4222-8222-222222222222",
      "exportedAt": "2024-02-01T00:00:00Z",
      "files": {},
      "vulnerabilities": {},
      "description": "b",
      "license": "MIT",
      "tier": "free",
      "addedBy": "another tool"
    }
  },
  "futureTopLevel": true
}"#;

    /// A rewrite that changes nothing leaves a manifest with unknown fields
    /// byte for byte as it was: the fields survive, where they were.
    #[tokio::test]
    async fn test_write_manifest_keeps_unknown_fields_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manifest.json");
        tokio::fs::write(&path, MANIFEST_WITH_UNKNOWN_FIELDS)
            .await
            .unwrap();

        let manifest = read_manifest(&path).await.unwrap().unwrap();
        write_manifest(&path, &manifest).await.unwrap();

        assert_eq!(
            tokio::fs::read_to_string(&path).await.unwrap(),
            MANIFEST_WITH_UNKNOWN_FIELDS
        );
    }

    /// Removing one record keeps the other record's unknown fields and the
    /// top-level ones; the removed record takes its own along, and a record
    /// another patch replaced (a new `uuid`) does not inherit them.
    #[tokio::test]
    async fn test_write_manifest_unknown_fields_follow_their_record() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manifest.json");
        tokio::fs::write(&path, MANIFEST_WITH_UNKNOWN_FIELDS)
            .await
            .unwrap();

        let mut manifest = read_manifest(&path).await.unwrap().unwrap();
        manifest.patches.remove("pkg:npm/pkg-a@1.0.0");
        write_manifest(&path, &manifest).await.unwrap();
        let written: serde_json::Value =
            serde_json::from_str(&tokio::fs::read_to_string(&path).await.unwrap()).unwrap();
        assert_eq!(written["schemaVersion"], 2);
        assert_eq!(written["futureTopLevel"], true);
        assert!(written["patches"].get("pkg:npm/pkg-a@1.0.0").is_none());
        assert_eq!(
            written["patches"]["pkg:npm/pkg-b@2.0.0"]["addedBy"],
            "another tool"
        );
        assert!(!written.to_string().contains("futureRecordField"));

        let record = manifest.patches.get_mut("pkg:npm/pkg-b@2.0.0").unwrap();
        record.uuid = TEST_UUID_1.to_string();
        write_manifest(&path, &manifest).await.unwrap();
        let written: serde_json::Value =
            serde_json::from_str(&tokio::fs::read_to_string(&path).await.unwrap()).unwrap();
        assert_eq!(
            written["patches"]["pkg:npm/pkg-b@2.0.0"]["uuid"],
            TEST_UUID_1
        );
        assert!(written["patches"]["pkg:npm/pkg-b@2.0.0"]
            .get("addedBy")
            .is_none());
        assert_eq!(written["futureTopLevel"], true);
    }

    /// A manifest without unknown fields is written exactly as the schema
    /// serializes it (no trailing newline), whatever was on disk before.
    #[tokio::test]
    async fn test_write_manifest_plain_rewrite_is_byte_stable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manifest.json");
        let manifest = create_test_manifest();
        let expected = serde_json::to_string_pretty(&manifest).unwrap();

        write_manifest(&path, &manifest).await.unwrap();
        assert_eq!(tokio::fs::read_to_string(&path).await.unwrap(), expected);
        write_manifest(&path, &manifest).await.unwrap();
        assert_eq!(tokio::fs::read_to_string(&path).await.unwrap(), expected);

        // Something that is not a manifest holds nothing to keep.
        tokio::fs::write(&path, b"[1, 2").await.unwrap();
        write_manifest(&path, &manifest).await.unwrap();
        assert_eq!(tokio::fs::read_to_string(&path).await.unwrap(), expected);
    }

    /// The known-key lists are the schema's own keys: a field added to the
    /// schema without its key here would be treated as another writer's.
    #[test]
    fn test_known_keys_match_the_schema() {
        let mut manifest = create_test_manifest();
        manifest.setup = Some(crate::manifest::schema::SetupConfig {
            exclude: vec!["packages/a".to_string()],
            manual: Vec::new(),
        });
        let document = serde_json::to_value(&manifest).unwrap();
        let keys = |value: &serde_json::Value| -> Vec<String> {
            value.as_object().unwrap().keys().cloned().collect()
        };
        assert_eq!(keys(&document), MANIFEST_KEYS);
        let record = document["patches"].as_object().unwrap().values().next();
        assert_eq!(keys(record.unwrap()), RECORD_KEYS);
    }

    /// A rewrite keeps the manifest's permission bits: a private `0600`
    /// manifest does not become world-readable.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_write_manifest_keeps_the_file_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manifest.json");
        let manifest = create_test_manifest();
        write_manifest(&path, &manifest).await.unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        write_manifest(&path, &manifest).await.unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o600);
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
}
