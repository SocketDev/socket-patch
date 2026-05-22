//! Cargo `.cargo-checksum.json` rewriter.
//!
//! `cargo build` verifies on-disk source files against the per-crate
//! checksum file in `<crate-root>/.cargo-checksum.json`. The format
//! is documented (and trivially small):
//!
//! ```json
//! {
//!   "files": {
//!     "src/lib.rs": "abc...sha256hex",
//!     "Cargo.toml": "def...sha256hex"
//!   },
//!   "package": "ghi...sha256hex of the .crate tarball"
//! }
//! ```
//!
//! Each value under `files` is the lowercase-hex SHA256 of the raw
//! file content (NOT the Git "blob N\0" framing we use elsewhere —
//! cargo uses the plain digest). The `package` field is the
//! pre-extraction `.crate` tarball hash; we can't recompute that
//! honestly without the tarball, but cargo only checks it at
//! install time, not build time, so leaving it stale is acceptable
//! for an already-extracted crate.
//!
//! If the file does not exist, this is a no-op — some local-path
//! dependencies don't ship a checksum file. We treat that as
//! "nothing to fix up" rather than an error.

use std::path::Path;

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::patch::apply::normalize_file_path;

use super::{SidecarError, SidecarFile, SidecarFileAction, SidecarPayload};

const CHECKSUM_FILE: &str = ".cargo-checksum.json";

/// Rewrite `<pkg_path>/.cargo-checksum.json` so each entry for a
/// patched file reflects the on-disk SHA256.
///
/// Returns:
///   * `Ok(Some(payload))` with one `SidecarFile{path: ".cargo-checksum.json", action: Rewritten}`
///     when the file existed and was rewritten;
///   * `Ok(None)` when there's no `.cargo-checksum.json` to fix up
///     (some local-path deps don't ship one);
///   * `Err(SidecarError)` on I/O or JSON parse failure.
pub(crate) async fn fixup(
    pkg_path: &Path,
    patched: &[String],
) -> Result<Option<SidecarPayload>, SidecarError> {
    let checksum_path = pkg_path.join(CHECKSUM_FILE);

    // Read the existing file. NotFound is fine — no checksums to update.
    let raw = match tokio::fs::read_to_string(&checksum_path).await {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(None);
        }
        Err(source) => {
            return Err(SidecarError::Io {
                path: checksum_path.display().to_string(),
                source,
            });
        }
    };

    let mut json: Value =
        serde_json::from_str(&raw).map_err(|e| SidecarError::Malformed {
            path: checksum_path.display().to_string(),
            detail: e.to_string(),
        })?;

    let files = json
        .get_mut("files")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| SidecarError::Malformed {
            path: checksum_path.display().to_string(),
            detail: "missing or non-object `files` field".to_string(),
        })?;

    update_entries(files, pkg_path, patched).await?;

    // Pretty-print with two-space indent — matches what cargo
    // itself writes. Not strictly required (cargo accepts any
    // formatting) but keeps diffs reviewable.
    let mut out = serde_json::to_vec_pretty(&json).map_err(|e| SidecarError::Malformed {
        path: checksum_path.display().to_string(),
        detail: e.to_string(),
    })?;
    out.push(b'\n');

    tokio::fs::write(&checksum_path, out).await.map_err(|source| {
        SidecarError::Io {
            path: checksum_path.display().to_string(),
            source,
        }
    })?;

    Ok(Some(SidecarPayload {
        files: vec![SidecarFile {
            path: CHECKSUM_FILE.to_string(),
            action: SidecarFileAction::Rewritten,
        }],
        advisory: None,
    }))
}

/// For each patched entry, recompute the on-disk SHA256 and write it
/// into the `files` map keyed by the normalized relative path.
///
/// Entries in the patch list may include the `package/` prefix used
/// by the API; the on-disk file lives at `pkg_path.join(normalized)`,
/// and the cargo-checksum key is the same `normalized` path. New
/// files added by a patch get a fresh entry.
async fn update_entries(
    files: &mut Map<String, Value>,
    pkg_path: &Path,
    patched: &[String],
) -> Result<(), SidecarError> {
    for file_name in patched {
        let normalized = normalize_file_path(file_name).to_string();
        let on_disk = pkg_path.join(&normalized);
        let hash = sha256_file(&on_disk).await.map_err(|source| SidecarError::Io {
            path: on_disk.display().to_string(),
            source,
        })?;
        files.insert(normalized, Value::String(hash));
    }
    Ok(())
}

/// Compute the lowercase-hex SHA256 of the file at `path`. Streamed —
/// no in-memory copy of the whole file. (Cargo source files are
/// usually small, but defensive.)
async fn sha256_file(path: &Path) -> std::io::Result<String> {
    let mut file = tokio::fs::File::open(path).await?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    use tokio::io::AsyncReadExt;
    loop {
        let n = file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expected_sha256(bytes: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(bytes);
        format!("{:x}", h.finalize())
    }

    /// Round trip: file with a known hash gets rewritten to its
    /// post-patch hash. Other entries are left untouched.
    #[tokio::test]
    async fn rewrites_only_patched_files() {
        let d = tempfile::tempdir().unwrap();
        let pkg = d.path();
        // Write the patched file (create parent dir first).
        tokio::fs::create_dir_all(pkg.join("src")).await.unwrap();
        tokio::fs::write(pkg.join("src/lib.rs"), b"patched lib")
            .await
            .unwrap();
        // Write a file we do NOT patch — its hash stays stale.
        tokio::fs::write(pkg.join("Cargo.toml"), b"unchanged").await.unwrap();

        // Pre-existing checksum file with bogus hashes for both.
        let starting = serde_json::json!({
            "files": {
                "src/lib.rs": "00".repeat(32),
                "Cargo.toml": "11".repeat(32),
            },
            "package": "stale-package-hash",
        });
        tokio::fs::write(
            pkg.join(CHECKSUM_FILE),
            serde_json::to_string_pretty(&starting).unwrap(),
        )
        .await
        .unwrap();

        let out = fixup(pkg, &["src/lib.rs".to_string()]).await.unwrap();
        let payload = out.expect("checksum file existed, fixup should return a payload");
        assert_eq!(payload.files.len(), 1);
        assert_eq!(payload.files[0].path, CHECKSUM_FILE);
        assert_eq!(payload.files[0].action, SidecarFileAction::Rewritten);
        assert!(payload.advisory.is_none());

        // Read back and assert.
        let post: serde_json::Value = serde_json::from_str(
            &tokio::fs::read_to_string(pkg.join(CHECKSUM_FILE)).await.unwrap(),
        )
        .unwrap();
        let files = post["files"].as_object().unwrap();

        // Patched entry now reflects the real on-disk SHA256.
        assert_eq!(
            files["src/lib.rs"].as_str().unwrap(),
            expected_sha256(b"patched lib")
        );
        // Untouched entry is left as it was — we don't rehash files
        // that weren't part of the patch.
        assert_eq!(files["Cargo.toml"].as_str().unwrap(), "11".repeat(32));
        // `package` is preserved unchanged.
        assert_eq!(post["package"].as_str().unwrap(), "stale-package-hash");
    }

    /// Patches that add new files create fresh entries in the
    /// `files` map.
    #[tokio::test]
    async fn adds_entries_for_new_files() {
        let d = tempfile::tempdir().unwrap();
        let pkg = d.path();
        tokio::fs::create_dir_all(pkg.join("src")).await.unwrap();
        tokio::fs::write(pkg.join("src/new.rs"), b"brand new").await.unwrap();

        let starting = serde_json::json!({
            "files": {
                "Cargo.toml": "ff".repeat(32),
            },
            "package": "x",
        });
        tokio::fs::write(
            pkg.join(CHECKSUM_FILE),
            serde_json::to_string_pretty(&starting).unwrap(),
        )
        .await
        .unwrap();

        let _ = fixup(pkg, &["src/new.rs".to_string()]).await.unwrap();

        let post: serde_json::Value = serde_json::from_str(
            &tokio::fs::read_to_string(pkg.join(CHECKSUM_FILE)).await.unwrap(),
        )
        .unwrap();
        let files = post["files"].as_object().unwrap();
        assert_eq!(
            files["src/new.rs"].as_str().unwrap(),
            expected_sha256(b"brand new")
        );
        assert_eq!(files.len(), 2);
    }

    /// Patch entries may carry the API-side `package/` prefix; the
    /// rewriter normalizes to the cargo-style relative path.
    #[tokio::test]
    async fn normalizes_package_prefix() {
        let d = tempfile::tempdir().unwrap();
        let pkg = d.path();
        tokio::fs::create_dir_all(pkg.join("src")).await.unwrap();
        tokio::fs::write(pkg.join("src/lib.rs"), b"patched").await.unwrap();

        let starting = serde_json::json!({
            "files": { "src/lib.rs": "00".repeat(32) },
            "package": "x",
        });
        tokio::fs::write(
            pkg.join(CHECKSUM_FILE),
            serde_json::to_string_pretty(&starting).unwrap(),
        )
        .await
        .unwrap();

        // Patch list uses the "package/" prefix.
        let _ = fixup(pkg, &["package/src/lib.rs".to_string()]).await.unwrap();

        let post: serde_json::Value = serde_json::from_str(
            &tokio::fs::read_to_string(pkg.join(CHECKSUM_FILE)).await.unwrap(),
        )
        .unwrap();
        assert_eq!(
            post["files"]["src/lib.rs"].as_str().unwrap(),
            expected_sha256(b"patched")
        );
        // No bogus "package/src/lib.rs" key created.
        assert!(post["files"].get("package/src/lib.rs").is_none());
    }

    /// Missing checksum file is a no-op — local-path deps sometimes
    /// don't ship one. The patch already wrote the file; we just
    /// don't have a sidecar to fix.
    #[tokio::test]
    async fn missing_checksum_file_is_noop() {
        let d = tempfile::tempdir().unwrap();
        let out = fixup(d.path(), &["src/lib.rs".to_string()]).await.unwrap();
        assert!(out.is_none());
    }

    /// Malformed JSON produces a clean error (caller surfaces as a
    /// warning event; the patch itself is already on disk).
    #[tokio::test]
    async fn malformed_json_surfaces_error() {
        let d = tempfile::tempdir().unwrap();
        tokio::fs::write(d.path().join(CHECKSUM_FILE), b"this is not json")
            .await
            .unwrap();
        let err = fixup(d.path(), &["src/lib.rs".to_string()])
            .await
            .unwrap_err();
        assert!(matches!(err, SidecarError::Malformed { .. }));
    }
}
