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

use crate::hash::git_sha256::compute_git_sha256_from_bytes;
use crate::patch::apply::{apply_file_patch, is_safe_relative_subpath, normalize_file_path};

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

    let mut json: Value = serde_json::from_str(&raw).map_err(|e| SidecarError::Malformed {
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
    //
    // `to_vec_pretty` is total over `serde_json::Value` — the only
    // way it can fail is if a custom `Serialize` impl errors, and
    // we're serializing a Value built entirely from string/object
    // primitives. `.expect()` rather than `.map_err()` because
    // making this an `Err` path produces dead code (uncoverable
    // from any input, by serde's contract).
    let mut out = serde_json::to_vec_pretty(&json)
        .expect("serializing a Value just deserialized from valid JSON must succeed");
    out.push(b'\n');

    // Commit through the hardened shared write path — NOT a bare
    // `tokio::fs::write`. The checksum file lives inside a Cargo
    // registry/vendor `<crate>-<version>/` tree, which Cargo marks
    // read-only (files `0o444` inside `0o555` dirs) for tamper
    // detection. A plain in-place truncating write has three defects
    // there, all of which the rest of the patch engine was hardened
    // against (see `apply::apply_file_patch` and `rollback`):
    //
    //   1. **Read-only-hostile.** Opening the existing `0o444` file
    //      `O_TRUNC` fails `EACCES`, so the fixup errored out exactly
    //      in the real-registry case it exists to handle — leaving the
    //      checksum stale-patched and every future `cargo build` of the
    //      crate refusing the (correctly) patched sources.
    //   2. **Non-atomic.** A crash / `ENOSPC` mid-write leaves a
    //      truncated, unparseable `.cargo-checksum.json` — strictly
    //      worse than a stale hash, because cargo can no longer even
    //      parse it to report a mismatch; the crate is wedged.
    //   3. **Copy-on-write-unsafe.** A vendored tree hardlinked into a
    //      shared store would have its sibling mutated in place.
    //
    // `apply_file_patch` stages a sibling, fsyncs, and `rename(2)`s
    // atomically; breaks CoW inodes; relaxes then restores BOTH the
    // file's and the directory's read-only modes; and verifies the
    // bytes that landed. The `expected_hash` is just the digest of the
    // bytes we hand it (a self-check) — the file already exists, so
    // its original mode is snapshotted and restored bit-for-bit.
    let expected_hash = compute_git_sha256_from_bytes(&out);
    apply_file_patch(pkg_path, CHECKSUM_FILE, &out, &expected_hash)
        .await
        .map_err(|source| SidecarError::Io {
            path: checksum_path.display().to_string(),
            source,
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

        // SECURITY (fail closed): `normalized` is joined to `pkg_path` and
        // both read (to hash) and used as a `.cargo-checksum.json` key. An
        // escaping key (`../../etc/passwd`, an absolute path) would make us
        // hash an arbitrary out-of-tree file and embed its digest under a
        // bogus key in the committed checksum — an info leak that also
        // corrupts the checksum so cargo can no longer verify the crate.
        // The apply *write* path (`apply_file_patch`) already refuses these,
        // but `fixup` is `pub(crate)` and reached directly via `dispatch_fixup`
        // and tests, so the *read* path must guard itself too. Mirror apply's
        // `InvalidData` refusal rather than silently skipping — an escaping
        // key never names a legitimate patch target.
        if !is_safe_relative_subpath(&normalized) {
            return Err(SidecarError::Io {
                path: file_name.clone(),
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Unsafe patch path (escapes package directory): {file_name}"),
                ),
            });
        }

        let on_disk = pkg_path.join(&normalized);
        let hash = sha256_file(&on_disk)
            .await
            .map_err(|source| SidecarError::Io {
                path: on_disk.display().to_string(),
                source,
            })?;
        files.insert(normalized, Value::String(hash));
    }
    Ok(())
}

/// Compute the lowercase-hex SHA256 of the file at `path`.
///
/// Loads the whole file into memory and hashes in one go.
/// Cargo source files are bounded (the registry rejects crates
/// whose `.crate` tarball exceeds ~10MB unpacked), so a single
/// `read()` is cheaper than the streaming-loop dance and
/// collapses the open + read into one `?` arm — which the
/// `dispatch_fixup_cargo_sha256_file_failure_arm` integration
/// test drives via a non-existent path.
async fn sha256_file(path: &Path) -> std::io::Result<String> {
    let bytes = tokio::fs::read(path).await?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
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
        tokio::fs::write(pkg.join("Cargo.toml"), b"unchanged")
            .await
            .unwrap();

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
            &tokio::fs::read_to_string(pkg.join(CHECKSUM_FILE))
                .await
                .unwrap(),
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
        tokio::fs::write(pkg.join("src/new.rs"), b"brand new")
            .await
            .unwrap();

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
            &tokio::fs::read_to_string(pkg.join(CHECKSUM_FILE))
                .await
                .unwrap(),
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
        tokio::fs::write(pkg.join("src/lib.rs"), b"patched")
            .await
            .unwrap();

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
        let _ = fixup(pkg, &["package/src/lib.rs".to_string()])
            .await
            .unwrap();

        let post: serde_json::Value = serde_json::from_str(
            &tokio::fs::read_to_string(pkg.join(CHECKSUM_FILE))
                .await
                .unwrap(),
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

    /// Regression (read-only checksum file): a real Cargo registry/vendor
    /// tree marks `.cargo-checksum.json` read-only (`0o444`) for tamper
    /// detection. The rewrite must still succeed — the hardened
    /// stage+rename path relaxes the file's mode, swaps a fresh inode in
    /// atomically, and restores the original `0o444` mode afterward.
    /// Before the fix the bare in-place `tokio::fs::write` failed `EACCES`
    /// here, leaving the checksum stale-patched and the crate unbuildable.
    #[cfg(unix)]
    #[tokio::test]
    async fn rewrites_readonly_checksum_file_and_restores_mode() {
        use std::os::unix::fs::PermissionsExt;

        let d = tempfile::tempdir().unwrap();
        let pkg = d.path();
        tokio::fs::create_dir_all(pkg.join("src")).await.unwrap();
        tokio::fs::write(pkg.join("src/lib.rs"), b"patched lib")
            .await
            .unwrap();

        let starting = serde_json::json!({
            "files": { "src/lib.rs": "00".repeat(32) },
            "package": "stale",
        });
        let checksum = pkg.join(CHECKSUM_FILE);
        tokio::fs::write(&checksum, serde_json::to_string_pretty(&starting).unwrap())
            .await
            .unwrap();
        // Lock the checksum file down exactly as Cargo would.
        tokio::fs::set_permissions(&checksum, std::fs::Permissions::from_mode(0o444))
            .await
            .unwrap();

        let out = fixup(pkg, &["src/lib.rs".to_string()]).await.unwrap();
        assert!(out.is_some(), "read-only checksum must still be rewritten");

        // The new hash landed...
        let post: serde_json::Value =
            serde_json::from_str(&tokio::fs::read_to_string(&checksum).await.unwrap()).unwrap();
        assert_eq!(
            post["files"]["src/lib.rs"].as_str().unwrap(),
            expected_sha256(b"patched lib")
        );
        // ...and the original read-only mode was restored bit-for-bit.
        let mode = tokio::fs::metadata(&checksum)
            .await
            .unwrap()
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(
            mode, 0o444,
            "checksum file must stay read-only after rewrite"
        );
    }

    /// Regression (read-only package directory): Cargo also marks the
    /// crate directory `0o555`. The atomic stage+rename needs write
    /// permission on the *parent dir* to create its sibling stage file,
    /// so the write path must temporarily grant directory write and
    /// restore the exact `0o555` mode afterward. The bare write could
    /// not stage inside a read-only directory at all.
    #[cfg(unix)]
    #[tokio::test]
    async fn rewrites_inside_readonly_package_dir() {
        use std::os::unix::fs::PermissionsExt;

        let d = tempfile::tempdir().unwrap();
        let pkg = d.path();
        tokio::fs::create_dir_all(pkg.join("src")).await.unwrap();
        tokio::fs::write(pkg.join("src/lib.rs"), b"patched lib")
            .await
            .unwrap();
        let checksum = pkg.join(CHECKSUM_FILE);
        let starting = serde_json::json!({
            "files": { "src/lib.rs": "00".repeat(32) },
            "package": "x",
        });
        tokio::fs::write(&checksum, serde_json::to_string_pretty(&starting).unwrap())
            .await
            .unwrap();
        // Lock the directory down, Cargo-cache style.
        tokio::fs::set_permissions(pkg, std::fs::Permissions::from_mode(0o555))
            .await
            .unwrap();

        let out = fixup(pkg, &["src/lib.rs".to_string()]).await;

        // Re-grant write so the TempDir can clean itself up regardless
        // of the assertion outcome.
        tokio::fs::set_permissions(pkg, std::fs::Permissions::from_mode(0o755))
            .await
            .unwrap();

        assert!(
            out.expect("fixup in read-only dir must not error")
                .is_some(),
            "read-only package dir must still be rewritten",
        );
        let post: serde_json::Value =
            serde_json::from_str(&tokio::fs::read_to_string(&checksum).await.unwrap()).unwrap();
        assert_eq!(
            post["files"]["src/lib.rs"].as_str().unwrap(),
            expected_sha256(b"patched lib")
        );
    }

    /// Security regression (path escape via `..`): a poisoned patch
    /// entry whose key walks out of the package dir must be refused —
    /// NOT hashed and embedded under an escaping key in the committed
    /// checksum. Before the guard, `sha256_file` read the out-of-tree
    /// target and `update_entries` inserted `../secret.txt` into the
    /// `files` map (info leak + checksum corruption).
    #[tokio::test]
    async fn refuses_dotdot_escape_path() {
        let d = tempfile::tempdir().unwrap();
        let pkg = d.path().join("pkg");
        tokio::fs::create_dir_all(&pkg).await.unwrap();

        // A secret living OUTSIDE the package dir, reachable only via `..`.
        let secret = d.path().join("secret.txt");
        tokio::fs::write(&secret, b"top secret bytes")
            .await
            .unwrap();

        let starting = serde_json::json!({
            "files": { "Cargo.toml": "ff".repeat(32) },
            "package": "x",
        });
        let checksum = pkg.join(CHECKSUM_FILE);
        let original = serde_json::to_string_pretty(&starting).unwrap();
        tokio::fs::write(&checksum, &original).await.unwrap();

        let err = fixup(&pkg, &["../secret.txt".to_string()])
            .await
            .unwrap_err();
        match err {
            SidecarError::Io { path, source } => {
                assert!(path.contains("secret.txt"), "error must name the bad key");
                assert_eq!(source.kind(), std::io::ErrorKind::InvalidData);
            }
            other => panic!("expected InvalidData Io error, got {other:?}"),
        }

        // The checksum file must be untouched — no escaping key, no leaked
        // hash of the secret.
        let after = tokio::fs::read_to_string(&checksum).await.unwrap();
        assert_eq!(after, original, "checksum must not be rewritten on refusal");
        assert!(
            !after.contains(&expected_sha256(b"top secret bytes")),
            "the out-of-tree secret's hash must never be embedded"
        );
    }

    /// Security regression (absolute-path escape): `Path::join` discards
    /// the base when the key is absolute, so an absolute key would hash
    /// an arbitrary system file. Must be refused exactly like `..`.
    #[tokio::test]
    async fn refuses_absolute_escape_path() {
        let d = tempfile::tempdir().unwrap();
        let pkg = d.path();
        let starting = serde_json::json!({
            "files": { "Cargo.toml": "ff".repeat(32) },
            "package": "x",
        });
        tokio::fs::write(
            pkg.join(CHECKSUM_FILE),
            serde_json::to_string_pretty(&starting).unwrap(),
        )
        .await
        .unwrap();

        let err = fixup(pkg, &["/etc/hosts".to_string()]).await.unwrap_err();
        assert!(matches!(
            err,
            SidecarError::Io { source, .. } if source.kind() == std::io::ErrorKind::InvalidData
        ));
    }

    /// Atomicity hygiene: the stage+rename commit must leave no
    /// `.socket-stage-*` litter in the package directory.
    #[tokio::test]
    async fn rewrite_leaves_no_stage_litter() {
        let d = tempfile::tempdir().unwrap();
        let pkg = d.path();
        tokio::fs::create_dir_all(pkg.join("src")).await.unwrap();
        tokio::fs::write(pkg.join("src/lib.rs"), b"patched lib")
            .await
            .unwrap();
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

        fixup(pkg, &["src/lib.rs".to_string()]).await.unwrap();

        let mut entries = tokio::fs::read_dir(pkg).await.unwrap();
        while let Some(entry) = entries.next_entry().await.unwrap() {
            let name = entry.file_name().to_string_lossy().to_string();
            assert!(
                !name.starts_with(".socket-stage-") && !name.starts_with(".socket-cow-"),
                "stage/cow litter leaked into package dir: {name}"
            );
        }
    }

    /// Copy-on-write safety: when `.cargo-checksum.json` is hardlinked
    /// into a shared store (a vendored tree shared between projects),
    /// the rewrite must give us a private inode and leave the sibling
    /// untouched. The atomic rename-over-target achieves this; the old
    /// in-place write would have mutated the shared inode.
    #[cfg(unix)]
    #[tokio::test]
    async fn rewrite_does_not_mutate_hardlinked_sibling() {
        let d = tempfile::tempdir().unwrap();
        let pkg = d.path().join("pkg");
        tokio::fs::create_dir_all(pkg.join("src")).await.unwrap();
        tokio::fs::write(pkg.join("src/lib.rs"), b"patched lib")
            .await
            .unwrap();

        let starting = serde_json::json!({
            "files": { "src/lib.rs": "00".repeat(32) },
            "package": "x",
        });
        let checksum = pkg.join(CHECKSUM_FILE);
        let original_json = serde_json::to_string_pretty(&starting).unwrap();
        tokio::fs::write(&checksum, &original_json).await.unwrap();

        // A sibling in the shared store points at the same inode.
        let sibling = d.path().join("shared-store-checksum.json");
        tokio::fs::hard_link(&checksum, &sibling).await.unwrap();

        fixup(&pkg, &["src/lib.rs".to_string()]).await.unwrap();

        // Our copy was rewritten...
        let post: serde_json::Value =
            serde_json::from_str(&tokio::fs::read_to_string(&checksum).await.unwrap()).unwrap();
        assert_eq!(
            post["files"]["src/lib.rs"].as_str().unwrap(),
            expected_sha256(b"patched lib")
        );
        // ...but the shared-store sibling kept its original bytes.
        assert_eq!(
            tokio::fs::read_to_string(&sibling).await.unwrap(),
            original_json,
        );
    }
}
