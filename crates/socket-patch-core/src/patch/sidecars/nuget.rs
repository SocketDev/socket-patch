//! NuGet `.nupkg.metadata` neutralizer.
//!
//! NuGet stores a per-package metadata file at
//! `<pkg>/.nupkg.metadata` containing a `contentHash` — the SHA512 of
//! the original `.nupkg` archive — used to detect tampering or
//! corruption of the on-disk install. After we patch a file the hash
//! no longer matches, and `dotnet restore` flags the package as
//! tampered.
//!
//! We cannot recompute the hash honestly — that would require the
//! original `.nupkg` and the original file order, neither of which we
//! have post-extraction. The pragmatic move (and what NuGet itself
//! tolerates) is to delete the metadata file: NuGet treats a missing
//! metadata as "unknown state, accept the install" rather than
//! "checksum mismatch, refuse". A signed-package detail tag
//! (`<name>.<ver>.nupkg.sha512`) — if present — still flags
//! tampering at the package-archive level; the new typed surface
//! carries that as an advisory ALONGSIDE the metadata-deleted file
//! entry (no longer collapsed).

use std::path::Path;

use crate::patch::apply::DirWriteGuard;

use super::{
    SidecarAdvisory, SidecarAdvisoryCode, SidecarError, SidecarFile, SidecarFileAction,
    SidecarPayload, SidecarSeverity,
};

const METADATA_FILE: &str = ".nupkg.metadata";

/// Delete `.nupkg.metadata` if present, and surface an advisory if
/// the package also carries a `.nupkg.sha512` signature sidecar
/// that we cannot honestly fix.
///
/// Returns:
///   * `Ok(Some(payload))` carrying any combination of the
///     metadata-deleted file entry and the signed-package advisory;
///   * `Ok(None)` when there's no metadata and no signature
///     (nothing to report);
///   * `Err(SidecarError)` on I/O failure.
pub(crate) async fn fixup(pkg_path: &Path) -> Result<Option<SidecarPayload>, SidecarError> {
    let mut files = Vec::new();

    let metadata_path = pkg_path.join(METADATA_FILE);

    // `unlink(2)` needs write permission on the *parent directory*, not
    // on the file. NuGet caches can live inside a read-only (`0o555`)
    // tree — the same tamper-proofing layout the apply path hardened
    // against for Cargo/Go (see `apply::DirWriteGuard`). Without the
    // guard a bare `remove_file` fails `EACCES` exactly in the
    // real-cache case, leaving the stale-hash metadata in place so every
    // future `dotnet restore` flags the (correctly) patched package as
    // tampered. Grant directory-write for the unlink, then restore the
    // directory's exact mode — even if the unlink itself errors.
    let dir_guard = DirWriteGuard::acquire(Some(pkg_path)).await;
    let remove_result = tokio::fs::remove_file(&metadata_path).await;
    dir_guard.restore().await;

    match remove_result {
        Ok(()) => files.push(SidecarFile {
            path: METADATA_FILE.to_string(),
            action: SidecarFileAction::Deleted,
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => { /* nothing to do */ }
        Err(source) => {
            return Err(SidecarError::Io {
                path: metadata_path.display().to_string(),
                source,
            });
        }
    }

    // If a `*.nupkg.sha512` sibling exists, the package is signed at
    // the archive level. We can't fix that. Surface a structured
    // advisory regardless of whether we also deleted metadata — the
    // old design's lossy collapse hid this when both fired.
    let advisory = if has_signed_marker(pkg_path).await {
        Some(SidecarAdvisory {
            code: SidecarAdvisoryCode::NugetSignedPackageTampered,
            severity: SidecarSeverity::Warning,
            message: "NuGet: package has a .nupkg.sha512 signature sidecar — \
                      NuGet may flag this install as tampered. No safe recovery."
                .to_string(),
        })
    } else {
        None
    };

    if files.is_empty() && advisory.is_none() {
        return Ok(None);
    }

    Ok(Some(SidecarPayload { files, advisory }))
}

/// Return true if the directory contains any `*.nupkg.sha512` file —
/// a NuGet content-signing marker.
///
/// Matches against `OsStr::as_encoded_bytes()` rather than
/// `to_str()`. The `.nupkg.sha512` suffix is pure ASCII, so a byte-
/// level `ends_with` is exactly as correct as the str check would
/// be — and it naturally handles non-UTF-8 filenames (ext4, NTFS
/// junk left over from corrupt installs) without an implicit-else
/// arm that coverage can never reach on filesystems that reject
/// non-UTF-8 bytes at creation time (APFS).
async fn has_signed_marker(pkg_path: &Path) -> bool {
    let mut entries = match tokio::fs::read_dir(pkg_path).await {
        Ok(rd) => rd,
        Err(_) => return false,
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        if entry
            .file_name()
            .as_encoded_bytes()
            .ends_with(b".nupkg.sha512")
        {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn deletes_metadata_when_present() {
        let d = tempfile::tempdir().unwrap();
        tokio::fs::write(d.path().join(METADATA_FILE), b"{}")
            .await
            .unwrap();

        let out = fixup(d.path()).await.unwrap();
        let payload = out.expect("metadata existed, expect a payload");
        assert_eq!(payload.files.len(), 1);
        assert_eq!(payload.files[0].path, METADATA_FILE);
        assert_eq!(payload.files[0].action, SidecarFileAction::Deleted);
        assert!(payload.advisory.is_none());
        // File is gone.
        assert!(tokio::fs::metadata(d.path().join(METADATA_FILE))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn no_metadata_yields_none() {
        let d = tempfile::tempdir().unwrap();
        let out = fixup(d.path()).await.unwrap();
        assert!(out.is_none());
    }

    /// Signed package (sha512 sidecar present) but no metadata to
    /// delete: payload carries an advisory only.
    #[tokio::test]
    async fn signed_without_metadata_returns_advisory_only() {
        let d = tempfile::tempdir().unwrap();
        tokio::fs::write(d.path().join("pkg.1.0.0.nupkg.sha512"), b"hash")
            .await
            .unwrap();

        let out = fixup(d.path()).await.unwrap();
        let payload = out.expect("signed package expects a payload");
        assert!(payload.files.is_empty());
        let adv = payload.advisory.expect("expected advisory");
        assert_eq!(adv.code, SidecarAdvisoryCode::NugetSignedPackageTampered);
        assert_eq!(adv.severity, SidecarSeverity::Warning);
    }

    /// Regression (read-only package directory): NuGet caches — like
    /// Cargo's registry and Go's module cache — can live inside a
    /// directory the host marks read-only (`0o555`) for tamper
    /// detection. Removing `.nupkg.metadata` requires *write permission
    /// on the parent directory*, not on the file itself, so a bare
    /// `remove_file` fails `EACCES` there — leaving the stale-hash
    /// metadata in place and every future `dotnet restore` flagging the
    /// (correctly) patched package as tampered. The fixup must grant
    /// directory-write for the unlink and restore the original mode.
    #[cfg(unix)]
    #[tokio::test]
    async fn deletes_metadata_inside_readonly_dir() {
        use std::os::unix::fs::PermissionsExt;

        let d = tempfile::tempdir().unwrap();
        let pkg = d.path();
        tokio::fs::write(pkg.join(METADATA_FILE), b"{}")
            .await
            .unwrap();
        // Lock the package directory down exactly as a tamper-proofed
        // cache would.
        tokio::fs::set_permissions(pkg, std::fs::Permissions::from_mode(0o555))
            .await
            .unwrap();

        let out = fixup(pkg).await;

        // Capture the post-fixup directory mode BEFORE re-granting write
        // for cleanup — the guard must have restored it to 0o555 itself.
        let mode = tokio::fs::metadata(pkg).await.unwrap().permissions().mode() & 0o7777;

        // Re-grant write so the TempDir can clean itself up regardless
        // of the assertion outcome.
        tokio::fs::set_permissions(pkg, std::fs::Permissions::from_mode(0o755))
            .await
            .unwrap();

        let payload = out
            .expect("delete inside a read-only dir must not error")
            .expect("metadata existed, expect a payload");
        assert_eq!(payload.files.len(), 1);
        assert_eq!(payload.files[0].action, SidecarFileAction::Deleted);
        // The metadata is actually gone.
        assert!(tokio::fs::metadata(pkg.join(METADATA_FILE)).await.is_err());
        // ...and the directory's original read-only mode was restored.
        assert_eq!(
            mode, 0o555,
            "package dir mode must be restored after the unlink"
        );
    }

    /// Signed package WITH metadata: the typed payload now carries
    /// BOTH the file entry and the advisory — the lossy collapse
    /// from the old design is fixed.
    #[tokio::test]
    async fn signed_with_metadata_carries_files_and_advisory() {
        let d = tempfile::tempdir().unwrap();
        tokio::fs::write(d.path().join(METADATA_FILE), b"{}")
            .await
            .unwrap();
        tokio::fs::write(d.path().join("pkg.1.0.0.nupkg.sha512"), b"hash")
            .await
            .unwrap();

        let out = fixup(d.path()).await.unwrap();
        let payload = out.expect("expect a payload");
        assert_eq!(payload.files.len(), 1);
        assert_eq!(payload.files[0].action, SidecarFileAction::Deleted);
        let adv = payload
            .advisory
            .expect("signed-package case must surface advisory alongside the file entry");
        assert_eq!(adv.code, SidecarAdvisoryCode::NugetSignedPackageTampered);
        assert!(tokio::fs::metadata(d.path().join(METADATA_FILE))
            .await
            .is_err());
    }
}
