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
//! tampering at the package-archive level; we leave that alone and
//! surface a warning so the operator knows what to expect.

use std::path::Path;

use super::{SidecarError, SidecarOutcome};

const METADATA_FILE: &str = ".nupkg.metadata";

/// Delete `.nupkg.metadata` if present, and surface an advisory if
/// the package also carries a `.nupkg.sha512` signature sidecar
/// that we cannot honestly fix.
pub async fn fixup(pkg_path: &Path) -> Result<SidecarOutcome, SidecarError> {
    let mut touched: Vec<String> = Vec::new();

    let metadata_path = pkg_path.join(METADATA_FILE);
    match tokio::fs::remove_file(&metadata_path).await {
        Ok(()) => touched.push(METADATA_FILE.to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => { /* nothing to do */ }
        Err(source) => {
            return Err(SidecarError::Io {
                path: metadata_path.display().to_string(),
                source,
            });
        }
    }

    // If a `*.nupkg.sha512` sibling exists, the package is signed at
    // the archive level. We can't fix that. Surface the warning by
    // appending to the outcome — but the metadata deletion (if any)
    // is still the actionable thing we did.
    let signed = has_signed_marker(pkg_path).await;

    if touched.is_empty() {
        if signed {
            return Ok(SidecarOutcome::Advisory(
                "NuGet: package has a .nupkg.sha512 signature sidecar — \
                 NuGet may flag this install as tampered. No safe recovery."
                    .to_string(),
            ));
        }
        return Ok(SidecarOutcome::None);
    }

    if signed {
        // We did delete metadata, but still warn about the signature.
        // Return Updated so the caller sees the actionable change; the
        // CLI envelope can layer an advisory event on top.
        return Ok(SidecarOutcome::Updated(touched));
    }

    Ok(SidecarOutcome::Updated(touched))
}

/// Return true if the directory contains any `*.nupkg.sha512` file —
/// a NuGet content-signing marker.
async fn has_signed_marker(pkg_path: &Path) -> bool {
    let mut entries = match tokio::fs::read_dir(pkg_path).await {
        Ok(rd) => rd,
        Err(_) => return false,
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        if let Some(name) = entry.file_name().to_str() {
            if name.ends_with(".nupkg.sha512") {
                return true;
            }
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
        assert_eq!(
            out,
            SidecarOutcome::Updated(vec![METADATA_FILE.to_string()])
        );
        // File is gone.
        assert!(tokio::fs::metadata(d.path().join(METADATA_FILE))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn no_metadata_yields_none() {
        let d = tempfile::tempdir().unwrap();
        let out = fixup(d.path()).await.unwrap();
        assert_eq!(out, SidecarOutcome::None);
    }

    /// Signed package (sha512 sidecar present) but no metadata to
    /// delete: surface the advisory so the operator knows.
    #[tokio::test]
    async fn signed_without_metadata_returns_advisory() {
        let d = tempfile::tempdir().unwrap();
        tokio::fs::write(d.path().join("pkg.1.0.0.nupkg.sha512"), b"hash")
            .await
            .unwrap();

        let out = fixup(d.path()).await.unwrap();
        match out {
            SidecarOutcome::Advisory(s) => assert!(s.contains("sha512")),
            other => panic!("expected Advisory, got {other:?}"),
        }
    }

    /// Signed package WITH metadata: we delete metadata and report
    /// Updated. (A separate advisory event for the signature is up
    /// to the CLI layer to emit.)
    #[tokio::test]
    async fn signed_with_metadata_deletes_and_reports() {
        let d = tempfile::tempdir().unwrap();
        tokio::fs::write(d.path().join(METADATA_FILE), b"{}")
            .await
            .unwrap();
        tokio::fs::write(d.path().join("pkg.1.0.0.nupkg.sha512"), b"hash")
            .await
            .unwrap();

        let out = fixup(d.path()).await.unwrap();
        match out {
            SidecarOutcome::Updated(v) => assert_eq!(v, vec![METADATA_FILE.to_string()]),
            other => panic!("expected Updated, got {other:?}"),
        }
        assert!(tokio::fs::metadata(d.path().join(METADATA_FILE))
            .await
            .is_err());
    }
}
