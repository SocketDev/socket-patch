//! Per-ecosystem fixups for the integrity sidecars that package
//! managers verify at build/install time.
//!
//! Patching a file inside a package directory leaves the ecosystem's
//! own checksum metadata pointing at the pre-patch hash. The next
//! `cargo build`, `pip check`, or `nuget restore` then either fails
//! ("checksum changed") or flags the install as tampered. This
//! module owns the post-apply rewrites that keep those sidecars
//! consistent with what we just wrote to disk.
//!
//! Coverage in this revision:
//!
//! - **Cargo** ([`cargo::fixup`]): rewrite `.cargo-checksum.json` so
//!   `cargo build` accepts the patched sources.
//! - **NuGet** ([`nuget::fixup`]): delete `.nupkg.metadata` (we
//!   cannot honestly recompute `contentHash` without the original
//!   `.nupkg`; deletion is the "unknown" state vs. tampering-flag
//!   for a stale hash). A signed-package `.nupkg.sha512` marker
//!   surfaces an advisory ALONGSIDE the metadata deletion.
//! - **PyPI / gem / Go**: advisory only — emit a structured
//!   advisory so downstream tooling consequences are programmatic.
//!   Full sidecar rewrites land in follow-ups.
//!
//! All ecosystems return a [`SidecarRecord`] via [`dispatch_fixup`].
//! The record is the canonical JSON-envelope shape — see
//! [`types`] for field documentation and stability guarantees.

use std::collections::HashMap;
use std::path::Path;

use crate::crawlers::Ecosystem;
use crate::manifest::schema::PatchFileInfo;

#[cfg(feature = "cargo")]
pub(crate) mod cargo;
#[cfg(feature = "nuget")]
pub(crate) mod nuget;
pub mod types;

pub use types::{
    SidecarAdvisory, SidecarAdvisoryCode, SidecarFile, SidecarFileAction, SidecarRecord,
    SidecarSeverity,
};

/// Intermediate payload returned by per-ecosystem fixups. The
/// wrapper [`dispatch_fixup`] adds `purl` + `ecosystem` to form a
/// full [`SidecarRecord`]. Per-ecosystem code doesn't need to know
/// PURL parsing.
#[derive(Debug, Clone)]
pub(crate) struct SidecarPayload {
    pub files: Vec<SidecarFile>,
    pub advisory: Option<SidecarAdvisory>,
}

/// Errors a sidecar fixup can return. Each is best-effort: a failing
/// sidecar does NOT undo the patch (the patched bytes are already on
/// disk). The boundary in `apply_package_patch` converts these to
/// a [`SidecarRecord`] carrying `SidecarAdvisoryCode::SidecarFixupFailed`
/// so consumers see a uniform shape.
#[derive(Debug, thiserror::Error)]
pub enum SidecarError {
    #[error("sidecar I/O error at {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("malformed sidecar at {path}: {detail}")]
    Malformed { path: String, detail: String },
}

/// Helper for advisory-only ecosystems (PyPI / gem / Go) — builds a
/// payload with no touched files and a single structured advisory.
pub(crate) fn advisory_only_payload(
    code: SidecarAdvisoryCode,
    severity: SidecarSeverity,
    message: &str,
) -> SidecarPayload {
    SidecarPayload {
        files: Vec::new(),
        advisory: Some(SidecarAdvisory {
            code,
            severity,
            message: message.to_string(),
        }),
    }
}

/// Run the post-apply integrity fixup for the package's ecosystem.
///
/// Returns a fully-formed [`SidecarRecord`] (PURL + ecosystem +
/// payload) when the ecosystem produced any output, `None` when
/// the ecosystem has no sidecar contract at all (e.g. npm), or
/// `Err(SidecarError)` when the fixup tried to do something and
/// failed mid-flight. The caller is responsible for converting
/// the error case into an `Error`-severity record.
///
/// `package_key` is the PURL. `pkg_path` is the package directory
/// on disk. `patched` lists the patch-file keys that were actually
/// written (same convention as `apply_package_patch.files_patched`).
/// `files` is reserved for future use (currently unread).
#[allow(unused_variables)] // `pkg_path` is feature-gated below
pub async fn dispatch_fixup(
    package_key: &str,
    pkg_path: &Path,
    patched: &[String],
    _files: &HashMap<String, PatchFileInfo>,
) -> Result<Option<SidecarRecord>, SidecarError> {
    if patched.is_empty() {
        return Ok(None);
    }

    let ecosystem = match Ecosystem::from_purl(package_key) {
        Some(eco) => eco,
        None => return Ok(None),
    };

    let payload: Option<SidecarPayload> = match ecosystem {
        #[cfg(feature = "cargo")]
        Ecosystem::Cargo => cargo::fixup(pkg_path, patched).await?,
        #[cfg(feature = "nuget")]
        Ecosystem::Nuget => nuget::fixup(pkg_path).await?,
        Ecosystem::Pypi => Some(advisory_only_payload(
            SidecarAdvisoryCode::PypiRecordStale,
            SidecarSeverity::Warning,
            "PyPI: run `pip check` (or `uv pip check`) to verify \
             .dist-info/RECORD consistency. `pip install --force-reinstall` \
             or `uv pip install --reinstall` will revert these patches.",
        )),
        Ecosystem::Gem => Some(advisory_only_payload(
            SidecarAdvisoryCode::GemBundleInstallReverts,
            SidecarSeverity::Warning,
            "Ruby gem: `bundle install --redownload` will revert these \
             patches by reinstalling from the cached .gem.",
        )),
        #[cfg(feature = "golang")]
        Ecosystem::Golang => Some(advisory_only_payload(
            SidecarAdvisoryCode::GoModVerifyFails,
            SidecarSeverity::Warning,
            "Go: `go mod verify` will report a checksum mismatch against \
             go.sum. `go build` works as long as the module cache stays warm.",
        )),
        _ => None,
    };

    Ok(payload.map(|p| SidecarRecord {
        purl: package_key.to_string(),
        ecosystem: ecosystem.cli_name().to_string(),
        files: p.files,
        advisory: p.advisory,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_files() -> HashMap<String, PatchFileInfo> {
        HashMap::new()
    }

    #[tokio::test]
    async fn empty_patched_returns_none() {
        let d = tempfile::tempdir().unwrap();
        let out = dispatch_fixup("pkg:npm/anything@1.0.0", d.path(), &[], &empty_files())
            .await
            .unwrap();
        assert!(out.is_none());
    }

    #[tokio::test]
    async fn npm_has_no_sidecar() {
        let d = tempfile::tempdir().unwrap();
        let out = dispatch_fixup(
            "pkg:npm/anything@1.0.0",
            d.path(),
            &["package/x.js".to_string()],
            &empty_files(),
        )
        .await
        .unwrap();
        assert!(out.is_none());
    }

    #[tokio::test]
    async fn pypi_returns_structured_advisory() {
        let d = tempfile::tempdir().unwrap();
        let out = dispatch_fixup(
            "pkg:pypi/requests@2.28.0",
            d.path(),
            &["package/foo.py".to_string()],
            &empty_files(),
        )
        .await
        .unwrap();
        let record = out.expect("pypi should return a record");
        assert_eq!(record.ecosystem, "pypi");
        assert_eq!(record.purl, "pkg:pypi/requests@2.28.0");
        assert!(record.files.is_empty());
        let advisory = record.advisory.expect("pypi must carry an advisory");
        assert_eq!(advisory.code, SidecarAdvisoryCode::PypiRecordStale);
        assert_eq!(advisory.severity, SidecarSeverity::Warning);
        assert!(advisory.message.contains("pip"));
    }

    #[tokio::test]
    async fn gem_returns_structured_advisory() {
        let d = tempfile::tempdir().unwrap();
        let out = dispatch_fixup(
            "pkg:gem/rails@7.1.0",
            d.path(),
            &["lib/rails.rb".to_string()],
            &empty_files(),
        )
        .await
        .unwrap();
        let record = out.expect("gem should return a record");
        assert_eq!(record.ecosystem, "gem");
        let advisory = record.advisory.expect("gem must carry an advisory");
        assert_eq!(
            advisory.code,
            SidecarAdvisoryCode::GemBundleInstallReverts
        );
    }

    #[tokio::test]
    async fn unknown_ecosystem_returns_none() {
        // PURL has no recognized prefix → dispatcher bails with None.
        let d = tempfile::tempdir().unwrap();
        let out = dispatch_fixup(
            "pkg:weirdo/x@1",
            d.path(),
            &["x".to_string()],
            &empty_files(),
        )
        .await
        .unwrap();
        assert!(out.is_none());
    }
}
